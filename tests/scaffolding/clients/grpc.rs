//! gRPC client for scripted-backend tests.
//!
//! Built on the `h2` crate's raw client so the test can speak gRPC without
//! a `.proto` codegen step. The client sends:
//!
//! 1. HTTP/2 HEADERS with `:method = POST`, `:path = /pkg.Service/Method`,
//!    `content-type: application/grpc`, `te: trailers`.
//! 2. A 5-byte gRPC length-prefix + the message bytes as a DATA frame.
//! 3. End-of-stream.
//!
//! It returns the parsed response: HTTP status, message bytes (demarshaled
//! from the 5-byte gRPC header), trailers, and any intermediate error.
//!
//! ## Transport
//!
//! - [`GrpcClient::h2c`] — plaintext h2c, for the gateway routing to a
//!   plain HTTP backend that the gateway's own gRPC pool would reach via
//!   h2c. Rare in production but common for tests.
//! - [`GrpcClient::tls`] — h2 over TLS, for the gateway's typical
//!   `backend_scheme: https` gRPC flow.

use bytes::{BufMut, Bytes, BytesMut};
use h2::client as h2_client;
use http::{HeaderMap, HeaderValue, Request, Response};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// A buffered gRPC response, captured eagerly.
#[derive(Debug, Clone)]
pub struct GrpcResponse {
    /// HTTP status. gRPC always uses 200 on the happy path; gateway
    /// rejections on input can surface as non-200.
    pub http_status: u16,
    /// Initial response headers (excluding trailers).
    pub headers: HeaderMap,
    /// Whether the first response HEADERS frame carried END_STREAM on the wire.
    pub initial_headers_end_stream: bool,
    /// Concatenated message bodies with gRPC 5-byte prefix stripped. If the
    /// server emitted multiple messages, they're concatenated in order —
    /// tests that care about individual messages should inspect
    /// `raw_body_frames`.
    pub messages: Vec<Bytes>,
    /// Raw DATA frames as delivered by h2. Useful when a test wants to
    /// assert on framing (e.g. that two messages weren't coalesced).
    pub raw_body_frames: Vec<Bytes>,
    /// Response trailers, if any. `grpc-status` lives here on the happy
    /// path.
    pub trailers: Option<HeaderMap>,
    /// Stream-level error if the response failed mid-stream.
    pub stream_error: Option<String>,
    /// Error from the local h2 `send_data` of the request body, kept separate
    /// from `stream_error` because it can legitimately coexist with a complete,
    /// well-formed response: a fast Trailers-Only gateway error can close the
    /// request direction before the client DATA write is observed locally.
    /// Diagnostic only — response-shape assertions should use `stream_error`.
    pub request_send_error: Option<String>,
}

impl GrpcResponse {
    /// Shorthand: parse `grpc-status` from the trailers, falling back to
    /// initial response headers for the gRPC "Trailers-Only" response
    /// shape (where the HEADERS frame carries `grpc-status` + `grpc-message`
    /// and the stream ends immediately — used for error responses without
    /// a message body).
    pub fn grpc_status(&self) -> Option<u32> {
        if let Some(trailers) = self.trailers.as_ref()
            && let Some(raw) = trailers.get("grpc-status")
            && let Ok(s) = raw.to_str()
            && let Ok(n) = s.parse()
        {
            return Some(n);
        }
        if !self.initial_headers_end_stream {
            return None;
        }
        let raw = self.headers.get("grpc-status")?.to_str().ok()?;
        raw.parse().ok()
    }

    /// Returns the effective gRPC status for the response, following the
    /// canonical HTTP-to-gRPC mapping from
    /// <https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md>:
    ///
    /// * If `grpc-status` is present (in trailers OR in Trailers-Only
    ///   initial headers) → return that value verbatim.
    /// * Else apply the HTTP-to-gRPC code table (400 → INTERNAL(13),
    ///   401 → UNAUTHENTICATED(16), 403 → PERMISSION_DENIED(7),
    ///   404 → UNIMPLEMENTED(12), 429/502/503/504 → UNAVAILABLE(14)).
    /// * Every other HTTP status — including the anomalous
    ///   `HTTP 200 + no grpc-status` case — maps to UNKNOWN(2), per the
    ///   "Every other code" default row in the mapping doc.
    /// * `http_status == 0` (the test client synthesized a response
    ///   because the headers future errored / timed out) → UNAVAILABLE(14):
    ///   transport-level failure, no HTTP response received.
    ///
    /// The `HTTP 200 + missing grpc-status` case deserves a note: the
    /// wire protocol says a server MUST send `grpc-status`, and
    /// real-world Rust / Go implementations diverge on what to
    /// synthesize when it's absent — tonic and some grpc-go paths use
    /// INTERNAL(13), others use UNKNOWN(2). We follow the mapping doc's
    /// "every other code ⇒ UNKNOWN" default because it's the
    /// spec-canonical rule and keeps the helper honest about the
    /// ambiguity (missing trailer is "we don't know what happened at
    /// the server", not specifically "server had an internal error").
    ///
    /// Use this in tests that care about the *semantic* outcome of an
    /// RPC rather than the literal bytes on the wire. [`Self::grpc_status`]
    /// returns `None` for any case where the backend (or gateway) did not
    /// emit an explicit `grpc-status`; `effective_grpc_status` fills in
    /// the code a spec-compliant client would observe.
    pub fn effective_grpc_status(&self) -> u32 {
        if let Some(s) = self.grpc_status() {
            return s;
        }
        match self.http_status {
            0 => 14,                     // UNAVAILABLE — transport/connection failure, no HTTP response.
            400 => 13,                   // INTERNAL
            401 => 16,                   // UNAUTHENTICATED
            403 => 7,                    // PERMISSION_DENIED
            404 => 12,                   // UNIMPLEMENTED
            429 | 502 | 503 | 504 => 14, // UNAVAILABLE
            // Every other code (including 200 + missing grpc-status) ⇒ UNKNOWN.
            _ => 2,
        }
    }

    /// Shorthand: parse `grpc-message` from trailers, falling back to
    /// initial headers (Trailers-Only response).
    pub fn grpc_message(&self) -> Option<&str> {
        if let Some(t) = self.trailers.as_ref()
            && let Some(v) = t.get("grpc-message").and_then(|v| v.to_str().ok())
        {
            return Some(v);
        }
        if !self.initial_headers_end_stream {
            return None;
        }
        self.headers.get("grpc-message")?.to_str().ok()
    }
}

/// A simple gRPC client.
pub struct GrpcClient {
    target: String,
    transport: Transport,
}

enum Transport {
    H2c,
    Tls {
        root_pem: Option<String>,
        insecure: bool,
    },
}

impl GrpcClient {
    /// Plaintext h2c client against `target` (`host:port`).
    pub fn h2c(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            transport: Transport::H2c,
        }
    }

    /// h2-over-TLS client. `root_pem` is an optional CA PEM the client
    /// will trust; if `None`, the Mozilla/webpki root bundle (same set
    /// hyper/reqwest use by default) is loaded so the client can verify
    /// any publicly-trusted certificate out of the box. For private CAs
    /// (e.g. the `TestCa` fixture), pass the CA's PEM in `root_pem`.
    pub fn tls(target: impl Into<String>, root_pem: Option<String>) -> Self {
        Self {
            target: target.into(),
            transport: Transport::Tls {
                root_pem,
                insecure: false,
            },
        }
    }

    /// h2-over-TLS client that accepts any server cert. Use for tests
    /// pointing at self-signed backends.
    pub fn tls_insecure(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            transport: Transport::Tls {
                root_pem: None,
                insecure: true,
            },
        }
    }

    /// Send a unary RPC at `path` with `body` as the single gRPC message.
    /// `body` is raw bytes — the client adds the 5-byte gRPC frame header.
    pub async fn unary(
        &self,
        path: &str,
        body: Bytes,
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.unary_with_headers(path, body, &[]).await
    }

    /// Like [`Self::unary`] but allows passing extra request headers.
    pub async fn unary_with_headers(
        &self,
        path: &str,
        body: Bytes,
        extra_headers: &[(&str, String)],
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.request_with_headers(path, body, extra_headers, true)
            .await
    }

    /// Send the first message of a bidirectional RPC while deliberately
    /// keeping the request direction open until the response terminates.
    pub async fn bidi_with_headers(
        &self,
        path: &str,
        body: Bytes,
        extra_headers: &[(&str, String)],
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.request_with_headers(path, body, extra_headers, false)
            .await
    }

    async fn request_with_headers(
        &self,
        path: &str,
        body: Bytes,
        extra_headers: &[(&str, String)],
        end_request_stream: bool,
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        let (host, port) = parse_target(&self.target)?;
        let response = match &self.transport {
            Transport::H2c => {
                let tcp = TcpStream::connect((host.as_str(), port)).await?;
                self.send_over_io(
                    tcp,
                    &host,
                    port,
                    path,
                    body,
                    extra_headers,
                    false,
                    end_request_stream,
                )
                .await?
            }
            Transport::Tls { root_pem, insecure } => {
                let tls = tls_connect(&host, port, root_pem.as_deref(), *insecure).await?;
                self.send_over_io(
                    tls,
                    &host,
                    port,
                    path,
                    body,
                    extra_headers,
                    true,
                    end_request_stream,
                )
                .await?
            }
        };
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_over_io<T>(
        &self,
        io: T,
        host: &str,
        port: u16,
        path: &str,
        body: Bytes,
        extra_headers: &[(&str, String)],
        tls: bool,
        end_request_stream: bool,
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Observe the inbound HTTP/2 framing on the raw byte stream before h2
        // consumes it. `h2`'s per-stream recv state is NOT a durable record of
        // END_STREAM, so it cannot answer "was this response Trailers-Only?"
        // after the fact — see `InboundResponseFraming` (#3422).
        let framing = Arc::new(InboundResponseFraming::default());
        let io = FrameObservingIo::new(io, Arc::clone(&framing));

        let (mut send_req, connection) = h2_client::handshake(io).await?;
        // Abort the connection driver on every exit — including task
        // cancellation. Dropping the JoinHandle alone detaches it, so
        // `hold.abort()` would leave the client→gateway H2 session up and the
        // gateway would never observe the cancel.
        let conn_task = AbortOnDrop(tokio::spawn(connection));

        let scheme = if tls { "https" } else { "http" };
        let mut req_builder = Request::builder()
            .method("POST")
            .uri(format!("{scheme}://{host}:{port}{path}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        for (k, v) in extra_headers {
            req_builder = req_builder.header(*k, v);
        }
        let request = req_builder.body(())?;

        let (response_fut, mut req_body) = send_req.send_request(request, false)?;

        // Frame the gRPC message: 1-byte compressed flag + 4-byte BE length + body.
        let mut framed = BytesMut::with_capacity(body.len() + 5);
        framed.put_u8(0);
        framed.put_u32(body.len() as u32);
        framed.extend_from_slice(&body);
        // A fast Trailers-Only gateway error can close the request direction
        // before this DATA write is observed locally. h2 then reports an
        // `inactive stream`, but the response future can still carry the
        // well-formed gRPC error that the caller needs to assert on. Preserve
        // the write error for the no-response case and keep collecting.
        let request_send_error = req_body
            .send_data(framed.freeze(), end_request_stream)
            .err()
            .map(|e| format!("request body error: {e}"));

        let response_result = tokio::time::timeout(Duration::from_secs(20), response_fut).await;
        let response: Response<h2::RecvStream> = match response_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                // Stream-level error before headers arrived. Synthesize a
                // response so the caller can inspect it.
                let stream_error = match request_send_error.as_deref() {
                    Some(send_error) => format!("{send_error}; response error: {e}"),
                    None => format!("response error: {e}"),
                };
                return Ok(GrpcResponse {
                    http_status: 0,
                    headers: HeaderMap::new(),
                    initial_headers_end_stream: false,
                    messages: Vec::new(),
                    raw_body_frames: Vec::new(),
                    trailers: None,
                    stream_error: Some(stream_error),
                    request_send_error,
                });
            }
            Err(_) => {
                let stream_error = match request_send_error.as_deref() {
                    Some(send_error) => format!("{send_error}; response timed out"),
                    None => "response timed out".to_string(),
                };
                return Ok(GrpcResponse {
                    http_status: 0,
                    headers: HeaderMap::new(),
                    initial_headers_end_stream: false,
                    messages: Vec::new(),
                    raw_body_frames: Vec::new(),
                    trailers: None,
                    stream_error: Some(stream_error),
                    request_send_error,
                });
            }
        };

        let http_status = response.status().as_u16();
        let headers = response.headers().clone();
        // Wire truth, not h2 stream state: did the FIRST response HEADERS frame
        // carry END_STREAM (the gRPC Trailers-Only shape)? `RecvStream::
        // is_end_stream()` cannot answer this, because a later
        // RST_STREAM(NO_ERROR) rewrites the same recv state it reads and makes
        // it report `false` for a response that already completed (#3422).
        let initial_headers_end_stream = framing.initial_headers_end_stream();
        let (_parts, mut body_stream) = response.into_parts();

        // Bound body + trailer collection separately from `response_fut` so
        // a backend that sends headers and then stalls (e.g. a scripted
        // fixture that hangs mid-stream) cannot hang the test indefinitely.
        // The 20s envelope matches the `response_fut` timeout above.
        let body_trailers_fut = async {
            let mut raw_frames = Vec::new();
            let mut stream_error: Option<String> = None;
            let mut stream_error_is_remote_no_error_reset = false;
            loop {
                match body_stream.data().await {
                    Some(Ok(chunk)) => {
                        let _ = body_stream.flow_control().release_capacity(chunk.len());
                        raw_frames.push(chunk);
                    }
                    Some(Err(e)) => {
                        stream_error_is_remote_no_error_reset = is_remote_h2_no_error_reset(&e);
                        stream_error = Some(format!("body error: {e}"));
                        break;
                    }
                    None => break,
                }
            }
            let trailers = if stream_error.is_none() {
                match body_stream.trailers().await {
                    Ok(t) => t,
                    Err(e) => {
                        stream_error_is_remote_no_error_reset = is_remote_h2_no_error_reset(&e);
                        stream_error = Some(format!("trailers error: {e}"));
                        None
                    }
                }
            } else {
                None
            };
            (
                raw_frames,
                trailers,
                stream_error,
                stream_error_is_remote_no_error_reset,
            )
        };

        let (raw_frames, trailers, stream_error, stream_error_is_remote_no_error_reset) =
            match tokio::time::timeout(Duration::from_secs(20), body_trailers_fut).await {
                Ok(collected) => collected,
                Err(_) => {
                    return Ok(GrpcResponse {
                        http_status,
                        headers,
                        initial_headers_end_stream,
                        messages: Vec::new(),
                        raw_body_frames: Vec::new(),
                        trailers: None,
                        stream_error: Some("body/trailers read timed out".into()),
                        request_send_error,
                    });
                }
            };

        // RFC 9113 §8.1: after a complete early response, the server MAY send
        // RST_STREAM(NO_ERROR) to cancel an unread request body. Raw h2 surfaces
        // that as `stream error received: not a result of an error` on the recv
        // half even when Trailers-Only `grpc-status` already arrived in HEADERS.
        // Clients MUST NOT discard the response. Clear only a typed, remotely
        // received h2 reset with reason NO_ERROR when a valid explicit
        // grpc-status is already present (#2057 residual).
        let stream_error = suppress_benign_early_response_reset(
            stream_error,
            stream_error_is_remote_no_error_reset,
            &headers,
            initial_headers_end_stream,
            trailers.as_ref(),
        );

        let messages = decode_grpc_messages(&raw_frames);
        drop(conn_task);

        Ok(GrpcResponse {
            http_status,
            headers,
            initial_headers_end_stream,
            messages,
            raw_body_frames: raw_frames,
            trailers,
            stream_error,
            request_send_error,
        })
    }
}

/// Returns `None` when `stream_error` is solely the RFC 9113 early-response
/// `RST_STREAM(NO_ERROR)` signal and a valid explicit `grpc-status` is already
/// present in terminal headers or trailers. An initial `grpc-status` is
/// authoritative only when that HEADERS block also ended the stream; otherwise
/// a later reset could have truncated DATA and must remain visible.
///
/// `initial_headers_end_stream` must come from
/// [`InboundResponseFraming::initial_headers_end_stream`] — a sticky wire
/// observation — and not from `h2::RecvStream::is_end_stream()`, which the very
/// reset being classified here can flip to `false` (#3422).
fn suppress_benign_early_response_reset(
    stream_error: Option<String>,
    stream_error_is_remote_no_error_reset: bool,
    headers: &HeaderMap,
    initial_headers_end_stream: bool,
    trailers: Option<&HeaderMap>,
) -> Option<String> {
    let err = stream_error?;
    let trailers_only_status = initial_headers_end_stream
        .then(|| headers.get("grpc-status"))
        .flatten();
    let explicit_grpc_status = trailers
        .and_then(|map| map.get("grpc-status"))
        .or(trailers_only_status);
    if stream_error_is_remote_no_error_reset
        && explicit_grpc_status.is_some_and(is_valid_explicit_grpc_status)
    {
        return None;
    }
    Some(err)
}

fn is_valid_explicit_grpc_status(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes.len() == 1 || bytes[0] != b'0')
        && value
            .to_str()
            .ok()
            .and_then(|status| status.parse::<u32>().ok())
            .is_some()
}

fn is_remote_h2_no_error_reset(err: &h2::Error) -> bool {
    err.is_reset() && err.is_remote() && err.reason() == Some(h2::Reason::NO_ERROR)
}

// ────────────────────────────────────────────────────────────────────────────
// Wire-level inbound framing observation (#3422)
// ────────────────────────────────────────────────────────────────────────────
//
// `suppress_benign_early_response_reset` may only clear the RFC 9113 §8.1
// early-response `RST_STREAM(NO_ERROR)` when the response was genuinely
// terminal — for the gateway's synthesized gRPC errors that means the initial
// HEADERS block carried both END_STREAM and an explicit `grpc-status`
// (Trailers-Only). That END_STREAM fact used to be read back from
// `h2::RecvStream::is_end_stream()` AFTER the response future resolved, which
// is not a durable record of the wire event:
//
//   * `Recv::is_end_stream` is `state.is_recv_end_stream() && pending_recv
//     .is_empty()`, and `is_recv_end_stream()` matches only
//     `Closed(Cause::EndStream) | HalfClosedRemote(..)`.
//   * `State::recv_reset` overwrites ANY non-closed state — including the
//     `HalfClosedRemote` a completed response just produced — with
//     `Closed(Cause::Error(remote_reset))`, regardless of the reset's reason.
//
// So once the connection task processes the gateway's post-response
// `RST_STREAM(NO_ERROR)`, `is_end_stream()` starts reporting `false` for a
// response that arrived complete. Whether that happens before the test task
// reads it is pure scheduling luck, which is exactly the nondeterminism behind
// the recurring `backend_refuses_returns_502__grpc_to_grpc` failure
// (HTTP 200 + `body error: stream error received: not a result of an error`).
//
// The bytes, unlike h2's mutable stream state, are unambiguous. Scanning the
// inbound frame headers as they are read off the transport records END_STREAM
// once, stickily, and independently of task interleaving. It deliberately does
// NOT relax anything: a HEADERS block that did not carry END_STREAM is still
// reported as non-terminal, so truncated DATA/trailers, local resets, and
// non-`NO_ERROR` resets keep failing.

/// HTTP/2 frame header length (RFC 9113 §4.1).
const H2_FRAME_HEADER_LEN: usize = 9;
/// `HEADERS` frame type.
const H2_FRAME_TYPE_HEADERS: u8 = 0x1;
/// `END_STREAM` flag, bit 0 of the frame `flags` octet.
const H2_FLAG_END_STREAM: u8 = 0x1;

/// No response HEADERS block has been observed yet.
const FIRST_HEADERS_UNSEEN: u8 = 0;
/// The first response HEADERS block carried `END_STREAM`.
const FIRST_HEADERS_END_STREAM: u8 = 1;
/// The first response HEADERS block left the response stream open.
const FIRST_HEADERS_OPEN: u8 = 2;

/// Sticky, wire-derived record of the inbound framing this client observed.
///
/// Shared between the transport wrapper (writer) and the request path (reader),
/// so it uses an atomic rather than a lock — the client's read path is on the
/// h2 connection task while the assertions run on the test task.
#[derive(Debug, Default)]
pub(crate) struct InboundResponseFraming {
    /// One of the `FIRST_HEADERS_*` constants. Written at most once so a
    /// trailers HEADERS block can never restate the initial response's shape.
    first_headers: AtomicU8,
}

impl InboundResponseFraming {
    fn record_response_headers(&self, end_stream: bool) {
        let observed = if end_stream {
            FIRST_HEADERS_END_STREAM
        } else {
            FIRST_HEADERS_OPEN
        };
        // First writer wins: a second HEADERS block on the same stream is
        // trailers, and an interim 1xx would likewise not describe the final
        // response's terminal shape.
        let _ = self.first_headers.compare_exchange(
            FIRST_HEADERS_UNSEEN,
            observed,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    /// `true` only when a response HEADERS block was observed AND it carried
    /// `END_STREAM`. An unobserved response (never possible once the response
    /// future has resolved) reports `false`, keeping the caller strict.
    pub(crate) fn initial_headers_end_stream(&self) -> bool {
        self.first_headers.load(Ordering::Acquire) == FIRST_HEADERS_END_STREAM
    }
}

/// Incremental scanner over the server → client HTTP/2 byte stream.
///
/// The inbound direction carries no connection preface, so the stream is a bare
/// sequence of `[9-byte header][payload]`. Only frame headers are inspected;
/// payloads (including HPACK blocks and any `CONTINUATION`) are skipped, which
/// is sufficient because `END_STREAM` lives in the HEADERS frame's own flags.
/// State is carried across `poll_read` calls so a frame header split across
/// reads is still parsed exactly once.
#[derive(Debug, Default)]
struct H2FrameScanner {
    /// Payload octets of the current frame still to be skipped.
    payload_remaining: usize,
    /// Partially received frame header.
    header: [u8; H2_FRAME_HEADER_LEN],
    /// Octets of `header` filled so far.
    header_len: usize,
}

impl H2FrameScanner {
    fn observe(&mut self, mut bytes: &[u8], framing: &InboundResponseFraming) {
        while !bytes.is_empty() {
            if self.payload_remaining > 0 {
                let skip = self.payload_remaining.min(bytes.len());
                self.payload_remaining -= skip;
                bytes = &bytes[skip..];
                continue;
            }
            let take = (H2_FRAME_HEADER_LEN - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&bytes[..take]);
            self.header_len += take;
            bytes = &bytes[take..];
            if self.header_len < H2_FRAME_HEADER_LEN {
                return;
            }
            let [
                len_hi,
                len_mid,
                len_lo,
                frame_type,
                flags,
                id0,
                id1,
                id2,
                id3,
            ] = self.header;
            let payload_len = u32::from_be_bytes([0, len_hi, len_mid, len_lo]) as usize;
            let stream_id = u32::from_be_bytes([id0, id1, id2, id3]) & 0x7fff_ffff;
            self.header_len = 0;
            self.payload_remaining = payload_len;
            // Stream 0 is connection control (SETTINGS/PING/GOAWAY/WINDOW_UPDATE)
            // and never carries a response.
            if frame_type == H2_FRAME_TYPE_HEADERS && stream_id != 0 {
                framing.record_response_headers(flags & H2_FLAG_END_STREAM != 0);
            }
        }
    }
}

/// Transport wrapper that records inbound HTTP/2 framing while passing bytes
/// through untouched. Wraps whatever IO the request path uses, so it sees
/// plaintext h2c frames and post-decryption h2-over-TLS frames alike.
pub(crate) struct FrameObservingIo<T> {
    io: T,
    framing: Arc<InboundResponseFraming>,
    scanner: H2FrameScanner,
}

impl<T> FrameObservingIo<T> {
    pub(crate) fn new(io: T, framing: Arc<InboundResponseFraming>) -> Self {
        Self {
            io,
            framing,
            scanner: H2FrameScanner::default(),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FrameObservingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let already_filled = buf.filled().len();
        let this = &mut *self;
        let poll = Pin::new(&mut this.io).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > already_filled {
            let fresh = &buf.filled()[already_filled..];
            this.scanner.observe(fresh, &this.framing);
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FrameObservingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Decode the length-prefixed gRPC messages out of a concatenation of DATA
/// frames. A single message may span multiple DATA frames, so we concat
/// first and then walk the 5-byte headers.
fn decode_grpc_messages(frames: &[Bytes]) -> Vec<Bytes> {
    let mut joined = BytesMut::new();
    for f in frames {
        joined.extend_from_slice(f);
    }
    let buf = joined.freeze();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= buf.len() {
        // 1-byte flag, 4-byte BE length. We don't bother with compression
        // semantics; just validate the length fits.
        let len = u32::from_be_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]) as usize;
        if i + 5 + len > buf.len() {
            break;
        }
        out.push(buf.slice(i + 5..i + 5 + len));
        i += 5 + len;
    }
    out
}

/// Abort an h2 connection driver when the request future is dropped, including
/// `JoinHandle::abort()` of the caller task. Detaching the driver would leave
/// the TCP session up so the gateway never saw the cancel.
struct AbortOnDrop(JoinHandle<Result<(), h2::Error>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn parse_target(t: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let (host, port) = t
        .rsplit_once(':')
        .ok_or_else(|| format!("bad target {t:?}: expected host:port"))?;
    let port = port.parse::<u16>()?;
    Ok((host.to_string(), port))
}

/// Build the verified-TLS `RootCertStore` for [`GrpcClient::tls`].
///
/// * `Some(pem)` → load every certificate from the supplied PEM bundle
///   and trust only those (no webpki fallback — the caller is being
///   explicit about which roots to trust).
/// * `None` → load the Mozilla/webpki root bundle so a verified
///   handshake against a publicly-trusted certificate succeeds out of
///   the box. Without this, the `RootCertStore` would stay empty and
///   every verified handshake would fail with `UnknownIssuer` — the
///   cause flagged in the PR-486 review.
///
/// Extracted from `tls_connect` so the `None` path can be unit-tested
/// without a public-network handshake (the previous regression test
/// reached `tls.cloudflare.com:443`, which is non-hermetic in
/// restricted CI environments).
fn build_root_cert_store(
    root_pem: Option<&str>,
) -> Result<rustls::RootCertStore, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::RootCertStore;
    use rustls_pemfile::certs;

    let mut root = RootCertStore::empty();
    if let Some(pem) = root_pem {
        let mut reader = pem.as_bytes();
        for cert in certs(&mut reader).filter_map(|c| c.ok()) {
            root.add(cert)?;
        }
    } else {
        root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(root)
}

async fn tls_connect(
    host: &str,
    port: u16,
    root_pem: Option<&str>,
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?;
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
            .with_no_client_auth()
    } else {
        let root = build_root_cert_store(root_pem)?;
        builder.with_root_certificates(root).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, port)).await?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let stream = connector.connect(name, tcp).await?;
    Ok(stream)
}

/// Dangerous cert verifier: accepts every server cert. Used only when
/// `tls_insecure()` is requested.
#[derive(Debug)]
struct AcceptAnyVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        let (h, p) = parse_target("127.0.0.1:8080").expect("parse");
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8080);
    }

    #[test]
    fn decode_grpc_messages_single_frame() {
        // 1-byte flag + 4-byte len + "hi"
        let frame = Bytes::from_static(b"\x00\x00\x00\x00\x02hi");
        let msgs = decode_grpc_messages(&[frame]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], b"hi");
    }

    #[test]
    fn decode_grpc_messages_split_across_frames() {
        let a = Bytes::from_static(b"\x00\x00\x00\x00\x03ab");
        let b = Bytes::from_static(b"c");
        let msgs = decode_grpc_messages(&[a, b]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], b"abc");
    }

    fn response(
        http_status: u16,
        grpc_status_header: Option<&str>,
        grpc_status_trailer: Option<&str>,
    ) -> GrpcResponse {
        let mut headers = HeaderMap::new();
        if let Some(v) = grpc_status_header {
            headers.insert("grpc-status", v.parse().unwrap());
        }
        let trailers = grpc_status_trailer.map(|v| {
            let mut t = HeaderMap::new();
            t.insert("grpc-status", v.parse().unwrap());
            t
        });
        GrpcResponse {
            http_status,
            headers,
            initial_headers_end_stream: grpc_status_header.is_some()
                && grpc_status_trailer.is_none(),
            messages: Vec::new(),
            raw_body_frames: Vec::new(),
            trailers,
            stream_error: None,
            request_send_error: None,
        }
    }

    #[test]
    fn initial_grpc_status_requires_wire_end_stream() {
        let mut malformed = response(200, Some("5"), None);
        malformed.initial_headers_end_stream = false;
        malformed
            .headers
            .insert("grpc-message", "missing".parse().unwrap());
        assert_eq!(malformed.grpc_status(), None);
        assert_eq!(malformed.grpc_message(), None);
        assert_eq!(malformed.effective_grpc_status(), 2);
        malformed.initial_headers_end_stream = true;
        assert_eq!(malformed.grpc_status(), Some(5));
        assert_eq!(malformed.grpc_message(), Some("missing"));
        assert_eq!(malformed.effective_grpc_status(), 5);

        let mut real_trailers = response(200, Some("5"), Some("7"));
        real_trailers.initial_headers_end_stream = false;
        assert_eq!(real_trailers.grpc_status(), Some(7));
    }

    #[test]
    fn suppress_no_error_reset_when_trailers_only_status_present() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "14".parse().unwrap());
        let cleared = suppress_benign_early_response_reset(
            Some("body error: stream error received: not a result of an error".into()),
            true,
            &headers,
            true,
            None,
        );
        assert!(
            cleared.is_none(),
            "RFC 9113 early-response NO_ERROR must not override Trailers-Only grpc-status"
        );
    }

    #[test]
    fn preserve_non_no_error_stream_failures_even_with_grpc_status() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "14".parse().unwrap());
        let kept = suppress_benign_early_response_reset(
            Some("body error: unrelated failure mentioning not a result of an error".into()),
            false,
            &headers,
            true,
            None,
        );
        assert_eq!(
            kept.as_deref(),
            Some("body error: unrelated failure mentioning not a result of an error"),
            "diagnostic text must never substitute for the typed h2 reset reason"
        );
    }

    #[test]
    fn preserve_no_error_reset_without_explicit_grpc_status() {
        let headers = HeaderMap::new();
        let kept = suppress_benign_early_response_reset(
            Some("body error: stream error received: not a result of an error".into()),
            true,
            &headers,
            true,
            None,
        );
        assert!(
            kept.is_some(),
            "NO_ERROR without grpc-status is not a well-formed gateway error"
        );
    }

    #[test]
    fn preserve_no_error_reset_with_malformed_grpc_status() {
        for malformed in ["invalid", "+14", "014"] {
            let mut headers = HeaderMap::new();
            headers.insert("grpc-status", malformed.parse().unwrap());
            let kept = suppress_benign_early_response_reset(
                Some("body error: stream error received: not a result of an error".into()),
                true,
                &headers,
                true,
                None,
            );
            assert!(
                kept.is_some(),
                "malformed grpc-status {malformed:?} must not make an incomplete response valid"
            );
        }
    }

    #[test]
    fn suppress_no_error_reset_with_unknown_numeric_grpc_status() {
        // The gRPC wire grammar accepts any decimal integer without leading
        // zeros. Codes outside the defined 0..=16 set map to UNKNOWN at the
        // client API, but still form an explicit terminal status.
        for unknown in ["17", "999"] {
            let mut headers = HeaderMap::new();
            headers.insert("grpc-status", unknown.parse().unwrap());
            let cleared = suppress_benign_early_response_reset(
                Some("body error: stream error received: not a result of an error".into()),
                true,
                &headers,
                true,
                None,
            );
            assert!(
                cleared.is_none(),
                "numeric grpc-status {unknown:?} must retain the terminal response"
            );
        }
    }

    #[test]
    fn preserve_no_error_reset_when_initial_grpc_status_did_not_end_stream() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "14".parse().unwrap());
        let kept = suppress_benign_early_response_reset(
            Some("body error: stream error received: not a result of an error".into()),
            true,
            &headers,
            false,
            None,
        );
        assert!(
            kept.is_some(),
            "non-terminal initial grpc-status must not mask truncated DATA"
        );
    }

    /// Serialize one HTTP/2 frame (header + opaque payload) for the scanner.
    fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        assert!(len <= 0xff_ffff, "test frame payload too large");
        let mut out = Vec::with_capacity(H2_FRAME_HEADER_LEN + len);
        out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        out.push(frame_type);
        out.push(flags);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    const H2_FRAME_TYPE_DATA: u8 = 0x0;
    const H2_FRAME_TYPE_SETTINGS: u8 = 0x4;
    const H2_FRAME_TYPE_RST_STREAM: u8 = 0x3;
    const H2_FLAG_END_HEADERS: u8 = 0x4;

    /// The exact recurring `backend_refuses_returns_502__grpc_to_grpc` wire
    /// sequence (#3422): SETTINGS, a Trailers-Only HEADERS block carrying
    /// `grpc-status`, then the RFC 9113 §8.1 `RST_STREAM(NO_ERROR)` that cancels
    /// the client's unread upload. The observed END_STREAM must stay recorded
    /// after the reset — that stickiness is what h2's own recv state lacks.
    #[test]
    fn backend_refusal_trailers_only_signature_survives_late_no_error_reset() {
        let framing = InboundResponseFraming::default();
        let mut scanner = H2FrameScanner::default();

        let trailers_only = h2_frame(
            H2_FRAME_TYPE_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            b"hpack-block",
        );
        let mut wire = h2_frame(H2_FRAME_TYPE_SETTINGS, 0, 0, &[]);
        wire.extend_from_slice(&trailers_only);
        scanner.observe(&wire, &framing);
        assert!(
            framing.initial_headers_end_stream(),
            "Trailers-Only HEADERS must be recorded as terminal"
        );

        // The gateway's post-response reset arrives; the record must not move.
        let reset = h2_frame(H2_FRAME_TYPE_RST_STREAM, 0, 1, &[0; 4]);
        scanner.observe(&reset, &framing);
        assert!(
            framing.initial_headers_end_stream(),
            "a late RST_STREAM(NO_ERROR) must not erase the observed END_STREAM"
        );

        // Full decision chain: this is the signature that must now pass.
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "14".parse().unwrap());
        let cleared = suppress_benign_early_response_reset(
            Some("body error: stream error received: not a result of an error".into()),
            true,
            &headers,
            framing.initial_headers_end_stream(),
            None,
        );
        assert!(
            cleared.is_none(),
            "complete Trailers-Only UNAVAILABLE + NO_ERROR reset must be well-formed"
        );
    }

    /// Negative control: HEADERS that left the stream open is still reported
    /// non-terminal, so a reset that may have truncated DATA keeps failing even
    /// though `grpc-status` was present in the initial headers.
    #[test]
    fn open_initial_headers_are_not_recorded_as_terminal() {
        let framing = InboundResponseFraming::default();
        let mut scanner = H2FrameScanner::default();
        let open_headers = h2_frame(H2_FRAME_TYPE_HEADERS, H2_FLAG_END_HEADERS, 1, b"hpack");
        scanner.observe(&open_headers, &framing);
        assert!(
            !framing.initial_headers_end_stream(),
            "HEADERS without END_STREAM must never be reported as Trailers-Only"
        );

        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "14".parse().unwrap());
        let kept = suppress_benign_early_response_reset(
            Some("body error: stream error received: not a result of an error".into()),
            true,
            &headers,
            framing.initial_headers_end_stream(),
            None,
        );
        assert!(
            kept.is_some(),
            "non-terminal initial HEADERS must keep the reset visible"
        );
    }

    /// Negative control: a terminal trailers HEADERS block after DATA must not
    /// retroactively relabel the initial response as Trailers-Only.
    #[test]
    fn trailers_headers_block_does_not_overwrite_initial_headers_record() {
        let framing = InboundResponseFraming::default();
        let mut scanner = H2FrameScanner::default();
        let data = h2_frame(H2_FRAME_TYPE_DATA, 0, 1, &[0; 5]);
        let trailers = h2_frame(
            H2_FRAME_TYPE_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            b"trailers",
        );
        let mut wire = h2_frame(H2_FRAME_TYPE_HEADERS, H2_FLAG_END_HEADERS, 1, b"hpack");
        wire.extend_from_slice(&data);
        wire.extend_from_slice(&trailers);
        scanner.observe(&wire, &framing);
        assert!(
            !framing.initial_headers_end_stream(),
            "only the FIRST HEADERS block describes the initial response shape"
        );
    }

    /// A frame header may be split across `poll_read` boundaries; the scanner
    /// must still classify it exactly once. Byte-by-byte feeding is the
    /// worst case.
    #[test]
    fn scanner_parses_frame_headers_split_across_reads() {
        let terminal_headers = h2_frame(
            H2_FRAME_TYPE_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            b"hpack-block-spanning-reads",
        );
        let mut wire = h2_frame(H2_FRAME_TYPE_SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]);
        wire.extend_from_slice(&terminal_headers);

        let framing = InboundResponseFraming::default();
        let mut scanner = H2FrameScanner::default();
        for byte in &wire {
            scanner.observe(std::slice::from_ref(byte), &framing);
        }
        assert!(
            framing.initial_headers_end_stream(),
            "split frame headers must not lose the END_STREAM observation"
        );
    }

    /// Stream 0 carries connection control only. A malformed control frame with
    /// the END_STREAM bit set must never be mistaken for a response.
    #[test]
    fn connection_control_frames_never_record_response_headers() {
        let framing = InboundResponseFraming::default();
        let mut scanner = H2FrameScanner::default();
        let control = h2_frame(H2_FRAME_TYPE_HEADERS, H2_FLAG_END_STREAM, 0, b"bogus");
        scanner.observe(&control, &framing);
        assert!(
            !framing.initial_headers_end_stream(),
            "stream 0 never carries a response HEADERS block"
        );
    }

    /// No response observed at all (transport failure before HEADERS) must
    /// report non-terminal, so `suppress_benign_early_response_reset` stays
    /// strict on the failed-before-headers path.
    #[test]
    fn unobserved_response_headers_report_non_terminal() {
        let framing = InboundResponseFraming::default();
        assert!(!framing.initial_headers_end_stream());
    }

    #[test]
    fn generic_no_error_reason_is_not_a_remote_stream_reset() {
        let error = h2::Error::from(h2::Reason::NO_ERROR);
        assert!(!is_remote_h2_no_error_reset(&error));
    }

    #[test]
    fn effective_grpc_status_returns_trailer_value_verbatim_when_present() {
        assert_eq!(
            response(200, None, Some("7")).effective_grpc_status(),
            7,
            "explicit grpc-status trailer must win over fallback"
        );
    }

    #[test]
    fn effective_grpc_status_reads_trailers_only_header_before_fallback() {
        assert_eq!(
            response(200, Some("4"), None).effective_grpc_status(),
            4,
            "Trailers-Only grpc-status in initial headers must win"
        );
    }

    #[test]
    fn effective_grpc_status_fills_unknown_for_http_200_missing_trailers() {
        // Per the HTTP-to-gRPC mapping doc's "every other code ⇒ UNKNOWN"
        // default. Rust/Go clients diverge here (tonic/some-grpc-go use
        // INTERNAL), so we follow the spec-canonical rule.
        assert_eq!(
            response(200, None, None).effective_grpc_status(),
            2,
            "http 200 + no grpc-status ⇒ UNKNOWN per mapping doc"
        );
    }

    #[test]
    fn effective_grpc_status_maps_http_fallback_status_codes() {
        // 400 → INTERNAL, 401 → UNAUTHENTICATED, 403 → PERMISSION_DENIED,
        // 404 → UNIMPLEMENTED, 429/502/503/504 → UNAVAILABLE, other → UNKNOWN.
        // Regression guard: the earlier blanket "missing ⇒ 13" collapsed all
        // of these to 13 and would have masked wrongly-classified outcomes.
        assert_eq!(response(400, None, None).effective_grpc_status(), 13);
        assert_eq!(response(401, None, None).effective_grpc_status(), 16);
        assert_eq!(response(403, None, None).effective_grpc_status(), 7);
        assert_eq!(response(404, None, None).effective_grpc_status(), 12);
        assert_eq!(response(429, None, None).effective_grpc_status(), 14);
        assert_eq!(response(502, None, None).effective_grpc_status(), 14);
        assert_eq!(response(503, None, None).effective_grpc_status(), 14);
        assert_eq!(response(504, None, None).effective_grpc_status(), 14);
        assert_eq!(response(418, None, None).effective_grpc_status(), 2);
    }

    #[test]
    fn effective_grpc_status_reports_unavailable_for_transport_level_failure() {
        // http_status == 0 is the client's synthesized "no response" shape
        // (response_fut errored or timed out); a real gRPC stack would
        // surface that as UNAVAILABLE, not INTERNAL.
        assert_eq!(response(0, None, None).effective_grpc_status(), 14);
    }

    #[test]
    fn build_root_cert_store_with_none_loads_webpki_bundle() {
        // Regression guard for the PR-486 review's "docs say webpki
        // fallback, code returns empty store" finding. The minimal
        // observable property is that `None` produces a store
        // populated from `webpki_roots::TLS_SERVER_ROOTS`. A purely
        // local check — no DNS, no public network, no certificate
        // intermediation. Replaces the earlier `tls.cloudflare.com:443`
        // smoke test (P3 review feedback: hermetic tests preferred).
        let store = build_root_cert_store(None).expect("build store with webpki fallback");
        assert_eq!(
            store.roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "None must load the full webpki bundle (currently {} roots); \
             the empty-store regression would set this to 0",
            webpki_roots::TLS_SERVER_ROOTS.len()
        );
        // Sanity: webpki ships well over 100 trust anchors. A single
        // digit count would indicate a different, equally-broken
        // regression (partial fill, malformed iteration).
        assert!(
            store.roots.len() >= 100,
            "webpki bundle suspiciously small ({} roots)",
            store.roots.len()
        );
    }

    #[test]
    fn build_root_cert_store_with_pem_loads_only_supplied_certs() {
        // Complementary check: an explicit PEM bundle must NOT mix in
        // the webpki bundle. `Some(...)` is the operator-explicit path
        // and must trust *only* the supplied roots — that's the
        // contract documented on `GrpcClient::tls`.
        let ca = crate::scaffolding::certs::TestCa::new("grpc-client-test")
            .expect("build TestCa fixture");
        let store = build_root_cert_store(Some(&ca.cert_pem)).expect("build store from PEM");
        assert_eq!(
            store.roots.len(),
            1,
            "Some(pem) must trust *only* the supplied root, not mix in webpki"
        );
    }
}
