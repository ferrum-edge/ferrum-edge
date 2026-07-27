//! HTTP/3 client connection pool for proxying to HTTP/3 backends.
//!
//! Uses `connections_per_backend` QUIC connections per target to distribute
//! frame processing across driver tasks (prevents CPU bottleneck on a single
//! QUIC connection). The pool key includes a connection index for sharding.
//!
//! TLS config is constructed lazily via closure to avoid cloning root cert
//! stores on every request. On connection failure, a fallback scan checks
//! other cached connection indices before creating a new connection.
//!
//! This pool is used by both the main hyper-based proxy path (`proxy/mod.rs`)
//! for H3 backend targets and the H3 frontend server (`http3/server.rs`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Buf;
use futures_util::StreamExt as _;
use http::Request;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::debug;

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::pool::{GenericPool, PoolManager};
use crate::proxy::headers::{
    is_backend_request_strip_header, is_backend_response_strip_header,
    parse_connection_listed_headers,
};
use crate::tls::backend::{
    BackendSvidGeneration, SvidGenerationMatcher, append_backend_tls_pool_key_fields,
    append_optional_pool_key_component, append_pool_key_component,
    backend_svid_generation_for_client_cert,
};

/// Classify an HTTP/3 backend error into the shared `ErrorClass` taxonomy.
///
/// Walks the error source chain looking for recognizable `quinn::ConnectionError`
/// variants, and falls back to string heuristics for `h3::Error` wrappers and
/// anyhow chains. Without this, H3-specific errors previously landed in the
/// transaction log with no `error_class` because `classify_boxed_error` only
/// knew about reqwest/hyper patterns.
pub fn classify_http3_error(err: &(dyn std::error::Error + 'static)) -> crate::retry::ErrorClass {
    use crate::retry::ErrorClass;

    // Coalesced GenericPool create waiters receive `anyhow` wrapping
    // `SharedPoolCreateError`. Prefer the captured ErrorClass before the
    // quinn/io/substring walk so fan-out preserves creator classification.
    let mut shared_walk: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = shared_walk {
        if let Some(shared) = node.downcast_ref::<crate::pool::SharedPoolCreateError>() {
            return shared.error_class();
        }
        shared_walk = node.source();
    }

    // A DnsCacheResolver egress-policy denial (a hostname that resolves — or
    // rebinds — to a blocked IP) surfaces here as a resolve error carrying
    // "...denied by backend egress policy...". Classify it as the non-retryable,
    // backend-health-neutral DispatchPolicyRejected before the typed/DNS walk
    // below maps it to DnsLookupError (which would be retried and charged to
    // backend health even though no backend was dialed).
    if format!("{err:?}").contains("egress policy") {
        return ErrorClass::DispatchPolicyRejected;
    }

    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = current {
        if let Some(ce) = node.downcast_ref::<quinn::ConnectionError>() {
            return match ce {
                quinn::ConnectionError::TimedOut => ErrorClass::ConnectionTimeout,
                quinn::ConnectionError::Reset => ErrorClass::ConnectionReset,
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed => ErrorClass::ConnectionClosed,
                quinn::ConnectionError::VersionMismatch
                | quinn::ConnectionError::TransportError(_) => ErrorClass::ProtocolError,
                quinn::ConnectionError::CidsExhausted => ErrorClass::ConnectionPoolError,
            };
        }
        if let Some(ce) = node.downcast_ref::<quinn::ConnectError>() {
            return match ce {
                quinn::ConnectError::EndpointStopping
                | quinn::ConnectError::CidsExhausted
                | quinn::ConnectError::NoDefaultClientConfig => ErrorClass::ConnectionPoolError,
                quinn::ConnectError::UnsupportedVersion => ErrorClass::ProtocolError,
                quinn::ConnectError::InvalidRemoteAddress(_)
                | quinn::ConnectError::InvalidServerName(_) => ErrorClass::DnsLookupError,
            };
        }
        if let Some(io) = node.downcast_ref::<std::io::Error>() {
            if matches!(io.raw_os_error(), Some(99) | Some(49) | Some(10049)) {
                return ErrorClass::PortExhaustion;
            }
            match io.kind() {
                std::io::ErrorKind::TimedOut => return ErrorClass::ConnectionTimeout,
                std::io::ErrorKind::ConnectionRefused => return ErrorClass::ConnectionRefused,
                std::io::ErrorKind::ConnectionReset => return ErrorClass::ConnectionReset,
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted => {
                    return ErrorClass::ConnectionClosed;
                }
                // Generic kinds (Other, etc.) commonly wrap QUIC/H3 typed
                // errors — keep walking the source chain so typed variants
                // and string heuristics can still classify them.
                _ => {}
            }
        }
        current = node.source();
    }

    // Fallback string heuristics for h3::Error and anyhow-wrapped errors that
    // don't expose a typed chain.
    let msg = err.to_string().to_ascii_lowercase();
    if crate::retry::is_port_exhaustion_message(&msg) {
        ErrorClass::PortExhaustion
    } else if msg.contains("dns") || msg.contains("resolve") {
        ErrorClass::DnsLookupError
    } else if msg.contains("tls") || msg.contains("certificate") || msg.contains("handshake") {
        ErrorClass::TlsError
    } else if msg.contains("timed out") || msg.contains("timeout") {
        if msg.contains("connect") {
            ErrorClass::ConnectionTimeout
        } else {
            ErrorClass::ReadWriteTimeout
        }
    } else if msg.contains("refused") {
        ErrorClass::ConnectionRefused
    // IMPORTANT: H3/QUIC stream-protocol markers must be checked BEFORE the
    // generic "reset" / "closed" substrings below. `RESET_STREAM` (an H3
    // frame that aborts a single stream, not the whole connection) contains
    // "reset", and `stream_closed` contains "closed" — classifying these as
    // `ConnectionReset` / `ConnectionClosed` would hide the fact that they
    // are protocol-level stream errors. Also do NOT use the bare substring
    // "stream" here — it would match "upstream" (as in "upstream target",
    // "upstream id") and mislabel load-balancer / backend-selection failures
    // as protocol errors. Keep the matches anchored to tokens h3/quinn
    // actually emit.
    } else if msg.contains("goaway")
        || msg.contains("protocol")
        || msg.contains("reset_stream")
        || msg.contains("stream reset")
        || msg.contains("stream id")
        || msg.contains("stream_id")
        || msg.contains("stream_closed")
        || msg.contains("stream closed")
        // h3 0.0.8 emits typed `LocalError::Application { code: H3_*, ... }`
        // variants on protocol violations (e.g. stream finished without
        // response headers after a GOAWAY) that render with an `H3_` prefix
        // in the message. Treat any `h3_` token as a protocol error so the
        // downgrade path fires for the full family of H3 protocol faults
        // (H3_FRAME_UNEXPECTED, H3_FRAME_ERROR, H3_GENERAL_PROTOCOL_ERROR,
        // etc.). `h3::` is kept for typed errors that render with the
        // fully-qualified Rust path.
        || msg.contains("stream finished")
        || msg.contains("h3::")
        || msg.contains("h3_")
        || msg.contains("quic")
    {
        ErrorClass::ProtocolError
    } else if msg.contains("reset") {
        ErrorClass::ConnectionReset
    } else if msg.contains("broken pipe")
        || msg.contains("closed")
        // h3 0.0.8 renders `ConnectionErrorIncoming::ApplicationClose` as
        // `"ApplicationClose"` (no trailing 'd') — doesn't match the
        // `"closed"` substring above, leaving these as RequestError and
        // bypassing the H3 capability-registry downgrade. The typed chain
        // doesn't help either: h3's error types don't implement `source()`
        // so we never reach the quinn::ConnectionError downcast. Match
        // the h3 spelling explicitly.
        || msg.contains("applicationclose")
    {
        ErrorClass::ConnectionClosed
    } else {
        ErrorClass::RequestError
    }
}

/// Cap on Content-Length-driven `Vec` pre-allocation for buffered H3 response
/// bodies. Bounds the worst case when a malicious or misconfigured backend
/// sends a huge `content-length` header — the actual body can still grow past
/// this via `extend_from_slice`, but the initial reservation is capped.
pub(crate) const H3_BODY_PREALLOC_CAP_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(crate) enum H3BodyDrainError {
    Stream(h3::error::StreamError),
    ResponseTooLarge {
        limit: usize,
    },
    ReadTimeout {
        timeout_ms: u64,
    },
    /// The backend FIN'd the DATA stream before delivering its declared
    /// Content-Length (truncation) — a framing violation surfaced as a backend
    /// failure rather than a short-but-successful body.
    Truncated {
        received: u64,
        declared: Option<u64>,
    },
}

impl std::fmt::Display for H3BodyDrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(err) => write!(f, "{err}"),
            Self::ResponseTooLarge { limit } => {
                write!(
                    f,
                    "Backend response body exceeds maximum size of {limit} bytes"
                )
            }
            Self::ReadTimeout { timeout_ms } => {
                write!(f, "Backend response read timeout after {timeout_ms}ms")
            }
            Self::Truncated { received, declared } => match declared {
                Some(d) => write!(
                    f,
                    "Backend FIN after {received} of {d} declared Content-Length bytes"
                ),
                None => write!(
                    f,
                    "Backend FIN after {received} of unknown declared Content-Length bytes"
                ),
            },
        }
    }
}

impl std::error::Error for H3BodyDrainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(err) => Some(err),
            Self::ResponseTooLarge { .. } | Self::ReadTimeout { .. } | Self::Truncated { .. } => {
                None
            }
        }
    }
}

impl From<h3::error::StreamError> for H3BodyDrainError {
    fn from(err: h3::error::StreamError) -> Self {
        Self::Stream(err)
    }
}

/// A fully buffered HTTP/3 backend response returned by the pool's buffered
/// request APIs ([`Http3ConnectionPool::request`] /
/// [`Http3ConnectionPool::request_with_target`]).
///
/// `headers` carries the response headers (hop-by-hop names already stripped
/// during collection). `trailers` carries any backend response trailers read
/// after the body (issue #1630), still unsanitized — the buffered native-H3
/// server send path either drops them when response plugins are active (plugins
/// cannot inspect trailers today) or strips response-direction hop-by-hop
/// trailer names before forwarding them to the client. `trailers` is `None`
/// when the backend sent none, the trailer read timed out, or it ended with a
/// graceful close.
#[derive(Debug)]
pub struct H3BufferedResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
    pub trailers: Option<http::HeaderMap>,
}

/// Drain an H3 response stream into a `Vec<u8>`, tolerating a post-body
/// graceful close signal. Two variants are recovered:
///
/// - `CONNECTION_CLOSE(H3_NO_ERROR)` — matched by `is_h3_no_error()`. The
///   common case: backend finishes the response and tears down the connection.
/// - `GOAWAY` — surfaces as `StreamError::RemoteClosing`. Per RFC 9114 §5.2,
///   GOAWAY is graceful and in-progress streams should complete. If FIN+GOAWAY
///   coalesce, recv_data returns `RemoteClosing` instead of `Ok(None)`.
///
/// Note: `StreamError::RemoteTerminate { code: H3_NO_ERROR }` (stream-level
/// reset) is NOT recovered — a stream reset means the server aborted this
/// particular stream, whereas the connection-level signals above don't
/// invalidate already-sent data.
///
/// Trailers (issue #1630): after the DATA-frame drain completes (FIN or a
/// recoverable graceful close), this helper reads backend response trailers
/// via `recv_trailers()`, bounded by the same `backend_read_timeout_ms`
/// deadline used for `recv_data`. The trailers are returned (unsanitized) as
/// the second tuple element so the buffered native-H3 server path can strip
/// response-direction hop-by-hop names and forward them to the client before
/// FIN — matching the streaming-path
/// `finish_h3_response_with_backend_trailers` in `http3/server.rs`. A trailer
/// read timeout, a graceful close at the trailer phase, or simply no trailers
/// yields `None` (not an error), mirroring the body-phase graceful-close
/// handling: trailers are optional and their absence must not fail a complete
/// response.
pub(crate) async fn drain_h3_response_body(
    stream: &mut H3RequestStream,
    method: &str,
    status: u16,
    content_length: Option<u64>,
    max_response_body_size_bytes: usize,
    backend_read_timeout_ms: u64,
) -> Result<(Vec<u8>, Option<http::HeaderMap>), H3BodyDrainError> {
    if max_response_body_size_bytes > 0
        && content_length.is_some_and(|len| len > max_response_body_size_bytes as u64)
    {
        return Err(H3BodyDrainError::ResponseTooLarge {
            limit: max_response_body_size_bytes,
        });
    }

    let mut body = match content_length {
        Some(cl) => Vec::with_capacity(cl.min(H3_BODY_PREALLOC_CAP_BYTES) as usize),
        None => Vec::new(),
    };
    loop {
        let recv_result = if backend_read_timeout_ms > 0 {
            match tokio::time::timeout(
                Duration::from_millis(backend_read_timeout_ms),
                stream.recv_data(),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    return Err(H3BodyDrainError::ReadTimeout {
                        timeout_ms: backend_read_timeout_ms,
                    });
                }
            }
        } else {
            stream.recv_data().await
        };
        match recv_result {
            Ok(Some(chunk)) => {
                let chunk = chunk.chunk();
                if max_response_body_size_bytes > 0
                    && body.len().saturating_add(chunk.len()) > max_response_body_size_bytes
                {
                    return Err(H3BodyDrainError::ResponseTooLarge {
                        limit: max_response_body_size_bytes,
                    });
                }
                body.extend_from_slice(chunk);
            }
            Ok(None) => {
                // Clean FIN. A declared Content-Length that the body did NOT
                // satisfy (truncation / overlong) is a framing violation: surface
                // it as a backend failure rather than returning a short body as a
                // success, mirroring the streaming `H3FrameSource` FIN check. An
                // absent Content-Length is FIN-delimited and complete here.
                if !is_response_body_complete_after_fin(
                    body.len() as u64,
                    method,
                    status,
                    content_length,
                ) {
                    return Err(H3BodyDrainError::Truncated {
                        received: body.len() as u64,
                        declared: content_length,
                    });
                }
                break;
            }
            Err(e) => {
                if is_h3_graceful_close(&e)
                    && is_response_body_complete(body.len() as u64, method, status, content_length)
                {
                    debug!(
                        bytes_received = body.len(),
                        "H3 recv_data hit graceful close after complete body; treating as success"
                    );
                    break;
                }
                return Err(e.into());
            }
        }
    }

    // Body fully drained (FIN or a recoverable graceful close). Read any
    // backend trailers so the buffered native-H3 server path can forward them
    // — the streaming path already does this via
    // `finish_h3_response_with_backend_trailers`. Bound by the same
    // `backend_read_timeout_ms` deadline as `recv_data`.
    //
    // Trailer absence is benign and yields `None` (not an error): a read
    // timeout (collapsed to `Ok(None)` inside the helper), a graceful close at
    // the trailer phase (`is_h3_graceful_close`), or simply no trailers must
    // NOT fail an otherwise-complete response. A genuine non-graceful
    // `recv_trailers()` error (malformed/oversized trailers, an invalid
    // post-body frame), however, is a real backend protocol violation and
    // propagates as `H3BodyDrainError::Stream` — the buffered path then
    // surfaces it as a backend failure (mapped to `H3PoolError::post_wire`,
    // driving CB / passive-health accounting), mirroring the streaming path's
    // `H3TrailerFinishError::Backend(...)` classification. Swallowing it to
    // `None` would hide the violation and keep an unhealthy H3 backend in
    // rotation.
    let trailers = match read_h3_trailers_with_timeout(stream, backend_read_timeout_ms).await {
        Ok(trailers) => trailers,
        Err(e) if is_h3_graceful_close(&e) => None,
        Err(e) => {
            debug!(
                error = %e,
                "H3 recv_trailers failed non-gracefully after complete body; propagating as backend failure"
            );
            return Err(e.into());
        }
    };
    Ok((body, trailers))
}

/// Read backend response trailers, bounded by `backend_read_timeout_ms`.
///
/// A timeout collapses into `Ok(None)` (treated identically to "no trailers")
/// rather than a `StreamError`, so the buffered drain path can forward an
/// otherwise-complete response without trailers instead of failing it.
async fn read_h3_trailers_with_timeout(
    stream: &mut H3RequestStream,
    backend_read_timeout_ms: u64,
) -> Result<Option<http::HeaderMap>, h3::error::StreamError> {
    if backend_read_timeout_ms > 0 {
        match tokio::time::timeout(
            Duration::from_millis(backend_read_timeout_ms),
            stream.recv_trailers(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                if let Some(trailers) = stream.peek_recv_trailers()? {
                    debug!(
                        timeout_ms = backend_read_timeout_ms,
                        "H3 recv_trailers timed out after trailers were buffered; forwarding trailers without waiting for delayed FIN"
                    );
                    return Ok(Some(trailers));
                }
                debug!(
                    timeout_ms = backend_read_timeout_ms,
                    "H3 recv_trailers timed out after complete body; forwarding response without trailers"
                );
                Ok(None)
            }
        }
    } else {
        stream.recv_trailers().await
    }
}

async fn recv_h3_response_with_timeout(
    stream: &mut H3RequestStream,
    backend_read_timeout_ms: u64,
) -> H3PoolResult<http::Response<()>> {
    let recv = stream.recv_response();
    let result = if backend_read_timeout_ms > 0 {
        match tokio::time::timeout(Duration::from_millis(backend_read_timeout_ms), recv).await {
            Ok(result) => result,
            Err(_) => {
                return Err(H3PoolError::read_timeout(anyhow::anyhow!(
                    "recv_response read timeout after {}ms",
                    backend_read_timeout_ms
                )));
            }
        }
    } else {
        recv.await
    };
    result.map_err(recv_response_err)
}

#[inline]
fn connection_listed_headers_if_present(headers: &http::HeaderMap) -> Vec<http::HeaderName> {
    if headers.contains_key(http::header::CONNECTION) {
        parse_connection_listed_headers(headers)
    } else {
        Vec::new()
    }
}

fn collect_h3_response_headers(source: &http::HeaderMap) -> HashMap<String, String> {
    let mut headers: HashMap<String, String> = HashMap::with_capacity(source.keys_len());
    // RFC 9110 §7.6.1: snapshot the Connection-listed names before
    // iterating so any header NAMED in `Connection` is also skipped during
    // collection. Hyper rejects `Connection` on H2/H3 frames (RFC 9114 §4.2),
    // so this is typically empty for native H3 backends; the snapshot exists
    // for defence in depth.
    let connection_listed = connection_listed_headers_if_present(source);
    for (name, value) in source {
        if is_backend_response_strip_header(name.as_str()) {
            continue;
        }
        // RFC 9110 §7.6.1: also skip every header NAMED in `Connection`.
        if connection_listed.iter().any(|n| n == name) {
            continue;
        }
        if let Ok(value_str) = value.to_str() {
            let sep = if name == http::header::SET_COOKIE {
                "\n"
            } else {
                ", "
            };
            match headers.get_mut(name.as_str()) {
                Some(existing) => {
                    existing.push_str(sep);
                    existing.push_str(value_str);
                }
                None => {
                    headers.insert(name.as_str().to_string(), value_str.to_string());
                }
            }
        }
    }
    headers
}

/// Whether `e` is a connection-level graceful-close signal that may legally
/// follow a complete response body: `CONNECTION_CLOSE(H3_NO_ERROR)` or
/// `GOAWAY` (RFC 9114 §5.1, §5.2). Stream-level resets (`RemoteTerminate`)
/// are intentionally NOT considered graceful — the server aborted the stream.
///
/// The `RemoteClosing` (GOAWAY) variant is `#[non_exhaustive]` and h3 marks
/// the unit variant itself unconstructible from outside the crate, so it
/// cannot be matched by name. We fall back to its `Display` string (stable
/// in h3 0.0.8); any future wording change is caught by
/// `h3_goaway_after_complete_body_is_treated_as_graceful`.
///
/// Two distinct call sites use this predicate:
/// - [`drain_h3_response_body`] / streaming-response paths: a graceful close
///   AFTER a complete body is silently recovered into a successful response.
/// - The four `recv_response` `.map_err` sites (via
///   [`recv_response_err`]): a graceful close BEFORE headers are parsed
///   surfaces an unrecoverable 502 (no headers to forward), but is
///   wrapped via [`H3PoolError::graceful_close`] so gateway dispatch
///   sites suppress `mark_h3_unsupported` — `H3_NO_ERROR` is not a
///   transport-level capability failure even when the response is lost.
pub(crate) fn is_h3_graceful_close(e: &h3::error::StreamError) -> bool {
    e.is_h3_no_error() || e.to_string() == "Remote is closing the connection"
}

/// Map an h3 [`StreamError`](h3::error::StreamError) returned by
/// `recv_response()` into the corresponding [`H3PoolError`] variant.
///
/// Centralises the four identical `.map_err` closures across the pool's
/// inner request helpers (`do_request`, `do_request_streaming`,
/// `do_request_streaming_body`, `do_request_streaming_incoming_body`) so
/// the graceful-close detection cannot drift between sites on future
/// edits.
///
/// - [`is_h3_graceful_close`] true → [`H3PoolError::graceful_close`]:
///   the request was committed (post-wire) and the backend chose to
///   tear down without an error code; gateway dispatch sites suppress
///   `mark_h3_unsupported`. The 502 still propagates because no headers
///   are available to forward.
/// - Otherwise → [`H3PoolError::post_wire`]: a real transport / protocol
///   failure that should drive the H3 capability downgrade.
#[inline]
fn recv_response_err(e: h3::error::StreamError) -> H3PoolError {
    if is_h3_graceful_close(&e) {
        // Backend tore the connection down with `H3_NO_ERROR` (or sent
        // GOAWAY) before we could parse a usable response. The 502 still
        // propagates because no headers are available, but the gateway
        // must NOT treat this as an H3 capability failure — see
        // [`H3PoolError::graceful_close`] for the rationale.
        H3PoolError::graceful_close(anyhow::anyhow!(
            "recv_response after graceful remote close: {}",
            e
        ))
    } else {
        H3PoolError::post_wire(anyhow::anyhow!("recv_response failed: {}", e))
    }
}

/// Whether the received body is semantically complete for this response.
///
/// Uses exact equality for Content-Length-delimited bodies — an overlong body
/// (more bytes than declared) is malformed and must not be accepted as
/// "complete". HEAD, 204, and 304 responses have no body by definition
/// (RFC 9110 §6.4.1, §15.3.5, §15.4.5) and are complete when empty.
/// Returns `false` when Content-Length is absent and the response normally
/// carries a body, since completeness cannot be determined without the FIN.
pub(crate) fn is_response_body_complete(
    body_len: u64,
    method: &str,
    status: u16,
    content_length: Option<u64>,
) -> bool {
    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 {
        return body_len == 0;
    }
    match content_length {
        Some(declared) => body_len == declared,
        None => false,
    }
}

/// Like [`is_response_body_complete`], but for the case where a clean FIN has
/// ALREADY ended the DATA stream — e.g. the native-H3 trailer phase, entered
/// only after `recv_data` returned `Ok(None)`.
///
/// The only difference is the absent-Content-Length case: a FIN-delimited
/// (chunked / unknown-length) body is COMPLETE once the FIN arrives, so an
/// absent length is accepted here (matching the buffered drain, which forwards a
/// FIN-delimited body without a length check). A DECLARED length must still
/// match exactly — a truncated or overlong body that FINs early is a framing
/// violation that must surface, not be laundered into a clean EOS.
pub(crate) fn is_response_body_complete_after_fin(
    body_len: u64,
    method: &str,
    status: u16,
    content_length: Option<u64>,
) -> bool {
    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 {
        return body_len == 0;
    }
    content_length.is_none_or(|declared| body_len == declared)
}

/// Type alias for the h3 send request handle.
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

/// Pool entry bundling an `H3SendRequest` with the underlying `quinn::Connection`.
///
/// `is_healthy()` needs to detect closed QUIC connections (peer GOAWAY,
/// transport-level reset, network blip, idle timeout from the QUIC layer)
/// so the cleanup task can evict dead handles before their idle deadline
/// — `h3::client::SendRequest` doesn't surface a `close_reason()` /
/// `is_closed()` query of its own, so we hold a clone of the source
/// `quinn::Connection` (cheap `Arc`-based clone via `ConnectionRef`) and
/// inspect that. Without this, closed connections stayed cached until
/// `idle_timeout_seconds` elapsed; the next request fetched a dead
/// handle, failed, and only then was invalidated by the per-request
/// retry logic — wasted handshake amortization plus an avoidable
/// fast-fail on the hot path.
///
/// Both fields are `Clone` and the clones share underlying state, so this
/// struct is `Clone` at the same cost as the original `H3SendRequest`.
#[derive(Clone)]
struct H3PooledConnection {
    send_request: H3SendRequest,
    connection: quinn::Connection,
}

impl H3PooledConnection {
    fn new(send_request: H3SendRequest, connection: quinn::Connection) -> Self {
        Self {
            send_request,
            connection,
        }
    }

    /// Returns `true` once the underlying QUIC connection has reached a
    /// terminal state (peer-initiated `CONNECTION_CLOSE`, transport reset,
    /// idle-timeout, or local close). Used by `Http3PoolManager::is_healthy`
    /// so the shared pool cleanup task evicts dead entries on its next pass.
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/// Type alias for the h3 client request stream (bidirectional).
pub type H3RequestStream =
    h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;

/// Build a typed `io::Error` of kind `TimedOut` for an H3 backend-connect
/// budget exhaustion. The shared classifier ([`classify_http3_error`])
/// downcasts to `std::io::Error` first and maps `ErrorKind::TimedOut` to
/// `ConnectionTimeout` — without the typed wrapper, the message-based
/// fallback matches `"handshake"` before `"timeout"` and misclassifies
/// these errors as `TlsError`. Mirrors the H2/gRPC pool pattern where
/// `BackendTimeout` carries an `io::Error::TimedOut` source.
fn h3_backend_connect_timeout(proxy: &Proxy, host: &str, port: u16, phase: &str) -> anyhow::Error {
    anyhow::Error::from(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "HTTP/3 backend connect timeout after {}ms during {} to {}:{} for proxy {}",
            proxy.backend_connect_timeout_ms, phase, host, port, proxy.id
        ),
    ))
}

/// Error returned by [`Http3ConnectionPool`] when an HTTP/3 request fails.
///
/// Carries the underlying [`anyhow::Error`] alongside `request_on_wire`, a
/// sticky boolean tracking whether the request was committed to the
/// backend's application layer on ANY attempt within this pool call —
/// including internal cached-then-fallback retries. Once `request_on_wire`
/// is `true`, gateway-level retries must respect `retry_on_methods` because
/// the backend may have processed the request; replaying it could cause
/// non-idempotent double-execution.
///
/// Set to `true` as soon as `send_request().await` succeeds (the QUIC
/// stream is opened and request headers are committed) — regardless of
/// whether `send_data` / `finish` / `recv_response` succeeds afterwards.
/// The pool's internal retry chain promotes the flag forward so a later
/// failed-connect attempt cannot mask the earlier wire commitment.
///
/// Also carries `graceful_close`, set when the underlying error is a
/// graceful remote close (`H3_NO_ERROR` `ApplicationClose` or
/// `GOAWAY`/`RemoteClosing`) at the response read boundary. The 502
/// propagates to the caller because we have no headers / partial body to
/// forward, but the gateway MUST NOT treat this as an H3 capability
/// failure — `H3_NO_ERROR` is by definition the peer's spec-legal
/// teardown signal (RFC 9114 §8.1), not a transport-level fault.
///
/// Constructors:
/// - [`H3PoolError::pre_wire`] — request never reached the backend (DNS,
///   TLS, connect, h3 session creation, or `send_request` itself failed).
/// - [`H3PoolError::post_wire`] — request was at least partially sent;
///   any failure here loses idempotency safety.
/// - [`H3PoolError::graceful_close`] — request reached the wire but the
///   backend closed gracefully before a usable response could be parsed.
///   Post-wire by construction; suppresses `mark_h3_unsupported` at
///   gateway dispatch sites.
/// - [`H3PoolError::promote_on_wire_if`] — conditionally promote a stored
///   error to `request_on_wire=true` (no-op when the condition is false).
///   Used by the pool's internal retry chain to surface the "any attempt
///   committed" semantics: each fresh-connect setup `?` exit threads
///   `any_request_on_wire` through this method so a previous post-wire
///   attempt's commitment is preserved across the final error.
#[derive(Debug)]
pub struct H3PoolError {
    inner: anyhow::Error,
    request_on_wire: bool,
    graceful_close: bool,
    read_timeout: bool,
}

impl H3PoolError {
    /// Construct an error for a failure that occurred BEFORE the request
    /// reached the backend's application layer (DNS / TLS / handshake /
    /// `send_request` itself failed). Safe to retry regardless of
    /// idempotency.
    pub fn pre_wire(error: impl Into<anyhow::Error>) -> Self {
        Self {
            inner: error.into(),
            request_on_wire: false,
            graceful_close: false,
            read_timeout: false,
        }
    }

    /// Construct an error for a failure that occurred AFTER the H3 stream
    /// was opened (request headers were committed). Even if the body is
    /// only partially sent, the backend may have processed the request,
    /// so retries must respect `retry_on_methods`.
    pub fn post_wire(error: impl Into<anyhow::Error>) -> Self {
        Self {
            inner: error.into(),
            request_on_wire: true,
            graceful_close: false,
            read_timeout: false,
        }
    }

    /// Construct an error for a graceful remote close at the response
    /// read boundary (post-wire by definition: the request was sent;
    /// the backend started or completed the response and tore the
    /// connection down with `H3_NO_ERROR` / GOAWAY before headers
    /// could be parsed).
    ///
    /// The 502 still propagates to the caller because no headers are
    /// available to forward, but [`graceful_close`] returns `true` so
    /// gateway dispatch sites suppress `mark_h3_unsupported` —
    /// `H3_NO_ERROR` is the peer's spec-legal teardown signal, not a
    /// transport-level capability failure.
    pub fn graceful_close(error: impl Into<anyhow::Error>) -> Self {
        Self {
            inner: error.into(),
            request_on_wire: true,
            graceful_close: true,
            read_timeout: false,
        }
    }

    /// Construct an error for a `backend_read_timeout_ms` deadline expiring
    /// while waiting for the backend's response (headers via
    /// `recv_response()` or buffered body frames via `recv_data()`).
    ///
    /// Post-wire by definition: the request was fully committed before the
    /// gateway started waiting on the response, so `request_on_wire=true`
    /// and gateway retries must respect `retry_on_methods`. The typed
    /// [`is_read_timeout`](Self::is_read_timeout) signal lets dispatch
    /// sites surface 504 Backend timeout (matching the direct-H2 / HBONE
    /// read-timeout arms) instead of a generic 502, and classify as
    /// [`ReadWriteTimeout`](crate::retry::ErrorClass::ReadWriteTimeout)
    /// without relying on string heuristics. A read timeout must NOT
    /// trigger `mark_h3_unsupported` — a stalled backend has not proved it
    /// lost QUIC/H3 support (`is_h3_transport_error_class` excludes
    /// `ReadWriteTimeout`).
    pub fn read_timeout(error: impl Into<anyhow::Error>) -> Self {
        Self {
            inner: error.into(),
            request_on_wire: true,
            graceful_close: false,
            read_timeout: true,
        }
    }

    /// Borrow the underlying error for downcast / display / `tracing` use.
    pub fn as_error(&self) -> &anyhow::Error {
        &self.inner
    }

    /// Returns `true` if the request was committed to the wire on any
    /// attempt covered by this error. Drives `BackendResponse::connection_error`
    /// at the gateway: `connection_error = !request_on_wire`.
    pub fn request_on_wire(&self) -> bool {
        self.request_on_wire
    }

    /// Returns `true` if this error originates from a graceful remote
    /// close (`H3_NO_ERROR` `ApplicationClose` or `GOAWAY`/`RemoteClosing`)
    /// at the response read boundary. Gateway dispatch sites use this
    /// signal to suppress `mark_h3_unsupported`: the in-flight request
    /// still 502s (no headers to forward), but the next request must
    /// stay on H3 — `H3_NO_ERROR` is the peer's spec-legal teardown
    /// signal, not a transport-level capability failure.
    pub fn is_graceful_close(&self) -> bool {
        self.graceful_close
    }

    /// Returns `true` if this error originates from a
    /// `backend_read_timeout_ms` deadline expiring while waiting for the
    /// backend response (header wait or buffered body drain). Gateway
    /// dispatch sites use this typed signal to return 504 Backend timeout
    /// (consistent with the direct-H2 / HBONE read-timeout arms) and to
    /// classify as `ReadWriteTimeout` deterministically. Read timeouts do
    /// not trigger `mark_h3_unsupported`.
    pub fn is_read_timeout(&self) -> bool {
        self.read_timeout
    }

    /// Conditionally promote the sticky `request_on_wire` flag.
    ///
    /// - When `condition` is `true`, the flag is set to `true` (no-op if
    ///   already `true`).
    /// - When `condition` is `false`, this is a NO-OP — the existing flag
    ///   is preserved, never demoted from `true` back to `false`.
    ///
    /// A `false` value just means "no earlier attempt committed the body" — it
    /// must NOT clobber a `true` flag that an earlier
    /// `H3PoolError::post_wire(...)` constructor set. `graceful_close` is
    /// preserved verbatim — promotion only affects the body-on-wire signal.
    ///
    /// The pool's `request*` methods no longer thread this flag across internal
    /// attempts. A POST-WIRE failure is returned immediately (it must never be
    /// replayed on another connection), so the cached/fallback/fresh chain is
    /// only driven by PRE-WIRE failures and the fresh-connect setup errors are
    /// genuinely pre-wire. This method is retained as a utility for combining a
    /// prior on-wire observation with a later pre-wire error.
    #[allow(dead_code)] // Retained public utility for combining a prior on-wire observation with a later pre-wire error.
    pub fn promote_on_wire_if(mut self, condition: bool) -> Self {
        if condition {
            self.request_on_wire = true;
        }
        self
    }

    /// Consume and return the underlying error, dropping the body-on-wire
    /// signal. Used by callers that have already extracted the signal.
    #[allow(dead_code)] // Public escape hatch for callers that need owned anyhow::Error.
    pub fn into_error(self) -> anyhow::Error {
        self.inner
    }
}

impl std::fmt::Display for H3PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for H3PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // `anyhow::Error::source()` walks through the chain to the next
        // typed cause — exactly what classifiers expect.
        self.inner.source()
    }
}

/// Convenience: lets callers pass `&H3PoolError` directly to classifiers
/// that take `&(dyn std::error::Error + 'static)` (e.g.
/// [`classify_http3_error`] and the H3 dispatcher's `classify_h3_error`
/// wrapper).
///
/// Without this impl, every call site would need a manual
/// `e.as_error().as_ref()` to peel back to the inner anyhow chain —
/// `anyhow::Error::deref` returns `&(dyn Error + Send + Sync + 'static)`,
/// not the same trait-object shape the classifier signature expects, and
/// `H3PoolError::as_error()` returns the wrapper rather than a trait
/// object. Implementing `AsRef<dyn Error + Send + Sync + 'static>`
/// lets `e.as_ref()` flow through the wrapper to the inner anyhow's
/// `as_ref()` in one step, which the Rust trait-object upcast at the
/// classifier signature accepts.
///
/// Net effect at call sites: `classify_h3_error(e.as_ref())` reads as
/// "classify the underlying error chain" without leaking the
/// `H3PoolError` -> `anyhow::Error` -> `dyn Error` shuffle.
impl AsRef<dyn std::error::Error + Send + Sync + 'static> for H3PoolError {
    fn as_ref(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self.inner.as_ref()
    }
}

/// Result type alias for the H3 pool.
pub type H3PoolResult<T> = std::result::Result<T, H3PoolError>;

fn should_probe_selected_h3_cache_after_fast_path(fast_path_failed_pre_wire: bool) -> bool {
    !fast_path_failed_pre_wire
}

/// A native-H3 streaming request may reconnect after a cached-connection
/// failure only while the request is still pre-wire. `do_request_streaming_body`
/// does not poll the borrowed frontend body until `send_request` opens the
/// backend stream, so a pre-wire failure leaves that body untouched and safe to
/// forward on a fresh connection. Once `request_on_wire` is true, replay would
/// risk double-executing a non-idempotent gRPC call.
fn should_reconnect_streaming_body_after_cached_failure(error: &H3PoolError) -> bool {
    !error.request_on_wire()
}

/// Reconnect gate for the hyper-`Incoming` streaming variants, where the body
/// is moved into `do_request_streaming_incoming_body` instead of borrowed:
/// fall through to a fresh connection only when the cached-connection failure
/// was pre-wire AND the callee handed the un-polled body back. The two
/// conditions agree by construction, but requiring both means a mislabeled
/// error can never replay a body that may already have reached the backend.
fn incoming_body_for_reconnect<B>(error: &H3PoolError, recovered_body: Option<B>) -> Option<B> {
    recovered_body.filter(|_| should_reconnect_streaming_body_after_cached_failure(error))
}

/// Result of a streaming HTTP/3 request — headers received, body still in flight.
///
/// The caller reads response body chunks via `recv_stream.recv_data()`.
pub struct H3StreamingResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub recv_stream: H3RequestStream,
}

/// HTTP/3 connection pool for proxying requests to HTTP/3 backends.
///
/// Caches QUIC connections and h3 session handles per backend `host:port`,
/// avoiding the enormous overhead of creating a new UDP socket, QUIC handshake,
/// and h3 session for every request. Each cached connection supports full
/// HTTP/3 multiplexing (concurrent streams).
pub struct Http3ConnectionPool {
    pool: Arc<GenericPool<Http3PoolManager>>,
    env_config: Arc<crate::config::EnvConfig>,
    /// Shared DNS cache for backend hostname resolution.
    dns_cache: crate::dns::DnsCache,
    /// Round-robin counter for distributing streams across backend connections.
    conn_counter: AtomicU64,
    /// Number of QUIC connections to maintain per backend. Multiple connections
    /// distribute frame processing across QUIC driver tasks, preventing a
    /// single-driver CPU bottleneck at high concurrency.
    connections_per_backend: usize,
    /// Shared backend SVID revision. Pool keys include this so new requests
    /// after a rotation create fresh QUIC/TLS state without disturbing
    /// established connections.
    backend_svid_generation: BackendSvidGeneration,
    /// Shared QUIC endpoint for IPv4 backends. All IPv4 connections share a
    /// single UDP socket, reducing FD usage and enabling kernel-level port reuse.
    ipv4_endpoint: tokio::sync::OnceCell<quinn::Endpoint>,
    /// Shared QUIC endpoint for IPv6 backends.
    ipv6_endpoint: tokio::sync::OnceCell<quinn::Endpoint>,
}

#[derive(Clone)]
struct Http3PoolManager {
    backend_svid_generation: BackendSvidGeneration,
    global_backend_client_cert_path: Option<String>,
    workload_svid_cert_path: Option<String>,
}

#[async_trait]
impl PoolManager for Http3PoolManager {
    type Connection = H3PooledConnection;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        Http3ConnectionPool::write_pool_key_with_host_and_generation(
            buf,
            host,
            port,
            proxy,
            shard,
            self.svid_generation_for_proxy(proxy),
        );
    }

    // HTTP/3 request paths establish new connections through
    // `GenericPool::create_or_get_existing_owned()` because QUIC setup needs
    // per-call TLS and H3 config objects that are not part of the manager.
    async fn create(&self, _key: &str, _proxy: &Proxy) -> Result<Self::Connection> {
        Err(anyhow::anyhow!(
            "Http3ConnectionPool uses GenericPool::create_or_get_existing_owned for creation"
        ))
    }

    /// Reject pool entries whose underlying QUIC connection has already
    /// terminated. The shared cleanup task in `pool::GenericPool` evicts
    /// any entry where `is_healthy` returns `false` on its next pass, so
    /// dead handles no longer survive until `idle_timeout_seconds`.
    /// Mirrors `Http2PoolManager::is_healthy` (which calls
    /// `!conn.is_closed()` on the hyper H2 sender).
    fn is_healthy(&self, conn: &Self::Connection) -> bool {
        !conn.is_closed()
    }

    fn destroy(&self, conn: Self::Connection) {
        drop(conn);
    }

    fn runtime_metrics_kind(&self) -> Option<crate::runtime_metrics::PoolKind> {
        Some(crate::runtime_metrics::PoolKind::Http3)
    }
}

impl Http3PoolManager {
    fn current_svid_generation(&self) -> u64 {
        self.backend_svid_generation.load(Ordering::Acquire)
    }

    fn svid_generation_for_proxy(&self, proxy: &Proxy) -> Option<u64> {
        let effective_client_cert_path = proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .or(self.global_backend_client_cert_path.as_deref());
        backend_svid_generation_for_client_cert(
            effective_client_cert_path,
            self.workload_svid_cert_path.as_deref(),
            self.current_svid_generation(),
        )
    }
}

impl Http3ConnectionPool {
    #[allow(dead_code)] // Used by tests and standalone H3 callers without shared SVID rotation state.
    pub fn new(env_config: Arc<crate::config::EnvConfig>, dns_cache: crate::dns::DnsCache) -> Self {
        Self::new_with_svid_generation(env_config, dns_cache, Arc::new(AtomicU64::new(0)))
    }

    pub fn new_with_svid_generation(
        env_config: Arc<crate::config::EnvConfig>,
        dns_cache: crate::dns::DnsCache,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        let connections_per_backend = env_config.http3_connections_per_backend;
        let cleanup_interval = Duration::from_secs(env_config.pool_cleanup_interval_seconds.max(1));
        let shards = crate::util::sharding::pool_shard_amount(env_config.pool_shard_amount);
        let pool_cfg = PoolConfig {
            idle_timeout_seconds: env_config.http3_pool_idle_timeout_seconds,
            max_idle_per_host: connections_per_backend.max(1),
            ..PoolConfig::default()
        };

        Self {
            pool: GenericPool::new(
                Arc::new(Http3PoolManager {
                    backend_svid_generation: backend_svid_generation.clone(),
                    global_backend_client_cert_path: env_config
                        .backend_tls_client_cert_path
                        .clone(),
                    workload_svid_cert_path: env_config.gateway_svid_cert_path.clone(),
                }),
                pool_cfg,
                cleanup_interval,
                shards,
            ),
            env_config,
            dns_cache,
            conn_counter: AtomicU64::new(0),
            connections_per_backend,
            backend_svid_generation,
            ipv4_endpoint: tokio::sync::OnceCell::new(),
            ipv6_endpoint: tokio::sync::OnceCell::new(),
        }
    }

    /// Get or lazily create the shared QUIC endpoint for the given address family.
    ///
    /// All connections to backends of the same address family share a single UDP
    /// socket, reducing FD usage from O(connections) to O(1) per address family.
    async fn get_shared_endpoint(&self, is_ipv6: bool) -> Result<quinn::Endpoint, anyhow::Error> {
        let cell = if is_ipv6 {
            &self.ipv6_endpoint
        } else {
            &self.ipv4_endpoint
        };
        let endpoint = cell
            .get_or_try_init(|| async { create_shared_quic_endpoint(is_ipv6) })
            .await?;
        Ok(endpoint.clone())
    }

    /// Number of connections in the pool (for metrics).
    pub fn pool_size(&self) -> usize {
        self.pool.pool_size()
    }

    pub fn force_drain_svid_generation(&self, generation: u64) {
        let matcher = SvidGenerationMatcher::new(generation);
        self.pool.invalidate_matching(|key| matcher.matches(key));
    }

    pub fn force_drain_all(&self) {
        self.pool.clear();
    }

    fn current_svid_generation(&self) -> u64 {
        self.backend_svid_generation.load(Ordering::Acquire)
    }

    fn svid_generation_for_proxy(&self, proxy: &Proxy) -> Option<u64> {
        let effective_client_cert_path = proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .or(self.env_config.backend_tls_client_cert_path.as_deref());
        backend_svid_generation_for_client_cert(
            effective_client_cert_path,
            self.env_config.gateway_svid_cert_path.as_deref(),
            self.current_svid_generation(),
        )
    }

    /// Pool key — includes TLS-differentiating fields (CA, mTLS, verify).
    /// Uses `|` as delimiter to avoid ambiguity with `:` in IPv6 addresses.
    #[allow(dead_code)] // Public test/helper surface; runtime paths use generation-aware methods.
    pub fn pool_key(proxy: &Proxy, index: usize) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key(&mut key, proxy, index);
        key
    }

    /// Write pool key into the provided buffer, avoiding intermediate
    /// `format!()` allocations. Called from both the allocating `pool_key()`
    /// (cold path) and the thread-local buffer lookup (hot path).
    #[allow(dead_code)] // Paired with pool_key() for external tests/helpers.
    fn write_pool_key(buf: &mut String, proxy: &Proxy, index: usize) {
        Self::write_pool_key_with_host_and_generation(
            buf,
            &proxy.backend_host,
            proxy.backend_port,
            proxy,
            index,
            None,
        );
    }

    #[allow(dead_code)] // Paired with pool_key_for_target() for external tests/helpers.
    fn write_pool_key_with_host(
        buf: &mut String,
        host: &str,
        port: u16,
        proxy: &Proxy,
        index: usize,
    ) {
        Self::write_pool_key_with_host_and_generation(buf, host, port, proxy, index, None);
    }

    fn write_pool_key_with_host_and_generation(
        buf: &mut String,
        host: &str,
        port: u16,
        proxy: &Proxy,
        index: usize,
        svid_generation: Option<u64>,
    ) {
        use std::fmt::Write;
        buf.clear();
        // Key shape:
        //   host|port|index|dns_override|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N
        // User/config-controlled components are escaped before delimiters are
        // appended so values containing `|`, `#`, or `%` cannot collide with
        // adjacent fields or shard suffixes.
        //
        // This must cover every dimension that affects QUIC connection
        // identity *and* matches the backend-capability registry key for
        // the same target (see `backend_capabilities::write_capability_key`).
        // Dropping `dns_override` or either mTLS path would let one proxy's
        // probed QUIC connection be reused for another proxy whose
        // resolver / cert material differs — the exact wrong-backend /
        // wrong-identity bug the reviewer flagged.
        //
        // `subset` partitions H3 pools so two proxies that share
        // `(host, port, dns_override)` but select different DestinationRule
        // subsets cannot share a QUIC connection even when their TLS
        // material is byte-identical. Empty when the proxy has no
        // `upstream_subset`.
        append_pool_key_component(buf, host);
        let _ = write!(buf, "|{port}|{index}|");
        append_optional_pool_key_component(buf, proxy.dns_override.as_deref());
        buf.push('|');
        append_optional_pool_key_component(buf, proxy.upstream_subset.as_deref());
        buf.push('|');
        append_backend_tls_pool_key_fields(
            buf,
            &proxy.resolved_tls,
            proxy.resolved_tls.client_cert_path.as_deref(),
            proxy.resolved_tls.client_key_path.as_deref(),
            proxy.resolved_tls.verify_server_cert,
            svid_generation,
        );
    }

    /// Pool key for the retry / upstream-target path.
    ///
    /// Takes `&Proxy` (not just host/port) so the key includes every
    /// dimension that affects QUIC connection identity —
    /// `dns_override`, CA, mTLS cert/key, verify flag — matching the
    /// backend-capability registry key for the same target. Without this,
    /// a capability probed through one proxy's resolver / cert material
    /// could be served by a pooled QUIC connection originated by a
    /// different proxy.
    #[allow(dead_code)] // Public test/helper surface; runtime paths use generation-aware methods.
    pub fn pool_key_for_target(proxy: &Proxy, host: &str, port: u16, index: usize) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key_with_host(&mut key, host, port, proxy, index);
        key
    }

    fn pool_key_with_current_generation(&self, proxy: &Proxy, index: usize) -> String {
        self.pool_key_with_generation(proxy, index, self.svid_generation_for_proxy(proxy))
    }

    /// Build a pool key using a pre-snapshotted generation.
    ///
    /// Callers that issue multiple key constructions inside a single request
    /// should snapshot `svid_generation_for_proxy` once at the top and pass it
    /// in. This avoids redundant `Ordering::Acquire` atomic loads per shard
    /// and — more importantly — pins the generation across retry attempts so
    /// a rotation landing mid-request can't fragment the lookup window across
    /// two generations.
    fn pool_key_with_generation(
        &self,
        proxy: &Proxy,
        index: usize,
        svid_generation: Option<u64>,
    ) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key_with_host_and_generation(
            &mut key,
            &proxy.backend_host,
            proxy.backend_port,
            proxy,
            index,
            svid_generation,
        );
        key
    }

    fn pool_key_for_target_with_current_generation(
        &self,
        proxy: &Proxy,
        host: &str,
        port: u16,
        index: usize,
    ) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key_with_host_and_generation(
            &mut key,
            host,
            port,
            proxy,
            index,
            self.svid_generation_for_proxy(proxy),
        );
        key
    }

    /// Build a target-keyed pool key using a pre-snapshotted SVID generation.
    /// See [`pool_key_with_generation`] for the rationale (atomic-load
    /// amortization + generation pinning across retry shards).
    fn pool_key_for_target_with_generation(
        &self,
        proxy: &Proxy,
        host: &str,
        port: u16,
        index: usize,
        svid_generation: Option<u64>,
    ) -> String {
        let mut key = String::with_capacity(128);
        Self::write_pool_key_with_host_and_generation(
            &mut key,
            host,
            port,
            proxy,
            index,
            svid_generation,
        );
        key
    }

    /// Return the shard indices startup warmup should attempt for a proxy.
    #[doc(hidden)]
    pub fn warmup_shard_indices(
        proxy: &Proxy,
        default_connections_per_backend: usize,
    ) -> std::ops::Range<usize> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(default_connections_per_backend)
            .max(1);
        0..conns_per_backend
    }

    async fn create_or_get_proxy_sender(
        &self,
        key: String,
        proxy: &Proxy,
        tls_config: Arc<rustls::ClientConfig>,
        h3_config: super::config::Http3ServerConfig,
    ) -> Result<H3PooledConnection, anyhow::Error> {
        // H3 is the one pool that needs extra creation context beyond the
        // `Proxy`, so it uses the shared shell's explicit creation closure.
        self.pool
            .create_or_get_existing_owned(key, |_| {
                let tls_config = tls_config.clone();
                let h3_config = h3_config.clone();
                async move {
                    self.create_connection(proxy, &tls_config, Some(&h3_config))
                        .await
                }
            })
            .await
    }

    async fn create_or_get_target_sender(
        &self,
        key: String,
        proxy: &Proxy,
        host: &str,
        port: u16,
        tls_config: Arc<rustls::ClientConfig>,
        h3_config: super::config::Http3ServerConfig,
    ) -> Result<H3PooledConnection, anyhow::Error> {
        self.pool
            .create_or_get_existing_owned(key, |_| {
                let tls_config = tls_config.clone();
                let h3_config = h3_config.clone();
                async move {
                    self.create_connection_to_target(
                        proxy,
                        host,
                        port,
                        &tls_config,
                        Some(&h3_config),
                    )
                    .await
                }
            })
            .await
    }

    /// Pre-establish configured QUIC connections and cache them in the pool.
    ///
    /// Used at startup to warm the connection pool so the first request to each
    /// H3 backend does not pay the QUIC + TLS 1.3 handshake cost. Shard 0 is
    /// the capability probe and must succeed; additional shards are best-effort
    /// so one slow parallel connection does not mark an H3-capable backend
    /// unsupported.
    pub async fn warmup_connection(
        &self,
        proxy: &Proxy,
        tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<(), anyhow::Error> {
        let conns_per_backend =
            Self::warmup_shard_indices(proxy, self.connections_per_backend).len();
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);

        let primary_key = self.pool_key_with_current_generation(proxy, 0);
        if self.pool.cached(&primary_key).is_none() {
            let _ = self
                .create_or_get_proxy_sender(
                    primary_key,
                    proxy,
                    tls_config.clone(),
                    h3_config.clone(),
                )
                .await?;
        }

        if conns_per_backend == 1 {
            return Ok(());
        }

        futures_util::stream::iter(1..conns_per_backend)
            .for_each_concurrent(conns_per_backend.min(8), |index| {
                let tls_config = tls_config.clone();
                let h3_config = h3_config.clone();
                async move {
                    let key = self.pool_key_with_current_generation(proxy, index);
                    if self.pool.cached(&key).is_some() {
                        return;
                    }

                    if let Err(err) = self
                        .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
                        .await
                    {
                        debug!(
                            "HTTP/3 pool warmup: optional shard {} of {} failed for {}:{}: {}",
                            index, conns_per_backend, proxy.backend_host, proxy.backend_port, err
                        );
                    }
                }
            })
            .await;
        Ok(())
    }

    /// Send an HTTP/3 request, reusing a cached QUIC connection if available.
    ///
    /// Round-robins across `connections_per_backend` connections to distribute
    /// QUIC frame processing across multiple driver tasks.
    /// Send an HTTP/3 request, reusing a cached QUIC connection if available.
    ///
    /// The `tls_config_fn` closure is only called on cache miss (when a new
    /// QUIC connection must be established), avoiding the overhead of cloning
    /// the TLS root certificate store on every request.
    ///
    /// Body-on-wire safety: the pool tries the cached connection first, then
    /// falls back across other cached indices, then opens a new connection —
    /// but ONLY for PRE-WIRE failures (the connection was dead before
    /// `send_request` committed the request). The moment an attempt reports a
    /// POST-WIRE failure ([`H3PoolError::request_on_wire`] is `true`) the error
    /// is returned immediately: the request (headers + body) already reached the
    /// backend on that stream, so replaying it on another connection would
    /// double-execute a possibly non-idempotent request and bypass the gateway's
    /// `retry_on_methods` policy. The gateway's own retry layer then decides
    /// whether the request (if idempotent) may be retried.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3BufferedResponse> {
        // Per-proxy override takes priority over global default
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // Snapshot the SVID generation once at the top of the request so all
        // pool key constructions (cache probe, slow-path build, retry shards)
        // see the same value. Pinning the generation across attempts is also
        // a correctness property: a rotation landing mid-`request()` could
        // otherwise have the cache probe target `svidg=N` and the retry probe
        // target `svidg=N+1`, fragmenting lookups across generations and
        // missing live entries on either side.
        let svid_generation = self.svid_generation_for_proxy(proxy);

        let cached = self.pool.cached_with(|buf| {
            Self::write_pool_key_with_host_and_generation(
                buf,
                &proxy.backend_host,
                proxy.backend_port,
                proxy,
                start,
                svid_generation,
            )
        });
        let max_response_body_size_bytes = self.env_config.max_response_body_size_bytes;

        // PRE-WIRE failures (the connection was dead before the request was
        // committed) are safe to retry on the next cached/fresh connection. A
        // POST-WIRE failure means the request (headers + body) already reached
        // the backend on this stream, so replaying it on another connection
        // would double-execute a possibly non-idempotent request and bypass the
        // gateway's retry_on_methods policy — surface it immediately instead.
        let mut fast_path_failed_pre_wire = false;
        if let Some(pooled) = cached {
            let mut sr = pooled.send_request;
            match Self::do_request(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
                max_response_body_size_bytes,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) if e.request_on_wire() => return Err(e),
                Err(_) => {
                    // Pre-wire cached failure — fall through to the full
                    // retry/reconnect path below which allocates pool keys.
                    fast_path_failed_pre_wire = true;
                }
            }
        }

        // Slow path: allocate pool key String for cache miss, error recovery,
        // and new connection creation.
        let key = self.pool_key_with_generation(proxy, start, svid_generation);

        let mut try_fallback_indices = fast_path_failed_pre_wire;
        if fast_path_failed_pre_wire {
            self.pool.invalidate(&key);
        }

        // Try cached connection on the selected index first, unless the
        // thread-local fast path already tried that same entry and failed
        // before the request reached the wire.
        if should_probe_selected_h3_cache_after_fast_path(fast_path_failed_pre_wire)
            && let Some(pooled) = self.pool.cached(&key)
        {
            let mut sr = pooled.send_request;
            match Self::do_request(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
                max_response_body_size_bytes,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) if e.request_on_wire() => return Err(e),
                Err(e) => {
                    debug!("HTTP/3 cached connection failed, reconnecting: {}", e);
                    self.pool.invalidate(&key);
                    try_fallback_indices = true;
                }
            }
        }

        if try_fallback_indices {
            // Try other cached indices before creating a new connection.
            for offset in 1..conns_per_backend {
                let fallback_index = (start + offset) % conns_per_backend;
                let fallback_key =
                    self.pool_key_with_generation(proxy, fallback_index, svid_generation);
                if let Some(fallback_pooled) = self.pool.cached(&fallback_key) {
                    let mut fallback_sr = fallback_pooled.send_request;
                    match Self::do_request(
                        &mut fallback_sr,
                        proxy,
                        method,
                        backend_url,
                        headers,
                        body.clone(),
                        max_response_body_size_bytes,
                    )
                    .await
                    {
                        Ok(result) => return Ok(result),
                        Err(e) if e.request_on_wire() => return Err(e),
                        Err(_) => {
                            self.pool.invalidate(&fallback_key);
                        }
                    }
                }
            }
        }

        // Create new connection — only now do we need the TLS config. Any
        // post-wire failure on an earlier cached attempt has already returned
        // above, so reaching here means every prior attempt was pre-wire (the
        // request never reached a backend) and this fresh attempt is the
        // request's first delivery; connection-setup failures are therefore
        // genuinely pre-wire.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
            max_response_body_size_bytes,
        )
        .await
    }

    /// Send an HTTP/3 request to an explicit host/port target, independent of
    /// `proxy.backend_host`/`proxy.backend_port`. Used by the retry path to
    /// route to a different load-balanced upstream target.
    ///
    /// Pool entries are keyed by the explicit target host:port so connections
    /// are cached and reused per target, not per proxy.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3BufferedResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        // Snapshot the SVID generation once; see `request()` for rationale —
        // pinning across the cache probe + retry-shard fan-out prevents a
        // mid-request rotation from fragmenting the lookup window across
        // two `|svidg=N` values.
        let svid_generation = self.svid_generation_for_proxy(proxy);
        let key = self.pool_key_for_target_with_generation(
            proxy,
            target_host,
            target_port,
            start,
            svid_generation,
        );

        let max_response_body_size_bytes = self.env_config.max_response_body_size_bytes;

        // Try cached connection on the selected index first. A PRE-WIRE failure
        // is safe to retry on another connection; a POST-WIRE failure means the
        // request already reached the backend on this stream, so return it
        // immediately to avoid double-executing a possibly non-idempotent
        // request and bypassing the gateway's retry_on_methods policy.
        if let Some(pooled) = self.pool.cached(&key) {
            let mut sr = pooled.send_request;
            match Self::do_request(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
                max_response_body_size_bytes,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) if e.request_on_wire() => return Err(e),
                Err(e) => {
                    debug!(
                        "HTTP/3 cached connection to {}:{} failed, reconnecting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);

                    // Try other cached indices before creating a new connection
                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = self.pool_key_for_target_with_generation(
                            proxy,
                            target_host,
                            target_port,
                            fallback_index,
                            svid_generation,
                        );
                        if let Some(fallback_pooled) = self.pool.cached(&fallback_key) {
                            let mut fallback_sr = fallback_pooled.send_request;
                            match Self::do_request(
                                &mut fallback_sr,
                                proxy,
                                method,
                                backend_url,
                                headers,
                                body.clone(),
                                max_response_body_size_bytes,
                            )
                            .await
                            {
                                Ok(result) => return Ok(result),
                                Err(e) if e.request_on_wire() => return Err(e),
                                Err(_) => {
                                    self.pool.invalidate(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Create new connection to the explicit target. Any post-wire failure
        // on an earlier cached attempt has already returned above, so reaching
        // here means every prior attempt was pre-wire; connection-setup
        // failures are therefore genuinely pre-wire.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
            max_response_body_size_bytes,
        )
        .await
    }

    /// Create a new QUIC connection + h3 session using a shared endpoint.
    ///
    /// Reuses the pool's shared IPv4/IPv6 QUIC endpoint instead of creating
    /// a new UDP socket per connection, reducing FD usage from O(connections)
    /// to O(1) per address family.
    async fn create_connection(
        &self,
        proxy: &Proxy,
        tls_config: &Arc<rustls::ClientConfig>,
        h3_config: Option<&super::config::Http3ServerConfig>,
    ) -> Result<H3PooledConnection, anyhow::Error> {
        let quic_client_config = QuicClientConfig::try_from(tls_config.clone()).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}",
                e
            )
        })?;

        let default_cfg = super::config::Http3ServerConfig::default();
        let cfg = h3_config.unwrap_or(&default_cfg);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.initial_mtu(cfg.initial_mtu);
        transport_config.stream_receive_window(crate::http3::config::quic_varint_or_default(
            cfg.stream_receive_window,
            crate::http3::config::H3_STREAM_RECEIVE_WINDOW_DEFAULT,
        ));
        transport_config.receive_window(crate::http3::config::quic_varint_or_default(
            cfg.receive_window,
            crate::http3::config::H3_RECEIVE_WINDOW_DEFAULT,
        ));
        transport_config.send_window(cfg.send_window);

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let host = &proxy.backend_host;
        let port = proxy.backend_port;
        let candidates = resolve_backend_addrs_cached(
            host,
            &self.dns_cache,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await?;

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let tls_server_name =
            crate::tls::backend::backend_tls_server_name(&proxy.resolved_tls, host);
        let (pooled, addr) =
            crate::dns::connect_candidates(&candidates, port, connect_timeout, |addr| {
                let client_config = client_config.clone();
                async move {
                    let endpoint = self.get_shared_endpoint(addr.is_ipv6()).await?;
                    let connection = endpoint
                        .connect_with(client_config, addr, tls_server_name)?
                        .await
                        .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

                    // Keep the H3 session setup inside the candidate attempt so a
                    // QUIC-successful peer that cannot speak HTTP/3 cannot pin
                    // this pool and suppress failover to a later DNS address.
                    let quic_conn = connection.clone();
                    let (mut driver, send_request) =
                        h3::client::new(h3_quinn::Connection::new(connection))
                            .await
                            .map_err(|e| anyhow::anyhow!("HTTP/3 handshake failed: {}", e))?;

                    tokio::spawn(async move {
                        let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
                        debug!("HTTP/3 pool connection driver closed: {}", err);
                    });
                    Ok(H3PooledConnection::new(send_request, quic_conn))
                }
            })
            .await
            .map_err(|error| match error {
                crate::dns::CandidateConnectError::TimedOut { .. } => {
                    h3_backend_connect_timeout(proxy, host, port, "HTTP/3")
                }
                crate::dns::CandidateConnectError::Failed { source, .. } => source,
            })?;

        debug!(
            "HTTP/3 pool: connected to {}:{} (resolved: {})",
            host, port, addr
        );

        Ok(pooled)
    }

    /// Create a new QUIC connection + h3 session to an explicit host/port
    /// using a shared endpoint.
    ///
    /// Used by `request_with_target` for load-balanced retries where the target
    /// differs from `proxy.backend_host`/`proxy.backend_port`. Honors the
    /// proxy's `dns_override` / `dns_cache_ttl_seconds` so retries resolve
    /// through the same path the capability probe used — otherwise a
    /// proxy pinning a specific IP via `dns_override` would silently dial
    /// the default DNS answer for the load-balanced target instead.
    async fn create_connection_to_target(
        &self,
        proxy: &Proxy,
        host: &str,
        port: u16,
        tls_config: &Arc<rustls::ClientConfig>,
        h3_config: Option<&super::config::Http3ServerConfig>,
    ) -> Result<H3PooledConnection, anyhow::Error> {
        let quic_client_config = QuicClientConfig::try_from(tls_config.clone()).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}",
                e
            )
        })?;

        let default_cfg = super::config::Http3ServerConfig::default();
        let cfg = h3_config.unwrap_or(&default_cfg);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.initial_mtu(cfg.initial_mtu);
        transport_config.stream_receive_window(crate::http3::config::quic_varint_or_default(
            cfg.stream_receive_window,
            crate::http3::config::H3_STREAM_RECEIVE_WINDOW_DEFAULT,
        ));
        transport_config.receive_window(crate::http3::config::quic_varint_or_default(
            cfg.receive_window,
            crate::http3::config::H3_RECEIVE_WINDOW_DEFAULT,
        ));
        transport_config.send_window(cfg.send_window);

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let candidates = resolve_backend_addrs_cached(
            host,
            &self.dns_cache,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await?;

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let tls_server_name =
            crate::tls::backend::backend_tls_server_name(&proxy.resolved_tls, host);
        let (pooled, addr) =
            crate::dns::connect_candidates(&candidates, port, connect_timeout, |addr| {
                let client_config = client_config.clone();
                async move {
                    let endpoint = self.get_shared_endpoint(addr.is_ipv6()).await?;
                    let connection = endpoint
                        .connect_with(client_config, addr, tls_server_name)?
                        .await
                        .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

                    // Keep the H3 session setup inside the candidate attempt so a
                    // QUIC-successful peer that cannot speak HTTP/3 cannot pin
                    // this pool and suppress failover to a later DNS address.
                    let quic_conn = connection.clone();
                    let (mut driver, send_request) =
                        h3::client::new(h3_quinn::Connection::new(connection))
                            .await
                            .map_err(|e| anyhow::anyhow!("HTTP/3 handshake failed: {}", e))?;

                    tokio::spawn(async move {
                        let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
                        debug!("HTTP/3 pool connection driver closed: {}", err);
                    });
                    Ok(H3PooledConnection::new(send_request, quic_conn))
                }
            })
            .await
            .map_err(|error| match error {
                crate::dns::CandidateConnectError::TimedOut { .. } => {
                    h3_backend_connect_timeout(proxy, host, port, "HTTP/3")
                }
                crate::dns::CandidateConnectError::Failed { source, .. } => source,
            })?;

        debug!(
            "HTTP/3 pool: connected to {}:{} (resolved: {})",
            host, port, addr
        );

        Ok(pooled)
    }

    /// Execute an HTTP/3 request on an existing SendRequest handle.
    ///
    /// Returns [`H3PoolError`] on failure with `request_on_wire` set
    /// according to whether `send_request` had already opened the QUIC
    /// stream when the failure surfaced — once the stream is open, the
    /// request headers (and possibly body bytes) are committed and the
    /// backend may have processed the request, so the gateway must
    /// respect `retry_on_methods` instead of replaying blindly.
    async fn do_request(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        max_response_body_size_bytes: usize,
    ) -> H3PoolResult<H3BufferedResponse> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                // RFC 9110 §7.6.1 hop-by-hop strip — see `proxy::headers`.
                n if is_backend_request_strip_header(n) => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        // `send_request().await` opens the QUIC stream and commits the
        // request headers. Failure here is pre-wire (no stream, no body
        // delivery). Anything below this line is post-wire — the
        // backend may already be processing the request.
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;

        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response =
            recv_h3_response_with_timeout(&mut stream, proxy.backend_read_timeout_ms).await?;
        let status = response.status().as_u16();

        let response_headers = collect_h3_response_headers(response.headers());

        let content_length: Option<u64> = response_headers
            .get("content-length")
            .and_then(|v| v.parse().ok());

        // Body-on-wire semantics: `send_request` already returned Ok by this
        // point, so any recv_data error is post_wire. Recovery for graceful
        // CONNECTION_CLOSE(H3_NO_ERROR) / GOAWAY after a complete body lives
        // inside `drain_h3_response_body`, which also reads any backend
        // trailers (returned here so the buffered server path can forward
        // them — see issue #1630).
        let (response_body, response_trailers) = drain_h3_response_body(
            &mut stream,
            method,
            status,
            content_length,
            max_response_body_size_bytes,
            proxy.backend_read_timeout_ms,
        )
        .await
        .map_err(|e| match e {
            H3BodyDrainError::ReadTimeout { .. } => {
                // Preserve the typed read-timeout signal so the gateway
                // dispatch sites map it to 504 Backend timeout instead of
                // a generic 502 — see `H3PoolError::read_timeout`.
                H3PoolError::read_timeout(anyhow::anyhow!("recv_data failed: {}", e))
            }
            other => H3PoolError::post_wire(anyhow::anyhow!("recv_data failed: {}", other)),
        })?;

        Ok(H3BufferedResponse {
            status,
            body: response_body,
            headers: response_headers,
            trailers: response_trailers,
        })
    }

    /// Execute an HTTP/3 request, returning headers and a stream handle for the
    /// response body. Unlike `do_request`, this does NOT buffer the body — the
    /// caller reads chunks via `recv_stream.recv_data()`.
    ///
    /// Body-on-wire semantics match [`do_request`] — `request_on_wire`
    /// flips to `true` once `send_request().await` succeeds.
    async fn do_request_streaming(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
    ) -> H3PoolResult<H3StreamingResponse> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                // RFC 9110 §7.6.1 hop-by-hop strip — see `proxy::headers`.
                n if is_backend_request_strip_header(n) => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;

        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response =
            recv_h3_response_with_timeout(&mut stream, proxy.backend_read_timeout_ms).await?;
        let status = response.status().as_u16();

        let response_headers = collect_h3_response_headers(response.headers());

        Ok(H3StreamingResponse {
            status,
            headers: response_headers,
            recv_stream: stream,
        })
    }

    /// Execute an HTTP/3 request, streaming the request body from an h3 server
    /// frontend stream directly to the backend without buffering into `Vec<u8>`.
    ///
    /// Returns headers and a stream handle for the response body. Body size
    /// limits are enforced inline during streaming. This is the zero-copy
    /// request body path for the H3 frontend when no plugins need body buffering
    /// and no retries are configured.
    ///
    /// Body-on-wire semantics: `request_on_wire` flips to `true` once the
    /// QUIC stream is opened (`send_request` succeeded). The size-limit
    /// rejection is post-wire because we cannot abort the stream cleanly
    /// after dispatch — the H3 server callers translate this back into a
    /// 413 status which is intentionally not a transport-class failure.
    #[allow(clippy::too_many_arguments)]
    async fn do_request_streaming_body(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_stream: &mut h3::server::RequestStream<
            h3_quinn::BidiStream<bytes::Bytes>,
            bytes::Bytes,
        >,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        // Response-header wait bound (ms; `0` = unbounded). Normally
        // `proxy.backend_read_timeout_ms`, but the native-H3 gRPC path overrides it
        // with `0` when a client `grpc-timeout` is present so the outer absolute
        // deadline governs the header wait instead of the (shorter) read timeout.
        header_read_timeout_ms: u64,
        // Set to `true` the instant `send_request` opens the backend stream (the
        // request reaches the wire). The native-H3 gRPC dispatch wraps this future
        // in an outer `timeout_at`; when that fires it inspects this flag — NOT the
        // uploaded-byte count — to decide pre-wire (connect still in flight →
        // capability downgrade) vs post-wire (stream already open → read timeout).
        // A valid zero-message / trailers-only client-streaming RPC opens the stream
        // with no body bytes, so byte count alone would misclassify it as pre-wire.
        stream_opened: Arc<AtomicBool>,
        // Set to `true` once the client request upload is fully forwarded and the
        // backend stream is `finish`ed (i.e. we are now waiting on backend response
        // headers). The native-H3 gRPC dispatch reads this to separate an upload-phase
        // timeout (a stalled client — neutral for backend health) from a header-wait
        // timeout (a slow backend — a real read-timeout fault).
        upload_complete: Arc<AtomicBool>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                // `te: trailers` is the single hop-by-hop exception that MUST reach
                // the backend: HTTP/3 permits only that one value (RFC 9114 §4.2) and
                // strict gRPC backends require it. The native-H3 gRPC dispatch authors
                // this header explicitly (after `build_h3_backend_headers` has already
                // stripped any client-supplied `te`), so forward `te: trailers` as-is
                // instead of dropping it with the generic hop-by-hop strip below.
                "te" if value.as_bytes().eq_ignore_ascii_case(b"trailers") => {
                    req_builder = req_builder.header(name, value);
                }
                // RFC 9110 §7.6.1 hop-by-hop strip — see `proxy::headers`.
                n if is_backend_request_strip_header(n) => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        let mut backend_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))?;
        // The stream is now open on the backend QUIC connection — the request has
        // reached the wire. Any failure from here on is post-wire (the caller's
        // dispatch `timeout_at` reads this to avoid misclassifying a slow upload /
        // zero-message client-streaming RPC as a pre-wire connect failure).
        stream_opened.store(true, Ordering::Release);

        // Stream request body: read chunks from frontend, forward to backend.
        // Uses Buf::copy_to_bytes() which is zero-copy when the underlying
        // buffer is already bytes::Bytes (common with h3-quinn).
        let mut total_sent: usize = 0;
        loop {
            let recv_res = frontend_stream.recv_data().await;
            let chunk_opt = match recv_res {
                Ok(c) => c,
                Err(e) => {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "client disconnected while sending request body: {}",
                        e
                    )));
                }
            };
            let Some(mut chunk) = chunk_opt else { break };
            let len = chunk.remaining();
            if max_request_body_size > 0 {
                total_sent += len;
                if total_sent > max_request_body_size {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "Request body exceeds maximum size"
                    )));
                }
            }
            if len == 0 {
                continue;
            }
            backend_stream
                .send_data(chunk.copy_to_bytes(len))
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
            bytes_seen.fetch_add(len as u64, Ordering::Release);
        }
        // Forward client REQUEST trailers (trailing metadata) the client sent after
        // the final DATA frame, before FINishing the backend stream — client- /
        // bidi-streaming gRPC RPCs may carry them, and the H2 streaming gRPC path
        // forwards them too. A trailer DECODE error means the inbound request is
        // malformed (oversized / undecodable HEADERS block), so abort the request
        // rather than silently dropping the trailing metadata and finishing the
        // backend stream as if the client had sent none. Classified as a client
        // request-body fault (post-wire, neutral for backend health — see
        // `is_h3_client_request_body_disconnect`). Absent trailers are fine.
        match frontend_stream.recv_trailers().await {
            Ok(Some(mut trailers)) if !trailers.is_empty() => {
                // Client request trailers are read AFTER the initial headers were
                // stripped/sanitized, so a malicious client can smuggle hop-by-hop
                // fields (`connection`, `te`, ...) or reserved gateway metadata
                // (`x-consumer-*`, `x-geo-country`, `x-path-param-*`) here that
                // the gateway removed from the initial header block. Apply the
                // same backend-request strip + reserved-name filter before
                // forwarding. HTTP/3 header names are always lowercase, so exact
                // lowercase comparisons suffice.
                let strip: Vec<http::header::HeaderName> = trailers
                    .keys()
                    .filter(|n| {
                        let s = n.as_str();
                        is_backend_request_strip_header(s)
                            || s == "x-consumer-username"
                            || s == "x-consumer-custom-id"
                            || s == "x-geo-country"
                            || s.starts_with("x-path-param-")
                    })
                    .cloned()
                    .collect();
                for name in strip {
                    trailers.remove(&name);
                }
                // Only forward a still-non-empty block; an all-reserved trailer set
                // collapses to nothing and must not emit an empty trailer frame.
                if !trailers.is_empty() {
                    backend_stream.send_trailers(trailers).await.map_err(|e| {
                        H3PoolError::post_wire(anyhow::anyhow!(
                            "send request trailers failed: {}",
                            e
                        ))
                    })?;
                }
            }
            Ok(_) => {}
            Err(e) => {
                return Err(H3PoolError::post_wire(anyhow::anyhow!(
                    "malformed client request trailers: {}",
                    e
                )));
            }
        }
        backend_stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;
        // The client upload (body + trailers) is fully forwarded and the backend
        // send side is FINished — any timeout from here on is the backend being slow
        // to return response headers, NOT a stalled client upload.
        upload_complete.store(true, Ordering::Release);

        let response =
            recv_h3_response_with_timeout(&mut backend_stream, header_read_timeout_ms).await?;
        let status = response.status().as_u16();

        let response_headers = collect_h3_response_headers(response.headers());

        Ok(H3StreamingResponse {
            status,
            headers: response_headers,
            recv_stream: backend_stream,
        })
    }

    /// Execute an HTTP/3 request, streaming the request body from a hyper
    /// `Incoming` body directly to the backend without collecting into `Vec<u8>`.
    ///
    /// Used by the H1/H2 frontend -> H3 backend path when no request-body
    /// plugins need buffering and no retries can replay the body.
    ///
    /// Body-on-wire semantics: `request_on_wire` flips to `true` once
    /// `send_request` succeeds; subsequent client-disconnect / size-limit
    /// errors are post-wire because the backend already received headers.
    ///
    /// Unlike `do_request_streaming_body` (whose frontend stream is borrowed),
    /// the `Incoming` body is moved in. A failure before `send_request` opens
    /// the backend stream returns the still-unpolled body alongside the error
    /// so the caller can replay it on a fresh connection; failures at or past
    /// that boundary return `None` — the body may already be partially sent.
    #[allow(clippy::too_many_arguments)]
    async fn do_request_streaming_incoming_body(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
    ) -> Result<H3StreamingResponse, (H3PoolError, Option<Incoming>)> {
        let backend_stream = match Self::open_streaming_incoming_backend_stream(
            send_request,
            proxy,
            method,
            backend_url,
            headers,
        )
        .await
        {
            Ok(stream) => stream,
            // Pre-wire: `frontend_body` has not been polled — hand it back so
            // the caller can forward it on a fresh connection.
            Err(e) => return Err((e, Some(frontend_body))),
        };

        Self::forward_incoming_body_and_read_response(
            backend_stream,
            proxy,
            frontend_body,
            max_request_body_size,
            bytes_seen,
        )
        .await
        .map_err(|e| (e, None))
    }

    /// Pre-wire phase of `do_request_streaming_incoming_body`: build the
    /// backend request and open the backend stream. Must not touch the
    /// frontend body — the caller relies on it being replayable when this
    /// fails.
    async fn open_streaming_incoming_backend_stream(
        send_request: &mut H3SendRequest,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
    ) -> H3PoolResult<H3RequestStream> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("Invalid backend URL: {}", e)))?;

        let _host = uri.host().unwrap_or(&proxy.backend_host);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let req_method: http::Method = method.parse().map_err(|_| {
            H3PoolError::pre_wire(anyhow::anyhow!("Invalid HTTP method: {}", method))
        })?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);
        for (name, value) in headers {
            match name.as_str() {
                // RFC 9110 §7.6.1 hop-by-hop strip — see `proxy::headers`.
                n if is_backend_request_strip_header(n) => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(()).map_err(H3PoolError::pre_wire)?;
        send_request
            .send_request(req)
            .await
            .map_err(|e| H3PoolError::pre_wire(anyhow::anyhow!("send_request failed: {}", e)))
    }

    /// Post-wire phase of `do_request_streaming_incoming_body`: forward the
    /// frontend body, FIN the send side, and read the response headers. The
    /// backend stream is already open, so nothing here may be replayed.
    async fn forward_incoming_body_and_read_response(
        mut backend_stream: H3RequestStream,
        proxy: &Proxy,
        mut frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let mut total_sent: usize = 0;
        while let Some(frame_result) = frontend_body.frame().await {
            let frame = frame_result.map_err(|e| {
                H3PoolError::post_wire(anyhow::anyhow!(
                    "Client disconnected while sending request body: {}",
                    e
                ))
            })?;
            let Ok(mut chunk) = frame.into_data() else {
                continue;
            };
            let len = chunk.remaining();
            if max_request_body_size > 0 {
                total_sent += len;
                if total_sent > max_request_body_size {
                    return Err(H3PoolError::post_wire(anyhow::anyhow!(
                        "Request body exceeds maximum size"
                    )));
                }
            }
            if len == 0 {
                continue;
            }
            backend_stream
                .send_data(chunk.copy_to_bytes(len))
                .await
                .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("send_data failed: {}", e)))?;
            bytes_seen.fetch_add(len as u64, Ordering::Release);
        }
        backend_stream
            .finish()
            .await
            .map_err(|e| H3PoolError::post_wire(anyhow::anyhow!("finish failed: {}", e)))?;

        let response =
            recv_h3_response_with_timeout(&mut backend_stream, proxy.backend_read_timeout_ms)
                .await?;
        let status = response.status().as_u16();

        let response_headers = collect_h3_response_headers(response.headers());

        Ok(H3StreamingResponse {
            status,
            headers: response_headers,
            recv_stream: backend_stream,
        })
    }

    /// Send an HTTP/3 request with a streaming request body from the frontend,
    /// returning headers and a stream handle for the response body.
    ///
    /// The request body is read from `frontend_stream.recv_data()` and forwarded
    /// directly to the backend without buffering. This avoids `Vec<u8>` allocation
    /// for large request bodies when no plugins need body inspection.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_streaming_body(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_stream: &mut h3::server::RequestStream<
            h3_quinn::BidiStream<bytes::Bytes>,
            bytes::Bytes,
        >,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        // Response-header wait bound (ms; `0` = unbounded), forwarded to
        // `do_request_streaming_body`. Callers pass `proxy.backend_read_timeout_ms`
        // normally; the native-H3 gRPC path passes `0` under a client `grpc-timeout`
        // so the outer absolute deadline governs the header wait.
        header_read_timeout_ms: u64,
        // Flipped to `true` once the backend stream opens; the native-H3 gRPC
        // dispatch reads it to distinguish pre-wire connect failures from post-wire
        // read timeouts. Forwarded verbatim to `do_request_streaming_body`.
        stream_opened: Arc<AtomicBool>,
        // Flipped to `true` once the client upload is fully forwarded and the backend
        // stream is FINished; lets the dispatch separate an upload-phase stall (client
        // fault) from a header-wait timeout (backend fault). Forwarded verbatim.
        upload_complete: Arc<AtomicBool>,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // No thread-local fast path for streaming body. A post-wire failure may
        // have consumed frontend bytes and cannot be replayed, but a cached
        // connection that fails before `send_request` opens the backend stream
        // leaves the borrowed frontend body untouched, so reconnecting is safe.
        let key = self.pool_key_with_current_generation(proxy, start);

        if let Some(pooled) = self.pool.cached(&key) {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_stream,
                max_request_body_size,
                Arc::clone(&bytes_seen),
                header_read_timeout_ms,
                Arc::clone(&stream_opened),
                Arc::clone(&upload_complete),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 streaming body: cached connection failed, evicting: {}",
                        e
                    );
                    self.pool.invalidate(&key);
                    if !should_reconnect_streaming_body_after_cached_failure(&e) {
                        return Err(e);
                    }
                    // `send_request` failed before opening a backend stream, so
                    // `frontend_stream` has not been polled. Fall through to a
                    // fresh connection instead of surfacing a spurious gRPC
                    // UNAVAILABLE for a stale warmed pool entry.
                }
            }
        }

        // Create a new connection. Reaching here after a cached failure is safe
        // only because the gate above proved it was pre-wire; therefore no sticky
        // `request_on_wire` state needs to be promoted into this attempt.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request_streaming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_stream,
            max_request_body_size,
            bytes_seen,
            header_read_timeout_ms,
            stream_opened,
            upload_complete,
        )
        .await
    }

    /// Send an HTTP/3 request with a streaming request body sourced from a
    /// hyper `Incoming` body, returning headers and a stream handle for the
    /// response body.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_streaming_incoming_body(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        mut frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = self.pool_key_with_current_generation(proxy, start);

        if let Some(pooled) = self.pool.cached(&key) {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming_incoming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_body,
                max_request_body_size,
                Arc::clone(&bytes_seen),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err((e, recovered_body)) => {
                    debug!(
                        "HTTP/3 streaming body from Incoming: cached connection failed, evicting: {}",
                        e
                    );
                    self.pool.invalidate(&key);
                    // A pre-wire failure hands the un-polled `Incoming` body
                    // back; fall through to a fresh connection with it instead
                    // of surfacing a spurious error for a stale warmed pool
                    // entry. Post-wire failures may have consumed body bytes
                    // and are never replayed.
                    match incoming_body_for_reconnect(&e, recovered_body) {
                        Some(body) => frontend_body = body,
                        None => return Err(e),
                    }
                }
            }
        }

        // Create a new connection. Any cached failure that reached this point
        // was pre-wire (the gate above recovered the un-polled body), so
        // replay safety is preserved and no sticky `request_on_wire` state
        // needs to be promoted into this attempt.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request_streaming_incoming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_body,
            max_request_body_size,
            bytes_seen,
        )
        .await
        .map_err(|(e, _)| e)
    }

    /// Send an HTTP/3 request with a streaming request body to an explicit
    /// host/port target.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target_streaming_body(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        frontend_stream: &mut h3::server::RequestStream<
            h3_quinn::BidiStream<bytes::Bytes>,
            bytes::Bytes,
        >,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        // Response-header wait bound (ms; `0` = unbounded), forwarded to
        // `do_request_streaming_body`. Callers pass `proxy.backend_read_timeout_ms`
        // normally; the native-H3 gRPC path passes `0` under a client `grpc-timeout`
        // so the outer absolute deadline governs the header wait.
        header_read_timeout_ms: u64,
        // Flipped to `true` once the backend stream opens; the native-H3 gRPC
        // dispatch reads it to distinguish pre-wire connect failures from post-wire
        // read timeouts. Forwarded verbatim to `do_request_streaming_body`.
        stream_opened: Arc<AtomicBool>,
        // Flipped to `true` once the client upload is fully forwarded and the backend
        // stream is FINished; lets the dispatch separate an upload-phase stall (client
        // fault) from a header-wait timeout (backend fault). Forwarded verbatim.
        upload_complete: Arc<AtomicBool>,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = self.pool_key_for_target_with_current_generation(
            proxy,
            target_host,
            target_port,
            start,
        );

        if let Some(pooled) = self.pool.cached(&key) {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_stream,
                max_request_body_size,
                Arc::clone(&bytes_seen),
                header_read_timeout_ms,
                Arc::clone(&stream_opened),
                Arc::clone(&upload_complete),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "HTTP/3 streaming body: cached connection to {}:{} failed, evicting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);
                    if !should_reconnect_streaming_body_after_cached_failure(&e) {
                        return Err(e);
                    }
                    // Pre-wire means the borrowed frontend stream is still
                    // untouched, so retry the same target on a fresh connection.
                }
            }
        }

        // Create a new connection. Any cached failure that reached this point
        // was pre-wire, so replay safety is preserved.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request_streaming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_stream,
            max_request_body_size,
            bytes_seen,
            header_read_timeout_ms,
            stream_opened,
            upload_complete,
        )
        .await
    }

    /// Send an HTTP/3 request with a streaming `Incoming` request body to an
    /// explicit host/port target.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target_streaming_incoming_body(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        mut frontend_body: Incoming,
        max_request_body_size: usize,
        bytes_seen: Arc<AtomicU64>,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        let key = self.pool_key_for_target_with_current_generation(
            proxy,
            target_host,
            target_port,
            start,
        );

        if let Some(pooled) = self.pool.cached(&key) {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming_incoming_body(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                frontend_body,
                max_request_body_size,
                Arc::clone(&bytes_seen),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err((e, recovered_body)) => {
                    debug!(
                        "HTTP/3 streaming body from Incoming: cached connection to {}:{} failed, evicting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);
                    // Pre-wire means the un-polled `Incoming` body was handed
                    // back — retry the same target on a fresh connection.
                    // Post-wire failures may have consumed body bytes and are
                    // never replayed.
                    match incoming_body_for_reconnect(&e, recovered_body) {
                        Some(body) => frontend_body = body,
                        None => return Err(e),
                    }
                }
            }
        }

        // Create a new connection. Any cached failure that reached this point
        // was pre-wire (the gate above recovered the un-polled body), so
        // replay safety is preserved and no sticky `request_on_wire` state
        // needs to be promoted into this attempt.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request_streaming_incoming_body(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            frontend_body,
            max_request_body_size,
            bytes_seen,
        )
        .await
        .map_err(|(e, _)| e)
    }

    /// Send an HTTP/3 request, returning headers and a stream handle for the
    /// response body. Same pool key / fallback / reconnect logic as `request()`.
    pub async fn request_streaming(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;

        // Snapshot the SVID generation once for the whole request. See
        // `request()` for the rationale (atomic-load amortization plus
        // generation pinning across retries).
        let svid_generation = self.svid_generation_for_proxy(proxy);

        let cached = self.pool.cached_with(|buf| {
            Self::write_pool_key_with_host_and_generation(
                buf,
                &proxy.backend_host,
                proxy.backend_port,
                proxy,
                start,
                svid_generation,
            )
        });
        // A PRE-WIRE failure is safe to retry on another connection; a
        // POST-WIRE failure means the request already reached the backend on
        // this stream, so return it immediately rather than replaying it (see
        // `request()`).
        let mut fast_path_failed_pre_wire = false;
        if let Some(pooled) = cached {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) if e.request_on_wire() => return Err(e),
                Err(_) => {
                    fast_path_failed_pre_wire = true;
                }
            }
        }

        // Slow path: allocate pool key String
        let key = self.pool_key_with_generation(proxy, start, svid_generation);

        let mut try_fallback_indices = fast_path_failed_pre_wire;
        if fast_path_failed_pre_wire {
            self.pool.invalidate(&key);
        }

        if should_probe_selected_h3_cache_after_fast_path(fast_path_failed_pre_wire)
            && let Some(pooled) = self.pool.cached(&key)
        {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) if e.request_on_wire() => return Err(e),
                Err(e) => {
                    debug!("HTTP/3 cached connection failed, reconnecting: {}", e);
                    self.pool.invalidate(&key);
                    try_fallback_indices = true;
                }
            }
        }

        if try_fallback_indices {
            for offset in 1..conns_per_backend {
                let fallback_index = (start + offset) % conns_per_backend;
                let fallback_key =
                    self.pool_key_with_generation(proxy, fallback_index, svid_generation);
                if let Some(fallback_pooled) = self.pool.cached(&fallback_key) {
                    let mut fallback_sr = fallback_pooled.send_request;
                    match Self::do_request_streaming(
                        &mut fallback_sr,
                        proxy,
                        method,
                        backend_url,
                        headers,
                        body.clone(),
                    )
                    .await
                    {
                        Ok(result) => return Ok(result),
                        Err(e) if e.request_on_wire() => return Err(e),
                        Err(_) => {
                            self.pool.invalidate(&fallback_key);
                        }
                    }
                }
            }
        }

        // Create a fresh connection. Post-wire failures on earlier cached
        // attempts have already returned above, so setup failures here are
        // genuinely pre-wire.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_proxy_sender(key, proxy, tls_config, h3_config)
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request_streaming(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
    }

    /// Send an HTTP/3 request to an explicit host/port target, returning headers
    /// and a stream handle for the response body.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_target_streaming(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        method: &str,
        backend_url: &str,
        headers: &[(http::header::HeaderName, http::header::HeaderValue)],
        body: bytes::Bytes,
        tls_config_fn: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, anyhow::Error>,
    ) -> H3PoolResult<H3StreamingResponse> {
        let conns_per_backend = proxy
            .pool_http3_connections_per_backend
            .unwrap_or(self.connections_per_backend)
            .max(1);
        let start = self.conn_counter.fetch_add(1, Ordering::Relaxed) as usize % conns_per_backend;
        // Pin the SVID generation across cache probe + retry shards. See
        // `request()` for the rationale.
        let svid_generation = self.svid_generation_for_proxy(proxy);
        let key = self.pool_key_for_target_with_generation(
            proxy,
            target_host,
            target_port,
            start,
            svid_generation,
        );

        // A PRE-WIRE failure is safe to retry on another connection; a
        // POST-WIRE failure means the request already reached the backend on
        // this stream, so return it immediately rather than replaying it (see
        // `request()`).
        if let Some(pooled) = self.pool.cached(&key) {
            let mut sr = pooled.send_request;
            match Self::do_request_streaming(
                &mut sr,
                proxy,
                method,
                backend_url,
                headers,
                body.clone(),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) if e.request_on_wire() => return Err(e),
                Err(e) => {
                    debug!(
                        "HTTP/3 cached connection to {}:{} failed, reconnecting: {}",
                        target_host, target_port, e
                    );
                    self.pool.invalidate(&key);

                    for offset in 1..conns_per_backend {
                        let fallback_index = (start + offset) % conns_per_backend;
                        let fallback_key = self.pool_key_for_target_with_generation(
                            proxy,
                            target_host,
                            target_port,
                            fallback_index,
                            svid_generation,
                        );
                        if let Some(fallback_pooled) = self.pool.cached(&fallback_key) {
                            let mut fallback_sr = fallback_pooled.send_request;
                            match Self::do_request_streaming(
                                &mut fallback_sr,
                                proxy,
                                method,
                                backend_url,
                                headers,
                                body.clone(),
                            )
                            .await
                            {
                                Ok(result) => return Ok(result),
                                Err(e) if e.request_on_wire() => return Err(e),
                                Err(_) => {
                                    self.pool.invalidate(&fallback_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Create a fresh connection to the explicit target. Post-wire failures
        // on earlier cached attempts have already returned above, so setup
        // failures here are genuinely pre-wire.
        let tls_config = tls_config_fn().map_err(H3PoolError::pre_wire)?;
        let h3_config = super::config::Http3ServerConfig::from_env_config(&self.env_config);
        let pooled = self
            .create_or_get_target_sender(
                key,
                proxy,
                target_host,
                target_port,
                tls_config,
                h3_config,
            )
            .await
            .map_err(H3PoolError::pre_wire)?;
        let mut sr_for_request = pooled.send_request;

        Self::do_request_streaming(
            &mut sr_for_request,
            proxy,
            method,
            backend_url,
            headers,
            body,
        )
        .await
    }
}

/// HTTP/3 client for connecting to backend services over QUIC.
///
/// Note: For the reverse proxy hot path, use `Http3ConnectionPool` instead.
/// This client creates a new QUIC endpoint per instance and a new connection
/// per `request()` call — suitable for integration tests but not for
/// high-throughput proxying.
#[derive(Clone)]
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

#[allow(dead_code)]
impl Http3Client {
    /// Create a new HTTP/3 client with the given TLS configuration.
    ///
    /// The `tls_config` must have ALPN protocols set (typically `b"h3"` for HTTP/3).
    /// The crypto provider must be installed before calling this function
    /// (typically once at application startup via `rustls::crypto::ring::default_provider().install_default()`).
    ///
    /// The optional `h3_config` provides QUIC transport tuning parameters
    /// (stream/connection window sizes, send window). When `None`, uses
    /// the same optimized defaults as `Http3ServerConfig::default()`.
    pub fn new(
        tls_config: Arc<rustls::ClientConfig>,
        h3_config: Option<&super::config::Http3ServerConfig>,
    ) -> Result<Self, anyhow::Error> {
        // Convert rustls config to QUIC-compatible config.
        // This validates that the config has TLS 1.3 support with an appropriate
        // initial cipher suite (AES-128-GCM-SHA256).
        let quic_client_config = QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}", e))?;

        let default_cfg = super::config::Http3ServerConfig::default();
        let cfg = h3_config.unwrap_or(&default_cfg);

        // Apply QUIC transport tuning for the client side
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.initial_mtu(cfg.initial_mtu);
        transport_config.stream_receive_window(crate::http3::config::quic_varint_or_default(
            cfg.stream_receive_window,
            crate::http3::config::H3_STREAM_RECEIVE_WINDOW_DEFAULT,
        ));
        transport_config.receive_window(crate::http3::config::quic_varint_or_default(
            cfg.receive_window,
            crate::http3::config::H3_RECEIVE_WINDOW_DEFAULT,
        ));
        transport_config.send_window(cfg.send_window);

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        // Bind to any available local UDP port
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Send an HTTP/3 request to the specified backend.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
        body: bytes::Bytes,
    ) -> Result<(u16, Vec<u8>, std::collections::HashMap<String, String>), anyhow::Error> {
        // Parse URL to get host and port
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let host = uri.host().unwrap_or(&proxy.backend_host);
        let port = uri.port_u16().unwrap_or(proxy.backend_port);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Resolve the backend address
        let addr = resolve_backend_addr(host, port).await?;

        debug!(
            "HTTP/3 client connecting to {}:{} (resolved: {})",
            host, port, addr
        );

        // Establish QUIC connection
        let connection = self
            .endpoint
            .connect(addr, host)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        // Create HTTP/3 connection
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        // Drive the connection in background. The driver future completes when
        // the connection is closed, so we spawn it and let it clean up naturally.
        tokio::spawn(async move {
            let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 connection driver closed: {}", err);
        });

        // Build the request with the correct URI (path only, not full URL)
        let req_method: http::Method = method
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method))?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);

        // Add headers, skipping connection-level headers not valid in HTTP/3
        for (name, value) in &headers {
            match name.as_str() {
                // These are hop-by-hop headers from HTTP/1.1, not valid in HTTP/3
                // RFC 9110 §7.6.1 hop-by-hop strip — see `proxy::headers`.
                n if is_backend_request_strip_header(n) => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;

        // Send request
        let mut stream = send_request.send_request(req).await?;

        // Send body if present
        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        // Receive response
        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        // Collect response headers
        let response_headers = collect_h3_response_headers(response.headers());

        // Collect response body
        let content_length: Option<u64> = response_headers
            .get("content-length")
            .and_then(|v| v.parse().ok());

        // This integration/test client does not surface trailers; discard the
        // trailer slot the shared drain helper now returns (issue #1630).
        let (response_body, _trailers) =
            drain_h3_response_body(&mut stream, method, status, content_length, 0, 0).await?;

        Ok((status, response_body, response_headers))
    }
}

/// Create a shared QUIC endpoint for one address family (IPv4 or IPv6).
///
/// The endpoint has no default client config — callers use `connect_with()`
/// to pass per-connection TLS config. On Linux, applies `IP_BIND_ADDRESS_NO_PORT`
/// to defer ephemeral port allocation to `connect()` time.
fn create_shared_quic_endpoint(is_ipv6: bool) -> Result<quinn::Endpoint, anyhow::Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let _ = crate::socket_opts::set_ip_bind_address_no_port(socket.as_raw_fd(), true);
    }

    let bind_addr: SocketAddr = if is_ipv6 {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime found"))?;
    let endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, std_socket, runtime)?;
    Ok(endpoint)
}

/// Resolve a hostname to its rotated, policy-approved cached answer set.
///
/// Uses the gateway's `DnsCache` exclusively — no fallback to system DNS.
/// The cache is pre-warmed at startup and refreshes in the background.
async fn resolve_backend_addrs_cached(
    host: &str,
    dns_cache: &crate::dns::DnsCache,
    dns_override: Option<&str>,
    dns_cache_ttl_seconds: Option<u64>,
) -> Result<crate::dns::ResolvedAddresses, anyhow::Error> {
    dns_cache
        .resolve_candidates(host, dns_override, dns_cache_ttl_seconds)
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}: {}", host, e))
}

/// Resolve a hostname:port to a SocketAddr (system DNS, no cache).
///
/// Used only by `Http3Client` (test/integration client). The pool uses
/// `resolve_backend_addrs_cached` instead.
async fn resolve_backend_addr(host: &str, port: u16) -> Result<SocketAddr, anyhow::Error> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}:{}: {}", host, port, e))?
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("DNS resolution returned no addresses for {}:{}", host, port)
        })?;

    Ok(addr)
}

#[cfg(test)]
mod h3_pool_error_tests {
    //! Inline tests for the body-on-wire signal carried by [`H3PoolError`].
    //!
    //! These cover the construction primitives and the sticky-promotion
    //! behaviour that the pool's internal retry chain relies on. The
    //! end-to-end body-on-wire integration is exercised by the new
    //! functional test in `tests/functional/`.

    use super::*;

    #[test]
    fn collect_h3_response_headers_matches_h1_h2_folding() {
        let mut source = http::HeaderMap::new();
        source.append(
            "cache-control",
            http::HeaderValue::from_static("no-transform"),
        );
        source.append(
            "cache-control",
            http::HeaderValue::from_static("max-age=60"),
        );
        source.append("set-cookie", http::HeaderValue::from_static("session=a"));
        source.append("set-cookie", http::HeaderValue::from_static("theme=dark"));
        source.insert("connection", http::HeaderValue::from_static("x-hop"));
        source.insert("x-hop", http::HeaderValue::from_static("strip-me"));

        let headers = collect_h3_response_headers(&source);

        assert_eq!(
            headers.get("cache-control").map(String::as_str),
            Some("no-transform, max-age=60")
        );
        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some("session=a\ntheme=dark")
        );
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-hop"));
    }

    #[test]
    fn pre_wire_marks_request_not_committed() {
        let e = H3PoolError::pre_wire(anyhow::anyhow!("connect refused"));
        assert!(
            !e.request_on_wire(),
            "pre_wire constructor must report request_on_wire=false"
        );
    }

    #[test]
    fn post_wire_marks_request_committed() {
        let e = H3PoolError::post_wire(anyhow::anyhow!("send_data failed"));
        assert!(
            e.request_on_wire(),
            "post_wire constructor must report request_on_wire=true"
        );
    }

    #[test]
    fn promote_on_wire_if_only_promotes_false_to_true() {
        // The pool's retry chain calls `e.promote_on_wire_if(any_request_on_wire)`
        // on each fresh-connect setup `?` exit. The contract is asymmetric:
        // `condition=true` flips false → true; `condition=false` is a no-op.
        let pre = H3PoolError::pre_wire(anyhow::anyhow!("connect refused"));
        let promoted = pre.promote_on_wire_if(true);
        assert!(promoted.request_on_wire());

        // `condition=false` must NOT demote an already-true flag — that's
        // exactly the case where an earlier post-wire attempt set the
        // flag and a later pre-wire setup failure would otherwise clobber
        // it. Verify both directions: `true → true` is idempotent and
        // `false on an already-true` is a no-op.
        let post = H3PoolError::post_wire(anyhow::anyhow!("recv_response failed"));
        assert!(post.promote_on_wire_if(false).request_on_wire());

        let post = H3PoolError::post_wire(anyhow::anyhow!("recv_response failed"));
        assert!(post.promote_on_wire_if(true).request_on_wire());
    }

    #[test]
    fn fast_path_pre_wire_failure_skips_selected_slow_cache_probe() {
        assert!(
            should_probe_selected_h3_cache_after_fast_path(false),
            "cache misses or absent fast-path entries should still probe the selected slow-path key"
        );
        assert!(
            !should_probe_selected_h3_cache_after_fast_path(true),
            "a pre-wire fast-path failure already tried the selected entry, so the slow path must skip it"
        );
    }

    #[test]
    fn streaming_body_reconnects_only_before_request_reaches_wire() {
        let pre_wire = H3PoolError::pre_wire(anyhow::anyhow!("cached send_request failed"));
        assert!(
            should_reconnect_streaming_body_after_cached_failure(&pre_wire),
            "pre-wire cached failure leaves the borrowed frontend body untouched"
        );

        let post_wire = H3PoolError::post_wire(anyhow::anyhow!("cached send_data failed"));
        assert!(
            !should_reconnect_streaming_body_after_cached_failure(&post_wire),
            "post-wire cached failure may have consumed body bytes and must not replay"
        );
    }

    #[test]
    fn incoming_streaming_body_reconnects_only_pre_wire_with_recovered_body() {
        let pre_wire = H3PoolError::pre_wire(anyhow::anyhow!("cached send_request failed"));
        assert!(
            incoming_body_for_reconnect(&pre_wire, Some(())).is_some(),
            "pre-wire cached failure with the un-polled body recovered must replay on a fresh connection"
        );
        assert!(
            incoming_body_for_reconnect::<()>(&pre_wire, None).is_none(),
            "without the recovered body there is nothing safe to replay, even for a pre-wire error"
        );

        let post_wire = H3PoolError::post_wire(anyhow::anyhow!("cached send_data failed"));
        assert!(
            incoming_body_for_reconnect(&post_wire, Some(())).is_none(),
            "post-wire cached failure may have consumed body bytes and must not replay"
        );
    }

    #[test]
    fn display_forwards_to_inner_error() {
        let e = H3PoolError::pre_wire(anyhow::anyhow!("synthetic connect failure"));
        let rendered = format!("{}", e);
        assert!(
            rendered.contains("synthetic connect failure"),
            "Display must forward to inner anyhow::Error: got {:?}",
            rendered
        );
    }

    #[test]
    fn classify_http3_error_picks_protocol_for_application_close() {
        // Regression: h3 0.0.8 renders ConnectionError::ApplicationClose
        // as the bare token "ApplicationClose" (no trailing 'd'), so the
        // generic "closed" substring used to miss it. The shared
        // classifier explicitly handles `applicationclose`.
        let err: anyhow::Error = anyhow::anyhow!("connection ApplicationClose received");
        let class = classify_http3_error(err.as_ref());
        assert_eq!(
            class,
            crate::retry::ErrorClass::ConnectionClosed,
            "ApplicationClose must classify as ConnectionClosed (post-wire)"
        );
    }

    #[test]
    fn classify_http3_error_keeps_h3_protocol_codes_as_protocol() {
        // Regression: a stream-level RESET_STREAM contains "reset", and
        // the classifier used to short-circuit on bare "reset" before
        // checking the more specific protocol tokens. The fix puts
        // protocol tokens first.
        let err: anyhow::Error = anyhow::anyhow!("h3 stream RESET_STREAM code=H3_REQUEST_REJECTED");
        assert_eq!(
            classify_http3_error(err.as_ref()),
            crate::retry::ErrorClass::ProtocolError,
            "RESET_STREAM is application-layer (stream abort), not connection reset"
        );
    }

    #[test]
    fn classify_http3_error_treats_backend_connect_timeout_as_connection_timeout() {
        // Regression (Codex P3): the H3 backend-connect timeout helpers
        // emit a typed `io::Error::TimedOut` so the unified classifier's
        // typed walker maps them to `ConnectionTimeout`. A previous version
        // used `anyhow::anyhow!("...handshake...")` which fell through to
        // the substring fallback where "handshake" matched before "timeout"
        // and the error was misclassified as `TlsError` — diverging from
        // H2/gRPC/TCP which all classify the same `backend_connect_timeout_ms`
        // budget exhaustion as `ConnectionTimeout`.
        let io_err = std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "HTTP/3 backend connect timeout after 5000ms during HTTP/3 handshake to 127.0.0.1:443 for proxy test",
        );
        let err: anyhow::Error = anyhow::Error::from(io_err);
        assert_eq!(
            classify_http3_error(err.as_ref()),
            crate::retry::ErrorClass::ConnectionTimeout,
            "backend connect timeout must classify as ConnectionTimeout regardless of phase substring"
        );
    }

    /// Codex P1 regression: when an earlier internal attempt set
    /// `any_request_on_wire = true` (post-wire) and then `tls_config_fn()`
    /// or `create_or_get_proxy_sender()` fails on the fresh-connect
    /// fallback, the pool MUST promote the sticky flag onto the resulting
    /// `H3PoolError::pre_wire`. Without that promotion, the gateway sees
    /// `request_on_wire=false`, treats the call as pre-wire, and replays
    /// a non-idempotent request via `retry_on_connect_failure` even
    /// though the FIRST internal attempt may already have been processed
    /// by the backend.
    ///
    /// **Coverage scope.** This test is unit-level and only verifies the
    /// closure shape — `H3PoolError::pre_wire(e).promote_on_wire_if(true)`
    /// returns `request_on_wire=true`. It does NOT exercise the live
    /// `Http3ConnectionPool::request*` retry chain (cached attempt's
    /// post-wire failure → fresh-connect setup failure) end-to-end,
    /// because doing that requires a scripted QUIC backend that:
    /// (a) accepts the QUIC handshake, (b) accepts the stream open, (c)
    /// fails the body / response so the cached attempt is post-wire,
    /// then (d) refuses subsequent connect attempts so the fresh-connect
    /// setup also fails. The functional test
    /// `retry_on_connect_failure_fires_with_empty_methods_and_statuses`
    /// covers the gateway-level retry contract end-to-end via ECONNREFUSED
    /// but does not tickle this specific cached-success → fresh-connect
    /// setup-failure ordering. Tracked as a follow-up coverage gap; the
    /// closure-shape assertion below is the regression guard for the
    /// fix that this PR introduces.
    #[test]
    fn pre_wire_setup_failure_after_post_wire_attempt_preserves_sticky_flag() {
        // Simulate: any_request_on_wire = true (an earlier internal attempt
        // sent the request body). Now tls_config_fn() fails.
        let any_request_on_wire = true;
        let synthetic_setup_failure = anyhow::anyhow!("synthetic tls_config_fn() failure");

        let propagated: H3PoolError =
            H3PoolError::pre_wire(synthetic_setup_failure).promote_on_wire_if(any_request_on_wire);

        assert!(
            propagated.request_on_wire(),
            "TLS / sender-creation failure path must propagate sticky \
             request_on_wire=true so the gateway respects retry_on_methods \
             instead of replaying via retry_on_connect_failure. If this \
             assertion fails, a future refactor likely reverted to the \
             bare `map_err(pre_wire)?` shape — restore the closure form: \
             `|e| H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire)`"
        );
    }

    #[test]
    fn pre_wire_setup_failure_with_no_prior_post_wire_attempt_stays_pre_wire() {
        // Counterpart: if NO earlier internal attempt sent the body
        // (any_request_on_wire = false), the same closure must NOT
        // mistakenly mark the error as post-wire.
        let any_request_on_wire = false;
        let synthetic_setup_failure = anyhow::anyhow!("synthetic tls_config_fn() failure");

        let propagated: H3PoolError =
            H3PoolError::pre_wire(synthetic_setup_failure).promote_on_wire_if(any_request_on_wire);

        assert!(
            !propagated.request_on_wire(),
            "Setup failure with no prior post-wire attempt must remain \
             request_on_wire=false so retry_on_connect_failure can fire"
        );
    }

    #[test]
    fn graceful_close_constructor_marks_post_wire_and_graceful() {
        // The graceful-close constructor is used at the four `recv_response`
        // sites when the backend tore down with `H3_NO_ERROR` /
        // `RemoteClosing`. By definition the request was already sent
        // (post-wire), so retries must respect `retry_on_methods` —
        // matches `post_wire` semantics for the body-on-wire signal.
        // The new flag is what suppresses `mark_h3_unsupported`.
        let e = H3PoolError::graceful_close(anyhow::anyhow!(
            "recv_response after graceful remote close: ApplicationClose"
        ));
        assert!(
            e.request_on_wire(),
            "graceful_close constructor must report request_on_wire=true — \
             the request was committed to the wire before the backend closed"
        );
        assert!(
            e.is_graceful_close(),
            "graceful_close constructor must report is_graceful_close=true \
             so gateway dispatch sites suppress mark_h3_unsupported"
        );
    }

    #[test]
    fn pre_wire_and_post_wire_constructors_do_not_set_graceful_close() {
        // Only the dedicated `graceful_close` constructor sets the flag.
        // Any other failure path (DNS / TLS / send_data / finish) remains
        // a transport failure and must continue to drive the H3 capability
        // downgrade path.
        let pre = H3PoolError::pre_wire(anyhow::anyhow!("connect refused"));
        assert!(!pre.is_graceful_close());

        let post = H3PoolError::post_wire(anyhow::anyhow!("send_data failed"));
        assert!(!post.is_graceful_close());
    }

    #[test]
    fn promote_on_wire_if_preserves_graceful_close_flag() {
        // The pool's internal retry chain pipes errors through
        // `.promote_on_wire_if(any_request_on_wire)` on every fresh-connect
        // setup `?` exit. That helper only modifies `request_on_wire` —
        // a graceful-close error that flows through the chain MUST keep
        // `is_graceful_close()=true` so the gateway suppression still fires.
        let e = H3PoolError::graceful_close(anyhow::anyhow!(
            "recv_response after graceful remote close"
        ));
        let promoted_true = e.promote_on_wire_if(true);
        assert!(promoted_true.is_graceful_close());
        assert!(promoted_true.request_on_wire());

        let e = H3PoolError::graceful_close(anyhow::anyhow!(
            "recv_response after graceful remote close"
        ));
        let promoted_false = e.promote_on_wire_if(false);
        assert!(promoted_false.is_graceful_close());
        // request_on_wire stays true (graceful_close constructor sets it true)
        assert!(promoted_false.request_on_wire());
    }
}

#[cfg(test)]
mod h3_pool_health_tests {
    //! Inline tests for [`Http3PoolManager::is_healthy`] — the bug fix
    //! that motivates this module is described on the manager impl.
    //!
    //! These tests stand up a real local QUIC server + client using rcgen
    //! self-signed certs (no h3 layer needed; we exercise the QUIC layer
    //! exclusively). After establishing a connection, we wrap the
    //! `quinn::Connection` in [`H3PooledConnection`] alongside an h3
    //! `SendRequest`, then verify:
    //!
    //! 1. `is_healthy` returns `true` for a live connection.
    //! 2. After `connection.close(...)`, `is_healthy` flips to `false`
    //!    (because `close_reason()` becomes `Some(_)`).
    //!
    //! That is exactly the predicate the shared cleanup task in
    //! `pool::GenericPool::spawn_cleanup` uses to decide whether an entry
    //! should be evicted before its idle deadline. The previous
    //! implementation returned `true` unconditionally and dead handles
    //! survived until `idle_timeout_seconds`.
    //!
    //! Note on the SendRequest test plumbing: the bug only requires the
    //! `quinn::Connection` half of the pooled struct to be live; the
    //! `H3SendRequest` plays no role in `is_healthy()`. To avoid the full
    //! h3-handshake dance for an in-process unit test (and the matching
    //! peer that needs to drive the H3 control streams), we build the
    //! pool entry by completing only the QUIC handshake on both sides
    //! and constructing a `SendRequest` against the client-side QUIC
    //! connection via `h3::client::new`. The `is_healthy` predicate is
    //! purely a `close_reason()` check, so the SendRequest's own
    //! liveness is irrelevant to this test.

    use super::*;
    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    fn test_pool_manager() -> Http3PoolManager {
        Http3PoolManager {
            backend_svid_generation: Arc::new(AtomicU64::new(0)),
            global_backend_client_cert_path: None,
            workload_svid_cert_path: None,
        }
    }

    fn install_provider() {
        // rustls 0.23 requires a process-wide crypto provider before any
        // `ClientConfig::builder()` / `ServerConfig::builder()` call. The
        // "ring" provider is installed wholesale by the gateway main; in
        // unit tests several test mods may race to install — `_ = ...`
        // ignores the "already installed" return.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn issue_cert() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");

        let cert_pem = cert.pem();
        let mut cert_reader = cert_pem.as_bytes();
        let mut chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader)
                .filter_map(Result::ok)
                .collect();
        let cert_der = chain.pop().expect("at least one cert");

        let key_pem = key_pair.serialize_pem();
        let mut key_reader = key_pem.as_bytes();
        let key_der = rustls_pemfile::private_key(&mut key_reader)
            .expect("read private key")
            .expect("private key present");

        (cert_der, key_der)
    }

    fn make_server_endpoint(addr: SocketAddr) -> Endpoint {
        let (cert, key) = issue_cert();

        let mut server_crypto =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config");
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("quic server config");
        let server_config = ServerConfig::with_crypto(Arc::new(quic_server));

        Endpoint::server(server_config, addr).expect("server endpoint")
    }

    fn make_client_endpoint() -> Endpoint {
        // Trust any cert — this is a localhost-only loopback test.
        #[derive(Debug)]
        struct AcceptAny;
        impl rustls::client::danger::ServerCertVerifier for AcceptAny {
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
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                ]
            }
        }

        let mut client_crypto =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny))
                .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("quic client config");
        let client_config = ClientConfig::new(Arc::new(quic_client));

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .expect("client endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    /// Drive a real QUIC handshake on loopback and return both peer
    /// connections so the caller can manipulate either side.
    async fn handshake_pair() -> (quinn::Connection, quinn::Connection, Endpoint, Endpoint) {
        install_provider();

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = make_server_endpoint(server_addr);
        let bound = server.local_addr().expect("server bound");

        let client = make_client_endpoint();

        // Race the client connect against the server accept — both must
        // succeed. quinn doesn't expose a single-call `connect_pair`.
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server_clone.accept().await.expect("server accept");
            incoming.await.expect("server connection")
        });

        let client_conn = client
            .connect(bound, "localhost")
            .expect("client connect_with")
            .await
            .expect("client connection");
        let server_conn = server_task.await.expect("server task");

        (client_conn, server_conn, client, server)
    }

    #[tokio::test]
    async fn pool_manager_reports_live_connection_healthy() {
        let (client_conn, _server_conn, _client_ep, _server_ep) = handshake_pair().await;

        // Build an h3 client SendRequest off the live QUIC connection.
        // The `_driver` task processes h3 control frames; we don't need
        // to drive it because is_healthy() inspects only the QUIC
        // close_reason — h3 protocol state is irrelevant.
        let h3_conn = h3_quinn::Connection::new(client_conn.clone());
        let (mut driver, send_request) =
            h3::client::new(h3_conn).await.expect("h3 client handshake");
        let driver_handle = tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let pooled = H3PooledConnection::new(send_request, client_conn);
        let manager = test_pool_manager();

        assert!(
            manager.is_healthy(&pooled),
            "freshly-handshaken QUIC connection must report healthy"
        );

        driver_handle.abort();
    }

    #[tokio::test]
    async fn pool_manager_reports_closed_connection_unhealthy() {
        let (client_conn, _server_conn, _client_ep, _server_ep) = handshake_pair().await;

        let h3_conn = h3_quinn::Connection::new(client_conn.clone());
        let (mut driver, send_request) =
            h3::client::new(h3_conn).await.expect("h3 client handshake");
        let driver_handle = tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let pooled = H3PooledConnection::new(send_request, client_conn.clone());
        let manager = test_pool_manager();

        // Sanity: live before close.
        assert!(manager.is_healthy(&pooled));

        // Initiate local close and wait for `close_reason()` to surface.
        // `Connection::close` is fire-and-forget at the API level; the
        // close_reason is set synchronously inside the connection's
        // shared state so a single read suffices, but loop briefly to
        // tolerate any internal scheduling.
        client_conn.close(0u32.into(), b"test");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if !manager.is_healthy(&pooled) {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "expected is_healthy=false after close(), got true (close_reason={:?})",
                    client_conn.close_reason()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Final check — the predicate stayed false (no flapping).
        assert!(!manager.is_healthy(&pooled));

        driver_handle.abort();
    }

    /// Regression for the original bug: an entry whose underlying QUIC
    /// connection has been closed must be evicted from the shared pool
    /// shell (`pool::GenericPool`), BEFORE the idle-timeout would
    /// otherwise fire. Previously `Http3PoolManager::is_healthy`
    /// returned `true` unconditionally, so closed entries lingered until
    /// `idle_timeout_seconds` elapsed and the next request to that key
    /// fetched a dead handle.
    ///
    /// Two eviction paths share the same `is_healthy` predicate:
    ///   1. The background cleanup task in `spawn_cleanup` (interval-driven).
    ///   2. The synchronous `cached()` lookup (which invalidates and
    ///      returns `None` when `is_healthy` returns `false`).
    ///
    /// Both paths are valid eviction mechanisms; what matters for the
    /// regression is that NEITHER returned a dead handle once the
    /// connection had closed. The previous unconditional `true` broke
    /// both paths simultaneously. This test asserts the cumulative
    /// behaviour: after `client_conn.close()`, `pool.cached(&key)`
    /// stops returning the entry within a tight bound — a behaviour
    /// the bugged implementation could not satisfy because the cleanup
    /// task ignored closed entries AND `cached()` always saw
    /// `is_healthy=true` and returned the dead handle.
    #[tokio::test]
    async fn closed_connection_is_evicted_from_pool() {
        use crate::config::PoolConfig;
        use crate::pool::GenericPool;

        let (client_conn, _server_conn, _client_ep, _server_ep) = handshake_pair().await;

        let h3_conn = h3_quinn::Connection::new(client_conn.clone());
        let (mut driver, send_request) =
            h3::client::new(h3_conn).await.expect("h3 client handshake");
        let driver_handle = tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // Long idle timeout so any eviction observed within the test
        // window can only come from `is_healthy=false`, never from the
        // timeout branch. Tight cleanup interval just keeps the test fast.
        let pool_cfg = PoolConfig {
            idle_timeout_seconds: 3600,
            max_idle_per_host: 1,
            ..PoolConfig::default()
        };
        let pool = GenericPool::new(
            Arc::new(test_pool_manager()),
            pool_cfg,
            Duration::from_millis(50),
            64,
        );

        let key = "evict-test-key".to_string();
        let pooled = H3PooledConnection::new(send_request, client_conn.clone());

        // Seed the pool with this entry. Use the explicit-create path
        // because Http3PoolManager::create() returns an error by design
        // (H3 needs per-call TLS / h3 config — see the manager docstring).
        pool.create_or_get_existing_owned::<_, _, anyhow::Error>(key.clone(), |_| {
            let pooled = pooled.clone();
            async move { Ok(pooled) }
        })
        .await
        .expect("seed pool");

        // While the connection is live, cached() returns the entry.
        // (Sanity check: this would also have passed under the old buggy
        // is_healthy=true, so it is NOT a regression guard on its own —
        // the next loop is what proves the fix.)
        assert!(pool.cached(&key).is_some(), "live entry present");

        // Close the underlying QUIC connection. `is_healthy` MUST flip
        // to false (via `connection.close_reason() == Some(...)`) and
        // the pool MUST stop handing out the dead entry. The previous
        // implementation returned `true` unconditionally and `cached()`
        // would keep returning the dead handle indefinitely.
        client_conn.close(0u32.into(), b"test-close");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if pool.cached(&key).is_none() {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "pool kept returning dead QUIC entry 2s after close — \
                     Http3PoolManager::is_healthy regression? \
                     close_reason={:?}",
                    client_conn.close_reason()
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        driver_handle.abort();
    }
}
