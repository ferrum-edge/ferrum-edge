//! The one terminal convention for a proven client-origin abort (issue #6772).
//!
//! A client that resets its request stream, sends `STOP_SENDING` on the
//! response, or loses its connection before the gateway commits response
//! headers has cancelled the request. Every HTTP-family path (H1/H2 buffered
//! intake, native HTTP/3, the HTTP/3 bridges, and native gRPC) records that
//! terminal the same way:
//!
//! * HTTP transaction logs and request metrics record nginx-style
//!   `499 Client Closed Request`. This is logging vocabulary only: the gateway
//!   never writes a `499` to a client that has already gone.
//! * Native gRPC outcome accounting records `CANCELLED` (1), never
//!   `UNAVAILABLE` (14): the client cancelled the RPC, the service did not
//!   fail.
//! * The transaction's `error_class` is `ClientDisconnect` and its
//!   `client_disconnected` flag is set.
//! * Backend health stays neutral. `ClientDisconnect` is a
//!   `client_side_no_backend_signal` class, so the circuit breaker, passive
//!   health, least-latency sampling, and the adaptive-concurrency limiter all
//!   skip the outcome.
//!
//! After response headers are committed, the committed status stands. A later
//! client abort only marks the transaction `client_disconnected` and
//! incomplete. A gRPC status is not committed until the trailers, so a native
//! gRPC RPC whose client aborts its upload mid-response still ends `CANCELLED`.
//!
//! The terminal is reached through a [`ProvenClientAbort`], never through
//! `ErrorClass::ClientDisconnect` alone. That class also marks health-neutral
//! terminals the gateway itself chose while the client may still be connected
//! (a client RPC deadline, an expired authorization lifetime, a stalled
//! upload), and those keep their own `504` / `401` / `DEADLINE_EXCEEDED`
//! accounting. A read failure is classified positively
//! (`crate::http3::stream_util::classify_h3_request_read_error`): a request that
//! violated HTTP/3 framing is malformed input (`400` / `INVALID_ARGUMENT`), and a
//! stream or connection the gateway ended itself is
//! [`GATEWAY_CLOSED_UPLOAD_TERMINAL`], never a client abort.

use crate::retry::ErrorClass;

/// nginx's non-standard `499 Client Closed Request`, recorded for a client
/// that went away before response headers were committed.
pub const CLIENT_CLOSED_REQUEST_STATUS: u16 = 499;

/// The gRPC status recorded for a client-cancelled RPC.
pub const CLIENT_ABORT_GRPC_STATUS: u32 = crate::proxy::grpc_proxy::grpc_status::CANCELLED;

/// Fixed `grpc-message` / log message for a client-cancelled request. Compiled
/// in: it echoes nothing from the client's transport error.
pub const CLIENT_ABORT_MESSAGE: &str = "Client disconnected";

/// Fixed JSON body the H1/H2 handlers attach to a `499` rejection response
/// (hyper discards it when the client is gone).
pub const CLIENT_ABORT_HTTP_BODY: &str = r#"{"error":"Client disconnected"}"#;

/// Fixed JSON body for a client upload refused as malformed before the backend
/// response head: `400`, never `499` (issues #6772, #6776).
pub const MALFORMED_UPLOAD_HTTP_BODY: &str = r#"{"error":"Malformed request body"}"#;

/// Fixed `grpc-message` for the same refusal on a gRPC-flavored request
/// (`INVALID_ARGUMENT`).
pub const MALFORMED_UPLOAD_GRPC_MESSAGE: &str = "Malformed request body";

/// Terminal accounting for a proven client abort before response headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAbortTerminal {
    /// Status for HTTP logs and request metrics.
    pub http_status: u16,
    /// gRPC outcome for a native gRPC RPC.
    pub grpc_status: u32,
    /// Fixed `grpc-message` for that outcome.
    pub grpc_message: &'static str,
    /// The transaction's error class; health-neutral.
    pub error_class: ErrorClass,
    /// The transaction's `client_disconnected` flag.
    pub client_disconnected: bool,
}

/// The one pre-header client-abort terminal every path records.
pub const PRE_HEADER_CLIENT_ABORT_TERMINAL: ClientAbortTerminal = ClientAbortTerminal {
    http_status: CLIENT_CLOSED_REQUEST_STATUS,
    grpc_status: CLIENT_ABORT_GRPC_STATUS,
    grpc_message: CLIENT_ABORT_MESSAGE,
    error_class: ErrorClass::ClientDisconnect,
    client_disconnected: true,
};

/// Terminal for a request stream the GATEWAY ended before response headers:
/// its own graceful or error close, a local QUIC failure, or a cause that is not
/// observable. Not a client abort and not a backend fault, so backend health
/// stays neutral, but it is logged as the gateway's `503` / `UNAVAILABLE` with
/// `client_disconnected` unset. Nothing is written to the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayClosedUploadTerminal {
    /// Status for HTTP logs and request metrics.
    pub http_status: u16,
    /// gRPC outcome for a native gRPC RPC.
    pub grpc_status: u32,
    /// Fixed `grpc-message` for that outcome.
    pub grpc_message: &'static str,
}

/// The one gateway-closed upload terminal every streamed path records.
pub const GATEWAY_CLOSED_UPLOAD_TERMINAL: GatewayClosedUploadTerminal =
    GatewayClosedUploadTerminal {
        http_status: 503,
        grpc_status: crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE,
        grpc_message: "Request stream closed by the gateway",
    };

/// Evidence that the client, not the gateway or the backend, ended a request.
///
/// Only the constructors below mint one, each named for the evidence it
/// stands for, so a terminal that reports `499` / `CANCELLED` can always be
/// traced back to an observed client action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenClientAbort {
    _evidence: (),
}

impl ProvenClientAbort {
    /// A failed read of the client's HTTP/3 request stream that the client
    /// caused: a peer reset with any code (`H3_NO_ERROR` included), or a
    /// connection the peer closed. The classifier is the one every
    /// buffered drain and streamed upload uses, so buffered and streamed uploads
    /// can never disagree about the same error. Malformed input and a stream or
    /// connection the gateway ended itself return `None`.
    pub fn from_h3_request_read_error(error: &h3::error::StreamError) -> Option<Self> {
        crate::http3::stream_util::h3_request_read_error_is_client_abort(error)
            .then_some(Self { _evidence: () })
    }

    /// The client's response direction or connection ended while the gateway
    /// still owed it a response head. `peer_stop_sending` is true when the
    /// client sent `STOP_SENDING` on the response, which only the client can
    /// do. Otherwise the connection ended, and only a close the peer sent or a
    /// stateless reset is the client's (an idle-timeout expiry is local)
    /// ([`crate::plugins::PeerConnectionSignal::closed_by_peer`]); the gateway's
    /// own close returns `None`.
    pub fn from_response_cancellation(
        peer_stop_sending: bool,
        peer: Option<&crate::plugins::PeerConnectionSignal>,
    ) -> Option<Self> {
        let proven = peer_stop_sending
            || peer.is_some_and(|signal| signal.is_closed() && signal.closed_by_peer());
        proven.then_some(Self { _evidence: () })
    }

    /// The client's connection is already closed, and the client closed it: a
    /// close it sent or a stateless reset
    /// ([`crate::plugins::PeerConnectionSignal::closed_by_peer`]). Terminal
    /// decision points consult this before recording an unproven
    /// gateway-closed cause, because a request-stream read on a connection
    /// the client closed can fail as an unclassified closed stream rather
    /// than as the connection error itself. The gateway's own close, an
    /// idle-timeout expiry, and an open connection return `None`.
    pub fn from_peer_connection(
        peer: Option<&crate::plugins::PeerConnectionSignal>,
    ) -> Option<Self> {
        peer.is_some_and(|signal| signal.is_closed() && signal.closed_by_peer())
            .then_some(Self { _evidence: () })
    }

    /// A client abort already proven by typed evidence and carried across a
    /// task or a typed latch: an upload fault the shared H3 read-failure
    /// classifier accepted (a pump's fault, a reader's failure code, a typed
    /// pool error), or an H1/H2 relayed upload terminal attributed by
    /// `upload_pump::pre_header_send_termination` (issue #6776). Mint it only
    /// behind such a latch.
    pub const fn latched_upload_abort() -> Self {
        Self { _evidence: () }
    }

    /// The terminal to record when the abort came before response headers.
    pub const fn pre_header_terminal(self) -> ClientAbortTerminal {
        PRE_HEADER_CLIENT_ABORT_TERMINAL
    }
}
