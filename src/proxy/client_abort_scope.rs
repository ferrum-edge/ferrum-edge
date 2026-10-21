//! Terminal accounting for an admitted H1/H2 request whose handler future is
//! dropped before it produced a response (issue #6768).
//!
//! hyper drops a pending service future when an HTTP/2 client resets the stream
//! (`RST_STREAM`) and when an HTTP/1.1 client closes its connection while the
//! handler is still waiting. Nothing async runs on that path: only `Drop`
//! implementations do. Every terminal record the handler emits itself
//! (`record_request`, the plugin `log` chain through `log_with_mirror`, the
//! runtime terminal outcome) sits on a code path the drop skips, so a request
//! cancelled during its upload, its plugin phases, backend acquisition, the
//! WebSocket upgrade handshake, or the wait for backend response headers used
//! to leave no terminal record at all. Only its `RequestGuard` was released.
//!
//! [`ClientAbortScope`] closes that gap. The request handler's
//! [`RequestContext`] lives in the scope and the handler borrows it, so the
//! context is still intact when hyper drops the handler. The scope's `Drop`
//! then settles the request's terminal exactly once, according to how far the
//! request's own terminal record had got
//! ([`crate::plugins::TerminalRecordState`]) and WHY the handler was dropped
//! ([`TerminationCause`]):
//!
//! * **Not started** — one terminal record (status counter, and with a plugin
//!   chain a `TransactionSummary` handed to the bounded terminal delivery the
//!   streaming terminal uses, since `Drop` cannot await a plugin):
//!   * `499` client abort only on positive evidence of a PEER-originated
//!     cancellation: the HTTP/2 peer's `RST_STREAM` / `GOAWAY` or a lost
//!     transport, as the vendored hyper reports it while it drops the stream
//!     (Hyper patch 006), or an HTTP/1.1 dispatcher dropping an in-flight
//!     request, which it does only on the client's EOF or I/O error.
//!   * `400` when hyper's own HTTP/2 stack reset the stream for a protocol
//!     violation in what the peer sent.
//!   * `444` (nginx's "closed without response") when the gateway itself
//!     ended the connection — withdrawn client-certificate trust, an
//!     authorization-lifetime close a sibling stream triggered, or shutdown
//!     teardown after the drain wait — or when no cause could be attributed.
//!
//!   All three are logs-and-metrics vocabulary: nothing is written to the
//!   client. A request the handler had already counted is not counted again.
//! * **In flight** — the request's own terminal summary was being logged.
//!   `log_with_mirror` hands the sinks that had not started, the runtime
//!   counters, and the mirrors to detached delivery when it is dropped, so the
//!   summary arrives at most once per sink; the scope settles only the status
//!   count, if the handler had not taken it yet.
//! * **Finished** — nothing is owed.
//!
//! Backend health is untouched: no backend outcome exists, the half-open probe
//! and backend admission guards the handler owned already released neutrally
//! when the handler was dropped, and nothing here reaches a circuit breaker,
//! passive health, or retry budget. A status the transport already committed
//! is never rewritten (RFC 9112 §8): once hyper has the response, its body owns
//! the terminal (`DeferredTransactionLogger`) and this scope has settled.
//!
//! The scope never records twice. Normal completion calls
//! [`ClientAbortScope::complete`] in the same poll the handler returns in,
//! before hyper sees the response. The one handler that needs the context by
//! value, the streaming terminal logger, takes it with
//! [`ClientAbortScope::hand_off`] and owns the terminal from then on. A handler
//! unwinding from a panic records nothing. Requests the frontend refused before
//! admission never reach a scope, so a connection that closes without an
//! admitted request never becomes a transaction record.
//!
//! Cost on the request path: one `Arc<ProxyState>` clone at install, one
//! plugin-chain `Arc` clone when the request has plugins, and a few word-sized
//! stores. The context itself is not cloned, and no allocation or lock is
//! added. Summaries are built only on the cancellation path.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::plugins::{
    LATENCY_UNKNOWN_MS, Plugin, RequestContext, ResponseDelivery, TerminalRecordState,
    TransactionSummary,
};
use crate::proxy::ProxyState;
use crate::proxy::grpc_proxy::{CLIENT_CLOSED_REQUEST_STATUS, grpc_status};
use crate::retry::ErrorClass;
use crate::runtime_metrics::TerminalOutcome;

/// `rejection_phase` on the client-abort transaction record.
pub const CLIENT_ABORT_REJECTION_PHASE: &str = "client_disconnect_before_response";

/// `rejection_phase` on the record of a request hyper's HTTP/2 stack reset for
/// a protocol violation by the peer.
pub const PROTOCOL_RESET_REJECTION_PHASE: &str = "protocol_error_before_response";

/// Status recorded for an admitted request whose connection the gateway itself
/// closed before any response head, or whose drop has no attributable cause:
/// nginx's `444` ("connection closed without response"). Logging and metrics
/// vocabulary only; it is never sent.
pub const GATEWAY_CLOSED_REQUEST_STATUS: u16 = 444;

/// Status recorded for a request the local HTTP/2 stack reset because the peer
/// violated the protocol. Logging and metrics vocabulary only.
pub const PROTOCOL_RESET_REQUEST_STATUS: u16 = 400;

/// Why an admitted H1/H2 request handler was dropped before its response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationCause {
    /// The peer cancelled: an HTTP/2 `RST_STREAM` / `GOAWAY` from the client,
    /// a lost client transport, or an HTTP/1.1 client EOF.
    PeerCancelled,
    /// The local HTTP/2 stack reset the stream or connection because what the
    /// peer sent violated the protocol.
    LocalProtocolReset,
    /// The connection's client-certificate trust was withdrawn.
    ClientTrustWithdrawn,
    /// A sibling stream outlived its authorization and the gateway closed the
    /// shared connection. This request's own authorization did not fail.
    AuthorizationConnectionClose,
    /// Shutdown stopped waiting for in-flight work and tore the handler down.
    ShutdownTeardown,
    /// No cause could be attributed.
    Unattributed,
}

impl TerminationCause {
    /// The `rejection_phase` on the transaction record.
    pub fn rejection_phase(self) -> &'static str {
        match self {
            Self::PeerCancelled => CLIENT_ABORT_REJECTION_PHASE,
            Self::LocalProtocolReset => PROTOCOL_RESET_REJECTION_PHASE,
            Self::ClientTrustWithdrawn => "gateway_close_client_trust_withdrawn",
            Self::AuthorizationConnectionClose => "gateway_close_authorization_lifetime",
            Self::ShutdownTeardown => "gateway_close_shutdown",
            Self::Unattributed => "connection_closed_before_response",
        }
    }

    /// The status the transaction record and counters carry.
    pub fn status(self) -> u16 {
        match self {
            Self::PeerCancelled => CLIENT_CLOSED_REQUEST_STATUS,
            Self::LocalProtocolReset => PROTOCOL_RESET_REQUEST_STATUS,
            Self::ClientTrustWithdrawn
            | Self::AuthorizationConnectionClose
            | Self::ShutdownTeardown
            | Self::Unattributed => GATEWAY_CLOSED_REQUEST_STATUS,
        }
    }

    fn error_class(self) -> Option<ErrorClass> {
        match self {
            Self::PeerCancelled => Some(ErrorClass::ClientDisconnect),
            Self::LocalProtocolReset => Some(ErrorClass::ProtocolError),
            _ => None,
        }
    }

    fn grpc_terminal(self) -> (u32, &'static str) {
        match self {
            // The client's own cancellation, even when a backend outcome was
            // already copied into the context: the client never received it.
            Self::PeerCancelled => (
                grpc_status::CANCELLED,
                super::GRPC_CLIENT_DISCONNECT_MESSAGE,
            ),
            // gRPC maps an HTTP/2 PROTOCOL_ERROR stream reset to INTERNAL.
            Self::LocalProtocolReset => (grpc_status::INTERNAL, "HTTP/2 protocol error"),
            Self::ClientTrustWithdrawn => (
                grpc_status::UNAUTHENTICATED,
                "Client certificate trust withdrawn",
            ),
            // Collateral connection loss: this request's credentials did not
            // fail, so it is UNAVAILABLE, never UNAUTHENTICATED.
            Self::AuthorizationConnectionClose => {
                (grpc_status::UNAVAILABLE, "Connection closed by the gateway")
            }
            Self::ShutdownTeardown => (grpc_status::UNAVAILABLE, "Gateway shutting down"),
            Self::Unattributed => (grpc_status::UNAVAILABLE, "Connection closed"),
        }
    }
}

/// Owner of an admitted H1/H2 request's [`RequestContext`] for the lifetime of
/// its handler. See the [module documentation](self).
///
/// The H1/H2 frontend creates one per admitted request, next to the handler
/// future and in the same allocation, and calls [`Self::complete`] when the
/// handler returns. Dropping the scope without either `complete` or
/// [`Self::hand_off`] settles the request's terminal.
pub struct ClientAbortScope {
    ctx: Option<RequestContext>,
    record: ClientAbortRecord,
    settled: bool,
}

/// What the handler tells the scope as it learns it, borrowed beside the
/// context so neither borrow blocks the other. Everything here is only read
/// on the cancellation path.
pub struct ClientAbortRecord {
    state: Option<Arc<ProxyState>>,
    start_time: Option<Instant>,
    /// Whether the request arrived over HTTP/2, whose stream terminations
    /// hyper attributes explicitly (Hyper patch 006).
    http2: bool,
    plugins: Option<Arc<Vec<Arc<dyn Plugin>>>>,
    client_request_path: Option<String>,
}

impl Default for ClientAbortScope {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientAbortScope {
    /// An empty scope. Nothing is recorded until [`Self::install`] runs.
    pub const fn new() -> Self {
        Self {
            ctx: None,
            record: ClientAbortRecord {
                state: None,
                start_time: None,
                http2: false,
                plugins: None,
                client_request_path: None,
            },
            settled: false,
        }
    }

    /// Take ownership of the request's context and return the handler's
    /// borrow of it, together with the record the handler fills in as it
    /// learns the request's route.
    ///
    /// `start_time` is the instant the handler first saw the request, so the
    /// terminal record's `latency_total_ms` covers the same span as every
    /// other terminal record. `version` is the frontend wire version, which
    /// decides how a drop is attributed.
    pub fn install(
        &mut self,
        state: &Arc<ProxyState>,
        start_time: Instant,
        version: http::Version,
        ctx: RequestContext,
    ) -> (&mut RequestContext, &mut ClientAbortRecord) {
        self.record.state = Some(Arc::clone(state));
        self.record.start_time = Some(start_time);
        self.record.http2 = version == http::Version::HTTP_2;
        (self.ctx.insert(ctx), &mut self.record)
    }

    /// Move the context out to the owner that now accounts for the request's
    /// terminal record. `None` only if no context was installed.
    pub fn hand_off(&mut self) -> Option<RequestContext> {
        self.ctx.take()
    }

    /// The handler returned. Its response, or the owner it handed the
    /// context to, accounts for the terminal record; release the context
    /// now, where the handler used to drop it.
    pub fn complete(&mut self) {
        self.settled = true;
        self.ctx = None;
        self.record.plugins = None;
        self.record.client_request_path = None;
        self.record.state = None;
    }

    /// Whether the scope still owns an installed context.
    pub fn is_installed(&self) -> bool {
        self.ctx.is_some()
    }
}

impl ClientAbortRecord {
    /// The plugin chain the handler resolved for this request. An empty chain
    /// is not retained: there is no `log` to call, so a cancelled request
    /// records its counters alone.
    pub fn observe_plugins(&mut self, plugins: &Arc<Vec<Arc<dyn Plugin>>>) {
        self.plugins = if plugins.is_empty() {
            None
        } else {
            Some(Arc::clone(plugins))
        };
    }

    /// The path the client requested, retained only once a route override has
    /// rebased `RequestContext::path` to the backend path. Every other request
    /// logs `RequestContext::path`, which still is the client's path.
    pub fn retain_client_request_path(&mut self, path: &str) {
        if self.client_request_path.as_deref() != Some(path) {
            self.client_request_path = Some(path.to_owned());
        }
    }

    fn settle(
        &mut self,
        ctx: RequestContext,
        h2_termination: Option<hyper::ext::H2StreamTermination>,
    ) {
        let Some(state) = self.state.take() else {
            return;
        };
        let counted = ctx.terminal_status_counted();
        match ctx.terminal_record_state() {
            TerminalRecordState::Finished => {}
            // The summary's unstarted sinks and runtime counters continue in
            // detached delivery; the status count the handler takes after its
            // log is what the drop skipped, unless it was taken already.
            TerminalRecordState::InFlight { status } => {
                if !counted {
                    super::record_request(&state, status);
                }
            }
            TerminalRecordState::NotStarted => {
                let cause = termination_cause(&ctx, &state, self.http2, h2_termination);
                self.record_terminal(&state, ctx, cause, counted);
            }
        }
    }

    fn record_terminal(
        &mut self,
        state: &ProxyState,
        ctx: RequestContext,
        cause: TerminationCause,
        counted: bool,
    ) {
        if !counted {
            super::record_request(state, cause.status());
        }
        let Some(plugins) = self.plugins.take() else {
            if counted {
                return;
            }
            crate::runtime_metrics::global_ref().record_terminal_outcome(TerminalOutcome {
                proxy_id: ctx.matched_proxy.as_ref().map(|proxy| proxy.id.as_str()),
                grpc: crate::runtime_metrics::terminal_metadata_is_grpc(&ctx.metadata),
                error_class: cause.error_class(),
                body_error_class: None,
                client_disconnected: cause == TerminationCause::PeerCancelled,
            });
            return;
        };
        let mut summary = self.terminal_summary(
            &ctx,
            cause.status(),
            cause.rejection_phase(),
            cause.grpc_terminal(),
        );
        summary.client_disconnected = cause == TerminationCause::PeerCancelled;
        summary.error_class = cause.error_class();
        deliver(plugins, summary, ctx);
    }

    fn terminal_summary(
        &self,
        ctx: &RequestContext,
        status: u16,
        rejection_phase: &str,
        grpc_terminal: (u32, &str),
    ) -> TransactionSummary {
        let proxy = ctx.matched_proxy.as_deref();
        let latency_total_ms = self.start_time.map_or(LATENCY_UNKNOWN_MS, |start| {
            start.elapsed().as_secs_f64() * 1000.0
        });
        let mut metadata = super::clone_log_metadata(ctx);
        metadata.insert("rejection_phase".to_string(), rejection_phase.to_string());
        // Whatever gRPC status the handler had already copied into the context
        // (a backend's trailers, for instance) never reached the client; the
        // terminal is the one this scope decided.
        if metadata
            .get("request_protocol")
            .is_some_and(|protocol| protocol == "grpc")
        {
            let (code, message) = grpc_terminal;
            super::insert_grpc_error_metadata(&mut metadata, code, message);
        }
        TransactionSummary {
            namespace: proxy
                .map(|proxy| proxy.namespace.clone())
                .unwrap_or_else(crate::config::types::default_namespace),
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.effective_identity().map(str::to_owned),
            auth_method: ctx.auth_method,
            http_method: ctx.method.clone(),
            request_path: self
                .client_request_path
                .clone()
                .unwrap_or_else(|| ctx.path.clone()),
            proxy_id: proxy.map(|proxy| proxy.id.clone()),
            proxy_name: proxy.and_then(|proxy| proxy.name.clone()),
            backend_target: proxy.and_then(|proxy| {
                let url = super::rejected_request_backend_url(proxy, ctx)?;
                Some(super::strip_query_params(&url).to_string())
            }),
            response_status_code: status,
            latency_total_ms,
            // The handler's phase timers died with it, and a backend exchange
            // in flight at the drop has no separable duration.
            latency_gateway_processing_ms: LATENCY_UNKNOWN_MS,
            latency_backend_ttfb_ms: LATENCY_UNKNOWN_MS,
            latency_backend_total_ms: LATENCY_UNKNOWN_MS,
            latency_plugin_execution_ms: LATENCY_UNKNOWN_MS,
            latency_plugin_external_io_ms: ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64
                / 1_000_000.0,
            latency_gateway_overhead_ms: LATENCY_UNKNOWN_MS,
            request_user_agent: ctx.headers.get("user-agent").cloned(),
            // The transport ended the request before any response head; that
            // is the boundary this record describes.
            response_delivery: ResponseDelivery::Observed,
            bytes_sent: ctx.bytes_sent_observed.load(Ordering::Acquire),
            grpc_request_messages: ctx.grpc_request_messages_observed.load(Ordering::Acquire),
            grpc_response_messages: ctx.grpc_response_messages_observed.load(Ordering::Acquire),
            metadata,
            ai_usage_export: ctx.ai_usage_export.clone(),
            proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
            ..TransactionSummary::default()
        }
    }
}

/// Hand one terminal summary to bounded detached terminal delivery.
fn deliver(
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    summary: TransactionSummary,
    mut ctx: RequestContext,
) {
    // The bounded admissions the context still holds end with the request,
    // not with the detached log task.
    ctx.release_leases_before_terminal_handoff();
    let _ = crate::observability_delivery::spawn_terminal(async move {
        crate::plugins::log_with_mirror(plugins.as_slice(), &summary, &ctx).await;
    });
}

/// Attribute a dropped handler (see [`TerminationCause`]).
///
/// Gateway-initiated connection closes come first: their teardown also loses
/// the transport underneath the stream, which must not read as the peer's.
/// Then the HTTP/2 termination hyper published while dropping the stream
/// (Hyper patch 006), which separates the peer's reset from the local stack's.
/// An HTTP/1.1 dispatcher drops an in-flight request only on the client's EOF
/// or I/O error, every gateway-initiated HTTP/1.1 close being one of the
/// causes checked first. Anything else is unattributed and never labelled a
/// client cancellation.
fn termination_cause(
    ctx: &RequestContext,
    state: &ProxyState,
    http2: bool,
    h2_termination: Option<hyper::ext::H2StreamTermination>,
) -> TerminationCause {
    if ctx
        .client_trust_session
        .as_ref()
        .is_some_and(crate::tls::ClientTrustSession::is_retired)
    {
        return TerminationCause::ClientTrustWithdrawn;
    }
    if ctx
        .authorization_connection_closer
        .as_ref()
        .is_some_and(crate::proxy::auth_lifetime::AuthorizationConnectionCloser::close_requested)
    {
        return TerminationCause::AuthorizationConnectionClose;
    }
    if state.overload.drain_wait_ended.load(Ordering::Acquire) {
        return TerminationCause::ShutdownTeardown;
    }
    if http2 {
        return match h2_termination {
            Some(
                hyper::ext::H2StreamTermination::PeerReset { .. }
                | hyper::ext::H2StreamTermination::TransportLost,
            ) => TerminationCause::PeerCancelled,
            Some(hyper::ext::H2StreamTermination::LocalReset { .. }) => {
                TerminationCause::LocalProtocolReset
            }
            // `H2StreamTermination` is non-exhaustive; an unknown cause, or
            // none, is not evidence of the peer's cancellation.
            Some(_) | None => TerminationCause::Unattributed,
        };
    }
    TerminationCause::PeerCancelled
}

impl Drop for ClientAbortScope {
    fn drop(&mut self) {
        // A handler unwinding from a panic was not cancelled by its client.
        if self.settled || std::thread::panicking() {
            return;
        }
        // Take hyper's HTTP/2 termination cause even when nothing is owed, so
        // it can never be read by an unrelated drop.
        let h2_termination = hyper::ext::take_h2_stream_termination();
        let Some(ctx) = self.ctx.take() else {
            return;
        };
        self.record.settle(ctx, h2_termination);
    }
}
