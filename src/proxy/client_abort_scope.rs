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
//! ([`crate::plugins::TerminalRecordState`]):
//!
//! * **Not started, client cancellation** — `record_request(499)` (the nginx
//!   client-closed-request status, logs and metrics only: nothing is written to
//!   the departed client) and, with a plugin chain, one `TransactionSummary`
//!   with `499`, `error_class: client_disconnect`, `client_disconnected:
//!   true`, `response_delivery: observed`, rejection phase
//!   [`CLIENT_ABORT_REJECTION_PHASE`], and gRPC `CANCELLED` for a gRPC
//!   request, handed to the bounded terminal delivery the streaming terminal
//!   uses (`Drop` cannot await a plugin). Without a chain, the runtime terminal
//!   outcome the summary would have fed.
//! * **Not started, gateway close** — the gateway itself is tearing the
//!   connection down (withdrawn client-certificate trust, an
//!   authorization-lifetime close, or shutdown drain), so the drop proves no
//!   client cancellation. The request is settled as
//!   [`GATEWAY_CLOSED_REQUEST_STATUS`] (`444`, nginx's "closed without a
//!   response"; again logs and metrics only) with a `gateway_close_*`
//!   rejection phase naming the cause and no client-disconnect claim.
//! * **In flight** — the request's own terminal summary was being logged.
//!   `log_with_mirror` hands its remaining sinks, the runtime counters, and
//!   the mirrors to detached delivery when it is dropped, so the summary still
//!   arrives once; the scope settles only the status count the handler takes
//!   right after that log, with the status the summary carries.
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

/// Status recorded for an admitted request whose connection the gateway itself
/// closed before any response head: nginx's `444` ("connection closed without
/// response"). Logging and metrics vocabulary only; it is never sent.
pub const GATEWAY_CLOSED_REQUEST_STATUS: u16 = 444;

/// Why the gateway, not the client, ended a request before its response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayCloseCause {
    /// The connection's client-certificate trust was withdrawn.
    ClientTrustWithdrawn,
    /// An authenticated stream on the connection outlived its authorization
    /// and the gateway closed the connection.
    AuthorizationLifetime,
    /// Shutdown drain had begun, so the gateway may be tearing the handler down
    /// itself and a client cancellation cannot be proven.
    Shutdown,
}

impl GatewayCloseCause {
    /// The `rejection_phase` on the gateway-close transaction record.
    pub fn rejection_phase(self) -> &'static str {
        match self {
            Self::ClientTrustWithdrawn => "gateway_close_client_trust_withdrawn",
            Self::AuthorizationLifetime => "gateway_close_authorization_lifetime",
            Self::Shutdown => "gateway_close_shutdown",
        }
    }

    fn grpc_terminal(self) -> (u32, &'static str) {
        match self {
            Self::ClientTrustWithdrawn => (
                grpc_status::UNAUTHENTICATED,
                "Client certificate trust withdrawn",
            ),
            Self::AuthorizationLifetime => (
                grpc_status::UNAUTHENTICATED,
                "Connection closed at authorization lifetime",
            ),
            Self::Shutdown => (grpc_status::UNAVAILABLE, "Gateway shutting down"),
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
    /// other terminal record.
    pub fn install(
        &mut self,
        state: &Arc<ProxyState>,
        start_time: Instant,
        ctx: RequestContext,
    ) -> (&mut RequestContext, &mut ClientAbortRecord) {
        self.record.state = Some(Arc::clone(state));
        self.record.start_time = Some(start_time);
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

    fn settle(&mut self, ctx: RequestContext) {
        let Some(state) = self.state.take() else {
            return;
        };
        match ctx.terminal_record_state() {
            TerminalRecordState::Finished => {}
            // The summary's remaining sinks and runtime counters continue in
            // detached delivery; the status count the handler takes after its
            // log is what the drop skipped.
            TerminalRecordState::InFlight { status } => super::record_request(&state, status),
            TerminalRecordState::NotStarted => match gateway_close_cause(&ctx, &state) {
                Some(cause) => self.record_gateway_close(&state, ctx, cause),
                None => self.record_client_abort(&state, ctx),
            },
        }
    }

    fn record_client_abort(&mut self, state: &ProxyState, ctx: RequestContext) {
        super::record_request(state, CLIENT_CLOSED_REQUEST_STATUS);
        let Some(plugins) = self.plugins.take() else {
            crate::runtime_metrics::global_ref().record_terminal_outcome(TerminalOutcome {
                proxy_id: ctx.matched_proxy.as_ref().map(|proxy| proxy.id.as_str()),
                grpc: crate::runtime_metrics::terminal_metadata_is_grpc(&ctx.metadata),
                error_class: Some(ErrorClass::ClientDisconnect),
                body_error_class: None,
                client_disconnected: true,
            });
            return;
        };
        let mut summary = self.terminal_summary(
            &ctx,
            CLIENT_CLOSED_REQUEST_STATUS,
            CLIENT_ABORT_REJECTION_PHASE,
            // A proven pre-header frontend cancellation is the client's
            // CANCELLED, even when a backend outcome was already copied into
            // the context: the client never received it.
            (
                grpc_status::CANCELLED,
                super::GRPC_CLIENT_DISCONNECT_MESSAGE,
            ),
        );
        summary.client_disconnected = true;
        summary.error_class = Some(ErrorClass::ClientDisconnect);
        deliver(plugins, summary, ctx);
    }

    fn record_gateway_close(
        &mut self,
        state: &ProxyState,
        ctx: RequestContext,
        cause: GatewayCloseCause,
    ) {
        super::record_request(state, GATEWAY_CLOSED_REQUEST_STATUS);
        let Some(plugins) = self.plugins.take() else {
            return;
        };
        let summary = self.terminal_summary(
            &ctx,
            GATEWAY_CLOSED_REQUEST_STATUS,
            cause.rejection_phase(),
            cause.grpc_terminal(),
        );
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

/// Whether the gateway itself is ending this request's connection, which a
/// dropped handler then cannot be told apart from. Each listed cause
/// hard-closes the connection (after a bounded settle) or tears the runtime
/// down, dropping every handler still pending on it.
fn gateway_close_cause(ctx: &RequestContext, state: &ProxyState) -> Option<GatewayCloseCause> {
    if ctx
        .client_trust_session
        .as_ref()
        .is_some_and(crate::tls::ClientTrustSession::is_retired)
    {
        return Some(GatewayCloseCause::ClientTrustWithdrawn);
    }
    if ctx
        .authorization_connection_closer
        .as_ref()
        .is_some_and(crate::proxy::auth_lifetime::AuthorizationConnectionCloser::close_requested)
    {
        return Some(GatewayCloseCause::AuthorizationLifetime);
    }
    if state.overload.draining.load(Ordering::Acquire) {
        return Some(GatewayCloseCause::Shutdown);
    }
    None
}

impl Drop for ClientAbortScope {
    fn drop(&mut self) {
        // A handler unwinding from a panic was not cancelled by its client.
        if self.settled || std::thread::panicking() {
            return;
        }
        let Some(ctx) = self.ctx.take() else {
            return;
        };
        self.record.settle(ctx);
    }
}
