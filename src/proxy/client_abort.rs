//! Terminal accounting for an admitted H1/H2 request whose handler future is
//! dropped before it produced a response (issue #6768).
//!
//! hyper drops a pending service future when an HTTP/2 client resets the stream
//! (`RST_STREAM`) and when an HTTP/1.1 client closes its connection while the
//! handler is still waiting. Nothing async runs on that path: only `Drop`
//! implementations do. Every terminal record the handler emits itself
//! (`record_request`, the plugin `log` chain through `log_with_mirror`, the
//! runtime terminal outcome) sits on a code path the drop skips, so a request
//! cancelled during its upload, its plugin phases, backend acquisition, or the
//! wait for backend response headers used to leave no terminal record at all.
//! Only its `RequestGuard` was released.
//!
//! [`ClientAbortScope`] closes that gap. The request handler's
//! [`RequestContext`] lives in the scope and the handler borrows it, so the
//! context is still intact when hyper drops the handler. The scope's `Drop`
//! then records exactly one client-abort terminal:
//!
//! * `record_request(499)`: the nginx client-closed-request status, used only
//!   for logs and metrics. Nothing is written to the departed client, and a
//!   response head the transport already committed is never rewritten
//!   (RFC 9112 §8). Once hyper has the response, its body owns the terminal
//!   (`DeferredTransactionLogger`) and this scope has already settled.
//! * With a plugin chain resolved for the request, one `TransactionSummary`
//!   carrying `499`, `error_class: client_disconnect`, `client_disconnected:
//!   true`, `response_delivery: observed`, and the `rejection_phase`
//!   [`CLIENT_ABORT_REJECTION_PHASE`], handed to the same bounded terminal
//!   delivery the streaming terminal uses (`Drop` cannot await a plugin).
//! * Without one, the runtime terminal outcome the summary would have fed.
//!
//! Backend health is untouched: no backend outcome exists, the half-open probe
//! and backend admission guards the handler owned already released neutrally
//! when the handler was dropped, and nothing here reaches a circuit breaker,
//! passive health, or retry budget.
//!
//! The scope never records twice:
//!
//! * Normal completion calls [`ClientAbortScope::complete`] in the same poll
//!   that the handler returns in, before hyper sees the response. There is no
//!   point at which the handler has finished but the scope can still fire.
//! * A handler that gives its context to a later owner (the streaming terminal
//!   logger or the WebSocket upgrade handler) takes it out with
//!   [`ClientAbortScope::hand_off`], and that owner accounts for the terminal.
//! * A handler dropped after its own terminal log started (the shared funnel
//!   latches `RequestContext::terminal_record_started` before it can first
//!   suspend) already has its record in flight, so the scope records nothing.
//!
//! Only a proven client cancellation is recorded. A handler dropped because the
//! gateway is closing the connection itself (withdrawn client-certificate
//! trust, an authorization-lifetime close), or unwinding from a panic, is not a
//! client abort and records nothing here.
//!
//! Requests the frontend refused before admission never reach a scope, so a
//! connection that closes without an admitted request is never turned into a
//! transaction record.
//!
//! Cost on the request path: one `Arc<ProxyState>` clone at install, one
//! plugin-chain `Arc` clone when the request has plugins, and a few word-sized
//! stores. The context itself is not cloned, and no allocation or lock is
//! added. The summary is built only on the cancellation path.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::plugins::{
    LATENCY_UNKNOWN_MS, Plugin, RequestContext, ResponseDelivery, TransactionSummary,
};
use crate::proxy::ProxyState;
use crate::retry::ErrorClass;
use crate::runtime_metrics::TerminalOutcome;

/// Status recorded for a request the client abandoned before any response
/// head: nginx's `499 Client Closed Request`. Logging and metrics vocabulary
/// only; it is never sent.
pub const CLIENT_CLOSED_REQUEST_STATUS: u16 = 499;

/// `rejection_phase` metadata on the client-abort transaction record.
pub const CLIENT_ABORT_REJECTION_PHASE: &str = "client_disconnect_before_response";

/// Owner of an admitted H1/H2 request's [`RequestContext`] for the lifetime of
/// its handler. See the [module documentation](self).
///
/// The H1/H2 frontend creates one per admitted request, next to the handler
/// future and in the same allocation, and calls [`Self::complete`] when the
/// handler returns. Dropping the scope without either `complete` or
/// [`Self::hand_off`] records the client abort.
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
    /// client-abort record's `latency_total_ms` covers the same span as every
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
    /// is not retained: there is no `log` to call, so a client abort records
    /// the runtime terminal outcome alone.
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

    fn record_client_abort(&mut self, mut ctx: RequestContext) {
        let Some(state) = self.state.take() else {
            return;
        };
        super::record_request(&state, CLIENT_CLOSED_REQUEST_STATUS);
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
        let summary = self.client_abort_summary(&ctx);
        // The bounded admissions the context still holds end with the request,
        // not with the detached log task.
        ctx.release_leases_before_terminal_handoff();
        let _ = crate::observability_delivery::spawn_terminal(async move {
            crate::plugins::log_with_mirror(plugins.as_slice(), &summary, &ctx).await;
        });
    }

    fn client_abort_summary(&self, ctx: &RequestContext) -> TransactionSummary {
        let proxy = ctx.matched_proxy.as_deref();
        let latency_total_ms = self.start_time.map_or(LATENCY_UNKNOWN_MS, |start| {
            start.elapsed().as_secs_f64() * 1000.0
        });
        let mut metadata = super::clone_log_metadata(ctx);
        metadata.insert(
            "rejection_phase".to_string(),
            CLIENT_ABORT_REJECTION_PHASE.to_string(),
        );
        // A gRPC client that cancels is `CANCELLED`, as the buffered gRPC
        // upload's client-disconnect path records it, rather than the UNKNOWN a
        // gRPC record without a terminal status reports.
        if metadata
            .get("request_protocol")
            .is_some_and(|protocol| protocol == "grpc")
            && !metadata.contains_key("grpc_status")
        {
            metadata.insert(
                "grpc_status".to_string(),
                super::grpc_proxy::grpc_status::CANCELLED.to_string(),
            );
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
            response_status_code: CLIENT_CLOSED_REQUEST_STATUS,
            latency_total_ms,
            // The handler's phase timers died with it, and a backend exchange
            // in flight at the abort has no separable duration.
            latency_gateway_processing_ms: LATENCY_UNKNOWN_MS,
            latency_backend_ttfb_ms: LATENCY_UNKNOWN_MS,
            latency_backend_total_ms: LATENCY_UNKNOWN_MS,
            latency_plugin_execution_ms: LATENCY_UNKNOWN_MS,
            latency_plugin_external_io_ms: ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64
                / 1_000_000.0,
            latency_gateway_overhead_ms: LATENCY_UNKNOWN_MS,
            request_user_agent: ctx.headers.get("user-agent").cloned(),
            client_disconnected: true,
            error_class: Some(ErrorClass::ClientDisconnect),
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

impl Drop for ClientAbortScope {
    fn drop(&mut self) {
        // A handler unwinding from a panic was not cancelled by its client.
        if self.settled || std::thread::panicking() {
            return;
        }
        let Some(ctx) = self.ctx.take() else {
            return;
        };
        if ctx.terminal_record_started() || gateway_closed_connection(&ctx) {
            return;
        }
        self.record.record_client_abort(ctx);
    }
}

/// Whether the gateway itself is tearing down this request's connection: a
/// withdrawn client-certificate trust decision or an authorization-lifetime
/// close, each of which hard-closes the connection after a bounded settle and
/// drops the handlers still pending on it. That drop is not a client
/// cancellation, so it is never recorded as one.
fn gateway_closed_connection(ctx: &RequestContext) -> bool {
    ctx.client_trust_session
        .as_ref()
        .is_some_and(crate::tls::ClientTrustSession::is_retired)
        || ctx.authorization_connection_closer.as_ref().is_some_and(
            crate::proxy::auth_lifetime::AuthorizationConnectionCloser::close_requested,
        )
}
