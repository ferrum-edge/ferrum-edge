//! Per-attempt CLIENT spans for `otel_tracing` (issue #5864).
//!
//! `otel_tracing` installs a [`BackendAttemptTrace`] on a sampled request's
//! context in `before_proxy` when it has an exporter. Every backend attempt the
//! retry loops dispatch (the H1/H2 loop, the native gRPC loop, and the native
//! HTTP/3 frontend loop, retries included) then:
//!
//! 1. begins at its dispatch site ([`BackendAttemptTrace::begin`]), which mints
//!    the attempt's span id and returns a copy of the backend header map whose
//!    `traceparent` names that span, so the backend's SERVER span becomes a
//!    child of the attempt instead of the gateway's SERVER span;
//! 2. is polled inside a task-local scope, through which the direct HTTP/2 and
//!    gRPC connection pools report pooled-connection reuse versus setup (and
//!    the setup phases they time) without the request context being threaded
//!    through every pool signature;
//! 3. ends at the loops' existing per-attempt hook
//!    (`RequestContext::record_backend_attempt`, issue #5846), which exports it.
//!
//! A dispatch path that never begins an attempt keeps the gateway SERVER
//! span's `traceparent` and exports no attempt span, so an uninstrumented path
//! can never hand a backend a parent span that is not exported.
//!
//! Cost: without an installed trace (tracing disabled, no exporter, or an
//! unsampled request) every hook is one `Option` check, and a pooled-connection
//! checkout adds one task-local lookup. Nothing allocates and nothing locks.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::warn;

use crate::retry::ErrorClass;
use crate::util::accept_backoff::LogRateLimiter;

use super::{
    OtelTracing, SUPPORTED_TRACEPARENT_VERSION, SpanData, SpanKind, TRACEPARENT_HEADER,
    TraceExporter, build_traceparent, http_method_for_span_name, is_lowercase_hex, otlp_attribute,
    otlp_attribute_bool, otlp_attribute_double, otlp_attribute_int, parse_backend_host_port,
    timestamp_before_now, timestamp_nanos, trace_is_sampled, truncate_attr,
};

/// Exporter handle shared by every trace one `otel_tracing` instance installs.
pub(crate) struct AttemptSpanSink {
    exporter: Arc<dyn TraceExporter>,
    service_name: String,
    max_attribute_bytes: usize,
    drop_log_limiter: Mutex<LogRateLimiter>,
}

impl AttemptSpanSink {
    pub(crate) fn new(
        exporter: Arc<dyn TraceExporter>,
        service_name: String,
        max_attribute_bytes: usize,
    ) -> Self {
        Self {
            exporter,
            service_name,
            max_attribute_bytes,
            drop_log_limiter: Mutex::new(LogRateLimiter::new()),
        }
    }

    fn export(&self, span: SpanData) {
        let Err(error) = self.exporter.try_export(span) else {
            return;
        };
        let now_ms = crate::socket_opts::monotonic_now_ms();
        let suppressed = match self.drop_log_limiter.lock() {
            Ok(mut limiter) => limiter.on_event(now_ms),
            Err(poisoned) => poisoned.into_inner().on_event(now_ms),
        };
        if let Some(suppressed) = suppressed {
            warn!(
                provider = self.exporter.provider_name(),
                suppressed = suppressed,
                error = %error,
                "trace export buffer rejected a backend attempt span"
            );
        }
    }
}

/// Connection evidence for one backend attempt. Every field is set only by a
/// pool that observed it; an unobserved value stays `None` and is omitted from
/// the span, never exported as zero.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct ConnectionEvidence {
    /// `true` when the attempt rode a pooled connection it did not open,
    /// `false` when the attempt established the connection itself.
    pub(crate) reused: Option<bool>,
    /// Whole connection establishment the attempt performed.
    pub(crate) setup: Option<Duration>,
    pub(crate) dns: Option<Duration>,
    pub(crate) tcp_connect: Option<Duration>,
    pub(crate) tls_handshake: Option<Duration>,
}

/// Attempt-specific span fields, present only on CLIENT attempt spans.
#[derive(Debug, Clone)]
pub(crate) struct BackendAttemptAttributes {
    /// 1-based attempt number; `http.request.resend_count` is this minus one.
    pub(crate) attempt: u32,
    /// Outcome of the previous attempt that made this one a retry.
    pub(crate) retry_reason: Option<&'static str>,
    /// OTel `error.type`: the gateway error class, or the status code of a
    /// `4xx`/`5xx` backend response.
    pub(crate) error_type: Option<String>,
    pub(crate) connection: ConnectionEvidence,
}

impl BackendAttemptAttributes {
    pub(super) fn approx_bytes(&self) -> usize {
        self.error_type.as_ref().map(String::len).unwrap_or(0)
            + self.retry_reason.map(str::len).unwrap_or(0)
            + 128
    }
}

/// Per-request recorder of backend attempt spans. Shared by `Arc` between the
/// request context (and its hook clones) and the task-local attempt scope.
pub(crate) struct BackendAttemptTrace {
    sink: Arc<AttemptSpanSink>,
    trace_id: String,
    /// The gateway SERVER span every attempt span is a child of.
    server_span_id: String,
    /// Request method, bounded to the `http.request.method` attribute size.
    http_method: String,
    state: Mutex<AttemptState>,
}

impl std::fmt::Debug for BackendAttemptTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendAttemptTrace")
            .field("trace_id", &self.trace_id)
            .field("server_span_id", &self.server_span_id)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct AttemptState {
    /// Attempts recorded so far, begun or not.
    recorded: u32,
    /// Outcome label of the latest recorded attempt: the reason a following
    /// attempt is a retry.
    last_outcome: Option<&'static str>,
    in_flight: Option<InFlightAttempt>,
}

struct InFlightAttempt {
    span_id: String,
    server_address: Option<String>,
    server_port: Option<u16>,
    /// When the attempt began at its dispatch site, or, for a dispatch that
    /// first prepares its request, when it was handed to the backend.
    started_at: Instant,
    connection: ConnectionEvidence,
}

impl BackendAttemptTrace {
    /// The attempt recorder for a request `otel_tracing` has decided to sample,
    /// parented under the request's SERVER span. `None` for an unsampled
    /// request or trace metadata that is not W3C-shaped.
    pub(crate) fn for_request(
        sink: &Arc<AttemptSpanSink>,
        metadata: &HashMap<String, String>,
        method: &str,
    ) -> Option<Arc<Self>> {
        if !trace_is_sampled(metadata) {
            return None;
        }
        let trace_id = metadata.get("trace_id")?;
        let server_span_id = metadata.get("span_id")?;
        if !is_lowercase_hex(trace_id, 32) || !is_lowercase_hex(server_span_id, 16) {
            return None;
        }
        Some(Arc::new(Self {
            sink: Arc::clone(sink),
            trace_id: trace_id.clone(),
            server_span_id: server_span_id.clone(),
            http_method: truncate_attr(method, 32),
            state: Mutex::new(AttemptState::default()),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, AttemptState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Begin the next backend attempt, dispatched to `backend_url` with
    /// `headers`. Returns the header map the attempt must carry: `headers` with
    /// `traceparent` naming this attempt's span.
    pub(crate) fn begin(
        self: &Arc<Self>,
        backend_url: &str,
        headers: &HashMap<String, String>,
    ) -> BackendAttemptSpan {
        let span_id = OtelTracing::generate_span_id();
        let (server_address, server_port) = parse_backend_host_port(backend_url);
        let mut attempt_headers = headers.clone();
        attempt_headers.retain(|name, _| !name.eq_ignore_ascii_case(TRACEPARENT_HEADER));
        attempt_headers.insert(
            TRACEPARENT_HEADER.to_string(),
            build_traceparent(
                SUPPORTED_TRACEPARENT_VERSION,
                &self.trace_id,
                &span_id,
                "01",
            ),
        );
        self.lock().in_flight = Some(InFlightAttempt {
            span_id,
            server_address: server_address
                .map(|address| truncate_attr(&address, self.sink.max_attribute_bytes)),
            server_port,
            started_at: Instant::now(),
            connection: ConnectionEvidence::default(),
        });
        BackendAttemptSpan(Some(Box::new(BegunAttempt {
            trace: Arc::clone(self),
            headers: attempt_headers,
        })))
    }

    /// End the attempt in flight with its outcome and export its span. Called
    /// once per attempt from `RequestContext::record_backend_attempt`. An
    /// attempt no dispatch site began is counted but not exported.
    pub(crate) fn finish(&self, error_class: Option<ErrorClass>, response_status: Option<u16>) {
        let ended_at = Instant::now();
        let (attempt, retry_reason, in_flight) = {
            let mut state = self.lock();
            state.recorded = state.recorded.saturating_add(1);
            let retry_reason = if state.recorded > 1 {
                Some(state.last_outcome.unwrap_or("unknown"))
            } else {
                None
            };
            state.last_outcome = Some(attempt_outcome_label(error_class, response_status));
            (state.recorded, retry_reason, state.in_flight.take())
        };
        let Some(in_flight) = in_flight else {
            return;
        };
        let duration_ms = ended_at
            .saturating_duration_since(in_flight.started_at)
            .as_secs_f64()
            * 1000.0;
        // A gateway-classified failure carries a synthesized status, not one
        // the backend sent, so only an unclassified outcome reports its status.
        let http_status_code = response_status.filter(|_| error_class.is_none());
        let error_type = match (error_class, http_status_code) {
            (Some(class), _) => Some(class.as_str().to_string()),
            (None, Some(status)) if status >= 400 => Some(status.to_string()),
            _ => None,
        };
        let span_name = http_method_for_span_name(&self.http_method).to_string();
        let otlp_error = error_type.is_some();
        let span = SpanData::backend_attempt(
            self.trace_id.clone(),
            in_flight.span_id,
            self.server_span_id.clone(),
            self.sink.service_name.clone(),
            span_name,
            self.http_method.clone(),
            http_status_code,
            duration_ms,
            timestamp_before_now(duration_ms),
            in_flight.server_address,
            in_flight.server_port,
            otlp_error,
            BackendAttemptAttributes {
                attempt,
                retry_reason,
                error_type,
                connection: in_flight.connection,
            },
        );
        self.sink.export(span);
    }

    fn update_in_flight(&self, update: impl FnOnce(&mut InFlightAttempt)) {
        if let Some(in_flight) = self.lock().in_flight.as_mut() {
            update(in_flight);
        }
    }
}

/// Stable label of an attempt outcome, used as the next attempt's retry
/// reason: the gateway error class, or `http_status` for a retried status.
fn attempt_outcome_label(
    error_class: Option<ErrorClass>,
    response_status: Option<u16>,
) -> &'static str {
    match (error_class, response_status) {
        (Some(class), _) => class.as_str(),
        (None, Some(_)) => "http_status",
        (None, None) => "unknown",
    }
}

struct BegunAttempt {
    trace: Arc<BackendAttemptTrace>,
    headers: HashMap<String, String>,
}

/// One begun backend attempt: the header map it carries and the scope it is
/// polled in. Inactive, and allocation-free, when the request has no trace.
#[must_use]
pub(crate) struct BackendAttemptSpan(Option<Box<BegunAttempt>>);

impl BackendAttemptSpan {
    pub(crate) const INACTIVE: Self = Self(None);

    /// The header map this attempt dispatches: the attempt's own copy when a
    /// trace is active, `base` otherwise.
    pub(crate) fn headers<'a>(
        &'a self,
        base: &'a HashMap<String, String>,
    ) -> &'a HashMap<String, String> {
        self.0.as_ref().map_or(base, |begun| &begun.headers)
    }

    /// The dispatch began the backend dial / send at `handed_off_at`, after
    /// preparing the request: the attempt starts there, never before it began.
    pub(crate) fn handed_off_at(&self, handed_off_at: Instant) {
        if let Some(begun) = self.0.as_ref() {
            begun.trace.update_in_flight(|attempt| {
                attempt.started_at = attempt.started_at.max(handed_off_at);
            });
        }
    }

    /// The trace to scope the attempt's polls in, for
    /// `proxy::await_backend_attempt_route_deadline`.
    pub(crate) fn trace(&self) -> Option<Arc<BackendAttemptTrace>> {
        self.0.as_ref().map(|begun| Arc::clone(&begun.trace))
    }

    /// Poll an already-pinned attempt future inside this attempt's scope.
    /// Borrows the future, so the wrapper adds a pointer, not a second copy of
    /// the (large) dispatch future.
    pub(crate) fn scope<'a, F>(&self, attempt: Pin<&'a mut F>) -> BackendAttemptScope<'a, F> {
        BackendAttemptScope {
            attempt,
            trace: self.trace(),
        }
    }
}

/// Future returned by [`BackendAttemptSpan::scope`].
pub(crate) struct BackendAttemptScope<'a, F> {
    attempt: Pin<&'a mut F>,
    trace: Option<Arc<BackendAttemptTrace>>,
}

impl<F: Future> Future for BackendAttemptScope<'_, F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // `Pin<&mut F>` and `Option<Arc<_>>` are both `Unpin`, so this is a
        // plain reborrow.
        let this = &mut *self;
        poll_backend_attempt(this.trace.as_ref(), this.attempt.as_mut(), cx)
    }
}

tokio::task_local! {
    /// The backend attempt the current poll belongs to. Set only while a
    /// begun attempt of a traced request is being polled.
    static ACTIVE_BACKEND_ATTEMPT: Arc<BackendAttemptTrace>;
}

/// Poll `attempt`, with `trace` as the active backend attempt when present.
pub(crate) fn poll_backend_attempt<F: Future>(
    trace: Option<&Arc<BackendAttemptTrace>>,
    attempt: Pin<&mut F>,
    cx: &mut Context<'_>,
) -> Poll<F::Output> {
    match trace {
        None => attempt.poll(cx),
        Some(trace) => ACTIVE_BACKEND_ATTEMPT.sync_scope(Arc::clone(trace), || attempt.poll(cx)),
    }
}

fn with_active_attempt(update: impl FnOnce(&mut InFlightAttempt)) {
    let _ = ACTIVE_BACKEND_ATTEMPT.try_with(|trace| trace.update_in_flight(update));
}

/// The active attempt rides a pooled connection it did not open.
pub(crate) fn note_backend_connection_reused() {
    with_active_attempt(|attempt| attempt.connection.reused = Some(true));
}

/// The active attempt is establishing a new connection.
pub(crate) fn note_backend_connection_setup_started() {
    with_active_attempt(|attempt| attempt.connection.reused = Some(false));
}

/// The active attempt established a new connection in `setup`.
pub(crate) fn note_backend_connection_established(setup: Duration) {
    with_active_attempt(|attempt| {
        attempt.connection.reused = Some(false);
        attempt.connection.setup = Some(setup);
    });
}

/// DNS resolution for the active attempt's new connection took `elapsed`.
pub(crate) fn note_backend_dns_resolution(elapsed: Duration) {
    with_active_attempt(|attempt| attempt.connection.dns = Some(elapsed));
}

/// The TCP connect for the active attempt's new connection took `elapsed`.
/// With several DNS candidates, the last connected candidate's time wins.
pub(crate) fn note_backend_tcp_connect(elapsed: Duration) {
    with_active_attempt(|attempt| attempt.connection.tcp_connect = Some(elapsed));
}

/// The TLS handshake for the active attempt's new connection took `elapsed`.
pub(crate) fn note_backend_tls_handshake(elapsed: Duration) {
    with_active_attempt(|attempt| attempt.connection.tls_handshake = Some(elapsed));
}

fn duration_millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// OTLP/JSON span for a CLIENT backend attempt, following the OTel HTTP client
/// conventions. SERVER-only gateway attributes are not repeated here.
pub(super) fn otlp_attempt_span(span: &SpanData, attempt: &BackendAttemptAttributes) -> Value {
    let start_ns = timestamp_nanos(&span.timestamp_received);
    let end_ns = start_ns + (span.duration_ms.max(0.0) * 1_000_000.0) as i64;

    let mut attributes = vec![
        otlp_attribute("http.request.method", &span.http_method),
        otlp_attribute_int("gateway.backend.attempt", i64::from(attempt.attempt)),
    ];
    if attempt.attempt > 1 {
        attributes.push(otlp_attribute_int(
            "http.request.resend_count",
            i64::from(attempt.attempt - 1),
        ));
    }
    if let Some(reason) = attempt.retry_reason {
        attributes.push(otlp_attribute("gateway.backend.retry_reason", reason));
    }
    if let Some(ref address) = span.server_address {
        attributes.push(otlp_attribute("server.address", address));
    }
    if let Some(port) = span.server_port {
        attributes.push(otlp_attribute_int("server.port", i64::from(port)));
    }
    if let Some(status) = span.http_status_code {
        attributes.push(otlp_attribute_int(
            "http.response.status_code",
            i64::from(status),
        ));
    }
    if let Some(ref error_type) = attempt.error_type {
        attributes.push(otlp_attribute("error.type", error_type));
    }
    let connection = &attempt.connection;
    if let Some(reused) = connection.reused {
        attributes.push(otlp_attribute_bool(
            "gateway.backend.connection.reused",
            reused,
        ));
    }
    for (name, value) in [
        ("gateway.backend.connection.setup_ms", connection.setup),
        ("gateway.backend.connection.dns_ms", connection.dns),
        (
            "gateway.backend.connection.tcp_connect_ms",
            connection.tcp_connect,
        ),
        (
            "gateway.backend.connection.tls_handshake_ms",
            connection.tls_handshake,
        ),
    ] {
        if let Some(value) = value {
            attributes.push(otlp_attribute_double(name, duration_millis(value)));
        }
    }

    // OTel CLIENT semconv: a transport failure and any `4xx`/`5xx` response
    // are errors; everything else stays `Unset`.
    let status_code = if span.otlp_error { 2 } else { 0 };
    serde_json::json!({
        "traceId": span.trace_id.as_str(),
        "spanId": span.span_id.as_str(),
        "parentSpanId": span.parent_span_id.as_str(),
        "name": span.span_name.as_str(),
        "kind": span.span_kind,
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": attributes,
        "status": {
            "code": status_code
        }
    })
}

impl SpanData {
    #[allow(clippy::too_many_arguments)]
    fn backend_attempt(
        trace_id: String,
        span_id: String,
        parent_span_id: String,
        service_name: String,
        span_name: String,
        http_method: String,
        http_status_code: Option<u16>,
        duration_ms: f64,
        timestamp_received: String,
        server_address: Option<String>,
        server_port: Option<u16>,
        otlp_error: bool,
        attempt: BackendAttemptAttributes,
    ) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id,
            service_name,
            span_name,
            span_kind: SpanKind::Client.otlp_code(),
            span_kind_typed: SpanKind::Client,
            http_method,
            http_url: String::new(),
            http_status_code,
            grpc_status: None,
            client_ip: String::new(),
            duration_ms,
            gateway_processing_ms: 0.0,
            backend_ttfb_ms: 0.0,
            backend_ms: duration_ms,
            plugin_execution_ms: 0.0,
            gateway_overhead_ms: 0.0,
            consumer: None,
            timestamp_received,
            user_agent: None,
            proxy_id: None,
            matched_route: None,
            namespace: None,
            server_address,
            server_port,
            backend_target: None,
            backend_host: None,
            backend_port: None,
            backend_resolved_ip: None,
            error_class: None,
            body_error_class: None,
            body_completed: true,
            response_streamed: false,
            client_disconnected: false,
            otlp_error,
            mesh_attributes: Vec::new(),
            stream_protocol: None,
            stream_listen_port: None,
            stream_bytes_sent: None,
            stream_bytes_received: None,
            disconnect_direction: None,
            disconnect_cause: None,
            stream_io_side: None,
            ws_frames_client_to_backend: None,
            ws_frames_backend_to_client: None,
            backend_attempt: Some(Box::new(attempt)),
        }
    }
}
