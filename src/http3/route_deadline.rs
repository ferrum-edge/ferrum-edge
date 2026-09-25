//! Native HTTP/3 enforcement of a matched route rule's deadlines (#5646).
//!
//! A route rule can carry a total request deadline (`mesh_route_dispatch`
//! `request_timeout_ms`, Gateway API `HTTPRoute.rules[].timeouts.request`) and
//! a per-attempt total bound (`attempt_timeout_ms`, `timeouts.backendRequest`).
//! Proxy core enforces both for HTTP/1.1 and HTTP/2 around every backend
//! attempt ([`crate::proxy::await_route_request_deadline`]) and on the committed
//! response body (`ProxyBody::with_route_request_deadline`). The native HTTP/3
//! relays write the response head and body from inside their own dispatch, so
//! they apply the same bounds at the same phases with the helpers here:
//!
//! * Each backend attempt runs under the total deadline and a fresh attempt
//!   budget, started when the attempt is handed to the backend.
//! * Before the response head, an expired total deadline is the
//!   gateway-authored `504` (`{"error":"Request timeout"}`, `backend_timeout`
//!   `X-Gateway-Error`) and is never retried. It is charged to the backend
//!   only when the backend held the attempt; expiry while the gateway is still
//!   buffering a client upload, taking admission, or in retry backoff is
//!   health-neutral and names its phase under
//!   [`crate::plugins::ROUTE_REQUEST_TIMEOUT_METADATA_KEY`].
//! * An expired attempt budget is the ordinary backend-timeout `504`, charged
//!   to the backend and retryable by the rule's retry policy, which replays
//!   the retained request body.
//! * After the response head, the earlier of the total deadline and the
//!   committed attempt's budget cuts the body: the stream is reset with
//!   `H3_REQUEST_CANCELLED` (the HTTP/3 counterpart of the HTTP/2 stream
//!   reset), never finished cleanly. The cut is health-neutral and is logged
//!   with `body_error_class: read_write_timeout`.
//!
//! gRPC-flavored requests fold both bounds into their RPC deadline instead
//! (`RequestContext::arm_route_request_deadline`), which the native-H3 gRPC
//! relays already enforce, so nothing here applies to them.
//!
//! When the rule carries neither bound, [`H3RouteDeadlines`] is two `None`s:
//! no timer is armed, nothing is allocated, and every wrapper polls straight
//! through.

use std::time::Duration;

use bytes::Bytes;
use h3::error::Code;
use h3::quic::SendStream;
use h3::server::RequestStream;

use crate::plugins::{ROUTE_REQUEST_TIMEOUT_METADATA_KEY, RequestContext};
use crate::proxy::RouteDeadlineExpiry;
use crate::retry::ErrorClass;

/// The HTTP/3 error code a route deadline cut resets a committed response
/// with: RFC 9114 `H3_REQUEST_CANCELLED` (`0x010c`), "the request or its
/// response is cancelled".
pub(crate) const ROUTE_DEADLINE_RESET_CODE: Code = Code::H3_REQUEST_CANCELLED;

/// The matched route rule's deadlines for one NON-gRPC HTTP/3 request, read
/// once from the request context after `before_proxy` selected the rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct H3RouteDeadlines {
    total: Option<tokio::time::Instant>,
    attempt_timeout: Option<Duration>,
}

impl H3RouteDeadlines {
    /// The deadlines armed by `RequestContext::arm_route_request_deadline`.
    /// Both are `None` for a gRPC-flavored request and for a rule without
    /// timeouts.
    #[inline]
    pub(crate) fn from_ctx(ctx: &RequestContext) -> Self {
        Self {
            total: ctx.route_request_deadline_at(),
            attempt_timeout: ctx.route_attempt_timeout(),
        }
    }

    #[inline]
    pub(crate) fn new(
        total: Option<tokio::time::Instant>,
        attempt_timeout: Option<Duration>,
    ) -> Self {
        Self {
            total,
            attempt_timeout,
        }
    }

    /// The absolute total request deadline.
    #[inline]
    pub(crate) fn total(self) -> Option<tokio::time::Instant> {
        self.total
    }

    /// The per-attempt budget, started for each attempt at its handoff.
    #[inline]
    pub(crate) fn attempt_timeout(self) -> Option<Duration> {
        self.attempt_timeout
    }

    /// Start one attempt's budget now, at its handoff to the backend: the
    /// instant it expires. `None` when the rule carries no attempt budget.
    #[inline]
    pub(crate) fn start_attempt(self) -> Option<tokio::time::Instant> {
        let timeout = self.attempt_timeout?;
        tokio::time::Instant::now().checked_add(timeout)
    }

    /// The instant the committed attempt's response body is cut: the earlier
    /// of the total deadline and that attempt's budget.
    #[inline]
    pub(crate) fn body_deadline(
        self,
        committed_attempt_deadline: Option<tokio::time::Instant>,
    ) -> Option<tokio::time::Instant> {
        crate::proxy::earliest_deadline(self.total, committed_attempt_deadline)
    }

    /// Whether the total deadline has already elapsed.
    #[inline]
    pub(crate) fn total_elapsed(self) -> bool {
        let now = tokio::time::Instant::now();
        self.total.is_some_and(|deadline| deadline <= now)
    }

    /// Whether an attempt's own budget, and not the total deadline, has
    /// expired: the ordinary backend timeout, which the rule's retry policy
    /// may retry. The total deadline wins a tie, as in proxy core.
    #[inline]
    pub(crate) fn attempt_budget_expired(
        self,
        attempt_deadline: Option<tokio::time::Instant>,
    ) -> bool {
        let now = tokio::time::Instant::now();
        self.total.is_none_or(|total| now < total)
            && attempt_deadline.is_some_and(|attempt| attempt <= now)
    }

    /// How the committed attempt's [`Self::body_deadline`] ended it once it
    /// fired: the total deadline when that has elapsed (it wins a tie, as in
    /// proxy core, so a spent transaction is never retried), otherwise the
    /// attempt's own budget.
    #[inline]
    pub(crate) fn body_expiry(self) -> RouteDeadlineExpiry {
        if self.total_elapsed() {
            RouteDeadlineExpiry::InFlight
        } else {
            RouteDeadlineExpiry::AttemptBudget
        }
    }
}

/// The class a route deadline that ended an attempt is recorded under, for
/// an attempt that was handed to the backend from its first poll (every
/// native-H3 attempt wrapper): the health-neutral `DispatchPolicyRejected`
/// only when the total deadline was already spent before the attempt started,
/// otherwise `ReadWriteTimeout`, charged to the backend that held it.
#[inline]
pub(crate) fn expiry_error_class(expiry: RouteDeadlineExpiry) -> ErrorClass {
    expiry.error_class(true)
}

/// The client-visible `504` status and body for an attempt a route deadline
/// ended before the response head: proxy core's route timeout body for the
/// total deadline, the ordinary backend-timeout body for an attempt budget.
#[inline]
pub(crate) fn expiry_status_body(expiry: RouteDeadlineExpiry) -> (u16, &'static str) {
    if expiry == RouteDeadlineExpiry::AttemptBudget {
        crate::proxy::http_backend_failure_status_and_body(ErrorClass::ReadWriteTimeout)
    } else {
        (504, crate::proxy::ROUTE_REQUEST_TIMEOUT_BODY)
    }
}

/// Record a total-deadline expiry's phase in the transaction log, exactly as
/// proxy core does for its route timeout `504`. An attempt budget expiry is
/// the ordinary backend timeout and records no phase.
#[inline]
pub(crate) fn mark_expiry_phase(ctx: &mut RequestContext, expiry: RouteDeadlineExpiry) {
    if expiry != RouteDeadlineExpiry::AttemptBudget {
        ctx.mark_route_request_timeout_exceeded(expiry.phase(true));
    }
}

/// Record a total-deadline expiry's phase unless an earlier, more specific
/// site already recorded one.
#[inline]
pub(crate) fn mark_phase_once(ctx: &mut RequestContext, phase: &'static str) {
    if !ctx
        .metadata
        .contains_key(ROUTE_REQUEST_TIMEOUT_METADATA_KEY)
    {
        ctx.mark_route_request_timeout_exceeded(phase);
    }
}

/// Record a total deadline that expired in retry backoff, where no backend
/// held the request, exactly as proxy core does.
#[inline]
pub(crate) fn mark_backoff_expiry(ctx: &mut RequestContext) {
    ctx.mark_route_request_timeout_exceeded(
        crate::proxy::ROUTE_REQUEST_TIMEOUT_PHASE_RETRY_BACKOFF,
    );
}

/// Whether the matched route rule's total deadline already produced this
/// request's route timeout `504` (its phase is recorded in the transaction
/// log). A retry loop stops on it: the whole budget is spent and the `504`
/// stands, exactly as proxy core's retry planner stops on its typed expiry.
/// Free when the rule carries no total deadline.
#[inline]
pub(crate) fn total_expiry_recorded(route: H3RouteDeadlines, ctx: &RequestContext) -> bool {
    route.total.is_some()
        && ctx
            .metadata
            .contains_key(ROUTE_REQUEST_TIMEOUT_METADATA_KEY)
}

/// The backend response for an attempt a route deadline cancelled, exactly as
/// proxy core's retry loop sees it (`route_deadline_expiry_response`), with a
/// total-deadline expiry's phase recorded and the `backend_timeout`
/// `X-Gateway-Error` token proxy core's response builder attaches to a `504`.
pub(crate) fn expiry_backend_response(
    ctx: &mut RequestContext,
    expiry: RouteDeadlineExpiry,
) -> crate::retry::BackendResponse {
    let mut phase = None;
    let mut response = crate::proxy::route_deadline_expiry_response(expiry, true, &mut phase);
    if let Some(phase) = phase {
        ctx.mark_route_request_timeout_exceeded(phase);
    }
    crate::proxy::insert_x_gateway_error_for_backend_failure(
        &mut response.headers,
        response.connection_error,
        response.status_code,
    );
    response
}

/// The native-H3 pool error for an attempt a route deadline cancelled, with
/// its transaction-log phase recorded (see [`mark_expiry_phase`]).
pub(crate) fn expiry_pool_error(
    ctx: &mut RequestContext,
    expiry: RouteDeadlineExpiry,
) -> crate::http3::client::H3PoolError {
    mark_expiry_phase(ctx, expiry);
    crate::http3::client::H3PoolError::route_deadline(expiry)
}

/// Reset a COMMITTED response whose body a route deadline cut. Response
/// HEADERS are already on the wire, so a clean `finish()` would present the
/// truncated body as complete; RFC 9114 has no in-band way to retract it, so
/// the send half is reset with [`ROUTE_DEADLINE_RESET_CODE`].
///
/// Idempotent at the QUIC layer: a later fail-closed `stop_stream` from a
/// committed-response guard is a no-op and keeps this code on the wire.
#[inline]
pub(crate) fn cancel_response_stream<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: SendStream<Bytes>,
{
    stream.stop_stream(ROUTE_DEADLINE_RESET_CODE);
}
