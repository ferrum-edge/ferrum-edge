//! Multiplexed aggregate-router SSE session broker for `mcp_gateway`.
//!
//! One downstream MCP session holds at most one live `text/event-stream`
//! listener. Every JSON-RPC event published for that session is routed onto
//! that one listener and identified by a bounded, type-sensitive request/stream
//! identity, so many concurrent MCP request streams share one connection.
//!
//! Design invariants — each one is load bearing:
//!
//! * Each session's state lives behind ONE synchronous [`std::sync::Mutex`]
//!   whose critical sections never await and never take another session lock.
//!   Attach, publish, open, cancel, complete, reap and teardown are therefore
//!   serialized against each other. A separate broker admission gate orders
//!   session insertion against generation retirement; it is never touched by
//!   the per-request stream path. Together those gates make replay-then-live
//!   ordering deterministic and teardown reliable: there is no `try_lock`
//!   best-effort path anywhere, so a contended reload, delete or disconnect can
//!   never leave a listener alive.
//! * Retained event bytes have exactly ONE budget. Every event is retained
//!   once, in a single ring that serves both pre-listener staging and
//!   `Last-Event-ID` replay; delivery clones a `Bytes` handle, never the
//!   payload. A response that has selected its POST-side `202` reserves one
//!   event/count window before that response can enter final header policy;
//!   direct publishers account for those reservations, so the later committed
//!   hook cannot lose the event to a capacity race.
//! * An undelivered event is never evicted. When the ring cannot admit one, the
//!   publish fails closed and the caller answers the POST inline, so a JSON-RPC
//!   response is never silently dropped. A refused publish still TERMINALIZES
//!   its identity inside the same critical section, so the inline answer is
//!   that identity's one terminal outcome and its stream capacity is returned
//!   exactly once instead of leaking.
//! * An open request stream is owned by an RAII lease
//!   ([`AggregateSseStream`]) held privately on the request context. Every exit
//!   path — publish, cancellation, inline fallback, backend error, policy
//!   replacement, transport disconnect, task cancellation — releases the
//!   identity exactly once through that lease, with no detached task and
//!   without the lease retaining the broker generation.
//! * Session ids, JSON-RPC ids, `Last-Event-ID` values and event payloads are
//!   never logged and never reach a diagnostic. Every reason is a fixed,
//!   low-cardinality token derived from the error variant.

use bytes::Bytes;
use dashmap::DashMap;
use http_body::Frame;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Frame item produced by [`AggregateSseBody`]. Structurally identical to the
/// proxy body error type, so the stream can back a `ProxyBody` directly without
/// naming a crate-private alias in a public signature.
pub type SseFrameResult = Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>;

/// Default max concurrent open request streams per downstream session.
pub const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 64;
/// Default retained-event ring capacity (staging and replay share this ring).
pub const DEFAULT_MAX_RETAINED_EVENTS: usize = 128;
/// Default aggregate retained-byte budget for that one ring.
pub const DEFAULT_MAX_RETAINED_BYTES: usize = 1024 * 1024;
/// Default max serialized JSON bytes admitted for one SSE event payload.
pub const DEFAULT_MAX_EVENT_BYTES: usize = 256 * 1024;
/// Default number of already-delivered events kept for `Last-Event-ID`.
pub const DEFAULT_MAX_REPLAY_EVENTS: usize = 64;
/// Default max accepted stream-identity bytes (canonical JSON-RPC id form).
pub const DEFAULT_MAX_STREAM_ID_BYTES: usize = 128;
/// Default max accepted `Last-Event-ID` header bytes.
pub const DEFAULT_MAX_LAST_EVENT_ID_BYTES: usize = 64;
/// Default bounded lifetime of one attached listener, after which the client is
/// expected to resume with `Last-Event-ID`.
pub const DEFAULT_LISTENER_MAX_LIFETIME_SECONDS: u64 = 300;
/// Default idle keepalive comment interval.
pub const DEFAULT_KEEPALIVE_SECONDS: u64 = 15;

/// Absolute ceilings for operator overrides (fail closed outside these).
pub const MAX_STREAMS_PER_SESSION_CEILING: usize = 4_096;
pub const MAX_RETAINED_EVENTS_CEILING: usize = 16_384;
pub const MAX_RETAINED_BYTES_CEILING: usize = 16 * 1024 * 1024;
pub const MAX_EVENT_BYTES_CEILING: usize = 2 * 1024 * 1024;
pub const MAX_REPLAY_EVENTS_CEILING: usize = 4_096;
pub const MAX_STREAM_ID_BYTES_CEILING: usize = 512;
pub const MAX_LAST_EVENT_ID_BYTES_CEILING: usize = 1_024;
pub const LISTENER_MIN_LIFETIME_SECONDS: u64 = 5;
pub const LISTENER_MAX_LIFETIME_SECONDS_CEILING: u64 = 86_400;
pub const KEEPALIVE_SECONDS_CEILING: u64 = 3_600;

/// Upper bound on the framing one event adds around its payload:
/// `id: <20 digits>\nevent: message\ndata: ` plus the terminating blank line.
const SSE_FRAME_OVERHEAD_BYTES: usize = 64;

/// Opening comment so a client sees an established stream immediately.
const SSE_GREETING: &[u8] = b": mcp-sse\n\n";
/// Idle keepalive comment; also how a vanished peer is discovered.
const SSE_KEEPALIVE: &[u8] = b": keep-alive\n\n";

/// Operator-tunable bounds for the aggregate SSE broker.
#[derive(Debug, Clone)]
pub struct AggregateSseBounds {
    pub max_streams_per_session: usize,
    pub max_retained_events: usize,
    pub max_retained_bytes: usize,
    pub max_event_bytes: usize,
    pub max_replay_events: usize,
    pub max_stream_id_bytes: usize,
    pub max_last_event_id_bytes: usize,
    pub listener_max_lifetime: Duration,
    pub keepalive_interval: Duration,
}

impl Default for AggregateSseBounds {
    fn default() -> Self {
        Self {
            max_streams_per_session: DEFAULT_MAX_STREAMS_PER_SESSION,
            max_retained_events: DEFAULT_MAX_RETAINED_EVENTS,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_replay_events: DEFAULT_MAX_REPLAY_EVENTS,
            max_stream_id_bytes: DEFAULT_MAX_STREAM_ID_BYTES,
            max_last_event_id_bytes: DEFAULT_MAX_LAST_EVENT_ID_BYTES,
            listener_max_lifetime: Duration::from_secs(DEFAULT_LISTENER_MAX_LIFETIME_SECONDS),
            keepalive_interval: Duration::from_secs(DEFAULT_KEEPALIVE_SECONDS),
        }
    }
}

impl AggregateSseBounds {
    /// Validate operator bounds. Diagnostics name the field and never echo the
    /// configured value.
    pub fn validate(self) -> Result<Self, String> {
        validate_bound(
            self.max_streams_per_session,
            1,
            MAX_STREAMS_PER_SESSION_CEILING,
            "sse_max_streams_per_session",
        )?;
        validate_bound(
            self.max_retained_events,
            1,
            MAX_RETAINED_EVENTS_CEILING,
            "sse_max_retained_events",
        )?;
        validate_bound(
            self.max_retained_bytes,
            1,
            MAX_RETAINED_BYTES_CEILING,
            "sse_max_retained_bytes",
        )?;
        validate_bound(
            self.max_event_bytes,
            1,
            MAX_EVENT_BYTES_CEILING,
            "sse_max_event_bytes",
        )?;
        validate_bound(
            self.max_replay_events,
            0,
            MAX_REPLAY_EVENTS_CEILING,
            "sse_max_replay_events",
        )?;
        validate_bound(
            self.max_stream_id_bytes,
            1,
            MAX_STREAM_ID_BYTES_CEILING,
            "sse_max_stream_id_bytes",
        )?;
        validate_bound(
            self.max_last_event_id_bytes,
            1,
            MAX_LAST_EVENT_ID_BYTES_CEILING,
            "sse_max_last_event_id_bytes",
        )?;
        validate_seconds(
            self.listener_max_lifetime,
            LISTENER_MIN_LIFETIME_SECONDS,
            LISTENER_MAX_LIFETIME_SECONDS_CEILING,
            "sse_listener_max_lifetime_seconds",
        )?;
        validate_seconds(
            self.keepalive_interval,
            1,
            KEEPALIVE_SECONDS_CEILING,
            "sse_keepalive_seconds",
        )?;
        // One max-size payload plus the framing the broker adds around it must
        // fit the single retained-byte budget; otherwise the largest admitted
        // event could never be staged and every publish would fail closed.
        let framed_ceiling = self
            .max_event_bytes
            .saturating_add(SSE_FRAME_OVERHEAD_BYTES);
        if framed_ceiling > self.max_retained_bytes {
            return Err(field_error(
                "sse_max_event_bytes",
                "must leave room for SSE framing inside 'sessions.sse_max_retained_bytes'",
            ));
        }
        if self.max_replay_events > self.max_retained_events {
            return Err(field_error(
                "sse_max_replay_events",
                "must not exceed 'sessions.sse_max_retained_events'",
            ));
        }
        if self.keepalive_interval > self.listener_max_lifetime {
            return Err(field_error(
                "sse_keepalive_seconds",
                "must not exceed 'sessions.sse_listener_max_lifetime_seconds'",
            ));
        }
        Ok(self)
    }
}

fn field_error(field: &str, detail: &str) -> String {
    format!("mcp_gateway: 'sessions.{field}' {detail}")
}

fn validate_bound(value: usize, min: usize, max: usize, field: &str) -> Result<(), String> {
    if value < min || value > max {
        return Err(field_error(
            field,
            &format!("must be between {min} and {max}"),
        ));
    }
    Ok(())
}

fn validate_seconds(value: Duration, min: u64, max: u64, field: &str) -> Result<(), String> {
    let seconds = value.as_secs();
    if seconds < min || seconds > max || value.subsec_nanos() != 0 {
        return Err(field_error(
            field,
            &format!("must be between {min} and {max}"),
        ));
    }
    Ok(())
}

/// Fail-closed broker admission / routing outcomes. Every variant maps to a
/// fixed reason and a fixed status; none of them carries request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateSseError {
    MissingSession,
    UnknownSession,
    StaleSession,
    BrokerRetired,
    DuplicateListener,
    InvalidAccept,
    LastEventIdTooLarge,
    LastEventIdInvalid,
    LastEventIdTooOld,
    LastEventIdUnknown,
    StreamIdMissing,
    StreamIdTooLarge,
    StreamIdInvalid,
    DuplicateStream,
    UnknownStream,
    StreamCompleted,
    StreamCancelled,
    ResponseEnvelopeInvalid,
    EventTooLarge,
    EventFramingInvalid,
    RetentionOverflow,
    StreamCardinalityOverflow,
    SessionCardinalityOverflow,
}

impl AggregateSseError {
    /// Client-visible reason. Fixed strings only — never a session id, a
    /// JSON-RPC id, a header value, or an event payload.
    pub fn as_static_reason(self) -> &'static str {
        match self {
            Self::MissingSession => "MCP session header is required for aggregate SSE",
            Self::UnknownSession => "MCP session not found",
            Self::StaleSession => "MCP session is no longer live for SSE multiplexing",
            Self::BrokerRetired => "MCP SSE broker generation was retired",
            Self::DuplicateListener => "SSE listener already attached for this session",
            Self::InvalidAccept => "Accept must include text/event-stream for aggregate SSE",
            Self::LastEventIdTooLarge => "Last-Event-ID exceeds the maximum length",
            Self::LastEventIdInvalid => "Last-Event-ID is not a valid event cursor",
            Self::LastEventIdTooOld => "Last-Event-ID is older than the retained event history",
            Self::LastEventIdUnknown => "Last-Event-ID is ahead of the retained event history",
            Self::StreamIdMissing => "stream identity is required",
            Self::StreamIdTooLarge => "stream identity exceeds the maximum length",
            Self::StreamIdInvalid => "stream identity is not a representable JSON-RPC id",
            Self::DuplicateStream => "stream identity is already open on this session",
            Self::UnknownStream => "stream identity is unknown on this session",
            Self::StreamCompleted => "stream identity already completed on this session",
            Self::StreamCancelled => "stream identity was cancelled by the client",
            Self::ResponseEnvelopeInvalid => {
                "JSON-RPC response envelope is invalid for the open stream"
            }
            Self::EventTooLarge => "SSE event payload exceeds the maximum length",
            Self::EventFramingInvalid => "SSE event payload cannot be framed as one event record",
            Self::RetentionOverflow => "SSE session retention capacity exceeded",
            Self::StreamCardinalityOverflow => "SSE stream cardinality exceeded for this session",
            Self::SessionCardinalityOverflow => "SSE session cardinality exceeded",
        }
    }

    /// Fixed low-cardinality metadata token. Safe in transaction metadata
    /// because it is derived from the variant, never from request data.
    pub fn reason_token(self) -> &'static str {
        match self {
            Self::MissingSession => "missing_session",
            Self::UnknownSession => "unknown_session",
            Self::StaleSession => "stale_session",
            Self::BrokerRetired => "broker_retired",
            Self::DuplicateListener => "duplicate_listener",
            Self::InvalidAccept => "invalid_accept",
            Self::LastEventIdTooLarge => "last_event_id_too_large",
            Self::LastEventIdInvalid => "last_event_id_invalid",
            Self::LastEventIdTooOld => "last_event_id_too_old",
            Self::LastEventIdUnknown => "last_event_id_unknown",
            Self::StreamIdMissing => "stream_id_missing",
            Self::StreamIdTooLarge => "stream_id_too_large",
            Self::StreamIdInvalid => "stream_id_invalid",
            Self::DuplicateStream => "duplicate_stream",
            Self::UnknownStream => "unknown_stream",
            Self::StreamCompleted => "stream_completed",
            Self::StreamCancelled => "stream_cancelled",
            Self::ResponseEnvelopeInvalid => "response_envelope_invalid",
            Self::EventTooLarge => "event_too_large",
            Self::EventFramingInvalid => "event_framing_invalid",
            Self::RetentionOverflow => "retention_overflow",
            Self::StreamCardinalityOverflow => "stream_cardinality_overflow",
            Self::SessionCardinalityOverflow => "session_cardinality_overflow",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::MissingSession
            | Self::InvalidAccept
            | Self::LastEventIdTooLarge
            | Self::LastEventIdInvalid
            | Self::LastEventIdUnknown
            | Self::StreamIdMissing
            | Self::StreamIdTooLarge
            | Self::StreamIdInvalid
            | Self::ResponseEnvelopeInvalid
            | Self::EventTooLarge
            | Self::EventFramingInvalid => 400,
            Self::UnknownSession | Self::StaleSession | Self::UnknownStream => 404,
            Self::DuplicateListener
            | Self::DuplicateStream
            | Self::StreamCompleted
            | Self::StreamCancelled
            | Self::BrokerRetired => 409,
            // The retained history this cursor asks for is gone for good, so a
            // retry cannot recover it. That is a 410, not a 404 "try again".
            Self::LastEventIdTooOld => 410,
            Self::RetentionOverflow
            | Self::StreamCardinalityOverflow
            | Self::SessionCardinalityOverflow => 503,
        }
    }
}

/// Canonical, bounded, TYPE-SENSITIVE stream identity from a JSON-RPC id.
///
/// JSON-RPC distinguishes the string `"1"` from the number `1`, so the two must
/// never collapse onto one multiplexed stream. The discriminant participates in
/// `Eq`/`Hash`, which is what keeps them apart.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamIdentity {
    /// JSON-RPC string id, verbatim within the configured byte bound.
    Text(Arc<str>),
    /// JSON-RPC numeric id in its canonical serialized form.
    Number(Arc<str>),
}

impl StreamIdentity {
    /// Admit a JSON-RPC id as a stream identity. Objects, arrays, booleans and
    /// null fail closed, as do over-bound and control-bearing values. A
    /// rejected value is never retained, echoed, or logged.
    pub fn from_json_rpc_id(id: &Value, max_bytes: usize) -> Result<Self, AggregateSseError> {
        match id {
            Value::String(text) => {
                if text.is_empty() {
                    return Err(AggregateSseError::StreamIdMissing);
                }
                if text.len() > max_bytes {
                    return Err(AggregateSseError::StreamIdTooLarge);
                }
                // Control bytes would let an identity break SSE framing or a
                // log line if it were ever mirrored outward.
                if text.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
                    return Err(AggregateSseError::StreamIdInvalid);
                }
                Ok(Self::Text(Arc::from(text.as_str())))
            }
            Value::Number(number) => {
                let canonical = number.to_string();
                if canonical.len() > max_bytes {
                    return Err(AggregateSseError::StreamIdTooLarge);
                }
                Ok(Self::Number(Arc::from(canonical.as_str())))
            }
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
                Err(AggregateSseError::StreamIdInvalid)
            }
        }
    }

    /// Canonical text form. Internal/equality use only — callers must not log
    /// it, because it is a verbatim client-controlled JSON-RPC id.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn canonical(&self) -> &str {
        match self {
            Self::Text(value) | Self::Number(value) => value,
        }
    }
}

/// Lifecycle phase of a request stream on a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamPhase {
    Open,
    Completed,
    Cancelled,
}

/// One retained event: the pre-framed SSE record plus its assigned id.
struct RetainedEvent {
    event_id: u64,
    framed: Bytes,
}

/// The single attached listener for a session.
struct ListenerState {
    epoch: u64,
    /// Highest event id already handed to this listener.
    cursor: u64,
    waker: Option<Waker>,
    greeted: bool,
    /// Absolute end of this listener's bounded lifetime.
    ///
    /// The body's own timer ends the stream at this age whenever the transport
    /// is still polling it. It is ALSO the supersession deadline, which is the
    /// part that does not depend on polling: past it, a fresh attach takes the
    /// slot. That is what keeps a listener whose transport stopped polling the
    /// body — a peer that stopped reading can park an HTTP/1.1 or HTTP/2 write
    /// indefinitely — from locking its session out of SSE for good.
    expires_at: Instant,
}

/// All mutable session state, guarded by one non-async mutex. No method here
/// awaits, allocates without a bound, or acquires a second lock.
struct SessionInner {
    closed: bool,
    streams: HashMap<StreamIdentity, StreamPhase>,
    open_streams: usize,
    /// FIFO of terminal identities. Terminal records exist only to refuse a
    /// late or duplicate response, so they are bounded like the open set.
    terminal_order: VecDeque<StreamIdentity>,
    /// Single retained ring: pre-listener staging AND `Last-Event-ID` replay.
    history: VecDeque<RetainedEvent>,
    history_bytes: usize,
    /// Capacity promised to responses that selected an empty POST-side `202`
    /// but have not crossed the observe-only committed-response boundary yet.
    /// Reserved payloads live on their request contexts, not in this ring, so
    /// listeners cannot observe them before the final response is accepted.
    reserved_events: usize,
    reserved_bytes: usize,
    last_event_id: u64,
    delivered_through: u64,
    /// Highest event id dropped from history. A cursor below it cannot resume.
    evicted_through: u64,
    listener: Option<ListenerState>,
    next_listener_epoch: u64,
    last_activity: Instant,
}

impl SessionInner {
    fn new() -> Self {
        Self {
            closed: false,
            streams: HashMap::new(),
            open_streams: 0,
            terminal_order: VecDeque::new(),
            history: VecDeque::new(),
            history_bytes: 0,
            reserved_events: 0,
            reserved_bytes: 0,
            last_event_id: 0,
            delivered_through: 0,
            evicted_through: 0,
            listener: None,
            next_listener_epoch: 1,
            last_activity: Instant::now(),
        }
    }

    fn take_waker(&mut self) -> Option<Waker> {
        match self.listener.as_mut() {
            Some(listener) => listener.waker.take(),
            None => None,
        }
    }

    /// Number of leading history entries a consumer has already taken. Only
    /// those are eviction candidates.
    fn replayable_prefix(&self, consumed: u64) -> usize {
        self.history
            .partition_point(|event| event.event_id <= consumed)
    }

    /// The watermark below which history is replay-only. With a listener
    /// attached it is that listener's cursor, so a mid-replay resume cannot
    /// have events evicted out from under it; with none attached it is the
    /// last delivery watermark.
    fn consumed_watermark(&self) -> u64 {
        match self.listener.as_ref() {
            Some(listener) => listener.cursor,
            None => self.delivered_through,
        }
    }

    /// Drop retained events from the front. ONLY already-consumed events are
    /// eligible: an event still owed to a consumer is a JSON-RPC response no
    /// client has seen, so capacity pressure fails the publish instead of
    /// losing it.
    fn trim(&mut self, bounds: &AggregateSseBounds) {
        self.trim_for_admission(bounds, 0, 0);
    }

    /// Evict already-consumed history until the current ring plus an incoming
    /// reservation fits. The incoming totals include every outstanding private
    /// publication reservation plus, for publish/commit admission, the event
    /// currently being considered.
    ///
    /// Looking only at the current ring is insufficient for publish admission:
    /// a ring exactly at its event or byte cap can still contain delivered,
    /// safely-evictable history. Reserve the incoming footprint while trimming
    /// so that history is released before a new response is refused. Events
    /// still owed to the listener remain ineligible, preserving fail-closed
    /// delivery.
    fn trim_for_admission(
        &mut self,
        bounds: &AggregateSseBounds,
        incoming_events: usize,
        incoming_bytes: usize,
    ) {
        let consumed = self.consumed_watermark();
        let mut replayable = self.replayable_prefix(consumed);
        while replayable > 0 {
            let over_replay = replayable > bounds.max_replay_events;
            let over_events =
                self.history.len().saturating_add(incoming_events) > bounds.max_retained_events;
            let over_bytes =
                self.history_bytes.saturating_add(incoming_bytes) > bounds.max_retained_bytes;
            if !over_replay && !over_events && !over_bytes {
                break;
            }
            let Some(event) = self.history.pop_front() else {
                break;
            };
            let released = event.framed.len();
            self.history_bytes = self.history_bytes.saturating_sub(released);
            self.evicted_through = self.evicted_through.max(event.event_id);
            replayable -= 1;
        }
    }

    /// Admit and retain one event, returning its assigned id. The id is
    /// committed only after admission succeeds, so a refused publish never
    /// leaves a hole in the sequence a resuming client could stall on.
    fn retain_event(
        &mut self,
        bounds: &AggregateSseBounds,
        encoded: &[u8],
    ) -> Result<u64, AggregateSseError> {
        let event_id = self.last_event_id.saturating_add(1);
        let framed = frame_sse_event(event_id, encoded);
        self.trim_for_admission(
            bounds,
            self.reserved_events.saturating_add(1),
            self.reserved_bytes.saturating_add(framed.len()),
        );
        let projected_events = self
            .history
            .len()
            .saturating_add(self.reserved_events)
            .saturating_add(1);
        let projected_bytes = self
            .history_bytes
            .saturating_add(self.reserved_bytes)
            .saturating_add(framed.len());
        if projected_events > bounds.max_retained_events {
            return Err(AggregateSseError::RetentionOverflow);
        }
        if projected_bytes > bounds.max_retained_bytes {
            return Err(AggregateSseError::RetentionOverflow);
        }
        self.history_bytes = self.history_bytes.saturating_add(framed.len());
        self.history.push_back(RetainedEvent { event_id, framed });
        self.last_event_id = event_id;
        self.last_activity = Instant::now();
        Ok(event_id)
    }

    /// Move an OPEN identity to a terminal phase and return its capacity.
    ///
    /// Idempotent by construction: an unknown or already-terminal identity is
    /// left alone, so however many release paths run for one request the
    /// open-stream count is decremented exactly once and a cancellation is
    /// never overwritten by a later completion.
    fn terminalize_stream(
        &mut self,
        identity: &StreamIdentity,
        phase: StreamPhase,
        max_open: usize,
    ) -> bool {
        if !matches!(self.streams.get(identity), Some(StreamPhase::Open)) {
            return false;
        }
        self.open_streams = self.open_streams.saturating_sub(1);
        record_terminal(self, identity.clone(), phase, max_open);
        true
    }

    /// First retained event strictly after `cursor`. History ids ascend, so
    /// this is a partition point rather than a scan.
    fn event_after(&self, cursor: u64) -> Option<(u64, Bytes)> {
        let index = self.replayable_prefix(cursor);
        self.history
            .get(index)
            .map(|event| (event.event_id, event.framed.clone()))
    }
}

/// Per-session broker state. Private on purpose: no public method hands one
/// out, so the type never appears in a public signature.
struct SessionState {
    /// Shared with the owning broker so the delivery side can apply the same
    /// retention policy the publish side does, without a second lock.
    bounds: Arc<AggregateSseBounds>,
    inner: Mutex<SessionInner>,
}

impl SessionState {
    fn new(bounds: Arc<AggregateSseBounds>) -> Self {
        Self {
            bounds,
            inner: Mutex::new(SessionInner::new()),
        }
    }

    /// Lock the session. Poisoning is recovered rather than propagated: the
    /// guarded state is plain bookkeeping, and one panicking holder must not be
    /// able to wedge teardown for every other session.
    fn lock(&self) -> MutexGuard<'_, SessionInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Mark a session dead and release every payload-bearing allocation before
    /// returning its listener waker. Old response bodies or request leases may
    /// still hold this `SessionState` after DELETE/eviction/reload (especially a
    /// transport parked in a write), but a dead generation has no legal replay
    /// consumer. Clearing here prevents each stale body from pinning a full
    /// retained-byte budget until the peer finally disconnects.
    fn close_inner(inner: &mut SessionInner) -> Option<Waker> {
        inner.closed = true;
        let waker = inner.take_waker();
        inner.listener = None;
        inner.streams.clear();
        inner.open_streams = 0;
        inner.terminal_order.clear();
        inner.history.clear();
        inner.history_bytes = 0;
        inner.reserved_events = 0;
        inner.reserved_bytes = 0;
        waker
    }

    /// Close the session and hand back the listener waker, so the caller can
    /// wake the body AFTER releasing every lock it holds.
    fn close(&self) -> Option<Waker> {
        let mut inner = self.lock();
        Self::close_inner(&mut inner)
    }

    fn close_if_idle(&self, now: Instant, ttl: Duration) -> (bool, Option<Waker>) {
        let mut inner = self.lock();
        if now.saturating_duration_since(inner.last_activity) < ttl {
            return (false, None);
        }
        let waker = Self::close_inner(&mut inner);
        (true, waker)
    }

    /// Release the single listener slot when `epoch` still owns it. Epoch
    /// matching keeps a stale body's teardown from evicting the listener a
    /// later reattach installed.
    fn release_listener(&self, epoch: u64) {
        let mut inner = self.lock();
        let owned = match inner.listener.as_ref() {
            Some(listener) => listener.epoch == epoch,
            None => false,
        };
        if owned {
            inner.listener = None;
            inner.last_activity = Instant::now();
        }
    }

    /// Publish the terminal event for an already-open identity.
    ///
    /// Admission, retention, completion and waker capture happen in ONE
    /// critical section, so a concurrent cancel or a duplicate response can
    /// never interleave. Every outcome is terminal for the identity: a
    /// successful publish completes it, a cancel refuses it (its capacity was
    /// already returned by the cancel), and a retention/encoding refusal
    /// completes it anyway so the caller's inline answer is the identity's one
    /// terminal outcome and its capacity is returned exactly once.
    // Kept as the direct-publication primitive for library consumers and the
    // external broker contract suite. The ferrum-edge binary's private module
    // copy uses the later two-phase reservation path exclusively.
    #[allow(dead_code)]
    fn publish_terminal(
        &self,
        identity: &StreamIdentity,
        encoded: &[u8],
    ) -> Result<u64, AggregateSseError> {
        let max_open = self.bounds.max_streams_per_session;
        let (outcome, waker) = {
            let mut inner = self.lock();
            if inner.closed {
                return Err(AggregateSseError::StaleSession);
            }
            match inner.streams.get(identity).copied() {
                Some(StreamPhase::Open) => {}
                Some(StreamPhase::Completed) => return Err(AggregateSseError::StreamCompleted),
                Some(StreamPhase::Cancelled) => return Err(AggregateSseError::StreamCancelled),
                None => return Err(AggregateSseError::UnknownStream),
            }
            match inner.retain_event(&self.bounds, encoded) {
                Ok(event_id) => {
                    inner.terminalize_stream(identity, StreamPhase::Completed, max_open);
                    let waker = inner.take_waker();
                    (Ok(event_id), waker)
                }
                Err(error) => {
                    inner.terminalize_stream(identity, StreamPhase::Completed, max_open);
                    inner.last_activity = Instant::now();
                    (Err(error), None)
                }
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        outcome
    }

    /// Promise one future retained-event slot without making payload bytes
    /// visible to the listener. Every direct publisher includes this promise in
    /// its own admission calculation, so a successful reservation remains
    /// commit-capable even if unrelated responses publish first.
    fn reserve_terminal(
        &self,
        identity: &StreamIdentity,
        reserved_bytes: usize,
    ) -> Result<(), AggregateSseError> {
        let max_open = self.bounds.max_streams_per_session;
        let mut inner = self.lock();
        if inner.closed {
            return Err(AggregateSseError::StaleSession);
        }
        match inner.streams.get(identity).copied() {
            Some(StreamPhase::Open) => {}
            Some(StreamPhase::Completed) => return Err(AggregateSseError::StreamCompleted),
            Some(StreamPhase::Cancelled) => return Err(AggregateSseError::StreamCancelled),
            None => return Err(AggregateSseError::UnknownStream),
        }
        let incoming_events = inner.reserved_events.saturating_add(1);
        let incoming_bytes = inner.reserved_bytes.saturating_add(reserved_bytes);
        inner.trim_for_admission(&self.bounds, incoming_events, incoming_bytes);
        if inner.history.len().saturating_add(incoming_events) > self.bounds.max_retained_events
            || inner.history_bytes.saturating_add(incoming_bytes) > self.bounds.max_retained_bytes
        {
            inner.terminalize_stream(identity, StreamPhase::Completed, max_open);
            inner.last_activity = Instant::now();
            return Err(AggregateSseError::RetentionOverflow);
        }
        inner.reserved_events = incoming_events;
        inner.reserved_bytes = incoming_bytes;
        inner.last_activity = Instant::now();
        Ok(())
    }

    /// Commit a previously reserved payload after the POST-side response has
    /// survived every rejecting header/body phase. Capacity failure is excluded
    /// by `reserve_terminal` plus reservation-aware direct publication; the
    /// `Result` remains defensive for teardown/cancellation races.
    fn commit_reserved_terminal(
        &self,
        identity: &StreamIdentity,
        encoded: &[u8],
        reserved_bytes: usize,
    ) -> Result<u64, AggregateSseError> {
        let max_open = self.bounds.max_streams_per_session;
        let (outcome, waker) = {
            let mut inner = self.lock();
            inner.reserved_events = inner.reserved_events.saturating_sub(1);
            inner.reserved_bytes = inner.reserved_bytes.saturating_sub(reserved_bytes);
            if inner.closed {
                return Err(AggregateSseError::StaleSession);
            }
            match inner.streams.get(identity).copied() {
                Some(StreamPhase::Open) => {}
                Some(StreamPhase::Completed) => return Err(AggregateSseError::StreamCompleted),
                Some(StreamPhase::Cancelled) => return Err(AggregateSseError::StreamCancelled),
                None => return Err(AggregateSseError::UnknownStream),
            }
            match inner.retain_event(&self.bounds, encoded) {
                Ok(event_id) => {
                    inner.terminalize_stream(identity, StreamPhase::Completed, max_open);
                    let waker = inner.take_waker();
                    (Ok(event_id), waker)
                }
                Err(error) => {
                    // This means reservation accounting drifted. Stay
                    // fail-closed and return the identity capacity rather than
                    // panicking on a production request path.
                    inner.terminalize_stream(identity, StreamPhase::Completed, max_open);
                    inner.last_activity = Instant::now();
                    (Err(error), None)
                }
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        outcome
    }

    /// Release a reservation whose POST-side response was replaced or whose
    /// request ended before the committed boundary. Idempotence is owned by the
    /// reservation lease; saturating counters also make stale-generation drops
    /// harmless after `close_inner` has zeroed the session.
    fn abort_reserved_terminal(&self, identity: &StreamIdentity, reserved_bytes: usize) {
        let max_open = self.bounds.max_streams_per_session;
        let mut inner = self.lock();
        inner.reserved_events = inner.reserved_events.saturating_sub(1);
        inner.reserved_bytes = inner.reserved_bytes.saturating_sub(reserved_bytes);
        if inner.closed {
            return;
        }
        if inner.terminalize_stream(identity, StreamPhase::Completed, max_open) {
            inner.last_activity = Instant::now();
        }
    }

    /// Release an open identity without publishing anything, because the POST
    /// answered inline or the request ended before producing a response.
    fn settle_stream(&self, identity: &StreamIdentity) {
        let max_open = self.bounds.max_streams_per_session;
        let mut inner = self.lock();
        if inner.closed {
            // Session teardown already discarded every stream record.
            return;
        }
        if inner.terminalize_stream(identity, StreamPhase::Completed, max_open) {
            inner.last_activity = Instant::now();
        }
    }

    fn poll_next_frame(&self, epoch: u64, waker: &Waker) -> NextFrame {
        let mut inner = self.lock();
        if inner.closed {
            return NextFrame::Ended;
        }
        let (cursor, greeted) = match inner.listener.as_ref() {
            Some(listener) if listener.epoch == epoch => (listener.cursor, listener.greeted),
            _ => return NextFrame::Ended,
        };
        if !greeted {
            if let Some(listener) = inner.listener.as_mut() {
                listener.greeted = true;
            }
            return NextFrame::Frame(Bytes::from_static(SSE_GREETING));
        }
        let Some((event_id, framed)) = inner.event_after(cursor) else {
            if let Some(listener) = inner.listener.as_mut() {
                listener.waker = Some(waker.clone());
            }
            return NextFrame::Idle;
        };
        if let Some(listener) = inner.listener.as_mut() {
            listener.cursor = event_id;
        }
        if event_id > inner.delivered_through {
            inner.delivered_through = event_id;
        }
        // Apply the retention policy on DELIVERY as well as on publish, so a
        // zero-length replay window really does drop a delivered event (and a
        // later cursor for it fails closed instead of silently resuming).
        inner.trim(&self.bounds);
        inner.last_activity = Instant::now();
        NextFrame::Frame(framed)
    }
}

enum NextFrame {
    Frame(Bytes),
    Idle,
    Ended,
}

/// Monotonic broker-generation source: one ordinal per constructed broker, so a
/// retired generation stays distinguishable in tests and diagnostics.
static NEXT_BROKER_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Process-local multiplexed SSE broker for one `mcp_gateway` plugin
/// generation. Dropping the owning plugin instance drops this broker, which
/// closes every session and ends every attached body.
pub struct AggregateSseBroker {
    generation: u64,
    bounds: Arc<AggregateSseBounds>,
    max_sessions: usize,
    retired: AtomicBool,
    /// Serializes the only state-creating operation against retirement. Without
    /// this gate, an `ensure_session` that observed `retired == false` could be
    /// descheduled until after `retire_generation` swept the map, then insert a
    /// live session into the already-retired generation.
    admission: Mutex<()>,
    /// Reserved slot count. Reservation happens BEFORE insertion, so concurrent
    /// distinct sessions cannot race past `max_sessions` the way a `len()`
    /// probe followed by an insert can.
    reserved_sessions: AtomicUsize,
    sessions: DashMap<String, Arc<SessionState>>,
}

impl AggregateSseBroker {
    pub fn new(bounds: AggregateSseBounds, max_sessions: usize, shard_amount: usize) -> Self {
        Self {
            generation: NEXT_BROKER_GENERATION.fetch_add(1, Ordering::Relaxed),
            bounds: Arc::new(bounds),
            max_sessions: max_sessions.max(1),
            retired: AtomicBool::new(false),
            admission: Mutex::new(()),
            reserved_sessions: AtomicUsize::new(0),
            sessions: DashMap::with_shard_amount(shard_amount.max(1)),
        }
    }

    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn bounds(&self) -> &AggregateSseBounds {
        &self.bounds
    }

    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Retire this generation: refuse every further operation, close every
    /// session, and wake every attached body so its next poll ends the
    /// response. Blocking locks throughout — teardown is never best effort.
    pub fn retire_generation(&self) {
        // Take the same gate as admission before publishing retirement or
        // sweeping. When this function returns, no pre-retirement admission
        // can still insert behind the sweep, and every later admission observes
        // the retired flag while it owns the gate.
        let _admission = self.lock_admission();
        self.retired.store(true, Ordering::Release);
        let mut wakers = Vec::new();
        self.sessions.retain(|_, state| {
            if let Some(waker) = state.close() {
                wakers.push(waker);
            }
            false
        });
        self.reserved_sessions.store(0, Ordering::Release);
        wake_all(wakers);
    }

    /// Admit a broker session for a live downstream MCP session. Idempotent for
    /// an existing live session, and fails closed rather than silently
    /// exceeding the cap.
    pub fn ensure_session(&self, session_id: &str) -> Result<(), AggregateSseError> {
        if session_id.is_empty() {
            return Err(AggregateSseError::MissingSession);
        }
        // This is a cold session-lifecycle operation, not a per-request stream
        // operation. Hold the admission gate through insertion so retirement's
        // sweep is a complete, linearizable boundary.
        let _admission = self.lock_admission();
        if self.retired.load(Ordering::Acquire) {
            return Err(AggregateSseError::BrokerRetired);
        }
        if let Some(state) = self.session_state(session_id) {
            if state.lock().closed {
                return Err(AggregateSseError::StaleSession);
            }
            return Ok(());
        }
        self.reserve_session_slot()?;
        let state = Arc::new(SessionState::new(Arc::clone(&self.bounds)));
        match self.sessions.entry(session_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                // Lost the insert race: hand the reservation straight back so
                // the accounting keeps matching the map exactly.
                let existing = Arc::clone(occupied.get());
                drop(occupied);
                self.release_session_slot();
                if existing.lock().closed {
                    return Err(AggregateSseError::StaleSession);
                }
                Ok(())
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(state);
                Ok(())
            }
        }
    }

    /// Tear down broker state for a deleted, evicted, or expired downstream
    /// session. Synchronous and unconditional: the attached body ends on its
    /// next poll.
    pub fn remove_session(&self, session_id: &str) {
        let Some((_, state)) = self.sessions.remove(session_id) else {
            return;
        };
        self.release_session_slot();
        if let Some(waker) = state.close() {
            waker.wake();
        }
    }

    /// Drop broker sessions idle for at least `ttl`, returning how many were
    /// reclaimed.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn reap_idle(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut wakers = Vec::new();
        let mut reaped = 0usize;
        self.sessions.retain(|_, state| {
            let (closed, waker) = state.close_if_idle(now, ttl);
            if !closed {
                return true;
            }
            if let Some(waker) = waker {
                wakers.push(waker);
            }
            reaped += 1;
            false
        });
        for _ in 0..reaped {
            self.release_session_slot();
        }
        wake_all(wakers);
        reaped
    }

    /// Attach the one SSE listener for a session.
    ///
    /// The cursor decision and the listener install happen inside a single
    /// critical section that every publish also takes, so replay can never be
    /// overtaken by a live event: whichever side wins the lock completes
    /// entirely before the other begins.
    ///
    /// A listener that is past its configured lifetime is SUPERSEDED rather
    /// than refused. The listener's own timer only runs while the transport
    /// polls its body, which a peer that stopped reading can prevent, so
    /// supersession is what actually guarantees the session's single-listener
    /// slot is reusable after `sse_listener_max_lifetime_seconds`. The epoch
    /// bump ends the superseded body on its next poll and makes its own
    /// release a no-op.
    pub fn attach_listener(
        &self,
        session_id: &str,
        last_event_id: Option<&str>,
    ) -> Result<AggregateSseListener, AggregateSseError> {
        let max_leid = self.bounds.max_last_event_id_bytes;
        let requested = parse_last_event_id(last_event_id, max_leid)?;
        if self.retired.load(Ordering::Acquire) {
            return Err(AggregateSseError::BrokerRetired);
        }
        let Some(state) = self.session_state(session_id) else {
            return Err(AggregateSseError::UnknownSession);
        };
        let mut superseded = None;
        let epoch = {
            let mut inner = state.lock();
            if inner.closed {
                return Err(AggregateSseError::StaleSession);
            }
            let now = Instant::now();
            let attached_until = inner.listener.as_ref().map(|listener| listener.expires_at);
            if let Some(expires_at) = attached_until
                && now < expires_at
            {
                return Err(AggregateSseError::DuplicateListener);
            }
            if attached_until.is_some() {
                // Past its lifetime: supersede it. Wake the old body so it
                // observes the epoch change and ends itself; a body parked in a
                // transport write has no waker registered here and simply loses
                // the slot it can no longer serve.
                superseded = inner.take_waker();
            }
            let cursor = match requested {
                // No cursor: resume at the delivery watermark. Events staged
                // while nobody was attached are delivered; events an earlier
                // listener already received are not, so attach never
                // duplicates and never fabricates continuity.
                None => inner.delivered_through,
                Some(cursor) if cursor > inner.last_event_id => {
                    return Err(AggregateSseError::LastEventIdUnknown);
                }
                Some(cursor) if cursor < inner.evicted_through => {
                    return Err(AggregateSseError::LastEventIdTooOld);
                }
                Some(cursor) => cursor,
            };
            let epoch = inner.next_listener_epoch;
            inner.next_listener_epoch = epoch.saturating_add(1);
            inner.listener = Some(ListenerState {
                epoch,
                cursor,
                waker: None,
                greeted: false,
                expires_at: now
                    .checked_add(self.bounds.listener_max_lifetime)
                    .unwrap_or(now),
            });
            inner.last_activity = now;
            epoch
        };
        if let Some(waker) = superseded {
            waker.wake();
        }
        Ok(AggregateSseListener::new(
            state,
            epoch,
            self.bounds.listener_max_lifetime,
            self.bounds.keepalive_interval,
        ))
    }

    /// Whether this session has a listener that can still take delivery.
    ///
    /// A listener past its lifetime is deliberately reported as absent: its
    /// stream is about to end (or has already stopped being polled), so a new
    /// response belongs on the POST rather than staged behind it.
    pub fn has_listener(&self, session_id: &str) -> bool {
        let Some(state) = self.session_state(session_id) else {
            return false;
        };
        let inner = state.lock();
        if inner.closed {
            return false;
        }
        let now = Instant::now();
        inner
            .listener
            .as_ref()
            .is_some_and(|listener| now < listener.expires_at)
    }

    /// Open a request-stream identity on a session and lease it.
    ///
    /// This is the ONLY way a stream becomes open. The request path calls it
    /// before any catalog refresh, upstream initialize, or backend dispatch
    /// begins, so a concurrent `notifications/cancelled` can mark a genuinely
    /// in-flight request rather than an unknown one. The returned lease owns
    /// the identity's capacity: publishing, settling, or simply dropping it
    /// returns that capacity exactly once.
    pub fn open_stream(
        &self,
        session_id: &str,
        identity: &StreamIdentity,
    ) -> Result<AggregateSseStream, AggregateSseError> {
        let state = self.live_session(session_id)?;
        {
            let mut inner = state.lock();
            if inner.closed {
                return Err(AggregateSseError::StaleSession);
            }
            inner.last_activity = Instant::now();
            let max_open = self.bounds.max_streams_per_session;
            admit_stream_open(&mut inner, identity, max_open)?;
        }
        Ok(AggregateSseStream::new(state, identity.clone()))
    }

    /// Cancel an open stream. A cancelled identity refuses its own later
    /// response, which is what makes `notifications/cancelled` meaningful.
    pub fn cancel_stream(
        &self,
        session_id: &str,
        identity: &StreamIdentity,
    ) -> Result<(), AggregateSseError> {
        let state = self.live_session(session_id)?;
        let mut inner = state.lock();
        if inner.closed {
            return Err(AggregateSseError::StaleSession);
        }
        inner.last_activity = Instant::now();
        // Bind the phase before the match: a scrutinee temporary would keep the
        // borrow of `inner` alive across the arms that mutate it.
        let phase = inner.streams.get(identity).copied();
        match phase {
            None => Err(AggregateSseError::UnknownStream),
            Some(StreamPhase::Completed) => Err(AggregateSseError::StreamCompleted),
            Some(StreamPhase::Cancelled) => Err(AggregateSseError::StreamCancelled),
            Some(StreamPhase::Open) => {
                let max_open = self.bounds.max_streams_per_session;
                // Cancellation returns the capacity here; the request's own
                // lease then finds a terminal phase and releases nothing more,
                // so one identity is never decremented twice.
                inner.terminalize_stream(identity, StreamPhase::Cancelled, max_open);
                Ok(())
            }
        }
    }

    fn session_state(&self, session_id: &str) -> Option<Arc<SessionState>> {
        // Clone the handle and drop the shard guard before any session lock is
        // taken, so the two locks are never held together in either order.
        self.sessions
            .get(session_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    fn live_session(&self, session_id: &str) -> Result<Arc<SessionState>, AggregateSseError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(AggregateSseError::BrokerRetired);
        }
        self.session_state(session_id)
            .ok_or(AggregateSseError::UnknownSession)
    }

    fn lock_admission(&self) -> MutexGuard<'_, ()> {
        self.admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn reserve_session_slot(&self) -> Result<(), AggregateSseError> {
        let mut current = self.reserved_sessions.load(Ordering::Acquire);
        loop {
            if current >= self.max_sessions {
                return Err(AggregateSseError::SessionCardinalityOverflow);
            }
            match self.reserved_sessions.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    /// Return one reserved slot, saturating at zero so a retirement that reset
    /// the counter can never make a late removal underflow it.
    fn release_session_slot(&self) {
        let mut current = self.reserved_sessions.load(Ordering::Acquire);
        while current > 0 {
            match self.reserved_sessions.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for AggregateSseBroker {
    fn drop(&mut self) {
        // Reload / update / delete drops the owning plugin instance, which
        // drops this broker: every attached body ends on its next poll and no
        // event can cross generations.
        self.retire_generation();
    }
}

/// Admit a new open stream identity under the per-session cardinality bound.
fn admit_stream_open(
    inner: &mut SessionInner,
    identity: &StreamIdentity,
    max_open: usize,
) -> Result<(), AggregateSseError> {
    let phase = inner.streams.get(identity).copied();
    match phase {
        Some(StreamPhase::Open) => return Err(AggregateSseError::DuplicateStream),
        Some(StreamPhase::Completed) => return Err(AggregateSseError::StreamCompleted),
        Some(StreamPhase::Cancelled) => return Err(AggregateSseError::StreamCancelled),
        None => {}
    }
    if inner.open_streams >= max_open {
        return Err(AggregateSseError::StreamCardinalityOverflow);
    }
    inner.streams.insert(identity.clone(), StreamPhase::Open);
    inner.open_streams += 1;
    Ok(())
}

/// Record a terminal stream phase, evicting the oldest terminal record once the
/// terminal set would outgrow the open-stream bound.
fn record_terminal(
    inner: &mut SessionInner,
    identity: StreamIdentity,
    phase: StreamPhase,
    max_open: usize,
) {
    inner.streams.insert(identity.clone(), phase);
    inner.terminal_order.push_back(identity);
    while inner.terminal_order.len() > max_open {
        let Some(stale) = inner.terminal_order.pop_front() else {
            break;
        };
        let is_terminal = matches!(
            inner.streams.get(&stale),
            Some(StreamPhase::Completed | StreamPhase::Cancelled)
        );
        if is_terminal {
            inner.streams.remove(&stale);
        }
    }
}

fn wake_all(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

/// RAII lease for ONE open multiplexed request stream.
///
/// Held privately on the `RequestContext` for the whole life of the request it
/// opened, which is what makes cleanup exact-once without a detached task:
/// publish, inline settlement, and plain drop all funnel into the same
/// idempotent terminalization, and a context clone shares one lease rather than
/// minting a second claim on the identity. The lease holds only the session
/// state it opened on, never the broker, so an in-flight request cannot delay a
/// generation retirement.
#[derive(Clone)]
pub struct AggregateSseStream(Arc<StreamLease>);

struct StreamLease {
    session: Arc<SessionState>,
    identity: StreamIdentity,
    /// One-shot terminal claim. Set BEFORE the session operation runs, because
    /// every outcome of that operation — published, refused, cancelled — is
    /// terminal for this identity.
    settled: AtomicBool,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        if self.settled.swap(true, Ordering::AcqRel) {
            return;
        }
        // The request ended without publishing: an inline answer, a backend or
        // policy replacement, or a client that went away. Return the capacity
        // and leave a terminal record so a late duplicate is refused.
        self.session.settle_stream(&self.identity);
    }
}

impl fmt::Debug for AggregateSseStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: the identity is a verbatim client JSON-RPC id.
        formatter.write_str("AggregateSseStream { .. }")
    }
}

impl AggregateSseStream {
    fn new(session: Arc<SessionState>, identity: StreamIdentity) -> Self {
        Self(Arc::new(StreamLease {
            session,
            identity,
            settled: AtomicBool::new(false),
        }))
    }

    /// Publish the already-serialized terminal JSON-RPC response for this
    /// identity, exactly as the inline answer would have carried it.
    ///
    /// Bytes, not a `Value`: every producer already holds the exact
    /// client-visible representation — the gateway-authored response body or
    /// the buffered upstream body — so the event is the same octets the inline
    /// answer would have carried, never a re-serialization of them.
    ///
    /// `Err(StreamCancelled)` means the client cancelled this request id and
    /// its result must not be sent; `Err(RetentionOverflow)` / `EventTooLarge` /
    /// `EventFramingInvalid` mean the caller must answer this POST inline.
    /// Either way the identity is terminal afterwards and its capacity has been
    /// returned exactly once.
    // Public library primitive exercised by the external broker contract suite;
    // the ferrum-edge binary itself publishes governed responses in two phases.
    #[allow(dead_code)]
    pub fn publish_encoded(&self, encoded: &[u8]) -> Result<u64, AggregateSseError> {
        if self.0.settled.swap(true, Ordering::AcqRel) {
            // A second terminal attempt on one lease is a duplicate response,
            // never a second event under the same identity.
            return Err(AggregateSseError::StreamCompleted);
        }
        let max_event_bytes = self.0.session.bounds.max_event_bytes;
        if let Err(error) = validate_event_bytes(encoded, max_event_bytes) {
            self.0.session.settle_stream(&self.0.identity);
            return Err(error);
        }
        // The HTTP request and its terminal JSON-RPC body must name the same
        // type-sensitive identity. Without this check a broken or hostile
        // upstream could answer request A with id B and have that response
        // published on the shared listener under A's cancellation/capacity
        // lifecycle. Parsing is bounded by `max_event_bytes`, and the original
        // bytes are still what gets retained after the identity check.
        if !response_matches_stream_identity(
            encoded,
            &self.0.identity,
            self.0.session.bounds.max_stream_id_bytes,
        ) {
            self.0.session.settle_stream(&self.0.identity);
            return Err(AggregateSseError::ResponseEnvelopeInvalid);
        }
        self.0.session.publish_terminal(&self.0.identity, encoded)
    }

    /// Reserve delivery of the already-governed response while the POST-side
    /// empty `202` crosses the final response-header and committed boundaries.
    /// The payload is retained privately by the returned RAII lease and is not
    /// visible to the listener until [`AggregateSsePublication::commit`].
    pub fn reserve_encoded(
        &self,
        encoded: &[u8],
    ) -> Result<AggregateSsePublication, AggregateSseError> {
        if self.0.settled.swap(true, Ordering::AcqRel) {
            return Err(AggregateSseError::StreamCompleted);
        }
        let max_event_bytes = self.0.session.bounds.max_event_bytes;
        if let Err(error) = validate_event_bytes(encoded, max_event_bytes) {
            self.0.session.settle_stream(&self.0.identity);
            return Err(error);
        }
        if !response_matches_stream_identity(
            encoded,
            &self.0.identity,
            self.0.session.bounds.max_stream_id_bytes,
        ) {
            self.0.session.settle_stream(&self.0.identity);
            return Err(AggregateSseError::ResponseEnvelopeInvalid);
        }
        // Reserve against the framing ceiling rather than today's event-id
        // width. Unrelated direct publications may advance the id before this
        // response commits; the fixed ceiling keeps that harmless.
        let reserved_bytes = encoded.len().saturating_add(SSE_FRAME_OVERHEAD_BYTES);
        self.0
            .session
            .reserve_terminal(&self.0.identity, reserved_bytes)?;
        Ok(AggregateSsePublication::new(
            Arc::clone(&self.0.session),
            self.0.identity.clone(),
            Bytes::copy_from_slice(encoded),
            reserved_bytes,
        ))
    }

    /// Give up the identity without publishing, because this POST answered
    /// inline. Idempotent, and never overwrites a cancellation.
    pub fn settle_inline(&self) {
        if self.0.settled.swap(true, Ordering::AcqRel) {
            return;
        }
        self.0.session.settle_stream(&self.0.identity);
    }
}

/// Clone-safe, RAII-owned publication staged between final body policy and the
/// observe-only committed-response hook.
///
/// A `RequestContext` clone shares this one claim. Exactly one caller can commit
/// or abort it; dropping the last handle aborts and returns both the retained
/// reservation and the request-stream capacity.
#[derive(Clone)]
pub struct AggregateSsePublication(Arc<PublicationLease>);

struct PublicationLease {
    session: Arc<SessionState>,
    identity: StreamIdentity,
    encoded: Bytes,
    reserved_bytes: usize,
    finished: AtomicBool,
}

impl Drop for PublicationLease {
    fn drop(&mut self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.session
            .abort_reserved_terminal(&self.identity, self.reserved_bytes);
    }
}

impl fmt::Debug for AggregateSsePublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: both the identity and payload are client data.
        formatter.write_str("AggregateSsePublication { .. }")
    }
}

impl AggregateSsePublication {
    fn new(
        session: Arc<SessionState>,
        identity: StreamIdentity,
        encoded: Bytes,
        reserved_bytes: usize,
    ) -> Self {
        Self(Arc::new(PublicationLease {
            session,
            identity,
            encoded,
            reserved_bytes,
            finished: AtomicBool::new(false),
        }))
    }

    /// Make the reserved event visible. Capacity is already promised; errors
    /// are limited to cancellation/session teardown or defensive accounting
    /// failure and never panic the proxy path.
    pub fn commit(&self) -> Result<u64, AggregateSseError> {
        if self.0.finished.swap(true, Ordering::AcqRel) {
            return Err(AggregateSseError::StreamCompleted);
        }
        self.0.session.commit_reserved_terminal(
            &self.0.identity,
            &self.0.encoded,
            self.0.reserved_bytes,
        )
    }

    /// Settle the identity without publication because final policy replaced
    /// the POST-side acknowledgement. Idempotent across context clones.
    pub fn abort(&self) {
        if self.0.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.0
            .session
            .abort_reserved_terminal(&self.0.identity, self.0.reserved_bytes);
    }
}

/// Single-consumer handle to a session's attached SSE stream.
///
/// Cloning this handle (a `RequestContext` clone does) shares one inner lease:
/// [`AggregateSseListener::take_body`] is a one-shot compare-and-swap, so a
/// clone can neither duplicate nor steal the stream. Dropping every clone
/// without taking the body releases the listener slot, so a rejection a later
/// plugin replaced does not strand the session.
#[derive(Clone)]
pub struct AggregateSseListener(Arc<ListenerLease>);

struct ListenerLease {
    session: Arc<SessionState>,
    epoch: u64,
    max_lifetime: Duration,
    keepalive: Duration,
    taken: AtomicBool,
}

impl Drop for ListenerLease {
    fn drop(&mut self) {
        if self.taken.load(Ordering::Acquire) {
            // The body owns the slot now and releases it on its own drop.
            return;
        }
        self.session.release_listener(self.epoch);
    }
}

impl fmt::Debug for AggregateSseListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: never expose a session id or an event cursor.
        formatter.write_str("AggregateSseListener { .. }")
    }
}

impl AggregateSseListener {
    fn new(
        session: Arc<SessionState>,
        epoch: u64,
        max_lifetime: Duration,
        keepalive: Duration,
    ) -> Self {
        Self(Arc::new(ListenerLease {
            session,
            epoch,
            max_lifetime,
            keepalive,
            taken: AtomicBool::new(false),
        }))
    }

    /// Take the streaming body exactly once. Every later caller gets `None`,
    /// which is what makes ownership single-consumer across context clones and
    /// across the H1/H2 and native H3 response builders alike.
    pub fn take_body(&self) -> Option<AggregateSseBody> {
        let lease = &self.0;
        if lease.taken.swap(true, Ordering::AcqRel) {
            return None;
        }
        let now = tokio::time::Instant::now();
        let deadline = now + lease.max_lifetime;
        let first_wake = now + lease.keepalive.min(lease.max_lifetime);
        Some(AggregateSseBody {
            session: Arc::clone(&lease.session),
            epoch: lease.epoch,
            deadline,
            keepalive: lease.keepalive,
            timer: Box::pin(tokio::time::sleep_until(first_wake)),
            finished: false,
        })
    }
}

/// The multiplexed SSE response body for one attached listener.
///
/// Ending this stream is the ONLY way the listener slot is released on the
/// delivery side, and it happens in `Drop` through one plain bookkeeping
/// critical section — no channel, no async lock, no best-effort `try_lock`. A
/// client transport disconnect therefore always permits a reattach.
pub struct AggregateSseBody {
    session: Arc<SessionState>,
    epoch: u64,
    deadline: tokio::time::Instant,
    keepalive: Duration,
    timer: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
}

impl fmt::Debug for AggregateSseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AggregateSseBody { .. }")
    }
}

impl AggregateSseBody {
    /// Absolute end of this stream's broker-owned listener lifetime.
    ///
    /// The in-body timer only advances while the transport polls this stream.
    /// Native HTTP/3 writes with an awaited `send_data`, which a peer that stops
    /// reading can park indefinitely, so that writer composes this deadline with
    /// the admitted request's captured authorization plan and enforces the
    /// earliest of the two as a hard bound around every flow-control-blocked
    /// write instead of relying on the poll.
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    /// Retained payload bytes still owned by this body's session. External
    /// regressions use this to prove teardown releases history even when the
    /// body itself deliberately remains alive like a stalled transport.
    #[allow(dead_code)]
    pub fn retained_session_bytes_for_test(&self) -> usize {
        self.session.lock().history_bytes
    }
}

impl Drop for AggregateSseBody {
    fn drop(&mut self) {
        self.session.release_listener(self.epoch);
    }
}

impl futures_util::Stream for AggregateSseBody {
    type Item = SseFrameResult;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        match this.session.poll_next_frame(this.epoch, cx.waker()) {
            NextFrame::Ended => {
                this.finished = true;
                return Poll::Ready(None);
            }
            NextFrame::Frame(framed) => return Poll::Ready(Some(Ok(Frame::data(framed)))),
            NextFrame::Idle => {}
        }
        // Idle: the timer is what bounds an otherwise silent stream. It ends
        // the response at the lifetime deadline and otherwise emits a keepalive
        // comment, which is how a vanished peer is discovered on a quiet
        // session. It advances only while this body is being polled, so it is
        // not by itself a reclamation guarantee — a peer that stops reading can
        // park the transport's write and with it this poll. The unconditional
        // guarantees are elsewhere: `AggregateSseBroker::attach_listener`
        // supersedes a listener past `expires_at`, session delete / idle
        // reaping / generation retirement close the session outright, and the
        // native H3 writer composes `deadline()` with the captured
        // authorization plan and bounds its send loop by the earlier instant.
        if this.timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        let now = tokio::time::Instant::now();
        if now >= this.deadline {
            this.finished = true;
            return Poll::Ready(None);
        }
        let next_wake = this.deadline.min(now + this.keepalive);
        this.timer.as_mut().reset(next_wake);
        let keepalive = Bytes::from_static(SSE_KEEPALIVE);
        Poll::Ready(Some(Ok(Frame::data(keepalive))))
    }
}

/// Admit already-serialized event bytes under the per-event ceiling. Bytes whose
/// framing would break SSE line structure are refused rather than escaped, so
/// the wire representation stays exactly one `data:` line.
///
/// The two refusals are DISTINCT reasons. A CR/LF-bearing payload — an upstream
/// JSON body terminated by a newline is the common one — is not oversized: SSE
/// line folding would silently reshape those bytes, and this multiplexer only
/// ever publishes the exact octets the inline answer would have carried. Fixed
/// diagnostics must describe the refusal that actually happened, so it gets its
/// own low-cardinality token instead of being reported as `event_too_large`.
fn validate_event_bytes(encoded: &[u8], max_event_bytes: usize) -> Result<(), AggregateSseError> {
    if encoded.len() > max_event_bytes {
        return Err(AggregateSseError::EventTooLarge);
    }
    if encoded.iter().any(|byte| *byte == b'\n' || *byte == b'\r') {
        return Err(AggregateSseError::EventFramingInvalid);
    }
    Ok(())
}

fn response_matches_stream_identity(
    encoded: &[u8],
    expected: &StreamIdentity,
    max_identity_bytes: usize,
) -> bool {
    // Different JSON consumers disagree on duplicate object members. A shared
    // stream cannot safely route an envelope when one peer may read a different
    // `id`, `result`, or `error` than the gateway did.
    if crate::util::json_dup_keys::slice_ambiguity(encoded).is_some() {
        return false;
    }
    let Ok(response) = serde_json::from_slice::<Value>(encoded) else {
        return false;
    };
    let Some(object) = response.as_object() else {
        return false;
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.contains_key("result") == object.contains_key("error")
    {
        return false;
    }
    let Some(id) = object.get("id") else {
        return false;
    };
    StreamIdentity::from_json_rpc_id(id, max_identity_bytes)
        .is_ok_and(|observed| &observed == expected)
}

/// Parse `Last-Event-ID` into a resume cursor. Bounded, digits only, and never
/// echoed back to the client or into a log.
fn parse_last_event_id(
    raw: Option<&str>,
    max_bytes: usize,
) -> Result<Option<u64>, AggregateSseError> {
    let trimmed = raw.map(str::trim).filter(|value| !value.is_empty());
    let Some(value) = trimmed else {
        return Ok(None);
    };
    if value.len() > max_bytes {
        return Err(AggregateSseError::LastEventIdTooLarge);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AggregateSseError::LastEventIdInvalid);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| AggregateSseError::LastEventIdInvalid)
}

fn frame_sse_event(event_id: u64, data: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(SSE_FRAME_OVERHEAD_BYTES + data.len());
    out.extend_from_slice(b"id: ");
    out.extend_from_slice(event_id.to_string().as_bytes());
    out.extend_from_slice(b"\nevent: message\ndata: ");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\n\n");
    Bytes::from(out)
}

/// Returns true when request headers carry a usable `text/event-stream` Accept.
pub fn headers_request_aggregate_sse(headers: &HashMap<String, String>) -> bool {
    crate::plugins::utils::sse::headers_accept_sse(headers)
}
