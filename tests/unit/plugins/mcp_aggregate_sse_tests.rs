//! External unit coverage for the aggregate MCP SSE session broker (#3295).
//!
//! Covers the invariants the broker exists to hold: one listener per session
//! multiplexing many request streams, race-free session and stream
//! cardinality, a single retained-byte budget, deterministic replay-then-live
//! ordering, explicit `Last-Event-ID` semantics, reliable teardown on
//! disconnect / delete / reload, and value-free diagnostics.

use ferrum_edge::plugins::mcp_aggregate_sse::{
    AggregateSseBody, AggregateSseBounds, AggregateSseBroker, AggregateSseError as SseError,
    AggregateSseStream, SseFrameResult, StreamIdentity,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

const FRAME_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_WINDOW: Duration = Duration::from_millis(150);

fn bounds() -> AggregateSseBounds {
    AggregateSseBounds::default()
}

fn broker() -> AggregateSseBroker {
    AggregateSseBroker::new(bounds(), 16, 4)
}

fn text_id(value: &str) -> StreamIdentity {
    match StreamIdentity::from_json_rpc_id(&json!(value), 128) {
        Ok(identity) => identity,
        Err(error) => panic!("string id must be admissible: {error:?}"),
    }
}

fn number_id(value: i64) -> StreamIdentity {
    match StreamIdentity::from_json_rpc_id(&json!(value), 128) {
        Ok(identity) => identity,
        Err(error) => panic!("number id must be admissible: {error:?}"),
    }
}

fn identity_error(id: Value) -> SseError {
    match StreamIdentity::from_json_rpc_id(&id, 128) {
        Ok(_) => panic!("identity must be refused"),
        Err(error) => error,
    }
}

/// One request's whole broker lifecycle: open the identity, then publish its
/// terminal response. This is the production shape — the request path opens
/// before its slow work and the response path publishes on the lease.
fn publish(broker: &AggregateSseBroker, session: &str, id: i64) -> Result<u64, SseError> {
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": {"n": id}});
    let stream = broker.open_stream(session, &number_id(id))?;
    stream.publish_encoded(&encode(&payload))
}

fn publish_text(broker: &AggregateSseBroker, session: &str, id: &str) -> Result<u64, SseError> {
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": {}});
    let stream = broker.open_stream(session, &text_id(id))?;
    stream.publish_encoded(&encode(&payload))
}

/// The exact client-visible bytes a response carries. Production never hands
/// the broker a `Value`: it publishes the response representation itself.
fn encode(payload: &Value) -> Vec<u8> {
    match serde_json::to_vec(payload) {
        Ok(encoded) => encoded,
        Err(error) => panic!("payload must serialize: {error}"),
    }
}

/// Open and HOLD a stream identity, the way an in-flight request does.
fn open(broker: &AggregateSseBroker, session: &str, id: &str) -> AggregateSseStream {
    match broker.open_stream(session, &text_id(id)) {
        Ok(stream) => stream,
        Err(error) => panic!("stream must open: {error:?}"),
    }
}

fn frame_text(frame: Option<SseFrameResult>) -> String {
    let frame = match frame {
        Some(Ok(frame)) => frame,
        Some(Err(error)) => panic!("broker bodies never error: {error}"),
        None => panic!("stream ended before the expected frame"),
    };
    let data = match frame.into_data() {
        Ok(data) => data,
        Err(_) => panic!("broker bodies emit data frames only"),
    };
    String::from_utf8_lossy(&data).into_owned()
}

async fn next_frame(body: &mut AggregateSseBody) -> Option<SseFrameResult> {
    match tokio::time::timeout(FRAME_TIMEOUT, body.next()).await {
        Ok(frame) => frame,
        Err(_) => panic!("expected a frame within the timeout"),
    }
}

/// True when the stream produces nothing within `IDLE_WINDOW`.
async fn stays_idle(body: &mut AggregateSseBody) -> bool {
    let polled = tokio::time::timeout(IDLE_WINDOW, body.next()).await;
    polled.is_err()
}

async fn assert_ended(body: &mut AggregateSseBody) {
    match tokio::time::timeout(FRAME_TIMEOUT, body.next()).await {
        Ok(None) => {}
        Ok(Some(_)) => panic!("stream produced a frame after it should have ended"),
        Err(_) => panic!("stream did not end promptly"),
    }
}

/// Drain frames until every needle has been seen or the stream stalls.
async fn drain_until(body: &mut AggregateSseBody, wanted: &[&str], max_frames: usize) -> String {
    let mut seen = String::new();
    for _ in 0..max_frames {
        if wanted.iter().all(|needle| seen.contains(needle)) {
            break;
        }
        let Ok(frame) = tokio::time::timeout(FRAME_TIMEOUT, body.next()).await else {
            break;
        };
        if frame.is_none() {
            break;
        }
        seen.push_str(&frame_text(frame));
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_listener_multiplexes_concurrent_request_streams() {
    let broker = Arc::new(broker());
    broker.ensure_session("sess-a").unwrap();
    let listener = broker.attach_listener("sess-a", None).unwrap();
    let mut body = listener.take_body().expect("body claimed once");

    let publish_a = {
        let broker = Arc::clone(&broker);
        tokio::spawn(async move { publish_text(&broker, "sess-a", "req-a") })
    };
    let publish_b = {
        let broker = Arc::clone(&broker);
        tokio::spawn(async move { publish(&broker, "sess-a", 42) })
    };
    let first = publish_a.await.unwrap().unwrap();
    let second = publish_b.await.unwrap().unwrap();
    // Each multiplexed event carries its own monotonic SSE id.
    assert_ne!(first, second);

    let seen = drain_until(&mut body, &["req-a", "\"n\":42"], 8).await;
    // The greeting proves the stream is established before any event.
    assert!(seen.contains(": mcp-sse"));
    assert!(seen.contains("req-a"), "string identity delivered");
    assert!(seen.contains("\"n\":42"), "number identity delivered");
    assert!(seen.contains("event: message"));
}

#[test]
fn json_rpc_string_and_number_identities_never_collide() {
    let string_one = StreamIdentity::from_json_rpc_id(&json!("1"), 128);
    let number_one = StreamIdentity::from_json_rpc_id(&json!(1), 128);
    assert_ne!(string_one.unwrap(), number_one.unwrap());
}

#[test]
fn string_and_number_identities_are_separate_streams() {
    let broker = broker();
    broker.ensure_session("sess-id").unwrap();
    publish_text(&broker, "sess-id", "1").unwrap();
    // A DIFFERENT stream, so it is still admissible even though the string
    // form just completed and would otherwise be refused as a duplicate.
    publish(&broker, "sess-id", 1).unwrap();
}

#[test]
fn unrepresentable_and_oversized_identities_fail_closed() {
    let object = identity_error(json!({"x": 1}));
    assert_eq!(object, SseError::StreamIdInvalid);
    let array = identity_error(json!([1]));
    assert_eq!(array, SseError::StreamIdInvalid);
    let boolean = identity_error(json!(true));
    assert_eq!(boolean, SseError::StreamIdInvalid);
    let null = identity_error(json!(null));
    assert_eq!(null, SseError::StreamIdInvalid);
    let empty = identity_error(json!(""));
    assert_eq!(empty, SseError::StreamIdMissing);
    let long = identity_error(json!("x".repeat(200)));
    assert_eq!(long, SseError::StreamIdTooLarge);
    // Control bytes would break SSE framing if an identity were ever mirrored.
    let control = identity_error(json!("a\nb"));
    assert_eq!(control, SseError::StreamIdInvalid);
}

#[test]
fn completed_stream_releases_capacity_and_refuses_late_duplicates() {
    let tuned = AggregateSseBounds {
        max_streams_per_session: 2,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-cap").unwrap();

    let first = open(&broker, "sess-cap", "s1");
    let _second = open(&broker, "sess-cap", "s2");
    // A third concurrent OPEN stream exceeds the per-session bound.
    let overflow = broker.open_stream("sess-cap", &text_id("s3"));
    assert_eq!(overflow.unwrap_err(), SseError::StreamCardinalityOverflow);

    // Completing a stream must return its capacity, or the session would be
    // permanently exhausted after `max_streams_per_session` requests.
    let reply = json!({"jsonrpc": "2.0", "id": "s1", "result": {}});
    first.publish_encoded(&encode(&reply)).unwrap();
    let _third = open(&broker, "sess-cap", "s3");

    // A late or duplicate response for a completed identity is refused rather
    // than misattributed onto a fresh stream. The lease itself refuses a second
    // terminal attempt, and re-opening the identity is refused too.
    let late = first.publish_encoded(&encode(&reply));
    assert_eq!(late.unwrap_err(), SseError::StreamCompleted);
    let reopen = broker.open_stream("sess-cap", &text_id("s1"));
    assert_eq!(reopen.unwrap_err(), SseError::StreamCompleted);
}

#[test]
fn dropping_an_open_lease_releases_capacity_exactly_once() {
    let tuned = AggregateSseBounds {
        max_streams_per_session: 2,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-drop-lease").unwrap();

    // A request that ends without ever publishing — a backend error, a policy
    // replacement, or a client that went away — must return its capacity.
    let abandoned = open(&broker, "sess-drop-lease", "d1");
    let held = open(&broker, "sess-drop-lease", "d2");
    let full = broker.open_stream("sess-drop-lease", &text_id("d3"));
    assert_eq!(full.unwrap_err(), SseError::StreamCardinalityOverflow);
    drop(abandoned);
    let _reused = open(&broker, "sess-drop-lease", "d3");

    // The abandoned identity is terminal, so a late duplicate cannot reopen it.
    let reopen = broker.open_stream("sess-drop-lease", &text_id("d1"));
    assert_eq!(reopen.unwrap_err(), SseError::StreamCompleted);

    // Exactly ONE slot comes back per lease: after the second drop a single
    // fresh identity fits and the next one does not. A double release would
    // have left room for both.
    drop(held);
    let _fourth = open(&broker, "sess-drop-lease", "d4");
    let overflow = broker.open_stream("sess-drop-lease", &text_id("d5"));
    assert_eq!(overflow.unwrap_err(), SseError::StreamCardinalityOverflow);
}

#[test]
fn cancelled_lease_release_never_republishes_or_double_counts() {
    let tuned = AggregateSseBounds {
        max_streams_per_session: 2,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-cancel-drop").unwrap();

    let identity = text_id("c1");
    let in_flight = open(&broker, "sess-cancel-drop", "c1");
    let _sibling = open(&broker, "sess-cancel-drop", "c2");
    broker.cancel_stream("sess-cancel-drop", &identity).unwrap();
    // The cancel already returned the capacity; dropping the request's lease
    // must neither return it a second time nor overwrite the cancellation. One
    // fresh identity fits the slot the cancel freed, and the next does not.
    drop(in_flight);
    let _next = open(&broker, "sess-cancel-drop", "c3");
    let saturated = broker.open_stream("sess-cancel-drop", &text_id("c4"));
    assert_eq!(saturated.unwrap_err(), SseError::StreamCardinalityOverflow);
    let still_cancelled = broker.cancel_stream("sess-cancel-drop", &identity);
    assert_eq!(still_cancelled.unwrap_err(), SseError::StreamCancelled);
}

#[test]
fn repeated_retention_overflow_cannot_exhaust_stream_capacity() {
    // One retained event and no replay window: with nothing consuming the ring,
    // every publish after the first fails closed.
    let tuned = AggregateSseBounds {
        max_streams_per_session: 4,
        max_retained_events: 1,
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-overflow").unwrap();
    publish(&broker, "sess-overflow", 0).unwrap();

    // Far more overflowing responses than `max_streams_per_session`. Each one
    // must be refused for RETENTION, never for cardinality: the refusal
    // terminalizes its identity, so capacity is returned every time.
    for id in 1..=12 {
        let refused = publish(&broker, "sess-overflow", id);
        assert_eq!(
            refused.unwrap_err(),
            SseError::RetentionOverflow,
            "overflow {id} must not consume stream capacity"
        );
    }

    // An inline-completed identity is terminal: a retry of it can never be
    // published onto the stream later.
    let retry = broker.open_stream("sess-overflow", &number_id(12));
    assert_eq!(retry.unwrap_err(), SseError::StreamCompleted);

    // Capacity really is reusable: a full set of fresh identities still opens.
    let mut held = Vec::new();
    for id in 100..104 {
        match broker.open_stream("sess-overflow", &number_id(id)) {
            Ok(stream) => held.push(stream),
            Err(error) => panic!("capacity must be reusable after overflow: {error:?}"),
        }
    }
    assert_eq!(held.len(), 4);
    let beyond = broker.open_stream("sess-overflow", &number_id(104));
    assert_eq!(beyond.unwrap_err(), SseError::StreamCardinalityOverflow);
}

#[test]
fn oversized_event_on_an_open_lease_releases_capacity() {
    let tuned = AggregateSseBounds {
        max_streams_per_session: 1,
        max_event_bytes: 512,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-oversize").unwrap();

    let stream = open(&broker, "sess-oversize", "big");
    let blob = "y".repeat(4096);
    let payload = json!({"jsonrpc": "2.0", "id": "big", "result": {"blob": blob}});
    let refused = stream.publish_encoded(&encode(&payload));
    assert_eq!(refused.unwrap_err(), SseError::EventTooLarge);
    // Refused before retention, but still terminal: the identity's capacity is
    // back and the identity itself cannot be reused.
    let _next = open(&broker, "sess-oversize", "small");
    let reopen = broker.open_stream("sess-oversize", &text_id("big"));
    assert_eq!(reopen.unwrap_err(), SseError::StreamCompleted);
}

#[test]
fn cancelled_stream_refuses_its_own_response() {
    let broker = broker();
    broker.ensure_session("sess-cancel").unwrap();
    let identity = text_id("c1");
    let unknown = broker.cancel_stream("sess-cancel", &identity);
    assert_eq!(unknown.unwrap_err(), SseError::UnknownStream);

    // Hold the lease the way an in-flight request does, so the cancel lands on
    // a genuinely OPEN stream and the eventual response is the one refused.
    let in_flight = open(&broker, "sess-cancel", "c1");
    broker.cancel_stream("sess-cancel", &identity).unwrap();
    let again = broker.cancel_stream("sess-cancel", &identity);
    assert_eq!(again.unwrap_err(), SseError::StreamCancelled);

    let reply = json!({"jsonrpc": "2.0", "id": "c1", "result": {}});
    let refused = in_flight.publish_encoded(&encode(&reply));
    assert_eq!(refused.unwrap_err(), SseError::StreamCancelled);
}

#[test]
fn invalid_response_envelope_falls_back_and_releases_capacity() {
    let tuned = AggregateSseBounds {
        max_streams_per_session: 1,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-id-match").unwrap();

    let stream = open(&broker, "sess-id-match", "expected");
    let mismatched = json!({
        "jsonrpc": "2.0",
        "id": "different",
        "result": {}
    });
    let refused = stream.publish_encoded(&encode(&mismatched));
    assert_eq!(refused.unwrap_err(), SseError::ResponseEnvelopeInvalid);

    // Refusal is terminal and returns the one stream slot, so the gateway can
    // reject the bad response and admit a fresh identity immediately.
    let _next = open(&broker, "sess-id-match", "next");
    let reopen = broker.open_stream("sess-id-match", &text_id("expected"));
    assert_eq!(reopen.unwrap_err(), SseError::StreamCompleted);
}

#[tokio::test]
async fn duplicate_listener_is_refused_and_disconnect_permits_reattach() {
    let broker = broker();
    broker.ensure_session("sess-dup").unwrap();
    let listener = broker.attach_listener("sess-dup", None).unwrap();
    let body = listener.take_body().expect("first claim wins");
    // The body is single-consumer: a second claim on the same lease fails.
    assert!(listener.take_body().is_none());
    let duplicate = broker.attach_listener("sess-dup", None);
    assert_eq!(duplicate.unwrap_err(), SseError::DuplicateListener);

    // A transport disconnect drops the body, which is the ONLY delivery-side
    // release path. Without it the session stays locked out forever.
    drop(body);
    let reattached = broker.attach_listener("sess-dup", None).unwrap();
    assert!(reattached.take_body().is_some());
}

#[tokio::test]
async fn listener_past_its_lifetime_is_superseded_not_refused() {
    // The in-body timer only advances while the transport polls the body, which
    // a peer that stopped reading can prevent. Supersession is therefore the
    // guarantee that the single-listener slot stays usable, and it must not
    // depend on the stalled body being polled at all.
    //
    // Sub-minimum lifetime on purpose: operator ranges are enforced by
    // `AggregateSseBounds::validate` (covered separately), while the broker
    // itself must honor whatever bound it was constructed with. A real, short
    // wall-clock window is required because the supersession deadline is a
    // `std::time::Instant`, which a paused tokio clock does not move.
    let tuned = AggregateSseBounds {
        listener_max_lifetime: Duration::from_millis(60),
        keepalive_interval: Duration::from_millis(60),
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned, 4, 2);
    broker.ensure_session("sess-stall").unwrap();
    let stalled = broker.attach_listener("sess-stall", None).unwrap();
    // Deliberately never polled: this models a transport parked in a write, the
    // exact case an in-body timer cannot resolve.
    let mut stalled_body = stalled.take_body().expect("body claimed once");

    // Inside the lifetime the slot is owned, and the gateway routes to it.
    let duplicate = broker.attach_listener("sess-stall", None);
    assert_eq!(duplicate.unwrap_err(), SseError::DuplicateListener);
    assert!(broker.has_listener("sess-stall"));

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Past the lifetime the session stops routing new responses to it, and a
    // fresh attach takes the slot instead of receiving 409.
    assert!(!broker.has_listener("sess-stall"));
    let replacement = broker
        .attach_listener("sess-stall", None)
        .expect("expired listener must be superseded");
    // Hold the replacement body: dropping it would release the slot again.
    let _replacement_body = replacement.take_body().expect("body claimed once");
    assert!(broker.has_listener("sess-stall"));

    // The superseded body ends on its next poll and its own release is a no-op,
    // so it cannot evict the listener that replaced it.
    assert_ended(&mut stalled_body).await;
    drop(stalled_body);
    assert!(broker.has_listener("sess-stall"));
}

#[tokio::test]
async fn unclaimed_listener_lease_releases_the_slot_on_drop() {
    let broker = broker();
    broker.ensure_session("sess-lease").unwrap();
    let listener = broker.attach_listener("sess-lease", None).unwrap();
    // A clone is what a `RequestContext` clone produces: it shares the lease,
    // so the slot is released only once every handle is gone.
    let clone = listener.clone();
    drop(listener);
    let still_held = broker.attach_listener("sess-lease", None);
    assert_eq!(still_held.unwrap_err(), SseError::DuplicateListener);
    drop(clone);
    assert!(broker.attach_listener("sess-lease", None).is_ok());
}

#[tokio::test]
async fn attach_delivers_staged_events_exactly_once() {
    let broker = broker();
    broker.ensure_session("sess-stage").unwrap();
    publish(&broker, "sess-stage", 1).unwrap();

    let listener = broker.attach_listener("sess-stage", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let seen = drain_until(&mut body, &["\"n\":1"], 4).await;
    // Staging and replay share one ring, so an event is never delivered twice.
    assert_eq!(seen.matches("\"n\":1").count(), 1);

    // Reattaching without a cursor resumes at the delivery watermark, so an
    // already-delivered event is not replayed.
    drop(body);
    let listener = broker.attach_listener("sess-stage", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let greeting = frame_text(next_frame(&mut body).await);
    assert!(greeting.contains(": mcp-sse"));
    assert!(stays_idle(&mut body).await);
}

#[tokio::test]
async fn last_event_id_replays_only_newer_events() {
    let broker = broker();
    broker.ensure_session("sess-replay").unwrap();
    let listener = broker.attach_listener("sess-replay", None).unwrap();
    let mut body = listener.take_body().unwrap();

    let mut ids = Vec::new();
    for index in 1..=3 {
        ids.push(publish(&broker, "sess-replay", index).unwrap());
    }
    let seen = drain_until(&mut body, &["\"n\":3"], 8).await;
    assert!(seen.contains("\"n\":1"));
    assert!(seen.contains("\"n\":3"));
    drop(body);

    let cursor = ids[0].to_string();
    let resumed = broker.attach_listener("sess-replay", Some(&cursor));
    let mut body = resumed.unwrap().take_body().unwrap();
    let seen = drain_until(&mut body, &["\"n\":3"], 8).await;
    assert!(!seen.contains("\"n\":1"), "cursor event is not replayed");
    assert!(seen.contains("\"n\":2"), "newer events are replayed");
    assert!(seen.contains("\"n\":3"));
}

#[tokio::test]
async fn last_event_id_boundaries_fail_closed() {
    let broker = broker();
    broker.ensure_session("sess-cursor").unwrap();
    let invalid = broker.attach_listener("sess-cursor", Some("not-a-number"));
    assert_eq!(invalid.unwrap_err(), SseError::LastEventIdInvalid);

    let long = "9".repeat(200);
    let too_large = broker.attach_listener("sess-cursor", Some(&long));
    assert_eq!(too_large.unwrap_err(), SseError::LastEventIdTooLarge);

    // A cursor ahead of anything the broker ever issued is not continuity the
    // gateway may fabricate.
    let ahead = broker.attach_listener("sess-cursor", Some("99"));
    assert_eq!(ahead.unwrap_err(), SseError::LastEventIdUnknown);
    assert_eq!(SseError::LastEventIdUnknown.http_status(), 400);
}

#[tokio::test]
async fn cursor_older_than_retained_history_is_gone_not_silently_resumed() {
    // Replay disabled: a consumed event is evicted immediately, so only the
    // exact delivery watermark can resume.
    let tuned = AggregateSseBounds {
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-gone").unwrap();
    let listener = broker.attach_listener("sess-gone", None).unwrap();
    let mut body = listener.take_body().unwrap();

    let mut ids = Vec::new();
    for index in 1..=3 {
        ids.push(publish(&broker, "sess-gone", index).unwrap());
    }
    let seen = drain_until(&mut body, &["\"n\":3"], 8).await;
    assert!(seen.contains("\"n\":3"));
    drop(body);

    let stale = ids[0].to_string();
    let refused = broker.attach_listener("sess-gone", Some(&stale));
    assert_eq!(refused.unwrap_err(), SseError::LastEventIdTooOld);
    // Lost history is gone for good, not a retryable 404.
    assert_eq!(SseError::LastEventIdTooOld.http_status(), 410);

    // The current watermark still resumes: nothing was missed there.
    let current = ids[2].to_string();
    assert!(broker.attach_listener("sess-gone", Some(&current)).is_ok());
}

#[tokio::test]
async fn retention_is_one_budget_and_never_drops_an_undelivered_response() {
    // Two retained events, no replay window. With no listener attached every
    // event is still owed to a consumer, so the third publish must fail closed
    // rather than evict a JSON-RPC response nobody has seen.
    let tuned = AggregateSseBounds {
        max_retained_events: 2,
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-budget").unwrap();
    publish(&broker, "sess-budget", 1).unwrap();
    publish(&broker, "sess-budget", 2).unwrap();
    let overflow = publish(&broker, "sess-budget", 3);
    assert_eq!(overflow.unwrap_err(), SseError::RetentionOverflow);

    // Draining frees the consumed prefix, so the session recovers instead of
    // being stranded by one overflow. Identity 3 was answered inline and is
    // therefore terminal for good, so recovery is proven with a fresh id — a
    // retry of an inline-completed identity must never reach the stream.
    let listener = broker.attach_listener("sess-budget", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let seen = drain_until(&mut body, &["\"n\":2"], 6).await;
    assert!(seen.contains("\"n\":1"));
    assert!(seen.contains("\"n\":2"));
    let retried = broker.open_stream("sess-budget", &number_id(3));
    assert_eq!(retried.unwrap_err(), SseError::StreamCompleted);
    publish(&broker, "sess-budget", 4).unwrap();
}

#[tokio::test]
async fn delivered_history_is_evicted_to_admit_at_the_event_cap() {
    // Replay may use the full retained-event allowance. Once that event has
    // been delivered it is safely evictable, and a new response must replace
    // it instead of being refused merely because the ring was exactly full
    // before admission.
    let tuned = AggregateSseBounds {
        max_retained_events: 1,
        max_replay_events: 1,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-event-admit").unwrap();
    let listener = broker.attach_listener("sess-event-admit", None).unwrap();
    let mut body = listener.take_body().unwrap();

    publish(&broker, "sess-event-admit", 1).unwrap();
    let seen = drain_until(&mut body, &["\"n\":1"], 4).await;
    assert!(seen.contains("\"n\":1"));

    publish(&broker, "sess-event-admit", 2)
        .expect("delivered history at the event cap must make room for a new response");
    let seen = drain_until(&mut body, &["\"n\":2"], 4).await;
    assert!(seen.contains("\"n\":2"));
}

#[tokio::test]
async fn delivered_history_is_evicted_to_admit_at_the_byte_cap() {
    // The event-count budget has room, but the byte budget fits only one of
    // these responses. Delivery makes the first event evictable, so byte
    // pressure must reclaim it before deciding the second response overflows.
    let tuned = AggregateSseBounds {
        max_event_bytes: 4096,
        max_retained_bytes: 4096 + 128,
        max_retained_events: 8,
        max_replay_events: 8,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-byte-admit").unwrap();
    let listener = broker.attach_listener("sess-byte-admit", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let filler = "x".repeat(3800);

    let first_payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"blob": filler.clone()}});
    let first = broker
        .open_stream("sess-byte-admit", &number_id(1))
        .unwrap();
    first.publish_encoded(&encode(&first_payload)).unwrap();
    let seen = drain_until(&mut body, &["\"id\":1"], 4).await;
    assert!(seen.contains("\"id\":1"));

    let second_payload = json!({"jsonrpc": "2.0", "id": 2, "result": {"blob": filler}});
    let second = broker
        .open_stream("sess-byte-admit", &number_id(2))
        .unwrap();
    second
        .publish_encoded(&encode(&second_payload))
        .expect("delivered history at the byte cap must make room for a new response");
    let seen = drain_until(&mut body, &["\"id\":2"], 4).await;
    assert!(seen.contains("\"id\":2"));
}

#[test]
fn byte_budget_bounds_total_retained_bytes() {
    // One ~4 KiB event fits; two do not. The retired design's independent
    // pending and replay caps would have retained about twice this.
    let tuned = AggregateSseBounds {
        max_event_bytes: 4096,
        max_retained_bytes: 4096 + 128,
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-bytes").unwrap();
    let filler = "x".repeat(3800);
    // Each response must name its OWN stream identity: publishing id 1's body
    // under id 2 is refused as an invalid envelope long before retention is
    // consulted, which would make this a byte-budget test in name only.
    let first_payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"blob": filler.clone()}});
    let second_payload = json!({"jsonrpc": "2.0", "id": 2, "result": {"blob": filler}});
    let one = number_id(1);
    let two = number_id(2);
    let first = broker.open_stream("sess-bytes", &one).unwrap();
    first.publish_encoded(&encode(&first_payload)).unwrap();
    let second = broker.open_stream("sess-bytes", &two).unwrap();
    let overflow = second.publish_encoded(&encode(&second_payload));
    assert_eq!(overflow.unwrap_err(), SseError::RetentionOverflow);
}

#[tokio::test]
async fn reserved_publication_is_invisible_and_protects_commit_capacity() {
    let tuned = AggregateSseBounds {
        max_retained_events: 2,
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-reserved").unwrap();
    let listener = broker.attach_listener("sess-reserved", None).unwrap();
    let mut body = listener.take_body().unwrap();
    assert!(frame_text(next_frame(&mut body).await).contains(": mcp-sse"));

    let first = broker.open_stream("sess-reserved", &number_id(1)).unwrap();
    let first_payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let reserved = first.reserve_encoded(&first_payload).unwrap();
    assert!(
        stays_idle(&mut body).await,
        "a reservation must not become listener-visible before commit"
    );

    publish(&broker, "sess-reserved", 2)
        .expect("one direct publication fits beside the promised event");
    let third = broker.open_stream("sess-reserved", &number_id(3)).unwrap();
    let third_payload = encode(&json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
    assert_eq!(
        third.publish_encoded(&third_payload).unwrap_err(),
        SseError::RetentionOverflow,
        "direct publishers must account for promised event capacity"
    );

    reserved
        .commit()
        .expect("a successful reservation must remain commit-capable");
    let seen = drain_until(&mut body, &["\"id\":2", "\"id\":1"], 5).await;
    assert!(seen.contains("\"id\":2"));
    assert!(seen.contains("\"id\":1"));
    assert!(!seen.contains("\"id\":3"));
}

#[test]
fn oversized_event_payload_fails_closed() {
    let tuned = AggregateSseBounds {
        max_event_bytes: 512,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-big").unwrap();
    let blob = "y".repeat(4096);
    let payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"blob": blob}});
    let one = number_id(1);
    let stream = broker.open_stream("sess-big", &one).unwrap();
    let refused = stream.publish_encoded(&encode(&payload));
    assert_eq!(refused.unwrap_err(), SseError::EventTooLarge);
}

/// An upstream JSON body terminated by a newline is a routine shape, and SSE
/// line folding cannot carry it without reshaping the exact octets the inline
/// answer would have used. It must be refused under its OWN fixed reason rather
/// than being reported as an oversized payload, and — like every other refusal —
/// it must still terminalize the identity so the capacity comes back once.
#[test]
fn unframable_event_payload_fails_closed_with_its_own_reason() {
    let broker = broker();
    broker.ensure_session("sess-frame").unwrap();
    let one = number_id(1);
    let stream = broker.open_stream("sess-frame", &one).unwrap();

    let mut encoded = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    encoded.push(b'\n');
    assert!(
        encoded.len() <= bounds().max_event_bytes,
        "the refusal under test must be framing, not size"
    );
    let refused = stream.publish_encoded(&encoded);
    assert_eq!(refused.unwrap_err(), SseError::EventFramingInvalid);
    assert_eq!(
        SseError::EventFramingInvalid.reason_token(),
        "event_framing_invalid"
    );

    let reopen = broker.open_stream("sess-frame", &number_id(1));
    assert_eq!(reopen.unwrap_err(), SseError::StreamCompleted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_cardinality_is_race_free_under_concurrent_distinct_sessions() {
    let broker = Arc::new(AggregateSseBroker::new(bounds(), 4, 8));
    let mut handles = Vec::new();
    for index in 0..32 {
        let broker = Arc::clone(&broker);
        let key = format!("sess-{index}");
        let handle = tokio::spawn(async move { broker.ensure_session(&key) });
        handles.push(handle);
    }
    let mut admitted = 0usize;
    let mut refused = 0usize;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => admitted += 1,
            Err(SseError::SessionCardinalityOverflow) => refused += 1,
            Err(other) => panic!("unexpected admission error: {other:?}"),
        }
    }
    // Reservation precedes insertion, so admission can never exceed the cap.
    assert_eq!(admitted, 4);
    assert_eq!(refused, 28);
    assert_eq!(broker.session_count(), 4);

    // Removal returns capacity exactly once, so accounting cannot drift.
    broker.remove_session("does-not-exist");
    for index in 0..32 {
        broker.remove_session(&format!("sess-{index}"));
    }
    assert_eq!(broker.session_count(), 0);
    assert!(broker.ensure_session("sess-fresh").is_ok());
}

#[tokio::test]
async fn session_removal_ends_the_attached_body() {
    let broker = broker();
    broker.ensure_session("sess-del").unwrap();
    let listener = broker.attach_listener("sess-del", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let greeting = frame_text(next_frame(&mut body).await);
    assert!(greeting.contains(": mcp-sse"));

    publish(&broker, "sess-del", 1).unwrap();
    assert!(
        body.retained_session_bytes_for_test() > 0,
        "the live session must retain the staged response"
    );

    broker.remove_session("sess-del");
    assert_eq!(
        body.retained_session_bytes_for_test(),
        0,
        "session teardown must release payload history even while a stale body is held"
    );
    assert_ended(&mut body).await;
}

#[tokio::test]
async fn retiring_a_generation_ends_every_body_and_refuses_new_work() {
    let broker = broker();
    broker.ensure_session("sess-gen").unwrap();
    let listener = broker.attach_listener("sess-gen", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let _greeting = next_frame(&mut body).await;

    broker.retire_generation();
    assert!(broker.is_retired());
    assert_eq!(broker.session_count(), 0);
    assert_ended(&mut body).await;

    let readmit = broker.ensure_session("sess-gen");
    assert_eq!(readmit.unwrap_err(), SseError::BrokerRetired);
    let published = publish(&broker, "sess-gen", 1);
    assert_eq!(published.unwrap_err(), SseError::BrokerRetired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retirement_is_a_complete_boundary_for_concurrent_session_admission() {
    let broker = Arc::new(AggregateSseBroker::new(bounds(), 256, 8));
    let start = Arc::new(tokio::sync::Barrier::new(65));
    let mut admissions = Vec::new();
    for index in 0..64 {
        let broker = Arc::clone(&broker);
        let start = Arc::clone(&start);
        admissions.push(tokio::spawn(async move {
            start.wait().await;
            broker.ensure_session(&format!("retire-race-{index}"))
        }));
    }

    start.wait().await;
    broker.retire_generation();
    for admission in admissions {
        match admission.await.unwrap() {
            Ok(()) | Err(SseError::BrokerRetired) => {}
            Err(other) => panic!("unexpected admission result: {other:?}"),
        }
    }

    assert!(broker.is_retired());
    assert_eq!(
        broker.session_count(),
        0,
        "retirement must drain every admission that linearized before it and reject every later one"
    );
    assert_eq!(
        broker.ensure_session("post-retirement").unwrap_err(),
        SseError::BrokerRetired
    );
}

#[tokio::test]
async fn dropping_the_broker_ends_in_flight_bodies() {
    let broker = broker();
    broker.ensure_session("sess-drop").unwrap();
    let listener = broker.attach_listener("sess-drop", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let _greeting = next_frame(&mut body).await;

    // Reload / update / delete drops the owning plugin instance, which drops
    // the broker: no event may cross generations.
    drop(broker);
    assert_ended(&mut body).await;
}

#[test]
fn unknown_session_operations_fail_closed() {
    let broker = broker();
    let attach = broker.attach_listener("missing", None);
    assert_eq!(attach.unwrap_err(), SseError::UnknownSession);
    let open = broker.open_stream("missing", &text_id("x"));
    assert_eq!(open.unwrap_err(), SseError::UnknownSession);
    let published = publish(&broker, "missing", 1);
    assert_eq!(published.unwrap_err(), SseError::UnknownSession);
    assert!(!broker.has_listener("missing"));
    let empty = broker.ensure_session("");
    assert_eq!(empty.unwrap_err(), SseError::MissingSession);
}

#[tokio::test]
async fn idle_sessions_are_reaped_and_their_bodies_end() {
    let broker = broker();
    broker.ensure_session("sess-idle").unwrap();
    let listener = broker.attach_listener("sess-idle", None).unwrap();
    let mut body = listener.take_body().unwrap();

    assert_eq!(broker.reap_idle(Duration::from_secs(3600)), 0);
    assert_eq!(broker.reap_idle(Duration::from_millis(0)), 1);
    assert_eq!(broker.session_count(), 0);
    assert_ended(&mut body).await;
}

#[test]
fn bounds_validation_is_field_specific_and_value_free() {
    let err = AggregateSseBounds {
        max_event_bytes: 100,
        max_retained_bytes: 50,
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_max_event_bytes"));
    // Diagnostics name the field and never echo the configured value.
    assert!(!err.contains("100"));

    let err = AggregateSseBounds {
        max_replay_events: 4096,
        max_retained_events: 8,
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_max_replay_events"));

    let err = AggregateSseBounds {
        max_streams_per_session: 0,
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_max_streams_per_session"));

    let err = AggregateSseBounds {
        listener_max_lifetime: Duration::from_secs(1),
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_listener_max_lifetime_seconds"));

    let err = AggregateSseBounds {
        keepalive_interval: Duration::from_secs(3600),
        listener_max_lifetime: Duration::from_secs(60),
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_keepalive_seconds"));

    assert!(bounds().validate().is_ok());
}

#[test]
fn every_error_reason_is_a_fixed_low_cardinality_token() {
    let errors = [
        SseError::MissingSession,
        SseError::UnknownSession,
        SseError::StaleSession,
        SseError::BrokerRetired,
        SseError::DuplicateListener,
        SseError::InvalidAccept,
        SseError::LastEventIdTooLarge,
        SseError::LastEventIdInvalid,
        SseError::LastEventIdTooOld,
        SseError::LastEventIdUnknown,
        SseError::StreamIdMissing,
        SseError::StreamIdTooLarge,
        SseError::StreamIdInvalid,
        SseError::DuplicateStream,
        SseError::UnknownStream,
        SseError::StreamCompleted,
        SseError::StreamCancelled,
        SseError::ResponseEnvelopeInvalid,
        SseError::EventTooLarge,
        SseError::EventFramingInvalid,
        SseError::RetentionOverflow,
        SseError::StreamCardinalityOverflow,
        SseError::SessionCardinalityOverflow,
    ];
    for error in errors {
        let token = error.reason_token();
        assert!(!token.is_empty());
        let low_cardinality = token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
        assert!(low_cardinality, "reason token stays a fixed slug: {token}");
        assert!(!error.as_static_reason().is_empty());
        assert!((400..=599).contains(&error.http_status()));
    }
}

#[test]
fn raw_numeric_identities_are_injective_and_responses_must_match() {
    let ids = [
        "18446744073709551616",
        "18446744073709551617",
        "1.00000000000000001",
        "1.00000000000000002",
        "1e0",
        "1.0",
        "-0",
        "0",
        "\"0\"",
    ];
    let identities: Vec<StreamIdentity> = ids
        .iter()
        .map(|id| {
            let raw = serde_json::value::RawValue::from_string((*id).to_string()).unwrap();
            StreamIdentity::from_raw_json_rpc_id(&raw, 128).unwrap()
        })
        .collect();
    for (index, identity) in identities.iter().enumerate() {
        for other in &identities[index + 1..] {
            assert_ne!(identity, other);
        }
    }
    for reserve in [false, true] {
        let broker = broker();
        broker.ensure_session("exact").unwrap();
        let wrong = broker.open_stream("exact", &identities[0]).unwrap();
        let response = format!(r#"{{"jsonrpc":"2.0","id":{},"result":{{}}}}"#, ids[1]);
        let error = if reserve {
            wrong.reserve_encoded(response.as_bytes()).err().unwrap()
        } else {
            wrong.publish_encoded(response.as_bytes()).unwrap_err()
        };
        assert_eq!(error, SseError::ResponseEnvelopeInvalid);
        let correct = broker.open_stream("exact", &identities[1]).unwrap();
        assert_eq!(correct.publish_encoded(response.as_bytes()).unwrap(), 1);
    }
}

#[test]
fn mismatched_pretty_printed_response_cannot_use_the_inline_fallback() {
    let broker = broker();
    broker.ensure_session("pretty").unwrap();
    let stream = open(&broker, "pretty", "expected");
    let body = b"{\n\"jsonrpc\":\"2.0\",\"id\":\"wrong\",\"result\":{}}";
    assert_eq!(
        stream.reserve_encoded(body).err().unwrap(),
        SseError::ResponseEnvelopeInvalid
    );
}

#[test]
fn an_escaped_jsonrpc_version_token_still_matches_the_envelope() {
    // The raw-byte comparison is a fast path, not the contract: a conforming
    // peer may spell the fixed "2.0" literal with escapes, and that response
    // must still be admitted for the identity it names.
    let broker = broker();
    broker.ensure_session("escaped").unwrap();
    let stream = open(&broker, "escaped", "esc-1");
    let body = b"{\"jsonrpc\":\"\\u0032.0\",\"id\":\"esc-1\",\"result\":{}}";
    assert_eq!(stream.publish_encoded(body).unwrap(), 1);

    // A different version string is still refused.
    let other = open(&broker, "escaped", "esc-2");
    let wrong = br#"{"jsonrpc":"2.1","id":"esc-2","result":{}}"#;
    assert_eq!(
        other.publish_encoded(wrong).unwrap_err(),
        SseError::ResponseEnvelopeInvalid
    );
}

#[test]
fn a_stream_identity_renders_its_json_rpc_id_token() {
    // The gateway's mismatch refusal names the request through this token.
    let numeric = StreamIdentity::from_raw_json_rpc_id(
        &serde_json::value::RawValue::from_string("1.00".to_string()).unwrap(),
        128,
    )
    .unwrap();
    assert_eq!(numeric.json_rpc_id_token(), "1.00");

    let text = StreamIdentity::from_raw_json_rpc_id(
        &serde_json::value::RawValue::from_string(r#""abc""#.to_string()).unwrap(),
        128,
    )
    .unwrap();
    assert_eq!(text.json_rpc_id_token(), "\"abc\"");
}

// ===========================================================================
// POST-attached response streams (issue #5410)
// ===========================================================================

/// The Streamable HTTP delivery: the answer to a POST that carried a request is
/// framed as that POST's own complete event stream, and an attached `GET`
/// listener is advanced past it rather than being handed a second copy.
#[tokio::test]
async fn a_post_attached_response_is_framed_on_the_post_and_never_on_the_listener() {
    let broker = broker();
    broker.ensure_session("sess-post").unwrap();
    let listener = broker.attach_listener("sess-post", None).unwrap();
    let mut body = listener.take_body().expect("body claimed once");
    let greeting = frame_text(next_frame(&mut body).await);
    assert_eq!(greeting, ": mcp-sse\n\n");

    let payload = json!({"jsonrpc": "2.0", "id": 7, "result": {"n": 7}});
    let encoded = encode(&payload);
    let stream = broker.open_stream("sess-post", &number_id(7)).unwrap();
    let framed = stream
        .post_attached_response(&encoded)
        .expect("a correlated response frames its own POST stream");
    let framed = String::from_utf8(framed.to_vec()).expect("the POST body is UTF-8");

    // Greeting, exactly one `message` record carrying the governed bytes, and a
    // resumption cursor the client can hand back later.
    assert!(framed.starts_with(": mcp-sse\n\n"));
    assert!(framed.contains("id: 1\nevent: message\ndata: "));
    assert!(framed.contains(r#""id":7"#));
    assert!(framed.ends_with("\n\n"));
    assert_eq!(framed.matches("event: message").count(), 1);

    // The listener that was attached the whole time is advanced past it.
    assert!(stays_idle(&mut body).await);

    // The identity is terminal, so a duplicate answer for it is refused rather
    // than framed a second time.
    let duplicate = broker.open_stream("sess-post", &number_id(7));
    assert_eq!(duplicate.unwrap_err(), SseError::StreamCompleted);
}

/// A cancelled request refuses its own response, and a mismatched envelope is
/// never framed under the requesting identity. Both terminalize exactly once.
#[tokio::test]
async fn post_attached_delivery_refuses_a_cancelled_or_mismatched_response() {
    let broker = broker();
    broker.ensure_session("sess-refuse").unwrap();

    let cancelled = broker.open_stream("sess-refuse", &number_id(1)).unwrap();
    broker.cancel_stream("sess-refuse", &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    assert_eq!(
        cancelled.post_attached_response(&payload).unwrap_err(),
        SseError::StreamCancelled
    );

    let mismatched = broker.open_stream("sess-refuse", &number_id(2)).unwrap();
    let wrong = encode(&json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
    assert_eq!(
        mismatched.post_attached_response(&wrong).unwrap_err(),
        SseError::ResponseEnvelopeInvalid
    );
    // Capacity came back: the same identity can be opened again only because a
    // refusal terminalized it exactly once, and the terminal record refuses it.
    assert_eq!(
        broker
            .open_stream("sess-refuse", &number_id(2))
            .unwrap_err(),
        SseError::StreamCompleted
    );

    // A cancellation that lands while the gateway is still producing the answer
    // outranks a payload the gateway would have refused anyway.
    let both = broker.open_stream("sess-refuse", &number_id(4)).unwrap();
    broker.cancel_stream("sess-refuse", &number_id(4)).unwrap();
    assert_eq!(
        both.post_attached_response(&wrong).unwrap_err(),
        SseError::StreamCancelled
    );
}

/// A POST-attached event enters the ring already delivered, so only an explicit
/// `Last-Event-ID` replays it: a fresh listener starts past it.
#[tokio::test]
async fn a_post_attached_event_replays_only_for_an_explicit_cursor() {
    let broker = broker();
    broker.ensure_session("sess-resume").unwrap();

    // Event ids come from the one per-session counter, so the two POST streams
    // publish cursors 1 and 2.
    for id in [1_i64, 2] {
        let payload = encode(&json!({"jsonrpc": "2.0", "id": id, "result": {}}));
        let stream = broker.open_stream("sess-resume", &number_id(id)).unwrap();
        let framed = stream.post_attached_response(&payload).unwrap();
        let framed = String::from_utf8(framed.to_vec()).expect("the POST body is UTF-8");
        assert!(framed.contains(&format!("id: {id}\nevent: message")));
    }

    // No cursor: the listener attaches at the delivery watermark and sees
    // nothing, because both answers already went out on their own POSTs.
    let fresh = broker.attach_listener("sess-resume", None).unwrap();
    let mut fresh_body = fresh.take_body().expect("body claimed once");
    let greeting = frame_text(next_frame(&mut fresh_body).await);
    assert_eq!(greeting, ": mcp-sse\n\n");
    assert!(stays_idle(&mut fresh_body).await);
    drop(fresh_body);

    // An explicit cursor resumes the stream an earlier POST began.
    let resumed = broker.attach_listener("sess-resume", Some("1")).unwrap();
    let mut resumed_body = resumed.take_body().expect("body claimed once");
    let seen = drain_until(&mut resumed_body, &[r#""id":2"#], 4).await;
    assert!(seen.contains(r#""id":2"#), "resumption replays: {seen:?}");
    assert!(!seen.contains(r#""id":1"#));
}

/// Settling for an inline JSON answer reports a cancellation the caller has to
/// honour, and stays idempotent across the lease's other exits.
#[tokio::test]
async fn settling_for_an_inline_response_reports_a_cancellation() {
    let broker = broker();
    broker.ensure_session("sess-inline").unwrap();

    let ready = open(&broker, "sess-inline", "ready");
    assert_eq!(ready.settle_for_inline_response(), Ok(()));
    assert_eq!(
        ready.settle_for_inline_response().unwrap_err(),
        SseError::StreamCompleted
    );

    let withdrawn = open(&broker, "sess-inline", "withdrawn");
    broker
        .cancel_stream("sess-inline", &text_id("withdrawn"))
        .unwrap();
    assert_eq!(
        withdrawn.settle_for_inline_response().unwrap_err(),
        SseError::StreamCancelled
    );
}
