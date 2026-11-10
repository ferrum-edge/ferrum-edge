//! External unit coverage for the aggregate MCP SSE session broker (#3295).
//!
//! Covers the invariants the broker exists to hold: POST-attached delivery
//! with `Last-Event-ID` replay, one listener per session, race-free session and
//! stream cardinality, a single retained-byte budget, explicit `Last-Event-ID`
//! semantics, reliable teardown on disconnect / delete / reload, and
//! value-free diagnostics.

use bytes::Bytes;
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

/// One request's whole broker lifecycle: open the identity, stage its terminal
/// response as the POST-attached body, then commit it the way the pipeline does
/// once the final policy accepted those bytes. Returns the assigned cursor.
fn publish(broker: &AggregateSseBroker, session: &str, id: i64) -> Result<u64, SseError> {
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": {"n": id}});
    let stream = broker.open_stream(session, &number_id(id))?;
    stage_and_commit(&stream, &encode(&payload))
}

fn publish_text(broker: &AggregateSseBroker, session: &str, id: &str) -> Result<u64, SseError> {
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": {}});
    let stream = broker.open_stream(session, &text_id(id))?;
    stage_and_commit(&stream, &encode(&payload))
}

/// Stage `encoded` on an open lease and commit it, returning the cursor.
fn stage_and_commit(stream: &AggregateSseStream, encoded: &[u8]) -> Result<u64, SseError> {
    let (_framed, publication) = stream.reserve_post_attached_response(encoded)?;
    publication.commit()
}

/// Stage and commit, returning the POST-attached body the client receives.
fn post_attached(stream: &AggregateSseStream, encoded: &[u8]) -> Result<Bytes, SseError> {
    let (framed, publication) = stream.reserve_post_attached_response(encoded)?;
    publication.commit()?;
    Ok(framed)
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
async fn concurrent_post_attached_responses_never_reach_a_plain_listener() {
    let broker = Arc::new(broker());
    broker.ensure_session("sess-a").unwrap();
    let listener = broker.attach_listener("sess-a", None).unwrap();
    let mut body = listener.take_body().expect("body claimed once");
    let greeting = frame_text(next_frame(&mut body).await);
    assert!(greeting.contains(": mcp-sse"));

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
    // Each response carries its own session-wide SSE cursor.
    assert_ne!(first, second);
    // Both answers went out on their own POSTs: the plain `GET` listener that
    // was attached the whole time is advanced past them, never handed a copy.
    assert!(stays_idle(&mut body).await);
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
    stage_and_commit(&first, &encode(&reply)).unwrap();
    let _third = open(&broker, "sess-cap", "s3");

    // A late or duplicate response for a completed identity is refused rather
    // than misattributed onto a fresh stream. The lease itself refuses a second
    // terminal attempt, and re-opening the identity is refused too.
    let late = first.reserve_post_attached_response(&encode(&reply));
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

#[tokio::test]
async fn retention_pressure_costs_resumability_never_delivery_or_capacity() {
    // One retained event and one replay slot: every commit after the first
    // evicts the previous response, because it already went out on its POST.
    let tuned = AggregateSseBounds {
        max_streams_per_session: 4,
        max_retained_events: 1,
        max_replay_events: 1,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-pressure").unwrap();

    // Far more responses than either the ring or `max_streams_per_session`:
    // staging is never refused for capacity, and every commit returns its
    // stream slot.
    for id in 1..=12 {
        assert_eq!(publish(&broker, "sess-pressure", id), Ok(id as u64));
    }
    assert_eq!(broker.outstanding_reservations("sess-pressure"), Some(0));

    // A completed identity is terminal: a retry of it is refused.
    let retry = broker.open_stream("sess-pressure", &number_id(12));
    assert_eq!(retry.unwrap_err(), SseError::StreamCompleted);

    // Capacity really is reusable: a full set of fresh identities still opens.
    let mut held = Vec::new();
    for id in 100..104 {
        match broker.open_stream("sess-pressure", &number_id(id)) {
            Ok(stream) => held.push(stream),
            Err(error) => panic!("capacity must be reusable: {error:?}"),
        }
    }
    let beyond = broker.open_stream("sess-pressure", &number_id(104));
    assert_eq!(beyond.unwrap_err(), SseError::StreamCardinalityOverflow);

    // Only resumability was lost: a cursor below the evicted prefix fails
    // closed, and the newest cursor still resumes the last response.
    let gone = broker.attach_listener("sess-pressure", Some("0"));
    assert_eq!(gone.unwrap_err(), SseError::LastEventIdTooOld);
    let resumed = broker.attach_listener("sess-pressure", Some("11")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    let seen = drain_until(&mut body, &["\"n\":12"], 4).await;
    assert!(
        seen.contains("\"n\":12"),
        "the newest response replays: {seen:?}"
    );
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
    let refused = stream.reserve_post_attached_response(&encode(&payload));
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
    let refused = in_flight.reserve_post_attached_response(&encode(&reply));
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
    let refused = stream.reserve_post_attached_response(&encode(&mismatched));
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

    // Inside the lifetime the slot is owned.
    let duplicate = broker.attach_listener("sess-stall", None);
    assert_eq!(duplicate.unwrap_err(), SseError::DuplicateListener);

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Past the lifetime a fresh attach takes the slot instead of receiving 409.
    let replacement = broker
        .attach_listener("sess-stall", None)
        .expect("expired listener must be superseded");
    // Hold the replacement body: dropping it would release the slot again.
    let _replacement_body = replacement.take_body().expect("body claimed once");

    // The superseded body ends on its next poll and its own release is a no-op,
    // so it cannot evict the listener that replaced it.
    assert_ended(&mut stalled_body).await;
    drop(stalled_body);
    let still_owned = broker.attach_listener("sess-stall", None);
    assert_eq!(still_owned.unwrap_err(), SseError::DuplicateListener);
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
async fn last_event_id_replays_only_newer_events() {
    let broker = broker();
    broker.ensure_session("sess-replay").unwrap();

    let mut ids = Vec::new();
    for index in 1..=3 {
        ids.push(publish(&broker, "sess-replay", index).unwrap());
    }

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

    let mut ids = Vec::new();
    for index in 1..=3 {
        ids.push(publish(&broker, "sess-gone", index).unwrap());
    }

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
async fn consumed_history_is_evicted_to_retain_at_the_byte_cap() {
    // The event-count budget has room, but the byte budget fits only one of
    // these responses. Both already went out on their POSTs, so byte pressure
    // evicts the older one and the newer one stays resumable.
    let tuned = AggregateSseBounds {
        max_event_bytes: 4096,
        max_retained_bytes: 4096 + 128,
        max_retained_events: 8,
        max_replay_events: 8,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-byte-admit").unwrap();
    let filler = "x".repeat(3800);

    let first_payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"blob": filler.clone()}});
    let first = broker
        .open_stream("sess-byte-admit", &number_id(1))
        .unwrap();
    assert_eq!(stage_and_commit(&first, &encode(&first_payload)), Ok(1));

    let second_payload = json!({"jsonrpc": "2.0", "id": 2, "result": {"blob": filler}});
    let second = broker
        .open_stream("sess-byte-admit", &number_id(2))
        .unwrap();
    assert_eq!(stage_and_commit(&second, &encode(&second_payload)), Ok(2));

    let gone = broker.attach_listener("sess-byte-admit", Some("0"));
    assert_eq!(gone.unwrap_err(), SseError::LastEventIdTooOld);
    let resumed = broker
        .attach_listener("sess-byte-admit", Some("1"))
        .unwrap();
    let mut body = resumed.take_body().unwrap();
    let seen = drain_until(&mut body, &["\"id\":2"], 4).await;
    assert!(seen.contains("\"id\":2"));
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
    let refused = stream.reserve_post_attached_response(&encode(&payload));
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
    let refused = stream.reserve_post_attached_response(&encoded);
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
        "the live session must retain the committed response for replay"
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
    let empty = broker.ensure_session("");
    assert_eq!(empty.unwrap_err(), SseError::MissingSession);
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
fn rendered_bounds_diagnostics_keep_fields_and_reasons_without_supplied_numbers() {
    let cases = [
        (
            AggregateSseBounds {
                max_streams_per_session: 987654321,
                ..bounds()
            },
            "`sessions.sse_max_streams_per_session`",
            "must be between",
        ),
        (
            AggregateSseBounds {
                max_event_bytes: 314159,
                max_retained_bytes: 271828,
                ..bounds()
            },
            "`sessions.sse_max_event_bytes`",
            "must leave room for SSE framing inside `sessions.sse_max_retained_bytes`",
        ),
        (
            AggregateSseBounds {
                max_replay_events: 4095,
                max_retained_events: 2047,
                ..bounds()
            },
            "`sessions.sse_max_replay_events`",
            "must not exceed `sessions.sse_max_retained_events`",
        ),
        (
            AggregateSseBounds {
                keepalive_interval: Duration::from_secs(59),
                listener_max_lifetime: Duration::from_secs(31),
                ..bounds()
            },
            "`sessions.sse_keepalive_seconds`",
            "must not exceed `sessions.sse_listener_max_lifetime_seconds`",
        ),
    ];
    for (bounds, field, reason) in cases {
        let error = bounds
            .validate()
            .expect_err("invalid bounds must be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for supplied in ["987654321", "314159", "271828", "4095", "2047", "59", "31"] {
            assert!(!rendered.contains(supplied), "{rendered}");
        }
    }
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
    let broker = broker();
    broker.ensure_session("exact").unwrap();
    let wrong = broker.open_stream("exact", &identities[0]).unwrap();
    let response = format!(r#"{{"jsonrpc":"2.0","id":{},"result":{{}}}}"#, ids[1]);
    let error = wrong
        .reserve_post_attached_response(response.as_bytes())
        .unwrap_err();
    assert_eq!(error, SseError::ResponseEnvelopeInvalid);
    let correct = broker.open_stream("exact", &identities[1]).unwrap();
    assert_eq!(stage_and_commit(&correct, response.as_bytes()), Ok(1));
}

#[test]
fn mismatched_pretty_printed_response_cannot_use_the_inline_fallback() {
    let broker = broker();
    broker.ensure_session("pretty").unwrap();
    let stream = open(&broker, "pretty", "expected");
    let body = b"{\n\"jsonrpc\":\"2.0\",\"id\":\"wrong\",\"result\":{}}";
    assert_eq!(
        stream.reserve_post_attached_response(body).unwrap_err(),
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
    assert_eq!(stage_and_commit(&stream, body), Ok(1));

    // A different version string is still refused.
    let other = open(&broker, "escaped", "esc-2");
    let wrong = br#"{"jsonrpc":"2.1","id":"esc-2","result":{}}"#;
    assert_eq!(
        other.reserve_post_attached_response(wrong).unwrap_err(),
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
    let framed =
        post_attached(&stream, &encoded).expect("a correlated response frames its own POST stream");
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
        post_attached(&cancelled, &payload).unwrap_err(),
        SseError::StreamCancelled
    );

    let mismatched = broker.open_stream("sess-refuse", &number_id(2)).unwrap();
    let wrong = encode(&json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
    assert_eq!(
        post_attached(&mismatched, &wrong).unwrap_err(),
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
        post_attached(&both, &wrong).unwrap_err(),
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
        let framed = post_attached(&stream, &payload).unwrap();
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

/// Issue #5441: staging a POST-attached response frames the bytes the client
/// receives but retains NOTHING. Only the pipeline's commit — which runs after
/// the authoritative final response policy and the pre-commit authorization
/// gate have accepted those exact bytes — makes the event replayable.
#[tokio::test]
async fn a_staged_post_attached_response_is_replayable_only_after_it_commits() {
    let broker = broker();
    broker.ensure_session("sess-staged").unwrap();
    let stream = broker.open_stream("sess-staged", &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let (framed, publication) = stream
        .reserve_post_attached_response(&payload)
        .expect("a correlated response stages its own POST stream");
    let framed = String::from_utf8(framed.to_vec()).expect("the POST body is UTF-8");
    assert!(framed.contains("id: 1\nevent: message\ndata: "));
    assert!(framed.contains(r#""id":1"#));

    // Before the commit the only copy of these bytes is the POST body above.
    let early = broker.attach_listener("sess-staged", Some("0")).unwrap();
    let mut early_body = early.take_body().expect("body claimed once");
    let greeting = frame_text(next_frame(&mut early_body).await);
    assert_eq!(greeting, ": mcp-sse\n\n");
    assert!(
        stays_idle(&mut early_body).await,
        "a staged response must not be replayable before it commits"
    );
    drop(early_body);

    assert_eq!(publication.commit().unwrap(), 1);
    let resumed = broker.attach_listener("sess-staged", Some("0")).unwrap();
    let mut resumed_body = resumed.take_body().expect("body claimed once");
    let seen = drain_until(&mut resumed_body, &[r#""id":1"#], 4).await;
    assert!(
        seen.contains(r#""id":1"#),
        "a committed response resumes: {seen:?}"
    );
}

/// A response a later policy replaced or refused aborts its reservation: the
/// bytes never enter replay history, and the identity's per-session capacity
/// comes back exactly once.
#[tokio::test]
async fn a_refused_post_attached_response_aborts_and_never_enters_replay() {
    let broker = broker();
    broker.ensure_session("sess-refused").unwrap();
    let stream = broker.open_stream("sess-refused", &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let (_framed, publication) = stream.reserve_post_attached_response(&payload).unwrap();

    publication.abort();
    // Idempotent across context clones, and a refused response can never be
    // resurrected by a later commit.
    publication.abort();
    let recommitted = publication.commit();
    assert_eq!(recommitted.unwrap_err(), SseError::StreamCompleted);

    // Terminalized exactly once: the identity is refused rather than reopened.
    assert_eq!(
        broker
            .open_stream("sess-refused", &number_id(1))
            .unwrap_err(),
        SseError::StreamCompleted
    );

    let resumed = broker.attach_listener("sess-refused", Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    let greeting = frame_text(next_frame(&mut body).await);
    assert_eq!(greeting, ": mcp-sse\n\n");
    assert!(
        stays_idle(&mut body).await,
        "a refused response must never become replay history"
    );
}

/// Dropping the last handle is the same release: a request that ended before
/// the commit boundary — a transport disconnect, an early error return — leaks
/// neither the reservation nor the stream identity.
#[tokio::test]
async fn dropping_a_staged_post_attached_publication_releases_it() {
    let broker = broker();
    broker.ensure_session("sess-dropped").unwrap();
    let stream = broker.open_stream("sess-dropped", &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let (_framed, publication) = stream.reserve_post_attached_response(&payload).unwrap();
    drop(publication);

    assert_eq!(
        broker
            .open_stream("sess-dropped", &number_id(1))
            .unwrap_err(),
        SseError::StreamCompleted
    );
    let resumed = broker.attach_listener("sess-dropped", Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    let greeting = frame_text(next_frame(&mut body).await);
    assert_eq!(greeting, ": mcp-sse\n\n");
    assert!(stays_idle(&mut body).await);
}

/// A POST-attached cursor is assigned when the response is STAGED, because the
/// framed body the client receives has to carry it. Two concurrent requests on
/// one session can therefore commit out of order, and replay must still ascend
/// — the retained ring is partitioned, never scanned.
#[tokio::test]
async fn concurrent_post_attached_publications_keep_replay_ordered() {
    let broker = broker();
    broker.ensure_session("sess-order").unwrap();
    let first = broker.open_stream("sess-order", &number_id(1)).unwrap();
    let second = broker.open_stream("sess-order", &number_id(2)).unwrap();
    let first_payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let second_payload = encode(&json!({"jsonrpc": "2.0", "id": 2, "result": {}}));
    let (first_framed, first_publication) = first
        .reserve_post_attached_response(&first_payload)
        .unwrap();
    let (second_framed, second_publication) = second
        .reserve_post_attached_response(&second_payload)
        .unwrap();
    let first_framed = String::from_utf8_lossy(&first_framed).into_owned();
    let second_framed = String::from_utf8_lossy(&second_framed).into_owned();
    assert!(first_framed.contains("id: 1\nevent: message"));
    assert!(second_framed.contains("id: 2\nevent: message"));

    // The second response clears its policy pass first.
    assert_eq!(second_publication.commit().unwrap(), 2);
    assert_eq!(first_publication.commit().unwrap(), 1);

    let resumed = broker.attach_listener("sess-order", Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    let seen = drain_until(&mut body, &[r#""id":2"#], 4).await;
    let first_at = seen.find(r#""id":1"#).expect("earlier cursor replays");
    let second_at = seen.find(r#""id":2"#).expect("later cursor replays");
    assert!(
        first_at < second_at,
        "replay must ascend by event id: {seen:?}"
    );
}

/// Staging reports the stream PHASE in preference to a payload refusal, and a
/// second terminal attempt on one lease is a duplicate response rather than a
/// second reservation.
#[test]
fn staging_a_post_attached_response_reports_the_phase_before_the_payload() {
    let broker = broker();
    broker.ensure_session("sess-stage-refuse").unwrap();
    let wrong = encode(&json!({"jsonrpc": "2.0", "id": 9, "result": {}}));

    let cancelled = broker
        .open_stream("sess-stage-refuse", &number_id(1))
        .unwrap();
    broker
        .cancel_stream("sess-stage-refuse", &number_id(1))
        .unwrap();
    let cancelled_refusal = cancelled.reserve_post_attached_response(&wrong);
    assert_eq!(
        cancelled_refusal.unwrap_err(),
        SseError::StreamCancelled,
        "a cancellation outranks a refused payload"
    );

    let mismatched = broker
        .open_stream("sess-stage-refuse", &number_id(2))
        .unwrap();
    let mismatch_refusal = mismatched.reserve_post_attached_response(&wrong);
    assert_eq!(
        mismatch_refusal.unwrap_err(),
        SseError::ResponseEnvelopeInvalid
    );
    assert_eq!(
        broker
            .open_stream("sess-stage-refuse", &number_id(2))
            .unwrap_err(),
        SseError::StreamCompleted
    );

    let open = broker
        .open_stream("sess-stage-refuse", &number_id(3))
        .unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
    let (_framed, publication) = open.reserve_post_attached_response(&payload).unwrap();
    let duplicate = open.reserve_post_attached_response(&payload);
    assert_eq!(
        duplicate.unwrap_err(),
        SseError::StreamCompleted,
        "one lease stages one terminal response"
    );
    assert_eq!(publication.commit().unwrap(), 1);
}

/// A `notifications/cancelled` that lands AFTER the response was staged
/// suppresses retention only. The commit is refused, nothing becomes
/// replayable, and the POST body the gateway already produced is still the
/// gateway's answer — cancellation in this window means "not resumable", not
/// "withheld".
#[tokio::test]
async fn a_cancellation_after_staging_refuses_the_commit_and_retains_nothing() {
    let session = "s-late-cancel";
    let broker = broker();
    broker.ensure_session(session).unwrap();
    let stream = broker.open_stream(session, &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let (framed, publication) = stream.reserve_post_attached_response(&payload).unwrap();
    assert!(String::from_utf8_lossy(&framed).contains(r#""id":1"#));

    broker.cancel_stream(session, &number_id(1)).unwrap();
    assert_eq!(
        publication.commit().unwrap_err(),
        SseError::StreamCancelled,
        "a cancelled identity refuses its own staged retention"
    );

    let resumed = broker.attach_listener(session, Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    assert_eq!(frame_text(next_frame(&mut body).await), ": mcp-sse\n\n");
    assert!(
        stays_idle(&mut body).await,
        "a cancelled response must never become replay history"
    );
}

/// The stale-lease case the generation binding exists for.
///
/// A terminal record is evicted once the terminal set outgrows the open-stream
/// bound, after which the SAME JSON-RPC id may legitimately be opened again by a
/// different request. A publication staged under the FIRST admission must then
/// refuse: it must not retain its bytes under the live request's identity, must
/// not terminalize it, and must not hand away its per-session capacity.
#[tokio::test]
async fn a_stale_publication_cannot_act_on_a_reused_identity() {
    let session = "s-reuse";
    let tuned = AggregateSseBounds {
        max_streams_per_session: 1,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session(session).unwrap();

    // The first admission of id 1 stages its response; the client cancels it.
    let first = broker.open_stream(session, &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {"gen": 1}}));
    let (_framed, stale) = first.reserve_post_attached_response(&payload).unwrap();
    broker.cancel_stream(session, &number_id(1)).unwrap();
    drop(first);

    // An unrelated request completes, which evicts the cancellation record for
    // id 1: the terminal set is bounded by the open-stream bound.
    publish(&broker, session, 2).expect("an unrelated response publishes");

    // The same id is now admissible again, and belongs to a NEW request.
    let reopened = broker.open_stream(session, &number_id(1)).unwrap();

    assert_eq!(
        stale.commit().unwrap_err(),
        SseError::StreamCompleted,
        "a lease from the previous admission is terminal for itself only"
    );
    // The live admission is untouched: still open, still holding the session's
    // only stream slot.
    assert_eq!(
        broker.open_stream(session, &number_id(3)).unwrap_err(),
        SseError::StreamCardinalityOverflow,
        "the stale commit must not have released the live request's capacity"
    );
    let live_payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {"gen": 2}}));
    let (_live_framed, live) = reopened
        .reserve_post_attached_response(&live_payload)
        .expect("the live admission is still open and still stageable");
    live.commit().expect("the live response commits normally");

    let resumed = broker.attach_listener(session, Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    let seen = drain_until(&mut body, &[r#""gen":2"#], 5).await;
    assert!(
        seen.contains(r#""gen":2"#),
        "the live answer replays: {seen:?}"
    );
    assert!(
        !seen.contains(r#""gen":1"#),
        "the withdrawn answer must never replay: {seen:?}"
    );
}

/// Session teardown between staging and the commit boundary refuses the commit
/// and never resurrects the dead generation.
#[test]
fn a_staged_publication_refuses_after_session_teardown() {
    let session = "s-torn-down";
    let broker = broker();
    broker.ensure_session(session).unwrap();
    let stream = broker.open_stream(session, &number_id(1)).unwrap();
    let payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let (_framed, publication) = stream.reserve_post_attached_response(&payload).unwrap();

    broker.remove_session(session);
    assert_eq!(publication.commit().unwrap_err(), SseError::StaleSession);
    // The lease is spent either way, so a session that comes back under the same
    // id starts clean rather than inheriting a withdrawn answer.
    broker.ensure_session(session).unwrap();
    assert!(
        broker.open_stream(session, &number_id(1)).is_ok(),
        "a fresh session admits the id again"
    );
}

/// Aborting or dropping a staged reservation returns its stream slot and its
/// staged count exactly once, and never leaves a replayable copy behind.
#[tokio::test]
async fn aborted_and_dropped_stages_release_their_slot_and_retain_nothing() {
    let session = "s-returned";
    let tuned = AggregateSseBounds {
        max_streams_per_session: 1,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session(session).unwrap();

    // Abort.
    let first = broker.open_stream(session, &number_id(1)).unwrap();
    let first_payload = encode(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    let (_framed, aborted) = first
        .reserve_post_attached_response(&first_payload)
        .expect("the first response stages");
    assert_eq!(broker.outstanding_reservations(session), Some(1));
    aborted.abort();
    assert_eq!(broker.outstanding_reservations(session), Some(0));

    // Drop.
    let second = broker.open_stream(session, &number_id(2)).unwrap();
    let second_payload = encode(&json!({"jsonrpc": "2.0", "id": 2, "result": {}}));
    let (_framed, dropped) = second
        .reserve_post_attached_response(&second_payload)
        .expect("the aborted stage returned the only stream slot");
    drop(dropped);
    assert_eq!(broker.outstanding_reservations(session), Some(0));

    // A third, fresh id still opens in the only slot and commits.
    let third = broker.open_stream(session, &number_id(3)).unwrap();
    let third_payload = encode(&json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
    assert_eq!(stage_and_commit(&third, &third_payload), Ok(3));
    assert_eq!(broker.outstanding_reservations(session), Some(0));

    let resumed = broker.attach_listener(session, Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    let seen = drain_until(&mut body, &[r#""id":3"#], 4).await;
    assert!(
        seen.contains(r#""id":3"#),
        "the committed response replays: {seen:?}"
    );
    assert!(!seen.contains(r#""id":1"#), "{seen:?}");
    assert!(!seen.contains(r#""id":2"#), "{seen:?}");
}

/// Issue #7138: a commit that lands while a resumed listener is still
/// replaying must not move that listener's cursor past the older events it
/// asked for. Advancing by `max(event_id)` there skipped every event between
/// the cursor and the new commit.
#[tokio::test]
async fn a_commit_during_replay_does_not_skip_the_events_being_replayed() {
    let session = "s-mid-replay";
    let broker = broker();
    broker.ensure_session(session).unwrap();
    assert_eq!(publish(&broker, session, 1), Ok(1));
    assert_eq!(publish(&broker, session, 2), Ok(2));

    let resumed = broker.attach_listener(session, Some("0")).unwrap();
    let mut body = resumed.take_body().expect("body claimed once");
    assert_eq!(frame_text(next_frame(&mut body).await), ": mcp-sse\n\n");
    let first = frame_text(next_frame(&mut body).await);
    assert!(first.contains("\"n\":1"), "{first:?}");

    // Event 2 is still owed to this replay when event 3 commits.
    assert_eq!(publish(&broker, session, 3), Ok(3));

    let seen = drain_until(&mut body, &["\"n\":2", "\"n\":3"], 4).await;
    let second_at = seen
        .find("\"n\":2")
        .expect("the older replayed event is not skipped");
    let third_at = seen
        .find("\"n\":3")
        .expect("the newer event replays after it");
    assert!(second_at < third_at, "replay stays ordered: {seen:?}");

    // Caught up, the listener is advanced past later commits as usual.
    assert_eq!(publish(&broker, session, 4), Ok(4));
    assert!(stays_idle(&mut body).await);
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
