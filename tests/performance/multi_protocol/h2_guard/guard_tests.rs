//! Injected only into the verified h2 crate's private streams test module.
//! These call upstream recv_data/poll_data/clear_recv_buffer, not a guard model.
use super::*;
use crate::proto::DataFrameBudget;
use crate::proto::streams::guard_observe::{admit, Limit, TARGET};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Barrier};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>, Option<Arc<EmissionGate>>);

struct EmissionGate {
    emitted: mpsc::Sender<bool>,
    resume: Mutex<mpsc::Receiver<()>>,
}

struct Message(String);
impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}
impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == TARGET
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        self.0.lock().unwrap().push(message.0);
        if let Some(gate) = &self.1 {
            gate.emitted.send(true).unwrap();
            gate.resume.lock().unwrap().recv().unwrap();
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn observed(f: impl FnOnce()) -> Vec<String> {
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), f);
    let rows = capture.0.lock().unwrap().clone();
    assert!(rows.iter().all(|row| row.len() < 4096));
    rows
}

struct NoopWake;
impl std::task::Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWake))
}

struct ConnectionFixture(Streams<Bytes, client::Peer>);

impl std::ops::Deref for ConnectionFixture {
    type Target = Streams<Bytes, client::Peer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ConnectionFixture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ConnectionFixture {
    fn drop(&mut self) {
        // Match the real Connection::drop: retire live streams and reset queues
        // before Counts checks its lifetime invariant, including during unwind.
        let _ = self.0.recv_eof(true);
    }
}

fn connection() -> ConnectionFixture {
    connection_with_budget(32767)
}

fn connection_with_budget(budget: usize) -> ConnectionFixture {
    ConnectionFixture(Streams::new(Config {
        initial_max_send_streams: 1000,
        local_max_buffer_size: 1024 * 1024,
        local_next_stream_id: 1.into(),
        local_push_enabled: false,
        extended_connect_protocol_enabled: false,
        local_reset_duration: std::time::Duration::from_secs(30),
        local_reset_max: 1000,
        remote_reset_max: 1000,
        remote_init_window_sz: 65535,
        remote_max_initiated: Some(1000),
        local_max_error_reset_streams: Some(1000),
        data_frame_budget: DataFrameBudget::Configured(budget),
    }))
}

fn response(s: &mut Streams<Bytes, client::Peer>) -> StreamRef<Bytes> {
    let (mut stream, _) = s
        .send_request(Request::builder().uri("https://fixture.invalid/").body(()).unwrap(), true, None)
        .unwrap();
    // send_request only queues opening HEADERS. Drive the real prioritizer and
    // codec before receiving a response; an unflushed stream is still idle.
    let (io, _peer) = tokio::io::duplex(4096);
    let mut codec = Codec::new(io);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(s.poll_complete(&mut cx, &mut codec), Poll::Ready(Ok(()))));
    let headers = frame::Headers::new(
        stream.stream_id(),
        frame::Pseudo::response(http::StatusCode::OK),
        HeaderMap::new(),
    );
    let outcome = s.as_dyn().recv_headers(headers).unwrap();
    assert!(matches!(outcome, RecvOutcome::Processed), "{outcome:?}");
    assert!(matches!(
        stream.opaque.poll_response(&Context::from_waker(&noop_waker())),
        Poll::Ready(Ok(_))
    ));
    stream
}

fn data(s: &Streams<Bytes, client::Peer>, stream: &StreamRef<Bytes>, len: usize, end: bool) -> Result<(), Error> {
    let mut frame = frame::Data::new(stream.stream_id(), Bytes::from(vec![b'x'; len]));
    frame.set_end_stream(end);
    s.as_dyn().recv_data(frame)
}

fn state(s: &Streams<Bytes, client::Peer>) -> [usize; 7] {
    s.inner.lock().unwrap().counts.guard_state()
}

fn guard_error(error: Error) {
    match error {
        Error::GoAway(debug, Reason::ENHANCE_YOUR_CALM, Initiator::Library) => {
            assert_eq!(debug.as_ref(), b"too_many_data_frames");
        }
        other => panic!("unexpected guard result: {other:?}"),
    }
}

#[test]
fn guard_observation_small_credit_boundary_and_failure_snapshot() {
    let rows = observed(|| {
        let mut s = connection();
        let stream = response(&mut s);
        for _ in 0..128 {
            data(&s, &stream, 1, false).unwrap();
        }
        assert_eq!(&state(&s)[..3], &[32767, 127, 0]);
        guard_error(data(&s, &stream, 1, false).unwrap_err());
        assert_eq!(&state(&s)[..3], &[32767, 127, 0]);
        let me = s.inner.lock().unwrap();
        let observation = me.counts.observation.as_ref().unwrap();
        assert_eq!(observation.branch, 1);
        assert_eq!(observation.counters[1], 129);
        assert_eq!(observation.counters[5], 129); // queued before guard, including failure
    });
    let failures: Vec<_> = rows.iter().filter(|s| s.contains(" event=1 ")).collect();
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains(" branch=1 reason=11 "));
    assert!(failures[0].contains(" max=32767 available=127 empty=0 "));
    assert!(failures[0].contains(" last_len=1 last_flow=1 last_end=0 disposition=1 "));
    assert!(rows.iter().all(|s| !s.contains("fixture.invalid")));
}

#[test]
fn guard_observation_100_101_empty_nonfinal_and_final_empty_exemption() {
    observed(|| {
        let mut s = connection();
        let stream = response(&mut s);
        for _ in 0..100 {
            data(&s, &stream, 0, false).unwrap();
        }
        assert_eq!(&state(&s)[..3], &[32767, 32767, 100]);
        guard_error(data(&s, &stream, 0, false).unwrap_err());
        assert_eq!(&state(&s)[..3], &[32767, 32767, 101]);
        assert_eq!(s.inner.lock().unwrap().counts.observation.as_ref().unwrap().branch, 2);

        let mut s = connection();
        for _ in 0..101 {
            let mut stream = response(&mut s);
            data(&s, &stream, 0, true).unwrap();
            assert!(matches!(stream.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        }
        assert_eq!(&state(&s)[..3], &[32767, 32767, 0]);
    });
}

#[test]
fn guard_observation_poll_and_drop_return_real_queue_credit() {
    observed(|| {
        let mut s = connection();
        let mut stream = response(&mut s);
        data(&s, &stream, 1, false).unwrap();
        assert_eq!(state(&s)[1], 32512);
        assert!(matches!(stream.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        assert_eq!(state(&s)[1], 32767);
        data(&s, &stream, 2, false).unwrap();
        assert_eq!(state(&s)[1], 32513);
        drop(stream); // real OpaqueStreamRef::drop -> release_closed_capacity
        assert_eq!(state(&s)[1], 32767);
        let me = s.inner.lock().unwrap();
        let observation = me.counts.observation.as_ref().unwrap();
        assert_eq!(&observation.counters[11..], &[1, 1, 509]);
    });
}

#[test]
fn guard_observation_released_and_reset_frames_are_charged_but_not_queued() {
    observed(|| {
        let mut s = connection();
        let mut stream = response(&mut s);
        stream.opaque.clear_recv_buffer();
        data(&s, &stream, 1, false).unwrap();
        assert_eq!(state(&s)[1], 32512);
        assert_eq!(s.inner.lock().unwrap().counts.observation.as_ref().unwrap().disposition, 3);
        stream.send_reset(Reason::CANCEL);
        data(&s, &stream, 1, false).unwrap();
        assert_eq!(state(&s)[1], 32257);
        assert_eq!(s.inner.lock().unwrap().counts.observation.as_ref().unwrap().disposition, 2);
    });
}

#[test]
fn guard_observation_window_growth_retains_guard_and_large_frames_replenish() {
    observed(|| {
        let mut s = connection();
        s.set_target_connection_window_size(65535).unwrap();
        let stream = response(&mut s);
        data(&s, &stream, 1, false).unwrap();
        data(&s, &stream, 512, false).unwrap();
        assert_eq!(state(&s)[1], 32767);
        s.set_target_connection_window_size(33554432).unwrap();
        let mut settings = frame::Settings::default();
        settings.set_initial_window_size(Some(8388608));
        s.apply_local_settings(&settings).unwrap();
        assert_eq!(&state(&s)[..3], &[32767, 32767, 0]);
        for _ in 0..128 {
            data(&s, &stream, 1, false).unwrap();
        }
        guard_error(data(&s, &stream, 1, false).unwrap_err());
        let me = s.inner.lock().unwrap();
        let observation = me.counts.observation.as_ref().unwrap();
        assert_eq!(observation.initial_target, 65535);
        assert_eq!(observation.target, 33554432);
        assert_eq!(observation.target_updates, 2);
        assert_eq!(observation.stream_window, 8388608);
        assert_eq!(observation.branch, 1);
    });
}

#[test]
fn guard_observation_opt_in_and_bounded_suppression() {
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        let issued = crate::proto::streams::guard_observe::SEQUENCE.load(Ordering::Relaxed);
        assert!(connection().inner.lock().unwrap().counts.observation.is_none());
        assert_eq!(super::guard_snapshot(), "# H2_GUARD_ACK_V2 ack=0\n");
        assert_eq!(crate::proto::streams::guard_observe::SEQUENCE.load(Ordering::Relaxed), issued);
    });
    let limit = Limit::new(3);
    for id in 1..=3 {
        assert_eq!(limit.take(1), Ok(id));
    }
    let mut notices = 0;
    for suppressed in 1u64..=10000 {
        assert_eq!(limit.take(1), Err(suppressed));
        notices += usize::from(suppressed.is_power_of_two());
    }
    assert_eq!(limit.suppressed.load(Ordering::Relaxed), 10000);
    assert_eq!(notices, 14);
    let reserve = Limit::new(2048);
    for used in [513, 1026, 1539] {
        assert_eq!(reserve.take(513), Ok(used));
    }
    assert_eq!(reserve.take(513), Err(1));
    assert_eq!(reserve.take(509), Ok(2048)); // refused dumps consume no units
    assert_eq!(reserve.take(1), Err(2));
    let rows = observed(|| {
        let limit = Limit::new(0);
        for _ in 0..10000 {
            assert_eq!(admit(&limit, 3), None);
        }
    });
    assert_eq!(rows.len(), 14);
    assert!(rows.last().unwrap().contains("scope=3 suppressed=8192"));
    let rows = observed(|| {
        let mut s = connection();
        let mut stream = response(&mut s);
        for _ in 0..100 {
            data(&s, &stream, 256, false).unwrap();
            assert!(matches!(stream.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
            stream.opaque.release_capacity(256).unwrap();
        }
    });
    assert_eq!(rows.len(), 2); // initial and terminal, no per-frame records
}

#[test]
fn guard_observation_live_snapshot_and_contended_lock_are_explicit() {
    observed(|| {
        let mut s = connection_with_budget(16777216);
        let stream = response(&mut s);
        data(&s, &stream, 1, false).unwrap();
        let ack = super::guard_snapshot();
        assert!(ack.contains("captured=1"));
        assert!(ack.contains("missed=0"));
        let _held = s.inner.lock().unwrap();
        let ack = super::guard_snapshot();
        assert!(ack.contains("captured=0"));
        assert!(ack.contains("missed=1"));
    });
}

#[test]
fn guard_observation_memory_admission_is_finite_and_released() {
    use crate::proto::streams::guard_observe::{Observation, MEMORY_OVERFLOW, SLOTS};
    observed(|| {
        let before = MEMORY_OVERFLOW.load(Ordering::Relaxed);
        let admitted: Vec<_> = (0..SLOTS).map(|_| Observation::new(false, 32767).unwrap()).collect();
        assert!(admitted.iter().all(|observation| observation.allocation_with_metadata_allowance() <= 128 * 1024));
        assert!(Observation::new(false, 32767).is_none());
        assert_eq!(MEMORY_OVERFLOW.load(Ordering::Relaxed), before + 1);
        assert!(super::guard_snapshot().contains(&format!("memory_overflow={}", before + 1)));
        drop(admitted);
        assert!(Observation::new(false, 32767).is_some());
    });
}

#[test]
fn guard_observation_ring_drops_before_last_clone_returns_live_permit() {
    use crate::proto::streams::guard_observe::{Observation, SLOTS};
    observed(|| {
        let mut admitted: Vec<_> = (0..SLOTS).map(|_| Observation::new(false, 32767).unwrap()).collect();
        let mut original = admitted.pop().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        original.pause_tail_drop(barrier.clone());
        let snapshot = original.clone(); // the one separately budgeted snapshot
        for observation in [original, snapshot] {
            let destructor = std::thread::spawn(move || drop(observation));
            // An actual element of the boxed ring is still being destroyed.
            // Always release/join the destructor before asserting, including
            // under the old order where the last clone advertises a free slot.
            barrier.wait();
            let premature = Observation::new(false, 32767);
            barrier.wait();
            destructor.join().unwrap();
            assert!(premature.is_none(), "a live ring's slot was reused during destruction");
        }
        let replacement = Observation::new(false, 32767).unwrap();
        assert!(Observation::new(false, 32767).is_none());
        drop(replacement);
        drop(admitted);
    });
}

fn numeric_field(row: &str, name: &str) -> u64 {
    row.split_ascii_whitespace()
        .filter_map(|field| field.split_once('='))
        .find(|(key, _)| *key == name).unwrap().1.parse().unwrap()
}

#[test]
#[ignore = "requires a fresh process-wide failure quota; run separately in hosted CI"]
fn guard_observation_concurrent_failure_dumps_reserve_complete_tails() {
    use crate::proto::streams::guard_observe::TAIL;
    let start = Arc::new(Barrier::new(4));
    let mut schedules = Vec::new();
    let mut producers = Vec::new();
    for _ in 0..4 {
        let (emitted, steps) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let gate = Arc::new(EmissionGate { emitted: emitted.clone(), resume: Mutex::new(resumed) });
        let start = start.clone();
        schedules.push((steps, resume, true));
        producers.push(std::thread::spawn(move || {
            let capture = Capture(Arc::default(), Some(gate));
            tracing::subscriber::with_default(capture.clone(), || {
                let mut s = connection();
                let mut body = response(&mut s);
                // Fill/wrap the real ring without changing the upstream budget.
                for _ in 0..200 {
                    data(&s, &body, 256, false).unwrap();
                    assert!(matches!(body.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
                    body.opaque.release_capacity(256).unwrap();
                }
                for _ in 0..128 { data(&s, &body, 1, false).unwrap(); }
                assert_eq!(&state(&s)[..3], &[32767, 127, 0]);
                start.wait();
                guard_error(data(&s, &body, 1, false).unwrap_err());
            });
            let rows = capture.0.lock().unwrap().clone();
            emitted.send(false).unwrap();
            rows
        }));
    }
    // Block each producer in its actual tracing callback and release one record
    // per producer per round. Old per-record admission spends all 2048 units on
    // four partial dumps; a serial loop over quota arithmetic cannot catch it.
    while schedules.iter().any(|(_, _, active)| *active) {
        for (steps, resume, active) in &mut schedules {
            if *active {
                *active = steps.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
                if *active { resume.send(()).unwrap(); }
            }
        }
    }
    let rows: Vec<_> = producers.into_iter().flat_map(|producer| producer.join().unwrap()).collect();
    assert!(rows.iter().all(|row| row.len() < 4096));
    let failures: Vec<_> = rows.iter().filter(|row| row.contains(" event=1 ")).collect();
    assert_eq!(failures.len(), 3);
    let tails: Vec<_> = rows.iter().filter(|row| row.starts_with("H2_GUARD_TAIL_V2 ")).collect();
    assert_eq!(tails.len(), 3 * TAIL);
    for summary in failures {
        assert_eq!(numeric_field(summary, "tail_len"), TAIL as u64);
        let last = numeric_field(summary, "transitions");
        assert!(last > TAIL as u64);
        let tail: Vec<_> = tails.iter().filter(|row| numeric_field(row, "snapshot") == numeric_field(summary, "seq")).collect();
        assert_eq!(tail.len(), TAIL);
        assert_eq!(tail.iter().map(|row| numeric_field(row, "n")).collect::<Vec<_>>(),
                   (last - TAIL as u64 + 1..=last).collect::<Vec<_>>());
        assert!(tail.iter().all(|row| numeric_field(row, "cid") == numeric_field(summary, "cid")));
        assert!(tail.last().unwrap().contains("consume=2 before=127 after=127"));
    }
    let notices: Vec<_> = rows.iter().filter(|row| row.starts_with("H2_GUARD_LIMIT_V1 ") && row.contains(" scope=3 ")).collect();
    assert_eq!(notices.len(), 1);
    assert_eq!(numeric_field(notices[0], "suppressed"), 1);
    assert_eq!(rows.iter().filter(|row| row.contains(" event=2 ")).count(), 4);
}

#[test]
fn guard_observation_export_contract() {
    // A second, isolated hosted invocation exports the actual producer's messages
    // for Python completeness/negative tests. This synthetic boundary fixture is
    // NOT a replay of the campaign's unobserved fragmentation/poll schedule.
    let mut acks = Vec::new();
    let rows = observed(|| {
        let mut fixed = connection_with_budget(16777216);
        let mut body = response(&mut fixed);
        acks.push(super::guard_snapshot());
        acks.push(super::guard_snapshot());
        fixed.clear_expired_reset_streams(); // real receive poll2 entry hook
        data(&fixed, &body, 1, false).unwrap();
        data(&fixed, &body, 512, false).unwrap(); // capped receive replenishment
        assert!(matches!(body.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        body.opaque.clear_recv_buffer(); // actual clear, including a large event
        let mut body = response(&mut fixed);
        for _ in 0..180 {
            fixed.clear_expired_reset_streams();
            data(&fixed, &body, 256, false).unwrap();
            assert!(matches!(body.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
            body.opaque.release_capacity(256).unwrap();
        }
        let padded = frame::Data::load(
            frame::Head::new(frame::Kind::Data, 0x8, body.stream_id()),
            Bytes::from_static(&[2, b'x', 0, 0]),
        ).unwrap();
        fixed.as_dyn().recv_data(padded).unwrap();
        data(&fixed, &body, 512, false).unwrap();
        assert!(matches!(body.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        body.opaque.clear_recv_buffer();
        fixed.set_target_connection_window_size(33554432).unwrap();
        let mut settings = frame::Settings::default();
        settings.set_initial_window_size(Some(8388608));
        fixed.apply_local_settings(&settings).unwrap();
        let mut final_body = response(&mut fixed);
        data(&fixed, &final_body, 1, true).unwrap(); // final exemption stays explicit
        assert!(matches!(final_body.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        let mut failing = connection();
        let failed_body = response(&mut failing);
        failing.clear_expired_reset_streams();
        for _ in 0..128 { data(&failing, &failed_body, 1, false).unwrap(); }
        guard_error(data(&failing, &failed_body, 1, false).unwrap_err());
        assert_eq!(failing.inner.lock().unwrap().counts.observation.as_ref().unwrap().pending, 129);
        acks.push(super::guard_snapshot()); // both fixed and failed Inner are LIVE
    });
    assert!(rows.iter().any(|row| row.contains("H2_GUARD_TAIL_V2") && row.contains("consume=2 before=127 after=127")));
    if let Some(path) = std::env::var_os("H2_GUARD_PRODUCER_CONTRACT") {
        let mut text = rows.join("\n");
        text.push('\n');
        text.push_str(&acks.concat());
        std::fs::write(path, text).unwrap();
    }
}
