use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ferrum_edge::logging::non_blocking::EnqueueResult;
use ferrum_edge::logging::{NonBlockingOptions, NonBlockingSink, SinkName};
use ferrum_edge::plugins::{TransactionSummary, stdout_logging::StdoutLogging};
use ferrum_edge::retry::ErrorClass;
use serde::Serialize;
use serde_json::json;

fn options(record_capacity: usize, shutdown_timeout: Duration) -> NonBlockingOptions {
    NonBlockingOptions {
        record_capacity,
        byte_capacity: record_capacity * 64,
        max_record_bytes: 64,
        shutdown_timeout,
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(predicate(), "condition did not become true before deadline");
}

struct BrokenPipeWriter;

impl Write for BrokenPipeWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn broken_pipe_is_accounted_without_blocking_producer() {
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        BrokenPipeWriter,
        options(4, Duration::from_millis(200)),
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(sink.try_write_bytes(b"one\n"), EnqueueResult::Queued);
    assert!(started.elapsed() < Duration::from_millis(50));

    wait_until(|| sink.snapshot().writer_failures_total == 1);
    let snapshot = sink.snapshot();
    assert!(!snapshot.healthy);
    assert_eq!(snapshot.accepted_records_total, 1);
    assert_eq!(
        snapshot
            .last_failure
            .as_ref()
            .map(|failure| failure.error_kind),
        Some("broken_pipe")
    );
    assert!(guard.shutdown());
}

struct FlushFailureWriter;

impl Write for FlushFailureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[test]
fn flush_failure_has_a_distinct_counter_and_last_failure() {
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        FlushFailureWriter,
        options(2, Duration::from_millis(200)),
    )
    .unwrap();
    assert_eq!(sink.try_write_bytes(b"one\n"), EnqueueResult::Queued);
    wait_until(|| sink.snapshot().queued_records == 0);
    assert!(guard.shutdown());

    let snapshot = sink.snapshot();
    assert_eq!(snapshot.writer_failures_total, 0);
    assert_eq!(snapshot.flush_failures_total, 1);
    assert_eq!(
        snapshot
            .last_failure
            .as_ref()
            .map(|failure| failure.operation),
        Some("flush")
    );
}

#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stdout_failure_notice_uses_separate_stderr_sink_and_is_rate_limited() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let (stderr, mut stderr_guard) = NonBlockingSink::spawn(
        SinkName::Stderr,
        SharedBuffer(Arc::clone(&output)),
        NonBlockingOptions {
            record_capacity: 4,
            byte_capacity: 2_048,
            max_record_bytes: 512,
            shutdown_timeout: Duration::from_millis(200),
        },
    )
    .unwrap();
    let (stdout, mut stdout_guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        BrokenPipeWriter,
        options(4, Duration::from_millis(200)),
    )
    .unwrap();
    stdout
        .set_failure_fallback(stderr.clone())
        .expect("separate stderr fallback");

    assert_eq!(stdout.try_write_bytes(b"one\n"), EnqueueResult::Queued);
    assert_eq!(stdout.try_write_bytes(b"two\n"), EnqueueResult::Queued);
    wait_until(|| stdout.snapshot().writer_failures_total == 2);
    assert!(stdout_guard.shutdown());
    assert!(stderr_guard.shutdown());

    let captured = match output.lock() {
        Ok(guard) => String::from_utf8(guard.clone()).unwrap(),
        Err(poisoned) => String::from_utf8(poisoned.into_inner().clone()).unwrap(),
    };
    assert_eq!(captured.lines().count(), 1, "{captured}");
    assert!(captured.contains("stdout log sink failure"), "{captured}");
}

#[test]
fn errors_only_body_failure_and_disconnect_emit_finalized_stdout_json() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        SharedBuffer(Arc::clone(&output)),
        NonBlockingOptions {
            record_capacity: 4,
            byte_capacity: 16_384,
            max_record_bytes: 4_096,
            shutdown_timeout: Duration::from_millis(200),
        },
    )
    .unwrap();
    let plugin = StdoutLogging::new(&json!({"filter": {"errors_only": true}})).unwrap();

    let mut success = TransactionSummary {
        proxy_id: Some("terminal-success".to_string()),
        response_status_code: 200,
        response_streamed: true,
        body_completed: true,
        ..TransactionSummary::default()
    };
    assert!(!plugin.should_log_transaction(&success));

    success.proxy_id = Some("body-failure".to_string());
    success.body_completed = false;
    success.body_error_class = Some(ErrorClass::ConnectionReset);
    assert!(plugin.should_log_transaction(&success));
    assert_eq!(
        sink.try_write_json(&success).unwrap(),
        EnqueueResult::Queued
    );

    let disconnect = TransactionSummary {
        proxy_id: Some("client-disconnect".to_string()),
        response_status_code: 200,
        response_streamed: true,
        client_disconnected: true,
        body_error_class: Some(ErrorClass::ClientDisconnect),
        ..TransactionSummary::default()
    };
    assert!(plugin.should_log_transaction(&disconnect));
    assert_eq!(
        sink.try_write_json(&disconnect).unwrap(),
        EnqueueResult::Queued
    );
    wait_until(|| sink.snapshot().queued_records == 0);
    assert!(guard.shutdown());

    let captured = match output.lock() {
        Ok(guard) => String::from_utf8(guard.clone()).unwrap(),
        Err(poisoned) => String::from_utf8(poisoned.into_inner().clone()).unwrap(),
    };
    let entries: Vec<serde_json::Value> = captured
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 2, "{captured}");
    assert_eq!(entries[0]["proxy_id"], "body-failure");
    assert_eq!(entries[0]["body_error_class"], "connection_reset");
    assert_eq!(entries[1]["proxy_id"], "client-disconnect");
    assert_eq!(entries[1]["client_disconnected"], true);
}

struct BlockingWriter {
    started: mpsc::SyncSender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

struct CountingSerialization(Arc<AtomicUsize>);

impl Serialize for CountingSerialization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.fetch_add(1, Ordering::Relaxed);
        serializer.serialize_str("attacker-shaped-record")
    }
}

impl Write for BlockingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let _ = self.started.try_send(());
        let (lock, wake) = &*self.release;
        let mut released = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        while !*released {
            released = match wake.wait(released) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn saturation_is_non_blocking_and_stdout_stderr_counters_are_independent() {
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let writer = BlockingWriter {
        started: started_tx,
        release: Arc::clone(&release),
    };
    let (stdout, mut stdout_guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        writer,
        options(2, Duration::from_millis(200)),
    )
    .unwrap();
    let (stderr, mut stderr_guard) = NonBlockingSink::spawn(
        SinkName::Stderr,
        Vec::<u8>::new(),
        options(2, Duration::from_millis(200)),
    )
    .unwrap();
    let stdout_errors = stdout.error_counter();
    let stderr_errors = stderr.error_counter();

    assert_eq!(stdout.try_write_bytes(b"one\n"), EnqueueResult::Queued);
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(stdout.try_write_bytes(b"two\n"), EnqueueResult::Queued);
    let started = Instant::now();
    assert_eq!(stdout.try_write_bytes(b"three\n"), EnqueueResult::Saturated);
    assert!(started.elapsed() < Duration::from_millis(50));
    assert_eq!(stdout_errors.saturation_dropped_records(), 1);
    assert_eq!(stderr_errors.saturation_dropped_records(), 0);
    assert_eq!(stderr_errors.oversized_dropped_records(), 0);
    assert_eq!(stderr_errors.closed_dropped_records(), 0);
    let serialization_count = Arc::new(AtomicUsize::new(0));
    assert_eq!(
        stdout
            .try_write_json(&CountingSerialization(Arc::clone(&serialization_count)))
            .unwrap(),
        EnqueueResult::Saturated
    );
    assert_eq!(
        serialization_count.load(Ordering::Relaxed),
        0,
        "full-queue admission must happen before serialization"
    );

    let (lock, wake) = &*release;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    assert!(stdout_guard.shutdown());
    assert!(stderr_guard.shutdown());
}

#[test]
fn aggregate_byte_budget_rejects_before_record_slots_are_full() {
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let writer = BlockingWriter {
        started: started_tx,
        release: Arc::clone(&release),
    };
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        writer,
        NonBlockingOptions {
            record_capacity: 4,
            byte_capacity: 96,
            max_record_bytes: 64,
            shutdown_timeout: Duration::from_millis(200),
        },
    )
    .unwrap();

    assert_eq!(sink.try_write_bytes(&[b'a'; 32]), EnqueueResult::Queued);
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(sink.try_write_bytes(&[b'b'; 32]), EnqueueResult::Queued);

    let before_rejection = sink.snapshot();
    assert_eq!(before_rejection.queued_records, 2);
    assert_eq!(before_rejection.reserved_bytes, 64);
    assert!(before_rejection.queued_records < before_rejection.queue_capacity_records);
    assert_eq!(sink.try_write_bytes(b"c"), EnqueueResult::Saturated);
    assert_eq!(sink.snapshot().saturation_dropped_records_total, 1);

    let (lock, wake) = &*release;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    assert!(guard.shutdown());
}

#[test]
fn oversized_record_is_bounded_and_counted_separately() {
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        Vec::<u8>::new(),
        options(2, Duration::from_millis(200)),
    )
    .unwrap();
    assert_eq!(
        sink.try_write_bytes(&[b'x'; 65]),
        EnqueueResult::RecordTooLarge
    );
    let snapshot = sink.snapshot();
    assert_eq!(snapshot.oversized_dropped_records_total, 1);
    assert_eq!(snapshot.accepted_records_total, 0);
    assert!(guard.shutdown());
}

#[test]
fn admission_after_shutdown_is_closed_and_counted() {
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        Vec::<u8>::new(),
        options(2, Duration::from_millis(200)),
    )
    .unwrap();
    assert!(guard.shutdown());

    assert_eq!(
        sink.try_write_bytes(b"after shutdown\n"),
        EnqueueResult::Closed
    );
    let snapshot = sink.snapshot();
    assert_eq!(snapshot.closed_dropped_records_total, 1);
    assert_eq!(snapshot.queued_records, 0);
    assert_eq!(snapshot.reserved_bytes, 0);
}

#[test]
fn blocked_writer_produces_bounded_shutdown_and_incomplete_drain_count() {
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let writer = BlockingWriter {
        started: started_tx,
        release: Arc::clone(&release),
    };
    let (sink, mut guard) = NonBlockingSink::spawn(
        SinkName::Stdout,
        writer,
        options(2, Duration::from_millis(25)),
    )
    .unwrap();
    assert_eq!(sink.try_write_bytes(b"blocked\n"), EnqueueResult::Queued);
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    let started = Instant::now();
    assert!(!guard.shutdown());
    assert!(started.elapsed() < Duration::from_millis(200));
    let snapshot = sink.snapshot();
    assert_eq!(snapshot.shutdown_timeouts_total, 1);
    assert_eq!(snapshot.shutdown_incomplete_records_total, 1);
    assert_eq!(
        snapshot
            .last_failure
            .as_ref()
            .map(|failure| failure.error_kind),
        Some("drain_timeout")
    );

    let (lock, wake) = &*release;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    wait_until(|| sink.snapshot().queued_records == 0);
}

/// Thread-safe in-memory `MakeWriter` for the filter tests below.
#[derive(Clone, Default)]
struct FilterCapture(Arc<Mutex<Vec<u8>>>);

impl FilterCapture {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap_or_default()
    }
}

impl Write for FilterCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FilterCapture {
    type Writer = FilterCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Emit, through an output layer filtered by `directives` AND the gateway's
/// credential-dumping filter (the same composition `init_logging` builds),
/// the dependency records that render credentials plus sibling controls, and
/// return what reached the output.
fn render_under_gateway_filter(directives: &str) -> String {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let writer = FilterCapture::default();
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_writer(writer.clone())
        .with_filter(tracing_subscriber::EnvFilter::new(directives))
        .with_filter(ferrum_edge::logging::credential_dumping_log_filter());
    let subscriber = tracing_subscriber::registry().with(layer);
    crate::diagnostic_test_interest::ensure_interest_floor();
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("ws_connect");
        let _entered = span.enter();
        tracing::trace!(
            target: "tungstenite::handshake::client",
            "Request: GET /ingest?stream=handshake-path-canary HTTP/1.1 authorization: Bearer handshake-header-canary"
        );
        tracing::debug!(
            target: "tungstenite::handshake::client",
            "Client handshake done."
        );
        tracing::trace!(
            target: "tungstenite::protocol",
            "Received message {{\"token\":\"protocol-payload-canary\"}}"
        );
        tracing::trace!(
            target: "tungstenite::protocol::frame",
            "writing frame frame-payload-canary"
        );
        tracing::debug!(target: "tungstenite::protocol", "close-frame-debug-visible");
        tracing::trace!(target: "tungstenite::handshake::server", "sibling-target-visible");
        tracing::trace!(target: "tungstenite::protocolx", "lookalike-target-visible");
    });
    writer.contents()
}

#[test]
fn credential_dumping_records_stay_off_under_every_directive_shape() {
    for directives in [
        "trace",
        "tungstenite=trace",
        "warn,tungstenite::handshake::client=trace",
        // Field-scoped and span-scoped directives are more specific than any
        // target directive; the AND-composed filter must still drop them.
        "warn,tungstenite::handshake::client[{message}]=trace,tungstenite::protocol[{message}]=trace",
        "warn,tungstenite::handshake::client[ws_connect]=trace,tungstenite::protocol[ws_connect]=trace",
    ] {
        let output = render_under_gateway_filter(directives);
        for canary in [
            "handshake-path-canary",
            "handshake-header-canary",
            "Client handshake done.",
            "protocol-payload-canary",
            "frame-payload-canary",
        ] {
            assert!(
                !output.contains(canary),
                "{directives}: {canary} leaked: {output}"
            );
        }
    }

    // Controls: the filter is target- and level-scoped, so other tungstenite
    // records keep their configured verbosity...
    let output = render_under_gateway_filter("trace");
    assert!(output.contains("sibling-target-visible"), "{output}");
    assert!(output.contains("close-frame-debug-visible"), "{output}");
    assert!(output.contains("lookalike-target-visible"), "{output}");
    // ...and the field-scoped directive shape really does enable records,
    // so its suppression assertion above is not vacuous.
    let output =
        render_under_gateway_filter("warn,tungstenite::handshake::server[{message}]=trace");
    assert!(output.contains("sibling-target-visible"), "{output}");
}

#[test]
fn credential_dumping_filter_never_raises_verbosity() {
    let output = render_under_gateway_filter("warn");
    for record in [
        "sibling-target-visible",
        "close-frame-debug-visible",
        "lookalike-target-visible",
    ] {
        assert!(!output.contains(record), "{record}: {output}");
    }
}

/// Every output layer the binary installs must carry the credential filter
/// outside its reloadable `EnvFilter`; a layer without it would let any
/// directive or RTDS reload re-enable the records.
#[test]
fn every_gateway_output_layer_composes_the_credential_dumping_filter() {
    let source = include_str!("../../src/gateway_entry.rs");
    let output_layers = source.matches("tracing_subscriber::fmt::layer()").count();
    let filtered = source
        .matches(".with_filter(logging::credential_dumping_log_filter())")
        .count();
    assert!(output_layers >= 2, "expected both init_logging branches");
    assert_eq!(
        filtered, output_layers,
        "every fmt output layer must compose credential_dumping_log_filter()"
    );
    assert!(
        ferrum_edge::logging::CREDENTIAL_DUMPING_LOG_TARGETS
            .iter()
            .any(|(target, _)| *target == "tungstenite::handshake::client")
    );
}
