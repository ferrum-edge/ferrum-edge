//! Deterministic delivery-lifecycle tests for notification dispatch +
//! proxy_alerts pending-state / generation retirement contracts (#2448).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::notifications::channels::email::{SmtpFailure, SmtpPhase};
use ferrum_edge::notifications::channels::{NotificationChannel, parse_channels};
use ferrum_edge::notifications::dispatch::{DeliveryRetryPolicy, dispatch_one};
use ferrum_edge::notifications::generation::{DispatchGeneration, DispatchSettle};
use ferrum_edge::notifications::metrics::DeliveryMetrics;
use ferrum_edge::notifications::outcome::{
    ABANDON_REASONS, AbandonReason, FailureClass, REJECT_REASONS, classify_http_status,
    classify_smtp_failure,
};
use ferrum_edge::notifications::{EventAction, Notification, NotificationField, Severity};
use ferrum_edge::observability_delivery::DeliverySlot;
use ferrum_edge::plugins::proxy_alerts::ProxyAlerts;
use ferrum_edge::plugins::proxy_alerts::cooldown::{LifecycleOutcome, RecoveryGate, RuleState};
use ferrum_edge::plugins::proxy_alerts::windows::monotonic_now_ms;
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{Plugin, TransactionSummary};
use futures_util::FutureExt as _;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, oneshot};
use tokio::time::timeout;

fn fixed_notification() -> Notification {
    Notification {
        title: "x".to_string(),
        body: "y".to_string(),
        severity: Severity::High,
        event_action: EventAction::Trigger,
        source: None,
        subject_id: None,
        namespace: None,
        fired_at: chrono::Utc::now(),
        fields: vec![NotificationField::new("k", "v")],
    }
}

fn webhook_channel_to(url: String) -> Arc<NotificationChannel> {
    let map = parse_channels(&json!({
        "delivery_test": {
            "type": "webhook",
            "url": url,
            "body_template": "{}",
        }
    }))
    .unwrap();
    map.into_values().next().unwrap()
}

async fn read_request_headers(socket: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 8192 {
            break;
        }
    }
}

async fn spawn_status_sequence_server(
    statuses: Vec<u16>,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let server_count = Arc::clone(&count);
    let server_notify = Arc::clone(&notify);

    let handle = tokio::spawn(async move {
        for status in statuses {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_count.fetch_add(1, Ordering::SeqCst);
            server_notify.notify_waiters();
            let body =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(body.as_bytes()).await.unwrap();
        }
    });

    (addr, count, notify, handle)
}

/// A live listener that keeps accepting and answering with the same status so
/// a buggy retry is observable as an extra counted request.
async fn spawn_persistent_status_server(
    status: u16,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let server_count = Arc::clone(&count);
    let server_notify = Arc::clone(&notify);

    let handle = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_count.fetch_add(1, Ordering::SeqCst);
            server_notify.notify_waiters();
            let body =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(body.as_bytes()).await.unwrap();
        }
    });

    (addr, count, notify, handle)
}

/// Await an observable condition without any sleep or polling cadence.
///
/// The `Notified` future is pinned and `enable()`d *before* `ready` is
/// evaluated. That ordering is load-bearing: `notify_waiters` retains no permit
/// for a waiter that is not yet registered, and merely constructing
/// `notified()` does not register — registration happens on first poll or on
/// `enable()`. Without it, a signal landing between the state read and the
/// first poll would be lost and the test would hang until its timeout.
async fn wait_until<F>(notify: &Notify, ready: F, what: &str)
where
    F: Fn() -> bool,
{
    let wait = async {
        loop {
            let notified = notify.notified();
            tokio::pin!(notified);
            let _ = notified.as_mut().enable();
            if ready() {
                return;
            }
            notified.as_mut().await;
        }
    };
    timeout(Duration::from_secs(10), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn wait_for_count(count: &AtomicUsize, notify: &Notify, expected: usize) {
    wait_until(
        notify,
        || count.load(Ordering::SeqCst) >= expected,
        &format!("{expected} requests"),
    )
    .await;
}

/// Records every producer settle callback and lets a test await the Nth one
/// event-driven, so no assertion depends on a sleep landing after the callback.
#[derive(Default)]
struct SettleLog {
    settles: std::sync::Mutex<Vec<DispatchSettle>>,
    changed: Notify,
}

impl SettleLog {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn snapshot(&self) -> Vec<DispatchSettle> {
        self.settles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn len(&self) -> usize {
        self.settles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Producer callback. Runs synchronously on the settling task — never
    /// re-spawned — so "the callback ran" and "the task settled" are the same
    /// observable event.
    fn callback(self: &Arc<Self>) -> Arc<dyn Fn(DispatchSettle) + Send + Sync> {
        let log = Arc::clone(self);
        Arc::new(move |settle| {
            log.settles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(settle);
            log.changed.notify_waiters();
        })
    }

    async fn wait_for_settles(&self, expected: usize) -> Vec<DispatchSettle> {
        wait_until(
            &self.changed,
            || self.len() >= expected,
            &format!("{expected} delivery settles"),
        )
        .await;
        self.snapshot()
    }
}

#[test]
fn http_status_classification_is_bounded_and_stable() {
    assert_eq!(
        classify_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
        FailureClass::Transient
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::REQUEST_TIMEOUT),
        FailureClass::Transient
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        FailureClass::Transient
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::BAD_REQUEST),
        FailureClass::Permanent
    );
    assert_eq!(
        classify_http_status(reqwest::StatusCode::UNAUTHORIZED),
        FailureClass::Permanent
    );
    assert_eq!(
        classify_smtp_failure(&SmtpFailure::UnexpectedCode {
            phase: SmtpPhase::Data,
            code: 451,
        }),
        FailureClass::Transient
    );
    assert_eq!(
        classify_smtp_failure(&SmtpFailure::UnexpectedCode {
            phase: SmtpPhase::Data,
            code: 550,
        }),
        FailureClass::Permanent
    );
}

#[test]
fn prometheus_contract_emits_fixed_channel_type_series() {
    let text = ferrum_edge::notifications::render_delivery_prometheus();
    for kind in ["slack", "teams", "discord", "webhook", "email"] {
        assert!(
            text.contains(&format!(
                "ferrum_notification_delivery_attempted_total{{channel_type=\"{kind}\"}}"
            )),
            "missing attempted series for {kind}"
        );
        assert!(
            text.contains(&format!(
                "ferrum_notification_delivery_in_flight{{channel_type=\"{kind}\"}}"
            )),
            "missing in-flight gauge for {kind}"
        );
    }
    assert!(text.contains("# HELP ferrum_notification_delivery_abandoned_at_deadline_total"));
    assert!(text.contains("# HELP ferrum_notification_delivery_backpressure_dropped_total"));
    assert!(
        text.contains(
            "# HELP ferrum_notification_delivery_attempted_total Notification delivery tasks whose registry-owned delivery body started executing"
        ),
        "attempted HELP must describe body-start, not an unguaranteed transport-start claim"
    );
    assert!(
        text.contains("may advance before any channel transport call"),
        "attempted HELP must admit the admit-then-cancel/no-transport case"
    );
    assert!(!text.contains("channel_name="));

    // The reason taxonomy is fixed and fully materialized from the first
    // scrape, and the two families are disjoint: a pre-body rejection reason
    // must never appear on the abandoned family and vice versa.
    for kind in ["slack", "teams", "discord", "webhook", "email"] {
        for reason in REJECT_REASONS {
            let reason = reason.as_str();
            assert!(
                text.contains(&format!(
                    "ferrum_notification_delivery_rejected_total{{channel_type=\"{kind}\",reason=\"{reason}\"}}"
                )),
                "missing rejected series for {kind}/{reason}"
            );
            assert!(
                !text.contains(&format!(
                    "ferrum_notification_delivery_abandoned_total{{channel_type=\"{kind}\",reason=\"{reason}\"}}"
                )),
                "pre-body reason {reason} must not appear on the abandoned family"
            );
        }
        for reason in ABANDON_REASONS {
            let reason = reason.as_str();
            assert!(
                text.contains(&format!(
                    "ferrum_notification_delivery_abandoned_total{{channel_type=\"{kind}\",reason=\"{reason}\"}}"
                )),
                "missing abandoned series for {kind}/{reason}"
            );
            assert!(
                !text.contains(&format!(
                    "ferrum_notification_delivery_rejected_total{{channel_type=\"{kind}\",reason=\"{reason}\"}}"
                )),
                "post-body reason {reason} must not appear on the rejected family"
            );
        }
    }
    // Backpressure keeps its own dedicated family and is never double counted
    // into the rejection taxonomy.
    assert!(!text.contains("reason=\"backpressure\""));
    // Exactly the fixed cardinality: 5 channel types x each reason set.
    assert_eq!(
        text.matches("ferrum_notification_delivery_rejected_total{")
            .count(),
        5 * REJECT_REASONS.len()
    );
    assert_eq!(
        text.matches("ferrum_notification_delivery_abandoned_total{")
            .count(),
        5 * ABANDON_REASONS.len()
    );
}

/// The reason taxonomy must stay closed and the two families disjoint, so a
/// future variant cannot silently land in both (or in neither, losing the
/// signal entirely).
#[test]
fn abandon_reason_taxonomy_is_closed_and_partitioned() {
    let all = [
        AbandonReason::Backpressure,
        AbandonReason::GenerationClosed,
        AbandonReason::RegistryRejected,
        AbandonReason::GenerationRetired,
        AbandonReason::ShutdownDeadline,
        AbandonReason::TaskDropped,
    ];
    for reason in all {
        assert!(
            reason.reject_index().is_none() || reason.abandon_index().is_none(),
            "{reason} must not belong to both families"
        );
        // Backpressure is the deliberate exception: it has its own family.
        if reason != AbandonReason::Backpressure {
            assert!(
                reason.reject_index().is_some() || reason.abandon_index().is_some(),
                "{reason} must be counted somewhere"
            );
        }
    }
    assert!(AbandonReason::ShutdownDeadline.is_shutdown_deadline());
    for reason in all {
        if reason != AbandonReason::ShutdownDeadline {
            assert!(
                !reason.is_shutdown_deadline(),
                "{reason} must not inflate abandoned_at_deadline"
            );
        }
    }
    assert_eq!(REJECT_REASONS.len(), 2);
    assert_eq!(ABANDON_REASONS.len(), 3);
}

#[tokio::test]
async fn semaphore_exhaustion_increments_backpressure_and_skips_send() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(42, Arc::clone(&metrics));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sem = Arc::new(Semaphore::new(0));
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let notification = Arc::new(fixed_notification());
    let settles = SettleLog::new();

    let admitted = dispatch_one(
        notification,
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        generation,
        DeliveryRetryPolicy {
            max_retries: 0,
            ..DeliveryRetryPolicy::DEFAULT
        },
        "test",
        Some(settles.callback()),
    );
    assert!(!admitted);
    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(snap.backpressure_dropped, 1);
    // Backpressure is a *pre-body* drop: it must not inflate `attempted`,
    // must not move the in-flight gauge, must not be double counted into the
    // rejection taxonomy, and above all must not charge the shutdown-deadline
    // counter.
    assert_eq!(snap.attempted, 0);
    assert_eq!(snap.in_flight, 0);
    assert_eq!(snap.total_rejected(), 0);
    assert_eq!(snap.total_abandoned(), 0);
    assert_eq!(snap.abandoned_at_deadline, 0);
    // The producer is still rolled back exactly once, with a reason it can act
    // on. `dispatch_one` invokes this synchronously before returning.
    assert_eq!(
        settles.snapshot(),
        vec![DispatchSettle::Abandoned(AbandonReason::Backpressure)]
    );
    match listener.accept().now_or_never() {
        None => {}
        other => panic!("exhausted semaphore must not connect: {other:?}"),
    }
}

/// A generation that already stopped admitting rejects *before* `begin_task()`.
/// That path historically incremented nothing at all — no attempt, no
/// backpressure, no failure, no abandonment — so a reload that raced a breach
/// was completely invisible. It must now be visible under its own bounded
/// reason, without inventing a delivery-body start that never happened.
#[tokio::test]
async fn pre_task_generation_rejection_is_visible_without_inflating_attempted() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(4242, Arc::clone(&metrics));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let settles = SettleLog::new();

    // Retire the generation first: this is the reload/Drop boundary.
    generation.cancel();
    assert!(!generation.is_admitting());

    let admitted = dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        webhook_channel_to(format!("http://{addr}/notify")),
        // A wide-open semaphore, so the rejection provably comes from the
        // generation rather than from backpressure.
        Arc::new(Semaphore::new(16)),
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy::DEFAULT,
        "test",
        Some(settles.callback()),
    );

    assert!(!admitted, "a retired generation must not admit new work");
    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(
        snap.rejected_for(AbandonReason::GenerationClosed),
        1,
        "pre-task rejection must be counted"
    );
    assert_eq!(
        snap.attempted, 0,
        "no channel attempt ran, so `attempted` must not be inflated"
    );
    assert_eq!(snap.in_flight, 0);
    assert_eq!(snap.backpressure_dropped, 0);
    assert_eq!(
        snap.abandoned_at_deadline, 0,
        "reload rejection is not a shutdown-deadline abandonment"
    );
    assert_eq!(snap.total_abandoned(), 0);
    assert_eq!(
        settles.snapshot(),
        vec![DispatchSettle::Abandoned(AbandonReason::GenerationClosed)],
        "the producer callback must still run exactly once, with a precise reason"
    );
    // Non-vacuous: prove nothing was ever sent.
    match listener.accept().now_or_never() {
        None => {}
        other => panic!("a rejected dispatch must not reach the endpoint: {other:?}"),
    }
    assert_eq!(generation.in_flight(), 0);
    assert!(generation.wait_drain(Duration::from_secs(5)).await);
}

#[tokio::test]
async fn transient_retry_then_success() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(7, Arc::clone(&metrics));
    let (addr, count, notify, server) = spawn_status_sequence_server(vec![503, 200]).await;
    let sem = Arc::new(Semaphore::new(1));
    let channel = webhook_channel_to(format!("http://{addr}/notify"));
    let settles = SettleLog::new();

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        },
        "test",
        Some(settles.callback()),
    ));

    wait_for_count(&count, &notify, 2).await;
    server.await.unwrap();
    // The settle callback runs synchronously on the settling task, so awaiting
    // it is the authoritative completion barrier — no sleep, no detached task.
    assert_eq!(
        settles.wait_for_settles(1).await,
        vec![DispatchSettle::Succeeded]
    );
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "a settled dispatch must drain"
    );
    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(snap.attempted, 1);
    assert_eq!(snap.succeeded, 1);
    assert_eq!(snap.failed_transient, 0);
    assert_eq!(snap.in_flight, 0);
    assert_eq!(snap.total_abandoned(), 0);
    assert_eq!(snap.total_rejected(), 0);
}

#[tokio::test]
async fn permanent_failure_does_not_retry() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(8, Arc::clone(&metrics));
    let (addr, count, notify, server) = spawn_persistent_status_server(401).await;
    let sem = Arc::new(Semaphore::new(1));
    let channel = webhook_channel_to(format!("http://{addr}/notify"));

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        },
        "test",
        None,
    ));

    wait_for_count(&count, &notify, 1).await;
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "a settled permanent failure must drain"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "permanent 401 must not be retried"
    );
    server.abort();
    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(snap.attempted, 1);
    assert_eq!(snap.failed_permanent, 1);
    assert_eq!(snap.succeeded, 0);
}

#[tokio::test]
async fn proxy_alerts_failed_trigger_releases_cooldown_and_pending_state() {
    let (addr, count, notify, server) = spawn_status_sequence_server(vec![500]).await;
    let cfg = json!({
        "max_concurrent_dispatches": 2,
        "max_delivery_retries": 0,
        "channels": {
            "c": { "type": "webhook", "url": format!("http://{addr}/alert"), "body_template": "x" }
        },
        "rules": [
            { "name": "status", "type": "status_code_count",
              "status_codes": [500], "threshold_count": 1,
              "cooldown_seconds": 60, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
    let generation = plugin.dispatch_generation_for_test();
    let summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_name: Some("api".to_string()),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    plugin.log(&summary).await;

    // Non-vacuous ordering: first prove the endpoint really observed the send
    // (so the 500 classification is the thing under test, not a connect
    // failure), then use the generation drain as the settle barrier. `settle()`
    // runs the producer callback before `end_task()`, so a drained generation
    // means producer state is already committed — no sleep, no state polling.
    wait_for_count(&count, &notify, 1).await;
    assert!(
        generation.wait_drain(Duration::from_secs(10)).await,
        "the failed dispatch must settle and drain"
    );

    assert_eq!(
        plugin.recovery_state_for_test(0, "ferrum|p1", 0),
        Some(RuleState::Healthy),
        "a permanently failed trigger must roll back to Healthy, never Active"
    );
    assert!(
        plugin.try_acquire_cooldown_for_test(0, "ferrum|p1", 0, 60_000, monotonic_now_ms(), 0,),
        "failed trigger must release cooldown"
    );
    drop(server);
}

#[tokio::test]
async fn proxy_alerts_successful_trigger_commits_active_and_cooldown() {
    let (addr, count, notify, server) = spawn_status_sequence_server(vec![204]).await;
    let cfg = json!({
        "max_concurrent_dispatches": 2,
        "max_delivery_retries": 0,
        "channels": {
            "c": { "type": "webhook", "url": format!("http://{addr}/alert"), "body_template": "x" }
        },
        "rules": [
            { "name": "status", "type": "status_code_count",
              "status_codes": [500], "threshold_count": 1,
              "cooldown_seconds": 60, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
    let summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_name: Some("api".to_string()),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    let generation = plugin.dispatch_generation_for_test();
    plugin.log(&summary).await;
    wait_for_count(&count, &notify, 1).await;
    server.await.unwrap();
    assert!(
        generation.wait_drain(Duration::from_secs(10)).await,
        "the successful dispatch must settle and drain"
    );

    assert!(
        matches!(
            plugin.recovery_state_for_test(0, "ferrum|p1", 0),
            Some(RuleState::Active { .. })
        ),
        "successful trigger should commit Active"
    );
    assert!(
        !plugin.try_acquire_cooldown_for_test(0, "ferrum|p1", 0, 60_000, monotonic_now_ms(), 0,),
        "successful trigger must consume cooldown"
    );
}

/// An endpoint that answers `preface` statuses and then accepts one more
/// request which it never answers, deliberately stalling the dispatch future
/// inside `transport.dispatch`.
struct StalledEndpoint {
    addr: SocketAddr,
    /// Fires once the stalled request's headers have been read server-side —
    /// the barrier proving the dispatch future was actually polled and put
    /// bytes on the wire before the test cancels.
    stalled_request_started: oneshot::Receiver<()>,
    /// Fires when the stalled connection reaches EOF. An unanswered request
    /// can never be pooled or reused, so the only way this socket closes is
    /// the in-flight transport future being dropped: a deterministic drop
    /// witness that does not depend on any timeout.
    stalled_connection_closed: oneshot::Receiver<()>,
    requests: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

async fn spawn_stalled_endpoint(preface: Vec<u16>) -> StalledEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let (started_tx, stalled_request_started) = oneshot::channel();
    let (closed_tx, stalled_connection_closed) = oneshot::channel();

    let server = tokio::spawn(async move {
        for status in preface {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_requests.fetch_add(1, Ordering::SeqCst);
            let response =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_headers(&mut socket).await;
        server_requests.fetch_add(1, Ordering::SeqCst);
        let _ = started_tx.send(());
        // Never respond. Drain until the peer hangs up.
        let mut buf = [0u8; 256];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = closed_tx.send(());
        // Keep serving so a post-cancellation retry is observable as an extra
        // counted request rather than a silent connection refusal.
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request_headers(&mut socket).await;
            server_requests.fetch_add(1, Ordering::SeqCst);
        }
    });

    StalledEndpoint {
        addr,
        stalled_request_started,
        stalled_connection_closed,
        requests,
        server,
    }
}

/// Cancelling a generation must abandon an attempt that is stalled *inside*
/// the transport call, not merely one sitting between attempts. The endpoint
/// never responds, so before the fix the task stayed alive until the 60s
/// `PluginHttpClient` request timeout; every bound below is orders of
/// magnitude under that, so passing proves preemption rather than expiry.
#[tokio::test]
async fn reload_retirement_cancels_stalled_in_flight_dispatch_and_settles_abandoned_once() {
    let mut endpoint = spawn_stalled_endpoint(Vec::new()).await;
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(99, Arc::clone(&metrics));
    let sem = Arc::new(Semaphore::new(1));
    let addr = endpoint.addr;
    let channel = webhook_channel_to(format!("http://{addr}/slow"));
    let settles = SettleLog::new();
    let notification = Arc::new(fixed_notification());
    let extras: Arc<HashMap<String, String>> = Arc::new(HashMap::new());

    assert!(dispatch_one(
        Arc::clone(&notification),
        Arc::clone(&extras),
        channel,
        sem,
        PluginHttpClient::default(),
        Arc::clone(&generation),
        // A retry budget is configured on purpose: cancellation must also
        // suppress the retry this transient stall would otherwise earn.
        DeliveryRetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        },
        "test",
        Some(settles.callback()),
    ));

    timeout(
        Duration::from_secs(5),
        &mut endpoint.stalled_request_started,
    )
    .await
    .expect("server must observe the live transport attempt before retirement")
    .expect("stall barrier sender must not be dropped");
    assert_eq!(generation.in_flight(), 1, "the attempt must be accounted");
    assert_eq!(metrics.channel_snapshot("webhook").in_flight, 1);

    generation.cancel();
    assert!(!generation.is_admitting());
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "retirement must abandon a stalled attempt promptly, not wait out the transport timeout"
    );
    timeout(
        Duration::from_secs(5),
        &mut endpoint.stalled_connection_closed,
    )
    .await
    .expect("the cancelled dispatch future must be dropped, closing the stalled connection")
    .expect("close witness sender must not be dropped");

    let rejected = dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        webhook_channel_to(format!("http://{addr}/slow2")),
        Arc::new(Semaphore::new(8)),
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy::DEFAULT,
        "test",
        None,
    );
    assert!(!rejected, "retired generation must not admit new work");
    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        1,
        "a cancelled attempt must not be retried"
    );

    let snapshot = metrics.channel_snapshot("webhook");
    assert_eq!(snapshot.attempted, 1);
    assert_eq!(
        snapshot.abandoned_for(AbandonReason::GenerationRetired),
        1,
        "reload retirement must be reported as retirement"
    );
    assert_eq!(
        snapshot.abandoned_at_deadline, 0,
        "reload retirement is NOT a shutdown-deadline abandonment; charging it \
         to that counter is what made the metric operationally false"
    );
    // The intentional post-cancel `dispatch_one` above is a pre-task
    // GenerationClosed rejection; that bounded counter must record it exactly
    // once (it must not be conflated with the live attempt's retirement).
    assert_eq!(
        snapshot.rejected_for(AbandonReason::GenerationClosed),
        1,
        "post-retirement dispatch probe must witness GenerationClosed"
    );
    assert_eq!(
        snapshot.total_rejected(),
        1,
        "exactly one pre-task rejection from the post-cancel probe"
    );
    assert_eq!(snapshot.succeeded, 0);
    assert_eq!(snapshot.failed_transient, 0);
    assert_eq!(snapshot.failed_permanent, 0);
    assert_eq!(snapshot.in_flight, 0);
    // A double settle would `fetch_sub` this counter twice and wrap, so an
    // exact zero is itself the exactly-once witness for in-flight accounting.
    assert_eq!(generation.in_flight(), 0);
    assert_eq!(
        settles.snapshot(),
        vec![DispatchSettle::Abandoned(AbandonReason::GenerationRetired)],
        "retirement must roll producer state back exactly once"
    );
    // A drained generation means the dispatch future itself is gone, not just
    // that the transport returned: nothing still holds its captured payload.
    assert_eq!(Arc::strong_count(&notification), 1);
    assert_eq!(Arc::strong_count(&extras), 1);
    endpoint.server.abort();
}

/// The same preemption must hold for a *retried* attempt, so cancellation
/// cannot be escaped by a transient failure re-entering the transport.
#[tokio::test]
async fn retirement_cancels_stalled_retry_attempt_after_transient_failure() {
    let mut endpoint = spawn_stalled_endpoint(vec![503]).await;
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(101, Arc::clone(&metrics));
    let settles = SettleLog::new();
    let addr = endpoint.addr;

    assert!(dispatch_one(
        Arc::new(fixed_notification()),
        Arc::new(Default::default()),
        webhook_channel_to(format!("http://{addr}/retry-then-stall")),
        Arc::new(Semaphore::new(1)),
        PluginHttpClient::default(),
        Arc::clone(&generation),
        DeliveryRetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
        },
        "test",
        Some(settles.callback()),
    ));

    timeout(
        Duration::from_secs(5),
        &mut endpoint.stalled_request_started,
    )
    .await
    .expect("the retry attempt must reach the endpoint before retirement")
    .expect("stall barrier sender must not be dropped");
    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        2,
        "the transient 503 must have been retried before the stall"
    );

    generation.cancel();
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "retirement must abandon a stalled retry attempt promptly"
    );
    timeout(
        Duration::from_secs(5),
        &mut endpoint.stalled_connection_closed,
    )
    .await
    .expect("the cancelled retry future must be dropped, closing the stalled connection")
    .expect("close witness sender must not be dropped");

    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        2,
        "cancellation must not schedule a further retry"
    );
    let snapshot = metrics.channel_snapshot("webhook");
    assert_eq!(snapshot.attempted, 1, "retries share one admitted task");
    assert_eq!(snapshot.abandoned_for(AbandonReason::GenerationRetired), 1);
    assert_eq!(
        snapshot.abandoned_at_deadline, 0,
        "a retired retry is not a shutdown-deadline abandonment"
    );
    assert_eq!(snapshot.failed_transient, 0);
    assert_eq!(snapshot.succeeded, 0);
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(
        settles.snapshot(),
        vec![DispatchSettle::Abandoned(AbandonReason::GenerationRetired)],
        "a cancelled retry must settle exactly once"
    );
    endpoint.server.abort();
}

/// The cancel signal is edge-triggered, so an in-flight attempt observes
/// retirement on a task wakeup rather than a polling cadence. Registration
/// happens before the flag re-read, so a cancel racing the waiter is not lost.
#[tokio::test]
async fn generation_cancelled_future_resolves_without_polling_cadence() {
    let generation = DispatchGeneration::new(5);
    let waiter = Arc::clone(&generation);
    let observed = tokio::spawn(async move {
        waiter.cancelled().await;
        waiter.is_cancelled()
    });

    // Not cancelled: the future must stay pending.
    assert!(
        timeout(Duration::from_millis(50), generation.cancelled())
            .await
            .is_err(),
        "a live generation must never resolve its cancel future"
    );

    generation.cancel();
    assert!(
        timeout(Duration::from_secs(2), observed)
            .await
            .expect("cancel must wake a registered waiter")
            .expect("waiter task must not panic"),
        "a woken waiter must observe the published cancel flag"
    );
    // Already cancelled: resolves immediately on the first poll.
    timeout(Duration::from_millis(500), generation.cancelled())
        .await
        .expect("an already-cancelled generation must resolve immediately");
}

/// `attempted` advances at registry-owned body start, not at the first channel
/// transport poll. An admit-then-cancel race that parks the body before any
/// channel call must therefore still increment `attempted`, settle exactly once
/// as `Abandoned(GenerationRetired)`, and leave the endpoint untouched.
#[tokio::test]
async fn admit_then_cancel_before_transport_counts_attempted_under_body_start_contract() {
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(77, Arc::clone(&metrics));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let settles = SettleLog::new();

    let body_entered = Arc::new(Notify::new());
    let body_entered_flag = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let body_entered_signal = Arc::clone(&body_entered);
    let body_entered_flag_set = Arc::clone(&body_entered_flag);
    let cancel_watch = Arc::clone(&generation);

    assert!(
        generation.spawn("webhook", Some(settles.callback()), async move {
            // Reaching this future proves the pre-future cancel check passed
            // after `mark_attempt_started`, so `attempted` already advanced
            // with no channel call yet.
            body_entered_flag_set.store(1, Ordering::Release);
            body_entered_signal.notify_waiters();
            let _ = release_rx.await;
            assert!(
                cancel_watch.is_cancelled(),
                "fixture must observe retirement before any channel call"
            );
            DispatchSettle::Abandoned(AbandonReason::GenerationRetired)
        }),
        "open generation must admit the body"
    );

    wait_until(
        &body_entered,
        || body_entered_flag.load(Ordering::Acquire) == 1,
        "delivery body future entered after attempt mark",
    )
    .await;

    let mid = metrics.channel_snapshot("webhook");
    assert_eq!(mid.attempted, 1, "body start reserves attempted");
    assert_eq!(mid.in_flight, 1, "body start reserves in_flight");
    assert_eq!(mid.total_abandoned(), 0);
    assert_eq!(mid.total_rejected(), 0);
    match listener.accept().now_or_never() {
        None => {}
        other => panic!("body must not reach the endpoint before release: {other:?}"),
    }

    generation.cancel();
    release_tx
        .send(())
        .expect("parked body must still own the release oneshot");

    assert_eq!(
        settles.wait_for_settles(1).await,
        vec![DispatchSettle::Abandoned(AbandonReason::GenerationRetired)]
    );
    assert!(generation.wait_drain(Duration::from_secs(5)).await);

    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(
        snap.attempted, 1,
        "admit-then-cancel/no-transport still counts under the body-start contract"
    );
    assert_eq!(snap.abandoned_for(AbandonReason::GenerationRetired), 1);
    assert_eq!(snap.abandoned_at_deadline, 0);
    assert_eq!(snap.abandoned_for(AbandonReason::ShutdownDeadline), 0);
    assert_eq!(snap.abandoned_for(AbandonReason::TaskDropped), 0);
    assert_eq!(snap.total_rejected(), 0);
    assert_eq!(snap.succeeded, 0);
    assert_eq!(snap.failed_transient, 0);
    assert_eq!(snap.failed_permanent, 0);
    assert_eq!(snap.in_flight, 0);
    assert_eq!(generation.in_flight(), 0);
    match listener.accept().now_or_never() {
        None => {}
        other => panic!("cancelled body must never open a channel connection: {other:?}"),
    }
}

/// A hard process-shutdown deadline must abort an admitted notification and
/// compose exactly: one `Abandoned(ShutdownDeadline)` callback, one
/// `abandoned_total{reason="shutdown_deadline"}`, one `abandoned_at_deadline`,
/// zero success/transient/permanent outcomes, and zero leaked generation /
/// metric in-flight. Reload retirement stays disjoint, and classification must
/// read the exact admitted lifecycle even if a replacement generation is
/// installed mid-drain.
///
/// The delivery body is a deterministic never-completing future admitted
/// through the owned-slot test seam: ordinary channel/transport completion
/// cannot race `FailedTransient` (or any other settle) ahead of the hard
/// abort. One-shot barriers prove body entry after attempt start, shutdown
/// admission closure after the deadline is fixed, and pending-body drop on hard
/// abort — no polling loops or scheduler luck.
///
/// Ordering is driven with Tokio paused virtual time so replacement-before-abort
/// is causal: A begins shutdown under a long virtual budget, B is installed and
/// proven admitting while A has not hard-aborted, and only then is virtual time
/// advanced past A's deadline. A real-time 1 ms race cannot pass this test if
/// drop classification incorrectly samples B.
#[tokio::test(start_paused = true)]
async fn hard_shutdown_deadline_aborts_admitted_notification_exactly_once() {
    let slot = Arc::new(DeliverySlot::new(0));
    let lifecycle_a_generation = slot.begin_cycle();
    let metrics = Arc::new(DeliveryMetrics::new());
    let generation = DispatchGeneration::with_metrics(88, Arc::clone(&metrics));
    let settles = SettleLog::new();

    let (body_entered_tx, body_entered_rx) = oneshot::channel::<()>();
    let (pending_body_dropped_tx, dropped_rx) = oneshot::channel::<()>();

    assert!(
        generation.spawn_pending_with_delivery_slot_for_test(
            "webhook",
            Some(settles.callback()),
            &slot,
            body_entered_tx,
            pending_body_dropped_tx,
        ),
        "open owned-slot lifecycle must admit the pending body"
    );

    // Causal: the admitted body must be live-and-pending before drain starts.
    timeout(Duration::from_secs(1), body_entered_rx)
        .await
        .expect("timed out waiting for admitted delivery body entry")
        .expect("admitted delivery body must signal entry after attempt start");
    assert_eq!(generation.in_flight(), 1);
    assert_eq!(metrics.channel_snapshot("webhook").in_flight, 1);
    assert!(
        !generation.is_cancelled(),
        "reload retirement must stay disjoint"
    );

    // Comfortably long virtual budget: hard abort cannot fire until the test
    // advances paused time past this deadline.
    let drain_budget = Duration::from_secs(5);
    let drain_slot = Arc::clone(&slot);
    let (admission_closed_tx, admission_closed_rx) = oneshot::channel::<()>();
    let drain = tokio::spawn(async move {
        drain_slot
            .shutdown_with_admission_closed_for_test(drain_budget, admission_closed_tx)
            .await
    });
    timeout(Duration::from_secs(1), admission_closed_rx)
        .await
        .expect("timed out waiting for A shutdown admission closure")
        .expect("A shutdown must signal after fixing its drain deadline");
    assert!(
        !slot.spawn_terminal(async {}),
        "draining A must reject new external work before B replaces it"
    );

    // A is admission-closed but must still be draining — not hard-aborting —
    // because virtual time has not crossed the budget.
    assert_eq!(
        settles.len(),
        0,
        "A must not settle ShutdownDeadline before the virtual deadline advances"
    );
    assert_eq!(
        generation.in_flight(),
        1,
        "pending A delivery must still be in flight before the virtual deadline"
    );
    assert_eq!(
        metrics
            .channel_snapshot("webhook")
            .abandoned_for(AbandonReason::ShutdownDeadline),
        0,
        "no shutdown-deadline abandonment before virtual time advances"
    );

    let lifecycle_b_generation = slot.begin_cycle();
    assert_ne!(
        lifecycle_b_generation, lifecycle_a_generation,
        "mid-drain begin_cycle must install a fresh non-cancelling lifecycle"
    );
    assert!(
        slot.spawn_terminal(async {}),
        "replacement lifecycle B must admit work while A is still not hard-aborting"
    );
    assert_eq!(
        settles.len(),
        0,
        "installing B must precede A's hard abort; no settle may land yet"
    );
    assert_eq!(
        generation.in_flight(),
        1,
        "A's pending delivery must still be alive after B opens"
    );

    // Only now advance past A's drain budget so cancel_remaining runs on A
    // while B is the slot's current non-cancelling lifecycle.
    tokio::time::advance(drain_budget + Duration::from_millis(1)).await;

    assert_eq!(
        settles.wait_for_settles(1).await,
        vec![DispatchSettle::Abandoned(AbandonReason::ShutdownDeadline)],
        "hard abort must settle ShutdownDeadline, not TaskDropped/GenerationRetired"
    );
    assert!(
        generation.wait_drain(Duration::from_secs(5)).await,
        "generation task accounting must clear after the hard abort"
    );
    assert!(
        !generation.is_cancelled(),
        "shutdown-deadline abort must not retire the producer generation"
    );

    let report = drain.await.expect("drain task must join");
    assert!(
        !report.complete(),
        "pending send must force the shutdown budget to expire"
    );

    timeout(Duration::from_secs(1), dropped_rx)
        .await
        .expect("timed out waiting for the hard abort to drop the pending body")
        .expect("hard abort must drop the in-flight pending delivery future");

    let snap = metrics.channel_snapshot("webhook");
    assert_eq!(snap.attempted, 1);
    assert_eq!(snap.abandoned_for(AbandonReason::ShutdownDeadline), 1);
    assert_eq!(snap.abandoned_at_deadline, 1);
    assert_eq!(snap.abandoned_for(AbandonReason::GenerationRetired), 0);
    assert_eq!(snap.abandoned_for(AbandonReason::TaskDropped), 0);
    assert_eq!(snap.total_rejected(), 0);
    assert_eq!(snap.succeeded, 0);
    assert_eq!(snap.failed_transient, 0);
    assert_eq!(snap.failed_permanent, 0);
    assert_eq!(snap.in_flight, 0);
    assert_eq!(generation.in_flight(), 0);
    assert_eq!(settles.snapshot().len(), 1, "exactly-once settle callback");
}

/// Dropping the plugin — the reload boundary — must retire the *old*
/// generation's live transport, not merely stop admitting new work.
///
/// The endpoint accepts the connection and then never answers, so before the
/// cancellation path existed the task would have stayed alive until the 60s
/// `PluginHttpClient` request timeout and the plugin's pending incident state
/// would have stayed reserved for just as long. Every bound here is orders of
/// magnitude under that, so passing proves preemption rather than expiry.
///
/// This is deliberately driven through the real plugin `log()` hook rather than
/// `dispatch_one`, so the whole producer chain (window → recovery gate →
/// cooldown reservation → fan-out settle) is exercised across the drop.
#[tokio::test]
async fn proxy_alerts_drop_retires_stalled_dispatch_and_settles_producer_state_once() {
    let mut endpoint = spawn_stalled_endpoint(Vec::new()).await;
    let addr = endpoint.addr;
    let cfg = json!({
        "max_concurrent_dispatches": 2,
        // A retry budget on purpose: retirement must also suppress the retry
        // this stall would otherwise earn.
        "max_delivery_retries": 3,
        "delivery_retry_base_ms": 10,
        "delivery_retry_max_ms": 20,
        "channels": {
            "c": { "type": "webhook", "url": format!("http://{addr}/alert"), "body_template": "x" }
        },
        "rules": [
            { "name": "status", "type": "status_code_count",
              "status_codes": [500], "threshold_count": 1,
              "cooldown_seconds": 60, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
    // Held across the drop: after the plugin is gone these are the only
    // handles that can witness retirement and producer settlement.
    let generation = plugin.dispatch_generation_for_test();
    let recovery = plugin.recovery_gate_for_test();

    plugin
        .log(&TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        })
        .await;

    // Prove the fixture actually reached the intended blocked state before
    // asserting anything about cancellation: the server has read the request
    // headers, so bytes are on the wire and the transport future is parked
    // inside the call, not merely queued.
    timeout(
        Duration::from_secs(10),
        &mut endpoint.stalled_request_started,
    )
    .await
    .expect("the endpoint must observe the live send before the plugin is dropped")
    .expect("stall barrier sender must not be dropped");
    assert_eq!(
        generation.in_flight(),
        1,
        "the stalled send must be accounted in flight"
    );
    assert!(
        matches!(
            recovery.current_state(0, "ferrum|p1", 0),
            Some(RuleState::PendingTrigger { .. })
        ),
        "the incident must be holding a pending delivery seat while stalled"
    );

    // The reload boundary.
    drop(plugin);

    assert!(
        generation.is_cancelled(),
        "Drop must retire the dispatch generation"
    );
    assert!(
        !generation.is_admitting(),
        "a retired generation must not admit new work"
    );
    assert!(
        generation.wait_drain(Duration::from_secs(10)).await,
        "retirement must abandon the stalled send promptly, not wait out the transport timeout"
    );
    // An unanswered request can never be pooled or reused, so EOF on this
    // socket is a deterministic witness that the old generation's transport
    // future was really dropped — it does not depend on any timeout.
    timeout(
        Duration::from_secs(10),
        &mut endpoint.stalled_connection_closed,
    )
    .await
    .expect("the retired dispatch future must be dropped, closing the stalled connection")
    .expect("close witness sender must not be dropped");

    assert_eq!(
        endpoint.requests.load(Ordering::SeqCst),
        1,
        "a retired attempt must not be retried"
    );
    assert_eq!(
        recovery.current_state(0, "ferrum|p1", 0),
        Some(RuleState::Healthy),
        "abandonment must roll the pending trigger back so a later generation can re-alert"
    );
    // `end_task` decrements this once per settle, so a double settle would wrap
    // it: an exact zero is the exactly-once witness.
    assert_eq!(generation.in_flight(), 0);
    endpoint.server.abort();
}

// ---------------------------------------------------------------------------
// Resolve / re-breach race and the compensating Trigger (#2448)
//
// These drive `RecoveryGate` directly with an injected monotonic clock, which
// is exactly the surface `proxy_alerts::process_observation` and
// `PendingDeliveryFanout::on_channel_settle` use. There is no timing luck: the
// "Resolve is externally in flight" window is the interval between admitting
// the Resolve (`observe` → `PendingResolve`) and its settle, and the test owns
// both ends of it.
// ---------------------------------------------------------------------------

const RACE_RULE: u32 = 7;
const RACE_PROXY: &str = "ferrum|p1";
const RACE_GEN: u64 = 0;
const RECOVERY_MS: u64 = 5_000;

/// Drive a gate to the exact instant a Resolve has been admitted for dispatch
/// but has not settled, then re-breach. Returns the gate and the Resolve's
/// reservation token.
fn gate_with_resolve_in_flight_then_rebreach() -> (RecoveryGate, u64) {
    let gate = RecoveryGate::new();

    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 1_000, RACE_GEN),
        LifecycleOutcome::Trigger
    );
    gate.settle_trigger_success(RACE_RULE, RACE_PROXY, RACE_GEN, 1_000, 1_000);
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Active { .. })
    ));

    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 2_000, RACE_GEN),
        LifecycleOutcome::EnteringRecovery
    );
    // Resolved window elapsed: the Resolve is admitted and now externally in
    // flight. This is the reservation the producer hands to the fan-out.
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 8_000, RACE_GEN),
        LifecycleOutcome::Resolve
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingResolve {
            left_threshold_at_ms: 2_000,
            reserved_at_ms: 8_000,
        }),
        "the fixture must actually hold an in-flight Resolve seat before racing it"
    );

    // The race: observations breach again while that Resolve is on the wire.
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 9_000, RACE_GEN),
        LifecycleOutcome::Reactivate,
        "a re-breach during an in-flight Resolve must not itself emit a notification"
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::ResolveInFlightRebreached {
            resolve_reserved_at_ms: 8_000,
            rebreached_at_ms: 9_000,
        }),
        "the re-breach must be retained against the outstanding Resolve token"
    );

    (gate, 8_000)
}

/// A Resolve that succeeded at the endpoint told the operator the incident is
/// over. If observations breached again while it was in flight, the incident is
/// genuinely alerting and must get a compensating Trigger — the old
/// `PendingResolve + breach -> Active` shortcut suppressed it forever, because
/// `Active` never re-enters the `Trigger` transition.
#[test]
fn successful_resolve_racing_a_rebreach_schedules_a_compensating_trigger() {
    let (gate, resolve_token) = gate_with_resolve_in_flight_then_rebreach();

    // While the Resolve is still outstanding, further breaching samples stay
    // quiet: a Trigger emitted now could overtake the Resolve on the wire and
    // leave "resolved" as the operator's last view.
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 9_500, RACE_GEN),
        LifecycleOutcome::Quiet
    );
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::ResolveInFlightRebreached { .. })
    ));

    // The Resolve lands successfully. It is now known-stale.
    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, resolve_token);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::CompensatingTrigger {
            rebreached_at_ms: 9_000
        }),
        "a delivered-but-stale Resolve must leave the incident owing a Trigger"
    );

    // The next breaching sample re-alerts.
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 10_000, RACE_GEN),
        LifecycleOutcome::Trigger,
        "the compensating Trigger must actually be emitted"
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingTrigger {
            reserved_at_ms: 10_000
        })
    );
    gate.settle_trigger_success(RACE_RULE, RACE_PROXY, RACE_GEN, 10_000, 10_000);
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Active { .. })
    ));
}

/// A failed or abandoned Resolve is *not* proof the endpoint did not act on it:
/// transport timeouts, post-write connection errors, and cancellation after
/// bytes left the process all report failure while the peer may have processed
/// the send. The uncertain boundary therefore converges the same way, so the
/// worst case is one extra Trigger rather than a silently suppressed alert.
#[test]
fn failed_or_abandoned_resolve_racing_a_rebreach_also_compensates() {
    let (gate, resolve_token) = gate_with_resolve_in_flight_then_rebreach();

    gate.settle_resolve_failure(RACE_RULE, RACE_PROXY, RACE_GEN, 2_000, resolve_token);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::CompensatingTrigger {
            rebreached_at_ms: 9_000
        }),
        "an uncertain Resolve delivery must not silently return to Recovering \
         while the incident is breached"
    );
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 10_000, RACE_GEN),
        LifecycleOutcome::Trigger
    );
}

/// If the rule is no longer breaching by the time the compensating decision is
/// due, the possibly-delivered Resolve already matches reality: no phantom
/// alert, and the row becomes evictable again.
#[test]
fn compensating_trigger_is_dropped_when_the_rule_recovered_again() {
    let (gate, resolve_token) = gate_with_resolve_in_flight_then_rebreach();
    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, resolve_token);
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::CompensatingTrigger { .. })
    ));

    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 11_000, RACE_GEN),
        LifecycleOutcome::Quiet,
        "a recovered rule must not emit a phantom compensating Trigger"
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Healthy)
    );
    gate.evict_resolved();
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        None,
        "the terminal Healthy row must become evictable"
    );
}

/// Both new states are non-terminal incidents, so background eviction must
/// retain them: sweeping either one would drop a breached incident's
/// compensating obligation on the floor.
#[test]
fn eviction_retains_in_flight_rebreach_and_compensating_states() {
    let (gate, resolve_token) = gate_with_resolve_in_flight_then_rebreach();
    gate.evict_resolved();
    assert!(
        matches!(
            gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
            Some(RuleState::ResolveInFlightRebreached { .. })
        ),
        "an outstanding Resolve race must survive the eviction sweep"
    );

    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, resolve_token);
    gate.evict_resolved();
    assert!(
        matches!(
            gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
            Some(RuleState::CompensatingTrigger { .. })
        ),
        "an owed compensating Trigger must survive the eviction sweep"
    );
}

/// Stale-token isolation must hold across the new states too: a settle carrying
/// a superseded reservation must never commit or clear the current row.
#[test]
fn stale_resolve_settle_cannot_clear_a_rebreached_incident() {
    let (gate, resolve_token) = gate_with_resolve_in_flight_then_rebreach();

    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, resolve_token + 1);
    gate.settle_resolve_failure(RACE_RULE, RACE_PROXY, RACE_GEN, 2_000, resolve_token + 1);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::ResolveInFlightRebreached {
            resolve_reserved_at_ms: 8_000,
            rebreached_at_ms: 9_000,
        }),
        "a stale-token settle must not resolve or compensate the live incident"
    );

    // A settle for a different ownership generation is likewise isolated.
    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN + 1, resolve_token);
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::ResolveInFlightRebreached { .. })
    ));

    // The matching token still works, proving the assertions above were not
    // vacuously passing on an unreachable row.
    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, resolve_token);
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::CompensatingTrigger { .. })
    ));
}

/// The ordinary (unraced) Resolve paths must be unchanged by the compensating
/// machinery.
#[test]
fn unraced_resolve_settles_keep_their_original_semantics() {
    let gate = RecoveryGate::new();
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 1_000, RACE_GEN),
        LifecycleOutcome::Trigger
    );
    gate.settle_trigger_success(RACE_RULE, RACE_PROXY, RACE_GEN, 1_000, 1_000);
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 2_000, RACE_GEN),
        LifecycleOutcome::EnteringRecovery
    );
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 8_000, RACE_GEN),
        LifecycleOutcome::Resolve
    );

    // Failure rolls back to Recovering so the next healthy sample retries.
    gate.settle_resolve_failure(RACE_RULE, RACE_PROXY, RACE_GEN, 2_000, 8_000);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Recovering {
            left_threshold_at_ms: 2_000
        })
    );
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 9_000, RACE_GEN),
        LifecycleOutcome::Resolve
    );

    // Success commits Healthy.
    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, 9_000);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Healthy)
    );
}

/// Non-event evaluate → observe can race a concurrent resolve settle into an
/// unadmitted `PendingTrigger`. Without rollback that seat is orphaned: the
/// outer path reserved no dispatch, so nothing can ever settle it.
///
/// Interleaving owned entirely by the test (no sleeps):
/// 1. `PendingResolve` + breach: `evaluate` returns `Reactivate` (non-event).
/// 2. Concurrent resolve success settles the old reservation to `Healthy`.
/// 3. Non-event commit `observe(breach)` returns `Trigger` / installs
///    `PendingTrigger`.
/// 4. `rollback_unadmitted_reservation` clears that exact seat.
/// 5. A later legitimate `observe(breach)` can admit a fresh `Trigger`.
#[test]
fn non_event_commit_racing_resolve_settle_does_not_orphan_pending_trigger() {
    let gate = RecoveryGate::new();

    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 1_000, RACE_GEN),
        LifecycleOutcome::Trigger
    );
    gate.settle_trigger_success(RACE_RULE, RACE_PROXY, RACE_GEN, 1_000, 1_000);
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 2_000, RACE_GEN),
        LifecycleOutcome::EnteringRecovery
    );
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, false, RECOVERY_MS, 8_000, RACE_GEN),
        LifecycleOutcome::Resolve
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingResolve {
            left_threshold_at_ms: 2_000,
            reserved_at_ms: 8_000,
        })
    );

    // Phase 1: non-event snapshot — Reactivate, state not yet committed.
    assert_eq!(
        gate.evaluate(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 9_000, RACE_GEN),
        LifecycleOutcome::Reactivate
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingResolve {
            left_threshold_at_ms: 2_000,
            reserved_at_ms: 8_000,
        }),
        "evaluate must not commit; the Resolve seat is still outstanding"
    );

    // Phase 2: the in-flight Resolve settles successfully before the non-event
    // commit runs — the exact race `process_observation` can hit.
    gate.settle_resolve_success(RACE_RULE, RACE_PROXY, RACE_GEN, 8_000);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Healthy)
    );

    // Phase 3: non-event observe commits against Healthy + breach → Trigger.
    let committed = gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 9_000, RACE_GEN);
    assert_eq!(
        committed,
        LifecycleOutcome::Trigger,
        "the raced commit must actually reserve a Trigger seat"
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingTrigger {
            reserved_at_ms: 9_000
        })
    );

    // Phase 4: roll back the unadmitted reservation (non-event path has no
    // dispatch permits/callbacks to settle it).
    gate.rollback_unadmitted_reservation(RACE_RULE, RACE_PROXY, RACE_GEN, committed, 9_000);
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Healthy),
        "the raced PendingTrigger must not remain orphaned"
    );

    // Non-reserving outcomes must be harmless no-ops (same helper, adjacent
    // non-event class).
    gate.rollback_unadmitted_reservation(
        RACE_RULE,
        RACE_PROXY,
        RACE_GEN,
        LifecycleOutcome::Reactivate,
        9_000,
    );
    gate.rollback_unadmitted_reservation(
        RACE_RULE,
        RACE_PROXY,
        RACE_GEN,
        LifecycleOutcome::StillActive,
        9_000,
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Healthy)
    );

    // Phase 5: a subsequent legitimate breach can still reserve a Trigger.
    assert_eq!(
        gate.observe(RACE_RULE, RACE_PROXY, true, RECOVERY_MS, 10_000, RACE_GEN),
        LifecycleOutcome::Trigger,
        "after rollback the gate must admit a fresh Trigger"
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingTrigger {
            reserved_at_ms: 10_000
        })
    );

    // A stale unadmitted-rollback token must not clear the newer seat.
    gate.rollback_unadmitted_reservation(
        RACE_RULE,
        RACE_PROXY,
        RACE_GEN,
        LifecycleOutcome::Trigger,
        9_000,
    );
    assert_eq!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::PendingTrigger {
            reserved_at_ms: 10_000
        }),
        "token mismatch must leave the newer PendingTrigger intact"
    );

    gate.settle_trigger_success(RACE_RULE, RACE_PROXY, RACE_GEN, 10_000, 10_000);
    assert!(matches!(
        gate.current_state(RACE_RULE, RACE_PROXY, RACE_GEN),
        Some(RuleState::Active { .. })
    ));
}
