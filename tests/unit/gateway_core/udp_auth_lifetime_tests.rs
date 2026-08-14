//! Authorization lifetime of an admitted PLAIN-UDP session (issue #3816).
//!
//! `admit_plain_udp_stream` runs the full `on_stream_connect` chain, so a
//! plain-UDP session can carry an identified consumer, an authenticated
//! identity, and a `credential_deadline_at` exactly like the DTLS-terminating
//! frontend does — but `on_stream_connect` runs ONCE, at admission, and is
//! never repeated. Without this contract a plain-UDP session outlived the
//! credential that admitted it indefinitely, and any custom or future
//! stream-auth plugin could create an indefinitely authorized session.
//!
//! These drive the production seams — the anchored plan, the bounded
//! post-admission setup stages, the pre-commit re-check, the client→backend
//! datagram gate, the hook-ingress gate, the backend reply direction's
//! deadline arm, and the exactly-once teardown — through
//! `UdpAuthorizationSessionProbe`, which builds a REAL `UdpSession` with a real
//! connected backend socket, a real overload connection guard, and a real
//! bounded hook-ingress channel.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_edge::_test_support::{
    UdpAuthorizationSessionProbe, UdpFrontendSendOutcomeForTest, UdpReplyRecvOutcomeForTest,
    dtls_c2b_until_expiry_for_test, udp_authorization_disconnect_classification_for_test,
    udp_authorization_expired_before_commit_for_test, udp_frontend_send_until_expiry_for_test,
    udp_frontend_writable_until_expiry_for_test, udp_setup_stage_under_authorization_for_test,
};
use ferrum_edge::plugins::{Direction, DisconnectCause};
use ferrum_edge::proxy::auth_lifetime::{
    STREAM_AUTH_TERMINATION_METADATA_KEY, StreamAuthDeadline, StreamAuthProtocolFamily,
    StreamAuthTermination, StreamAuthTerminationLatch, counters, effective_stream_auth_deadline,
};
use ferrum_edge::proxy::stream_error::StreamSetupKind;
use ferrum_edge::retry::ErrorClass;

/// A plan that has ALREADY elapsed, so no scheduling can change the verdict.
///
/// `checked_sub` rather than `-`: `tokio::time::Instant` is monotonic-clock
/// based, so a process started very close to boot could underflow. Falling back
/// to "now" is still an elapsed plan, because every check reads the clock again
/// and settles on `>=`.
fn elapsed_plan(termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(tokio::time::Instant::now),
        termination,
    }
}

fn future_plan(after: Duration, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now() + after,
        termination,
    }
}

/// The process-wide `stream_udp` counter pair.
///
/// The unit-test binary runs in parallel and other suites (the DTLS
/// authorization coverage) share this family, so these tests assert the counter
/// MOVED rather than pinning an exact global delta. "Exactly once" is asserted
/// deterministically against the session's own shared
/// [`StreamAuthTerminationLatch`], which is the mechanism that gates the counter
/// increment in the first place.
fn stream_udp_terminations() -> (u64, u64) {
    let snapshot = counters();
    (
        snapshot.credential_expired["stream_udp"],
        snapshot.authenticated_stream_max_lifetime["stream_udp"],
    )
}

async fn probe(
    plan: Option<StreamAuthDeadline>,
    latch: StreamAuthTerminationLatch,
    with_hooks: bool,
) -> UdpAuthorizationSessionProbe {
    UdpAuthorizationSessionProbe::new(plan, latch, with_hooks)
        .await
        .expect("probe session binds loopback UDP sockets")
}

// ── The plan itself ─────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_plain_udp_session_carries_no_authorization_bound() {
    // No principal was admitted, so there is nothing to bound. This is the
    // overwhelmingly common plain-UDP posture (DNS, syslog, QUIC passthrough),
    // and it must keep its exact previous behavior.
    assert_eq!(
        effective_stream_auth_deadline(
            false,
            Some(tokio::time::Instant::now() + Duration::from_secs(5)),
            tokio::time::Instant::now(),
            3_600,
        ),
        None,
        "an unauthenticated UDP session must not be given an authorization plan"
    );

    let latch = StreamAuthTerminationLatch::default();
    let session = probe(None, latch.clone(), false).await;

    session.forward(b"unauthenticated").await.expect(
        "an unauthenticated session forwards exactly as it did before the contract existed",
    );
    assert_eq!(
        session.backend_recv().await.expect("backend datagram"),
        b"unauthenticated".to_vec()
    );
    // Time far past any plausible maximum: still unbounded, because there is
    // no plan at all.
    tokio::time::advance(Duration::from_secs(86_400 * 2)).await;
    session
        .forward(b"still-unauthenticated")
        .await
        .expect("an unauthenticated session is never terminated by this contract");
    assert_eq!(
        session.backend_recv().await.expect("backend datagram"),
        b"still-unauthenticated".to_vec()
    );

    assert_eq!(session.observed_termination(), None);
    assert!(!session.reply_task_stop_requested());
    assert!(
        !session
            .metadata()
            .contains_key(STREAM_AUTH_TERMINATION_METADATA_KEY)
    );
    assert!(
        latch.observed().is_none(),
        "an unauthenticated session settles no termination, so it moves no stream_udp counter"
    );
}

#[tokio::test(start_paused = true)]
async fn the_effective_bound_is_the_earliest_of_credential_and_finite_maximum() {
    let anchor = tokio::time::Instant::now();

    // A short-TTL credential wins over the maximum.
    let credential =
        effective_stream_auth_deadline(true, Some(anchor + Duration::from_secs(30)), anchor, 3_600)
            .expect("an authenticated session is bounded");
    assert_eq!(
        credential.termination,
        StreamAuthTermination::CredentialExpired
    );
    assert_eq!(credential.at, anchor + Duration::from_secs(30));

    // A credential with no authoritative expiry still gets a finite bound.
    let fallback = effective_stream_auth_deadline(true, None, anchor, 120)
        .expect("a credential with no expiry is bounded by the finite maximum");
    assert_eq!(
        fallback.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(fallback.at, anchor + Duration::from_secs(120));

    // A credential that outlives the maximum is capped by the maximum.
    let capped = effective_stream_auth_deadline(
        true,
        Some(anchor + Duration::from_secs(9_000)),
        anchor,
        120,
    )
    .expect("an authenticated session is bounded");
    assert_eq!(
        capped.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(capped.at, anchor + Duration::from_secs(120));
}

#[tokio::test(start_paused = true)]
async fn the_maximum_is_anchored_at_admission_not_after_the_plugin_chain() {
    // `process_new_session_datagram` captures the anchor BEFORE the epoch
    // resolve, the mesh egress decision, and `on_stream_connect`. A
    // deliberately slow admission plugin must therefore not buy the session
    // extra authorized lifetime.
    let anchor = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(90)).await;

    let plan = effective_stream_auth_deadline(true, None, anchor, 120)
        .expect("an authenticated session is bounded");
    assert_eq!(
        plan.at,
        anchor + Duration::from_secs(120),
        "the maximum must be measured from admission, not from when the chain finished"
    );
    assert!(
        plan.at < tokio::time::Instant::now() + Duration::from_secs(120),
        "a 90s admission chain must consume the session's own lifetime, not extend it"
    );
}

// ── Post-admission setup stages ─────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_already_expired_admission_never_polls_a_setup_stage() {
    // First-datagram policy hooks, DNS resolution, and the backend connect are
    // all `stream_udp_setup_stage_under_authorization` stages. An
    // already-elapsed plan must run NONE of them: no hook side effect, no name
    // resolved, no backend dialled.
    let entered = Arc::new(AtomicBool::new(false));
    let stage_entered = Arc::clone(&entered);
    let failure = udp_setup_stage_under_authorization_for_test(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        || async move {
            stage_entered.store(true, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("an elapsed plan refuses the stage");

    assert!(
        !entered.load(Ordering::SeqCst),
        "the stage future must be dropped unpolled"
    );
    assert_eq!(
        failure.setup_kind,
        Some(StreamSetupKind::AuthorizationExpired)
    );
    assert_eq!(failure.error_class, ErrorClass::RequestError);
    assert_eq!(failure.disconnect_cause, DisconnectCause::RecvError);
    assert_eq!(failure.disconnect_direction, Direction::ClientToBackend);
    assert_eq!(
        failure.probe_releases, 1,
        "a claimed HALF_OPEN probe slot is released NEUTRALLY exactly once"
    );
    assert_eq!(
        failure
            .metadata
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("credential_expired")
    );
}

#[tokio::test(start_paused = true)]
async fn an_expiry_during_setup_drops_the_running_stage() {
    // A stage that started before the deadline is CANCELLED at it, so a
    // half-finished DNS lookup or backend connect is abandoned rather than
    // completed for a credential that is no longer authorizing.
    let completed = Arc::new(AtomicBool::new(false));
    let stage_completed = Arc::clone(&completed);
    let failure = udp_setup_stage_under_authorization_for_test(
        Some(future_plan(
            Duration::from_millis(50),
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        || async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            stage_completed.store(true, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("a stage that outruns the deadline is cancelled");

    assert!(
        !completed.load(Ordering::SeqCst),
        "the cancelled stage must not run its completion side effect"
    );
    assert_eq!(
        failure
            .metadata
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("authenticated_stream_max_lifetime")
    );
    assert_eq!(failure.probe_releases, 1);
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_setup_stage_runs_unbounded() {
    let completed = udp_setup_stage_under_authorization_for_test(None, || async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        "done"
    })
    .await
    .expect("an unauthenticated session registers no timer at all");
    assert_eq!(completed, "done");
}

#[tokio::test(start_paused = true)]
async fn the_pre_commit_recheck_refuses_a_session_that_expired_during_synchronous_setup() {
    // The synchronous work between two await points is invisible to the
    // deadline arms, so the plan is re-read immediately before the session is
    // inserted, counted as a backend success, or handed its first send.
    let plan = future_plan(
        Duration::from_secs(10),
        StreamAuthTermination::CredentialExpired,
    );
    assert_eq!(
        udp_authorization_expired_before_commit_for_test(Some(plan), tokio::time::Instant::now()),
        None,
        "a live plan commits"
    );
    assert_eq!(
        udp_authorization_expired_before_commit_for_test(Some(plan), plan.at),
        Some(StreamAuthTermination::CredentialExpired),
        "exact-deadline equality settles as expiry"
    );
    assert_eq!(
        udp_authorization_expired_before_commit_for_test(None, tokio::time::Instant::now()),
        None,
        "an unauthenticated session is always committable"
    );
}

// ── Client → backend direction ──────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_elapsed_deadline_refuses_the_next_client_datagram_immediately() {
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    let error = session
        .forward(b"post-expiry")
        .await
        .expect_err("an expired credential forwards no datagram");

    // Refused inline, not by a timer task that has yet to be scheduled.
    assert!(
        session.backend_received().is_none(),
        "no datagram may reach the backend after expiry"
    );
    assert_eq!(session.bytes_sent(), 0);
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        session.reply_task_stop_requested(),
        "the first observer wakes the reply task so teardown does not wait for a backend datagram"
    );
    assert_eq!(
        session
            .metadata()
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("credential_expired")
    );
    let after = stream_udp_terminations();
    assert!(
        after.0 > before.0,
        "the fixed-cardinality stream_udp credential_expired counter records the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the session is already settled, so no second class can ever be counted for it"
    );

    // Redaction: the client-visible/logged error names the contract only.
    let message = error.to_lowercase();
    for forbidden in [
        "probe-consumer",
        "key_auth",
        "127.0.0.1",
        "expires",
        "certificate",
        "token",
    ] {
        assert!(
            !message.contains(forbidden),
            "the authorization setup error must not disclose {forbidden}: {error}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn continuous_traffic_does_not_refresh_the_authorization_deadline() {
    let latch = StreamAuthTerminationLatch::default();
    // Anchor AFTER fixture bind/connect. A plan captured before
    // `UdpAuthorizationSessionProbe::new` can already be elapsed by the first
    // forward under the hosted coverage scheduler; setup-expiry is covered
    // elsewhere and must not consume this relay budget.
    let session = UdpAuthorizationSessionProbe::with_lifetime_after_setup(
        Duration::from_millis(300),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        latch.clone(),
        false,
    )
    .await
    .expect("probe session binds loopback UDP sockets");

    // In-window commits must not await OS UDP readiness. Under paused time a
    // pending socket send/recv lets Tokio auto-advance to the next timer —
    // here the 300 ms authorization deadline — so a supposedly in-window
    // round can lose to expiry regardless of wall-clock milliseconds.
    // `forward_commit_with` still drives production
    // `forward_client_datagram_commit` (refuse-if-expired, amplification
    // budget, `udp_frontend_send_until_expiry`, and `bytes_sent` accounting);
    // the send future is caller-owned and immediately Ready so the paused
    // clock cannot jump. Real loopback UDP coverage stays in the
    // unauthenticated tests in this module.
    let mut committed = 0u64;
    for round in 0..3u8 {
        let payload = [round];
        session
            .forward_commit_with(
                &payload,
                std::future::ready(Ok::<usize, std::io::Error>(payload.len())),
            )
            .await
            .expect("traffic inside the lifetime is forwarded");
        committed += payload.len() as u64;
        assert_eq!(
            session.bytes_sent(),
            committed,
            "a successful in-window commit accounts the datagram"
        );
        tokio::time::advance(Duration::from_millis(90)).await;
    }
    assert_eq!(session.observed_termination(), None, "still authorized");
    assert_eq!(
        session.bytes_sent(),
        3,
        "three in-window commits were accepted"
    );

    // 270ms of continuous activity did not move the absolute deadline.
    tokio::time::advance(Duration::from_millis(60)).await;
    let send_polled = Arc::new(AtomicBool::new(false));
    let send_polled_flag = Arc::clone(&send_polled);
    session
        .forward_commit_with(
            b"past-deadline",
            std::future::poll_fn(move |_| {
                send_polled_flag.store(true, Ordering::SeqCst);
                std::task::Poll::Ready(Ok::<usize, std::io::Error>(13))
            }),
        )
        .await
        .expect_err("relayed datagrams never extend an anchored authorization deadline");
    assert!(
        !send_polled.load(Ordering::SeqCst),
        "an elapsed plan must refuse before polling the backend send"
    );
    assert_eq!(
        session.bytes_sent(),
        3,
        "a refused post-deadline datagram must not be accounted"
    );
    assert!(session.backend_received().is_none());
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
}

#[tokio::test(start_paused = true)]
async fn settlement_is_exactly_once_across_a_burst_of_refused_datagrams() {
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    for _ in 0..16 {
        assert!(session.forward(b"burst").await.is_err());
    }

    assert!(
        stream_udp_terminations().0 > before.0,
        "the burst recorded the termination"
    );
    assert_eq!(session.metadata().len(), 1, "one bounded metadata stamp");
    assert!(
        !latch.record_once(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the shared latch refuses a second settlement, so no later phase can double count"
    );
}

// ── Hook-ingress direction ──────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_hook_ingress_path_refuses_after_expiry_without_a_backpressure_drop() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(future_plan(
            Duration::from_millis(100),
            StreamAuthTermination::CredentialExpired,
        )),
        latch.clone(),
        true,
    )
    .await;

    assert!(
        session.enqueue_hook_datagram(b"authorized"),
        "an authorized datagram is admitted to the bounded hook queue"
    );
    let drops_before = session.hook_ingress_drops();

    tokio::time::advance(Duration::from_millis(150)).await;
    assert!(
        !session.enqueue_hook_datagram(b"post-expiry"),
        "an expired session queues no payload and runs no datagram hook"
    );
    assert_eq!(
        session.hook_ingress_drops(),
        drops_before,
        "a policy refusal is not gateway backpressure and must not move hook_ingress_drops"
    );
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(session.reply_task_stop_requested());
}

#[tokio::test(start_paused = true)]
async fn expiry_teardown_cancels_the_hook_ingress_worker() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        true,
    )
    .await;
    assert!(session.spawn_hook_ingress_worker());
    assert!(session.hook_ingress_sender_present());

    // Settle through the production client-side gate, then run the teardown the
    // reply task performs at exit.
    assert!(session.forward(b"post-expiry").await.is_err());
    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert!(summary.connection_error.is_some());

    // The worker's cancellation IS the dropped ingress sender: `recv` resolves
    // to `None` and the worker exits instead of waiting for another client
    // datagram, and an in-flight hook await is cancelled by the dedicated
    // hook-ingress notify.
    assert!(
        !session.hook_ingress_sender_present(),
        "teardown must take the hook-ingress sender so the worker wakes and exits"
    );
    assert!(
        !session.enqueue_hook_datagram(b"after-teardown"),
        "nothing can be enqueued for a torn-down session"
    );
    // Give the worker a scheduling turn; it must not forward anything.
    tokio::task::yield_now().await;
    assert!(session.backend_received().is_none());
}

// ── Backend → client direction ──────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_backend_reply_direction_settles_an_already_elapsed_plan_before_a_ready_datagram() {
    // Biased and pre-checked: a backend datagram that is ALREADY readable must
    // not be delivered to a client whose credential stopped authorizing the
    // session, and the verdict must not depend on `select!` scheduling.
    let stop = AtomicBool::new(false);
    let notify = tokio::sync::Notify::new();
    let plan = elapsed_plan(StreamAuthTermination::AuthenticatedStreamMaxLifetime);
    let outcome: UdpReplyRecvOutcomeForTest<u8> =
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            Some(plan),
            std::future::ready(7u8),
            std::future::pending(),
        )
        .await;
    assert_eq!(
        outcome,
        UdpReplyRecvOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
}

#[tokio::test(start_paused = true)]
async fn the_backend_reply_direction_stops_when_the_deadline_fires_mid_wait() {
    let stop = AtomicBool::new(false);
    let notify = tokio::sync::Notify::new();
    let outcome: UdpReplyRecvOutcomeForTest<u8> =
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            Some(future_plan(
                Duration::from_millis(40),
                StreamAuthTermination::CredentialExpired,
            )),
            std::future::pending::<u8>(),
            std::future::pending(),
        )
        .await;
    assert_eq!(
        outcome,
        UdpReplyRecvOutcomeForTest::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_reply_receive_is_unchanged() {
    let stop = AtomicBool::new(false);
    let notify = tokio::sync::Notify::new();
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            None,
            std::future::ready(9u8),
            std::future::pending(),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Received(9u8)
    );

    // Idle/drain stop still wins for an unauthenticated session.
    stop.store(true, Ordering::Release);
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            None,
            std::future::pending::<u8>(),
            std::future::pending(),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Stopped
    );
}

#[tokio::test(start_paused = true)]
async fn an_authorized_session_still_observes_idle_and_drain_stops() {
    // The authorization arm must not shadow the pre-existing idle/drain/global
    // shutdown races.
    let stop = AtomicBool::new(true);
    let notify = tokio::sync::Notify::new();
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            Some(future_plan(
                Duration::from_secs(3_600),
                StreamAuthTermination::CredentialExpired
            )),
            std::future::pending::<u8>(),
            std::future::pending(),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Stopped
    );

    let live = AtomicBool::new(false);
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &live,
            &notify,
            Some(future_plan(
                Duration::from_secs(3_600),
                StreamAuthTermination::CredentialExpired
            )),
            std::future::pending::<u8>(),
            std::future::ready(()),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Stopped,
        "listener/global shutdown still cancels an authorized session"
    );
}

#[tokio::test(start_paused = true)]
async fn a_reply_held_in_a_slow_backend_hook_is_not_committed_after_expiry() {
    // The receive can win just before expiry; the subsequent awaitable
    // backend→client hook is what used to smuggle the payload past the
    // deadline. The production hook-chain race must refuse send and cancel
    // the still-pending hook.
    struct SlowBackendToClientHook {
        delay: Duration,
        ran: Arc<AtomicUsize>,
        started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }
    #[async_trait::async_trait]
    impl ferrum_edge::plugins::Plugin for SlowBackendToClientHook {
        fn name(&self) -> &str {
            "test_slow_backend_to_client_udp_datagram"
        }
        async fn on_udp_datagram(
            &self,
            _ctx: &ferrum_edge::plugins::UdpDatagramContext<'_>,
        ) -> ferrum_edge::plugins::UdpDatagramVerdict {
            self.ran.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = self
                .started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let _ = started.send(());
            }
            tokio::time::sleep(self.delay).await;
            ferrum_edge::plugins::UdpDatagramVerdict::Forward
        }
    }

    let ran = Arc::new(AtomicUsize::new(0));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let plugin = Arc::new(SlowBackendToClientHook {
        delay: Duration::from_millis(80),
        ran: Arc::clone(&ran),
        started: Mutex::new(Some(started_tx)),
    });
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = vec![plugin];
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::CredentialExpired,
    );

    let commit = tokio::spawn(async move {
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"held-until-after-expiry",
            Some(plan),
        )
        .await
    });
    started_rx
        .await
        .expect("the slow hook must start before paused time advances past expiry");
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(
        commit.await.expect("join"),
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        ),
        "a datagram received before expiry but held in a slow hook must not be committed afterwards"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1, "the hook did run");
}

#[tokio::test(start_paused = true)]
async fn expiry_during_a_dropping_hook_still_terminates_the_session() {
    // A plugin Drop after the deadline must not keep the unauthorized session
    // alive by returning Drop instead of AuthorizationExpired.
    struct SlowDropHook;
    #[async_trait::async_trait]
    impl ferrum_edge::plugins::Plugin for SlowDropHook {
        fn name(&self) -> &str {
            "test_slow_drop_backend_to_client_udp_datagram"
        }
        async fn on_udp_datagram(
            &self,
            _ctx: &ferrum_edge::plugins::UdpDatagramContext<'_>,
        ) -> ferrum_edge::plugins::UdpDatagramVerdict {
            tokio::time::sleep(Duration::from_millis(80)).await;
            ferrum_edge::plugins::UdpDatagramVerdict::Drop
        }
    }

    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = vec![Arc::new(SlowDropHook)];
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let commit = tokio::spawn(async move {
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"drop-after-expiry",
            Some(plan),
        )
        .await
    });
    tokio::time::advance(Duration::from_millis(80)).await;
    assert_eq!(
        commit.await.expect("join"),
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
}

/// A backend→client hook whose future never completes, and which reports
/// when that future is dropped.
struct NeverCompletingBackendToClientHook {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    dropped: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ferrum_edge::plugins::Plugin for NeverCompletingBackendToClientHook {
    fn name(&self) -> &str {
        "test_never_completing_backend_to_client_udp_datagram"
    }
    async fn on_udp_datagram(
        &self,
        _ctx: &ferrum_edge::plugins::UdpDatagramContext<'_>,
    ) -> ferrum_edge::plugins::UdpDatagramVerdict {
        struct HookFutureGuard(Arc<AtomicBool>);

        impl Drop for HookFutureGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let _guard = HookFutureGuard(Arc::clone(&self.dropped));
        if let Some(entered) = self
            .entered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = entered.send(());
        }
        std::future::pending::<()>().await;
        unreachable!("the pending backend→client hook never completes")
    }
}

struct PollCountingBackendToClientHook {
    polled: Arc<AtomicBool>,
    verdict: ferrum_edge::plugins::UdpDatagramVerdict,
}

#[async_trait::async_trait]
impl ferrum_edge::plugins::Plugin for PollCountingBackendToClientHook {
    fn name(&self) -> &str {
        "test_poll_counting_backend_to_client_udp_datagram"
    }
    async fn on_udp_datagram(
        &self,
        _ctx: &ferrum_edge::plugins::UdpDatagramContext<'_>,
    ) -> ferrum_edge::plugins::UdpDatagramVerdict {
        self.polled.store(true, Ordering::SeqCst);
        self.verdict
    }
}

struct ImmediateDropBackendToClientHook;

#[async_trait::async_trait]
impl ferrum_edge::plugins::Plugin for ImmediateDropBackendToClientHook {
    fn name(&self) -> &str {
        "test_immediate_drop_backend_to_client_udp_datagram"
    }
    async fn on_udp_datagram(
        &self,
        _ctx: &ferrum_edge::plugins::UdpDatagramContext<'_>,
    ) -> ferrum_edge::plugins::UdpDatagramVerdict {
        ferrum_edge::plugins::UdpDatagramVerdict::Drop
    }
}

struct ParkedUnauthenticatedHook {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    dropped: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ferrum_edge::plugins::Plugin for ParkedUnauthenticatedHook {
    fn name(&self) -> &str {
        "test_parked_unauthenticated_backend_to_client_udp_datagram"
    }
    async fn on_udp_datagram(
        &self,
        _ctx: &ferrum_edge::plugins::UdpDatagramContext<'_>,
    ) -> ferrum_edge::plugins::UdpDatagramVerdict {
        struct HookFutureGuard(Arc<AtomicBool>);

        impl Drop for HookFutureGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let _guard = HookFutureGuard(Arc::clone(&self.dropped));
        if let Some(entered) = self
            .entered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = entered.send(());
        }
        let release = {
            self.release
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        };
        if let Some(release) = release {
            let _ = release.await;
        }
        ferrum_edge::plugins::UdpDatagramVerdict::Forward
    }
}

#[tokio::test(start_paused = true)]
async fn a_never_completing_backend_hook_is_dropped_at_the_authorization_deadline() {
    // A hook future that NEVER completes used to pin the reply task past the
    // credential deadline because the timer was only polled while awaiting
    // the next backend receive. Expiry must win without a later wake.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let plugin = Arc::new(NeverCompletingBackendToClientHook {
        entered: Mutex::new(Some(entered_tx)),
        dropped: Arc::clone(&dropped),
    });
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = vec![plugin];
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::CredentialExpired,
    );

    let commit = tokio::spawn(async move {
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"never-completing-hook",
            Some(plan),
        )
        .await
    });
    entered_rx.await.expect("the hook future must start");
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the hook must still be pending before the deadline"
    );

    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(
        commit.await.expect("join"),
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        ),
        "expiry must complete the race without waiting for the hook to finish"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the still-pending hook future must be dropped at the absolute deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_plan_never_polls_a_backend_to_client_hook() {
    let polled = Arc::new(AtomicBool::new(false));
    let plugin = Arc::new(PollCountingBackendToClientHook {
        polled: Arc::clone(&polled),
        verdict: ferrum_edge::plugins::UdpDatagramVerdict::Forward,
    });
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = vec![plugin];
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"already-elapsed",
            Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        )
        .await,
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed plan must refuse before polling any hook"
    );
}

#[tokio::test(start_paused = true)]
async fn expiry_and_drop_ready_together_is_expiry_first() {
    // `future_plan(0)` is an exact-boundary plan: the already-elapsed precheck
    // treats `now >= plan.at` as expiry and never polls the Drop hook.
    let polled = Arc::new(AtomicBool::new(false));
    let plugin = Arc::new(PollCountingBackendToClientHook {
        polled: Arc::clone(&polled),
        verdict: ferrum_edge::plugins::UdpDatagramVerdict::Drop,
    });
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = vec![plugin];
    let plan = future_plan(
        Duration::from_millis(0),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"exact-tie-drop",
            Some(plan),
        )
        .await,
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "an exact-deadline tie must not poll a simultaneously-ready Drop hook"
    );
}

#[tokio::test(start_paused = true)]
async fn a_plugin_drop_before_the_deadline_is_honored() {
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> =
        vec![Arc::new(ImmediateDropBackendToClientHook)];
    let plan = future_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"drop-while-authorized",
            Some(plan),
        )
        .await,
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::Drop,
        "a Drop that becomes ready strictly before expiry must not terminate the session"
    );
}

#[tokio::test(start_paused = true)]
async fn expiry_among_try_recv_batch_processing_stops_later_replies() {
    // Each drain step re-reads the same absolute plan. The first payload is
    // still authorized; after the deadline elapses the drain must refuse
    // further backend payloads rather than continue try_recv.
    let plan = future_plan(
        Duration::from_millis(40),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_expired_at_commit_for_test(Some(plan)),
        None,
        "the first drain step is still inside the lifetime"
    );

    tokio::time::advance(Duration::from_millis(40)).await;
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_expired_at_commit_for_test(Some(plan)),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime),
        "a later try_recv step must stop accepting backend payloads"
    );
    // Relayed traffic must not have moved the deadline.
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_expired_at_commit_for_test(Some(plan)),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_commitment_checks_never_expire() {
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_expired_at_commit_for_test(None),
        None
    );
    tokio::time::advance(Duration::from_secs(86_400)).await;
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_expired_at_commit_for_test(None),
        None,
        "an unauthenticated session has no plan, so commitment checks stay a miss"
    );

    assert_eq!(
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &[],
            b"unauthenticated-reply",
            None,
        )
        .await,
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::Commit
    );

    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> =
        vec![Arc::new(ImmediateDropBackendToClientHook)];
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"unauthenticated-drop",
            None,
        )
        .await,
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::Drop,
        "unauthenticated sessions still honor plugin Drop with no timer or clock"
    );

    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let plugin = Arc::new(ParkedUnauthenticatedHook {
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(Some(release_rx)),
        dropped: Arc::clone(&dropped),
    });
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = vec![plugin];
    let commit = tokio::spawn(async move {
        ferrum_edge::_test_support::udp_reply_commit_after_backend_hooks_for_test(
            &plugins,
            b"unauthenticated-parked",
            None,
        )
        .await
    });
    entered_rx
        .await
        .expect("the unauthenticated hook must start");
    tokio::time::advance(Duration::from_secs(86_400)).await;
    assert!(
        !dropped.load(Ordering::SeqCst),
        "an unauthenticated hook must not be cancelled by a timer that does not exist"
    );
    let _ = release_tx.send(());
    assert_eq!(
        commit.await.expect("join"),
        ferrum_edge::_test_support::UdpReplyDatagramCommitForTest::Commit
    );
}

/// Hold `send` pending until `release` is sent, then mark `emitted`.
async fn gated_client_emit(
    release: tokio::sync::oneshot::Receiver<()>,
    emitted: Arc<AtomicBool>,
) -> usize {
    let _ = release.await;
    emitted.store(true, Ordering::SeqCst);
    4
}

/// Production-shaped backend send future: park until `release`, then emit.
async fn gated_backend_send(
    release: tokio::sync::oneshot::Receiver<()>,
    emitted: Arc<AtomicBool>,
) -> Result<usize, std::io::Error> {
    let _ = release.await;
    emitted.store(true, Ordering::SeqCst);
    Ok(4)
}

#[tokio::test(start_paused = true)]
async fn a_pending_client_send_to_is_dropped_at_the_authorization_deadline() {
    // Ordinary non-batched `send_to`: the socket future stays pending across
    // the deadline, then is released. Expiry must win, the send future must
    // be dropped (no client-facing packet), and settlement stays exact-once.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(Some(plan), latch.clone(), false).await;

    let raced = tokio::spawn(async move {
        udp_frontend_send_until_expiry_for_test(
            Some(plan),
            gated_client_emit(release_rx, emitted_send),
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        UdpFrontendSendOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a send that became ready after the deadline must not emit a client packet"
    );

    assert!(session.forward(b"post-expiry").await.is_err());
    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert!(summary.connection_error.is_some());
    assert!(
        stream_udp_terminations().0 > before.0,
        "send-path expiry records the stream_udp counter once"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "settlement remains exactly once"
    );
    assert!(session.run_reply_task_exit_teardown().is_none());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_pending_writable_retry_is_dropped_at_the_authorization_deadline() {
    // Linux pktinfo `WouldBlock` path: `writable()` stays pending across the
    // deadline, then is released. Expiry must win over send readiness so the
    // post-writable syscall never runs.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let ready = Arc::new(AtomicBool::new(false));
    let ready_wait = Arc::clone(&ready);
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );

    let raced = tokio::spawn(async move {
        udp_frontend_writable_until_expiry_for_test(Some(plan), async move {
            let _ = release_rx.await;
            ready_wait.store(true, Ordering::SeqCst);
            Ok::<(), std::io::Error>(())
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    match raced.await.expect("join") {
        UdpFrontendSendOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        ) => {}
        other => panic!("expected authorization expiry at max lifetime, got {other:?}"),
    }
    assert!(
        !ready.load(Ordering::SeqCst),
        "writable readiness after the deadline must not reach the pktinfo syscall"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_writable_wait_never_reaches_the_syscall() {
    // An elapsed plan must refuse before polling writable, so a ready socket
    // cannot emit. The post-ready recheck is the same predicate; source
    // inspection pins it immediately before `send_with_pktinfo`.
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);
    let polled = Arc::new(AtomicBool::new(false));
    let polled_wait = Arc::clone(&polled);
    let outcome = udp_frontend_writable_until_expiry_for_test(
        Some(plan),
        std::future::poll_fn(move |_| {
            polled_wait.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(Ok::<(), std::io::Error>(()))
        }),
    )
    .await;
    match outcome {
        UdpFrontendSendOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired,
        ) => {}
        other => panic!("expected authorization expiry for credential expiry, got {other:?}"),
    }
    assert!(
        !polled.load(Ordering::SeqCst),
        "an elapsed plan must not poll writable or issue the client-facing syscall"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_pending_send_has_no_deadline() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);

    let raced = tokio::spawn(async move {
        udp_frontend_send_until_expiry_for_test(None, gated_client_emit(release_rx, emitted_send))
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(86_400)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        UdpFrontendSendOutcomeForTest::Sent(4)
    );
    assert!(
        emitted.load(Ordering::SeqCst),
        "an unauthenticated session keeps the no-timer send path"
    );
}

#[tokio::test(start_paused = true)]
async fn a_send_that_finishes_before_the_deadline_is_delivered() {
    let plan = future_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let outcome = udp_frontend_send_until_expiry_for_test(Some(plan), async { 7usize }).await;
    assert_eq!(outcome, UdpFrontendSendOutcomeForTest::Sent(7));
}

#[tokio::test(start_paused = true)]
async fn post_hook_expiry_settles_once_and_uses_the_shared_teardown() {
    // The new post-receive / post-hook / try_recv / flush checks settle
    // through the same latch the receive-arm expiry used, then the existing
    // identity-aware teardown runs exactly once.
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    assert_eq!(
        ferrum_edge::_test_support::udp_reply_expired_at_commit_for_test(Some(elapsed_plan(
            StreamAuthTermination::CredentialExpired
        ))),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(session.forward(b"post-expiry").await.is_err());
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::CredentialExpired)
    );

    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert!(summary.connection_error.is_some());
    assert!(
        stream_udp_terminations().0 > before.0,
        "the reply-path expiry still records the stream_udp counter once"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "settlement remains exactly once"
    );
    assert!(session.run_reply_task_exit_teardown().is_none());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);
}

// ── Teardown, generation identity, and accounting ───────────────────────

#[tokio::test(start_paused = true)]
async fn expiry_teardown_invalidates_the_cached_generation_and_removes_only_it() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    assert_eq!(
        session.cached_generation_is_live(),
        (true, true),
        "before teardown the recv-loop fast-path cache resolves this generation"
    );
    assert!(session.session_map_contains());

    assert!(session.forward(b"post-expiry").await.is_err());
    assert!(session.run_reply_task_exit_teardown().is_some());

    assert_eq!(
        session.cached_generation_is_live(),
        (false, false),
        "the generation is marked expired BEFORE reuse, and the stale cache entry is cleared"
    );
    assert!(
        !session.session_map_contains(),
        "the exact expired generation is removed, so the next datagram creates a new session"
    );
}

#[tokio::test(start_paused = true)]
async fn teardown_releases_the_overload_guard_and_session_slot_exactly_once() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        latch.clone(),
        false,
    )
    .await;
    assert_eq!(session.overload_active_connections(), 1);
    assert_eq!(session.active_sessions(), 1);

    assert!(session.forward(b"post-expiry").await.is_err());
    assert!(session.run_reply_task_exit_teardown().is_some());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);

    // Identity-aware removal: a second teardown owns nothing and must not
    // decrement anything a second time.
    assert!(
        session.run_reply_task_exit_teardown().is_none(),
        "only the generation that won the removal emits a summary"
    );
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_simultaneous_idle_removal_and_authorization_expiry_release_exactly_once() {
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        true,
    )
    .await;

    // The authorization expiry is observed on the client side …
    assert!(session.forward(b"post-expiry").await.is_err());
    // … while the idle-cleanup task wins the identity-aware removal.
    assert!(session.run_idle_cleanup_removal());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);

    // The reply task's own exit then owns nothing.
    assert!(session.run_reply_task_exit_teardown().is_none());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);
    assert!(
        stream_udp_terminations().0 > before.0,
        "the race recorded the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "exactly one settlement: the idle path cannot count a second one"
    );
    // The bounded class still reaches whichever summary is delivered, because
    // it was stamped into the session metadata before the removal race.
    assert_eq!(
        session
            .metadata()
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("credential_expired")
    );
}

#[tokio::test(start_paused = true)]
async fn the_disconnect_summary_names_a_client_side_health_neutral_authorization_decision() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        latch.clone(),
        false,
    )
    .await;
    assert!(session.forward(b"post-expiry").await.is_err());

    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");

    let (message, class, cause, direction) = udp_authorization_disconnect_classification_for_test();
    assert_eq!(summary.connection_error.as_deref(), Some(message.as_str()));
    assert_eq!(summary.error_class, Some(class));
    assert_eq!(summary.disconnect_cause, Some(cause));
    assert_eq!(summary.disconnect_direction, Some(direction));

    // Client-side and backend-health-neutral: the same attribution the DTLS
    // relay-phase expiry uses, so `stream_disconnects` never reads a gateway
    // policy decision as a backend outage.
    assert_eq!(cause, DisconnectCause::RecvError);
    assert_eq!(direction, Direction::ClientToBackend);
    assert_eq!(class, ErrorClass::RequestError);

    assert_eq!(
        summary
            .metadata
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("authenticated_stream_max_lifetime"),
        "the bounded class reaches the transaction summary and on_stream_disconnect"
    );

    // Redaction: nothing about the credential, the identity, the deadline, the
    // certificate, the token, or the source address is in the cause text.
    let lower = message.to_lowercase();
    for forbidden in [
        "probe-consumer",
        "127.0.0.1",
        "certificate",
        "token",
        "jwt",
        "notafter",
        "exp=",
    ] {
        assert!(
            !lower.contains(forbidden),
            "the disconnect cause must not disclose {forbidden}: {message}"
        );
    }
    assert!(
        !message.chars().any(|c| c.is_ascii_digit()),
        "the disconnect cause must carry no expiry or address digits: {message}"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_session_teardown_reports_no_authorization_decision() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(None, latch, false).await;
    session.forward(b"data").await.expect("forward succeeds");
    let _ = session.backend_recv().await;

    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert_eq!(summary.connection_error, None);
    assert_eq!(summary.error_class, None);
    assert!(
        !summary
            .metadata
            .contains_key(STREAM_AUTH_TERMINATION_METADATA_KEY),
        "an unauthenticated session carries no authorization termination metadata"
    );
}

// ── Concurrency ─────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn concurrent_directions_settle_one_termination_between_them() {
    // Both directions are armed from the same absolute plan, so both can become
    // ready at the same instant. The shared latch makes the pair record one
    // termination for the session.
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = Arc::new(
        probe(
            Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
            latch.clone(),
            true,
        )
        .await,
    );

    let settles = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let session = Arc::clone(&session);
        let settles = Arc::clone(&settles);
        handles.push(tokio::spawn(async move {
            if session.forward(b"race").await.is_err() {
                settles.fetch_add(1, Ordering::Relaxed);
            }
            let _ = session.enqueue_hook_datagram(b"race");
        }));
    }
    for handle in handles {
        let _ = handle.await;
    }

    assert_eq!(
        settles.load(Ordering::Relaxed),
        4,
        "every datagram is refused"
    );
    assert!(
        stream_udp_terminations().0 > before.0,
        "the concurrent observers recorded the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "concurrent observers still settle exactly once between them"
    );
    assert_eq!(session.metadata().len(), 1);
}

// ── Hot-path and wiring contracts ───────────────────────────────────────

const UDP_PROXY_SOURCE: &str = include_str!("../../../src/proxy/udp_proxy.rs");

fn body_of(marker: &str) -> &'static str {
    UDP_PROXY_SOURCE
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("{marker} not found in udp_proxy.rs"))
}

/// The datagram gate must stay lock-free and allocation-free.
///
/// A UDP proxy's per-datagram budget is why the module already keeps a coarse
/// cached clock and a `last_client` fast path. The authorization gate is one
/// `Option` discriminant test plus, for an AUTHENTICATED session only, one
/// monotonic instant comparison — no per-datagram mutex, map walk, allocation,
/// timer task, or formatted string.
#[test]
fn the_client_to_backend_authorization_gate_stays_on_the_hot_path_budget() {
    let gate = body_of("fn refuse_if_authorization_expired(")
        .split("\n    }\n")
        .next()
        .expect("the gate body");
    for forbidden in ["format!(", "to_string()", "tokio::spawn", "sleep", "iter()"] {
        assert!(
            !gate.contains(forbidden),
            "the per-datagram authorization gate must not use `{forbidden}`: {gate}"
        );
    }

    let expired_now = body_of("fn authorization_expired_now(")
        .split("\n    }\n")
        .next()
        .expect("the expiry predicate body");
    assert!(
        expired_now.contains("self.authorization.as_ref()"),
        "an unauthenticated session must short-circuit before any clock read"
    );
    assert!(
        expired_now.contains("udp_reply_expired_at_commit("),
        "the client→backend gate shares the reply-path commitment predicate"
    );
    for forbidden in ["lock()", "format!(", "Vec::", "String::"] {
        assert!(
            !expired_now.contains(forbidden),
            "the per-datagram expiry predicate must not use `{forbidden}`"
        );
    }

    let commit = body_of("pub(crate) fn udp_reply_expired_at_commit")
        .split("\n}\n")
        .next()
        .expect("the commitment predicate body");
    let unauthenticated = commit
        .find("let plan = plan?;")
        .expect("an unauthenticated session must return before any clock read");
    let clock = commit
        .find("tokio::time::Instant::now()")
        .expect("authenticated sessions compare the monotonic clock");
    assert!(
        unauthenticated < clock,
        "an unauthenticated session must return before any clock read"
    );
    assert!(
        commit.contains("tokio::time::Instant::now() >= plan.at"),
        "an authenticated check is one monotonic instant comparison"
    );
    for forbidden in ["lock()", "format!(", "sleep", "spawn"] {
        assert!(
            !commit.contains(forbidden),
            "the commitment predicate must not use `{forbidden}`"
        );
    }
}

/// The backend reply direction arms ONE timer, outside its receive loop.
#[test]
fn the_reply_task_arms_its_authorization_timer_once() {
    let create_session = body_of("async fn create_session(");
    let arm_at = create_session
        .find("let mut reply_authorization_deadline")
        .expect("the reply task's authorization arm");
    let loop_at = create_session[arm_at..]
        .find("\n        'reply: loop {")
        .expect("the labeled reply receive loop");
    assert!(
        loop_at > 0,
        "the deadline must be armed BEFORE the receive loop, so no per-datagram timer is \
         registered"
    );
    let receive_loop = &create_session[arm_at + loop_at..];
    assert!(
        !receive_loop.contains("tokio::time::sleep_until("),
        "the receive loop must not re-arm a timer per datagram"
    );
    assert_eq!(
        receive_loop
            .matches("udp_reply_recv_until_stop_or_expiry(")
            .count(),
        2,
        "both the DTLS-backend and plain-UDP-backend receive arms are bounded"
    );
}

/// The authorization arm is biased first, and an already-elapsed plan settles
/// without polling the receive at all.
#[test]
fn the_reply_receive_prefers_the_authorization_arm() {
    let body = body_of("pub(crate) async fn udp_reply_recv_until_stop_or_expiry");
    let precheck_at = body
        .find("if tokio::time::Instant::now() >= plan.at {")
        .expect("the already-elapsed pre-check");
    let select_at = body.find("tokio::select! {").expect("the bounded select");
    assert!(
        precheck_at < select_at,
        "an already-elapsed plan must settle before `select!` can pick a ready receive"
    );
    let select = &body[select_at..];
    let biased_at = select.find("biased;").expect("biased select");
    let deadline_at = select
        .find("authorization_deadline.as_mut()")
        .expect("the authorization arm");
    let recv_at = select
        .find("udp_reply_recv_until_stop(")
        .expect("the receive arm");
    assert!(
        biased_at < deadline_at && deadline_at < recv_at,
        "the authorization arm must be the FIRST select arm"
    );
}

/// Every post-admission setup stage that can await is bounded, and the session
/// is re-checked before it is committed.
#[test]
fn every_plain_udp_setup_stage_runs_under_the_authorization_deadline() {
    let new_session = body_of("async fn process_new_session_datagram(");
    // Anchored before the epoch resolve and the admission chain.
    let anchor_at = new_session
        .find("let auth_anchor = tokio::time::Instant::now();")
        .expect("the admission anchor");
    let epoch_at = new_session
        .find("let epoch = request_epoch.load();")
        .expect("the epoch resolve");
    let admit_at = new_session
        .find("admit_plain_udp_stream(")
        .expect("the on_stream_connect chain");
    assert!(
        anchor_at < epoch_at && epoch_at < admit_at,
        "the fallback maximum must be anchored before any slow admission work"
    );
    assert!(
        new_session.contains("effective_stream_auth_deadline("),
        "the plain-UDP path must compute an effective authorization plan"
    );
    // The first-datagram policy hooks are bounded.
    let first_datagram = new_session
        .find("let first_datagram_allowed =")
        .expect("the bounded first-datagram policy stage");
    assert!(first_datagram > admit_at);
    // The pending drain stops at expiry.
    let drain_gate = new_session
        .find("'drain: while let Some(batch) = take_pending_datagrams(")
        .expect("the labeled pending-datagram drain");
    let drain_break = new_session[drain_gate..]
        .find("break 'drain;")
        .expect("the drain's expiry break");
    let drain_hook = new_session[drain_gate..]
        .find("udp_datagram_allowed(")
        .expect("the drain's per-datagram hook");
    assert!(
        drain_break < drain_hook,
        "the pending-datagram drain must stop at expiry BEFORE running another hook"
    );

    let create_session = body_of("async fn create_session(");
    assert_eq!(
        create_session
            .matches("stream_udp_setup_stage_under_authorization(")
            .count(),
        2,
        "DNS resolution and the backend connect/handshake are both bounded"
    );
    let commit_check = create_session
        .find("udp_authorization_expired_before_commit(")
        .expect("the pre-commit re-check");
    let cb_success = create_session
        .find("// Record circuit breaker success")
        .expect("the backend success accounting");
    let insert = create_session
        .find("sessions.insert(client_addr, session.clone());")
        .expect("the session map insert");
    assert!(
        commit_check < cb_success && cb_success < insert,
        "the synchronous gap must be re-checked before ANY backend success is recorded and \
         before the session is committed"
    );
}

/// The gate is installed on every client→backend production path, and the
/// gateway-owned send itself is authorization-aware.
#[test]
fn every_client_to_backend_path_is_gated() {
    let forward = body_of("async fn forward_client_datagram_to_backend(")
        .split("\n}\n")
        .next()
        .expect("the forward body");
    assert!(
        forward.contains("forward_client_datagram_commit("),
        "every client→backend send must go through the authorization-aware commit"
    );

    let commit = body_of("async fn forward_client_datagram_commit<F>(")
        .split("\n}\n")
        .next()
        .expect("the commit body");
    let gate_at = commit
        .find("session.refuse_if_authorization_expired().is_some()")
        .expect("the forward gate");
    let publish_at = commit
        .find("publish_session_request_budget(")
        .expect("the amplification budget publish");
    let race_at = commit
        .find("udp_frontend_send_until_expiry(")
        .expect("the authorization-aware send race");
    assert!(
        gate_at < publish_at,
        "the gate must precede the amplification-budget publish and the backend send, so an \
         expired credential moves no gateway state"
    );
    assert!(
        publish_at < race_at,
        "the gateway-owned send must race the absolute plan after the pre-send refusal"
    );

    let enqueue = body_of("fn enqueue_session_hook_datagram(")
        .split("\n}\n")
        .next()
        .expect("the enqueue body");
    let enqueue_gate = enqueue
        .find("session.refuse_if_authorization_expired().is_some()")
        .expect("the hook-ingress gate");
    let queue_at = enqueue.find("hook_ingress_tx").expect("the queue lookup");
    assert!(
        enqueue_gate < queue_at,
        "an expired session must be refused before any payload is queued or charged"
    );
    assert!(
        !enqueue[..enqueue_gate].contains("record_hook_ingress_drop"),
        "a policy refusal must not be recorded as gateway backpressure"
    );
}

/// Backend→client expiry is re-checked at every post-receive commitment
/// boundary, awaitable hooks are raced against the same plan, and queued
/// GSO/sendmmsg payloads are discarded — not flushed.
#[test]
fn the_reply_task_rechecks_and_discards_at_every_commitment_boundary() {
    let create_session = body_of("async fn create_session(");
    let reply_loop = create_session
        .split("'reply: loop {")
        .nth(1)
        .expect("the labeled reply loop");

    assert!(
        reply_loop.contains("udp_reply_expired_at_commit(reply_authorization_plan)"),
        "the reply loop rechecks the admitted absolute plan at commitment boundaries"
    );
    assert!(
        reply_loop.contains("udp_reply_commit_after_backend_hooks("),
        "awaitable backend→client hooks race the absolute plan before send or enqueue"
    );
    assert!(
        reply_loop.contains("gso_batch.discard()"),
        "expiry discards queued GSO datagrams rather than flushing them"
    );
    assert!(
        reply_loop.contains("send_batch.discard()"),
        "expiry discards queued sendmmsg datagrams rather than flushing them"
    );

    let after_recv = reply_loop
        .find("let send_data =")
        .expect("post-receive send_data");
    let after_recv_check = reply_loop[after_recv..]
        .find("udp_reply_expired_at_commit(reply_authorization_plan)")
        .expect("post-receive commitment check");
    let hooks = reply_loop
        .find("udp_reply_commit_after_backend_hooks(")
        .expect("post-hook commitment");
    assert!(
        after_recv_check < hooks - after_recv,
        "the plan is rechecked after recv returns, before the hook chain"
    );

    let try_recv_for = reply_loop
        .find("for _ in 0..batch_limit {")
        .expect("the try_recv drain");
    let drain = &reply_loop[try_recv_for..];
    let drain_check = drain
        .find("udp_reply_expired_at_commit(reply_authorization_plan)")
        .expect("try_recv drain commitment check");
    let try_recv = drain.find("sock.try_recv(").expect("try_recv");
    assert!(
        drain_check < try_recv,
        "expiry at the top of the try_recv drain must stop accepting more backend payloads"
    );

    let flush_section = reply_loop
        .find("// Flush batched sends after draining all pending replies.")
        .expect("the flush section");
    let flush = &reply_loop[flush_section..];
    let flush_check = flush
        .find("udp_reply_expired_at_commit(reply_authorization_plan)")
        .expect("pre-flush commitment check");
    let flush_gso = flush.find("flush_gso_batch(").expect("GSO flush");
    assert!(
        flush_check < flush_gso,
        "queued GSO/sendmmsg payloads must be rechecked before any client flush"
    );

    let expire_breaks = reply_loop.matches("break 'reply;").count();
    assert!(
        expire_breaks >= 6,
        "expiry must exit the entire reply loop (got {expire_breaks} labeled breaks), so the \
         shared identity-aware teardown runs exactly once"
    );
    assert!(
        !reply_loop.contains("tokio::time::sleep_until("),
        "commitment rechecks must not arm a per-datagram timer"
    );
}

/// Client-facing asynchronous sends are owned by the absolute plan: a pre-send
/// check then `send_to`/`writable().await` is not enough.
#[test]
fn client_facing_sends_are_raced_against_the_authorization_plan() {
    let send = body_of("pub(crate) async fn udp_frontend_send_until_expiry")
        .split("\n}\n")
        .next()
        .expect("the send race body");
    let precheck_at = send
        .find("if tokio::time::Instant::now() >= plan.at {")
        .expect("the already-elapsed pre-check");
    let select_at = send.find("tokio::select! {").expect("the send race");
    assert!(
        precheck_at < select_at,
        "an already-elapsed plan must not poll the client send"
    );
    let none_at = send
        .find("let Some(plan) = plan else")
        .expect("the unauthenticated fast path");
    assert!(
        none_at < precheck_at,
        "an unauthenticated session must await send with no timer or clock"
    );
    assert!(
        send[..precheck_at].contains("return UdpFrontendSendOutcome::Sent(send.await)"),
        "the unauthenticated path is a plain await"
    );
    let select = &send[select_at..];
    let biased_at = select.find("biased;").expect("biased select");
    let deadline_at = select
        .find("tokio::time::sleep_until(plan.at)")
        .expect("the authorization arm");
    let send_at = select.find("result = send =>").expect("the send arm");
    assert!(
        biased_at < deadline_at && deadline_at < send_at,
        "the expiry arm must be first so exact-deadline ties fail closed"
    );
    assert!(
        !send.contains("timeout_at("),
        "the timeout helper that polls the inner future first would emit on a tie"
    );
    assert!(
        !send.contains("tokio::spawn"),
        "the send future must stay owned by the race, not detached"
    );

    let writable = body_of("pub(crate) async fn udp_frontend_writable_until_expiry")
        .split("\n}\n")
        .next()
        .expect("the writable race body");
    let race_at = writable
        .find("udp_frontend_send_until_expiry(plan, writable)")
        .expect("writable waits through the same race");
    let recheck_at = writable
        .find("udp_reply_expired_at_commit(plan)")
        .expect("post-ready authorization recheck");
    assert!(
        race_at < recheck_at,
        "authorization must be re-read after writable readiness and before the syscall"
    );

    let create_session = body_of("async fn create_session(");
    let reply_loop = create_session
        .split("'reply: loop {")
        .nth(1)
        .expect("the labeled reply loop");
    assert_eq!(
        reply_loop
            .matches("udp_frontend_send_until_expiry(")
            .count(),
        2,
        "both non-batched frontend.send_to sites (first reply and try_recv drain) \
         must race the send"
    );
    assert!(
        !reply_loop.contains("frontend.send_to(send_data, client_addr).await"),
        "the ordinary send_to path must not await the socket future unguarded"
    );
    assert!(
        !reply_loop.contains("frontend.send_to(&buf[..len2], client_addr).await"),
        "the try_recv send_to path must not await the socket future unguarded"
    );

    let linux_direct = body_of("async fn direct_send_to_client(")
        .split("\n}\n")
        .next()
        .expect("direct_send_to_client body");
    assert!(
        linux_direct.contains("udp_frontend_send_until_expiry("),
        "the Linux send_to fallback must race the client send"
    );
    assert!(
        linux_direct.contains("frontend.send_to(data, client_addr)"),
        "the Linux family-mismatch fallback still uses send_to under the race"
    );
    assert!(
        linux_direct.contains("udp_frontend_writable_until_expiry("),
        "the Linux pktinfo WouldBlock path must race writable()"
    );
    let writable_wait = linux_direct
        .find("udp_frontend_writable_until_expiry(")
        .expect("writable race");
    let would_block = linux_direct
        .find("ErrorKind::WouldBlock")
        .expect("WouldBlock path");
    let syscall = linux_direct
        .find("send_with_pktinfo(")
        .expect("the pktinfo syscall");
    assert!(
        linux_direct[..syscall].contains("udp_reply_expired_at_commit(authorization)"),
        "the pktinfo syscall must be preceded by an authorization recheck"
    );
    assert!(
        writable_wait > would_block,
        "writable wait is the authorization-owned helper, not a bare frontend.writable().await"
    );
    assert!(
        !linux_direct.contains("frontend.writable().await"),
        "writable() must not be awaited outside the authorization race"
    );

    let dtls_inner = body_of("async fn handle_dtls_client_inner(");
    assert!(
        dtls_inner.contains("udp_frontend_send_until_expiry("),
        "DTLS frontend client sends must race the same absolute plan"
    );
    assert!(
        dtls_inner.contains("client_sender.send_committed("),
        "the raced operation is the deadline-aware actual-commit DTLS send"
    );
    assert!(
        dtls_inner.contains("dtls_c2b_until_expiry("),
        "DTLS client→backend receive, hooks, and backend commits must race the plan"
    );
    let dtls_c2b_publish = dtls_inner
        .find("publish_request_budget(")
        .expect("DTLS client→backend must publish the cumulative amplification budget");
    let dtls_c2b_send = dtls_inner[dtls_c2b_publish..]
        .find("dtls_c2b_until_expiry(")
        .expect("the DTLS backend send must race the plan after the budget publish");
    assert!(
        dtls_c2b_send > 0,
        "the remaining-budget publish must precede the authorization-raced backend send"
    );
    assert!(
        dtls_inner.contains("bind_authorization_deadline(plan.at)"),
        "the admitted deadline must be published into the per-client DTLS driver"
    );
    assert!(
        !dtls_inner.contains("client_sender.send(&data)"),
        "the DTLS frontend send must not use the unauthenticated enqueue-only convenience API"
    );
    assert!(
        !dtls_inner.contains("if client_sender.send(&data).await.is_err()"),
        "the DTLS frontend send must not await unguarded"
    );

    let dtls_b2c = dtls_inner
        .split("let backend_to_client = tokio::spawn(async move {")
        .nth(1)
        .expect("the terminating-DTLS backend→client task")
        .split("client_sender.send_committed(")
        .next()
        .expect("DTLS B2C hooks precede the client send race");
    assert!(
        dtls_b2c.contains("udp_reply_commit_after_backend_hooks("),
        "terminating-DTLS backend→client hooks share the raced helper"
    );
    assert!(
        !dtls_b2c.contains("plugin.on_udp_datagram(&ctx).await"),
        "DTLS backend→client hooks must not await unguarded"
    );
}

/// A post-hook clock recheck is not sufficient: the hook-chain future itself
/// must be owned by the same expiry-first race as client-facing sends.
#[test]
fn backend_to_client_hooks_race_the_authorization_plan() {
    let body = body_of("pub(crate) async fn udp_reply_commit_after_backend_hooks")
        .split("\n}\n")
        .next()
        .expect("the backend→client hook helper body");
    assert!(
        body.contains("udp_frontend_send_until_expiry(plan, chain)"),
        "the hook chain must be owned by the expiry-first race, not awaited then rechecked"
    );
    assert!(
        !body.contains("udp_reply_expired_at_commit("),
        "a post-hook clock recheck cannot cancel a still-pending hook future"
    );
    assert!(
        body.contains("plugin.on_udp_datagram(ctx).await"),
        "plugin order is preserved inside the raced chain"
    );
    let none_path = body_of("pub(crate) async fn udp_frontend_send_until_expiry")
        .split("\n}\n")
        .next()
        .expect("the shared race body");
    assert!(
        none_path.contains("return UdpFrontendSendOutcome::Sent(send.await)"),
        "unauthenticated sessions still take the no-timer fast path"
    );
}

#[tokio::test(start_paused = true)]
async fn a_parked_client_to_backend_send_is_dropped_at_the_authorization_deadline() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = Arc::new(probe(Some(plan), latch.clone(), false).await);

    let raced = tokio::spawn({
        let session = Arc::clone(&session);
        async move {
            session
                .forward_commit_with(b"parked", gated_backend_send(release_rx, emitted_send))
                .await
        }
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert!(
        raced.await.expect("join").is_err(),
        "a send parked on writability must refuse at the authorization deadline"
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a send that became ready after the deadline must not emit a backend datagram"
    );
    assert!(session.forward(b"post-expiry").await.is_err());
    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert!(summary.connection_error.is_some());
    assert!(
        stream_udp_terminations().0 > before.0,
        "send-path expiry records the stream_udp counter once"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "settlement remains exactly once"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_client_to_backend_send_never_polls_the_socket() {
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(Some(plan), latch.clone(), false).await;
    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let result = session
        .forward_commit_with(
            b"late",
            std::future::poll_fn(move |_| {
                polled_send.store(true, Ordering::SeqCst);
                std::task::Poll::Ready(Ok::<usize, std::io::Error>(4))
            }),
        )
        .await;
    assert!(result.is_err());
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed plan must refuse before polling the backend send"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the pre-send refusal settles the latch once"
    );
}

#[tokio::test(start_paused = true)]
async fn an_exact_tie_on_a_ready_client_to_backend_send_is_expiry_first() {
    let plan = future_plan(
        Duration::from_millis(0),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(Some(plan), latch.clone(), false).await;
    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let result = session
        .forward_commit_with(
            b"tie",
            std::future::poll_fn(move |_| {
                polled_send.store(true, Ordering::SeqCst);
                std::task::Poll::Ready(Ok::<usize, std::io::Error>(4))
            }),
        )
        .await;
    assert!(result.is_err());
    assert!(
        !polled.load(Ordering::SeqCst),
        "an exact-deadline tie must not poll a simultaneously-ready backend send"
    );
}

#[tokio::test(start_paused = true)]
async fn a_parked_dtls_c2b_hook_is_dropped_at_the_authorization_deadline() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_hook = Arc::clone(&emitted);
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = StreamAuthTerminationLatch::default();
    let raced = tokio::spawn({
        let latch = latch.clone();
        async move {
            dtls_c2b_until_expiry_for_test(
                Some(plan),
                &latch,
                gated_client_emit(release_rx, emitted_hook),
            )
            .await
        }
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        Err(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a blocked hook must not complete after the authorization deadline"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "DTLS C2B expiry settles the shared latch once"
    );
}

#[tokio::test(start_paused = true)]
async fn a_parked_dtls_c2b_backend_send_is_dropped_at_the_authorization_deadline() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let plan = future_plan(
        Duration::from_millis(20),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = StreamAuthTerminationLatch::default();
    let raced = tokio::spawn({
        let latch = latch.clone();
        async move {
            dtls_c2b_until_expiry_for_test(
                Some(plan),
                &latch,
                gated_client_emit(release_rx, emitted_send),
            )
            .await
        }
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        Err(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a parked backend send must not commit an application datagram after expiry"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_dtls_c2b_stage_never_polls() {
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);
    let latch = StreamAuthTerminationLatch::default();
    let polled = Arc::new(AtomicBool::new(false));
    let polled_stage = Arc::clone(&polled);
    let result = dtls_c2b_until_expiry_for_test(
        Some(plan),
        &latch,
        std::future::poll_fn(move |_| {
            polled_stage.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(1usize)
        }),
    )
    .await;
    assert_eq!(result, Err(StreamAuthTermination::CredentialExpired));
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed DTLS C2B plan must not poll receive, hook, or send"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_dtls_c2b_stage_has_no_timer() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_stage = Arc::clone(&emitted);
    let latch = StreamAuthTerminationLatch::default();
    let raced = tokio::spawn(async move {
        dtls_c2b_until_expiry_for_test(None, &latch, gated_client_emit(release_rx, emitted_stage))
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(86_400)).await;
    let _ = release_tx.send(());
    assert_eq!(raced.await.expect("join"), Ok(4));
    assert!(emitted.load(Ordering::SeqCst));
}
