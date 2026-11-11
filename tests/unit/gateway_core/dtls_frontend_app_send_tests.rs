//! Terminating frontend DTLS application-send wire-commit (issue #3820)
//! and established-session trust-retirement delivery races (issue #3857).
//!
//! Enqueue into `app_in_rx` is not a client-facing commit. These drive the
//! production driver/helper seam: queued plaintext is cancelled on deadline
//! or send-future drop; a `send_to` wait crossing the deadline emits nothing;
//! exact ties fail closed; shutdown does not flush expired/cancelled queued
//! replies; success completes only after the send future itself completes;
//! unauthenticated behavior keeps the no-timer path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::{
    FrontendAppSendAdmitForTest, FrontendAppSendRejectForTest, admit_frontend_app_send_for_test,
    earliest_frontend_app_send_deadline_for_test,
    encode_frontend_session_auth_deadline_offset_for_test,
    frontend_app_ciphertext_send_until_expiry_for_test, frontend_app_send_cancel_fired_for_test,
    frontend_app_send_reject_as_str_for_test, frontend_session_auth_deadline_for_test,
    frontend_trust_raced_delivery_for_test, publish_frontend_session_auth_deadline_for_test,
    read_frontend_session_auth_deadline_for_test,
    reconstruct_frontend_session_auth_deadline_for_test,
    reconstruct_frontend_session_auth_deadline_from_duration_for_test,
    shutdown_queued_frontend_app_send_for_test,
};
use ferrum_edge::tls::client_trust::{self, ClientTrustScope};

const DTLS_SOURCE: &str = include_str!("../../../src/dtls/mod.rs");
const UDP_PROXY_SOURCE: &str = include_str!("../../../src/proxy/udp_proxy.rs");

fn elapsed_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("elapsed deadline")
}

fn future_deadline(delta: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + delta
}

#[test]
fn later_per_call_publication_then_earlier_bind_tightens_session() {
    let auth = frontend_session_auth_deadline_for_test();
    let now = tokio::time::Instant::now();
    let later = now + Duration::from_secs(60);
    let earlier = now + Duration::from_secs(5);

    publish_frontend_session_auth_deadline_for_test(&auth, later);
    assert_eq!(
        read_frontend_session_auth_deadline_for_test(&auth),
        Some(later),
        "first publication installs the per-call bound"
    );

    publish_frontend_session_auth_deadline_for_test(&auth, earlier);
    assert_eq!(
        read_frontend_session_auth_deadline_for_test(&auth),
        Some(earlier),
        "an explicit earlier bind must tighten the shared session deadline"
    );
}

#[test]
fn encode_clamps_overflow_and_avoids_unset_sentinel() {
    const UNSET: u64 = u64::MAX;
    const MAX_ENCODED: u64 = u64::MAX - 1;

    assert_eq!(encode_frontend_session_auth_deadline_offset_for_test(0), 0);
    assert_eq!(
        encode_frontend_session_auth_deadline_offset_for_test(1_500),
        1_500
    );
    assert_eq!(
        encode_frontend_session_auth_deadline_offset_for_test(u64::MAX as u128),
        MAX_ENCODED,
        "exactly u64::MAX nanoseconds must not collide with the unset sentinel"
    );
    assert_eq!(
        encode_frontend_session_auth_deadline_offset_for_test(u128::from(u64::MAX) + 1),
        MAX_ENCODED,
        "offsets above u64::MAX must clamp instead of wrapping"
    );
    assert_eq!(
        encode_frontend_session_auth_deadline_offset_for_test(u128::MAX),
        MAX_ENCODED,
        "extreme offsets must clamp to the largest representable encoded value"
    );
    assert_ne!(
        encode_frontend_session_auth_deadline_offset_for_test(u128::MAX),
        UNSET
    );
}

#[test]
fn reconstruct_fails_closed_when_offset_is_unrepresentable() {
    let anchor = tokio::time::Instant::now();
    assert_eq!(
        reconstruct_frontend_session_auth_deadline_for_test(anchor, 0),
        anchor,
        "zero offset reconstructs to the anchor"
    );
    assert_eq!(
        reconstruct_frontend_session_auth_deadline_from_duration_for_test(anchor, Duration::MAX),
        anchor,
        "an unrepresentable reconstruction must fail closed to the anchor"
    );
}

#[test]
fn publish_already_expired_bind_encodes_zero_and_reads_anchor() {
    let auth = frontend_session_auth_deadline_for_test();
    publish_frontend_session_auth_deadline_for_test(&auth, elapsed_deadline());
    let read = read_frontend_session_auth_deadline_for_test(&auth).expect("published");
    assert!(
        read <= tokio::time::Instant::now(),
        "an already-expired bind must read as immediately expired"
    );
}

#[test]
fn earlier_session_deadline_cannot_be_extended_by_later_publication() {
    let auth = frontend_session_auth_deadline_for_test();
    let now = tokio::time::Instant::now();
    let earlier = now + Duration::from_secs(5);
    let later = now + Duration::from_secs(60);

    publish_frontend_session_auth_deadline_for_test(&auth, earlier);
    publish_frontend_session_auth_deadline_for_test(&auth, later);
    assert_eq!(
        read_frontend_session_auth_deadline_for_test(&auth),
        Some(earlier),
        "a later publication must not extend authorization"
    );
}

#[test]
fn concurrent_publications_settle_on_earliest_deadline() {
    use std::sync::{Arc, Barrier};

    let auth = Arc::new(frontend_session_auth_deadline_for_test());
    let now = tokio::time::Instant::now();
    let deadlines = [
        now + Duration::from_secs(30),
        now + Duration::from_secs(5),
        now + Duration::from_secs(15),
        now + Duration::from_secs(10),
        now + Duration::from_secs(20),
    ];
    let expected = now + Duration::from_secs(5);
    let barrier = Arc::new(Barrier::new(deadlines.len()));
    let handles: Vec<_> = deadlines
        .into_iter()
        .map(|at| {
            let auth = Arc::clone(&auth);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                publish_frontend_session_auth_deadline_for_test(&auth, at);
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("publisher thread");
    }
    assert_eq!(
        read_frontend_session_auth_deadline_for_test(&auth),
        Some(expected),
        "concurrent publishers must settle on the earliest instant"
    );
}

#[test]
fn earliest_frontend_app_send_deadline_composition() {
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(None, None),
        None,
        "no deadline only when both inputs are absent"
    );

    let session = future_deadline(Duration::from_secs(10));
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(None, Some(session)),
        Some(session)
    );
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(session), None),
        Some(session)
    );

    let earlier = future_deadline(Duration::from_secs(5));
    let later = future_deadline(Duration::from_secs(30));
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(earlier), Some(later)),
        Some(earlier)
    );
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(later), Some(earlier)),
        Some(earlier),
        "a later per-call deadline must not override an earlier session bound"
    );
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(session), Some(session)),
        Some(session),
        "equal deadlines stay unchanged"
    );
}

#[test]
fn later_per_call_deadline_cannot_extend_session_authorization() {
    let now = tokio::time::Instant::now();
    let session = now + Duration::from_secs(5);
    let later_per_call = now + Duration::from_secs(60);
    let effective =
        earliest_frontend_app_send_deadline_for_test(Some(later_per_call), Some(session));
    assert_eq!(effective, Some(session));

    let after_session = now + Duration::from_secs(10);
    assert_eq!(
        admit_frontend_app_send_for_test(false, effective, after_session),
        FrontendAppSendAdmitForTest::Expired,
        "effective deadline must honor the earlier session bound"
    );
    assert_eq!(
        admit_frontend_app_send_for_test(false, Some(later_per_call), after_session),
        FrontendAppSendAdmitForTest::Proceed,
        "sanity: per-call alone would incorrectly proceed"
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(false, effective, after_session),
        FrontendAppSendRejectForTest::Expired,
        "shutdown classification must use the same earliest bound"
    );
}

#[test]
fn queued_application_data_is_cancelled_on_deadline() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        admit_frontend_app_send_for_test(false, Some(elapsed_deadline()), now),
        FrontendAppSendAdmitForTest::Expired,
        "an already-elapsed deadline must not encrypt queued plaintext"
    );
    assert_eq!(
        admit_frontend_app_send_for_test(false, Some(now), now),
        FrontendAppSendAdmitForTest::Expired,
        "exact-deadline ties fail closed"
    );
}

#[test]
fn dropping_the_send_future_marks_the_queued_request_cancelled() {
    let (_cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    assert!(
        !frontend_app_send_cancel_fired_for_test(&mut cancel_rx),
        "a live send future must not look cancelled"
    );
    drop(_cancel_tx);
    assert!(
        frontend_app_send_cancel_fired_for_test(&mut cancel_rx),
        "dropping the proxy send future must mark the queued request cancelled"
    );
    let now = tokio::time::Instant::now();
    assert_eq!(
        admit_frontend_app_send_for_test(true, Some(future_deadline(Duration::from_secs(30))), now),
        FrontendAppSendAdmitForTest::Cancelled,
        "a cancelled queued request must not be encrypted even if the deadline has not elapsed"
    );
}

#[test]
fn shutdown_does_not_flush_expired_or_cancelled_queued_replies() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(false, Some(elapsed_deadline()), now),
        FrontendAppSendRejectForTest::Expired
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(
            true,
            Some(future_deadline(Duration::from_secs(30))),
            now
        ),
        FrontendAppSendRejectForTest::Cancelled
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(
            false,
            Some(future_deadline(Duration::from_secs(30))),
            now
        ),
        FrontendAppSendRejectForTest::Closed,
        "a leftover authorized queued reply is closed on shutdown, not flushed as a wire commit"
    );
}

#[test]
fn unauthenticated_admission_stays_unbounded() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        admit_frontend_app_send_for_test(false, None, now),
        FrontendAppSendAdmitForTest::Proceed
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(false, None, now),
        FrontendAppSendRejectForTest::Closed
    );
}

#[test]
fn reject_strings_are_bounded_and_redacted() {
    for reject in [
        FrontendAppSendRejectForTest::Expired,
        FrontendAppSendRejectForTest::Cancelled,
        FrontendAppSendRejectForTest::Closed,
    ] {
        let text = frontend_app_send_reject_as_str_for_test(reject);
        assert!(!text.is_empty());
        let lower = text.to_ascii_lowercase();
        for forbidden in [
            "notafter",
            "spiffe",
            "certificate",
            "identity",
            "bearer",
            "1970-",
            "not_before",
        ] {
            assert!(
                !lower.contains(forbidden),
                "reject string {text:?} must not carry {forbidden}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_deadline_never_polls_the_application_send() {
    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let outcome = frontend_app_ciphertext_send_until_expiry_for_test(
        Some(elapsed_deadline()),
        None,
        std::future::poll_fn(move |_| {
            polled_send.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(7usize)
        }),
    )
    .await;
    assert_eq!(outcome, Err(FrontendAppSendRejectForTest::Expired));
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed deadline must never poll socket.send_to"
    );
}

#[tokio::test(start_paused = true)]
async fn a_socket_send_wait_crossing_the_deadline_emits_nothing() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let deadline = future_deadline(Duration::from_millis(20));
    let raced = tokio::spawn(async move {
        frontend_app_ciphertext_send_until_expiry_for_test(Some(deadline), None, async move {
            let _ = release_rx.await;
            emitted_send.store(true, Ordering::SeqCst);
            1usize
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        Err(FrontendAppSendRejectForTest::Expired)
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a send_to that became ready after the deadline must not emit ciphertext"
    );
}

#[tokio::test(start_paused = true)]
async fn exact_deadline_ties_fail_closed() {
    let now = tokio::time::Instant::now();
    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let outcome = frontend_app_ciphertext_send_until_expiry_for_test(
        Some(now),
        None,
        std::future::poll_fn(move |_| {
            polled_send.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(3usize)
        }),
    )
    .await;
    assert_eq!(outcome, Err(FrontendAppSendRejectForTest::Expired));
    assert!(
        !polled.load(Ordering::SeqCst),
        "an exact-deadline tie must not poll the application send"
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_cancel_during_a_socket_wait_emits_nothing() {
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let deadline = future_deadline(Duration::from_secs(30));
    let raced = tokio::spawn(async move {
        let mut cancel_rx = cancel_rx;
        frontend_app_ciphertext_send_until_expiry_for_test(
            Some(deadline),
            Some(&mut cancel_rx),
            async move {
                let _ = release_rx.await;
                emitted_send.store(true, Ordering::SeqCst);
                1usize
            },
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    drop(cancel_tx);
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        Err(FrontendAppSendRejectForTest::Cancelled)
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "cancelling an in-flight send_to must drop it rather than emit ciphertext"
    );
}

#[tokio::test(start_paused = true)]
async fn success_completes_only_after_the_socket_accepts() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_send = Arc::clone(&accepted);
    let deadline = future_deadline(Duration::from_secs(30));
    let raced = tokio::spawn(async move {
        frontend_app_ciphertext_send_until_expiry_for_test(Some(deadline), None, async move {
            let _ = release_rx.await;
            accepted_send.store(true, Ordering::SeqCst);
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(
        !accepted.load(Ordering::SeqCst),
        "success must not complete at enqueue; the socket wait is still pending"
    );
    let _ = release_tx.send(());
    assert_eq!(raced.await.expect("join"), Ok(()));
    assert!(accepted.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_sends_have_no_timer() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let raced = tokio::spawn(async move {
        frontend_app_ciphertext_send_until_expiry_for_test(None, None, async move {
            let _ = release_rx.await;
            emitted_send.store(true, Ordering::SeqCst);
            4usize
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(86_400)).await;
    let _ = release_tx.send(());
    assert_eq!(raced.await.expect("join"), Ok(4));
    assert!(
        emitted.load(Ordering::SeqCst),
        "unauthenticated DTLS keeps the no-timer send path"
    );
}

#[test]
fn driver_and_proxy_use_the_deadline_aware_actual_commit_api() {
    assert!(
        DTLS_SOURCE.contains("pub async fn send_committed("),
        "the terminating frontend sender must expose the actual-commit API"
    );
    assert!(
        DTLS_SOURCE.contains("earliest_frontend_app_send_deadline("),
        "per-call and session deadlines must compose with earliest-deadline-wins"
    );
    assert!(
        DTLS_SOURCE.contains("struct FrontendSessionAuthDeadline"),
        "session authorization must use a monotonically-earliest lock-free slot"
    );
    assert!(
        DTLS_SOURCE.contains("compare_exchange_weak("),
        "concurrent publication must tighten via atomic compare-exchange"
    );
    assert!(
        !DTLS_SOURCE.contains("auth_deadline.set("),
        "first-set-wins OnceLock publication must not be used for session bounds"
    );
    assert!(
        !DTLS_SOURCE.contains("deadline.or(session_deadline)"),
        "Option::or prefers the per-call deadline and must not be used"
    );
    assert!(
        DTLS_SOURCE.contains("fail_queued_frontend_app_sends("),
        "shutdown must fail queued application sends rather than encrypt them"
    );
    assert!(
        !DTLS_SOURCE.contains("Drain any queued replies before"),
        "shutdown must not drain queued application replies onto the wire"
    );
    // The client-role driver also matches `_ = shutdown_rx.recv() => {`. Pin the
    // terminating-frontend arm that sits beside the demuxed `incoming_rx`.
    let shutdown_body = DTLS_SOURCE
        .split("Some(data) = incoming_rx.recv() => {")
        .next()
        .expect("incoming demux arm")
        .rsplit("_ = shutdown_rx.recv() => {")
        .next()
        .expect("server shutdown arm");
    assert!(
        shutdown_body.contains("fail_queued_frontend_app_sends("),
        "shutdown must complete queued sends as expired/cancelled/closed"
    );
    assert!(
        !shutdown_body.contains("send_application_data"),
        "shutdown must not encrypt queued application replies"
    );
    assert!(
        DTLS_SOURCE.contains("frontend_app_ciphertext_send_until_expiry("),
        "application ciphertext send_to must go through the deadline-aware helper"
    );
    assert!(
        DTLS_SOURCE.contains("struct PendingAppSend"),
        "client-side DtlsConnection completion semantics stay on PendingAppSend"
    );

    let helper = DTLS_SOURCE
        .split("pub(crate) async fn frontend_app_ciphertext_send_until_expiry")
        .nth(1)
        .expect("ciphertext helper")
        .split("\nfn fail_queued_frontend_app_sends")
        .next()
        .expect("helper body");
    let precheck = helper
        .find("admit_frontend_app_send(")
        .expect("already-elapsed admit");
    let authenticated = helper
        .split("(Some(at), None) =>")
        .nth(1)
        .expect("authenticated no-cancel arm");
    let biased = authenticated.find("biased;").expect("biased");
    let expiry = authenticated
        .find("tokio::time::sleep_until(at)")
        .expect("expiry arm");
    let send_arm = authenticated.find("result = send =>").expect("send arm");
    assert!(
        precheck < helper.find("(Some(at), None) =>").expect("arm"),
        "an elapsed deadline is refused before polling send"
    );
    assert!(
        biased < expiry && expiry < send_arm,
        "expiry is biased first so exact-deadline ties fail closed"
    );
    assert!(
        !helper.contains("timeout_at("),
        "timeout_at would poll the inner send first"
    );
    assert!(
        helper.contains("(None, None) => Ok(send.await)"),
        "unauthenticated sends await with no timer"
    );

    let dtls_inner = UDP_PROXY_SOURCE
        .split("async fn handle_dtls_client_inner(")
        .nth(1)
        .expect("dtls inner");
    assert!(dtls_inner.contains("client_sender.send_committed("));
    assert!(dtls_inner.contains("bind_authorization_deadline(plan.at)"));
    assert!(!dtls_inner.contains("client_sender.send(&data)"));
    let send_call = dtls_inner
        .split("client_sender.send_committed(")
        .nth(1)
        .expect("commit call");
    assert!(
        send_call.contains("reply_auth_plan.map(|plan| plan.at)"),
        "the proxy must pass the admitted deadline into the actual-commit API"
    );
}

/// Established-session trust withdrawal must not emit the post-loop packet
/// drain when the session authorization deadline is still in the future
/// (issue #3857). Ordinary shutdown still flushes protocol records unless
/// that deadline has elapsed.
#[test]
fn trust_withdrawal_suppresses_final_packet_drain_while_deadline_unexpired() {
    let select_body = DTLS_SOURCE
        .split("tokio::select! {")
        .find(|body| body.contains("Frontend client-certificate trust withdrawn (issue"))
        .expect("DTLS session select");
    let biased = select_body.find("biased;").expect("biased DTLS select");
    let retirement = select_body
        .find("Some(guard) => guard.session().retired().await")
        .expect("trust-retirement arm");
    let application = select_body
        .find("Some(pending) = app_in_rx.recv()")
        .expect("application-send arm");
    assert!(
        biased < retirement && retirement < application,
        "an already-ready trust withdrawal must win over queued application data"
    );

    let trust_race = DTLS_SOURCE
        .split("async fn frontend_trust_raced_delivery<F>(")
        .nth(1)
        .expect("trust-raced delivery helper")
        .split("async fn frontend_app_ciphertext_send_until_expiry_and_trust")
        .next()
        .expect("trust-raced helper body");
    let none_path = trust_race
        .find("return Ok(op.await)")
        .expect("unauthenticated path");
    let precheck = trust_race.find("session.is_retired()").expect("precheck");
    let biased = trust_race.find("biased;").expect("biased delivery race");
    let retirement = trust_race
        .find("session.retired()")
        .expect("retirement race");
    let op_arm = trust_race.find("result = op =>").expect("delivery arm");
    assert!(
        none_path < precheck && precheck < biased && biased < retirement && retirement < op_arm,
        "trust retirement must fence both an already-retired session and an in-flight delivery without polling a retirement future when unauthenticated"
    );

    let ciphertext = DTLS_SOURCE
        .split("async fn frontend_app_ciphertext_send_until_expiry_and_trust")
        .nth(1)
        .expect("trust-fenced ciphertext helper")
        .split("fn fail_queued_frontend_app_sends")
        .next()
        .expect("trust-fenced helper body");
    assert!(
        ciphertext.contains("frontend_trust_raced_delivery("),
        "application ciphertext send_to must reuse the shared trust-raced delivery helper"
    );
    assert!(
        DTLS_SOURCE.contains("frontend_app_ciphertext_send_until_expiry_and_trust("),
        "the production DTLS wire-commit path must use the trust-fenced helper"
    );

    let handshake_udp = DTLS_SOURCE
        .split("if !connected {")
        .nth(1)
        .expect("post-registration handshake UDP")
        .split("match write_connected_frontend_record(")
        .next()
        .expect("handshake UDP body");
    assert!(
        handshake_udp.contains("frontend_trust_raced_delivery("),
        "post-registration handshake UDP writes must observe trust retirement"
    );

    let accept_site = DTLS_SOURCE
        .split("let conn = DtlsServerConn {")
        .nth(1)
        .expect("accepted connection")
        .split("Output::PeerCert(der)")
        .next()
        .expect("accept arm");
    assert!(
        accept_site.contains("frontend_trust_raced_delivery("),
        "accepted-connection delivery must observe trust retirement"
    );
    assert!(
        accept_site.contains("accept_tx.send((conn, peer_addr))"),
        "the accept channel is still the delivery path"
    );
    assert!(
        !accept_site.contains("accept_tx.send((conn, peer_addr)).await.is_err()"),
        "accept_tx.send must not await outside the trust-retirement race"
    );

    let frontend_driver = DTLS_SOURCE
        .split("let mut client_trust_guard: Option<crate::tls::ClientTrustSessionGuard> = None;")
        .nth(1)
        .expect("frontend session driver")
        .split("pub async fn close(")
        .next()
        .expect("frontend session body");
    let app_data_arm = frontend_driver
        .split("Output::ApplicationData(data)")
        .nth(1)
        .expect("application-data arm")
        .split("Output::")
        .next()
        .expect("application-data arm body");
    assert!(
        app_data_arm.contains("frontend_trust_raced_delivery("),
        "plaintext application delivery must observe trust retirement"
    );
    assert!(
        app_data_arm.contains("app_out_tx.send(data.to_vec())"),
        "plaintext still goes through the proxy delivery channel"
    );
    assert!(
        !app_data_arm.contains("if app_out_tx.send(data.to_vec()).await.is_err()"),
        "app_out_tx.send must not await in a match guard outside the trust-retirement race"
    );

    // Window = the withdrawal arm's BODY (from its warn! literal to its
    // `break;`). The old markers ("Frontend client-certificate trust
    // withdrawn" comment → "Shutdown signal" comment) span the whole biased
    // select, so the ordinary app-data arm that legitimately calls
    // `send_application_data` (behind its own `is_retired()` fence) sat inside
    // the scanned text and failed the negative asserts spuriously.
    let established_arm = DTLS_SOURCE
        .split(
            "\"Retiring established DTLS session: frontend client-certificate \
             trust was withdrawn\"",
        )
        .nth(1)
        .expect("established-session trust-withdrawal arm")
        .split("break;")
        .next()
        .expect("trust-withdrawal arm body");
    assert!(
        established_arm.contains("retired_by_trust_withdrawal = true"),
        "trust withdrawal must record an explicit termination reason before break"
    );
    assert!(
        established_arm.contains("fail_queued_frontend_app_sends("),
        "trust withdrawal must fail queued application sends rather than encrypt them"
    );
    assert!(
        !established_arm.contains("send_application_data"),
        "trust withdrawal must not encrypt queued application replies"
    );
    assert!(
        !established_arm.contains("send_to"),
        "the retirement arm itself must not drain packets onto the wire"
    );
    assert!(
        !established_arm.contains("send_dtls_record"),
        "the retirement arm must not drain packets from the pinned source either"
    );

    let post_loop = DTLS_SOURCE
        .split("let discard_final_packets")
        .nth(1)
        .expect("post-loop drain predicate")
        .split("pub async fn close(")
        .next()
        .expect("final packet drain");
    let squeezed: String = post_loop.split_whitespace().collect();
    assert!(
        squeezed.contains(
            "=retired_by_trust_withdrawal||session_authorization_elapsed(&auth_deadline)"
        ),
        "trust withdrawal must suppress the final drain even when the session deadline has not elapsed"
    );
    assert!(
        post_loop.contains("if discard_final_packets"),
        "the final drain must honor the combined trust-withdrawal / deadline predicate"
    );
    assert!(
        post_loop.contains("send_dtls_record(&socket, data, peer_addr, reply_local)"),
        "ordinary shutdown still flushes protocol records when the deadline has not elapsed, \
         and from the session's pinned reply source"
    );
    assert!(
        !post_loop.contains("socket.send_to(data, peer_addr)"),
        "a generated NodeWaypoint listener must never fall back to a route-selected reply source"
    );

    let shutdown_body = DTLS_SOURCE
        .split("Some(data) = incoming_rx.recv() => {")
        .next()
        .expect("incoming demux arm")
        .rsplit("_ = shutdown_rx.recv() => {")
        .next()
        .expect("server shutdown arm");
    assert!(
        !shutdown_body.contains("retired_by_trust_withdrawal = true"),
        "ordinary shutdown must not reuse the trust-withdrawal termination reason"
    );
}

/// Post-accept application-send refusal must not double-count the fenced
/// counter: the detached handler's `DtlsClientTrustFence` latch owns stream
/// accounting for accepted connections (issue #3857).
#[test]
fn connected_application_send_refuses_without_direct_fence_accounting() {
    let connected_send_arm = DTLS_SOURCE
        .split("Some(pending) = app_in_rx.recv(), if connected => {")
        .nth(1)
        .expect("connected application-send arm")
        .split("match admit_frontend_app_send(")
        .next()
        .expect("connected application-send arm body");
    assert!(
        connected_send_arm.contains("session.is_retired()"),
        "the connected send gate must still fail closed on trust withdrawal"
    );
    assert!(
        connected_send_arm.contains("fail_queued_frontend_app_sends("),
        "the connected send gate must still fail queued application sends"
    );
    assert!(
        !connected_send_arm.contains("session.record_fenced()"),
        "post-accept send refusal must not increment the fence counter; the \
         accepted handler's once-only latch owns stream accounting"
    );

    for (marker, label) in [
        (
            "Output::Connected => {",
            "the Connected pre-handoff fence before accept()",
        ),
        (
            "client_trust_guard.is_none()",
            "the registration re-check inside the handshake drain",
        ),
    ] {
        let site = DTLS_SOURCE
            .split(marker)
            .nth(1)
            .expect(label)
            .split("session.record_fenced()")
            .next()
            .expect(label);
        assert!(
            site.contains("session.is_retired()"),
            "{label} must still consult the withdrawal fence"
        );
    }
    assert_eq!(
        DTLS_SOURCE.matches("session.record_fenced()").count(),
        2,
        "only pre-accept driver sites may record the fence counter directly"
    );
}

/// A refused frontend DTLS client certificate must not complete the handshake.
///
/// dimpl's DTLS 1.2 server queues ChangeCipherSpec+Finished and only THEN
/// pushes `Connected` onto the local-event queue that `poll_output` pops first,
/// so at both refusal sites the server final flight exists but is unsent. A
/// refusal that drains `poll_output` onto the socket therefore delivers that
/// flight, the peer reaches `SSL_is_init_finished`, and an unauthenticated
/// client observes an ESTABLISHED session before the alert queued behind it
/// arrives. Pin the discard-before-write order, the fail-closed bailout when the
/// bounded discard does not reach the end of the queue, and the pinned reply
/// source. `tests/integration/dtls_integration_tests.rs` proves the wire
/// outcome; this proves no refusal site can reintroduce the drain.
#[test]
fn refused_dtls_handshakes_never_commit_the_server_final_flight() {
    let helper = DTLS_SOURCE
        .split("async fn refuse_dtls_handshake(")
        .nth(1)
        .expect("handshake refusal helper")
        .split("// Sans-IO Helpers")
        .next()
        .expect("handshake refusal helper body");
    let discard = helper.find("Output::Timeout(_)").expect("queue discard");
    let bail = helper.find("if !queue_drained {").expect("bailout");
    let close = helper.find("dtls.close()").expect("alert");
    let write = helper
        .find("send_dtls_record(socket, data, peer_addr, reply_local)")
        .expect("pinned refusal write");
    assert!(
        discard < bail && bail < close && close < write,
        "a refusal must discard every queued record, bail out when that discard did not \
         reach the end of the queue, and only then queue and write its own alert"
    );
    assert!(
        !helper.contains("socket.send_to("),
        "refusal datagrams must leave from the session's pinned reply source"
    );
    let discard_arm = &helper[discard..close];
    assert!(
        !discard_arm.contains("send_dtls_record") && !discard_arm.contains("send_to"),
        "the discard pass must drop queued records rather than write them"
    );

    for (marker, site) in [
        (
            "\"DTLS frontend mTLS required but client presented no verified certificate; \
             dropping session\"",
            "an unauthenticated peer under a configured client verifier",
        ),
        (
            "warn!(client = %peer_addr, \"Client cert validation failed: {}\", e);",
            "a client chain the configured verifier refuses",
        ),
    ] {
        let gate = DTLS_SOURCE
            .split(marker)
            .nth(1)
            .and_then(|tail| tail.split("return;").next())
            .unwrap_or_else(|| panic!("no refusal site found for {site}"));
        assert!(
            gate.contains("refuse_dtls_handshake("),
            "{site} must be refused through the discard-first helper"
        );
        assert!(
            gate.contains("reply_local"),
            "{site} must refuse from the session's pinned reply source"
        );
        assert!(
            !gate.contains("accept_tx.send") && !gate.contains("app_out_tx.send"),
            "{site} must never reach accept or application delivery"
        );
    }

    assert!(
        !DTLS_SOURCE.contains("abort_dtls_handshake"),
        "the drain-and-forward abort helper must not come back"
    );
}

/// After a refused client certificate, flight-5 retransmits are still handshake
/// records (`content-type 0x16`). Spawning a session on any such record reserved
/// a handshake-timeout slot for a half-open engine that then swallowed a later
/// ClientHello at the same UDP 4-tuple. Pin the demux gate to the ClientHello
/// predicate and the Closed-arm re-dispatch of an opening datagram.
#[test]
fn dtls_demux_opens_sessions_only_on_client_hello() {
    let dispatch = DTLS_SOURCE
        .split("} else if dtls_datagram_opens_session(data) {")
        .nth(1)
        .expect("ClientHello demux spawn arm")
        .split("fn spawn_session(")
        .next()
        .expect("spawn_session follows demux");
    assert!(
        dispatch.contains(
            "self.spawn_session(peer_addr, data.to_vec(), reply_local, forwarded_client);"
        ),
        "a ClientHello from an unknown peer must still spawn a session"
    );
    assert!(
        !dispatch.contains("data[0] == 0x16"),
        "content-type 0x16 alone must not open a session: Certificate/Finished retransmits \
         are also handshake records"
    );

    let closed = DTLS_SOURCE
        .split("Err(mpsc::error::TrySendError::Closed(data)) => {")
        .nth(1)
        .expect("Closed-arm re-dispatch")
        .split("} else if dtls_datagram_opens_session(data) {")
        .next()
        .expect("Closed arm ends before unknown-peer spawn");
    assert!(
        closed.contains("dtls_datagram_opens_session(&data)"),
        "a ClientHello that raced driver teardown must be eligible to start a replacement"
    );
    assert!(
        closed.contains("self.sessions.get(&peer_addr).is_none()"),
        "Closed-arm re-dispatch must not replace a newer generation already in the map"
    );
    assert!(
        closed.contains("self.spawn_session(peer_addr, data, reply_local, forwarded_client);"),
        "Closed-arm re-dispatch of a ClientHello must spawn rather than drop the opening flight"
    );
}

fn registered_frontend_dtls_session() -> ferrum_edge::tls::ClientTrustSessionGuard {
    client_trust::arm_at_generation_for_test(ClientTrustScope::FrontendDtls, 1);
    client_trust::capture(ClientTrustScope::FrontendDtls)
        .expect("armed")
        .register(true)
        .expect("registered")
}

#[tokio::test]
async fn unauthenticated_delivery_does_not_poll_a_retirement_future() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    tx.try_send(b"held".to_vec()).expect("fill channel");
    let raced = tokio::spawn(async move {
        frontend_trust_raced_delivery_for_test(None, tx.send(b"payload".to_vec())).await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(
        !raced.is_finished(),
        "unauthenticated DTLS must wait on a full channel instead of polling retirement"
    );
    assert_eq!(rx.recv().await.expect("held"), b"held".to_vec());
    assert_eq!(
        raced.await.expect("join"),
        Ok(Ok(())),
        "unauthenticated delivery completes once capacity exists"
    );
    assert_eq!(rx.recv().await.expect("payload"), b"payload".to_vec());
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // isolated_registry() must span awaits to serialize process-global registry state
async fn already_retired_session_wins_an_exact_ready_tie_without_delivering() {
    let _registry = crate::unit::client_trust_registry_lock::isolated_registry();
    let guard = registered_frontend_dtls_session();
    let session = guard.session().clone();
    session.cancellation_token().cancel();

    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let outcome = frontend_trust_raced_delivery_for_test(Some(&session), async move {
        polled_send.store(true, Ordering::SeqCst);
        tx.send(b"payload".to_vec()).await
    })
    .await;
    assert_eq!(outcome, Err(FrontendAppSendRejectForTest::Closed));
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-ready retirement must never poll the delivery future"
    );
    assert!(
        rx.try_recv().is_err(),
        "an exact-ready tie must not deliver application plaintext"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // isolated_registry() must span awaits to serialize process-global registry state
async fn a_full_channel_delivery_is_released_by_trust_withdrawal_without_delivering() {
    let _registry = crate::unit::client_trust_registry_lock::isolated_registry();
    let guard = registered_frontend_dtls_session();
    let session = guard.session().clone();
    let session_for_task = session.clone();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    tx.try_send(b"held".to_vec()).expect("fill channel");
    let raced = tokio::spawn(async move {
        frontend_trust_raced_delivery_for_test(
            Some(&session_for_task),
            tx.send(b"payload".to_vec()),
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(
        !raced.is_finished(),
        "a full delivery channel must park until retirement or capacity"
    );
    session.cancellation_token().cancel();
    assert_eq!(
        raced.await.expect("join"),
        Err(FrontendAppSendRejectForTest::Closed)
    );
    assert_eq!(rx.try_recv().expect("held"), b"held".to_vec());
    assert!(
        rx.try_recv().is_err(),
        "trust withdrawal must drop the in-flight send rather than deliver plaintext"
    );
}
