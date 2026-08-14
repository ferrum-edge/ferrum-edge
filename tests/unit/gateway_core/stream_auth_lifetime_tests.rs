//! Protocol-neutral authorization lifetime for admitted streams (issue #3815).
//!
//! These cover the arbiter itself — earliest-deadline-wins, the finite fallback
//! maximum for credentials with no authoritative expiry, the unauthenticated
//! carve-out, non-extension by activity — plus the bounded termination classes
//! and the fixed-cardinality counter surface.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::_test_support::{
    BufferedUploadWaitOutcomeForTest, DtlsAuthorizationExpiryForTest, EarlyUploadBoundKind,
    H3AuthorizedHeadersWrite, H3BackendOrPeerForTest, H3UploadWaitOutcomeForTest,
    PrecommitPhaseOutcomeForTest, ProbePumpOutcome, ProbeTransportPoll,
    ResponseCollectBoundForTest, StreamIoSide, UploadPumpProbe,
    attribute_dispatch_phase_bound_for_test, authorization_bounded_header_deadline_for_test,
    authorization_expired_dispatch_placeholder_for_test,
    authorization_expired_pre_commitment_response_for_test,
    await_authorized_headers_write_for_test, await_deadline_first_for_test,
    await_h3_backend_or_peer_for_test, await_precommit_response_phase_for_test,
    bidirectional_copy_with_authorization_for_test,
    collect_buffered_upload_under_authorization_for_test,
    collect_buffered_upload_under_composed_bound_for_test,
    collect_h3_upload_under_authorization_for_test, compose_aggregate_sse_bound_for_test,
    compose_buffered_upload_bound_for_test, compose_dispatch_phase_bound_for_test,
    compose_h3_upload_bound_for_test, compose_precommit_response_phase_bound_for_test,
    direct_h2_upload_join_bound_for_test, dispatch_phase_authorization_expiry_for_test,
    dtls_authorization_expired_before_relay_for_test,
    dtls_setup_stage_under_authorization_for_test, precommit_authorization_gate_for_test,
    relay_failure_is_client_facing, request_received_at_for_test,
    request_upload_auth_deadline_for_test, set_grpc_deadline_budget_for_test,
    set_request_credential_deadline_for_test, settle_dtls_relay_authorization_expiry_for_test,
    tcp_plain_splice_eligible_for_test, within_stream_auth_deadline_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::{Direction, DisconnectCause, RequestContext};
use ferrum_edge::proxy::auth_lifetime::{
    ComposedAuthBound, StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination,
    StreamAuthTerminationLatch, counters, effective_request_auth_deadline,
    effective_stream_auth_deadline, expired_authorization, record_termination,
    request_is_authenticated,
};
use ferrum_edge::proxy::stream_error::StreamSetupKind;
use ferrum_edge::retry::ErrorClass;

const DEFAULT_MAX: u64 = 3_600;

fn consumer(username: &str) -> Arc<Consumer> {
    Arc::new(Consumer {
        id: username.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: std::collections::HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
}

fn anonymous_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/sse".to_string(),
    )
}

fn authenticated_ctx() -> RequestContext {
    let mut ctx = anonymous_ctx();
    ctx.identified_consumer = Some(consumer("alice"));
    ctx
}

// --- The arbiter -----------------------------------------------------------

#[tokio::test]
async fn unauthenticated_streams_are_not_bounded_by_this_contract() {
    let ctx = anonymous_ctx();
    assert!(!request_is_authenticated(&ctx));
    assert!(effective_request_auth_deadline(&ctx, DEFAULT_MAX).is_none());
}

#[tokio::test]
async fn an_external_identity_alone_is_an_authenticated_principal() {
    let mut ctx = anonymous_ctx();
    ctx.authenticated_identity = Some("spiffe://example/sa/api".to_string());
    assert!(request_is_authenticated(&ctx));
    assert!(effective_request_auth_deadline(&ctx, DEFAULT_MAX).is_some());
}

#[tokio::test]
async fn credential_deadline_wins_when_earlier_than_the_fallback_maximum() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(30)));

    let plan = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(plan.at, received_at + Duration::from_secs(30));
}

#[tokio::test]
async fn fallback_maximum_bounds_a_credential_without_authoritative_expiry() {
    // `key_auth` / `basic_auth` / `hmac_auth` / LDAP shape: authenticated, but
    // no provider-supplied expiry. There must still be a finite bound.
    let ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);

    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(
        plan.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(plan.at, received_at + Duration::from_secs(900));
}

#[tokio::test]
async fn fallback_maximum_wins_when_the_credential_outlives_it() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(received_at + Duration::from_secs(7_200)),
    );

    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(
        plan.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(plan.at, received_at + Duration::from_secs(900));
}

#[tokio::test]
async fn an_exactly_equal_credential_deadline_is_attributed_to_the_credential() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(received_at + Duration::from_secs(900)),
    );

    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
}

#[tokio::test]
async fn an_already_elapsed_credential_deadline_stays_in_the_past() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    let elapsed = received_at
        .checked_sub(Duration::from_secs(1))
        .expect("representable");
    set_request_credential_deadline_for_test(&mut ctx, Some(elapsed));

    let plan = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(plan.at, elapsed);
}

#[tokio::test(start_paused = true)]
async fn activity_never_extends_the_deadline() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(30)));

    let first = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");
    // Simulate a continuously active stream: time advances, the request context
    // is re-consulted, and the answer must be the same absolute instant.
    tokio::time::advance(Duration::from_secs(20)).await;
    let later = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");

    assert_eq!(first.at, later.at);
    assert_eq!(first.termination, later.termination);
}

#[tokio::test(start_paused = true)]
async fn the_fallback_maximum_is_anchored_at_request_receipt_not_at_evaluation() {
    let ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);

    // A slow request must not buy extra authorized lifetime.
    tokio::time::advance(Duration::from_secs(120)).await;
    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(plan.at, received_at + Duration::from_secs(900));
}

// --- Stream (TCP/TLS, UDP/DTLS) sessions -----------------------------------

#[tokio::test]
async fn unauthenticated_stream_sessions_are_not_bounded() {
    let anchor = tokio::time::Instant::now();
    assert!(effective_stream_auth_deadline(false, None, anchor, DEFAULT_MAX).is_none());
    // Even with a deadline present, an unauthenticated session is out of scope.
    assert!(
        effective_stream_auth_deadline(
            false,
            Some(anchor + Duration::from_secs(5)),
            anchor,
            DEFAULT_MAX
        )
        .is_none()
    );
}

#[tokio::test]
async fn stream_sessions_take_the_earlier_of_certificate_expiry_and_the_maximum() {
    let anchor = tokio::time::Instant::now();

    let cert = effective_stream_auth_deadline(
        true,
        Some(anchor + Duration::from_secs(45)),
        anchor,
        DEFAULT_MAX,
    )
    .expect("authenticated");
    assert_eq!(cert.termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(cert.at, anchor + Duration::from_secs(45));

    let capped = effective_stream_auth_deadline(true, None, anchor, 60).expect("authenticated");
    assert_eq!(
        capped.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(capped.at, anchor + Duration::from_secs(60));
}

// --- Bounded, redacted vocabulary ------------------------------------------

#[test]
fn termination_classes_are_a_closed_set_of_compiled_in_literals() {
    assert_eq!(
        StreamAuthTermination::CredentialExpired.as_str(),
        "credential_expired"
    );
    assert_eq!(
        StreamAuthTermination::AuthenticatedStreamMaxLifetime.as_str(),
        "authenticated_stream_max_lifetime"
    );
}

#[test]
fn client_visible_messages_never_carry_credential_or_expiry_detail() {
    // Match the `exp` claim as a field/token rather than as a raw substring:
    // the fixed, non-sensitive word "expired" is intentionally client-visible.
    let forbidden = [
        "\"exp\"",
        "exp=",
        "exp:",
        "exp ",
        "notAfter",
        "not_after",
        "notBefore",
        "sub",
        "jwt",
        "token",
        "issuer",
        "cert",
        "serial",
        "@",
        "spiffe",
    ];
    for termination in [
        StreamAuthTermination::CredentialExpired,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    ] {
        for message in [
            termination.grpc_message(),
            termination.post_commit_message(),
            termination.as_str(),
        ] {
            let lowered = message.to_ascii_lowercase();
            for needle in forbidden {
                assert!(
                    !lowered.contains(&needle.to_ascii_lowercase()),
                    "{message:?} must not leak {needle:?}"
                );
            }
            // No digits: an expiry value or a timestamp could only appear as one.
            assert!(
                !message.chars().any(|c| c.is_ascii_digit()),
                "{message:?} must not carry a numeric value"
            );
        }
    }
}

#[test]
fn protocol_families_are_a_fixed_closed_inventory() {
    let families = [
        StreamAuthProtocolFamily::Http,
        StreamAuthProtocolFamily::Grpc,
        StreamAuthProtocolFamily::GrpcWeb,
        StreamAuthProtocolFamily::StreamTcp,
        StreamAuthProtocolFamily::StreamUdp,
    ];
    let names: Vec<&str> = families.iter().map(|f| f.as_str()).collect();
    assert_eq!(
        names,
        vec!["http", "grpc", "grpc_web", "stream_tcp", "stream_udp"]
    );
}

#[test]
fn counters_expose_every_family_and_only_those_families() {
    let snapshot = counters();
    let expected = ["http", "grpc", "grpc_web", "stream_tcp", "stream_udp"];
    assert_eq!(snapshot.credential_expired.len(), expected.len());
    assert_eq!(
        snapshot.authenticated_stream_max_lifetime.len(),
        expected.len()
    );
    for family in expected {
        assert!(snapshot.credential_expired.contains_key(family));
        assert!(
            snapshot
                .authenticated_stream_max_lifetime
                .contains_key(family)
        );
    }
}

/// Serializes every test that asserts an EXACT delta on the process-global
/// termination counters against every test that records one through a
/// production path. The counters carry no test dimension (that is the point of
/// their fixed cardinality), so without this the binary's default parallelism
/// could interleave two `stream_udp` increments inside one before/after pair.
static COUNTER_DELTA_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Serialize every exact-delta assertion over the process-global termination
/// counters, so a concurrent test in the same binary cannot be observed inside
/// another test's `before`/`after` window.
///
/// Deliberately an ASYNC mutex: several of these tests must hold the guard
/// across `.await` points (the whole point is that the awaited work is what
/// moves the counter), and a `std::sync::MutexGuard` held across an await is
/// both a clippy error here and a real cross-runtime hazard.
async fn counter_delta_guard() -> tokio::sync::MutexGuard<'static, ()> {
    COUNTER_DELTA_GUARD.lock().await
}

#[tokio::test]
async fn recording_a_termination_increments_only_its_own_class_and_family() {
    let _guard = counter_delta_guard().await;
    // Process-global monotonic counters: compare deltas, never absolutes, so
    // this stays correct alongside other tests in the same binary.
    let before = counters();
    record_termination(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::StreamUdp,
    );
    let after = counters();

    assert_eq!(
        after.credential_expired["stream_udp"] - before.credential_expired["stream_udp"],
        1
    );
    assert_eq!(
        after.authenticated_stream_max_lifetime["stream_udp"],
        before.authenticated_stream_max_lifetime["stream_udp"]
    );
    // The counter carries no dimension other than the family, so recording one
    // family cannot move another. `stream_tcp` is the witness deliberately:
    // this guard only serializes tests in THIS file, and the body-termination
    // suite in the same binary records `http`, `grpc`, and `grpc_web` through
    // production paths that never take it.
    assert_eq!(
        after.credential_expired["stream_tcp"],
        before.credential_expired["stream_tcp"]
    );
}

#[test]
fn the_runtime_metrics_snapshot_serializes_without_any_unbounded_label() {
    let snapshot = counters();
    let json = serde_json::to_value(&snapshot).expect("serializable");
    let object = json.as_object().expect("object");
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            &"authenticated_stream_max_lifetime".to_string(),
            &"credential_expired".to_string()
        ]
    );
}

// --- kTLS fallback for deadline-bearing stream sessions (issue #3816) -------
//
// A kernel-TLS frontend leg is relayed by `splice(2)`: the kernel owns both
// sockets, so the relay cannot be wrapped by `AuthorizationDeadlineStream`, and
// after `dangerous_into_kernel_connection` there is no safe conversion back to a
// userspace rustls session. The handoff is therefore refused BEFORE the
// handshake for any listener whose plugin chain can admit an authenticated
// principal, and such a connection is relayed normally on the buffered
// userspace path where the deadline IS enforceable.

fn mtls_auth_plugin() -> Arc<dyn ferrum_edge::plugins::Plugin> {
    Arc::new(
        ferrum_edge::plugins::mtls_auth::MtlsAuth::new(&serde_json::json!({
            "cert_field": "subject_cn"
        }))
        .expect("valid mtls_auth config"),
    )
}

fn observability_plugin() -> Arc<dyn ferrum_edge::plugins::Plugin> {
    Arc::new(
        ferrum_edge::plugins::correlation_id::CorrelationId::new(&serde_json::json!({}))
            .expect("valid correlation_id config"),
    )
}

#[test]
fn mtls_auth_declares_that_it_admits_an_authenticated_stream_principal() {
    assert!(
        mtls_auth_plugin().admits_authenticated_stream_principal(),
        "mtls_auth maps a client certificate to a consumer and contributes the leaf notAfter \
         as the session authorization deadline, so it must keep a listener off the kTLS path"
    );
}

#[test]
fn an_ordinary_stream_plugin_does_not_declare_a_stream_principal() {
    assert!(!observability_plugin().admits_authenticated_stream_principal());
}

#[test]
fn a_listener_with_mtls_auth_is_kept_off_the_ktls_handoff() {
    let plugins = vec![observability_plugin(), mtls_auth_plugin()];
    assert!(
        !ferrum_edge::_test_support::ktls_handoff_eligible_for_test(true, false, false, &plugins),
        "an mTLS-authenticated TCP+TLS listener must stay on the buffered userspace path so its \
         admitted session can be bounded by the certificate deadline"
    );
}

#[test]
fn the_ktls_fast_path_survives_for_listeners_that_cannot_admit_a_principal() {
    let plugins = vec![observability_plugin()];
    assert!(ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true, false, false, &plugins
    ));
    assert!(ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true,
        false,
        false,
        &[] as &[Arc<dyn ferrum_edge::plugins::Plugin>]
    ));
}

#[test]
fn the_pre_existing_ktls_refusals_are_unchanged() {
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = Vec::new();
    // opt-in off
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        false, false, false, &plugins
    ));
    // TLS backend: splice needs both ends raw
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true, true, false, &plugins
    ));
    // decrypted first-bytes inspection already took plaintext out of the session
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true, false, true, &plugins
    ));
}

#[test]
fn the_authenticated_ktls_defensive_path_fails_closed_without_a_debug_panic() {
    let src = include_str!("../../../src/proxy/tcp_proxy.rs");
    let arm = src
        .split("ClientRelayStream::Ktls(..) if stream_auth_deadline.is_some() => {")
        .nth(1)
        .expect("authenticated kTLS defensive arm");
    let arm_body = arm
        .split("ClientRelayStream::Tls(tls_stream) => {")
        .next()
        .expect("authenticated kTLS arm bounded");
    assert!(
        !arm_body.contains("debug_assert!(false"),
        "the defensive authenticated-kTLS path must fail closed without a debug panic"
    );
    assert!(
        arm_body.contains("authenticated_ktls_relay_fail_closed()"),
        "the defensive path must use the fixed fail-closed helper"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn an_authenticated_ktls_frontend_leg_fails_closed_without_relaying_bytes() {
    use ferrum_edge::_test_support::authenticated_ktls_relay_fail_closed_for_test;
    use ferrum_edge::plugins::Direction;

    let result = authenticated_ktls_relay_fail_closed_for_test();
    assert_eq!(result.bytes_client_to_backend, 0);
    assert_eq!(result.bytes_backend_to_client, 0);
    let (direction, _class, side, message) = result
        .first_failure
        .as_ref()
        .expect("defensive authenticated-kTLS path must surface a typed failure");
    assert_eq!(*direction, Direction::Unknown);
    assert!(side.is_none());
    assert!(
        message.contains(
            "kTLS client leg cannot carry an authenticated stream authorization deadline"
        ),
        "failure must use the fixed fail-closed diagnostic, got: {message}"
    );
}

// --- The deadline-aware userspace frontend leg -----------------------------

/// The relay wrapper terminates BOTH directions of a continuously active
/// session at the absolute deadline, and relayed bytes never push it out.
#[tokio::test(start_paused = true)]
async fn the_userspace_frontend_leg_terminates_both_directions_at_the_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let expired = Arc::new(AtomicBool::new(false));
    let deadline_at = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut leg = ferrum_edge::_test_support::authorization_deadline_stream_for_test(
        client,
        deadline_at,
        Arc::clone(&expired),
    );

    // Continuous traffic BEFORE the deadline keeps working in both directions.
    for _ in 0..8 {
        leg.write_all(b"ping").await.expect("write before deadline");
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).await.expect("peer read");
        peer.write_all(b"pong").await.expect("peer write");
        let mut back = [0u8; 4];
        leg.read_exact(&mut back)
            .await
            .expect("read before deadline");
        assert_eq!(&back, b"pong");
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(
        !expired.load(Ordering::Acquire),
        "relayed bytes must never refresh an absolute authorization deadline, but they also \
         must not trip it early"
    );

    // Cross the deadline. Both halves now fail, deterministically and with a
    // fixed, credential-free `TimedOut` classification.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let read_err = leg
        .read(&mut [0u8; 4])
        .await
        .expect_err("read after deadline");
    assert_eq!(read_err.kind(), std::io::ErrorKind::TimedOut);
    let write_err = leg.write(b"ping").await.expect_err("write after deadline");
    assert_eq!(write_err.kind(), std::io::ErrorKind::TimedOut);
    assert!(expired.load(Ordering::Acquire));

    // Nothing credential-bearing reaches the classifier or the debug log.
    let message = read_err.to_string();
    assert!(!message.contains("alice"));
    assert!(!message.contains("notAfter"));
    assert!(!message.to_ascii_lowercase().contains("cert"));

    // Shutdown is always allowed through: it is the teardown the deadline is
    // trying to reach, so refusing it would leave the socket half-open.
    leg.shutdown().await.expect("shutdown after deadline");
}

/// Backend that accepts the first non-empty write (level-triggered progress)
/// and then parks forever on both halves. c2b therefore stays in `Writing`
/// without polling the wrapped client leg; b2c parks on `poll_read`.
struct StallAfterAcceptingWrite {
    progress: tokio::sync::watch::Sender<u64>,
}

impl tokio::io::AsyncRead for StallAfterAcceptingWrite {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl tokio::io::AsyncWrite for StallAfterAcceptingWrite {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if *this.progress.borrow() > 0 {
            return std::task::Poll::Pending;
        }
        let n = buf.len().min(1);
        if n == 0 {
            return std::task::Poll::Ready(Ok(0));
        }
        this.progress.send_replace(n as u64);
        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// A backend write stall after a client chunk is buffered must still terminate
/// at the authorization deadline with ordinary relay timeouts disabled.
///
/// Once `bidirectional_copy` has a client chunk, that direction parks on
/// backend `poll_write`; the other direction parks on backend `poll_read`.
/// Neither polls the wrapped client leg, so only a top-level authorization
/// timer can latch expiry. The fast path is refused because first-failure
/// direction is the typed client-side `TimedOut`, not `Unknown`.
#[tokio::test(start_paused = true)]
async fn a_stalled_backend_write_cannot_starve_the_tcp_authorization_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::AsyncWriteExt;

    let _guard = counter_delta_guard().await;
    let before = counters();

    let (client, mut client_peer) = tokio::io::duplex(64 * 1024);
    let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(0u64);
    let backend = StallAfterAcceptingWrite {
        progress: progress_tx,
    };
    let expired = Arc::new(AtomicBool::new(false));
    let deadline_at = tokio::time::Instant::now() + Duration::from_secs(2);
    client_peer
        .write_all(&[0xab; 1024])
        .await
        .expect("buffer a client chunk before the backend write stalls");

    let copy = tokio::spawn(bidirectional_copy_with_authorization_for_test(
        client,
        backend,
        deadline_at,
        Arc::clone(&expired),
        8 * 1024,
    ));
    progress_rx
        .wait_for(|n| *n > 0)
        .await
        .expect("the copy must accept the buffered client chunk onto a stalled backend write");
    let accepted = *progress_rx.borrow();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), copy)
        .await
        .expect("authorization expiry must terminate both relay halves")
        .expect("copy task");

    assert!(
        expired.load(Ordering::Acquire),
        "the shared authorization-expiry flag must latch exactly once"
    );
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("expiry must surface a typed client-side TimedOut result");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(
        msg.contains("authorization lifetime reached"),
        "failure message must be the fixed authorization lifetime text, got {msg}"
    );
    assert!(
        relay_failure_is_client_facing(result.first_failure.as_ref().expect("failure")),
        "authorization expiry must stay health-neutral as a client-facing failure"
    );
    assert_eq!(
        result.bytes_client_to_backend, accepted,
        "bytes the stalled backend already accepted must be counted; a fast-path \
         error reports zero"
    );

    record_termination(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::StreamTcp,
    );
    let after = counters();
    assert_eq!(
        after.credential_expired["stream_tcp"] - before.credential_expired["stream_tcp"],
        1,
        "post-relay accounting must record the session exactly once"
    );
}

/// A backend read stall after the client has half-closed must still terminate
/// at the authorization deadline with ordinary relay timeouts disabled.
///
/// Client EOF completes c2b; Phase 2 then parks solely on backend `poll_read`
/// and never polls the wrapped client leg. The top-level authorization timer
/// is what ends both halves.
#[tokio::test(start_paused = true)]
async fn a_stalled_backend_read_cannot_starve_the_tcp_authorization_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = counter_delta_guard().await;
    let before = counters();

    let (client, mut client_peer) = tokio::io::duplex(64 * 1024);
    let (backend, mut backend_peer) = tokio::io::duplex(64 * 1024);
    let expired = Arc::new(AtomicBool::new(false));
    let deadline_at = tokio::time::Instant::now() + Duration::from_secs(2);

    tokio::spawn(async move {
        let mut buf = [0u8; 16];
        let _ = backend_peer.read(&mut buf).await;
        std::future::pending::<()>().await
    });
    client_peer.write_all(b"hello").await.expect("client chunk");
    client_peer.shutdown().await.expect("client half-close");

    let copy = tokio::spawn(bidirectional_copy_with_authorization_for_test(
        client,
        backend,
        deadline_at,
        Arc::clone(&expired),
        8 * 1024,
    ));
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    tokio::time::sleep(Duration::from_secs(2)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), copy)
        .await
        .expect("authorization expiry must terminate both relay halves")
        .expect("copy task");

    assert!(expired.load(Ordering::Acquire));
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("expiry must surface a typed client-side TimedOut result");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(msg.contains("authorization lifetime reached"));
    assert!(relay_failure_is_client_facing(
        result.first_failure.as_ref().expect("failure")
    ));
    assert_eq!(
        result.bytes_client_to_backend, 5,
        "the half-closed client payload must be counted exactly once"
    );

    record_termination(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::StreamTcp,
    );
    let after = counters();
    assert_eq!(
        after.credential_expired["stream_tcp"] - before.credential_expired["stream_tcp"],
        1
    );
}

/// The userspace fast path parks both halves on the opposite endpoint and
/// cannot observe the client-leg wrapper. An authorization-bound session
/// must take the direction-tracking path and pass the deadline into both
/// TLS Deadline arms.
#[test]
fn an_authorization_bound_tcp_relay_refuses_the_unbounded_fast_path() {
    let src = include_str!("../../../src/proxy/tcp_proxy.rs");
    assert!(
        src.contains("&& auth_deadline.is_none()"),
        "the copy_bidirectional_with_sizes fast path must refuse an authorization bound"
    );
    assert!(src.contains("copy_bidirectional_with_sizes"));
    assert!(src.contains("drain_remaining_or_authorization_expire"));
    let tls = src
        .split("ClientRelayStream::Tls(tls_stream) => {")
        .nth(1)
        .expect("TLS userspace relay");
    assert!(
        tls.contains("stream_auth_deadline.map(|plan| AuthorizationCopyBound {"),
        "both TLS Deadline arms must race the authorization instant as a top-level copy bound"
    );
}

/// An admitted plaintext TCP identity never splices: the kernel cannot carry
/// the session's authorization deadline. Unauthenticated plain-to-plain keeps
/// splice/IORING eligibility.
#[test]
fn an_authenticated_plaintext_tcp_session_never_splices() {
    assert!(
        tcp_plain_splice_eligible_for_test(None),
        "unauthenticated plain TCP remains splice/IORING eligible"
    );
    let plan = StreamAuthDeadline {
        at: tokio::time::Instant::now(),
        termination: StreamAuthTermination::CredentialExpired,
    };
    assert!(
        !tcp_plain_splice_eligible_for_test(Some(plan)),
        "an admitted plaintext identity must take the userspace deadline-aware relay"
    );

    let src = include_str!("../../../src/proxy/tcp_proxy.rs");
    let plain = src
        .split("ClientRelayStream::Plain(client_stream) => {")
        .nth(1)
        .expect("plain TCP relay");
    let some_plain = plain
        .split("(Some(plan), BackendStream::Plain(bs)) => {")
        .nth(1)
        .expect("authenticated plain-to-plain arm");
    let some_plain_body = some_plain
        .split("(None, BackendStream::Tls(bs)) => {")
        .next()
        .expect("authenticated plain-to-plain arm bounded");
    assert!(
        some_plain_body.contains("bidirectional_copy_with_stream_auth("),
        "an admitted plaintext identity must use the deadline-aware userspace relay"
    );
    assert!(
        !some_plain_body.contains("bidirectional_splice(")
            && !some_plain_body.contains("bidirectional_splice_io_uring"),
        "an admitted plaintext identity must never splice"
    );
    let none_plain = plain
        .split("(None, BackendStream::Plain(bs)) => {")
        .nth(1)
        .expect("unauthenticated plain-to-plain arm");
    assert!(
        none_plain.contains("debug_assert!(tcp_plain_splice_eligible(stream_auth_deadline))"),
        "unauthenticated plain-to-plain must keep splice eligibility"
    );

    let passthrough = src
        .split("// ----- Passthrough mode: forward encrypted bytes without TLS termination -----")
        .nth(1)
        .expect("passthrough branch")
        .split("ClientRelayStream::Tls(tls_stream) => {")
        .next()
        .expect("passthrough branch bounded");
    let connect_at = passthrough
        .find("on_stream_connect")
        .expect("passthrough on_stream_connect");
    let plan_at = passthrough
        .find("admitted_stream_auth_deadline(")
        .expect("passthrough must compute the session plan after admission");
    assert!(
        connect_at < plan_at,
        "passthrough must compute stream_auth_deadline immediately after on_stream_connect"
    );
    assert!(
        passthrough.contains("within_stream_auth_deadline("),
        "passthrough DNS, connect, and PROXY write must be authorization-bounded"
    );
    assert!(
        passthrough.contains("bidirectional_copy_with_stream_auth("),
        "authenticated passthrough must use the deadline-aware userspace relay"
    );
    assert!(
        passthrough.contains("tcp_plain_splice_eligible(stream_auth_deadline)"),
        "passthrough splice is only eligible for an unauthenticated session"
    );
}

/// An admitted plaintext TCP identity relays application bytes before its
/// deadline, then terminates both directions at it with one health-neutral
/// authorization termination.
#[tokio::test(start_paused = true)]
async fn an_admitted_plaintext_tcp_identity_relays_then_expires_both_directions() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = counter_delta_guard().await;
    let before = counters();

    let (client, mut client_peer) = tokio::io::duplex(64 * 1024);
    let (backend, mut backend_peer) = tokio::io::duplex(64 * 1024);
    let expired = Arc::new(AtomicBool::new(false));
    let deadline_at = tokio::time::Instant::now() + Duration::from_secs(2);

    let copy = tokio::spawn(bidirectional_copy_with_authorization_for_test(
        client,
        backend,
        deadline_at,
        Arc::clone(&expired),
        8 * 1024,
    ));
    client_peer
        .write_all(b"hello")
        .await
        .expect("client payload before the deadline");
    let mut got = [0u8; 5];
    backend_peer
        .read_exact(&mut got)
        .await
        .expect("plaintext payload must relay before the deadline");
    assert_eq!(&got, b"hello");

    tokio::time::sleep(Duration::from_secs(2)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), copy)
        .await
        .expect("authorization expiry must terminate both relay halves")
        .expect("copy task");

    assert!(
        expired.load(Ordering::Acquire),
        "the shared authorization-expiry flag must latch exactly once"
    );
    assert!(relay_failure_is_client_facing(
        result
            .first_failure
            .as_ref()
            .expect("expiry must surface a typed client-side TimedOut result")
    ));
    assert_eq!(result.bytes_client_to_backend, 5);

    record_termination(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::StreamTcp,
    );
    let after = counters();
    assert_eq!(
        after.credential_expired["stream_tcp"] - before.credential_expired["stream_tcp"],
        1,
        "post-relay accounting must record the session exactly once"
    );
    assert!(!tcp_plain_splice_eligible_for_test(Some(
        StreamAuthDeadline {
            at: deadline_at,
            termination: StreamAuthTermination::CredentialExpired,
        }
    )));
}

/// A session with no authorization deadline is untouched: the wrapper is only
/// installed when the arbiter produced a plan.
#[tokio::test(start_paused = true)]
async fn an_unauthenticated_stream_session_gets_no_deadline_plan() {
    let anchor = tokio::time::Instant::now();
    assert!(effective_stream_auth_deadline(false, None, anchor, DEFAULT_MAX).is_none());
}

// ── Composed absolute bounds for the H3 write / upload seams (issue #3815) ──
//
// Every H3 downstream write and request-upload drain races the EARLIEST of the
// authorization plan and whatever absolute bound the protocol already had. The
// composer and its attribution helper are the one place that decision is made,
// so ~fifteen call sites cannot drift apart.

fn plan_at(at: tokio::time::Instant, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline { at, termination }
}

// ── TCP connect-retry backoff is authorization-bounded (issue #3816) ────────
//
// `retry_delay` grows with the attempt number, so a chain of failing
// candidates can hold an admitted authenticated session open for far longer
// than the credential that admitted it. Unlike DNS, connect, and the
// handshake, a raw `sleep` has no bound of its own at all.

#[tokio::test(start_paused = true)]
async fn a_retry_backoff_shorter_than_the_authorization_deadline_completes_normally() {
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let started = tokio::time::Instant::now();
    ferrum_edge::_test_support::tcp_retry_backoff_under_authorization_for_test(
        Some(plan),
        Duration::from_secs(2),
    )
    .await
    .expect("a backoff inside the authorization lifetime is an ordinary wait");
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(2)
    );
}

#[tokio::test(start_paused = true)]
async fn a_retry_backoff_is_cancelled_at_the_authorization_deadline() {
    // The operator's retry policy would wait five minutes; the credential has
    // three seconds left. The backoff must end at the credential's deadline,
    // not at the retry policy's.
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(3),
        StreamAuthTermination::CredentialExpired,
    );
    let started = tokio::time::Instant::now();
    let termination = ferrum_edge::_test_support::tcp_retry_backoff_under_authorization_for_test(
        Some(plan),
        Duration::from_secs(300),
    )
    .await
    .expect_err("the backoff must be cancelled at the absolute deadline");
    assert_eq!(termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(3)
    );
}

#[tokio::test(start_paused = true)]
async fn a_retry_backoff_entered_exactly_at_the_deadline_never_waits() {
    // Exact-deadline equality settles as expiry: a credential whose deadline is
    // exactly now no longer authorizes this session.
    let at = tokio::time::Instant::now();
    let termination = ferrum_edge::_test_support::tcp_retry_backoff_under_authorization_for_test(
        Some(plan_at(
            at,
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        Duration::from_secs(30),
    )
    .await
    .expect_err("an already-elapsed plan must not enter the backoff at all");
    assert_eq!(
        termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(tokio::time::Instant::now(), at, "no time may pass");
}

#[tokio::test(start_paused = true)]
async fn a_zero_length_backoff_at_the_deadline_still_settles_as_expiry() {
    // A zero delay resolves on its first poll, before any timer arm could be
    // consulted, so the elapsed-plan check has to precede the wait.
    let at = tokio::time::Instant::now();
    let termination = ferrum_edge::_test_support::tcp_retry_backoff_under_authorization_for_test(
        Some(plan_at(at, StreamAuthTermination::CredentialExpired)),
        Duration::ZERO,
    )
    .await
    .expect_err("an elapsed plan wins over a zero-length wait");
    assert_eq!(termination, StreamAuthTermination::CredentialExpired);
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_retry_backoff_is_unbounded() {
    let started = tokio::time::Instant::now();
    ferrum_edge::_test_support::tcp_retry_backoff_under_authorization_for_test(
        None,
        Duration::from_secs(300),
    )
    .await
    .expect("an unauthenticated session carries no authorization lifetime");
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(300)
    );
}

#[tokio::test(start_paused = true)]
async fn the_composed_bound_is_the_earliest_of_the_two_absolute_plans() {
    let now = tokio::time::Instant::now();
    let earlier = now + Duration::from_secs(5);
    let later = now + Duration::from_secs(50);

    // Authorization earlier than the client's RPC deadline.
    assert_eq!(
        ComposedAuthBound::compose(
            Some(later),
            Some(plan_at(earlier, StreamAuthTermination::CredentialExpired))
        )
        .deadline(),
        Some(earlier)
    );
    // Client's RPC deadline earlier than authorization.
    assert_eq!(
        ComposedAuthBound::compose(
            Some(earlier),
            Some(plan_at(later, StreamAuthTermination::CredentialExpired))
        )
        .deadline(),
        Some(earlier)
    );
}

#[tokio::test(start_paused = true)]
async fn a_missing_bound_never_widens_the_other() {
    let now = tokio::time::Instant::now();
    let at = now + Duration::from_secs(5);

    // The client `grpc-timeout` is OPTIONAL, which is exactly why the plain
    // HTTP relays were unbounded before: with no protocol deadline the
    // authorization plan must still be the bound.
    assert_eq!(
        ComposedAuthBound::compose(
            None,
            Some(plan_at(
                at,
                StreamAuthTermination::AuthenticatedStreamMaxLifetime
            ))
        )
        .deadline(),
        Some(at)
    );
    // An unauthenticated request carries no authorization lifetime, so the
    // protocol's own bound is unchanged.
    assert_eq!(
        ComposedAuthBound::compose(Some(at), None).deadline(),
        Some(at)
    );
    assert_eq!(ComposedAuthBound::compose(None, None).deadline(), None);
}

#[tokio::test(start_paused = true)]
async fn attribution_reports_authorization_only_once_its_own_instant_has_passed() {
    let now = tokio::time::Instant::now();
    let plan = plan_at(
        now + Duration::from_secs(5),
        StreamAuthTermination::CredentialExpired,
    );

    // Before the authorization instant: a fired composed bound belongs to the
    // protocol deadline, so the client-deadline terminal stays selected.
    assert_eq!(expired_authorization(Some(plan)), None);
    assert_eq!(expired_authorization(None), None);

    // At/after it, authorization is attributed — a tie goes to the security
    // decision, matching the biased `select!` ordering in every relay.
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        expired_authorization(Some(plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    // Still nothing to attribute for an unauthenticated stream.
    assert_eq!(expired_authorization(None), None);
}

// --- The H1/H2 request-upload seam (#3815) ---------------------------------

#[tokio::test]
async fn an_unauthenticated_upload_installs_no_authorization_bound() {
    // No principal was admitted, so there is no authorization lifetime to
    // enforce and no timer is registered on the upload at all.
    assert!(request_upload_auth_deadline_for_test(&anonymous_ctx(), DEFAULT_MAX).is_none());
}

#[tokio::test]
async fn an_authenticated_upload_is_bounded_by_the_same_plan_as_its_response() {
    let mut ctx = authenticated_ctx();
    let credential_at = tokio::time::Instant::now() + Duration::from_secs(30);
    set_request_credential_deadline_for_test(&mut ctx, Some(credential_at));

    let (upload_plan, family, _latch) =
        request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).expect("authenticated upload");
    let response_plan =
        effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated response");

    // ONE plan for both directions: the upload cannot outlive the response
    // bound, and neither can outlive the credential.
    assert_eq!(upload_plan.at, credential_at);
    assert_eq!(upload_plan, response_plan);
    assert_eq!(
        upload_plan.termination,
        StreamAuthTermination::CredentialExpired
    );
    // A plain request is bounded, and reported, as HTTP.
    assert_eq!(family, StreamAuthProtocolFamily::Http);
}

#[tokio::test]
async fn an_upload_family_follows_the_request_flavor() {
    let mut ctx = authenticated_ctx();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let (_, family, _) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    assert_eq!(family, StreamAuthProtocolFamily::Grpc);

    let mut ctx = authenticated_ctx();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let (_, family, _) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    assert_eq!(family, StreamAuthProtocolFamily::GrpcWeb);

    let mut ctx = authenticated_ctx();
    ctx.headers
        .insert("content-type".to_string(), "text/event-stream".to_string());
    let (_, family, _) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    assert_eq!(family, StreamAuthProtocolFamily::Http);
}

#[tokio::test]
async fn an_upload_shares_one_latch_with_the_response_direction() {
    let ctx = authenticated_ctx();
    let (_, _, upload_latch) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    let (_, _, second_handle) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();

    // `GrpcWeb` keeps this test's increments clear of the `http` /
    // `stream_udp` delta assertions elsewhere in this binary.
    assert!(upload_latch.record_once(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::GrpcWeb
    ));
    assert!(
        !second_handle.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::GrpcWeb
        ),
        "both directions of one request share a single termination"
    );
    assert_eq!(
        second_handle.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

// --- The fixed pre-commitment terminal (#3815) -----------------------------

#[tokio::test]
async fn a_pre_commitment_expiry_is_a_fixed_redacted_401_for_plain_http() {
    let ctx = authenticated_ctx();
    let (status, headers, body) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::CredentialExpired,
        false,
    );
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(body, br#"{"error":"Unauthorized"}"#.to_vec());
    // Redaction: no expiry instant, claim, subject, or provider detail.
    let rendered = String::from_utf8(body).unwrap();
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()));
    assert!(!headers.contains_key("grpc-status"));
}

#[tokio::test]
async fn a_pre_commitment_expiry_is_unauthenticated_trailers_for_native_grpc() {
    let ctx = authenticated_ctx();
    let (status, headers, body) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::CredentialExpired,
        true,
    );
    // gRPC errors ride HTTP 200 with the status in trailing metadata.
    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("16"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("credential expired")
    );
    assert!(body.is_empty(), "no gRPC message may be fabricated");
}

#[tokio::test]
async fn the_pre_commitment_terminal_class_is_a_closed_bounded_vocabulary() {
    let ctx = authenticated_ctx();
    let (_, headers, _) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        true,
    );
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("authenticated stream lifetime reached")
    );
}

// --- Post-admission TCP setup enforcement (#3816) --------------------------

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_stream_setup_stage_runs_unbounded() {
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let result = within_stream_auth_deadline_for_test(None, async move {
        tokio::time::sleep(Duration::from_secs(600)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        7u8
    })
    .await;
    assert_eq!(result, Ok(7));
    assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_setup_stage_inside_the_authorization_lifetime_completes() {
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(60),
        StreamAuthTermination::CredentialExpired,
    );
    let result = within_stream_auth_deadline_for_test(Some(plan), async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        "connected"
    })
    .await;
    assert_eq!(result, Ok("connected"));
}

#[tokio::test(start_paused = true)]
async fn a_setup_stage_is_cancelled_at_the_authorization_deadline() {
    // The stage models a backend dial (or an outbound PROXY/prefix write) that
    // would otherwise complete AFTER the credential expired. Cancelling it is
    // what guarantees no backend byte is written on an expired credential.
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&completed);
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let result = within_stream_auth_deadline_for_test(Some(plan), async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .await;
    assert_eq!(
        result,
        Err(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
    assert!(
        !completed.load(std::sync::atomic::Ordering::SeqCst),
        "the setup stage must be dropped at the deadline, not allowed to finish"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_lifetime_refuses_a_setup_stage_outright() {
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&started);
    let plan = plan_at(
        tokio::time::Instant::now(),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = within_stream_auth_deadline_for_test(Some(plan), async move {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;
    assert_eq!(result, Err(StreamAuthTermination::CredentialExpired));
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "a stage entered after the deadline must never run"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_tcp_setup_bound_never_polls_ready_work() {
    let now = paused_clock_with_history().await;
    let plan = plan_at(
        elapsed_by(now, Duration::from_secs(1)),
        StreamAuthTermination::CredentialExpired,
    );
    let (polled, work) = ready_poll_counter();
    let result = within_stream_auth_deadline_for_test(Some(plan), work).await;
    assert_eq!(result, Err(StreamAuthTermination::CredentialExpired));
    assert_eq!(
        polled.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an already-elapsed TCP setup bound must not poll a ready stage"
    );
}

#[tokio::test(start_paused = true)]
async fn a_live_tcp_setup_bound_completes_ready_work() {
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let (polled, work) = ready_poll_counter();
    let result = within_stream_auth_deadline_for_test(Some(plan), work).await;
    assert_eq!(result, Ok(()));
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_setup_expiry_kind_is_client_side_and_health_neutral() {
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};

    let kind = StreamSetupKind::AuthorizationExpired;
    // Client-side: the gateway applied a policy to the client's own credential,
    // so the disconnect cause and direction are client-attributed and no
    // backend health signal is derived from it.
    assert!(kind.is_client_side());
    assert_eq!(kind.tls_side(), None);
    assert_eq!(
        kind.direction(),
        ferrum_edge::plugins::Direction::ClientToBackend
    );
    let rendered =
        StreamSetupError::new(kind, "before any backend byte was written".to_string()).to_string();
    // Redacted: the contract, never the credential, its subject, or its expiry.
    assert!(rendered.contains("authorization lifetime"), "{rendered}");
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()), "{rendered}");
}

// --- Buffered H1/H2 uploads (#3815) ----------------------------------------
//
// A request body that a request-body plugin, a gRPC-Web translation, or retry
// replay forces into memory never reaches the streaming upload adapters, so the
// collect itself must carry the absolute plan. A continuously active upload
// makes progress on every poll, so neither the (often absent) client RPC
// deadline nor the progress-refreshed operator stall timeout bounds it.

fn upload_plan(
    after: Duration,
    termination: StreamAuthTermination,
) -> (
    StreamAuthDeadline,
    StreamAuthProtocolFamily,
    ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch,
) {
    (
        plan_at(tokio::time::Instant::now() + after, termination),
        StreamAuthProtocolFamily::GrpcWeb,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    )
}

#[tokio::test(start_paused = true)]
async fn a_continuously_active_buffered_upload_stops_at_the_authorization_deadline() {
    // No client RPC deadline and `backend_read_timeout_ms = 0`: without the
    // authorization arm this collect is completely unbounded.
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async {
            // A client that keeps sending: the collect makes progress on every
            // poll, so it never stalls and never resolves either.
            for _ in 0..600 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(())
        },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the collect must latch the bounded class for the request"
    );
}

#[tokio::test(start_paused = true)]
async fn a_buffered_upload_reports_the_fallback_maximum_class_when_that_bound_wins() {
    let plan = upload_plan(
        Duration::from_secs(5),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_plan_fails_a_buffered_collect_closed_without_polling_it() {
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&polled);
    let plan = upload_plan(
        Duration::from_secs(0),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !polled.load(std::sync::atomic::Ordering::SeqCst),
        "the authorization arm is biased first, so an elapsed plan never reads client bytes"
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_client_rpc_deadline_still_wins_a_buffered_collect() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let rpc_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        Some(rpc_deadline),
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::DeadlineExceeded);
    assert_eq!(
        latch.observed(),
        None,
        "a client-chosen RPC expiry is not an authorization termination"
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_operator_stall_timeout_still_wins_a_buffered_collect() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        None,
        1_000,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::TimedOut);
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_buffered_collect_is_completely_unaffected() {
    let outcome =
        collect_buffered_upload_under_authorization_for_test(async { Ok(()) }, None, 0, None).await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::Collected);
}

#[tokio::test(start_paused = true)]
async fn a_buffered_collect_that_completes_before_expiry_is_forwarded() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::Collected);
    assert_eq!(latch.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn a_client_disconnect_during_a_buffered_collect_keeps_its_own_outcome() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async { Err(()) },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::ClientError);
}

#[tokio::test(start_paused = true)]
async fn a_buffered_collect_and_a_second_direction_record_one_termination() {
    let plan = upload_plan(
        Duration::from_secs(2),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        None,
        0,
        Some(plan),
    )
    .await;
    assert!(matches!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(_)
    ));
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::GrpcWeb
        ),
        "the opposite direction must not count a second termination"
    );
}

// --- Single composition of the buffered upload bound (#3815) ---------------
//
// The protocol bound (client RPC deadline vs operator whole-upload stall
// timeout) is composed ONCE per authorized collect, and that exact instant both
// selects the arm and is awaited. Composing a second time at wait time would
// rebase the fresh operator window onto a later `Instant::now()`, so a
// credential deadline landing between the two could be judged "later than the
// protocol bound" — disarming the security arm — while the instant actually
// awaited lands after it.

#[tokio::test(start_paused = true)]
async fn a_composed_operator_window_is_never_rebased_past_the_credential() {
    let start = tokio::time::Instant::now();
    let bound = compose_buffered_upload_bound_for_test(None, 100);
    assert_eq!(bound.kind(), Some(EarlyUploadBoundKind::OperatorTimeout));
    assert_eq!(bound.at(), Some(start + Duration::from_millis(100)));

    // The credential expires AFTER the composed operator window but BEFORE the
    // window a second composition would open (120 + 100 = 220ms from start).
    let plan = upload_plan(
        Duration::from_millis(150),
        StreamAuthTermination::CredentialExpired,
    );
    let plan_at = plan.0.at;
    let latch = plan.2.clone();

    // Arbitrary scheduling delay between composition and the wait.
    tokio::time::advance(Duration::from_millis(120)).await;

    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        std::future::pending::<Result<(), ()>>(),
        bound,
        100,
        Some(plan),
    )
    .await;

    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::TimedOut,
        "the composed operator bound owns this phase's terminal"
    );
    assert_eq!(
        latch.observed(),
        None,
        "an operator stall timeout is not an authorization termination"
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(120),
        "the wait must end at the ALREADY-ELAPSED composed bound, not at a \
         freshly rebased operator window"
    );
    assert!(
        tokio::time::Instant::now() <= plan_at,
        "a rebased operator window would have kept the upload alive past the \
         credential that admitted it"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_composed_operator_bound_never_polls_a_ready_upload() {
    let bound = compose_buffered_upload_bound_for_test(None, 100);
    assert_eq!(bound.kind(), Some(EarlyUploadBoundKind::OperatorTimeout));
    let plan = upload_plan(
        Duration::from_millis(150),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_millis(200)).await;

    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        ready_ok_h3_upload(&polled),
        bound,
        100,
        Some(plan),
    )
    .await;

    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::TimedOut,
        "a strictly earlier composed operator bound stays TimedOut after both instants pass"
    );
    assert_eq!(
        polled.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an already-elapsed operator bound must not poll a ready upload"
    );
}

#[tokio::test(start_paused = true)]
async fn a_credential_earlier_than_the_composed_bound_still_arms_after_a_delay() {
    let start = tokio::time::Instant::now();
    // Operator window at +300ms; a second composition taken 120ms later would
    // sit at +420ms, well past the credential either way.
    let bound = compose_buffered_upload_bound_for_test(None, 300);
    let plan = upload_plan(
        Duration::from_millis(200),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();

    tokio::time::advance(Duration::from_millis(120)).await;

    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        std::future::pending::<Result<(), ()>>(),
        bound,
        300,
        Some(plan),
    )
    .await;

    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(200),
        "the collect ends exactly at the credential deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn a_composed_rpc_deadline_keeps_its_attribution_across_the_gap() {
    let start = tokio::time::Instant::now();
    // The client's RPC deadline is earlier than the operator window, so
    // composition settles on it; only the operator side could ever be rebased.
    let bound =
        compose_buffered_upload_bound_for_test(Some(start + Duration::from_millis(100)), 5_000);
    assert_eq!(bound.kind(), Some(EarlyUploadBoundKind::RpcDeadline));

    let plan = upload_plan(
        Duration::from_millis(150),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();

    tokio::time::advance(Duration::from_millis(120)).await;

    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        std::future::pending::<Result<(), ()>>(),
        bound,
        5_000,
        Some(plan),
    )
    .await;

    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::DeadlineExceeded,
        "a client-chosen expiry stays an RPC deadline, never an operator timeout"
    );
    assert_eq!(latch.observed(), None);
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(120)
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_composed_rpc_deadline_never_polls_a_ready_upload() {
    let start = tokio::time::Instant::now();
    let bound =
        compose_buffered_upload_bound_for_test(Some(start + Duration::from_millis(100)), 5_000);
    let plan = upload_plan(
        Duration::from_millis(150),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_millis(200)).await;

    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        ready_ok_h3_upload(&polled),
        bound,
        5_000,
        Some(plan),
    )
    .await;

    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::DeadlineExceeded,
        "a strictly earlier client deadline stays DeadlineExceeded after both instants pass"
    );
    assert_eq!(
        polled.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an already-elapsed protocol bound must not poll a ready upload"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_collect_waits_on_the_same_composed_bound() {
    let start = tokio::time::Instant::now();
    let bound = compose_buffered_upload_bound_for_test(None, 100);

    tokio::time::advance(Duration::from_millis(120)).await;

    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        std::future::pending::<Result<(), ()>>(),
        bound,
        100,
        None,
    )
    .await;

    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::TimedOut);
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(120),
        "the unauthenticated arm waits on the composed bound too"
    );
}

#[tokio::test(start_paused = true)]
async fn a_disabled_operator_timeout_composes_no_bound_and_the_credential_owns_it() {
    // `backend_read_timeout_ms = 0` with no client RPC deadline: composition
    // yields NO absolute instant, which is exactly the unbounded case the
    // authorization arm exists for. There is nothing to rebase, and the arm is
    // armed regardless of how late the wait is observed.
    let bound = compose_buffered_upload_bound_for_test(None, 0);
    assert_eq!(bound.at(), None);
    assert_eq!(bound.kind(), None);

    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();

    tokio::time::advance(Duration::from_secs(10)).await;

    let outcome = collect_buffered_upload_under_composed_bound_for_test(
        std::future::pending::<Result<(), ()>>(),
        bound,
        0,
        Some(plan),
    )
    .await;

    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

// --- Dispatch-phase attribution (#3815) ------------------------------------

#[tokio::test(start_paused = true)]
async fn a_dispatch_phase_attributes_an_elapsed_authorization_bound_once() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    assert_eq!(
        dispatch_phase_authorization_expiry_for_test(Some(&plan)),
        None,
        "a bound that has not elapsed is the protocol's own, not authorization's"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        dispatch_phase_authorization_expiry_for_test(Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        plan.2.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    // Idempotent: a second phase observing the same elapsed plan cannot count
    // a second termination.
    assert_eq!(
        dispatch_phase_authorization_expiry_for_test(Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(!plan.2.record_once(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::GrpcWeb
    ));
}

#[tokio::test]
async fn an_unauthenticated_dispatch_phase_never_attributes_authorization() {
    assert_eq!(dispatch_phase_authorization_expiry_for_test(None), None);
}

#[tokio::test]
async fn the_dispatch_placeholder_is_health_neutral_and_redacted() {
    let (status, body, connection_error, error_class) =
        authorization_expired_dispatch_placeholder_for_test();
    assert_eq!(status, 401);
    assert_eq!(body, br#"{"error":"Unauthorized"}"#.to_vec());
    assert!(
        !connection_error,
        "the gateway cancelled the dispatch; no connect failure occurred"
    );
    // `client_disconnect` is never retried and is backend-health neutral, so the
    // gateway's own security decision cannot be charged to the upstream.
    assert_eq!(error_class, Some("client_disconnect"));
    let rendered = String::from_utf8(body).unwrap();
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()), "{rendered}");
}

// --- The response-header wait (#3815) --------------------------------------

#[tokio::test(start_paused = true)]
async fn the_authorization_lifetime_bounds_an_otherwise_unbounded_header_wait() {
    // No client `grpc-timeout` and `backend_read_timeout_ms = 0`: the wait had
    // no bound at all, and a bodyless request gives the upload adapter nothing
    // to fire on.
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 0, None),
        None
    );
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 0, Some(5_000)),
        Some((5_000, "authorization"))
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_protocol_header_bound_still_wins() {
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 1_000, Some(5_000)),
        Some((1_000, "operator"))
    );
    assert_eq!(
        authorization_bounded_header_deadline_for_test(Some(800), 0, Some(5_000)),
        Some((800, "client"))
    );
}

#[tokio::test(start_paused = true)]
async fn a_later_protocol_header_bound_loses_to_the_authorization_lifetime() {
    assert_eq!(
        authorization_bounded_header_deadline_for_test(Some(60_000), 30_000, Some(5_000)),
        Some((5_000, "authorization"))
    );
    // A tie is attributed to the security decision.
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 5_000, Some(5_000)),
        Some((5_000, "authorization"))
    );
}

// --- The direct-H2 early-response upload join (#3815) ----------------------

#[tokio::test(start_paused = true)]
async fn the_authorization_lifetime_bounds_an_otherwise_unbounded_upload_join() {
    // `backend_read_timeout_ms = 0` with no RPC deadline is the documented
    // "0 = no timeout" contract: an early backend response would otherwise wait
    // on the detached upload indefinitely.
    assert_eq!(direct_h2_upload_join_bound_for_test(None, 0, None), None);
    assert_eq!(
        direct_h2_upload_join_bound_for_test(None, 0, Some(4_000)),
        Some((4_000, "authorization"))
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_protocol_upload_join_bound_still_wins() {
    assert_eq!(
        direct_h2_upload_join_bound_for_test(None, 1_000, Some(9_000)),
        Some((1_000, "operator_timeout"))
    );
    assert_eq!(
        direct_h2_upload_join_bound_for_test(Some(700), 0, Some(9_000)),
        Some((700, "rpc_deadline"))
    );
}

#[tokio::test(start_paused = true)]
async fn a_later_protocol_upload_join_bound_loses_to_the_authorization_lifetime() {
    assert_eq!(
        direct_h2_upload_join_bound_for_test(Some(60_000), 30_000, Some(2_500)),
        Some((2_500, "authorization"))
    );
    assert_eq!(
        direct_h2_upload_join_bound_for_test(None, 2_500, Some(2_500)),
        Some((2_500, "authorization")),
        "a tie is attributed to the security decision"
    );
}

// --- Source contracts for the dispatch seams (#3815) -----------------------
//
// These seams live inside `handle_proxy_request_inner` / `proxy_to_backend*`,
// which need a live listener, a pooled backend, and a real hyper transport to
// drive. The behavior each one composes is unit-tested above; these assertions
// keep the WIRING from silently regressing — a buffered arm reverting to the
// unbounded collect, or the direct-H2 upload join losing its gate.

const PROXY_SOURCE: &str = include_str!("../../../src/proxy/mod.rs");
const GRPC_PROXY_SOURCE: &str = include_str!("../../../src/proxy/grpc_proxy.rs");
const H3_SERVER_SOURCE: &str = include_str!("../../../src/http3/server.rs");

#[test]
fn every_post_admission_buffered_upload_collect_carries_the_authorization_plan() {
    // reqwest buffered (limited + unlimited) and the H3-backend bridge's
    // buffered arms (limited + unlimited).
    assert_eq!(
        PROXY_SOURCE
            .matches("collect_request_body_under_authorization(")
            .count(),
        4,
        "a post-admission buffered upload arm reverted to the unbounded collect"
    );
    // Both buffered native-gRPC collects.
    assert_eq!(
        GRPC_PROXY_SOURCE
            .matches("collect_request_body_under_authorization(")
            .count(),
        2,
        "a buffered gRPC upload arm reverted to the unbounded collect"
    );
    // Every authorization arm returns the health-neutral placeholder, so the
    // single pre-commitment terminal decides the client-visible shape.
    assert_eq!(
        PROXY_SOURCE
            .matches("Err(AuthorizedUploadWaitError::AuthorizationExpired(_)) => {")
            .count(),
        4
    );
}

#[test]
fn the_authorized_buffered_collect_composes_its_protocol_bound_exactly_once() {
    let wait = PROXY_SOURCE
        .split("pub(crate) async fn collect_request_body_under_authorization_with_bound<")
        .nth(1)
        .expect("the authorized buffered wait must remain present")
        .split("\npub(crate) fn ")
        .next()
        .expect("the authorized buffered wait must remain bounded");
    assert_eq!(
        wait.matches("compose_early_upload_bound(").count(),
        0,
        "the wait takes an ALREADY-COMPOSED bound; recomposing here would rebase \
         the fresh operator window onto a later now() than the arm selection used"
    );
    assert_eq!(
        wait.matches("collect_request_body_with_deadline(").count(),
        0,
        "the deadline-composing entry point would compose a second time"
    );
    // The single parameter, threaded to the unauthenticated wait and to the ONE
    // authenticated `match` — never recomputed. Three uses, not four: the
    // arm-selection comparison and the awaited bound are the same `match`, so
    // they destructure one instant instead of reading the parameter twice.
    assert_eq!(wait.matches("protocol_bound").count(), 3);
    // What the count alone cannot show: the instant that is COMPARED against
    // the credential deadline is literally the instant that is AWAITED. A
    // second read of the composition (or of the clock) between the two is the
    // fail-closed race this seam exists to prevent.
    let authenticated = wait
        .split("match protocol_bound {")
        .nth(1)
        .expect("the authenticated arm selection");
    assert!(
        authenticated.contains("Some((at, kind)) if at < plan.at => {"),
        "arm selection must destructure the composed bound rather than recompose it"
    );
    assert!(
        authenticated.contains("await_deadline_first(Some(at), collect)"),
        "the protocol-earlier arm must await the very instant it just compared"
    );
    assert!(
        authenticated.contains("await_deadline_first(Some(plan.at), collect)"),
        "the authorization arm must await the captured credential deadline"
    );
    // Expiry-first on BOTH arms: `timeout_at` polls a ready upload before its
    // timer, so an already-elapsed bound would still accept a buffered FIN.
    assert_eq!(
        wait.matches("timeout_at(").count(),
        0,
        "an already-elapsed bound must refuse without polling the collect"
    );
}

#[test]
fn the_pre_authentication_prebuffer_stays_on_the_unbounded_collect() {
    // `buffer_request_body_for_before_proxy` runs BEFORE any principal is
    // admitted, so there is no authorization lifetime to enforce there and no
    // credential deadline to read. Widening it would be a false bound.
    // Bounded by the function that FOLLOWS it. `request_may_have_body` is
    // declared ahead of the prebuffer, so splitting on it left this pin reading
    // the whole rest of the module and asserting nothing about the prebuffer.
    let prebuffer = PROXY_SOURCE
        .split("async fn buffer_request_body_for_before_proxy(")
        .nth(1)
        .expect("pre-authentication prebuffer")
        .split("async fn prepare_mesh_request_body(")
        .next()
        .expect("bounded prebuffer body");
    assert!(
        prebuffer.contains("collect_request_body_with_deadline("),
        "the prebuffer must still be the unbounded, deadline-only collect"
    );
    assert!(!prebuffer.contains("collect_request_body_under_authorization"));
}

#[test]
fn the_direct_h2_upload_completion_gate_is_installed_for_authenticated_requests() {
    let gate = PROXY_SOURCE
        .split("let needs_upload_completion_gate =")
        .nth(1)
        .expect("direct-H2 upload-completion gate decision")
        .split(';')
        .next()
        .expect("bounded gate decision");
    assert!(
        gate.contains("effective_max_request_body_size_bytes > 0"),
        "the size-limit reason must stay: {gate}"
    );
    assert!(
        gate.contains("upload_auth_deadline.is_some()"),
        "an authenticated direct-H2 request needs the upload join even with limits off: {gate}"
    );
    assert!(
        PROXY_SOURCE.contains("if needs_upload_completion_gate {"),
        "the gate decision must drive the completion-channel installation"
    );
}

#[test]
fn the_direct_h2_upload_join_reports_authorization_rather_than_an_indeterminate_size() {
    // An authorization-terminated upload also reports `Abandoned`, which the
    // size gate classifies as FailClosed. That must not surface as a 502
    // backend fault.
    let fail_closed = PROXY_SOURCE
        .split("DirectH2UploadGate::FailClosed => {")
        .nth(1)
        .expect("direct-H2 fail-closed arm")
        .split("\"HTTP/2 request upload did not establish an authoritative size decision")
        .next()
        .expect("bounded fail-closed arm");
    assert!(fail_closed.contains("upload_auth_deadline"));
    assert!(fail_closed.contains("latch.observed()"));
    assert!(fail_closed.contains("authorization_expired_dispatch_placeholder("));
}

#[test]
fn every_h1h2_response_header_wait_composes_the_authorization_lifetime() {
    // The definition, five composed header waits (the reqwest initial attempt,
    // the reqwest retry attempt, mesh mTLS, HBONE, and the Unix-socket pool),
    // and the shared buffered-RESPONSE collect composer. Direct-H2 composes
    // through `authorization_bounded_header_deadline` instead, because it
    // carries a typed bound source.
    assert_eq!(
        PROXY_SOURCE
            .matches("compose_dispatch_phase_auth_bound(")
            .count(),
        7,
        "an H1/H2 response-header wait lost its authorization bound"
    );
    assert!(PROXY_SOURCE.contains("authorization_bounded_header_deadline("));
    assert!(PROXY_SOURCE.contains("ResponseHeaderDeadlineSource::Authorization => {"));
    // The definition plus eight attributions: those five waits, the direct-H2
    // header wait, the direct-H2 early-response upload join, and the shared
    // buffered-response collect composer. Each attributes the fired bound, so an
    // authorization expiry is never reported as a backend timeout or a client
    // RPC deadline.
    assert_eq!(
        PROXY_SOURCE
            .matches("dispatch_phase_authorization_expiry(")
            .count(),
        9,
        "an H1/H2 dispatch phase lost its authorization attribution"
    );
    // Every one of those exits returns the health-neutral placeholder. Seventeen
    // references name it directly: the definition, the out-of-line wrapper's own
    // single use, the three `proxy_to_backend_retry` returns, and the twelve
    // tuple-returning exits across HBONE, Unix, mesh mTLS, direct-H2, and the
    // native-H3 backend. The seven `proxy_to_backend` exits reach the same value
    // through that wrapper.
    assert_eq!(
        PROXY_SOURCE
            .matches("authorization_expired_dispatch_placeholder(")
            .count(),
        17,
        "an H1/H2 authorization exit stopped being health-neutral"
    );
    // The wrapper's definition plus its seven `proxy_to_backend` call sites.
    assert_eq!(
        PROXY_SOURCE
            .matches("authorization_expired_backend_dispatch(")
            .count(),
        8,
        "a reqwest-dispatch authorization exit stopped being health-neutral"
    );
}

/// Every buffered RESPONSE collection goes through the shared composer, and
/// every one of them settles an authorization expiry health-neutrally.
///
/// A buffered collect is the one response phase with no downstream body adapter
/// to fall back on, and its only other bound is the PER-FRAME
/// `backend_read_timeout_ms`, which `0` disables outright.
#[test]
fn every_buffered_response_collect_is_authorization_bounded() {
    // Ten call sites, one per buffered response arm: two reqwest retry arms,
    // four reqwest first-attempt arms, direct-H2, HBONE, the Unix-socket pool,
    // and the mesh-mTLS gRPC-Web arm. (The generic definition itself carries a
    // `<F>` and is not counted.)
    assert_eq!(
        PROXY_SOURCE
            .matches("collect_response_under_authorization(")
            .count(),
        10,
        "a buffered response collect lost its authorization bound"
    );
    for arm in PROXY_SOURCE
        .split("Err(ResponseCollectBound::AuthorizationExpired) => {")
        .skip(1)
    {
        let branch = arm
            .split("\n        };")
            .next()
            .expect("bounded authorization arm");
        assert!(
            branch.contains("authorization_expired_dispatch_placeholder(")
                || branch.contains("authorization_expired_backend_dispatch("),
            "a buffered response collect expiry stopped being health-neutral: {branch}"
        );
    }
}

/// The AUTHORITATIVE authorization gate, immediately before the terminal
/// transaction summary is built and the response head is committed.
///
/// The earlier pre-commitment check runs where backend dispatch converges;
/// every awaited response phase after it can still consume time up to the
/// deadline, so a protected or streaming head must not be logged, deferred, or
/// committed without this check. This IS the last authorization decision on the
/// path: nothing after it awaits on a request that carries a plan, which
/// `buffered_terminal_logging_never_awaits_after_the_authorization_gate` pins.
#[test]
fn a_final_authorization_gate_precedes_response_head_commitment() {
    let gate = PROXY_SOURCE
        .split("let final_precommit_authorization_terminal =")
        .nth(1)
        .expect("the pre-log pre-commitment authorization gate");
    let gate = gate
        .split("let total_ms =")
        .next()
        .expect("bounded pre-log gate");
    // The decision, the once-only latch record, and the fixed terminal all live
    // in the shared out-of-line applier (asserted in
    // `the_precommit_authorization_terminal_is_applied_out_of_line`), so the gate
    // itself only has to invoke it and correct the streamed classification.
    assert!(gate.contains("apply_precommit_authorization_terminal("));
    assert!(
        gate.contains("is_streaming_response = false;"),
        "the fixed terminal is buffered, so the summary must not describe it as streamed"
    );
    // The gate must precede the response builder, not follow it.
    let gate_at = PROXY_SOURCE
        .find("let final_precommit_authorization_terminal =")
        .expect("gate present");
    let builder_at = PROXY_SOURCE
        .find("    // Build final response\n    let mut resp_builder = Response::builder()")
        .expect("response builder present");
    assert!(
        gate_at < builder_at,
        "the authorization gate must run BEFORE the response head is built"
    );
}

/// Nothing awaits between the authoritative authorization gate and the
/// client-visible buffered response, and the ONE terminal summary that reaches
/// the logging plugins is the post-gate one (issue #3815).
///
/// Awaiting terminal transaction logging here reopened exactly the window the
/// gate closes. The summary is immutable and is built BEFORE the logging chain
/// runs, so a credential expiring while one logging plugin blocked produced an
/// audit record of the still-PROTECTED status — after some plugins had already
/// emitted it — while the client received the fixed authorization terminal.
/// A later gate can repair the response; it cannot retract an emitted record.
#[test]
fn buffered_terminal_logging_never_awaits_after_the_authorization_gate() {
    let gate_marker =
        "let final_precommit_authorization_terminal = apply_precommit_authorization_terminal(";
    let gate_at = PROXY_SOURCE.find(gate_marker).expect("final gate present");
    let builder_at = PROXY_SOURCE
        .find("    // Build final response\n    let mut resp_builder = Response::builder()")
        .expect("response builder present");
    assert!(
        gate_at < builder_at,
        "the authorization gate must run BEFORE the response head is built"
    );

    // The summary is built AFTER the gate, so it records the terminal status,
    // the buffered classification, and the bounded class the gate latched.
    let summary_at = PROXY_SOURCE[gate_at..builder_at]
        .find("let summary = TransactionSummary {")
        .map(|offset| gate_at + offset)
        .expect("the terminal transaction summary is built between the gate and the builder");

    // The buffered (non-streaming) arm that owns terminal-log delivery.
    let arm_marker = "// ── Buffered commitment / audit boundary (#3815)";
    let else_at = PROXY_SOURCE[summary_at..builder_at]
        .find(arm_marker)
        .map(|offset| summary_at + offset)
        .expect("buffered terminal-log delivery arm");
    let delivery_arm = &PROXY_SOURCE[else_at..builder_at];

    // The detach decision is derived from the gate's OWN plan predicate, taken
    // between the gate and the arm, so the two cannot disagree about which
    // requests carry an authorization decision to protect. Nothing in that
    // window may await either.
    let between = &PROXY_SOURCE[gate_at..else_at];
    assert!(
        between.contains("let has_authorization_plan ="),
        "the detach predicate must be bound between the gate and the delivery arm"
    );
    assert!(
        between.contains("effective_request_auth_deadline("),
        "the detach predicate must be the gate's own plan check"
    );
    assert!(
        !between.contains(".await"),
        "nothing between the gate and the terminal-log delivery arm may await"
    );
    assert!(
        delivery_arm.contains("if has_authorization_plan {"),
        "the buffered terminal-log arm must branch on that predicate"
    );
    assert!(
        delivery_arm.contains("crate::plugins::spawn_bounded_terminal_summary_log("),
        "an authenticated buffered response must hand its single terminal summary to bounded \
         detached delivery instead of awaiting a logging plugin after the gate"
    );
    assert!(
        delivery_arm.contains("crate::plugins::log_with_mirror_before_buffered_response("),
        "a request with no authorization plan keeps the historical awaited contract"
    );
    assert!(
        !delivery_arm.contains("apply_precommit_authorization_terminal("),
        "a second gate after the summary was built would decide a response the audit record \
         can no longer describe"
    );

    // The ONLY await between the gate and the response builder is the
    // no-authorization-plan branch, whose credential cannot expire behind it.
    assert_eq!(
        delivery_arm.matches(".await").count(),
        1,
        "no await may separate the authorization gate from the client-visible response"
    );
    let await_at = delivery_arm.find(".await").expect("awaited call");
    assert!(
        delivery_arm[..await_at]
            .rsplit_once("crate::plugins::")
            .is_some_and(|(_, call)| call.starts_with("log_with_mirror_before_buffered_response(")),
        "the one remaining await must be the unauthenticated buffered logger"
    );
}

/// The buffered terminal summary is built from POST-GATE state, so the audit
/// record and the client-visible security decision cannot disagree (#3815).
///
/// The gate rewrites the status/headers/body and latches the bounded class into
/// the request metadata BEFORE `TransactionSummary` is constructed, and the
/// summary's `metadata` is exactly `clone_log_metadata` of that context. There
/// is therefore no earlier, still-protected summary that could reach a logging
/// plugin first.
#[tokio::test]
async fn the_gate_publishes_the_terminal_class_before_the_summary_is_built() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    // A credential that elapsed while the pre-commitment response phases ran.
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at));

    let gate =
        precommit_authorization_gate_for_test(&mut ctx, DEFAULT_MAX, false, 200, b"protected");

    assert_eq!(
        gate.termination,
        Some(StreamAuthTermination::CredentialExpired)
    );
    // The client-visible response is the fixed pre-commitment terminal, and the
    // summary built from this state records that status, not the protected one.
    assert_eq!(gate.status, 401);
    assert_eq!(gate.body, br#"{"error":"Unauthorized"}"#.to_vec());
    let reason = gate.log_metadata.get(TERMINATION_REASON_KEY);
    assert_eq!(reason.map(String::as_str), Some("credential_expired"));
    // Compiled-in literals only: no token, claim, subject, provider detail, or
    // absolute expiry reaches the record the gate publishes.
    for value in gate.log_metadata.values() {
        assert_eq!(value, "credential_expired");
    }
}

/// The same gate on native gRPC selects the legal trailers-only terminal and
/// still publishes the bounded class for the terminal summary.
#[tokio::test]
async fn the_grpc_gate_publishes_the_bounded_class_with_its_trailers_only_terminal() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at));

    let gate =
        precommit_authorization_gate_for_test(&mut ctx, DEFAULT_MAX, true, 200, b"protected");

    assert_eq!(
        gate.termination,
        Some(StreamAuthTermination::CredentialExpired)
    );
    // gRPC errors ride HTTP 200 with the status in trailing metadata.
    assert_eq!(gate.status, 200);
    let grpc_status = gate.headers.get("grpc-status").map(String::as_str);
    assert_eq!(grpc_status, Some("16"));
    assert!(gate.body.is_empty());
    let reason = gate.log_metadata.get(TERMINATION_REASON_KEY);
    assert_eq!(reason.map(String::as_str), Some("credential_expired"));
}

/// A live credential and an unauthenticated request both leave the buffered
/// terminal summary describing the response the backend actually produced.
#[tokio::test]
async fn a_live_or_absent_credential_leaves_the_buffered_terminal_summary_untouched() {
    let mut live = authenticated_ctx();
    let received_at = request_received_at_for_test(&live);
    set_request_credential_deadline_for_test(
        &mut live,
        Some(received_at + Duration::from_secs(300)),
    );
    let gate = precommit_authorization_gate_for_test(&mut live, DEFAULT_MAX, false, 200, b"body");
    assert_eq!(gate.termination, None);
    assert_eq!(gate.status, 200);
    assert_eq!(gate.body, b"body".to_vec());
    assert!(!gate.log_metadata.contains_key(TERMINATION_REASON_KEY));

    // An unauthenticated request has no plan and is never gated.
    let mut anonymous = anonymous_ctx();
    let gate =
        precommit_authorization_gate_for_test(&mut anonymous, DEFAULT_MAX, false, 200, b"body");
    assert_eq!(gate.termination, None);
    assert_eq!(gate.status, 200);
    assert_eq!(gate.body, b"body".to_vec());
    assert!(!gate.log_metadata.contains_key(TERMINATION_REASON_KEY));
}

/// Every awaited pre-commitment RESPONSE phase runs under the composed bound.
///
/// `grpc_deadline_at()` alone is `None` for an ordinary HTTP request, which left
/// `after_proxy`, the buffered body hooks, the final client-visible body and
/// header policies, and the response-committed hook completely unbounded.
///
/// The bound carries the authorization PLAN, not just the composed instant, so
/// the phase that ends at it can tell whose deadline it was.
#[test]
fn every_precommit_response_phase_composes_the_authorization_lifetime() {
    assert_eq!(
        PROXY_SOURCE
            .matches("ctx.precommit_response_phase_bound()")
            .count(),
        7,
        "a pre-commitment response phase lost its authorization bound"
    );
    assert!(
        !PROXY_SOURCE.contains("ctx.precommit_response_phase_deadline_at()"),
        "a pre-commitment phase that keeps only the composed instant cannot tell an \
         authorization expiry from the client's own RPC deadline"
    );
}

/// An authorization expiry never blames the plugin or the backend, and never
/// selects the client `grpc-timeout` terminal (issue #3815, root finding 3).
#[test]
fn a_precommit_phase_authorization_expiry_selects_only_the_fixed_terminal() {
    let settle = PROXY_SOURCE
        .split("pub(crate) fn settle_precommit_authorization_expiry(")
        .nth(1)
        .expect("pre-commitment authorization settlement")
        .split("\n}\n")
        .next()
        .expect("bounded settlement");
    assert!(
        settle.contains("record_authorization_termination_once("),
        "the request's shared latch must record the class exactly once"
    );
    assert!(
        settle.contains("authorization_expired_pre_commitment_response("),
        "only the fixed, redacted pre-commitment terminal may be selected"
    );
    assert!(
        !settle.contains("mark_gateway_deadline_response_selected"),
        "RPC-deadline provenance would drive grpc-status 4 terminal write bias and blame \
         the client's own deadline for the gateway's security decision"
    );
    assert!(
        !settle.contains("grpc_deadline_exceeded_plugin_result"),
        "an authorization expiry must never synthesize DEADLINE_EXCEEDED"
    );

    // The generic resolver keeps the client `grpc-timeout` behavior byte for
    // byte on the OTHER arm.
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let resolver = plugins
        .split("impl PrecommitPhaseResult<PluginResult> {")
        .nth(1)
        .expect("pre-commitment phase resolver")
        .split("\n}\n")
        .next()
        .expect("bounded resolver");
    assert!(resolver.contains("Self::Expired(Some(termination)) =>"));
    assert!(resolver.contains("crate::proxy::settle_precommit_authorization_expiry("));
    assert!(resolver.contains("Self::Expired(None) =>"));
    assert!(resolver.contains("ctx.mark_gateway_deadline_response_selected();"));
    assert!(resolver.contains("grpc_deadline_exceeded_plugin_result()"));
}

/// A pending committed-response observer is DROPPED on authorization expiry,
/// never detached (issue #3815, root finding 4).
#[test]
fn an_expired_committed_hook_is_dropped_rather_than_detached() {
    let hook = PROXY_SOURCE
        .split("pub(crate) async fn run_response_committed_hook_until_deadline(")
        .nth(1)
        .expect("response-committed deadline hook")
        .split("pub(crate) fn spawn_detached_response_committed_hooks(")
        .next()
        .expect("bounded response-committed deadline hook");
    // Legacy detach survives for the client-owned RPC deadline only, and it
    // carries the credential's absolute bound into the detached lifecycle.
    assert!(hook.contains("ResponseCommittedHookOutcome::Detach(hook, detached_bound)"));
    // An ALREADY-elapsed authorization bound is decided before the observer —
    // and the clone of the request context and protected body it would own —
    // is even constructed.
    let early_gate_at = hook
        .find("if let Some(termination) = bound.expired_authorization() {")
        .expect("pre-construction authorization gate");
    let construct_at = hook
        .find("owned_response_committed_hook_future(")
        .expect("observer construction");
    assert!(
        early_gate_at < construct_at,
        "an expired credential must not have a clone of the request context or the \
         protected response body handed to a future at all"
    );
    // A hook that was already pending when the bound elapsed is DROPPED.
    assert!(
        hook.contains("drop(hook);"),
        "the pending hook — with the cloned request context and the protected response \
         body it owns — must be dropped rather than detached"
    );
    assert!(
        hook.contains("record_authorization_termination_once("),
        "the class is recorded exactly once through the request's shared latch"
    );
    assert_eq!(
        hook.matches("ResponseCommittedHookOutcome::AuthorizationExpired(termination)")
            .count(),
        2,
        "both the pre-construction gate and the pending-observer arm must report the \
         non-detachable authorization outcome"
    );
}

#[test]
fn both_buffered_grpc_authorization_exits_release_their_admission_state() {
    let branches: Vec<&str> = PROXY_SOURCE
        .split("Err(grpc_proxy::GrpcRequestBodyCollectError::AuthorizationExpired(")
        .skip(1)
        .map(|branch| {
            branch
                .split("Err(grpc_proxy::GrpcRequestBodyCollectError::Proxy")
                .next()
                .expect("bounded buffered gRPC authorization branch")
        })
        .collect();
    assert_eq!(branches.len(), 2, "split and mixed buffered gRPC arms");
    for branch in branches {
        assert!(branch.contains("grpc_probe_guard.disarm()"));
        assert!(branch.contains("release_circuit_breaker_probe_on_admission_reject("));
        assert!(branch.contains("preacquired_backend_admission.take_if_acquired()"));
        assert!(branch.contains("finalize_authorization_expired_rejection("));
        assert!(branch.contains("authorization_expired_buffered_grpc_upload"));
    }
}

#[test]
fn the_buffered_grpc_authorization_terminal_is_unauthenticated_and_latched() {
    // `grpc-status: 16` (`UNAUTHENTICATED`), never a fabricated DEADLINE_EXCEEDED.
    let normalized = PROXY_SOURCE
        .split("fn normalized_authorization_expired(")
        .nth(1)
        .expect("buffered gRPC authorization terminal")
        .split("\n}\n")
        .next()
        .expect("bounded terminal builder");
    assert!(normalized.contains("AUTHORIZATION_EXPIRED_GRPC_STATUS_HEADER"));
    assert!(normalized.contains("termination.grpc_message()"));
    assert!(
        !normalized.contains("GATEWAY_DEADLINE_EXCEEDED"),
        "an expired credential is never reported as a client-chosen RPC deadline"
    );
    // The bounded class reaches the transaction summary through the ordinary latch.
    let finalize = PROXY_SOURCE
        .split("async fn finalize_authorization_expired_rejection(")
        .nth(1)
        .expect("buffered gRPC authorization finalizer")
        .split("\n}\n")
        .next()
        .expect("bounded finalizer");
    assert!(finalize.contains("ctx.latch_authorization_termination(termination);"));
}

// --- Gateway-owned upload pump (#3815 / #3816) ------------------------------
//
// The pump exists because a body adapter alone cannot enforce the bound: hyper's
// `PipeToSendStream` awaits backend send capacity BEFORE it polls the request
// body, so a pipe parked on flow control polls nothing and observes no
// body-side signal. Every test below therefore holds the transport side and
// DELIBERATELY DOES NOT POLL IT while the bound fires.

#[tokio::test(start_paused = true)]
async fn the_authorization_deadline_releases_the_upload_while_the_backend_is_not_polling() {
    let plan = upload_plan(
        Duration::from_secs(2),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let mut probe = UploadPumpProbe::start(&plan);
    assert!(
        !probe.client_body_released(),
        "the pump must still own the client body before the deadline"
    );

    // No consumer poll, ever. The only thing that can end this upload is the
    // pump's own absolute bound.
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(probe.join().await, ProbePumpOutcome::AuthorizationExpired);
    assert!(
        probe.client_body_released(),
        "the pump must drop the inbound client body before it reports its outcome"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::Http
        ),
        "the pump must not count a second termination for the same request"
    );
}

#[tokio::test(start_paused = true)]
async fn an_expired_upload_ends_the_transport_body_with_an_error_not_a_clean_eof() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    let mut probe = UploadPumpProbe::start(&plan);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(probe.join().await, ProbePumpOutcome::AuthorizationExpired);

    // A clean end of stream here would let the backend treat a truncated
    // upload as a complete request.
    match probe.poll_transport_once() {
        ProbeTransportPoll::Errored(message) => {
            assert!(
                message.contains("authorization lifetime elapsed"),
                "unexpected termination message: {message}"
            );
            // Fixed literal: no expiry instant, claim, subject, or route.
            assert!(!message.contains(':') || message.starts_with("request upload terminated:"));
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_frame_queued_before_expiry_is_discarded_rather_than_forwarded_after_it() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    let mut probe = UploadPumpProbe::start(&plan);
    assert!(probe.feed("pre-expiry"));
    // Let the pump pick the frame up into the bounded bridge without the
    // transport ever draining it.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(probe.join().await, ProbePumpOutcome::AuthorizationExpired);

    assert!(
        matches!(probe.poll_transport_once(), ProbeTransportPoll::Errored(_)),
        "a frame still queued inside the gateway must not cross to the backend after expiry"
    );
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_pump_joins_it_while_the_backend_is_not_polling() {
    // The deadline is far away: this proves the DISPATCHER's join point works
    // on its own, which is what every bounded direct-H2 exit relies on.
    let plan = upload_plan(
        Duration::from_secs(3_600),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let latch = plan.2.clone();
    let mut probe = UploadPumpProbe::start(&plan);
    assert_eq!(probe.cancel_and_join().await, ProbePumpOutcome::Cancelled);
    assert!(
        probe.client_body_released(),
        "cancel_and_join must not return before the client body is released"
    );
    assert_eq!(
        latch.observed(),
        None,
        "a dispatcher cancellation is not an authorization termination"
    );
    assert!(matches!(
        probe.poll_transport_once(),
        ProbeTransportPoll::Errored(_)
    ));
}

#[tokio::test(start_paused = true)]
async fn releasing_the_transport_body_ends_the_pump() {
    let plan = upload_plan(
        Duration::from_secs(3_600),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let mut probe = UploadPumpProbe::start(&plan);
    probe.drop_transport();
    assert_eq!(probe.join().await, ProbePumpOutcome::ConsumerGone);
    assert!(
        probe.client_body_released(),
        "no pump may outlive the transport body it feeds"
    );
}

#[test]
fn the_upload_bridge_is_bounded_rather_than_a_buffer() {
    assert_eq!(
        UploadPumpProbe::channel_capacity(),
        1,
        "the pump must reserve capacity before reading, so it can never buffer the upload"
    );
}

// --- Composed dispatch-phase attribution under delayed observation (#3815) ---

#[tokio::test(start_paused = true)]
async fn an_earlier_protocol_bound_keeps_its_attribution_under_delayed_observation() {
    let plan = upload_plan(
        Duration::from_secs(2),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let bound = compose_dispatch_phase_bound_for_test(Some(1_000), Some(&plan));
    assert!(
        !bound.authorization_wins(),
        "a strictly earlier client/operator bound wins composition"
    );

    // Both instants are now in the past — the task was not scheduled until
    // after the LATER one. Re-deriving attribution from the clock here would
    // misreport the protocol's own timeout as an authorization expiry.
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&bound, Some(&plan)),
        None
    );
    assert_eq!(latch.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn an_earlier_authorization_bound_is_still_reported_under_delayed_observation() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    let bound = compose_dispatch_phase_bound_for_test(Some(2_000), Some(&plan));
    assert!(bound.authorization_wins());
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&bound, Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_exact_tie_is_attributed_to_the_authorization_decision() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    let bound = compose_dispatch_phase_bound_for_test(Some(1_000), Some(&plan));
    assert!(bound.authorization_wins());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&bound, Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_unbounded_phase_is_bounded_by_the_authorization_deadline_alone() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    let bound = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    assert!(bound.is_bounded());
    assert!(bound.authorization_wins());

    // No plan at all leaves the phase exactly as it was.
    let unauthenticated = compose_dispatch_phase_bound_for_test(None, None);
    assert!(!unauthenticated.is_bounded());
    assert!(!unauthenticated.authorization_wins());
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&unauthenticated, None),
        None
    );
}

#[tokio::test(start_paused = true)]
async fn a_buffered_collect_reports_the_earlier_protocol_bound_even_when_both_have_elapsed() {
    let start = tokio::time::Instant::now();
    let protocol_bound = start + Duration::from_secs(1);
    let plan = (
        plan_at(
            start + Duration::from_secs(2),
            StreamAuthTermination::CredentialExpired,
        ),
        StreamAuthProtocolFamily::GrpcWeb,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    );
    let latch = plan.2.clone();

    // The collect is not entered until after BOTH bounds have elapsed.
    tokio::time::advance(Duration::from_secs(5)).await;
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        Some(protocol_bound),
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::DeadlineExceeded);
    assert_eq!(
        latch.observed(),
        None,
        "the client RPC deadline bounded this collect, not the credential"
    );
}

// --- Source/wiring contracts for transports with no in-process harness -------

#[test]
fn every_streaming_h1h2_upload_installs_the_gateway_owned_pump() {
    // reqwest size-limited, reqwest unlimited, HBONE, Unix, mesh mTLS,
    // direct-H2 — plus the two definitions.
    assert_eq!(
        PROXY_SOURCE
            .matches("install_streaming_upload_authorization(")
            .count(),
        6,
        "an H1/H2 streaming upload lost its gateway-owned lifecycle"
    );
    assert_eq!(
        PROXY_SOURCE
            .matches("install_counting_upload_authorization(")
            .count(),
        2,
        "the unlimited-size reqwest upload lost its gateway-owned lifecycle"
    );
    // Native gRPC keeps its own body type, so it installs the pump directly on
    // the shared upload source rather than through the H1/H2 adapters.
    assert!(
        GRPC_PROXY_SOURCE.contains("UploadSource::for_streaming_upload(body, auth)"),
        "the fully-streamed native-gRPC upload lost its gateway-owned lifecycle"
    );
    // The adapter deadline and the pump are installed together from one place,
    // so a transport cannot get one without the other.
    let installer = PROXY_SOURCE
        .split("pub(crate) fn install_streaming_upload_authorization(")
        .nth(1)
        .expect("streaming upload installer")
        .split("\n}\n")
        .next()
        .expect("bounded installer body");
    assert!(installer.contains("with_authorization_deadline("));
    assert!(installer.contains("with_gateway_upload_pump("));
    // Unauthenticated requests keep the previous zero-overhead path.
    assert!(installer.contains("let Some(plan) = auth else {"));
}

#[test]
fn the_direct_h2_handler_joins_its_upload_before_returning() {
    // Every bounded direct-H2 exit, plus the normal completion path, joins the
    // pump; the residual error exits are covered by `cancel_on_drop`.
    assert_eq!(
        PROXY_SOURCE
            .matches("pump.cancel_and_join().await;")
            .count(),
        3,
        "a direct-H2 exit stopped joining the gateway-owned upload"
    );
    assert!(
        PROXY_SOURCE.contains("UploadPumpJoin::cancel_on_drop"),
        "direct-H2 must arm cancel-on-drop so residual early returns still release the upload"
    );
}

#[test]
fn the_authorization_expired_rejection_future_is_built_out_of_line() {
    // Stack-budget invariant, not style (the one issue #3764 established for
    // `boxed_proxy_to_backend_unix`). `handle_proxy_request_inner` is the
    // generic request future every HTTP request is polled through, and in an
    // unoptimized build every future awaited inline there is a fixed frame slot
    // charged to EVERY request — including ones that can never take the branch.
    // The rejection pipeline this arm awaits (after-proxy hooks, commit policy,
    // gRPC-Web translation, rejection logging) is large enough that two inline
    // copies overflowed a tokio worker stack on the coverage profile.
    assert_eq!(
        PROXY_SOURCE
            .matches("Ok(finalize_authorization_expired_rejection(")
            .count(),
        0,
        "the authorization-expired rejection future must not be materialized in \
         the generic request future's frame"
    );
    assert_eq!(
        PROXY_SOURCE
            .matches("Ok(boxed_finalize_authorization_expired_rejection(")
            .count(),
        2,
        "both buffered-gRPC authorization arms must use the out-of-line factory"
    );
    let factory = PROXY_SOURCE
        .split("fn boxed_finalize_authorization_expired_rejection<'a>(")
        .next()
        .expect("the out-of-line rejection factory must remain present");
    assert!(
        factory.ends_with("#[allow(clippy::too_many_arguments)]\n#[inline(never)]\n"),
        "the factory must stay `#[inline(never)]`: inlining it back into the \
         caller restores the frame slot it exists to remove"
    );
}

/// The same stack-budget invariant, for the authorization terminals that are
/// SYNCHRONOUS rather than awaited.
///
/// Boxing only helps a future. A cold block of straight-line code inside one of
/// the two deepest coroutines — `handle_proxy_request_inner` and
/// `proxy_to_backend` — still costs a permanent frame slot per temporary at
/// `opt-level = 0`, because every alloca is emitted on function entry whichever
/// branch runs. Three of this contract's constructions are wide
/// (`(status, HeaderMap, ResponseBody)` terminals, `ProxyBody` moves, and
/// `retry::BackendResponse`), and inlining them across eleven cold sites
/// overflowed a tokio worker stack on the coverage profile for a plain
/// unauthenticated non-gRPC request that can reach none of them. Each must stay
/// behind an `#[inline(never)]` frame that returns before anything is awaited.
#[test]
fn the_precommit_authorization_terminal_is_applied_out_of_line() {
    for (callee, expected_calls) in [
        ("apply_precommit_authorization_terminal(", 2),
        ("install_response_authorization_deadline(", 2),
        ("authorization_expired_backend_dispatch(", 7),
    ] {
        let definition = format!("fn {callee}");
        let before_definition = PROXY_SOURCE
            .split(definition.as_str())
            .next()
            .expect("the out-of-line helper must remain present");
        assert!(
            // A visibility modifier may sit between the attribute and `fn`; the
            // attribute itself is what must stay attached.
            before_definition.ends_with("#[inline(never)]\n")
                || before_definition.ends_with("#[inline(never)]\npub(crate) "),
            "{callee} must stay `#[inline(never)]`: inlining it back into the \
             caller restores the frame slots it exists to remove"
        );
        assert_eq!(
            PROXY_SOURCE.matches(callee).count(),
            expected_calls + 1,
            "{callee} lost a call site, so a cold authorization terminal is built \
             inline in a hot coroutine's frame again"
        );
    }

    // Moving the work out of line must not move the security decision: the
    // shared latch is still consulted first, an unlatched-but-elapsed plan is
    // still recorded exactly once through it, and the only terminal selectable
    // is still the fixed, redacted pre-commitment one.
    let applier = PROXY_SOURCE
        .split("fn apply_precommit_authorization_terminal(")
        .nth(1)
        .expect("the out-of-line applier body")
        .split("\n}\n")
        .next()
        .expect("bounded applier body");
    assert!(applier.contains("ctx.authorization_termination_latch.observed()"));
    assert!(applier.contains("expired_authorization("));
    assert!(applier.contains("record_once(elapsed, family)"));
    assert!(applier.contains("authorization_expired_pre_commitment_response("));
    assert!(applier.contains("ctx.latch_authorization_termination(termination);"));

    // The response funnels keep the family selection and the shared latch/closer
    // wiring they had inline.
    let installer = PROXY_SOURCE
        .split("fn install_response_authorization_deadline(")
        .nth(1)
        .expect("the out-of-line response installer body")
        .split("\n}\n")
        .next()
        .expect("bounded installer body");
    assert!(installer.contains("effective_request_auth_deadline("));
    assert!(installer.contains("StreamAuthProtocolFamily::GrpcWeb"));
    assert!(installer.contains("StreamAuthProtocolFamily::Grpc"));
    assert!(installer.contains("StreamAuthProtocolFamily::Http"));
    assert!(installer.contains("with_authorization_deadline("));
    assert!(installer.contains("Some(ctx.authorization_termination_latch())"));
    assert!(installer.contains("ctx.authorization_connection_closer.clone()"));
}

// ---------------------------------------------------------------------------
// DTLS session authorization lifetime (issue #3816).
//
// `on_stream_connect` runs once, at admission, so a DTLS session would
// otherwise outlive the certificate that admitted it. The absolute plan is
// composed over EVERY awaitable post-admission setup stage — DNS resolution and
// the backend UDP/DTLS connect + handshake — and re-checked immediately before
// relay task creation, so slow setup cannot carry an expired credential into a
// relay, a backend success, or a forwarded datagram.
// ---------------------------------------------------------------------------

const UDP_PROXY_SOURCE: &str = include_str!("../../../src/proxy/udp_proxy.rs");
const UPLOAD_PUMP_SOURCE: &str = include_str!("../../../src/proxy/upload_pump.rs");

const DTLS_SETUP_EXPIRED_ERROR: &str =
    "Authenticated stream authorization lifetime elapsed during setup (DTLS session)";
const DTLS_RELAY_EXPIRED_ERROR: &str =
    "authenticated DTLS session terminated: authorization lifetime reached";
const TERMINATION_REASON_KEY: &str = "authorization.termination_reason";

fn dtls_plan(after: Duration, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now() + after,
        termination,
    }
}

/// Every DTLS authorization expiry is client-side, health-neutral, classified
/// from the type rather than from message text, and publishes exactly one
/// bounded class into the metadata the disconnect summary carries.
fn assert_dtls_expiry_is_policy_neutral(expiry: &DtlsAuthorizationExpiryForTest) {
    assert_eq!(
        expiry.error_class,
        ErrorClass::RequestError,
        "an authorization expiry must never read as a transport or backend fault"
    );
    assert_eq!(expiry.disconnect_cause, DisconnectCause::RecvError);
    assert_eq!(expiry.disconnect_direction, Direction::ClientToBackend);
    // Redaction: the wording is a compiled-in literal, so no expiry instant,
    // identity, certificate field, provider detail, or client address can reach
    // it. Any of those would have to print a digit.
    assert!(
        !expiry.error.chars().any(|c| c.is_ascii_digit()),
        "unexpected value in a fixed termination message: {}",
        expiry.error
    );
    let reason = expiry.metadata.get(TERMINATION_REASON_KEY).cloned();
    assert_eq!(
        reason.as_deref(),
        Some("credential_expired"),
        "the bounded class must reach the stream transaction summary"
    );
    assert_eq!(expiry.metadata.len(), 1, "one class, nothing else");
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_dtls_plan_never_starts_a_setup_stage() {
    let _guard = counter_delta_guard().await;
    let plan = dtls_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_secs(2)).await;

    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&started);
    let stage = move || async move {
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
        "resolved"
    };
    let before = counters();
    let expiry = dtls_setup_stage_under_authorization_for_test(Some(plan), stage)
        .await
        .expect_err("an elapsed plan must not admit a post-admission setup stage");
    let after = counters();

    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "an expired credential must resolve no name and dial no backend"
    );
    assert_eq!(
        expiry.setup_kind,
        Some(StreamSetupKind::AuthorizationExpired)
    );
    assert!(
        expiry.setup_kind.expect("typed kind").is_client_side(),
        "a gateway policy decision about the client's credential is client-side"
    );
    assert_eq!(expiry.error, DTLS_SETUP_EXPIRED_ERROR);
    assert_eq!(
        expiry.probe_releases, 1,
        "a claimed HALF_OPEN probe slot must be released exactly once, neutrally"
    );
    assert_eq!(
        after.credential_expired["stream_udp"] - before.credential_expired["stream_udp"],
        1
    );
    assert_eq!(
        after.authenticated_stream_max_lifetime["stream_udp"],
        before.authenticated_stream_max_lifetime["stream_udp"],
        "only the class the plan carries may be counted"
    );
    assert_dtls_expiry_is_policy_neutral(&expiry);
}

#[tokio::test(start_paused = true)]
async fn a_dtls_setup_stage_outliving_the_plan_is_cancelled_and_health_neutral() {
    let _guard = counter_delta_guard().await;
    let plan = dtls_plan(
        Duration::from_millis(50),
        StreamAuthTermination::CredentialExpired,
    );
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker = Arc::clone(&finished);
    // A backend connect + DTLS handshake still in flight when the credential
    // expires.
    let stage = move || async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        marker.store(true, std::sync::atomic::Ordering::SeqCst);
    };
    let before = counters();
    let expiry = dtls_setup_stage_under_authorization_for_test(Some(plan), stage)
        .await
        .expect_err("the stage must be cancelled at the absolute deadline");
    let after = counters();

    assert!(
        !finished.load(std::sync::atomic::Ordering::SeqCst),
        "the in-flight setup future must be dropped, not finished"
    );
    assert_eq!(
        expiry.setup_kind,
        Some(StreamSetupKind::AuthorizationExpired)
    );
    assert_eq!(expiry.error, DTLS_SETUP_EXPIRED_ERROR);
    assert_eq!(
        expiry.probe_releases, 1,
        "the HALF_OPEN probe slot is released neutrally: no backend success, no failure"
    );
    let credential_expired_delta =
        after.credential_expired["stream_udp"] - before.credential_expired["stream_udp"];
    assert_eq!(
        credential_expired_delta, 1,
        "the fixed-cardinality termination is recorded exactly once"
    );
    assert_dtls_expiry_is_policy_neutral(&expiry);
}

#[tokio::test(start_paused = true)]
async fn a_dtls_setup_stage_inside_the_plan_completes_untouched() {
    let plan = dtls_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let stage = || async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        "backend connected"
    };
    let connected = dtls_setup_stage_under_authorization_for_test(Some(plan), stage)
        .await
        .expect("a stage that finishes before the deadline is untouched");
    assert_eq!(connected, "backend connected");
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_dtls_session_runs_setup_with_no_bound_at_all() {
    // Plain UDP and unauthenticated DTLS behaviour is preserved: no plan means
    // no timer is registered and the stage runs exactly as it always did.
    let stage = || async {
        tokio::time::sleep(Duration::from_secs(7_200)).await;
        "backend connected"
    };
    let connected = dtls_setup_stage_under_authorization_for_test(None, stage)
        .await
        .expect("an unauthenticated session is not bounded by this contract");
    assert_eq!(connected, "backend connected");
}

#[tokio::test(start_paused = true)]
async fn the_pre_relay_gate_refuses_an_elapsed_plan_and_admits_a_live_one() {
    let plan = dtls_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let expired = Some(StreamAuthTermination::CredentialExpired);
    let now = tokio::time::Instant::now();
    let live = dtls_authorization_expired_before_relay_for_test(Some(plan), now);
    // Exact equality goes to the security decision: at the instant itself the
    // session is already outside its authorization lifetime.
    let at_deadline = dtls_authorization_expired_before_relay_for_test(Some(plan), plan.at);
    let past_deadline = dtls_authorization_expired_before_relay_for_test(
        Some(plan),
        plan.at + Duration::from_millis(1),
    );
    let later = plan.at + Duration::from_secs(600);
    let unauthenticated = dtls_authorization_expired_before_relay_for_test(None, later);

    assert_eq!(live, None, "a live plan still admits the relay");
    assert_eq!(at_deadline, expired);
    assert_eq!(past_deadline, expired);
    assert_eq!(unauthenticated, None, "an unauthenticated session is fine");
}

#[tokio::test]
async fn a_relay_phase_dtls_expiry_publishes_the_bounded_class_exactly_once() {
    let _guard = counter_delta_guard().await;
    let latch = ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default();
    let session_metadata = std::sync::Mutex::new(std::collections::HashMap::new());

    let before = counters();
    let first = settle_dtls_relay_authorization_expiry_for_test(
        StreamAuthTermination::CredentialExpired,
        &latch,
        &session_metadata,
    );
    // The relay races both directions and the idle watchdog against one plan,
    // so a second settlement must be a no-op.
    let second = settle_dtls_relay_authorization_expiry_for_test(
        StreamAuthTermination::CredentialExpired,
        &latch,
        &session_metadata,
    );
    let after = counters();

    assert_eq!(
        after.credential_expired["stream_udp"] - before.credential_expired["stream_udp"],
        1
    );
    assert_eq!(first.setup_kind, None, "the relay phase is not setup");
    assert_eq!(first.error, DTLS_RELAY_EXPIRED_ERROR);
    assert_dtls_expiry_is_policy_neutral(&first);
    assert_dtls_expiry_is_policy_neutral(&second);

    // The accept loop merges `DtlsHandlerResult::metadata` over the metadata
    // taken from `on_stream_connect` before building the summary, so the
    // bounded class reaches `on_stream_disconnect` and the stream transaction
    // summary through the ordinary lifecycle.
    let mut merged =
        std::collections::HashMap::from([("waf.signature".to_string(), "none".to_string())]);
    merged.extend(first.metadata.clone());
    let merged_reason = merged.get(TERMINATION_REASON_KEY).cloned();
    let survived = merged.get("waf.signature").cloned();
    assert_eq!(merged_reason.as_deref(), Some("credential_expired"));
    assert_eq!(
        survived.as_deref(),
        Some("none"),
        "connect metadata survives"
    );
}

#[test]
fn the_dtls_and_upload_pump_authorization_paths_carry_no_production_panic() {
    // Ferrum's proxy path may not panic even behind a documented logical
    // invariant, so neither file may reintroduce one.
    for (name, source) in [
        ("src/proxy/udp_proxy.rs", UDP_PROXY_SOURCE),
        ("src/proxy/upload_pump.rs", UPLOAD_PUMP_SOURCE),
    ] {
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for macro_name in ["unreachable!", "panic!(", "todo!", "unimplemented!"] {
            assert!(
                !production.contains(macro_name),
                "{name} reintroduced `{macro_name}` on a proxy path"
            );
        }
    }
    // The disarmed upload cancellation arm expresses "this await never
    // resolves" as an uninhabited type instead of asserting it.
    assert!(
        UPLOAD_PUMP_SOURCE
            .contains("match std::future::pending::<std::convert::Infallible>().await {}"),
        "the disarmed cancellation arm must stay a panic-free never-type match"
    );
}

// ── Buffered RESPONSE collection and the pre-commitment response phases ─────
//
// A buffered collect is the one response phase with no downstream body adapter:
// the bytes are retained, not relayed, so there is nothing yet for a `ProxyBody`
// deadline to cancel. Its only other bound is the PER-FRAME
// `backend_read_timeout_ms`, which `0` disables outright — a backend that
// trickles frames then keeps an authenticated request collecting forever.

fn response_plan(
    after: Duration,
    termination: StreamAuthTermination,
) -> (
    StreamAuthDeadline,
    StreamAuthProtocolFamily,
    ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch,
) {
    (
        plan_at(tokio::time::Instant::now() + after, termination),
        StreamAuthProtocolFamily::Http,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    )
}

#[tokio::test(start_paused = true)]
async fn a_stalled_buffered_response_collect_is_cancelled_at_the_authorization_deadline() {
    // No client RPC deadline and `backend_read_timeout_ms = 0`: without the
    // authorization arm this collect is completely unbounded.
    let plan = response_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let started = tokio::time::Instant::now();
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        std::future::pending::<()>(),
        None,
        Some(&plan),
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::AuthorizationExpired);
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(30),
        "the collect must end AT the credential deadline, not later"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::Http
        ),
        "the expiry is counted exactly once for the request"
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_client_rpc_deadline_still_owns_a_buffered_response_collect() {
    let plan = response_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let rpc_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        std::future::pending::<()>(),
        Some(rpc_deadline),
        Some(&plan),
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::RpcDeadline);
    assert_eq!(
        latch.observed(),
        None,
        "a client-chosen RPC deadline is not an authorization termination"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_buffered_response_collect_keeps_its_own_bounds() {
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        std::future::ready(()),
        None,
        None,
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::Completed);
}

#[tokio::test(start_paused = true)]
async fn a_response_phase_is_bounded_by_the_authorization_deadline_alone() {
    // A slow response hook (`after_proxy`, a body transform, the final
    // client-visible policies, the committed hook) on an ordinary HTTP request
    // has no `grpc-timeout` at all, so before this composition every one of
    // them could run past the credential that admitted the stream and then
    // commit a protected response head.
    // The maximum is a PROCESS-WIDE scalar and this binary runs tests in
    // parallel, so every writer serializes through the one shared test lock and
    // restores the prior value on drop.
    let lifetime_guard = crate::unit::env_lock::StreamAuthMaxLifetimeGuard::new();
    lifetime_guard.publish(120);
    let ctx = authenticated_ctx();
    let bound = ferrum_edge::_test_support::precommit_response_phase_deadline_for_test(&ctx)
        .expect("an admitted authenticated request must bound every pre-commitment phase");
    assert!(
        bound <= tokio::time::Instant::now() + Duration::from_secs(120),
        "the phase bound must never exceed the finite authenticated-stream maximum"
    );

    // An unauthenticated request with no RPC deadline is untouched.
    assert_eq!(
        ferrum_edge::_test_support::precommit_response_phase_deadline_for_test(&anonymous_ctx()),
        None
    );

    // `lifetime_guard` restores the previous process-wide value on drop.
    drop(lifetime_guard);
}

/// Native-H3 gRPC dispatch composes the authorization deadline over BOTH
/// pre-commitment phases (issue #3815).
///
/// `dispatch_grpc_native_h3` opens the backend stream and then races the
/// request-upload pump against the backend's response head. Both of that race's
/// protocol bounds can be absent at once — no client `grpc-timeout` and
/// `backend_read_timeout_ms: 0` — and a continuously active upload keeps the
/// pump making progress forever, so without the composed bound an admitted
/// credential stayed authorized while NO response head existed.
#[test]
fn native_h3_grpc_dispatch_phases_compose_the_authorization_lifetime() {
    let dispatch = H3_SERVER_SOURCE
        .split("async fn dispatch_grpc_native_h3(")
        .nth(1)
        .expect("native-H3 gRPC dispatch")
        // Bounded at the next item: the counted assertions below are about THIS
        // dispatch, and an unbounded tail would fold in every later relay's own
        // hoisted plan.
        .split("async fn log_h3_grpc_transaction(")
        .next()
        .expect("bounded native-H3 gRPC dispatch");
    // The plan is hoisted AHEAD of the backend open, and the dispatch bound is
    // the composition rather than the raw protocol bound.
    let precommit = dispatch
        .split("// ── Phase 2:")
        .next()
        .expect("bounded pre-commitment section");
    assert!(precommit.contains("let protocol_dispatch_deadline_at ="));
    assert!(
        precommit.contains("ComposedAuthBound::compose(\n        protocol_dispatch_deadline_at,"),
        "the dispatch deadline must be the TYPED composition, not the protocol bound alone \
         and not a bare instant"
    );
    assert!(
        precommit.contains("let dispatch_deadline_at = dispatch_bound.deadline();"),
        "the awaited instant must be a projection of the captured composition"
    );
    // Both phases check authorization FIRST, so a policy expiry is never
    // reported as a backend timeout and never downgrades the H3 capability.
    assert_eq!(
        dispatch
            .matches("Some(termination) => Err(termination),")
            .count(),
        2,
        "a native-H3 gRPC dispatch phase lost its authorization attribution"
    );
    // ...and both attribute from the CAPTURED composition. Re-reading the clock
    // after the timeout returns would report the security decision for a phase
    // a strictly earlier client `grpc-timeout` actually bounded, whenever this
    // task was not scheduled again until after the later authorization deadline
    // had also passed.
    assert_eq!(
        dispatch
            .matches("Err(()) => match dispatch_bound.expired_authorization() {")
            .count(),
        2,
        "a native-H3 gRPC dispatch phase re-derives its owner from the clock"
    );
    assert_eq!(
        dispatch
            .matches("await_deadline_first(dispatch_deadline_at,")
            .count(),
        2,
        "both pre-commitment native-H3 gRPC waits must use the shared expiry-first primitive"
    );
    assert!(
        !dispatch.contains("timeout_at(at, open_fut)")
            && !dispatch.contains("timeout_at(at, header_fut)"),
        "timeout_at polls the protected future first, so an already-elapsed bound would accept it"
    );
    let bounded_phases = dispatch
        .split("let dispatch_bound =")
        .nth(1)
        .expect("composed dispatch bound")
        .split("let h3_resp = match head_result {")
        .next()
        .expect("bounded open + header-wait phases");
    assert!(
        !bounded_phases.contains("expired_authorization(auth_deadline_plan)"),
        "the dispatch phases must not re-read the clock to choose between the two owners"
    );
    assert_eq!(
        dispatch
            .matches("send_h3_grpc_authorization_expired_terminal(")
            .count(),
        2,
        "both pre-commitment phases must emit the fixed trailers-only terminal"
    );
    // The relay loop reuses the SAME hoisted plan rather than re-anchoring: one
    // arbiter call for the whole dispatch.
    assert_eq!(
        dispatch.matches("effective_request_auth_deadline(").count(),
        1,
        "the relay must not recompute its own authorization plan"
    );
    // The header-race arm cancels and JOINS the gateway-owned upload pump.
    assert!(dispatch.contains("pump_guard.retire().await;"));
}

/// The pre-commitment native-H3 gRPC terminal is `UNAUTHENTICATED`, redacted,
/// and health-neutral.
#[test]
fn the_native_h3_grpc_precommit_terminal_is_unauthenticated_and_health_neutral() {
    let terminal = H3_SERVER_SOURCE
        .split("async fn send_h3_grpc_authorization_expired_terminal<S>(")
        .nth(1)
        .expect("native-H3 gRPC pre-commitment terminal")
        .split("\n/// ")
        .next()
        .expect("bounded terminal builder");
    assert!(terminal.contains("grpc_status::UNAUTHENTICATED"));
    assert!(terminal.contains("termination.grpc_message()"));
    assert!(terminal.contains("record_once("));
    assert!(terminal.contains("ctx.latch_authorization_termination(termination);"));
    assert!(terminal.contains("outcome_connection_error: false,"));
    assert!(terminal.contains("crate::retry::ErrorClass::ClientDisconnect"));
    assert!(
        !terminal.contains("mark_h3_unsupported"),
        "a gateway policy expiry must never downgrade a proven backend capability"
    );
    assert!(
        !terminal.contains("DEADLINE_EXCEEDED"),
        "an expired credential is never reported as a client-chosen RPC deadline"
    );
}

/// Cross-protocol plain pre-commitment authorization expiry writes the fixed
/// redacted 401 under a fresh gateway-owned grace, then resets if QUIC credit
/// is withheld. The already-expired authorization instant must not race the
/// terminal, and a failed/timed-out write must not claim a completed body.
#[test]
fn cross_protocol_plain_precommit_401_is_grace_bounded_and_health_neutral() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = cross
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("cross-protocol plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol plain dispatcher");

    let upload = dispatch
        .split("if let Some(termination) = upload_auth_expired {")
        .nth(1)
        .expect("streaming upload authorization-expiry arm")
        .split("record_plain_grpc_web_client_deadline(")
        .next()
        .expect("bounded streaming upload authorization-expiry arm");
    assert!(upload.contains("record_authorization_termination_once("));
    assert!(upload.contains("write_plain_authorization_expired_terminal("));
    assert!(
        !upload.contains("write_plain_gateway_error("),
        "the upload-auth-expiry 401 must not use the unbounded reject writer"
    );
    let record_once = upload
        .find("record_authorization_termination_once(")
        .expect("upload expiry records the bounded class");
    let write_401 = upload
        .find("write_plain_authorization_expired_terminal(")
        .expect("upload expiry writes the bounded 401");
    assert!(
        record_once < write_401,
        "fixed-cardinality authorization termination must be recorded before the 401 write"
    );

    let header_expiry_arms: Vec<&str> = dispatch
        .split("if let Some(termination) = plain_write_bound.expired_authorization() {")
        .skip(1)
        .collect();
    let header_write_arms: Vec<&str> = header_expiry_arms
        .iter()
        .copied()
        .filter(|arm| arm.contains("write_plain_grpc_web_client_deadline_without_hooks("))
        .collect();
    assert_eq!(
        header_write_arms.len(),
        2,
        "buffered and streaming pre-commitment response-header authorization arms must remain"
    );
    for (label, arm) in [
        ("buffered response-header", header_write_arms[0]),
        ("streaming response-header", header_write_arms[1]),
    ] {
        let arm = arm
            .split("write_plain_grpc_web_client_deadline_without_hooks(")
            .next()
            .unwrap_or_else(|| panic!("bounded {label} authorization-expiry arm"));
        assert!(
            arm.contains("record_authorization_termination_once("),
            "{label} expiry must record the bounded class exactly on this arm"
        );
        assert!(
            arm.contains("write_plain_authorization_expired_terminal("),
            "{label} expiry must use the grace-bounded 401 writer"
        );
        assert!(
            !arm.contains("write_plain_gateway_error("),
            "{label} expiry must not use the unbounded reject writer"
        );
    }
    let postcommit = header_expiry_arms
        .iter()
        .copied()
        .find(|arm| arm.contains("append_plain_grpc_web_client_deadline("))
        .expect("post-commitment buffered-body authorization arm")
        .split("append_plain_grpc_web_client_deadline(")
        .next()
        .expect("bounded post-commitment buffered-body authorization arm");
    assert!(
        postcommit.contains("abort_response_stream(stream)"),
        "post-commitment expiry must RESET rather than append a 401"
    );
    assert!(
        !postcommit.contains("write_plain_authorization_expired_terminal("),
        "post-commitment expiry must not write a second client-visible terminal"
    );

    let helper = cross
        .split("async fn write_plain_authorization_expired_terminal<S>(")
        .nth(1)
        .expect("bounded plain authorization-expiry terminal writer")
        .split("async fn write_reject_with_headers<S>(")
        .next()
        .expect("bounded plain authorization-expiry terminal writer body");
    assert!(helper.contains("await_post_deadline_terminal_response_write(write)"));
    assert!(!helper.contains("await_terminal_response_write_before_deadline("));
    assert!(helper.contains("abort_response_stream(stream)"));
    assert!(helper.contains("halt_request_body(stream)"));
    assert!(helper.contains("terminal_deadline_write_aborted_outcome("));
    assert!(
        helper.contains("StatusCode::UNAUTHORIZED"),
        "a failed post-authorization write still accounts the gateway 401, not a backend fault"
    );
    assert!(
        !helper.contains("insert_grpc_error_metadata("),
        "plain HTTP must not fabricate gRPC metadata for the authorization 401"
    );
    let inner_write = helper
        .split("write_plain_gateway_reject_with_recv_halt(")
        .nth(1)
        .expect("inner send-only 401 writer")
        .split(");")
        .next()
        .expect("bounded inner send-only 401 writer");
    assert!(
        inner_write.contains("false,"),
        "the inner 401 writer must defer STOP_SENDING until the bounded write settles"
    );

    let aborted = cross
        .split("fn terminal_deadline_write_aborted_outcome(")
        .nth(1)
        .expect("terminal deadline write outcome")
        .split("async fn write_final_body_reject<S>(")
        .next()
        .expect("bounded terminal deadline write outcome");
    assert!(aborted.contains("body_completed: false,"));
    assert!(aborted.contains("connection_error: false,"));
    assert!(aborted.contains("error_class: None,"));
    assert!(aborted.contains("client_disconnected.then_some(ErrorClass::ClientDisconnect)"));
}

// --- Native HTTP/3 gRPC: the post-head gap (issue #3815, root finding 5) -----

/// The native-H3 gRPC relay writes its own response head, so a `ProxyBody`
/// adapter cannot bound it. Every client-visible terminal it can produce while
/// the head is still uncommitted — the declared-size refusal, the `after_proxy`
/// rejection, and the HEADERS themselves — must be preceded by the same
/// authorization gate, and the gate must produce the ONE fixed terminal.
#[test]
fn every_precommit_h3_grpc_terminal_is_preceded_by_the_authorization_gate() {
    let relay = H3_SERVER_SOURCE
        .split("macro_rules! h3_grpc_authorization_precommit_terminal {")
        .nth(1)
        .expect("the native H3 gRPC pre-commitment authorization terminal");

    // The gate expands at exactly three uncommitted-head points.
    assert_eq!(
        relay
            .matches("h3_grpc_authorization_precommit_terminal!(")
            .count(),
        4,
        "the declared-size refusal, the hook rejection, the response head, and the \
         head-write expiry must each take the SAME fixed authorization terminal"
    );

    let terminal = relay
        .split("\n    }\n")
        .next()
        .expect("bounded terminal macro body");
    // The fixed trailers-only `grpc-status: 16`, through the bounded write grace.
    assert!(terminal.contains("AUTHORIZATION_EXPIRED_GRPC_STATUS_HEADER"));
    assert!(terminal.contains("await_h3_grpc_terminal_write_with_grace("));
    assert!(terminal.contains("send_h3_grpc_reject_trailers_only("));
    // Counted once, through the request's shared latch.
    assert!(terminal.contains("ctx.record_authorization_termination_once("));
    // Cancel-and-join the gateway-owned upload pump, then release the permits
    // exactly once — response BEFORE teardown.
    let write_at = terminal
        .find("await_h3_grpc_terminal_write_with_grace(")
        .expect("terminal write");
    let retire_at = terminal
        .find("pump_guard.retire().await;")
        .expect("pump retire");
    let permits_at = terminal
        .find("record_h3_backend_admission_outcome(")
        .expect("admission permit release");
    assert!(
        write_at < retire_at && retire_at < permits_at,
        "the terminal must reach the wire before the upload pump is retired and the \
         admission permits are released"
    );
    assert_eq!(
        terminal
            .matches("record_h3_backend_admission_outcome(")
            .count(),
        1,
        "the admission permit set must be released exactly once"
    );
    // CB / passive health / adaptive concurrency stay neutral: the TRUE backend
    // status with NO error class.
    let outcome = terminal
        .split("record_backend_outcome(")
        .nth(1)
        .expect("backend outcome")
        .split(");")
        .next()
        .expect("bounded backend outcome");
    assert!(
        outcome.contains("response_status,"),
        "the gateway's own security decision must never rewrite the backend's status"
    );
    assert!(
        !outcome.contains("ErrorClass::"),
        "no error class may be charged to the backend for a gateway policy expiry"
    );
    // A gateway policy expiry is never a capability signal.
    assert!(!terminal.contains("mark_h3_unsupported"));
}

/// The response HEADERS write is bounded by the COMPOSED bound, and an
/// authorization expiry on it resets rather than misreporting the client's
/// `DEADLINE_EXCEEDED`.
///
/// The composition is the TYPED one: attribution must come from the captured
/// bound rather than from re-reading the clock after the write returns, or a
/// strictly earlier client `grpc-timeout` observed after a late wake would be
/// reattributed to the security decision.
#[test]
fn the_h3_grpc_response_head_write_is_bounded_by_the_composed_deadline() {
    let region = H3_SERVER_SOURCE
        .split("let response_header_write_bound =")
        .nth(1)
        .expect("composed response-header write bound");
    let assignment = region
        .split(';')
        .next()
        .expect("the composed bound assignment");
    assert!(
        assignment.contains("ComposedAuthBound::compose(")
            && assignment.contains("grpc_deadline_at")
            && assignment.contains("auth_deadline_plan"),
        "the head write must race the EARLIEST of the client RPC deadline and the \
         authorization deadline, not the client deadline alone, and must keep the \
         winning source"
    );
    let bounded = region
        .split("if let Err(write_error) = response_header_write {")
        .next()
        .expect("bounded head-write region");
    assert!(bounded.contains("send_half.send_response(resp),"));
    assert!(
        !bounded.contains("expired_authorization(auth_deadline_plan)"),
        "the head write must not re-derive the winning owner from the clock; a strictly \
         earlier client deadline observed after a late wake would be misattributed to \
         authorization"
    );
    // Authorization is attributed BEFORE the generic deadline branch, and the
    // generic branch is the only one that may report DEADLINE_EXCEEDED.
    let auth_at = bounded
        .find("response_header_write_bound.expired_authorization()")
        .expect("authorization attribution");
    let terminal_at = bounded
        .find("h3_grpc_authorization_precommit_terminal!(termination, false)")
        .expect("reset-instead-of-wait terminal");
    assert!(
        auth_at < terminal_at,
        "an expiry on the head write must be attributed before a terminal is chosen"
    );
    assert!(
        !bounded.contains("GATEWAY_DEADLINE_EXCEEDED_MESSAGE"),
        "an authorization expiry on the head write must not be misreported as the \
         client's own DEADLINE_EXCEEDED"
    );
}

/// A stalled (never-ready) streaming response HEADERS write expires at the
/// authorization deadline, latches exactly once, and never treats the write as
/// committed.
///
/// Exactly-once is asserted on the REQUEST-OWNED latch rather than on the
/// process-global termination counters. `record_once` performs its single
/// increment only for the caller that wins the latch CAS, so the latch is where
/// the invariant actually lives — and `credential_expired["http"]` is driven
/// concurrently by other suites in this binary (the body-termination tests
/// reach it through production paths and never take this file's guard), so an
/// exact global delta on the `http` family is not this test's to claim. Every
/// other exact-delta assertion in this file deliberately uses `stream_tcp` or
/// `stream_udp` for that reason.
#[tokio::test(start_paused = true)]
async fn a_stalled_h3_streaming_headers_write_expires_at_the_authorization_deadline() {
    let now = tokio::time::Instant::now();
    let plan = plan_at(
        now + Duration::from_secs(2),
        StreamAuthTermination::CredentialExpired,
    );
    let bound = ComposedAuthBound::compose(None, Some(plan));
    let latch = StreamAuthTerminationLatch::default();

    let write = std::future::pending::<Result<(), &'static str>>();
    let started = tokio::time::Instant::now();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        write,
    )
    .await;
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(2)
    );
    assert_eq!(
        outcome,
        H3AuthorizedHeadersWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    // The latch started fresh, so the awaited write is what claimed it — and a
    // claimed latch refuses every further record, which is precisely the one
    // counter increment `record_once` is allowed to make for this request.
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::Http
        ),
        "the HEADERS expiry must already own this request's single termination record"
    );

    // A second observer of the same expired bound must not record again.
    let second = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        std::future::pending::<Result<(), &'static str>>(),
    )
    .await;
    assert_eq!(
        second,
        H3AuthorizedHeadersWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "a second HEADERS expiry must not relatch a different class"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::Http
        ),
        "a second HEADERS expiry on the same latch must not double-count"
    );
}

/// An already-elapsed authorization bound must not poll the HEADERS write at
/// all, so no protected response head can commit after expiry.
#[tokio::test(start_paused = true)]
async fn an_elapsed_authorization_bound_never_polls_the_streaming_headers_write() {
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&polled);
    let write = std::future::poll_fn(move |_cx| {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(Ok::<(), &'static str>(()))
    });
    let plan = plan_at(
        tokio::time::Instant::now(),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let bound = ComposedAuthBound::compose(None, Some(plan));
    let latch = StreamAuthTerminationLatch::default();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        write,
    )
    .await;
    assert_eq!(
        outcome,
        H3AuthorizedHeadersWrite::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
    assert!(
        !polled.load(std::sync::atomic::Ordering::SeqCst),
        "an already-elapsed bound must not poll send_response, or a protected head could commit"
    );
}

/// Native-H3 aggregate MCP SSE composes the broker listener lifetime with the
/// captured authorization plan. Authorization earlier than the listener wins.
#[tokio::test(start_paused = true)]
async fn aggregate_sse_authorization_earlier_than_the_listener_wins() {
    let now = tokio::time::Instant::now();
    let auth_at = now + Duration::from_secs(2);
    let listener_at = now + Duration::from_secs(30);
    let bound = compose_aggregate_sse_bound_for_test(
        listener_at,
        Some(plan_at(auth_at, StreamAuthTermination::CredentialExpired)),
    );
    assert_eq!(bound.deadline(), Some(auth_at));
    assert_eq!(bound.expired_authorization(), None);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

/// When the listener lifetime is strictly earlier, expiry is the existing
/// non-authorization outcome even if a late wake also observes the credential
/// deadline as elapsed.
#[tokio::test(start_paused = true)]
async fn aggregate_sse_a_strictly_earlier_listener_is_not_an_authorization_expiry() {
    let now = tokio::time::Instant::now();
    let listener_at = now + Duration::from_secs(2);
    let auth_at = now + Duration::from_secs(30);
    let bound = compose_aggregate_sse_bound_for_test(
        listener_at,
        Some(plan_at(auth_at, StreamAuthTermination::CredentialExpired)),
    );
    assert_eq!(bound.deadline(), Some(listener_at));
    tokio::time::advance(Duration::from_secs(40)).await;
    assert_eq!(
        bound.expired_authorization(),
        None,
        "a late wake after both instants must not reattribute listener expiry to authorization"
    );
}

/// An exact tie between listener lifetime and authorization is attributed to
/// authorization, matching every other composed seam.
#[tokio::test(start_paused = true)]
async fn aggregate_sse_an_exact_tie_is_attributed_to_authorization() {
    let now = tokio::time::Instant::now();
    let at = now + Duration::from_secs(5);
    let bound = compose_aggregate_sse_bound_for_test(
        at,
        Some(plan_at(
            at,
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
    );
    assert_eq!(bound.deadline(), Some(at));
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
}

/// Unauthenticated aggregate SSE keeps the listener lifetime and never
/// produces an authorization termination.
#[tokio::test(start_paused = true)]
async fn aggregate_sse_unauthenticated_keeps_the_listener_lifetime() {
    let now = tokio::time::Instant::now();
    let listener_at = now + Duration::from_secs(12);
    let bound = compose_aggregate_sse_bound_for_test(listener_at, None);
    assert_eq!(bound.deadline(), Some(listener_at));
    tokio::time::advance(Duration::from_secs(12)).await;
    assert_eq!(bound.expired_authorization(), None);
}

/// A stalled aggregate-SSE HEADERS write expires at the authorization
/// deadline when that plan is earlier than the listener, latches exactly
/// once, and never treats the protected 200/event-stream head as committed.
#[tokio::test(start_paused = true)]
async fn a_stalled_aggregate_sse_headers_write_expires_at_the_authorization_deadline() {
    let now = tokio::time::Instant::now();
    let bound = compose_aggregate_sse_bound_for_test(
        now + Duration::from_secs(30),
        Some(plan_at(
            now + Duration::from_secs(2),
            StreamAuthTermination::CredentialExpired,
        )),
    );
    let latch = StreamAuthTerminationLatch::default();
    let write = std::future::pending::<Result<(), &'static str>>();
    let started = tokio::time::Instant::now();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        write,
    )
    .await;
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(2)
    );
    assert_eq!(
        outcome,
        H3AuthorizedHeadersWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::Http
        ),
        "the HEADERS expiry must already own this request's single termination record"
    );
}

/// A stalled aggregate-SSE HEADERS write that loses to the listener lifetime
/// is a protocol deadline, not an authorization termination.
#[tokio::test(start_paused = true)]
async fn a_stalled_aggregate_sse_headers_write_at_listener_lifetime_is_not_authorization() {
    let now = tokio::time::Instant::now();
    let bound = compose_aggregate_sse_bound_for_test(
        now + Duration::from_secs(2),
        Some(plan_at(
            now + Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        )),
    );
    let latch = StreamAuthTerminationLatch::default();
    let write = std::future::pending::<Result<(), &'static str>>();
    let started = tokio::time::Instant::now();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        write,
    )
    .await;
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(2)
    );
    assert_eq!(outcome, H3AuthorizedHeadersWrite::ProtocolDeadlineExceeded);
    assert_eq!(latch.observed(), None);
}

/// An exact listener/authorization tie on a stalled HEADERS write is the
/// security decision, and the protected head is never polled once elapsed.
#[tokio::test(start_paused = true)]
async fn a_stalled_aggregate_sse_headers_write_on_an_exact_tie_is_authorization() {
    let now = tokio::time::Instant::now();
    let at = now + Duration::from_secs(3);
    let bound = compose_aggregate_sse_bound_for_test(
        at,
        Some(plan_at(at, StreamAuthTermination::CredentialExpired)),
    );
    let latch = StreamAuthTerminationLatch::default();
    let write = std::future::pending::<Result<(), &'static str>>();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        write,
    )
    .await;
    assert_eq!(
        outcome,
        H3AuthorizedHeadersWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

/// An already-elapsed authorization bound with a later listener lifetime must
/// not poll send_response, so the protected 200/event-stream head cannot commit.
#[tokio::test(start_paused = true)]
async fn an_elapsed_aggregate_sse_authorization_bound_never_polls_the_protected_head() {
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&polled);
    let write = std::future::poll_fn(move |_cx| {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(Ok::<(), &'static str>(()))
    });
    let now = tokio::time::Instant::now();
    let bound = compose_aggregate_sse_bound_for_test(
        now + Duration::from_secs(30),
        Some(plan_at(
            now,
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
    );
    let latch = StreamAuthTerminationLatch::default();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::Http,
        &latch,
        write,
    )
    .await;
    assert_eq!(
        outcome,
        H3AuthorizedHeadersWrite::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
    assert!(
        !polled.load(std::sync::atomic::Ordering::SeqCst),
        "an already-elapsed authorization bound must not poll send_response"
    );
}

/// A stalled post-commit DATA/FIN write is cancelled at the composed deadline
/// so a non-reading client cannot retain the listener lease or request
/// accounting past authorization.
#[tokio::test(start_paused = true)]
async fn a_stalled_aggregate_sse_body_write_stops_at_the_composed_deadline() {
    let now = tokio::time::Instant::now();
    let bound = compose_aggregate_sse_bound_for_test(
        now + Duration::from_secs(30),
        Some(plan_at(
            now + Duration::from_secs(2),
            StreamAuthTermination::CredentialExpired,
        )),
    );
    let started = tokio::time::Instant::now();
    let result =
        await_deadline_first_for_test(bound.deadline(), std::future::pending::<()>()).await;
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(2)
    );
    assert!(
        result.is_err(),
        "a stalled DATA write must lose to the bound"
    );
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

/// The aggregate-SSE pre-commit terminal is the same fixed redacted 401 every
/// other plain-HTTP authorization expiry uses: no deadline instant, credential,
/// claim, identity, session id, or provider detail.
#[tokio::test]
async fn aggregate_sse_precommit_terminal_is_the_fixed_redacted_401() {
    let ctx = authenticated_ctx();
    let (status, headers, body) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::CredentialExpired,
        false,
    );
    assert_eq!(status, 401);
    assert_eq!(body, br#"{"error":"Unauthorized"}"#.to_vec());
    let rendered = String::from_utf8(body).expect("utf8 terminal");
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()));
    let header_blob = headers
        .values()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    for leaked in [
        "credential",
        "exp",
        "session",
        "spiffe",
        "bearer",
        "alice",
        "deadline",
    ] {
        assert!(
            !rendered.to_ascii_lowercase().contains(leaked),
            "pre-commit terminal leaked {leaked}"
        );
        assert!(
            !header_blob.contains(leaked),
            "pre-commit terminal header leaked {leaked}"
        );
    }
}

/// Every native-H3 streaming HTTP/SSE family races `send_response` through the
/// shared HEADERS helper, so the three call sites cannot drift apart.
#[test]
fn every_native_h3_streaming_response_headers_write_uses_the_shared_helper() {
    let helper = include_str!("../../../src/http3/stream_util.rs");
    assert!(helper.contains("pub(crate) async fn await_authorized_headers_write<"));
    assert!(helper.contains("pub(crate) async fn commit_authorized_streaming_response_headers<"));
    assert!(helper.contains("stream.send_response(resp)"));

    for (name, marker, next) in [
        (
            "handle_h3_request inline native-H3 streaming",
            "async fn handle_h3_request(",
            "async fn run_h3_backend_path_plugins_or_send_reject(",
        ),
        (
            "stream_h3_open_response_to_client",
            "async fn stream_h3_open_response_to_client(",
            "async fn run_h3_grpc_upload_pump(",
        ),
        (
            "proxy_to_backend_h3_streaming",
            "async fn proxy_to_backend_h3_streaming(",
            "async fn proxy_to_backend_h3(",
        ),
    ] {
        let region = H3_SERVER_SOURCE
            .split(marker)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} present"))
            .split(next)
            .next()
            .unwrap_or_else(|| panic!("{name} bounded"));
        assert!(
            region.contains("commit_authorized_streaming_response_headers("),
            "{name} must race streaming response HEADERS through the shared helper"
        );
        assert!(
            !region.contains("h3_stream.send_response(resp).await")
                && !region.contains("stream.send_response(resp).await"),
            "{name} still awaits send_response unbounded"
        );
    }

    let sse_writer = H3_SERVER_SOURCE
        .split("async fn send_h3_aggregate_sse_response(")
        .nth(1)
        .expect("native H3 aggregate SSE writer present")
        .split("async fn send_h3_grpc_error_with_recv_halt(")
        .next()
        .expect("native H3 aggregate SSE writer bounded");
    assert!(
        sse_writer.contains("await_authorized_headers_write("),
        "aggregate MCP SSE must race HEADERS through the shared authorized-write helper"
    );
    assert!(
        sse_writer.contains("compose_aggregate_sse_bound("),
        "aggregate MCP SSE must compose the listener lifetime with the captured plan"
    );
    assert!(
        !sse_writer.contains("stream.send_response(response).await")
            && !sse_writer.contains("stream.send_data(data).await"),
        "aggregate MCP SSE still awaits a flow-control-blocked write unbounded"
    );
    assert!(
        !sse_writer.contains("let _ = stream.finish().await"),
        "aggregate MCP SSE listener-lifetime expiry must not await finish unbounded"
    );
    let post_pump = sse_writer
        .split("if composed_deadline_fired {")
        .nth(1)
        .expect("composed deadline post-pump branch");
    let listener_terminal = post_pump
        .split("} else {")
        .nth(1)
        .expect("listener-lifetime else arm")
        .split("    } else {")
        .next()
        .expect("listener-lifetime else arm bounded");
    assert!(
        listener_terminal.contains("await_post_deadline_terminal_response_write("),
        "listener-lifetime post-pump FIN must use the bounded terminal grace"
    );
    assert!(
        listener_terminal.contains("abort_response_stream(stream)"),
        "listener-lifetime FIN blocked past grace must reset"
    );
    assert!(
        !listener_terminal.contains("record_authorization_termination_once("),
        "listener-lifetime post-pump expiry must not increment authorization accounting"
    );
}

/// Every HTTP/3 authorization exit records through the REQUEST's shared latch,
/// so concurrent upload / response / terminal paths cannot double count
/// (issue #3815, root finding 6).
#[test]
fn every_h3_authorization_exit_records_through_the_request_latch() {
    for (name, source) in [
        ("http3/server.rs", H3_SERVER_SOURCE),
        (
            "http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
        ),
        (
            "http3/stream_util.rs",
            include_str!("../../../src/http3/stream_util.rs"),
        ),
    ] {
        assert!(
            !source.contains("auth_lifetime::record_termination("),
            "{name} still increments the fixed-cardinality counter directly; every \
             precommit, blocked-write, idle, and mid-body authorization exit must go \
             through the request's shared once-only latch"
        );
    }
    // The shared blocked-write seam takes the latch rather than owning the
    // counter.
    let seam = include_str!("../../../src/http3/stream_util.rs")
        .split("pub(crate) async fn await_authorized_response_write<F, T, E>(")
        .nth(1)
        .expect("blocked-write seam");
    assert!(seam.contains("latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,"));
    assert!(seam.contains("latch.record_once(plan.termination, family);"));
}

/// Every composed HTTP/3 WRITE and DISPATCH bound carries typed provenance.
///
/// A downstream write parked in QUIC flow control, and a dispatch phase parked
/// on a backend that withholds its response head, are both routinely not
/// observed again until after BOTH composed instants have passed. Deciding the
/// owner by re-reading the clock there reports the gateway's security decision
/// for a phase the client's own strictly earlier `grpc-timeout` bounded — which
/// changes the client-visible terminal, the recorded class, and the
/// fixed-cardinality counter.
#[test]
fn every_composed_h3_write_bound_attributes_from_the_captured_composition() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    for (file, source, bound) in [
        ("server", H3_SERVER_SOURCE, "buffered_write_bound"),
        ("server", H3_SERVER_SOURCE, "downstream_write_bound"),
        ("server", H3_SERVER_SOURCE, "trailer_bound"),
        ("server", H3_SERVER_SOURCE, "aggregate_sse_bound"),
        ("cross", cross, "plain_write_bound"),
        ("cross", cross, "terminal_write_bound"),
        ("cross", cross, "downstream_write_bound"),
    ] {
        assert!(
            source.contains(&format!("let {bound} =")),
            "http3/{file}.rs lost its composed `{bound}`"
        );
        assert!(
            source.contains(&format!("{bound}.deadline()")),
            "http3/{file}.rs must await the composed instant through `{bound}`"
        );
        assert!(
            source.contains(&format!("{bound}.expired_authorization()")),
            "http3/{file}.rs must attribute `{bound}` from the captured composition"
        );
    }
    // No composed write seam may re-derive the owner from the clock. The
    // remaining `expired_authorization(<plan>)` calls in these files are
    // PRE-COMMITMENT gates — "is the credential live right now?" — which have no
    // second owner to choose between.
    assert!(
        !H3_SERVER_SOURCE.contains("expired_authorization(buffered_auth_deadline_plan"),
        "the buffered native-H3 write seam still re-reads the clock to attribute its \
         composed bound"
    );
    assert!(
        !cross.contains("expired_authorization(plain_auth_deadline_plan"),
        "the cross-protocol plain write seam still re-reads the clock to attribute its \
         composed bound"
    );
    assert!(
        !cross.contains("expired_authorization(auth_deadline)"),
        "a cross-protocol terminal write seam still re-reads the clock to attribute its \
         composed bound"
    );
}

// --- Late-wake attribution for the composed H3 dispatch/write bounds --------
//
// These exercise the typed bound the changed seams now carry through a LATE
// WAKE: attribution happens only after BOTH instants elapsed, which is exactly
// the state a task parked on QUIC flow control, or on a backend that withholds
// its response head, returns in.

type ComposedBound = ferrum_edge::proxy::auth_lifetime::ComposedAuthBound;

#[tokio::test(start_paused = true)]
async fn a_late_woken_h3_seam_keeps_an_earlier_client_deadline_as_the_clients_own() {
    let protocol_at = tokio::time::Instant::now() + Duration::from_secs(5);
    let bound = ComposedBound::compose(
        Some(protocol_at),
        plan_after(
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    assert_eq!(bound.deadline(), Some(protocol_at));

    // The write/dispatch fired at the client's deadline; the task is not
    // observed again until long after the LATER authorization deadline.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        bound.expired_authorization(),
        None,
        "a strictly earlier client `grpc-timeout` must keep DEADLINE_EXCEEDED and its \
         health-neutral client classification, never become an UNAUTHENTICATED terminal \
         plus a fixed-cardinality authorization count"
    );
    // ...and the credential's own instant is still reachable for the detached
    // work that must be bounded by it.
    assert!(bound.authorization_deadline_at().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_late_woken_h3_seam_reports_an_earlier_authorization_bound() {
    let bound = ComposedBound::compose(
        Some(tokio::time::Instant::now() + Duration::from_secs(30)),
        plan_after(
            Duration::from_secs(5),
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        ),
    );
    assert_eq!(bound.expired_authorization(), None, "not yet elapsed");

    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
}

#[tokio::test(start_paused = true)]
async fn an_h3_seam_tie_resolves_to_the_security_decision() {
    let at = tokio::time::Instant::now() + Duration::from_secs(5);
    let bound = ComposedBound::compose(
        Some(at),
        Some(StreamAuthDeadline {
            at,
            termination: StreamAuthTermination::CredentialExpired,
        }),
    );
    assert_eq!(bound.deadline(), Some(at));

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired),
        "a genuine tie goes to authorization, matching every biased select arm"
    );
}

#[tokio::test(start_paused = true)]
async fn an_h3_seam_with_no_client_deadline_is_owned_by_authorization_alone() {
    // The common native-H3 case: no `grpc-timeout`, and on the dispatch seam
    // `backend_read_timeout_ms: 0` as well, so the authorization bound is the
    // ONLY bound in existence.
    let bound = ComposedBound::compose(
        None,
        plan_after(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    assert!(bound.deadline().is_some());

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );

    // An unauthenticated request keeps no bound at all on these seams.
    let unbounded = ComposedBound::compose(None, None);
    assert_eq!(unbounded.deadline(), None);
    assert_eq!(unbounded.expired_authorization(), None);
}

// --- The native-H3 buffered request-upload seam (issue #3815) ---------------
//
// The seven native-H3 sites that BUFFER a client upload before dispatch were the
// last family that composed the client's optional RPC deadline with the admitted
// credential's authorization deadline and then chose the owner by re-reading the
// clock once the bound had fired. A buffered drain of a continuously active
// upload is exactly the shape that is observed late: the collect makes progress
// on every poll, so the task can be scheduled again only well after BOTH
// instants have passed. Re-reading there reports the gateway's security decision
// — a different client-visible terminal, a different recorded class, and a
// fixed-cardinality authorization count — for a drain the client's own strictly
// earlier `grpc-timeout` actually bounded.
//
// These drive the real collector, so they fail against any seam that re-derives
// the owner instead of consuming the captured composition. Pending-upload cases
// cover late-wake attribution; immediately-ready `Ok` futures cover the
// `timeout_at` fail-open (Tokio 1.52.3 polls the inner future before the timer).

/// Move the paused clock forward so "already elapsed" instants stay
/// representable without depending on the process's uptime.
async fn paused_clock_with_history() -> tokio::time::Instant {
    tokio::time::advance(Duration::from_secs(600)).await;
    tokio::time::Instant::now()
}

fn elapsed_by(now: tokio::time::Instant, ago: Duration) -> tokio::time::Instant {
    now.checked_sub(ago).expect("representable")
}

fn plan_elapsed(
    now: tokio::time::Instant,
    ago: Duration,
    termination: StreamAuthTermination,
) -> Option<StreamAuthDeadline> {
    Some(plan_at(elapsed_by(now, ago), termination))
}

/// An immediately-ready `Ok` upload that counts how many times it is polled.
/// This is the shape `tokio::time::timeout_at` cannot refuse: it polls the
/// inner future before the timer, so a fully-buffered client FIN would be
/// accepted even when the captured bound has already elapsed.
fn ready_ok_h3_upload(
    polled: &Arc<std::sync::atomic::AtomicUsize>,
) -> impl std::future::Future<Output = Result<(), ()>> {
    let polled = Arc::clone(polled);
    std::future::poll_fn(move |_cx| {
        polled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(Ok(()))
    })
}

fn ready_unit(
    polled: Arc<std::sync::atomic::AtomicUsize>,
) -> impl std::future::Future<Output = ()> {
    std::future::poll_fn(move |_cx| {
        polled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(())
    })
}

#[tokio::test(start_paused = true)]
async fn a_late_woken_h3_upload_keeps_a_strictly_earlier_client_deadline_as_the_clients_own() {
    let now = paused_clock_with_history().await;
    // The client's `grpc-timeout` fired first, and the credential's own deadline
    // has ALSO passed by the time the drain is observed. This is exactly the
    // state a late-woken buffered drain returns in.
    let bound = ComposedBound::compose(
        Some(elapsed_by(now, Duration::from_secs(60))),
        plan_elapsed(
            now,
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let upload = std::future::pending::<Result<(), ()>>();

    assert_eq!(
        collect_h3_upload_under_authorization_for_test(upload, bound, 0).await,
        H3UploadWaitOutcomeForTest::DeadlineExceeded,
        "a strictly earlier client RPC deadline must keep the deadline terminal; reporting \
         an authorization expiry here would change the client-visible response, latch a \
         termination class, and charge the fixed-cardinality counter"
    );
    // ...and the credential's own instant stays reachable for detached work that
    // must be bounded by it.
    assert!(bound.authorization_deadline_at().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_late_woken_h3_upload_carries_a_strictly_earlier_authorization_bound() {
    let now = paused_clock_with_history().await;
    let bound = ComposedBound::compose(
        Some(elapsed_by(now, Duration::from_secs(30))),
        plan_elapsed(
            now,
            Duration::from_secs(60),
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        ),
    );
    let upload = std::future::pending::<Result<(), ()>>();

    assert_eq!(
        collect_h3_upload_under_authorization_for_test(upload, bound, 0).await,
        H3UploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        ),
        "the earlier authorization bound owns the drain and carries its bounded class"
    );
}

#[tokio::test(start_paused = true)]
async fn an_exact_h3_upload_tie_goes_to_authorization() {
    let now = paused_clock_with_history().await;
    let bound = ComposedBound::compose(
        Some(elapsed_by(now, Duration::from_secs(30))),
        plan_elapsed(
            now,
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let upload = std::future::pending::<Result<(), ()>>();

    assert_eq!(
        collect_h3_upload_under_authorization_for_test(upload, bound, 0).await,
        H3UploadWaitOutcomeForTest::AuthorizationExpired(StreamAuthTermination::CredentialExpired),
        "a genuine tie resolves to the security decision, matching every biased select arm"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_h3_upload_bound_never_polls_a_ready_ok_future() {
    let now = paused_clock_with_history().await;
    let bound = ComposedBound::compose(
        None,
        plan_elapsed(
            now,
            Duration::from_secs(60),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outcome =
        collect_h3_upload_under_authorization_for_test(ready_ok_h3_upload(&polled), bound, 0).await;

    assert_eq!(
        outcome,
        H3UploadWaitOutcomeForTest::AuthorizationExpired(StreamAuthTermination::CredentialExpired),
        "an already-elapsed authorization bound must refuse a fully-buffered upload"
    );
    assert_eq!(
        polled.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an already-elapsed bound must not poll the upload at all; timeout_at would \
         accept this ready Ok on its first poll"
    );
}

#[tokio::test(start_paused = true)]
async fn an_exact_h3_upload_tie_refuses_a_ready_ok_future_as_authorization() {
    let now = paused_clock_with_history().await;
    let bound = ComposedBound::compose(
        Some(elapsed_by(now, Duration::from_secs(30))),
        plan_elapsed(
            now,
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outcome =
        collect_h3_upload_under_authorization_for_test(ready_ok_h3_upload(&polled), bound, 0).await;

    assert_eq!(
        outcome,
        H3UploadWaitOutcomeForTest::AuthorizationExpired(StreamAuthTermination::CredentialExpired),
        "an exact-deadline tie must choose the captured authorization bound, not a ready FIN"
    );
    assert_eq!(
        polled.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an exact-deadline tie must not poll the ready upload"
    );
}

#[tokio::test(start_paused = true)]
async fn a_strictly_earlier_client_deadline_refuses_a_ready_ok_future_as_deadline_exceeded() {
    let now = paused_clock_with_history().await;
    let bound = ComposedBound::compose(
        Some(elapsed_by(now, Duration::from_secs(60))),
        plan_elapsed(
            now,
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outcome =
        collect_h3_upload_under_authorization_for_test(ready_ok_h3_upload(&polled), bound, 0).await;

    assert_eq!(
        outcome,
        H3UploadWaitOutcomeForTest::DeadlineExceeded,
        "a strictly earlier client RPC deadline must stay DeadlineExceeded even when the \
         upload is already fully buffered; reporting authorization would change the \
         client-visible terminal and charge the fixed-cardinality counter"
    );
    assert_eq!(
        polled.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an already-elapsed protocol bound must not poll the ready upload either"
    );
}

#[tokio::test(start_paused = true)]
async fn an_operator_upload_timeout_earlier_than_the_composed_bound_stays_timed_out() {
    let now = paused_clock_with_history().await;
    // Authorization WINS composition here, so a seam that derived its terminal
    // from the bound alone would report a security expiry for a drain the
    // operator's own whole-upload stall guard ended.
    let bound = ComposedBound::compose(
        Some(now + Duration::from_secs(600)),
        Some(plan_at(
            now + Duration::from_secs(60),
            StreamAuthTermination::CredentialExpired,
        )),
    );
    assert_eq!(bound.deadline(), Some(now + Duration::from_secs(60)));

    let upload = std::future::pending::<Result<(), ()>>();
    let task = tokio::spawn(async move {
        collect_h3_upload_under_authorization_for_test(upload, bound, 10).await
    });
    // Register the waiter before advancing the paused clock.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;

    assert_eq!(
        task.await.expect("join"),
        H3UploadWaitOutcomeForTest::TimedOut,
        "the operator whole-upload stall guard keeps its own precedence and terminal"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_h3_upload_never_reports_an_authorization_expiry() {
    let now = paused_clock_with_history().await;
    let bound = ComposedBound::compose(Some(elapsed_by(now, Duration::from_secs(30))), None);
    assert_eq!(bound.authorization_deadline_at(), None);
    let upload = std::future::pending::<Result<(), ()>>();

    assert_eq!(
        collect_h3_upload_under_authorization_for_test(upload, bound, 0).await,
        H3UploadWaitOutcomeForTest::DeadlineExceeded
    );

    // With neither bound configured the drain stays unbounded, exactly as it was
    // before this contract existed.
    let unbounded = ComposedBound::compose(None, None);
    let completed = std::future::ready::<Result<(), ()>>(Ok(()));
    assert_eq!(
        collect_h3_upload_under_authorization_for_test(completed, unbounded, 0).await,
        H3UploadWaitOutcomeForTest::Collected
    );
    // A client read failure is still a read failure, never a policy terminal.
    let failed = std::future::ready::<Result<(), ()>>(Err(()));
    assert_eq!(
        collect_h3_upload_under_authorization_for_test(failed, unbounded, 0).await,
        H3UploadWaitOutcomeForTest::ClientError
    );
}

/// The composer the seven sites share derives BOTH the awaited instant and the
/// reported owner from one read of the arbiter.
#[tokio::test(start_paused = true)]
async fn the_native_h3_upload_composer_keeps_the_owner_from_the_request_context() {
    // The credential outlives the client's own RPC budget.
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(30)));
    set_grpc_deadline_budget_for_test(&mut ctx, Some(5_000));

    let bound = compose_h3_upload_bound_for_test(&ctx, DEFAULT_MAX);
    assert_eq!(bound.deadline(), Some(received_at + Duration::from_secs(5)));
    assert_eq!(
        bound.authorization_deadline_at(),
        Some(received_at + Duration::from_secs(30))
    );
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(
        bound.expired_authorization(),
        None,
        "both instants are in the past now, and the client's is still the owner"
    );

    // The credential expires first.
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(5)));
    set_grpc_deadline_budget_for_test(&mut ctx, Some(30_000));
    let bound = compose_h3_upload_bound_for_test(&ctx, DEFAULT_MAX);
    assert_eq!(bound.deadline(), Some(received_at + Duration::from_secs(5)));
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );

    // An exact tie between the two goes to authorization.
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(5)));
    set_grpc_deadline_budget_for_test(&mut ctx, Some(5_000));
    let bound = compose_h3_upload_bound_for_test(&ctx, DEFAULT_MAX);
    assert_eq!(bound.deadline(), Some(received_at + Duration::from_secs(5)));
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired),
        "a tie at the arbiter is still the security decision"
    );

    // An unauthenticated request keeps only the client's own bound.
    let mut anonymous = anonymous_ctx();
    let received_at = request_received_at_for_test(&anonymous);
    set_grpc_deadline_budget_for_test(&mut anonymous, Some(5_000));
    let bound = compose_h3_upload_bound_for_test(&anonymous, DEFAULT_MAX);
    assert_eq!(bound.deadline(), Some(received_at + Duration::from_secs(5)));
    assert_eq!(bound.authorization_deadline_at(), None);
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(bound.expired_authorization(), None);
}

/// Every native-H3 buffered upload site consumes the captured winner, and the
/// projection that discarded it no longer exists.
#[test]
fn every_native_h3_upload_site_attributes_from_the_captured_composition() {
    let collector = H3_SERVER_SOURCE
        .split("pub(crate) async fn collect_h3_request_body_under_authorization<F, T, E>(")
        .nth(1)
        .expect("the typed native-H3 upload collector")
        .split("\n/// ")
        .next()
        .expect("bounded collector");
    assert!(
        collector.contains("compose_early_upload_bound(bound.deadline()"),
        "the awaited instant must be a projection of the captured composition"
    );
    let collector_compact: String = collector.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        collector_compact.contains("DeadlineExceeded(bound.expired_authorization())")
            || collector_compact.contains("DeadlineExceeded(bound.expired_authorization(),)"),
        "the deadline terminal must carry the owner captured at composition time"
    );
    assert!(
        collector.contains("EarlyUploadBoundKind::OperatorTimeout)) => {")
            && collector.contains("H3RequestBodyReadError::TimedOut"),
        "the operator whole-upload stall guard keeps its own precedence and TimedOut"
    );
    assert!(
        !collector.contains("record_termination(") && !collector.contains("record_once("),
        "the collector only REPORTS an owner; the request's shared latch is what counts it"
    );

    let operator_arm = collector
        .split("EarlyUploadBoundKind::OperatorTimeout)) => {")
        .nth(1)
        .expect("operator stall-guard arm")
        .split("EarlyUploadBoundKind::RpcDeadline")
        .next()
        .expect("bounded operator stall-guard arm");
    assert!(
        operator_arm.contains("await_deadline_first(") && operator_arm.contains("TimedOut"),
        "the operator stall guard is expiry-first and keeps TimedOut"
    );
    assert!(
        !operator_arm.contains("timeout_at("),
        "timeout_at polls the upload first, so an already-elapsed operator bound would accept a ready FIN"
    );

    let rpc_deadline_arm = collector
        .split("EarlyUploadBoundKind::RpcDeadline)) => {")
        .nth(1)
        .expect("absolute-bound arm")
        .split("None =>")
        .next()
        .expect("bounded absolute-bound arm");
    assert!(
        rpc_deadline_arm.contains("await_deadline_first("),
        "the absolute bound must use the shared expiry-first wait"
    );
    assert!(
        !rpc_deadline_arm.contains("timeout_at("),
        "timeout_at polls the upload first, so an already-elapsed bound would accept a ready FIN"
    );

    // The no-plan wrapper the cross-protocol bridge uses composes against
    // `None`, so its deadline is structurally the client's own.
    let wrapper = H3_SERVER_SOURCE
        .split("pub(crate) async fn collect_h3_request_body_with_deadline<F, T, E>(")
        .nth(1)
        .expect("the no-plan native-H3 upload wrapper")
        .split("\n/// ")
        .next()
        .expect("bounded wrapper");
    assert!(wrapper.contains("ComposedAuthBound::compose(deadline, None)"));

    // All seven sites bind the captured winner rather than recomputing one.
    let server_compact: String = H3_SERVER_SOURCE
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let typed_arm_count = server_compact
        .matches("Err(H3RequestBodyReadError::DeadlineExceeded(authorization_expiry))=>{")
        .count()
        + server_compact
            .matches("Err(H3RequestBodyReadError::DeadlineExceeded(authorization_expiry,))=>{")
            .count();
    assert_eq!(
        typed_arm_count, 7,
        "a native-H3 upload site stopped consuming the winner captured at composition"
    );
    let compact = H3_SERVER_SOURCE
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        !compact.contains("expired_authorization( crate::proxy::auth_lifetime::"),
        "no H3 upload site may re-derive its owner from the clock against a freshly \
         recomputed authorization plan"
    );

    // The projection that returned only the instant is gone, so a seam cannot
    // compose a bound and then be left with no way to name its owner.
    for (name, source) in [
        ("http3/server.rs", H3_SERVER_SOURCE),
        (
            "http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
        ),
        (
            "proxy/auth_lifetime.rs",
            include_str!("../../../src/proxy/auth_lifetime.rs"),
        ),
    ] {
        assert!(
            !source.contains("compose_absolute_bound"),
            "{name} still reaches for the owner-discarding projection"
        );
    }
}

/// The H3→plain mesh force-buffer drain uses the composed authorization bound
/// and routes a captured authorization winner to the fixed pre-commitment 401.
#[test]
fn cross_protocol_mesh_force_buffer_uses_the_composed_authorization_bound() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = cross
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("cross-protocol plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol plain dispatcher");
    let bound_at = dispatch
        .find("let plain_write_bound =")
        .expect("plain_write_bound must be composed in dispatch_plain");
    let mesh_block_start = dispatch
        .find("target_requires_http_mesh_egress")
        .expect("mesh force-buffer gate");
    assert!(
        bound_at < mesh_block_start,
        "plain_write_bound must be composed before the mesh force-buffer branch"
    );
    let mesh_block = &dispatch[mesh_block_start..];
    let mesh_block_end = mesh_block
        .find("let (response, bytes_sent, mut backend_admission_permits")
        .expect("bounded mesh force-buffer");
    let mesh_collection = &mesh_block[..mesh_block_end];
    assert!(
        mesh_collection.contains("collect_h3_request_body_under_authorization(")
            && mesh_collection.contains("plain_write_bound"),
        "the mesh force-buffer must drain under the composed authorization bound"
    );
    assert!(
        !mesh_collection.contains("collect_h3_request_body_with_deadline(")
            && !mesh_collection.contains("grpc_web_deadline_at"),
        "the mesh force-buffer must not compose against the client RPC deadline alone"
    );
    // Bind the exact force-buffer match arm (typed capture included) so a
    // rustfmt wrap cannot make the remainder start after `DeadlineExceeded`.
    let mesh_deadline_start = mesh_collection
        .find("H3RequestBodyReadError::DeadlineExceeded")
        .expect("mesh force-buffer DeadlineExceeded arm");
    let mesh_deadline = mesh_collection[mesh_deadline_start..]
        .split("H3RequestBodyReadError::TimedOut")
        .next()
        .expect("bounded mesh force-buffer DeadlineExceeded arm");
    let mesh_deadline_compact: String = mesh_deadline
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(
        mesh_deadline_compact.contains("DeadlineExceeded(authorization_expiry)")
            || mesh_deadline_compact.contains("DeadlineExceeded(authorization_expiry,)"),
        "the mesh force-buffer must bind the captured winner rather than a unit variant"
    );
    let mesh_record = mesh_deadline_compact
        .find("record_authorization_termination_once(")
        .expect("mesh force-buffer must latch the termination once");
    let mesh_write = mesh_deadline_compact
        .find("write_plain_authorization_expired_terminal(")
        .expect("mesh force-buffer must take the fixed pre-commitment 401");
    assert!(
        mesh_record < mesh_write,
        "fixed-cardinality authorization termination must be recorded before the 401 write"
    );
    assert!(
        mesh_deadline_compact.contains("StreamAuthProtocolFamily::Http"),
        "the mesh force-buffer is the HTTP family on the plain bridge"
    );
    assert!(
        !mesh_deadline_compact.contains("write_plain_gateway_error(")
            && !mesh_deadline.contains("warn!(")
            && !mesh_deadline.contains("error!("),
        "the authorization terminal must stay redacted and must not log identity"
    );
    assert!(
        mesh_deadline_compact.contains("write_plain_grpc_web_client_deadline("),
        "DeadlineExceeded(None) must keep the client's own gRPC-Web/client deadline terminal"
    );
}

// --- Captured attribution for the pre-commitment phase bound ----------------
//
// Two very different owners can drive the same instant: the client's own
// `grpc-timeout` and the admitted credential's authorization lifetime. Once the
// bound has fired, "is the authorization deadline in the past?" is not a sound
// way to ask which of them ended the phase — a task that is not polled again
// until after the LATER of the two sees both as elapsed. Attribution must come
// from the composition, where both instants were known.

fn plan_after(after: Duration, termination: StreamAuthTermination) -> Option<StreamAuthDeadline> {
    Some(StreamAuthDeadline {
        at: tokio::time::Instant::now() + after,
        termination,
    })
}

#[tokio::test(start_paused = true)]
async fn a_strictly_earlier_protocol_bound_stays_the_protocols_after_a_late_wake() {
    let protocol_at = tokio::time::Instant::now() + Duration::from_secs(5);
    let bound = ferrum_edge::_test_support::compose_precommit_response_phase_bound_for_test(
        Some(protocol_at),
        plan_after(
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    assert_eq!(
        bound.deadline(),
        Some(protocol_at),
        "the earliest bound owns the phase"
    );

    // The phase fires at the client's deadline, and the task that must
    // attribute it is not scheduled again until long after the LATER
    // authorization deadline has also passed.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        bound.expired_authorization(),
        None,
        "a strictly earlier client RPC deadline must stay the client's own bound; \
         re-reading the clock after a late wake would reattribute it to the gateway's \
         security decision and change client grpc-timeout behavior"
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_authorization_bound_is_reported_once_its_instant_elapsed() {
    let bound = ferrum_edge::_test_support::compose_precommit_response_phase_bound_for_test(
        Some(tokio::time::Instant::now() + Duration::from_secs(30)),
        plan_after(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    // Composed, but not yet elapsed: an early gate must not report an expiry
    // for a credential that is still authorized.
    assert_eq!(bound.expired_authorization(), None);

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired),
        "the earlier authorization bound owns the phase once its instant has elapsed"
    );
}

#[tokio::test(start_paused = true)]
async fn an_exact_tie_between_the_two_bounds_goes_to_authorization() {
    let at = tokio::time::Instant::now() + Duration::from_secs(5);
    let bound = ferrum_edge::_test_support::compose_precommit_response_phase_bound_for_test(
        Some(at),
        Some(StreamAuthDeadline {
            at,
            termination: StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        }),
    );
    assert_eq!(bound.deadline(), Some(at));

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime),
        "a genuine tie resolves to the security decision, matching every biased select arm"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_precommit_phase_never_reports_an_authorization_expiry() {
    let bound = ferrum_edge::_test_support::compose_precommit_response_phase_bound_for_test(
        Some(tokio::time::Instant::now() + Duration::from_secs(1)),
        None,
    );
    assert_eq!(bound.authorization_deadline_at(), None);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(bound.expired_authorization(), None);
}

fn ready_poll_counter() -> (
    Arc<std::sync::atomic::AtomicUsize>,
    impl std::future::Future<Output = ()>,
) {
    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    (Arc::clone(&polled), ready_unit(Arc::clone(&polled)))
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_deadline_first_wait_never_polls_ready_work() {
    let now = paused_clock_with_history().await;
    let (polled, work) = ready_poll_counter();
    assert_eq!(
        await_deadline_first_for_test(Some(elapsed_by(now, Duration::from_secs(1))), work).await,
        Err(())
    );
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_live_deadline_first_wait_completes_ready_work() {
    let (polled, work) = ready_poll_counter();
    assert_eq!(
        await_deadline_first_for_test(
            Some(tokio::time::Instant::now() + Duration::from_secs(30)),
            work
        )
        .await,
        Ok(())
    );
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_unbounded_deadline_first_wait_keeps_the_no_timer_hot_path() {
    let (polled, work) = ready_poll_counter();
    assert_eq!(await_deadline_first_for_test(None, work).await, Ok(()));
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_precommit_authorization_bound_never_polls_ready_work() {
    let now = paused_clock_with_history().await;
    let bound = compose_precommit_response_phase_bound_for_test(
        None,
        plan_elapsed(
            now,
            Duration::from_secs(60),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let (polled, work) = ready_poll_counter();
    assert_eq!(
        await_precommit_response_phase_for_test(bound, work).await,
        PrecommitPhaseOutcomeForTest::ExpiredAuthorization(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_strictly_earlier_precommit_protocol_bound_never_polls_ready_work() {
    let now = paused_clock_with_history().await;
    let bound = compose_precommit_response_phase_bound_for_test(
        Some(elapsed_by(now, Duration::from_secs(60))),
        plan_elapsed(
            now,
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let (polled, work) = ready_poll_counter();
    assert_eq!(
        await_precommit_response_phase_for_test(bound, work).await,
        PrecommitPhaseOutcomeForTest::ExpiredProtocol
    );
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn an_exact_precommit_tie_never_polls_ready_work_and_goes_to_authorization() {
    let now = paused_clock_with_history().await;
    let at = elapsed_by(now, Duration::from_secs(30));
    let bound = compose_precommit_response_phase_bound_for_test(
        Some(at),
        Some(plan_at(at, StreamAuthTermination::CredentialExpired)),
    );
    let (polled, work) = ready_poll_counter();
    assert_eq!(
        await_precommit_response_phase_for_test(bound, work).await,
        PrecommitPhaseOutcomeForTest::ExpiredAuthorization(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_live_precommit_bound_completes_ready_work() {
    let bound = compose_precommit_response_phase_bound_for_test(
        Some(tokio::time::Instant::now() + Duration::from_secs(30)),
        plan_after(
            Duration::from_secs(60),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    let (polled, work) = ready_poll_counter();
    assert_eq!(
        await_precommit_response_phase_for_test(bound, work).await,
        PrecommitPhaseOutcomeForTest::Completed(())
    );
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_response_collect_authorization_bound_never_polls_ready_work() {
    let now = paused_clock_with_history().await;
    let plan = (
        plan_at(
            elapsed_by(now, Duration::from_secs(60)),
            StreamAuthTermination::CredentialExpired,
        ),
        StreamAuthProtocolFamily::Http,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    );
    let (polled, work) = ready_poll_counter();
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        work,
        None,
        Some(&plan),
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::AuthorizationExpired);
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_strictly_earlier_response_collect_protocol_bound_never_polls_ready_work() {
    let now = paused_clock_with_history().await;
    let plan = (
        plan_at(
            elapsed_by(now, Duration::from_secs(30)),
            StreamAuthTermination::CredentialExpired,
        ),
        StreamAuthProtocolFamily::Http,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    );
    let (polled, work) = ready_poll_counter();
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        work,
        Some(elapsed_by(now, Duration::from_secs(60))),
        Some(&plan),
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::RpcDeadline);
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn an_exact_response_collect_tie_never_polls_ready_work_and_goes_to_authorization() {
    let now = paused_clock_with_history().await;
    let at = elapsed_by(now, Duration::from_secs(30));
    let plan = (
        plan_at(at, StreamAuthTermination::CredentialExpired),
        StreamAuthProtocolFamily::Http,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    );
    let (polled, work) = ready_poll_counter();
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        work,
        Some(at),
        Some(&plan),
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::AuthorizationExpired);
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_live_response_collect_bound_completes_ready_work() {
    let plan = response_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let (polled, work) = ready_poll_counter();
    let outcome = ferrum_edge::_test_support::collect_response_under_authorization_for_test(
        work,
        None,
        Some(&plan),
    )
    .await;
    assert_eq!(outcome, ResponseCollectBoundForTest::Completed);
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_h3_backend_wait_never_polls_a_ready_backend() {
    let now = paused_clock_with_history().await;
    let (polled, work) = ready_poll_counter();
    let outcome =
        await_h3_backend_or_peer_for_test(Some(elapsed_by(now, Duration::from_secs(1))), work)
            .await;
    assert_eq!(outcome, H3BackendOrPeerForTest::Deadline);
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_live_h3_backend_wait_completes_ready_work() {
    let (polled, work) = ready_poll_counter();
    let outcome = await_h3_backend_or_peer_for_test(
        Some(tokio::time::Instant::now() + Duration::from_secs(30)),
        work,
    )
    .await;
    assert_eq!(outcome, H3BackendOrPeerForTest::Ready(()));
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_unbounded_h3_backend_wait_keeps_the_no_timer_hot_path() {
    let (polled, work) = ready_poll_counter();
    let outcome = await_h3_backend_or_peer_for_test(None, work).await;
    assert_eq!(outcome, H3BackendOrPeerForTest::Ready(()));
    assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn cross_protocol_owner_composition_keeps_a_strictly_earlier_client_deadline() {
    let now = paused_clock_with_history().await;
    let bound = ComposedAuthBound::compose(
        Some(elapsed_by(now, Duration::from_secs(60))),
        plan_elapsed(
            now,
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
    );
    assert_eq!(
        bound.expired_authorization(),
        None,
        "a strictly earlier client deadline must keep client ownership after both instants pass"
    );
}

#[tokio::test(start_paused = true)]
async fn cross_protocol_owner_composition_gives_an_exact_tie_to_authorization() {
    let now = paused_clock_with_history().await;
    let at = elapsed_by(now, Duration::from_secs(30));
    let bound = ComposedAuthBound::compose(
        Some(at),
        Some(plan_at(at, StreamAuthTermination::CredentialExpired)),
    );
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[test]
fn composed_authorization_waits_use_the_shared_expiry_first_primitive() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let helper = plugins
        .split("pub(crate) async fn await_deadline_first<F, T>(")
        .nth(1)
        .expect("shared expiry-first wait")
        .split("pub(crate) async fn await_precommit_response_phase<F, T>(")
        .next()
        .expect("bounded expiry-first wait");
    assert!(
        helper.contains("if tokio::time::Instant::now() >= deadline"),
        "an already-elapsed bound must refuse before the protected future is polled"
    );
    let biased_at = helper.find("biased;").expect("biased select");
    let sleep_at = helper.find("sleep_until(deadline)").expect("deadline arm");
    let future_at = helper.find("result = future").expect("protected-work arm");
    assert!(
        biased_at < sleep_at && sleep_at < future_at,
        "the captured bound must be the first select arm"
    );
    assert!(
        !helper.contains("timeout_at("),
        "timeout_at polls the inner future first"
    );

    let precommit = plugins
        .split("pub(crate) async fn await_precommit_response_phase<F, T>(")
        .nth(1)
        .expect("precommit wait")
        .split("impl PrecommitPhaseResult<PluginResult>")
        .next()
        .expect("bounded precommit wait");
    assert!(
        precommit.contains("await_deadline_first(bound.deadline(), future)"),
        "the composed precommit path must use the expiry-first primitive"
    );
    assert!(
        !precommit.contains("await_grpc_deadline("),
        "request-plugin timeout_at semantics must not leak into the composed precommit path"
    );

    let proxy = include_str!("../../../src/proxy/mod.rs");
    let collect = proxy
        .split("pub(crate) async fn collect_response_under_authorization<F>(")
        .nth(1)
        .expect("buffered response collect")
        .split("pub(crate) fn dispatch_phase_authorization_expiry(")
        .next()
        .expect("bounded buffered response collect");
    assert!(collect.contains("await_deadline_first(bound.at, collect)"));
    assert!(!collect.contains("timeout_at("));

    assert!(
        proxy
            .matches("await_deadline_first(send_bound.at, req_builder.send())")
            .count()
            >= 2,
        "reqwest response-header waits must use the expiry-first primitive"
    );

    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = cross
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("cross-protocol plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol plain dispatcher");
    assert_eq!(
        dispatch
            .matches("await_deadline_first(\n                        plain_write_bound.deadline()")
            .count()
            + dispatch
                .matches("await_deadline_first(\n                    plain_write_bound.deadline()")
                .count(),
        2,
        "both client acquisitions must wait under the captured composed bound"
    );
    assert!(
        dispatch.contains("plain_write_bound.deadline(),")
            && dispatch.contains("await_h3_backend_or_peer("),
        "the buffered header wait must use the captured composed bound"
    );
    assert!(
        dispatch.contains("upload_deadline_active")
            && dispatch.contains("plain_write_bound.expired_authorization()"),
        "the streaming upload loop must race the composed earliest bound and keep typed ownership"
    );
    assert!(
        !dispatch.contains("grpc_web_deadline_active")
            && !dispatch.contains("upload_auth_deadline_active"),
        "independently ordered authorization and client-deadline arms must not remain"
    );

    let tcp = include_str!("../../../src/proxy/tcp_proxy.rs");
    let setup = tcp
        .split("pub(crate) async fn within_stream_auth_deadline<F>(")
        .nth(1)
        .expect("TCP setup wait")
        .split("pub(crate) async fn retry_backoff_within_stream_auth_deadline(")
        .next()
        .expect("bounded TCP setup wait");
    assert!(setup.contains("await_deadline_first(Some(plan.at), stage)"));
    assert!(
        !setup.contains("timeout_at("),
        "timeout_at polls a ready setup stage after the captured bound elapsed"
    );
    let backoff = tcp
        .split("pub(crate) async fn retry_backoff_within_stream_auth_deadline(")
        .nth(1)
        .expect("TCP retry backoff")
        .split("/// Settle a post-admission setup-phase authorization expiry.")
        .next()
        .expect("bounded TCP retry backoff");
    assert!(
        backoff.contains("await_deadline_first(Some(plan.at), tokio::time::sleep(delay))"),
        "retry backoff must refuse an already-elapsed authorization bound"
    );
    assert!(!backoff.contains("timeout_at("));

    let util = include_str!("../../../src/http3/stream_util.rs");
    let headers = util
        .split("pub(crate) async fn await_response_write_before_deadline<F, T, E>(")
        .nth(1)
        .expect("H3 write wait")
        .split("pub(crate) async fn await_terminal_response_write_before_deadline<F, T, E>(")
        .next()
        .expect("bounded H3 write wait");
    assert!(headers.contains("await_deadline_first(deadline, write)"));
    assert!(!headers.contains("timeout_at("));
}

// --- Detached committed-response cleanup ------------------------------------
//
// `run_response_committed_hook_until_deadline` detaches a pending observer when
// the CLIENT's own RPC deadline is the winning bound. That detached invocation
// still owns a clone of the request context and the protected response body, so
// the fixed post-response cleanup timeout alone would let it keep them past the
// credential's authorization lifetime whenever
// `client_deadline < authorization_deadline < client_deadline + 5s`.

/// A detached hook that never completes and reports when it is dropped.
struct NeverCompletingHook(Arc<std::sync::atomic::AtomicBool>);

impl Drop for NeverCompletingHook {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn never_completing_hook(
    dropped: &Arc<std::sync::atomic::AtomicBool>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = RequestContext> + Send + 'static>> {
    let guard = NeverCompletingHook(Arc::clone(dropped));
    Box::pin(async move {
        // The guard is owned by the future, exactly as the real detached hook
        // owns the cloned request context and the protected response body.
        let _guard = guard;
        std::future::pending::<()>().await;
        unreachable!("the pending hook never completes")
    })
}

#[tokio::test(start_paused = true)]
async fn a_detached_committed_hook_is_cancelled_at_the_authorization_bound() {
    let cleanup_timeout = ferrum_edge::_test_support::detached_response_committed_cleanup_timeout();
    // The client RPC deadline already won and detached this hook; the
    // credential's own lifetime is still ahead, but strictly inside the fixed
    // cleanup window.
    let authorization_at = tokio::time::Instant::now() + Duration::from_secs(2);
    assert!(
        Duration::from_secs(2) < cleanup_timeout,
        "this test only means anything while the authorization bound is inside the \
         fixed cleanup window"
    );
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        never_completing_hook(&dropped),
        Some(authorization_at),
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the detached observer runs normally while the credential is still authorized"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the detached hook — and with it the cloned request context and the protected \
         response body — must be dropped at the authorization lifetime, not held for the \
         remainder of the fixed cleanup timeout"
    );
}

#[tokio::test(start_paused = true)]
async fn a_detached_committed_hook_keeps_the_fixed_timeout_without_an_authorization_bound() {
    let cleanup_timeout = ferrum_edge::_test_support::detached_response_committed_cleanup_timeout();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        never_completing_hook(&dropped),
        None,
    );

    tokio::time::sleep(cleanup_timeout - Duration::from_millis(500)).await;
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "an unauthenticated request is not bounded by this contract at all"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the fixed post-response cleanup timeout still applies"
    );
}

#[tokio::test(start_paused = true)]
async fn a_later_authorization_bound_never_extends_the_fixed_cleanup_timeout() {
    let cleanup_timeout = ferrum_edge::_test_support::detached_response_committed_cleanup_timeout();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        never_completing_hook(&dropped),
        Some(tokio::time::Instant::now() + cleanup_timeout * 10),
    );

    tokio::time::sleep(cleanup_timeout + Duration::from_secs(1)).await;
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the EARLIEST of the two bounds wins; a long-lived credential may not extend the \
         fixed post-response cleanup window"
    );
}

/// A detached observer that is READY on its FIRST poll, counting the protected
/// side effect it performs. This is the shape `tokio::time::timeout_at` cannot
/// bound: it polls the inner future before it ever observes the timer.
fn ready_hook(
    observed: &Arc<std::sync::atomic::AtomicUsize>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = RequestContext> + Send + 'static>> {
    let observed = Arc::clone(observed);
    Box::pin(async move {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        anonymous_ctx()
    })
}

/// A detached observer that parks first and performs its side effect only after
/// `delay` — so the wake-up that would run it lands after the bound.
fn delayed_hook(
    observed: &Arc<std::sync::atomic::AtomicUsize>,
    delay: Duration,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = RequestContext> + Send + 'static>> {
    let observed = Arc::clone(observed);
    Box::pin(async move {
        tokio::time::sleep(delay).await;
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        anonymous_ctx()
    })
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_authorization_bound_refuses_a_ready_detached_cleanup() {
    // Spawning is not running: an unbounded amount of time can pass between
    // `tokio::spawn` and the first poll. With the bound already elapsed at that
    // first poll, NOTHING protected may execute — not the pending observer's
    // next step, not the remaining chain.
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        ready_hook(&observed),
        tokio::time::Instant::now().checked_sub(Duration::from_secs(1)),
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a credential that is no longer authorized must not execute one more protected \
         side effect, however ready the chain is on its first poll"
    );
}

#[tokio::test(start_paused = true)]
async fn a_live_authorization_bound_still_runs_a_ready_detached_cleanup() {
    // The complement: the refusal must not turn into a blanket cancellation of
    // authenticated post-response work.
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        ready_hook(&observed),
        Some(tokio::time::Instant::now() + Duration::from_secs(2)),
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a still-authorized credential keeps its ordinary cleanup window"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_ready_detached_cleanup_keeps_the_fixed_timeout() {
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        ready_hook(&observed),
        None,
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an unauthenticated request is not bounded by this contract at all"
    );
}

#[tokio::test(start_paused = true)]
async fn a_detached_cleanup_resumed_after_the_bound_never_runs_its_observer() {
    // Not the first poll but a RESUMPTION: the chain parks, and the wake-up
    // that would complete it lands after the authorization bound.
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        delayed_hook(&observed, Duration::from_secs(10)),
        Some(tokio::time::Instant::now() + Duration::from_secs(2)),
    );

    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the chain must be cancelled at the bound, not resumed past it"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_authorization_bound_detaches_nothing() {
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    ferrum_edge::_test_support::spawn_detached_response_committed_hook_for_test(
        never_completing_hook(&dropped),
        tokio::time::Instant::now().checked_sub(Duration::from_secs(1)),
    );

    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "a credential that is already unauthorized must not get a cleanup window at all"
    );
}

#[tokio::test]
async fn the_detached_bound_carries_the_credential_lifetime_even_when_the_client_wins() {
    // The seam that produces the detached bound is the same composed
    // pre-commitment bound the synchronous phase used, so a client `grpc-timeout`
    // winning the phase must NOT erase the credential's absolute deadline.
    let lifetime_guard = crate::unit::env_lock::StreamAuthMaxLifetimeGuard::new();
    lifetime_guard.publish(120);
    let ctx = authenticated_ctx();
    let authorization_at =
        ferrum_edge::_test_support::detached_response_committed_authorization_bound_for_test(&ctx)
            .expect("an admitted authenticated request carries an absolute authorization bound");
    assert!(
        authorization_at <= tokio::time::Instant::now() + Duration::from_secs(120),
        "the detached bound must never exceed the finite authenticated-stream maximum"
    );
    assert_eq!(
        ferrum_edge::_test_support::detached_response_committed_authorization_bound_for_test(
            &anonymous_ctx()
        ),
        None,
        "an unauthenticated request carries no authorization bound"
    );
    drop(lifetime_guard);
}

/// Every detached committed-response handoff carries the bound (issue #3815).
///
/// The spawner is reached from six lifecycles across `proxy/mod.rs`,
/// `http3/server.rs`, and `http3/cross_protocol.rs`; a call site that forgot the
/// bound would silently restore the unbounded-past-expiry shape.
#[test]
fn every_detached_committed_hook_handoff_carries_the_authorization_bound() {
    for (name, source) in [
        ("proxy/mod.rs", include_str!("../../../src/proxy/mod.rs")),
        ("http3/server.rs", H3_SERVER_SOURCE),
        (
            "http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
        ),
    ] {
        for (index, call) in source
            .split("spawn_detached_response_committed_hooks(")
            .skip(1)
            .enumerate()
        {
            // Skip the definition and the doc/test-support references, which do
            // not open an argument list ending in `);`.
            let args = call.split(");").next().expect("bounded argument list");
            if args.contains("pending_hook: OwnedResponseCommittedHookFuture") {
                continue;
            }
            assert!(
                args.contains("detached_bound") || args.contains("DetachedResponseCommittedBound"),
                "{name} handoff #{index} detaches committed-response work without the \
                 admitted credential's absolute authorization bound"
            );
        }
    }

    // Cancelling that cleanup must not record a termination: the RPC terminal
    // was already decided by the client's own deadline, so counting one here
    // would be a false — and, on a stream the response body also bounded, a
    // double — authorization termination.
    let spawner = include_str!("../../../src/proxy/mod.rs")
        .split("pub(crate) fn spawn_detached_response_committed_hooks(")
        .nth(1)
        .expect("the detached committed-response spawner")
        .split("\n/// ")
        .next()
        .expect("bounded spawner body");
    assert!(
        !spawner.contains("record_once(") && !spawner.contains("record_termination("),
        "the detached cleanup must not record an authorization termination for a response \
         whose terminal another bound already decided"
    );
    assert!(
        spawner.contains("sleep_until(deadline)"),
        "the detached cleanup must run under an ABSOLUTE bound, not a fresh relative timeout"
    );
    assert!(
        !spawner.contains("timeout_at("),
        "`timeout_at` polls its inner future before it observes the timer, so a chain that \
         is ready on its first poll executes once even when the bound already elapsed"
    );
    // The bound is enforced twice: a refusal that polls nothing, and a per-poll
    // clock gate ahead of every resumption.
    let refusal_at = spawner
        .find("if let Some(at) = authorization_at\n            && started_at >= at\n        {")
        .expect("past-deadline refusal");
    let cleanup_at = spawner
        .find("let cleanup = async move {")
        .expect("cleanup chain construction");
    assert!(
        refusal_at < cleanup_at,
        "an already-elapsed authorization bound must be refused before the chain exists"
    );
    assert!(
        spawner.contains("std::future::poll_fn(move |cx| {")
            && spawner.contains("&& tokio::time::Instant::now() >= at"),
        "every resumption of the detached chain must re-check the authorization bound"
    );
    // Deadline-biased: the bound arm is first, so a chain that becomes ready in
    // the same wake-up as the bound loses to it.
    let select = spawner
        .split("let completed = tokio::select! {")
        .nth(1)
        .expect("deadline-biased race")
        .split("};")
        .next()
        .expect("bounded select");
    let biased_at = select.find("biased;").expect("biased select");
    let sleep_at = select.find("&mut deadline_sleep").expect("deadline arm");
    let chain_at = select.find("&mut guarded").expect("cleanup arm");
    assert!(
        biased_at < sleep_at && sleep_at < chain_at,
        "the authorization bound must be the FIRST select arm"
    );
}

/// Normalize a collected `tracing` macro invocation for phrase matching.
///
/// Rust string continuations split a message across source lines with a
/// trailing backslash and leading indentation, so the raw source text of a
/// wrapped "reached its authorization lifetime" message does not contain that
/// phrase at all. Dropping backslashes and collapsing whitespace runs is what
/// makes the contract below match the message an operator actually sees —
/// without it, wrapping a line would silently exempt a site.
fn normalize_log_message(invocation: &str) -> String {
    let mut normalized = String::with_capacity(invocation.len());
    let mut last_was_space = false;
    for ch in invocation.chars() {
        if ch == '\\' {
            continue;
        }
        if ch.is_whitespace() {
            if !last_was_space {
                normalized.push(' ');
                last_was_space = true;
            }
            continue;
        }
        last_was_space = false;
        normalized.extend(ch.to_lowercase());
    }
    normalized
}

/// Ordinary authorization expiry must never be a warning-log amplification
/// surface (root review of PR #3820).
///
/// An expiry is expected lifecycle AND client-triggerable: any client holding a
/// short-TTL credential produces one on every stream it opens, and a single
/// request can reach several of these sites across the H3 relays, the
/// cross-protocol relays, and the detached committed-response cleanup. At
/// `warn!` that is an unbounded, client-driven flood of a severity operators
/// page on.
///
/// The observable record of an expiry is the fixed-cardinality
/// `authorization_lifetime` counter pair and the bounded
/// `authorization.termination_reason` transaction-summary metadata — neither
/// depends on a log line — so the messages are `debug!`. `warn!`/`error!`
/// stays for genuinely anomalous cleanup, write, or invariant failures, which
/// is why this contract keys on the MESSAGE naming the authorization lifetime
/// rather than on a site list.
#[test]
fn ordinary_authorization_expiry_is_never_logged_at_warning_level() {
    const SOURCES: &[(&str, &str)] = &[
        ("proxy/mod.rs", include_str!("../../../src/proxy/mod.rs")),
        ("proxy/body.rs", include_str!("../../../src/proxy/body.rs")),
        (
            "proxy/tcp_proxy.rs",
            include_str!("../../../src/proxy/tcp_proxy.rs"),
        ),
        (
            "proxy/udp_proxy.rs",
            include_str!("../../../src/proxy/udp_proxy.rs"),
        ),
        (
            "proxy/upload_pump.rs",
            include_str!("../../../src/proxy/upload_pump.rs"),
        ),
        (
            "proxy/response_watchdog.rs",
            include_str!("../../../src/proxy/response_watchdog.rs"),
        ),
        (
            "proxy/grpc_proxy.rs",
            include_str!("../../../src/proxy/grpc_proxy.rs"),
        ),
        ("http3/server.rs", H3_SERVER_SOURCE),
        (
            "http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
        ),
        (
            "http3/stream_util.rs",
            include_str!("../../../src/http3/stream_util.rs"),
        ),
    ];
    // Phrases that only an ORDINARY expiry message carries. A genuinely
    // anomalous failure describes the failure ("cleanup exceeded its
    // post-response bound"), not the lifetime.
    const EXPIRY_PHRASES: &[&str] = &[
        "authorization lifetime",
        "credential expired",
        "authenticated stream lifetime",
    ];

    let mut offenders: Vec<String> = Vec::new();
    for (name, source) in SOURCES {
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("warn!(") || trimmed.starts_with("error!(")) {
                continue;
            }
            // Collect the whole macro invocation by paren balance.
            let mut depth = 0i32;
            let mut invocation = String::new();
            for candidate in source.lines().skip(index) {
                invocation.push(' ');
                invocation.push_str(candidate);
                depth += candidate.matches('(').count() as i32;
                depth -= candidate.matches(')').count() as i32;
                if depth <= 0 {
                    break;
                }
            }
            if EXPIRY_PHRASES
                .iter()
                .any(|phrase| normalize_log_message(&invocation).contains(phrase))
            {
                offenders.push(format!("{name}:{}", index + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "ordinary authorization-lifetime expiry must be logged at debug!, not warn!/error! \
         (offending sites: {offenders:?}); see the `Log level` section of \
         src/proxy/auth_lifetime.rs"
    );
}

/// The downgrade must not have deleted the messages: they stay compiled in, at
/// `debug!`, so an operator can still turn them on for one investigation
/// without also arming a client-triggerable warning flood.
#[test]
fn authorization_expiry_messages_are_still_compiled_in_at_debug_level() {
    for (name, source) in [
        ("http3/server.rs", H3_SERVER_SOURCE),
        (
            "http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
        ),
        ("proxy/mod.rs", include_str!("../../../src/proxy/mod.rs")),
    ] {
        let mut debug_expiry_sites = 0usize;
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("debug!(") {
                continue;
            }
            let mut depth = 0i32;
            let mut invocation = String::new();
            for candidate in lines.iter().skip(index) {
                invocation.push(' ');
                invocation.push_str(candidate);
                depth += candidate.matches('(').count() as i32;
                depth -= candidate.matches(')').count() as i32;
                if depth <= 0 {
                    break;
                }
            }
            if normalize_log_message(&invocation).contains("authorization lifetime") {
                debug_expiry_sites += 1;
            }
        }
        assert!(
            debug_expiry_sites > 0,
            "{name} must still carry its authorization-lifetime expiry messages, at debug level"
        );
    }
}
