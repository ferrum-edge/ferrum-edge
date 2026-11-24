//! Post-admission TCP+TLS setup under frontend client-trust retirement
//! (issue #3857).
//!
//! Registration happens right after the frontend handshake, but the client leg
//! is not polled again until the relay starts. Everything in between — the
//! `on_stream_connect` chain, the decrypted first-bytes read, DNS resolution,
//! retry backoff, the backend dial and its TLS/PROXY setup, and the forward of
//! the decrypted prefix that first-bytes inspection had already consumed — is an
//! await the relay's `TrustFencedStream` cannot reach. A withdrawal landing
//! there used to retire the session while setup carried on, and the buffered
//! prefix was then written straight to the backend under nothing but the
//! credential's own lifetime.
//!
//! These cases drive the production seams directly:
//!
//! - a blocked setup stage is interrupted promptly, and its future is dropped
//!   rather than resumed;
//! - a connect-retry backoff is interrupted the same way;
//! - a blocked `on_stream_connect` hook is dropped mid-poll, no later hook runs,
//!   and the chain still releases its admission permits and settles the mesh
//!   opened/closed finalizer exactly once;
//! - the buffered prefix is never written after retirement, whether the
//!   withdrawal lands before the forward or races a write parked on a full
//!   backend buffer;
//! - trust retirement and credential expiry stay independent, earliest-wins
//!   causes, with the operator's decision reported on a tie — on the prefix
//!   forward too, which is driven through the same combined bound;
//! - settlement is client-side, health-neutral, redacted, and counted once.
//!
//! No sleeps: every case is driven by an explicit publication.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    PrefixForwardRejectForTest, StreamSetupInterruptForTest,
    stream_ctx_hold_admission_permit_for_test, tcp_forward_prefix_under_trust_fence_for_test,
    tcp_forward_prefix_within_setup_bounds_for_test, tcp_retry_backoff_within_bounds_for_test,
    tcp_settle_stream_trust_withdrawal_for_test, tcp_setup_stage_within_bounds_for_test,
    tcp_stream_connect_chain_under_trust_fence_for_test,
};
use ferrum_edge::plugins::mesh::prometheus_helpers;
use ferrum_edge::plugins::{Plugin, PluginResult, StreamConnectionContext};
use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};
use ferrum_edge::proxy::stream_error::{StreamSetupKind, find_stream_setup_error};
use ferrum_edge::tls::ClientTrustSessionGuard;
use ferrum_edge::tls::client_trust::{self, ClientTrustMaterial, ClientTrustScope};
use ferrum_edge::{BackendScheme, ConsumerIndex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use super::client_trust_tests::isolated_registry;

const SCOPE: ClientTrustScope = ClientTrustScope::ProxyFrontend;

/// Long enough that the backend duplex buffer fills part way through.
const PREFIX: &[u8] = b"0123456789abcdef";

/// Arm the proxy-frontend domain and register one client-certificate
/// transport, exactly as the TCP+TLS path does after its handshake.
fn armed_transport() -> ClientTrustSessionGuard {
    client_trust::publish_accepted_material(
        SCOPE,
        ClientTrustMaterial::from_test_digest([1u8; 32]),
    );
    client_trust::capture(SCOPE)
        .expect("scope is armed")
        .register(true)
        .expect("a client-certificate transport registers")
}

/// Publish a candidate that drops the accepted anchor: authority narrows, so
/// every transport registered below the new generation is retired.
fn withdraw_client_ca() {
    client_trust::publish_accepted_material(
        SCOPE,
        ClientTrustMaterial::from_test_digest([2u8; 32]),
    );
}

fn fenced_total() -> u64 {
    client_trust::snapshot()
        .into_iter()
        .find(|row| row.scope == SCOPE)
        .map(|row| row.fenced)
        .expect("every scope is snapshotted")
}

fn elapsed_plan(termination: StreamAuthTermination) -> Option<StreamAuthDeadline> {
    Some(StreamAuthDeadline {
        at: tokio::time::Instant::now() - Duration::from_secs(1),
        termination,
    })
}

/// A setup stage that never completes and records whether it was dropped.
struct BlockedStage(Arc<AtomicBool>);

impl Future for BlockedStage {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for BlockedStage {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A setup stage that records whether it was ever polled.
struct ObservedStage(Arc<AtomicBool>);

impl Future for ObservedStage {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Ready(())
    }
}

// ---------------------------------------------------------------------------
// Setup stages
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn an_already_withdrawn_transport_never_polls_a_setup_stage() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    assert!(transport.session().is_retired());

    let polled = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&polled));
    let session = transport.session();
    let outcome = tcp_setup_stage_within_bounds_for_test(None, Some(session), stage).await;

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "a withdrawn transport must not run another setup stage at all"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_interrupts_a_blocked_post_admission_setup_stage() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let dropped = Arc::new(AtomicBool::new(false));
    let stage = BlockedStage(Arc::clone(&dropped));
    let session = transport.session();

    // The stage stands in for DNS resolution, the backend dial, or the backend
    // TLS handshake: it is parked, and only the withdrawal can end it.
    let (outcome, ()) = tokio::join!(
        tcp_setup_stage_within_bounds_for_test(None, Some(session), stage),
        async {
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the interrupted stage must be dropped, not left to finish"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_interrupts_a_connect_retry_backoff() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let backoff = Duration::from_secs(3600);

    // A retry backoff is the longest unattended setup wait there is. The clock
    // is left alone: the case only completes if the withdrawal — not the delay
    // — is what returns.
    let (outcome, ()) = tokio::join!(
        tcp_retry_backoff_within_bounds_for_test(None, Some(session), backoff),
        async {
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
}

#[tokio::test]
async fn an_unregistered_transport_runs_setup_stages_unbounded() {
    // Plaintext, kTLS, and anonymous-TLS connections register nothing, so they
    // keep the previous behaviour and poll no retirement future at all.
    let polled = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&polled));
    let outcome = tcp_setup_stage_within_bounds_for_test(None, None, stage).await;

    assert!(outcome.is_ok());
    assert!(polled.load(Ordering::SeqCst));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn an_elapsed_credential_still_settles_as_an_authorization_expiry() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);

    // Trust still stands, so the credential's own lifetime keeps its own
    // termination class: the two bounds are independent.
    let stage = std::future::pending::<()>();
    let outcome = tcp_setup_stage_within_bounds_for_test(plan, Some(session), stage).await;

    let expected = StreamAuthTermination::CredentialExpired;
    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::AuthorizationExpired(expected)
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_outranks_a_credential_that_also_elapsed() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();
    let plan = elapsed_plan(StreamAuthTermination::AuthenticatedStreamMaxLifetime);

    // Both bounds are eligible at this observation. An authority decision the
    // operator has already taken outranks a timer that merely also elapsed —
    // the ordering the WebSocket stop arbiter and the DTLS delivery fence use.
    let stage = std::future::pending::<()>();
    let outcome = tcp_setup_stage_within_bounds_for_test(plan, Some(session), stage).await;

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
}

// ---------------------------------------------------------------------------
// The buffered decrypted prefix
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawn_transport_forwards_no_inspected_prefix_byte() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();

    let (mut backend, mut peer) = tokio::io::duplex(64);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session)).await;

    assert!(matches!(
        outcome,
        Err(PrefixForwardRejectForTest::TrustWithdrawn)
    ));
    let mut seen = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(50), peer.read(&mut seen)).await;
    assert!(
        read.is_err(),
        "not one already-decrypted client byte may reach the backend after retirement"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_racing_the_prefix_write_abandons_the_remainder() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    // The backend never reads, so the write parks with the prefix half
    // delivered — the exact window in which a withdrawal used to stay invisible
    // until the relay started.
    let (mut backend, mut peer) = tokio::io::duplex(4);
    let writer = &mut backend;
    let (outcome, ()) = tokio::join!(
        tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session)),
        async {
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    assert!(matches!(
        outcome,
        Err(PrefixForwardRejectForTest::TrustWithdrawn)
    ));
    let mut buffered = [0u8; 4];
    peer.read_exact(&mut buffered)
        .await
        .expect("bytes written before the withdrawal stay written");
    assert_eq!(&buffered, b"0123");
    let mut extra = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(50), peer.read(&mut extra)).await;
    assert!(
        read.is_err(),
        "the rest of the prefix must be abandoned, not completed after retirement"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_live_transport_forwards_the_whole_inspected_prefix() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    let (mut backend, mut peer) = tokio::io::duplex(64);
    let writer = &mut backend;
    tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session))
        .await
        .expect("a live transport forwards its prefix unchanged");

    let mut seen = [0u8; 16];
    peer.read_exact(&mut seen).await.expect("peer read");
    assert_eq!(&seen, PREFIX);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_backend_write_failure_stays_backend_evidence() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    // Trust still stands, so a failing backend leg reports as backend evidence
    // rather than borrowing the health-neutral trust refusal.
    let (mut backend, peer) = tokio::io::duplex(64);
    drop(peer);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session)).await;

    assert!(matches!(outcome, Err(PrefixForwardRejectForTest::Io(_))));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_outranks_a_credential_that_also_elapsed_on_the_prefix_forward() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);

    // Both post-admission bounds are eligible at this one observation. The
    // prefix forward is driven through the same combined bound as every other
    // paired observation, so the operator's withdrawal — not the timer that
    // merely also elapsed — is what the refusal reports.
    let (mut backend, mut peer) = tokio::io::duplex(64);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_within_setup_bounds_for_test(plan, Some(session), writer, PREFIX).await;

    assert_eq!(
        outcome.expect_err("a retired transport forwards nothing"),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
    let mut seen = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(50), peer.read(&mut seen)).await;
    assert!(
        read.is_err(),
        "not one already-decrypted client byte may reach the backend after retirement"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn an_elapsed_credential_alone_still_ends_the_prefix_forward_as_an_expiry() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let plan = elapsed_plan(StreamAuthTermination::AuthenticatedStreamMaxLifetime);

    // Trust still stands, so adding the trust bound did not absorb the
    // credential's own lifetime: the two stay independent causes.
    let (mut backend, _peer) = tokio::io::duplex(64);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_within_setup_bounds_for_test(plan, Some(session), writer, PREFIX).await;

    assert_eq!(
        outcome.expect_err("an elapsed credential forwards nothing"),
        StreamSetupInterruptForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_backend_write_failure_under_both_bounds_stays_backend_evidence() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    // Neither bound fired, so the composed path must still hand the backend's
    // own failure back as backend evidence rather than a health-neutral
    // authorization refusal.
    let (mut backend, peer) = tokio::io::duplex(64);
    drop(peer);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_within_setup_bounds_for_test(None, Some(session), writer, PREFIX).await;

    let forwarded = outcome.expect("no post-admission bound fired");
    assert!(matches!(forwarded, Err(PrefixForwardRejectForTest::Io(_))));
}

// ---------------------------------------------------------------------------
// The `on_stream_connect` chain
// ---------------------------------------------------------------------------

/// Records its own drop, so a test can prove a future was dropped rather than
/// left to finish.
struct DropWitness(Arc<AtomicBool>);

impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A stream-connect hook that parks forever, standing in for any plugin whose
/// hook is blocked or slow (a remote authorization call, a throttle wait, a
/// fault-injection delay).
struct BlockedStreamConnect {
    entered: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

#[async_trait]
impl Plugin for BlockedStreamConnect {
    fn name(&self) -> &str {
        "test_blocked_stream_connect"
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        let _witness = DropWitness(Arc::clone(&self.dropped));
        self.entered.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
        PluginResult::Continue
    }
}

/// A stream-connect hook that records whether it ran at all.
struct RecordingStreamConnect(Arc<AtomicBool>);

#[async_trait]
impl Plugin for RecordingStreamConnect {
    fn name(&self) -> &str {
        "test_recording_stream_connect"
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        self.0.store(true, Ordering::SeqCst);
        PluginResult::Continue
    }
}

/// A connected TCP pair. The chain takes the accepted client socket; the
/// initiator is held so the peer never resets under the test.
async fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).await.expect("connect");
    let (accepted, _) = listener.accept().await.expect("accept");
    (accepted, client)
}

/// A TCP+TLS stream context carrying the mesh observation markers, so the mesh
/// `TCP_OPENED_CONNECTIONS` finalizer this path owns is actually reachable.
fn mesh_observed_stream_ctx() -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "203.0.113.7".to_string(),
        "203.0.113.7".to_string(),
        "tcp-tls-proxy".to_string(),
        Some("TCP/TLS Proxy".to_string()),
        9443,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    let mut metadata = HashMap::new();
    metadata.insert(
        prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA.to_string(),
        "1".to_string(),
    );
    metadata.insert(
        prometheus_helpers::MESH_WORKLOAD_METRICS_OBSERVED_METADATA.to_string(),
        "1".to_string(),
    );
    metadata.insert("mesh.request_protocol".to_string(), "tcp".to_string());
    ctx.metadata = Some(metadata.into_iter().collect());
    ctx
}

fn opened_finalized(ctx: &StreamConnectionContext) -> bool {
    ctx.metadata
        .as_ref()
        .is_some_and(prometheus_helpers::mesh_tcp_opened_finalized)
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_interrupts_a_blocked_on_stream_connect_hook() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let (accepted, _initiator) = connected_pair().await;

    let entered = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let later_ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(BlockedStreamConnect {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
        }),
        Arc::new(RecordingStreamConnect(Arc::clone(&later_ran))),
    ];

    let mut stream_ctx = mesh_observed_stream_ctx();
    // Model a hook that already took an admission permit before the blocked one
    // parked: the fence must hand it back, exactly once.
    let released = Arc::new(AtomicUsize::new(0));
    stream_ctx_hold_admission_permit_for_test(&mut stream_ctx, Arc::clone(&released));

    let latch = AtomicBool::new(false);
    let before = fenced_total();

    let (outcome, ()) = tokio::join!(
        tcp_stream_connect_chain_under_trust_fence_for_test(
            &plugins,
            &mut stream_ctx,
            &accepted,
            Some(session),
            &latch,
        ),
        async {
            // No sleep: the blocked hook is parked, so the very next scheduling
            // point is the explicit publication that retires the transport.
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    let error = outcome.expect_err("a retired transport must not be admitted");
    assert!(
        entered.load(Ordering::SeqCst),
        "the case is only meaningful if the blocked hook really started"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the in-flight hook future must be dropped, not left to finish"
    );
    assert!(
        !later_ran.load(Ordering::SeqCst),
        "no later hook may run once the trust decision is withdrawn"
    );
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "every admission permit the chain took is released exactly once"
    );
    assert!(
        opened_finalized(&stream_ctx),
        "the mesh opened/closed finalizer settles under the completed hooks' metadata"
    );

    let kind = find_stream_setup_error(&error)
        .expect("the refusal carries a typed stream-setup kind")
        .kind;
    assert_eq!(kind, StreamSetupKind::ClientTrustWithdrawn);
    assert!(kind.is_client_side());
    assert_eq!(
        error.to_string(),
        "Frontend client trust withdrawn during setup with no further backend bytes written"
    );

    // The production path re-checks the fence after the chain returns. That
    // second observation shares the connection's latch, so the fixed-cardinality
    // fence counter stays at one for this connection.
    assert_eq!(fenced_total(), before + 1);
    let _repeat = tcp_settle_stream_trust_withdrawal_for_test(Some(session), &latch);
    assert_eq!(fenced_total(), before + 1);

    // Draining the permits was the release; dropping the context is not a
    // second one.
    drop(stream_ctx);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn an_already_withdrawn_transport_runs_no_stream_connect_hook() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();
    let (accepted, _initiator) = connected_pair().await;

    let ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RecordingStreamConnect(Arc::clone(&ran)))];
    let mut stream_ctx = mesh_observed_stream_ctx();
    let latch = AtomicBool::new(false);

    let error = tcp_stream_connect_chain_under_trust_fence_for_test(
        &plugins,
        &mut stream_ctx,
        &accepted,
        Some(session),
        &latch,
    )
    .await
    .expect_err("a retired transport must not be admitted");

    assert!(
        !ran.load(Ordering::SeqCst),
        "a withdrawn transport must not start a hook at all"
    );
    assert_eq!(
        find_stream_setup_error(&error)
            .expect("the refusal carries a typed stream-setup kind")
            .kind,
        StreamSetupKind::ClientTrustWithdrawn
    );
    assert!(opened_finalized(&stream_ctx));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_live_transport_runs_the_whole_stream_connect_chain() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let (accepted, _initiator) = connected_pair().await;

    let first = Arc::new(AtomicBool::new(false));
    let second = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(RecordingStreamConnect(Arc::clone(&first))),
        Arc::new(RecordingStreamConnect(Arc::clone(&second))),
    ];
    let mut stream_ctx = mesh_observed_stream_ctx();
    let released = Arc::new(AtomicUsize::new(0));
    stream_ctx_hold_admission_permit_for_test(&mut stream_ctx, Arc::clone(&released));
    let latch = AtomicBool::new(false);

    tcp_stream_connect_chain_under_trust_fence_for_test(
        &plugins,
        &mut stream_ctx,
        &accepted,
        Some(session),
        &latch,
    )
    .await
    .expect("a live transport is admitted");

    assert!(first.load(Ordering::SeqCst) && second.load(Ordering::SeqCst));
    assert!(
        opened_finalized(&stream_ctx),
        "an accepted chain still finalizes the mesh TCP lifecycle"
    );
    assert_eq!(
        released.load(Ordering::SeqCst),
        0,
        "an admitted connection keeps its permits for the relay"
    );
}

#[tokio::test]
async fn an_unregistered_transport_runs_the_stream_connect_chain_unfenced() {
    // Plaintext, passthrough, and kTLS connections register no withdrawable
    // trust decision: they poll no retirement future and keep the previous
    // behaviour.
    let (accepted, _initiator) = connected_pair().await;
    let ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RecordingStreamConnect(Arc::clone(&ran)))];
    let mut stream_ctx = mesh_observed_stream_ctx();
    let latch = AtomicBool::new(false);

    tcp_stream_connect_chain_under_trust_fence_for_test(
        &plugins,
        &mut stream_ctx,
        &accepted,
        None,
        &latch,
    )
    .await
    .expect("an unregistered transport is admitted");

    assert!(ran.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

#[test]
fn a_setup_withdrawal_settles_once_and_stays_client_side() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();
    let before = fenced_total();

    let latch = AtomicBool::new(false);
    let error = tcp_settle_stream_trust_withdrawal_for_test(Some(session), &latch);
    let repeat = tcp_settle_stream_trust_withdrawal_for_test(Some(session), &latch);

    assert_eq!(
        fenced_total(),
        before + 1,
        "a connection settles its withdrawal once however many fences observe it"
    );

    for settled in [&error, &repeat] {
        let kind = find_stream_setup_error(settled)
            .expect("the refusal carries a typed stream-setup kind")
            .kind;
        assert_eq!(kind, StreamSetupKind::ClientTrustWithdrawn);
        assert!(
            kind.is_client_side(),
            "a withdrawn client-trust decision is a local authorization event, \
             never evidence about the upstream"
        );
        // Fixed and redacted, and true at EVERY setup fence: a withdrawal can
        // land after a partially written outbound PROXY header, or after the
        // prefix forward already delivered its pre-withdrawal bytes. What the
        // fence guarantees is that nothing FURTHER is written.
        assert_eq!(
            settled.to_string(),
            "Frontend client trust withdrawn during setup with no further backend bytes written"
        );
    }
}
