//! Backend-send isolation for the shared UDP listener (issue #5045).
//!
//! The no-hook client→backend path used to `await` the backend send inside the
//! shared receive/drain loop, so a send parked for T added roughly T of delay to
//! every later client on that listener; with a DTLS backend even an ordinary
//! successful datagram cost an inter-task driver round trip before the next
//! packet could be looked at.
//!
//! These drive the production seams — the non-blocking admission, the bounded
//! per-session writer, its item and byte budgets, and the teardown that closes
//! it — through `UdpEgressWriterProbe`, which builds a REAL `UdpSession` with a
//! real connected backend socket. Only the backend send itself is injected, so
//! "the healthy session progressed while the other was blocked" is a scheduling
//! fact rather than a sleep, and no benchmark is needed to decide it.

use ferrum_edge::_test_support::{UdpEgressAdmissionForTest, UdpEgressWriterProbe};

/// Per-session writer depth, mirroring `SESSION_EGRESS_MAX_QUEUED_DATAGRAMS`.
const MAX_QUEUED_DATAGRAMS: usize = 64;

/// Per-session retained-payload budget, mirroring
/// `SESSION_EGRESS_MAX_QUEUED_BYTES`.
const MAX_QUEUED_BYTES: usize = 256 * 1024;

const UDP_PROXY_SOURCE: &str = include_str!("../../../src/proxy/udp_proxy.rs");

fn body_of(marker: &str) -> &'static str {
    UDP_PROXY_SOURCE
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("{marker} not found in udp_proxy.rs"))
}

async fn probe() -> UdpEgressWriterProbe {
    UdpEgressWriterProbe::new()
        .await
        .expect("the egress writer probe")
}

/// Yield until `predicate` holds. Bounded so a broken invariant fails instead of
/// hanging, and free of wall-clock waits so the verdict belongs to the scheduler
/// rather than to a timer.
async fn settle(what: &str, predicate: impl Fn() -> bool) {
    for _ in 0..5_000 {
        if predicate() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {what}");
}

/// An uncongested plain-UDP datagram must still be written straight out of the
/// borrowed receive buffer: no `Bytes`, no channel, no worker.
///
/// The probe drives its session socket to writability first, the way
/// production's awaited first forward drives it during session setup: tokio's
/// `try_send` answers `WouldBlock` without a syscall while the I/O driver has
/// not yet observed a freshly registered socket, and that is a probe artefact
/// rather than the local socket pressure the writer exists for.
#[tokio::test]
async fn an_uncongested_plain_udp_datagram_takes_the_borrowed_fast_path() {
    let probe = UdpEgressWriterProbe::with_amplification_factor(Some(4.0))
        .await
        .expect("the egress writer probe");

    assert_eq!(
        probe.forward_without_blocking(b"hello"),
        UdpEgressAdmissionForTest::Sent,
        "an immediately writable connected socket keeps the inline path"
    );

    assert_eq!(probe.backend_peer_recv().await, Ok(b"hello".to_vec()));
    assert_eq!(probe.handoffs(), 0, "no handoff for an uncongested send");
    assert_eq!(probe.started_sends(), 0, "the writer was never involved");
    assert_eq!(probe.queued_datagrams(), 0);
    assert_eq!(probe.queued_bytes(), 0);
    assert_eq!(probe.bytes_sent(), 5);
    assert!(
        probe.response_budget() > 0,
        "the response budget is published before the send, so a loopback reply \
         cannot beat the amplification guard"
    );
}

/// The core isolation property: one session parked on its backend send must not
/// hold up another session's traffic on the same listener.
#[tokio::test]
async fn a_parked_backend_send_on_one_session_does_not_stall_another_session() {
    let blocked = probe().await;
    // The SAME listener: one `UdpProxyMetrics`, two sessions.
    let healthy = UdpEgressWriterProbe::joining_listener_of(&blocked)
        .await
        .expect("a second session on the same listener");

    blocked.park_backend_sends();
    assert_eq!(
        blocked.hand_off_to_writer(b"blocked-1"),
        UdpEgressAdmissionForTest::Queued
    );
    settle("parked", || blocked.started_sends() == 1).await;

    for i in 0..8u8 {
        assert_eq!(
            healthy.hand_off_to_writer(&[i; 16]),
            UdpEgressAdmissionForTest::Queued,
            "the healthy session keeps admitting while its neighbour is parked"
        );
    }
    settle("healthy drain", || healthy.datagrams_out() == 8).await;

    assert_eq!(healthy.committed_sends().len(), 8);
    assert_eq!(healthy.queued_datagrams(), 0);
    assert_eq!(healthy.bytes_sent(), 8 * 16);
    assert_eq!(
        blocked.bytes_sent(),
        0,
        "the parked session made no progress, which is the point: it did not \
         have to, for the other session on this listener to finish"
    );
    assert_eq!(blocked.committed_sends(), Vec::<Vec<u8>>::new());
    assert_eq!(blocked.queued_datagrams(), 1);
    assert_eq!(blocked.queued_bytes(), b"blocked-1".len());

    blocked.release_backend_sends();
    settle("blocked drain", || blocked.datagrams_out() == 9).await;
    assert_eq!(blocked.committed_sends(), vec![b"blocked-1".to_vec()]);
    assert_eq!(blocked.queued_datagrams(), 0);
    assert_eq!(blocked.queued_bytes(), 0);
    assert_eq!(blocked.listener_queued_bytes(), 0);
}

/// Once the writer owns a datagram, a later fast-path datagram must queue behind
/// it rather than overtake it on the socket.
#[tokio::test]
async fn a_later_fast_path_datagram_queues_behind_the_writer_instead_of_overtaking() {
    let probe = probe().await;
    probe.park_backend_sends();

    assert_eq!(
        probe.hand_off_to_writer(b"first"),
        UdpEgressAdmissionForTest::Queued
    );
    settle("parked", || probe.started_sends() == 1).await;

    // The FIFO fence is what these two assertions are about: the connected
    // socket is perfectly writable, so without the fence both would be sent
    // immediately and would arrive ahead of `first`.
    assert_eq!(
        probe.forward_without_blocking(b"second"),
        UdpEgressAdmissionForTest::Queued
    );
    assert_eq!(
        probe.forward_without_blocking(b"third"),
        UdpEgressAdmissionForTest::Queued
    );
    assert_eq!(
        probe.backend_peer_received(),
        None,
        "no datagram may reach the backend socket ahead of the queued FIFO"
    );

    probe.release_backend_sends();
    settle("drain", || probe.datagrams_out() == 3).await;
    let committed = probe.committed_sends();
    assert_eq!(committed.len(), 3);
    assert_eq!(committed[0], b"first".to_vec());
    assert_eq!(committed[1], b"second".to_vec());
    assert_eq!(committed[2], b"third".to_vec());

    // Fence released: the next datagram takes the borrowed fast path again.
    assert_eq!(
        probe.forward_without_blocking(b"fourth"),
        UdpEgressAdmissionForTest::Sent
    );
    assert_eq!(probe.backend_peer_recv().await, Ok(b"fourth".to_vec()));
}

/// A handoff is an enqueue, not a wire commit. This is the property that keeps a
/// DTLS enqueue — which always goes through this writer — from being reported as
/// delivered ciphertext.
#[tokio::test]
async fn a_queued_datagram_is_not_counted_as_a_backend_send_until_it_settles() {
    let probe = probe().await;
    probe.park_backend_sends();

    assert_eq!(
        probe.hand_off_to_writer(b"payload-1234"),
        UdpEgressAdmissionForTest::Queued
    );
    settle("parked", || probe.started_sends() == 1).await;

    assert_eq!(probe.handoffs(), 1, "the handoff itself is counted");
    assert_eq!(probe.datagrams_out(), 0, "an enqueue is not a wire commit");
    assert_eq!(probe.bytes_out(), 0);
    assert_eq!(probe.bytes_sent(), 0);
    assert_eq!(probe.queue_drops(), 0);

    probe.release_backend_sends();
    settle("settled", || probe.datagrams_out() == 1).await;
    assert_eq!(probe.bytes_out(), 12);
    assert_eq!(probe.bytes_sent(), 12);
}

/// A failing backend send is accounted as a writer error — not as a completed
/// send, and not as a queue drop.
#[tokio::test]
async fn a_failed_queued_send_is_counted_as_a_writer_error() {
    let probe = probe().await;
    probe.park_backend_sends();
    probe.fail_backend_sends();

    assert_eq!(
        probe.hand_off_to_writer(b"doomed"),
        UdpEgressAdmissionForTest::Queued
    );
    settle("parked", || probe.started_sends() == 1).await;
    probe.release_backend_sends();

    settle("error", || probe.send_errors() == 1).await;
    assert_eq!(probe.datagrams_out(), 0, "a failed send is not a send");
    assert_eq!(probe.bytes_out(), 0);
    assert_eq!(probe.queue_drops(), 0, "a send error is not a queue drop");
    assert_eq!(
        probe.queued_datagrams(),
        0,
        "the item slot is released even when the send failed"
    );
    assert_eq!(probe.queued_bytes(), 0);
}

/// The item budget bounds pending work, tail-drops beyond it, and releases
/// exactly what a refused datagram charged.
#[tokio::test]
async fn the_writer_item_budget_tail_drops_and_releases_its_charge() {
    let probe = probe().await;
    probe.park_backend_sends();

    for _ in 0..MAX_QUEUED_DATAGRAMS {
        assert_eq!(
            probe.hand_off_to_writer(b"x"),
            UdpEgressAdmissionForTest::Queued
        );
    }
    assert_eq!(probe.queued_datagrams(), MAX_QUEUED_DATAGRAMS);
    assert_eq!(probe.queued_bytes(), MAX_QUEUED_DATAGRAMS);

    assert_eq!(
        probe.hand_off_to_writer(b"over"),
        UdpEgressAdmissionForTest::Dropped,
        "the item budget bounds pending work"
    );
    assert_eq!(probe.queue_drops(), 1);
    assert_eq!(
        probe.queued_datagrams(),
        MAX_QUEUED_DATAGRAMS,
        "a refused datagram must not leave an item slot charged"
    );
    assert_eq!(
        probe.queued_bytes(),
        MAX_QUEUED_DATAGRAMS,
        "a refused datagram must not leave bytes charged"
    );

    let expected = MAX_QUEUED_DATAGRAMS as u64;
    probe.release_backend_sends();
    settle("drain", || probe.datagrams_out() == expected).await;
    assert_eq!(probe.queued_bytes(), 0);
    assert_eq!(probe.listener_queued_bytes(), 0);
}

/// The byte budget is enforced independently of the item budget, so a
/// jumbo-datagram burst is bounded well before 64 queued packets.
#[tokio::test]
async fn the_writer_byte_budget_tail_drops_and_releases_its_charge() {
    let probe = probe().await;
    probe.park_backend_sends();

    let chunk = vec![0u8; 8 * 1024];
    let admitted = MAX_QUEUED_BYTES / chunk.len();
    assert!(
        admitted < MAX_QUEUED_DATAGRAMS,
        "the byte budget must be the binding one here"
    );
    for _ in 0..admitted {
        assert_eq!(
            probe.hand_off_to_writer(&chunk),
            UdpEgressAdmissionForTest::Queued
        );
    }
    assert_eq!(probe.queued_bytes(), MAX_QUEUED_BYTES);
    assert_eq!(probe.listener_queued_bytes(), MAX_QUEUED_BYTES);

    assert_eq!(
        probe.hand_off_to_writer(&chunk),
        UdpEgressAdmissionForTest::Dropped
    );
    assert_eq!(probe.queue_drops(), 1);
    assert_eq!(
        probe.queued_bytes(),
        MAX_QUEUED_BYTES,
        "the refused payload's bytes are released on both budgets"
    );
    assert_eq!(probe.listener_queued_bytes(), MAX_QUEUED_BYTES);
    assert_eq!(probe.queued_datagrams(), admitted);
}

/// A zero-length datagram is valid UDP and must be relayed like any other,
/// including across the handoff.
#[tokio::test]
async fn a_zero_length_datagram_survives_the_handoff() {
    let probe = probe().await;
    probe.park_backend_sends();

    assert_eq!(
        probe.hand_off_to_writer(b""),
        UdpEgressAdmissionForTest::Queued
    );
    settle("parked", || probe.started_sends() == 1).await;
    assert_eq!(
        probe.queued_datagrams(),
        1,
        "an empty datagram still holds an item slot"
    );
    assert_eq!(probe.queued_bytes(), 0);

    probe.release_backend_sends();
    settle("drain", || probe.datagrams_out() == 1).await;
    assert_eq!(probe.committed_sends(), vec![Vec::<u8>::new()]);
    assert_eq!(probe.queued_datagrams(), 0);
}

/// Teardown closes the writer through the SAME production call every session
/// teardown site already makes, nothing queued is sent afterwards, and both byte
/// budgets are released.
#[tokio::test]
async fn retiring_a_session_stops_the_writer_and_releases_every_queued_byte() {
    let probe = probe().await;
    probe.park_backend_sends();

    for _ in 0..5 {
        assert_eq!(
            probe.hand_off_to_writer(b"queued"),
            UdpEgressAdmissionForTest::Queued
        );
    }
    settle("parked", || probe.started_sends() == 1).await;

    probe.retire_session();
    assert!(
        !probe.writer_installed(),
        "`close_hook_ingress` must also close the backend-send writer"
    );
    probe.release_backend_sends();

    settle("released", || probe.queued_datagrams() == 0).await;
    assert_eq!(probe.queued_bytes(), 0);
    assert_eq!(probe.listener_queued_bytes(), 0);
    assert_eq!(
        probe.committed_sends().len(),
        1,
        "only the send already in flight settles; nothing still queued is sent \
         after the session is retired"
    );

    assert_eq!(
        probe.hand_off_to_writer(b"late"),
        UdpEgressAdmissionForTest::Dropped,
        "a late datagram must not resurrect a worker for a retired session"
    );
    assert_eq!(probe.queued_datagrams(), 0);
    assert_eq!(probe.queued_bytes(), 0);
}

// ── Wiring contracts ────────────────────────────────────────────────────

/// The shared receive/drain loop must not `await` a backend send for an
/// established no-hook session. That await is the listener-wide dependency this
/// change exists to remove, and it cannot be observed from outside a running
/// gateway, so it is asserted over the source.
#[test]
fn the_shared_receive_loop_never_awaits_a_backend_send() {
    let process = body_of("async fn process_datagram(");
    let inline = process
        .split("// Update cache for next datagram.")
        .nth(1)
        .expect("the established-session inline forward");
    assert!(
        inline.contains("forward_client_datagram_without_blocking(&session, data, metrics"),
        "the listener's no-hook branch admits without awaiting the backend send"
    );
    assert!(
        !inline.contains("forward_client_datagram_to_backend(&session, data).await"),
        "the shared receive loop must never await the backend send again"
    );
}

/// The fast path stays borrowed and ordered, and every fail-closed gate keeps
/// its place ahead of the amplification-budget publish and the send.
#[test]
fn the_nonblocking_admission_keeps_its_gates_and_its_borrowed_fast_path() {
    let admit = body_of("fn forward_client_datagram_without_blocking(")
        .split("\n}\n")
        .next()
        .expect("the admission body");

    let destination_at = admit
        .find("session.revalidate_destination()")
        .expect("the destination revalidation");
    let authorization_at = admit
        .find("session.refuse_if_authorization_expired().is_some()")
        .expect("the authorization gate");
    let fence_at = admit
        .find("session.egress_writer_engaged()")
        .expect("the FIFO fence");
    let publish_at = admit
        .find("publish_session_request_budget(")
        .expect("the amplification budget publish");
    let send_at = admit
        .find("socket.try_send(data)")
        .expect("the fast-path send");

    assert!(
        destination_at < authorization_at,
        "destination ownership is revalidated before anything else"
    );
    assert!(
        authorization_at < fence_at,
        "an expired credential is refused before any payload is queued or charged"
    );
    assert!(
        fence_at < publish_at,
        "the FIFO fence is consulted before the immediate path publishes or sends"
    );
    assert!(
        publish_at < send_at,
        "the response budget is published before the backend send"
    );
    assert!(
        !admit[..send_at].contains("Bytes::copy_from_slice"),
        "the immediate path must stay borrowed: nothing is copied before the send"
    );
    assert!(
        admit.contains("session.dtls_conn.is_some()"),
        "DTLS origination is routed to the per-session writer, never sent inline"
    );
}

/// A datagram that waited in the bounded queue is revalidated at the ACTUAL
/// commit, not only at the listener's first look.
#[test]
fn the_writer_revalidates_attribution_at_the_commit_after_queueing() {
    let writer = body_of("fn spawn_session_egress_writer<F, Fut>(")
        .split("\n}\n")
        .next()
        .expect("the writer body");

    let revalidate_at = writer
        .find("session.revalidate_destination().is_err()")
        .expect("the destination revalidation after dequeue");
    let source_at = writer
        .find("source.revalidate(source.ingress_ifindex, client_addr.ip())")
        .expect("the source re-authorization after dequeue");
    let commit_at = writer
        .find("forward_client_datagram_commit(")
        .expect("the authorization-aware commit");
    let account_at = writer.find("datagrams_out").expect("the send accounting");

    assert!(
        revalidate_at < commit_at,
        "destination ownership is rechecked at the commit, after queueing"
    );
    assert!(
        source_at < commit_at,
        "source attribution is rechecked at the commit, after queueing"
    );
    assert!(
        writer.contains("EgressRetainedGuard"),
        "the queued payload stays charged until its send settles"
    );
    assert!(
        account_at > commit_at,
        "a queued datagram is accounted only after its send settles"
    );
}

/// Every session teardown site already calls `close_hook_ingress`; routing the
/// writer's close through it is what makes the new worker exactly-once correct
/// at all of them.
#[test]
fn session_teardown_closes_the_backend_send_writer() {
    let close = body_of("fn close_hook_ingress(&self) {")
        .split("\n    }\n")
        .next()
        .expect("the close body");
    assert!(
        close.contains("self.close_egress_writer()"),
        "closing a session's client→backend workers must close both of them"
    );
    assert!(
        UDP_PROXY_SOURCE.contains("fn egress_writer_engaged(&self) -> bool {"),
        "the FIFO fence stays a session-level predicate"
    );
}

/// The writer's budgets are constants, not knobs, and both dimensions exist.
#[test]
fn the_writer_budgets_are_bounded_in_both_dimensions() {
    for constant in [
        "const SESSION_EGRESS_MAX_QUEUED_DATAGRAMS: usize = 64;",
        "const SESSION_EGRESS_MAX_QUEUED_BYTES: usize = 256 * 1024;",
        "const LISTENER_EGRESS_MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;",
    ] {
        assert!(
            UDP_PROXY_SOURCE.contains(constant),
            "the egress writer must keep its bound: {constant}"
        );
    }
    // Guards this file's mirrors against drifting away from the constants.
    assert_eq!(MAX_QUEUED_DATAGRAMS, 64);
    assert_eq!(MAX_QUEUED_BYTES, 256 * 1024);
}
