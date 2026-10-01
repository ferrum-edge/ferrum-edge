//! The post-EOS backend send-queue progress rule (issue #4411).
//!
//! `backend_write_timeout_ms` bounds transport write progress, including the
//! drain of the gateway's own send queue after the request body has reached a
//! clean end of stream. These tests pin the rule that decides "the backend is
//! not consuming this upload" without needing a socket or a real clock: the
//! sampler is fed depths and monotonic timestamps directly.

use ferrum_edge::_test_support::{
    SendQueueProbeVerdict, SendQueueProgressProbe, send_queue_sample_interval_ms,
};

const WRITE_TIMEOUT_MS: u64 = 800;

#[test]
fn an_empty_send_queue_is_drained_not_stalled() {
    let mut probe = SendQueueProgressProbe::new(0, WRITE_TIMEOUT_MS);
    // A body the peer's kernel accepted in full leaves nothing for a write
    // bound to enforce; the response-header wait belongs to
    // `backend_read_timeout_ms` from that point, which is the documented
    // residual of this mechanism.
    assert_eq!(probe.observe(0, 10_000), SendQueueProbeVerdict::Drained);
}

#[test]
fn a_strictly_decreasing_queue_is_progress_for_as_long_as_it_shrinks() {
    let mut probe = SendQueueProgressProbe::new(0, WRITE_TIMEOUT_MS);
    let mut depth = 2 * 1024 * 1024;
    let mut now = 0;
    // Far longer than the watermark in aggregate: a slow-but-draining upload
    // must never be terminated, however long it takes overall.
    for _ in 0..40 {
        now += 100;
        depth -= 16 * 1024;
        assert_eq!(
            probe.observe(depth, now),
            SendQueueProbeVerdict::Progressing,
            "a shrinking send queue is progress at depth={depth} now={now}"
        );
    }
}

#[test]
fn a_flat_non_empty_queue_stalls_exactly_at_the_write_timeout() {
    let mut probe = SendQueueProgressProbe::new(0, WRITE_TIMEOUT_MS);
    let depth = 1_900_000;
    // The first observation establishes the low-water mark and must NOT restart
    // the clock, or the watermark would always be charged one sampling interval
    // late.
    let mut now = 0;
    while now < WRITE_TIMEOUT_MS {
        now += 100;
        let verdict = probe.observe(depth, now);
        if now < WRITE_TIMEOUT_MS {
            assert_eq!(
                verdict,
                SendQueueProbeVerdict::Progressing,
                "must not fire before the watermark (now={now})"
            );
        } else {
            assert_eq!(
                verdict,
                SendQueueProbeVerdict::Stalled,
                "must fire at the watermark (now={now})"
            );
        }
    }
}

#[test]
fn an_oscillating_queue_that_never_falls_below_its_floor_is_a_stall() {
    // The whole point of stating the rule on *strictly decreasing* depth: a
    // connection whose send queue rises and falls back to the same value has
    // handed the peer nothing. Raising the floor on the way back down would
    // read that as progress and never terminate the request.
    let mut probe = SendQueueProgressProbe::new(0, WRITE_TIMEOUT_MS);
    let floor = 1_000_000;
    let mut now = 0;
    let mut verdicts = Vec::new();
    for step in 0..12 {
        now += 100;
        let depth = if step % 2 == 0 { floor } else { floor + 64_000 };
        verdicts.push(probe.observe(depth, now));
    }
    assert!(
        verdicts.contains(&SendQueueProbeVerdict::Stalled),
        "oscillation without a strict decrease must reach a stall: {verdicts:?}"
    );
    let first_stall = verdicts
        .iter()
        .position(|verdict| *verdict == SendQueueProbeVerdict::Stalled)
        .expect("a stall verdict");
    assert_eq!(
        (first_stall as u64 + 1) * 100,
        WRITE_TIMEOUT_MS,
        "the stall must land on the watermark, not earlier or later: {verdicts:?}"
    );
}

#[test]
fn one_strict_decrease_restarts_the_watermark() {
    let mut probe = SendQueueProgressProbe::new(0, WRITE_TIMEOUT_MS);
    assert_eq!(
        probe.observe(1_000_000, 100),
        SendQueueProbeVerdict::Progressing
    );
    assert_eq!(
        probe.observe(999_999, 700),
        SendQueueProbeVerdict::Progressing,
        "a strict decrease is progress however small"
    );
    // Without the restart this would have stalled at 800ms.
    assert_eq!(
        probe.observe(999_999, 800),
        SendQueueProbeVerdict::Progressing
    );
    assert_eq!(
        probe.observe(999_999, 1_500),
        SendQueueProbeVerdict::Stalled,
        "the watermark runs from the last strict decrease"
    );
}

#[test]
fn a_zero_write_timeout_never_stalls() {
    // `backend_write_timeout_ms = 0` is the operator opt-out and must stay one:
    // no pump is installed at all on that path, and the rule itself must not
    // manufacture a terminal if it ever is.
    let mut probe = SendQueueProgressProbe::new(0, 0);
    for step in 1..50 {
        assert_eq!(
            probe.observe(1_000_000, step * 1_000),
            SendQueueProbeVerdict::Progressing
        );
    }
}

#[test]
fn sampling_cadence_is_the_lesser_of_100ms_and_a_quarter_watermark() {
    assert_eq!(send_queue_sample_interval_ms(WRITE_TIMEOUT_MS), 100);
    assert_eq!(send_queue_sample_interval_ms(30_000), 100);
    // A short watermark samples proportionally, so a stall verdict is never
    // reached on a single reading.
    assert_eq!(send_queue_sample_interval_ms(200), 50);
    assert_eq!(send_queue_sample_interval_ms(40), 10);
    // Never zero: a 1ms watermark would otherwise spin.
    assert_eq!(send_queue_sample_interval_ms(1), 1);
    assert_eq!(send_queue_sample_interval_ms(0), 1);
}

/// The direct HTTP/1.1 pool's shared-stream handle (issue #5963) samples the
/// live socket, holds no descriptor of its own, and lets the socket close the
/// moment the transport drops its IO: the peer reads EOF at once instead of the
/// socket lingering in CLOSE_WAIT behind a duplicate.
#[tokio::test]
async fn a_shared_stream_handle_samples_without_holding_the_socket_open() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let client = tokio::net::TcpStream::connect(listener.local_addr().expect("addr"))
        .await
        .expect("connect");
    let (mut server, _) = listener.accept().await.expect("accept");
    let (mut io, handle) = ferrum_edge::_test_support::shared_tcp_stream_for_test(client);
    let handle = handle.expect("send-queue probe supported");

    // The IO works in both directions, vectored writes included.
    io.write_all(b"ping").await.expect("write");
    let bufs = [std::io::IoSlice::new(b"pi"), std::io::IoSlice::new(b"ng")];
    let written = io.write_vectored(&bufs).await.expect("vectored write");
    let mut buf = [0u8; 8];
    server
        .read_exact(&mut buf[..4 + written])
        .await
        .expect("server read");
    server.write_all(b"pong").await.expect("server write");
    let mut reply = [0u8; 4];
    io.read_exact(&mut reply).await.expect("read");
    assert_eq!(&reply, b"pong");
    assert!(handle.send_queue_bytes().is_some(), "live socket samples");

    drop(io);
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), server.read(&mut buf))
        .await
        .expect("peer must see the close promptly")
        .expect("read after close");
    assert_eq!(
        n, 0,
        "the socket closed with the IO: no duplicate keeps it open"
    );
    assert!(
        handle.send_queue_bytes().is_none(),
        "a dropped transport yields no sample"
    );
}
