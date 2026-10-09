//! Issue #6110 — the HTTP/3 transport proof that an exempted CORS preflight on
//! a gRPC-intended route carries no body. HTTP/3 may send DATA without
//! `Content-Length`, so the dispatcher requires the request stream to END with
//! no DATA frame, and it waits for that end at most
//! `min(backend_read_timeout_ms, H3_PREFLIGHT_END_OF_STREAM_WAIT_MS)` (the fixed
//! cap alone when the route's timeout is `0`). The wait runs before any plugin,
//! so a client that never sends FIN cannot park the stream for the route's
//! backend read timeout, or forever. Anything short of a clean end is no
//! exemption, and the preflight gets the ordinary `403`.

use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    H3_PREFLIGHT_END_OF_STREAM_WAIT_MS, h3_request_stream_ends_without_data_for_test,
};

type NextData = Result<Option<Bytes>, ()>;

const CAP: Duration = Duration::from_millis(H3_PREFLIGHT_END_OF_STREAM_WAIT_MS);

/// The request stream's next-DATA future: `next` after `delay`.
async fn next_data_after(delay: Duration, next: NextData) -> NextData {
    tokio::time::sleep(delay).await;
    next
}

/// Run the proof and return its verdict and how long the dispatcher waited.
/// `timeout_ms` is the route's `backend_read_timeout_ms`.
async fn prove(
    recv_data: impl std::future::Future<Output = NextData>,
    timeout_ms: u64,
) -> (bool, Duration) {
    let started = tokio::time::Instant::now();
    let exempt = h3_request_stream_ends_without_data_for_test(recv_data, timeout_ms).await;
    (exempt, started.elapsed())
}

/// The paused clock advances straight to the timer, so the wait is `bound`
/// (within the timer wheel's millisecond rounding), never the route timeout.
fn assert_waited(waited: Duration, bound: Duration) {
    assert!(
        waited >= bound && waited < bound + Duration::from_millis(5),
        "waited {waited:?}, expected {bound:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_ends_with_no_data_frame_is_exempt() {
    let (exempt, waited) = prove(next_data_after(Duration::ZERO, Ok(None)), 30_000).await;
    assert!(exempt);
    assert_eq!(waited, Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn a_preflight_sending_data_without_content_length_is_not_exempt() {
    let data = Ok(Some(Bytes::from_static(b"smuggled")));
    let (exempt, _) = prove(next_data_after(Duration::ZERO, data), 30_000).await;
    assert!(
        !exempt,
        "a DATA frame is a body, whatever the declared framing"
    );
}

#[tokio::test(start_paused = true)]
async fn an_empty_data_frame_is_not_exempt() {
    let empty = Ok(Some(Bytes::new()));
    let (exempt, _) = prove(next_data_after(Duration::ZERO, empty), 30_000).await;
    assert!(!exempt, "only the FIN proves an empty body");
}

#[tokio::test(start_paused = true)]
async fn a_stream_error_is_not_exempt() {
    let (exempt, _) = prove(next_data_after(Duration::ZERO, Err(())), 30_000).await;
    assert!(!exempt);
}

#[tokio::test(start_paused = true)]
async fn the_wait_is_capped_below_the_route_backend_read_timeout() {
    assert_eq!(H3_PREFLIGHT_END_OF_STREAM_WAIT_MS, 2_000);
    let (exempt, waited) = prove(std::future::pending(), 30_000).await;
    assert!(!exempt, "a stream with no FIN is not proof");
    // The default 30 s backend read timeout must not park a preflight.
    assert_waited(waited, CAP);
}

#[tokio::test(start_paused = true)]
async fn an_unbounded_route_timeout_still_gets_the_fixed_cap() {
    let (exempt, waited) = prove(std::future::pending(), 0).await;
    assert!(!exempt, "a stream with no FIN is not proof");
    // `backend_read_timeout_ms = 0` must not make the wait unbounded.
    assert_waited(waited, CAP);
}

#[tokio::test(start_paused = true)]
async fn a_shorter_route_timeout_shortens_the_wait() {
    let (exempt, waited) = prove(std::future::pending(), 500).await;
    assert!(!exempt);
    assert_waited(waited, Duration::from_millis(500));
}

#[tokio::test(start_paused = true)]
async fn a_fin_arriving_inside_the_cap_is_exempt() {
    let late_fin = next_data_after(CAP - Duration::from_millis(1), Ok(None));
    let (exempt, _) = prove(late_fin, 0).await;
    assert!(exempt);
}

#[tokio::test(start_paused = true)]
async fn data_arriving_after_the_cap_is_never_read() {
    let late_data = Ok(Some(Bytes::from_static(b"late")));
    let late_data = next_data_after(CAP + Duration::from_millis(1), late_data);
    let (exempt, waited) = prove(late_data, 0).await;
    assert!(!exempt);
    // The cap fires before the late frame arrives.
    assert_waited(waited, CAP);
}
