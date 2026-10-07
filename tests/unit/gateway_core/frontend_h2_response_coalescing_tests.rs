//! Frontend HTTP/2 response coalescing (issues #6033, #6038).
//!
//! Hyper patch 005 makes an HTTP/2 response body pipe hold capacity below a
//! useful DATA frame for a bounded wait, so a client that opens its window a
//! few bytes at a time does not receive one tiny DATA frame per increment.
//! The wait needs a timer, so the frontend HTTP/2 builders in both
//! `handle_connection` (h2c) and `handle_tls_connection` (ALPN `h2`) set one.
//! These tests drive the production accept loop with a raw-frame client that
//! controls every connection-level WINDOW_UPDATE.
//!
//! The paused-clock regressions in the vendored hyper crate pin exact frame
//! sizes. Here the clock is real, so the proof is a lower bound that does not
//! depend on machine speed: while the client opens its window in lockstep (32
//! bytes, then wait for them), capacity never reaches a useful frame, so a
//! pipe with a timer holds each increment for the whole bounded wait. Without
//! the frontend timer it sends each increment at once.

use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::frontend_h2_admission_tests::{
    H2_PREFACE, ProxyHarness, frontend_tls_pair, h2_frame, tls_connect,
};

const HEADER_READ_TIMEOUT_SECONDS: u64 = 30;

const H2_DATA: u8 = 0x0;
const H2_HEADERS: u8 = 0x1;
const H2_RST_STREAM: u8 = 0x3;
const H2_SETTINGS: u8 = 0x4;
const H2_PING: u8 = 0x6;
const H2_GOAWAY: u8 = 0x7;
const H2_WINDOW_UPDATE: u8 = 0x8;
const H2_END_STREAM: u8 = 0x1;
const H2_ACK: u8 = 0x1;
const H2_END_HEADERS: u8 = 0x4;

/// Every connection starts with this much connection window; SETTINGS cannot
/// change it.
const INITIAL_CONNECTION_WINDOW: usize = 65_535;
/// h2's `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`, the minimum a pipe with a
/// timer coalesces to.
const SMALL_DATA_FRAME: usize = 256;
/// Hyper patch 005's `MAX_COALESCE_WAIT`.
const COALESCE_WAIT: Duration = Duration::from_millis(2);
const INCREMENT: u32 = 32;
const TRICKLE_GRANTS: usize = 128;
const LOCKSTEP_ROUNDS: usize = 8;
const AFTER_TRICKLE: usize = INITIAL_CONNECTION_WINDOW + TRICKLE_GRANTS * INCREMENT as usize;
const BODY_LEN: usize = AFTER_TRICKLE + LOCKSTEP_ROUNDS * INCREMENT as usize;

/// HTTP/1.1 backend that answers every request with `BODY_LEN` bytes.
async fn start_large_body_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind large-body backend");
    let port = listener.local_addr().expect("backend addr").port();
    let body = Bytes::from(vec![b'x'; BODY_LEN]);
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let body = body.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let body = body.clone();
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/octet-stream")
                                .body(Full::new(body))
                                .expect("backend response"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (port, handle)
}

/// HPACK block for `GET {scheme}://localhost/slow`: indexed `:method GET`,
/// indexed `:scheme`, then `:path` and `:authority` as literals without
/// indexing on their static-table names.
fn request_header_block(tls: bool) -> Vec<u8> {
    let mut block = vec![0x82, if tls { 0x87 } else { 0x86 }];
    for (name_index, value) in [(0x04_u8, "/slow"), (0x01, "localhost")] {
        block.push(name_index);
        block.push(value.len() as u8);
        block.extend_from_slice(value.as_bytes());
    }
    block
}

/// Raw HTTP/2 client that sends every connection WINDOW_UPDATE itself and
/// records the length and END_STREAM flag of each response DATA frame.
struct WindowTricklingClient<S> {
    io: S,
    frames: Vec<(usize, bool)>,
    received: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WindowTricklingClient<S> {
    /// Sends the preface, SETTINGS_INITIAL_WINDOW_SIZE = 1 MiB (only the
    /// connection window ever limits the response) and the request.
    async fn open(mut io: S, tls: bool) -> Self {
        let mut opening = H2_PREFACE.to_vec();
        opening.extend(h2_frame(H2_SETTINGS, 0, 0, &[0, 4, 0, 0x10, 0, 0]));
        let flags = H2_END_HEADERS | H2_END_STREAM;
        opening.extend(h2_frame(H2_HEADERS, flags, 1, &request_header_block(tls)));
        io.write_all(&opening).await.expect("write request");
        io.flush().await.expect("flush request");
        Self {
            io,
            frames: Vec::new(),
            received: 0,
        }
    }

    async fn write(&mut self, frame: &[u8]) {
        self.io.write_all(frame).await.expect("write frame");
        self.io.flush().await.expect("flush frame");
    }

    /// Reads frames until `total` response body bytes have arrived.
    async fn read_body_until(&mut self, total: usize) {
        while self.received < total {
            let mut head = [0_u8; 9];
            self.io.read_exact(&mut head).await.expect("frame header");
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let mut payload = vec![0_u8; len];
            self.io
                .read_exact(&mut payload)
                .await
                .expect("frame payload");
            match (head[3], head[4]) {
                (H2_DATA, flags) => {
                    self.received += len;
                    self.frames.push((len, flags & H2_END_STREAM != 0));
                }
                (H2_SETTINGS, flags) if flags & H2_ACK == 0 => {
                    self.write(&h2_frame(H2_SETTINGS, H2_ACK, 0, &[])).await;
                }
                (H2_PING, flags) if flags & H2_ACK == 0 => {
                    self.write(&h2_frame(H2_PING, H2_ACK, 0, &payload)).await;
                }
                (H2_RST_STREAM | H2_GOAWAY, _) => {
                    panic!("the response failed: frame type {} {payload:?}", head[3]);
                }
                _ => {}
            }
        }
    }

    /// Opens the connection window by `INCREMENT` bytes.
    async fn grant(&mut self) {
        let increment = INCREMENT.to_be_bytes();
        self.write(&h2_frame(H2_WINDOW_UPDATE, 0, 0, &increment))
            .await;
    }
}

async fn assert_response_coalesces<S>(io: S, tls: bool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = WindowTricklingClient::open(io, tls).await;
    let run = async {
        client.read_body_until(INITIAL_CONNECTION_WINDOW).await;
        let initial = client.frames.len();
        // Increments that do not wait for the bytes they allow.
        for _ in 0..TRICKLE_GRANTS {
            client.grant().await;
        }
        client.read_body_until(AFTER_TRICKLE).await;
        let trickle_frames = client.frames.split_off(initial);
        // Lockstep increments: each opens the window only after the bytes it
        // allowed arrived, so capacity never reaches a useful frame.
        let mut waits = Vec::with_capacity(LOCKSTEP_ROUNDS);
        for _ in 0..LOCKSTEP_ROUNDS {
            let started = Instant::now();
            let target = client.received + INCREMENT as usize;
            client.grant().await;
            client.read_body_until(target).await;
            waits.push(started.elapsed());
        }
        (trickle_frames, waits)
    };
    let (trickle_frames, waits) = tokio::time::timeout(Duration::from_secs(20), run)
        .await
        .expect("the response completes");
    assert_eq!(client.received, BODY_LEN);

    let trickled: usize = trickle_frames.iter().map(|(len, _)| len).sum();
    assert_eq!(trickled, TRICKLE_GRANTS * INCREMENT as usize);
    // Increments that arrive together leave as one frame with or without a
    // timer, and a scheduling stall longer than the bounded wait legitimately
    // ends a hold, so the count of small frames here depends on the runner.
    // Without coalescing nearly every spread-out increment is its own frame;
    // fewer than half shows the increments coalesce.
    let small = trickle_frames
        .iter()
        .filter(|(len, end_stream)| !end_stream && *len < SMALL_DATA_FRAME)
        .count();
    assert!(
        small < TRICKLE_GRANTS / 2,
        "{small} of {} DATA frames cut from window increments were under \
         {SMALL_DATA_FRAME} bytes: {trickle_frames:?}",
        trickle_frames.len()
    );

    // The proof that the frontend sets a timer. A hold ends only at its
    // deadline, so a held round takes at least the bounded wait however fast
    // the runner is. The last round is not held: its 32 bytes end the body.
    // Neither is a round whose bytes end a body chunk exactly; the pipe
    // never waits for the next chunk. Body chunks are far larger than the
    // 256 bytes these rounds cover, so most rounds must hold.
    let held = waits[..LOCKSTEP_ROUNDS - 1]
        .iter()
        .filter(|wait| **wait >= COALESCE_WAIT)
        .count();
    assert!(
        held >= (LOCKSTEP_ROUNDS - 1) / 2,
        "a 32-byte window must be held for the bounded wait before it is \
         sent; round times: {waits:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_response_coalesces_small_connection_window_increments() {
    let (backend_port, backend) = start_large_body_backend().await;
    let harness = ProxyHarness::start(HEADER_READ_TIMEOUT_SECONDS, None, backend_port).await;

    let stream = harness.connect().await;
    stream.set_nodelay(true).expect("TCP_NODELAY");
    assert_response_coalesces(stream, false).await;

    harness.shutdown().await;
    backend.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_h2_response_coalesces_small_connection_window_increments() {
    let (backend_port, backend) = start_large_body_backend().await;
    let (tls, ca_pem) = frontend_tls_pair();
    let harness = ProxyHarness::start(HEADER_READ_TIMEOUT_SECONDS, Some(tls), backend_port).await;

    let stream = tls_connect(harness.addr, &ca_pem, b"h2").await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "frontend HTTPS must negotiate HTTP/2 via ALPN"
    );
    stream.get_ref().0.set_nodelay(true).expect("TCP_NODELAY");
    assert_response_coalesces(stream, true).await;

    harness.shutdown().await;
    backend.abort();
}

/// Hyper patch 005 reads h2 patch 003's inherent
/// `SendStream::capacity_and_assigned` through a trait whose fallback compiles
/// against stock h2 and silently splits every chunk the send buffer caps
/// (#6055). Binding the exact vendored signature here makes dropping, renaming
/// or re-receivering that accessor fail the gateway's own test build instead of
/// quietly reintroducing the large-payload regression.
#[test]
fn vendored_h2_exposes_the_send_capacity_accessor_hyper_patch_005_reads() {
    let accessor: fn(&h2::SendStream<Bytes>) -> (usize, usize) =
        h2::SendStream::<Bytes>::capacity_and_assigned;
    let _ = accessor;
}
