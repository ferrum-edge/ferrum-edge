//! `ScriptedUdpBackend` — a UDP server that executes a deterministic list
//! of [`UdpStep`]s against datagrams arriving on a pre-bound socket.
//!
//! The model mirrors [`super::tcp::ScriptedTcpBackend`] but at the datagram
//! level instead of the stream level:
//!
//! - **Per-datagram script.** Each incoming datagram triggers the next
//!   script cursor; `ExpectDatagram` asserts on the bytes, `Reply` /
//!   `ReplyN` sends datagrams back to the sender, `Silence` absorbs
//!   datagrams without replying for a fixed duration, `DropSocket`
//!   simulates the backend going away entirely (socket closed).
//!
//! - **Observability.** `received_datagrams()` exposes the full
//!   (src, bytes) log so tests can assert "gateway forwarded X to
//!   backend"; `packets_sent()` counts replies emitted (useful for
//!   amplification-bound tests).
//!
//! ## Determinism
//!
//! The script is interpreted sequentially against a single task that owns
//! the socket. `ExpectDatagram` waits up to a configurable deadline for a
//! datagram; on timeout the step is logged in `step_errors` and the task
//! exits.
//!
//! `ReplyN { count }` sends exactly `count` datagrams to the last observed
//! source address (typically captured by the prior `ExpectDatagram`). The
//! backend does NOT round-robin across multiple clients — amplification
//! tests should script a single client session.
//!
//! ## Caveats
//!
//! UDP is connectionless. Tests that care about "session count" observable
//! from the gateway should query the gateway's admin `/metrics` or log
//! output — the backend has no cross-datagram session concept.
//!
//! `Silence` absorbs datagrams (draining the socket) but does not reply;
//! set a duration longer than the gateway's `udp_idle_timeout_seconds` to
//! force session cleanup.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

/// Optional assertions on an incoming datagram. All provided fields must
/// match — unset fields are ignored. Designed for the same ergonomic shape
/// as [`super::http1::RequestMatcher`].
#[derive(Debug, Clone, Default)]
pub struct DatagramMatcher {
    /// Exact-equality check on the datagram bytes.
    pub payload_equals: Option<Vec<u8>>,
    /// Substring match on the datagram bytes.
    pub payload_contains: Option<Vec<u8>>,
    /// Exact datagram length in bytes.
    pub len_equals: Option<usize>,
    /// Minimum datagram length in bytes.
    pub min_len: Option<usize>,
    /// Maximum datagram length in bytes.
    pub max_len: Option<usize>,
}

impl DatagramMatcher {
    /// Accept any datagram.
    pub fn any() -> Self {
        Self::default()
    }

    /// Match datagrams whose bytes exactly equal `bytes`.
    pub fn exact(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            payload_equals: Some(bytes.into()),
            ..Self::default()
        }
    }

    /// Match datagrams that contain `needle` as a contiguous subsequence.
    pub fn contains(needle: impl Into<Vec<u8>>) -> Self {
        Self {
            payload_contains: Some(needle.into()),
            ..Self::default()
        }
    }

    /// Builder: add a length constraint.
    pub fn with_len(mut self, n: usize) -> Self {
        self.len_equals = Some(n);
        self
    }

    /// Check the matcher against an incoming payload. Returns `Ok(())` on
    /// match or a human-readable error string.
    pub fn check(&self, payload: &[u8]) -> Result<(), String> {
        if let Some(expected) = &self.payload_equals
            && expected.as_slice() != payload
        {
            return Err(format!(
                "payload mismatch: expected {} bytes, got {} bytes",
                expected.len(),
                payload.len()
            ));
        }
        if let Some(needle) = &self.payload_contains
            && !contains_subsequence(payload, needle)
        {
            return Err(format!(
                "payload does not contain {} bytes of expected subsequence",
                needle.len()
            ));
        }
        if let Some(n) = self.len_equals
            && payload.len() != n
        {
            return Err(format!(
                "length mismatch: expected {n}, got {}",
                payload.len()
            ));
        }
        if let Some(n) = self.min_len
            && payload.len() < n
        {
            return Err(format!(
                "length below floor: expected ≥ {n}, got {}",
                payload.len()
            ));
        }
        if let Some(n) = self.max_len
            && payload.len() > n
        {
            return Err(format!(
                "length above ceiling: expected ≤ {n}, got {}",
                payload.len()
            ));
        }
        Ok(())
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A single deterministic instruction in a UDP script.
#[derive(Debug, Clone)]
pub enum UdpStep {
    /// Wait for an incoming datagram (up to `deadline`, default 10 s), run
    /// the supplied matcher, and capture the source address for subsequent
    /// `Reply` / `ReplyN` steps.
    ///
    /// A failed match is recorded in `step_errors` and the task exits —
    /// further script steps do not run on that backend instance.
    ExpectDatagram(DatagramMatcher),
    /// Send `payload` to the most recently observed source address.
    /// No-op if no datagram has been observed yet (logs a step error).
    Reply(Vec<u8>),
    /// Send `payload` to the most recently observed source address,
    /// `count` times. Used for amplification-bound testing — the gateway's
    /// `udp_max_response_amplification_factor` should clamp how many of
    /// the replies reach the client.
    ReplyN { payload: Vec<u8>, count: usize },
    /// Drop (discard) every datagram received for `duration`. Useful for
    /// pushing the gateway past `udp_idle_timeout_seconds` to force
    /// session cleanup.
    Silence(Duration),
    /// Close the server socket entirely. Subsequent datagrams from the
    /// gateway will ICMP-error or just not reach any receiver. The task
    /// exits after dropping the socket.
    DropSocket,
}

/// Errors a UDP step can encounter. Preserved in `ScriptedUdpBackend`
/// state for post-mortem assertions.
#[derive(Debug)]
pub enum UdpStepError {
    Io(io::Error),
    /// `ExpectDatagram`'s deadline expired with no datagram received.
    Timeout,
    /// The matcher rejected the observed datagram.
    MatchFailed(String),
    /// Script contained an instruction that can't be executed (e.g.,
    /// `Reply` before any `ExpectDatagram`).
    InvalidScript(String),
}

impl std::fmt::Display for UdpStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpStepError::Io(e) => write!(f, "io error: {e}"),
            UdpStepError::Timeout => write!(f, "timeout: no datagram received"),
            UdpStepError::MatchFailed(m) => write!(f, "match failed: {m}"),
            UdpStepError::InvalidScript(m) => write!(f, "invalid script: {m}"),
        }
    }
}

impl std::error::Error for UdpStepError {}

impl From<io::Error> for UdpStepError {
    fn from(e: io::Error) -> Self {
        UdpStepError::Io(e)
    }
}

/// Per-datagram record: source address and payload bytes, in arrival
/// order.
#[derive(Debug, Clone)]
pub struct RecordedDatagram {
    pub src: SocketAddr,
    pub payload: Vec<u8>,
}

/// Fluent builder for [`ScriptedUdpBackend`].
pub struct ScriptedUdpBackendBuilder {
    socket: UdpSocket,
    steps: Vec<UdpStep>,
    default_expect_deadline: Duration,
}

impl ScriptedUdpBackendBuilder {
    /// Start a new builder against the given pre-bound UDP socket. Acquire
    /// one via [`super::super::ports::reserve_udp_port`] — Phase 4 introduced
    /// that helper alongside the existing TCP reservation.
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            steps: Vec::new(),
            default_expect_deadline: Duration::from_secs(10),
        }
    }

    /// Append a step.
    pub fn step(mut self, step: UdpStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Append multiple steps.
    pub fn steps(mut self, steps: impl IntoIterator<Item = UdpStep>) -> Self {
        self.steps.extend(steps);
        self
    }

    /// Override the default `ExpectDatagram` timeout (default 10 s).
    pub fn expect_deadline(mut self, d: Duration) -> Self {
        self.default_expect_deadline = d;
        self
    }

    /// Spawn the backend. Returns a handle whose `port` is the bound port.
    pub fn spawn(self) -> io::Result<ScriptedUdpBackend> {
        let port = self.socket.local_addr()?.port();
        let state = Arc::new(UdpBackendState::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let steps = self.steps;
        let default_deadline = self.default_expect_deadline;
        let socket = Arc::new(self.socket);

        let sock_task = socket.clone();
        let handle = tokio::spawn(async move {
            let state_err = state_task.clone();
            if let Err(e) = tokio::select! {
                biased;
                _ = &mut shutdown_rx => Ok(()),
                run = run_udp_script(sock_task, steps, state_task, default_deadline) => run,
            } {
                state_err.step_errors.lock().await.push(e.to_string());
            }
        });

        Ok(ScriptedUdpBackend {
            port,
            state,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

#[derive(Default)]
struct UdpBackendState {
    received_datagrams: Mutex<Vec<RecordedDatagram>>,
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    step_errors: Mutex<Vec<String>>,
    /// Holds the abort handle for the single script task so `Drop` can
    /// cut any in-flight `Silence`/`ExpectDatagram` wait cleanly.
    task_abort: StdMutex<Option<AbortHandle>>,
}

/// A running scripted UDP backend. Drop shuts it down.
pub struct ScriptedUdpBackend {
    /// The port the backend is listening on.
    pub port: u16,
    state: Arc<UdpBackendState>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ScriptedUdpBackend {
    /// Fluent builder given a pre-bound socket.
    pub fn builder(socket: UdpSocket) -> ScriptedUdpBackendBuilder {
        ScriptedUdpBackendBuilder::new(socket)
    }

    /// Snapshot of every datagram this backend has received, in arrival
    /// order.
    pub async fn received_datagrams(&self) -> Vec<RecordedDatagram> {
        self.state.received_datagrams.lock().await.clone()
    }

    /// Number of reply datagrams the backend has sent so far (via `Reply`
    /// or `ReplyN`).
    pub fn packets_sent(&self) -> u64 {
        self.state.packets_sent.load(Ordering::SeqCst)
    }

    /// Total bytes the backend has sent in replies so far.
    pub fn bytes_sent(&self) -> u64 {
        self.state.bytes_sent.load(Ordering::SeqCst)
    }

    /// Unique source addresses observed. Useful for asserting "gateway
    /// established one backend session".
    pub async fn unique_sources(&self) -> Vec<SocketAddr> {
        let dgrams = self.received_datagrams().await;
        let mut out = Vec::new();
        for d in dgrams {
            if !out.contains(&d.src) {
                out.push(d.src);
            }
        }
        out
    }

    /// Errors captured during script execution. Empty on the happy path.
    pub async fn step_errors(&self) -> Vec<String> {
        self.state.step_errors.lock().await.clone()
    }

    /// Panic with the captured errors if any script step failed.
    pub async fn assert_no_step_errors(&self) {
        let errs = self.step_errors().await;
        if !errs.is_empty() {
            panic!("{} UDP script step error(s): {:?}", errs.len(), errs);
        }
    }

    /// Signal shutdown; the script task exits on its next iteration.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        if let Ok(mut guard) = self.state.task_abort.lock()
            && let Some(a) = guard.take()
        {
            a.abort();
        }
    }
}

impl Drop for ScriptedUdpBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Execute a single script against the shared socket.
async fn run_udp_script(
    socket: Arc<UdpSocket>,
    script: Vec<UdpStep>,
    state: Arc<UdpBackendState>,
    default_deadline: Duration,
) -> Result<(), UdpStepError> {
    let mut last_src: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65535];

    for step in script {
        match step {
            UdpStep::ExpectDatagram(matcher) => {
                let (n, src) = match tokio::time::timeout(
                    default_deadline,
                    socket.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, src))) => (n, src),
                    Ok(Err(e)) => return Err(UdpStepError::Io(e)),
                    Err(_) => return Err(UdpStepError::Timeout),
                };
                let payload = buf[..n].to_vec();
                state
                    .received_datagrams
                    .lock()
                    .await
                    .push(RecordedDatagram {
                        src,
                        payload: payload.clone(),
                    });
                last_src = Some(src);
                if let Err(reason) = matcher.check(&payload) {
                    return Err(UdpStepError::MatchFailed(reason));
                }
            }
            UdpStep::Reply(bytes) => {
                let Some(target) = last_src else {
                    return Err(UdpStepError::InvalidScript(
                        "Reply with no previous ExpectDatagram to target".into(),
                    ));
                };
                socket.send_to(&bytes, target).await?;
                state.packets_sent.fetch_add(1, Ordering::SeqCst);
                state
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::SeqCst);
            }
            UdpStep::ReplyN { payload, count } => {
                let Some(target) = last_src else {
                    return Err(UdpStepError::InvalidScript(
                        "ReplyN with no previous ExpectDatagram to target".into(),
                    ));
                };
                for _ in 0..count {
                    socket.send_to(&payload, target).await?;
                    state.packets_sent.fetch_add(1, Ordering::SeqCst);
                    state
                        .bytes_sent
                        .fetch_add(payload.len() as u64, Ordering::SeqCst);
                }
            }
            UdpStep::Silence(d) => {
                // Keep draining the socket so the backend's kernel buffer
                // doesn't fill while we "silently ignore" — the gateway
                // under test is observing session idleness, not buffer
                // backpressure.
                let deadline = tokio::time::Instant::now() + d;
                loop {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline - now;
                    match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                        Ok(Ok((n, src))) => {
                            // Record the datagram so tests can still assert
                            // "backend saw N packets" even during silence.
                            state
                                .received_datagrams
                                .lock()
                                .await
                                .push(RecordedDatagram {
                                    src,
                                    payload: buf[..n].to_vec(),
                                });
                            last_src = Some(src);
                        }
                        Ok(Err(e)) => return Err(UdpStepError::Io(e)),
                        Err(_) => break, // deadline hit
                    }
                }
            }
            UdpStep::DropSocket => {
                // Drop our reference; the Arc is also held by the task
                // wrapper for send paths, but exiting the loop returns and
                // releases the final ref. Subsequent datagrams from the
                // gateway hit a dead address.
                drop(socket);
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_udp_port;

    #[tokio::test]
    async fn udp_expect_then_reply_round_trip() {
        let reservation = reserve_udp_port().await.expect("reserve udp");
        let port = reservation.port;
        let backend = ScriptedUdpBackend::builder(reservation.into_socket())
            .step(UdpStep::ExpectDatagram(DatagramMatcher::exact(
                b"hello".to_vec(),
            )))
            .step(UdpStep::Reply(b"pong".to_vec()))
            .spawn()
            .expect("spawn udp");

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        client
            .connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        client.send(b"hello").await.expect("send");

        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("recv in time")
            .expect("recv");
        assert_eq!(&buf[..n], b"pong");

        // Give the task a moment to post to received_datagrams.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let d = backend.received_datagrams().await;
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].payload, b"hello");
        assert_eq!(backend.packets_sent(), 1);
    }

    #[tokio::test]
    async fn udp_reply_n_emits_multiple_datagrams() {
        let reservation = reserve_udp_port().await.expect("reserve udp");
        let port = reservation.port;
        let backend = ScriptedUdpBackend::builder(reservation.into_socket())
            .step(UdpStep::ExpectDatagram(DatagramMatcher::any()))
            .step(UdpStep::ReplyN {
                payload: b"x".to_vec(),
                count: 5,
            })
            .spawn()
            .expect("spawn");

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client
            .connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        client.send(b"trigger").await.expect("send");

        let mut received = 0;
        let mut buf = [0u8; 8];
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    assert_eq!(&buf[..n], b"x");
                    received += 1;
                }
                _ => break,
            }
        }
        assert_eq!(received, 5);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(backend.packets_sent(), 5);
    }

    #[tokio::test]
    async fn udp_matcher_mismatch_recorded_in_step_errors() {
        let reservation = reserve_udp_port().await.expect("reserve udp");
        let port = reservation.port;
        let backend = ScriptedUdpBackend::builder(reservation.into_socket())
            .step(UdpStep::ExpectDatagram(DatagramMatcher::exact(
                b"expected".to_vec(),
            )))
            .spawn()
            .expect("spawn");

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client
            .connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        client.send(b"nope").await.expect("send");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let errs = backend.step_errors().await;
        assert!(
            errs.iter().any(|e| e.contains("match failed")),
            "expected match-failed error, got {errs:?}"
        );
    }

    #[tokio::test]
    async fn udp_silence_drains_datagrams_without_replying() {
        let reservation = reserve_udp_port().await.expect("reserve udp");
        let port = reservation.port;
        let backend = ScriptedUdpBackend::builder(reservation.into_socket())
            .step(UdpStep::Silence(Duration::from_millis(400)))
            .spawn()
            .expect("spawn");

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client
            .connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        client.send(b"one").await.expect("send");
        client.send(b"two").await.expect("send");
        tokio::time::sleep(Duration::from_millis(500)).await;

        // No replies were sent.
        assert_eq!(backend.packets_sent(), 0);
        // But the datagrams were observed.
        let d = backend.received_datagrams().await;
        assert!(d.len() >= 2, "expected ≥2 datagrams observed, got {d:?}");
    }

    #[tokio::test]
    async fn udp_reply_without_prior_expect_is_invalid_script() {
        let reservation = reserve_udp_port().await.expect("reserve udp");
        let backend = ScriptedUdpBackend::builder(reservation.into_socket())
            .step(UdpStep::Reply(b"bang".to_vec()))
            .spawn()
            .expect("spawn");
        // The script task runs immediately (no external trigger needed).
        tokio::time::sleep(Duration::from_millis(100)).await;
        let errs = backend.step_errors().await;
        assert!(
            errs.iter().any(|e| e.contains("invalid script")),
            "expected invalid-script error, got {errs:?}"
        );
    }
}
