//! Bounded task-group regressions and executor receipts for patch 007.
//! Duplex transports, positive barriers, and owned tasks keep the tests isolated.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::future::poll_fn;
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use tokio::sync::{mpsc, watch};

use super::H2ClientFuture;
use crate::common::io::Compat;
use crate::proto::h2::upgrade::UpgradedSendStreamTask;
use crate::rt::{Executor, Sleep, Timer};

type Frames = Result<Frame<Bytes>, io::Error>;
type Accepted = (
    http::Request<h2::RecvStream>,
    h2::server::SendResponse<Bytes>,
);
type ClientFuture = H2ClientFuture<TestBody, Compat<tokio::io::DuplexStream>, ProbeExecutor>;

enum TestBody {
    Eos,
    Full(http_body_util::Full<Bytes>),
    Ready(VecDeque<Frames>),
    Streaming(mpsc::Receiver<Frames>),
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Frames>> {
        match &mut *self {
            Self::Eos => Poll::Ready(None),
            Self::Full(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map_err(|never| match never {}))),
            Self::Ready(frames) => Poll::Ready(frames.pop_front()),
            Self::Streaming(rx) => rx.poll_recv(cx),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Eos => http_body::SizeHint::with_exact(0),
            Self::Full(body) => body.size_hint(),
            _ => http_body::SizeHint::default(),
        }
    }

    fn is_end_stream(&self) -> bool {
        // Ready deliberately reaches EOS through poll_frame, exercising the
        // eager-completion branch instead of the HEADERS END_STREAM branch.
        match self {
            Self::Eos => true,
            Self::Full(body) => body.is_end_stream(),
            _ => false,
        }
    }
}

#[derive(Clone)]
struct ProbeExecutor {
    observations: mpsc::UnboundedSender<Event>,
    head_gate: watch::Receiver<bool>,
}

#[derive(Debug, PartialEq)]
enum Event {
    Pipe,
    Head(usize),
    Finished(usize),
}

impl Executor<ClientFuture> for ProbeExecutor {
    fn execute(&self, future: ClientFuture) {
        let heads = match &future {
            H2ClientFuture::Pipe { .. } => {
                let _ = self.observations.send(Event::Pipe);
                0
            }
            H2ClientFuture::Send { .. } => 1,
            #[cfg(not(ferrum_h2_batch_control))]
            H2ClientFuture::Batch { send_batch } => send_batch.waiters.len(),
            H2ClientFuture::Task { .. } => 0,
        };
        let observations = self.observations.clone();
        let mut gate = self.head_gate.clone();
        if heads != 0 {
            let _ = observations.send(Event::Head(heads));
        }
        tokio::spawn(async move {
            if heads != 0 {
                while !*gate.borrow_and_update() {
                    gate.changed().await.unwrap();
                }
            }
            future.await;
            if heads != 0 {
                let _ = observations.send(Event::Finished(heads));
            }
        });
    }
}

impl Executor<UpgradedSendStreamTask<Bytes>> for ProbeExecutor {
    fn execute(&self, future: UpgradedSendStreamTask<Bytes>) {
        tokio::spawn(future);
    }
}

#[derive(Clone)]
struct TokioTimer;
struct TokioSleep(Pin<Box<tokio::time::Sleep>>);
impl Future for TokioSleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.as_mut().poll(cx)
    }
}
impl Sleep for TokioSleep {}
impl Timer for TokioTimer {
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep(Box::pin(tokio::time::sleep(duration))))
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep(Box::pin(tokio::time::sleep_until(
            deadline.into(),
        ))))
    }
}

// Test-only frame counting, without changing any h2 settings or frame bytes.
struct ObservedIo {
    io: tokio::io::DuplexStream,
    preface: bool,
    buffered: Vec<u8>,
    written: Vec<u8>,
    pings: Arc<AtomicUsize>,
    ping_seen: Arc<tokio::sync::Notify>,
    headers_sent: Arc<AtomicUsize>,
    headers_seen: Arc<tokio::sync::Notify>,
}
impl tokio::io::AsyncRead for ObservedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, buf);
        this.buffered.extend_from_slice(&buf.filled()[before..]);
        if !this.preface && this.buffered.len() >= 24 {
            this.buffered.drain(..24);
            this.preface = true;
        }
        if this.preface {
            while this.buffered.len() >= 9 {
                let length = ((this.buffered[0] as usize) << 16)
                    | ((this.buffered[1] as usize) << 8)
                    | this.buffered[2] as usize;
                if this.buffered.len() < 9 + length {
                    break;
                }
                if this.buffered[3] == 6 && this.buffered[4] & 1 == 0 {
                    this.pings.fetch_add(1, Ordering::Relaxed);
                    this.ping_seen.notify_one();
                }
                this.buffered.drain(..9 + length);
            }
        }
        result
    }
}
impl tokio::io::AsyncWrite for ObservedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.io).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            this.written.extend_from_slice(&bytes[..n]);
            while this.written.len() >= 9 {
                let length = ((this.written[0] as usize) << 16)
                    | ((this.written[1] as usize) << 8)
                    | this.written[2] as usize;
                if this.written.len() < 9 + length {
                    break;
                }
                if this.written[3] == 1 {
                    this.headers_sent.fetch_add(1, Ordering::Relaxed);
                    this.headers_seen.notify_one();
                }
                this.written.drain(..9 + length);
            }
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

struct Fixture {
    sender: crate::client::conn::http2::SendRequest<TestBody>,
    accepted: mpsc::UnboundedReceiver<Accepted>,
    observations: mpsc::UnboundedReceiver<Event>,
    server: tokio::task::JoinHandle<()>,
    client: tokio::task::JoinHandle<()>,
    head_gate: watch::Sender<bool>,
    server_ping: h2::PingPong,
    groups: Vec<usize>,
    observed: usize,
    started: usize,
    finished: usize,
    pings: Arc<AtomicUsize>,
    ping_seen: Arc<tokio::sync::Notify>,
    headers_sent: Arc<AtomicUsize>,
    headers_seen: Arc<tokio::sync::Notify>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        self.client.abort();
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("operation completed within its bound")
}

impl Fixture {
    async fn new() -> Self {
        Self::with_keepalive(false).await
    }

    async fn with_keepalive(keepalive: bool) -> Self {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let pings = Arc::new(AtomicUsize::new(0));
        let ping_seen = Arc::new(tokio::sync::Notify::new());
        let headers_sent = Arc::new(AtomicUsize::new(0));
        let headers_seen = Arc::new(tokio::sync::Notify::new());
        let server_io = ObservedIo {
            io: server_io,
            preface: false,
            buffered: Vec::new(),
            written: Vec::new(),
            pings: pings.clone(),
            ping_seen: ping_seen.clone(),
            headers_sent: headers_sent.clone(),
            headers_seen: headers_seen.clone(),
        };
        let (accepted_tx, accepted) = mpsc::unbounded_channel();
        let (ping_tx, ping_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            ping_tx.send(conn.ping_pong().unwrap()).unwrap();
            while let Some(request) = conn.accept().await {
                if accepted_tx.send(request.unwrap()).is_err() {
                    break;
                }
            }
        });
        let (observations_tx, observations) = mpsc::unbounded_channel();
        let (head_gate, gate_rx) = watch::channel(true);
        let executor = ProbeExecutor {
            observations: observations_tx,
            head_gate: gate_rx,
        };
        let mut builder = crate::client::conn::http2::Builder::new(executor);
        if keepalive {
            builder
                .timer(TokioTimer)
                .keep_alive_interval(Duration::from_secs(1))
                .keep_alive_timeout(Duration::from_secs(10))
                .keep_alive_while_idle(false);
        }
        let (sender, conn) = builder.handshake(Compat::new(client_io)).await.unwrap();
        let client = tokio::spawn(async move {
            let _ = conn.await;
        });
        Self {
            sender,
            accepted,
            observations,
            server,
            client,
            head_gate,
            server_ping: bounded(ping_rx).await.unwrap(),
            groups: Vec::new(),
            observed: 0,
            started: 0,
            finished: 0,
            pings,
            ping_seen,
            headers_sent,
            headers_seen,
        }
    }

    async fn accept(&mut self) -> Accepted {
        bounded(self.accepted.recv())
            .await
            .expect("server received request")
    }

    async fn observation(&mut self) {
        match bounded(self.observations.recv()).await.unwrap() {
            Event::Head(n) => {
                assert!((1..=8).contains(&n));
                self.groups.push(n);
                self.started += n;
            }
            Event::Finished(n) => self.finished += n,
            Event::Pipe => (),
        }
    }

    async fn head(&mut self, _pending_upload: bool) {
        self.observed += 1;
        while self.started < self.observed {
            self.observation().await;
        }
    }

    async fn finished(&mut self, count: usize) {
        while self.finished < count {
            self.observation().await;
        }
    }

    async fn headers_written(&self, count: usize) {
        bounded(async {
            while self.headers_sent.load(Ordering::Relaxed) < count {
                self.headers_seen.notified().await;
            }
        })
        .await;
    }

    async fn wire_barrier(&mut self) {
        bounded(self.server_ping.ping(h2::Ping::opaque()))
            .await
            .unwrap();
    }
}

fn request(body: TestBody) -> http::Request<TestBody> {
    http::Request::post("http://test/upload")
        .body(body)
        .unwrap()
}

fn upload() -> (mpsc::Sender<Frames>, TestBody) {
    let (tx, rx) = mpsc::channel(2);
    (tx, TestBody::Streaming(rx))
}

async fn read_upload(mut body: h2::RecvStream) -> (Vec<u8>, Option<http::HeaderMap>) {
    let mut bytes = Vec::new();
    while let Some(chunk) = bounded(body.data()).await {
        let chunk = chunk.unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        bytes.extend_from_slice(&chunk);
    }
    (bytes, bounded(body.trailers()).await.unwrap())
}

#[tokio::test]
async fn eos_and_eager_uploads_preserve_trailers() {
    let mut fixture = Fixture::new().await;
    let mut trailers = http::HeaderMap::new();
    trailers.insert("upload-check", "complete".parse().unwrap());
    let cases = [
        (TestBody::Eos, Vec::new(), None),
        (TestBody::Ready(VecDeque::new()), Vec::new(), None),
        (
            TestBody::Ready(VecDeque::from([
                Ok(Frame::data(Bytes::from_static(b"payload"))),
                Ok(Frame::trailers(trailers.clone())),
            ])),
            b"payload".to_vec(),
            Some(trailers.clone()),
        ),
    ];
    for (body, expected, expected_trailers) in cases {
        let response = fixture.sender.send_request(request(body));
        fixture.head(false).await;
        let (req, mut respond) = fixture.accept().await;
        assert_eq!(
            read_upload(req.into_body()).await,
            (expected, expected_trailers)
        );
        let mut stream = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        stream
            .send_data(Bytes::from_static(b"reply"), false)
            .unwrap();
        stream.send_trailers(trailers.clone()).unwrap();
        let collected = bounded(response)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(collected.trailers(), Some(&trailers));
        assert_eq!(collected.to_bytes(), "reply");
    }
}

#[tokio::test]
async fn eager_body_error_still_fails_request() {
    let mut fixture = Fixture::new().await;
    let response = fixture
        .sender
        .send_request(request(TestBody::Ready(VecDeque::from([Err(
            io::Error::new(io::ErrorKind::Other, "synthetic upload failure"),
        )]))));
    fixture.head(false).await;
    assert!(bounded(response).await.is_err());
}

#[tokio::test]
async fn connect_still_upgrades() {
    let mut fixture = Fixture::new().await;
    let response = fixture.sender.send_request(
        http::Request::connect("test:443")
            .body(TestBody::Eos)
            .unwrap(),
    );
    let sibling = fixture.sender.send_request(request(TestBody::Eos));
    fixture.head(false).await;
    let (_req, mut respond) = fixture.accept().await;
    let (_sibling_req, mut sibling_reply) = fixture.accept().await;
    let mut stream = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    stream
        .send_data(Bytes::from_static(b"tunnel"), true)
        .unwrap();
    let mut response = bounded(response).await.unwrap();
    let upgraded = bounded(crate::upgrade::on(&mut response)).await.unwrap();
    let mut io = Compat::new(upgraded);
    let mut bytes = Vec::new();
    bounded(tokio::io::AsyncReadExt::read_to_end(&mut io, &mut bytes))
        .await
        .unwrap();
    assert_eq!(bytes, b"tunnel");
    sibling_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    assert!(bounded(sibling).await.is_ok());
}

#[tokio::test]
async fn cancelling_head_wait_resets_eos_and_suspended_upload_streams() {
    let mut fixture = Fixture::new().await;
    for pending_upload in [false, true] {
        let (upload_tx, body) = upload();
        let response =
            fixture
                .sender
                .send_request(request(if pending_upload { body } else { TestBody::Eos }));
        fixture.head(pending_upload).await;
        let (_req, mut respond) = fixture.accept().await;
        drop(response);
        assert_eq!(
            bounded(poll_fn(|cx| respond.poll_reset(cx))).await.unwrap(),
            h2::Reason::CANCEL
        );
        if pending_upload {
            bounded(upload_tx.closed()).await;
        }
    }
    let response = fixture.sender.send_request(request(TestBody::Eos));
    fixture.head(false).await;
    let (_req, mut respond) = fixture.accept().await;
    respond
        .send_response(http::Response::new(()), true)
        .unwrap();
    assert_eq!(
        bounded(response).await.unwrap().status(),
        http::StatusCode::OK
    );
}

#[tokio::test]
async fn early_response_does_not_cancel_a_suspended_upload() {
    let mut fixture = Fixture::new().await;
    let (upload_tx, body) = upload();
    let response = fixture.sender.send_request(request(body));
    fixture.head(true).await;
    let (req, mut respond) = fixture.accept().await;
    respond
        .send_response(http::Response::new(()), true)
        .unwrap();
    let response = bounded(response).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut trailers = http::HeaderMap::new();
    trailers.insert("upload-check", "after-head".parse().unwrap());
    upload_tx
        .send(Ok(Frame::data(Bytes::from_static(b"after response"))))
        .await
        .unwrap();
    upload_tx
        .send(Ok(Frame::trailers(trailers.clone())))
        .await
        .unwrap();
    drop(upload_tx);
    assert_eq!(
        read_upload(req.into_body()).await,
        (b"after response".to_vec(), Some(trailers))
    );
}

#[tokio::test]
async fn pending_upload_and_many_head_waits_do_not_block_ready_responses() {
    const COUNT: usize = 64;
    let mut fixture = Fixture::new().await;
    let (upload_tx, body) = upload();
    let stalled = fixture.sender.send_request(request(body));
    fixture.head(true).await;
    let (_stalled_req, mut stalled_respond) = fixture.accept().await;
    let mut responses = Vec::new();
    for _ in 0..COUNT {
        responses.push(fixture.sender.send_request(request(TestBody::Eos)));
    }
    let mut held = Vec::new();
    for _ in 0..COUNT {
        fixture.head(false).await;
        held.push(fixture.accept().await);
    }
    // All heads remain pending together, then complete in reverse order while
    // the first upload is still suspended. No sleep or throughput threshold.
    for (_, mut respond) in held.into_iter().rev() {
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
    }
    for response in responses {
        assert!(bounded(response).await.is_ok());
    }
    assert!(!upload_tx.is_closed());
    drop(stalled);
    assert_eq!(
        bounded(poll_fn(|cx| stalled_respond.poll_reset(cx)))
            .await
            .unwrap(),
        h2::Reason::CANCEL
    );
    bounded(upload_tx.closed()).await;
}

#[tokio::test]
async fn connection_loss_fails_all_waiters_and_releases_the_upload() {
    let mut fixture = Fixture::new().await;
    let (upload_tx, body) = upload();
    let streaming = fixture.sender.send_request(request(body));
    let empty = fixture.sender.send_request(request(TestBody::Eos));
    fixture.head(true).await;
    let _streaming_request = fixture.accept().await;
    fixture.head(false).await;
    let _empty_request = fixture.accept().await;
    fixture.server.abort();
    assert!(bounded(&mut fixture.server)
        .await
        .unwrap_err()
        .is_cancelled());
    assert!(bounded(streaming).await.is_err());
    assert!(bounded(empty).await.is_err());
    bounded(upload_tx.closed()).await;
}

#[tokio::test]
async fn singleton_buffered_1k_posts_keep_one_head_task() {
    let mut fixture = Fixture::new().await;
    for _ in 0..32 {
        let payload = Bytes::from(vec![b'x'; 1024]);
        let response =
            fixture
                .sender
                .send_request(request(TestBody::Full(http_body_util::Full::new(
                    payload.clone(),
                ))));
        fixture.head(false).await;
        let (req, mut respond) = fixture.accept().await;
        assert_eq!(read_upload(req.into_body()).await, (payload.to_vec(), None));
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
        assert!(bounded(response).await.is_ok());
    }
    assert_eq!(fixture.groups, vec![1; 32]);
    eprintln!("controlled singleton receipt: requests=32 head_tasks=32 groups_of_one=32");
}

#[tokio::test]
async fn backend_reset_releases_pending_upload_and_preserves_sibling() {
    let mut fixture = Fixture::new().await;
    let (upload_tx, body) = upload();
    let response = fixture.sender.send_request(request(body));
    let sibling = fixture.sender.send_request(request(TestBody::Eos));
    fixture.head(true).await;
    let (_req, mut respond) = fixture.accept().await;
    fixture.head(false).await;
    let (_sibling_req, mut sibling_respond) = fixture.accept().await;
    respond.send_reset(h2::Reason::REFUSED_STREAM);
    assert!(bounded(response).await.is_err());
    bounded(upload_tx.closed()).await;
    sibling_respond
        .send_response(http::Response::new(()), true)
        .unwrap();
    assert!(bounded(sibling).await.is_ok());
}

#[tokio::test]
async fn queued_seventeen_heads_flush_as_eight_eight_one_without_waiting() {
    let mut fixture = Fixture::new().await;
    let responses = (0..17)
        .map(|_| fixture.sender.send_request(request(TestBody::Eos)))
        .collect::<Vec<_>>();
    let mut held = Vec::new();
    for _ in 0..17 {
        fixture.head(false).await;
        held.push(fixture.accept().await);
    }
    let expected = if cfg!(ferrum_h2_batch_control) {
        vec![1; 17]
    } else {
        vec![8, 8, 1]
    };
    assert_eq!(fixture.groups, expected);
    eprintln!(
        "controlled queued receipt: requests=17 head_tasks={} groups={:?}",
        fixture.groups.len(),
        fixture.groups
    );
    for (_, mut respond) in held {
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
    }
    for response in responses {
        assert!(bounded(response).await.is_ok());
    }
}

#[tokio::test]
async fn parked_early_success_keeps_upload_alive_while_slow_sibling_waits() {
    let mut fixture = Fixture::new().await;
    let slow = fixture.sender.send_request(request(TestBody::Eos));
    let (upload_tx, body) = upload();
    let parked = fixture.sender.send_request(request(body));
    let fast = fixture.sender.send_request(request(TestBody::Eos));
    let (_slow_req, mut slow_reply) = fixture.accept().await;
    let (upload_req, mut early_reply) = fixture.accept().await;
    let (_fast_req, mut fast_reply) = fixture.accept().await;
    early_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    fast_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    assert!(bounded(fast).await.is_ok());
    // A complete child must be dropped even while its group has a slow sibling.
    // The requester never polls parked, including while its successful head arrives.
    drop(parked);
    upload_tx
        .send(Ok(Frame::data(Bytes::from_static(b"after parked head"))))
        .await
        .unwrap();
    drop(upload_tx);
    assert_eq!(
        read_upload(upload_req.into_body()).await.0,
        b"after parked head"
    );
    drop(slow);
    assert_eq!(
        bounded(poll_fn(|cx| slow_reply.poll_reset(cx)))
            .await
            .unwrap(),
        h2::Reason::CANCEL
    );
}

#[tokio::test]
async fn ready_head_precedes_already_canceled_callback_and_keeps_upload() {
    let mut fixture = Fixture::new().await;
    fixture.head_gate.send(false).unwrap();
    let (upload_tx, body) = upload();
    let parked = fixture.sender.send_request(request(body));
    let sibling = fixture.sender.send_request(request(TestBody::Eos));
    let (upload_req, mut early_reply) = fixture.accept().await;
    let (_sibling_req, mut sibling_reply) = fixture.accept().await;
    early_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    sibling_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    fixture.headers_written(2).await;
    // PING is queued after observed HEADERS writes. Its ACK proves the independently driven
    // h2 connection received the successful head before the waiters are unparked.
    fixture.wire_barrier().await;
    drop(parked);
    fixture.head_gate.send(true).unwrap();
    assert!(bounded(sibling).await.is_ok());
    fixture.finished(2).await;
    upload_tx
        .send(Ok(Frame::data(Bytes::from_static(b"success wins"))))
        .await
        .unwrap();
    drop(upload_tx);
    assert_eq!(read_upload(upload_req.into_body()).await.0, b"success wins");
}

#[tokio::test]
async fn canceled_child_releases_upload_before_pending_sibling_finishes() {
    let mut fixture = Fixture::new().await;
    let (upload_tx, body) = upload();
    let canceled = fixture.sender.send_request(request(body));
    let sibling = fixture.sender.send_request(request(TestBody::Eos));
    let (_req, mut reply) = fixture.accept().await;
    let (_sibling_req, mut sibling_reply) = fixture.accept().await;
    drop(canceled);
    assert_eq!(
        bounded(poll_fn(|cx| reply.poll_reset(cx))).await.unwrap(),
        h2::Reason::CANCEL
    );
    bounded(upload_tx.closed()).await;
    sibling_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    assert!(bounded(sibling).await.is_ok());
}

#[tokio::test]
async fn dispatch_shutdown_flushes_partial_group_before_returning() {
    let mut fixture = Fixture::new().await;
    let other = Fixture::new().await;
    let mut sender = std::mem::replace(&mut fixture.sender, other.sender.clone());
    let first = sender.send_request(request(TestBody::Eos));
    let second = sender.send_request(request(TestBody::Eos));
    drop(sender);
    // The dispatcher returns Shutdown after consuming its closed queue, but
    // both accepted heads must already have autonomous owners when it returns.
    bounded(&mut fixture.client).await.unwrap();
    fixture.head(false).await;
    fixture.head(false).await;
    assert_eq!(
        fixture.groups,
        if cfg!(ferrum_h2_batch_control) {
            vec![1, 1]
        } else {
            vec![2]
        }
    );
    for _ in 0..2 {
        let (_req, mut reply) = fixture.accept().await;
        reply.send_response(http::Response::new(()), true).unwrap();
    }
    assert!(bounded(first).await.is_ok());
    assert!(bounded(second).await.is_ok());
}

#[tokio::test]
async fn unaccepted_request_retains_retry_ownership_after_dispatch_drop() {
    let mut fixture = Fixture::new().await;
    let response =
        fixture
            .sender
            .try_send_request(request(TestBody::Full(http_body_util::Full::new(
                Bytes::from_static(b"unsent"),
            ))));
    fixture.client.abort();
    assert!(bounded(&mut fixture.client)
        .await
        .unwrap_err()
        .is_cancelled());
    let mut error = bounded(response).await.unwrap_err();
    assert!(error.take_message().is_some());
}

#[tokio::test(start_paused = true)]
async fn parked_success_releases_keepalive_activity_while_pending_heads_ping() {
    let mut fixture = Fixture::with_keepalive(true).await;
    let first = fixture.sender.send_request(request(TestBody::Eos));
    let second = fixture.sender.send_request(request(TestBody::Eos));
    let (_first_req, mut first_reply) = fixture.accept().await;
    let (_second_req, mut second_reply) = fixture.accept().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    bounded(async {
        while fixture.pings.load(Ordering::Relaxed) == 0 {
            fixture.ping_seen.notified().await;
        }
    })
    .await;
    fixture.wire_barrier().await;
    first_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    second_reply
        .send_response(http::Response::new(()), true)
        .unwrap();
    fixture.finished(2).await;
    fixture.wire_barrier().await;
    let before = fixture.pings.load(Ordering::Relaxed);
    // Neither requester was polled. Successful EOS mapping still made the
    // connection idle, so while_idle=false suppresses further keepalive PINGs.
    tokio::time::advance(Duration::from_secs(3)).await;
    fixture.wire_barrier().await;
    assert_eq!(fixture.pings.load(Ordering::Relaxed), before);
    assert!(bounded(first).await.is_ok());
    assert!(bounded(second).await.is_ok());
}
