use std::error::Error as StdError;
use std::future::Future;
use std::io::{Cursor, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_core::ready;
use h2::SendStream;
use http::header::{HeaderName, CONNECTION, TE, TRANSFER_ENCODING, UPGRADE};
use http::HeaderMap;
use pin_project_lite::pin_project;

use crate::body::Body;
use crate::common::time::Time;

pub(crate) mod ping;
pub(crate) mod upgrade;

cfg_client! {
    pub(crate) mod client;
    pub(crate) use self::client::ClientTask;
}

cfg_server! {
    pub(crate) mod server;
    pub(crate) use self::server::Server;
}

/// Default initial stream window size defined in HTTP2 spec.
pub(crate) const SPEC_WINDOW_SIZE: u32 = 65_535;

// List of connection headers from RFC 9110 Section 7.6.1
//
// TE headers are allowed in HTTP/2 requests as long as the value is "trailers", so they're
// tested separately.
static CONNECTION_HEADERS: [HeaderName; 4] = [
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    TRANSFER_ENCODING,
    UPGRADE,
];

fn strip_connection_headers(headers: &mut HeaderMap, is_request: bool) {
    for header in &CONNECTION_HEADERS {
        if headers.remove(header).is_some() {
            warn!("Connection header illegal in HTTP/2: {}", header.as_str());
        }
    }

    if is_request {
        if headers
            .get(TE)
            .map_or(false, |te_header| te_header != "trailers")
        {
            warn!("TE headers not set to \"trailers\" are illegal in HTTP/2 requests");
            headers.remove(TE);
        }
    } else if headers.remove(TE).is_some() {
        warn!("TE headers illegal in HTTP/2 responses");
    }

    if let Some(header) = headers.remove(CONNECTION) {
        warn!(
            "Connection header illegal in HTTP/2: {}",
            CONNECTION.as_str()
        );
        // A `Connection` header may have a comma-separated list of names of other headers that
        // are meant for only this specific connection.
        //
        // Iterate these names and remove them as headers. Connection-specific headers are
        // forbidden in HTTP2, as that information has been moved into frame types of the h2
        // protocol.
        if let Ok(header_contents) = header.to_str() {
            for name in header_contents.split(',') {
                let name = name.trim();
                headers.remove(name);
            }
        }
    }
}

// body adapters used by both Client and Server

pin_project! {
    pub(crate) struct PipeToSendStream<S>
    where
        S: Body,
    {
        body_tx: SendStream<SendBuf<S::Data>>,
        data_done: bool,
        // FERRUM PATCH 002: a polled DATA chunk (and its end-of-stream flag)
        // waiting for any positive assigned capacity (empty DATA needs none).
        pending_data: Option<(S::Data, bool)>,
        // FERRUM PATCH 004: bound a ready chunk waiting for send capacity.
        write_timeout: Option<WriteTimeout>,
        // FERRUM PATCH 005: hold capacity too small for a useful DATA frame,
        // for a bounded time, while the peer opens more of its window.
        coalesce: Option<Coalesce>,
        #[pin]
        stream: S,
    }
}

/// FERRUM PATCH 005: the shortest non-final DATA frame worth cutting while the
/// peer is still opening its window. It matches h2's
/// `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`: an h2 0.4.16+ receiver charges
/// every DATA frame below it against a connection-wide budget and answers an
/// exhausted budget with `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`.
const MIN_COALESCED_DATA_FRAME: usize = 256;

/// FERRUM PATCH 005: how long a ready chunk may hold positive capacity below
/// `MIN_COALESCED_DATA_FRAME` waiting for more. The bound is what keeps every
/// legal window live: a peer whose window can never reach the minimum (a
/// stream window under 256 bytes, or one that opens only after it receives
/// the bytes held here) gets the smaller frame once the wait ends.
const MAX_COALESCE_WAIT: Duration = Duration::from_millis(2);

/// FERRUM PATCH 005: the running state of small-window coalescing.
///
/// h2 cuts each DATA frame from whatever capacity is assigned when it writes.
/// Handing it a whole chunk while the peer opens its window a few bytes at a
/// time turns every increment into its own DATA frame, and the pattern feeds
/// itself: the peer releases each small frame as it reads it and grants
/// another small increment. So while assigned capacity is below a useful
/// frame, the pipe waits up to `MAX_COALESCE_WAIT` for more, then hands h2
/// exactly the capacity it has. A chunk that fits the assigned capacity is
/// sent at once; the pipe never waits for the next chunk; a tail smaller than
/// the coalescing threshold that does not fit is held for at most 2 ms.
///
/// Only a window-limited stream reaches this state. The one sleep is
/// allocated on its first hold and reset for later ones; a sleep that fires
/// before the deadline (a `Timer` whose `reset` did nothing) is replaced for
/// the rest of the hold, so the hold ends by the deadline with any `Timer`.
struct Coalesce {
    timer: Time,
    sleep: Option<Pin<Box<dyn crate::rt::Sleep>>>,
    deadline: Option<std::time::Instant>,
}

impl Coalesce {
    /// Reports whether a chunk with `remaining` bytes should keep waiting
    /// while `capacity` bytes are assigned. Registers the waker while it
    /// does.
    fn should_hold(&mut self, capacity: usize, remaining: usize, cx: &mut Context<'_>) -> bool {
        if capacity >= remaining.min(MIN_COALESCED_DATA_FRAME) {
            return false;
        }
        let now = self.timer.now();
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = now + MAX_COALESCE_WAIT;
                self.deadline = Some(deadline);
                if let Some(sleep) = self.sleep.as_mut() {
                    self.timer.reset(sleep, deadline);
                } else {
                    self.sleep = Some(self.timer.sleep(MAX_COALESCE_WAIT));
                }
                deadline
            }
        };
        if now >= deadline {
            return false;
        }
        let Some(sleep) = self.sleep.as_mut() else {
            return false;
        };
        if sleep.as_mut().poll(cx).is_ready() {
            // Fired before the deadline: sleep for the rest of the hold. A
            // timer that reports even that sleep ready cannot wake a hold, so
            // stop holding rather than wait for the peer.
            *sleep = self.timer.sleep(deadline - now);
            return sleep.as_mut().poll(cx).is_pending();
        }
        true
    }

    /// The held chunk was handed to h2: the hold, if any, is over.
    ///
    /// A hold that ends before its deadline leaves the sleep armed, so the
    /// task can be woken once more at that deadline and find nothing to do.
    /// That is deliberate. The next hold moves the deadline later, which
    /// tokio does in place without the timer driver; disarming here would
    /// make every next hold move it earlier, a timer-wheel update per hold.
    /// Only a pause between holds longer than the rest of the wait costs the
    /// spurious wake.
    fn release(&mut self) {
        self.deadline = None;
    }
}

/// FERRUM PATCH 005: `SendStream::capacity` together with the flow-control
/// window the stream already holds, which the send-buffer limit does not cap.
///
/// Ferrum's vendored h2 adds an inherent `SendStream::capacity_and_assigned`
/// (h2 patch 003) that reads both under one lock, and method resolution prefers
/// an inherent method over this trait's. Against stock h2 this fallback reports
/// `capacity()` twice, so no chunk is ever treated as covered by window and the
/// pipe splits as it always has. Ferrum's gateway tests bind the vendored
/// method's exact signature, so dropping or changing it fails there rather
/// than silently selecting this fallback.
trait CapacityAndAssigned {
    // Unused when the inherent method exists, which is the point.
    #[allow(dead_code)]
    fn capacity_and_assigned(&self) -> (usize, usize);
}

impl<B: Buf> CapacityAndAssigned for SendStream<B> {
    fn capacity_and_assigned(&self) -> (usize, usize) {
        let capacity = self.capacity();
        (capacity, capacity)
    }
}

/// FERRUM PATCH 004: the running state of an `Http2BodyWriteTimeout`.
///
/// A window-limited upload stalls many times per request (each wait for a
/// WINDOW_UPDATE), so a stall must not touch the timer driver. A stall only
/// records when it started. The one sleep, allocated on the first stall, is
/// left alone between stalls: its deadline was set from an earlier stall, so
/// it can only fire early, never late. When it fires, the real deadline is
/// checked and, if the current stall started later, a fresh sleep is created
/// for the remainder. That is at most one timer-driver update per timeout
/// period. A fresh sleep, rather than `Timer::reset`, keeps this correct with
/// any `Timer`: a `reset` that silently does nothing would leave an elapsed
/// sleep `Ready` forever.
pub(crate) struct WriteTimeout {
    signal: crate::ext::Http2BodyWriteTimeout,
    timer: crate::common::time::Time,
    sleep: Option<Pin<Box<dyn crate::rt::Sleep>>>,
    stalled_since: Option<std::time::Instant>,
}

impl WriteTimeout {
    #[cfg(feature = "client")]
    pub(crate) fn new(
        signal: crate::ext::Http2BodyWriteTimeout,
        timer: crate::common::time::Time,
    ) -> Self {
        WriteTimeout {
            signal,
            timer,
            sleep: None,
            stalled_since: None,
        }
    }

    /// Called while a chunk is ready but cannot be written. Reports whether
    /// the current stall has lasted the full bound.
    fn poll_stalled(&mut self, cx: &mut Context<'_>) -> bool {
        let timeout = self.signal.timeout();
        let since = *self.stalled_since.get_or_insert_with(|| self.timer.now());
        // A bound too large to represent never fires.
        let Some(deadline) = since.checked_add(timeout) else {
            return false;
        };
        let sleep = self
            .sleep
            .get_or_insert_with(|| self.timer.sleep(timeout));
        if sleep.as_mut().poll(cx).is_pending() {
            return false;
        }
        let now = self.timer.now();
        if now >= deadline {
            return true;
        }
        // Fired for an earlier stall: sleep for the rest of this one. A fresh
        // sleep of a positive duration is pending; polling it registers the
        // waker. (A timer that reports it ready anyway is not trusted to
        // expire the stall: only the deadline above does that.)
        #[cfg(all(test, feature = "client"))]
        ferrum_body_write_timeout_tests::REARMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *sleep = self.timer.sleep(deadline - now);
        let _ = sleep.as_mut().poll(cx);
        false
    }

    /// A chunk was handed to h2: the stall, if any, is over.
    fn progressed(&mut self) {
        self.stalled_since = None;
    }
}

impl<S> PipeToSendStream<S>
where
    S: Body,
{
    fn new(stream: S, tx: SendStream<SendBuf<S::Data>>) -> PipeToSendStream<S> {
        PipeToSendStream {
            body_tx: tx,
            data_done: false,
            pending_data: None,
            write_timeout: None,
            coalesce: None,
            stream,
        }
    }

    /// FERRUM PATCH 005: coalesce DATA frames that small window increments
    /// would otherwise cut. The wait needs the connection's timer to stay
    /// bounded; without one the pipe sends at every positive capacity.
    pub(crate) fn with_coalescing(mut self, timer: Time) -> Self {
        if !matches!(timer, Time::Empty) {
            self.coalesce = Some(Coalesce {
                timer,
                sleep: None,
                deadline: None,
            });
        }
        self
    }

    /// FERRUM PATCH 004: bound how long a polled chunk may wait to be written.
    #[cfg(feature = "client")]
    pub(crate) fn with_write_timeout(mut self, write_timeout: WriteTimeout) -> Self {
        self.write_timeout = Some(write_timeout);
        self
    }

    #[cfg(feature = "client")]
    fn send_reset(self: Pin<&mut Self>, reason: h2::Reason) {
        self.project().body_tx.send_reset(reason);
    }
}

impl<S> Future for PipeToSendStream<S>
where
    S: Body,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = crate::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            // Register for RST_STREAM notification while we wait for the next
            // body chunk or for send capacity, so the task wakes up if the
            // peer resets the stream.
            if let Poll::Ready(reason) = me
                .body_tx
                .poll_reset(cx)
                .map_err(crate::Error::new_body_write)?
            {
                debug!("stream received RST_STREAM: {:?}", reason);
                return Poll::Ready(Err(crate::Error::new_body_write(::h2::Error::from(reason))));
            }

            // FERRUM PATCH 002: a ready chunk must make progress with every
            // legal peer window. Waiting for a fixed minimum can deadlock when
            // the peer advertises a smaller stream window or only one byte of
            // connection capacity remains.
            if let Some((mut chunk, is_eos)) = me.pending_data.take() {
                let (mut capacity, mut assigned) = me.body_tx.capacity_and_assigned();
                // FERRUM PATCH 005: whether the stream already holds window
                // for the whole chunk. Then only the send buffer limits
                // `capacity`, and h2 frames the whole chunk from window it
                // already has, so no later increment can cut a small frame;
                // holding or splitting would only stall the pipe. A pipe with
                // a write-stall bound (patch 004) keeps splitting: the bound
                // can only time a chunk the pipe still holds, so a chunk
                // handed over whole would sit in h2 untimed.
                let mut covered = false;
                while chunk.has_remaining() {
                    // FERRUM PATCH 005: positive capacity is enough unless it
                    // is too small for a useful frame and the bounded wait
                    // for more is still running.
                    if capacity > 0 {
                        covered = me.coalesce.is_some()
                            && me.write_timeout.is_none()
                            && capacity < chunk.remaining()
                            && assigned >= chunk.remaining();
                        if covered
                            || !me.coalesce.as_mut().map_or(false, |coalesce| {
                                coalesce.should_hold(capacity, chunk.remaining(), cx)
                            })
                        {
                            break;
                        }
                    }
                    match me.body_tx.poll_capacity(cx) {
                        Poll::Pending => {
                            // FERRUM PATCH 004: a ready chunk that cannot be
                            // written is a write stall; bound it.
                            if capacity == 0 {
                                if let Some(write_timeout) = me.write_timeout.as_mut() {
                                    if write_timeout.poll_stalled(cx) {
                                        debug!("request body write timed out, resetting stream");
                                        write_timeout.signal.mark_expired();
                                        me.body_tx.send_reset(h2::Reason::CANCEL);
                                        return Poll::Ready(Err(crate::Error::new_body_write(
                                            "HTTP/2 request body write timed out",
                                        )));
                                    }
                                }
                            }
                            *me.pending_data = Some((chunk, is_eos));
                            return Poll::Pending;
                        }
                        Poll::Ready(Some(Ok(_))) => {
                            (capacity, assigned) = me.body_tx.capacity_and_assigned()
                        }
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Err(crate::Error::new_body_write(e)))
                        }
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                    }
                }
                // FERRUM PATCH 005: hand h2 only the capacity it can frame
                // now. Given the whole chunk, h2 would buffer the rest and cut
                // a DATA frame from each later window increment.
                if let Some(coalesce) = me.coalesce.as_mut() {
                    coalesce.release();
                    if !covered && capacity > 0 && chunk.remaining() > capacity {
                        let head = chunk.copy_to_bytes(capacity);
                        me.body_tx
                            .send_data(SendBuf::Bytes(head), false)
                            .map_err(crate::Error::new_body_write)?;
                        if let Some(write_timeout) = me.write_timeout.as_mut() {
                            write_timeout.progressed();
                        }
                        *me.pending_data = Some((chunk, is_eos));
                        continue;
                    }
                }
                me.body_tx
                    .send_data(SendBuf::Buf(chunk), is_eos)
                    .map_err(crate::Error::new_body_write)?;
                if let Some(write_timeout) = me.write_timeout.as_mut() {
                    write_timeout.progressed();
                }
                if is_eos {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            // Hyper 1.10: poll the body before reserving capacity. An idle
            // body must not pin connection window needed by another stream.
            match ready!(me.stream.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if frame.is_data() {
                        let chunk = frame.into_data().unwrap_or_else(|_| unreachable!());
                        let is_eos = me.stream.is_end_stream();
                        trace!(
                            "send body chunk: {} bytes, eos={}",
                            chunk.remaining(),
                            is_eos,
                        );

                        // Reserve only real DATA, preserving Hyper 1.10
                        // idle-stream fairness and positive-window progress.
                        me.body_tx.reserve_capacity(chunk.remaining());
                        *me.pending_data = Some((chunk, is_eos));
                        continue;
                    } else if frame.is_trailers() {
                        // no more DATA, so give any capacity back
                        me.body_tx.reserve_capacity(0);
                        me.body_tx
                            .send_trailers(frame.into_trailers().unwrap_or_else(|_| unreachable!()))
                            .map_err(crate::Error::new_body_write)?;
                        return Poll::Ready(Ok(()));
                    } else {
                        trace!("discarding unknown frame");
                        // loop again
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(me.body_tx.on_user_err(e))),
                None => {
                    // no more frames means we're done here
                    // but at this point, we haven't sent an EOS DATA, or
                    // any trailers, so send an empty EOS DATA.
                    return Poll::Ready(me.body_tx.send_eos_frame());
                }
            }
        }
    }
}

trait SendStreamExt {
    fn on_user_err<E>(&mut self, err: E) -> crate::Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>;
    fn send_eos_frame(&mut self) -> crate::Result<()>;
}

impl<B: Buf> SendStreamExt for SendStream<SendBuf<B>> {
    fn on_user_err<E>(&mut self, err: E) -> crate::Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let err = crate::Error::new_user_body(err);
        debug!("send body user stream error: {}", err);
        self.send_reset(err.h2_reason());
        err
    }

    fn send_eos_frame(&mut self) -> crate::Result<()> {
        trace!("send body eos");
        self.send_data(SendBuf::None, true)
            .map_err(crate::Error::new_body_write)
    }
}

#[repr(usize)]
enum SendBuf<B> {
    Buf(B),
    Cursor(Cursor<Box<[u8]>>),
    None,
    // FERRUM PATCH 005: the leading part of a chunk split at the assigned
    // capacity.
    Bytes(Bytes),
}

impl<B: Buf> Buf for SendBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        match *self {
            Self::Buf(ref b) => b.remaining(),
            Self::Cursor(ref c) => Buf::remaining(c),
            Self::None => 0,
            Self::Bytes(ref b) => b.remaining(),
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match *self {
            Self::Buf(ref b) => b.chunk(),
            Self::Cursor(ref c) => c.chunk(),
            Self::None => &[],
            Self::Bytes(ref b) => b.chunk(),
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match *self {
            Self::Buf(ref mut b) => b.advance(cnt),
            Self::Cursor(ref mut c) => c.advance(cnt),
            Self::None => {}
            Self::Bytes(ref mut b) => b.advance(cnt),
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        match *self {
            Self::Buf(ref b) => b.chunks_vectored(dst),
            Self::Cursor(ref c) => c.chunks_vectored(dst),
            Self::None => 0,
            Self::Bytes(ref b) => b.chunks_vectored(dst),
        }
    }
}

#[cfg(test)]
mod ferrum_h2_flow_control_progress_tests {
    //! FERRUM PATCH 002 regressions (hyperium/hyper#4212): every positive
    //! amount of assigned send capacity must allow a ready body to progress.
    use bytes::Bytes;
    use http_body_util::Full;

    use super::{PipeToSendStream, SendBuf};

    #[tokio::test]
    async fn body_progresses_with_a_peer_window_below_one_kibibyte() {
        const PEER_STREAM_WINDOW: u32 = 512;
        const BODY_LEN: usize = 2048;

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (received_tx, received_rx) = tokio::sync::oneshot::channel::<usize>();

        tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(PEER_STREAM_WINDOW);
            let mut conn = builder
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            let (request, response) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });

            let _response = response;
            let mut body = request.into_body();
            let mut received = 0;
            while let Some(frame) = body.data().await {
                let data = frame.expect("request DATA");
                received += data.len();
                body.flow_control()
                    .release_capacity(data.len())
                    .expect("release receive capacity");
            }
            let _ = received_tx.send(received);
        });

        let (mut client, conn) = h2::client::Builder::new()
            .handshake::<_, SendBuf<Bytes>>(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let (_response, send) = client
            .send_request(http::Request::post("http://t/body").body(()).unwrap(), false)
            .unwrap();
        let pipe = PipeToSendStream::new(Full::new(Bytes::from(vec![b'B'; BODY_LEN])), send);
        tokio::spawn(pipe);

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), received_rx)
            .await
            .expect("body must make progress with a 512-byte peer stream window")
            .expect("received_rx");
        assert_eq!(received, BODY_LEN);
    }

    #[tokio::test]
    async fn body_uses_the_last_byte_of_connection_capacity() {
        // Leave exactly one byte of the 65535-byte initial connection window.
        const STREAM_A_LEN: usize = 65534;
        const STREAM_B_LEN: usize = 10_000;

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (stream_a_full_tx, stream_a_full_rx) = tokio::sync::oneshot::channel::<()>();
        let (first_b_tx, first_b_rx) = tokio::sync::oneshot::channel::<usize>();

        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.expect("server handshake");
            let (req_a, respond_a) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                let _respond_a = respond_a;
                let mut body_a = req_a.into_body();
                let mut received = 0usize;
                while received < STREAM_A_LEN {
                    match body_a.data().await {
                        Some(Ok(f)) => received += f.len(),
                        _ => return,
                    }
                }
                let _ = stream_a_full_tx.send(());
                std::future::pending::<()>().await;
            });
            let (req_b, _respond_b) = conn.accept().await.unwrap().unwrap();
            // Keep the connection driven for the rest of the test.
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut body_b = req_b.into_body();
            if let Some(Ok(first)) = body_b.data().await {
                let _ = first_b_tx.send(first.len());
            }
            std::future::pending::<()>().await;
        });

        let (mut client, conn) = h2::client::Builder::new()
            .handshake::<_, SendBuf<Bytes>>(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Stream A spends the connection window down to one byte.
        let (_resp_a, mut send_a) = client
            .send_request(http::Request::post("http://t/a").body(()).unwrap(), false)
            .unwrap();
        send_a.reserve_capacity(STREAM_A_LEN);
        let mut sent = 0;
        while sent < STREAM_A_LEN {
            let take = (STREAM_A_LEN - sent).min(16_384);
            send_a
                .send_data(SendBuf::Buf(Bytes::from(vec![b'A'; take])), false)
                .unwrap();
            sent += take;
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), stream_a_full_rx)
            .await
            .expect("stream A must consume all but one byte of connection capacity")
            .expect("stream_a_full_rx");

        // Stream B pipes a 10 KB body against that one byte.
        let mut client = client.ready().await.expect("client ready");
        let (_resp_b, send_b) = client
            .send_request(http::Request::post("http://t/b").body(()).unwrap(), false)
            .unwrap();
        let pipe = PipeToSendStream::new(Full::new(Bytes::from(vec![b'B'; STREAM_B_LEN])), send_b);
        tokio::spawn(pipe);

        let first_b = tokio::time::timeout(std::time::Duration::from_secs(5), first_b_rx)
            .await
            .expect("stream B must use the remaining connection capacity")
            .expect("first_b_rx");
        assert_eq!(first_b, 1);
    }
}

#[cfg(all(test, feature = "client"))]
mod ferrum_body_write_timeout_tests {
    //! FERRUM PATCH 004: `Http2BodyWriteTimeout` bounds how long a request
    //! body chunk may wait to be written, and nothing else.
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, StreamBody};

    use crate::common::io::Compat;
    use crate::ext::Http2BodyWriteTimeout;
    use crate::rt::{Sleep, Timer};

    #[derive(Clone)]
    struct TokioExecutor;

    impl<F> crate::rt::Executor<F> for TokioExecutor
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        fn execute(&self, fut: F) {
            tokio::spawn(fut);
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
        fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
            Box::pin(TokioSleep(Box::pin(tokio::time::sleep(duration))))
        }
        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
            Box::pin(TokioSleep(Box::pin(tokio::time::sleep_until(deadline.into()))))
        }
    }

    const TIMEOUT: Duration = Duration::from_millis(150);

    async fn client(
        io: tokio::io::DuplexStream,
        timer: bool,
    ) -> crate::client::conn::http2::SendRequest<
        http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>,
    > {
        let mut builder = crate::client::conn::http2::Builder::new(TokioExecutor);
        if timer {
            builder.timer(TokioTimer);
        }
        let (sender, conn) = builder.handshake(Compat::new(io)).await.expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    }

    fn request(
        body: http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>,
        signal: &Http2BodyWriteTimeout,
    ) -> http::Request<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>> {
        let mut req = http::Request::post("http://t/").body(body).unwrap();
        req.extensions_mut().insert(signal.clone());
        req
    }

    /// A backend that never reads (so never opens the window) gets the stream
    /// reset with CANCEL once the timeout passes, and the signal reports it.
    #[tokio::test]
    async fn a_backend_that_stops_reading_trips_the_timeout() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, _respond) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut body = req.into_body();
            // Take the first window's worth but never release capacity.
            let outcome = loop {
                match body.data().await {
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => break e.reason(),
                    None => break None,
                }
            };
            let _ = reset_tx.send(outcome);
            std::future::pending::<()>().await;
        });
        let mut sender = client(client_io, true).await;
        let signal = Http2BodyWriteTimeout::new(TIMEOUT);
        let started = Instant::now();
        // An upload arrives as a run of chunks (one per inbound DATA frame).
        // h2 buffers the chunk it was handed; the stall shows on the next one.
        let chunks: Vec<Result<http_body::Frame<Bytes>, std::convert::Infallible>> = (0..16)
            .map(|_| Ok(http_body::Frame::data(Bytes::from(vec![b'x'; 16 * 1024]))))
            .collect();
        let body = StreamBody::new(futures_util::stream::iter(chunks)).boxed();
        let _response = sender.send_request(request(body, &signal));
        let reason = tokio::time::timeout(Duration::from_secs(5), reset_rx)
            .await
            .expect("the stalled stream is reset")
            .unwrap();
        assert_eq!(reason, Some(h2::Reason::CANCEL));
        assert!(signal.expired());
        assert!(started.elapsed() >= TIMEOUT);
    }

    /// The early fires that `poll_stalled` re-arms. Every pipe in this module
    /// shares it, so tests compare deltas.
    pub(super) static REARMS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn chunks(n: usize, len: usize, fill: u8) -> http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible> {
        let frames: Vec<Result<http_body::Frame<Bytes>, std::convert::Infallible>> = (0..n)
            .map(|_| Ok(http_body::Frame::data(Bytes::from(vec![fill; len]))))
            .collect();
        StreamBody::new(futures_util::stream::iter(frames)).boxed()
    }

    /// A server whose stream window holds one chunk: every further chunk
    /// stalls until the server releases capacity, `release_after` after it
    /// read the previous one. Reports the bytes received.
    async fn window_limited_server(
        server_io: tokio::io::DuplexStream,
        window: u32,
        release_after: Duration,
        done_tx: tokio::sync::oneshot::Sender<usize>,
    ) {
        let mut conn = h2::server::Builder::new()
            .initial_window_size(window)
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        let (req, mut respond) = conn.accept().await.unwrap().unwrap();
        tokio::spawn(async move { while conn.accept().await.is_some() {} });
        let mut body = req.into_body();
        let mut received = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received += chunk.len();
            tokio::time::sleep(release_after).await;
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        respond.send_response(http::Response::new(()), true).unwrap();
        let _ = done_tx.send(received);
    }

    /// Time spent waiting on the request body (a slow client) is never a
    /// write stall, even while the stream window is exhausted: the client
    /// fills the window and then pauses for several bounds before the
    /// server, slower still, opens it again.
    #[tokio::test]
    async fn a_slow_client_body_never_trips_the_timeout() {
        const CHUNK: usize = 16 * 1024;
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        // The server holds the window closed for 2 bounds after each chunk.
        tokio::spawn(window_limited_server(server_io, CHUNK as u32, TIMEOUT * 2, done_tx));
        let mut sender = client(client_io, true).await;
        let signal = Http2BodyWriteTimeout::new(TIMEOUT);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, std::convert::Infallible>>(1);
        let body = StreamBody::new(tokio_stream_from(rx)).boxed();
        let response = sender.send_request(request(body, &signal));
        tokio::spawn(async move {
            for _ in 0..3 {
                // One chunk fills the window; the client then waits 3 bounds,
                // longer than the server keeps the window closed, so no chunk
                // is ever ready while capacity is missing.
                tx.send(Ok(http_body::Frame::data(Bytes::from(vec![b'y'; CHUNK]))))
                    .await
                    .unwrap();
                tokio::time::sleep(TIMEOUT * 3).await;
            }
        });
        let response = tokio::time::timeout(Duration::from_secs(10), response)
            .await
            .expect("response")
            .expect("request succeeds");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(done_rx.await.unwrap(), 3 * CHUNK);
        assert!(!signal.expired());
    }

    /// A backend that keeps opening the window, each time sooner than the
    /// bound, completes an upload that stalls on every chunk and takes many
    /// bounds overall. The sleep armed on the first stall fires during a later
    /// stall and must re-arm for that stall instead of expiring it.
    #[tokio::test]
    async fn steady_progress_rearms_the_timeout() {
        const CHUNK: usize = 16 * 1024;
        const CHUNKS: usize = 12;
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(window_limited_server(server_io, CHUNK as u32, TIMEOUT / 3, done_tx));
        let mut sender = client(client_io, true).await;
        let signal = Http2BodyWriteTimeout::new(TIMEOUT);
        let rearms_before = REARMS.load(std::sync::atomic::Ordering::Relaxed);
        let started = Instant::now();
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_request(request(chunks(CHUNKS, CHUNK, b'z'), &signal)),
        )
        .await
        .expect("response")
        .expect("request succeeds");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(done_rx.await.unwrap(), CHUNKS * CHUNK);
        assert!(!signal.expired());
        assert!(
            started.elapsed() > TIMEOUT * 2,
            "the upload must outlast several bounds for this test to mean anything"
        );
        assert!(
            REARMS.load(std::sync::atomic::Ordering::Relaxed) > rearms_before,
            "an early fire must have been re-armed for a later stall"
        );
    }

    /// A bound too large to represent as an instant never fires and never
    /// panics.
    #[tokio::test]
    async fn an_unrepresentable_bound_never_fires() {
        const CHUNK: usize = 16 * 1024;
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(window_limited_server(server_io, CHUNK as u32, Duration::from_millis(20), done_tx));
        let mut sender = client(client_io, true).await;
        let signal = Http2BodyWriteTimeout::new(Duration::MAX);
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_request(request(chunks(4, CHUNK, b'm'), &signal)),
        )
        .await
        .expect("response")
        .expect("request succeeds");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(done_rx.await.unwrap(), 4 * CHUNK);
        assert!(!signal.expired());
    }

    /// Without a timer the bound cannot be enforced, so the request fails
    /// instead of sending an unbounded body.
    #[tokio::test]
    async fn a_timeout_without_a_timer_fails_the_request() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            while conn.accept().await.is_some() {}
        });
        let mut sender = client(client_io, false).await;
        let signal = Http2BodyWriteTimeout::new(TIMEOUT);
        let body = Full::new(Bytes::from_static(b"data")).boxed();
        let result = sender.send_request(request(body, &signal)).await;
        assert!(result.is_err());
    }

    fn tokio_stream_from<T>(
        mut rx: tokio::sync::mpsc::Receiver<T>,
    ) -> impl futures_core::Stream<Item = T> {
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
    }
}

#[cfg(all(test, feature = "client"))]
mod ferrum_h2_small_window_coalescing_tests {
    //! FERRUM PATCH 005: capacity that a peer opens a few bytes at a time is
    //! coalesced into useful DATA frames, the end of a body is never held,
    //! and a window that never reaches a useful frame still progresses once
    //! the bounded wait ends.
    //!
    //! The peer speaks raw frames so it controls every WINDOW_UPDATE, and the
    //! runtime's clock is paused: the bounded wait elapses only while every
    //! task is idle, so frame sizes do not depend on machine speed.
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http_body_util::Full;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{MAX_COALESCE_WAIT, MIN_COALESCED_DATA_FRAME};
    use crate::common::io::Compat;
    use crate::rt::{Sleep, Timer};

    #[derive(Clone)]
    struct TokioExecutor;

    impl<F> crate::rt::Executor<F> for TokioExecutor
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        fn execute(&self, fut: F) {
            tokio::spawn(fut);
        }
    }

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
        fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
            Box::pin(TokioSleep(Box::pin(tokio::time::sleep(duration))))
        }
        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
            Box::pin(TokioSleep(Box::pin(tokio::time::sleep_until(deadline.into()))))
        }
        // The paused clock moves tokio's time, not the system's.
        fn now(&self) -> Instant {
            tokio::time::Instant::now().into_std()
        }
    }

    /// Every connection starts with this much connection window; SETTINGS
    /// cannot change it.
    const INITIAL_CONNECTION_WINDOW: usize = 65_535;
    /// How far the peer opens the connection window at a time.
    const INCREMENT: u32 = 32;

    const DATA: u8 = 0x0;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const WINDOW_UPDATE: u8 = 0x8;
    const END_STREAM: u8 = 0x1;
    const ACK: u8 = 0x1;

    fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// A raw HTTP/2 server that records the length and END_STREAM flag of
    /// every request DATA frame.
    struct Peer {
        io: tokio::io::DuplexStream,
        frames: Vec<(usize, bool)>,
        received: usize,
    }

    impl Peer {
        async fn accept(mut io: tokio::io::DuplexStream) -> Peer {
            let mut preface = [0u8; 24];
            io.read_exact(&mut preface).await.expect("client preface");
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            // SETTINGS_INITIAL_WINDOW_SIZE = 1 MiB: only the connection
            // window ever limits the client.
            io.write_all(&frame(SETTINGS, 0, 0, &[0, 4, 0, 0x10, 0, 0]))
                .await
                .expect("server SETTINGS");
            Peer {
                io,
                frames: Vec::new(),
                received: 0,
            }
        }

        /// Reads frames until `total` body bytes have arrived.
        async fn read_body_until(&mut self, total: usize) {
            while self.received < total {
                let mut head = [0u8; 9];
                self.io.read_exact(&mut head).await.expect("frame header");
                let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                let mut payload = vec![0u8; len];
                self.io.read_exact(&mut payload).await.expect("frame payload");
                match (head[3], head[4]) {
                    (DATA, flags) => {
                        self.received += len;
                        self.frames.push((len, flags & END_STREAM != 0));
                    }
                    (SETTINGS, flags) if flags & ACK == 0 => {
                        self.io
                            .write_all(&frame(SETTINGS, ACK, 0, &[]))
                            .await
                            .expect("SETTINGS ACK");
                    }
                    (PING, flags) if flags & ACK == 0 => {
                        self.io
                            .write_all(&frame(PING, ACK, 0, &payload))
                            .await
                            .expect("PING ACK");
                    }
                    _ => {}
                }
            }
        }

        /// Opens the connection window by `INCREMENT` bytes, then yields so
        /// the client handles it before the next one arrives. Yielding never
        /// advances the paused clock.
        async fn grant(&mut self) {
            self.io
                .write_all(&frame(WINDOW_UPDATE, 0, 0, &INCREMENT.to_be_bytes()))
                .await
                .expect("WINDOW_UPDATE");
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        }
    }

    async fn client(
        io: tokio::io::DuplexStream,
        timer: bool,
    ) -> crate::client::conn::http2::SendRequest<Full<Bytes>> {
        let mut builder = crate::client::conn::http2::Builder::new(TokioExecutor);
        if timer {
            builder.timer(TokioTimer);
        }
        let (sender, conn) = builder.handshake(Compat::new(io)).await.expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    }

    fn upload(len: usize) -> http::Request<Full<Bytes>> {
        http::Request::post("http://t/")
            .body(Full::new(Bytes::from(vec![b'x'; len])))
            .unwrap()
    }

    fn small_non_final_frames(frames: &[(usize, bool)]) -> usize {
        frames
            .iter()
            .filter(|(len, end_stream)| !end_stream && *len < MIN_COALESCED_DATA_FRAME)
            .count()
    }

    /// Uploads a body against a peer that, once the initial connection window
    /// is spent, opens it `INCREMENT` bytes at a time, `grants` times, without
    /// waiting for the bytes it allows. Returns the DATA frames sent after the
    /// initial window.
    async fn frames_after_initial_window(timer: bool, grants: usize) -> Vec<(usize, bool)> {
        let body_len = INITIAL_CONNECTION_WINDOW + grants * INCREMENT as usize;
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let peer = tokio::spawn(async move {
            let mut peer = Peer::accept(server_io).await;
            peer.read_body_until(INITIAL_CONNECTION_WINDOW).await;
            let initial = peer.frames.len();
            for _ in 0..grants {
                peer.grant().await;
            }
            peer.read_body_until(body_len).await;
            assert_eq!(peer.received, body_len);
            peer.frames.split_off(initial)
        });
        let mut sender = client(client_io, timer).await;
        let _response = sender.send_request(upload(body_len));
        tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("the upload completes")
            .expect("peer")
    }

    /// A chunk the stream already holds window for is handed to h2 whole,
    /// even when the send buffer caps `capacity` below it: h2 frames it at
    /// its maximum frame size rather than in send-buffer-sized pieces, and
    /// the pipe never waits for that buffer to drain mid-chunk. Needs the
    /// vendored h2's `SendStream::assigned_capacity` (h2 patch 003); against
    /// stock h2 the chunk is split at the send-buffer capacity.
    #[tokio::test(start_paused = true)]
    async fn a_chunk_within_the_assigned_window_is_not_split_at_the_send_buffer() {
        const SEND_BUFFER: usize = 10_000;
        // Inside the 65,535-byte initial connection window and the peer's
        // 1 MiB stream window, so the whole chunk is assigned at once.
        const BODY: usize = 60_000;
        const MAX_FRAME: usize = 16_384;

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let peer = tokio::spawn(async move {
            let mut peer = Peer::accept(server_io).await;
            peer.read_body_until(BODY).await;
            peer.frames
        });
        let mut builder = crate::client::conn::http2::Builder::new(TokioExecutor);
        builder.timer(TokioTimer).max_send_buf_size(SEND_BUFFER);
        let (mut sender, conn) = builder
            .handshake(Compat::new(client_io))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let _response = sender.send_request(upload(BODY));
        let frames = tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("the upload completes")
            .expect("peer");
        let total: usize = frames.iter().map(|(len, _)| len).sum();
        assert_eq!(total, BODY);
        let (last, rest) = frames.split_last().expect("DATA frames");
        assert!(last.1, "the last frame ends the stream: {frames:?}");
        assert!(
            rest.iter().all(|(len, _)| *len == MAX_FRAME),
            "every non-final frame is a full {MAX_FRAME}-byte frame: {frames:?}"
        );
    }

    /// The response direction: the server's body pipe hands a chunk the
    /// client's window already covers to h2 whole, even when the send buffer
    /// caps `capacity` below it. This is the frontend leg, where a backend's
    /// 1 MiB response chunk meets the 400 KiB default server send buffer.
    /// Needs the vendored h2 (h2 patch 003), like the request-direction test.
    #[tokio::test(start_paused = true)]
    async fn a_response_chunk_within_the_assigned_window_is_not_split_at_the_send_buffer() {
        const SEND_BUFFER: usize = 10_000;
        // Inside the 65,535-byte initial connection and stream windows.
        const BODY: usize = 60_000;
        const MAX_FRAME: usize = 16_384;
        const HEADERS: u8 = 0x1;
        const END_HEADERS: u8 = 0x4;

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let mut builder = crate::server::conn::http2::Builder::new(TokioExecutor);
        builder.timer(TokioTimer).max_send_buf_size(SEND_BUFFER);
        let body = Bytes::from(vec![b'x'; BODY]);
        let service = crate::service::service_fn(move |_request| {
            let response = http::Response::new(Full::new(body.clone()));
            async move { Ok::<_, std::convert::Infallible>(response) }
        });
        let connection = builder.serve_connection(Compat::new(server_io), service);
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let client = tokio::spawn(async move {
            let mut io = client_io;
            io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await
                .expect("client preface");
            io.write_all(&frame(SETTINGS, 0, 0, &[]))
                .await
                .expect("SETTINGS");
            // GET http://t/ from the static table, with a literal authority.
            let block = [0x82, 0x86, 0x84, 0x01, 0x01, b't'];
            io.write_all(&frame(HEADERS, END_STREAM | END_HEADERS, 1, &block))
                .await
                .expect("HEADERS");
            let mut frames = Vec::new();
            loop {
                let mut head = [0u8; 9];
                io.read_exact(&mut head).await.expect("frame header");
                let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                let mut payload = vec![0u8; len];
                io.read_exact(&mut payload).await.expect("frame payload");
                match (head[3], head[4]) {
                    (DATA, flags) => {
                        frames.push((len, flags & END_STREAM != 0));
                        if flags & END_STREAM != 0 {
                            return frames;
                        }
                    }
                    (SETTINGS, flags) if flags & ACK == 0 => {
                        io.write_all(&frame(SETTINGS, ACK, 0, &[]))
                            .await
                            .expect("SETTINGS ACK");
                    }
                    _ => {}
                }
            }
        });
        let frames = tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("the response completes")
            .expect("client");
        let total: usize = frames.iter().map(|(len, _)| len).sum();
        assert_eq!(total, BODY);
        let (last, rest) = frames.split_last().expect("DATA frames");
        assert!(last.1, "the last frame ends the stream: {frames:?}");
        assert!(
            rest.iter().all(|(len, _)| *len == MAX_FRAME),
            "every non-final frame is a full {MAX_FRAME}-byte frame: {frames:?}"
        );
    }

    /// Control: without a timer the pipe cannot bound a wait, so it sends at
    /// every positive capacity and each increment leaves as its own DATA
    /// frame. This is the run of small frames that an h2 0.4.16+ receiver
    /// charges against its budget.
    #[tokio::test(start_paused = true)]
    async fn without_a_timer_each_increment_is_its_own_frame() {
        const GRANTS: usize = 128;
        let frames = frames_after_initial_window(false, GRANTS).await;
        assert!(
            small_non_final_frames(&frames) >= GRANTS / 2,
            "expected a run of small DATA frames: {frames:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn small_window_increments_coalesce_into_useful_frames() {
        const GRANTS: usize = 128;
        let frames = frames_after_initial_window(true, GRANTS).await;
        let total: usize = frames.iter().map(|(len, _)| len).sum();
        assert_eq!(total, GRANTS * INCREMENT as usize);
        assert_eq!(
            small_non_final_frames(&frames),
            0,
            "window increments must coalesce into frames of at least \
             {MIN_COALESCED_DATA_FRAME} bytes: {frames:?}"
        );
    }

    /// A peer that opens its window only after it has received the bytes it
    /// allowed never lets capacity reach a useful frame. Each increment is
    /// held for the bounded wait and then sent anyway. The last piece of the
    /// body is useful at its own length, so it is not held at all.
    #[tokio::test(start_paused = true)]
    async fn a_window_below_a_useful_frame_progresses_after_the_bounded_wait() {
        const ROUNDS: usize = 8;
        let body_len = INITIAL_CONNECTION_WINDOW + ROUNDS * INCREMENT as usize;
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let peer = tokio::spawn(async move {
            let mut peer = Peer::accept(server_io).await;
            peer.read_body_until(INITIAL_CONNECTION_WINDOW).await;
            let initial = peer.frames.len();
            let mut waits = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                let started = tokio::time::Instant::now();
                let target = peer.received + INCREMENT as usize;
                peer.grant().await;
                peer.read_body_until(target).await;
                waits.push(started.elapsed());
            }
            (peer.frames.split_off(initial), waits)
        });
        let mut sender = client(client_io, true).await;
        let _response = sender.send_request(upload(body_len));
        let (frames, waits) = tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("the upload completes")
            .expect("peer");
        assert_eq!(frames.len(), ROUNDS, "{frames:?}");
        assert!(
            frames.iter().all(|(len, _)| *len == INCREMENT as usize),
            "{frames:?}"
        );
        assert!(frames[ROUNDS - 1].1, "the last frame ends the stream");
        for wait in &waits[..ROUNDS - 1] {
            assert!(*wait >= MAX_COALESCE_WAIT, "held for the bounded wait: {waits:?}");
            assert!(*wait < MAX_COALESCE_WAIT * 4, "and no longer: {waits:?}");
        }
        assert!(
            waits[ROUNDS - 1] < MAX_COALESCE_WAIT,
            "the end of the body is not held: {waits:?}"
        );
    }
}
