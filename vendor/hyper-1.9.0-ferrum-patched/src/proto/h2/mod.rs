use std::error::Error as StdError;
use std::future::Future;
use std::io::{Cursor, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Buf;
use futures_core::ready;
use h2::SendStream;
use http::header::{HeaderName, CONNECTION, TE, TRANSFER_ENCODING, UPGRADE};
use http::HeaderMap;
use pin_project_lite::pin_project;

use crate::body::Body;

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
        // waiting for enough assigned capacity to avoid a sliver frame.
        pending_data: Option<(S::Data, bool)>,
        // FERRUM PATCH 004: optional bound on how long a polled chunk may wait
        // to be written (see `crate::ext::Http2BodyWriteTimeout`).
        write_timeout: Option<WriteTimeout>,
        #[pin]
        stream: S,
    }
}

/// FERRUM PATCH 004: the running state of an `Http2BodyWriteTimeout`.
///
/// A window-limited upload stalls many times per request (each wait for a
/// WINDOW_UPDATE), so a stall must not touch the timer driver. A stall only
/// records when it started. The one sleep, allocated on the first stall, is
/// left alone between stalls: its deadline was set from an earlier stall, so
/// it can only fire early, never late. When it fires, the real deadline is
/// checked and the sleep re-armed once if the current stall started later.
/// That is at most one timer-driver update per timeout period.
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
        let deadline = since + timeout;
        let sleep = self
            .sleep
            .get_or_insert_with(|| self.timer.sleep(timeout));
        loop {
            if sleep.as_mut().poll(cx).is_pending() {
                return false;
            }
            if self.timer.now() >= deadline {
                return true;
            }
            // Fired for an earlier stall: re-arm for this one and poll again
            // so the waker is registered.
            self.timer.reset(sleep, deadline);
        }
    }

    /// A chunk was handed to h2: the stall, if any, is over.
    fn progressed(&mut self) {
        self.stalled_since = None;
    }
}

/// FERRUM PATCH 002: smallest DATA frame worth cutting while more of the
/// chunk is still waiting for capacity. h2 cuts a frame from whatever capacity
/// a stream holds, so on a connection whose window is nearly spent a chunk can
/// leave as a run of 1-byte frames (silly-window syndrome). h2 >= 0.4.16 peers
/// charge every DATA frame under 256 bytes to a small per-connection budget and
/// answer its exhaustion with GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames"),
/// failing every stream on the connection. Kept at 1 KiB so no peer window a
/// real server advertises can hold a chunk back indefinitely.
const MIN_DATA_FRAME_CAPACITY: usize = 1024;

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
            stream,
        }
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
            // FERRUM PATCH 002: a chunk already polled from the body is sent
            // only once it holds `min(len, MIN_DATA_FRAME_CAPACITY)` capacity.
            if let Some((chunk, is_eos)) = me.pending_data.take() {
                let len = chunk.remaining();
                let needed = len.min(MIN_DATA_FRAME_CAPACITY);
                while me.body_tx.capacity() < needed {
                    match me.body_tx.poll_capacity(cx) {
                        Poll::Pending => {
                            // FERRUM PATCH 004: a ready chunk that cannot be
                            // written is a write stall; bound it.
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
                            *me.pending_data = Some((chunk, is_eos));
                            return Poll::Pending;
                        }
                        Poll::Ready(Some(Ok(_))) => {}
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

            // we don't have the next chunk of data yet, so just reserve 1 byte to make
            // sure there's some capacity available. h2 will handle the capacity management
            // for the actual body chunk.
            me.body_tx.reserve_capacity(1);

            // FERRUM PATCH 004: with a write timeout, poll the body before
            // waiting for capacity, so the timer runs only while a chunk is
            // actually ready (a slow client is never a write stall). At most
            // one chunk is held, as when a 1-byte claim admits a whole chunk.
            if me.body_tx.capacity() == 0 && me.write_timeout.is_none() {
                loop {
                    match ready!(me.body_tx.poll_capacity(cx)) {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        Some(Err(e)) => return Poll::Ready(Err(crate::Error::new_body_write(e))),
                        None => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                    }
                }
            } else if let Poll::Ready(reason) = me
                .body_tx
                .poll_reset(cx)
                .map_err(crate::Error::new_body_write)?
            {
                debug!("stream received RST_STREAM: {:?}", reason);
                return Poll::Ready(Err(crate::Error::new_body_write(::h2::Error::from(reason))));
            }

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

                        // FERRUM PATCH 002: raise the claim to what a useful
                        // first frame needs (still small, per hyper#4003), and
                        // let the top of the loop send the chunk once that
                        // much is assigned. An empty END_STREAM chunk needs none.
                        let len = chunk.remaining();
                        if len > 1 {
                            me.body_tx
                                .reserve_capacity(len.min(MIN_DATA_FRAME_CAPACITY));
                        }
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
}

impl<B: Buf> Buf for SendBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        match *self {
            Self::Buf(ref b) => b.remaining(),
            Self::Cursor(ref c) => Buf::remaining(c),
            Self::None => 0,
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match *self {
            Self::Buf(ref b) => b.chunk(),
            Self::Cursor(ref c) => c.chunk(),
            Self::None => &[],
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match *self {
            Self::Buf(ref mut b) => b.advance(cnt),
            Self::Cursor(ref mut c) => c.advance(cnt),
            Self::None => {}
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        match *self {
            Self::Buf(ref b) => b.chunks_vectored(dst),
            Self::Cursor(ref c) => c.chunks_vectored(dst),
            Self::None => 0,
        }
    }
}

#[cfg(test)]
mod ferrum_min_data_frame_capacity_tests {
    //! FERRUM PATCH 002 regression (hyperium/hyper#4211): a chunk polled while
    //! its stream holds a sliver of capacity must not leave as a sliver frame.
    use bytes::Bytes;
    use http_body_util::Full;

    use super::{PipeToSendStream, SendBuf};

    #[tokio::test]
    async fn chunk_waits_for_useful_capacity_instead_of_sliver_frames() {
        // Leave exactly one byte of the 65535-byte initial connection window.
        const STREAM_A_LEN: usize = 65534;
        const STREAM_B_LEN: usize = 10_000;

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (release_a_tx, release_a_rx) = tokio::sync::oneshot::channel::<()>();
        let (first_b_tx, first_b_rx) = tokio::sync::oneshot::channel::<usize>();

        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.expect("server handshake");
            let (req_a, respond_a) = conn.accept().await.unwrap().unwrap();
            // Stream A: take its burst without releasing capacity until the
            // test says so, then release all of it (a WINDOW_UPDATE).
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
                let _ = release_a_rx.await;
                let _ = body_a.flow_control().release_capacity(received);
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
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Stream B pipes a 10 KB body against that one byte.
        let mut client = client.ready().await.expect("client ready");
        let (_resp_b, send_b) = client
            .send_request(http::Request::post("http://t/b").body(()).unwrap(), false)
            .unwrap();
        let pipe = PipeToSendStream::new(Full::new(Bytes::from(vec![b'B'; STREAM_B_LEN])), send_b);
        tokio::spawn(pipe);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = release_a_tx.send(());

        let first_b = tokio::time::timeout(std::time::Duration::from_secs(5), first_b_rx)
            .await
            .expect("stream B reaches the server once the window is released")
            .expect("first_b_rx");
        assert!(
            first_b >= 1024,
            "stream B's first DATA frame was {first_b} bytes: cut from a sliver of capacity"
        );
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

    /// Time spent waiting on the request body (a slow client) is never a
    /// write stall, however long it lasts.
    #[tokio::test]
    async fn a_slow_client_body_never_trips_the_timeout() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut body = req.into_body();
            let mut received = 0;
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                received += chunk.len();
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            respond.send_response(http::Response::new(()), true).unwrap();
            let _ = done_tx.send(received);
        });
        let mut sender = client(client_io, true).await;
        let signal = Http2BodyWriteTimeout::new(TIMEOUT);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, std::convert::Infallible>>(1);
        let body = StreamBody::new(tokio_stream_from(rx)).boxed();
        let response = sender.send_request(request(body, &signal));
        tokio::spawn(async move {
            for _ in 0..3 {
                tx.send(Ok(http_body::Frame::data(Bytes::from(vec![b'y'; 1000]))))
                    .await
                    .unwrap();
                tokio::time::sleep(TIMEOUT * 3).await;
            }
        });
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("response")
            .expect("request succeeds");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(done_rx.await.unwrap(), 3000);
        assert!(!signal.expired());
    }

    /// A backend that keeps opening the window, each time sooner than the
    /// timeout, completes a body that takes longer than the timeout overall.
    #[tokio::test]
    async fn steady_progress_rearms_the_timeout() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        const LEN: usize = 256 * 1024;
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut body = req.into_body();
            let mut received = 0;
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                received += chunk.len();
                tokio::time::sleep(TIMEOUT / 3).await;
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            respond.send_response(http::Response::new(()), true).unwrap();
            let _ = done_tx.send(received);
        });
        let mut sender = client(client_io, true).await;
        let signal = Http2BodyWriteTimeout::new(TIMEOUT);
        let started = Instant::now();
        let body = Full::new(Bytes::from(vec![b'z'; LEN])).boxed();
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_request(request(body, &signal)),
        )
        .await
        .expect("response")
        .expect("request succeeds");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(done_rx.await.unwrap(), LEN);
        assert!(!signal.expired());
        assert!(
            started.elapsed() > TIMEOUT,
            "the transfer must outlast one timeout for this test to mean anything"
        );
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
