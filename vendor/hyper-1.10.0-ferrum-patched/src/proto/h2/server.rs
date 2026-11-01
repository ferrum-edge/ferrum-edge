use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::ready;
use h2::server::{Connection, Handshake, SendResponse};
use h2::{Reason, RecvStream};
use http::{Method, Request};
use pin_project_lite::pin_project;

use super::{ping, PipeToSendStream, SendBuf};
use crate::body::{Body, Incoming as IncomingBody};
use crate::common::date;
use crate::common::io::Compat;
use crate::common::time::Time;
use crate::ext::Protocol;
// FERRUM PATCH 006
use crate::ext::{publish_h2_stream_termination, ClearH2StreamTermination, H2StreamTermination};
use crate::headers;
use crate::proto::h2::ping::Recorder;
use crate::proto::Dispatched;
use crate::rt::bounds::{Http2ServerConnExec, Http2UpgradedExec};
use crate::rt::{Read, Write};
use crate::service::HttpService;

use crate::upgrade::{OnUpgrade, Pending, Upgraded};
use crate::Response;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
//
// At the same time, a server more often has multiple clients connected, and
// so is more likely to use more resources than a client would.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 400; // 400kb
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) adaptive_window: bool,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_stream_window_size: u32,
    pub(crate) max_frame_size: u32,
    pub(crate) enable_connect_protocol: bool,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) max_local_error_reset_streams: Option<usize>,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) max_header_list_size: u32,
    pub(crate) date_header: bool,
    // FERRUM PATCH 008: bound on a response body chunk waiting for window.
    pub(crate) response_write_timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            adaptive_window: false,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_stream_window_size: DEFAULT_STREAM_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            enable_connect_protocol: false,
            max_concurrent_streams: Some(200),
            max_pending_accept_reset_streams: None,
            max_local_error_reset_streams: Some(DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS),
            header_table_size: None,
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_header_list_size: DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE,
            date_header: true,
            response_write_timeout: None,
        }
    }
}

pin_project! {
    pub(crate) struct Server<T, S, B, E>
    where
        S: HttpService<IncomingBody>,
        B: Body,
    {
        exec: E,
        timer: Time,
        service: S,
        state: State<T, B>,
        date_header: bool,
        // FERRUM PATCH 008
        response_write_timeout: Option<Duration>,
        close_pending: bool
    }
}

enum State<T, B>
where
    B: Body,
{
    Handshaking {
        ping_config: ping::Config,
        hs: Handshake<Compat<T>, SendBuf<B::Data>>,
    },
    Serving(Serving<T, B>),
}

struct Serving<T, B>
where
    B: Body,
{
    ping: Option<(ping::Recorder, ping::Ponger)>,
    conn: Connection<Compat<T>, SendBuf<B::Data>>,
    closing: Option<crate::Error>,
    date_header: bool,
    // FERRUM PATCH 005: bounds each response body pipe's coalescing wait.
    timer: Time,
    // FERRUM PATCH 008: each response body pipe's write-stall bound.
    response_write_timeout: Option<Duration>,
}

impl<T, S, B, E> Server<T, S, B, E>
where
    T: Read + Write + Unpin,
    S: HttpService<IncomingBody, ResBody = B>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    B: Body + 'static,
    E: Http2ServerConnExec<S::Future, B>,
{
    pub(crate) fn new(
        io: T,
        service: S,
        config: &Config,
        exec: E,
        timer: Time,
    ) -> Server<T, S, B, E> {
        let mut builder = h2::server::Builder::default();
        builder
            .initial_window_size(config.initial_stream_window_size)
            .initial_connection_window_size(config.initial_conn_window_size)
            .max_frame_size(config.max_frame_size)
            .max_header_list_size(config.max_header_list_size)
            .max_local_error_reset_streams(config.max_local_error_reset_streams)
            .max_send_buffer_size(config.max_send_buffer_size);
        if let Some(max) = config.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
        if let Some(max) = config.max_pending_accept_reset_streams {
            builder.max_pending_accept_reset_streams(max);
        }
        if let Some(size) = config.header_table_size {
            builder.header_table_size(size);
        }
        if config.enable_connect_protocol {
            builder.enable_connect_protocol();
        }
        let handshake = builder.handshake(Compat::new(io));

        let bdp = if config.adaptive_window {
            Some(config.initial_stream_window_size)
        } else {
            None
        };

        let ping_config = ping::Config {
            bdp_initial_window: bdp,
            keep_alive_interval: config.keep_alive_interval,
            keep_alive_timeout: config.keep_alive_timeout,
            // If keep-alive is enabled for servers, always enabled while
            // idle, so it can more aggressively close dead connections.
            keep_alive_while_idle: true,
        };

        Server {
            exec,
            timer,
            state: State::Handshaking {
                ping_config,
                hs: handshake,
            },
            service,
            date_header: config.date_header,
            response_write_timeout: config.response_write_timeout,
            close_pending: false,
        }
    }

    pub(crate) fn graceful_shutdown(&mut self) {
        trace!("graceful_shutdown");
        match self.state {
            State::Handshaking { .. } => {
                self.close_pending = true;
            }
            State::Serving(ref mut srv) => {
                if srv.closing.is_none() {
                    srv.conn.graceful_shutdown();
                }
            }
        }
    }
}

impl<T, S, B, E> Future for Server<T, S, B, E>
where
    T: Read + Write + Unpin,
    S: HttpService<IncomingBody, ResBody = B>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    B: Body + 'static,
    E: Http2ServerConnExec<S::Future, B>,
{
    type Output = crate::Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            let next = match me.state {
                State::Handshaking {
                    ref mut hs,
                    ref ping_config,
                } => {
                    let mut conn = ready!(Pin::new(hs).poll(cx).map_err(crate::Error::new_h2))?;
                    let ping = if ping_config.is_enabled() {
                        let pp = conn.ping_pong().expect("conn.ping_pong");
                        Some(ping::channel(pp, ping_config.clone(), me.timer.clone()))
                    } else {
                        None
                    };
                    State::Serving(Serving {
                        ping,
                        conn,
                        closing: None,
                        date_header: me.date_header,
                        timer: me.timer.clone(),
                        response_write_timeout: me.response_write_timeout,
                    })
                }
                State::Serving(ref mut srv) => {
                    // graceful_shutdown was called before handshaking finished,
                    if me.close_pending && srv.closing.is_none() {
                        srv.conn.graceful_shutdown();
                    }
                    ready!(srv.poll_server(cx, &mut me.service, &mut me.exec))?;
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }
            };
            me.state = next;
        }
    }
}

impl<T, B> Serving<T, B>
where
    T: Read + Write + Unpin,
    B: Body + 'static,
{
    fn poll_server<S, E>(
        &mut self,
        cx: &mut Context<'_>,
        service: &mut S,
        exec: &mut E,
    ) -> Poll<crate::Result<()>>
    where
        S: HttpService<IncomingBody, ResBody = B>,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        E: Http2ServerConnExec<S::Future, B>,
    {
        if self.closing.is_none() {
            loop {
                self.poll_ping(cx);

                match ready!(self.conn.poll_accept(cx)) {
                    Some(Ok((req, mut respond))) => {
                        trace!("incoming request");
                        let content_length = headers::content_length_parse_all(req.headers());
                        let ping = self
                            .ping
                            .as_ref()
                            .map(|ping| ping.0.clone())
                            .unwrap_or_else(ping::disabled);

                        // Record the headers received
                        ping.record_non_data();

                        let is_connect = req.method() == Method::CONNECT;
                        let (mut parts, stream) = req.into_parts();
                        let (mut req, connect_parts) = if !is_connect {
                            (
                                Request::from_parts(
                                    parts,
                                    IncomingBody::h2(stream, content_length.into(), ping),
                                ),
                                None,
                            )
                        } else {
                            if content_length.map_or(false, |len| len != 0) {
                                warn!("h2 connect request with non-zero body not supported");
                                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                                return Poll::Ready(Ok(()));
                            }
                            let (pending, upgrade) = crate::upgrade::pending();
                            debug_assert!(parts.extensions.get::<OnUpgrade>().is_none());
                            parts.extensions.insert(upgrade);
                            (
                                Request::from_parts(parts, IncomingBody::empty()),
                                Some(ConnectParts {
                                    pending,
                                    ping,
                                    recv_stream: stream,
                                }),
                            )
                        };

                        if let Some(protocol) = req.extensions_mut().remove::<h2::ext::Protocol>() {
                            req.extensions_mut().insert(Protocol::from_inner(protocol));
                        }

                        let fut = H2Stream::new(
                            service.call(req),
                            connect_parts,
                            respond,
                            self.date_header,
                            self.timer.clone(),
                            self.response_write_timeout,
                            exec.clone(),
                        );

                        exec.execute_h2stream(fut);
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(Err(crate::Error::new_h2(e)));
                    }
                    None => {
                        // no more incoming streams...
                        if let Some((ref ping, _)) = self.ping {
                            ping.ensure_not_timed_out()?;
                        }

                        trace!("incoming connection complete");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        debug_assert!(
            self.closing.is_some(),
            "poll_server broke loop without closing"
        );

        ready!(self.conn.poll_closed(cx).map_err(crate::Error::new_h2))?;

        Poll::Ready(Err(self.closing.take().expect("polled after error")))
    }

    fn poll_ping(&mut self, cx: &mut Context<'_>) {
        if let Some((_, ref mut estimator)) = self.ping {
            match estimator.poll(cx) {
                Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                    self.conn.set_target_window_size(wnd);
                    let _ = self.conn.set_initial_window_size(wnd);
                }
                Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                    debug!("keep-alive timed out, closing connection");
                    self.conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                }
                Poll::Pending => {}
            }
        }
    }
}

pin_project! {
    #[allow(missing_debug_implementations)]
    pub struct H2Stream<F, B, E>
    where
        B: Body,
    {
        reply: SendResponse<SendBuf<B::Data>>,
        #[pin]
        state: H2StreamState<F, B>,
        date_header: bool,
        // FERRUM PATCH 005: bounds the response body pipe's coalescing wait.
        timer: Time,
        // FERRUM PATCH 008: the response body pipe's write-stall bound.
        response_write_timeout: Option<Duration>,
        exec: E,
        // FERRUM PATCH 006: declared after `state`, so it drops after the
        // service future and clears a termination cause nobody took.
        _termination: ClearH2StreamTermination,
    }
}

pin_project! {
    #[project = H2StreamStateProj]
    enum H2StreamState<F, B>
    where
        B: Body,
    {
        Service {
            #[pin]
            fut: F,
            connect_parts: Option<ConnectParts>,
        },
        Body {
            #[pin]
            pipe: PipeToSendStream<B>,
        },
    }
}

struct ConnectParts {
    pending: Pending,
    ping: Recorder,
    recv_stream: RecvStream,
}

/// FERRUM PATCH 006: whether the reset that closed a stream was local.
///
/// Ferrum's vendored h2 adds an inherent `SendResponse::reset_is_local`
/// (h2 patch 004), and method resolution prefers an inherent method over this
/// trait's. Against stock h2 this fallback reports `None`, so no termination
/// cause is published for a reset and the service never reads it as the
/// peer's. Ferrum's gateway tests bind the vendored method's exact signature,
/// so dropping or changing it fails there rather than silently selecting this
/// fallback.
trait ResetIsLocal {
    // Unused when the inherent method exists, which is the point.
    #[allow(dead_code)]
    fn reset_is_local(&self) -> Option<bool>;
}

impl<B: bytes::Buf> ResetIsLocal for SendResponse<B> {
    fn reset_is_local(&self) -> Option<bool> {
        None
    }
}

impl<F, B, E> H2Stream<F, B, E>
where
    B: Body,
{
    fn new(
        fut: F,
        connect_parts: Option<ConnectParts>,
        respond: SendResponse<SendBuf<B::Data>>,
        date_header: bool,
        timer: Time,
        response_write_timeout: Option<Duration>,
        exec: E,
    ) -> H2Stream<F, B, E> {
        H2Stream {
            reply: respond,
            state: H2StreamState::Service { fut, connect_parts },
            date_header,
            timer,
            response_write_timeout,
            exec,
            _termination: ClearH2StreamTermination,
        }
    }
}

macro_rules! reply {
    ($me:expr, $res:expr, $eos:expr) => {{
        match $me.reply.send_response($res, $eos) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("send response error: {}", e);
                $me.reply.send_reset(Reason::INTERNAL_ERROR);
                return Poll::Ready(Err(crate::Error::new_h2(e)));
            }
        }
    }};
}

impl<F, B, Ex, E> H2Stream<F, B, Ex>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Ex: Http2UpgradedExec<B::Data>,
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    fn poll2(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let mut me = self.as_mut().project();
        loop {
            let next = match me.state.as_mut().project() {
                H2StreamStateProj::Service {
                    fut: h,
                    connect_parts,
                } => {
                    let res = match h.poll(cx) {
                        Poll::Ready(Ok(r)) => r,
                        Poll::Pending => {
                            // Response is not yet ready, so we want to check if the client has sent a
                            // RST_STREAM frame which would cancel the current request.
                            //
                            // FERRUM PATCH 006: before returning, publish who ended the
                            // stream; the service future is dropped with this stream.
                            match me.reply.poll_reset(cx) {
                                Poll::Ready(Ok(reason)) => {
                                    let code = u32::from(reason);
                                    // Without the vendored h2's origin (stock h2), publish
                                    // nothing: an unattributed reset is never the peer's.
                                    match me.reply.reset_is_local() {
                                        Some(true) => publish_h2_stream_termination(
                                            H2StreamTermination::LocalReset { reason: code },
                                        ),
                                        Some(false) => publish_h2_stream_termination(
                                            H2StreamTermination::PeerReset { reason: code },
                                        ),
                                        None => {}
                                    }
                                    debug!("stream received RST_STREAM: {:?}", reason);
                                    return Poll::Ready(Err(crate::Error::new_h2(reason.into())));
                                }
                                Poll::Ready(Err(e)) => {
                                    if e.is_io() {
                                        publish_h2_stream_termination(
                                            H2StreamTermination::TransportLost,
                                        );
                                    } else if let Some(reason) = e.reason() {
                                        let code = u32::from(reason);
                                        publish_h2_stream_termination(if e.is_remote() {
                                            H2StreamTermination::PeerReset { reason: code }
                                        } else {
                                            H2StreamTermination::LocalReset { reason: code }
                                        });
                                    }
                                    return Poll::Ready(Err(crate::Error::new_h2(e)));
                                }
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            let err = crate::Error::new_user_service(e);
                            warn!("http2 service errored: {}", err);
                            me.reply.send_reset(err.h2_reason());
                            return Poll::Ready(Err(err));
                        }
                    };

                    let (head, body) = res.into_parts();
                    let mut res = ::http::Response::from_parts(head, ());
                    super::strip_connection_headers(res.headers_mut(), false);

                    // set Date header if it isn't already set if instructed
                    if *me.date_header {
                        res.headers_mut()
                            .entry(::http::header::DATE)
                            .or_insert_with(date::update_and_header_value);
                    }

                    if let Some(connect_parts) = connect_parts.take() {
                        if res.status().is_success() {
                            if headers::content_length_parse_all(res.headers())
                                .map_or(false, |len| len != 0)
                            {
                                warn!("h2 successful response to CONNECT request with body not supported");
                                me.reply.send_reset(h2::Reason::INTERNAL_ERROR);
                                return Poll::Ready(Err(crate::Error::new_user_header()));
                            }
                            if res
                                .headers_mut()
                                .remove(::http::header::CONTENT_LENGTH)
                                .is_some()
                            {
                                warn!("successful response to CONNECT request disallows content-length header");
                            }
                            let send_stream = reply!(me, res, false);
                            let (h2_up, up_task) = super::upgrade::pair(
                                send_stream,
                                connect_parts.recv_stream,
                                connect_parts.ping,
                            );
                            connect_parts
                                .pending
                                .fulfill(Upgraded::new(h2_up, Bytes::new()));
                            self.exec.execute_upgrade(up_task);
                            return Poll::Ready(Ok(()));
                        }
                    }

                    if !body.is_end_stream() {
                        // automatically set Content-Length from body...
                        if let Some(len) = body.size_hint().exact() {
                            headers::set_content_length_if_missing(res.headers_mut(), len);
                        }

                        // FERRUM PATCH 008: a bound with no timer to run it
                        // fails the stream before the response starts,
                        // rather than serving a body nothing bounds.
                        if me.response_write_timeout.is_some()
                            && matches!(me.timer, Time::Empty)
                        {
                            debug!("response body write timeout set without a timer");
                            me.reply.send_reset(Reason::INTERNAL_ERROR);
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "HTTP/2 response body write timeout requires a timer",
                            )));
                        }
                        let body_tx = reply!(me, res, false);
                        // FERRUM PATCH 005: coalesce DATA frames cut from
                        // small window increments, bounded by the timer.
                        let mut pipe =
                            PipeToSendStream::new(body, body_tx).with_coalescing(me.timer.clone());
                        // FERRUM PATCH 008: bound how long a ready chunk may
                        // wait for the client to open its window.
                        if let Some(timeout) = *me.response_write_timeout {
                            pipe = pipe.with_write_timeout(super::WriteTimeout::for_response(
                                timeout,
                                me.timer.clone(),
                            ));
                        }
                        H2StreamState::Body { pipe }
                    } else {
                        reply!(me, res, true);
                        return Poll::Ready(Ok(()));
                    }
                }
                H2StreamStateProj::Body { pipe } => {
                    return pipe.poll(cx);
                }
            };
            me.state.set(next);
        }
    }
}

impl<F, B, Ex, E> Future for H2Stream<F, B, Ex>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Ex: Http2UpgradedExec<B::Data>,
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll2(cx).map(|res| {
            if let Err(_e) = res {
                debug!("stream error: {}", _e);
            }
        })
    }
}

#[cfg(test)]
mod ferrum_response_write_timeout_tests {
    //! FERRUM PATCH 008: the server's `response_write_timeout` resets a
    //! response stream whose client grants no window for a ready chunk, and
    //! nothing else.
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http_body::Frame;
    use http_body_util::{BodyExt, Full};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        // The tests run on tokio's paused clock; the bound must read it too.
        fn now(&self) -> Instant {
            tokio::time::Instant::now().into_std()
        }
    }

    const TIMEOUT: Duration = Duration::from_secs(60);
    const CHUNK: usize = 16 * 1024;

    type ResBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

    /// A response body that yields `chunks` chunks (forever when `None`) and
    /// then stays pending without ever ending. It records when it is dropped,
    /// which is what releases whatever a proxy's body holds upstream.
    struct Streaming {
        chunks: Option<usize>,
        dropped: Arc<AtomicBool>,
    }

    impl http_body::Body for Streaming {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            match self.chunks.as_mut() {
                Some(0) => Poll::Pending,
                Some(left) => {
                    *left -= 1;
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; CHUNK])))))
                }
                None => Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; CHUNK]))))),
            }
        }
    }

    impl Drop for Streaming {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn streaming(chunks: Option<usize>) -> (ResBody, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let body = Streaming {
            chunks,
            dropped: Arc::clone(&dropped),
        };
        (body.boxed(), dropped)
    }

    /// Serves every request with the body `make_body` builds.
    fn serve<I>(
        io: I,
        timer: bool,
        bound: Option<Duration>,
        max_send_buf: Option<usize>,
        make_body: impl Fn() -> ResBody + Send + Sync + 'static,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = crate::server::conn::http2::Builder::new(TokioExecutor);
        if timer {
            builder.timer(TokioTimer);
        }
        builder.response_write_timeout(bound);
        if let Some(max) = max_send_buf {
            builder.max_send_buf_size(max);
        }
        let make_body = Arc::new(make_body);
        let service = crate::service::service_fn(move |_request| {
            let body = make_body();
            async move { Ok::<_, std::convert::Infallible>(http::Response::new(body)) }
        });
        let connection = builder.serve_connection(Compat::new(io), service);
        tokio::spawn(async move {
            let _ = connection.await;
        });
    }

    /// An h2 client with `window` for its stream and connection windows. It
    /// sends a `WINDOW_UPDATE` only when the test releases capacity.
    async fn client<I>(io: I, window: u32) -> h2::client::SendRequest<Bytes>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(window)
            .initial_connection_window_size(window)
            .handshake::<_, Bytes>(io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender
    }

    async fn get(sender: &mut h2::client::SendRequest<Bytes>) -> h2::RecvStream {
        let request = http::Request::get("http://t/").body(()).unwrap();
        let (response, _) = sender.send_request(request, true).expect("send request");
        let response = response.await.expect("response head");
        assert_eq!(response.status(), http::StatusCode::OK);
        response.into_body()
    }

    /// Reads DATA without releasing capacity, so no `WINDOW_UPDATE` is ever
    /// sent. Returns the bytes received and the reset that ended the stream,
    /// or `None` if it is still open after `within`.
    async fn drain_withholding_window(
        body: &mut h2::RecvStream,
        within: Duration,
    ) -> (usize, Option<h2::Reason>) {
        let mut received = 0;
        let ended = tokio::time::timeout(within, async {
            loop {
                match body.data().await {
                    Some(Ok(data)) => received += data.len(),
                    Some(Err(err)) => return err.reason(),
                    None => return None,
                }
            }
        })
        .await;
        match ended {
            Ok(reason) => (received, Some(reason.unwrap_or(h2::Reason::NO_ERROR))),
            Err(_) => (received, None),
        }
    }

    /// The reproduction: with no bound, a client that keeps its connection
    /// alive but never opens its window parks the response pipe on send
    /// capacity forever, holding the response body.
    #[tokio::test(start_paused = true)]
    async fn without_the_bound_a_closed_window_holds_the_response_forever() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (body, dropped) = streaming(None);
        let body = Mutex::new(Some(body));
        serve(server_io, true, None, None, move || {
            body.lock().unwrap().take().expect("one request")
        });
        let mut sender = client(client_io, 65_535).await;
        let mut stream = get(&mut sender).await;

        let (received, reset) = drain_withholding_window(&mut stream, TIMEOUT * 10).await;
        assert_eq!(reset, None, "nothing ends the stalled stream");
        assert_eq!(received, 65_535, "the client's whole window was used");
        assert!(!dropped.load(Ordering::SeqCst), "the response body is still held");
    }

    /// With the bound, the stalled stream is reset with `CANCEL` once the
    /// client has granted no window for a whole bound, and the response body
    /// is dropped. The connection stays usable.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_opens_its_window_has_the_response_reset() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (first, first_dropped) = streaming(None);
        let bodies = Mutex::new(vec![Full::new(Bytes::from_static(b"ok")).boxed(), first]);
        serve(server_io, true, Some(TIMEOUT), None, move || {
            bodies.lock().unwrap().pop().expect("two requests")
        });
        let mut sender = client(client_io, 65_535).await;
        let mut stream = get(&mut sender).await;

        let started = tokio::time::Instant::now();
        let (received, reset) = drain_withholding_window(&mut stream, TIMEOUT * 10).await;
        assert_eq!(reset, Some(h2::Reason::CANCEL));
        assert_eq!(received, 65_535);
        let elapsed = started.elapsed();
        assert!(elapsed >= TIMEOUT, "reset before a whole bound: {elapsed:?}");
        assert!(elapsed < TIMEOUT * 2, "reset late: {elapsed:?}");
        tokio::task::yield_now().await;
        assert!(first_dropped.load(Ordering::SeqCst), "the response body is released");

        // Only the stream was reset. The connection window is still closed,
        // so ask for a body that needs no window.
        let request = http::Request::get("http://t/").body(()).unwrap();
        let (response, _) = sender.send_request(request, true).expect("second request");
        let response = response.await.expect("the connection still serves");
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    /// A client that keeps opening its window, each time sooner than the
    /// bound, is never cut, however many bounds the response lasts.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_keeps_opening_its_window_is_never_cut() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (body, dropped) = streaming(None);
        let body = Mutex::new(Some(body));
        serve(server_io, true, Some(TIMEOUT), None, move || {
            body.lock().unwrap().take().expect("one request")
        });
        // One frame fills the window; h2 sends a WINDOW_UPDATE as soon as the
        // test releases it.
        let mut sender = client(client_io, CHUNK as u32).await;
        let mut stream = get(&mut sender).await;

        let started = tokio::time::Instant::now();
        let mut received = 0;
        while started.elapsed() < TIMEOUT * 8 {
            let data = stream
                .data()
                .await
                .expect("the stream stays open")
                .expect("the stream is never reset");
            received += data.len();
            tokio::time::sleep(TIMEOUT * 3 / 4).await;
            stream.flow_control().release_capacity(data.len()).unwrap();
        }
        assert!(received >= 4 * CHUNK, "only {received} bytes");
        assert!(!dropped.load(Ordering::SeqCst));
    }

    /// Time spent waiting for the response body is never a stall, even while
    /// the client's window is closed: the pipe holds no chunk.
    #[tokio::test(start_paused = true)]
    async fn an_idle_body_behind_a_closed_window_never_trips_the_bound() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        // Exactly one window's worth, then the body has nothing more.
        let (body, dropped) = streaming(Some(1));
        let body = Mutex::new(Some(body));
        serve(server_io, true, Some(TIMEOUT), None, move || {
            body.lock().unwrap().take().expect("one request")
        });
        let mut sender = client(client_io, CHUNK as u32).await;
        let mut stream = get(&mut sender).await;

        let (received, reset) = drain_withholding_window(&mut stream, TIMEOUT * 10).await;
        assert_eq!(reset, None);
        assert_eq!(received, CHUNK);
        assert!(!dropped.load(Ordering::SeqCst));
    }

    /// A transport the client stops reading, `AsyncRead`-side only, until
    /// the test resumes it.
    struct Pausable<T> {
        inner: T,
        paused: Arc<AtomicBool>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl<T: AsyncRead + Unpin> AsyncRead for Pausable<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.paused.load(Ordering::SeqCst) {
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for Pausable<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A full send buffer with window in hand waits on the transport, which
    /// the bound leaves to whatever bounds the socket: a client with a wide
    /// window that stops reading its socket for many bounds still gets the
    /// whole response once it reads again. Needs the vendored h2 (h2 patch
    /// 003): stock h2 cannot tell the two waits apart.
    #[tokio::test(start_paused = true)]
    async fn a_full_send_buffer_with_window_in_hand_is_not_a_stall() {
        const BODY: usize = 64 * CHUNK;
        const WINDOW: u32 = 8 * 1024 * 1024;
        let (client_io, server_io) = tokio::io::duplex(CHUNK);
        // Many chunks: one handed over fills the send buffer, and the next
        // waits with window in hand while the client reads nothing.
        serve(server_io, true, Some(TIMEOUT), Some(CHUNK), || {
            let frames: Vec<Result<Frame<Bytes>, std::convert::Infallible>> = (0..BODY / CHUNK)
                .map(|_| Ok(Frame::data(Bytes::from(vec![b'x'; CHUNK]))))
                .collect();
            http_body_util::StreamBody::new(futures_util::stream::iter(frames)).boxed()
        });
        let paused = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None::<Waker>));
        let io = Pausable {
            inner: client_io,
            paused: Arc::clone(&paused),
            waker: Arc::clone(&waker),
        };
        let mut sender = client(io, WINDOW).await;
        let request = http::Request::get("http://t/").body(()).unwrap();
        let (response, _) = sender.send_request(request, true).expect("send request");
        let response = response.await.expect("response head");
        paused.store(true, Ordering::SeqCst);

        tokio::time::sleep(TIMEOUT * 10).await;
        paused.store(false, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }

        let mut body = response.into_body();
        let mut received = 0;
        while let Some(data) = body.data().await {
            let data = data.expect("the stream is never reset");
            received += data.len();
            body.flow_control().release_capacity(data.len()).unwrap();
        }
        assert_eq!(received, BODY);
    }

    /// An h2 client on a transport whose reads the test can pause, with a
    /// connection driver that applies each `SETTINGS_INITIAL_WINDOW_SIZE`
    /// sent on the returned channel.
    async fn settings_client(
        io: tokio::io::DuplexStream,
        window: u32,
    ) -> (
        h2::client::SendRequest<Bytes>,
        tokio::sync::mpsc::UnboundedSender<u32>,
        impl Fn(bool),
    ) {
        let paused = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None::<Waker>));
        let io = Pausable {
            inner: io,
            paused: Arc::clone(&paused),
            waker: Arc::clone(&waker),
        };
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(window)
            .initial_connection_window_size(window)
            .handshake::<_, Bytes>(io)
            .await
            .expect("client handshake");
        let (settings_tx, mut settings_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
        tokio::spawn(async move {
            let mut connection = connection;
            let _ = std::future::poll_fn(|cx| {
                while let Poll::Ready(Some(size)) = settings_rx.poll_recv(cx) {
                    connection
                        .set_initial_window_size(size)
                        .expect("change the stream window");
                }
                Pin::new(&mut connection).poll(cx)
            })
            .await;
        });
        let set_paused = move |pause: bool| {
            paused.store(pause, Ordering::SeqCst);
            if !pause {
                if let Some(waker) = waker.lock().unwrap().take() {
                    waker.wake();
                }
            }
        };
        (sender, settings_tx, set_paused)
    }

    /// h2 takes a stream's assigned window back on a
    /// `SETTINGS_INITIAL_WINDOW_SIZE` decrease without waking the body pipe.
    /// A pipe parked on a full send buffer (window in hand, so not timed)
    /// must still find the closed window and reset the stream, and must time
    /// it from when it found it, never from when it parked: the client stops
    /// reading with a wide window, shrinks it to zero, then reads what is in
    /// flight but never grants window again.
    #[tokio::test(start_paused = true)]
    async fn a_window_taken_back_by_settings_still_trips_the_bound() {
        const WINDOW: u32 = 8 * 1024 * 1024;
        let (client_io, server_io) = tokio::io::duplex(CHUNK);
        let (body, dropped) = streaming(None);
        let body = Mutex::new(Some(body));
        serve(server_io, true, Some(TIMEOUT), Some(CHUNK), move || {
            body.lock().unwrap().take().expect("one request")
        });
        let (mut sender, settings, set_paused) = settings_client(client_io, WINDOW).await;
        let mut stream = get(&mut sender).await;

        // Stop reading: the pipe fills the transport and h2's send buffer and
        // parks with window in hand.
        set_paused(true);
        tokio::time::sleep(TIMEOUT / 2).await;
        // Take the window back, then read what is in flight without ever
        // granting more.
        let shrunk = tokio::time::Instant::now();
        settings.send(0).expect("driver alive");
        tokio::time::sleep(TIMEOUT / 10).await;
        set_paused(false);

        let (_, reset) = drain_withholding_window(&mut stream, TIMEOUT * 10).await;
        assert_eq!(reset, Some(h2::Reason::CANCEL));
        // Found at the next wake (at most one bound later), then timed for a
        // whole bound.
        let elapsed = shrunk.elapsed();
        assert!(elapsed >= TIMEOUT, "reset before a whole closed bound: {elapsed:?}");
        assert!(elapsed <= TIMEOUT * 2, "reset late: {elapsed:?}");
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::SeqCst), "the response body is released");
    }

    /// The wakeup kept while the send buffer is full is not a stall start: a
    /// window taken back just before it fires and given back within a bound
    /// never resets the stream.
    #[tokio::test(start_paused = true)]
    async fn a_window_taken_back_briefly_is_not_cut_early() {
        const WINDOW: u32 = 8 * 1024 * 1024;
        let (client_io, server_io) = tokio::io::duplex(CHUNK);
        let (body, dropped) = streaming(None);
        let body = Mutex::new(Some(body));
        serve(server_io, true, Some(TIMEOUT), Some(CHUNK), move || {
            body.lock().unwrap().take().expect("one request")
        });
        let (mut sender, settings, set_paused) = settings_client(client_io, WINDOW).await;
        let mut stream = get(&mut sender).await;

        // The pipe parks on the full send buffer right away and keeps its
        // wakeup about one bound out.
        set_paused(true);
        tokio::time::sleep(TIMEOUT * 9 / 10).await;
        // Take the window back just before that wakeup...
        settings.send(0).expect("driver alive");
        tokio::time::sleep(TIMEOUT / 20).await;
        set_paused(false);
        // ...and give it back eight tenths of a bound later.
        tokio::time::sleep(TIMEOUT * 3 / 4).await;
        settings.send(WINDOW).expect("driver alive");

        for _ in 0..64 {
            let data = stream
                .data()
                .await
                .expect("the stream stays open")
                .expect("the stream is never reset");
            stream.flow_control().release_capacity(data.len()).unwrap();
        }
        assert!(!dropped.load(Ordering::SeqCst));
    }

    /// A bound on a connection with no timer to run it resets each response
    /// with a body before its headers are sent, rather than serving it
    /// unbounded.
    #[tokio::test]
    async fn a_bound_without_a_timer_resets_the_stream() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (body, _dropped) = streaming(None);
        let body = Mutex::new(Some(body));
        serve(server_io, false, Some(TIMEOUT), None, move || {
            body.lock().unwrap().take().expect("one request")
        });
        let mut sender = client(client_io, 65_535).await;
        let request = http::Request::get("http://t/").body(()).unwrap();
        let (response, _) = sender.send_request(request, true).expect("send request");
        let err = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("the stream ends")
            .expect_err("no response is served");
        assert_eq!(err.reason(), Some(h2::Reason::INTERNAL_ERROR));
    }
}
