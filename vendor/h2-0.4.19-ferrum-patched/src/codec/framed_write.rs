use crate::codec::UserError;
use crate::codec::UserError::*;
use crate::frame::{self, Frame, FrameSize};
use crate::hpack;

use bytes::{Buf, BufMut, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;

use std::io::{self, Cursor};

// A macro to get around a method needing to borrow &mut self
macro_rules! limited_write_buf {
    ($self:expr) => {{
        let limit = $self.max_frame_size() + frame::HEADER_LEN;
        $self.buf.get_mut().limit(limit)
    }};
}

#[derive(Debug)]
pub struct FramedWrite<T, B> {
    /// Upstream `AsyncWrite`
    inner: T,
    final_flush_done: bool,

    encoder: Encoder<B>,
}

#[derive(Debug)]
struct Encoder<B> {
    /// HPACK encoder
    hpack: hpack::Encoder,

    /// Write buffer
    ///
    /// TODO: Should this be a ring buffer?
    buf: Cursor<BytesMut>,

    /// Next frame to encode
    next: Option<Next<B>>,

    /// Last data frame
    last_data_frame: Option<frame::Data<B>>,

    /// Max frame size, this is specified by the peer
    max_frame_size: FrameSize,

    /// Chain payloads bigger than this.
    chain_threshold: usize,

    /// Min buffer required to attempt to write a frame
    min_buffer_capacity: usize,

    /// Test-only: the buffer grew to coalesce DATA frames at least once.
    #[cfg(test)]
    grew_to_coalesce: bool,
}

#[derive(Debug)]
enum Next<B> {
    Data(frame::Data<B>),
    Continuation(frame::Continuation),
}

/// Initialize the connection with this amount of write buffer.
///
/// The minimum MAX_FRAME_SIZE is 16kb, so always be able to send a HEADERS
/// frame that big.
const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1_024;

/// Chain payloads bigger than this when vectored I/O is enabled. The remote
/// will never advertise a max frame size less than this (well, the spec says
/// the max frame size can't be less than 16kb, so not even close).
const CHAIN_THRESHOLD: usize = 256;

/// Chain payloads bigger than this when vectored I/O is **not** enabled.
/// A larger value in this scenario will reduce the number of small and
/// fragmented data being sent, and hereby improve the throughput.
const CHAIN_THRESHOLD_WITHOUT_VECTORED_IO: usize = 1024;

/// FERRUM PATCH (h2-001-coalesce-data-frame-writes): copy a DATA payload into
/// the write buffer, instead of chaining it as the single in-flight frame,
/// while the buffer stays within about this many bytes. (Control frames
/// encoded after the copied DATA can take it past the limit, by at most one
/// frame.)
///
/// Chaining holds one DATA frame at a time, so every frame cost its own
/// write: one `writev` per frame, and over TLS one extra short record per
/// maximum-size frame (a 16 KiB payload plus its 9-byte header is 9 bytes too
/// long for one record). Copying lets the frames popped in one pass, across
/// streams, leave in one write, as an event-loop proxy batches them. Larger
/// payloads are still chained without a copy. Upstream tracks the same
/// problem as hyperium/h2#902; hyperium/h2#903 batches frames without
/// copying.
const COALESCE_LIMIT: usize = 64 * 1_024;

// TODO: Make generic
impl<T, B> FramedWrite<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    pub fn new(inner: T) -> FramedWrite<T, B> {
        let chain_threshold = if inner.is_write_vectored() {
            CHAIN_THRESHOLD
        } else {
            CHAIN_THRESHOLD_WITHOUT_VECTORED_IO
        };
        FramedWrite {
            inner,
            final_flush_done: false,
            encoder: Encoder {
                hpack: hpack::Encoder::default(),
                buf: Cursor::new(BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY)),
                next: None,
                last_data_frame: None,
                max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
                chain_threshold,
                min_buffer_capacity: chain_threshold + frame::HEADER_LEN,
                #[cfg(test)]
                grew_to_coalesce: false,
            },
        }
    }

    /// Returns `Ready` when `send` is able to accept a frame
    ///
    /// Calling this function may result in the current contents of the buffer
    /// to be flushed to `T`.
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.encoder.has_capacity() {
            // Try flushing
            ready!(self.flush(cx))?;

            if !self.encoder.has_capacity() {
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Returns whether a frame can be buffered without first flushing the
    /// underlying I/O object.
    pub(crate) fn has_capacity(&self) -> bool {
        self.encoder.has_capacity()
    }

    /// Buffer a frame.
    ///
    /// `poll_ready` must be called first to ensure that a frame may be
    /// accepted.
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        self.encoder.buffer(item)
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let span = tracing::trace_span!("FramedWrite::flush");
        let _e = span.enter();

        loop {
            while !self.encoder.is_empty() {
                let n = match self.encoder.next {
                    Some(Next::Data(ref mut frame)) => {
                        tracing::trace!(queued_data_frame = true);
                        let mut buf = (&mut self.encoder.buf).chain(frame.payload_mut());
                        ready!(poll_write_buf(Pin::new(&mut self.inner), cx, &mut buf))?
                    }
                    _ => {
                        tracing::trace!(queued_data_frame = false);
                        ready!(poll_write_buf(
                            Pin::new(&mut self.inner),
                            cx,
                            &mut self.encoder.buf
                        ))?
                    }
                };
                if n == 0 {
                    // No progress is possible; retrying would busy-loop.
                    tracing::trace!("write returned zero, but non-zero bytes remaining");
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }

            match self.encoder.unset_frame() {
                ControlFlow::Continue => (),
                ControlFlow::Break => break,
            }
        }

        tracing::trace!("flushing buffer");
        // Flush the upstream
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    /// Close the codec
    pub fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.final_flush_done {
            ready!(self.flush(cx))?;
            self.final_flush_done = true;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[must_use]
enum ControlFlow {
    Continue,
    Break,
}

impl<B> Encoder<B>
where
    B: Buf,
{
    fn unset_frame(&mut self) -> ControlFlow {
        // Clear internal buffer
        self.buf.set_position(0);
        self.buf.get_mut().clear();

        // The data frame has been written, so unset it
        match self.next.take() {
            Some(Next::Data(frame)) => {
                self.last_data_frame = Some(frame);
                debug_assert!(self.is_empty());
                ControlFlow::Break
            }
            Some(Next::Continuation(frame)) => {
                // Buffer the continuation frame, then try to write again
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = frame.encode(&mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
                ControlFlow::Continue
            }
            None => ControlFlow::Break,
        }
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        // Ensure that we have enough capacity to accept the write.
        assert!(self.has_capacity());
        let span = tracing::trace_span!("FramedWrite::buffer", frame = ?item);
        let _e = span.enter();

        tracing::debug!(frame = ?item, "send");

        match item {
            Frame::Data(mut v) => {
                // Ensure that the payload is not greater than the max frame.
                let len = v.payload().remaining();

                if len > self.max_frame_size() {
                    return Err(PayloadTooBig);
                }

                let buf_len = self.buf.get_ref().len();
                if len >= self.chain_threshold
                    && buf_len + frame::HEADER_LEN + len <= COALESCE_LIMIT
                {
                    // FERRUM PATCH: coalesce. Grow once, straight to the
                    // limit, rather than by doubling across several frames.
                    let buf = self.buf.get_mut();
                    if buf.capacity() - buf_len < frame::HEADER_LEN + len {
                        buf.reserve(COALESCE_LIMIT - buf_len);
                        #[cfg(test)]
                        {
                            self.grew_to_coalesce = true;
                        }
                    }
                    v.encode_chunk(buf);
                    // Fully copied, so the frame is complete once buffered,
                    // the same as a frame under the chain threshold.
                    self.last_data_frame = Some(v);
                } else if len >= self.chain_threshold {
                    let head = v.head();

                    // Encode the frame head to the buffer
                    head.encode(len, self.buf.get_mut());

                    if self.buf.get_ref().remaining() < self.chain_threshold {
                        let extra_bytes = self.chain_threshold - self.buf.remaining();
                        self.buf.get_mut().put(v.payload_mut().take(extra_bytes));
                    }

                    // Save the data frame
                    self.next = Some(Next::Data(v));
                } else {
                    v.encode_chunk(self.buf.get_mut());

                    // The chunk has been fully encoded, so there is no need to
                    // keep it around
                    assert_eq!(v.payload().remaining(), 0, "chunk not fully encoded");

                    // Save off the last frame...
                    self.last_data_frame = Some(v);
                }
            }
            Frame::Headers(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::PushPromise(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::Settings(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded settings");
            }
            Frame::GoAway(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded go_away");
            }
            Frame::Ping(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded ping");
            }
            Frame::WindowUpdate(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded window_update");
            }

            Frame::Priority(_) => {
                /*
                v.encode(self.buf.get_mut());
                tracing::trace!("encoded priority; rem={:?}", self.buf.remaining());
                */
                unimplemented!();
            }
            Frame::Reset(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded reset");
            }
        }

        Ok(())
    }

    fn has_capacity(&self) -> bool {
        let buf = self.buf.get_ref();
        // FERRUM PATCH: the buffer may grow up to `COALESCE_LIMIT`, so room
        // under that limit counts even before the allocation exists.
        self.next.is_none()
            && (buf.capacity() - buf.len() >= self.min_buffer_capacity
                || buf.len() + self.min_buffer_capacity <= COALESCE_LIMIT)
    }

    fn is_empty(&self) -> bool {
        match self.next {
            Some(Next::Data(ref frame)) => !frame.payload().has_remaining(),
            _ => !self.buf.has_remaining(),
        }
    }
}

impl<B> Encoder<B> {
    fn max_frame_size(&self) -> usize {
        self.max_frame_size as usize
    }
}

impl<T, B> FramedWrite<T, B> {
    /// Returns the max frame size that can be sent
    pub fn max_frame_size(&self) -> usize {
        self.encoder.max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(val <= frame::MAX_MAX_FRAME_SIZE as usize);
        self.encoder.max_frame_size = val as FrameSize;
    }

    /// Set the peer's header table size.
    pub fn set_header_table_size(&mut self, val: usize) {
        self.encoder.hpack.update_max_size(val);
    }

    /// Retrieve the last data frame that has been sent
    pub fn take_last_data_frame(&mut self) -> Option<frame::Data<B>> {
        self.encoder.last_data_frame.take()
    }

    /// FERRUM PATCH: drop a write buffer that grew to coalesce DATA frames,
    /// once everything in it has been written. Called when the connection has
    /// nothing more to write, so a busy connection keeps one grown buffer
    /// across writes and an idle one holds only the initial 16 KiB.
    pub(crate) fn shrink_if_idle(&mut self) {
        let buf = self.encoder.buf.get_ref();
        if self.encoder.next.is_none()
            && buf.is_empty()
            && buf.capacity() > DEFAULT_BUFFER_CAPACITY
        {
            self.encoder.buf = Cursor::new(BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY));
        }
    }

    /// Test-only view of the write buffer: (capacity, whether it ever grew to
    /// coalesce).
    #[cfg(test)]
    pub(crate) fn write_buf_state(&self) -> (usize, bool) {
        (self.encoder.buf.get_ref().capacity(), self.encoder.grew_to_coalesce)
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + Unpin, B> AsyncRead for FramedWrite<T, B> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// We never project the Pin to `B`.
impl<T: Unpin, B> Unpin for FramedWrite<T, B> {}

#[cfg(feature = "unstable")]
mod unstable {
    use super::*;

    impl<T, B> FramedWrite<T, B> {
        pub fn get_ref(&self) -> &T {
            &self.inner
        }
    }
}

#[cfg(test)]
mod ferrum_coalesce_data_frame_writes_tests {
    //! FERRUM PATCH (h2-001-coalesce-data-frame-writes).
    use super::*;
    use bytes::Bytes;
    use std::sync::{Arc, Mutex};

    /// Records every write call; accepts everything.
    struct RecordingIo {
        vectored: bool,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncWrite for RecordingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let joined: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
            let n = joined.len();
            self.writes.lock().unwrap().push(joined);
            Poll::Ready(Ok(n))
        }

        fn is_write_vectored(&self) -> bool {
            self.vectored
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn framed(vectored: bool) -> (FramedWrite<RecordingIo, Bytes>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let io = RecordingIo {
            vectored,
            writes: Arc::clone(&writes),
        };
        let mut framed = FramedWrite::new(io);
        framed.set_max_frame_size(frame::MAX_MAX_FRAME_SIZE as usize);
        (framed, writes)
    }

    fn data(stream: u32, len: usize, fill: u8) -> Frame<Bytes> {
        frame::Data::new(stream.into(), Bytes::from(vec![fill; len])).into()
    }

    /// Wire bytes of one DATA frame without flags.
    fn wire(stream: u32, len: usize, fill: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(frame::HEADER_LEN + len);
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
        out.push(0x0); // DATA
        out.push(0x0); // no flags
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend(std::iter::repeat(fill).take(len));
        out
    }

    /// Buffer every frame the way `Prioritize::buffer_pending` does (checking
    /// capacity and taking back the completed frame), flushing whenever the
    /// codec is full, then flush the rest.
    fn send_all(framed: &mut FramedWrite<RecordingIo, Bytes>, frames: Vec<Frame<Bytes>>) {
        let waker = futures_util_noop_waker();
        let mut cx = Context::from_waker(&waker);
        for f in frames {
            while !framed.has_capacity() {
                assert!(framed.flush(&mut cx).is_ready());
                let _ = framed.take_last_data_frame();
            }
            framed.buffer(f).unwrap();
            let _ = framed.take_last_data_frame();
        }
        assert!(framed.flush(&mut cx).is_ready());
        let _ = framed.take_last_data_frame();
    }

    /// Compare recorded writes by size and content without dumping payloads.
    fn assert_writes(writes: &[Vec<u8>], expected: &[Vec<u8>], what: &str) {
        let sizes: Vec<usize> = writes.iter().map(Vec::len).collect();
        let want: Vec<usize> = expected.iter().map(Vec::len).collect();
        assert_eq!(sizes, want, "{what}: write sizes");
        assert!(writes == expected, "{what}: write contents differ");
    }

    fn futures_util_noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable};
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: every vtable entry ignores the data pointer.
        unsafe { std::task::Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn data_frames_within_the_limit_leave_in_one_write() {
        for vectored in [true, false] {
            let (mut framed, writes) = framed(vectored);
            send_all(
                &mut framed,
                vec![data(1, 16_384, b'a'), data(3, 16_384, b'b'), data(1, 10_000, b'c')],
            );
            let mut expected = wire(1, 16_384, b'a');
            expected.extend(wire(3, 16_384, b'b'));
            expected.extend(wire(1, 10_000, b'c'));
            assert_writes(&writes.lock().unwrap(), &[expected], &format!("vectored={vectored}"));
        }
    }

    /// A frame that no longer fits is chained behind the copied ones, so with
    /// vectored I/O both still leave in one write, and the third frame waits
    /// for the next one.
    #[test]
    fn a_frame_past_the_limit_is_chained_behind_the_copied_ones() {
        let (mut framed, writes) = framed(true);
        send_all(
            &mut framed,
            vec![data(1, 40_000, b'a'), data(1, 40_000, b'b'), data(1, 1_000, b'c')],
        );
        let mut first = wire(1, 40_000, b'a');
        first.extend(wire(1, 40_000, b'b'));
        assert_writes(&writes.lock().unwrap(), &[first, wire(1, 1_000, b'c')], "vectored");
    }

    #[test]
    fn a_frame_larger_than_the_limit_is_chained_whole() {
        let (mut framed, writes) = framed(true);
        send_all(&mut framed, vec![data(5, 100_000, b'z')]);
        assert_writes(&writes.lock().unwrap(), &[wire(5, 100_000, b'z')], "large frame");
        assert!(framed.encoder.buf.get_ref().capacity() <= DEFAULT_BUFFER_CAPACITY);
    }

    /// A grown buffer survives a write (no reallocation per batch); it is
    /// dropped by `shrink_if_idle` only once nothing is left to write.
    #[test]
    fn a_grown_buffer_is_kept_across_writes_and_dropped_when_idle() {
        let (mut framed, _writes) = framed(true);
        send_all(&mut framed, vec![data(1, 30_000, b'a'), data(3, 30_000, b'b')]);
        assert!(framed.encoder.buf.get_ref().is_empty());
        assert!(framed.encoder.buf.get_ref().capacity() >= COALESCE_LIMIT);
        send_all(&mut framed, vec![data(1, 1_000, b'c')]);
        assert!(framed.encoder.buf.get_ref().capacity() >= COALESCE_LIMIT);

        // Unwritten bytes are never dropped.
        framed.buffer(data(1, 30_000, b'd')).unwrap();
        let _ = framed.take_last_data_frame();
        framed.shrink_if_idle();
        assert_eq!(framed.encoder.buf.get_ref().len(), frame::HEADER_LEN + 30_000);

        send_all(&mut framed, vec![]);
        framed.shrink_if_idle();
        assert!(framed.encoder.buf.get_ref().is_empty());
        assert!(framed.encoder.buf.get_ref().capacity() <= DEFAULT_BUFFER_CAPACITY);
    }

    /// End to end: a client connection that uploaded a bulk body, which grew
    /// its write buffer to coalesce DATA frames, holds only the initial
    /// buffer once it goes idle. Ferrum's frontend sets no keepalive, so an
    /// idle connection may never write again.
    #[tokio::test]
    async fn an_idle_connection_holds_only_the_initial_write_buffer() {
        use std::future::{poll_fn, Future};

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut conn = crate::server::Builder::new()
                .initial_window_size(1 << 20)
                .initial_connection_window_size(1 << 20)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            // The server connection only makes progress while `accept` is
            // polled, so each request is handled on its own task.
            while let Some(request) = conn.accept().await {
                let (request, mut respond) = request.unwrap();
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                    }
                    respond
                        .send_response(http::Response::new(()), true)
                        .unwrap();
                });
            }
        });

        let (client, mut conn) = crate::client::handshake(client_io).await.unwrap();
        let exchange = async move {
            let mut client = client.ready().await.unwrap();
            let request = http::Request::post("https://example.com/").body(()).unwrap();
            let (response, mut stream) = client.send_request(request, false).unwrap();
            stream.send_data(Bytes::from(vec![b'x'; 512 * 1024]), true).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            client
        };
        tokio::pin!(exchange);
        let client = loop {
            tokio::select! {
                client = &mut exchange => break client,
                result = poll_fn(|cx| std::pin::Pin::new(&mut conn).poll(cx)) => {
                    panic!("connection ended early: {result:?}")
                }
            }
        };
        // Let the connection drain everything it still has to write.
        for _ in 0..8 {
            poll_fn(|cx| {
                let _ = std::pin::Pin::new(&mut conn).poll(cx);
                Poll::Ready(())
            })
            .await;
            tokio::task::yield_now().await;
        }
        let (capacity, grew) = conn.write_buf_state();
        assert!(grew, "the bulk upload must have coalesced DATA frames");
        assert!(
            capacity <= DEFAULT_BUFFER_CAPACITY,
            "an idle connection kept a {capacity}-byte write buffer"
        );
        drop(client);
        drop(conn);
        server.await.unwrap();
    }

    /// The limit is inclusive: a frame that brings the buffer to exactly
    /// `COALESCE_LIMIT` bytes is copied, one byte more is chained.
    #[test]
    fn the_limit_is_inclusive() {
        let fits = COALESCE_LIMIT - frame::HEADER_LEN;
        let (mut copied, _writes) = framed(true);
        copied.buffer(data(1, fits, b'a')).unwrap();
        assert!(copied.encoder.next.is_none(), "a frame filling the limit is copied");
        assert_eq!(copied.encoder.buf.get_ref().len(), COALESCE_LIMIT);
        assert!(copied.take_last_data_frame().is_some());

        let (mut chained, _writes) = framed(true);
        chained.buffer(data(1, fits + 1, b'a')).unwrap();
        assert!(
            matches!(chained.encoder.next, Some(Next::Data(_))),
            "one byte over the limit is chained"
        );
        // Stock chaining: the head plus enough payload to reach the chain
        // threshold sit in the buffer, the rest stays in the frame.
        assert_eq!(chained.encoder.buf.get_ref().len(), chained.encoder.chain_threshold);
    }

    /// Without vectored I/O a chained frame still goes out whole and in order.
    #[test]
    fn a_chained_frame_without_vectored_io_is_written_whole() {
        let (mut framed, writes) = framed(false);
        send_all(&mut framed, vec![data(1, 2_000, b'a'), data(1, 100_000, b'b')]);
        let joined: Vec<u8> = writes.lock().unwrap().concat();
        let mut expected = wire(1, 2_000, b'a');
        expected.extend(wire(1, 100_000, b'b'));
        assert_eq!(joined.len(), expected.len());
        assert!(joined == expected, "non-vectored chained bytes differ");
    }

    /// A transport that takes at most `max` bytes per call and answers every
    /// other call with `Pending` (waking itself).
    struct ChokedIo {
        max: usize,
        pend: bool,
        written: Vec<u8>,
    }

    impl AsyncWrite for ChokedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.pend = !self.pend;
            if self.pend {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.len().min(self.max);
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Partial writes and `Pending` neither lose, duplicate nor reorder bytes,
    /// and new frames are refused until the coalesced batch has drained.
    #[test]
    fn partial_writes_and_pending_keep_the_byte_stream_intact() {
        let waker = futures_util_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let io = ChokedIo {
            max: 1_000,
            pend: false,
            written: Vec::new(),
        };
        let mut framed: FramedWrite<ChokedIo, Bytes> = FramedWrite::new(io);
        framed.set_max_frame_size(frame::MAX_MAX_FRAME_SIZE as usize);
        let frames = vec![
            data(1, 20_000, b'a'),
            data(3, 20_000, b'b'),
            data(5, 30_000, b'c'),
            data(1, 7, b'd'),
        ];
        let mut expected = Vec::new();
        for (stream, len, fill) in [(1, 20_000, b'a'), (3, 20_000, b'b'), (5, 30_000, b'c'), (1, 7, b'd')] {
            expected.extend(wire(stream, len, fill));
        }
        for f in frames {
            while !framed.has_capacity() {
                while framed.flush(&mut cx).is_pending() {}
                let _ = framed.take_last_data_frame();
            }
            framed.buffer(f).unwrap();
            if let Some(reclaimed) = framed.take_last_data_frame() {
                assert!(!reclaimed.payload().has_remaining());
            }
        }
        while framed.flush(&mut cx).is_pending() {}
        let _ = framed.take_last_data_frame();
        let written = &framed.get_mut().written;
        assert_eq!(written.len(), expected.len());
        assert!(*written == expected, "partial-write byte stream differs");
    }

    /// (type, flags, stream id, payload length) of every frame in `bytes`.
    fn frame_heads(bytes: &[u8]) -> Vec<(u8, u8, u32, usize)> {
        let mut heads = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let len = u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]]) as usize;
            let stream = u32::from_be_bytes([
                bytes[at + 5] & 0x7f,
                bytes[at + 6],
                bytes[at + 7],
                bytes[at + 8],
            ]);
            heads.push((bytes[at + 3], bytes[at + 4], stream, len));
            at += frame::HEADER_LEN + len;
        }
        assert_eq!(at, bytes.len(), "trailing partial frame");
        heads
    }

    /// Control frames buffered between copied DATA frames keep their order,
    /// and END_STREAM survives the copy.
    #[test]
    fn control_frames_interleave_in_order_and_end_stream_is_kept() {
        let (mut framed, writes) = framed(true);
        let headers = frame::Headers::new(
            1.into(),
            frame::Pseudo::response(http::StatusCode::OK),
            http::HeaderMap::new(),
        );
        let mut last = frame::Data::new(3.into(), Bytes::from(vec![b'z'; 3_000]));
        last.set_end_stream(true);
        send_all(
            &mut framed,
            vec![
                headers.into(),
                data(1, 10_000, b'a'),
                frame::Reset::new(5.into(), frame::Reason::CANCEL).into(),
                frame::Ping::new([7; 8]).into(),
                frame::WindowUpdate::new(0.into(), 65_535).into(),
                last.into(),
            ],
        );
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "everything leaves in one write");
        let heads = frame_heads(&writes[0]);
        let kinds: Vec<u8> = heads.iter().map(|h| h.0).collect();
        // HEADERS, DATA, RST_STREAM, PING, WINDOW_UPDATE, DATA
        assert_eq!(kinds, vec![0x1, 0x0, 0x3, 0x6, 0x8, 0x0]);
        assert_eq!(heads[1], (0x0, 0x0, 1, 10_000));
        assert_eq!(heads[5], (0x0, 0x1, 3, 3_000), "END_STREAM flag kept");
    }

    #[test]
    fn a_copied_frame_is_handed_back_fully_consumed() {
        let (mut framed, _writes) = framed(true);
        framed.buffer(data(1, 20_000, b'a')).unwrap();
        let reclaimed = framed.take_last_data_frame().expect("copied frame");
        assert!(!reclaimed.payload().has_remaining());
        assert!(framed.has_capacity());
    }
}
