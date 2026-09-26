use std::future::Future;
use std::task::{Context, Poll};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
    // A connection error observed while frame bytes were still buffered.
    // Those bytes are delivered first, then this error is surfaced exactly once.
    pending_quic_error: Option<FrameStreamError>,
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self::with_max_buffered_frame_len(stream, FrameDecoder::UNBOUNDED_FRAME_LEN)
    }

    /// Build a [`FrameStream`] whose decoder refuses any non-`DATA` frame that
    /// declares more than `max_buffered_frame_len` payload bytes.
    ///
    /// [`FrameDecoder::UNBOUNDED_FRAME_LEN`] reproduces [`FrameStream::new`].
    pub fn with_max_buffered_frame_len(
        stream: BufRecvStream<S, B>,
        max_buffered_frame_len: u64,
    ) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::with_max_buffered_frame_len(max_buffered_frame_len),
            remaining_data: 0,
            pending_quic_error: None,
        }
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> crate::quic::SendStreamStopped for FrameStream<S, B>
where
    S: crate::quic::SendStreamStopped,
{
    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<u64>, StreamErrorIncoming>> + Send + 'static {
        self.stream.stopped()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            // A connection error must not discard frames that are already buffered: defer it
            // until they are decoded. Any other error, notably a peer stream reset, surfaces now.
            // While an error is pending the transport is not polled again.
            let end = if self.pending_quic_error.is_some() {
                Poll::Ready(true)
            } else {
                match self.try_recv(cx) {
                    Poll::Ready(Ok(end)) => Poll::Ready(end),
                    Poll::Ready(Err(e)) if e.is_connection_error() => {
                        self.pending_quic_error = Some(e);
                        Poll::Ready(true)
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            };

            return match self.decoder.decode(self.stream.buf_mut())? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))))
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    Poll::Ready(Ok(frame))
                }
                Some(frame) => Poll::Ready(Ok(Some(frame))),
                None => match end {
                    // Received a chunk but frame is incomplete, poll until we get `Pending`.
                    Poll::Ready(false) => continue,
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(true) => {
                        if let Some(error) = self.pending_quic_error.take() {
                            // Every buffered frame has been delivered: surface the deferred
                            // connection error.
                            Poll::Ready(Err(error))
                        } else if self.stream.buf_mut().has_remaining() {
                            // Reached the end of receive stream, but there is still some data:
                            // The frame is incomplete.
                            Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
                        } else {
                            Poll::Ready(Ok(None))
                        }
                    }
                },
            };
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        // A connection error must not discard body bytes that are already buffered: defer it
        // until they are drained. Any other error, notably a peer stream reset, surfaces now.
        let end = if self.pending_quic_error.is_some() {
            true
        } else {
            match self.try_recv(cx) {
                Poll::Ready(Ok(end)) => end,
                Poll::Ready(Err(e)) if e.is_connection_error() => {
                    self.pending_quic_error = Some(e);
                    true
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => false,
            }
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            (None, true) => match self.pending_quic_error.take() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(None)),
            },
            (None, false) => Poll::Pending,
            // The stream finished cleanly in the middle of the frame. After a connection
            // error, the partial body is delivered and the connection error follows instead.
            (Some(d), true)
                if self.pending_quic_error.is_none()
                    && d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        let max_buffered_frame_len = self.decoder.max_buffered_frame_len;
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::with_max_buffered_frame_len(max_buffered_frame_len),
                remaining_data: 0,
                pending_quic_error: None,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
                pending_quic_error: self.pending_quic_error,
            },
        )
    }
}

pub struct FrameDecoder {
    expected: Option<usize>,
    /// Receive-side ceiling on the DECLARED payload length of a non-`DATA`
    /// frame, which this decoder has to accumulate whole before it can be
    /// interpreted. Without it a peer can declare a 2^62-1 length and stream
    /// bytes into `BufList` forever: QUIC flow control caps bytes IN FLIGHT,
    /// and every poll here consumes from the stream and re-grants credit.
    ///
    /// Defaults to [`FrameDecoder::UNBOUNDED_FRAME_LEN`], which is stock
    /// upstream behaviour, so the bound only applies to callers that opt in.
    max_buffered_frame_len: u64,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::with_max_buffered_frame_len(Self::UNBOUNDED_FRAME_LEN)
    }
}

impl FrameDecoder {
    /// The ceiling value that applies no receive-side bound beyond what the
    /// platform can address.
    pub const UNBOUNDED_FRAME_LEN: u64 = u64::MAX;

    /// Build a decoder that refuses any non-`DATA` frame declaring more than
    /// `max_buffered_frame_len` payload bytes.
    pub fn with_max_buffered_frame_len(max_buffered_frame_len: u64) -> Self {
        Self {
            expected: None,
            max_buffered_frame_len,
        }
    }

    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Decode in a loop since we ignore unknown frames, and there may be
        // other frames already in our BufList.
        loop {
            if !src.has_remaining() {
                return Ok(None);
            }

            if let Some(min) = self.expected {
                if src.remaining() < min {
                    return Ok(None);
                }
            }

            let (pos, decoded) = {
                let mut cur = src.cursor();
                let decoded = Frame::decode_bounded(&mut cur, self.max_buffered_frame_len);
                (cur.position(), decoded)
            };

            match decoded {
                Err(frame::FrameError::UnknownFrame(_ty)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                    //# Endpoints MUST
                    //# NOT consider these frames to have any meaning upon receipt.
                    #[cfg(feature = "tracing")]
                    trace!("ignore unknown frame type {:#x}", _ty);

                    src.advance(pos);
                    self.expected = None;
                    continue;
                }
                Err(frame::FrameError::Incomplete(min)) => {
                    self.expected = Some(min);
                    return Ok(None);
                }
                Ok(frame) => {
                    src.advance(pos);
                    self.expected = None;
                    return Ok(Some(frame));
                }
                // -------------- Map the error Values --------------
                Err(frame::FrameError::InvalidStreamId(e)) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidStreamId(e),
                    ));
                }
                Err(frame::FrameError::InvalidPushId(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::InvalidPushId(
                        e,
                    )));
                }
                Err(frame::FrameError::Settings(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)));
                }
                Err(frame::FrameError::UnsupportedFrame(ty)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                        ty,
                    )));
                }
                Err(frame::FrameError::InvalidFrameValue) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidFrameValue,
                    ));
                }
                Err(frame::FrameError::Malformed) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
                // Refused on the DECLARED length: `src` is left untouched and
                // `self.expected` is never set, so not one payload byte of the
                // offending frame is retained.
                Err(frame::FrameError::ExceedsMaxBufferedLen { ty, len, max }) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::ExceedsMaxBufferedFrameLen { ty, len, max },
                    ));
                }
            }
        }
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
}

impl FrameStreamError {
    /// Whether this error closed the whole QUIC connection, not just this stream.
    ///
    /// Only a connection error is deferred behind buffered bytes. A peer stream reset is
    /// reported once and frees the stream, and RFC 9114 section 7.1 only treats a truncated
    /// frame as a connection error when the stream terminates cleanly. Holding a reset back
    /// would turn a DATA frame it truncated into `UnexpectedEnd`, a connection-level
    /// H3_FRAME_ERROR that tears down every other stream on the connection.
    ///
    /// Every other stream-level error surfaces immediately too. h3-quinn maps a read of
    /// rejected 0-RTT data (`ZeroRttRejected`) and a read of a freed stream (`ClosedStream`)
    /// to `Unknown`: deferring those would hand the application bytes the transport has
    /// already disowned, such as data from rejected 0-RTT.
    fn is_connection_error(&self) -> bool {
        matches!(
            self,
            FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming { .. })
        )
    }
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
    /// A non-`DATA` frame declared more payload than the receive-side ceiling
    /// permits this decoder to buffer, or more than the platform can address.
    ExceedsMaxBufferedFrameLen {
        /// The frame type varint as received.
        ty: u64,
        /// The declared payload length as received.
        len: u64,
        /// The ceiling that was applied.
        max: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};
    use crate::quic::ConnectionErrorIncoming;

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // ---------------------------------------------------------------
    // Receive-side buffered non-DATA frame ceiling (Ferrum patch 005)
    // ---------------------------------------------------------------

    /// Largest length a QUIC variable-length integer can carry.
    const QUIC_VARINT_MAX: u64 = (1 << 62) - 1;

    const FRAME_TYPE_DATA: u64 = 0x00;
    const FRAME_TYPE_HEADERS: u64 = 0x01;
    const FRAME_TYPE_SETTINGS: u64 = 0x04;
    /// A reserved "grease" type: unknown to h3, so the decoder's skip arm.
    const FRAME_TYPE_UNKNOWN: u64 = 0x21;

    /// Encode only a frame header: the type varint followed by a DECLARED
    /// payload length. No payload byte follows, which is exactly the attacker
    /// shape — declare an enormous frame, then stream bytes forever.
    fn declared_frame_header(ty: u64, len: u64) -> BytesMut {
        use crate::proto::varint::BufMutExt;

        let mut buf = BytesMut::with_capacity(32);
        buf.write_var(ty);
        buf.write_var(len);
        buf
    }

    /// A HEADERS frame whose DECLARED length is above the ceiling must be
    /// refused the moment its length varint is decoded: no payload byte is
    /// buffered, the source buffer is left untouched, and no accumulation
    /// target is armed.
    #[test]
    fn oversized_declared_headers_frame_is_refused_without_buffering() {
        let header = declared_frame_header(FRAME_TYPE_HEADERS, QUIC_VARINT_MAX);
        let header_len = header.len();
        let mut buf = BufList::from(header);

        let mut decoder = FrameDecoder::with_max_buffered_frame_len(16 * 1024);

        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(
                FrameProtocolError::ExceedsMaxBufferedFrameLen {
                    ty: FRAME_TYPE_HEADERS,
                    len: QUIC_VARINT_MAX,
                    max: 16_384,
                }
            ))
        );
        // Nothing was consumed and, crucially, nothing was retained: the
        // decoder did not arm `expected`, so `FrameStream` will not keep
        // pulling QUIC chunks into its `BufList` waiting for the payload.
        assert_eq!(buf.remaining(), header_len);
        assert_eq!(decoder.expected, None);
    }

    /// Same refusal on the peer control stream, where SETTINGS and GOAWAY are
    /// decoded by an identically bounded `FrameDecoder`.
    #[test]
    fn oversized_declared_settings_frame_is_refused_without_buffering() {
        let mut buf = BufList::from(declared_frame_header(FRAME_TYPE_SETTINGS, 1 << 40));

        let mut decoder = FrameDecoder::with_max_buffered_frame_len(4096);

        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(
                FrameProtocolError::ExceedsMaxBufferedFrameLen { .. }
            ))
        );
        assert_eq!(decoder.expected, None);
    }

    /// The unknown-frame skip arm is reached only AFTER the whole payload is
    /// buffered, so an oversized unknown frame must be refused too rather than
    /// accumulated merely to be discarded.
    #[test]
    fn oversized_declared_unknown_frame_is_refused_rather_than_buffered_to_skip() {
        let mut buf = BufList::from(declared_frame_header(FRAME_TYPE_UNKNOWN, QUIC_VARINT_MAX));

        let mut decoder = FrameDecoder::with_max_buffered_frame_len(64 * 1024);

        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(
                FrameProtocolError::ExceedsMaxBufferedFrameLen {
                    ty: FRAME_TYPE_UNKNOWN,
                    ..
                }
            ))
        );
        assert_eq!(decoder.expected, None);
    }

    /// A declared length exactly AT the ceiling is legal and still decodes.
    #[test]
    fn headers_frame_at_the_max_buffered_frame_len_is_accepted() {
        const CAP: usize = 1024;

        let mut buf = BytesMut::with_capacity(CAP + 16);
        Frame::headers(vec![0x2a_u8; CAP]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::with_max_buffered_frame_len(CAP as u64);

        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Headers(payload))) if payload.len() == CAP
        );
    }

    /// One byte over the ceiling is refused, so the bound is exact.
    #[test]
    fn headers_frame_one_byte_over_the_max_buffered_frame_len_is_refused() {
        const CAP: usize = 1024;

        let mut buf = BytesMut::with_capacity(CAP + 16);
        Frame::headers(vec![0x2a_u8; CAP + 1]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::with_max_buffered_frame_len(CAP as u64);

        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(
                FrameProtocolError::ExceedsMaxBufferedFrameLen { .. }
            ))
        );
    }

    /// DATA payloads are streamed to the caller, never accumulated by the
    /// decoder, so a request body far larger than the header ceiling must keep
    /// flowing. Bounding it here would break every large upload.
    #[test]
    fn data_frame_length_is_not_bounded_by_max_buffered_frame_len() {
        let declared: u64 = 64 * 1024 * 1024;
        let mut buf = BufList::from(declared_frame_header(FRAME_TYPE_DATA, declared));

        let mut decoder = FrameDecoder::with_max_buffered_frame_len(16 * 1024);

        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(len)))) if len as u64 == declared
        );
    }

    /// The bound is opt-in: a default decoder reproduces stock upstream
    /// behaviour, parking on the declared length instead of erroring.
    #[test]
    fn default_frame_decoder_keeps_unbounded_upstream_behaviour() {
        let mut buf = BufList::from(declared_frame_header(FRAME_TYPE_HEADERS, 1 << 40));

        let mut decoder = FrameDecoder::default();

        assert_matches!(decoder.decode(&mut buf), Ok(None));
        assert!(decoder.expected.is_some());
    }

    // FrameStream

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    /// End-to-end through `FrameStream`: the refusal surfaces on `poll_next`
    /// and the payload bytes the peer streamed afterwards are never merged
    /// into an accumulation buffer.
    #[tokio::test]
    async fn frame_stream_refuses_oversized_declared_frame_before_accumulating() {
        let mut recv = FakeRecv::default();
        recv.chunk(declared_frame_header(FRAME_TYPE_HEADERS, QUIC_VARINT_MAX).freeze());
        // The attacker keeps writing payload for the frame it declared.
        recv.chunk(Bytes::from(vec![0x5a_u8; 4096]));

        let mut stream: FrameStream<_, ()> =
            FrameStream::with_max_buffered_frame_len(BufRecvStream::new(recv), 16 * 1024);

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Proto(
                FrameProtocolError::ExceedsMaxBufferedFrameLen { .. }
            ))
        );
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    /// Regression: a connection error read while a complete HEADERS frame is still buffered must
    /// not discard it. The `poll_data` that drains the body reads the error with the trailing
    /// HEADERS frame in the buffer.
    #[tokio::test]
    async fn poll_next_drains_buffered_headers_before_quic_close() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), connection_close());
        let transport_polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        // This poll reads the connection error, with the body and the trailers still buffered.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(None));
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(|cx| stream.poll_next(cx), Err(FrameStreamError::Quic(_)));
        // The saved error is surfaced exactly once, without polling the transport again.
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
    }

    /// Regression: h3 0.0.8's `poll_next` polls the transport before it decodes, so it can read
    /// the connection error itself while a complete frame is still buffered. The frame is
    /// delivered, then the error follows exactly once without another transport poll.
    #[tokio::test]
    async fn poll_next_drains_a_buffered_frame_when_it_reads_the_quic_close() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), connection_close());
        let transport_polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        // This poll reads the connection error with the second HEADERS frame still buffered.
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming { .. }))
        );
        assert_eq!(transport_polls.get(), 2);
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
    }

    /// Regression: a connection error must not strand DATA frame body bytes that were buffered
    /// before it arrived, and must still be reported once the body is delivered.
    #[tokio::test]
    async fn poll_data_drains_buffered_body_before_quic_close() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), connection_close());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        // This poll reads the connection error but still returns the buffered body.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        // Otherwise the close would look like a clean end of stream to the caller.
        assert_poll_matches!(|cx| stream.poll_next(cx), Err(FrameStreamError::Quic(_)));
    }

    /// A connection error that truncates a DATA frame delivers the buffered part of the body,
    /// then surfaces as the connection error rather than as `UnexpectedEnd`.
    #[tokio::test]
    async fn poll_data_surfaces_quic_close_over_a_truncated_buffered_body() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        FrameType::DATA.encode(&mut buf);
        VarInt::from(8u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.freeze());
        recv.chunk_then_error(Bytes::from_static(b"dy"), connection_close());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(8))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );
        // This poll reads the connection error with "dy" buffered and the frame 4 bytes short.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming { .. }))
        );
    }

    /// Regression: a peer RESET_STREAM that truncates a DATA frame while part of that frame is
    /// still buffered must surface as the reset. Holding it back to drain the buffer would end
    /// the body in `UnexpectedEnd`, which the request stream escalates to a connection-level
    /// H3_FRAME_ERROR ("received incomplete frame").
    #[tokio::test]
    async fn poll_data_surfaces_stream_reset_over_a_truncated_buffered_body() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        FrameType::DATA.encode(&mut buf);
        VarInt::from(8u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.freeze());
        recv.chunk_then_error(Bytes::from_static(b"dy"), stream_reset());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(8))))
        );
        // This poll pulls "dy" into the buffer behind "bo".
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );
        // The reset arrives with "dy" buffered and the frame 4 bytes short.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { error_code }))
                if error_code == RESET_CODE
        );
    }

    /// Regression: a peer RESET_STREAM read while whole frames are still buffered surfaces as the
    /// reset instead of those frames. Quinn reports a reset only once, so holding it back would
    /// lose its error code.
    #[tokio::test]
    async fn poll_data_surfaces_stream_reset_over_a_buffered_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), stream_reset());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { error_code }))
                if error_code == RESET_CODE
        );
    }

    /// Regression: a peer RESET_STREAM observed by `poll_next` with a decodable frame buffered
    /// surfaces as the reset instead of the frame. Returning the frame first lost the one-shot
    /// reset: the next read of the freed QUIC stream no longer carries its code.
    #[tokio::test]
    async fn poll_next_surfaces_stream_reset_over_a_buffered_frame() {
        let recv = FakeRecv {
            pending_error: Some(stream_reset()),
            ..FakeRecv::default()
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { error_code }))
                if error_code == RESET_CODE
        );
    }

    /// Regression: only a connection error is deferred. h3-quinn reports a read of rejected
    /// 0-RTT data as `Unknown`; deferring it behind the buffered body handed the application
    /// bytes from a 0-RTT flight the server had rejected.
    #[tokio::test]
    async fn poll_data_surfaces_unknown_stream_error_over_a_buffered_body() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        recv.chunk_then_error(buf.freeze(), zero_rtt_rejected());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        // The error is read with the whole body buffered: none of it is delivered.
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(_)))
        );
    }

    /// Regression: the `poll_next` side of the same rule. An `Unknown` stream error read with a
    /// decodable HEADERS frame buffered surfaces ahead of that frame.
    #[tokio::test]
    async fn poll_next_surfaces_unknown_stream_error_over_a_buffered_frame() {
        let recv = FakeRecv {
            pending_error: Some(zero_rtt_rejected()),
            ..FakeRecv::default()
        };
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(_)))
        );
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    // Helpers

    /// `H3_REQUEST_CANCELLED`, the code a peer that cuts a response resets the stream with.
    const RESET_CODE: u64 = 0x010c;

    fn connection_close() -> StreamErrorIncoming {
        StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: ConnectionErrorIncoming::ApplicationClose { error_code: 0x100 },
        }
    }

    fn stream_reset() -> StreamErrorIncoming {
        StreamErrorIncoming::StreamTerminated {
            error_code: RESET_CODE,
        }
    }

    /// The `Unknown` error h3-quinn reports for a read of rejected 0-RTT data.
    fn zero_rtt_rejected() -> StreamErrorIncoming {
        StreamErrorIncoming::Unknown(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "0-RTT rejected",
        )))
    }

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        pending_error: Option<StreamErrorIncoming>,
        poll_count: Rc<Cell<usize>>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }

        /// Queue a last chunk, after which the transport reports `err` instead of the end of the
        /// stream.
        fn chunk_then_error(&mut self, buf: Bytes, err: StreamErrorIncoming) -> &mut Self {
            self.chunks.push_back(buf);
            self.pending_error = Some(err);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.poll_count.set(self.poll_count.get() + 1);
            if let Some(chunk) = self.chunks.pop_front() {
                return Poll::Ready(Ok(Some(chunk)));
            }
            match self.pending_error.take() {
                Some(err) => Poll::Ready(Err(err)),
                None => Poll::Ready(Ok(None)),
            }
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
