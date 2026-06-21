//! Datagram-over-HBONE framing codec (F3 §3.3 Stage 4).
//!
//! HBONE (`src/proxy/hbone_pool.rs`'s `H2ConnectTunnel`) is a bidirectional
//! BYTE stream — it carries no message boundaries (h2 DATA frames split and
//! coalesce freely under flow control). UDP is message-oriented. To tunnel a
//! captured datagram over HBONE and recover it intact on the far side, each
//! datagram is length-delimited on the wire:
//!
//! ```text
//! [u16 length, big-endian][payload bytes ...]
//! ```
//!
//! - **Length** is a 2-byte big-endian (network-order) prefix. UDP payloads are
//!   bounded by [`MAX_FRAME_PAYLOAD`] (65535 = the largest possible UDP datagram
//!   = `udp_batch::MAX_DGRAM_SIZE`), so a `u16` always suffices and a frame can
//!   never claim more than a single datagram's worth of bytes.
//! - **Zero-length** datagrams are legal in UDP (a bare `sendto(fd, "", 0, ...)`
//!   delivers a 0-byte datagram) and ARE preserved: a `[0x00, 0x00]` frame with
//!   no payload decodes to an empty `Bytes` and is forwarded as an empty
//!   datagram. The codec round-trips it; the relay re-emits it.
//!
//! The decoder is STATEFUL over the tunnel byte stream: a single h2 read may
//! return a partial length prefix, a partial payload, several whole frames, or
//! any split in between. [`read_datagram`] accumulates into a caller-owned
//! buffer across calls, parses exactly one complete frame per call when the
//! buffer holds one, and leaves any trailing partial bytes for the next call.
//! A clean EOF (tunnel half-close) returns `Ok(None)`; an EOF in the MIDDLE of a
//! frame is treated as end-of-session and ALSO returns `Ok(None)` — a partial
//! datagram is NEVER emitted (a truncated datagram would be wrong on the wire).
//!
//! This module is transport-agnostic (`AsyncRead`/`Write`, not HBONE-specific)
//! and fully unit-testable without a live tunnel.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest UDP payload a single frame can carry: the maximum UDP datagram size
/// (`udp_batch::MAX_DGRAM_SIZE` = 65535). A `u16` length prefix exactly covers
/// it, so a peer can never frame more than one datagram's worth of bytes — a
/// hostile/garbled length is intrinsically bounded.
pub const MAX_FRAME_PAYLOAD: usize = 65535;

/// Bytes of the length prefix (`u16`, big-endian).
const LEN_PREFIX: usize = 2;

/// Encode one datagram into `out` as `[u16 len big-endian][payload]`, appending
/// to whatever is already buffered (so multiple datagrams can be batched into
/// one tunnel write). The payload length is bounded by [`MAX_FRAME_PAYLOAD`];
/// the caller is responsible for not handing an oversize datagram (a captured
/// UDP datagram is intrinsically `<= 65535`). Zero-length payloads encode to a
/// bare `[0x00, 0x00]` prefix, which decodes back to an empty datagram.
///
/// Returns `Err` if `payload` exceeds [`MAX_FRAME_PAYLOAD`] — a defensive
/// boundary check; a real UDP datagram can never be larger, so this only fires
/// on a programming error.
pub fn encode_datagram(out: &mut BytesMut, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "datagram payload {} exceeds max framed size {}",
                payload.len(),
                MAX_FRAME_PAYLOAD
            ),
        ));
    }
    out.reserve(LEN_PREFIX + payload.len());
    // `len <= MAX_FRAME_PAYLOAD == u16::MAX`, so the cast is lossless.
    out.put_u16(payload.len() as u16);
    out.put_slice(payload);
    Ok(())
}

/// Read exactly one complete framed datagram off `reader`, using `buf` as the
/// stateful accumulator that persists across calls (the tunnel byte stream has
/// no message boundaries). Returns:
///
/// - `Ok(Some(payload))` — one whole datagram (possibly empty) was decoded; any
///   trailing bytes that began the next frame stay in `buf` for the next call.
/// - `Ok(None)` — the tunnel reached EOF. This covers BOTH a clean half-close
///   between frames AND an EOF in the middle of a frame: a partial datagram is
///   never emitted (returning truncated bytes would corrupt the datagram).
/// - `Err(_)` — a transport read error.
///
/// The buffer is drained by exactly one frame per successful `Some` return, so a
/// caller that received whole back-to-back frames in one underlying read drains
/// them one call at a time without another syscall (the inner reads short-circuit
/// on the buffered bytes).
pub async fn read_datagram<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
) -> std::io::Result<Option<Bytes>> {
    loop {
        // 1. Do we already have a full frame buffered? Parse and return it
        //    WITHOUT touching the transport — back-to-back frames from one read
        //    drain one call at a time.
        if buf.len() >= LEN_PREFIX {
            // Peek the length without consuming, so a short payload leaves the
            // prefix intact for the next attempt.
            let payload_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() >= LEN_PREFIX + payload_len {
                buf.advance(LEN_PREFIX);
                let payload = buf.split_to(payload_len).freeze();
                return Ok(Some(payload));
            }
        }

        // 2. Need more bytes. Read another chunk from the transport.
        //    `read_buf` appends to `buf` and grows it as needed.
        let n = reader.read_buf(buf).await?;
        if n == 0 {
            // EOF. If `buf` still holds bytes they are an incomplete frame at
            // session end — never emit a partial datagram.
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Encode a sequence of datagrams into one contiguous buffer (the wire form
    /// a batched writer would produce).
    fn encode_all(datagrams: &[&[u8]]) -> BytesMut {
        let mut out = BytesMut::new();
        for d in datagrams {
            encode_datagram(&mut out, d).expect("encode");
        }
        out
    }

    /// Drain every frame from `wire` through `read_datagram`, feeding the bytes
    /// in `chunk_size`-byte slices through an in-memory async pipe to exercise
    /// arbitrary read fragmentation (1 byte at a time, split header, etc.).
    async fn decode_all_chunked(wire: &[u8], chunk_size: usize) -> Vec<Bytes> {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let wire = wire.to_vec();
        let writer = tokio::spawn(async move {
            for chunk in wire.chunks(chunk_size.max(1)) {
                client.write_all(chunk).await.expect("write chunk");
                // Flush each chunk so the reader observes the fragmentation.
                client.flush().await.expect("flush");
            }
            // Drop `client` → EOF on `server`.
        });

        let mut out = Vec::new();
        let mut buf = BytesMut::new();
        while let Some(dg) = read_datagram(&mut server, &mut buf)
            .await
            .expect("read_datagram")
        {
            out.push(dg);
        }
        writer.await.expect("writer task");
        out
    }

    #[tokio::test]
    async fn round_trip_single_datagram() {
        let wire = encode_all(&[b"hello world"]);
        let out = decode_all_chunked(&wire, usize::MAX).await;
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][..], b"hello world");
    }

    #[tokio::test]
    async fn round_trip_back_to_back_datagrams_one_read() {
        // Three frames delivered in a SINGLE underlying read must decode as
        // three distinct datagrams, one per `read_datagram` call.
        let wire = encode_all(&[b"one", b"two", b"three"]);
        let out = decode_all_chunked(&wire, usize::MAX).await;
        let got: Vec<&[u8]> = out.iter().map(|b| &b[..]).collect();
        assert_eq!(got, vec![&b"one"[..], &b"two"[..], &b"three"[..]]);
    }

    #[tokio::test]
    async fn round_trip_one_byte_at_a_time() {
        // Feeding the wire one byte per read exercises partial-prefix and
        // partial-payload accumulation across many calls.
        let wire = encode_all(&[b"abc", b"defgh", b"i"]);
        let out = decode_all_chunked(&wire, 1).await;
        let got: Vec<&[u8]> = out.iter().map(|b| &b[..]).collect();
        assert_eq!(got, vec![&b"abc"[..], &b"defgh"[..], &b"i"[..]]);
    }

    #[tokio::test]
    async fn split_header_across_reads() {
        // A 2-byte chunk size splits exactly on/around frame boundaries; in
        // particular the length prefix of the second frame straddles a read.
        let wire = encode_all(&[b"xy", b"zzzz"]);
        let out = decode_all_chunked(&wire, 2).await;
        let got: Vec<&[u8]> = out.iter().map(|b| &b[..]).collect();
        assert_eq!(got, vec![&b"xy"[..], &b"zzzz"[..]]);
    }

    #[tokio::test]
    async fn max_size_datagram_round_trips() {
        let big = vec![0xABu8; MAX_FRAME_PAYLOAD];
        let wire = encode_all(&[&big]);
        // Chunk it so the 65535-byte payload spans many reads.
        let out = decode_all_chunked(&wire, 4096).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), MAX_FRAME_PAYLOAD);
        assert_eq!(&out[0][..], &big[..]);
    }

    #[tokio::test]
    async fn dtls_handshake_datagram_round_trips_opaque() {
        // F3 §3.3 Stage 5 — DTLS passthrough: the mesh relays DTLS over the UDP
        // datagram tunnel OPAQUELY. It never terminates or inspects DTLS — no
        // ClientHello/SNI parse (unlike the standalone `passthrough` DTLS proxy);
        // the inner DTLS rides the secured outer mesh hop (HBONE/mesh-mTLS)
        // untouched. A DTLS 1.2 ClientHello record (content_type=22 handshake,
        // version 0xFEFD, epoch/seq, length, handshake bytes) must therefore
        // round-trip through the framing codec BYTE-FOR-BYTE — proving the relay is
        // content-agnostic and needs no DTLS-specific handling.
        let dtls_client_hello: &[u8] = &[
            0x16, // content type: handshake (22)
            0xFE, 0xFD, // DTLS 1.2 (0xFEFD)
            0x00, 0x00, // epoch 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // record sequence number
            0x00, 0x0C, // record length
            0x01, // handshake type: client_hello (1)
            0xFE, 0xFD, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xFF,
        ];
        // Interleave a second opaque datagram to confirm no cross-frame bleed.
        let wire = encode_all(&[dtls_client_hello, b"app-data"]);
        let out = decode_all_chunked(&wire, 3).await;
        assert_eq!(out.len(), 2);
        assert_eq!(
            &out[0][..],
            dtls_client_hello,
            "a DTLS handshake datagram must relay byte-for-byte (opaque passthrough)"
        );
        assert_eq!(&out[1][..], b"app-data");
    }

    #[tokio::test]
    async fn zero_length_datagram_is_preserved() {
        // A 0-length datagram is UDP-legal and must round-trip as an empty
        // datagram, not be dropped or merged with a neighbor.
        let wire = encode_all(&[b"", b"after-empty", b""]);
        let out = decode_all_chunked(&wire, 1).await;
        assert_eq!(out.len(), 3);
        assert!(out[0].is_empty());
        assert_eq!(&out[1][..], b"after-empty");
        assert!(out[2].is_empty());
    }

    #[tokio::test]
    async fn eof_mid_frame_returns_none_without_partial() {
        // Claim a 10-byte payload but only deliver 4 bytes, then EOF. The
        // decoder must return None (session end) — never a truncated datagram.
        let mut wire = BytesMut::new();
        wire.put_u16(10);
        wire.put_slice(b"four"); // only 4 of the claimed 10 payload bytes
        let out = decode_all_chunked(&wire, 1).await;
        assert!(out.is_empty(), "partial frame must not be emitted");
    }

    #[tokio::test]
    async fn eof_mid_length_prefix_returns_none() {
        // Only the first byte of a 2-byte length prefix arrives, then EOF.
        let wire = [0x00u8]; // half a length prefix
        let out = decode_all_chunked(&wire, 1).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn clean_eof_between_frames_returns_none() {
        // A whole frame followed by a clean half-close: the frame decodes, then
        // the next call returns None.
        let wire = encode_all(&[b"only"]);
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&wire).await.unwrap();
        client.flush().await.unwrap();
        drop(client);
        let mut buf = BytesMut::new();
        let first = read_datagram(&mut server, &mut buf).await.unwrap();
        assert_eq!(first.as_deref(), Some(&b"only"[..]));
        let second = read_datagram(&mut server, &mut buf).await.unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn encode_rejects_oversize_payload() {
        let mut out = BytesMut::new();
        let too_big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let err = encode_datagram(&mut out, &too_big).expect_err("must reject");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(out.is_empty(), "nothing should be written on error");
    }

    #[test]
    fn encode_zero_length_writes_bare_prefix() {
        let mut out = BytesMut::new();
        encode_datagram(&mut out, b"").expect("encode empty");
        assert_eq!(&out[..], &[0x00, 0x00]);
    }
}
