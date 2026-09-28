//! Gateway-terminated `permessage-deflate` (`websocket_permessage_deflate:
//! terminate`, issue #5769): per-leg negotiation, the inflating transport the
//! relay framer reads through, the outbound encoder, and the decompression
//! bounds.
//!
//! The transport tests put a real tungstenite framer, configured exactly like
//! the shared relay's (masking enforced, auto-Pong off), over
//! `PermessageDeflateIo`, so what they read is what frame plugins receive.

use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::finish_permessage_deflate_termination_for_test;
use ferrum_edge::proxy::ws_permessage_deflate::{
    BACKEND_OFFER, DeflateLegConfig, InflateLimits, MAX_WINDOW_BITS, PermessageDeflateEncoder,
    PermessageDeflateFault, PermessageDeflateIo, PlainOutbound, SCRATCH_BYTES,
    WsDeflateTermination, WsOutboundCodec, inflate_message_for_test, negotiate_client_offer,
    offer_termination, parse_backend_answer, permessage_deflate_fault,
};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use futures_util::StreamExt;
use hyper::HeaderMap;
use hyper::header::{HeaderValue, SEC_WEBSOCKET_EXTENSIONS};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};

/// RFC 7692 §7.2.3.1: "Hello" compressed with an empty sliding window.
const DEFLATED_HELLO: [u8; 7] = [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

const FIN_RSV1_TEXT: u8 = 0xc1;
const FIN_TEXT: u8 = 0x81;
const RSV1_TEXT: u8 = 0x41;
const FIN_CONTINUATION: u8 = 0x80;
const FIN_PING: u8 = 0x89;

const LIMITS: InflateLimits = InflateLimits {
    max_frame_bytes: 1 << 20,
    max_message_bytes: 4 << 20,
};

const FULL_WINDOW: DeflateLegConfig = DeflateLegConfig {
    outbound_no_context_takeover: false,
    outbound_max_window_bits: MAX_WINDOW_BITS,
};

/// One RFC 6455 frame with an explicit first byte (FIN, RSV bits, opcode).
fn frame(first: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(mask_bit | 126);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    match mask {
        Some(mask) => {
            out.extend_from_slice(&mask);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    frame(first, Some(MASK), payload)
}

/// Raw DEFLATE with a sync flush and the RFC 7692 tail removed, from a fresh
/// compressor.
fn deflate(data: &[u8]) -> Vec<u8> {
    let mut compress = Compress::new(Compression::default(), false);
    let mut out = Vec::with_capacity(data.len() + 1024);
    compress
        .compress_vec(data, &mut out, FlushCompress::Sync)
        .expect("deflate");
    assert!(out.ends_with(&[0x00, 0x00, 0xff, 0xff]), "sync flush tail");
    out.truncate(out.len() - 4);
    out
}

/// Inverse of [`deflate`] through a caller-owned (possibly context-keeping)
/// decoder.
fn inflate(decoder: &mut Decompress, data: &[u8]) -> Vec<u8> {
    let mut input = data.to_vec();
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
    let mut out = Vec::with_capacity(4 << 20);
    decoder
        .decompress_vec(&input, &mut out, FlushDecompress::Sync)
        .expect("inflate");
    out
}

/// Deterministic, poorly compressible bytes.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect()
}

/// A framer configured like the shared relay's, reading `wire` through the
/// inflating transport.
async fn framer_over(
    wire: Vec<u8>,
    role: Role,
    prefix: Bytes,
    inflate: Option<InflateLimits>,
) -> WebSocketStream<PermessageDeflateIo<DuplexStream>> {
    let (mut peer, gateway_side) = tokio::io::duplex(8 << 20);
    peer.write_all(&wire).await.expect("write wire bytes");
    drop(peer);
    let config = WebSocketConfig::default()
        .accept_unmasked_frames(false)
        .auto_pong(false)
        .max_frame_size(Some(LIMITS.max_frame_bytes))
        .max_message_size(Some(LIMITS.max_message_bytes));
    WebSocketStream::from_raw_socket(
        PermessageDeflateIo::new(gateway_side, prefix, inflate),
        role,
        Some(config),
    )
    .await
}

async fn server_framer(wire: Vec<u8>) -> WebSocketStream<PermessageDeflateIo<DuplexStream>> {
    framer_over(wire, Role::Server, Bytes::new(), Some(LIMITS)).await
}

async fn next_message(
    framer: &mut WebSocketStream<PermessageDeflateIo<DuplexStream>>,
) -> Result<Message, WsError> {
    framer.next().await.expect("framer yields an item")
}

async fn next_fault(
    framer: &mut WebSocketStream<PermessageDeflateIo<DuplexStream>>,
) -> PermessageDeflateFault {
    let error = next_message(framer)
        .await
        .expect_err("the inflater must fail the read");
    permessage_deflate_fault(&error).unwrap_or_else(|| panic!("not a deflate fault: {error}"))
}

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

#[test]
fn client_offer_is_answered_with_supported_parameters() {
    for offer in [
        "permessage-deflate",
        "permessage-deflate; client_max_window_bits",
        "permessage-deflate; client_max_window_bits=10; client_no_context_takeover",
        "x-webkit-deflate-frame, permessage-deflate",
    ] {
        let agreement = negotiate_client_offer(offer).expect("acceptable offer");
        assert_eq!(agreement.response, "permessage-deflate", "offer {offer:?}");
        assert_eq!(agreement.leg, FULL_WINDOW, "offer {offer:?}");
    }

    let agreement = negotiate_client_offer(
        "permessage-deflate; server_no_context_takeover; server_max_window_bits=10",
    )
    .expect("acceptable offer");
    assert_eq!(
        agreement.response,
        "permessage-deflate; server_no_context_takeover; server_max_window_bits=10"
    );
    assert_eq!(
        agreement.leg,
        DeflateLegConfig {
            outbound_no_context_takeover: true,
            outbound_max_window_bits: 10,
        }
    );

    let quoted = negotiate_client_offer("permessage-deflate; server_max_window_bits=\"12\"")
        .expect("a quoted window value is accepted");
    assert_eq!(quoted.leg.outbound_max_window_bits, 12);
}

#[test]
fn invalid_offer_elements_are_declined_and_the_next_one_is_tried() {
    let fallback = negotiate_client_offer(
        "permessage-deflate; foo, permessage-deflate; server_no_context_takeover",
    )
    .expect("the second element is acceptable");
    assert_eq!(
        fallback.response,
        "permessage-deflate; server_no_context_takeover"
    );

    for offer in [
        "permessage-deflate; foo",
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        "permessage-deflate; server_no_context_takeover=1",
        "permessage-deflate; server_max_window_bits",
        "permessage-deflate; server_max_window_bits=09",
        "permessage-deflate; server_max_window_bits=7",
        "permessage-deflate; client_max_window_bits=16",
        "permessage-deflate;",
        "permessage-deflate; server_max_window_bits=\"1",
        "x-webkit-deflate-frame",
        "permessage-deflate-v2",
        "",
    ] {
        assert_eq!(negotiate_client_offer(offer), None, "offer {offer:?}");
    }
}

#[test]
fn backend_answer_must_be_one_valid_element() {
    assert_eq!(parse_backend_answer("permessage-deflate"), Ok(FULL_WINDOW));
    let answer = "permessage-deflate; client_no_context_takeover; server_max_window_bits=9";
    assert_eq!(
        parse_backend_answer(answer),
        Ok(DeflateLegConfig {
            outbound_no_context_takeover: true,
            outbound_max_window_bits: MAX_WINDOW_BITS,
        })
    );
    for answer in [
        "permessage-deflate; client_max_window_bits=10",
        "permessage-deflate; client_max_window_bits",
        "permessage-deflate, permessage-deflate",
        "permessage-deflate; bogus",
        "permessage-deflate; server_max_window_bits=20",
        "x-other",
        "",
    ] {
        assert!(
            parse_backend_answer(answer).is_err(),
            "answer {answer:?} must be refused"
        );
    }
}

#[test]
fn termination_offers_the_backend_independently_of_the_client() {
    let mut backend_headers = vec![
        ("x-trace".to_string(), "1".to_string()),
        (
            "Sec-WebSocket-Extensions".to_string(),
            "x-leftover".to_string(),
        ),
    ];
    let handshake = offer_termination(
        Some("permessage-deflate; client_max_window_bits"),
        false,
        &mut backend_headers,
    );
    let offers: Vec<_> = backend_headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(offers, vec![BACKEND_OFFER], "only our offer");
    assert!(handshake.client_agreement().is_some());

    // No client offer, or one nominated as hop-by-hop: the backend is still
    // offered compression, the client leg stays uncompressed.
    for (offer, listed) in [(None, false), (Some("permessage-deflate"), true)] {
        let mut backend_headers = Vec::new();
        let handshake = offer_termination(offer, listed, &mut backend_headers);
        assert!(handshake.client_agreement().is_none());
        assert_eq!(backend_headers.len(), 1);
        assert_eq!(backend_headers[0].0, "sec-websocket-extensions");
        assert_eq!(backend_headers[0].1, BACKEND_OFFER);
    }
}

#[test]
fn legs_negotiate_independently() {
    let client_only = offer_termination(Some("permessage-deflate"), false, &mut Vec::new())
        .complete(None, 0)
        .expect("a declining backend is fine");
    assert_eq!(
        client_only.client_response.as_deref(),
        Some("permessage-deflate")
    );
    let session = client_only.session.expect("the client leg negotiated");
    assert_eq!(session.client, Some(FULL_WINDOW));
    assert_eq!(session.backend, None);

    let backend_only = offer_termination(None, false, &mut Vec::new())
        .complete(Some("permessage-deflate; client_no_context_takeover"), 4096)
        .expect("valid backend answer");
    assert_eq!(backend_only.client_response, None);
    let session = backend_only.session.expect("the backend leg negotiated");
    assert_eq!(session.client, None);
    assert_eq!(
        session.backend.map(|leg| leg.outbound_no_context_takeover),
        Some(true)
    );
    assert_eq!(session.max_decompressed_message_bytes, 4096);

    let neither = offer_termination(None, false, &mut Vec::new())
        .complete(None, 0)
        .expect("nothing negotiated");
    assert!(neither.client_response.is_none());
    assert!(
        neither.session.is_none(),
        "no negotiated leg keeps the ordinary relay"
    );
    assert_eq!(WsDeflateTermination::new(None, None, 0), None);

    let invalid = offer_termination(Some("permessage-deflate"), false, &mut Vec::new())
        .complete(Some("permessage-deflate; client_max_window_bits=9"), 0);
    assert!(invalid.is_err(), "an invalid backend answer is refused");
}

#[test]
fn whole_backend_extension_answer_is_validated() {
    fn finish(lines: &[HeaderValue]) -> Result<bool, &'static str> {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(SEC_WEBSOCKET_EXTENSIONS, line.clone());
        }
        let handshake = offer_termination(None, false, &mut Vec::new());
        finish_permessage_deflate_termination_for_test(handshake, &headers, 0)
            .map(|negotiated| negotiated.session.is_some())
    }

    assert_eq!(finish(&[]), Ok(false), "no answer: plain backend leg");
    assert_eq!(
        finish(&[HeaderValue::from_static("permessage-deflate")]),
        Ok(true)
    );
    // The gateway offered only permessage-deflate, so anything else in the
    // answer (on any field line) fails the upgrade instead of being dropped.
    let non_ascii = HeaderValue::from_bytes(b"permessage-deflate\xe9")
        .expect("obs-text is a valid field value");
    let refused: [&[HeaderValue]; 5] = [
        &[HeaderValue::from_static("x-unrequested")],
        &[
            HeaderValue::from_static("x-unrequested"),
            HeaderValue::from_static("permessage-deflate"),
        ],
        &[HeaderValue::from_static("permessage-deflate, x-other")],
        &[HeaderValue::from_static("permessage-deflate; x=\"1")],
        std::slice::from_ref(&non_ascii),
    ];
    for lines in refused {
        assert!(finish(lines).is_err(), "answer {lines:?} must be refused");
    }
    assert_eq!(finish(&[non_ascii]), Err("non-ASCII extension answer"));
}

// ---------------------------------------------------------------------------
// Inflate: what the relay framer (and so every frame plugin) receives
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compressed_client_message_reaches_the_framer_as_plaintext() {
    let mut framer = server_framer(client_frame(FIN_RSV1_TEXT, &DEFLATED_HELLO)).await;
    assert_eq!(
        next_message(&mut framer).await.expect("inflated message"),
        Message::text("Hello")
    );
}

#[tokio::test]
async fn encoder_output_round_trips_with_context_takeover() {
    let messages = [
        "the quick brown fox jumps over the lazy dog".to_string(),
        "the quick brown fox jumps over the lazy dog".to_string(),
        "x".repeat(70_000),
        "the quick brown fox jumps over the lazy cat".to_string(),
    ];
    let mut encoder = PermessageDeflateEncoder::new(FULL_WINDOW);
    let mut wire = Vec::new();
    for message in &messages {
        let compressed = encoder
            .compress_payload(message.as_bytes())
            .expect("compressible");
        wire.extend(client_frame(FIN_RSV1_TEXT, &compressed));
    }
    let mut framer = server_framer(wire).await;
    for message in &messages {
        assert_eq!(
            next_message(&mut framer).await.expect("inflated message"),
            Message::text(message.as_str())
        );
    }
}

#[tokio::test]
async fn fragmented_compressed_message_keeps_rsv1_on_its_first_frame_only() {
    let compressed = deflate(b"fragmented permessage-deflate message");
    let (head, tail) = compressed.split_at(compressed.len() / 2);
    let mut wire = client_frame(RSV1_TEXT, head);
    // A control frame may interleave with the fragments; it is never
    // compressed and is forwarded as-is.
    wire.extend(client_frame(FIN_PING, b"ka"));
    wire.extend(client_frame(FIN_CONTINUATION, tail));
    let mut framer = server_framer(wire).await;
    assert_eq!(
        next_message(&mut framer).await.expect("interleaved ping"),
        Message::Ping(Bytes::from_static(b"ka"))
    );
    assert_eq!(
        next_message(&mut framer)
            .await
            .expect("reassembled message"),
        Message::text("fragmented permessage-deflate message")
    );
}

#[tokio::test]
async fn rsv1_on_a_control_or_continuation_frame_fails_the_connection() {
    let mut framer = server_framer(client_frame(0xc9, b"ka")).await;
    assert!(matches!(
        next_message(&mut framer).await,
        Err(WsError::Protocol(ProtocolError::NonZeroReservedBits))
    ));

    let compressed = deflate(b"two fragments");
    let (head, tail) = compressed.split_at(4);
    let mut wire = client_frame(RSV1_TEXT, head);
    wire.extend(client_frame(FIN_CONTINUATION | 0x40, tail));
    let mut framer = server_framer(wire).await;
    assert!(matches!(
        next_message(&mut framer).await,
        Err(WsError::Protocol(ProtocolError::NonZeroReservedBits))
    ));
}

#[tokio::test]
async fn uncompressed_messages_and_unnegotiated_legs_are_untouched() {
    let mut wire = client_frame(FIN_TEXT, b"plain");
    wire.extend(client_frame(FIN_RSV1_TEXT, &DEFLATED_HELLO));
    wire.extend(client_frame(FIN_TEXT, b"plain again"));
    let mut framer = server_framer(wire).await;
    for expected in ["plain", "Hello", "plain again"] {
        assert_eq!(
            next_message(&mut framer).await.expect("message"),
            Message::text(expected)
        );
    }

    // A leg that did not negotiate the extension has no inflater: an RSV1
    // frame there is the protocol violation it always was.
    let mut framer = framer_over(
        client_frame(FIN_RSV1_TEXT, &DEFLATED_HELLO),
        Role::Server,
        Bytes::new(),
        None,
    )
    .await;
    assert!(matches!(
        next_message(&mut framer).await,
        Err(WsError::Protocol(ProtocolError::NonZeroReservedBits))
    ));
}

#[tokio::test]
async fn masking_rules_still_apply_after_inflation() {
    // Unmasked client frame: still refused by the server framer.
    let mut framer = server_framer(frame(FIN_RSV1_TEXT, None, &DEFLATED_HELLO)).await;
    assert!(matches!(
        next_message(&mut framer).await,
        Err(WsError::Protocol(ProtocolError::UnmaskedFrameFromClient))
    ));

    // Masked server frame on the backend leg: still refused by the client
    // framer.
    let mut framer = framer_over(
        frame(FIN_RSV1_TEXT, Some(MASK), &DEFLATED_HELLO),
        Role::Client,
        Bytes::new(),
        Some(LIMITS),
    )
    .await;
    assert!(matches!(
        next_message(&mut framer).await,
        Err(WsError::Protocol(ProtocolError::MaskedFrameFromServer))
    ));
}

#[tokio::test]
async fn backend_bytes_recovered_from_the_handshake_are_inflated_first() {
    let prefix = Bytes::from(frame(FIN_RSV1_TEXT, None, &DEFLATED_HELLO));
    let mut framer = framer_over(
        frame(FIN_TEXT, None, b"later"),
        Role::Client,
        prefix,
        Some(LIMITS),
    )
    .await;
    assert_eq!(
        next_message(&mut framer).await.expect("recovered message"),
        Message::text("Hello")
    );
    assert_eq!(
        next_message(&mut framer).await.expect("later message"),
        Message::text("later")
    );

    // A pass-through leg replays its recovered bytes verbatim.
    let prefix = Bytes::from(frame(FIN_TEXT, None, b"recovered"));
    let mut framer = framer_over(Vec::new(), Role::Client, prefix, None).await;
    assert_eq!(
        next_message(&mut framer).await.expect("recovered message"),
        Message::text("recovered")
    );
}

// ---------------------------------------------------------------------------
// Decompression bounds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decompression_bomb_is_refused_with_1009() {
    let bomb = deflate(&vec![0u8; 8 << 20]);
    assert!(bomb.len() < 64 * 1024, "the bomb is small on the wire");
    let limits = InflateLimits {
        max_frame_bytes: 1 << 20,
        max_message_bytes: 64 * 1024,
    };
    let mut framer = framer_over(
        client_frame(0xc2, &bomb),
        Role::Server,
        Bytes::new(),
        Some(limits),
    )
    .await;
    let fault = next_fault(&mut framer).await;
    assert_eq!(
        fault,
        PermessageDeflateFault::DecompressedMessageTooLarge { max: 64 * 1024 }
    );
    let close = fault.close_frame();
    assert_eq!(close.code, CloseCode::Size);
    assert!(close.reason.len() <= 123);
    assert!(fault.is_size_limit());
}

#[tokio::test]
async fn a_fault_is_sticky_on_the_transport() {
    let (mut peer, gateway_side) = tokio::io::duplex(64 * 1024);
    peer.write_all(&client_frame(FIN_RSV1_TEXT, &[0xff; 4]))
        .await
        .expect("write wire bytes");
    let mut io = PermessageDeflateIo::new(gateway_side, Bytes::new(), Some(LIMITS));
    let mut buf = [0u8; 64];
    for _ in 0..2 {
        let error = io.read(&mut buf).await.expect_err("the fault repeats");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
    drop(peer);
}

#[tokio::test]
async fn decompressed_message_ceiling_spans_fragments() {
    let limits = InflateLimits {
        max_frame_bytes: 1 << 20,
        max_message_bytes: 4096,
    };
    // One compressed message split into two frames that each inflate to
    // 3000 bytes of a shared stream: the first fits, the second crosses the
    // 4096-byte message ceiling.
    let plaintext = noise(6000, 7);
    let mut compress = Compress::new(Compression::default(), false);
    let mut first = Vec::with_capacity(8192);
    compress
        .compress_vec(&plaintext[..3000], &mut first, FlushCompress::Sync)
        .expect("deflate first half");
    let mut second = Vec::with_capacity(8192);
    compress
        .compress_vec(&plaintext[3000..], &mut second, FlushCompress::Sync)
        .expect("deflate second half");
    assert!(second.ends_with(&[0x00, 0x00, 0xff, 0xff]));
    second.truncate(second.len() - 4);

    let mut wire = client_frame(0x42, &first);
    wire.extend(client_frame(FIN_CONTINUATION, &second));
    let mut framer = framer_over(wire, Role::Server, Bytes::new(), Some(limits)).await;
    assert_eq!(
        next_fault(&mut framer).await,
        PermessageDeflateFault::DecompressedMessageTooLarge { max: 4096 }
    );
}

#[tokio::test]
async fn frame_ceilings_bound_compressed_and_inflated_frames() {
    let limits = InflateLimits {
        max_frame_bytes: 1024,
        max_message_bytes: 1 << 20,
    };
    // A compressed frame larger than the frame ceiling is refused from its
    // header, before its payload is buffered.
    let oversized = noise(2048, 3);
    let mut framer = framer_over(
        client_frame(0xc2, &oversized),
        Role::Server,
        Bytes::new(),
        Some(limits),
    )
    .await;
    assert_eq!(
        next_fault(&mut framer).await,
        PermessageDeflateFault::CompressedFrameTooLarge {
            size: 2048,
            max: 1024,
        }
    );

    // A small compressed frame that inflates past the frame ceiling.
    let mut framer = framer_over(
        client_frame(0xc2, &deflate(&[b'a'; 4096])),
        Role::Server,
        Bytes::new(),
        Some(limits),
    )
    .await;
    let fault = next_fault(&mut framer).await;
    assert_eq!(
        fault,
        PermessageDeflateFault::DecompressedFrameTooLarge { max: 1024 }
    );
    assert_eq!(fault.close_frame().code, CloseCode::Size);
}

#[tokio::test]
async fn a_stalled_compressed_frame_header_reserves_nothing() {
    // An RSV1 header declaring a frame-ceiling-sized payload, a few payload
    // bytes, then silence: the declared length must not be reserved.
    let declared = LIMITS.max_frame_bytes as u64;
    let mut wire = vec![FIN_RSV1_TEXT, 0x80 | 127];
    wire.extend_from_slice(&declared.to_be_bytes());
    wire.extend_from_slice(&MASK);
    wire.extend_from_slice(&[0u8; 100]);
    let (mut peer, gateway_side) = tokio::io::duplex(64 * 1024);
    peer.write_all(&wire).await.expect("write wire bytes");
    let mut io = PermessageDeflateIo::new(gateway_side, Bytes::new(), Some(LIMITS));
    let mut buf = [0u8; 64];
    let stalled = tokio::time::timeout(Duration::from_millis(50), io.read(&mut buf)).await;
    assert!(stalled.is_err(), "the incomplete frame blocks the read");
    assert!(
        io.raw_buffer_capacity() <= SCRATCH_BYTES,
        "a {declared}-byte header reserved {} bytes",
        io.raw_buffer_capacity()
    );
    drop(peer);
}

#[test]
fn inflate_buffer_capacity_never_exceeds_its_limit() {
    const LIMIT: usize = 256 * 1024;
    let limits = InflateLimits {
        max_frame_bytes: LIMIT,
        max_message_bytes: LIMIT,
    };
    // A bomb: the buffer stops one byte past the limit, and its capacity
    // must not have doubled past it on the way.
    let bomb = deflate(&vec![0u8; 8 << 20]);
    let (result, capacity) = inflate_message_for_test(limits, &bomb);
    assert_eq!(
        result,
        Err(PermessageDeflateFault::DecompressedMessageTooLarge { max: LIMIT })
    );
    assert!(capacity <= LIMIT + 1, "bomb capacity {capacity}");

    // Legitimate frames up to the limit stay within it too, including one
    // that lands exactly on it.
    for len in [3 * SCRATCH_BYTES + 5, 150 * 1024, LIMIT] {
        let plaintext = noise(len, 11);
        let (result, capacity) = inflate_message_for_test(limits, &deflate(&plaintext));
        assert_eq!(result, Ok(len));
        assert!(capacity <= LIMIT + 1, "{len}-byte capacity {capacity}");
    }
}

#[tokio::test]
async fn corrupt_compressed_data_closes_with_1007() {
    let mut framer = server_framer(client_frame(FIN_RSV1_TEXT, &[0xff, 0xff, 0xff, 0xff])).await;
    let fault = next_fault(&mut framer).await;
    assert_eq!(fault, PermessageDeflateFault::InvalidCompressedData);
    assert_eq!(fault.close_frame().code, CloseCode::Invalid);
    assert!(!fault.is_size_limit());
}

// ---------------------------------------------------------------------------
// Deflate: what the relay writes toward a compressing leg
// ---------------------------------------------------------------------------

#[test]
fn encoder_compresses_data_messages_into_one_rsv1_frame() {
    let mut encoder = PermessageDeflateEncoder::new(FULL_WINDOW);
    let Message::Frame(frame) = encoder.encode_message(Message::text("Hello")) else {
        panic!("a text message becomes one compressed frame");
    };
    assert!(frame.header().rsv1);
    assert!(frame.header().is_final);
    assert_eq!(frame.header().opcode, OpCode::Data(Data::Text));
    let mut decoder = Decompress::new(false);
    assert_eq!(inflate(&mut decoder, frame.payload()), b"Hello");

    let Message::Frame(frame) = encoder.encode_message(Message::binary(vec![1, 2, 3])) else {
        panic!("a binary message becomes one compressed frame");
    };
    assert_eq!(frame.header().opcode, OpCode::Data(Data::Binary));
    assert_eq!(inflate(&mut decoder, frame.payload()), [1, 2, 3]);
}

#[test]
fn encoder_never_compresses_control_frames_or_empty_messages() {
    let mut encoder = PermessageDeflateEncoder::new(FULL_WINDOW);
    for message in [
        Message::Ping(Bytes::from_static(b"ping")),
        Message::Pong(Bytes::from_static(b"pong")),
        Message::Close(None),
        Message::text(""),
    ] {
        assert_eq!(encoder.encode_message(message.clone()), message);
    }
}

#[test]
fn encoder_honors_context_takeover_choice() {
    let payload = noise(400, 11);

    let mut takeover = PermessageDeflateEncoder::new(FULL_WINDOW);
    let first = takeover.compress_payload(&payload).expect("compressible");
    let second = takeover.compress_payload(&payload).expect("compressible");
    assert!(
        second.len() * 4 < first.len(),
        "context takeover must reference the previous message ({} vs {})",
        second.len(),
        first.len()
    );
    let mut decoder = Decompress::new(false);
    assert_eq!(inflate(&mut decoder, &first), payload);
    assert_eq!(inflate(&mut decoder, &second), payload);

    let mut fresh = PermessageDeflateEncoder::new(DeflateLegConfig {
        outbound_no_context_takeover: true,
        outbound_max_window_bits: MAX_WINDOW_BITS,
    });
    for _ in 0..2 {
        let compressed = fresh.compress_payload(&payload).expect("compressible");
        // Each message decodes on its own, with no shared history.
        assert_eq!(inflate(&mut Decompress::new(false), &compressed), payload);
    }
}

#[test]
fn encoder_stays_inside_a_negotiated_small_window() {
    let mut encoder = PermessageDeflateEncoder::new(DeflateLegConfig {
        outbound_no_context_takeover: false,
        outbound_max_window_bits: 9,
    });
    let small = noise(512, 5);
    let compressed = encoder.compress_payload(&small).expect("fits the window");
    assert_eq!(inflate(&mut Decompress::new(false), &compressed), small);
    // A message longer than the 512-byte window is sent uncompressed.
    assert_eq!(encoder.compress_payload(&noise(513, 5)), None);
    let message = Message::binary(noise(600, 9));
    assert_eq!(encoder.encode_message(message.clone()), message);
}

#[test]
fn plain_outbound_is_the_identity() {
    let message = Message::text("unchanged");
    assert_eq!(PlainOutbound.encode(message.clone()), message);
    let mut none: Option<PermessageDeflateEncoder> = None;
    assert_eq!(none.encode(message.clone()), message);
    let mut some = Some(PermessageDeflateEncoder::new(FULL_WINDOW));
    assert!(matches!(some.encode(message), Message::Frame(_)));
}
