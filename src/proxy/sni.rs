//! SNI (Server Name Indication) extraction from TLS/DTLS ClientHello messages.
//!
//! Used by passthrough mode to peek at the ClientHello without terminating TLS,
//! extracting the SNI hostname for logging and routing decisions.

/// Maximum bytes to peek from a TCP stream for ClientHello SNI extraction.
///
/// Typical ClientHellos are a few hundred bytes, but modern stacks with
/// post-quantum `key_share` (e.g. X25519MLKEM768 ≈ 1.2 KiB), ECH payloads, and
/// large ALPN/cert-compression lists routinely push past 4 KiB. Extension order
/// is client-chosen, so SNI can land after those fat extensions. Cap at 16 KiB
/// (one max TLS record) so valid oversized hellos still yield SNI for
/// passthrough routing. The peek buffer starts at
/// [`INITIAL_CLIENT_HELLO_PEEK_LEN`] and grows toward this hard bound only when
/// more bytes are needed; hostile length fields cannot request more than this
/// hard memory bound.
const MAX_CLIENT_HELLO_LEN: usize = 16 * 1024;

/// Initial peek buffer size for ClientHello SNI extraction.
///
/// Matches the historical 4 KiB floor so ordinary connections (typical
/// ClientHellos are 200-600 bytes; most modern stacks stay under 4 KiB) do not
/// pay a zeroed 16 KiB allocation on the pre-auth accept path. Oversized hellos
/// grow toward [`MAX_CLIENT_HELLO_LEN`] lazily via [`next_peek_capacity`].
const INITIAL_CLIENT_HELLO_PEEK_LEN: usize = 4 * 1024;

/// Polling interval between peeks while waiting for the rest of a partially
/// arrived ClientHello (mirrors `STREAM_FIRST_BYTES_PEEK_RETRY_INTERVAL` in
/// `tcp_proxy.rs` — `peek()` returns as soon as ≥1 byte is readable, so
/// back-to-back peeks would busy-loop).
const SNI_PEEK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// How many times the no-deadline peek may re-await readiness after a spurious
/// readiness signal (the socket reported readable but the non-blocking peek
/// returned `WouldBlock`).
///
/// The no-deadline path must never hold the hard-cap buffer across a
/// suspension, so a spurious wakeup drops the buffer and waits again rather
/// than parking with it allocated. Each retry costs one readiness event from
/// the OS — not a busy loop — but the count is still bounded so a socket that
/// somehow keeps reporting phantom readiness fails closed instead of spinning.
const MAX_PEEK_READINESS_RETRIES: usize = 3;

/// Initial capacity of the TCP ClientHello peek buffer.
///
/// Pure sizing seam so external tests can lock the lazy-allocation floor
/// without observing live buffer capacity through the async peek path.
pub fn initial_peek_capacity() -> usize {
    INITIAL_CLIENT_HELLO_PEEK_LEN
}

/// Capacity of the buffer used by the no-deadline (single-peek) path.
///
/// The no-deadline path cannot loop on the wire, so its one peek must be able
/// to see a standards-valid oversized ClientHello in full — it sizes straight
/// to the hard cap rather than the lazy floor. Lazy growth exists to bound
/// memory held ACROSS the deadline-driven peek loop while a slow peer dribbles
/// bytes; it does not apply to a buffer that is allocated only after the socket
/// is already readable and dropped before the next await. Capping this at the
/// 4 KiB floor would silently truncate SNI extraction whenever the frontend
/// handshake timeout is disabled (`FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=0`),
/// which is the oversized-ClientHello misrouting of issue #2962.
///
/// Pure sizing seam so external tests can lock this without observing live
/// buffer capacity through the async peek path.
pub fn no_deadline_peek_capacity() -> usize {
    MAX_CLIENT_HELLO_LEN
}

/// Next peek-buffer capacity after `have` bytes have already been observed and
/// the wire-span parser still needs more data.
///
/// Growth is a single step from the initial 4 KiB floor to the 16 KiB hard cap
/// once the initial buffer is full (`have >=` initial). While `have` is still
/// below the initial size the capacity stays at the floor — the peer simply has
/// not delivered more bytes yet, so growing would not help.
///
/// This applies to the deadline-driven peek loop only; the no-deadline path
/// uses [`no_deadline_peek_capacity`].
pub fn next_peek_capacity(have: usize) -> usize {
    if have >= INITIAL_CLIENT_HELLO_PEEK_LEN {
        MAX_CLIENT_HELLO_LEN
    } else {
        INITIAL_CLIENT_HELLO_PEEK_LEN
    }
}

/// One immediate, non-suspending poll of `TcpStream::poll_peek`.
///
/// The returned future is `Ready` on its first poll no matter what, so the
/// caller's peek buffer is never held across a suspension point. The inner
/// `Poll` reports whether bytes were actually peeked (`Ready`) or the readiness
/// signal was spurious / the socket returned `WouldBlock` (`Pending`).
async fn poll_peek_once(
    stream: &tokio::net::TcpStream,
    buf: &mut tokio::io::ReadBuf<'_>,
) -> std::task::Poll<std::io::Result<usize>> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(stream.poll_peek(cx, buf))).await
}

/// Single bounded ClientHello peek for callers that pass no handshake deadline.
///
/// Takes one peek of the wire and never loops on it, so a stalled peer cannot
/// park the task waiting for a record that never completes. Two invariants have
/// to hold at once, so readiness and the buffer are deliberately separated:
///
/// 1. A silent peer must not pin a hard-cap allocation. `readable()` carries no
///    buffer, so an idle connection suspends here holding nothing.
/// 2. Once bytes are actually available, the single peek must still be able to
///    inspect a standards-valid ClientHello up to [`MAX_CLIENT_HELLO_LEN`]
///    (issue #2962) — so the buffer is allocated only *after* readiness, at the
///    full cap.
///
/// The peek itself is one non-blocking `poll_peek` wrapped in an always-`Ready`
/// future: it cannot suspend, so the hard-cap buffer is never live across an
/// await. A spurious readiness signal yields `Pending`; the buffer is dropped
/// and a fresh readiness event awaited, bounded by
/// [`MAX_PEEK_READINESS_RETRIES`] so this can never spin. There is no unbounded
/// read loop and no blocking wait.
async fn peek_sni_without_deadline(stream: &tokio::net::TcpStream) -> Option<String> {
    for _ in 0..=MAX_PEEK_READINESS_RETRIES {
        // No buffer is alive across this await: an idle peer pins nothing.
        stream.readable().await.ok()?;

        let mut buf = vec![0u8; no_deadline_peek_capacity()];
        let polled = {
            let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
            poll_peek_once(stream, &mut read_buf).await
        };
        match polled {
            std::task::Poll::Ready(Ok(n)) => return extract_sni_from_client_hello(&buf[..n]),
            std::task::Poll::Ready(Err(_)) => return None,
            // Spurious readiness / `WouldBlock`: drop the buffer, then wait for
            // a fresh readiness event rather than holding it across the await.
            std::task::Poll::Pending => continue,
        }
    }
    // Readiness kept proving phantom: fail closed rather than spin.
    None
}

/// Extract the SNI hostname from a TLS ClientHello by peeking at a TCP stream.
///
/// Uses `TcpStream::peek()` to read bytes without consuming them, so the same
/// stream can be forwarded to the backend with the ClientHello intact.
///
/// `handshake_timeout` bounds how long the peek can wait for the ClientHello
/// before giving up. A `None` value preserves the single-peek behavior used by
/// internal callers that have already enforced a deadline elsewhere; passthrough
/// listeners pass `Some(d)` (mapped from `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`)
/// so a peer that opens a TCP connection and sends nothing cannot park a
/// connection-handler task indefinitely. The no-deadline path awaits socket
/// readiness with no buffer allocated, then takes one non-blocking peek into a
/// full [`no_deadline_peek_capacity`] buffer that is dropped before any further
/// await — so an idle peer pins nothing, while a readable peer's oversized
/// ClientHello is still inspected up to the hard cap.
///
/// When a deadline is set, the peek LOOPS until the full ClientHello handshake
/// (`5 + record_len` bytes across records, capped at [`MAX_CLIENT_HELLO_LEN`])
/// is buffered. The peek buffer starts at [`initial_peek_capacity`] and grows
/// toward the hard cap only when the wire-span parser reports more bytes are
/// needed and the current buffer is full. `peek()` re-reads from byte 0 of the
/// socket receive buffer on every call, so growing between iterations is safe.
/// `peek()` returns as soon as ≥1 byte is readable, so a single peek sees a
/// truncated ClientHello whenever it spans multiple TCP segments — routine for
/// modern ~1.7 KB post-quantum ClientHellos — and a truncated parse silently
/// misroutes the connection to the catch-all proxy. Mirrors the bounded peek
/// loop in `tcp_proxy::peek_tcp_first_bytes`.
///
/// Returns `None` if the data is not a valid TLS ClientHello, has no SNI
/// extension, the peek fails, or the timeout fires.
pub async fn extract_sni_from_tcp_stream(
    stream: &tokio::net::TcpStream,
    handshake_timeout: Option<std::time::Duration>,
) -> Option<String> {
    let Some(d) = handshake_timeout else {
        return peek_sni_without_deadline(stream).await;
    };

    let mut buf = vec![0u8; initial_peek_capacity()];

    let deadline = tokio::time::Instant::now() + d;
    let mut have = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(0)) => return None, // EOF before a complete ClientHello
            Ok(Ok(n)) => have = n,
            Ok(Err(_)) => return None,
            Err(_) => {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                tracing::debug!(
                    peer = %peer,
                    timeout_ms = d.as_millis() as u64,
                    buffered = have,
                    "TCP passthrough SNI peek timed out before full ClientHello arrived"
                );
                // Parse whatever prefix was observed — a complete-but-slow
                // record already parsed below, so this only salvages the
                // (unlikely) case where SNI sits inside the partial prefix.
                return extract_sni_from_client_hello(&buf[..have]);
            }
        }
        // Reject non-TLS prefixes as soon as the first byte is visible. Waiting
        // for the full record header would let one malformed byte park this
        // task until the handshake timeout.
        if have >= 1 && buf[0] != 0x16 {
            return None;
        }

        // Determine how many wire bytes cover the full ClientHello handshake
        // message — which MAY span multiple TLS records (record fragmentation) —
        // and keep peeking until they are all buffered. The span is known once
        // the handshake header (msg_type + 3-byte length) has been reassembled
        // across records — which may take more than the first record when a
        // fragment splits inside that 4-byte header; before that, keep peeking.
        match tls_clienthello_wire_span(&buf[..have], MAX_CLIENT_HELLO_LEN) {
            WireSpan::Span(want) if have >= want => {
                // Full ClientHello handshake (across all its records) buffered.
                return extract_sni_from_client_hello(&buf[..have]);
            }
            WireSpan::NotClientHello => {
                // The first handshake byte proved this is not a ClientHello (e.g.
                // a complete handshake record whose msg_type != 0x01). Reject now
                // rather than re-peek the same bytes until the handshake timeout —
                // a no-SNI `None` routes the connection to the catch-all per the
                // existing non-ClientHello semantics.
                return None;
            }
            // `Span` with more bytes still to buffer, or `NeedMore`: keep peeking
            // only while the hard peek bound still has room. A full buffer that
            // still cannot complete the ClientHello must fail closed immediately —
            // further peeks cannot grow past `MAX_CLIENT_HELLO_LEN`, and waiting
            // until the handshake deadline would only prolong the same truncated
            // parse (which must not invent an SNI from a partial oversized hello).
            WireSpan::Span(_) | WireSpan::NeedMore if have >= MAX_CLIENT_HELLO_LEN => {
                return extract_sni_from_client_hello(&buf[..have]);
            }
            WireSpan::Span(_) | WireSpan::NeedMore => {
                // Grow lazily only when the current buffer is full and the
                // parser still needs more wire bytes. `peek()` always re-reads
                // from byte 0 of the socket receive buffer, so resizing here is
                // safe: the next peek fills the larger slice from the start and
                // replaces `have`. If we grew, retry immediately — more bytes
                // may already be sitting in the socket buffer.
                if have >= buf.len() {
                    let want = next_peek_capacity(have);
                    if want > buf.len() {
                        buf.resize(want, 0);
                        continue;
                    }
                }
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return extract_sni_from_client_hello(&buf[..have]);
        }
        let wake = (now + SNI_PEEK_RETRY_INTERVAL).min(deadline);
        tokio::time::sleep_until(wake).await;
    }
}

/// Extract the SNI hostname from a TLS ClientHello byte slice.
///
/// Parses the TLS record layer and handshake message to find the
/// server_name extension (type 0x0000) per RFC 6066 §3.
///
/// Works for both TLS 1.2 and TLS 1.3 ClientHello messages.
pub fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // TLS record header: content_type (1) + version (2) + length (2) = 5 bytes
    if data.len() < 5 {
        return None;
    }

    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let first_payload = data.get(5..5 + record_len.min(data.len() - 5))?;

    // Fast path (the overwhelmingly common case): the whole ClientHello handshake
    // message fits inside the first TLS record, so parse it in place with no
    // allocation. The handshake header is msg_type (1) + length (3).
    if first_payload.len() >= 4 {
        let msg_len = u24_to_usize(&first_payload[1..4]);
        if first_payload.len() >= 4 + msg_len {
            return parse_client_hello_sni(first_payload);
        }
    }

    // The ClientHello handshake message spans multiple TLS records (record
    // fragmentation — protocol-valid: a single handshake message MAY be split
    // across records, and SNI can land in a later record). Reassemble the
    // handshake-layer bytes from consecutive handshake records and parse the
    // joined message. Without this, SNI in a non-first record is missed and the
    // connection silently misroutes to the catch-all proxy.
    let handshake = reassemble_tls_handshake_records(data)?;
    parse_client_hello_sni(&handshake)
}

/// Concatenate the handshake-layer payloads of consecutive TLS handshake records
/// in `data` so a ClientHello fragmented across records can be parsed as one
/// message. Stops at the first non-handshake record, a record truncated in the
/// buffer, or the end of the buffer. Bounded by the caller's buffer length
/// (`MAX_CLIENT_HELLO_LEN` on the peek path).
fn reassemble_tls_handshake_records(data: &[u8]) -> Option<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut pos = 0usize;
    while pos + 5 <= data.len() {
        // Only handshake (0x16) records carry ClientHello fragments.
        if data[pos] != 0x16 {
            break;
        }
        let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let payload_start = pos + 5;
        let avail = (data.len() - payload_start).min(record_len);
        handshake.extend_from_slice(&data[payload_start..payload_start + avail]);
        if avail < record_len {
            // Record payload truncated in the buffer — can't continue past it.
            break;
        }
        pos = payload_start + record_len;
    }
    if handshake.is_empty() {
        None
    } else {
        Some(handshake)
    }
}

/// Outcome of computing how many wire bytes span a ClientHello handshake.
///
/// The peek loop must distinguish "keep peeking" from "this can never be a
/// ClientHello", so it can reject a non-ClientHello first record immediately
/// instead of re-peeking the same bytes until the handshake timeout fires. A
/// bare `Option<usize>` conflated those two: `None` was returned both when more
/// bytes were needed AND when the first handshake byte proved the message was
/// not a ClientHello, so the loop treated a definitive rejection as need-more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireSpan {
    /// The full extent (in wire bytes from the buffer start) of the ClientHello
    /// handshake message is known and equals this many bytes.
    Span(usize),
    /// More bytes must be buffered before the span can be computed — keep peeking.
    NeedMore,
    /// The first handshake `msg_type` is present and is not ClientHello (`0x01`):
    /// this stream is definitively not a ClientHello. The peek loop must stop and
    /// reject promptly rather than wait for more bytes.
    NotClientHello,
}

/// Total wire bytes (TLS record headers + payloads) that span the complete
/// ClientHello handshake message, given a buffer that begins with a handshake
/// record. The handshake message length (its 3-byte header field) determines how
/// many record payloads must be summed; a single message MAY be fragmented
/// across records. Returns [`WireSpan::NeedMore`] while more bytes are needed to
/// compute the span and [`WireSpan::NotClientHello`] as soon as the first
/// handshake byte proves the message is not a ClientHello. Capped at `cap` so a
/// hostile length field cannot request unbounded buffering.
///
/// The 4-byte handshake header (msg_type + u24 length) is itself reassembled
/// across records before the length is read: record fragmentation can split the
/// handshake message after only the 1-byte msg_type, so the length bytes may
/// live in the NEXT TLS record. Reading them from a fixed `buf[6..9]` offset
/// would then capture the next record's header instead. We therefore walk the
/// handshake-record payloads, accumulating bytes until at least 4 handshake-layer
/// bytes are available, and only then compute the span. The `msg_type` check
/// happens as soon as the first handshake byte lands (it may arrive before the
/// remaining 3 length bytes), so a non-ClientHello is rejected at the earliest
/// possible point.
fn tls_clienthello_wire_span(buf: &[u8], cap: usize) -> WireSpan {
    if buf.is_empty() {
        return WireSpan::NeedMore;
    }
    if buf[0] != 0x16 {
        // Not even a TLS handshake record — definitively not a ClientHello.
        return WireSpan::NotClientHello;
    }

    let mut pos = 0usize;
    // Handshake-layer bytes seen so far (payload only, record headers excluded).
    let mut handshake_seen = 0usize;
    // First four reassembled handshake-layer bytes: msg_type (1) + u24 length (3).
    let mut header = [0u8; 4];
    let mut header_filled = 0usize;
    // `handshake_total` becomes known once the 4-byte header is reassembled.
    let mut handshake_total: Option<usize> = None;

    loop {
        if pos + 5 > buf.len() {
            // Need the next record header before the span can be extended.
            return WireSpan::NeedMore;
        }
        if buf[pos] != 0x16 {
            // Interleaved non-handshake record: stop at the previous boundary so
            // the handshake records gathered so far are parsed.
            return WireSpan::Span(pos.clamp(1, cap));
        }
        let record_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let payload_start = pos + 5;
        let record_end = payload_start + record_len;

        // Reassemble the handshake header (msg_type + u24 length) across records
        // before trusting the length. Only consume the bytes actually buffered in
        // this record's payload — a record may be truncated in `buf`.
        if header_filled < 4 {
            let avail = buf.len().min(record_end).saturating_sub(payload_start);
            let take = avail.min(4 - header_filled);
            header[header_filled..header_filled + take]
                .copy_from_slice(&buf[payload_start..payload_start + take]);
            header_filled += take;
            // Reject as soon as the 1-byte msg_type is known — it may land before
            // the remaining 3 length bytes when a fragment splits inside the
            // handshake header. msg_type 0x01 = ClientHello; anything else is not
            // a ClientHello and must be rejected promptly so the peek loop stops
            // re-peeking instead of stalling until the handshake timeout.
            if header_filled >= 1 && header[0] != 0x01 {
                return WireSpan::NotClientHello;
            }
            if header_filled == 4 {
                handshake_total = Some(4usize.saturating_add(u24_to_usize(&header[1..4])));
            }
        }

        handshake_seen = handshake_seen.saturating_add(record_len);

        if let Some(total) = handshake_total {
            if handshake_seen >= total || record_end >= cap {
                return WireSpan::Span(record_end.min(cap));
            }
        } else if record_end >= cap {
            // Header still unknown but we've hit the cap — buffer no further.
            return WireSpan::Span(record_end.min(cap));
        }

        pos = record_end;
    }
}

/// Outcome of parsing a DTLS ClientHello datagram for its SNI hostname.
///
/// The distinction between [`NoSni`](DtlsSniResult::NoSni) and
/// [`InvalidFragment`](DtlsSniResult::InvalidFragment) is load-bearing for
/// passthrough routing: `NoSni` is eligible for the empty-host catch-all proxy
/// (matching plain no-SNI behavior), whereas `InvalidFragment` must be DROPPED.
/// A fragmented DTLS ClientHello (a continuation fragment, or an initial fragment
/// whose SNI lives in a later, unseen fragment) carries no usable SNI start, so
/// creating a catch-all session for it would bind a partial-message datagram with
/// no real SNI to the catch-all. Collapsing both to a bare `None` (the old return
/// type) hid that case as no-SNI and routed it.
///
/// `InvalidFragment` is returned for any DTLS ClientHello fragment that cannot be
/// fully parsed in this single datagram: a continuation fragment
/// (`fragment_offset != 0`) or an initial fragment of a fragmented message
/// (`fragment_offset == 0 && fragment_length < length`) from which no SNI was
/// extracted. Every other "can't extract an SNI" path (too short, wrong content
/// type, non-ClientHello, malformed body, or a complete single-fragment
/// ClientHello with no SNI) stays `NoSni` so existing catch-all routing is
/// preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtlsSniResult {
    /// A ClientHello with a parsed SNI hostname (already ASCII-lowercased).
    Hostname(String),
    /// No SNI could be extracted, but the datagram may legitimately begin a
    /// session — routes to the catch-all, matching plain (no-SNI) behavior.
    NoSni,
    /// A DTLS ClientHello fragment that cannot be fully parsed from this single
    /// datagram: a continuation fragment (`fragment_offset != 0`), or an initial
    /// fragment of a fragmented message (`fragment_length < length`) whose SNI is
    /// not present in this fragment. The passthrough caller DROPS this rather than
    /// binding it to the empty-host catch-all.
    InvalidFragment,
}

/// Extract the SNI hostname from a DTLS ClientHello datagram.
///
/// DTLS uses a 13-byte record header (vs 5 for TLS) and a 12-byte handshake
/// header (vs 4 for TLS) with epoch, sequence number, and fragment offsets.
///
/// Returns a [`DtlsSniResult`] so the passthrough caller can tell a genuine
/// no-SNI ClientHello (catch-all eligible) apart from a fragment that must be
/// dropped rather than routed (a continuation fragment, or an initial fragment of
/// a fragmented ClientHello whose SNI is not in this datagram).
pub fn extract_sni_from_dtls_client_hello(data: &[u8]) -> DtlsSniResult {
    // DTLS record header: content_type (1) + version (2) + epoch (2) +
    //                     sequence_number (6) + length (2) = 13 bytes
    if data.len() < 13 {
        return DtlsSniResult::NoSni;
    }

    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return DtlsSniResult::NoSni;
    }

    let record_len = u16::from_be_bytes([data[11], data[12]]) as usize;
    let Some(handshake_data) = data.get(13..13 + record_len.min(data.len() - 13)) else {
        return DtlsSniResult::NoSni;
    };

    // DTLS handshake header: msg_type (1) + length (3) + message_seq (2) +
    //                        fragment_offset (3) + fragment_length (3) = 12 bytes
    if handshake_data.len() < 12 {
        return DtlsSniResult::NoSni;
    }

    // msg_type 0x01 = ClientHello
    if handshake_data[0] != 0x01 {
        return DtlsSniResult::NoSni;
    }

    // DTLS handshake header: total length (1..4), message_seq (4..6),
    // fragment_offset (6..9), fragment_length (9..12). A ClientHello MAY be
    // fragmented across datagrams. Passthrough mode does not reassemble fragments
    // across datagrams, so signal `InvalidFragment` on a fragment that does not
    // carry a complete, parseable ClientHello rather than misparse partial bytes
    // and bind a bogus session. Returning `InvalidFragment` (not `NoSni`) keeps
    // the caller from binding the fragment to the empty-host catch-all.
    let fragment_offset = u24_to_usize(&handshake_data[6..9]);
    if fragment_offset != 0 {
        // A continuation fragment carries no parseable handshake start.
        return DtlsSniResult::InvalidFragment;
    }
    let handshake_total_len = u24_to_usize(&handshake_data[1..4]);
    let fragment_len = u24_to_usize(&handshake_data[9..12]);
    let Some(client_hello) =
        handshake_data.get(12..12 + fragment_len.min(handshake_data.len() - 12))
    else {
        return DtlsSniResult::NoSni;
    };

    match parse_dtls_client_hello_body(client_hello) {
        // SNI was found within this fragment — route on it regardless of whether
        // the full message spans more datagrams.
        Some(hostname) => DtlsSniResult::Hostname(hostname),
        // No SNI parsed from this fragment. An INITIAL fragment (offset 0) of a
        // FRAGMENTED ClientHello (`fragment_length < length`) does not contain the
        // whole message: the SNI extension may live in a later, unseen fragment.
        // Passthrough does not reassemble, so fail closed (`InvalidFragment`)
        // rather than treat it as genuinely no-SNI and bind the empty-host
        // catch-all — exactly the bogus session this guard exists to prevent. A
        // complete single-fragment ClientHello (`fragment_length == length`) with
        // no SNI is genuinely no-SNI and stays catch-all eligible (`NoSni`).
        None if fragment_len < handshake_total_len => DtlsSniResult::InvalidFragment,
        None => DtlsSniResult::NoSni,
    }
}

/// Parse the SNI from a TLS handshake payload (after the 5-byte TLS record header).
fn parse_client_hello_sni(handshake: &[u8]) -> Option<String> {
    // Handshake header: msg_type (1) + length (3) = 4 bytes
    if handshake.len() < 4 {
        return None;
    }

    // msg_type 0x01 = ClientHello
    if handshake[0] != 0x01 {
        return None;
    }

    let body_len = u24_to_usize(&handshake[1..4]);
    let body = handshake.get(4..4 + body_len.min(handshake.len() - 4))?;

    parse_tls_client_hello_body(body)
}

/// Parse the SNI from a TLS ClientHello body (after handshake header).
///
/// Layout: version (2) + random (32) + session_id_len (1) + session_id (N) +
///         cipher_suites_len (2) + cipher_suites (N) + compression_len (1) +
///         compression (N) + extensions_len (2) + extensions (N)
fn parse_tls_client_hello_body(body: &[u8]) -> Option<String> {
    let mut pos: usize = 0;

    // version (2) + random (32)
    pos = pos.checked_add(34)?;
    if body.len() < pos {
        return None;
    }

    // session_id
    let session_id_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + session_id_len)?;
    if body.len() < pos {
        return None;
    }

    // cipher_suites
    if body.len() < pos + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2 + cipher_suites_len)?;
    if body.len() < pos {
        return None;
    }

    // compression_methods
    let compression_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + compression_len)?;
    if body.len() < pos {
        return None;
    }

    // extensions
    if body.len() < pos + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len.min(body.len() - pos);
    parse_sni_from_extensions(&body[pos..extensions_end])
}

/// Parse the SNI from a DTLS ClientHello body (after handshake header).
///
/// Layout: version (2) + random (32) + session_id_len (1) + session_id (N) +
///         cookie_len (1) + cookie (N) + cipher_suites_len (2) + cipher_suites (N) +
///         compression_len (1) + compression (N) + extensions_len (2) + extensions (N)
fn parse_dtls_client_hello_body(body: &[u8]) -> Option<String> {
    let mut pos: usize = 0;

    // version (2) + random (32)
    pos = pos.checked_add(34)?;
    if body.len() < pos {
        return None;
    }

    // session_id
    let session_id_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + session_id_len)?;
    if body.len() < pos {
        return None;
    }

    // cookie (DTLS-specific, not present in TLS)
    let cookie_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + cookie_len)?;
    if body.len() < pos {
        return None;
    }

    // cipher_suites
    if body.len() < pos + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2 + cipher_suites_len)?;
    if body.len() < pos {
        return None;
    }

    // compression_methods
    let compression_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + compression_len)?;
    if body.len() < pos {
        return None;
    }

    // extensions
    if body.len() < pos + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len.min(body.len() - pos);
    parse_sni_from_extensions(&body[pos..extensions_end])
}

/// Walk the TLS extensions list and extract the hostname from the SNI extension.
///
/// Extension format: type (2) + length (2) + data (N)
/// SNI extension (type 0x0000) data: list_length (2) + name_type (1) + name_length (2) + name (N)
fn parse_sni_from_extensions(mut ext: &[u8]) -> Option<String> {
    while ext.len() >= 4 {
        let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
        let ext_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;

        if ext.len() < 4 + ext_len {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI extension
            let sni_data = &ext[4..4 + ext_len];
            return parse_sni_hostname(sni_data);
        }

        ext = &ext[4 + ext_len..];
    }
    None
}

/// Parse the hostname from SNI extension data.
///
/// SNI list: total_length (2) + entries...
/// Each entry: name_type (1) + name_length (2) + name (N)
/// name_type 0x00 = host_name (DNS hostname)
fn parse_sni_hostname(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + list_len {
        return None;
    }

    let names = &data[2..];
    let mut pos = 0;

    while pos + 3 <= names.len() {
        let name_type = names[pos];
        let name_len = u16::from_be_bytes([names[pos + 1], names[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > names.len() {
            return None;
        }

        if name_type == 0x00 {
            // host_name. SNI host_name is a DNS hostname; validate before
            // allocating so oversized or malformed attacker-controlled names do
            // not get retained by stream lifecycle logging.
            let hostname = &names[pos..pos + name_len];
            return is_valid_sni_dns_hostname(hostname).then(|| {
                hostname
                    .iter()
                    .map(u8::to_ascii_lowercase)
                    .map(char::from)
                    .collect()
            });
        }

        pos += name_len;
    }

    None
}

fn is_valid_sni_dns_hostname(hostname: &[u8]) -> bool {
    const MAX_DNS_HOSTNAME_LEN: usize = 253;
    const MAX_DNS_LABEL_LEN: usize = 63;

    if hostname.is_empty() || hostname.len() > MAX_DNS_HOSTNAME_LEN {
        return false;
    }

    let mut label_len = 0usize;
    let mut previous = b'.';

    for &byte in hostname {
        if byte == b'.' {
            if label_len == 0 || label_len > MAX_DNS_LABEL_LEN || previous == b'-' {
                return false;
            }
            label_len = 0;
            previous = byte;
            continue;
        }

        if !byte.is_ascii_alphanumeric() && byte != b'-' {
            return false;
        }

        if label_len == 0 && byte == b'-' {
            return false;
        }

        label_len += 1;
        if label_len > MAX_DNS_LABEL_LEN {
            return false;
        }
        previous = byte;
    }

    label_len > 0 && previous != b'-'
}

/// Read a 3-byte big-endian unsigned integer.
fn u24_to_usize(data: &[u8]) -> usize {
    ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize)
}

/// Resolve which proxy should handle a connection based on SNI hostname.
///
/// Given an extracted SNI and a list of candidate proxy IDs (all sharing the
/// same listen_port with `passthrough: true`), finds the matching proxy by
/// comparing the SNI against each proxy's `hosts` field.
///
/// Matching rules (in priority order):
/// 1. Exact host match (case-insensitive, SNI is already lowercased)
/// 2. Wildcard host match (e.g., `*.example.com` matches any DNS name below `example.com`)
/// 3. Fallback: first proxy with empty `hosts` (catch-all/default)
/// 4. If no match and no fallback: `None`
///
/// Namespace-agnostic single-namespace helper.
///
/// **Not for runtime use.** Candidate IDs are matched against `config.proxies`
/// by bare ID, so it cannot distinguish two namespaces that reuse one proxy ID.
/// Every listener path resolves through
/// [`resolve_proxy_by_sni_in_epoch`], which takes namespace-qualified
/// candidates.
#[allow(dead_code)] // Public test/library helper; runtime uses the RequestEpoch-indexed variant.
pub fn resolve_proxy_by_sni<'a>(
    sni: Option<&str>,
    proxy_ids: &'a [String],
    config: &crate::config::types::GatewayConfig,
) -> Option<&'a str> {
    resolve_proxy_by_sni_with_lookup(sni, proxy_ids, |proxy_id| {
        config.proxies.iter().find(|p| &p.id == proxy_id)
    })
    .map(String::as_str)
}

/// Resolve a shared passthrough listener's SNI to one of its namespace-qualified
/// candidate proxies.
///
/// Candidates carry their owning namespace because a single `listen_port` may be
/// shared by same-ID passthrough proxies in different namespaces; matching by
/// bare ID would route one tenant's connection to another tenant's proxy.
pub fn resolve_proxy_by_sni_in_epoch<'a>(
    sni: Option<&str>,
    candidates: &'a [crate::config::db_backend::NamespacedResourceId],
    epoch: &crate::request_epoch::RequestEpoch,
) -> Option<&'a crate::config::db_backend::NamespacedResourceId> {
    resolve_proxy_by_sni_with_lookup(sni, candidates, |candidate| {
        epoch.proxy_by_namespaced_id(&candidate.namespace, &candidate.id)
    })
}

fn resolve_proxy_by_sni_with_lookup<'a, 'p, C>(
    sni: Option<&str>,
    candidates: &'a [C],
    mut find_proxy: impl FnMut(&C) -> Option<&'p crate::config::types::Proxy>,
) -> Option<&'a C> {
    let mut fallback: Option<&'a C> = None;
    let mut wildcard_match: Option<&'a C> = None;

    for proxy_id in candidates {
        let Some(proxy) = find_proxy(proxy_id) else {
            continue;
        };

        if proxy.hosts.is_empty() {
            // Empty hosts = catch-all, use as fallback
            if fallback.is_none() {
                fallback = Some(proxy_id);
            }
            continue;
        }

        if let Some(hostname) = sni {
            for host in &proxy.hosts {
                if host == hostname {
                    // Exact match wins immediately — a wildcard proxy listed
                    // earlier in `proxy_ids` must not steal traffic from an
                    // exact-host proxy (routing tier order: exact, wildcard,
                    // catch-all).
                    return Some(proxy_id);
                }
                if wildcard_match.is_none()
                    && crate::config::types::wildcard_matches(host, hostname)
                {
                    wildcard_match = Some(proxy_id);
                }
            }
        }
    }

    // No exact match — first wildcard match, then catch-all fallback
    wildcard_match.or(fallback)
}
