//! SNI (Server Name Indication) extraction from TLS/DTLS ClientHello messages.
//!
//! This is the gateway's ONE ClientHello parser. Everything that needs to know
//! what a client asked for before any TLS state exists goes through it:
//! passthrough and ordinary opaque TCP stream listeners routing by SNI, mesh
//! inbound classification, the Linux kTLS handoff gate, and DTLS passthrough.
//! Do not add a second parser — extend this one.
//!
//! Two levels of answer:
//!
//! * [`peek_client_hello_sni`] / [`classify_client_hello`] validate the complete
//!   bounded ClientHello, then answer "what hostname, and why not" as
//!   [`ClientHelloSni`]. [`extract_sni_from_tcp_stream`] is the `Option<String>`
//!   projection of that same strict result for non-routing consumers.
//! * [`extract_sni_from_client_hello`] is the shared lenient raw-slice hostname
//!   parser. Admission invokes it only after strict whole-hello validation; a
//!   readable early SNI must not hide an oversized or malformed tail.
//!
//! SNI *route selection* needs the typed answer: a hello that timed out,
//! overran the peek bound, ended early, is malformed, or names something
//! unrepresentable must fail closed ([`admit_opaque_tls_sni`]) rather than
//! silently inherit the listener's catch-all route, which would be a
//! cross-tenant downgrade (issue #3264).
//!
//! Peeking never consumes: the ClientHello and every other inspected byte stay
//! queued on the socket and reach the selected backend verbatim.

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
/// returned `WouldBlock`) or after observing a still-incomplete ClientHello.
///
/// The no-deadline path must never hold the hard-cap buffer across a
/// suspension, so a spurious wakeup drops the buffer and waits again rather
/// than parking with it allocated. Each retry costs one readiness event from
/// the OS plus one [`SNI_PEEK_RETRY_INTERVAL`] tick — not a busy loop — but the
/// count is still bounded so a socket that somehow keeps reporting phantom
/// readiness (or a peer that dribbles a ClientHello forever) fails closed
/// instead of spinning.
const MAX_PEEK_READINESS_RETRIES: usize = 3;

/// Why a bounded ClientHello peek could not reach a determinate answer.
///
/// Every variant is a **fail-closed** signal for SNI route selection: the
/// connection may well have declared a tenant hostname that this peek could not
/// read, so routing it to the listener's catch-all would be a cross-tenant
/// downgrade. Callers that only need "did we learn a hostname" keep using
/// [`extract_sni_from_tcp_stream`], which collapses all of these to `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniPeekFailure {
    /// The handshake deadline expired before the ClientHello was fully buffered.
    Timeout,
    /// The hard peek bound ([`MAX_CLIENT_HELLO_LEN`]) filled while the
    /// ClientHello was still incomplete.
    Oversized,
    /// The peer closed (or half-closed) before finishing the ClientHello.
    Eof,
    /// The buffered prefix is a TLS handshake record but not yet a complete
    /// ClientHello, and the peek ended with no more specific reason.
    Truncated,
    /// A complete ClientHello was buffered but its structure is invalid.
    Malformed,
    /// A complete ClientHello carried a `server_name` extension whose value is
    /// not a representable DNS host name (see [`is_valid_sni_dns_hostname`]).
    /// The client named *something*; refusing is what keeps an unreadable name
    /// from silently becoming the catch-all's traffic.
    UnrepresentableName,
    /// Peeking the socket failed, or readiness never produced readable bytes.
    Io,
}

impl SniPeekFailure {
    /// Stable, allocation-free label for logs and operator diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Oversized => "oversized",
            Self::Eof => "eof",
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
            Self::UnrepresentableName => "unrepresentable_server_name",
            Self::Io => "io_error",
        }
    }
}

/// Typed outcome of inspecting a TLS ClientHello for SNI.
///
/// The historical `Option<String>` collapsed four very different situations
/// into `None` — "well-formed hello with no `server_name`", "these bytes are
/// not TLS at all", "the hello never finished arriving", and "the hello is
/// malformed". SNI route selection then sent all four to the listener's
/// catch-all proxy, so a slow, fragmented, oversized, or hostile ClientHello
/// that *did* declare `tenant-a.example.com` landed on whichever tenant owned
/// the default route. This enum is what lets the routing plane fail closed on
/// the indeterminate cases while preserving catch-all semantics for the two
/// determinate ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloSni {
    /// A ClientHello whose `server_name` yielded a representable, normalized
    /// (ASCII-lowercased) DNS host name.
    Sni(String),
    /// A complete, well-formed ClientHello that carried no `server_name`
    /// extension. Determinate: the client asked for no host.
    NoSni,
    /// The opening bytes are provably not a TLS ClientHello — the first byte is
    /// not a handshake record (`0x16`), or the first handshake message type is
    /// not `client_hello` (`0x01`). Determinate.
    NotTls,
    /// No determinate answer could be reached. Always fail closed.
    Indeterminate(SniPeekFailure),
}

impl ClientHelloSni {
    /// Borrow the parsed hostname, if any.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::Sni(hostname) => Some(hostname.as_str()),
            _ => None,
        }
    }

    /// Consume into the historical `Option<String>` shape.
    pub fn into_hostname(self) -> Option<String> {
        match self {
            Self::Sni(hostname) => Some(hostname),
            _ => None,
        }
    }
}

/// Why an opaque-TLS SNI listener refused a connection outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniRefusal {
    /// The bytes are provably not TLS and the listener does not authorize a
    /// plaintext fallback.
    NotTls,
    /// The ClientHello could not be read to a determinate answer.
    Indeterminate(SniPeekFailure),
}

impl SniRefusal {
    /// Stable, allocation-free label for logs and operator diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotTls => "not_tls",
            Self::Indeterminate(failure) => failure.as_str(),
        }
    }
}

/// What an opaque-TLS SNI listener does with a peeked ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniAdmission {
    /// Continue route selection with this SNI. `None` selects the catch-all
    /// tier (a proxy with empty `hosts`); when no catch-all is declared,
    /// resolution itself fails and the connection is still refused.
    Route(Option<String>),
    /// Refuse before any backend is resolved, dialed, or health/breaker-charged.
    Refuse(SniRefusal),
}

/// Decide whether a peeked ClientHello may proceed to SNI route selection on an
/// **opaque-TLS SNI listener** (a stream listener that never terminates TLS and
/// picks its route from `server_name`).
///
/// Precedence, deliberately fail-closed:
///
/// | peek outcome | admission |
/// |---|---|
/// | [`ClientHelloSni::Sni`] | route by that host through exact → wildcard → catch-all |
/// | [`ClientHelloSni::NoSni`] | route through the catch-all tier only |
/// | [`ClientHelloSni::NotTls`] | refuse, unless `allow_plaintext_fallback` |
/// | [`ClientHelloSni::Indeterminate`] | **always** refuse |
///
/// `allow_plaintext_fallback` is the operator's explicit authorization
/// (`FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK`) to keep direct, non-TLS TCP working
/// on a listener whose route table is keyed by SNI. It deliberately does NOT
/// extend to the indeterminate cases: "not TLS" is a determinate protocol
/// mismatch the operator can reason about, whereas a truncated/oversized/
/// timed-out/malformed hello may have declared any tenant's hostname.
pub fn admit_opaque_tls_sni(
    outcome: ClientHelloSni,
    allow_plaintext_fallback: bool,
) -> SniAdmission {
    match outcome {
        ClientHelloSni::Sni(hostname) => SniAdmission::Route(Some(hostname)),
        ClientHelloSni::NoSni => SniAdmission::Route(None),
        ClientHelloSni::NotTls if allow_plaintext_fallback => SniAdmission::Route(None),
        ClientHelloSni::NotTls => SniAdmission::Refuse(SniRefusal::NotTls),
        ClientHelloSni::Indeterminate(failure) => {
            SniAdmission::Refuse(SniRefusal::Indeterminate(failure))
        }
    }
}

/// Initial capacity of the TCP ClientHello peek buffer.
///
/// Pure sizing seam so external tests can lock the lazy-allocation floor
/// without observing live buffer capacity through the async peek path.
pub fn initial_peek_capacity() -> usize {
    INITIAL_CLIENT_HELLO_PEEK_LEN
}

/// Capacity of the buffer used by the no-deadline path.
///
/// That path has no handshake clock to loop against, so it re-peeks only on a
/// small fixed budget ([`MAX_PEEK_READINESS_RETRIES`]) and every one of those
/// peeks must be able to see a standards-valid oversized ClientHello in full —
/// it sizes straight to the hard cap rather than the lazy floor. Lazy growth
/// exists to bound memory held ACROSS the deadline-driven peek loop while a slow
/// peer dribbles bytes; it does not apply to a buffer that is allocated only
/// after the socket is already readable and dropped before the next await.
/// Capping this at the 4 KiB floor would silently truncate SNI extraction
/// whenever the frontend handshake timeout is disabled
/// (`FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=0`),
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

/// Bounded ClientHello peek for callers that pass no handshake deadline.
///
/// One initial peek plus at most [`MAX_PEEK_READINESS_RETRIES`] further peeks —
/// a fixed budget rather than a clock — so a stalled peer cannot park the task
/// waiting for a record that never completes. Two invariants have to hold at
/// once, so readiness and the buffer are deliberately separated:
///
/// 1. A silent peer must not pin a hard-cap allocation. `readable()` carries no
///    buffer, so an idle connection suspends here holding nothing.
/// 2. Once bytes are actually available, each peek must still be able to
///    inspect a standards-valid ClientHello up to [`MAX_CLIENT_HELLO_LEN`]
///    (issue #2962) — so the buffer is allocated only *after* readiness, at the
///    full cap, and dropped again before the next suspension.
///
/// Each peek is one non-blocking `poll_peek` wrapped in an always-`Ready`
/// future: it cannot suspend, so the hard-cap buffer is never live across an
/// await. A spurious readiness signal yields `Pending`; the buffer is dropped
/// and a fresh readiness event awaited, bounded by
/// [`MAX_PEEK_READINESS_RETRIES`] so this can never spin. There is no unbounded
/// read loop and no blocking wait.
///
/// A peek that lands mid-ClientHello is retried on the same bounded budget
/// (one [`SNI_PEEK_RETRY_INTERVAL`] tick apart, buffer dropped in between).
/// Without the handshake clock there is no deadline to loop against, and a
/// fragmented hello — routine for post-quantum ClientHellos — would otherwise
/// be reported as truncated on its first segment and refused by an SNI-routing
/// listener. Worst case adds `MAX_PEEK_READINESS_RETRIES` ticks.
async fn peek_sni_without_deadline(stream: &tokio::net::TcpStream) -> ClientHelloSni {
    let mut last = ClientHelloSni::Indeterminate(SniPeekFailure::Io);
    for attempt in 0..=MAX_PEEK_READINESS_RETRIES {
        if attempt > 0 {
            // `peek()` does not consume, so an immediate re-peek would observe
            // the same bytes; give the peer one bounded tick to deliver the
            // rest of a fragmented ClientHello. Nothing is allocated here — the
            // previous iteration's buffer was dropped at the end of its scope,
            // which is what preserves the "no hard-cap buffer across a
            // suspension" invariant.
            tokio::time::sleep(SNI_PEEK_RETRY_INTERVAL).await;
        }
        // No buffer is alive across this await: an idle peer pins nothing.
        if stream.readable().await.is_err() {
            return ClientHelloSni::Indeterminate(SniPeekFailure::Io);
        }

        let mut buf = vec![0u8; no_deadline_peek_capacity()];
        let polled = {
            let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
            poll_peek_once(stream, &mut read_buf).await
        };
        match polled {
            std::task::Poll::Ready(Ok(n)) => {
                let outcome = classify_client_hello(&buf[..n]);
                // A determinate answer is final. An incomplete hello may still
                // complete — modern post-quantum ClientHellos routinely span
                // several TCP segments — so re-peek (bounded) rather than fail
                // closed on the first fragment.
                if !matches!(
                    outcome,
                    ClientHelloSni::Indeterminate(SniPeekFailure::Truncated)
                ) {
                    return outcome;
                }
                last = outcome;
            }
            std::task::Poll::Ready(Err(_)) => {
                return ClientHelloSni::Indeterminate(SniPeekFailure::Io);
            }
            // Spurious readiness / `WouldBlock`: drop the buffer, then wait for
            // a fresh readiness event rather than holding it across the await.
            std::task::Poll::Pending => {
                last = ClientHelloSni::Indeterminate(SniPeekFailure::Io);
            }
        }
    }
    // Readiness kept proving phantom, or the hello never completed within the
    // bounded retry budget: fail closed rather than spin.
    last
}

/// Extract the SNI hostname from a TLS ClientHello by peeking at a TCP stream.
///
/// Uses `TcpStream::peek()` to read bytes without consuming them, so the same
/// stream can be forwarded to the backend with the ClientHello intact.
///
/// `handshake_timeout` bounds how long the peek can wait for the ClientHello
/// before giving up. A `None` value is for internal callers that have already
/// enforced a deadline elsewhere; passthrough listeners pass `Some(d)` (mapped
/// from `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`) so a peer that opens a
/// TCP connection and sends nothing cannot park a connection-handler task
/// indefinitely. With no deadline there is no clock to loop against, so the
/// path is bounded by a fixed retry budget instead: it awaits socket readiness
/// with no buffer allocated, then takes a non-blocking peek into a full
/// [`no_deadline_peek_capacity`] buffer that is dropped before any further
/// await, repeating at most `MAX_PEEK_READINESS_RETRIES` more times (one
/// `SNI_PEEK_RETRY_INTERVAL` tick apart) while the hello is still incomplete
/// or readiness proves spurious. So an idle peer pins nothing, a fragmented
/// hello is not misreported as truncated on its first segment, and a readable
/// peer's oversized ClientHello is still inspected up to the hard cap.
///
/// When a deadline is set, the peek LOOPS until the full ClientHello handshake
/// (`5 + record_len` bytes across records, capped at [`MAX_CLIENT_HELLO_LEN`])
/// is buffered. The peek buffer starts at [`initial_peek_capacity`] and grows
/// toward the hard cap only when the wire-span parser reports more bytes are
/// needed and the current buffer is full. `peek()` re-reads from byte 0 of the
/// socket receive buffer on every call, so growing between iterations is safe.
/// `peek()` returns as soon as ≥1 byte is readable, so a single peek sees a
/// truncated ClientHello whenever it spans multiple TCP segments — routine for
/// modern ~1.7 KB post-quantum ClientHellos. Mirrors the bounded peek loop in
/// `tcp_proxy::peek_tcp_first_bytes`.
///
/// Returns `None` if the data is not a valid TLS ClientHello, has no SNI
/// extension, the peek fails, or the timeout fires. Callers that must
/// distinguish those cases — SNI *route selection*, which has to fail closed
/// rather than default an unreadable hello to its catch-all — use
/// [`peek_client_hello_sni`] instead.
pub async fn extract_sni_from_tcp_stream(
    stream: &tokio::net::TcpStream,
    handshake_timeout: Option<std::time::Duration>,
) -> Option<String> {
    peek_client_hello_sni(stream, handshake_timeout)
        .await
        .into_hostname()
}

/// Bounded ClientHello peek that reports **why** no SNI was learned.
///
/// Same wire behavior, same parser, and the same hostname answer as
/// [`extract_sni_from_tcp_stream`] — every `Some(host)` there is
/// [`ClientHelloSni::Sni`] here and every `None` is one of the other variants.
/// The extra resolution exists so an SNI-routing listener can fail closed on
/// the indeterminate cases instead of silently defaulting them to its catch-all
/// route (issue #3264).
///
/// `TcpStream::peek()` never consumes, so every byte inspected here is still
/// queued on the socket and is replayed verbatim to whichever backend the route
/// table selects. Opaque TLS stays opaque: nothing is decrypted, rewritten, or
/// dropped.
pub async fn peek_client_hello_sni(
    stream: &tokio::net::TcpStream,
    handshake_timeout: Option<std::time::Duration>,
) -> ClientHelloSni {
    let Some(d) = handshake_timeout else {
        return peek_sni_without_deadline(stream).await;
    };

    let mut buf = vec![0u8; initial_peek_capacity()];

    let now = tokio::time::Instant::now();
    let deadline = match now.checked_add(d) {
        Some(deadline) => deadline,
        // Internal callers can supply a Duration directly. Keep that boundary
        // panic-free and fail closed if the requested Instant is not
        // representable instead of accidentally disabling the timeout.
        None => now,
    };
    let mut have = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            // EOF before a complete ClientHello.
            Ok(Ok(0)) => return terminal_client_hello(&buf[..have], SniPeekFailure::Eof),
            Ok(Ok(n)) => have = n,
            Ok(Err(_)) => return ClientHelloSni::Indeterminate(SniPeekFailure::Io),
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
                // Anything short of a readable hostname is `Timeout`, which an
                // SNI-routing listener refuses instead of defaulting.
                return terminal_client_hello(&buf[..have], SniPeekFailure::Timeout);
            }
        }
        // Reject non-TLS prefixes as soon as the first byte is visible. Waiting
        // for the full record header would let one malformed byte park this
        // task until the handshake timeout.
        if have >= 1 && buf[0] != 0x16 {
            return ClientHelloSni::NotTls;
        }

        // Determine how many wire bytes cover the full ClientHello handshake
        // message — which MAY span multiple TLS records (record fragmentation) —
        // and keep peeking until they are all buffered. The span is known once
        // the handshake header (msg_type + 3-byte length) has been reassembled
        // across records — which may take more than the first record when a
        // fragment splits inside that 4-byte header; before that, keep peeking.
        match tls_clienthello_wire_span(&buf[..have], MAX_CLIENT_HELLO_LEN) {
            WireSpan::NotClientHello => {
                // The first handshake byte proved this is not a ClientHello (e.g.
                // a complete handshake record whose msg_type != 0x01). Reject now
                // rather than re-peek the same bytes until the handshake timeout.
                // Determinate, so an SNI-routing listener may still honor an
                // explicitly authorized plaintext fallback.
                return ClientHelloSni::NotTls;
            }
            // The hard peek bound is full. Further peeks cannot grow past
            // `MAX_CLIENT_HELLO_LEN` and waiting until the handshake deadline
            // would only prolong the same truncated parse (which must not
            // invent an SNI from a partial oversized hello), so decide now. A
            // determinate answer that fits inside the bound still stands;
            // anything else is attributed to the bound. Checked BEFORE the
            // "span complete" arm because `tls_clienthello_wire_span` clamps
            // its answer to the cap, which would otherwise report an
            // over-cap hello as complete and mislabel it.
            WireSpan::Span(_) | WireSpan::NeedMore if have >= MAX_CLIENT_HELLO_LEN => {
                return terminal_client_hello(&buf[..have], SniPeekFailure::Oversized);
            }
            WireSpan::Span(want) if have >= want => {
                // Full ClientHello handshake (across all its records) buffered.
                return classify_client_hello(&buf[..have]);
            }
            // `Span` with more bytes still to buffer, or `NeedMore`: keep peeking.
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
            return terminal_client_hello(&buf[..have], SniPeekFailure::Timeout);
        }
        let wake = (now + SNI_PEEK_RETRY_INTERVAL).min(deadline);
        tokio::time::sleep_until(wake).await;
    }
}

/// Classify a buffered ClientHello prefix that the peek loop can no longer
/// extend, attributing any indeterminate result to the terminal `reason`
/// (deadline expiry, hard peek cap, or EOF) rather than the generic
/// "truncated". A determinate answer — a readable hostname, a well-formed
/// no-SNI hello, or provably non-TLS bytes — is returned unchanged.
fn terminal_client_hello(data: &[u8], reason: SniPeekFailure) -> ClientHelloSni {
    match classify_client_hello(data) {
        ClientHelloSni::Indeterminate(_) => ClientHelloSni::Indeterminate(reason),
        determinate => determinate,
    }
}

/// Classify a buffered TLS ClientHello prefix.
///
/// The bounded wire span and strict whole-hello parser run before the lenient
/// hostname extractor. This ordering is security-sensitive: a prefix can carry
/// a complete, readable `server_name` and still belong to an oversized hello or
/// be followed by malformed/duplicate extension data. Routing on that prefix
/// would let an indeterminate hello select and dial a tenant backend despite
/// the fail-closed admission contract. Once the whole hello is proven valid,
/// [`extract_sni_from_client_hello`] supplies the same normalized hostname used
/// by the other SNI consumers.
///
/// * not a handshake record / not `client_hello` → [`ClientHelloSni::NotTls`]
/// * hello not fully buffered → `Indeterminate(Truncated)`
/// * complete hello, no `server_name` → [`ClientHelloSni::NoSni`]
/// * complete hello, `server_name` present but unrepresentable →
///   `Indeterminate(UnrepresentableName)`
/// * complete but structurally invalid → `Indeterminate(Malformed)`
pub fn classify_client_hello(data: &[u8]) -> ClientHelloSni {
    let Some(&first) = data.first() else {
        return ClientHelloSni::Indeterminate(SniPeekFailure::Truncated);
    };
    // Content type 0x16 = Handshake. Anything else is provably not TLS.
    if first != 0x16 {
        return ClientHelloSni::NotTls;
    }
    match tls_clienthello_wire_span(data, MAX_CLIENT_HELLO_LEN) {
        WireSpan::NotClientHello => ClientHelloSni::NotTls,
        WireSpan::NeedMore => ClientHelloSni::Indeterminate(SniPeekFailure::Truncated),
        WireSpan::Span(want) if data.len() < want => {
            ClientHelloSni::Indeterminate(SniPeekFailure::Truncated)
        }
        // The whole ClientHello handshake message is buffered but yielded no
        // hostname. `client_hello_ktls_facts` is the strict whole-message
        // parser: it refuses any structural violation and reports whether a
        // `server_name` extension was present at all.
        WireSpan::Span(_) => match client_hello_ktls_facts(data) {
            Some(facts) => match extract_sni_from_client_hello(data) {
                Some(hostname) => ClientHelloSni::Sni(hostname),
                None if facts.offers_server_name => {
                    ClientHelloSni::Indeterminate(SniPeekFailure::UnrepresentableName)
                }
                None => ClientHelloSni::NoSni,
            },
            // `tls_clienthello_wire_span` clamps its answer to the hard bound,
            // so a buffer sitting exactly at the bound may hold only a prefix
            // of a larger hello. At the bound, "oversized" is the actionable
            // diagnosis; "malformed" would blame the client for framing this
            // parser deliberately refused to buffer.
            None if data.len() >= MAX_CLIENT_HELLO_LEN => {
                ClientHelloSni::Indeterminate(SniPeekFailure::Oversized)
            }
            None => ClientHelloSni::Indeterminate(SniPeekFailure::Malformed),
        },
    }
}

/// Normalize the hostname a TLS stack reports for a received `server_name`.
///
/// rustls validates a received SNI with its `DnsName` rules, which accept a
/// trailing root dot, and `ServerConnection::server_name()` (and quinn's
/// `HandshakeData::server_name`) report the name with that dot kept. Consumers
/// such as `mesh_authz`'s `connection.sni` compare the name as a string, so a
/// client sending `admin.example.com.` would otherwise slip past a policy
/// written for `admin.example.com`. This strips exactly one trailing dot and
/// ASCII-lowercases the rest, giving every read site one spelling of the name.
/// Returns `None` when nothing is left.
pub fn normalize_received_server_name(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// Extract the SNI hostname from a TLS ClientHello byte slice.
///
/// Parses the TLS record layer and handshake message to find the
/// server_name extension (type 0x0000) per RFC 6066 §3.
/// This helper is intentionally lenient about bytes after a complete SNI entry;
/// route admission must use [`classify_client_hello`], which validates the
/// entire declared ClientHello before invoking this extractor.
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

/// TLS 1.2 cipher suite code points rustls can actually negotiate, grouped by
/// the kernel TLS cipher family each maps to. Any other offered suite is
/// unselectable by rustls and therefore cannot influence the negotiated cipher.
const TLS12_AES128_GCM_SUITES: [u16; 2] = [0xC02B, 0xC02F];
const TLS12_AES256_GCM_SUITES: [u16; 2] = [0xC02C, 0xC030];
const TLS12_CHACHA20_POLY1305_SUITES: [u16; 2] = [0xCCA8, 0xCCA9];

/// TLS ClientHello facts that decide Linux kTLS handoff eligibility *before*
/// any handshake work is performed.
///
/// Deciding from the peeked ClientHello is what keeps the fallback free: the
/// gateway can refuse the kTLS path while the socket is still pristine, so the
/// ordinary buffered tokio-rustls accept takes over with nothing consumed. It
/// also avoids paying a second server flight (an extra signature) for the
/// dominant TLS 1.3 case, which is refused outright because the kernel holds a
/// static traffic secret and KeyUpdate is not handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientHelloKtlsFacts {
    /// The client offered TLS 1.3 through `supported_versions` (RFC 8446).
    pub offers_tls13: bool,
    /// At least one TLS 1.2 AES-128-GCM suite rustls can select was offered.
    pub offers_aes128_gcm: bool,
    /// At least one TLS 1.2 AES-256-GCM suite rustls can select was offered.
    pub offers_aes256_gcm: bool,
    /// At least one TLS 1.2 ChaCha20-Poly1305 suite rustls can select was offered.
    pub offers_chacha20_poly1305: bool,
    /// A `server_name` extension (RFC 6066, type 0x0000) was present, so the
    /// buffered accept would have had a hostname to report.
    pub offers_server_name: bool,
}

impl ClientHelloKtlsFacts {
    /// Whether the SNI derived from this peeked ClientHello can stand in for
    /// the value the buffered accept would have reported.
    ///
    /// The kTLS branch has no `ServerConnection::server_name()` to read back —
    /// `UnbufferedServerConnection` exposes no equivalent accessor — so it
    /// re-parses the hello with [`extract_sni_from_client_hello`]. That
    /// validator is deliberately stricter than the `DnsName` rules rustls
    /// applies to a received SNI: it refuses underscore labels and a trailing
    /// root dot, both of which rustls accepts. The buffered path passes
    /// rustls's name through [`normalize_received_server_name`], which strips
    /// a trailing root dot, so for a dotted name the difference is only that
    /// the handoff is declined (a performance cost, not a different name). An
    /// underscore label is the case that matters: the buffered path reports
    /// it, while a handed-off connection would report `None`, silently
    /// changing what stream lifecycle plugins, policy, and transaction
    /// summaries observe. Declining the handoff whenever a present
    /// `server_name` extension yields no hostname here keeps the two paths
    /// observationally identical; the socket is still pristine, so the
    /// buffered accept surfaces the normalized rustls value.
    pub fn sni_is_representable(&self, parsed_sni: Option<&str>) -> bool {
        !self.offers_server_name || parsed_sni.is_some()
    }

    /// Whether a kTLS handoff may be attempted for this ClientHello, given the
    /// per-cipher handoff-usability results.
    ///
    /// The three booleans are *handoff usability*, not bare kernel install
    /// probes: production marks AES-GCM families unusable (finite
    /// confidentiality limit; Linux cannot establish a race-free receive-record
    /// bound after accept) and ChaCha20-Poly1305 usable only when that cipher's
    /// kernel probe passed.
    ///
    /// Fails closed on every axis:
    /// * a TLS 1.3 offer disqualifies the connection outright, and
    /// * **every** selectable TLS 1.2 AEAD suite the client offered must be
    ///   handoff-usable. Predicting rustls's exact suite choice would mean
    ///   duplicating its selection logic, so an offer set that contains even
    ///   one unusable suite (AES-GCM under the confidentiality gate, or any
    ///   suite this kernel cannot install) is declined rather than gambled on.
    pub fn ktls_eligible(
        &self,
        aes128gcm_available: bool,
        aes256gcm_available: bool,
        chacha20_poly1305_available: bool,
    ) -> bool {
        if self.offers_tls13 {
            return false;
        }
        let mut selectable = false;
        if self.offers_aes128_gcm {
            if !aes128gcm_available {
                return false;
            }
            selectable = true;
        }
        if self.offers_aes256_gcm {
            if !aes256gcm_available {
                return false;
            }
            selectable = true;
        }
        if self.offers_chacha20_poly1305 {
            if !chacha20_poly1305_available {
                return false;
            }
            selectable = true;
        }
        selectable
    }
}

/// Parse kTLS handoff eligibility facts from a TLS ClientHello byte slice.
///
/// Returns `None` unless the **complete** ClientHello handshake message is
/// buffered and well formed. A truncated parse could miss the
/// `supported_versions` extension and mistake a TLS 1.3 client for a TLS 1.2
/// one, so partial input is a refusal, never an optimistic answer.
pub fn client_hello_ktls_facts(data: &[u8]) -> Option<ClientHelloKtlsFacts> {
    // TLS record header: content_type (1) + version (2) + length (2).
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let first_payload = data.get(5..5 + record_len.min(data.len() - 5))?;

    // Fast path: the whole ClientHello fits in the first record.
    if first_payload.len() >= 4 {
        let msg_len = u24_to_usize(&first_payload[1..4]);
        if first_payload.len() >= 4 + msg_len {
            return parse_client_hello_ktls_facts(first_payload);
        }
    }

    // Record-fragmented ClientHello: reassemble the handshake layer first.
    let handshake = reassemble_tls_handshake_records(data)?;
    parse_client_hello_ktls_facts(&handshake)
}

/// Parse kTLS facts from a complete handshake message (msg_type + u24 length +
/// body). Returns `None` if the message is not a fully buffered ClientHello.
fn parse_client_hello_ktls_facts(handshake: &[u8]) -> Option<ClientHelloKtlsFacts> {
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }
    let body_len = u24_to_usize(&handshake[1..4]);
    // Strict: the whole body must be present (no `.min(len)` salvage here).
    let body = handshake.get(4..4usize.checked_add(body_len)?)?;
    parse_tls_client_hello_ktls_facts(body)
}

/// Walk a complete ClientHello body for its cipher suite list and the
/// `supported_versions` extension.
///
/// Layout: version (2) + random (32) + session_id_len (1) + session_id (N) +
///         cipher_suites_len (2) + cipher_suites (N) + compression_len (1) +
///         compression (N) + [extensions_len (2) + extensions (N)]
fn parse_tls_client_hello_ktls_facts(body: &[u8]) -> Option<ClientHelloKtlsFacts> {
    let mut facts = ClientHelloKtlsFacts::default();

    // version (2) + random (32)
    let mut pos: usize = 34;
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
    if body.len() < pos.checked_add(2)? {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    // RFC 8446 §4.1.2: the vector contains two-byte CipherSuite values and
    // cannot be empty. An odd or empty vector is not a provable ClientHello;
    // do not let a trailing byte disappear from the eligibility decision.
    if cipher_suites_len < 2 || !cipher_suites_len.is_multiple_of(2) {
        return None;
    }
    let suites_start = pos.checked_add(2)?;
    let suites_end = suites_start.checked_add(cipher_suites_len)?;
    if body.len() < suites_end {
        return None;
    }
    let mut i = suites_start;
    while i + 2 <= suites_end {
        let suite = u16::from_be_bytes([body[i], body[i + 1]]);
        if TLS12_AES128_GCM_SUITES.contains(&suite) {
            facts.offers_aes128_gcm = true;
        } else if TLS12_AES256_GCM_SUITES.contains(&suite) {
            facts.offers_aes256_gcm = true;
        } else if TLS12_CHACHA20_POLY1305_SUITES.contains(&suite) {
            facts.offers_chacha20_poly1305 = true;
        }
        i += 2;
    }
    pos = suites_end;

    // compression_methods
    let compression_len = *body.get(pos)? as usize;
    // The legacy compression vector must contain at least the null method.
    if compression_len == 0 {
        return None;
    }
    pos = pos.checked_add(1 + compression_len)?;
    if body.len() < pos {
        return None;
    }

    // A ClientHello with no extensions block cannot request TLS 1.3.
    if body.len() == pos {
        return Some(facts);
    }

    // extensions
    if body.len() < pos.checked_add(2)? {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2)?;
    let extensions_end = pos.checked_add(extensions_len)?;
    // The extension vector is the final ClientHello field. Both truncation and
    // bytes outside its declared boundary are malformed and must be refused.
    if body.len() != extensions_end {
        return None;
    }

    let scanned = scan_client_hello_extensions(&body[pos..extensions_end])?;
    facts.offers_tls13 = scanned.offers_tls13;
    facts.offers_server_name = scanned.offers_server_name;
    Some(facts)
}

/// What the ClientHello extension block tells the pre-handshake kTLS gate.
#[derive(Debug, Clone, Copy, Default)]
struct ScannedExtensions {
    /// TLS 1.3 (0x0304) appeared in `supported_versions` (0x002b).
    offers_tls13: bool,
    /// A `server_name` extension (0x0000) was present.
    offers_server_name: bool,
}

/// Fixed-capacity "have I already seen this code point" bitset for the bounded
/// TLS enumerations this parser has to de-duplicate (extension types,
/// `ServerNameList` name types).
///
/// Both vectors are attacker-controlled up to [`MAX_CLIENT_HELLO_LEN`], so a
/// hostile peer can pack thousands of entries into one hello. Rescanning the
/// already-seen values for each entry would therefore be quadratic in a count
/// the client chooses. A bitset covering the *whole* code-point space makes
/// each test O(1) against a fixed, input-independent amount of stack — 8 KiB
/// for the 2^16 extension types, 32 bytes for the 2^8 name types — with no
/// allocation and no growth with input size.
struct SeenCodePoints<const WORDS: usize> {
    words: [u64; WORDS],
}

impl<const WORDS: usize> SeenCodePoints<WORDS> {
    fn empty() -> Self {
        Self {
            words: [0u64; WORDS],
        }
    }

    /// Record `code_point` and report whether it had already been recorded.
    ///
    /// A code point outside the sized space reports `true` (fail closed, so the
    /// caller refuses the hello) rather than indexing out of bounds; callers
    /// only pass `u16`/`u8` values that fit their chosen `WORDS`.
    fn insert_is_duplicate(&mut self, code_point: usize) -> bool {
        let Some(word) = self.words.get_mut(code_point / 64) else {
            return true;
        };
        let bit = 1u64 << (code_point % 64);
        let already_seen = *word & bit != 0;
        *word |= bit;
        already_seen
    }
}

/// Number of `u64` words needed to cover every 16-bit TLS extension type.
const EXTENSION_TYPE_BITSET_WORDS: usize = (u16::MAX as usize + 1) / 64;
/// Number of `u64` words needed to cover every 8-bit `ServerNameList` name type.
const NAME_TYPE_BITSET_WORDS: usize = (u8::MAX as usize + 1) / 64;

/// Walk the extension list for `supported_versions` (0x002b) and `server_name`
/// (0x0000), reporting whether TLS 1.3 was offered and whether the hello
/// carried an SNI extension at all.
///
/// Returns `None` on a malformed extension list: callers must treat that as
/// "cannot prove this is TLS 1.2", never as "this is TLS 1.2".
fn scan_client_hello_extensions(mut ext: &[u8]) -> Option<ScannedExtensions> {
    let mut scanned = ScannedExtensions::default();
    // RFC 8446 §4.2 (and RFC 5246 §7.4.1.4 before it): "There MUST NOT be more
    // than one extension of the same type in a given extension block." That
    // holds for EVERY extension type, not only the two this scan interprets —
    // so the whole-hello gate rejects a repeated arbitrary type as malformed.
    // Two reasons this has to be general:
    //   * the lenient hostname extractor returns from the FIRST `server_name`
    //     it sees, so a hello with a valid early SNI followed by any duplicate
    //     extension would otherwise still be admitted and select a tenant
    //     route off a structure the TLS grammar forbids, and
    //   * for `supported_versions` specifically, an earlier TLS 1.2-only copy
    //     must never hide a later TLS 1.3 offer from this pre-handshake gate.
    let mut seen_extension_types = SeenCodePoints::<EXTENSION_TYPE_BITSET_WORDS>::empty();

    while !ext.is_empty() {
        if ext.len() < 4 {
            return None;
        }
        let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
        let ext_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        let extension_end = 4usize.checked_add(ext_len)?;
        if ext.len() < extension_end {
            return None;
        }
        if seen_extension_types.insert_is_duplicate(ext_type as usize) {
            return None;
        }
        if ext_type == 0x0000 {
            if !server_name_extension_is_well_formed(&ext[4..extension_end]) {
                return None;
            }
            // Presence and structure only. Whether the host_name bytes are a
            // representable DNS name is decided by the extractor over the same
            // validated hello so it can produce `UnrepresentableName`.
            scanned.offers_server_name = true;
        }
        if ext_type == 0x002b {
            let data = &ext[4..extension_end];
            // ClientHello form: list_len (1) + versions (2 each).
            let list_len = *data.first()? as usize;
            if list_len < 2 || !list_len.is_multiple_of(2) || data.len() != 1 + list_len {
                return None;
            }
            let mut i = 1usize;
            while i < data.len() {
                if u16::from_be_bytes([data[i], data[i + 1]]) == 0x0304 {
                    scanned.offers_tls13 = true;
                }
                i += 2;
            }
        }
        ext = &ext[extension_end..];
    }
    Some(scanned)
}

/// Validate the RFC 6066 `ServerNameList` shape without interpreting DNS bytes.
///
/// Unknown future name types remain structurally valid (no length constraint is
/// imposed on them), but RFC 6066 §3 forbids more than one name of the *same*
/// `name_type` — for every one of the 256 types, not just `host_name` — and a
/// `host_name` entry must additionally be non-empty. Representability is
/// deliberately left to [`parse_sni_hostname`] so the typed classifier can
/// distinguish an unreadable name from a malformed extension.
fn server_name_extension_is_well_formed(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let names = &data[2..];
    if list_len == 0 || names.len() != list_len {
        return false;
    }

    let mut pos = 0usize;
    // RFC 6066 §3: "The ServerNameList MUST NOT contain more than one name of
    // the same name_type." Tracked across the whole 8-bit name-type space with
    // the same bounded, non-quadratic detector the extension scan uses, so a
    // list that repeats an unknown future type is refused just like a repeated
    // `host_name`.
    let mut seen_name_types = SeenCodePoints::<NAME_TYPE_BITSET_WORDS>::empty();
    while pos < names.len() {
        let Some(header_end) = pos.checked_add(3) else {
            return false;
        };
        let Some(header) = names.get(pos..header_end) else {
            return false;
        };
        let name_type = header[0];
        let name_len = u16::from_be_bytes([header[1], header[2]]) as usize;
        pos = header_end;
        let Some(next) = pos.checked_add(name_len) else {
            return false;
        };
        if next > names.len() {
            return false;
        }
        if seen_name_types.insert_is_duplicate(name_type as usize) {
            return false;
        }
        // `host_name` additionally may not be empty; unknown future types carry
        // no length contract here and stay structurally valid.
        if name_type == 0x00 && name_len == 0 {
            return false;
        }
        pos = next;
    }
    true
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
/// Tier order is absolute, not declaration order: an exact-host candidate wins
/// over a wildcard candidate declared before it, and both win over the
/// catch-all. Within one tier, ambiguity is impossible in validated config —
/// `GatewayConfig::validate_stream_proxies` rejects overlapping `hosts` and
/// more than one empty-`hosts` catch-all on a shared SNI port — so config that
/// reaches this function has exactly one owner per hostname.
///
/// Both sides are already normalized when they get here: config `hosts` are
/// validated ASCII, lowercase, label-checked, and trailing-dot-free
/// (`validate_host_entry`); the wire SNI is ASCII-lowercased and rejected
/// outright if it is not a representable DNS name. IDNA is therefore an
/// A-label (`xn--…`) contract on both sides — a U-label in `hosts` is a config
/// error, and a non-ASCII `server_name` is not a representable SNI.
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
