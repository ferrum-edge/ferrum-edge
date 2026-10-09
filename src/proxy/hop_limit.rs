//! Request-time proxy hop limit (issue #6109).
//!
//! A route whose upstream resolves back to the gateway itself — a control
//! plane that admitted a self-referencing target, or DNS that changed after
//! publication — turns every client request into an unbounded request loop.
//! The gateway therefore carries its own hop count on every HTTP-family
//! request it forwards, in the gateway-owned `X-Ferrum-Hops` request header,
//! and refuses a request that already crossed `FERRUM_MAX_PROXY_HOPS` gateway
//! hops with `508 Loop Detected` (gRPC: Trailers-Only `RESOURCE_EXHAUSTED`).
//!
//! The decision is taken ONCE per inbound request at the frontend, before
//! routing or any plugin runs, by both frontends: the H1/H2 handler (which
//! also serves gRPC and the HTTP/1.1 and RFC 8441 WebSocket upgrades) and the
//! native HTTP/3 handler (gRPC, the H3 bridge, and RFC 9220 WebSocket). The
//! forwarded value is always `received + 1`, written over the client's raw
//! header block before it is stored on the request context, so every backend
//! builder — reqwest, direct HTTP/2, native gRPC (raw-map merge), the HTTP/3
//! client and bridge, WebSocket handshakes, HBONE / mesh-mTLS replay, retries
//! — forwards the incremented count and the client's own value never reaches
//! a backend. A client can only RAISE the count, never reset it.
//!
//! Field-value policy (documented in `docs/routing.md`):
//!
//! - The value is `1*DIGIT` with optional surrounding whitespace, read as an
//!   unsigned decimal that saturates instead of overflowing.
//! - An absent field is hop `0`.
//! - A malformed field — empty, signed, fractional, non-decimal, or repeated
//!   (more than one field line) — is REFUSED with `400 Bad Request` (gRPC:
//!   `INVALID_ARGUMENT`) rather than treated as `0`: the gateway never writes
//!   a malformed value itself, so one can only come from a client or a foreign
//!   intermediary, and resetting it would let a loop through an intermediary
//!   that mangles the field run unbounded.
//! - `FERRUM_MAX_PROXY_HOPS=0` disables the whole feature: no refusal, and the
//!   field is neither parsed nor written (a client value passes through as an
//!   ordinary header).
//!
//! Stream proxies (`tcp`, `tcp_tls`, `udp`, `dtls`) relay opaque bytes and
//! carry no request headers, so the limit does not apply to them.
//!
//! Hot path: the decision is one `HeaderMap` lookup by a pre-built
//! `HeaderName` plus a bounded digit scan, and stamping inserts a pre-built
//! `HeaderValue` — neither allocates.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Lowercase wire name of the gateway-owned hop-count request header.
pub const PROXY_HOPS_HEADER: &str = "x-ferrum-hops";

/// Default `FERRUM_MAX_PROXY_HOPS`.
pub const DEFAULT_MAX_PROXY_HOPS: u8 = 10;

/// Rejection-phase label for both refusals (loop detected and malformed
/// field). It is also the diagnostic-reference fence phase and maps to the
/// `loop_detected` metrics token for the `508`.
pub const PROXY_HOP_LIMIT_REJECTION_PHASE: &str = "proxy_hop_limit";

/// Client-visible body of the `508 Loop Detected` refusal.
pub const LOOP_DETECTED_BODY: &str = r#"{"error":"Proxy hop limit exceeded"}"#;

/// gRPC status message of the loop refusal.
pub const LOOP_DETECTED_GRPC_MESSAGE: &str = "Proxy hop limit exceeded";

/// Client-visible body when `X-Ferrum-Hops` cannot be read as one decimal.
pub const INVALID_PROXY_HOPS_BODY: &str = r#"{"error":"Invalid X-Ferrum-Hops header"}"#;

/// gRPC status message of the malformed-field refusal.
pub const INVALID_PROXY_HOPS_GRPC_MESSAGE: &str = "Invalid X-Ferrum-Hops header";

/// [`PROXY_HOPS_HEADER`] as a pre-built `HeaderName`. A `static` rather than a
/// `const`: the custom name holds a `Bytes`, and a `const` would be an
/// interior-mutable constant copied at every use.
static PROXY_HOPS_HEADER_NAME: http::HeaderName = http::HeaderName::from_static(PROXY_HOPS_HEADER);

/// Pre-built decimal values `0..=255`, so stamping a hop count clones a shared
/// `HeaderValue` instead of formatting one per request.
static PROXY_HOPS_VALUES: LazyLock<[http::HeaderValue; 256]> = LazyLock::new(proxy_hops_values);

fn proxy_hops_values() -> [http::HeaderValue; 256] {
    std::array::from_fn(proxy_hops_value)
}

fn proxy_hops_value(hops: usize) -> http::HeaderValue {
    // `hops < 256` by construction of the table.
    http::HeaderValue::from(u16::try_from(hops).unwrap_or(u16::MAX))
}

/// Outcome of the hop-limit check for one inbound request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyHopDecision {
    /// `FERRUM_MAX_PROXY_HOPS=0`: nothing is checked or written.
    Disabled,
    /// Forward the request carrying this hop count (`received + 1`).
    Forward(u8),
    /// The received count already reached the limit: `508 Loop Detected`.
    LoopDetected,
    /// The field is present but not one valid decimal: `400 Bad Request`.
    Malformed,
}

/// Parse an `X-Ferrum-Hops` field value as `1*DIGIT`, tolerating surrounding
/// spaces and tabs and saturating at `u32::MAX`. Anything else (empty, sign,
/// separator, fraction, a comma-folded list) is `None`. Allocation-free.
pub fn parse_proxy_hops(value: &[u8]) -> Option<u32> {
    let digits = value.trim_ascii();
    if digits.is_empty() {
        return None;
    }
    let mut total: u32 = 0;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        // Keep validating every byte after saturating, so an oversized value
        // followed by garbage is still malformed.
        total = total
            .saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'));
    }
    Some(total)
}

/// Decide the hop-limit outcome for an inbound request's raw header block.
///
/// `max_hops` is `FERRUM_MAX_PROXY_HOPS`; `0` disables the check. A request
/// whose received count is `>= max_hops` is refused, so with the default `10`
/// a request is forwarded at most ten times through Ferrum gateways.
pub fn decide_proxy_hops(headers: &http::HeaderMap, max_hops: u8) -> ProxyHopDecision {
    if max_hops == 0 {
        return ProxyHopDecision::Disabled;
    }
    let mut values = headers.get_all(&PROXY_HOPS_HEADER_NAME).iter();
    let received = match values.next() {
        None => 0,
        Some(first) => {
            // The field is a single count, not a list (RFC 9110 §5.3): two
            // field lines are malformed, never "pick one".
            if values.next().is_some() {
                return ProxyHopDecision::Malformed;
            }
            match parse_proxy_hops(first.as_bytes()) {
                Some(received) => received,
                None => return ProxyHopDecision::Malformed,
            }
        }
    };
    if received >= u32::from(max_hops) {
        return ProxyHopDecision::LoopDetected;
    }
    // `received < max_hops <= 255`, so the increment always fits.
    match u8::try_from(received.saturating_add(1)) {
        Ok(next) => ProxyHopDecision::Forward(next),
        Err(_) => ProxyHopDecision::LoopDetected,
    }
}

/// Replace every client field line of `X-Ferrum-Hops` with the gateway's
/// forwarded count. Allocation-free: the name and value are pre-built.
pub fn stamp_proxy_hops(headers: &mut http::HeaderMap, hops: u8) {
    headers.insert(
        PROXY_HOPS_HEADER_NAME.clone(),
        PROXY_HOPS_VALUES[usize::from(hops)].clone(),
    );
}

/// Whether `name` is the gateway-owned hop-count field, ASCII
/// case-insensitive with `_` equivalent to `-` (the folding CGI-style
/// backends apply). Plugin configuration that would write, rename, or remove
/// it is refused at admission, so no configured header rule can reset the
/// count a later gateway hop reads.
#[inline]
pub fn is_proxy_hops_header(name: &str) -> bool {
    crate::proxy::headers::field_names_equivalent_for_backends(name, PROXY_HOPS_HEADER)
}

/// Re-assert the gateway's forwarded hop count on the authoritative outbound
/// header map after every request-phase plugin has run.
///
/// `outbound_hops` is the count the frontend stamped (`None` when the limit is
/// disabled). `owned_proxy_headers` is the plugin-transformed outbound map
/// when one exists; otherwise `ctx_headers` IS the outbound map. Built-in
/// plugins cannot be configured to touch the field, so this is defence in
/// depth: the common request pays one map lookup and one scan of the key
/// lengths, and allocates only when a plugin rewrote, removed, or re-cased
/// the field.
pub fn reassert_outbound_proxy_hops(
    outbound_hops: Option<u8>,
    owned_proxy_headers: &mut Option<HashMap<String, String>>,
    ctx_headers: &mut HashMap<String, String>,
) {
    let Some(hops) = outbound_hops else {
        return;
    };
    let headers = owned_proxy_headers.as_mut().unwrap_or(ctx_headers);
    let expected = PROXY_HOPS_VALUES[usize::from(hops)].as_bytes();
    let intact = headers
        .get(PROXY_HOPS_HEADER)
        .is_some_and(|value| value.as_bytes() == expected);
    let has_variant = headers.keys().any(|name| {
        name.len() == PROXY_HOPS_HEADER.len()
            && name != PROXY_HOPS_HEADER
            && is_proxy_hops_header(name)
    });
    if intact && !has_variant {
        return;
    }
    if has_variant {
        headers.retain(|name, _| !is_proxy_hops_header(name));
    }
    if let Ok(value) = std::str::from_utf8(expected) {
        headers.insert(PROXY_HOPS_HEADER.to_string(), value.to_string());
    }
}

/// Rate-limits the operator warning for a request refused at the hop limit,
/// so a live loop cannot flood the log with one line per looped request.
static LOOP_DETECTED_WARN: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter =
    crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new();

/// Emit the rate-limited warning for a `508 Loop Detected` refusal. The line
/// names only the configured limit and the frontend protocol — never the
/// received header value, the route, or the client — so it is safe at any
/// volume and cannot echo request data.
pub(crate) fn warn_loop_detected(max_hops: u8, frontend: &'static str) {
    let now_ms = crate::socket_opts::monotonic_now_ms();
    if let Some(suppressed) = LOOP_DETECTED_WARN.on_event(now_ms) {
        tracing::warn!(
            max_proxy_hops = max_hops,
            frontend,
            suppressed,
            "Refused request at the proxy hop limit (508 Loop Detected): a route's upstream \
             likely resolves back to a Ferrum gateway; raise FERRUM_MAX_PROXY_HOPS only if \
             the chain of gateway hops is intentional"
        );
    }
}
