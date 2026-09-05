//! RFC 9110 §7.6.2 `Max-Forwards` processing for proxied `OPTIONS` requests.
//!
//! An intermediary that forwards `OPTIONS` (or `TRACE`, which this gateway
//! refuses with 405 before routing) must check the hop budget the client
//! attached: a received value of `0` means the gateway is the final recipient
//! and must answer without contacting the origin, and a positive value is
//! decremented before the request is forwarded. This module is the ONE checked,
//! bounded decision every frontend (HTTP/1.1, HTTP/2, native HTTP/3 and the
//! HTTP/3 cross-protocol bridge) applies at the same point in the request
//! ladder: after every request-phase plugin (authentication, authorization,
//! the `cors` plugin's local preflight answer, `before_proxy`) and before any
//! backend transport can be dialed.
//!
//! The decision mutates the AUTHORITATIVE outbound header map (the plugin
//! facing `HashMap<String, String>` view). Every backend builder — reqwest,
//! direct HTTP/2, the HTTP/3 client, HBONE and mesh-mTLS replay — takes its
//! wire headers from that map or layers it over the pristine raw snapshot with
//! [`crate::proxy::headers::merge_proxy_headers_preserving_repeated`], which
//! replaces a raw field line whenever the materialized value differs. The
//! decremented budget is therefore what goes on the wire for every transport
//! and for every retry attempt (retries reuse the same map), and the original
//! value cannot reappear through a header rebuild.
//!
//! Field-value policy (documented in `docs/routing.md`):
//!
//! - The value is `1*DIGIT`, read as an unsigned 32-bit decimal with
//!   saturation. A value beyond [`MAX_FORWARDS_RECIPIENT_MAX`] is treated as
//!   that maximum, which RFC 9110 §7.6.2 explicitly permits ("the greatest
//!   integer value that the recipient is capable of processing"). No digit
//!   count can overflow or panic.
//! - `Max-Forwards` is not a list-based field (RFC 9110 §5.3), so repeated
//!   field lines — the materialized view folds them with `", "` — are
//!   malformed, as are empty, signed, fractional, or non-decimal values. A
//!   malformed field is REFUSED with `400 Bad Request` and never forwarded:
//!   the gateway cannot honor a hop budget it cannot read, and silently
//!   dropping or resetting the field would let an unbounded request continue.
//! - Only `OPTIONS` is processed. RFC 9110 lets every other method ignore the
//!   field, so those requests keep their existing forwarding behaviour and
//!   the field, if present, travels unchanged.
//! - The check costs nothing for non-`OPTIONS` requests and exactly one map
//!   lookup for `OPTIONS` without the field. Only a positive budget allocates
//!   (the replacement decimal string).

use std::collections::HashMap;

use bytes::Bytes;
use hyper::StatusCode;

/// Lowercase wire name of the field. `hyper` lowercases HTTP/1.1 field names
/// at parse time and HTTP/2 / HTTP/3 mandate lowercase, so this is the only
/// key the materialized request-header map carries for it.
pub const MAX_FORWARDS_HEADER: &str = "max-forwards";

/// Greatest hop budget this gateway processes. A received decimal beyond this
/// saturates here instead of overflowing, so the forwarded value is
/// `MAX_FORWARDS_RECIPIENT_MAX - 1` for any oversized budget.
pub const MAX_FORWARDS_RECIPIENT_MAX: u32 = u32::MAX;

/// Client-visible body when the field cannot be read as one decimal.
pub const MAX_FORWARDS_INVALID_BODY: &[u8] = br#"{"error":"Invalid Max-Forwards header"}"#;

/// Rejection-phase label recorded by transaction logging for both terminal
/// outcomes, so operators can attribute a local answer to hop processing.
pub const MAX_FORWARDS_REJECTION_PHASE: &str = "max_forwards";

/// Why the gateway answers an `OPTIONS` request itself instead of forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaxForwardsTerminal {
    /// `Max-Forwards: 0`: the gateway is the final recipient and responds with
    /// `204 No Content` plus an `Allow` field describing the route.
    FinalRecipient,
    /// The field was present but not a single valid decimal: `400 Bad
    /// Request`, and the origin is never contacted.
    Malformed,
}

impl MaxForwardsTerminal {
    /// Status of the local answer before response-phase plugins run.
    #[inline]
    pub fn status(self) -> StatusCode {
        match self {
            Self::FinalRecipient => StatusCode::NO_CONTENT,
            Self::Malformed => StatusCode::BAD_REQUEST,
        }
    }

    /// Body of the local answer. The final-recipient answer is bodiless.
    #[inline]
    pub fn body(self) -> Bytes {
        match self {
            Self::FinalRecipient => Bytes::new(),
            Self::Malformed => Bytes::from_static(MAX_FORWARDS_INVALID_BODY),
        }
    }
}

/// Outcome of the hop-budget check for one inbound request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaxForwardsDecision {
    /// Not an `OPTIONS` request, or no `Max-Forwards` field: forward as-is.
    Forward,
    /// A positive budget was decremented in place in the outbound map.
    Decremented,
    /// The gateway answers locally; nothing is forwarded.
    Terminal(MaxForwardsTerminal),
}

/// Parse a `Max-Forwards` field value as `1*DIGIT`, saturating at
/// [`MAX_FORWARDS_RECIPIENT_MAX`]. Surrounding optional whitespace is
/// tolerated; anything else (empty, sign, separator, fraction, a folded list
/// of repeated field lines) is `None`.
pub fn parse_max_forwards(value: &str) -> Option<u32> {
    let digits = value.trim_matches([' ', '\t']);
    if digits.is_empty() {
        return None;
    }
    let recipient_max = u64::from(MAX_FORWARDS_RECIPIENT_MAX);
    let mut total: u64 = 0;
    for byte in digits.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        // Saturate at the recipient maximum but keep validating every
        // remaining byte, so an oversized value followed by garbage is still
        // malformed rather than silently accepted as the maximum.
        total = total
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
            .min(recipient_max);
    }
    u32::try_from(total).ok()
}

/// Apply the hop-budget decision to the effective outbound header map of an
/// inbound request.
///
/// `owned_proxy_headers` is the plugin-transformed outbound map when one
/// exists; otherwise `ctx_headers` (the request context's materialized view)
/// IS the outbound map and is mutated in place. Exactly one of the two is
/// touched, and only when a positive budget is decremented. Callers must
/// invoke this once per inbound request, never per retry attempt.
pub fn apply_options_max_forwards(
    method: &str,
    owned_proxy_headers: &mut Option<HashMap<String, String>>,
    ctx_headers: &mut HashMap<String, String>,
) -> MaxForwardsDecision {
    if method != "OPTIONS" {
        return MaxForwardsDecision::Forward;
    }
    let headers = owned_proxy_headers.as_mut().unwrap_or(ctx_headers);
    decide_options_max_forwards(headers)
}

/// The `OPTIONS`-only core of [`apply_options_max_forwards`]: one lookup, and
/// an in-place replacement of the value when a positive budget is decremented.
pub fn decide_options_max_forwards(headers: &mut HashMap<String, String>) -> MaxForwardsDecision {
    let Some(value) = headers.get_mut(MAX_FORWARDS_HEADER) else {
        return MaxForwardsDecision::Forward;
    };
    match parse_max_forwards(value) {
        None => MaxForwardsDecision::Terminal(MaxForwardsTerminal::Malformed),
        Some(0) => MaxForwardsDecision::Terminal(MaxForwardsTerminal::FinalRecipient),
        Some(received) => {
            *value = (received - 1).to_string();
            MaxForwardsDecision::Decremented
        }
    }
}

/// Response headers for a terminal outcome. The final-recipient answer carries
/// `Allow`: the route's configured `allowed_methods` when set (uppercased in
/// config order, the same formatting the 405 path uses), otherwise the static
/// protocol-level list the gateway itself admits. The malformed answer adds
/// nothing; the shared rejection pipeline supplies the JSON content type.
pub fn max_forwards_response_headers(
    terminal: MaxForwardsTerminal,
    allowed_methods: Option<&[String]>,
) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    if terminal == MaxForwardsTerminal::FinalRecipient {
        let allow = match allowed_methods {
            Some(methods) => crate::proxy::allow_header_from_allowed_methods(methods),
            None => crate::proxy::PROTOCOL_LEVEL_405_ALLOW.to_string(),
        };
        headers.insert("allow".to_string(), allow);
    }
    headers
}
