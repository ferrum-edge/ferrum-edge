//! Canonical policy path — the single request-path representation that every
//! security decision and the backend request line share.
//!
//! # Why
//!
//! A percent-encoded request target has more than one plausible reading. The
//! gateway used to evaluate WAF URL-path rules, `openapi_validator` operation
//! selection, `request_termination` prefixes, authorization, and cache keys
//! against the *raw* target while common backend frameworks percent-decode
//! path segments before dispatch. A client could therefore pick a raw spelling
//! (`/%61dmin`) that misses an operator's literal policy while the backend
//! still executed the protected handler (private advisory
//! `GHSA-69xf-42xm-4w4f`).
//!
//! The fix is representational, not per-plugin: canonicalize once at the
//! frontend boundary, store the result in [`RequestContext::path`], and let
//! every existing consumer keep reading that one field.
//!
//! [`RequestContext::path`]: crate::plugins::RequestContext::path
//!
//! # Contract
//!
//! [`canonicalize_policy_path`] either returns a canonical path or rejects the
//! request. The canonical form guarantees:
//!
//! 1. **Every `%` starts a complete, valid `%XX` escape.** A truncated or
//!    non-hex escape is [`PolicyPathRejection::InvalidEscape`]; there is no
//!    "leave it alone" fallback, because a lenient backend parser and the
//!    gateway would then disagree about where the escape ends.
//! 2. **Decoding is structure-preserving.** An escape that decodes to `/`,
//!    `?`, `#` ([`PolicyPathRejection::EncodedSeparator`]) or `\` ([`PolicyPathRejection::EncodedBackslash`]) is
//!    rejected, so the canonical path has exactly the segment structure of the
//!    raw target. Routing, policy, and the backend cannot disagree about how
//!    many segments the request has.
//! 3. **Decoding cannot repeat.** An encoded `%` (`%25`, the first byte of any
//!    double encoding) is [`PolicyPathRejection::DoubleEncoding`]. Combined with rule 2 this means
//!    a second decode of the canonical path can never introduce a separator,
//!    so "decoded once" and "decoded twice" describe the same route.
//! 4. **Only a `pchar`-legal escape is decoded; every other escape is
//!    refused.** An escape of a byte outside the decode table — space, `"`,
//!    `<`, `>`, `[`, `]`, `^`, `` ` ``, `{`, `|`, `}`, and every non-ASCII
//!    byte, whether or not it is part of a valid UTF-8 sequence — is
//!    [`PolicyPathRejection::UnrepresentableEscape`]. Retaining such an escape
//!    would put a *different* string on the wire than the one policy read:
//!    the gateway would evaluate `/api%20name` while a decoding backend
//!    resolves `/api name`, which is the same policy/backend semantic
//!    mismatch this module exists to remove. Decoding it is not an answer
//!    either: the decoded byte is one the backend URL parser cannot carry at
//!    all (space, controls) or one it percent-encodes again (`"`, `{`, `}`,
//!    non-ASCII), so the forwarded request line would not be the canonical
//!    string. Refusing keeps the *decoded* alphabet to bytes that survive that
//!    parser byte-for-byte. See "Literal non-`pchar` bytes" below for what this
//!    rule does and does not say about a byte sent literally.
//! 5. **No `.` or `..` path segment survives, literal or escaped.** A segment
//!    that became `.`/`..` only through a percent escape (`/a/%2e%2e/b`) is
//!    [`PolicyPathRejection::AmbiguousDotSegment`]; one written literally
//!    (`/a/../b`) is [`PolicyPathRejection::LiteralDotSegment`]. Neither is
//!    removed — removal *is* a second reading. A dot segment is not a single
//!    policy/backend coordinate: Ferrum forwards through URL parsers (the
//!    `url` crate behind `reqwest` on the HTTP/1.1, HTTP/2, and H3
//!    cross-protocol paths) and every RFC 3986 / WHATWG normalizer removes dot
//!    segments, so policy would evaluate `/a/../protected` while the request
//!    line resolves `/protected`. That is exactly the divergence this module
//!    exists to remove, so the target is refused.
//! 6. **No `\` survives, literal or escaped.** An encoded `\` is
//!    [`PolicyPathRejection::EncodedBackslash`] and a literal one is
//!    [`PolicyPathRejection::LiteralBackslash`]. The `url` crate treats a
//!    backslash as a path separator for special HTTP(S) URLs, as do several
//!    backend stacks, so a literal `\` is the same route-structure mismatch an
//!    encoded one is.
//! 7. **Encoded C0 controls and `DEL` are rejected** ([`PolicyPathRejection::EncodedControl`]),
//!    including `%00`: a NUL truncates the path in several backend runtimes.
//! 8. **Escapes of characters that are legal literally in a path are decoded**
//!    (RFC 3986 `pchar` = `unreserved` / `sub-delims` / `:` / `@`), so
//!    `/%61dmin` canonicalizes to `/admin` and an operator's literal rule
//!    matches.
//!
//! Rules 4 and 8 together mean **no percent escape survives canonicalization**:
//! an escape is either decoded to the literal byte it names or the request is
//! refused. The canonical path is therefore always a valid HTTP request target
//! *and* is byte-identical to what a decoding backend resolves. That is what
//! lets one representation serve both policy and forwarding: there is no
//! second "wire" coordinate system to keep in sync, and no spelling on which
//! the gateway and the backend can disagree.
//!
//! The function is idempotent: `canonicalize(canonicalize(p)) == canonicalize(p)`.
//!
//! # Literal non-`pchar` bytes
//!
//! Rule 4 governs *escapes*, not literal bytes, and the two sets are not the
//! same. `http`'s request-target parser (`http::uri::PathAndQuery`, used by
//! hyper for H1/H2 and by the h3 frontend) permits several non-`pchar` bytes
//! literally in a path: `"`, `{`, `}`, `[`, `]`, `^`, `|`, and any byte
//! sequence that is valid UTF-8. Those reach the canonicalizer as ordinary
//! path bytes, clear the scan, and are accepted — so a literal `/café` is
//! served while `/caf%C3%A9` is refused, and `/a{b` is served while `/a%7Bb`
//! is refused.
//!
//! That asymmetry is deliberate and safe, but it bounds what the contract above
//! claims. The `url` crate's path percent-encode set covers controls,
//! space, `"`, `<`, `>`, `` ` ``, `#`, `?`, `{`, `}`, and every non-ASCII byte,
//! so when a canonical path carrying a literal one of those is parsed into the
//! backend URL, the forwarded request line is the percent-encoded spelling
//! rather than the canonical bytes. Percent-encoding only ever expands one byte
//! into `%XX`; it can never synthesize a `/`, `?`, or `#`, and a decoding
//! backend resolves it straight back to the canonical byte. So segment
//! structure is still preserved and policy still reads what a decoding backend
//! resolves — but the canonical path is *not* always byte-for-byte the
//! forwarded request line. Only the accepted escape alphabet is.
//!
//! # Fast path
//!
//! The normal path is allocation-free but not unvalidated. A single scan
//! proves the target carries no percent escape, no literal `\`, and no literal
//! `.`/`..` segment; only then is it returned borrowed and unmodified. That
//! covers the overwhelming majority of production traffic, so the hot path
//! never allocates, but a target is accepted because the scan cleared it, not
//! because it happened to contain no `%`. The scan hands off to the decoding
//! pass as soon as it sees a `%`, and that pass re-validates from the start, so
//! the two cannot disagree about what is accepted.
//!
//! The result's ownership is still a reliable signal: because no escape
//! survives, a borrowed result means the target contained no escape at all, and
//! an owned result always means at least one escape was decoded.
//!
//! # Relationship to `normalize_encoded_slashes`
//!
//! [`crate::router_cache::normalize_encoded_slashes`] predates this module and
//! folded `%2F`/`%252F` into `/` for route lookup. Folding *changes* structure,
//! so the router and a non-decoding backend could still disagree; this module
//! rejects those targets instead and runs strictly earlier. The router helper
//! is retained as an unreachable defense-in-depth residual for callers that do
//! not come through the frontend boundary (mesh authz normalization, backend
//! listen-path stripping). It is not a competing model: after canonicalization
//! it is always the identity function.

use std::borrow::Cow;

/// Why a request target was refused as a policy path.
///
/// Every variant maps to a fixed, non-echoing client error body: the raw
/// target is attacker-controlled and is never interpolated into a response or
/// a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPathRejection {
    /// A `%` was not followed by two hexadecimal digits.
    InvalidEscape,
    /// An encoded `%` (`%25`) — the lead byte of a double encoding.
    DoubleEncoding,
    /// An encoded `/`, `?`, or `#`.
    EncodedSeparator,
    /// An encoded `\`, which several backend stacks treat as a separator.
    EncodedBackslash,
    /// A literal `\`. The `url` crate — which parses the backend URL on the
    /// reqwest dispatch paths — treats it as a path separator for special
    /// HTTP(S) URLs, so the forwarded segment structure would not be the one
    /// policy evaluated.
    LiteralBackslash,
    /// An encoded C0 control character or `DEL` (includes `%00`).
    EncodedControl,
    /// An escape of a byte outside the `pchar` decode table (space, `{`, `[`,
    /// any non-ASCII byte, …). Keeping the escape would make the forwarded
    /// spelling differ from the string policy evaluated; decoding it would emit
    /// a byte the backend URL parser cannot carry or re-encodes, so the
    /// forwarded request line would not be the canonical string either. This
    /// governs escapes only — such a byte sent *literally* is accepted (see the
    /// module docs).
    UnrepresentableEscape,
    /// A percent escape produced a `.` or `..` path segment.
    AmbiguousDotSegment,
    /// A literal `.` or `..` path segment. Every RFC 3986 / WHATWG normalizer
    /// removes dot segments, so policy would read `/a/../protected` while the
    /// forwarded request line resolves `/protected`.
    LiteralDotSegment,
}

impl PolicyPathRejection {
    /// Stable machine-readable reason token, safe for logs and metrics.
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidEscape => "invalid_escape",
            Self::DoubleEncoding => "double_encoding",
            Self::EncodedSeparator => "encoded_separator",
            Self::EncodedBackslash => "encoded_backslash",
            Self::LiteralBackslash => "literal_backslash",
            Self::EncodedControl => "encoded_control",
            Self::UnrepresentableEscape => "unrepresentable_escape",
            Self::AmbiguousDotSegment => "ambiguous_dot_segment",
            Self::LiteralDotSegment => "literal_dot_segment",
        }
    }

    /// Fixed JSON error body returned to the client. Contains no request bytes.
    pub fn client_error_body(self) -> &'static str {
        match self {
            Self::InvalidEscape => {
                r#"{"error":"Request path contains an incomplete percent-escape"}"#
            }
            Self::DoubleEncoding => {
                r#"{"error":"Request path contains a double-encoded percent-escape"}"#
            }
            Self::EncodedSeparator => {
                r#"{"error":"Request path contains an encoded path separator"}"#
            }
            Self::EncodedBackslash => r#"{"error":"Request path contains an encoded backslash"}"#,
            Self::LiteralBackslash => r#"{"error":"Request path contains a backslash"}"#,
            Self::EncodedControl => {
                r#"{"error":"Request path contains an encoded control character"}"#
            }
            Self::UnrepresentableEscape => {
                r#"{"error":"Request path contains an unrepresentable percent-escape"}"#
            }
            Self::AmbiguousDotSegment => {
                r#"{"error":"Request path contains an encoded dot segment"}"#
            }
            Self::LiteralDotSegment => r#"{"error":"Request path contains a dot segment"}"#,
        }
    }

    /// Fixed gRPC status message for gRPC/gRPC-Web shaped rejections.
    pub fn grpc_message(self) -> &'static str {
        match self {
            Self::InvalidEscape => "Incomplete percent-escape in request path",
            Self::DoubleEncoding => "Double-encoded percent-escape in request path",
            Self::EncodedSeparator => "Encoded path separator in request path",
            Self::EncodedBackslash => "Encoded backslash in request path",
            Self::LiteralBackslash => "Backslash in request path",
            Self::EncodedControl => "Encoded control character in request path",
            Self::UnrepresentableEscape => "Unrepresentable percent-escape in request path",
            Self::AmbiguousDotSegment => "Encoded dot segment in request path",
            Self::LiteralDotSegment => "Dot segment in request path",
        }
    }
}

/// Bytes that are legal to appear literally in a path segment and are
/// therefore decoded: RFC 3986 `pchar` minus `pct-encoded`, i.e.
/// `unreserved / sub-delims / ":" / "@"`.
///
/// This table is exhaustive for what canonicalization *decodes*. An escape of
/// any other byte is refused: a retained escape is a second spelling the
/// backend may read differently than policy did, and a decoded one would be a
/// byte the backend URL parser either cannot carry or percent-encodes again, so
/// neither reading leaves one coordinate. (Some of those bytes are still
/// accepted when sent literally — see the module docs.)
///
/// `/` is deliberately absent — an encoded `/` is rejected with its own
/// dedicated reason, because decoding it would add a segment the raw target
/// did not have.
const DECODE_TO_LITERAL: [bool; 256] = build_decode_table();

const fn build_decode_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut index = 0usize;
    while index < 256 {
        let byte = index as u8;
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        let sub_delims = matches!(
            byte,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        );
        table[index] = unreserved || sub_delims || byte == b':' || byte == b'@';
        index += 1;
    }
    table
}

#[inline]
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Whether the *literal* bytes of the input are held to the request-path
/// contract, or only its percent escapes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralStructure {
    /// Full contract. Used for request targets and for every operator value
    /// that is compared literally against one.
    Enforced,
    /// Escape rules only: a literal `\` or `.`/`..` segment is left alone.
    ///
    /// Used for operator-authored *patterns* (`~regex` listen paths), where
    /// `\` and `.` are regex syntax rather than path bytes — `~^/v1\.0/.*`
    /// matches the perfectly reachable canonical path `/v1.0/x`. Percent
    /// escapes are still refused, because a regex has no metacharacter that
    /// makes `%2F` match anything: no canonical request path contains a `%`,
    /// so such a pattern is dead config either way.
    PatternOnly,
}

#[inline]
fn is_dot_segment(segment: &[u8]) -> bool {
    segment == b".".as_slice() || segment == b"..".as_slice()
}

/// Reject a completed `.` or `..` segment, naming whether an escape built it.
#[inline]
fn check_segment(
    canonical: &[u8],
    segment_start: usize,
    segment_has_escape: bool,
    structure: LiteralStructure,
) -> Result<(), PolicyPathRejection> {
    if structure == LiteralStructure::PatternOnly {
        return Ok(());
    }
    if is_dot_segment(&canonical[segment_start..]) {
        return Err(if segment_has_escape {
            PolicyPathRejection::AmbiguousDotSegment
        } else {
            PolicyPathRejection::LiteralDotSegment
        });
    }
    Ok(())
}

/// What the allocation-free pre-scan concluded about a target.
enum Prescan {
    /// No percent escape, no literal backslash, and no literal dot segment:
    /// the input is already canonical and can be returned borrowed.
    AlreadyCanonical,
    /// A `%` was reached. The decoding pass re-validates from the first byte,
    /// so the scan stops here rather than duplicating its rules.
    NeedsDecoding,
}

/// Prove a target needs neither decoding nor rejection, without allocating.
///
/// This is the hot path for essentially all production traffic. It is a
/// validating scan, not a "no `%` means accept" shortcut: a literal `\` or a
/// literal `.`/`..` segment is refused here exactly as the decoding pass
/// refuses it.
fn prescan(bytes: &[u8], structure: LiteralStructure) -> Result<Prescan, PolicyPathRejection> {
    let enforced = structure == LiteralStructure::Enforced;
    let mut segment_start = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'%' => return Ok(Prescan::NeedsDecoding),
            b'\\' if enforced => return Err(PolicyPathRejection::LiteralBackslash),
            b'/' if enforced => {
                if is_dot_segment(&bytes[segment_start..index]) {
                    return Err(PolicyPathRejection::LiteralDotSegment);
                }
                segment_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }

    if enforced && is_dot_segment(&bytes[segment_start..]) {
        return Err(PolicyPathRejection::LiteralDotSegment);
    }
    Ok(Prescan::AlreadyCanonical)
}

/// Build the canonical policy path for `raw`, or reject the request target.
///
/// See the module documentation for the full contract. `raw` is the path
/// component only — the query string is never part of the policy path.
pub fn canonicalize_policy_path(raw: &str) -> Result<Cow<'_, str>, PolicyPathRejection> {
    canonicalize(raw, LiteralStructure::Enforced)
}

fn canonicalize(
    raw: &str,
    structure: LiteralStructure,
) -> Result<Cow<'_, str>, PolicyPathRejection> {
    let bytes = raw.as_bytes();
    match prescan(bytes, structure)? {
        Prescan::AlreadyCanonical => return Ok(Cow::Borrowed(raw)),
        Prescan::NeedsDecoding => {}
    }
    let enforced = structure == LiteralStructure::Enforced;

    // Every accepted escape is decoded to one literal byte, so this is both the
    // canonical policy path and the byte stream a decoding backend resolves —
    // there is only one buffer because there is only one coordinate system.
    let mut canonical: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut segment_start = 0usize;
    let mut segment_has_escape = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        if byte == b'/' {
            check_segment(&canonical, segment_start, segment_has_escape, structure)?;
            canonical.push(b'/');
            segment_start = canonical.len();
            segment_has_escape = false;
            index += 1;
            continue;
        }

        // A literal backslash is refused for the same reason `%5C` is: the
        // `url` crate reads it as a path separator for special HTTP(S) URLs,
        // so the forwarded request line would not have the segment structure
        // policy evaluated.
        if byte == b'\\' && enforced {
            return Err(PolicyPathRejection::LiteralBackslash);
        }

        if byte != b'%' {
            canonical.push(byte);
            index += 1;
            continue;
        }

        let (Some(high), Some(low)) = (
            bytes.get(index + 1).copied().and_then(hex_value),
            bytes.get(index + 2).copied().and_then(hex_value),
        ) else {
            return Err(PolicyPathRejection::InvalidEscape);
        };
        let value = (high << 4) | low;

        match value {
            b'%' => return Err(PolicyPathRejection::DoubleEncoding),
            b'/' | b'?' | b'#' => return Err(PolicyPathRejection::EncodedSeparator),
            b'\\' => return Err(PolicyPathRejection::EncodedBackslash),
            0x00..=0x1F | 0x7F => return Err(PolicyPathRejection::EncodedControl),
            // Anything left is outside the decode table. Retaining the escape
            // would leave policy reading `/api%20name` while a decoding backend
            // resolves `/api name`; decoding it would emit a byte the backend
            // URL parser cannot carry (space, controls) or re-encodes (`{`,
            // non-ASCII), so the forwarded request line would not be the
            // canonical string. Either way it is two coordinates, so the target
            // is refused. This also covers every non-ASCII byte, valid UTF-8
            // sequence or not, so there is no decoded byte stream left to UTF-8
            // validate.
            _ if !DECODE_TO_LITERAL[value as usize] => {
                return Err(PolicyPathRejection::UnrepresentableEscape);
            }
            _ => {}
        }

        canonical.push(value);
        segment_has_escape = true;
        index += 3;
    }

    check_segment(&canonical, segment_start, segment_has_escape, structure)?;

    // Reaching here means at least one `%` was consumed (the pre-scan handled
    // the escape-free case) and every escape collapsed from three bytes to one,
    // so the canonical form always differs from `raw` and is always owned.
    //
    // `canonical` is `raw`'s literal bytes (valid UTF-8, copied in order and
    // never split mid-codepoint) interleaved with decoded ASCII `pchar`s, so it
    // is valid UTF-8 by construction. The fallible form keeps that a documented
    // invariant instead of a panic.
    String::from_utf8(canonical)
        .map(Cow::Owned)
        .map_err(|_| PolicyPathRejection::UnrepresentableEscape)
}

/// Why an operator-configured path value is not already a canonical policy
/// path, or `None` when it is.
///
/// Configured `listen_path` prefixes and plugin path triggers are compared
/// against the canonical request path, so a configured value that is itself
/// non-canonical can never match anything. Admission uses this to reject at
/// config time rather than fail silently at request time; sharing
/// [`canonicalize_policy_path`] keeps admission and runtime on one model.
pub fn non_canonical_policy_path_reason(path: &str) -> Option<&'static str> {
    reason_for(canonicalize(path, LiteralStructure::Enforced))
}

/// The same admission check for an operator-authored path *pattern* rather
/// than a literal path.
///
/// A `~regex` `listen_path` is compiled and matched against the canonical
/// request path, so it is subject to the escape half of the contract — no
/// canonical path contains a `%`, so a pattern that does is dead config. It is
/// *not* subject to the literal half: `\` and `.` are regex syntax there, and
/// `~^/v1\.0/.*` matches the entirely reachable canonical path `/v1.0/x`.
/// Applying the literal rules to a pattern would reject working routes without
/// closing anything, because the canonical path a pattern is matched against
/// already cannot contain a dot segment or a backslash.
pub fn non_canonical_policy_path_pattern_reason(pattern: &str) -> Option<&'static str> {
    reason_for(canonicalize(pattern, LiteralStructure::PatternOnly))
}

fn reason_for(result: Result<Cow<'_, str>, PolicyPathRejection>) -> Option<&'static str> {
    match result {
        Ok(Cow::Borrowed(_)) => None,
        Ok(Cow::Owned(_)) => Some("percent-escapes that canonicalize to a different path"),
        Err(rejection) => Some(rejection.reason()),
    }
}
