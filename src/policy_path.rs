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
//! 5. **No `.` or `..` path segment survives, literal or escaped, with or
//!    without path parameters.** A segment is a dot segment when its text
//!    before the first `;` is `.` or `..`: `..`, `.`, and also `..;`, `.;x`,
//!    and `..;jsessionid=1`. A dot segment that an escape helped form — an
//!    escaped dot (`/a/%2e%2e/b`, `/a/.%2e;x/b`) or an escaped `;` delimiter
//!    (`/a/..%3b/b`) — is [`PolicyPathRejection::AmbiguousDotSegment`]; one
//!    written literally (`/a/../b`, `/a/..;/b`) is
//!    [`PolicyPathRejection::LiteralDotSegment`]. Neither is removed —
//!    removal *is* a second reading. A dot segment is not a single
//!    policy/backend coordinate: Ferrum forwards through URL parsers (the
//!    `url` crate behind `reqwest` on the HTTP/1.1, HTTP/2, and H3
//!    cross-protocol paths) and every RFC 3986 / WHATWG normalizer removes dot
//!    segments, so policy would evaluate `/a/../protected` while the request
//!    line resolves `/protected`. The `;` form is the same divergence one hop
//!    later: `;` is a legal `pchar`, so the `url` crate forwards `/a/..;/b`
//!    unchanged, but servlet containers and frameworks that strip RFC 3986
//!    path parameters before resolving dot segments (Tomcat, Spring, some
//!    Jetty configurations) resolve it to `/b`. That is exactly the divergence
//!    this module exists to remove, so the target is refused.
//!
//!    An escaped `;` (`%3B`) is decoded like every other `sub-delims` escape
//!    (rule 8), so the dot-segment check sees the decoded `;` and `..%3B` is
//!    refused. No escape survives canonicalization, so there is no retained
//!    `%3B` a decoding backend could turn into `..;` after policy ran. A `;`
//!    that does not follow a bare `.`/`..` (`/v1;version=2`, `/a;b`,
//!    `/..a;b`) is not a dot segment; whether it is accepted at all is rule 10.
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
//! 9. **No empty segment survives except a trailing one.** A non-final empty
//!    segment (`//admin`, `/a//b`) and a segment that is empty before its
//!    first `;` (`/;x/admin`, `/a/;/b`) are
//!    [`PolicyPathRejection::EmptySegment`]. A trailing slash (`/a/`) and the
//!    root path (`/`) are unaffected. Common backends collapse `//` (Tomcat,
//!    Spring, nginx `merge_slashes`) and strip `;…` before doing so, so
//!    `//admin/users` and `/;x/admin/users` would execute `/admin/users`
//!    while routing and policy read a different path. Collapsing here instead
//!    would be a second reading, so the target is refused.
//! 10. **A `;` path parameter is refused unless the matched proxy opts in.**
//!     Tomcat and Spring strip `;…` from every segment, so `/admin;x/users`
//!     executes `/admin/users` while policy reads `/admin;x/users`. Stripping
//!     the parameter here as well would forward a different request than the
//!     client sent, and forwarding one path while evaluating another is the
//!     two-coordinate model this module exists to remove. So `;` — literal or
//!     decoded from `%3B` — is refused with
//!     [`PolicyPathRejection::PathParameter`] unless the proxy sets
//!     `allow_path_parameters`. That decision needs the routed proxy, which
//!     does not exist yet when the target is canonicalized, so
//!     [`canonicalize_request_path`] only *reports* whether a `;` is present
//!     (folded into the same scan) and the frontend applies
//!     [`check_path_parameters`] right after route lookup and before any
//!     plugin runs. Route lookup itself is a literal match on the canonical
//!     path, not policy, so letting it see the `;` cannot grant anything: a
//!     request routed to a proxy that has not opted in is refused before any
//!     policy runs. Rules 5 and 9 still apply on an opted-in proxy.
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
//! proves the target carries no percent escape, no literal `\`, no literal
//! `.`/`..` segment (with or without a `;` parameter), and no non-final empty
//! segment; only then is it returned borrowed and unmodified. That covers the
//! overwhelming majority of production traffic, so the hot path never
//! allocates. Each segment is classified once, when its `/` or the end of the
//! target is reached, by a fixed-length slice match (the empty-segment check
//! is one comparison per `/`), and noting a `;` for rule 10 is one more arm
//! of the same byte match, not a second scan. A target is accepted because the
//! scan cleared it, not because it happened to contain no `%`. The scan hands
//! off to the decoding pass as soon as it sees a `%`, and that pass
//! re-validates from the start, so the two cannot disagree about what is
//! accepted.
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
//! is retained only for backend listen-path stripping, which needs the router's
//! own offset coordinate system. It is not a competing model: after
//! canonicalization it is always the identity function.
//!
//! Mesh authorization (`src/plugins/mesh/authz.rs`) used to fold through the
//! router helper before evaluating Istio `paths:` / `notPaths:`. Folding closed
//! only the encoded-slash half of issue #1701 and left `.`/`..` untouched
//! (issue #4149), so it now re-runs [`canonicalize_policy_path`] instead:
//! identity — and allocation-free — on every target the boundary admits, and a
//! fail-closed `403` on anything that somehow reaches `authorize` without
//! having passed it.

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
    /// A percent escape helped produce a `.` or `..` path segment: an escaped
    /// dot (`%2e%2e`, `.%2e;x`) or an escaped `;` delimiter (`..%3B`).
    AmbiguousDotSegment,
    /// A literal `.` or `..` path segment, including one carrying a `;` path
    /// parameter (`..;`, `.;x`). Every RFC 3986 / WHATWG normalizer removes
    /// dot segments, so policy would read `/a/../protected` while the
    /// forwarded request line resolves `/protected`; a backend that strips
    /// path parameters first resolves `/a/..;/protected` the same way.
    LiteralDotSegment,
    /// A non-final empty path segment (`//a`, `/a//b`), or a segment that is
    /// empty before its first `;` (`/;x/a`). Backends that collapse `//` and
    /// strip path parameters would resolve a different path than policy read.
    /// A trailing slash is not an empty segment in this sense.
    EmptySegment,
    /// A `;` path parameter (literal or `%3B`) on a proxy that has not set
    /// `allow_path_parameters`. Never returned by the canonicalizer itself:
    /// the frontend applies [`check_path_parameters`] once the route is known.
    PathParameter,
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
            Self::EmptySegment => "empty_segment",
            Self::PathParameter => "path_parameter",
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
            Self::EmptySegment => r#"{"error":"Request path contains an empty path segment"}"#,
            Self::PathParameter => r#"{"error":"Request path contains a path parameter"}"#,
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
            Self::EmptySegment => "Empty path segment in request path",
            Self::PathParameter => "Path parameter in request path",
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
    /// Escape rules only: a literal `\`, a `.`/`..` segment, or an empty
    /// segment (`//` is ordinary regex text) is left alone.
    ///
    /// Used for operator-authored *patterns* (`~regex` listen paths), where
    /// `\` and `.` are regex syntax rather than path bytes — `~^/v1\.0/.*`
    /// matches the perfectly reachable canonical path `/v1.0/x`. Percent
    /// escapes are still refused, because a regex has no metacharacter that
    /// makes `%2F` match anything: no canonical request path contains a `%`,
    /// so such a pattern is dead config either way.
    PatternOnly,
}

/// How many leading bytes of `segment` form a dot segment, or `None` when it
/// is not one.
///
/// A segment is a dot segment when its text before the first `;` is `.` or
/// `..`. The returned length covers the dots and, when present, the `;`
/// delimiter — the bytes that make the segment resolve as a dot segment on a
/// backend that strips path parameters. Any bytes after the `;` are the
/// parameter and do not matter. A constant-size slice match: no scan and no
/// allocation, so the hot path pays nothing for the parameter form.
#[inline]
fn dot_segment_len(segment: &[u8]) -> Option<usize> {
    match segment {
        [b'.'] => Some(1),
        [b'.', b'.'] | [b'.', b';', ..] => Some(2),
        [b'.', b'.', b';', ..] => Some(3),
        _ => None,
    }
}

/// Whether one path segment, taken literally, is a dot segment under rule 5 of
/// the module contract: its text before the first `;` is `.` or `..`.
///
/// `segment` must not contain `/`. Percent escapes are *not* decoded — this
/// is for callers that have already refused `%` or that validate a decoded
/// value. Anything that may still carry escapes should go through
/// [`canonicalize_policy_path`] instead, which applies the same rule after
/// decoding.
pub fn is_literal_dot_segment(segment: &str) -> bool {
    dot_segment_len(segment.as_bytes()).is_some()
}

/// Reject a completed segment that rule 5 or rule 9 of the module contract
/// refuses.
///
/// `segment` is the segment's canonical bytes, without its `/` delimiters.
/// `empty_allowed` is true only for the text before a leading `/` and for the
/// final segment, so the root path and a trailing slash stay legal while every
/// other empty segment (`//`, `/a//b`) is refused: one comparison per `/`.
///
/// `first_escape` is the offset, within the segment, of the first byte that
/// was decoded from a percent escape. A dot segment is ambiguous when that byte
/// is one of the dots or the `;` delimiter that make it a dot segment; an
/// escape inside the trailing parameter (`..;%61`) does not change that the
/// dot segment itself was written literally.
#[inline]
fn check_segment(
    segment: &[u8],
    empty_allowed: bool,
    first_escape: Option<usize>,
) -> Result<(), PolicyPathRejection> {
    match segment {
        [] if empty_allowed => Ok(()),
        // A segment that is empty, or empty before its first `;`, collapses
        // into its neighbour on a backend that merges `//` after stripping
        // path parameters.
        [] | [b';', ..] => Err(PolicyPathRejection::EmptySegment),
        _ => match dot_segment_len(segment) {
            Some(dot_len) if first_escape.is_some_and(|offset| offset < dot_len) => {
                Err(PolicyPathRejection::AmbiguousDotSegment)
            }
            Some(_) => Err(PolicyPathRejection::LiteralDotSegment),
            None => Ok(()),
        },
    }
}

/// What the allocation-free pre-scan concluded about a target.
enum Prescan {
    /// No percent escape, no literal backslash, no literal dot segment, and no
    /// non-final empty segment: the input is already canonical and can be
    /// returned borrowed. `has_path_parameter` records whether it contains a
    /// `;` (rule 10).
    AlreadyCanonical { has_path_parameter: bool },
    /// A `%` was reached. The decoding pass re-validates from the first byte,
    /// so the scan stops here rather than duplicating its rules.
    NeedsDecoding,
}

/// Prove a target needs neither decoding nor rejection, without allocating.
///
/// This is the hot path for essentially all production traffic. It is a
/// validating scan, not a "no `%` means accept" shortcut: a literal `\`, a
/// literal `.`/`..` segment (including `..;` and `.;x`), or a non-final empty
/// segment (including `;x`) is refused here exactly as the decoding pass
/// refuses it.
fn prescan(bytes: &[u8], structure: LiteralStructure) -> Result<Prescan, PolicyPathRejection> {
    let enforced = structure == LiteralStructure::Enforced;
    let mut segment_start = 0usize;
    let mut has_path_parameter = false;
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'%' => return Ok(Prescan::NeedsDecoding),
            b'\\' if enforced => return Err(PolicyPathRejection::LiteralBackslash),
            b';' => has_path_parameter = true,
            b'/' if enforced => {
                // `segment_start` is 0 only for the text before the first
                // `/`, which is empty for every absolute path.
                check_segment(&bytes[segment_start..index], segment_start == 0, None)?;
                segment_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }

    if enforced {
        check_segment(&bytes[segment_start..], true, None)?;
    }
    Ok(Prescan::AlreadyCanonical { has_path_parameter })
}

/// A canonical request path, and whether it carries a `;` path parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRequestPath<'a> {
    /// The canonical policy path. Borrowed when the target contained no
    /// percent escape, owned when at least one escape was decoded.
    pub path: Cow<'a, str>,
    /// Whether the canonical path contains a `;` (literal, or decoded from
    /// `%3B`). The frontend passes this to [`check_path_parameters`] once the
    /// route is known (rule 10 of the module contract).
    pub has_path_parameter: bool,
}

/// Build the canonical request path for `raw` at the frontend boundary, or
/// reject the request target.
///
/// Applies every rule of the module contract that does not depend on the
/// routed proxy, and reports whether the path carries a `;` so the frontend
/// can apply the per-proxy rule 10 through [`check_path_parameters`] right
/// after route lookup, before any plugin runs. `raw` is the path component
/// only — the query string is never part of the policy path.
pub fn canonicalize_request_path(
    raw: &str,
) -> Result<CanonicalRequestPath<'_>, PolicyPathRejection> {
    let (path, has_path_parameter) = canonicalize(raw, LiteralStructure::Enforced)?;
    Ok(CanonicalRequestPath {
        path,
        has_path_parameter,
    })
}

/// Build the canonical policy path for `raw`, or reject the request target.
///
/// See the module documentation for the full contract. `raw` is the path
/// component only — the query string is never part of the policy path. This
/// does not apply the per-proxy `;` rule (rule 10): a path parameter is
/// accepted here, because this is also the re-check that runs on already
/// admitted paths (mesh authorization, route overrides) and on operator
/// configuration. Frontends use [`canonicalize_request_path`] instead.
pub fn canonicalize_policy_path(raw: &str) -> Result<Cow<'_, str>, PolicyPathRejection> {
    canonicalize(raw, LiteralStructure::Enforced).map(|(path, _)| path)
}

/// Apply rule 10 of the module contract for a routed request.
///
/// `has_path_parameter` comes from [`canonicalize_request_path`];
/// `allow_path_parameters` is the matched proxy's opt-in. A `;` on a proxy
/// that has not opted in is [`PolicyPathRejection::PathParameter`].
#[inline]
pub fn check_path_parameters(
    has_path_parameter: bool,
    allow_path_parameters: bool,
) -> Result<(), PolicyPathRejection> {
    if has_path_parameter && !allow_path_parameters {
        Err(PolicyPathRejection::PathParameter)
    } else {
        Ok(())
    }
}

fn canonicalize(
    raw: &str,
    structure: LiteralStructure,
) -> Result<(Cow<'_, str>, bool), PolicyPathRejection> {
    let bytes = raw.as_bytes();
    match prescan(bytes, structure)? {
        Prescan::AlreadyCanonical { has_path_parameter } => {
            return Ok((Cow::Borrowed(raw), has_path_parameter));
        }
        Prescan::NeedsDecoding => {}
    }
    let enforced = structure == LiteralStructure::Enforced;

    // Every accepted escape is decoded to one literal byte, so this is both the
    // canonical policy path and the byte stream a decoding backend resolves —
    // there is only one buffer because there is only one coordinate system.
    let mut canonical: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut segment_start = 0usize;
    // Offset within the current segment of its first escape-decoded byte.
    let mut segment_first_escape: Option<usize> = None;
    let mut has_path_parameter = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        if byte == b'/' {
            if enforced {
                check_segment(
                    &canonical[segment_start..],
                    segment_start == 0,
                    segment_first_escape,
                )?;
            }
            canonical.push(b'/');
            segment_start = canonical.len();
            segment_first_escape = None;
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
            has_path_parameter |= byte == b';';
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

        // `;` is a `sub-delims` byte, so `%3B` decodes here like any other
        // `pchar` escape and the segment check below sees the real delimiter:
        // `..%3B` is refused exactly like `..;`, `/%3Bx/a` exactly like
        // `/;x/a`, and a decoded `;` is a path parameter for rule 10 exactly
        // like a literal one.
        if segment_first_escape.is_none() {
            segment_first_escape = Some(canonical.len() - segment_start);
        }
        has_path_parameter |= value == b';';
        canonical.push(value);
        index += 3;
    }

    if enforced {
        check_segment(&canonical[segment_start..], true, segment_first_escape)?;
    }

    // Reaching here means at least one `%` was consumed (the pre-scan handled
    // the escape-free case) and every escape collapsed from three bytes to one,
    // so the canonical form always differs from `raw` and is always owned.
    //
    // `canonical` is `raw`'s literal bytes (valid UTF-8, copied in order and
    // never split mid-codepoint) interleaved with decoded ASCII `pchar`s, so it
    // is valid UTF-8 by construction. The fallible form keeps that a documented
    // invariant instead of a panic.
    String::from_utf8(canonical)
        .map(|canonical| (Cow::Owned(canonical), has_path_parameter))
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
/// already cannot contain a dot segment, an empty segment, or a backslash.
pub fn non_canonical_policy_path_pattern_reason(pattern: &str) -> Option<&'static str> {
    reason_for(canonicalize(pattern, LiteralStructure::PatternOnly))
}

fn reason_for(result: Result<(Cow<'_, str>, bool), PolicyPathRejection>) -> Option<&'static str> {
    match result {
        Ok((Cow::Borrowed(_), _)) => None,
        Ok((Cow::Owned(_), _)) => Some("percent-escapes that canonicalize to a different path"),
        Err(rejection) => Some(rejection.reason()),
    }
}
