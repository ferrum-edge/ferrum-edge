//! HMAC Authentication Plugin
//!
//! Validates HMAC-signed requests where the client signs the request
//! with a shared secret. Supports hmac-sha256 and hmac-sha512.
//!
//! Expected Authorization header format (`ferrum-hmac-v2`, the default):
//!   hmac username="<username>", algorithm="hmac-sha256", nonce="<nonce>", signature="<base64-sig>"
//!
//! ## Signing string
//!
//! Ferrum's `Authorization: hmac` scheme is not RFC 9421 HTTP Message
//! Signatures. The signing base is versioned; its first field is the profile
//! version itself, so a signature produced for one profile can never verify
//! under another.
//!
//! Version 2 (`ferrum-hmac-v2`, the default) signs these newline-separated
//! fields:
//!
//!   ```text
//!   ferrum-hmac-v2\n{NAMESPACE}\n{USERNAME}\n{AUTHORITY}\n{METHOD}\n{PATH}\n{QUERY}\n{DATE}\n{DIGEST_HEADER_VALUE}\n{NONCE}
//!   ```
//!
//! Version 1 (`ferrum-hmac-v1`) is the same base without the trailing
//! `{NONCE}` field and without any single-use guarantee — see "Replay
//! protection" below.
//!
//! `{PATH}` is the request path component only; `{QUERY}` is the raw query
//! string as received (percent-encoded, without the leading `?`, empty when
//! there is no query). Binding the query means query parameters cannot be
//! altered or added without invalidating the signature. Clients must sign the
//! byte-for-byte raw query string the gateway receives.
//!
//! The client must also include exactly one body-integrity field: an RFC 9530
//! `Content-Digest:` structured-field dictionary such as
//! `sha-256=:<base64>:`, or a legacy RFC 3230 `Digest:` value such as
//! `sha-256=<base64>`. Sending both headers is refused as ambiguous. The
//! digest is SHA-256 and/or SHA-512 of the exact client bytes; unsupported
//! algorithms, malformed members, duplicate algorithm keys, and mixed
//! RFC 9530 / legacy spellings fail closed. The plugin verifies that digest
//! against the hashed forwarding buffer (never an invented empty body);
//! tampering with the body, the query string, the nonce, or the digest header
//! invalidates the HMAC. `{DIGEST_HEADER_VALUE}` in the signing base is that
//! field's literal value.
//!
//! ## Replay protection
//!
//! A signed `Date` bounds *freshness*; it can never bound *uniqueness*.
//! `ferrum-hmac-v2` therefore requires a client-generated `nonce` that is
//! cryptographically bound together with the profile version, namespace,
//! consumer identity, authority, method, raw path, raw query, `Date`, and body
//! digest, and claims it against the shared
//! [`crate::plugins::utils::replay_authority`] once — and only once — every
//! other check has passed. The second presentation of the same signed bytes is
//! rejected before backend dispatch.
//!
//! Ordering is load-bearing. The nonce is *syntactically* validated at
//! extraction (bounded length, constrained alphabet, ≥128 bits of entropy), but
//! the replay claim happens only after the `Date` window, the digest header
//! shape, the consumer lookup, the HMAC signature, and the body digest have all
//! verified. Invalid or unauthenticated traffic can therefore neither fill
//! replay storage nor consume a shared-backend round trip.
//!
//! A verbatim transport retry **is** a replay and is rejected. A client that
//! needs safe retries sends a fresh nonce with a recomputed signature, and
//! expresses at-most-once application semantics with its own idempotency key —
//! that is an application/backend contract and is deliberately not conflated
//! with gateway proof uniqueness.
//!
//! ### Legacy `ferrum-hmac-v1`
//!
//! Version 1 has no nonce and no replay store: a captured, fully valid signed
//! request can be replayed verbatim any number of times until the `Date` window
//! elapses. It is **not** selected by default and cannot be selected by
//! accident — it requires both `signing_profile: "ferrum-hmac-v1"` and the
//! explicit `allow_unsafe_replayable_v1: true` acknowledgement — and every
//! acceptance under it increments the fixed-cardinality
//! `legacy_unsafe_profile_accepted` counter. Do not use it on non-idempotent
//! routes.
//!
//! ## Retention horizon
//!
//! A request is acceptable while its `Date` is within `now ± clock_skew`, so
//! the widest span over which one unchanged signed request can ever be accepted
//! is `2 * MAX_HMAC_CLOCK_SKEW_SECONDS`. [`HMAC_MARKER_RETENTION_SECONDS`] is
//! that span plus one second, is fixed rather than configurable, and is written
//! identically by every generation and replica — so a marker always outlives
//! every window in which its request could be re-presented, including after a
//! reload that widens `clock_skew_seconds`.
//!
//! Consumer credentials should include:
//!   { "hmac_auth": { "secret": "<shared-secret>" } }

#[cfg(test)]
use crate::fips::approved::Sha512;
use crate::fips::approved::{HmacSha256, HmacSha512, Sha256};
use async_trait::async_trait;
use base64::Engine as _;
use serde_json::Value;
use std::fmt;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

use super::utils::PluginHttpClient;
use super::utils::auth_attempt::AuthenticationAttempt;
use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, commit_authentication_attempt,
    constant_time_eq,
};
use super::utils::header_extract::{ConfiguredHeaderLookup, lookup_configured_header};
use super::utils::redis_rate_limiter::{
    REDIS_PLUGIN_CONFIG_KEYS, RedisConfig, RedisRateLimitClient,
};
use super::utils::replay_authority::{
    self, ReplayAdmission, ReplayAuthority, ReplayDomain, ReplayScope, validate_scope_backend,
};
use super::{RequestContext, strip_auth_scheme};
use crate::config::types::Consumer;
use crate::consumer_index::ConsumerIndex;
use crate::util::unknown_keys::reject_unknown_keys;

const HMAC_REQUEST_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
const HMAC_SIGNING_VERSION_V1: &str = "ferrum-hmac-v1";
const HMAC_SIGNING_VERSION_V2: &str = "ferrum-hmac-v2";

/// Widest admissible `clock_skew_seconds`.
///
/// Bounded because the fixed replay retention horizon must dominate the widest
/// acceptance window any admissible configuration can open. A larger freshness
/// window is also poor practice on its own: it is the interval during which a
/// captured `ferrum-hmac-v1` request stays replayable.
pub const MAX_HMAC_CLOCK_SKEW_SECONDS: u64 = 300;

/// Fixed retention horizon for an admitted `ferrum-hmac-v2` nonce marker.
///
/// Dominates `2 * MAX_HMAC_CLOCK_SKEW_SECONDS` — the widest span over which any
/// admissible configuration can accept one unchanged signed request — plus one
/// second for whole-second `Date` truncation.
pub const HMAC_MARKER_RETENTION_SECONDS: u64 = 2 * MAX_HMAC_CLOCK_SKEW_SECONDS + 1;

const _: () = assert!(HMAC_MARKER_RETENTION_SECONDS > 2 * MAX_HMAC_CLOCK_SKEW_SECONDS);

/// Default capacity of a `replay_scope: process` lane.
///
/// Markers live for the fixed horizon above, so this bounds sustained
/// authenticated v2 throughput on a process lane at roughly
/// `capacity / retention` requests per second. Under-provisioning surfaces as
/// fail-closed refusals, never as a reusable signature; `shared` scope moves
/// the cost into Redis.
pub const DEFAULT_HMAC_REPLAY_MAX_ENTRIES: usize = 100_000;

/// Plugin-config id used when no stable resource id is supplied (Admin config
/// validation and direct/test construction). Distinct from any real id, so a
/// validation-constructed instance can never join a live policy's replay lane
/// or Redis keyspace.
pub const STANDALONE_HMAC_AUTH_CONFIG_ID: &str = "__standalone__";

/// Nonce wire-form bounds.
///
/// The alphabet is base64url without padding (`A-Za-z0-9-_`), which excludes
/// every whitespace and control byte, `=`, `+`, and `/` by construction. Two
/// canonical forms are admitted and each is held to its own ≥128-bit floor:
///
/// * an all-hex value is read as **hex**, so it needs at least 32 characters
///   (128 bits) and an even length — a 22-character all-hex nonce carries only
///   88 bits and must not be admitted merely because 22 base64url characters
///   would have been enough;
/// * anything else is read as **base64url**, needing at least 22 characters
///   (132 bits).
const HMAC_NONCE_MIN_BASE64URL_CHARS: usize = 22;
const HMAC_NONCE_MIN_HEX_CHARS: usize = 32;
const HMAC_NONCE_MAX_CHARS: usize = 86;

/// Closed root key set owned by this plugin. The complete admissible root is
/// this unioned with [`REDIS_PLUGIN_CONFIG_KEYS`]; both halves must stay in
/// exact parity with the `additionalProperties: false` `HmacAuthConfig` schema
/// in `openapi.yaml`.
pub const HMAC_AUTH_CONFIG_KEYS: &[&str] = &[
    "clock_skew_seconds",
    "signing_profile",
    "allow_unsafe_replayable_v1",
    "replay_scope",
    "replay_max_entries",
];

/// Complete root allowlist: the plugin's own fields plus the shared Redis
/// fields that back `replay_scope: shared`.
fn root_config_keys() -> Vec<&'static str> {
    let mut allowed = HMAC_AUTH_CONFIG_KEYS.to_vec();
    allowed.extend_from_slice(REDIS_PLUGIN_CONFIG_KEYS);
    allowed
}

/// Versioned signing profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacSigningProfile {
    /// Freshness-only. No nonce, no replay store, no single-use guarantee.
    /// Selectable only with an explicit unsafe acknowledgement.
    V1Unsafe,
    /// Mandatory client nonce, cryptographically bound and claimed exactly once.
    V2,
}

impl HmacSigningProfile {
    fn version(self) -> &'static str {
        match self {
            Self::V1Unsafe => HMAC_SIGNING_VERSION_V1,
            Self::V2 => HMAC_SIGNING_VERSION_V2,
        }
    }
}

/// Fixed client-visible bodies. None carries a nonce, a signature, a consumer
/// identity, a marker, or any backend detail.
const REPLAY_DETECTED_BODY: &str = r#"{"error":"Signed request has already been used"}"#;
const REPLAY_CAPACITY_BODY: &str = r#"{"error":"Signed-request replay protection is at capacity"}"#;
const REPLAY_UNAVAILABLE_BODY: &str = r#"{"error":"Signed-request replay protection unavailable"}"#;
const MISSING_NONCE_BODY: &str = r#"{"error":"Missing nonce in HMAC authorization"}"#;
const MALFORMED_NONCE_BODY: &str = r#"{"error":"Malformed nonce in HMAC authorization"}"#;
const UNEXPECTED_NONCE_BODY: &str =
    r#"{"error":"HMAC authorization nonce is not accepted by this signing profile"}"#;
const MISSING_DIGEST_BODY: &str = r#"{"error":"Missing required Digest header"}"#;
const AMBIGUOUS_DIGEST_BODY: &str = r#"{"error":"Ambiguous Digest and Content-Digest headers"}"#;
const MALFORMED_DIGEST_BODY: &str = r#"{"error":"Malformed digest header"}"#;
const UNSUPPORTED_DIGEST_BODY: &str = r#"{"error":"Unsupported digest algorithm"}"#;
const DIGEST_MISMATCH_BODY: &str = r#"{"error":"Digest header does not match request body"}"#;

/// Which body-integrity field the client presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestSyntax {
    /// RFC 9530 `Content-Digest` structured-field dictionary of byte sequences.
    Rfc9530,
    /// RFC 3230 `Digest` `algorithm=base64` list.
    Rfc3230,
}

/// Decoded SHA-256 / SHA-512 members from one well-formed digest field.
#[derive(Debug, Clone, Copy)]
struct ParsedBodyDigest {
    sha256: Option<[u8; 32]>,
    sha512: Option<[u8; 64]>,
}

/// Whether `nonce` is an admissible `ferrum-hmac-v2` wire nonce.
///
/// Rejects before any credential lookup or replay-store interaction, so a
/// malformed marker costs a bounded character scan and nothing else.
fn nonce_wire_form_is_valid(nonce: &str) -> bool {
    let bytes = nonce.as_bytes();
    if bytes.len() > HMAC_NONCE_MAX_CHARS {
        return false;
    }
    if !bytes
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    if bytes.iter().all(u8::is_ascii_hexdigit) {
        return bytes.len() >= HMAC_NONCE_MIN_HEX_CHARS && bytes.len().is_multiple_of(2);
    }
    bytes.len() >= HMAC_NONCE_MIN_BASE64URL_CHARS
}

fn is_standard_base64_alphabet(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn parse_standard_base64_digest(value: &str, expected_len: usize) -> Result<Vec<u8>, &'static str> {
    if value.is_empty() || !is_standard_base64_alphabet(value.as_bytes()) {
        return Err(MALFORMED_DIGEST_BODY);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| MALFORMED_DIGEST_BODY)?;
    if decoded.len() != expected_len {
        return Err(MALFORMED_DIGEST_BODY);
    }
    Ok(decoded)
}

fn parse_sf_byte_sequence(value: &str) -> Result<&str, &'static str> {
    let value = value.trim();
    if value.len() < 2 || !value.starts_with(':') || !value.ends_with(':') {
        return Err(MALFORMED_DIGEST_BODY);
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty() || inner.contains(':') || inner.contains(';') {
        return Err(MALFORMED_DIGEST_BODY);
    }
    Ok(inner)
}

fn parse_legacy_digest_value(value: &str) -> Result<&str, &'static str> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with(':')
        || value.starts_with('"')
        || value.contains(';')
        || value.contains(':')
    {
        return Err(MALFORMED_DIGEST_BODY);
    }
    Ok(value)
}

fn digest_algorithm_len(algorithm: &str) -> Result<usize, &'static str> {
    match algorithm {
        "sha-256" => Ok(32),
        "sha-512" => Ok(64),
        _ => Err(UNSUPPORTED_DIGEST_BODY),
    }
}

fn parse_body_digest_header(
    digest_header: &str,
    syntax: DigestSyntax,
) -> Result<ParsedBodyDigest, &'static str> {
    if digest_header.trim().is_empty() {
        return Err(MALFORMED_DIGEST_BODY);
    }
    let mut parsed = ParsedBodyDigest {
        sha256: None,
        sha512: None,
    };
    for member in digest_header.split(',') {
        let member = member.trim();
        if member.is_empty() {
            return Err(MALFORMED_DIGEST_BODY);
        }
        let Some((raw_key, raw_value)) = member.split_once('=') else {
            return Err(MALFORMED_DIGEST_BODY);
        };
        let algorithm = raw_key.trim().to_ascii_lowercase();
        if algorithm.is_empty() {
            return Err(MALFORMED_DIGEST_BODY);
        }
        let expected_len = digest_algorithm_len(&algorithm)?;
        let encoded = match syntax {
            DigestSyntax::Rfc9530 => parse_sf_byte_sequence(raw_value)?,
            DigestSyntax::Rfc3230 => parse_legacy_digest_value(raw_value)?,
        };
        let decoded = parse_standard_base64_digest(encoded, expected_len)?;
        match algorithm.as_str() {
            "sha-256" => {
                if parsed.sha256.is_some() {
                    return Err(MALFORMED_DIGEST_BODY);
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&decoded);
                parsed.sha256 = Some(hash);
            }
            "sha-512" => {
                if parsed.sha512.is_some() {
                    return Err(MALFORMED_DIGEST_BODY);
                }
                let mut hash = [0u8; 64];
                hash.copy_from_slice(&decoded);
                parsed.sha512 = Some(hash);
            }
            _ => return Err(UNSUPPORTED_DIGEST_BODY),
        }
    }
    if parsed.sha256.is_none() && parsed.sha512.is_none() {
        return Err(MALFORMED_DIGEST_BODY);
    }
    Ok(parsed)
}

fn digest_field_line_state(ctx: &RequestContext, name: &str) -> (bool, bool) {
    let mut present = false;
    let mut all_utf8 = true;
    for value in ctx.header_field_lines(name) {
        present = true;
        all_utf8 &= std::str::from_utf8(value).is_ok();
    }
    (present, all_utf8)
}

fn select_digest_header(ctx: &RequestContext) -> Result<(&str, DigestSyntax), &'static str> {
    // The materialized map comma-folds repeated valid field lines, which is
    // exactly the list representation both supported digest syntaxes parse.
    // It intentionally omits non-UTF-8 lines, however. Inspect the pristine
    // HeaderMap as well so a valid signed line plus an unparseable duplicate
    // cannot authenticate as though the competing wire line never existed.
    let (content_present, content_all_utf8) = digest_field_line_state(ctx, "content-digest");
    let (legacy_present, legacy_all_utf8) = digest_field_line_state(ctx, "digest");
    match (content_present, legacy_present) {
        (true, true) => Err(AMBIGUOUS_DIGEST_BODY),
        (true, false) => {
            if !content_all_utf8 {
                return Err(MALFORMED_DIGEST_BODY);
            }
            let value = ctx
                .headers
                .get("content-digest")
                .ok_or(MALFORMED_DIGEST_BODY)?;
            if value.trim().is_empty() {
                Err(MALFORMED_DIGEST_BODY)
            } else {
                Ok((value.as_str(), DigestSyntax::Rfc9530))
            }
        }
        (false, true) => {
            if !legacy_all_utf8 {
                return Err(MALFORMED_DIGEST_BODY);
            }
            let value = ctx.headers.get("digest").ok_or(MALFORMED_DIGEST_BODY)?;
            if value.trim().is_empty() {
                Err(MALFORMED_DIGEST_BODY)
            } else {
                Ok((value.as_str(), DigestSyntax::Rfc3230))
            }
        }
        (false, false) => Err(MISSING_DIGEST_BODY),
    }
}

fn parsed_digest_matches_body(
    parsed: &ParsedBodyDigest,
    body_sha256: &[u8; 32],
    body_sha512: &[u8; 64],
) -> bool {
    let mut matched = false;
    let mut ok = true;
    if let Some(expected) = parsed.sha256.as_ref() {
        matched = true;
        ok &= constant_time_eq(expected, body_sha256);
    }
    if let Some(expected) = parsed.sha512.as_ref() {
        matched = true;
        ok &= constant_time_eq(expected, body_sha512);
    }
    matched && ok
}

fn collected_body_hashes(ctx: &RequestContext) -> Option<(&[u8; 32], &[u8; 64])> {
    match (
        ctx.request_body_sha256.as_ref(),
        ctx.request_body_sha512.as_ref(),
    ) {
        (Some(sha256), Some(sha512)) => Some((sha256, sha512)),
        _ => None,
    }
}

#[derive(Clone)]
pub(super) struct HmacWirePath(String);

impl HmacWirePath {
    pub(super) fn new(path: String) -> Self {
        Self(path)
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for HmacWirePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacWirePath([REDACTED])")
    }
}

/// The request-target spelling covered by the client's HMAC.
///
/// The wrapper's contents and this accessor are private to `hmac_auth`, making
/// this the only place that can recover a pre-canonicalization spelling. Every
/// policy and routing consumer remains confined to `RequestContext::path`.
#[inline]
fn hmac_wire_path(ctx: &RequestContext) -> &str {
    ctx.raw_path
        .as_ref()
        .map(HmacWirePath::as_str)
        .unwrap_or(ctx.path.as_str())
}

struct ParsedHmacAuthorization {
    username: String,
    algorithm: String,
    signature: String,
    nonce: Option<String>,
}

fn is_auth_param_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_auth_param_value(raw: &str) -> Result<String, ()> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(());
    }
    if !value.starts_with('"') {
        if value
            .chars()
            .any(|ch| ch.is_ascii_whitespace() || matches!(ch, '"' | '\\') || ch.is_control())
        {
            return Err(());
        }
        return Ok(value.to_string());
    }

    let mut decoded = String::with_capacity(value.len().saturating_sub(2));
    let mut chars = value[1..].chars();
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if escaped {
            if matches!(ch, '\r' | '\n') {
                return Err(());
            }
            decoded.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                return chars
                    .as_str()
                    .trim()
                    .is_empty()
                    .then_some(decoded)
                    .ok_or(());
            }
            '\r' | '\n' => return Err(()),
            _ => decoded.push(ch),
        }
    }
    Err(())
}

fn parse_hmac_auth_segment(
    segment: &str,
    username: &mut Option<String>,
    algorithm: &mut Option<String>,
    signature: &mut Option<String>,
    nonce: &mut Option<String>,
) -> Result<(), &'static str> {
    let Some((raw_key, raw_value)) = segment.trim().split_once('=') else {
        return Err(r#"{"error":"Malformed HMAC authorization parameters"}"#);
    };
    let key = raw_key.trim();
    if key.is_empty() || !key.bytes().all(is_auth_param_name_char) {
        return Err(r#"{"error":"Malformed HMAC authorization parameters"}"#);
    }
    let value = parse_auth_param_value(raw_value)
        .map_err(|_| r#"{"error":"Malformed HMAC authorization parameters"}"#)?;
    if key.eq_ignore_ascii_case("username") {
        if username.replace(value).is_some() {
            return Err(r#"{"error":"Duplicate username in HMAC authorization"}"#);
        }
    } else if key.eq_ignore_ascii_case("algorithm") {
        if algorithm.replace(value).is_some() {
            return Err(r#"{"error":"Duplicate algorithm in HMAC authorization"}"#);
        }
    } else if key.eq_ignore_ascii_case("signature") {
        if signature.replace(value).is_some() {
            return Err(r#"{"error":"Duplicate signature in HMAC authorization"}"#);
        }
    } else if key.eq_ignore_ascii_case("nonce") && nonce.replace(value).is_some() {
        return Err(r#"{"error":"Duplicate nonce in HMAC authorization"}"#);
    }
    Ok(())
}

/// Parse the `Authorization: hmac …` parameters.
///
/// `profile` decides the nonce contract, and both directions are enforced: v2
/// requires a syntactically valid nonce, and v1 **rejects** one outright. A
/// client that sends a nonce believes its request is single-use; silently
/// ignoring it under v1 would leave that belief unfalsified while the request
/// stayed replayable, and the nonce is not part of the v1 signing base so it
/// would also be attacker-mutable.
fn parse_hmac_authorization(
    params: &str,
    profile: HmacSigningProfile,
) -> Result<ParsedHmacAuthorization, &'static str> {
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut username = None;
    let mut algorithm = None;
    let mut signature = None;
    let mut nonce = None;
    for (idx, ch) in params.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parse_hmac_auth_segment(
                    &params[start..idx],
                    &mut username,
                    &mut algorithm,
                    &mut signature,
                    &mut nonce,
                )?;
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return Err(r#"{"error":"Malformed HMAC authorization parameters"}"#);
    }
    parse_hmac_auth_segment(
        &params[start..],
        &mut username,
        &mut algorithm,
        &mut signature,
        &mut nonce,
    )?;

    let username = username
        .filter(|value| !value.is_empty())
        .ok_or(r#"{"error":"Missing username in HMAC authorization"}"#)?;
    let algorithm = algorithm
        .unwrap_or_else(|| "hmac-sha256".to_string())
        .to_ascii_lowercase();
    if !matches!(algorithm.as_str(), "hmac-sha256" | "hmac-sha512") {
        return Err(r#"{"error":"Unsupported HMAC algorithm"}"#);
    }
    let signature = signature
        .filter(|value| !value.is_empty())
        .ok_or(r#"{"error":"Missing signature in HMAC authorization"}"#)?;

    let nonce = match profile {
        HmacSigningProfile::V2 => {
            let nonce = nonce.ok_or(MISSING_NONCE_BODY)?;
            if !nonce_wire_form_is_valid(&nonce) {
                return Err(MALFORMED_NONCE_BODY);
            }
            Some(nonce)
        }
        HmacSigningProfile::V1Unsafe => {
            if nonce.is_some() {
                return Err(UNEXPECTED_NONCE_BODY);
            }
            None
        }
    };

    Ok(ParsedHmacAuthorization {
        username,
        algorithm,
        signature,
        nonce,
    })
}

/// Opaque, request-scoped identity of the `hmac_auth` instance that staged a
/// preverified authorization.
///
/// A request can be screened by several `hmac_auth` instances at once — sibling
/// proxy/global policies, a legacy `ferrum-hmac-v1` instance beside a
/// `ferrum-hmac-v2` one, or two v2 policies with different replay domains. A
/// staged record therefore may not be a request-global slot: it carries a
/// Consumer snapshot that one *specific* policy authenticated under one
/// *specific* signing profile and replay domain. Handing it to another instance
/// lets that instance skip its own verification and, worse, take a decision path
/// (v1's "no claim at all") for a proof that a different profile verified.
///
/// Identity is per **constructed instance** rather than per config id: the
/// plugin object that stages and the plugin object that consumes are the same
/// `Arc` inside one request (the `PluginCache` snapshot is pinned for the
/// request), while two instances built from identical configuration — including
/// two standalone/test constructions that share the placeholder config id — are
/// genuinely different owners. The serial is folded together with the policy
/// identity so a record can never be matched by a same-serial instance of a
/// different profile or replay domain.
#[derive(Clone, Copy, PartialEq, Eq)]
struct HmacPrebufferOwner([u8; 32]);

impl fmt::Debug for HmacPrebufferOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacPrebufferOwner(<digest>)")
    }
}

/// Process-monotonic instance serial. Never reused, never derived from
/// attacker-visible data, and never logged.
static HMAC_INSTANCE_SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl HmacPrebufferOwner {
    fn new(
        namespace: &str,
        policy_config_id: &str,
        profile: HmacSigningProfile,
        replay_domain: Option<&ReplayDomain>,
    ) -> Self {
        let serial = HMAC_INSTANCE_SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut hasher =
            super::utils::replay_partition::PartitionHasher::new("ferrum-edge/hmac-auth/owner/v1");
        hasher.u64_value("owner.serial", serial);
        hasher.text("owner.namespace", namespace);
        hasher.text("owner.config_id", policy_config_id);
        hasher.text("owner.profile", profile.version());
        match replay_domain {
            Some(domain) => hasher.nested("owner.replay_domain", &domain.digest()),
            None => hasher.count("owner.replay_domain", 0),
        }
        Self(hasher.digest())
    }
}

/// Maximum preverified authorizations staged for one request.
///
/// One slot per `hmac_auth` instance that both preverified a signature and will
/// consume its own record. The bound exists so a pathological chain cannot grow
/// request-scoped credential-bearing state without limit; an instance that
/// cannot stage simply falls through to the ordinary extract/verify path, which
/// re-derives everything and is never weaker.
const MAX_STAGED_HMAC_PREBUFFERS: usize = 8;

struct CachedHmacAuthorization {
    authorization_fingerprint: [u8; 32],
    namespace: String,
    username: String,
    authority: String,
    date: String,
    method: String,
    path: String,
    query: String,
    digest_header: String,
    /// `ferrum-hmac-v2` client nonce. `None` under the legacy v1 profile.
    ///
    /// Not re-validated by `cached_request_binding_matches`: the nonce is an
    /// `Authorization` parameter, so the retained SHA-256 fingerprint of that
    /// header already binds it byte-for-byte.
    nonce: Option<String>,
    preverified_consumer: Arc<Consumer>,
}

/// Owner-partitioned staging set for one request.
type StagedHmacRecords = Vec<(HmacPrebufferOwner, CachedHmacAuthorization)>;

/// Completion of the pre-buffered path: absent, verified consumer + v2 nonce, or
/// a fixed JSON authentication error.
type PrebufferedHmacAuthCompletion = Option<Result<(Arc<Consumer>, Option<String>), String>>;

/// Request-scoped bridge between HMAC's pre-body signature check and its
/// post-body digest check, **partitioned by owning plugin instance**.
///
/// After preverification the parsed signature is dropped; each record retains
/// only a fingerprint used to detect Authorization changes, the already-owned
/// signed request fields needed by the final digest check, and a Consumer
/// containing secret material. Its custom `Debug` reveals only how many records
/// are staged — never an owner, a consumer, or a nonce — and its custom `Clone`
/// deliberately drops every record so deferred-log/simulation contexts can never
/// inherit authentication data.
///
/// The partition is the security property. A single request-global slot let the
/// first instance to preverify hand its record to whichever instance consumed
/// first: an unsafe `ferrum-hmac-v1` policy could consume a `ferrum-hmac-v2`
/// instance's verified record and then take v1's "no single-use claim" path, and
/// two sibling v2 policies could cross-consume and claim in the wrong replay
/// domain. Every record here is readable and removable **only** by the exact
/// instance/policy/profile/replay-domain that staged it; one owner can neither
/// observe nor erase another's.
#[derive(Default)]
pub(crate) struct HmacPrebufferState {
    /// Small ordered set, bounded by [`MAX_STAGED_HMAC_PREBUFFERS`]. A `Vec`
    /// behind an uncontended request-local `Mutex` rather than a map: the
    /// cardinality is a handful, the staging path is already the cold
    /// post-signature-verification path, and the ordinary request that
    /// configures no `hmac_auth` never touches it at all.
    staged: Mutex<StagedHmacRecords>,
}

impl Clone for HmacPrebufferState {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl fmt::Debug for HmacPrebufferState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacPrebufferState")
            .field("staged", &self.len())
            .finish()
    }
}

impl HmacPrebufferState {
    fn lock(&self) -> std::sync::MutexGuard<'_, StagedHmacRecords> {
        self.staged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    /// Stage `cached` for `owner`.
    ///
    /// Returns `false` when nothing was staged — the owner already holds a
    /// record for this request, or the bound is reached. A refusal is safe:
    /// the caller then declines the pre-authenticate buffering path and the
    /// ordinary path re-extracts and re-verifies from scratch.
    fn stage(&self, owner: HmacPrebufferOwner, cached: CachedHmacAuthorization) -> bool {
        let mut staged = self.lock();
        if staged.iter().any(|(existing, _)| *existing == owner) {
            return false;
        }
        if staged.len() >= MAX_STAGED_HMAC_PREBUFFERS {
            return false;
        }
        staged.push((owner, cached));
        true
    }

    /// Remove and return **this owner's** record, leaving every other owner's
    /// record untouched.
    fn take(&mut self, owner: HmacPrebufferOwner) -> Option<CachedHmacAuthorization> {
        let mut staged = self.lock();
        let index = staged.iter().position(|(existing, _)| *existing == owner)?;
        Some(staged.remove(index).1)
    }
}

pub struct HmacAuth {
    clock_skew_seconds: u64,
    profile: HmacSigningProfile,
    /// Stable protection-domain identity for this policy's v2 nonces.
    /// Precomputed at construction; `None` under the legacy v1 profile.
    replay_domain: Option<ReplayDomain>,
    /// Single-use authority v2 nonces are claimed against. Owned by the shared
    /// registry, so an equivalent reload inherits live markers.
    replay_authority: Option<Arc<ReplayAuthority>>,
    /// Ownership token for this instance's request-scoped prebuffer records.
    /// Precomputed at construction, so no request path hashes configuration.
    prebuffer_owner: HmacPrebufferOwner,
}

impl HmacAuth {
    /// Construct without a stable policy identity.
    ///
    /// Admin config validation and direct/test construction take this path. A
    /// `replay_scope: process` policy then gets a **private** lane keyed by the
    /// standalone placeholder id, so a validation call can neither read,
    /// mutate, nor consume a live proxy's replay history. A `shared` policy
    /// constructs a detached fail-closed authority: construction never
    /// publishes a process readiness dependency or arms a Redis recovery task.
    /// Live readiness is published from
    /// [`crate::plugins::Plugin::commit_background_tasks`].
    #[allow(dead_code)] // exercised by external unit tests
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::build(config, None, None)
    }

    /// Construct with the shared HTTP client and the configured plugin-config
    /// resource id.
    ///
    /// That id, with the gateway namespace, is the stable protection-domain
    /// identity. Production `PluginCache` must pass it: with `None`, every
    /// reload generation would own a private replay lane and a rebuilt plugin
    /// would accept a signed request it had already admitted.
    pub fn new_with_http_client_and_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        Self::build(config, Some(&http_client), plugin_config_id)
    }

    /// `http_client` is `Option` on purpose: the plain `new()` path (Admin
    /// config validation and direct/test construction) must not have to build a
    /// reqwest/TLS/DNS stack it never uses.
    ///
    /// A `replay_scope: shared` config still constructs its Redis client on that
    /// path — the backend is chosen by the config, not by the caller — but the
    /// client stays detached until commit: no packed-health registration, no
    /// recovery task, no Redis dial, and no keyspace mutation.
    fn build(
        config: &Value,
        http_client: Option<&PluginHttpClient>,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("hmac_auth: config must be an object, got: {config}"))?;
        if config_obj.get("require_digest").is_some() {
            return Err(
                "hmac_auth: 'require_digest' was removed; request digests are always required"
                    .to_string(),
            );
        }
        // Closed root key set: a misspelled `replay_scope` or `signing_profile`
        // must fail admission rather than silently leave a policy on a weaker
        // posture than the operator wrote.
        // The prefix carries its own separator: `reject_unknown_keys` renders
        // `{error_prefix}unknown configuration key(s): …` verbatim.
        reject_unknown_keys(config_obj, "config", &root_config_keys(), "hmac_auth: ")?;

        // The shared Redis helper ASCII-lowercases `sync_mode` before matching,
        // which would admit spellings the published enum does not list. Screen
        // the exact wire form here first (same pattern as `graphql`) so the
        // schema and the constructor accept exactly the same set.
        match config_obj.get("sync_mode") {
            None => {}
            Some(Value::String(mode)) if matches!(mode.as_str(), "local" | "redis") => {}
            Some(Value::String(mode)) => {
                return Err(format!(
                    "hmac_auth: 'sync_mode' must be exactly 'local' or 'redis', got: {mode:?}"
                ));
            }
            Some(_) => return Err("hmac_auth: 'sync_mode' must be a string".to_string()),
        }

        let clock_skew_seconds = parse_u64_field(
            config_obj.get("clock_skew_seconds"),
            "clock_skew_seconds",
            300,
        )?;
        if clock_skew_seconds == 0 {
            return Err("hmac_auth: 'clock_skew_seconds' must be greater than 0".to_string());
        }
        if clock_skew_seconds > MAX_HMAC_CLOCK_SKEW_SECONDS {
            return Err(format!(
                "hmac_auth: 'clock_skew_seconds' must be <= {MAX_HMAC_CLOCK_SKEW_SECONDS} — the \
                 freshness window bounds how long a captured request stays acceptable, and the \
                 fixed replay retention horizon is derived from this ceiling"
            ));
        }

        let allow_unsafe_v1 = match config_obj.get("allow_unsafe_replayable_v1") {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| {
                "hmac_auth: 'allow_unsafe_replayable_v1' must be a boolean".to_string()
            })?,
        };
        let profile = match config_obj.get("signing_profile") {
            None => HmacSigningProfile::V2,
            Some(value) => {
                let value = value
                    .as_str()
                    .ok_or_else(|| "hmac_auth: 'signing_profile' must be a string".to_string())?;
                // Exact, untrimmed: the diagnostic below promises "exactly",
                // and the published enum lists only the canonical spellings.
                match value {
                    HMAC_SIGNING_VERSION_V2 => HmacSigningProfile::V2,
                    HMAC_SIGNING_VERSION_V1 => HmacSigningProfile::V1Unsafe,
                    _ => {
                        return Err(format!(
                            "hmac_auth: 'signing_profile' must be exactly \
                             '{HMAC_SIGNING_VERSION_V2}' or '{HMAC_SIGNING_VERSION_V1}'"
                        ));
                    }
                }
            }
        };
        // v1 provides no single-use guarantee at all. Requiring a second,
        // separately named acknowledgement means it can never be reached by a
        // copied config snippet or a one-word typo.
        if profile == HmacSigningProfile::V1Unsafe && !allow_unsafe_v1 {
            return Err(format!(
                "hmac_auth: 'signing_profile' = '{HMAC_SIGNING_VERSION_V1}' has no replay \
                 protection — a captured valid request can be replayed verbatim for the whole \
                 'clock_skew_seconds' window. It is unsuitable for non-idempotent routes and \
                 requires an explicit 'allow_unsafe_replayable_v1': true acknowledgement. Prefer \
                 '{HMAC_SIGNING_VERSION_V2}', which binds a mandatory client nonce and makes each \
                 signed request single-use."
            ));
        }
        if profile == HmacSigningProfile::V2 && allow_unsafe_v1 {
            return Err(format!(
                "hmac_auth: 'allow_unsafe_replayable_v1' is only meaningful with \
                 'signing_profile' = '{HMAC_SIGNING_VERSION_V1}'"
            ));
        }

        // A blank id would collapse every hmac_auth config in a namespace onto
        // one replay domain; fail closed rather than merge them.
        if plugin_config_id.is_some_and(|config_id| config_id.trim().is_empty()) {
            return Err("hmac_auth: plugin config id must not be blank".to_string());
        }
        let namespace = match http_client {
            Some(client) => client.namespace(),
            None => crate::config::types::DEFAULT_NAMESPACE,
        };
        let policy_config_id = plugin_config_id.unwrap_or(STANDALONE_HMAC_AUTH_CONFIG_ID);

        // Redis fields are parsed and range-validated whether or not the
        // profile activates them, matching every other Redis-backed plugin.
        let default_prefix = default_replay_redis_key_prefix(namespace, policy_config_id);
        let redis_config = RedisConfig::from_plugin_config(config, &default_prefix)?;
        let redis_configured = redis_config.is_some();

        let declared_scope = match config_obj.get("replay_scope") {
            None => None,
            Some(value) => {
                let value = value
                    .as_str()
                    .ok_or_else(|| "hmac_auth: 'replay_scope' must be a string".to_string())?;
                // `ReplayScope::parse` trims and ASCII-lowercases, which would
                // admit spellings the published enum does not list. Screen the
                // exact wire form first (same pattern as `sync_mode` above) so
                // the schema and the constructor accept exactly the same set;
                // the shared parser still owns the value mapping.
                if !matches!(value, "process" | "shared") {
                    return Err(
                        "hmac_auth: 'replay_scope' must be exactly 'process' or 'shared' — use \
                         'shared' together with sync_mode: 'redis' for any deployment running \
                         more than one gateway replica, or 'process' to declare a single-process \
                         deployment whose replay protection is not cross-replica"
                            .to_string(),
                    );
                }
                Some(ReplayScope::parse("hmac_auth", "replay_scope", value)?)
            }
        };
        let replay_max_entries = match config_obj.get("replay_max_entries") {
            None => DEFAULT_HMAC_REPLAY_MAX_ENTRIES,
            Some(value) => {
                let parsed = value.as_u64().ok_or_else(|| {
                    "hmac_auth: 'replay_max_entries' must be an unsigned integer".to_string()
                })?;
                let parsed = usize::try_from(parsed)
                    .map_err(|_| "hmac_auth: 'replay_max_entries' is too large".to_string())?;
                if parsed == 0 {
                    return Err(
                        "hmac_auth: 'replay_max_entries' must be greater than 0".to_string()
                    );
                }
                parsed
            }
        };

        match (profile, declared_scope) {
            // The scope has no default. A gateway cannot observe its own
            // replica count, so declaring it is what distinguishes "this really
            // is one process" from "we silently accept one replay per replica".
            (HmacSigningProfile::V2, None) => {
                return Err(format!(
                    "hmac_auth: 'replay_scope' is required for \
                     '{HMAC_SIGNING_VERSION_V2}' — use 'shared' together with sync_mode: 'redis' \
                     for any deployment running more than one gateway replica, or 'process' to \
                     declare a single-process deployment whose replay protection is not \
                     cross-replica"
                ));
            }
            (HmacSigningProfile::V1Unsafe, Some(_)) => {
                return Err(format!(
                    "hmac_auth: 'replay_scope' is not accepted with 'signing_profile' = \
                     '{HMAC_SIGNING_VERSION_V1}', which has no replay state at all"
                ));
            }
            _ => {}
        }
        if profile == HmacSigningProfile::V1Unsafe && redis_configured {
            return Err(format!(
                "hmac_auth: sync_mode: 'redis' is not accepted with 'signing_profile' = \
                 '{HMAC_SIGNING_VERSION_V1}', which has no replay state at all"
            ));
        }
        if let Some(scope) = declared_scope {
            validate_scope_backend("hmac_auth", "replay_scope", scope, redis_configured)?;
        }

        let replay_domain = (profile == HmacSigningProfile::V2).then(|| {
            ReplayDomain::new(
                HMAC_SIGNING_VERSION_V2,
                namespace,
                "hmac_auth",
                policy_config_id,
                "",
            )
        });
        let retention = std::time::Duration::from_secs(HMAC_MARKER_RETENTION_SECONDS);
        let replay_authority = match (declared_scope, replay_domain.as_ref()) {
            (Some(ReplayScope::Process), Some(domain)) => {
                let shard_amount = http_client
                    .map(|client| client.pool_shard_amount())
                    .unwrap_or_else(|| crate::util::sharding::pool_shard_amount(0));
                Some(Arc::new(ReplayAuthority::process(
                    "hmac_auth",
                    domain,
                    replay_max_entries,
                    retention,
                    shard_amount,
                )?))
            }
            (Some(ReplayScope::Shared), Some(_)) => {
                // `validate_scope_backend` above already rejected `shared`
                // without a backend, so `redis_config` is present here.
                let redis_config = redis_config.ok_or_else(|| {
                    "hmac_auth: 'replay_scope' = 'shared' requires sync_mode: 'redis' and a \
                     'redis_url'"
                        .to_string()
                })?;
                // Classification-only diagnostics: never raw RedisError text or
                // the operator key prefix.
                let client = Arc::new(RedisRateLimitClient::for_replay_authority(
                    redis_config,
                    http_client.and_then(|client| client.dns_cache().cloned()),
                    http_client.is_some_and(|client| client.tls_no_verify()),
                    http_client.and_then(|client| client.tls_ca_bundle_path()),
                )?);
                // Detached until `commit_background_tasks`: an invalid later
                // plugin in the same candidate, or this instance if it is never
                // installed, must not mark live readiness unavailable or dial
                // Redis.
                Some(Arc::new(ReplayAuthority::shared(client, retention)))
            }
            _ => None,
        };

        let prebuffer_owner =
            HmacPrebufferOwner::new(namespace, policy_config_id, profile, replay_domain.as_ref());

        Ok(Self {
            clock_skew_seconds,
            profile,
            replay_domain,
            replay_authority,
            prebuffer_owner,
        })
    }

    /// Configured signing profile (test support).
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn signing_profile(&self) -> HmacSigningProfile {
        self.profile
    }

    /// Replay-authority mode (`None` under the legacy v1 profile). Test support.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn replay_mode(&self) -> Option<&'static str> {
        self.replay_authority.as_ref().map(|a| a.mode())
    }

    /// Whether this instance's shared Redis recovery checker has been armed.
    /// Test support for proving construction stays detached until commit.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn shared_replay_recovery_started_for_test(&self) -> bool {
        self.replay_authority
            .as_ref()
            .is_some_and(|authority| authority.recovery_checker_started_for_test())
    }

    /// Marker this policy would claim for `consumer_id` + `nonce`. Test-only
    /// visibility for the domain-isolation and reload/replica convergence
    /// contracts.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn replay_marker_digest(&self, consumer_id: &str, nonce: &str) -> Option<[u8; 32]> {
        self.replay_domain.as_ref().map(|domain| {
            domain
                .marker(&[consumer_id.as_bytes(), nonce.as_bytes()])
                .digest()
        })
    }

    /// Claim a fully verified signed request for exactly one use.
    ///
    /// Reached only after the `Date` window, digest shape, consumer lookup,
    /// HMAC signature, and body digest have all verified, so unauthenticated
    /// traffic can never consume replay capacity or a shared-backend round
    /// trip. Every non-admitted outcome is terminal; there is no path from a
    /// replay, a capacity refusal, or an unavailable authority to acceptance.
    async fn claim_single_use(
        &self,
        nonce: Option<&str>,
        consumer: &Consumer,
    ) -> Result<(), (u16, String)> {
        if self.profile == HmacSigningProfile::V1Unsafe {
            // Explicitly acknowledged freshness-only posture. Counted so the
            // dependency is visible in runtime metrics rather than implicit.
            replay_authority::record_legacy_unsafe_profile_accepted();
            return Ok(());
        }
        let (Some(domain), Some(authority), Some(nonce)) = (
            self.replay_domain.as_ref(),
            self.replay_authority.as_ref(),
            nonce,
        ) else {
            // Unreachable for an admitted v2 configuration. Refuse rather than
            // accept a signed request that would not be made single-use.
            warn!("hmac_auth: replay authority is not configured; refusing the signed request");
            return Err((503, REPLAY_UNAVAILABLE_BODY.to_string()));
        };

        // The marker binds the consumer's stable resource id (not the
        // attacker-supplied username spelling) to the client nonce, inside a
        // domain that already binds the profile version, namespace, and policy
        // id. Neither value survives this call.
        let marker = domain.marker(&[consumer.id.as_bytes(), nonce.as_bytes()]);
        match authority.admit(&marker).await {
            ReplayAdmission::Admitted => Ok(()),
            ReplayAdmission::Replay => Err((401, REPLAY_DETECTED_BODY.to_string())),
            ReplayAdmission::CapacityRefused => {
                warn!(
                    classification = ReplayAdmission::CapacityRefused.classification(),
                    mode = authority.mode(),
                    "hmac_auth: replay state is at capacity; refusing the request rather than \
                     discarding a live replay marker"
                );
                Err((503, REPLAY_CAPACITY_BODY.to_string()))
            }
            ReplayAdmission::AuthorityUnavailable => {
                warn!(
                    classification = ReplayAdmission::AuthorityUnavailable.classification(),
                    mode = authority.mode(),
                    "hmac_auth: replay authority is unavailable; failing closed without \
                     freshness-only fallback"
                );
                Err((503, REPLAY_UNAVAILABLE_BODY.to_string()))
            }
        }
    }

    fn hmac_matches(secret: &[u8], data: &[u8], algorithm: &str, expected: &[u8]) -> bool {
        match algorithm {
            "hmac-sha512" => {
                let Ok(mut mac) = HmacSha512::new_from_slice(secret) else {
                    return false;
                };
                mac.update(data);
                let computed = mac.finalize().into_bytes();
                constant_time_eq(&computed, expected)
            }
            "hmac-sha256" => {
                let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
                    return false;
                };
                mac.update(data);
                let computed = mac.finalize().into_bytes();
                constant_time_eq(&computed, expected)
            }
            _ => false,
        }
    }

    /// Validate that the Date header is within the allowed clock skew window.
    ///
    /// This enforces only the bounded freshness window
    /// (`now ± clock_skew_seconds`). Version 2 separately claims its nonce for
    /// single use; explicitly acknowledged version 1 has no replay store.
    fn validate_date(&self, date_str: &str) -> bool {
        if date_str.is_empty() {
            // No Date header means no freshness bound at all — reject.
            return false;
        }

        // Parse HTTP-date format (RFC 7231): "Sun, 06 Nov 1994 08:49:37 GMT"
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(date_str) {
            Self::timestamps_within_clock_skew(
                chrono::Utc::now().timestamp(),
                parsed.timestamp(),
                self.clock_skew_seconds,
            )
        } else if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(date_str) {
            Self::timestamps_within_clock_skew(
                chrono::Utc::now().timestamp(),
                parsed.timestamp(),
                self.clock_skew_seconds,
            )
        } else {
            warn!("hmac_auth: unparseable Date header");
            false
        }
    }

    /// Compare whole-second timestamps so the freshness horizon is exactly
    /// bounded by `clock_skew_seconds`. Truncating a signed duration would
    /// otherwise admit nearly one extra second at both ends of the window,
    /// outliving the fixed replay-marker retention contract.
    fn timestamps_within_clock_skew(now: i64, signed: i64, clock_skew_seconds: u64) -> bool {
        now.saturating_sub(signed).unsigned_abs() <= clock_skew_seconds
    }

    /// Verify that a digest field value matches `body` under `syntax`.
    #[cfg(test)]
    fn verify_body_digest(digest_header: &str, body: &[u8], syntax: DigestSyntax) -> bool {
        let Ok(parsed) = parse_body_digest_header(digest_header, syntax) else {
            return false;
        };
        parsed_digest_matches_body(&parsed, &Sha256::digest(body), &Sha512::digest(body))
    }

    /// Look up the single digest field on the request. Prefers neither header
    /// when both are present — that is ambiguous and fails closed.
    fn extract_digest_header(ctx: &RequestContext) -> Result<(String, DigestSyntax), &'static str> {
        let (value, syntax) = select_digest_header(ctx)?;
        parse_body_digest_header(value, syntax)?;
        Ok((value.to_string(), syntax))
    }

    fn digest_header_ref(ctx: &RequestContext) -> Option<&str> {
        match select_digest_header(ctx) {
            Ok((value, _)) => Some(value),
            Err(_) => None,
        }
    }

    fn has_hmac_authorization(&self, ctx: &RequestContext) -> bool {
        match lookup_configured_header(ctx, "authorization", None) {
            ConfiguredHeaderLookup::Absent => false,
            // Present but omitted from the materialized map still means the client
            // attempted `Authorization`; extraction will reject as invalid rather
            // than report the credential missing.
            ConfiguredHeaderLookup::PresentNonMaterialized => true,
            ConfiguredHeaderLookup::Value(auth_header) => {
                strip_auth_scheme(&auth_header, "hmac").is_some()
            }
        }
    }

    fn authorization_fingerprint(ctx: &RequestContext) -> Option<[u8; 32]> {
        ctx.headers
            .get("authorization")
            .map(|header| Sha256::digest(header.as_bytes()))
    }

    fn consumer_for_valid_signature(
        &self,
        credential: &auth_flow::HmacAuthCredential,
        consumer_index: &ConsumerIndex,
    ) -> Option<Arc<Consumer>> {
        let expected_signature_len = match credential.algorithm.as_str() {
            "hmac-sha256" => 32,
            "hmac-sha512" => 64,
            _ => return None,
        };
        let expected_signature = base64::engine::general_purpose::STANDARD
            .decode(&credential.signature)
            .ok()
            .filter(|signature| signature.len() == expected_signature_len)?;
        let consumer =
            consumer_index.find_hmac_by_identity(&credential.namespace, &credential.username)?;
        let hmac_entries = consumer.credential_entries("hmac_auth");
        if hmac_entries.is_empty() {
            return None;
        }

        let signing_string = build_signing_string(credential, self.profile);
        hmac_entries
            .iter()
            .any(|hmac_cred| {
                hmac_cred
                    .get("secret")
                    .and_then(|secret| secret.as_str())
                    .is_some_and(|secret| {
                        Self::hmac_matches(
                            secret.as_bytes(),
                            signing_string.as_bytes(),
                            &credential.algorithm,
                            &expected_signature,
                        )
                    })
            })
            .then_some(consumer)
    }

    fn cached_request_binding_matches(
        cached: &CachedHmacAuthorization,
        ctx: &RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> bool {
        let Some(current_fingerprint) = Self::authorization_fingerprint(ctx) else {
            return false;
        };
        if !constant_time_eq(&cached.authorization_fingerprint, &current_fingerprint)
            || ctx.request_authority.as_deref() != Some(cached.authority.as_str())
            || ctx
                .matched_proxy
                .as_ref()
                .map(|proxy| proxy.namespace.as_str())
                != Some(cached.namespace.as_str())
            || ctx.method != cached.method
            || hmac_wire_path(ctx) != cached.path
            || ctx.raw_query_string().unwrap_or_default() != cached.query
            || ctx.headers.get("date").map_or("", String::as_str) != cached.date
            || Self::digest_header_ref(ctx) != Some(cached.digest_header.as_str())
        {
            return false;
        }

        consumer_index
            .find_hmac_by_identity(&cached.namespace, &cached.username)
            .is_some_and(|current_consumer| {
                Arc::ptr_eq(&current_consumer, &cached.preverified_consumer)
            })
    }

    fn should_prebuffer_for_request(
        &self,
        ctx: &RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> bool {
        let ExtractedCredential::HmacAuth(credential) = self.extract(ctx) else {
            return false;
        };
        let Some(authorization_fingerprint) = Self::authorization_fingerprint(ctx) else {
            return false;
        };

        // The signing base binds only request-line/header data, so HMAC
        // verification does not require body bytes. Extract already refused a
        // malformed or unsupported digest field. Only a valid secret-holder
        // may enable collection; unknown and known-invalid identities both stay
        // on the same pre-auth 401 path without reaching the body-size limit.
        if !self.validate_date(&credential.date) {
            return false;
        }
        let Some(preverified_consumer) =
            self.consumer_for_valid_signature(&credential, consumer_index)
        else {
            return false;
        };
        let auth_flow::HmacAuthCredential {
            namespace,
            username,
            authority,
            date,
            method,
            path,
            query,
            digest_header,
            nonce,
            ..
        } = *credential;
        // Staged under this instance's own ownership token. A sibling
        // `hmac_auth` instance — a different policy, a different signing
        // profile, or a different replay domain — can neither read nor erase
        // this record, so it can never skip its own verification or claim in the
        // wrong replay domain. A refusal (duplicate owner or bound reached)
        // declines the pre-authenticate path for this instance only.
        ctx.hmac_prebuffer_state.stage(
            self.prebuffer_owner,
            CachedHmacAuthorization {
                authorization_fingerprint,
                namespace,
                username,
                authority,
                date,
                method,
                path,
                query,
                digest_header,
                nonce,
                preverified_consumer,
            },
        )
    }

    /// Complete the pre-buffered authentication path.
    ///
    /// Returns the resolved Consumer together with the v2 nonce still to be
    /// claimed; the claim itself is made by [`run_hmac_auth`], which is the one
    /// funnel both authentication paths pass through.
    fn take_prebuffered_auth(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PrebufferedHmacAuthCompletion {
        let cached = ctx.hmac_prebuffer_state.take(self.prebuffer_owner)?;

        // The record is already bound to this instance by ownership, so what is
        // left to check is that the *request* did not change under it. H1/H2 and
        // H3 call the prebuffer predicate immediately before body collection and
        // authentication, with no plugin hook in between, but bind the
        // Authorization header, every signed request field, and the exact
        // Consumer snapshot anyway; if that lifecycle ever changes, discard the
        // record and run ordinary extraction/verification.
        if !Self::cached_request_binding_matches(&cached, ctx, consumer_index) {
            return None;
        }

        if !self.validate_date(&cached.date) {
            return Some(Err(
                r#"{"error":"Missing or expired Date header"}"#.to_string()
            ));
        }
        let Some((body_sha256, body_sha512)) = collected_body_hashes(ctx) else {
            return Some(Err(DIGEST_MISMATCH_BODY.to_string()));
        };
        let syntax = match select_digest_header(ctx) {
            Ok((_, syntax)) => syntax,
            Err(body) => return Some(Err(body.to_string())),
        };
        let parsed = match parse_body_digest_header(&cached.digest_header, syntax) {
            Ok(parsed) => parsed,
            Err(body) => return Some(Err(body.to_string())),
        };
        if !parsed_digest_matches_body(&parsed, body_sha256, body_sha512) {
            debug!("hmac_auth: digest header does not match request body");
            return Some(Err(DIGEST_MISMATCH_BODY.to_string()));
        }

        Some(Ok((cached.preverified_consumer, cached.nonce)))
    }
}

#[async_trait]
impl AuthMechanism for HmacAuth {
    fn mechanism_name(&self) -> &'static str {
        "hmac_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        // RFC 6750-style `Authorization` parameters and digest headers are
        // visible-ASCII structured fields. A present but non-materialized line
        // is malformed, not absent.
        let auth_header = match lookup_configured_header(ctx, "authorization", None) {
            ConfiguredHeaderLookup::Absent => return ExtractedCredential::Missing,
            ConfiguredHeaderLookup::PresentNonMaterialized => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid Authorization header"}"#.into(),
                );
            }
            ConfiguredHeaderLookup::Value(header) => header,
        };

        let Some(params_str) = strip_auth_scheme(&auth_header, "hmac") else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid HMAC authorization format"}"#.to_string(),
            );
        };

        // Nonce syntax is validated here, before any consumer lookup, HMAC
        // computation, or replay-store interaction: a malformed or absent
        // marker is refused for the cost of a bounded character scan and can
        // never reach replay storage.
        let ParsedHmacAuthorization {
            username,
            algorithm,
            signature,
            nonce,
        } = match parse_hmac_authorization(params_str, self.profile) {
            Ok(parsed) => parsed,
            Err(body) => return ExtractedCredential::InvalidFormat(body.to_string()),
        };

        // Enforce digest presence at extraction so we surface the clearest
        // error before consumer lookup. The actual body-vs-digest comparison
        // happens in `verify` once we have the buffered body.
        //
        // HBONE CONNECT keeps the request body streaming so the upgrade handle
        // remains available for relay; request-body bytes are therefore not
        // available at authenticate time. Fail closed for this shape.
        let is_hbone_connect = ctx.method.eq_ignore_ascii_case("CONNECT")
            && ctx
                .metadata
                .get("request_protocol")
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("hbone"));
        if is_hbone_connect
            && ctx.request_body_bytes.is_none()
            && !ctx.metadata.contains_key("request_body")
        {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"HBONE CONNECT is incompatible with hmac_auth request-body digest verification"}"#.to_string(),
            );
        }
        let (digest_header, digest_syntax) = match Self::extract_digest_header(ctx) {
            Ok(header) => header,
            Err(body) => return ExtractedCredential::InvalidFormat(body.to_string()),
        };
        let Some(authority) = ctx.request_authority.clone() else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Missing request authority for HMAC authorization"}"#.to_string(),
            );
        };
        let Some(namespace) = ctx
            .matched_proxy
            .as_ref()
            .map(|proxy| proxy.namespace.clone())
        else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Missing proxy namespace for HMAC authorization"}"#.to_string(),
            );
        };

        ExtractedCredential::HmacAuth(Box::new(auth_flow::HmacAuthCredential {
            namespace,
            username,
            authority,
            algorithm,
            signature,
            date: ctx.headers.get("date").cloned().unwrap_or_default(),
            method: ctx.method.clone(),
            // The client signs the request target it put on the wire, so the
            // signing string must use the raw path, not the canonical policy
            // path: a canonicalized `/%61dmin` -> `/admin` would never verify.
            // Raw bytes are an input to signature verification only and never
            // reach routing or any policy surface, both of which already ran
            // on the canonical path (advisory GHSA-69xf-42xm-4w4f).
            path: hmac_wire_path(ctx).to_string(),
            // Bind the raw query string (verbatim, as received) so query
            // parameters are covered by the HMAC. The path field above is the
            // path component only, so without this an attacker could replay a
            // captured signed request with altered/added query parameters.
            query: ctx.raw_query_string().unwrap_or_default().to_string(),
            digest_header,
            digest_is_rfc9530: matches!(digest_syntax, DigestSyntax::Rfc9530),
            nonce,
            request_body_sha256: ctx.request_body_sha256,
            request_body_sha512: ctx.request_body_sha512,
        }))
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::HmacAuth(credential) = credential else {
            return VerifyOutcome::NotApplicable;
        };
        let credential = *credential;

        if !self.validate_date(&credential.date) {
            return VerifyOutcome::Invalid(
                r#"{"error":"Missing or expired Date header"}"#.to_string(),
            );
        }

        let syntax = if credential.digest_is_rfc9530 {
            DigestSyntax::Rfc9530
        } else {
            DigestSyntax::Rfc3230
        };
        let parsed = match parse_body_digest_header(&credential.digest_header, syntax) {
            Ok(parsed) => parsed,
            Err(body) => return VerifyOutcome::Invalid(body.to_string()),
        };
        let hashes = match (
            credential.request_body_sha256.as_ref(),
            credential.request_body_sha512.as_ref(),
        ) {
            (Some(sha256), Some(sha512)) => Some((sha256, sha512)),
            _ => None,
        };
        if let Some((body_sha256, body_sha512)) = hashes
            && !parsed_digest_matches_body(&parsed, body_sha256, body_sha512)
        {
            debug!("hmac_auth: digest header does not match request body");
            return VerifyOutcome::Invalid(DIGEST_MISMATCH_BODY.to_string());
        }

        // Tampering with the digest header itself (without re-signing with
        // the secret) breaks the HMAC because the digest value is signed.
        // The query string is bound too, so altering query params invalidates
        // the signature.
        if let Some(consumer) = self.consumer_for_valid_signature(&credential, consumer_index) {
            if hashes.is_none() {
                // A valid signature must still prove the body. Missing hashes
                // mean the forwarding buffer was never digested — fail closed
                // rather than treating that as the empty body.
                debug!("hmac_auth: signed request is missing collected body hashes");
                return VerifyOutcome::Invalid(DIGEST_MISMATCH_BODY.to_string());
            }
            return VerifyOutcome::consumer(consumer);
        }

        debug!("hmac_auth: credential verification failed");
        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid credentials"}"#.to_string())
    }
}

fn hmac_reject(status_code: u16, body: String) -> super::PluginResult {
    super::PluginResult::Reject {
        status_code,
        body,
        headers: std::collections::HashMap::new(),
    }
}

/// The single funnel both `hmac_auth` authentication paths pass through.
///
/// This deliberately does not delegate to [`auth_flow::run_auth`]. The
/// single-use claim has to land *between* verification and identity commit —
/// after the signature and body digest have proved the request authentic, and
/// before any consumer identity, `auth_method`, or staged header mutation is
/// published — and it has to be able to answer with its own status codes
/// (`401` for a replay, `503` for capacity/authority failure) rather than the
/// generic authentication mapping. Both requirements sit inside `run_auth`'s
/// `verify` → `commit_authentication_attempt` step, so the step is spelled out
/// here instead.
async fn run_hmac_auth(
    mechanism: &HmacAuth,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> super::PluginResult {
    // Pre-buffered path: the signature was verified before body collection and
    // the digest was verified against the collected bytes.
    match mechanism.take_prebuffered_auth(ctx, consumer_index) {
        Some(Err(body)) => return hmac_reject(401, body),
        Some(Ok((consumer, nonce))) => {
            if let Err((status, body)) = mechanism
                .claim_single_use(nonce.as_deref(), &consumer)
                .await
            {
                return hmac_reject(status, body);
            }
            if ctx.identified_consumer.is_none() {
                debug!(
                    "{}: identified consumer '{}'",
                    mechanism.mechanism_name(),
                    consumer.username
                );
                ctx.identified_consumer = Some(consumer);
            }
            if ctx.auth_method.is_none() {
                ctx.auth_method = Some(mechanism.mechanism_name());
            }
            return super::PluginResult::Continue;
        }
        None => {}
    }

    // Ordinary path.
    let credential = match mechanism.extract(ctx) {
        ExtractedCredential::Missing => {
            debug!("{}: no credential present", mechanism.mechanism_name());
            return super::PluginResult::Continue;
        }
        ExtractedCredential::InvalidFormat(body) => return hmac_reject(401, body),
        ExtractedCredential::HmacAuth(credential) => credential,
        // `HmacAuth::extract` only ever produces the three shapes above. Any
        // other shape is not applicable to this mechanism, which is exactly
        // what the shared `run_auth` flow does with it.
        _ => return super::PluginResult::Continue,
    };

    // The nonce is needed after `verify` consumes the credential.
    let nonce = credential.nonce.clone();
    let outcome = mechanism
        .verify(ExtractedCredential::HmacAuth(credential), consumer_index)
        .await;

    // Claim before committing: a rejected claim must leave no identity,
    // `auth_method`, or staged mutation behind, and must never reach backend
    // dispatch.
    //
    // `commit_authentication_attempt` below can still refuse after a successful
    // claim, which would consume the nonce. That is not attacker-reachable: the
    // only refusal it can raise here comes from the resolved Consumer's own
    // configured identity, which is operator data rather than request data, and
    // an attacker cannot present a valid signature for a Consumer's secret in
    // the first place.
    if let VerifyOutcome::Success {
        consumer: Some(consumer),
        ..
    } = &outcome
    {
        let claim = mechanism.claim_single_use(nonce.as_deref(), consumer).await;
        if let Err((status, body)) = claim {
            return hmac_reject(status, body);
        }
    }

    match commit_authentication_attempt(
        ctx,
        AuthenticationAttempt::new(),
        outcome,
        mechanism.mechanism_name(),
        false,
    ) {
        Ok(_) => super::PluginResult::Continue,
        Err(VerifyOutcome::InvalidFormat(body))
        | Err(VerifyOutcome::Invalid(body))
        | Err(VerifyOutcome::ConsumerNotFound(body))
        | Err(VerifyOutcome::VerificationFailed(body)) => hmac_reject(401, body),
        Err(VerifyOutcome::Forbidden(body)) => hmac_reject(403, body),
        Err(VerifyOutcome::Internal(body)) => hmac_reject(500, body),
        Err(VerifyOutcome::Success { .. }) | Err(VerifyOutcome::NotApplicable) => {
            super::PluginResult::Continue
        }
    }
}

auth_flow::impl_auth_plugin!(
    HmacAuth,
    "hmac_auth",
    super::priority::HMAC_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    run_hmac_auth;

    fn requires_request_body_before_authenticate(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &crate::plugins::RequestContext) -> bool {
        self.has_hmac_authorization(ctx)
    }

    fn should_buffer_request_body_before_authenticate(
        &self,
        ctx: &crate::plugins::RequestContext,
        consumer_index: &crate::consumer_index::ConsumerIndex,
    ) -> bool {
        self.should_prebuffer_for_request(ctx, consumer_index)
    }

    fn needs_request_body_bytes(&self) -> bool {
        false
    }

    fn needs_request_body_digests(&self) -> bool {
        true
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn request_body_buffer_limit(&self) -> Option<usize> {
        Some(HMAC_REQUEST_BODY_LIMIT_BYTES)
    }

    /// A shared replay authority is dialed on the authentication path, so its
    /// endpoint belongs in gateway DNS warmup like any other plugin egress.
    fn warmup_hostnames(&self) -> Vec<String> {
        self.replay_authority
            .as_ref()
            .map(|authority| authority.warmup_hostnames())
            .unwrap_or_default()
    }

    /// Publish the shared replay authority after this generation is installed.
    fn commit_background_tasks(&self) {
        if let Some(authority) = self.replay_authority.as_ref() {
            authority.activate();
        }
    }
);

fn parse_u64_field(value: Option<&Value>, field: &str, default_value: u64) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default_value);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("hmac_auth: '{field}' must be an unsigned integer, got: {value}"))
}

/// Default Redis key prefix for shared `ferrum-hmac-v2` replay markers:
/// `{namespace}:hmac_auth:{plugin-config-id}`.
///
/// The config-id component isolates independent policies inside one namespace
/// while every replica of the *same* policy keeps claiming against the same
/// keyspace — which is the whole point of the shared scope. An explicit
/// `redis_key_prefix` remains the documented opt-in for deliberately sharing a
/// keyspace across policies.
fn default_replay_redis_key_prefix(namespace: &str, plugin_config_id: &str) -> String {
    let mut prefix = String::with_capacity(namespace.len() + plugin_config_id.len() + 12);
    prefix.push_str(namespace);
    prefix.push_str(":hmac_auth:");
    prefix.push_str(plugin_config_id);
    prefix
}

/// Build the Ferrum HMAC signing base for `profile`. Fields are
/// newline-separated:
///
/// ```text
/// {VERSION}\n{NAMESPACE}\n{USERNAME}\n{AUTHORITY}\n{METHOD}\n{PATH}\n{QUERY}\n{DATE}\n{DIGEST}[\n{NONCE}]
/// ```
///
/// The version is the **first** field, so a v1 signature can never verify as v2
/// (or the reverse) even if every other field matches: downgrading the profile
/// does not downgrade the signature.
///
/// `query` is the raw request query string as received (percent-encoded, no
/// leading `?`), empty when the request has no query. Binding it prevents an
/// attacker from replaying a captured signature against the same path with
/// altered or added query parameters. Clients must sign the byte-for-byte raw
/// query string the gateway receives.
///
/// `nonce` is appended for `ferrum-hmac-v2` only, and the parser guarantees it
/// is present exactly when the profile is v2 — so a v2 base is never built with
/// an empty trailing field, and a nonce is never left unsigned.
fn build_signing_string(
    credential: &auth_flow::HmacAuthCredential,
    profile: HmacSigningProfile,
) -> String {
    let version = profile.version();
    let nonce = credential.nonce.as_deref().unwrap_or("");
    let mut signing_string = String::with_capacity(
        version.len()
            + credential.namespace.len()
            + credential.username.len()
            + credential.authority.len()
            + credential.method.len()
            + credential.path.len()
            + credential.query.len()
            + credential.date.len()
            + credential.digest_header.len()
            + nonce.len()
            + 9,
    );
    signing_string.push_str(version);
    signing_string.push('\n');
    signing_string.push_str(&credential.namespace);
    signing_string.push('\n');
    signing_string.push_str(&credential.username);
    signing_string.push('\n');
    signing_string.push_str(&credential.authority);
    signing_string.push('\n');
    signing_string.push_str(&credential.method);
    signing_string.push('\n');
    signing_string.push_str(&credential.path);
    signing_string.push('\n');
    signing_string.push_str(&credential.query);
    signing_string.push('\n');
    signing_string.push_str(&credential.date);
    signing_string.push('\n');
    signing_string.push_str(&credential.digest_header);
    if profile == HmacSigningProfile::V2 {
        signing_string.push('\n');
        signing_string.push_str(nonce);
    }
    signing_string
}

#[cfg(test)]
mod tests {
    //! Inline tests for `pub(crate)` helpers. Public API tests live in
    //! `tests/unit/plugins/hmac_auth_tests.rs`.

    use super::{DigestSyntax, HmacAuth, UNSUPPORTED_DIGEST_BODY, parse_body_digest_header};
    use crate::fips::approved::{Sha256, Sha512};
    use base64::Engine as _;

    fn sha256_digest_header(body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        )
    }

    fn sha512_digest_header(body: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(body);
        format!(
            "sha-512={}",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        )
    }

    #[test]
    fn verify_body_digest_accepts_correct_sha256() {
        let body = b"hello world";
        let digest = sha256_digest_header(body);
        assert!(HmacAuth::verify_body_digest(
            &digest,
            body,
            DigestSyntax::Rfc3230
        ));
    }

    #[test]
    fn verify_body_digest_accepts_correct_sha512() {
        let body = b"hello world";
        let digest = sha512_digest_header(body);
        assert!(HmacAuth::verify_body_digest(
            &digest,
            body,
            DigestSyntax::Rfc3230
        ));
    }

    #[test]
    fn verify_body_digest_rejects_wrong_body() {
        let body = b"hello world";
        let digest = sha256_digest_header(body);
        assert!(!HmacAuth::verify_body_digest(
            &digest,
            b"hello WORLD",
            DigestSyntax::Rfc3230
        ));
    }

    #[test]
    fn verify_body_digest_rejects_unknown_algorithm() {
        let body = b"hello world";
        let digest = "sha-1=abc123==";
        assert!(!HmacAuth::verify_body_digest(
            digest,
            body,
            DigestSyntax::Rfc3230
        ));
        assert_eq!(
            parse_body_digest_header(digest, DigestSyntax::Rfc3230).unwrap_err(),
            UNSUPPORTED_DIGEST_BODY
        );
    }

    #[test]
    fn verify_body_digest_rejects_garbage_value() {
        let body = b"hello world";
        let digest = "sha-256=not-valid-base64!!!";
        assert!(!HmacAuth::verify_body_digest(
            digest,
            body,
            DigestSyntax::Rfc3230
        ));
    }

    #[test]
    fn verify_body_digest_handles_empty_body() {
        let body = b"";
        let digest = sha256_digest_header(body);
        assert!(HmacAuth::verify_body_digest(
            &digest,
            body,
            DigestSyntax::Rfc3230
        ));
    }

    #[test]
    fn verify_body_digest_fails_closed_on_unsupported_companion_algorithm() {
        let body = b"hello";
        let valid = sha256_digest_header(body);
        let combined = format!("md5=ignored, {valid}");
        assert!(!HmacAuth::verify_body_digest(
            &combined,
            body,
            DigestSyntax::Rfc3230
        ));
        assert_eq!(
            parse_body_digest_header(&combined, DigestSyntax::Rfc3230).unwrap_err(),
            UNSUPPORTED_DIGEST_BODY
        );
    }

    #[test]
    fn verify_body_digest_accepts_rfc9530_byte_sequence_form() {
        let body = b"hello";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let digest = format!("sha-256=:{}:", b64);
        assert!(HmacAuth::verify_body_digest(
            &digest,
            body,
            DigestSyntax::Rfc9530
        ));
        assert!(!HmacAuth::verify_body_digest(
            &digest,
            body,
            DigestSyntax::Rfc3230
        ));
    }

    #[test]
    fn verify_body_digest_rejects_legacy_form_as_content_digest() {
        let body = b"hello";
        let digest = sha256_digest_header(body);
        assert!(!HmacAuth::verify_body_digest(
            &digest,
            body,
            DigestSyntax::Rfc9530
        ));
    }

    #[test]
    fn timestamp_freshness_has_exact_whole_second_boundaries() {
        const SKEW: u64 = 300;
        const NOW: i64 = 1_800_000_000;

        assert!(HmacAuth::timestamps_within_clock_skew(NOW, NOW, SKEW));
        assert!(HmacAuth::timestamps_within_clock_skew(
            NOW,
            NOW - SKEW as i64,
            SKEW
        ));
        assert!(HmacAuth::timestamps_within_clock_skew(
            NOW,
            NOW + SKEW as i64,
            SKEW
        ));
        assert!(!HmacAuth::timestamps_within_clock_skew(
            NOW,
            NOW - SKEW as i64 - 1,
            SKEW
        ));
        assert!(!HmacAuth::timestamps_within_clock_skew(
            NOW,
            NOW + SKEW as i64 + 1,
            SKEW
        ));
    }
}
