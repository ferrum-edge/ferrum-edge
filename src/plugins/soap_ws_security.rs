//! SOAP WS-Security Plugin
//!
//! Validates WS-Security headers in SOAP envelopes at the proxy layer.
//! Supports UsernameToken authentication (PasswordText and PasswordDigest),
//! X.509 certificate signature verification, SAML assertion validation
//! (XMLDSIG signature verification against trusted IdP signing certificates
//! plus issuer / NotBefore / NotOnOrAfter / Audience checks and an enveloped-
//! signature transform over the assertion), timestamp freshness checks, and
//! nonce replay protection.
//!
//! Runs in `before_proxy` with request body buffering. Priority 1500 places
//! it in the AuthN band after HMAC auth. When a co-located `compression`
//! plugin enables `decompress_request`, configured gzip/Brotli decoding runs
//! in the shared pre-`before_proxy` normalization phase so this plugin
//! validates the same size-bounded plaintext the backend receives.
//!
//! ## Configuration admission (strict, fail-closed)
//!
//! The root object and every nested fixed-shape object (`timestamp`,
//! `username_token`, each `credentials` entry, `x509_signature`, `saml`,
//! `nonce`) reject unknown keys and wrong-typed values — including explicit
//! JSON `null` — before any default applies. Omission selects the documented
//! default; `{"username_token":{"enabled":null}}`, `{"saml":{"audience":null}}`,
//! `{"nonce":null}`, and similar inputs are errors rather than weaker policy.
//! Silently defaulting a malformed value used to be able to disable
//! UsernameToken/SAML/X.509 policy, drop SAML audience binding, or reset a
//! freshness/replay window while startup, Admin validation, CP/DP propagation,
//! and reload all reported success — the `FailClosed` registration in
//! `src/plugins/mod.rs` never saw an error, so no last-known-good generation
//! was retained. There is no `nonce_replay_protection` alias: `nonce.*` is the
//! only canonical shape and the alias is rejected as an unknown key.
//!
//! Every duration and cache control has an enforced inclusive range. Upper
//! bounds sit far below `chrono::TimeDelta`'s representable range and parsed
//! WS-Security / SAML instants are clamped to a four-digit year, so no admitted
//! configuration and no hostile `Created` / `Expires` / `NotBefore` /
//! `NotOnOrAfter` value can overflow duration or `DateTime` arithmetic and panic
//! a request task. Durations are converted once at admission.
//!
//! ## Nonce replay cache bounds
//!
//! Replay state is bounded on three independent axes — per-nonce encoded
//! length, retained entries, and total retained key payload bytes — and a nonce
//! is only retained *after* its PasswordDigest verifies. The encoded-length
//! ceiling is checked before Base64 decoding. A `BTreeMap` age index makes
//! expiry and oldest eviction O(log n) per examined entry without scanning the
//! lookup map. Each index handle shares the lookup map's one immutable
//! nonce-string allocation. Maintenance examines at most
//! `NONCE_MAX_MAINTENANCE_ENTRIES` oldest entries per request; if that bounded
//! work cannot make room, the request fails closed rather than admitting a
//! nonce whose replay window cannot be recorded. Entry/byte admission,
//! eviction, and accounting share one narrow mutex held only for
//! security-state updates so concurrent PasswordDigest claims cannot overshoot
//! either hard cap (including same-key races); length checks and all
//! credential/XML/base64/crypto work stay outside that critical section.
//! Diagnostics use fixed-cardinality failure classes and never include the
//! nonce.
//!
//! ## Request body character encoding
//!
//! Matching SOAP media types are buffered as raw bytes
//! (`ctx.request_body_bytes`). Before XML/WS-Security validation the plugin
//! decodes UTF-8 and UTF-16 (LE/BE) deterministically from the BOM and/or
//! `Content-Type` charset, rejects charset/BOM/XML-declaration conflicts and
//! malformed sequences fail-closed, and leaves the original wire bytes
//! unchanged for the backend. BOM-less, charset-less payloads whose leading
//! bytes are unmistakably UTF-16 XML (`3c 00` / `00 3c`) are rejected rather
//! than interpreted as UTF-8. Unsupported XML charsets are rejected with
//! HTTP 415. Encoding diagnostics never log request bodies or credentials.
//!
//! ## XMLDSIG canonicalization (shared by X.509 and SAML signature paths)
//!
//! Both the WS-Security X.509 signature path and the SAML assertion signature
//! path apply Exclusive XML Canonicalization (`xml-exc-c14n#`) to
//! `<SignedInfo>` and to each referenced node before cryptographic verification.
//! `InclusiveNamespaces PrefixList` parameters are honored. Only the
//! enveloped-signature and exclusive-c14n Reference transforms are supported;
//! unknown algorithms and transform chains are rejected rather than falling
//! back to wire-byte hashing.
//!
//! ## XML Signature Wrapping (XSW) mitigation
//!
//! In addition to namespace-aware canonicalization, the X.509 path enforces
//! that every signed `#id` Reference resolves to a
//! UNIQUE decoded XML id-bearing attribute across the whole envelope (see
//! `count_dom_id_occurrences`), rejecting any envelope carrying a duplicate id —
//! the classic XSW vector where an attacker keeps the legitimately-signed
//! element and injects a second element with the same id that the backend
//! consumes. The duplicate scan includes WS-Security `wsu:Id` / prefixed `Id`,
//! bare `Id`, and common alternative spellings (`xml:id`, `ID`, `id`) so
//! backends with broader fragment-id rules fail closed instead of seeing a
//! forwarded alternate referent. A raw-attribute scan remains as a second,
//! independent guard. The SAML path retains its single-`<Assertion>`
//! guard plus the Reference-URI-equals-assertion-id check. These structural
//! checks remain defense-in-depth against a backend selecting a different
//! same-local-name element than the gateway's namespace-aware resolver.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Datelike, Utc};
use ring::digest;
use ring::signature as ring_sig;
use roxmltree::{Document, Node, NodeId, ParsingOptions};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, warn};
use x509_parser::prelude::*;

use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::util::unknown_keys::reject_unknown_keys;

use super::utils::auth_flow::constant_time_eq;
use super::{Plugin, PluginResult, RequestContext};

// ── Namespace URIs ──────────────────────────────────────────────────────────

const PASSWORD_DIGEST_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const PASSWORD_TEXT_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const XMLDSIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const XMLDSIG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const XMLDSIG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLDSIG_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const XMLDSIG_ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const XML_EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const WSU_NAMESPACE_URI: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/// Upper bound on the number of `<Reference>` elements processed in a single
/// `<SignedInfo>`. Each reference drives a full-envelope scan + digest before
/// the signature is checked, so this caps attacker-controlled CPU on the
/// unauthenticated request path. Real signatures reference a handful of
/// elements; 64 is far above any legitimate use.
const MAX_SIGNED_REFERENCES: usize = 64;

/// Bounds for attacker-controlled XML work before signature trust exists.
/// Legitimate SOAP and SAML signatures stay far below these ceilings.
const MAX_XML_NODES: u32 = 65_536;
const MAX_CANONICALIZATION_DEPTH: usize = 256;
const MAX_INCLUSIVE_NAMESPACE_PREFIXES: usize = 64;
const MAX_INCLUSIVE_PREFIX_LIST_BYTES: usize = 4_096;

// ── Configuration admission bounds ──────────────────────────────────────────

/// Inclusive bounds for every operator-supplied duration and cache control.
///
/// Upper bounds sit far below `chrono::TimeDelta`'s `i64::MAX / 1000` second
/// ceiling, so no admitted configuration can make duration construction or
/// `DateTime` arithmetic overflow on the request path. Lower bounds reject the
/// degenerate values that silently disable a defense (a zero freshness window
/// or a zero-entry replay cache).
const MIN_TIMESTAMP_MAX_AGE_SECONDS: u64 = 1;
const MAX_TIMESTAMP_MAX_AGE_SECONDS: u64 = 86_400;
/// Zero skew is allowed: it is strictly *stricter* than the default, unlike a
/// zero freshness window which would accept nothing or a zero cache which
/// would accept every replay.
const MIN_CLOCK_SKEW_SECONDS: u64 = 0;
const MAX_CLOCK_SKEW_SECONDS: u64 = 3_600;
const MIN_NONCE_CACHE_TTL_SECONDS: u64 = 1;
const MAX_NONCE_CACHE_TTL_SECONDS: u64 = 86_400;
const MIN_NONCE_MAX_CACHE_SIZE: u64 = 1;
const MAX_NONCE_MAX_CACHE_SIZE: u64 = 1_000_000;

/// WS-Security UsernameToken Profile nonces are short random values (16–32 raw
/// bytes is typical). The ceiling is enforced on the *encoded* value before
/// Base64 decoding, so an oversized nonce is never decoded or retained.
const DEFAULT_NONCE_MAX_ENCODED_LENGTH: u64 = 512;
const MIN_NONCE_MAX_ENCODED_LENGTH: u64 = 16;
const MAX_NONCE_MAX_ENCODED_LENGTH: u64 = 4_096;

/// Total retained nonce-key UTF-8 payload bytes, counted once per logical
/// nonce's shared immutable string allocation. The cache is bounded in bytes
/// as well as in entries so `max_cache_size` cannot be multiplied by the
/// per-nonce length to reach an arbitrary retained footprint.
const DEFAULT_NONCE_MAX_TOTAL_CACHE_BYTES: u64 = 8 * 1024 * 1024;
const MIN_NONCE_MAX_TOTAL_CACHE_BYTES: u64 = 4_096;
const MAX_NONCE_MAX_TOTAL_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

/// Hard ceiling on exact oldest-index entries examined by one request,
/// independent of `max_cache_size`. Expiry and forced eviction share this
/// budget. Each examined entry costs O(log n) tree/map work, and forced
/// eviction stages at most this many fixed-width age keys before committing.
const NONCE_MAX_MAINTENANCE_ENTRIES: usize = 64;

/// Representable-year window for parsed WS-Security / SAML instants.
///
/// `chrono`'s `%Y` accepts years far outside the four-digit range, and its
/// `DateTime` `Add`/`Sub` impls panic on overflow. Clamping attacker-supplied
/// instants at parse time keeps every later `instant ± skew` and instant
/// difference inside range without scattering checked arithmetic through the
/// validation paths. `xsd:dateTime` values outside this window have no
/// legitimate WS-Security use.
const MIN_PARSED_YEAR: i32 = 1970;
const MAX_PARSED_YEAR: i32 = 9999;

// ── Allowed configuration keys (exhaustive, per fixed-shape object) ─────────

const ROOT_CONFIG_KEYS: &[&str] = &[
    "reject_missing_security_header",
    "timestamp",
    "username_token",
    "x509_signature",
    "saml",
    "nonce",
];
const TIMESTAMP_CONFIG_KEYS: &[&str] = &[
    "require",
    "max_age_seconds",
    "require_expires",
    "clock_skew_seconds",
];
const USERNAME_TOKEN_CONFIG_KEYS: &[&str] = &["enabled", "password_type", "credentials"];
const CREDENTIAL_CONFIG_KEYS: &[&str] = &["username", "password"];
const X509_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "trusted_certs",
    "allowed_algorithms",
    "allowed_digest_algorithms",
    "require_signed_timestamp",
];
const SAML_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "trusted_issuers",
    "trusted_signing_certs",
    "allowed_signature_algorithms",
    "allowed_digest_algorithms",
    "audience",
    "clock_skew_seconds",
];
const NONCE_CONFIG_KEYS: &[&str] = &[
    "cache_ttl_seconds",
    "max_cache_size",
    "max_encoded_length",
    "max_total_cache_bytes",
];

/// UTF-16→UTF-8 size is bounded by construction for well-formed input: each
/// BMP code point uses 2 wire bytes and at most 3 UTF-8 bytes (≤ 3/2×), and
/// supplementary planes use a surrogate pair (4 wire bytes → 4 UTF-8 bytes).
/// UTF-8→UTF-8 is 1:1. A post-decode `len * 3/2` cap is therefore unreachable
/// and is omitted; odd-length / invalid-surrogate sequences fail closed during
/// incremental decoding instead.

// ── Config types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordType {
    PasswordText,
    PasswordDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureAlgorithm {
    RsaSha256,
    RsaSha1,
}

/// XMLDSIG digest algorithm used for `<Reference>` element hashing.
///
/// Tracked separately from `SignatureAlgorithm` so the config surface can
/// gate signature vs digest algorithms independently — overloading a single
/// "algorithms" knob to mean both signature method and reference digest is
/// confusing for operators and produces footguns (e.g. accepting SHA-1
/// digests just because rsa-sha1 is in the allow list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha256,
    Sha1,
}

// ── Strict cold-path configuration accessors ───────────────────────────────
//
// Every fixed-shape SOAP security object is checked for unknown keys and exact
// value types *before* defaults apply. A misspelled key or a wrong-typed value
// must fail admission — silently falling back to a default is how a
// string-valued `username_token.enabled` used to disable credential
// authentication while startup, Admin validation, CP/DP propagation, and reload
// all reported success. Omission selects the documented default; an explicit
// JSON `null` is rejected so it cannot silently apply the same weaker policy.

type ConfigObject = serde_json::Map<String, Value>;

/// Present value for `key`. Omission yields `None`. Explicit JSON `null` is an
/// error so it cannot silently apply the same default as a missing field.
fn present<'a>(
    object: Option<&'a ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<&'a Value>, String> {
    match object.and_then(|map| map.get(key)) {
        None => Ok(None),
        Some(Value::Null) => Err(null_error(path, key)),
        Some(value) => Ok(Some(value)),
    }
}

/// Uniform type-mismatch diagnostic for a fixed-shape configuration field.
fn type_error(path: &str, key: &str, expected: &str) -> String {
    format!("soap_ws_security: '{path}.{key}' must be {expected}")
}

fn null_error(path: &str, key: &str) -> String {
    format!("soap_ws_security: '{path}.{key}' must not be null; omit the field to use the default")
}

fn range_error(path: &str, key: &str, min: u64, max: u64) -> String {
    format!("soap_ws_security: '{path}.{key}' must be an integer {min}..={max}")
}

fn required_error(path: &str, key: &str) -> String {
    format!("soap_ws_security: '{path}.{key}' is required")
}

fn duplicate_error(path: &str) -> String {
    format!("soap_ws_security: '{path}.username' duplicates an earlier entry")
}

fn enum_error(path: &str, key: &str, allowed: &str) -> String {
    format!(
        "soap_ws_security: '{path}.{key}' contains an unsupported value; accepted values: {allowed}"
    )
}

fn allowed_values<T>(variants: &[(&str, T)]) -> String {
    let names: Vec<&str> = variants.iter().map(|(name, _)| *name).collect();
    names.join(", ")
}

/// Nested object at `key`, rejecting any non-object present value (including null).
fn soap_object<'a>(
    object: Option<&'a ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<&'a ConfigObject>, String> {
    match present(object, path, key)? {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err(type_error(path, key, "an object")),
    }
}

fn soap_bool(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    match present(object, path, key)? {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(type_error(path, key, "a boolean, not a string or number")),
    }
}

/// Unsigned integer within an inclusive range. Rejects non-integers, negatives,
/// fractional numbers, and out-of-range values so no admitted value can
/// overflow duration arithmetic or disable a bound.
fn soap_u64_bounded(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, String> {
    let value = match present(object, path, key)? {
        None => return Ok(default),
        Some(value) => value,
    };
    let Some(parsed) = value.as_u64() else {
        return Err(range_error(path, key, min, max));
    };
    if parsed < min || parsed > max {
        return Err(range_error(path, key, min, max));
    }
    Ok(parsed)
}

/// Non-empty string, rejecting any non-string present value.
fn soap_string(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<String>, String> {
    match present(object, path, key)? {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(type_error(path, key, "a non-empty string")),
        Some(_) => Err(type_error(path, key, "a string")),
    }
}

/// Array of non-empty strings. Malformed entries are rejected instead of
/// silently dropped, so a partially-bad cert / issuer list cannot narrow the
/// trust set while reporting success.
fn soap_string_array(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    let value = match present(object, path, key)? {
        None => return Ok(None),
        Some(value) => value,
    };
    let Some(array) = value.as_array() else {
        return Err(type_error(path, key, "an array of strings"));
    };
    let mut parsed = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        match entry.as_str() {
            Some(text) if !text.trim().is_empty() => parsed.push(text.to_string()),
            _ => {
                let indexed = format!("{key}[{index}]");
                return Err(type_error(path, &indexed, "a non-empty string"));
            }
        }
    }
    Ok(Some(parsed))
}

/// Enum-valued array with an explicit default. Unknown members are rejected —
/// dropping them used to be able to empty an allow-list or narrow it in ways
/// the operator never asked for.
fn soap_enum_array<T: Copy>(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
    variants: &[(&str, T)],
    default: &[T],
) -> Result<Vec<T>, String> {
    let Some(entries) = soap_string_array(object, path, key)? else {
        return Ok(default.to_vec());
    };
    if entries.is_empty() {
        let allowed = allowed_values(variants);
        let expected = format!("a non-empty subset of: {allowed}");
        return Err(type_error(path, key, &expected));
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in &entries {
        let matched = variants
            .iter()
            .find(|(name, _)| *name == entry.as_str())
            .map(|(_, variant)| *variant);
        let Some(matched) = matched else {
            let allowed = allowed_values(variants);
            return Err(enum_error(path, key, &allowed));
        };
        parsed.push(matched);
    }
    Ok(parsed)
}

/// Saturating `u64` → `usize`. Every ceiling in this module fits `u32`, so this
/// cannot narrow on any supported target; saturating keeps the conversion
/// panic-free without an `unwrap`.
fn usize_or_max(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

const SIGNATURE_ALGORITHM_VARIANTS: &[(&str, SignatureAlgorithm)] = &[
    ("rsa-sha256", SignatureAlgorithm::RsaSha256),
    ("rsa-sha1", SignatureAlgorithm::RsaSha1),
];
const DIGEST_ALGORITHM_VARIANTS: &[(&str, DigestAlgorithm)] = &[
    ("sha256", DigestAlgorithm::Sha256),
    ("sha1", DigestAlgorithm::Sha1),
];

/// Reject unknown keys on a fixed-shape object with the shared path-qualified
/// diagnostics (including spelling suggestions).
fn reject_unknown(
    object: Option<&ConfigObject>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let Some(map) = object else {
        return Ok(());
    };
    reject_unknown_keys(map, path, allowed, "soap_ws_security: ")
}

/// Configured duration, converted once at admission so the request path never
/// performs a fallible or panicking duration construction. The bounds above
/// already guarantee success; the fallible conversion stays so a future bound
/// change cannot reintroduce a panicking `Duration::seconds` on the hot path.
fn admitted_duration(path: &str, key: &str, seconds: u64) -> Result<chrono::Duration, String> {
    let signed = i64::try_from(seconds).ok();
    let duration = signed.and_then(chrono::Duration::try_seconds);
    let message = || type_error(path, key, "a representable duration");
    duration.ok_or_else(message)
}

fn sha256_array(value: &[u8]) -> [u8; 32] {
    let hashed = digest::digest(&digest::SHA256, value);
    let mut output = [0u8; 32];
    output.copy_from_slice(hashed.as_ref());
    output
}

#[derive(Debug, Clone)]
struct Credential {
    username: String,
    password: String,
    /// Fixed-width digest used by PasswordText verification so known and
    /// unknown principals take the same comparison path even when configured
    /// secret lengths differ from the process-local dummy material.
    password_text_hash: [u8; 32],
}

/// UsernameToken authentication outcomes that must not create a username oracle.
///
/// Structural token/policy failures remain distinguishable because they do not
/// depend on whether the supplied principal exists. Credential failures
/// (unknown user, wrong PasswordText, wrong PasswordDigest) share one public
/// body and one stable telemetry class.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UsernameTokenError {
    Structural(String),
    InvalidCredentials,
}

impl UsernameTokenError {
    /// Stable operational failure class for credential rejection (no username).
    const INVALID_CREDENTIALS_CLASS: &'static str = "username_token_invalid_credentials";
    /// Stable structural failure class for malformed / policy-mismatch tokens.
    const STRUCTURAL_CLASS: &'static str = "username_token_structural";
    /// Client-visible JSON body shared by every invalid-credential outcome.
    const INVALID_CREDENTIALS_BODY: &'static str =
        r#"{"error":"WS-Security: invalid credentials"}"#;
}

struct TrustedCert {
    /// DER-encoded public key bytes for signature verification.
    public_key_der: Vec<u8>,
    /// SHA-256 fingerprint of the full DER-encoded certificate (for matching).
    fingerprint: Vec<u8>,
}

// ── Nonce cache entry ───────────────────────────────────────────────────────

type NonceAgeKey = (Instant, u64);

struct NonceEntry {
    age_key: NonceAgeKey,
}

/// PasswordDigest replay security state.
///
/// `cache` provides expected O(1) same-nonce decisions. `age_index` provides
/// O(log n) expiration and exact-oldest selection without a full-cache scan.
/// Both containers hold `Arc` handles to the same immutable nonce allocation;
/// `retained_key_bytes` counts that allocation's UTF-8 payload exactly once
/// per logical entry (not map/tree node or `Arc` control-block overhead).
///
/// Entry count, age order, and retained key bytes are updated under one mutex
/// so concurrent admissions cannot overshoot either documented hard cap.
/// Checked arithmetic and structural cross-checks turn impossible drift into a
/// fail-closed outcome rather than hiding it with saturating repair.
struct NonceReplayState {
    cache: HashMap<Arc<str>, NonceEntry>,
    age_index: BTreeMap<NonceAgeKey, Arc<str>>,
    retained_key_bytes: usize,
    next_sequence: u64,
    last_expired_removals: usize,
    last_forced_candidates: usize,
}

impl NonceReplayState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            age_index: BTreeMap::new(),
            retained_key_bytes: 0,
            next_sequence: 0,
            last_expired_removals: 0,
            last_forced_candidates: 0,
        }
    }

    fn has_capacity(&self, incoming_bytes: usize, max_entries: usize, max_bytes: usize) -> bool {
        if self.cache.len() >= max_entries {
            return false;
        }
        self.retained_key_bytes
            .checked_add(incoming_bytes)
            .is_some_and(|total| total <= max_bytes)
    }

    fn structurally_consistent(&self) -> bool {
        self.cache.len() == self.age_index.len()
            && (!self.cache.is_empty() || self.retained_key_bytes == 0)
    }

    fn allocate_age_key(&mut self, now: Instant) -> Option<NonceAgeKey> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1)?;
        Some((now, sequence))
    }

    fn age_entry_matches(&self, age_key: &NonceAgeKey, nonce: &Arc<str>) -> bool {
        self.cache
            .get(nonce.as_ref())
            .is_some_and(|entry| entry.age_key == *age_key)
    }

    fn remove_age_entry(&mut self, age_key: &NonceAgeKey) -> Result<(), ()> {
        let Some(nonce) = self.age_index.get(age_key) else {
            return Err(());
        };
        if !self.age_entry_matches(age_key, nonce) {
            return Err(());
        }
        let Some(retained_key_bytes) = self.retained_key_bytes.checked_sub(nonce.len()) else {
            return Err(());
        };

        let nonce = match self.age_index.remove(age_key) {
            Some(nonce) => nonce,
            None => return Err(()),
        };
        if self.cache.remove(nonce.as_ref()).is_none() {
            return Err(());
        }
        self.retained_key_bytes = retained_key_bytes;
        Ok(())
    }
}

// The binary target compiles this module without the library's `_test_support`
// facade, so this external-test observation type is intentionally unused there.
#[allow(dead_code)]
pub(crate) struct NonceReplayObservationForTests {
    pub(crate) entry_count: usize,
    pub(crate) age_index_entry_count: usize,
    pub(crate) retained_key_bytes: usize,
    pub(crate) recomputed_key_bytes: usize,
    pub(crate) shared_key_entries: usize,
    pub(crate) last_expired_removals: usize,
    pub(crate) last_forced_candidates: usize,
    pub(crate) max_maintenance_entries: usize,
}

// ── Plugin struct ───────────────────────────────────────────────────────────

pub struct SoapWsSecurity {
    // Timestamp validation
    require_timestamp: bool,
    timestamp_max_age_seconds: u64,
    timestamp_require_expires: bool,
    /// Pre-converted at admission; the request path performs no fallible or
    /// panicking duration construction.
    timestamp_max_age: chrono::Duration,
    clock_skew: chrono::Duration,

    // UsernameToken
    username_token_enabled: bool,
    password_type: PasswordType,
    credentials: Vec<Credential>,
    /// Process-local padding secret used only to equalize verification work on
    /// username lookup misses. Never authenticates a principal.
    dummy_password: String,
    /// Fixed-width PasswordText verifier for `dummy_password`.
    dummy_password_text_hash: [u8; 32],

    // X.509 signature verification
    x509_enabled: bool,
    trusted_certs: Vec<TrustedCert>,
    allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    allowed_digest_algorithms: Vec<DigestAlgorithm>,
    require_signed_timestamp: bool,

    // SAML assertion validation
    saml_enabled: bool,
    saml_trusted_issuers: Vec<String>,
    saml_audience: Option<String>,
    saml_clock_skew: chrono::Duration,
    saml_trusted_signing_certs: Vec<TrustedCert>,
    saml_allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    saml_allowed_digest_algorithms: Vec<DigestAlgorithm>,

    // Nonce replay protection
    /// Admission, eviction, and retained-byte accounting for PasswordDigest
    /// replay state. See [`Self::check_nonce_replay`] for the critical-section
    /// scope: the mutex is held only while updating the lookup map, exact age
    /// index, and counter.
    nonce_replay: Mutex<NonceReplayState>,
    nonce_cache_ttl_seconds: u64,
    max_nonce_cache_size: usize,
    /// Encoded-nonce ceiling, enforced before Base64 decoding and before any
    /// cache insertion.
    max_nonce_encoded_length: usize,
    /// Logical UTF-8 key payload only. Hash/tree nodes and `Arc` control blocks
    /// are excluded and bounded independently by `max_nonce_cache_size`.
    max_nonce_cache_bytes: usize,

    // General
    reject_missing_security_header: bool,
}

impl SoapWsSecurity {
    pub fn new(config: &Value) -> Result<Self, String> {
        // Fixed/redacted diagnostic: never interpolate the configured value —
        // a non-object root can still carry credential-like material or be
        // unbounded in size.
        let config_obj = config
            .as_object()
            .ok_or_else(|| "soap_ws_security: config must be an object".to_string())?;

        // Strict admission: unknown root keys fail closed. This is what makes
        // the documented-but-never-read `nonce_replay_protection` object and
        // every misspelling an error instead of a silently weaker policy.
        let root = Some(config_obj);
        reject_unknown(root, "config", ROOT_CONFIG_KEYS)?;

        // ── Timestamp config ────────────────────────────────────────────
        let ts_cfg = soap_object(root, "config", "timestamp")?;
        reject_unknown(ts_cfg, "config.timestamp", TIMESTAMP_CONFIG_KEYS)?;
        let require_timestamp = soap_bool(ts_cfg, "config.timestamp", "require", true)?;
        let timestamp_max_age_seconds = soap_u64_bounded(
            ts_cfg,
            "config.timestamp",
            "max_age_seconds",
            300,
            MIN_TIMESTAMP_MAX_AGE_SECONDS,
            MAX_TIMESTAMP_MAX_AGE_SECONDS,
        )?;
        let timestamp_require_expires =
            soap_bool(ts_cfg, "config.timestamp", "require_expires", false)?;
        let clock_skew_seconds = soap_u64_bounded(
            ts_cfg,
            "config.timestamp",
            "clock_skew_seconds",
            300,
            MIN_CLOCK_SKEW_SECONDS,
            MAX_CLOCK_SKEW_SECONDS,
        )?;
        let timestamp_max_age = admitted_duration(
            "config.timestamp",
            "max_age_seconds",
            timestamp_max_age_seconds,
        )?;
        let clock_skew =
            admitted_duration("config.timestamp", "clock_skew_seconds", clock_skew_seconds)?;

        // ── UsernameToken config ────────────────────────────────────────
        let ut_cfg = soap_object(root, "config", "username_token")?;
        reject_unknown(ut_cfg, "config.username_token", USERNAME_TOKEN_CONFIG_KEYS)?;
        let username_token_enabled = soap_bool(ut_cfg, "config.username_token", "enabled", false)?;
        let configured_type = soap_string(ut_cfg, "config.username_token", "password_type")?;
        let password_type = match configured_type.as_deref().unwrap_or("PasswordDigest") {
            "PasswordText" => PasswordType::PasswordText,
            "PasswordDigest" => PasswordType::PasswordDigest,
            _ => {
                return Err(
                    "soap_ws_security: 'config.username_token.password_type' must be one of: PasswordText, PasswordDigest"
                        .to_string(),
                );
            }
        };

        // Credentials are validated entry by entry. A malformed entry is an
        // error rather than a dropped entry: silently shrinking the credential
        // set changes who can authenticate without any operator signal.
        let mut credentials: Vec<Credential> = Vec::new();
        if let Some(entries) = present(ut_cfg, "config.username_token", "credentials")? {
            let ut_path = "config.username_token";
            let Some(array) = entries.as_array() else {
                return Err(type_error(ut_path, "credentials", "an array"));
            };
            credentials.reserve(array.len());
            for (index, entry) in array.iter().enumerate() {
                let path = format!("{ut_path}.credentials[{index}]");
                let Some(entry_obj) = entry.as_object() else {
                    return Err(type_error(ut_path, "credentials", "an array of objects"));
                };
                let entry_ref = Some(entry_obj);
                reject_unknown(entry_ref, &path, CREDENTIAL_CONFIG_KEYS)?;
                let Some(username) = soap_string(entry_ref, &path, "username")? else {
                    return Err(required_error(&path, "username"));
                };
                let Some(password) = soap_string(entry_ref, &path, "password")? else {
                    return Err(required_error(&path, "password"));
                };
                // Duplicate usernames would make credential selection
                // first-wins, so a later rotation entry would be inert.
                if credentials.iter().any(|c| c.username == username) {
                    return Err(duplicate_error(&path));
                }
                let password_text_hash = sha256_array(password.as_bytes());
                credentials.push(Credential {
                    username,
                    password,
                    password_text_hash,
                });
            }
        }

        if username_token_enabled && credentials.is_empty() {
            return Err(
                "soap_ws_security: username_token is enabled but no credentials are configured"
                    .to_string(),
            );
        }

        // Random process-local material so lookup misses still execute the same
        // PasswordText / PasswordDigest verification work as known principals.
        // This value is never accepted as a configured credential.
        let dummy_password = format!("soap-ws-security-dummy:{}", uuid::Uuid::new_v4());
        let dummy_password_text_hash = sha256_array(dummy_password.as_bytes());

        // ── X.509 signature config ──────────────────────────────────────
        let x509_cfg = soap_object(root, "config", "x509_signature")?;
        reject_unknown(x509_cfg, "config.x509_signature", X509_CONFIG_KEYS)?;
        let x509_enabled = soap_bool(x509_cfg, "config.x509_signature", "enabled", false)?;

        let cert_paths = soap_string_array(x509_cfg, "config.x509_signature", "trusted_certs")?;
        let trusted_cert_paths: Vec<String> = cert_paths.unwrap_or_default();

        if x509_enabled && trusted_cert_paths.is_empty() {
            return Err(
                "soap_ws_security: x509_signature is enabled but no trusted_certs are configured"
                    .to_string(),
            );
        }

        let mut trusted_certs = Vec::with_capacity(trusted_cert_paths.len());
        for path in &trusted_cert_paths {
            let source = CertSource::parse(path, MaterialKind::Cert);
            let material = load_material_blocking(&source, MaterialKind::Cert)
                .map_err(|e| format!("soap_ws_security: failed to load trusted cert: {e}"))?;

            let pem_str = std::str::from_utf8(material.bytes.expose_secret()).map_err(|e| {
                format!(
                    "soap_ws_security: trusted cert '{}' is not valid UTF-8: {}",
                    material.display_source_id, e
                )
            })?;

            // Every failure past a *successful* fetch names the material by its
            // redacted `display_source_id`, never the configured `path`. A
            // `vault://`/`aws://`/`azure://`/`gcp://` source carries its
            // identifier in that path, and a PEM/X.509/RSA parse failure is
            // reachable by an operator who can see the error but not the
            // secret store — so interpolating `path` here would disclose the
            // provider reference on exactly the paths most likely to fire.
            // This matches `MaterializedMaterial::display_source_id`'s stated
            // contract, which names this module as one of its call sites.
            let der_bytes = extract_pem_der(pem_str).ok_or_else(|| {
                format!(
                    "soap_ws_security: failed to decode PEM from '{}'",
                    material.display_source_id
                )
            })?;

            let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
                format!(
                    "soap_ws_security: failed to parse X.509 cert '{}': {}",
                    material.display_source_id, e
                )
            })?;

            let public_key_der = load_rsa_public_key_from_cert(&cert).map_err(|e| {
                format!(
                    "soap_ws_security: trusted cert '{}' {}",
                    material.display_source_id, e
                )
            })?;

            let fingerprint = digest::digest(&digest::SHA256, &der_bytes)
                .as_ref()
                .to_vec();

            trusted_certs.push(TrustedCert {
                public_key_der,
                fingerprint,
            });
        }

        let allowed_signature_algorithms: Vec<SignatureAlgorithm> = soap_enum_array(
            x509_cfg,
            "config.x509_signature",
            "allowed_algorithms",
            SIGNATURE_ALGORITHM_VARIANTS,
            &[SignatureAlgorithm::RsaSha256],
        )?;

        if x509_enabled && allowed_signature_algorithms.is_empty() {
            return Err(
                "soap_ws_security: x509_signature.allowed_algorithms must contain at least one of \
                 'rsa-sha256' or 'rsa-sha1' when x509_signature is enabled"
                    .to_string(),
            );
        }

        let allowed_digest_algorithms: Vec<DigestAlgorithm> = soap_enum_array(
            x509_cfg,
            "config.x509_signature",
            "allowed_digest_algorithms",
            DIGEST_ALGORITHM_VARIANTS,
            &[DigestAlgorithm::Sha256],
        )?;

        if x509_enabled && allowed_digest_algorithms.is_empty() {
            return Err(
                "soap_ws_security: x509_signature.allowed_digest_algorithms must contain at least \
                 one of 'sha256' or 'sha1' when x509_signature is enabled"
                    .to_string(),
            );
        }

        let require_signed_timestamp = soap_bool(
            x509_cfg,
            "config.x509_signature",
            "require_signed_timestamp",
            true,
        )?;

        // ── SAML config ─────────────────────────────────────────────────
        let saml_cfg = soap_object(root, "config", "saml")?;
        reject_unknown(saml_cfg, "config.saml", SAML_CONFIG_KEYS)?;
        let saml_enabled = soap_bool(saml_cfg, "config.saml", "enabled", false)?;

        let issuers = soap_string_array(saml_cfg, "config.saml", "trusted_issuers")?;
        let saml_trusted_issuers: Vec<String> = issuers.unwrap_or_default();

        if saml_enabled && saml_trusted_issuers.is_empty() {
            return Err(
                "soap_ws_security: saml is enabled but no trusted_issuers are configured"
                    .to_string(),
            );
        }

        // A wrong-typed audience used to become `None`, silently removing
        // service binding while SAML stayed enabled.
        let saml_audience = soap_string(saml_cfg, "config.saml", "audience")?;
        let saml_clock_skew_seconds = soap_u64_bounded(
            saml_cfg,
            "config.saml",
            "clock_skew_seconds",
            300,
            MIN_CLOCK_SKEW_SECONDS,
            MAX_CLOCK_SKEW_SECONDS,
        )?;
        let saml_clock_skew =
            admitted_duration("config.saml", "clock_skew_seconds", saml_clock_skew_seconds)?;

        // SAML trusted signing certs — IdP X.509 certs used to verify the
        // assertion's `<Signature>`. Matched by SHA-256 fingerprint of the
        // full DER, so operators must trust each leaf cert directly (no CA
        // chain validation). This is the standard practice for SAML where
        // IdPs publish their signing certs in metadata.
        let signing_certs = soap_string_array(saml_cfg, "config.saml", "trusted_signing_certs")?;
        let saml_trusted_signing_cert_paths: Vec<String> = signing_certs.unwrap_or_default();

        if saml_enabled && saml_trusted_signing_cert_paths.is_empty() {
            return Err(
                "soap_ws_security: saml is enabled but no trusted_signing_certs are configured — \
                 without trusted IdP signing certs, assertion signatures cannot be verified and \
                 any caller could forge an assertion claiming to be issued by a trusted issuer"
                    .to_string(),
            );
        }

        let mut saml_trusted_signing_certs =
            Vec::with_capacity(saml_trusted_signing_cert_paths.len());
        for path in &saml_trusted_signing_cert_paths {
            let source = CertSource::parse(path, MaterialKind::Cert);
            let material = load_material_blocking(&source, MaterialKind::Cert).map_err(|e| {
                format!("soap_ws_security: failed to load SAML trusted signing cert: {e}")
            })?;

            let pem_str = std::str::from_utf8(material.bytes.expose_secret()).map_err(|e| {
                format!(
                    "soap_ws_security: SAML trusted signing cert '{}' is not valid UTF-8: {}",
                    material.display_source_id, e
                )
            })?;

            // Same rule as the WS-Security X.509 loop above: past a successful
            // fetch the material is named only by its redacted
            // `display_source_id`.
            let der_bytes = extract_pem_der(pem_str).ok_or_else(|| {
                format!(
                    "soap_ws_security: failed to decode PEM from SAML trusted signing cert '{}'",
                    material.display_source_id
                )
            })?;

            let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
                format!(
                    "soap_ws_security: failed to parse SAML trusted signing cert '{}': {}",
                    material.display_source_id, e
                )
            })?;

            let public_key_der = load_rsa_public_key_from_cert(&cert).map_err(|e| {
                format!(
                    "soap_ws_security: SAML trusted signing cert '{}' {}",
                    material.display_source_id, e
                )
            })?;
            let fingerprint = digest::digest(&digest::SHA256, &der_bytes)
                .as_ref()
                .to_vec();

            saml_trusted_signing_certs.push(TrustedCert {
                public_key_der,
                fingerprint,
            });
        }

        let saml_allowed_signature_algorithms: Vec<SignatureAlgorithm> = soap_enum_array(
            saml_cfg,
            "config.saml",
            "allowed_signature_algorithms",
            SIGNATURE_ALGORITHM_VARIANTS,
            &[SignatureAlgorithm::RsaSha256],
        )?;

        if saml_enabled && saml_allowed_signature_algorithms.is_empty() {
            return Err(
                "soap_ws_security: saml.allowed_signature_algorithms must contain at least one of \
                 'rsa-sha256' or 'rsa-sha1' when SAML is enabled"
                    .to_string(),
            );
        }

        let saml_allowed_digest_algorithms: Vec<DigestAlgorithm> = soap_enum_array(
            saml_cfg,
            "config.saml",
            "allowed_digest_algorithms",
            DIGEST_ALGORITHM_VARIANTS,
            &[DigestAlgorithm::Sha256],
        )?;

        if saml_enabled && saml_allowed_digest_algorithms.is_empty() {
            return Err(
                "soap_ws_security: saml.allowed_digest_algorithms must contain at least one of \
                 'sha256' or 'sha1' when SAML is enabled"
                    .to_string(),
            );
        }

        // ── Nonce / replay config ───────────────────────────────────────
        // Zero TTL or zero capacity used to be accepted and made replay
        // detection inert while the plugin still advertised it, so both now
        // have enforced lower bounds.
        let nonce_cfg = soap_object(root, "config", "nonce")?;
        reject_unknown(nonce_cfg, "config.nonce", NONCE_CONFIG_KEYS)?;
        let nonce_cache_ttl_seconds = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "cache_ttl_seconds",
            300,
            MIN_NONCE_CACHE_TTL_SECONDS,
            MAX_NONCE_CACHE_TTL_SECONDS,
        )?;
        let max_nonce_cache_size = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "max_cache_size",
            10_000,
            MIN_NONCE_MAX_CACHE_SIZE,
            MAX_NONCE_MAX_CACHE_SIZE,
        )?;
        let max_nonce_encoded_length = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "max_encoded_length",
            DEFAULT_NONCE_MAX_ENCODED_LENGTH,
            MIN_NONCE_MAX_ENCODED_LENGTH,
            MAX_NONCE_MAX_ENCODED_LENGTH,
        )?;
        let max_nonce_cache_bytes = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "max_total_cache_bytes",
            DEFAULT_NONCE_MAX_TOTAL_CACHE_BYTES,
            MIN_NONCE_MAX_TOTAL_CACHE_BYTES,
            MAX_NONCE_MAX_TOTAL_CACHE_BYTES,
        )?;
        // A byte cap below one maximum-length nonce would reject every
        // PasswordDigest request; refuse the contradiction at admission rather
        // than failing closed on live traffic.
        if max_nonce_cache_bytes < max_nonce_encoded_length {
            let expected = format!("at least max_encoded_length ({max_nonce_encoded_length})");
            let path = "config.nonce";
            return Err(type_error(path, "max_total_cache_bytes", &expected));
        }
        let max_nonce_cache_size = usize_or_max(max_nonce_cache_size);
        let max_nonce_encoded_length = usize_or_max(max_nonce_encoded_length);
        let max_nonce_cache_bytes = usize_or_max(max_nonce_cache_bytes);

        // ── General ─────────────────────────────────────────────────────
        let reject_missing_security_header =
            soap_bool(root, "config", "reject_missing_security_header", true)?;

        // Must have at least one security feature enabled
        if !username_token_enabled && !x509_enabled && !saml_enabled && !require_timestamp {
            return Err(
                "soap_ws_security: no security features enabled — enable at least one of: username_token, x509_signature, saml, or timestamp.require"
                    .to_string(),
            );
        }

        Ok(Self {
            require_timestamp,
            timestamp_max_age_seconds,
            timestamp_require_expires,
            timestamp_max_age,
            clock_skew,
            username_token_enabled,
            password_type,
            credentials,
            dummy_password,
            dummy_password_text_hash,
            x509_enabled,
            trusted_certs,
            allowed_signature_algorithms,
            allowed_digest_algorithms,
            require_signed_timestamp,
            saml_enabled,
            saml_trusted_issuers,
            saml_audience,
            saml_clock_skew,
            saml_trusted_signing_certs,
            saml_allowed_signature_algorithms,
            saml_allowed_digest_algorithms,
            nonce_replay: Mutex::new(NonceReplayState::new()),
            nonce_cache_ttl_seconds,
            max_nonce_cache_size,
            max_nonce_encoded_length,
            max_nonce_cache_bytes,
            reject_missing_security_header,
        })
    }

    // ── Timestamp validation ────────────────────────────────────────────

    fn validate_timestamp(&self, security_block: &str, now: DateTime<Utc>) -> Result<(), String> {
        let ts_block = match find_element_block(security_block, "Timestamp") {
            Some(b) => b,
            None => {
                return if self.require_timestamp {
                    Err("WS-Security: missing Timestamp element".to_string())
                } else {
                    Ok(())
                };
            }
        };

        let created_str = find_element_text(&ts_block, "Created")
            .ok_or_else(|| "WS-Security: Timestamp missing Created element".to_string())?;

        let created = parse_ws_datetime(&created_str)
            .ok_or_else(|| format!("WS-Security: invalid Created timestamp '{}'", created_str))?;

        // Durations are pre-converted at config admission and `parse_ws_datetime`
        // clamps parsed instants to `MIN_PARSED_YEAR..=MAX_PARSED_YEAR`, so
        // neither the duration construction nor the instant arithmetic below can
        // overflow and panic this request task.
        let skew = self.clock_skew;
        let max_age = self.timestamp_max_age;

        // Created must not be in the future (with clock skew tolerance)
        if created > now + skew {
            return Err("WS-Security: Timestamp Created is in the future".to_string());
        }

        // Created must not be too old
        if now - created > max_age + skew {
            return Err(format!(
                "WS-Security: Timestamp Created is too old (max age {}s)",
                self.timestamp_max_age_seconds
            ));
        }

        // Expires check
        if let Some(expires_str) = find_element_text(&ts_block, "Expires") {
            let expires = parse_ws_datetime(&expires_str).ok_or_else(|| {
                format!("WS-Security: invalid Expires timestamp '{}'", expires_str)
            })?;

            if now > expires + skew {
                return Err("WS-Security: Timestamp has expired".to_string());
            }
        } else if self.timestamp_require_expires {
            return Err("WS-Security: Timestamp missing required Expires element".to_string());
        }

        Ok(())
    }

    // ── UsernameToken validation ────────────────────────────────────────

    fn validate_username_token(&self, security_block: &str) -> Result<String, UsernameTokenError> {
        let ut_block = find_element_block(security_block, "UsernameToken").ok_or_else(|| {
            UsernameTokenError::Structural("WS-Security: missing UsernameToken element".to_string())
        })?;

        let username = find_element_text(&ut_block, "Username").ok_or_else(|| {
            UsernameTokenError::Structural(
                "WS-Security: UsernameToken missing Username element".to_string(),
            )
        })?;

        let password_element = find_element_block(&ut_block, "Password").ok_or_else(|| {
            UsernameTokenError::Structural(
                "WS-Security: UsernameToken missing Password element".to_string(),
            )
        })?;

        let password_value = extract_element_text_content(&password_element, "Password")
            .ok_or_else(|| {
                UsernameTokenError::Structural(
                    "WS-Security: Password element has no content".to_string(),
                )
            })?;

        // The verification mode is dictated solely by the operator-configured
        // `password_type`, NEVER by the client-supplied `Type` attribute.
        // Letting the wire value select the mode lets an attacker who knows the
        // plaintext credential downgrade a configured PasswordDigest policy
        // (Nonce / Created / replay protection) to plain PasswordText by sending
        // `Type="...#PasswordText"`. If a recognized `Type` attribute is present
        // it must agree with the configured policy; a mismatch is rejected.
        if let Some(type_attr) = find_attribute(&password_element, "Type") {
            let wire_type =
                if type_attr.contains("PasswordDigest") || type_attr == PASSWORD_DIGEST_TYPE {
                    Some(PasswordType::PasswordDigest)
                } else if type_attr.contains("PasswordText") || type_attr == PASSWORD_TEXT_TYPE {
                    Some(PasswordType::PasswordText)
                } else {
                    // Unrecognized Type value — fall through to the configured
                    // policy rather than guessing a verification mode.
                    None
                };
            if let Some(wire_type) = wire_type
                && wire_type != self.password_type
            {
                return Err(UsernameTokenError::Structural(
                    "WS-Security: Password Type does not match the configured password_type"
                        .to_string(),
                ));
            }
        }
        let effective_type = self.password_type;

        // Always run verification against either the matched credential or
        // process-local dummy material so lookup misses do not skip crypto work
        // and do not produce a distinct public failure.
        let cred = self.credentials.iter().find(|c| c.username == username);
        let password_material = cred
            .map(|c| c.password.as_str())
            .unwrap_or(self.dummy_password.as_str());
        let username_known = cred.is_some();

        match effective_type {
            PasswordType::PasswordText => {
                // Hash the attacker input once, then compare fixed-width
                // digests. `constant_time_eq` intentionally returns early on a
                // length mismatch, so comparing plaintext directly would make
                // the dummy path observably different whenever the configured
                // password and dummy material have different lengths.
                let supplied_hash = sha256_array(password_value.as_bytes());
                let expected_hash = cred
                    .map(|credential| &credential.password_text_hash)
                    .unwrap_or(&self.dummy_password_text_hash);
                let matched = constant_time_eq(&supplied_hash, expected_hash);
                // Dummy material is timing padding only and must never establish
                // identity for an unregistered username.
                if username_known && matched {
                    Ok(username)
                } else {
                    Err(UsernameTokenError::InvalidCredentials)
                }
            }
            PasswordType::PasswordDigest => {
                // Structural Nonce/Created requirements are enforced before the
                // known/unknown credential branch so missing digest inputs cannot
                // themselves become a username oracle.
                // PasswordDigest = Base64(SHA-1(nonce + created + password))
                let nonce_b64_raw = find_element_text(&ut_block, "Nonce").ok_or_else(|| {
                    UsernameTokenError::Structural(
                        "WS-Security: PasswordDigest requires Nonce element".to_string(),
                    )
                })?;

                // One canonical form for both the digest input and the replay
                // cache key (`find_element_text` already trims; being explicit
                // keeps the two derivations from drifting apart). The length
                // ceiling is enforced on the *encoded* value before Base64
                // decoding, so an oversized nonce never allocates a decode
                // buffer and is never retained.
                let nonce_b64 = nonce_b64_raw.trim();
                if nonce_b64.len() > self.max_nonce_encoded_length {
                    return Err(UsernameTokenError::Structural(
                        "WS-Security: Nonce exceeds the maximum permitted length".to_string(),
                    ));
                }

                let nonce_bytes = BASE64.decode(nonce_b64).map_err(|e| {
                    UsernameTokenError::Structural(format!(
                        "WS-Security: invalid Nonce base64 encoding: {}",
                        e
                    ))
                })?;

                let created = find_element_text(&ut_block, "Created").ok_or_else(|| {
                    UsernameTokenError::Structural(
                        "WS-Security: PasswordDigest requires Created element".to_string(),
                    )
                })?;

                // Compute expected digest: SHA-1(nonce + created + password)
                let mut data =
                    Vec::with_capacity(nonce_bytes.len() + created.len() + password_material.len());
                data.extend_from_slice(&nonce_bytes);
                data.extend_from_slice(created.as_bytes());
                data.extend_from_slice(password_material.as_bytes());

                let computed = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
                let expected_b64 = BASE64.encode(computed.as_ref());

                // Constant-time compare for consistency with the PasswordText
                // path (the digest is derived from the shared secret or dummy).
                let matched =
                    constant_time_eq(password_value.trim().as_bytes(), expected_b64.as_bytes());
                if username_known && matched {
                    // Only a successfully verified principal may consume a
                    // nonce. Recording attacker-controlled failed attempts
                    // would let an unknown-user or wrong-password request
                    // poison a victim's nonce before the legitimate request
                    // arrives. The atomic entry check also prevents two
                    // concurrent valid requests from both accepting it.
                    self.check_nonce_replay(nonce_b64)
                        .map_err(UsernameTokenError::Structural)?;
                    Ok(username)
                } else {
                    Err(UsernameTokenError::InvalidCredentials)
                }
            }
        }
    }

    // ── Nonce replay protection ─────────────────────────────────────────

    /// Stable, fixed-cardinality failure classes for replay-state outcomes.
    /// The attacker-supplied nonce is never interpolated into a log line or a
    /// client-visible body.
    const NONCE_TOO_LONG_CLASS: &'static str = "nonce_too_long";
    const NONCE_STATE_SATURATED_CLASS: &'static str = "nonce_state_saturated";

    fn nonce_state_saturated() -> String {
        warn!(
            failure_class = Self::NONCE_STATE_SATURATED_CLASS,
            "soap_ws_security: replay protection state is at capacity"
        );
        "WS-Security: replay protection state is at capacity".to_string()
    }

    fn nonce_state_saturated_after_unlock(
        state: std::sync::MutexGuard<'_, NonceReplayState>,
    ) -> String {
        drop(state);
        Self::nonce_state_saturated()
    }

    fn nonce_age_seconds(now: Instant, inserted_at: Instant) -> u64 {
        now.checked_duration_since(inserted_at)
            .map_or(0, |age| age.as_secs())
    }

    /// Check if a nonce has been seen before within the TTL window, inserting
    /// it when it is not a replay.
    ///
    /// The cache is bounded on three independent axes so a caller cannot turn
    /// replay state into a memory or CPU sink: per-nonce encoded length, total
    /// retained entries, and total retained key bytes. Lookup is expected O(1)
    /// and every age-index update is O(log n). At capacity, at most
    /// `NONCE_MAX_MAINTENANCE_ENTRIES` exact oldest entries are examined; there
    /// is no lookup-map scan and no stale FIFO that can grow beyond the entry
    /// cap. Forced candidates are committed only if the bounded batch makes
    /// room, so a rejected saturation probe does not discard live replay
    /// coverage.
    ///
    /// **Concurrency.** Encoded-length rejection and all XML/base64/credential/
    /// crypto work run outside the lock. Admission, exact-oldest maintenance,
    /// insert/refresh, and byte accounting share one mutex held only for those
    /// security-state updates, so concurrent fresh claims cannot all observe
    /// room and then overshoot either hard cap. Same-key races resolve under
    /// the lock: an in-TTL hit is a replay (no reservation); an expired hit
    /// refreshes the same shared key in place without changing count/bytes.
    /// Lock poison, checked-arithmetic failure, or map/index drift all fail
    /// closed with the fixed saturation class and never recover through the
    /// poisoned state.
    pub fn check_nonce_replay(&self, nonce: &str) -> Result<(), String> {
        self.check_nonce_replay_at(nonce, Instant::now())
    }

    fn check_nonce_replay_at(&self, nonce: &str, now: Instant) -> Result<(), String> {
        // Attacker-controlled length compare only — outside the admission lock.
        if nonce.len() > self.max_nonce_encoded_length {
            warn!(
                failure_class = Self::NONCE_TOO_LONG_CLASS,
                "soap_ws_security: Nonce exceeds the maximum permitted length"
            );
            return Err("WS-Security: Nonce exceeds the maximum permitted length".to_string());
        }

        let mut state = match self.nonce_replay.lock() {
            Ok(state) => state,
            Err(_) => return Err(Self::nonce_state_saturated()),
        };
        state.last_expired_removals = 0;
        state.last_forced_candidates = 0;

        if !state.structurally_consistent() {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }

        // Same-key path first: replay / in-place refresh must not consume a new
        // entry or byte reservation, and must not be rejected as saturated
        // merely because the cache is otherwise full.
        let existing_age_key = state.cache.get(nonce).map(|entry| entry.age_key);
        if let Some(age_key) = existing_age_key {
            let indexed_nonce_matches = state
                .age_index
                .get(&age_key)
                .is_some_and(|indexed_nonce| indexed_nonce.as_ref() == nonce);
            if !indexed_nonce_matches {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            }
            if Self::nonce_age_seconds(now, age_key.0) < self.nonce_cache_ttl_seconds {
                return Err("WS-Security: nonce replay detected".to_string());
            }

            let Some(new_age_key) = state.allocate_age_key(now) else {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            };
            let shared_nonce = match state.age_index.remove(&age_key) {
                Some(shared_nonce) => shared_nonce,
                None => return Err(Self::nonce_state_saturated_after_unlock(state)),
            };
            if state
                .age_index
                .insert(new_age_key, Arc::clone(&shared_nonce))
                .is_some()
            {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            }
            let Some(entry) = state.cache.get_mut(shared_nonce.as_ref()) else {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            };
            entry.age_key = new_age_key;
            return Ok(());
        }

        let incoming_bytes = nonce.len();
        if !state.has_capacity(
            incoming_bytes,
            self.max_nonce_cache_size,
            self.max_nonce_cache_bytes,
        ) {
            let made_room = match Self::make_nonce_room_locked(
                &mut state,
                incoming_bytes,
                self.max_nonce_cache_size,
                self.max_nonce_cache_bytes,
                self.nonce_cache_ttl_seconds,
                now,
            ) {
                Ok(made_room) => made_room,
                Err(()) => {
                    return Err(Self::nonce_state_saturated_after_unlock(state));
                }
            };
            if !made_room {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            }
        }

        let Some(retained_key_bytes) = state.retained_key_bytes.checked_add(incoming_bytes) else {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        };
        if retained_key_bytes > self.max_nonce_cache_bytes
            || state.cache.len() >= self.max_nonce_cache_size
        {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }
        let Some(age_key) = state.allocate_age_key(now) else {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        };

        let shared_nonce: Arc<str> = Arc::from(nonce);
        if state
            .age_index
            .insert(age_key, Arc::clone(&shared_nonce))
            .is_some()
        {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }
        if state
            .cache
            .insert(shared_nonce, NonceEntry { age_key })
            .is_some()
        {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }
        state.retained_key_bytes = retained_key_bytes;
        Ok(())
    }

    /// Reclaim enough exact-oldest state for one incoming nonce without ever
    /// walking the lookup map. Expiry removals commit immediately. Live forced
    /// candidates are staged as fixed-width age keys and commit only when the
    /// bounded batch can make room; otherwise the caller fails closed without
    /// discarding live replay entries.
    fn make_nonce_room_locked(
        state: &mut NonceReplayState,
        incoming_bytes: usize,
        max_entries: usize,
        max_bytes: usize,
        ttl_seconds: u64,
        now: Instant,
    ) -> Result<bool, ()> {
        while !state.has_capacity(incoming_bytes, max_entries, max_bytes)
            && state.last_expired_removals < NONCE_MAX_MAINTENANCE_ENTRIES
        {
            let Some((&age_key, nonce)) = state.age_index.first_key_value() else {
                return Err(());
            };
            if !state.age_entry_matches(&age_key, nonce) {
                return Err(());
            }
            if Self::nonce_age_seconds(now, age_key.0) < ttl_seconds {
                break;
            }
            state.remove_age_entry(&age_key)?;
            state.last_expired_removals += 1;
        }

        if state.has_capacity(incoming_bytes, max_entries, max_bytes) {
            return Ok(true);
        }

        let remaining_budget =
            NONCE_MAX_MAINTENANCE_ENTRIES.saturating_sub(state.last_expired_removals);
        if remaining_budget == 0 {
            return Ok(false);
        }

        let amortized_target = (max_entries / 10)
            .clamp(1, NONCE_MAX_MAINTENANCE_ENTRIES)
            .min(remaining_budget);
        let mut candidates = Vec::with_capacity(remaining_budget);
        let mut projected_entries = state.cache.len();
        let mut projected_bytes = state.retained_key_bytes;
        let mut candidates_make_room = false;
        let mut forced_candidates = 0usize;

        for (age_key, nonce) in state.age_index.iter().take(remaining_budget) {
            if !state.age_entry_matches(age_key, nonce) {
                return Err(());
            }
            projected_entries = projected_entries.checked_sub(1).ok_or(())?;
            projected_bytes = projected_bytes.checked_sub(nonce.len()).ok_or(())?;
            candidates.push(*age_key);
            forced_candidates += 1;

            let entry_room = projected_entries < max_entries;
            let byte_room = projected_bytes
                .checked_add(incoming_bytes)
                .is_some_and(|total| total <= max_bytes);
            if candidates.len() >= amortized_target && entry_room && byte_room {
                candidates_make_room = true;
                break;
            }
        }
        state.last_forced_candidates = forced_candidates;

        if !candidates_make_room {
            return Ok(false);
        }
        for age_key in candidates {
            state.remove_age_entry(&age_key)?;
        }
        Ok(state.has_capacity(incoming_bytes, max_entries, max_bytes))
    }

    // These seams are consumed through `lib::_test_support`; the binary target
    // compiles the shared plugin module without that facade.
    #[allow(dead_code)]
    pub(crate) fn check_nonce_replay_at_for_tests(
        &self,
        nonce: &str,
        now: Instant,
    ) -> Result<(), String> {
        self.check_nonce_replay_at(nonce, now)
    }

    #[allow(dead_code)]
    pub(crate) fn nonce_replay_observation_for_tests(
        &self,
    ) -> Result<NonceReplayObservationForTests, String> {
        let state = self
            .nonce_replay
            .lock()
            .map_err(|_| "soap_ws_security: nonce replay observation unavailable".to_string())?;
        let recomputed_key_bytes = state
            .cache
            .keys()
            .try_fold(0usize, |total, nonce| total.checked_add(nonce.len()));
        let Some(recomputed_key_bytes) = recomputed_key_bytes else {
            return Err(
                "soap_ws_security: nonce replay observation accounting overflow".to_string(),
            );
        };
        let shared_key_entries = state
            .age_index
            .iter()
            .filter(|item| {
                let (age_key, indexed_nonce) = *item;
                state
                    .cache
                    .get_key_value(indexed_nonce.as_ref())
                    .is_some_and(|(cache_nonce, entry)| {
                        entry.age_key == *age_key && Arc::ptr_eq(cache_nonce, indexed_nonce)
                    })
            })
            .count();

        Ok(NonceReplayObservationForTests {
            entry_count: state.cache.len(),
            age_index_entry_count: state.age_index.len(),
            retained_key_bytes: state.retained_key_bytes,
            recomputed_key_bytes,
            shared_key_entries,
            last_expired_removals: state.last_expired_removals,
            last_forced_candidates: state.last_forced_candidates,
            max_maintenance_entries: NONCE_MAX_MAINTENANCE_ENTRIES,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn corrupt_nonce_age_index_for_tests(&self) -> Result<(), String> {
        let mut state = self
            .nonce_replay
            .lock()
            .map_err(|_| "soap_ws_security: nonce replay test state unavailable".to_string())?;
        let age_key = state
            .age_index
            .first_key_value()
            .map(|(age_key, _)| *age_key)
            .ok_or_else(|| "soap_ws_security: nonce replay test state is empty".to_string())?;
        if state.age_index.remove(&age_key).is_none() {
            return Err("soap_ws_security: nonce replay test corruption failed".to_string());
        }
        Ok(())
    }

    // ── X.509 signature verification ────────────────────────────────────

    fn validate_x509_signature(&self, security_block: &str, envelope: &str) -> Result<(), String> {
        let document = parse_bounded_xml(envelope, "SOAP")?;
        let security_node = selected_security_node(&document, envelope, security_block)?;
        let sig_node = unique_child_element(security_node, "Signature", "WS-Security")?
            .ok_or_else(|| "WS-Security: missing Signature element".to_string())?;
        let signed_info_node = unique_child_element(sig_node, "SignedInfo", "WS-Security")?
            .ok_or_else(|| "WS-Security: Signature missing SignedInfo element".to_string())?;
        let sig_block = node_source(envelope, sig_node)?;

        // Determine signature algorithm
        let sig_method = unique_child_element(signed_info_node, "SignatureMethod", "WS-Security")?
            .ok_or_else(|| "WS-Security: SignedInfo missing SignatureMethod".to_string())?;
        let sig_algorithm_uri = sig_method.attribute("Algorithm").ok_or_else(|| {
            "WS-Security: SignatureMethod missing Algorithm attribute".to_string()
        })?;

        let sig_algorithm = match sig_algorithm_uri {
            XMLDSIG_RSA_SHA256 => SignatureAlgorithm::RsaSha256,
            XMLDSIG_RSA_SHA1 => SignatureAlgorithm::RsaSha1,
            other => {
                return Err(format!(
                    "WS-Security: unsupported signature algorithm '{}'",
                    other
                ));
            }
        };

        if !self.allowed_signature_algorithms.contains(&sig_algorithm) {
            return Err(format!(
                "WS-Security: signature algorithm '{}' is not allowed",
                sig_algorithm_uri
            ));
        }

        let canonicalization = parse_signed_info_canonicalization(signed_info_node, "WS-Security")?;

        // Verify Reference digests
        self.verify_reference_digests(signed_info_node, security_node, sig_node, envelope)?;

        // Check that Timestamp is signed (if required)
        if self.require_signed_timestamp {
            self.verify_timestamp_is_signed(signed_info_node, security_node)?;
        }

        // Extract SignatureValue
        let sig_value_node = unique_child_element(sig_node, "SignatureValue", "WS-Security")?
            .ok_or_else(|| "WS-Security: Signature missing SignatureValue".to_string())?;
        let sig_value_b64 = sig_value_node
            .text()
            .ok_or_else(|| "WS-Security: SignatureValue is empty".to_string())?;

        let sig_bytes = BASE64
            .decode(sig_value_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: invalid SignatureValue base64: {}", e))?;

        // Extract the certificate (BinarySecurityToken or inline KeyInfo)
        let cert_der = self.extract_signing_cert(security_block, sig_block)?;

        // Verify the cert is trusted
        let cert_fingerprint = digest::digest(&digest::SHA256, &cert_der).as_ref().to_vec();

        let trusted = self
            .trusted_certs
            .iter()
            .find(|tc| tc.fingerprint == cert_fingerprint);

        let public_key_der = match trusted {
            Some(tc) => &tc.public_key_der,
            None => {
                return Err("WS-Security: signing certificate is not trusted".to_string());
            }
        };

        // Verify the signature over the canonicalized SignedInfo node. Parsing
        // the full envelope preserves namespace declarations inherited from
        // Signature/Security/Envelope that are absent from the wire substring.
        let signed_info_bytes = exclusive_canonicalize(
            envelope,
            signed_info_node,
            &canonicalization.inclusive_prefixes,
            None,
        )?;

        let verify_algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_algorithm {
            SignatureAlgorithm::RsaSha256 => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaSha1 => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        let public_key = ring_sig::UnparsedPublicKey::new(verify_algorithm, public_key_der);

        public_key
            .verify(&signed_info_bytes, &sig_bytes)
            .map_err(|_| "WS-Security: signature verification failed".to_string())?;

        debug!("soap_ws_security: X.509 signature verified successfully");
        Ok(())
    }

    fn verify_reference_digests(
        &self,
        signed_info: Node<'_, '_>,
        security_node: Node<'_, '_>,
        signature_node: Node<'_, '_>,
        envelope: &str,
    ) -> Result<(), String> {
        let mut reference_count = 0;
        for reference in signed_info
            .children()
            .filter(|node| node.has_tag_name("Reference"))
        {
            reference_count += 1;
            // Bound attacker-controlled work: each Reference triggers a
            // full-envelope id-uniqueness scan plus an element resolution and a
            // digest over the referenced bytes, all before the signature is
            // verified. Capping the Reference count keeps an unauthenticated
            // request from forcing O(references × body) CPU. A legitimate
            // WS-Security signature covers a handful of elements (Timestamp,
            // Body, a few headers); 64 is far above any real use.
            if reference_count > MAX_SIGNED_REFERENCES {
                return Err(format!(
                    "WS-Security: too many Signature References (> {})",
                    MAX_SIGNED_REFERENCES
                ));
            }
            let uri = reference
                .attribute("URI")
                .ok_or_else(|| "WS-Security: Reference missing URI attribute".to_string())?;
            // Determine the digest algorithm
            let digest_method = unique_child_element(reference, "DigestMethod", "WS-Security")?
                .ok_or_else(|| "WS-Security: Reference missing DigestMethod".to_string())?;
            let digest_alg_uri = digest_method
                .attribute("Algorithm")
                .ok_or_else(|| "WS-Security: DigestMethod missing Algorithm".to_string())?;

            // Extract expected digest
            let digest_value = unique_child_element(reference, "DigestValue", "WS-Security")?
                .ok_or_else(|| "WS-Security: Reference missing DigestValue".to_string())?;
            let expected_b64 = digest_value
                .text()
                .ok_or_else(|| "WS-Security: DigestValue is empty".to_string())?;

            let expected_bytes = BASE64
                .decode(expected_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid DigestValue base64: {}", e))?;

            // Find the referenced element
            let referenced_node = if let Some(ref_id) = uri.strip_prefix('#') {
                if ref_id.is_empty() {
                    return Err("WS-Security: empty fragment Reference URI is unsupported".into());
                }
                // XML Signature Wrapping defense: a signed reference must
                // resolve to exactly ONE element in the whole envelope.
                // WS-Security / XMLDSIG ids are document-unique, so a duplicate
                // wsu:Id means an attacker wrapped the signed element — the bytes
                // we digest (the first match) could then differ from the element a
                // backend consumes. The count spans the FULL envelope, not just
                // the regions the resolver searches, so a duplicate injected
                // anywhere is caught. Mirrors the SAML single-Assertion guard.
                let occurrences = count_wsu_id_occurrences(envelope, ref_id)?;
                if occurrences > 1 {
                    return Err(format!(
                        "WS-Security: referenced id '{}' is not unique in the envelope \
                         ({} occurrences) — possible XML signature wrapping",
                        ref_id, occurrences
                    ));
                }
                let decoded_occurrences =
                    count_dom_id_occurrences(security_node.document(), ref_id);
                if decoded_occurrences != 1 {
                    return Err(format!(
                        "WS-Security: decoded referenced id '{}' is not unique in the envelope \
                         ({} occurrences) — possible XML signature wrapping",
                        ref_id, decoded_occurrences
                    ));
                }
                find_descendant_by_wsu_id(security_node, ref_id)
                    .or_else(|| {
                        envelope_body_node(security_node.document())
                            .and_then(|body| find_descendant_by_wsu_id(body, ref_id))
                    })
                    .ok_or_else(|| {
                        format!("WS-Security: referenced element '{}' not found", ref_id)
                    })?
            } else {
                return Err(format!("WS-Security: unsupported Reference URI '{}'", uri));
            };

            let transforms = parse_reference_transforms(reference, "WS-Security")?;
            let excluded_signature = transforms
                .enveloped_signature
                .then_some(signature_node.id());
            let referenced_content = exclusive_canonicalize(
                envelope,
                referenced_node,
                &transforms.inclusive_prefixes,
                excluded_signature,
            )?;

            // Compute and compare digest. The allowed_digest_algorithms list
            // is checked independently of the signature algorithm list — an
            // operator who wants rsa-sha256 signatures over sha1 digests
            // (rare but valid per XMLDSIG) configures both knobs explicitly,
            // and the default (sha256 only) refuses sha1 digests regardless
            // of which signature algorithm is in use.
            let computed = match digest_alg_uri {
                XMLDSIG_SHA256 => {
                    if !self
                        .allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha256)
                    {
                        return Err(format!(
                            "WS-Security: digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA256, &referenced_content)
                }
                XMLDSIG_SHA1 => {
                    if !self
                        .allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha1)
                    {
                        return Err(format!(
                            "WS-Security: digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &referenced_content)
                }
                other => {
                    return Err(format!(
                        "WS-Security: unsupported digest algorithm '{}'",
                        other
                    ));
                }
            };

            if computed.as_ref() != expected_bytes.as_slice() {
                return Err(format!(
                    "WS-Security: digest mismatch for Reference URI '{}'",
                    uri
                ));
            }
        }

        // XMLDSig requires SignedInfo to contain at least one Reference.
        // A signature with zero references would otherwise be considered
        // valid here even though it signs nothing meaningful — making it
        // trivial to bypass `require_signed_timestamp`.
        if reference_count == 0 {
            return Err("WS-Security: SignedInfo contains no Reference elements".to_string());
        }

        Ok(())
    }

    fn verify_timestamp_is_signed(
        &self,
        signed_info: Node<'_, '_>,
        security_node: Node<'_, '_>,
    ) -> Result<(), String> {
        let timestamp = match descendant_element(security_node, "Timestamp") {
            Some(timestamp) => timestamp,
            None => return Ok(()), // No timestamp to sign — timestamp validation handles this
        };
        let ts_id = timestamp
            .attributes()
            .find(|attribute| {
                attribute.name() == "Id"
                    && (attribute.namespace().is_none()
                        || attribute.namespace() == Some(WSU_NAMESPACE_URI))
            })
            .map(|attribute| attribute.value())
            .ok_or_else(|| {
                "WS-Security: Timestamp has no wsu:Id — cannot verify it is signed".to_string()
            })?;

        // DOM attribute values are entity-decoded, matching Reference
        // resolution and canonicalization semantics.
        let expected = format!("#{}", ts_id);
        for reference in signed_info
            .children()
            .filter(|node| node.has_tag_name("Reference"))
        {
            if reference.attribute("URI") == Some(expected.as_str()) {
                return Ok(());
            }
        }

        Err("WS-Security: Timestamp is not included in the signature".to_string())
    }

    fn extract_signing_cert(
        &self,
        security_block: &str,
        sig_block: &str,
    ) -> Result<Vec<u8>, String> {
        // Try BinarySecurityToken first
        if let Some(bst) = find_element_block(security_block, "BinarySecurityToken") {
            let cert_b64 = extract_element_text_content(&bst, "BinarySecurityToken")
                .ok_or_else(|| "WS-Security: BinarySecurityToken has no content".to_string())?;

            return BASE64
                .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid BinarySecurityToken base64: {}", e));
        }

        // Try inline X509Certificate in KeyInfo
        if let Some(key_info) = find_element_block(sig_block, "KeyInfo")
            && let Some(cert_b64) = find_element_text(&key_info, "X509Certificate")
        {
            return BASE64
                .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid X509Certificate base64: {}", e));
        }

        Err("WS-Security: no signing certificate found (expected BinarySecurityToken or X509Certificate in KeyInfo)".to_string())
    }

    // ── SAML assertion validation ───────────────────────────────────────

    /// Validate the SAML assertion inside a WS-Security header.
    ///
    /// Returns the assertion's Subject NameID on success (the "who" of the
    /// assertion) so callers can stash it in request metadata.
    ///
    /// Verification order is signature-first: an attacker who can post a SOAP
    /// body controls every text node in the assertion, so issuer / conditions
    /// / audience checks only mean something AFTER the assertion's XMLDSIG
    /// signature has been verified against a configured trusted IdP cert.
    fn validate_saml_assertion(
        &self,
        security_block: &str,
        envelope: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<String>, String> {
        let document = parse_bounded_xml(envelope, "SAML SOAP")?;
        let security_node = selected_security_node(&document, envelope, security_block)?;
        let assertion_node = match descendant_element(security_node, "Assertion") {
            Some(assertion) => assertion,
            None => {
                return if self.saml_enabled {
                    Err("WS-Security: missing SAML Assertion element".to_string())
                } else {
                    Ok(None)
                };
            }
        };

        // Defense in depth: only ever validate a single assertion. If an
        // attacker can wedge a second Assertion anywhere in the SOAP envelope,
        // downstream consumers that walk all assertions could see an
        // identity we never verified. Cheap insurance — reject and let the
        // operator deal with malformed/multi-assertion messages explicitly.
        if document
            .descendants()
            .filter(|node| node.has_tag_name("Assertion"))
            .count()
            > 1
        {
            return Err(
                "WS-Security: multiple SAML Assertion elements are not allowed".to_string(),
            );
        }

        // ── 1. Signature verification ─────────────────────────────────
        // Must run before any other check — every other field is
        // attacker-controlled until we know the IdP signed this assertion.
        self.validate_saml_signature(assertion_node, envelope)?;

        // ── 2. Issuer trust ───────────────────────────────────────────
        let issuer_node = unique_child_element(assertion_node, "Issuer", "WS-Security: SAML")?
            .ok_or_else(|| "WS-Security: SAML Assertion missing Issuer element".to_string())?;
        let issuer = decoded_element_text(issuer_node)
            .ok_or_else(|| "WS-Security: SAML Issuer is empty".to_string())?;

        if !self.saml_trusted_issuers.iter().any(|ti| ti == &issuer) {
            return Err(format!(
                "WS-Security: SAML Issuer '{}' is not trusted",
                escape_xml_chars(&issuer)
            ));
        }

        // ── 3. Conditions: NotBefore / NotOnOrAfter / Audience ────────
        if let Some(conditions) =
            unique_child_element(assertion_node, "Conditions", "WS-Security: SAML")?
        {
            // Pre-converted at admission; parsed condition instants are
            // year-clamped, so no arithmetic below can overflow.
            let skew = self.saml_clock_skew;

            if let Some(not_before_str) = conditions.attribute("NotBefore") {
                let not_before = parse_ws_datetime(not_before_str).ok_or_else(|| {
                    format!("WS-Security: invalid SAML NotBefore '{}'", not_before_str)
                })?;
                if now + skew < not_before {
                    return Err("WS-Security: SAML Assertion is not yet valid".to_string());
                }
            }

            if let Some(not_on_or_after_str) = conditions.attribute("NotOnOrAfter") {
                let not_on_or_after = parse_ws_datetime(not_on_or_after_str).ok_or_else(|| {
                    format!(
                        "WS-Security: invalid SAML NotOnOrAfter '{}'",
                        not_on_or_after_str
                    )
                })?;
                if now > not_on_or_after + skew {
                    return Err("WS-Security: SAML Assertion has expired".to_string());
                }
            }

            if let Some(ref expected_audience) = self.saml_audience {
                let Some(audience_restriction) =
                    descendant_element(conditions, "AudienceRestriction")
                else {
                    return Err(
                        "WS-Security: SAML AudienceRestriction is required when audience is configured"
                            .to_string(),
                    );
                };

                let audience_node =
                    unique_child_element(audience_restriction, "Audience", "WS-Security: SAML")?
                        .ok_or_else(|| {
                            "WS-Security: AudienceRestriction missing Audience element".to_string()
                        })?;
                let audience = decoded_element_text(audience_node)
                    .ok_or_else(|| "WS-Security: SAML Audience is empty".to_string())?;

                if &audience != expected_audience {
                    return Err(format!(
                        "WS-Security: SAML Audience '{}' does not match expected '{}'",
                        escape_xml_chars(&audience),
                        expected_audience
                    ));
                }
            }
        } else if self.saml_audience.is_some() {
            return Err(
                "WS-Security: SAML Conditions are required when audience is configured".to_string(),
            );
        }

        // ── 4. Extract Subject NameID for downstream identity use ─────
        let name_id = unique_child_element(assertion_node, "Subject", "WS-Security: SAML")?
            .and_then(|subject| descendant_element(subject, "NameID"))
            .and_then(decoded_element_text);

        debug!("soap_ws_security: SAML assertion validated successfully");
        Ok(name_id)
    }

    /// Verify the SAML assertion's XMLDSIG signature.
    ///
    /// Steps:
    /// 1. Locate `<Signature>` inside the assertion.
    /// 2. Resolve the signing algorithm and confirm it is in the allow list.
    /// 3. Verify each `<Reference>` digest after applying its declared
    ///    enveloped-signature / exclusive-c14n transform chain.
    /// 4. Extract the signing cert from `KeyInfo/X509Data/X509Certificate`
    ///    (or `BinarySecurityToken`) and confirm its SHA-256 fingerprint
    ///    matches a configured trusted IdP cert.
    /// 5. Verify `<SignatureValue>` over exclusive-canonicalized
    ///    `<SignedInfo>` using the matched cert's public key.
    fn validate_saml_signature(
        &self,
        assertion_node: Node<'_, '_>,
        envelope: &str,
    ) -> Result<(), String> {
        let sig_node = unique_child_element(assertion_node, "Signature", "WS-Security: SAML")?
            .ok_or_else(|| "WS-Security: SAML Assertion missing Signature element".to_string())?;
        let signed_info_node = unique_child_element(sig_node, "SignedInfo", "WS-Security: SAML")?
            .ok_or_else(|| {
            "WS-Security: SAML Signature missing SignedInfo element".to_string()
        })?;
        let sig_block = node_source(envelope, sig_node)?;

        // ── Resolve signature algorithm ───────────────────────────────
        let sig_method =
            unique_child_element(signed_info_node, "SignatureMethod", "WS-Security: SAML")?
                .ok_or_else(|| {
                    "WS-Security: SAML SignedInfo missing SignatureMethod".to_string()
                })?;
        let sig_algorithm_uri = sig_method.attribute("Algorithm").ok_or_else(|| {
            "WS-Security: SAML SignatureMethod missing Algorithm attribute".to_string()
        })?;

        let sig_algorithm = match sig_algorithm_uri {
            XMLDSIG_RSA_SHA256 => SignatureAlgorithm::RsaSha256,
            XMLDSIG_RSA_SHA1 => SignatureAlgorithm::RsaSha1,
            other => {
                return Err(format!(
                    "WS-Security: SAML unsupported signature algorithm '{}'",
                    other
                ));
            }
        };

        if !self
            .saml_allowed_signature_algorithms
            .contains(&sig_algorithm)
        {
            return Err(format!(
                "WS-Security: SAML signature algorithm '{}' is not allowed",
                sig_algorithm_uri
            ));
        }

        let canonicalization =
            parse_signed_info_canonicalization(signed_info_node, "WS-Security: SAML")?;

        // ── Verify Reference digest(s) ────────────────────────────────
        self.verify_saml_reference_digests(signed_info_node, assertion_node, sig_node, envelope)?;

        // ── Extract SignatureValue ────────────────────────────────────
        let sig_value_node = unique_child_element(sig_node, "SignatureValue", "WS-Security: SAML")?
            .ok_or_else(|| "WS-Security: SAML Signature missing SignatureValue".to_string())?;
        let sig_value_b64 = sig_value_node
            .text()
            .ok_or_else(|| "WS-Security: SAML SignatureValue is empty".to_string())?;
        let sig_bytes = BASE64
            .decode(sig_value_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid SignatureValue base64: {}", e))?;

        // ── Resolve signing cert and confirm it is trusted ────────────
        let cert_der = extract_saml_signing_cert(sig_block)?;
        let cert_fingerprint = digest::digest(&digest::SHA256, &cert_der).as_ref().to_vec();

        let trusted = self
            .saml_trusted_signing_certs
            .iter()
            .find(|tc| tc.fingerprint == cert_fingerprint);

        let public_key_der = match trusted {
            Some(tc) => &tc.public_key_der,
            None => {
                return Err("WS-Security: SAML signing certificate is not trusted".to_string());
            }
        };

        // ── Verify the signature over canonicalized SignedInfo ────────
        let verify_algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_algorithm {
            SignatureAlgorithm::RsaSha256 => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaSha1 => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        let public_key = ring_sig::UnparsedPublicKey::new(verify_algorithm, public_key_der);

        let canonical_signed_info = exclusive_canonicalize(
            envelope,
            signed_info_node,
            &canonicalization.inclusive_prefixes,
            None,
        )?;

        public_key
            .verify(&canonical_signed_info, &sig_bytes)
            .map_err(|_| "WS-Security: SAML signature verification failed".to_string())?;

        debug!("soap_ws_security: SAML assertion signature verified");
        Ok(())
    }

    /// Verify Reference digests inside the SAML SignedInfo.
    ///
    /// At least one Reference must be present, and at least one Reference
    /// must target the enclosing assertion via `URI="#<assertion-ID>"`. The
    /// declared transform chain is applied for the assertion-targeted
    /// Reference. Other References (e.g. SAML 2.0 SubjectConfirmationData)
    /// are NOT supported here — they would require resolving arbitrary IDs
    /// inside the assertion and applying additional transforms, which is
    /// outside the scope of the current pragmatic implementation.
    fn verify_saml_reference_digests(
        &self,
        signed_info: Node<'_, '_>,
        assertion: Node<'_, '_>,
        signature: Node<'_, '_>,
        envelope: &str,
    ) -> Result<(), String> {
        let assertion_id = assertion
            .attribute("ID")
            .or_else(|| assertion.attribute("AssertionID"))
            .ok_or_else(|| "WS-Security: SAML Assertion missing ID attribute".to_string())?;
        let expected_uri = format!("#{}", assertion_id);
        let mut reference_count = 0;
        let mut covered_assertion = false;

        for reference in signed_info
            .children()
            .filter(|node| node.has_tag_name("Reference"))
        {
            reference_count += 1;
            if reference_count > MAX_SIGNED_REFERENCES {
                return Err(format!(
                    "WS-Security: too many SAML Signature References (> {})",
                    MAX_SIGNED_REFERENCES
                ));
            }
            let uri = reference
                .attribute("URI")
                .ok_or_else(|| "WS-Security: SAML Reference missing URI attribute".to_string())?;

            // Only Reference URIs that target this assertion are accepted —
            // an attacker who can choose the Reference URI would otherwise
            // pick a stable subtree they can control.
            if uri != expected_uri {
                return Err(format!(
                    "WS-Security: SAML Reference URI '{}' does not target Assertion ID '{}'",
                    uri, expected_uri
                ));
            }

            let digest_method =
                unique_child_element(reference, "DigestMethod", "WS-Security: SAML")?.ok_or_else(
                    || "WS-Security: SAML Reference missing DigestMethod".to_string(),
                )?;
            let digest_alg_uri = digest_method.attribute("Algorithm").ok_or_else(|| {
                "WS-Security: SAML DigestMethod missing Algorithm attribute".to_string()
            })?;

            let digest_value = unique_child_element(reference, "DigestValue", "WS-Security: SAML")?
                .ok_or_else(|| "WS-Security: SAML Reference missing DigestValue".to_string())?;
            let expected_b64 = digest_value
                .text()
                .ok_or_else(|| "WS-Security: SAML DigestValue is empty".to_string())?;
            let expected_bytes = BASE64
                .decode(expected_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: SAML invalid DigestValue base64: {}", e))?;

            let transforms = parse_reference_transforms(reference, "WS-Security: SAML")?;
            let excluded_signature = transforms.enveloped_signature.then_some(signature.id());
            let canonical_assertion = exclusive_canonicalize(
                envelope,
                assertion,
                &transforms.inclusive_prefixes,
                excluded_signature,
            )?;

            let computed = match digest_alg_uri {
                XMLDSIG_SHA256 => {
                    if !self
                        .saml_allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha256)
                    {
                        return Err(format!(
                            "WS-Security: SAML digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA256, &canonical_assertion)
                }
                XMLDSIG_SHA1 => {
                    if !self
                        .saml_allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha1)
                    {
                        return Err(format!(
                            "WS-Security: SAML digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &canonical_assertion)
                }
                other => {
                    return Err(format!(
                        "WS-Security: SAML unsupported digest algorithm '{}'",
                        other
                    ));
                }
            };

            if computed.as_ref() != expected_bytes.as_slice() {
                return Err("WS-Security: SAML assertion digest mismatch".to_string());
            }

            covered_assertion = true;
        }

        if reference_count == 0 {
            return Err("WS-Security: SAML SignedInfo contains no Reference elements".to_string());
        }

        // Defensive: if all References had matching URIs they already produced
        // `covered_assertion = true`. This is a future-proofing check in case
        // the URI-matching invariant above is ever relaxed.
        if !covered_assertion {
            return Err(
                "WS-Security: SAML signature does not cover the enclosing assertion".to_string(),
            );
        }

        Ok(())
    }

    // ── Content-type check ──────────────────────────────────────────────

    fn is_soap_content_type(content_type: &str) -> bool {
        contains_ascii_case_insensitive(content_type, "text/xml")
            || contains_ascii_case_insensitive(content_type, "application/soap+xml")
            || contains_ascii_case_insensitive(content_type, "application/xml")
    }
}

// ── Plugin trait implementation ─────────────────────────────────────────────

#[async_trait]
impl Plugin for SoapWsSecurity {
    fn name(&self) -> &str {
        "soap_ws_security"
    }

    fn priority(&self) -> u16 {
        super::priority::SOAP_WS_SECURITY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn needs_request_body_bytes(&self) -> bool {
        // SOAP may arrive as UTF-16 (or other non-UTF-8 XML encodings). The
        // shared proxy handoff only populates metadata["request_body"] when
        // std::str::from_utf8 succeeds, so this plugin must retain raw bytes.
        true
    }

    fn needs_request_body_text(&self) -> bool {
        // Decode from request_body_bytes with strict BOM/charset rules instead
        // of relying on the UTF-8-only metadata copy.
        false
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.headers
            .get("content-type")
            .is_some_and(|ct| Self::is_soap_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only process SOAP content types
        // Read from `headers` param (not `ctx.headers`) because the handler may
        // temporarily move headers out of ctx when no plugin modifies them.
        let content_type = match headers.get("content-type") {
            Some(ct) if Self::is_soap_content_type(ct) => ct.clone(),
            _ => return PluginResult::Continue,
        };

        // Prefer bounded raw bytes (H1/H2/H3 handoff). Fall back to the UTF-8
        // metadata key only for fixtures that pre-seed text without bytes.
        let body = match resolve_soap_request_body(ctx, &content_type) {
            Ok(Some(body)) => body,
            Ok(None) => {
                if self.reject_missing_security_header {
                    return PluginResult::Reject {
                        status_code: 400,
                        body: r#"{"error":"SOAP request body is empty"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                return PluginResult::Continue;
            }
            Err(err) => {
                // Fail closed on hostile/unsupported encodings. Never log the
                // body, attacker-controlled Content-Type parameters, or
                // credential material — only the stable error class.
                warn!(
                    error_class = err.class(),
                    "soap_ws_security: SOAP body encoding rejected"
                );
                return PluginResult::Reject {
                    status_code: err.status_code(),
                    body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(err.message())),
                    headers: HashMap::new(),
                };
            }
        };

        // Find the SOAP envelope
        let envelope = body.trim();
        if contains_forbidden_xml_declaration(envelope) {
            return PluginResult::Reject {
                status_code: 400,
                body: r#"{"error":"SOAP request contains forbidden XML declaration"}"#.to_string(),
                headers: HashMap::new(),
            };
        }
        if !envelope.contains("Envelope") {
            if self.reject_missing_security_header {
                return PluginResult::Reject {
                    status_code: 400,
                    body: r#"{"error":"Request is not a SOAP envelope"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
            return PluginResult::Continue;
        }

        // Extract the SOAP Header and Body
        let soap_header = find_element_block(envelope, "Header");

        // Find the WS-Security header
        let security_block = soap_header
            .as_deref()
            .and_then(|h| find_element_block(h, "Security"));

        let security_block = match security_block {
            Some(s) => s,
            None => {
                if self.reject_missing_security_header {
                    return PluginResult::Reject {
                        status_code: 401,
                        body: r#"{"error":"WS-Security header is missing"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                return PluginResult::Continue;
            }
        };

        let now = Utc::now();

        // Validate Timestamp
        if self.require_timestamp
            && let Err(e) = self.validate_timestamp(&security_block, now)
        {
            warn!("soap_ws_security: timestamp validation failed: {}", e);
            return PluginResult::Reject {
                status_code: 401,
                body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                headers: HashMap::new(),
            };
        }

        // Keep authenticated identities local until every validation that
        // borrows the decoded request body has completed. Besides avoiding a
        // mutable borrow of `ctx` while `body` may borrow its raw bytes, this
        // prevents partially-authenticated metadata from escaping a later
        // X.509 or SAML rejection.
        let mut authenticated_username = None;
        let mut authenticated_saml_subject = None;

        // Validate UsernameToken
        if self.username_token_enabled {
            match self.validate_username_token(&security_block) {
                Ok(username) => {
                    authenticated_username = Some(username);
                    debug!(
                        content_type = %content_type,
                        "soap_ws_security: UsernameToken validated"
                    );
                }
                Err(UsernameTokenError::InvalidCredentials) => {
                    // Generic response + stable failure class: do not log the
                    // candidate username or password/digest verification detail.
                    warn!(
                        failure_class = UsernameTokenError::INVALID_CREDENTIALS_CLASS,
                        "soap_ws_security: UsernameToken authentication failed"
                    );
                    return PluginResult::Reject {
                        status_code: 401,
                        body: UsernameTokenError::INVALID_CREDENTIALS_BODY.to_string(),
                        headers: HashMap::new(),
                    };
                }
                Err(UsernameTokenError::Structural(detail)) => {
                    warn!(
                        failure_class = UsernameTokenError::STRUCTURAL_CLASS,
                        "soap_ws_security: UsernameToken validation failed: {}", detail
                    );
                    return PluginResult::Reject {
                        status_code: 401,
                        body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&detail)),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        // Validate X.509 signature
        if self.x509_enabled
            && let Err(e) = self.validate_x509_signature(&security_block, envelope)
        {
            warn!("soap_ws_security: X.509 signature validation failed: {}", e);
            return PluginResult::Reject {
                status_code: 401,
                body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                headers: HashMap::new(),
            };
        }

        // Validate SAML assertion
        if self.saml_enabled {
            match self.validate_saml_assertion(&security_block, envelope, now) {
                Ok(name_id) => {
                    authenticated_saml_subject = name_id;
                    debug!("soap_ws_security: SAML assertion accepted");
                }
                Err(e) => {
                    warn!("soap_ws_security: SAML validation failed: {}", e);
                    return PluginResult::Reject {
                        status_code: 401,
                        body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        if let Some(username) = authenticated_username {
            ctx.metadata
                .insert("soap_ws_username".to_string(), username);
        }
        if let Some(subject) = authenticated_saml_subject {
            ctx.metadata
                .insert("soap_ws_saml_subject".to_string(), subject);
        }

        PluginResult::Continue
    }
}

// ── XML Exclusive Canonicalization helpers ─────────────────────────────────

struct CanonicalizationSpec {
    inclusive_prefixes: Vec<String>,
}

struct ReferenceTransforms {
    enveloped_signature: bool,
    inclusive_prefixes: Vec<String>,
}

fn descendant_element<'a, 'input>(
    parent: Node<'a, 'input>,
    local_name: &str,
) -> Option<Node<'a, 'input>> {
    parent
        .descendants()
        .skip(1)
        .find(|node| node.has_tag_name(local_name))
}

fn unique_child_element<'a, 'input>(
    parent: Node<'a, 'input>,
    local_name: &str,
    context: &str,
) -> Result<Option<Node<'a, 'input>>, String> {
    let mut matches = parent
        .children()
        .filter(|node| node.has_tag_name(local_name));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(format!(
            "{}: multiple {} elements are not allowed",
            context, local_name
        ));
    }
    Ok(first)
}

fn node_source<'a>(xml: &'a str, node: Node<'_, '_>) -> Result<&'a str, String> {
    let range = node.range();
    xml.get(range)
        .ok_or_else(|| "WS-Security: XML parser returned an invalid source range".to_string())
}

fn parse_bounded_xml<'a>(xml: &'a str, context: &str) -> Result<Document<'a>, String> {
    Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_XML_NODES,
        },
    )
    .map_err(|error| {
        format!(
            "WS-Security: malformed or overly complex {} XML: {}",
            context, error
        )
    })
}

fn selected_security_node<'a, 'input>(
    document: &'a Document<'input>,
    xml: &str,
    selected_source: &str,
) -> Result<Node<'a, 'input>, String> {
    let header = document
        .descendants()
        .find(|node| node.has_tag_name("Header"))
        .ok_or_else(|| "WS-Security: SOAP Header element could not be located".to_string())?;
    header
        .descendants()
        .skip(1)
        .filter(|node| node.has_tag_name("Security"))
        .find(|node| node_source(xml, *node).is_ok_and(|source| source == selected_source))
        .ok_or_else(|| {
            "WS-Security: selected Security element could not be located in SOAP Header".to_string()
        })
}

fn envelope_body_node<'a, 'input>(document: &'a Document<'input>) -> Option<Node<'a, 'input>> {
    document
        .descendants()
        .find(|node| node.has_tag_name("Body"))
}

fn find_descendant_by_wsu_id<'a, 'input>(
    parent: Node<'a, 'input>,
    id: &str,
) -> Option<Node<'a, 'input>> {
    parent.descendants().find(|node| {
        node.is_element()
            && node.attributes().any(|attribute| {
                attribute.value() == id
                    && ((attribute.name() == "Id" && attribute.namespace().is_none())
                        || (attribute.name() == "Id"
                            && attribute.namespace() == Some(WSU_NAMESPACE_URI)))
            })
    })
}

fn count_dom_id_occurrences(document: &Document<'_>, id: &str) -> usize {
    document
        .descendants()
        .filter(Node::is_element)
        .flat_map(|node| node.attributes())
        .filter(|attribute| {
            attribute.value() == id && matches!(attribute.name(), "Id" | "ID" | "id")
        })
        .count()
}

fn decoded_element_text(node: Node<'_, '_>) -> Option<String> {
    node.text().map(|text| text.trim().to_string())
}

fn parse_signed_info_canonicalization(
    signed_info: Node<'_, '_>,
    context: &str,
) -> Result<CanonicalizationSpec, String> {
    let method = unique_child_element(signed_info, "CanonicalizationMethod", context)?
        .ok_or_else(|| format!("{}: SignedInfo missing CanonicalizationMethod", context))?;
    let algorithm = method.attribute("Algorithm").ok_or_else(|| {
        format!(
            "{}: CanonicalizationMethod missing Algorithm attribute",
            context
        )
    })?;
    if algorithm != XML_EXCLUSIVE_C14N {
        return Err(format!(
            "{}: unsupported CanonicalizationMethod algorithm '{}'",
            context, algorithm
        ));
    }

    Ok(CanonicalizationSpec {
        inclusive_prefixes: parse_inclusive_namespaces(method, context)?,
    })
}

fn parse_reference_transforms(
    reference: Node<'_, '_>,
    context: &str,
) -> Result<ReferenceTransforms, String> {
    let transforms = unique_child_element(reference, "Transforms", context)?.ok_or_else(|| {
        format!(
            "{}: Reference missing required exclusive-c14n Transform",
            context
        )
    })?;

    for child in transforms.children().filter(Node::is_element) {
        if !child.has_tag_name("Transform") {
            return Err(format!(
                "{}: unsupported element '{}' inside Transforms",
                context,
                child.tag_name().name()
            ));
        }
    }

    let mut enveloped_signature = false;
    let mut inclusive_prefixes = None;
    let mut transform_count = 0usize;
    for transform in transforms
        .children()
        .filter(|node| node.has_tag_name("Transform"))
    {
        transform_count += 1;
        if transform_count > 2 {
            return Err(format!(
                "{}: unsupported Reference transform chain length",
                context
            ));
        }
        let algorithm = transform
            .attribute("Algorithm")
            .ok_or_else(|| format!("{}: Transform missing Algorithm attribute", context))?;
        match algorithm {
            XMLDSIG_ENVELOPED_SIGNATURE => {
                if enveloped_signature {
                    return Err(format!(
                        "{}: duplicate enveloped-signature Transform",
                        context
                    ));
                }
                if inclusive_prefixes.is_some() {
                    return Err(format!(
                        "{}: enveloped-signature Transform cannot follow canonicalization",
                        context
                    ));
                }
                if transform.children().any(|node| node.is_element()) {
                    return Err(format!(
                        "{}: enveloped-signature Transform parameters are unsupported",
                        context
                    ));
                }
                enveloped_signature = true;
            }
            XML_EXCLUSIVE_C14N => {
                if inclusive_prefixes.is_some() {
                    return Err(format!("{}: duplicate exclusive-c14n Transform", context));
                }
                inclusive_prefixes = Some(parse_inclusive_namespaces(transform, context)?);
            }
            other => {
                return Err(format!(
                    "{}: unsupported Transform algorithm '{}'",
                    context, other
                ));
            }
        }
    }

    let inclusive_prefixes = inclusive_prefixes.ok_or_else(|| {
        format!(
            "{}: Reference transform chain does not include exclusive c14n",
            context
        )
    })?;

    Ok(ReferenceTransforms {
        enveloped_signature,
        inclusive_prefixes,
    })
}

fn parse_inclusive_namespaces(
    algorithm_node: Node<'_, '_>,
    context: &str,
) -> Result<Vec<String>, String> {
    let mut parameter = None;
    for child in algorithm_node.children().filter(Node::is_element) {
        if child.tag_name().name() != "InclusiveNamespaces"
            || child.tag_name().namespace() != Some(XML_EXCLUSIVE_C14N)
        {
            return Err(format!(
                "{}: unsupported canonicalization parameter '{}'",
                context,
                child.tag_name().name()
            ));
        }
        if parameter.replace(child).is_some() {
            return Err(format!(
                "{}: multiple InclusiveNamespaces parameters are not allowed",
                context
            ));
        }
    }

    let Some(parameter) = parameter else {
        return Ok(Vec::new());
    };
    let prefix_list = parameter
        .attribute("PrefixList")
        .ok_or_else(|| format!("{}: InclusiveNamespaces missing PrefixList", context))?;
    if prefix_list.len() > MAX_INCLUSIVE_PREFIX_LIST_BYTES {
        return Err(format!(
            "{}: InclusiveNamespaces PrefixList exceeds {} bytes",
            context, MAX_INCLUSIVE_PREFIX_LIST_BYTES
        ));
    }
    let mut prefixes = Vec::new();
    for token in prefix_list.split_whitespace() {
        if prefixes.len() >= MAX_INCLUSIVE_NAMESPACE_PREFIXES {
            return Err(format!(
                "{}: InclusiveNamespaces PrefixList contains more than {} prefixes",
                context, MAX_INCLUSIVE_NAMESPACE_PREFIXES
            ));
        }
        let prefix = if token == "#default" { "" } else { token };
        if token == "xmlns" || token.contains(':') || token.starts_with('#') && token != "#default"
        {
            return Err(format!(
                "{}: invalid InclusiveNamespaces prefix '{}'",
                context, token
            ));
        }
        if !prefixes.iter().any(|existing| existing == prefix) {
            prefixes.push(prefix.to_string());
        }
    }
    Ok(prefixes)
}

fn exclusive_canonicalize(
    xml: &str,
    root: Node<'_, '_>,
    inclusive_prefixes: &[String],
    excluded_node: Option<NodeId>,
) -> Result<Vec<u8>, String> {
    if !root.is_element() {
        return Err("WS-Security: exclusive c14n requires an element node".to_string());
    }

    let mut output = String::with_capacity(root.range().len());
    let mut rendered_namespaces = HashMap::new();
    rendered_namespaces.insert(
        "xml".to_string(),
        "http://www.w3.org/XML/1998/namespace".to_string(),
    );
    canonicalize_node(
        xml,
        root,
        inclusive_prefixes,
        excluded_node,
        0,
        &mut rendered_namespaces,
        &mut output,
    )?;
    Ok(output.into_bytes())
}

// Reached only via the lib target's `_test_support` shim (external unit tests);
// the bin target duplicates the module tree with no caller, so it sees this as
// dead code.
#[allow(dead_code)]
pub(crate) fn exclusive_canonicalize_element_for_test(
    xml: &str,
    local_name: &str,
    prefix_list: &str,
) -> Result<String, String> {
    let document = parse_bounded_xml(xml, "test fixture")?;
    let root = document
        .descendants()
        .find(|node| node.has_tag_name(local_name))
        .ok_or_else(|| format!("WS-Security: test fixture missing {}", local_name))?;
    let prefixes = prefix_list
        .split_whitespace()
        .map(|prefix| {
            if prefix == "#default" {
                String::new()
            } else {
                prefix.to_string()
            }
        })
        .collect::<Vec<_>>();
    let canonical = exclusive_canonicalize(xml, root, &prefixes, None)?;
    String::from_utf8(canonical).map_err(|_| "WS-Security: canonical XML was not UTF-8".to_string())
}

fn canonicalize_node(
    xml: &str,
    node: Node<'_, '_>,
    inclusive_prefixes: &[String],
    excluded_node: Option<NodeId>,
    depth: usize,
    rendered_namespaces: &mut HashMap<String, String>,
    output: &mut String,
) -> Result<(), String> {
    if depth > MAX_CANONICALIZATION_DEPTH {
        return Err(format!(
            "WS-Security: exclusive c14n depth exceeds {} elements",
            MAX_CANONICALIZATION_DEPTH
        ));
    }
    if excluded_node == Some(node.id()) {
        return Ok(());
    }

    if node.is_text() {
        if let Some(text) = node.text() {
            push_canonical_text(output, text);
        }
        return Ok(());
    }
    if node.is_comment() {
        return Ok(());
    }
    if let Some(pi) = node.pi() {
        output.push_str("<?");
        output.push_str(pi.target);
        if let Some(value) = pi.value {
            output.push(' ');
            output.push_str(value);
        }
        output.push_str("?>");
        return Ok(());
    }
    if !node.is_element() {
        return Ok(());
    }

    let qname = element_qname(xml, node)?;
    output.push('<');
    output.push_str(qname);

    let mut required_prefixes: Vec<(&str, bool)> = inclusive_prefixes
        .iter()
        .map(|prefix| (prefix.as_str(), false))
        .collect();
    let element_prefix = qname
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or("");
    add_required_prefix(&mut required_prefixes, element_prefix, true);

    let mut attributes = Vec::new();
    for attribute in node.attributes() {
        let qname_range = attribute.range_qname();
        let attribute_qname = xml.get(qname_range).ok_or_else(|| {
            "WS-Security: XML parser returned an invalid attribute range".to_string()
        })?;
        if let Some((prefix, _)) = attribute_qname.split_once(':') {
            add_required_prefix(&mut required_prefixes, prefix, true);
        }
        attributes.push((
            attribute.namespace().unwrap_or(""),
            attribute.name(),
            attribute_qname,
            attribute.value(),
        ));
    }

    let mut namespace_declarations = Vec::new();
    for (prefix, required) in required_prefixes {
        if prefix == "xml" {
            continue;
        }
        let namespace_uri = if prefix.is_empty() {
            node.lookup_namespace_uri(None).unwrap_or("")
        } else if let Some(uri) = node.lookup_namespace_uri(Some(prefix)) {
            uri
        } else if required {
            return Err(format!(
                "WS-Security: visibly used namespace prefix '{}' is not bound",
                prefix
            ));
        } else {
            continue;
        };

        let already_rendered = rendered_namespaces
            .get(prefix)
            .map(String::as_str)
            .unwrap_or("");
        if namespace_uri != already_rendered {
            namespace_declarations.push((prefix.to_string(), namespace_uri.to_string()));
        }
    }
    namespace_declarations.sort_by(|left, right| left.0.cmp(&right.0));

    let mut namespace_history = Vec::new();
    for (prefix, uri) in namespace_declarations {
        namespace_history.push((prefix.clone(), rendered_namespaces.get(&prefix).cloned()));
        rendered_namespaces.insert(prefix.clone(), uri.clone());
        output.push_str(" xmlns");
        if !prefix.is_empty() {
            output.push(':');
            output.push_str(&prefix);
        }
        output.push_str("=\"");
        push_canonical_attribute_value(output, &uri);
        output.push('"');
    }

    attributes.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
    for (_, _, qname, value) in attributes {
        output.push(' ');
        output.push_str(qname);
        output.push_str("=\"");
        push_canonical_attribute_value(output, value);
        output.push('"');
    }
    output.push('>');

    for child in node.children() {
        canonicalize_node(
            xml,
            child,
            inclusive_prefixes,
            excluded_node,
            depth + usize::from(child.is_element()),
            rendered_namespaces,
            output,
        )?;
    }

    output.push_str("</");
    output.push_str(qname);
    output.push('>');

    for (prefix, previous) in namespace_history.into_iter().rev() {
        if let Some(uri) = previous {
            rendered_namespaces.insert(prefix, uri);
        } else {
            rendered_namespaces.remove(&prefix);
        }
    }
    Ok(())
}

fn add_required_prefix<'a>(prefixes: &mut Vec<(&'a str, bool)>, prefix: &'a str, required: bool) {
    if let Some((_, existing_required)) = prefixes
        .iter_mut()
        .find(|(existing, _)| *existing == prefix)
    {
        *existing_required |= required;
    } else {
        prefixes.push((prefix, required));
    }
}

fn element_qname<'a>(xml: &'a str, node: Node<'_, '_>) -> Result<&'a str, String> {
    let range = node.range();
    let source = xml
        .get(range.start..range.end)
        .ok_or_else(|| "WS-Security: XML parser returned an invalid element range".to_string())?;
    let name = extract_full_tag_name_from_tag(source.strip_prefix('<').unwrap_or(source))
        .ok_or_else(|| "WS-Security: canonicalized element has no qualified name".to_string())?;
    Ok(name)
}

fn push_canonical_text(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#xD;"),
            other => output.push(other),
        }
    }
}

fn push_canonical_attribute_value(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            other => output.push(other),
        }
    }
}

// ── XML extraction helpers ──────────────────────────────────────────────────
//
// These helpers find elements by local name (ignoring namespace prefixes) to
// support various SOAP toolkit prefix conventions (wsse:, WSSE:, soap:, etc.).

/// Find an element block by local name, starting from position 0.
/// Returns the full element including its content and closing tag.
fn find_element_block(xml: &str, local_name: &str) -> Option<String> {
    find_element_block_from(xml, local_name, 0)
}

/// Find an element block by local name, starting from a given byte offset.
fn find_element_block_from(xml: &str, local_name: &str, start: usize) -> Option<String> {
    find_element_block_from_with_end(xml, local_name, start).map(|(block, _)| block)
}

/// Find an element block and also return the absolute end offset (within `xml`)
/// of the matched block. Callers that iterate over multiple sibling elements
/// must use this and advance their cursor with the returned end offset —
/// otherwise they will re-find the same element on the next iteration and
/// loop forever.
fn find_element_block_from_with_end(
    xml: &str,
    local_name: &str,
    start: usize,
) -> Option<(String, usize)> {
    if start > xml.len() {
        return None;
    }
    let search = &xml[start..];

    // Match <prefix:localName or <localName
    let open_pos = find_tag_start(search, local_name)?;

    let tag_start = open_pos;
    let after_open = &search[tag_start..];

    // Find the actual tag name (with optional prefix)
    let full_tag_name = extract_full_tag_name(after_open)?;

    // Check for self-closing tag
    let tag_header_end = after_open.find('>')?;
    if after_open.as_bytes().get(tag_header_end.checked_sub(1)?) == Some(&b'/') {
        let end = start + tag_start + tag_header_end + 1;
        return Some((after_open[..=tag_header_end].to_string(), end));
    }

    // Find matching closing tag </prefix:localName> or </localName>
    let closing = format!("</{}>", full_tag_name);
    let close_pos = search[tag_start..].find(&closing)?;
    let end_in_search = tag_start + close_pos + closing.len();
    let end = start + end_in_search;

    Some((search[tag_start..end_in_search].to_string(), end))
}

/// Find the text content of a direct child element by local name.
fn find_element_text(xml: &str, local_name: &str) -> Option<String> {
    let block = find_element_block(xml, local_name)?;
    extract_element_text_content(&block, local_name)
}

/// Extract text content between the opening and closing tags of an element.
fn extract_element_text_content(element: &str, local_name: &str) -> Option<String> {
    // Find end of opening tag
    let content_start = element.find('>')? + 1;

    // Find start of closing tag (search for </...localName>)
    let close_idx = find_closing_tag_pos(element, local_name)?;

    let content = &element[content_start..close_idx];
    Some(content.trim().to_string())
}

/// Find the position of a closing tag for the given local name.
fn find_closing_tag_pos(element: &str, local_name: &str) -> Option<usize> {
    let bytes = element.as_bytes();
    let name_bytes = local_name.as_bytes();
    let len = bytes.len();
    let name_len = name_bytes.len();

    let mut i = 0;
    while i + 2 + name_len < len {
        if bytes[i] == b'<' && bytes[i + 1] == b'/' {
            // Check for </localName> or </prefix:localName>
            let after_slash = &bytes[i + 2..];
            // Direct match: </localName
            if after_slash.starts_with(name_bytes) {
                let next = after_slash.get(name_len)?;
                if *next == b'>' {
                    return Some(i);
                }
            }
            // Prefixed match: </prefix:localName
            if let Some(colon_pos) = after_slash.iter().position(|&b| b == b':')
                && colon_pos + 1 + name_len <= after_slash.len()
            {
                let after_colon = &after_slash[colon_pos + 1..];
                if after_colon.starts_with(name_bytes) && after_colon.get(name_len) == Some(&b'>') {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Find the starting position of a tag with the given local name.
/// Matches both `<localName` and `<prefix:localName` patterns.
fn find_tag_start(xml: &str, local_name: &str) -> Option<usize> {
    let bytes = xml.as_bytes();
    let name_bytes = local_name.as_bytes();
    let len = bytes.len();
    let name_len = name_bytes.len();

    let mut i = 0;
    while i + 1 + name_len <= len {
        if bytes[i] == b'<' && !matches!(bytes[i + 1], b'/' | b'!' | b'?') {
            let after_lt = &bytes[i + 1..];

            // Direct match: <localName followed by space, >, or /
            if after_lt.starts_with(name_bytes)
                && let Some(&next) = after_lt.get(name_len)
                && matches!(next, b' ' | b'>' | b'/' | b'\t' | b'\n')
            {
                return Some(i);
            }

            // Prefixed match: <prefix:localName
            if let Some(colon_offset) = after_lt.iter().take(64).position(|&b| b == b':') {
                let prefix_part = &after_lt[..colon_offset];
                if prefix_part
                    .iter()
                    .all(|&b| !matches!(b, b' ' | b'>' | b'/'))
                {
                    let after_colon = &after_lt[colon_offset + 1..];
                    if after_colon.starts_with(name_bytes)
                        && let Some(&next) = after_colon.get(name_len)
                        && matches!(next, b' ' | b'>' | b'/' | b'\t' | b'\n')
                    {
                        return Some(i);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Extract the full tag name (including prefix) from a tag start: `<prefix:Name ...>`.
fn extract_full_tag_name(from_tag_start: &str) -> Option<String> {
    let after_lt = &from_tag_start[1..]; // skip '<'
    let end = after_lt.find([' ', '>', '/', '\t', '\n'])?;
    Some(after_lt[..end].to_string())
}

/// Find an attribute value in an element's opening tag.
fn find_attribute(element: &str, attr_name: &str) -> Option<String> {
    // Find the opening tag (up to the first >)
    let tag_end = element.find('>')?;
    let tag = &element[..tag_end];

    // Search for attr_name="value" or attr_name='value'
    // Also handle namespaced attributes like wsu:Id
    let patterns = [format!("{}=\"", attr_name), format!("{}='", attr_name)];

    for pattern in &patterns {
        if let Some(pos) = tag.find(pattern.as_str()) {
            let value_start = pos + pattern.len();
            let quote = tag.as_bytes()[value_start - 1]; // " or '
            let remaining = &tag[value_start..];
            if let Some(value_end) = remaining.find(quote as char) {
                return Some(remaining[..value_end].to_string());
            }
        }
    }

    None
}

fn extract_full_tag_name_from_tag(tag: &str) -> Option<&str> {
    let trimmed = tag.trim_start();
    let end = trimmed
        .find([' ', '>', '/', '\t', '\n', '\r'])
        .unwrap_or(trimmed.len());
    if end == 0 {
        None
    } else {
        Some(&trimmed[..end])
    }
}

fn scan_tag_attributes<F>(tag: &str, mut on_attr: F) -> bool
where
    F: FnMut(&str, &str) -> bool,
{
    let bytes = tag.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/' {
        i += 1;
    }

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'/' {
            break;
        }

        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/')
        {
            i += 1;
        }
        let name = &tag[name_start..i];

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let Some(&quote) = bytes.get(i) else {
            break;
        };
        if !matches!(quote, b'\'' | b'"') {
            continue;
        }
        i += 1;
        let value_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let value = &tag[value_start..i];
        i += 1;

        if on_attr(name, value) {
            return true;
        }
    }

    false
}

/// Count how many start tags in `xml` bear the given XML id attribute value.
/// Used to reject XML Signature Wrapping (XSW): a signed reference whose id
/// appears on more than one element means an attacker injected a duplicate, so
/// the byte range the signature covers may differ from the element a backend
/// consumes.
///
/// The resolver still accepts WS-Security `*:Id` / bare `Id`, but this security
/// gate intentionally counts broader id spellings (`xml:id`, `ID`, `id`) so a
/// backend with broader fragment resolution fails closed. Scanning only start
/// tags avoids rejecting a legitimate request merely because body text contains
/// `Id="..."`. Comments, CDATA, processing instructions, and declarations are
/// skipped as non-element spans. Unlike the narrower extraction helpers, this
/// full-envelope scan treats malformed start tags as errors rather than
/// returning a partial count.
pub(crate) fn count_wsu_id_occurrences(xml: &str, id: &str) -> Result<usize, String> {
    let mut count = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = xml[search_from..].find('<') {
        let tag_start = search_from + rel;
        let Some(after_lt) = xml.as_bytes().get(tag_start + 1) else {
            return Err(
                "WS-Security: malformed XML start tag while scanning referenced ids".into(),
            );
        };
        if *after_lt == b'/' {
            search_from = tag_start + 1;
            continue;
        }
        if *after_lt == b'!' {
            search_from = skip_markup_declaration(xml, tag_start)?;
            continue;
        }
        if *after_lt == b'?' {
            search_from = skip_processing_instruction(xml, tag_start)?;
            continue;
        }

        let tag_end_rel = find_start_tag_end(xml, tag_start).ok_or_else(|| {
            "WS-Security: malformed XML start tag while scanning referenced ids".to_string()
        })?;
        let tag = &xml[tag_start + 1..tag_start + tag_end_rel];
        count += count_id_attributes_in_tag(tag, id);
        search_from = tag_start + tag_end_rel + 1;
    }
    Ok(count)
}

fn skip_markup_declaration(xml: &str, tag_start: usize) -> Result<usize, String> {
    let from_start = xml.get(tag_start..).ok_or_else(|| {
        "WS-Security: malformed XML declaration while scanning referenced ids".to_string()
    })?;

    if from_start.starts_with("<!--") {
        return from_start
            .find("-->")
            .map(|end_rel| tag_start + end_rel + "-->".len())
            .ok_or_else(|| {
                "WS-Security: malformed XML comment while scanning referenced ids".to_string()
            });
    }

    if from_start.starts_with("<![CDATA[") {
        return from_start
            .find("]]>")
            .map(|end_rel| tag_start + end_rel + "]]>".len())
            .ok_or_else(|| {
                "WS-Security: malformed XML CDATA while scanning referenced ids".to_string()
            });
    }

    let decl_end_rel = find_markup_declaration_end(xml, tag_start).ok_or_else(|| {
        "WS-Security: malformed XML declaration while scanning referenced ids".to_string()
    })?;
    Ok(tag_start + decl_end_rel + 1)
}

fn skip_processing_instruction(xml: &str, tag_start: usize) -> Result<usize, String> {
    let from_start = xml.get(tag_start..).ok_or_else(|| {
        "WS-Security: malformed XML processing instruction while scanning referenced ids"
            .to_string()
    })?;

    from_start
        .find("?>")
        .map(|end_rel| tag_start + end_rel + "?>".len())
        .ok_or_else(|| {
            "WS-Security: malformed XML processing instruction while scanning referenced ids"
                .to_string()
        })
}

/// Return the byte offset, relative to `tag_start`, of the end of a `<!...>`
/// declaration. Comments and CDATA have custom terminators and are handled
/// before this helper is called.
fn find_markup_declaration_end(xml: &str, tag_start: usize) -> Option<usize> {
    debug_assert_eq!(xml.as_bytes().get(tag_start), Some(&b'<'));
    let bytes = xml.as_bytes().get(tag_start..)?;
    if !bytes.starts_with(b"<!") {
        return None;
    }

    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut i = 2usize;

    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'\'' | b'"') => quote = Some(bytes[i]),
            None if bytes[i] == b'[' => bracket_depth = bracket_depth.saturating_add(1),
            None if bytes[i] == b']' => bracket_depth = bracket_depth.saturating_sub(1),
            None if bytes[i] == b'>' && bracket_depth == 0 => return Some(i),
            None => {}
        }
        i += 1;
    }

    None
}

/// Return the byte offset, relative to `tag_start`, of the first unquoted `>`.
/// `tag_start` must point at `<`; malformed or unterminated start tags return
/// `None` so callers can fail closed instead of scanning a partial envelope.
fn find_start_tag_end(xml: &str, tag_start: usize) -> Option<usize> {
    debug_assert_eq!(xml.as_bytes().get(tag_start), Some(&b'<'));
    let bytes = xml.as_bytes().get(tag_start..)?;
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let mut quote = None;
    let mut i = 1usize;

    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'\'' | b'"') => quote = Some(bytes[i]),
            None if bytes[i] == b'>' => return Some(i),
            None => {}
        }
        i += 1;
    }

    None
}

fn count_id_attributes_in_tag(tag: &str, id: &str) -> usize {
    let mut count = 0usize;
    scan_tag_attributes(tag, |name, value| {
        if is_xml_id_attribute_name(name) && value == id {
            count += 1;
        }
        false
    });
    count
}

fn is_xml_id_attribute_name(name: &str) -> bool {
    matches!(name, "Id" | "xml:id" | "ID" | "id")
        || name
            .rsplit_once(':')
            .is_some_and(|(_, local_name)| local_name == "Id")
}

/// Resolve the signing certificate from a SAML `<Signature>` block.
///
/// SAML signatures conventionally carry the signing cert inline in
/// `KeyInfo/X509Data/X509Certificate`. A `BinarySecurityToken` reference is
/// also accepted for symmetry with the WS-Security X.509 path, though that
/// is unusual for SAML.
fn extract_saml_signing_cert(sig_block: &str) -> Result<Vec<u8>, String> {
    if let Some(key_info) = find_element_block(sig_block, "KeyInfo")
        && let Some(cert_b64) = find_element_text(&key_info, "X509Certificate")
    {
        return BASE64
            .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid X509Certificate base64: {}", e));
    }

    if let Some(bst) = find_element_block(sig_block, "BinarySecurityToken") {
        let cert_b64 = extract_element_text_content(&bst, "BinarySecurityToken")
            .ok_or_else(|| "WS-Security: SAML BinarySecurityToken has no content".to_string())?;
        return BASE64
            .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| {
                format!(
                    "WS-Security: SAML invalid BinarySecurityToken base64: {}",
                    e
                )
            });
    }

    Err(
        "WS-Security: SAML signature has no signing certificate (expected X509Certificate in KeyInfo)"
            .to_string(),
    )
}

/// Apply the XMLDSIG enveloped-signature transform: return a copy of `xml`
/// with the first `<Signature>` element (and its contents) removed.
///
/// This is what XMLDSIG verifiers do before hashing the referenced element
/// for an enveloped signature — the signer hashed the element with the
/// (then-empty) Signature placeholder excised, so the verifier has to remove
/// it too. For SAML assertions there is exactly one Signature child, so
/// taking the first `<Signature>` match is correct.
#[cfg(test)]
fn remove_envelope_signature(xml: &str) -> String {
    let Some((block, end)) = find_element_block_from_with_end(xml, "Signature", 0) else {
        return xml.to_string();
    };
    let start = end - block.len();
    let mut out = String::with_capacity(xml.len() - block.len());
    out.push_str(&xml[..start]);
    out.push_str(&xml[end..]);
    out
}

/// Extract a bare RFC 8017 `RSAPublicKey` DER from a parsed X.509 cert,
/// rejecting non-RSA keys and malformed encodings at load time.
///
/// Both the WS-Security X.509 trust store and the SAML `trusted_signing_certs`
/// trust store funnel cert PEMs through this helper so the verifier always
/// sees the bare `RSAPublicKey` that `ring::signature::RSA_PKCS1_*` expects —
/// passing a full `SubjectPublicKeyInfo` would reject every signature with
/// a generic parse error.
///
/// The returned error string already includes a leading context phrase
/// ("is not an RSA public key …", "RSA SPKI BIT STRING has …", "has
/// malformed RSA public key DER: …"), so callers prepend their own cert
/// path and surrounding identification.
fn load_rsa_public_key_from_cert(cert: &X509Certificate<'_>) -> Result<Vec<u8>, String> {
    let public_key_info = cert.public_key();

    // Defense-in-depth: this plugin only supports RSA-PKCS#1 v1.5 signature
    // verification (rsa-sha256 / rsa-sha1). A non-RSA cert (e.g. ECDSA P-256)
    // would otherwise load silently and surface at request time as a generic
    // "signature verification failed" message, making the misconfiguration
    // hard to diagnose. Reject at load with a precise error.
    if public_key_info.algorithm.algorithm != oid_registry::OID_PKCS1_RSAENCRYPTION {
        return Err(format!(
            "is not an RSA public key (algorithm OID '{}', expected \
             '1.2.840.113549.1.1.1' / rsaEncryption); only RSA certificates \
             are supported for WS-Security signature verification",
            public_key_info.algorithm.algorithm,
        ));
    }

    // An RSA SubjectPublicKeyInfo encapsulates the RSAPublicKey in a BIT
    // STRING whose `unused_bits` MUST be 0 (the contents are byte-aligned
    // DER). Anything else is a malformed cert.
    if public_key_info.subject_public_key.unused_bits != 0 {
        return Err(format!(
            "RSA SPKI BIT STRING has {} unused bits (expected 0)",
            public_key_info.subject_public_key.unused_bits,
        ));
    }

    // Ring's `RSA_PKCS1_*` verification algorithms expect a bare RFC 8017
    // §A.1.1 `RSAPublicKey` (modulus + exponent), NOT a full RFC 5280
    // `SubjectPublicKeyInfo` (which wraps the key with the algorithm
    // identifier OID). For RSA SPKI the inner `subject_public_key` BitString
    // contents ARE that bare `RSAPublicKey` encoding, so use that directly
    // instead of `public_key().raw` (which is the entire SPKI DER) —
    // passing SPKI bytes makes `UnparsedPublicKey::verify` fail to parse
    // the key and reject every signature regardless of validity.
    let public_key_der = public_key_info.subject_public_key.data.to_vec();

    // Structural regression guard: an `RSAPublicKey` DER is a top-level
    // SEQUENCE whose declared length matches the buffer length. A future
    // refactor that accidentally went back to `public_key().raw` (the full
    // SPKI) would also start with 0x30 — so a tag-only check is
    // insufficient — but its declared length would not agree with the
    // buffer. Verifying both tag and length encoding here catches that
    // class of mistake at load time rather than at request time.
    validate_rsa_public_key_der_shape(&public_key_der)
        .map_err(|e| format!("has malformed RSA public key DER: {}", e))?;

    Ok(public_key_der)
}

/// Structural sanity check: `der` must be a top-level DER `SEQUENCE` whose
/// declared length matches the buffer length exactly. This is intentionally
/// the narrow shape of an RFC 8017 `RSAPublicKey ::= SEQUENCE { modulus,
/// publicExponent }`. It does NOT parse the inner integers — ring does that
/// at verify time. The check exists specifically to catch a regression where
/// the full `SubjectPublicKeyInfo` (which also starts with 0x30, but whose
/// length header omits the wrapping `AlgorithmIdentifier` bytes that are
/// still present in the buffer) is passed in place of the bare `RSAPublicKey`.
fn validate_rsa_public_key_der_shape(der: &[u8]) -> Result<(), String> {
    if der.is_empty() {
        return Err("public key DER is empty".to_string());
    }
    if der[0] != 0x30 {
        return Err(format!(
            "expected DER SEQUENCE tag (0x30) at offset 0, got 0x{:02x}",
            der[0]
        ));
    }
    if der.len() < 2 {
        return Err("DER is truncated before length octet".to_string());
    }

    let first_len = der[1];
    let (declared_content_len, header_len) = if first_len & 0x80 == 0 {
        // Short-form: single-byte length, value 0..=127.
        ((first_len & 0x7f) as usize, 2)
    } else {
        // Long-form: low 7 bits give number of length octets that follow.
        let n = (first_len & 0x7f) as usize;
        if n == 0 {
            return Err("indefinite-length encoding is not valid DER".to_string());
        }
        if n > 4 {
            return Err(format!(
                "length uses {n} octets (refusing to parse > 4; a 4-octet length covers 4 GiB)"
            ));
        }
        if der.len() < 2 + n {
            return Err("DER is truncated inside length encoding".to_string());
        }
        let mut declared: usize = 0;
        for &b in &der[2..2 + n] {
            declared = (declared << 8) | b as usize;
        }
        (declared, 2 + n)
    };

    let expected_total = header_len
        .checked_add(declared_content_len)
        .ok_or_else(|| "declared length overflows usize".to_string())?;

    if expected_total != der.len() {
        return Err(format!(
            "length mismatch: header declares {declared_content_len} content bytes \
             ({expected_total}-byte total), buffer is {} bytes \
             (regression: looks like a full SubjectPublicKeyInfo, not a bare RSAPublicKey)",
            der.len()
        ));
    }

    Ok(())
}

/// Decode PEM to DER bytes (handles the common CERTIFICATE block).
fn extract_pem_der(pem: &str) -> Option<Vec<u8>> {
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem.find(start_marker)? + start_marker.len();
    let end = pem.find(end_marker)?;

    let b64 = pem[start..end].replace(char::is_whitespace, "");
    BASE64.decode(b64.as_bytes()).ok()
}

fn contains_forbidden_xml_declaration(xml: &str) -> bool {
    contains_ascii_case_insensitive(xml, "<!doctype")
        || contains_ascii_case_insensitive(xml, "<!entity")
}

/// Encoding rejection at the SOAP hostile-input boundary.
///
/// Messages are stable and body-free so logs/responses never echo credentials
/// or envelope contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoapBodyDecodeError {
    UnsupportedCharset,
    ConflictingCharset,
    MalformedEncoding,
}

impl SoapBodyDecodeError {
    fn status_code(self) -> u16 {
        match self {
            Self::UnsupportedCharset | Self::ConflictingCharset => 415,
            Self::MalformedEncoding => 400,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::UnsupportedCharset => "SOAP request uses an unsupported character encoding",
            Self::ConflictingCharset => {
                "SOAP request character encoding metadata is conflicting or ambiguous"
            }
            Self::MalformedEncoding => "SOAP request body is not valid for its character encoding",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::UnsupportedCharset => "unsupported_charset",
            Self::ConflictingCharset => "conflicting_charset",
            Self::MalformedEncoding => "malformed_encoding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoapXmlEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl SoapXmlEncoding {
    fn accepts_xml_decl_label(self, label: &str) -> bool {
        match self {
            Self::Utf8 => matches_utf8_label(label),
            // XML declarations commonly say encoding="UTF-16" without endianness;
            // the BOM / Content-Type already fixed the endian form.
            Self::Utf16Le | Self::Utf16Be => {
                matches_utf16_unspecified_label(label)
                    || (self == Self::Utf16Le && matches_utf16le_label(label))
                    || (self == Self::Utf16Be && matches_utf16be_label(label))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclaredCharset {
    Utf8,
    Utf16Le,
    Utf16Be,
    /// `charset=utf-16` without an endian hint — BOM required.
    Utf16Unspecified,
}

fn resolve_soap_request_body<'a>(
    ctx: &'a RequestContext,
    content_type: &str,
) -> Result<Option<Cow<'a, str>>, SoapBodyDecodeError> {
    if let Some(bytes) = ctx.request_body_bytes.as_ref() {
        if bytes.is_empty() {
            return Ok(None);
        }
        return decode_soap_xml_body(bytes, content_type).map(Some);
    }
    // Fixture-only fallback: production prefers raw bytes. Still enforce the
    // UTF-8 XML-declaration contract so encoding validation is not bypassed.
    match ctx.metadata.get("request_body") {
        Some(body) if body.is_empty() => Ok(None),
        Some(body) => {
            validate_xml_declaration_encoding(body, SoapXmlEncoding::Utf8)?;
            Ok(Some(Cow::Borrowed(body.as_str())))
        }
        None => Ok(None),
    }
}

/// Decode a buffered SOAP body into UTF-8 text for XML validation.
///
/// UTF-8 payloads borrow the wire buffer; UTF-16 payloads allocate a decoded
/// string. The original wire bytes in `ctx.request_body_bytes` are left
/// untouched so the backend still receives the client representation.
fn decode_soap_xml_body<'a>(
    bytes: &'a [u8],
    content_type: &str,
) -> Result<Cow<'a, str>, SoapBodyDecodeError> {
    let declared = parse_content_type_charset(content_type)?;
    let (encoding, payload) = resolve_soap_xml_encoding(bytes, declared)?;
    let decoded = decode_payload(encoding, payload)?;
    validate_xml_declaration_encoding(&decoded, encoding)?;
    Ok(decoded)
}

fn parse_content_type_charset(
    content_type: &str,
) -> Result<Option<DeclaredCharset>, SoapBodyDecodeError> {
    let mut charset = None;
    let mut rest = skip_content_type_media_type(content_type)?;
    while let Some((name, value, next)) = next_content_type_parameter(rest)? {
        rest = next;
        if !name.eq_ignore_ascii_case("charset") {
            continue;
        }
        if value.is_empty() {
            return Err(SoapBodyDecodeError::UnsupportedCharset);
        }
        if charset.is_some() {
            // Duplicate charset parameters are hostile/ambiguous metadata.
            return Err(SoapBodyDecodeError::ConflictingCharset);
        }
        charset = Some(normalize_declared_charset(value)?);
    }
    Ok(charset)
}

/// Advance past the media type (`type/subtype`) to the parameter region.
fn skip_content_type_media_type(content_type: &str) -> Result<&str, SoapBodyDecodeError> {
    let bytes = content_type.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b';' => return Ok(&content_type[i..]),
            // Media type tokens are not quoted; a quote here is hostile metadata.
            b'"' | b'\'' | b'\\' => return Err(SoapBodyDecodeError::ConflictingCharset),
            _ => i += 1,
        }
    }
    Ok("")
}

/// Parse the next `name=value` Content-Type parameter.
///
/// Parameter values may be tokens or quoted-strings. Semicolons inside a
/// quoted value do not terminate the parameter. Quoted-pair escapes (`\X`)
/// are rejected fail-closed — charset labels never require them.
fn next_content_type_parameter(
    rest: &str,
) -> Result<Option<(&str, &str, &str)>, SoapBodyDecodeError> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b';' || bytes[i].is_ascii_whitespace()) {
        i += 1;
    }
    if i >= bytes.len() {
        return Ok(None);
    }

    let name_start = i;
    while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b';' && !bytes[i].is_ascii_whitespace()
    {
        i += 1;
    }
    if name_start == i {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    let name = &rest[name_start..i];

    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'=' {
        // Parameter without a value — ignore and continue after the next ';'.
        while i < bytes.len() && bytes[i] != b';' {
            i += 1;
        }
        return Ok(Some((name, "", &rest[i..])));
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return Ok(Some((name, "", "")));
    }

    let (value, after_value) = if bytes[i] == b'"' || bytes[i] == b'\'' {
        parse_quoted_parameter_value(&rest[i..])?
    } else {
        let value_start = i;
        while i < bytes.len() && bytes[i] != b';' {
            if matches!(bytes[i], b'"' | b'\'' | b'\\') {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            i += 1;
        }
        let raw = rest[value_start..i].trim_end();
        (raw, &rest[i..])
    };
    Ok(Some((name, value, after_value)))
}

fn parse_quoted_parameter_value(raw: &str) -> Result<(&str, &str), SoapBodyDecodeError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    let quote = bytes[0];
    if quote != b'"' && quote != b'\'' {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Quoted-pair escapes are rejected deterministically. Charset
                // names are plain tokens and never require escaping.
                return Err(SoapBodyDecodeError::UnsupportedCharset);
            }
            b if b == quote => {
                let inner = &raw[1..i];
                if inner.is_empty() {
                    return Err(SoapBodyDecodeError::UnsupportedCharset);
                }
                let mut next = i + 1;
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if next < bytes.len() && bytes[next] != b';' {
                    return Err(SoapBodyDecodeError::ConflictingCharset);
                }
                return Ok((inner, &raw[next..]));
            }
            _ => i += 1,
        }
    }
    Err(SoapBodyDecodeError::ConflictingCharset)
}

fn normalize_declared_charset(raw: &str) -> Result<DeclaredCharset, SoapBodyDecodeError> {
    if matches_utf8_label(raw) {
        Ok(DeclaredCharset::Utf8)
    } else if matches_utf16le_label(raw) {
        Ok(DeclaredCharset::Utf16Le)
    } else if matches_utf16be_label(raw) {
        Ok(DeclaredCharset::Utf16Be)
    } else if matches_utf16_unspecified_label(raw) {
        Ok(DeclaredCharset::Utf16Unspecified)
    } else {
        Err(SoapBodyDecodeError::UnsupportedCharset)
    }
}

fn matches_utf8_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-8")
        || label.eq_ignore_ascii_case("utf8")
        || label.eq_ignore_ascii_case("unicode-1-1-utf-8")
}

fn matches_utf16le_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-16le") || label.eq_ignore_ascii_case("utf16le")
}

fn matches_utf16be_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-16be")
        || label.eq_ignore_ascii_case("utf16be")
        || label.eq_ignore_ascii_case("unicodefffe")
}

fn matches_utf16_unspecified_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-16") || label.eq_ignore_ascii_case("utf16")
}

fn detect_bom(bytes: &[u8]) -> Option<(SoapXmlEncoding, usize)> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some((SoapXmlEncoding::Utf8, 3))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Some((SoapXmlEncoding::Utf16Be, 2))
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Some((SoapXmlEncoding::Utf16Le, 2))
    } else {
        None
    }
}

fn resolve_soap_xml_encoding(
    bytes: &[u8],
    declared: Option<DeclaredCharset>,
) -> Result<(SoapXmlEncoding, &[u8]), SoapBodyDecodeError> {
    let bom = detect_bom(bytes);
    match (bom, declared) {
        (Some((encoding, skip)), None) => Ok((encoding, &bytes[skip..])),
        (Some((encoding, skip)), Some(DeclaredCharset::Utf8)) => {
            if encoding == SoapXmlEncoding::Utf8 {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (Some((encoding, skip)), Some(DeclaredCharset::Utf16Le)) => {
            if encoding == SoapXmlEncoding::Utf16Le {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (Some((encoding, skip)), Some(DeclaredCharset::Utf16Be)) => {
            if encoding == SoapXmlEncoding::Utf16Be {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (Some((encoding, skip)), Some(DeclaredCharset::Utf16Unspecified)) => {
            if matches!(
                encoding,
                SoapXmlEncoding::Utf16Le | SoapXmlEncoding::Utf16Be
            ) {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (None, Some(DeclaredCharset::Utf8)) => {
            if looks_like_bomless_utf16_xml(bytes) {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            Ok((SoapXmlEncoding::Utf8, bytes))
        }
        (None, None) => {
            // BOM-less, charset-less UTF-16 XML (`3c 00` / `00 3c`) is
            // unmistakable and must not be treated as UTF-8 (NUL-containing
            // bytes can otherwise pass leniently and be forwarded).
            if looks_like_bomless_utf16_xml(bytes) {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            Ok((SoapXmlEncoding::Utf8, bytes))
        }
        (None, Some(DeclaredCharset::Utf16Le)) => Ok((SoapXmlEncoding::Utf16Le, bytes)),
        (None, Some(DeclaredCharset::Utf16Be)) => Ok((SoapXmlEncoding::Utf16Be, bytes)),
        // charset=utf-16 without BOM/endian is ambiguous — fail closed.
        (None, Some(DeclaredCharset::Utf16Unspecified)) => {
            Err(SoapBodyDecodeError::ConflictingCharset)
        }
    }
}

/// True when the first code unit is ASCII '<' encoded as UTF-16LE or UTF-16BE
/// without a BOM (`3c 00 …` / `00 3c …`).
fn looks_like_bomless_utf16_xml(bytes: &[u8]) -> bool {
    matches!(bytes, [0x3c, 0x00, ..] | [0x00, 0x3c, ..])
}

fn decode_payload<'a>(
    encoding: SoapXmlEncoding,
    payload: &'a [u8],
) -> Result<Cow<'a, str>, SoapBodyDecodeError> {
    match encoding {
        SoapXmlEncoding::Utf8 => std::str::from_utf8(payload)
            .map(Cow::Borrowed)
            .map_err(|_| SoapBodyDecodeError::MalformedEncoding),
        SoapXmlEncoding::Utf16Le => decode_utf16(payload, false).map(Cow::Owned),
        SoapXmlEncoding::Utf16Be => decode_utf16(payload, true).map(Cow::Owned),
    }
}

/// Incrementally decode UTF-16 into UTF-8 without an intermediate `Vec<u16>`.
/// Odd length and unpaired / truncated surrogates fail closed.
fn decode_utf16(payload: &[u8], big_endian: bool) -> Result<String, SoapBodyDecodeError> {
    if !payload.len().is_multiple_of(2) {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }
    // UTF-8 output is at most 3/2 of the UTF-16 wire length (see module note).
    let mut out = String::with_capacity(payload.len().saturating_mul(3) / 2);
    let mut chunks = payload.chunks_exact(2);
    while let Some(pair) = chunks.next() {
        let unit = if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        };
        if (0xD800..=0xDBFF).contains(&unit) {
            let Some(low_pair) = chunks.next() else {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            };
            let low = if big_endian {
                u16::from_be_bytes([low_pair[0], low_pair[1]])
            } else {
                u16::from_le_bytes([low_pair[0], low_pair[1]])
            };
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            }
            let code = 0x10000 + (((u32::from(unit) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
            out.push(char::from_u32(code).ok_or(SoapBodyDecodeError::MalformedEncoding)?);
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        } else {
            // Non-surrogate BMP units are always valid scalar values.
            let ch =
                char::from_u32(u32::from(unit)).ok_or(SoapBodyDecodeError::MalformedEncoding)?;
            out.push(ch);
        }
    }
    Ok(out)
}

fn validate_xml_declaration_encoding(
    xml: &str,
    resolved: SoapXmlEncoding,
) -> Result<(), SoapBodyDecodeError> {
    let trimmed = xml.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    let bytes = trimmed.as_bytes();
    if !bytes.starts_with(b"<?xml") || !bytes.get(5).is_some_and(|byte| byte.is_ascii_whitespace())
    {
        return Ok(());
    }
    let Some(end) = trimmed.find("?>") else {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    };
    let decl = &trimmed[..end + 2];
    let Some(label) = extract_xml_decl_encoding(decl)? else {
        return Ok(());
    };
    if resolved.accepts_xml_decl_label(&label) {
        Ok(())
    } else if matches_utf8_label(&label)
        || matches_utf16le_label(&label)
        || matches_utf16be_label(&label)
        || matches_utf16_unspecified_label(&label)
    {
        Err(SoapBodyDecodeError::ConflictingCharset)
    } else {
        // Unknown declaration encodings (e.g. iso-8859-1) are unsupported.
        Err(SoapBodyDecodeError::UnsupportedCharset)
    }
}

fn extract_xml_decl_encoding(decl: &str) -> Result<Option<String>, SoapBodyDecodeError> {
    let Some(mut rest) = decl.strip_prefix("<?xml") else {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    };
    rest = rest
        .strip_suffix("?>")
        .ok_or(SoapBodyDecodeError::MalformedEncoding)?;

    let mut encoding = None;
    while !rest.trim_start().is_empty() {
        rest = rest.trim_start();
        let name_len = rest
            .bytes()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-' | b'.')
            })
            .count();
        if name_len == 0 {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        let (name, after_name) = rest.split_at(name_len);
        rest = after_name.trim_start();
        rest = rest
            .strip_prefix('=')
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?
            .trim_start();
        let quote = rest
            .chars()
            .next()
            .filter(|quote| matches!(quote, '"' | '\''))
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        rest = &rest[quote.len_utf8()..];
        let end = rest
            .find(quote)
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        let value = &rest[..end];
        rest = &rest[end + quote.len_utf8()..];

        if name.eq_ignore_ascii_case("encoding") {
            if encoding.is_some() || value.trim().is_empty() {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            encoding = Some(value.trim().to_string());
        }
    }
    Ok(encoding)
}

// Reached only via the lib target's `_test_support` shim (external unit tests).
#[allow(dead_code)]
pub(crate) fn decode_soap_xml_body_for_test(
    bytes: &[u8],
    content_type: &str,
) -> Result<String, String> {
    decode_soap_xml_body(bytes, content_type)
        .map(Cow::into_owned)
        .map_err(|err| err.message().to_string())
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Parse WS-Security datetime formats (ISO 8601 variants).
fn parse_ws_datetime(s: &str) -> Option<DateTime<Utc>> {
    // Reject instants outside the representable WS-Security window. `chrono`'s
    // `%Y` accepts years far beyond four digits and its `DateTime` `Add`/`Sub`
    // impls panic on overflow, so an unclamped `Expires` / `NotOnOrAfter` could
    // turn `instant + skew` into a panicked request task. No legitimate
    // WS-Security or SAML instant falls outside this range.
    let parsed = parse_ws_datetime_unbounded(s)?;
    let year = parsed.year();
    if !(MIN_PARSED_YEAR..=MAX_PARSED_YEAR).contains(&year) {
        return None;
    }
    Some(parsed)
}

fn parse_ws_datetime_unbounded(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();

    // Try standard RFC 3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try common WS-Security formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%:z",
    ];

    for fmt in &formats {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }

    // Try without timezone (assume UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }

    None
}

/// Escape special characters for JSON string interpolation.
fn escape_json_chars(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            ch if ch < '\u{20}' => {
                escaped.push_str("\\u00");
                let byte = ch as u8;
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

/// Escape XML special characters for safe interpolation.
fn escape_xml_chars(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_escape_json_chars_round_trips_control_characters() {
        let raw = "validation failed\"\n<xml>\u{00}\u{1f}\\";
        let body = format!(r#"{{"error":"{}"}}"#, escape_json_chars(raw));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("escaped SOAP error should be valid JSON");

        assert_eq!(parsed["error"], raw);
        assert!(!escape_json_chars(raw).chars().any(|ch| ch < '\u{20}'));
    }

    #[test]
    fn too_many_x509_signature_references_are_rejected() {
        let plugin = SoapWsSecurity::new(&serde_json::json!({
            "timestamp": { "require": true }
        }))
        .expect("timestamp-only config should construct");
        let timestamp = r#"<wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="TS-1"></wsu:Timestamp>"#;
        let canonical_timestamp =
            exclusive_canonicalize_element_for_test(timestamp, "Timestamp", "")
                .expect("timestamp should canonicalize");
        let digest = digest::digest(&digest::SHA256, canonical_timestamp.as_bytes());
        let digest_b64 = BASE64.encode(digest.as_ref());
        let reference = format!(
            r##"<Reference URI="#TS-1"><Transforms><Transform Algorithm="{}"/></Transforms><DigestMethod Algorithm="{}"/><DigestValue>{}</DigestValue></Reference>"##,
            XML_EXCLUSIVE_C14N, XMLDSIG_SHA256, digest_b64
        );
        let references =
            std::iter::repeat_n(reference.as_str(), MAX_SIGNED_REFERENCES + 1).collect::<String>();
        let envelope = format!(
            "<Envelope><Security>{}<Signature><SignedInfo>{}</SignedInfo></Signature></Security><Body></Body></Envelope>",
            timestamp, references
        );
        let document = Document::parse(&envelope).expect("test envelope should parse");
        let security = descendant_element(document.root(), "Security").expect("Security");
        let signature = descendant_element(security, "Signature").expect("Signature");
        let signed_info = descendant_element(signature, "SignedInfo").expect("SignedInfo");

        let err = plugin
            .verify_reference_digests(signed_info, security, signature, &envelope)
            .expect_err("reference cap must reject");

        assert!(err.contains("too many Signature References"), "got: {err}");
    }

    #[test]
    fn too_many_saml_signature_references_are_rejected() {
        let plugin = SoapWsSecurity::new(&serde_json::json!({
            "timestamp": { "require": true }
        }))
        .expect("timestamp-only config should construct");
        let assertion = r#"<Assertion ID="assertion-1"><Issuer>https://idp.example.com</Issuer><Signature></Signature><Subject><NameID>alice@example.com</NameID></Subject></Assertion>"#;
        let assertion_without_signature = remove_envelope_signature(assertion);
        let canonical_assertion =
            exclusive_canonicalize_element_for_test(&assertion_without_signature, "Assertion", "")
                .expect("assertion should canonicalize");
        let digest = digest::digest(&digest::SHA256, canonical_assertion.as_bytes());
        let digest_b64 = BASE64.encode(digest.as_ref());
        let reference = format!(
            r##"<Reference URI="#assertion-1"><Transforms><Transform Algorithm="{}"/><Transform Algorithm="{}"/></Transforms><DigestMethod Algorithm="{}"/><DigestValue>{}</DigestValue></Reference>"##,
            XMLDSIG_ENVELOPED_SIGNATURE, XML_EXCLUSIVE_C14N, XMLDSIG_SHA256, digest_b64
        );
        let references =
            std::iter::repeat_n(reference.as_str(), MAX_SIGNED_REFERENCES + 1).collect::<String>();
        let envelope = assertion.replacen(
            "<Signature></Signature>",
            &format!(
                "<Signature><SignedInfo>{}</SignedInfo></Signature>",
                references
            ),
            1,
        );
        let document = Document::parse(&envelope).expect("test assertion should parse");
        let assertion = descendant_element(document.root(), "Assertion").expect("Assertion");
        let signature = descendant_element(assertion, "Signature").expect("Signature");
        let signed_info = descendant_element(signature, "SignedInfo").expect("SignedInfo");

        let err = plugin
            .verify_saml_reference_digests(signed_info, assertion, signature, &envelope)
            .expect_err("SAML reference cap must reject");

        assert!(
            err.contains("too many SAML Signature References"),
            "got: {err}"
        );
    }

    /// Iterating over multiple `<Reference>` elements with
    /// `find_element_block_from_with_end` must advance the cursor far enough
    /// to skip past each match — the previous implementation incremented by
    /// just 1 byte and looped forever on signed SOAP envelopes.
    #[test]
    fn multiple_reference_iteration_terminates_and_finds_each_block() {
        // Use a `r##"..."##` raw string so the embedded `#` characters in URI
        // attributes don't terminate the literal early.
        let signed_info = r##"<SignedInfo>
            <Reference URI="#alpha"><DigestValue>aGVsbG8=</DigestValue></Reference>
            <Reference URI="#beta"><DigestValue>d29ybGQ=</DigestValue></Reference>
            <Reference URI="#gamma"><DigestValue>IQ==</DigestValue></Reference>
        </SignedInfo>"##;

        let mut search_from = 0;
        let mut uris = Vec::new();
        let mut iterations = 0;
        while let Some((block, next_start)) =
            find_element_block_from_with_end(signed_info, "Reference", search_from)
        {
            iterations += 1;
            assert!(
                iterations < 50,
                "iteration must terminate (regression: infinite loop)"
            );
            uris.push(find_attribute(&block, "URI").unwrap_or_default());
            search_from = next_start.max(search_from + 1);
        }
        assert_eq!(uris, vec!["#alpha", "#beta", "#gamma"]);
    }

    /// The end offset must point past the closing `</Reference>` so the next
    /// search starts after the just-matched element, not inside it.
    #[test]
    fn end_offset_points_past_closing_tag() {
        let xml = "prefix<Reference URI=\"#a\"></Reference>middle<Reference URI=\"#b\"></Reference>suffix";
        let Some((first_block, end1)) = find_element_block_from_with_end(xml, "Reference", 0)
        else {
            panic!("first Reference match should be present");
        };
        assert!(first_block.contains("#a"));
        // The remainder should still contain the second Reference.
        let remainder = &xml[end1..];
        assert!(remainder.contains("#b"));
        assert!(!remainder.contains("#a"));
    }

    /// Self-closing tags (e.g. `<Reference URI="#x"/>`) also yield a valid
    /// end offset so subsequent iterations advance past them.
    #[test]
    fn self_closing_tag_returns_correct_end() {
        let xml = "before<Foo/>after";
        let Some((block, end)) = find_element_block_from_with_end(xml, "Foo", 0) else {
            panic!("self-closing Foo match should be present");
        };
        assert_eq!(block, "<Foo/>");
        assert_eq!(&xml[end..], "after");
    }

    // ── RSA public-key DER shape validator ──────────────────────────────────
    //
    // These tests pin the structural regression guard that catches a future
    // refactor accidentally routing the full SubjectPublicKeyInfo (instead of
    // the bare RSAPublicKey) into `ring::signature::UnparsedPublicKey::new` —
    // the original PR #844 bug class.

    #[test]
    fn rsa_pk_shape_accepts_short_form_sequence_with_matching_length() {
        // SEQUENCE, content length 3, three content bytes — well-formed.
        let der = [0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(validate_rsa_public_key_der_shape(&der).is_ok());
    }

    #[test]
    fn rsa_pk_shape_accepts_long_form_two_octet_length() {
        // SEQUENCE, long-form length: 0x82 means "next 2 octets are length";
        // 0x01 0x00 = 256 content bytes. Build a buffer of exactly that size.
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0xAB_u8, 256));
        assert_eq!(der.len(), 4 + 256);
        assert!(validate_rsa_public_key_der_shape(&der).is_ok());
    }

    #[test]
    fn rsa_pk_shape_rejects_empty_buffer() {
        let err = validate_rsa_public_key_der_shape(&[]).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_non_sequence_tag() {
        // 0x02 = INTEGER tag — refused even with otherwise-valid length.
        let err = validate_rsa_public_key_der_shape(&[0x02, 0x01, 0x00]).unwrap_err();
        assert!(err.contains("SEQUENCE tag"), "got: {err}");
        assert!(err.contains("0x02"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_truncated_after_tag() {
        let err = validate_rsa_public_key_der_shape(&[0x30]).unwrap_err();
        assert!(err.contains("length octet"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_indefinite_length_encoding() {
        // 0x80 = "indefinite length" — invalid in DER (only BER allows it).
        let err = validate_rsa_public_key_der_shape(&[0x30, 0x80, 0x00, 0x00]).unwrap_err();
        assert!(err.contains("indefinite-length"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_overlong_length_field() {
        // 0x85 = 5 length octets — refused (a 4-octet length already covers 4 GiB).
        let der = [0x30, 0x85, 0, 0, 0, 0, 0, 0];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length uses 5 octets"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_truncated_long_form_length() {
        // 0x82 promises 2 length octets, but only 1 is present.
        let err = validate_rsa_public_key_der_shape(&[0x30, 0x82, 0x00]).unwrap_err();
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_full_spki_shape_via_length_mismatch() {
        // The exact regression: build a synthetic blob that resembles a
        // SubjectPublicKeyInfo's outer wrapping. Its top-level SEQUENCE length
        // header declares a content size that excludes the trailing bytes the
        // buffer still carries — the length check must reject this.
        //
        // Layout: 0x30 0x09 [9 content bytes] [4 extra trailing bytes].
        // 9 + 2 (header) = 11, but the buffer length is 15, so this rejects.
        let der = [
            0x30, 0x09, // SEQUENCE, 9 content bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // 9 content bytes
            0xAA, 0xBB, 0xCC, 0xDD, // trailing extras (would be the inner BIT STRING)
        ];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
        // The hint about the SPKI regression class is included so the
        // failure mode is recognizable to future maintainers.
        assert!(err.contains("SubjectPublicKeyInfo"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_declared_shorter_than_buffer() {
        // Header declares 2 content bytes but buffer has 4 content bytes.
        let der = [0x30, 0x02, 0x01, 0x02, 0x03, 0x04];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_declared_longer_than_buffer() {
        // Header declares 100 content bytes but only 2 content bytes follow.
        let der = [0x30, 0x64, 0x01, 0x02];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }
}
