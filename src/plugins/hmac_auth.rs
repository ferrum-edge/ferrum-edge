//! HMAC Authentication Plugin
//!
//! Validates HMAC-signed requests where the client signs the request
//! with a shared secret. Supports hmac-sha256 and hmac-sha512.
//!
//! Expected Authorization header format:
//!   hmac username="<username>", algorithm="hmac-sha256", signature="<base64-sig>"
//!
//! ## Signing string
//!
//! Ferrum's `Authorization: hmac` scheme is not RFC 9421 HTTP Message
//! Signatures. Version 1 signs these newline-separated fields:
//!
//!   ```text
//!   ferrum-hmac-v1\n{NAMESPACE}\n{USERNAME}\n{AUTHORITY}\n{METHOD}\n{PATH}\n{QUERY}\n{DATE}\n{DIGEST_HEADER_VALUE}
//!   ```
//!
//! `{PATH}` is the request path component only; `{QUERY}` is the raw query
//! string as received (percent-encoded, without the leading `?`, empty when
//! there is no query). Binding the query means query parameters cannot be
//! altered or added without invalidating the signature. Clients must sign the
//! byte-for-byte raw query string the gateway receives.
//!
//! The client must also include a legacy `Digest:` value such as
//! `sha-256=<base64>` or an RFC 9530 `Content-Digest:` structured-field value
//! such as `sha-256=:<base64>:`. The digest must match the SHA-256 / SHA-512 of
//! the request body. The plugin
//! verifies that the digest matches the actual buffered body bytes; tampering
//! with the body, the query string, or the digest header invalidates the HMAC.
//!
//! ## Replay protection (limitation)
//!
//! The signed `Date` header provides only a bounded *freshness window*, not
//! single-use replay prevention. A request is accepted while its `Date` is
//! within `now ± clock_skew_seconds` (default 300s). There is no nonce or
//! seen-signature store, so a captured, fully valid signed request can be
//! replayed verbatim any number of times until the window elapses. For
//! non-idempotent routes, keep `clock_skew_seconds` tight and do not rely on
//! `hmac_auth` alone. (A future enhancement could add an optional client nonce
//! plus a bounded TTL replay cache, mirroring `utils/dpop.rs`.)
//!
//! Consumer credentials should include:
//!   { "hmac_auth": { "secret": "<shared-secret>" } }

use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::sync::{Arc, OnceLock};
use tracing::{debug, warn};

use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq,
};
use super::{RequestContext, strip_auth_scheme};
use crate::config::types::Consumer;
use crate::consumer_index::ConsumerIndex;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const HMAC_REQUEST_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
const HMAC_SIGNING_VERSION: &str = "ferrum-hmac-v1";

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
    } else if key.eq_ignore_ascii_case("signature") && signature.replace(value).is_some() {
        return Err(r#"{"error":"Duplicate signature in HMAC authorization"}"#);
    }
    Ok(())
}

fn parse_hmac_authorization(params: &str) -> Result<ParsedHmacAuthorization, &'static str> {
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut username = None;
    let mut algorithm = None;
    let mut signature = None;
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

    Ok(ParsedHmacAuthorization {
        username,
        algorithm,
        signature,
    })
}

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
    preverified_consumer: Arc<Consumer>,
}

/// Request-scoped bridge between HMAC's pre-body signature check and its
/// post-body digest check.
///
/// After preverification the parsed signature is dropped; this retains only a
/// fingerprint used to detect Authorization changes, the already-owned signed
/// request fields needed by the final digest check, and a Consumer containing
/// secret material. Its custom `Debug` reveals only presence, and its custom
/// `Clone` deliberately drops the value so deferred-log/simulation contexts can
/// never inherit authentication data.
#[derive(Default)]
pub(crate) struct HmacPrebufferState {
    cached: OnceLock<CachedHmacAuthorization>,
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
            .field("staged", &self.cached.get().is_some())
            .finish()
    }
}

impl HmacPrebufferState {
    fn stage(&self, cached: CachedHmacAuthorization) {
        // Multiple hmac_auth instances may screen one request. The first valid
        // signature uses the same immutable signed fields and Consumer snapshot
        // that authentication will see, so retaining the first verified result
        // is sufficient and avoids replacing credential-bearing state.
        let _ = self.cached.set(cached);
    }

    fn take(&mut self) -> Option<CachedHmacAuthorization> {
        self.cached.take()
    }
}

pub struct HmacAuth {
    clock_skew_seconds: u64,
}

impl HmacAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("hmac_auth: config must be an object, got: {config}"))?;
        let clock_skew_seconds = parse_u64_field(
            config_obj.get("clock_skew_seconds"),
            "clock_skew_seconds",
            300,
        )?;
        if config_obj.get("require_digest").is_some() {
            return Err(
                "hmac_auth: 'require_digest' was removed; request digests are always required"
                    .to_string(),
            );
        }

        Ok(Self { clock_skew_seconds })
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
    /// This enforces a bounded freshness window (`now ± clock_skew_seconds`),
    /// not single-use replay prevention — there is no nonce store, so a
    /// captured valid request can be replayed within the window. See the
    /// module-level "Replay protection (limitation)" note.
    fn validate_date(&self, date_str: &str) -> bool {
        if date_str.is_empty() {
            // No Date header means no freshness bound at all — reject.
            return false;
        }

        // Parse HTTP-date format (RFC 7231): "Sun, 06 Nov 1994 08:49:37 GMT"
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(date_str) {
            let now = chrono::Utc::now();
            let diff = (now - parsed.with_timezone(&chrono::Utc))
                .num_seconds()
                .unsigned_abs();
            diff <= self.clock_skew_seconds
        } else if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(date_str) {
            let now = chrono::Utc::now();
            let diff = (now - parsed.with_timezone(&chrono::Utc))
                .num_seconds()
                .unsigned_abs();
            diff <= self.clock_skew_seconds
        } else {
            warn!("hmac_auth: unparseable Date header: {}", date_str);
            false
        }
    }

    /// Verify that the `Digest:` header value matches the SHA-256/SHA-512 of
    /// `body`. The header format is `<algo>=<base64>` per RFC 3230 §4.3.2,
    /// where `<algo>` is `sha-256` or `sha-512` (case-insensitive).
    ///
    /// Multiple comma-separated entries are accepted; verification succeeds
    /// if any one entry matches. Algorithms other than sha-256/sha-512 are
    /// silently ignored (per RFC 3230, the receiver picks).
    #[cfg(test)]
    pub(crate) fn verify_body_digest(digest_header: &str, body: &[u8]) -> bool {
        for entry in digest_header.split(',') {
            let entry = entry.trim();
            // RFC 9530 Content-Digest wraps a byte sequence in colons
            // (`sha-256=:base64:`); legacy Digest uses bare base64.
            let Some((algo_raw, value_raw)) = entry.split_once('=') else {
                continue;
            };
            let algo = algo_raw.trim().to_ascii_lowercase();
            // RFC 9530 Content-Digest uses the `:<base64>:` structured-field
            // byte-sequence form.
            let value = value_raw.trim().trim_matches(':').trim_matches('"');

            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
                continue;
            };

            let actual = match algo.as_str() {
                "sha-256" | "sha256" => {
                    let mut hasher = Sha256::new();
                    hasher.update(body);
                    hasher.finalize().to_vec()
                }
                "sha-512" | "sha512" => {
                    let mut hasher = Sha512::new();
                    hasher.update(body);
                    hasher.finalize().to_vec()
                }
                _ => continue,
            };

            if constant_time_eq(&decoded, &actual) {
                return true;
            }
        }
        false
    }

    fn verify_precomputed_body_digest(
        digest_header: &str,
        body_sha256: &[u8; 32],
        body_sha512: &[u8; 64],
    ) -> bool {
        for entry in digest_header.split(',') {
            let Some((algo_raw, value_raw)) = entry.trim().split_once('=') else {
                continue;
            };
            let value = value_raw.trim().trim_matches(':').trim_matches('"');
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
                continue;
            };
            match algo_raw.trim().to_ascii_lowercase().as_str() {
                "sha-256" | "sha256" if constant_time_eq(body_sha256, &decoded) => return true,
                "sha-512" | "sha512" if constant_time_eq(body_sha512, &decoded) => return true,
                _ => {}
            }
        }
        false
    }

    fn digest_header_has_supported_value(digest_header: &str) -> bool {
        digest_header.split(',').any(|entry| {
            let Some((algo_raw, value_raw)) = entry.trim().split_once('=') else {
                return false;
            };
            let expected_len = match algo_raw.trim().to_ascii_lowercase().as_str() {
                "sha-256" | "sha256" => 32,
                "sha-512" | "sha512" => 64,
                _ => return false,
            };
            let value = value_raw.trim().trim_matches(':').trim_matches('"');
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .is_ok_and(|decoded| decoded.len() == expected_len)
        })
    }

    /// Look up the digest header on the request. Prefers RFC 9530
    /// `Content-Digest` and falls back to RFC 3230 `Digest`.
    fn extract_digest_header(ctx: &RequestContext) -> Option<String> {
        if let Some(value) = ctx.headers.get("content-digest") {
            return Some(value.clone());
        }
        ctx.headers.get("digest").cloned()
    }

    fn has_hmac_authorization(&self, ctx: &RequestContext) -> bool {
        let Some(auth_header) = ctx.headers.get("authorization") else {
            return false;
        };
        strip_auth_scheme(auth_header, "hmac").is_some()
    }

    fn authorization_fingerprint(ctx: &RequestContext) -> Option<[u8; 32]> {
        ctx.headers
            .get("authorization")
            .map(|header| Sha256::digest(header.as_bytes()).into())
    }

    fn digest_header_ref(ctx: &RequestContext) -> Option<&str> {
        ctx.headers
            .get("content-digest")
            .or_else(|| ctx.headers.get("digest"))
            .map(String::as_str)
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

        let signing_string = build_signing_string(credential);
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
        // verification does not require body bytes. Only a valid secret-holder
        // may enable collection; unknown and known-invalid identities both stay
        // on the same pre-auth 401 path without reaching the body-size limit.
        if !self.validate_date(&credential.date)
            || !Self::digest_header_has_supported_value(&credential.digest_header)
        {
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
            ..
        } = *credential;
        ctx.hmac_prebuffer_state.stage(CachedHmacAuthorization {
            authorization_fingerprint,
            namespace,
            username,
            authority,
            date,
            method,
            path,
            query,
            digest_header,
            preverified_consumer,
        });
        true
    }

    fn take_prebuffered_auth(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> Option<Result<Arc<Consumer>, String>> {
        let cached = ctx.hmac_prebuffer_state.take()?;

        // H1/H2 and H3 call the prebuffer predicate immediately before body
        // collection and authentication, with no plug-in hook in between. Bind
        // the one-shot cache to the Authorization header, every signed request
        // field, and the exact Consumer snapshot anyway; if that lifecycle ever
        // changes, discard the cache and run ordinary extraction/verification.
        if !Self::cached_request_binding_matches(&cached, ctx, consumer_index) {
            return None;
        }

        if !self.validate_date(&cached.date) {
            return Some(Err(
                r#"{"error":"Missing or expired Date header"}"#.to_string()
            ));
        }
        let (Some(body_sha256), Some(body_sha512)) = (
            ctx.request_body_sha256.as_ref(),
            ctx.request_body_sha512.as_ref(),
        ) else {
            return Some(Err(
                r#"{"error":"Digest header does not match request body"}"#.to_string(),
            ));
        };
        if !Self::verify_precomputed_body_digest(&cached.digest_header, body_sha256, body_sha512) {
            debug!("hmac_auth: digest header does not match request body");
            return Some(Err(
                r#"{"error":"Digest header does not match request body"}"#.to_string(),
            ));
        }

        Some(Ok(cached.preverified_consumer))
    }
}

#[async_trait]
impl AuthMechanism for HmacAuth {
    fn mechanism_name(&self) -> &'static str {
        "hmac_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        let Some(auth_header) = ctx.headers.get("authorization") else {
            return ExtractedCredential::Missing;
        };

        let Some(params_str) = strip_auth_scheme(auth_header, "hmac") else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid HMAC authorization format"}"#.to_string(),
            );
        };

        let ParsedHmacAuthorization {
            username,
            algorithm,
            signature,
        } = match parse_hmac_authorization(params_str) {
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
        let digest_header = match Self::extract_digest_header(ctx) {
            Some(header) => header,
            None => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Missing required Digest header"}"#.to_string(),
                );
            }
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
            request_body_sha256: ctx
                .request_body_sha256
                .unwrap_or_else(|| Sha256::digest([]).into()),
            request_body_sha512: ctx
                .request_body_sha512
                .unwrap_or_else(|| Sha512::digest([]).into()),
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

        // Verify that the Digest header matches the actual request body.
        // Done before consumer lookup so a tampered body fails fast and the
        // error message is independent of whether the consumer exists.
        if !Self::verify_precomputed_body_digest(
            &credential.digest_header,
            &credential.request_body_sha256,
            &credential.request_body_sha512,
        ) {
            debug!("hmac_auth: digest header does not match request body");
            return VerifyOutcome::Invalid(
                r#"{"error":"Digest header does not match request body"}"#.to_string(),
            );
        }

        // Tampering with the digest header itself (without re-signing with
        // the secret) breaks the HMAC because the digest value is signed.
        // The query string is bound too, so altering query params invalidates
        // the signature.
        if let Some(consumer) = self.consumer_for_valid_signature(&credential, consumer_index) {
            return VerifyOutcome::consumer(consumer);
        }

        debug!("hmac_auth: credential verification failed");
        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid credentials"}"#.to_string())
    }
}

async fn run_hmac_auth(
    mechanism: &HmacAuth,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> super::PluginResult {
    match mechanism.take_prebuffered_auth(ctx, consumer_index) {
        None => auth_flow::run_auth(mechanism, ctx, consumer_index).await,
        Some(Err(body)) => super::PluginResult::Reject {
            status_code: 401,
            body,
            headers: std::collections::HashMap::new(),
        },
        Some(Ok(consumer)) => {
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
);

fn parse_u64_field(value: Option<&Value>, field: &str, default_value: u64) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default_value);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("hmac_auth: '{field}' must be an unsigned integer, got: {value}"))
}

/// Build Ferrum HMAC signing-base version 1. Fields are newline-separated:
/// `ferrum-hmac-v1\n{NAMESPACE}\n{USERNAME}\n{AUTHORITY}\n{METHOD}\n{PATH}\n{QUERY}\n{DATE}\n{DIGEST}`.
///
/// `query` is the raw request query string as received (percent-encoded, no
/// leading `?`), empty when the request has no query. Binding it prevents an
/// attacker from replaying a captured signature against the same path with
/// altered or added query parameters. Clients must sign the byte-for-byte raw
/// query string the gateway receives.
fn build_signing_string(credential: &auth_flow::HmacAuthCredential) -> String {
    let mut signing_string = String::with_capacity(
        HMAC_SIGNING_VERSION.len()
            + credential.namespace.len()
            + credential.username.len()
            + credential.authority.len()
            + credential.method.len()
            + credential.path.len()
            + credential.query.len()
            + credential.date.len()
            + credential.digest_header.len()
            + 8,
    );
    signing_string.push_str(HMAC_SIGNING_VERSION);
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
    signing_string
}

#[cfg(test)]
mod tests {
    //! Inline tests for `pub(crate)` helpers. Public API tests live in
    //! `tests/unit/plugins/hmac_auth_tests.rs`.

    use super::HmacAuth;
    use base64::Engine as _;
    use sha2::{Digest, Sha256, Sha512};

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
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }

    #[test]
    fn verify_body_digest_accepts_correct_sha512() {
        let body = b"hello world";
        let digest = sha512_digest_header(body);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }

    #[test]
    fn verify_body_digest_rejects_wrong_body() {
        let body = b"hello world";
        let digest = sha256_digest_header(body);
        assert!(!HmacAuth::verify_body_digest(&digest, b"hello WORLD"));
    }

    #[test]
    fn verify_body_digest_rejects_unknown_algorithm() {
        let body = b"hello world";
        // sha-1 is not supported by the verifier.
        let digest = "sha-1=abc123==";
        assert!(!HmacAuth::verify_body_digest(digest, body));
    }

    #[test]
    fn verify_body_digest_rejects_garbage_value() {
        let body = b"hello world";
        let digest = "sha-256=not-valid-base64!!!";
        assert!(!HmacAuth::verify_body_digest(digest, body));
    }

    #[test]
    fn verify_body_digest_handles_empty_body() {
        let body = b"";
        let digest = sha256_digest_header(body);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }

    #[test]
    fn verify_body_digest_accepts_multiple_entries() {
        // Per RFC 3230 the receiver picks any matching entry. The first one
        // is unsupported (md5), the second is correct sha-256.
        let body = b"hello";
        let valid = sha256_digest_header(body);
        let combined = format!("md5=ignored, {}", valid);
        assert!(HmacAuth::verify_body_digest(&combined, body));
    }

    #[test]
    fn verify_body_digest_accepts_rfc9530_byte_sequence_form() {
        // RFC 9530 wraps the byte sequence in `:base64:`.
        let body = b"hello";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let digest = format!("sha-256=:{}:", b64);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }
}
