//! Cross-Origin Resource Sharing (CORS) plugin.
//!
//! Handles preflight OPTIONS requests and injects CORS response headers
//! (`Access-Control-Allow-Origin`, `-Methods`, `-Headers`, `-Credentials`, etc.).
//!
//! Supports exact origin matching and wildcard subdomain patterns (e.g.,
//! `"*.company.com"` matches `https://app.company.com`). When `allowed_origins`
//! contains `"*"`, all origins are allowed. Native preflight requests are
//! short-circuited with a 204 response unless forwarding is configured; Istio
//! projections preserve that API's local-200 and unmatched-request behavior.
//!
//! In addition to the plain-string forms, `allowed_origins` entries may be
//! Istio `StringMatch`-shaped objects — `{"exact": ...}`, `{"prefix": ...}`, or
//! `{"regex": ...}` — so a VirtualService `corsPolicy` that uses `exact` /
//! `prefix` / `regex` origin matchers can be projected onto this plugin.
//!
//! The two families are deliberately SEPARATE matcher semantics and must not be
//! conflated (issue #3254):
//!
//! - a plain STRING entry is NATIVE syntax: `"*"` is allow-all,
//!   `"*.company.com"` is the wildcard-subdomain pattern, and anything else is
//!   an exact origin canonicalized once at config time and compared
//!   case-insensitively;
//! - an OBJECT `{"exact": ...}` entry is Istio `StringMatch.exact`: a LITERAL,
//!   byte-for-byte, case-sensitive comparison against the request `Origin`
//!   header with no canonicalization and no wildcard interpretation. That is
//!   what makes `{"exact": "*.example.com"}` representable: it stays the
//!   literal string upstream assigns it and is NEVER reinterpreted as the
//!   native wildcard-subdomain syntax (which would widen the policy to every
//!   subdomain). The single documented exception is `{"exact": "*"}`, which
//!   Istio itself defines as allow-all.
//!
//! `prefix` is a literal byte-prefix of the request `Origin` header; `regex` is
//! an RE2 full match of the entire `Origin` (same semantics Ferrum already
//! applies to Istio `StringMatch` elsewhere), compiled once at config
//! construction/reload under the explicit byte/complexity/count bounds below
//! (issue #3253) — never per request. A matching origin is reflected verbatim
//! into `Access-Control-Allow-Origin`.

use async_trait::async_trait;
use http::Method;
use http::header::HeaderName;
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tracing::{debug, warn};
use url::Url;

use super::{Plugin, PluginResult, RequestContext};

/// Discrete response fields `finalize_cors_response` can write that sit
/// outside the open-ended `access-control-` family. Built once per process and
/// shared by both the per-instance plugin and the cache-internal finalizer.
///
/// `vary` is the only such field today: `cors_headers` merges a token list into
/// it, and a backend trailer could otherwise overwrite that merge. Every
/// `access-control-*` name — including trailer-only extensions the finite write
/// list never enumerates — is covered by [`CORS_RESPONSE_POLICY_PREFIXES`].
static CORS_RESPONSE_POLICY_NAMES: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["vary".to_string()]);

/// Open-ended CORS response-header family. Mirrors the case-insensitive
/// `access-control-` prefix `remove_access_control_headers` strips on every
/// CORS-owned response, so a trailer-only extension name
/// (`access-control-allow-private-network`, …) cannot bypass sanitization
/// merely by being absent from the finite write list and the initial map.
static CORS_RESPONSE_POLICY_PREFIXES: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["access-control-".to_string()]);

const DEFAULT_ALLOWED_METHODS: &[&str] =
    &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const DEFAULT_ALLOWED_HEADERS: &[&str] = &[
    "Accept",
    "Authorization",
    "Content-Type",
    "Origin",
    "X-Requested-With",
];
const ACCESS_CONTROL_HEADER_PREFIX: &[u8] = b"access-control-";

pub(crate) const CORS_FINALIZER_NAME: &str = "__cors_finalizer";

// ── Origin-matcher bounds (issue #3253) ───────────────────────────────────
//
// Every bound below is EXPLICIT and shared. The `cors` plugin, the Istio
// VirtualService translator (`config_sources::k8s::istio`), and the
// native/file mesh validator (`modes::mesh::config`) all admit origin matchers
// through these same predicates, so a matcher that passes a config boundary can
// never fail `CorsPlugin` construction later, and an over-budget matcher is
// refused with a field-specific diagnostic rather than dropped, approximated,
// or widened.

/// Maximum number of `allowed_origins` entries in ONE policy. A CORS policy is
/// evaluated linearly per cross-origin request, so an unbounded matcher list is
/// a per-request cost multiplier; 64 covers every realistic origin allow-list.
pub(crate) const MAX_ALLOWED_ORIGIN_ENTRIES: usize = 64;

/// Maximum byte length of a single origin matcher value (exact literal, native
/// string, prefix, or regex pattern). Real origins are well under 512 bytes;
/// the bound keeps a hostile source resource from shipping a megabyte pattern
/// into every proxy's plugin cache.
pub(crate) const MAX_ORIGIN_MATCHER_BYTES: usize = 512;

/// Compiled-program byte ceiling for one origin regex. The regex crate is
/// finite-automaton based (no catastrophic backtracking), but an adversarial
/// pattern can still compile to a very large program; bound it explicitly
/// instead of inheriting the crate default (10 MiB).
const ORIGIN_REGEX_SIZE_LIMIT: usize = 64 * 1024;

/// Lazy-DFA cache ceiling for one origin regex, bounding per-match memory.
const ORIGIN_REGEX_DFA_SIZE_LIMIT: usize = 64 * 1024;

/// Maximum AST nesting depth for one origin regex — the explicit complexity
/// bound (the crate default is 250).
const ORIGIN_REGEX_NEST_LIMIT: u32 = 24;

const CORS_CONFIG_KEYS: &[&str] = &[
    "allowed_origins",
    "allowed_methods",
    "allowed_headers",
    "exposed_headers",
    "allow_credentials",
    "max_age",
    "preflight_continue",
    "unmatched_preflights",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnmatchedPreflights {
    /// Native direct-plugin behavior: reject an unmatched origin.
    Reject,
    /// Istio `UNSPECIFIED` / `FORWARD`: send an unmatched preflight upstream.
    Forward,
    /// Istio `IGNORE`: answer an unmatched preflight locally without CORS fields.
    Ignore,
}

/// Private per-request aggregate used by a contiguous chain of CORS instances.
///
/// The plugin cache inserts one [`CorsFinalizer`] after the chain. Individual
/// instances stage their decisions here, and the finalizer emits exactly one
/// response policy after every instance has evaluated the request. Keeping the
/// aggregate out of public metadata prevents internal policy details from
/// entering transaction logs.
#[derive(Debug, Clone, Default)]
pub(crate) struct CorsRequestState {
    policy_count: usize,
    is_preflight: bool,
    response_allowed: bool,
    all_wildcard: bool,
    allow_credentials: bool,
    allowed_methods: Option<Arc<Vec<String>>>,
    allowed_method_union: Option<Vec<String>>,
    allowed_headers: Option<Arc<Vec<String>>>,
    allowed_header_union: Option<Vec<String>>,
    exposed_headers: Option<Arc<Vec<String>>>,
    max_age: Option<Option<u64>>,
    forward_preflight: bool,
    ignore_preflight: bool,
    istio_policy_seen: bool,
    native_policy_seen: bool,
    sanitize_response: bool,
    pub(crate) defer_finalization: bool,
}

impl CorsRequestState {
    fn begin_policy(&mut self, is_preflight: bool) {
        if self.policy_count == 0 {
            self.is_preflight = is_preflight;
            self.response_allowed = true;
            self.all_wildcard = true;
            self.allow_credentials = true;
        }
        self.policy_count += 1;
    }

    fn stage_matching_policy(&mut self, plugin: &CorsPlugin, is_preflight: bool) {
        self.sanitize_response = true;
        self.all_wildcard &= matches!(&plugin.allowed_origins, AllowedOrigins::Wildcard);
        self.allow_credentials &= plugin.allow_credentials;
        intersect_only(&mut self.exposed_headers, &plugin.exposed_headers);
        if is_preflight {
            intersect_values(
                &mut self.allowed_methods,
                &mut self.allowed_method_union,
                &plugin.allowed_methods,
            );
            intersect_values(
                &mut self.allowed_headers,
                &mut self.allowed_header_union,
                &plugin.allowed_headers,
            );
            self.max_age = Some(match self.max_age.take() {
                None => plugin.max_age,
                Some(existing) => match (existing, plugin.max_age) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    _ => None,
                },
            });
        }
    }
}

fn intersect_only(intersection: &mut Option<Arc<Vec<String>>>, values: &Arc<Vec<String>>) {
    match intersection.take() {
        None => *intersection = Some(Arc::clone(values)),
        Some(existing) => {
            let mut narrowed = existing.as_ref().clone();
            narrowed.retain(|value| contains_ascii_case(values, value));
            *intersection = Some(Arc::new(narrowed));
        }
    }
}

fn contains_ascii_case(values: &[String], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(candidate))
}

fn intersect_values(
    intersection: &mut Option<Arc<Vec<String>>>,
    union: &mut Option<Vec<String>>,
    values: &Arc<Vec<String>>,
) {
    match intersection.take() {
        None => *intersection = Some(Arc::clone(values)),
        Some(existing) => {
            let union = union.get_or_insert_with(|| existing.as_ref().clone());
            for value in values.iter() {
                if !contains_ascii_case(union, value) {
                    union.push(value.clone());
                }
            }
            let mut narrowed = existing.as_ref().clone();
            narrowed.retain(|value| contains_ascii_case(values, value));
            *intersection = Some(Arc::new(narrowed));
        }
    }
}

/// A single origin pattern entry.
#[derive(Debug, Clone)]
enum OriginPattern {
    /// NATIVE exact origin match (case-insensitive) against the canonicalized
    /// origin, e.g. `"https://app.company.com"`. Produced by the plain-string
    /// config form only.
    Exact(String),
    /// Istio `StringMatch.exact` on the request `Origin` header: a LITERAL,
    /// byte-for-byte, case-sensitive comparison with NO canonicalization and NO
    /// wildcard interpretation (issue #3254).
    ///
    /// This variant exists so a source `exact` that merely LOOKS like native
    /// wildcard syntax (`*.example.com`) keeps its upstream literal meaning
    /// instead of being reinterpreted as [`OriginPattern::WildcardSubdomain`],
    /// which would authorize every subdomain the source never matched. It is
    /// also why a non-canonical literal (`https://Example.com:443`) is
    /// preserved verbatim rather than widened to the browser serialization.
    LiteralExact(String),
    /// Wildcard subdomain match, e.g. `"*.company.com"`.
    ///
    /// Stores the suffix to match against (e.g. `".company.com"`).
    /// Matches any origin whose host part ends with the suffix, so
    /// `*.company.com` matches `https://app.company.com` and
    /// `https://deep.sub.company.com` but NOT `https://company.com`.
    WildcardSubdomain(String),
    /// Istio `StringMatch.prefix` on the request `Origin` header: the origin
    /// must START WITH this literal string (case-sensitive, matching Istio's
    /// literal prefix semantics — e.g. `"https://app."` matches
    /// `https://app.company.com`).
    Prefix(String),
    /// Istio `StringMatch.regex` on the request `Origin` header: the compiled
    /// RE2 pattern must FULLY match the entire origin. Compiled once at config
    /// time under the explicit program, DFA, and nesting limits below (no
    /// catastrophic backtracking — the engine is finite-automaton based); an
    /// invalid or over-budget pattern is rejected at config validation, never
    /// panicked on.
    Regex(Regex),
}

/// How allowed origins are configured.
#[derive(Debug)]
enum AllowedOrigins {
    /// Any origin is allowed (`["*"]` or any list containing `"*"`).
    Wildcard,
    /// Only the listed patterns are allowed (exact or wildcard subdomain).
    List(Vec<OriginPattern>),
}

/// CORS (Cross-Origin Resource Sharing) plugin.
///
/// Handles preflight OPTIONS requests at the gateway level and injects the
/// appropriate CORS response headers on actual cross-origin requests, so
/// backend services do not need to implement CORS themselves.
pub struct CorsPlugin {
    allowed_origins: AllowedOrigins,
    allowed_methods: Arc<Vec<String>>,
    allowed_headers: Arc<Vec<String>>,
    exposed_headers: Arc<Vec<String>>,
    allow_credentials: bool,
    max_age: Option<u64>,
    preflight_continue: bool,
    unmatched_preflights: UnmatchedPreflights,
}

impl CorsPlugin {
    fn remove_access_control_headers(response_headers: &mut HashMap<String, String>) {
        response_headers.retain(|key, _| {
            !key.as_bytes()
                .get(..ACCESS_CONTROL_HEADER_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(ACCESS_CONTROL_HEADER_PREFIX))
        });
    }

    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "cors: configuration must be a JSON object".to_string())?;
        for (key, value) in object {
            if !CORS_CONFIG_KEYS.contains(&key.as_str()) {
                return Err(format!("cors: unknown configuration key '{key}'"));
            }
            if value.is_null() {
                return Err(format!(
                    "cors: '{key}' must not be null; omit the field to use its default"
                ));
            }
        }

        let unmatched_preflights = match object.get("unmatched_preflights") {
            None => UnmatchedPreflights::Reject,
            Some(Value::String(value)) if value == "forward" => UnmatchedPreflights::Forward,
            Some(Value::String(value)) if value == "ignore" => UnmatchedPreflights::Ignore,
            Some(Value::String(value)) => {
                return Err(format!(
                    "cors: 'unmatched_preflights' must be 'forward' or 'ignore', got: {value}"
                ));
            }
            Some(other) => {
                return Err(format!(
                    "cors: 'unmatched_preflights' must be a string, got: {other}"
                ));
            }
        };
        let istio_semantics = unmatched_preflights != UnmatchedPreflights::Reject;
        let allowed_origins = Self::parse_origins(config)?;

        let allowed_methods = Self::parse_string_array(
            config,
            "allowed_methods",
            DEFAULT_ALLOWED_METHODS,
            istio_semantics,
            validate_method,
        )?;
        let allowed_headers = Self::parse_string_array(
            config,
            "allowed_headers",
            DEFAULT_ALLOWED_HEADERS,
            istio_semantics,
            validate_header_name,
        )?;
        let exposed_headers =
            Self::parse_string_array(config, "exposed_headers", &[], true, validate_header_name)?;

        let mut allow_credentials = bool_config(config, "allow_credentials", false)?;
        let max_age = match object.get("max_age") {
            Some(_) => Some(u64_config(config, "max_age", 86400)?),
            None if istio_semantics => None,
            None => Some(86400),
        };
        let preflight_continue = bool_config(config, "preflight_continue", false)?;
        if istio_semantics && object.contains_key("preflight_continue") {
            return Err(
                "cors: 'preflight_continue' cannot be combined with Istio 'unmatched_preflights' semantics"
                    .to_string(),
            );
        }

        // Per CORS spec: Access-Control-Allow-Origin: * cannot be used with credentials.
        if allow_credentials && matches!(&allowed_origins, AllowedOrigins::Wildcard) {
            warn!(
                "cors: allow_credentials=true is incompatible with wildcard origins; \
                 credentials will be disabled. Specify explicit origins to use credentials."
            );
            allow_credentials = false;
        }

        Ok(Self {
            allowed_origins,
            allowed_methods: Arc::new(allowed_methods),
            allowed_headers: Arc::new(allowed_headers),
            exposed_headers: Arc::new(exposed_headers),
            allow_credentials,
            max_age,
            preflight_continue,
            unmatched_preflights,
        })
    }

    /// Parse the `allowed_origins` config field.
    ///
    /// Supports plain-string forms:
    /// - `["*"]` or any list containing `"*"` → `AllowedOrigins::Wildcard`
    /// - `["https://example.com"]` → exact match
    /// - `["*.company.com"]` → wildcard subdomain (matches any `*.company.com`)
    ///
    /// and Istio `StringMatch`-shaped object forms (so a VirtualService
    /// `corsPolicy` with `exact` / `prefix` / `regex` origin matchers can
    /// project here):
    /// - `[{"exact": "https://example.com"}]` → LITERAL byte-exact match of the
    ///   `Origin` header — NOT the canonicalizing, case-insensitive plain-string
    ///   form, so `{"exact": "*.example.com"}` stays the literal string it is
    ///   upstream instead of becoming native wildcard-subdomain syntax
    /// - `[{"prefix": "https://app."}]` → literal byte-prefix of the `Origin`
    /// - `[{"regex": "https://.*\\.example\\.com"}]` → RE2 full match of the
    ///   `Origin`
    ///
    /// String and object entries can be mixed. An object entry must carry
    /// exactly one of `exact` / `prefix` / `regex`. The list length and every
    /// entry's byte length are bounded ([`MAX_ALLOWED_ORIGIN_ENTRIES`] /
    /// [`MAX_ORIGIN_MATCHER_BYTES`]) with a field-specific error — never a
    /// silent truncation.
    fn parse_origins(config: &Value) -> Result<AllowedOrigins, String> {
        match config.get("allowed_origins") {
            None => Err(
                "cors: 'allowed_origins' is required; use ['*'] for intentional allow-all"
                    .to_string(),
            ),
            Some(Value::Array(arr)) => {
                if arr.is_empty() {
                    return Err(
                        "cors: 'allowed_origins' must contain at least one origin or '*'"
                            .to_string(),
                    );
                }
                validate_origin_matcher_count(arr.len())?;

                let mut patterns = Vec::with_capacity(arr.len());
                let mut wildcard = false;
                for value in arr {
                    match value {
                        Value::String(_) => {
                            // Safe: matched `Value::String`.
                            let raw_origin = value.as_str().unwrap_or_default();
                            let origin = raw_origin.trim();
                            if origin.is_empty() {
                                return Err(
                                    "cors: 'allowed_origins' entries must be non-empty strings"
                                        .to_string(),
                                );
                            }
                            if origin.len() != raw_origin.len() {
                                return Err(
                                    "cors: 'allowed_origins' string entries must not have leading or trailing whitespace"
                                        .to_string(),
                                );
                            }
                            if origin == "*" {
                                wildcard = true;
                                continue;
                            }
                            validate_origin_matcher_len("'allowed_origins' string entry", origin)?;
                            if origin.starts_with('*') {
                                patterns.push(OriginPattern::WildcardSubdomain(
                                    validate_wildcard_origin(origin)?,
                                ));
                            } else {
                                patterns
                                    .push(OriginPattern::Exact(canonicalize_exact_origin(origin)?));
                            }
                        }
                        Value::Object(_) => match Self::parse_origin_matcher(value)? {
                            Some(pattern) => patterns.push(pattern),
                            None => wildcard = true,
                        },
                        other => {
                            return Err(format!(
                                "cors: 'allowed_origins' entries must be strings or \
                                 {{exact|prefix|regex}} objects, got: {other}"
                            ));
                        }
                    }
                }

                if wildcard {
                    Ok(AllowedOrigins::Wildcard)
                } else {
                    Ok(AllowedOrigins::List(patterns))
                }
            }
            Some(other) => Err(format!(
                "cors: 'allowed_origins' must be an array of strings or \
                 {{exact|prefix|regex}} objects, got: {other}"
            )),
        }
    }

    /// Parse a single Istio `StringMatch`-shaped origin matcher object
    /// (`{"exact": ...}` / `{"prefix": ...}` / `{"regex": ...}`). Exactly one of
    /// the three keys must be present and a non-empty string. The `regex`
    /// pattern is compiled here (config time) under explicit bounds so an
    /// invalid or over-budget pattern is a config error, never a request-path
    /// panic or per-request cost.
    ///
    /// `exact` is LITERAL here (issue #3254) — see
    /// [`OriginPattern::LiteralExact`]. Do not route it through
    /// [`canonicalize_exact_origin`]: that predicate belongs to the native
    /// plain-string form, and applying it to an Istio matcher would both reject
    /// representable literals (`*.example.com`) and widen non-canonical ones to
    /// the browser serialization the source never matched.
    fn parse_origin_matcher(value: &Value) -> Result<Option<OriginPattern>, String> {
        // Istio `StringMatch` contract: EXACTLY ONE recognized key, and nothing
        // else. Reject unknown keys, extra keys, or a non-string value rather
        // than silently coercing — mirrors
        // `config_sources::k8s::string_match_has_exactly_one_supported_operator`
        // used for Istio request matchers. Without this, a malformed config like
        // `{"prefix":"x","regex":123}` would slip through as a bare prefix
        // matcher, dropping the invalid second key.
        const MATCHER_KEYS: [&str; 3] = ["exact", "prefix", "regex"];
        let obj = value.as_object().ok_or_else(|| {
            "cors: 'allowed_origins' object matcher must be a JSON object with one of \
             'exact', 'prefix', or 'regex'"
                .to_string()
        })?;
        if obj.len() != 1 || !obj.keys().all(|key| MATCHER_KEYS.contains(&key.as_str())) {
            return Err(
                "cors: 'allowed_origins' object matcher must specify exactly one of \
                 'exact', 'prefix', or 'regex' (no extra or unknown keys)"
                    .to_string(),
            );
        }
        let exact = value.get("exact").and_then(Value::as_str);
        let prefix = value.get("prefix").and_then(Value::as_str);
        let regex = value.get("regex").and_then(Value::as_str);

        match (exact, prefix, regex) {
            (Some(exact), None, None) => {
                // Istio explicitly assigns exact `*` allow-all semantics; every
                // OTHER value stays a literal, including one that looks like
                // native wildcard syntax.
                if exact == "*" {
                    return Ok(None);
                }
                validate_literal_exact_origin(exact)?;
                Ok(Some(OriginPattern::LiteralExact(exact.to_string())))
            }
            (None, Some(prefix), None) => {
                // Istio prefix is a literal string prefix of the Origin header;
                // do NOT trim (leading/trailing spaces would change matching)
                // beyond rejecting an all-empty value. An empty prefix would
                // match every origin (an open CORS policy by accident), so it
                // is rejected rather than silently allow-all.
                validate_origin_prefix(prefix)?;
                Ok(Some(OriginPattern::Prefix(prefix.to_string())))
            }
            (None, None, Some(regex)) => {
                Ok(Some(OriginPattern::Regex(compile_origin_regex(regex)?)))
            }
            (None, None, None) => Err(
                "cors: 'allowed_origins' object matcher must specify one of \
                 'exact', 'prefix', or 'regex'"
                    .to_string(),
            ),
            _ => Err(
                "cors: 'allowed_origins' object matcher must specify exactly one of \
                 'exact', 'prefix', or 'regex'"
                    .to_string(),
            ),
        }
    }

    /// Parse a JSON array of strings with a fallback default.
    fn parse_string_array(
        config: &Value,
        key: &str,
        defaults: &[&str],
        allow_empty: bool,
        validate: fn(&str, &str) -> Result<(), String>,
    ) -> Result<Vec<String>, String> {
        match config.get(key) {
            None => {
                if allow_empty {
                    Ok(Vec::new())
                } else {
                    Ok(defaults.iter().map(|s| (*s).to_string()).collect())
                }
            }
            Some(Value::Array(arr)) => {
                if arr.is_empty() && !allow_empty {
                    return Err(format!("cors: '{key}' must contain at least one value"));
                }
                let mut values = Vec::with_capacity(arr.len());
                for value in arr {
                    let value = value.as_str().ok_or_else(|| {
                        format!("cors: '{key}' entries must be strings, got: {value}")
                    })?;
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        return Err(format!("cors: '{key}' entries must be non-empty strings"));
                    }
                    if trimmed.len() != value.len() {
                        return Err(format!(
                            "cors: '{key}' entries must not have leading or trailing whitespace"
                        ));
                    }
                    validate(key, value)?;
                    values.push(value.to_string());
                }
                Ok(values)
            }
            Some(other) => Err(format!(
                "cors: '{key}' must be an array of strings, got: {other}"
            )),
        }
    }

    /// Check whether a request origin is allowed.
    ///
    /// For `Exact` patterns (native plain strings): case-insensitive
    /// full-string match against the canonicalized origin.
    /// For `LiteralExact` patterns (Istio `StringMatch.exact`): byte-for-byte
    /// case-sensitive equality with the raw `Origin` header.
    /// For `WildcardSubdomain` patterns: the origin's host portion must end
    /// with the stored suffix (e.g. `.company.com`). This means
    /// `*.company.com` matches `https://app.company.com` but NOT
    /// `https://company.com` (bare domain has no subdomain prefix).
    /// For `Prefix` patterns (Istio `StringMatch.prefix`): the origin must
    /// start with the literal prefix (case-sensitive).
    /// For `Regex` patterns (Istio `StringMatch.regex`): the compiled RE2
    /// pattern must FULLY match the entire origin (same anchoring Ferrum
    /// applies to Istio `StringMatch` regex elsewhere).
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if origin.is_empty() {
            return false;
        }
        match &self.allowed_origins {
            AllowedOrigins::Wildcard => true,
            AllowedOrigins::List(patterns) => patterns.iter().any(|p| match p {
                OriginPattern::Exact(expected) => expected.eq_ignore_ascii_case(origin),
                // Istio `StringMatch.exact`: literal, case-sensitive, no
                // canonicalization. Allocation-free on the hot path.
                OriginPattern::LiteralExact(expected) => expected == origin,
                OriginPattern::WildcardSubdomain(suffix) => origin_host(origin)
                    .is_some_and(|host| ascii_ends_with_ignore_case(host, suffix.as_str())),
                OriginPattern::Prefix(prefix) => origin.starts_with(prefix.as_str()),
                // The compiled pattern is anchored at parse time
                // (`anchor_regex_pattern`), so a full-string match is exactly
                // `is_match` — and it tries every alternation branch, unlike the
                // first unanchored `find`.
                OriginPattern::Regex(re) => re.is_match(origin),
            }),
        }
    }

    fn maybe_finalize_request(&self, ctx: &mut RequestContext) -> PluginResult {
        if ctx.cors_state.defer_finalization {
            PluginResult::Continue
        } else {
            finalize_cors_request(ctx)
        }
    }
}

#[async_trait]
impl Plugin for CorsPlugin {
    fn name(&self) -> &str {
        "cors"
    }

    fn priority(&self) -> u16 {
        super::priority::CORS
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // gRPC-Web is selected through the gRPC request-policy chain even
        // though browsers still require ordinary Origin/ACAO enforcement.
        super::HTTP_GRPC_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Record policy ownership before checking Origin. A participating
        // translated Istio policy owns every Access-Control-* response field
        // even when Origin is absent, preventing a shared-cache replay from
        // widening the gateway policy.
        if self.unmatched_preflights == UnmatchedPreflights::Reject {
            ctx.cors_state.native_policy_seen = true;
        } else {
            ctx.cors_state.istio_policy_seen = true;
        }

        // Only act on requests that include an Origin header
        let origin = match ctx.headers.get("origin") {
            Some(o) => o.clone(),
            None => return PluginResult::Continue,
        };

        // Detect preflight: OPTIONS with Access-Control-Request-Method header
        let is_preflight =
            ctx.method == "OPTIONS" && ctx.headers.contains_key("access-control-request-method");

        ctx.cors_state.begin_policy(is_preflight);
        let origin_allowed = self.is_origin_allowed(&origin);
        if !is_preflight {
            if !origin_allowed {
                ctx.cors_state.response_allowed = false;
                // Istio/Envoy forwards unmatched actual requests. Ferrum
                // preserves the upstream status/body but removes upstream
                // CORS authorization fields. Native direct-plugin policy
                // retains its historical fail-closed 403.
                if self.unmatched_preflights != UnmatchedPreflights::Reject {
                    return self.maybe_finalize_request(ctx);
                }
                debug!("cors: request rejected for disallowed origin '{}'", origin);
                return PluginResult::Reject {
                    status_code: 403,
                    body: "CORS origin not allowed".to_string(),
                    headers: HashMap::new(),
                };
            }
            ctx.cors_state.stage_matching_policy(self, false);
            ctx.metadata
                .insert("cors_origin".to_string(), origin.clone());
            return self.maybe_finalize_request(ctx);
        }

        // --- Preflight handling ---

        if !origin_allowed {
            ctx.cors_state.response_allowed = false;
            if self.preflight_continue {
                ctx.cors_state.sanitize_response = true;
                ctx.cors_state.forward_preflight = true;
                return self.maybe_finalize_request(ctx);
            }
            match self.unmatched_preflights {
                UnmatchedPreflights::Forward => {
                    ctx.cors_state.forward_preflight = true;
                    return self.maybe_finalize_request(ctx);
                }
                UnmatchedPreflights::Ignore => {
                    ctx.cors_state.ignore_preflight = true;
                    return self.maybe_finalize_request(ctx);
                }
                UnmatchedPreflights::Reject => {}
            }
            debug!(
                "cors: preflight rejected for disallowed origin '{}'",
                origin
            );
            return PluginResult::Reject {
                status_code: 403,
                body: "CORS origin not allowed".to_string(),
                headers: HashMap::new(),
            };
        }

        ctx.cors_state.stage_matching_policy(self, true);
        ctx.metadata
            .insert("cors_origin".to_string(), origin.clone());

        // Native backend-handled preflights keep the backend's status/body,
        // but the final response policy is rebuilt from the gateway config.
        if self.preflight_continue {
            ctx.cors_state.forward_preflight = true;
            return self.maybe_finalize_request(ctx);
        }

        // Preserve the native direct-plugin's explicit method rejection.
        // Istio/Envoy instead emits its configured list (possibly empty) and
        // lets the browser decide whether that list authorizes the request.
        if self.unmatched_preflights == UnmatchedPreflights::Reject
            && let Some(requested_method) = ctx.headers.get("access-control-request-method")
        {
            let method_allowed = self
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(requested_method));
            if !method_allowed {
                ctx.cors_state.response_allowed = false;
                debug!(
                    "cors: preflight rejected method '{}' for origin '{}'",
                    requested_method, origin
                );
                let mut body = String::with_capacity(
                    "CORS method not allowed: ".len() + requested_method.len(),
                );
                body.push_str("CORS method not allowed: ");
                body.push_str(requested_method);
                return PluginResult::Reject {
                    status_code: 403,
                    body,
                    headers: HashMap::new(),
                };
            }
        }

        debug!("cors: preflight approved for origin '{}'", origin);
        self.maybe_finalize_request(ctx)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.cors_state.defer_finalization {
            PluginResult::Continue
        } else {
            finalize_cors_response(ctx, response_headers)
        }
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        !ctx.cors_state.defer_finalization
            && ctx.cors_state.policy_count > 0
            && ctx.cors_state.response_allowed
            && ctx.metadata.contains_key("cors_origin")
            && name
                .get(.."access-control-".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("access-control-"))
    }

    /// The CORS response headers are the browser's entire cross-origin
    /// authorization decision. A backend trailer repeating one of them lands
    /// after `after_proxy` and could hand the client a second, contradictory
    /// `Access-Control-Allow-Origin` — and a backend that echoes the identical
    /// value is invisible to observed-mutation reconciliation. Ownership is the
    /// open-ended `access-control-` prefix `remove_access_control_headers`
    /// already strips, plus `vary` for the merge outside that family.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::NamesAndPrefixes {
            names: &CORS_RESPONSE_POLICY_NAMES,
            prefixes: &CORS_RESPONSE_POLICY_PREFIXES,
        }
    }
}

/// Cache-internal boundary after a contiguous set of CORS instances.
pub(crate) struct CorsFinalizer {
    priority: u16,
}

impl CorsFinalizer {
    pub(crate) fn new(priority: u16) -> Self {
        Self { priority }
    }
}

#[async_trait]
impl Plugin for CorsFinalizer {
    fn name(&self) -> &str {
        CORS_FINALIZER_NAME
    }

    fn priority(&self) -> u16 {
        self.priority
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        finalize_cors_request(ctx)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        finalize_cors_response(ctx, response_headers)
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        ctx.cors_state.policy_count > 0
            && ctx.cors_state.response_allowed
            && ctx.metadata.contains_key("cors_origin")
            && name
                .get(.."access-control-".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("access-control-"))
    }

    /// Same ownership contract as the per-instance plugin: this finalizer is
    /// the phase that actually writes the deferred CORS response headers, so it
    /// declares the same prefix family plus `vary`.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::NamesAndPrefixes {
            names: &CORS_RESPONSE_POLICY_NAMES,
            prefixes: &CORS_RESPONSE_POLICY_PREFIXES,
        }
    }
}

fn cors_reject(body: String) -> PluginResult {
    PluginResult::Reject {
        status_code: 403,
        body,
        headers: HashMap::new(),
    }
}

fn finalize_cors_request(ctx: &mut RequestContext) -> PluginResult {
    let state = &ctx.cors_state;
    if state.policy_count == 0 {
        return PluginResult::Continue;
    }

    // Requested methods and headers are preflight policy. For multiple
    // policies, reject a preflight value one instance authorizes but the
    // aggregate intersection does not. Actual requests evaluate only the
    // origin/credentials/exposure policy appropriate to that phase; browsers
    // do not repeat Access-Control-Request-* on the actual request.
    if state.policy_count > 1 && state.is_preflight {
        let methods = state
            .allowed_methods
            .as_ref()
            .map(|values| values.as_slice())
            .unwrap_or_default();
        let method_union = state.allowed_method_union.as_deref().unwrap_or_default();
        if let Some(requested_method) = ctx.headers.get("access-control-request-method")
            && contains_ascii_case(method_union, requested_method)
            && !contains_ascii_case(methods, requested_method)
        {
            let mut body =
                String::with_capacity("CORS method not allowed: ".len() + requested_method.len());
            body.push_str("CORS method not allowed: ");
            body.push_str(requested_method);
            return cors_reject(body);
        }
        if let Some(requested_headers) = ctx.headers.get("access-control-request-headers") {
            let headers = state
                .allowed_headers
                .as_ref()
                .map(|values| values.as_slice())
                .unwrap_or_default();
            let header_union = state.allowed_header_union.as_deref().unwrap_or_default();
            for requested in requested_headers.split(',').map(str::trim) {
                if !requested.is_empty()
                    && contains_ascii_case(header_union, requested)
                    && !contains_ascii_case(headers, requested)
                {
                    let mut body =
                        String::with_capacity("CORS header not allowed: ".len() + requested.len());
                    body.push_str("CORS header not allowed: ");
                    body.push_str(requested);
                    return cors_reject(body);
                }
            }
        }
    }

    if !state.is_preflight {
        return PluginResult::Continue;
    }
    if state.ignore_preflight {
        return PluginResult::Reject {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
        };
    }
    if state.forward_preflight {
        return PluginResult::Continue;
    }

    let headers = cors_headers(ctx, true);
    PluginResult::Reject {
        status_code: if state.istio_policy_seen { 200 } else { 204 },
        body: String::new(),
        headers,
    }
}

fn finalize_cors_response(
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
) -> PluginResult {
    let is_rejection_path = ctx
        .metadata
        .get(crate::proxy::REJECTION_RESPONSE_METADATA_KEY)
        .is_some_and(|value| value == "true");

    // A configured gateway CORS policy must remain authoritative even when an
    // Istio policy forwards an unmatched request. Otherwise a permissive
    // backend could re-authorize a disallowed origin with its own CORS fields.
    let should_sanitize = ctx.cors_state.sanitize_response
        || ctx.cors_state.native_policy_seen
        || ctx.cors_state.istio_policy_seen;
    // Synthetic responses belong to translated Istio policy as soon as its
    // request hook participates, including the no-Origin early return where no
    // policy is counted. Native no-Origin short-circuits retain direct-plugin
    // semantics; native requests with an Origin have a counted policy.
    let policy_owns_rejection = ctx.cors_state.policy_count > 0 || ctx.cors_state.istio_policy_seen;
    if should_sanitize && (!is_rejection_path || policy_owns_rejection) {
        CorsPlugin::remove_access_control_headers(response_headers);
    }
    if ctx.cors_state.policy_count == 0 || !ctx.cors_state.response_allowed {
        return PluginResult::Continue;
    }

    let existing_vary = response_headers.get("vary").cloned();
    let cors_headers = cors_headers(ctx, ctx.cors_state.is_preflight);
    for (name, mut value) in cors_headers {
        if name == "vary" {
            let required = if ctx.cors_state.is_preflight {
                &[
                    "Origin",
                    "Access-Control-Request-Method",
                    "Access-Control-Request-Headers",
                ][..]
            } else {
                &["Origin"][..]
            };
            value = merge_vary_tokens(existing_vary.as_deref(), required);
        }
        response_headers.insert(name, value);
    }
    PluginResult::Continue
}

fn cors_headers(ctx: &RequestContext, preflight: bool) -> HashMap<String, String> {
    let state = &ctx.cors_state;
    let mut headers = HashMap::new();
    let Some(origin) = ctx.metadata.get("cors_origin") else {
        return headers;
    };

    headers.insert(
        "access-control-allow-origin".to_string(),
        if state.all_wildcard && !state.allow_credentials {
            "*".to_string()
        } else {
            origin.clone()
        },
    );
    if state.allow_credentials {
        headers.insert(
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        );
    }
    if let Some(exposed) = state
        .exposed_headers
        .as_ref()
        .filter(|values| !values.is_empty())
    {
        headers.insert(
            "access-control-expose-headers".to_string(),
            exposed.join(", "),
        );
    }
    if preflight {
        if let Some(methods) = state
            .allowed_methods
            .as_ref()
            .filter(|values| !values.is_empty())
        {
            headers.insert(
                "access-control-allow-methods".to_string(),
                methods.join(", "),
            );
        }
        if let Some(allowed) = state
            .allowed_headers
            .as_ref()
            .filter(|values| !values.is_empty())
        {
            headers.insert(
                "access-control-allow-headers".to_string(),
                allowed.join(", "),
            );
        }
        if let Some(Some(max_age)) = state.max_age {
            headers.insert("access-control-max-age".to_string(), max_age.to_string());
        }
    }

    let vary_tokens = if preflight {
        &[
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
        ][..]
    } else {
        &["Origin"][..]
    };
    let vary = merge_vary_tokens(headers.get("vary").map(String::as_str), vary_tokens);
    headers.insert("vary".to_string(), vary);
    headers
}

fn merge_vary_tokens(existing: Option<&str>, required: &[&str]) -> String {
    let mut merged = existing.unwrap_or_default().trim().to_string();
    if merged == "*" {
        return merged;
    }
    for required in required {
        let present = merged
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case(required));
        if present {
            continue;
        }
        if !merged.is_empty() {
            merged.push_str(", ");
        }
        merged.push_str(required);
    }
    merged
}

/// `pub(crate)` like [`canonicalize_exact_origin`]: the K8s translator's
/// `cors_policy_translatable` and the native/file mesh source's
/// `validate_virtual_service_cors_policies` run the same method/header-name
/// admission the plugin applies at construction, so a policy that passes those
/// boundaries can never fail `CorsPlugin` construction later. Do not fork.
pub(crate) fn validate_method(key: &str, value: &str) -> Result<(), String> {
    Method::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| format!("cors: '{key}' contains an invalid HTTP method: {value}"))
}

/// Shared bound on how many `allowed_origins` entries one policy may carry.
/// `pub(crate)` for the same reason as [`validate_method`]: the Istio
/// translator and the native/file mesh validator admit against this exact
/// predicate, so an over-budget list is refused with a field-specific
/// diagnostic at the source boundary instead of failing plugin construction
/// later. Do not fork.
pub(crate) fn validate_origin_matcher_count(count: usize) -> Result<(), String> {
    if count > MAX_ALLOWED_ORIGIN_ENTRIES {
        return Err(format!(
            "cors: 'allowed_origins' must contain at most {MAX_ALLOWED_ORIGIN_ENTRIES} entries, got: {count}"
        ));
    }
    Ok(())
}

/// Shared byte bound for one origin matcher value — see
/// [`validate_origin_matcher_count`]. `label` names the offending field so the
/// diagnostic points at the matcher kind that failed.
pub(crate) fn validate_origin_matcher_len(label: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_ORIGIN_MATCHER_BYTES {
        return Err(format!(
            "cors: {label} exceeds the {MAX_ORIGIN_MATCHER_BYTES}-byte matcher limit (got {} bytes)",
            value.len()
        ));
    }
    Ok(())
}

/// Admission for an Istio `StringMatch.exact` origin matcher (issue #3254).
///
/// LITERAL semantics: the value is preserved byte-for-byte and compared
/// case-sensitively against the raw `Origin` header, so no canonicalization,
/// whitespace trimming, or wildcard interpretation is applied — that is exactly
/// what keeps `*.example.com` from being widened into the native
/// wildcard-subdomain matcher. Only genuinely unusable values are refused: an
/// empty or whitespace-only matcher (it can never equal a real `Origin`, so it
/// is a config mistake, not a policy) and an over-budget one.
///
/// Callers handle Istio's documented allow-all `*` BEFORE this gate.
pub(crate) fn validate_literal_exact_origin(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(
            "cors: 'allowed_origins' exact matcher must be a non-empty, non-whitespace string"
                .to_string(),
        );
    }
    validate_origin_matcher_len("'allowed_origins' exact matcher", value)
}

/// Admission for an Istio `StringMatch.prefix` origin matcher — see
/// [`validate_literal_exact_origin`]. An EMPTY prefix would match every origin
/// (an accidental open CORS policy), so it is refused rather than allowed.
pub(crate) fn validate_origin_prefix(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(
            "cors: 'allowed_origins' prefix matcher must be a non-empty string \
             (an empty prefix would match every origin)"
                .to_string(),
        );
    }
    validate_origin_matcher_len("'allowed_origins' prefix matcher", value)
}

/// Compile one Istio `StringMatch.regex` origin matcher under the explicit
/// bounds of issue #3253. Shared admission gate — see
/// [`validate_origin_matcher_count`].
///
/// Istio `StringMatch.regex` is a FULL match. The pattern is anchored at
/// compile time (the shared Ferrum convention for Istio-style regex, which also
/// strips a redundant leading `^` / trailing `$`) so matching is exactly
/// `is_match` — checking only the first unanchored `find` would reject an
/// Origin that a LATER alternation branch fully matches (e.g.
/// `https://app|https://app\.example\.com` against `https://app.example.com`,
/// where `find` returns the shorter `https://app`).
///
/// Compilation happens ONCE on the config construction/reload path, never per
/// request. The regex crate is finite-automaton based, so a hostile pattern
/// cannot trigger catastrophic backtracking, but size/complexity are still
/// bounded EXPLICITLY rather than inherited: pattern bytes
/// ([`MAX_ORIGIN_MATCHER_BYTES`]), compiled program size
/// ([`ORIGIN_REGEX_SIZE_LIMIT`]), lazy-DFA cache
/// ([`ORIGIN_REGEX_DFA_SIZE_LIMIT`]), and AST nesting
/// ([`ORIGIN_REGEX_NEST_LIMIT`]). Anything that fails is a config error with a
/// field-specific message — never a dropped or approximated matcher.
pub(crate) fn compile_origin_regex(pattern: &str) -> Result<Regex, String> {
    if pattern.is_empty() {
        return Err("cors: 'allowed_origins' regex matcher must be a non-empty string".to_string());
    }
    validate_origin_matcher_len("'allowed_origins' regex matcher", pattern)?;
    let anchored = crate::config::types::anchor_regex_pattern(pattern);
    RegexBuilder::new(&anchored)
        .size_limit(ORIGIN_REGEX_SIZE_LIMIT)
        .dfa_size_limit(ORIGIN_REGEX_DFA_SIZE_LIMIT)
        .nest_limit(ORIGIN_REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| {
            format!(
                "cors: 'allowed_origins' regex matcher '{pattern}' is invalid or exceeds the \
                 configured complexity bounds (size limit {ORIGIN_REGEX_SIZE_LIMIT} bytes, \
                 DFA limit {ORIGIN_REGEX_DFA_SIZE_LIMIT} bytes, nest limit \
                 {ORIGIN_REGEX_NEST_LIMIT}): {e}"
            )
        })
}

/// Shared admission gate — see [`validate_method`].
pub(crate) fn validate_header_name(key: &str, value: &str) -> Result<(), String> {
    HeaderName::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| format!("cors: '{key}' contains an invalid HTTP header name: {value}"))
}

fn validate_wildcard_origin(origin: &str) -> Result<String, String> {
    let Some(suffix) = origin.strip_prefix("*.") else {
        return Err(format!(
            "cors: wildcard origins must use the '*.example.com' form, got: {origin}"
        ));
    };
    if suffix.is_empty()
        || suffix.contains('*')
        || suffix.contains('/')
        || suffix.contains(':')
        || suffix.contains(char::is_whitespace)
    {
        return Err(format!(
            "cors: wildcard origin must be a hostname suffix without scheme, port, path, or whitespace: {origin}"
        ));
    }
    Ok(format!(".{}", suffix.to_ascii_lowercase()))
}

/// Validate and canonicalize an exact origin on the config/reload path.
/// Request matching remains an allocation-free ASCII comparison against this
/// browser-serialized form; no request-time URL parse is introduced.
/// `pub(crate)` because this is the shared admission gate for the K8s Istio
/// translator and native/file mesh validation as well as direct plugin
/// configuration. It governs the NATIVE plain-string form ONLY: Istio
/// `StringMatch.exact` matchers are literal and go through
/// [`validate_literal_exact_origin`] instead, because canonicalizing them would
/// widen the source matcher to the browser serialization it never matched. Do
/// not fork this predicate and do not re-apply it to literal matchers.
pub(crate) fn canonicalize_exact_origin(origin: &str) -> Result<String, String> {
    if origin.contains(char::is_whitespace) {
        return Err(format!(
            "cors: origin must not contain whitespace: {origin:?}"
        ));
    }

    // `url::Url` applies the WHATWG path normalizer while parsing. Inspect the
    // raw bytes first so `/foo/..`, encoded dot segments such as `/%2e%2e`, or
    // backslash path separators cannot collapse to `/` and then be serialized
    // as permission for the whole origin. An empty authority is left for the
    // hostname-specific diagnostic below.
    if let Some((authority, post_authority)) = split_raw_authority(origin)
        && !authority.is_empty()
        && !post_authority.is_empty()
    {
        return Err(format!(
            "cors: origin must be scheme://host[:port] without path, query, or fragment: {origin}"
        ));
    }

    let url = Url::parse(origin).map_err(|e| format!("cors: invalid origin '{origin}': {e}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "cors: origin scheme must be http or https, got: {scheme}"
            ));
        }
    }
    if !has_non_empty_authority(origin) || url.host_str().is_none() {
        return Err(format!("cors: origin must include a hostname: {origin}"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "cors: origin must not include credentials: {origin}"
        ));
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || origin.ends_with('/')
    {
        return Err(format!(
            "cors: origin must be scheme://host[:port] without path, query, or fragment: {origin}"
        ));
    }
    Ok(url.origin().ascii_serialization())
}

fn has_non_empty_authority(origin: &str) -> bool {
    split_raw_authority(origin).is_some_and(|(authority, _)| !authority.is_empty())
}

fn split_raw_authority(origin: &str) -> Option<(&str, &str)> {
    let (_, after_scheme) = origin.split_once(':')?;
    let authority_and_path = after_scheme.strip_prefix("//")?;
    let authority_end = authority_and_path
        .find(['/', '\\', '?', '#'])
        .unwrap_or(authority_and_path.len());

    Some(authority_and_path.split_at(authority_end))
}

fn bool_config(config: &Value, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!("cors: '{key}' must be a boolean, got: {other}")),
    }
}

fn u64_config(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("cors: '{key}' must be a non-negative integer")),
        Some(other) => Err(format!(
            "cors: '{key}' must be a non-negative integer, got: {other}"
        )),
    }
}

fn origin_host(origin: &str) -> Option<&str> {
    let (scheme, rest) = origin.split_once("://")?;
    // Enforce the same http(s) scheme allow-list that `canonicalize_exact_origin`
    // applies to exact origins, so wildcard-subdomain matching is not looser
    // than exact matching. Without this, an Origin like `ftp://app.company.com`
    // would satisfy a `*.company.com` rule and be reflected into
    // Access-Control-Allow-Origin. (Finding #51.)
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    if rest.starts_with('[')
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains(char::is_whitespace)
    {
        return None;
    }
    if rest.contains('/') {
        return None;
    }
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    if host.is_empty()
        || host.contains(':')
        || host.contains("..")
        || port.is_some_and(|port| port.parse::<u16>().is_err())
    {
        return None;
    }
    Some(host)
}

fn ascii_ends_with_ignore_case(value: &str, suffix: &str) -> bool {
    let value = value.as_bytes();
    let suffix = suffix.as_bytes();
    if suffix.len() > value.len() {
        return false;
    }
    value[value.len() - suffix.len()..]
        .iter()
        .zip(suffix.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
