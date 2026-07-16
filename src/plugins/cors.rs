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
//! `{"regex": ...}` — so a VirtualService `corsPolicy` that uses `prefix` /
//! `regex` origin matchers can be projected onto this plugin. `prefix` is a
//! literal byte-prefix of the request `Origin` header; `regex` is an RE2
//! full match of the entire `Origin` (same semantics Ferrum already applies to
//! Istio `StringMatch` elsewhere). A matching origin is reflected verbatim into
//! `Access-Control-Allow-Origin`.

use async_trait::async_trait;
use http::Method;
use http::header::HeaderName;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};
use url::Url;

use super::{Plugin, PluginResult, RequestContext};

const DEFAULT_ALLOWED_METHODS: &[&str] =
    &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const DEFAULT_ALLOWED_HEADERS: &[&str] = &[
    "Accept",
    "Authorization",
    "Content-Type",
    "Origin",
    "X-Requested-With",
];

pub(crate) const CORS_FINALIZER_NAME: &str = "__cors_finalizer";

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
    allowed_methods_header: Option<Arc<str>>,
    allowed_method_union: Option<Vec<String>>,
    allowed_headers: Option<Arc<Vec<String>>>,
    allowed_headers_header: Option<Arc<str>>,
    allowed_header_union: Option<Vec<String>>,
    exposed_headers: Option<Arc<Vec<String>>>,
    exposed_headers_header: Option<Arc<str>>,
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
        intersect_only(
            &mut self.exposed_headers,
            &mut self.exposed_headers_header,
            &plugin.exposed_headers,
            &plugin.exposed_headers_header,
        );
        if is_preflight {
            intersect_values(
                &mut self.allowed_methods,
                &mut self.allowed_methods_header,
                &mut self.allowed_method_union,
                &plugin.allowed_methods,
                &plugin.allowed_methods_header,
            );
            intersect_values(
                &mut self.allowed_headers,
                &mut self.allowed_headers_header,
                &mut self.allowed_header_union,
                &plugin.allowed_headers,
                &plugin.allowed_headers_header,
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

fn intersect_only(
    intersection: &mut Option<Arc<Vec<String>>>,
    intersection_header: &mut Option<Arc<str>>,
    values: &Arc<Vec<String>>,
    values_header: &Arc<str>,
) {
    match intersection.take() {
        None => {
            *intersection = Some(Arc::clone(values));
            *intersection_header = Some(Arc::clone(values_header));
        }
        Some(existing) => {
            let mut narrowed = existing.as_ref().clone();
            narrowed.retain(|value| contains_ascii_case(values, value));
            *intersection_header = Some(Arc::from(narrowed.join(", ")));
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
    intersection_header: &mut Option<Arc<str>>,
    union: &mut Option<Vec<String>>,
    values: &Arc<Vec<String>>,
    values_header: &Arc<str>,
) {
    match intersection.take() {
        None => {
            *intersection = Some(Arc::clone(values));
            *intersection_header = Some(Arc::clone(values_header));
        }
        Some(existing) => {
            let union = union.get_or_insert_with(|| existing.as_ref().clone());
            for value in values.iter() {
                if !contains_ascii_case(union, value) {
                    union.push(value.clone());
                }
            }
            let mut narrowed = existing.as_ref().clone();
            narrowed.retain(|value| contains_ascii_case(values, value));
            *intersection_header = Some(Arc::from(narrowed.join(", ")));
            *intersection = Some(Arc::new(narrowed));
        }
    }
}

/// A single origin pattern entry.
#[derive(Debug, Clone)]
enum OriginPattern {
    /// Exact origin match (case-insensitive), e.g. `"https://app.company.com"`.
    Exact(String),
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
    /// time with the regex crate's default size limit (no catastrophic
    /// backtracking — the engine is finite-automaton based); an invalid pattern
    /// is rejected at config validation, never panicked on.
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
    allowed_methods_header: Arc<str>,
    allowed_headers: Arc<Vec<String>>,
    allowed_headers_header: Arc<str>,
    exposed_headers: Arc<Vec<String>>,
    exposed_headers_header: Arc<str>,
    allow_credentials: bool,
    max_age: Option<u64>,
    preflight_continue: bool,
    unmatched_preflights: UnmatchedPreflights,
}

impl CorsPlugin {
    fn remove_access_control_headers(response_headers: &mut HashMap<String, String>) {
        response_headers.retain(|k, _| !k.to_ascii_lowercase().starts_with("access-control-"));
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
        let allowed_methods_header: Arc<str> = Arc::from(allowed_methods.join(", "));
        let allowed_headers = Self::parse_string_array(
            config,
            "allowed_headers",
            DEFAULT_ALLOWED_HEADERS,
            istio_semantics,
            validate_header_name,
        )?;
        let allowed_headers_header: Arc<str> = Arc::from(allowed_headers.join(", "));
        let exposed_headers =
            Self::parse_string_array(config, "exposed_headers", &[], true, validate_header_name)?;
        let exposed_headers_header: Arc<str> = Arc::from(exposed_headers.join(", "));

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
            if istio_semantics {
                return Err(
                    "cors: allow_credentials=true cannot be combined with wildcard origins for translated Istio policies"
                        .to_string(),
                );
            }
            warn!(
                "cors: allow_credentials=true is incompatible with wildcard origins; \
                 credentials will be disabled. Specify explicit origins to use credentials."
            );
            allow_credentials = false;
        }

        Ok(Self {
            allowed_origins,
            allowed_methods: Arc::new(allowed_methods),
            allowed_methods_header,
            allowed_headers: Arc::new(allowed_headers),
            allowed_headers_header,
            exposed_headers: Arc::new(exposed_headers),
            exposed_headers_header,
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
    /// `corsPolicy` with `prefix` / `regex` origin matchers can project here):
    /// - `[{"exact": "https://example.com"}]` → exact match (same as the string
    ///   form)
    /// - `[{"prefix": "https://app."}]` → literal byte-prefix of the `Origin`
    /// - `[{"regex": "https://.*\\.example\\.com"}]` → RE2 full match of the
    ///   `Origin`
    ///
    /// String and object entries can be mixed. An object entry must carry
    /// exactly one of `exact` / `prefix` / `regex`.
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
    /// pattern is compiled here (config time) so an invalid pattern is a config
    /// error, never a request-path panic.
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
                let trimmed = exact.trim();
                if trimmed.is_empty() {
                    return Err(
                        "cors: 'allowed_origins' exact matcher must be a non-empty string"
                            .to_string(),
                    );
                }
                if trimmed.len() != exact.len() {
                    return Err(
                        "cors: 'allowed_origins' exact matcher must not have leading or trailing whitespace"
                            .to_string(),
                    );
                }
                if exact == "*" {
                    return Ok(None);
                }
                let canonical = canonicalize_exact_origin(exact)?;
                Ok(Some(OriginPattern::Exact(canonical)))
            }
            (None, Some(prefix), None) => {
                // Istio prefix is a literal string prefix of the Origin header;
                // do NOT trim (leading/trailing spaces would change matching)
                // beyond rejecting an all-empty value. An empty prefix would
                // match every origin (an open CORS policy by accident), so it
                // is rejected rather than silently allow-all.
                if prefix.is_empty() {
                    return Err(
                        "cors: 'allowed_origins' prefix matcher must be a non-empty string \
                         (an empty prefix would match every origin)"
                            .to_string(),
                    );
                }
                Ok(Some(OriginPattern::Prefix(prefix.to_string())))
            }
            (None, None, Some(regex)) => {
                if regex.is_empty() {
                    return Err(
                        "cors: 'allowed_origins' regex matcher must be a non-empty string"
                            .to_string(),
                    );
                }
                // Istio `StringMatch.regex` is a FULL match. Anchor at compile
                // time (the shared Ferrum convention for Istio-style regex, also
                // strips a redundant leading `^`/trailing `$`) so matching can
                // use `is_match`: checking only the first unanchored `find`
                // would reject an Origin that a LATER alternation branch fully
                // matches (e.g. `https://app|https://app\.example\.com` vs
                // `https://app.example.com`, where `find` returns the shorter
                // `https://app`). Compile with the regex crate's default size
                // limit; the engine is finite-automaton based, so a hostile
                // pattern cannot trigger catastrophic backtracking. A pattern
                // that fails to compile is rejected here, not at request time.
                let anchored = crate::config::types::anchor_regex_pattern(regex);
                let compiled = Regex::new(&anchored).map_err(|e| {
                    format!("cors: 'allowed_origins' regex matcher '{regex}' is invalid: {e}")
                })?;
                Ok(Some(OriginPattern::Regex(compiled)))
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
    /// For `Exact` patterns: case-insensitive full-string match.
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
                // Istio/Envoy forwards unmatched actual requests and leaves
                // them without CORS response fields. Native direct-plugin
                // policy retains its historical fail-closed 403.
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

    // Native CORS retains its established sanitization of every backend
    // response. A matching translated Istio policy also owns the response
    // fields. Pure Istio unmatched/no-Origin forwarding is different: Envoy
    // leaves the upstream response untouched, so preserve that source
    // behavior instead of silently taking ownership.
    let should_sanitize = ctx.cors_state.native_policy_seen || ctx.cors_state.sanitize_response;
    if should_sanitize && !(is_rejection_path && ctx.cors_state.policy_count == 0) {
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
        .exposed_headers_header
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        headers.insert(
            "access-control-expose-headers".to_string(),
            exposed.to_string(),
        );
    }
    if preflight {
        if let Some(methods) = state
            .allowed_methods_header
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            headers.insert(
                "access-control-allow-methods".to_string(),
                methods.to_string(),
            );
        }
        if let Some(allowed) = state
            .allowed_headers_header
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            headers.insert(
                "access-control-allow-headers".to_string(),
                allowed.to_string(),
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
/// configuration. Callers that preserve literal Istio `StringMatch.exact`
/// semantics additionally require the returned serialization to equal the
/// source value. Do not fork this predicate.
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
