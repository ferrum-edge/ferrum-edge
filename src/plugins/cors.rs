//! Cross-Origin Resource Sharing (CORS) plugin.
//!
//! Handles preflight OPTIONS requests and injects CORS response headers
//! (`Access-Control-Allow-Origin`, `-Methods`, `-Headers`, `-Credentials`, etc.).
//!
//! Supports exact origin matching and wildcard subdomain patterns (e.g.,
//! `"*.company.com"` matches `https://app.company.com`). When `allowed_origins`
//! contains `"*"`, all origins are allowed. Preflight requests are short-circuited
//! with a 204 response before reaching the backend.

use async_trait::async_trait;
use http::Method;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::HashMap;
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
    allowed_methods: Vec<String>,
    allowed_methods_header: String,
    allowed_headers_header: String,
    exposed_headers_header: Option<String>,
    allow_credentials: bool,
    max_age: u64,
    preflight_continue: bool,
}

impl CorsPlugin {
    fn remove_access_control_headers(response_headers: &mut HashMap<String, String>) {
        response_headers.retain(|k, _| !k.to_ascii_lowercase().starts_with("access-control-"));
    }

    pub fn new(config: &Value) -> Result<Self, String> {
        let allowed_origins = Self::parse_origins(config)?;

        let allowed_methods = Self::parse_string_array(
            config,
            "allowed_methods",
            DEFAULT_ALLOWED_METHODS,
            false,
            validate_method,
        )?;
        let allowed_methods_header = allowed_methods.join(", ");

        let allowed_headers = Self::parse_string_array(
            config,
            "allowed_headers",
            DEFAULT_ALLOWED_HEADERS,
            false,
            validate_header_name,
        )?;
        let allowed_headers_header = allowed_headers.join(", ");

        let exposed_headers =
            Self::parse_string_array(config, "exposed_headers", &[], true, validate_header_name)?;
        let exposed_headers_header = if exposed_headers.is_empty() {
            None
        } else {
            Some(exposed_headers.join(", "))
        };

        let mut allow_credentials = bool_config(config, "allow_credentials", false)?;
        let max_age = u64_config(config, "max_age", 86400)?;
        let preflight_continue = bool_config(config, "preflight_continue", false)?;

        // Per CORS spec: Access-Control-Allow-Origin: * cannot be used with credentials.
        if allow_credentials && matches!(allowed_origins, AllowedOrigins::Wildcard) {
            warn!(
                "cors: allow_credentials=true is incompatible with wildcard origins; \
                 credentials will be disabled. Specify explicit origins to use credentials."
            );
            allow_credentials = false;
        }

        Ok(Self {
            allowed_origins,
            allowed_methods,
            allowed_methods_header,
            allowed_headers_header,
            exposed_headers_header,
            allow_credentials,
            max_age,
            preflight_continue,
        })
    }

    /// Parse the `allowed_origins` config field.
    ///
    /// Supports three forms:
    /// - `["*"]` or any list containing `"*"` → `AllowedOrigins::Wildcard`
    /// - `["https://example.com"]` → exact match
    /// - `["*.company.com"]` → wildcard subdomain (matches any `*.company.com`)
    ///
    /// These can be mixed: `["https://exact.com", "*.company.com"]`.
    fn parse_origins(config: &Value) -> Result<AllowedOrigins, String> {
        match config.get("allowed_origins") {
            None | Some(Value::Null) => Ok(AllowedOrigins::Wildcard),
            Some(Value::Array(arr)) => {
                if arr.is_empty() {
                    return Err(
                        "cors: 'allowed_origins' must contain at least one origin or '*'"
                            .to_string(),
                    );
                }

                let mut patterns = Vec::with_capacity(arr.len());
                for value in arr {
                    let origin = value.as_str().ok_or_else(|| {
                        format!("cors: 'allowed_origins' entries must be strings, got: {value}")
                    })?;
                    let origin = origin.trim();
                    if origin.is_empty() {
                        return Err(
                            "cors: 'allowed_origins' entries must be non-empty strings".to_string()
                        );
                    }
                    if origin == "*" {
                        return Ok(AllowedOrigins::Wildcard);
                    }
                    if origin.starts_with('*') {
                        patterns.push(OriginPattern::WildcardSubdomain(validate_wildcard_origin(
                            origin,
                        )?));
                    } else {
                        validate_exact_origin(origin)?;
                        patterns.push(OriginPattern::Exact(origin.to_string()));
                    }
                }

                Ok(AllowedOrigins::List(patterns))
            }
            Some(other) => Err(format!(
                "cors: 'allowed_origins' must be an array of strings, got: {other}"
            )),
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
            None | Some(Value::Null) => Ok(defaults.iter().map(|s| (*s).to_string()).collect()),
            Some(Value::Array(arr)) => {
                if arr.is_empty() && !allow_empty {
                    return Err(format!("cors: '{key}' must contain at least one value"));
                }
                let mut values = Vec::with_capacity(arr.len());
                for value in arr {
                    let value = value.as_str().ok_or_else(|| {
                        format!("cors: '{key}' entries must be strings, got: {value}")
                    })?;
                    let value = value.trim();
                    if value.is_empty() {
                        return Err(format!("cors: '{key}' entries must be non-empty strings"));
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
            }),
        }
    }

    /// Build the common CORS response headers (used for both preflight and actual).
    ///
    /// Note: this returns the headers the plugin wants to ADD/SET on the response.
    /// Vary is intentionally not included here — see `apply_cors_headers_to_response`
    /// which merges Vary with any pre-existing value to avoid clobbering backend Vary
    /// directives (e.g., `Vary: Accept-Encoding` from compression).
    fn build_cors_headers(&self, origin: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        // Set Access-Control-Allow-Origin
        match &self.allowed_origins {
            AllowedOrigins::Wildcard if !self.allow_credentials => {
                headers.insert("access-control-allow-origin".to_string(), "*".to_string());
            }
            _ => {
                headers.insert(
                    "access-control-allow-origin".to_string(),
                    origin.to_string(),
                );
            }
        }

        if self.allow_credentials {
            headers.insert(
                "access-control-allow-credentials".to_string(),
                "true".to_string(),
            );
        }

        if let Some(exposed_headers) = &self.exposed_headers_header {
            headers.insert(
                "access-control-expose-headers".to_string(),
                exposed_headers.clone(),
            );
        }

        headers
    }

    /// Merge `Origin` into an existing `Vary` header value (case-insensitive).
    /// Returns the merged Vary string. Preserves existing tokens (e.g., `Accept-Encoding`)
    /// to avoid breaking caching layers that depend on them.
    fn merge_vary_origin(existing: Option<&str>) -> String {
        match existing {
            None => "Origin".to_string(),
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return "Origin".to_string();
                }
                // Per RFC 9110 §12.5.5, Vary: * means "vary on any header" — adding
                // Origin is redundant. Preserve as-is.
                if trimmed == "*" {
                    return "*".to_string();
                }
                let already_present = trimmed
                    .split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("Origin"));
                if already_present {
                    return trimmed.to_string();
                }
                format!("{}, Origin", trimmed)
            }
        }
    }

    /// Build headers specific to preflight responses (superset of common headers).
    fn build_preflight_headers(&self, origin: &str) -> HashMap<String, String> {
        let mut headers = self.build_cors_headers(origin);

        // Preflight 204 responses have no backend Vary to preserve, so set Origin
        // directly. The actual-request response path uses merge_vary_origin().
        headers.insert("vary".to_string(), "Origin".to_string());

        headers.insert(
            "access-control-allow-methods".to_string(),
            self.allowed_methods_header.clone(),
        );

        headers.insert(
            "access-control-allow-headers".to_string(),
            self.allowed_headers_header.clone(),
        );

        headers.insert(
            "access-control-max-age".to_string(),
            self.max_age.to_string(),
        );

        headers
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

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Only act on requests that include an Origin header
        let origin = match ctx.headers.get("origin") {
            Some(o) => o.clone(),
            None => return PluginResult::Continue,
        };

        // Detect preflight: OPTIONS with Access-Control-Request-Method header
        let is_preflight =
            ctx.method == "OPTIONS" && ctx.headers.contains_key("access-control-request-method");

        if !is_preflight {
            // Simple/actual CORS request — reject if origin is not allowed
            if !self.is_origin_allowed(&origin) {
                debug!("cors: request rejected for disallowed origin '{}'", origin);
                return PluginResult::Reject {
                    status_code: 403,
                    body: "CORS origin not allowed".to_string(),
                    headers: HashMap::new(),
                };
            }
            ctx.metadata
                .insert("cors_origin".to_string(), origin.clone());
            return PluginResult::Continue;
        }

        // --- Preflight handling ---

        // If preflight_continue is set, let the request pass through to backend
        if self.preflight_continue {
            if self.is_origin_allowed(&origin) {
                ctx.metadata
                    .insert("cors_origin".to_string(), origin.clone());
            }
            return PluginResult::Continue;
        }

        // Check origin
        if !self.is_origin_allowed(&origin) {
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

        // Check requested method
        if let Some(requested_method) = ctx.headers.get("access-control-request-method") {
            let method_allowed = self
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(requested_method));
            if !method_allowed {
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

        // Preflight approved — return 204 with CORS headers
        let headers = self.build_preflight_headers(&origin);
        debug!("cors: preflight approved for origin '{}'", origin);
        PluginResult::Reject {
            status_code: 204,
            body: String::new(),
            headers,
        }
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // When `after_proxy` is being run as part of a plugin *rejection*
        // (`apply_after_proxy_hooks_to_rejection`), the response headers are
        // plugin-supplied, not backend-supplied. The strip step exists to
        // prevent backend-supplied `access-control-*` from leaking through —
        // running it on a rejection erases this plugin's own preflight reply
        // (e.g. the `204` headers from `on_request_received`). Skip the strip
        // on the rejection path so the preflight headers survive, but keep
        // running the re-inject pass below so the gateway can still attach
        // CORS headers onto a *different* plugin's rejection (e.g.
        // `request_termination` 503 → still gets `Allow-Origin` for allowed
        // origins). See `crate::proxy::apply_after_proxy_hooks_to_rejection`
        // for the marker.
        let is_rejection_path = ctx
            .metadata
            .get(crate::proxy::REJECTION_RESPONSE_METADATA_KEY)
            .is_some_and(|v| v == "true");
        if !is_rejection_path {
            // Strip backend-supplied CORS policy headers so the gateway CORS
            // policy remains authoritative.
            Self::remove_access_control_headers(response_headers);
        }

        // Check if on_request_received marked this as a valid CORS request
        let origin = match ctx.metadata.get("cors_origin") {
            Some(o) => o.clone(),
            None => return PluginResult::Continue,
        };

        match &self.allowed_origins {
            AllowedOrigins::Wildcard if !self.allow_credentials => {
                response_headers.insert("access-control-allow-origin".to_string(), "*".to_string());
            }
            _ => {
                response_headers.insert("access-control-allow-origin".to_string(), origin);
            }
        }

        if self.allow_credentials {
            response_headers.insert(
                "access-control-allow-credentials".to_string(),
                "true".to_string(),
            );
        }

        if let Some(exposed_headers) = &self.exposed_headers_header {
            response_headers.insert(
                "access-control-expose-headers".to_string(),
                exposed_headers.clone(),
            );
        }

        // Merge Origin into Vary rather than overwriting it. The backend may have
        // returned `Vary: Accept-Encoding` (compression), `Vary: Accept-Language`,
        // etc.; clobbering those would break downstream caches that segment by
        // those dimensions.
        let merged = Self::merge_vary_origin(response_headers.get("vary").map(|s| s.as_str()));
        response_headers.insert("vary".to_string(), merged);

        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }
}

fn validate_method(key: &str, value: &str) -> Result<(), String> {
    Method::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| format!("cors: '{key}' contains an invalid HTTP method: {value}"))
}

fn validate_header_name(key: &str, value: &str) -> Result<(), String> {
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

fn validate_exact_origin(origin: &str) -> Result<(), String> {
    let url = Url::parse(origin).map_err(|e| format!("cors: invalid origin '{origin}': {e}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "cors: origin scheme must be http or https, got: {scheme}"
            ));
        }
    }
    if url.host_str().is_none() {
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
    Ok(())
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
    let (_, rest) = origin.split_once("://")?;
    if rest.starts_with('[') {
        return None;
    }
    let host_port = rest.split('/').next().unwrap_or(rest);
    host_port.split(':').next().filter(|host| !host.is_empty())
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
