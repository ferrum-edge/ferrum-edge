//! Security Headers Plugin
//!
//! Hardens responses by injecting common security headers and stripping
//! fingerprinting headers the backend may have set. Runs in the response band
//! (`after_proxy`) so it applies to every proxied response regardless of the
//! backend's own header hygiene.
//!
//! Secure-by-default: simply enabling the plugin adds `X-Content-Type-Options`,
//! `X-Frame-Options`, and `Referrer-Policy`, and removes `Server` /
//! `X-Powered-By`. HSTS, CSP, and Permissions-Policy are opt-in because they
//! are deployment- or app-specific (HSTS requires HTTPS; CSP must match the
//! app). Operators can add or remove arbitrary headers via `set` / `remove`.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;

use crate::util::http_headers::{cache_control_has_directive, etag_value_is_strong};

use super::{HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

#[derive(Debug)]
pub struct SecurityHeaders {
    /// Header name (lowercase) -> value, applied to every response.
    set: Vec<(String, String)>,
    /// Header names (lowercase) to strip from the response.
    remove: Vec<String>,
    /// Unique canonical names touched by `set` or `remove`, precomputed for
    /// buffered initial-header provenance tracking.
    policy_header_names: Vec<String>,
    /// When false, only add a header if the backend did not already set it.
    override_existing: bool,
}

impl SecurityHeaders {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "security_headers: config must be an object".to_string())?;
        reject_unknown_keys(
            object,
            "security_headers",
            &[
                "content_type_options",
                "frame_options",
                "referrer_policy",
                "hsts",
                "content_security_policy",
                "permissions_policy",
                "set",
                "remove",
                "override_existing",
            ],
        )?;

        let override_existing = parse_bool(object, "override_existing", true)?;

        // Built-in headers with secure defaults. Each can be disabled with
        // `false`/`null` or customized with an explicit value.
        let mut set: Vec<(String, String)> = Vec::new();

        if let Some(value) = header_value(object, "content_type_options", "nosniff", true)? {
            set.push(("x-content-type-options".to_string(), value));
        }
        if let Some(value) = header_value(object, "frame_options", "SAMEORIGIN", true)? {
            set.push(("x-frame-options".to_string(), value));
        }
        if let Some(value) = header_value(
            object,
            "referrer_policy",
            "strict-origin-when-cross-origin",
            true,
        )? {
            set.push(("referrer-policy".to_string(), value));
        }
        // Opt-in headers: default disabled (no value unless configured).
        if let Some(value) = parse_hsts(object)? {
            set.push(("strict-transport-security".to_string(), value));
        }
        if let Some(value) = optional_header(object, "content_security_policy")? {
            set.push(("content-security-policy".to_string(), value));
        }
        if let Some(value) = optional_header(object, "permissions_policy")? {
            set.push(("permissions-policy".to_string(), value));
        }

        // Arbitrary operator-defined headers.
        for (name, value) in parse_set_map(object)? {
            // A later `set` entry overrides an earlier built-in of the same name.
            set.retain(|(existing, _)| existing != &name);
            set.push((name, value));
        }

        let remove = parse_remove(object)?;

        if set.is_empty() && remove.is_empty() {
            return Err(
                "security_headers: no headers to set or remove — configure at least one, or remove the plugin".to_string(),
            );
        }

        let mut policy_header_names = Vec::with_capacity(set.len() + remove.len());
        for name in remove.iter().chain(set.iter().map(|(name, _)| name)) {
            if !policy_header_names.contains(name) {
                policy_header_names.push(name.clone());
            }
        }

        Ok(Self {
            set,
            remove,
            policy_header_names,
            override_existing,
        })
    }

    fn apply(&self, headers: &mut HashMap<String, String>) {
        for name in &self.remove {
            remove_header_ci(headers, name);
        }
        for (name, value) in &self.set {
            if self.override_existing {
                remove_header_ci(headers, name);
                headers.insert(name.clone(), value.clone());
            } else if find_header_ci(headers, name).is_none() {
                headers.insert(name.clone(), value.clone());
            }
        }
    }
}

#[async_trait]
impl Plugin for SecurityHeaders {
    fn name(&self) -> &str {
        "security_headers"
    }

    fn priority(&self) -> u16 {
        super::priority::SECURITY_HEADERS
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_PROTOCOLS
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.apply(response_headers);
        PluginResult::Continue
    }

    fn is_initial_response_header_policy(&self) -> bool {
        true
    }

    fn apply_initial_response_header_policy(&self, response_headers: &mut HashMap<String, String>) {
        self.apply(response_headers);
    }

    fn initial_response_header_policy_names(&self) -> &[String] {
        &self.policy_header_names
    }

    /// A configured `remove` is a policy decision about the FIELD, not about
    /// the header section that happened to carry it: a backend that sends the
    /// same name as a trailer would otherwise reintroduce exactly what the
    /// policy suppressed, and the removal is a no-op on the initial map in that
    /// case, so no observed-mutation diff can catch it. `set` names are
    /// declared for the same reason — a trailer copy would leave the client
    /// holding two conflicting values for a header the gateway owns.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&self.policy_header_names)
    }

    fn may_add_response_cache_control_no_transform(
        &self,
        _ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.set.iter().any(|(name, value)| {
            name == "cache-control" && cache_control_has_directive(value, "no-transform")
        })
    }

    fn may_add_response_strong_etag(
        &self,
        _ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.set
            .iter()
            .any(|(name, value)| name == "etag" && etag_value_is_strong(value))
    }

    fn simulate_after_proxy_response_headers(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        self.apply(response_headers);
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }
}

fn find_header_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) {
    let keys: Vec<String> = headers
        .keys()
        .filter(|key| key.eq_ignore_ascii_case(name))
        .cloned()
        .collect();
    for key in keys {
        headers.remove(&key);
    }
}

/// Resolve a built-in security header. `key` is the config field; when present
/// and `true` (or absent and `default_on`) the `default_value` is used; an
/// explicit string overrides it; `false`/`null`/`""` disables it.
fn header_value(
    object: &serde_json::Map<String, Value>,
    key: &str,
    default_value: &str,
    default_on: bool,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None => Ok(default_on.then(|| default_value.to_string())),
        Some(Value::Null) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some(default_value.to_string())),
        Some(Value::Bool(false)) => Ok(None),
        Some(Value::String(value)) => {
            if value.is_empty() {
                return Ok(None);
            }
            validate_header_value(key, value)?;
            Ok(Some(value.clone()))
        }
        Some(other) => Err(format!(
            "security_headers: '{key}' must be a boolean or string, got {other}"
        )),
    }
}

fn optional_header(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => {
            validate_header_value(key, value)?;
            Ok(Some(value.clone()))
        }
        Some(other) => Err(format!(
            "security_headers: '{key}' must be a string, got {other}"
        )),
    }
}

/// HSTS accepts `true` (defaults), `false`/absent (disabled), a string (verbatim
/// value), or an object `{max_age, include_subdomains, preload}`.
fn parse_hsts(object: &serde_json::Map<String, Value>) -> Result<Option<String>, String> {
    match object.get("hsts") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some("max-age=31536000; includeSubDomains".to_string())),
        Some(Value::String(value)) => {
            if value.is_empty() {
                return Ok(None);
            }
            validate_header_value("hsts", value)?;
            Ok(Some(value.clone()))
        }
        Some(Value::Object(map)) => {
            reject_unknown_keys(
                map,
                "security_headers.hsts",
                &["max_age", "include_subdomains", "preload"],
            )?;
            let max_age = match map.get("max_age") {
                None | Some(Value::Null) => 31_536_000u64,
                Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    "security_headers: 'hsts.max_age' must be a non-negative integer".to_string()
                })?,
                Some(_) => {
                    return Err("security_headers: 'hsts.max_age' must be an integer".to_string());
                }
            };
            let mut value = format!("max-age={max_age}");
            if parse_bool(map, "include_subdomains", true)? {
                value.push_str("; includeSubDomains");
            }
            if parse_bool(map, "preload", false)? {
                value.push_str("; preload");
            }
            Ok(Some(value))
        }
        Some(other) => Err(format!(
            "security_headers: 'hsts' must be a boolean, string, or object, got {other}"
        )),
    }
}

fn parse_set_map(object: &serde_json::Map<String, Value>) -> Result<Vec<(String, String)>, String> {
    match object.get("set") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(map)) => {
            let mut out = Vec::with_capacity(map.len());
            for (name, value) in map {
                let name = parse_header_name("set", name)?;
                let value = value.as_str().ok_or_else(|| {
                    format!("security_headers: 'set.{name}' value must be a string")
                })?;
                validate_header_value(&format!("set.{name}"), value)?;
                out.push((name, value.to_string()));
            }
            Ok(out)
        }
        Some(other) => Err(format!(
            "security_headers: 'set' must be an object, got {other}"
        )),
    }
}

fn parse_remove(object: &serde_json::Map<String, Value>) -> Result<Vec<String>, String> {
    match object.get("remove") {
        None => Ok(vec!["server".to_string(), "x-powered-by".to_string()]),
        Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let name = value.as_str().ok_or_else(|| {
                    "security_headers: 'remove' entries must be strings".to_string()
                })?;
                out.push(parse_header_name("remove", name)?);
            }
            Ok(out)
        }
        Some(other) => Err(format!(
            "security_headers: 'remove' must be an array, got {other}"
        )),
    }
}

fn parse_header_name(field: &str, name: &str) -> Result<String, String> {
    HeaderName::from_bytes(name.as_bytes())
        .map(|name| name.as_str().to_string())
        .map_err(|_| {
            format!(
                "security_headers: '{field}' contains invalid HTTP field name '{}'",
                render_invalid_header_name(name)
            )
        })
}

/// Render an untrusted invalid field name without allowing hostile config to
/// inject control characters or create an unbounded validation error.
fn render_invalid_header_name(name: &str) -> String {
    const MAX_RENDERED_BYTES: usize = 96;

    let mut rendered = String::with_capacity(MAX_RENDERED_BYTES + 3);
    let mut chars = name.chars().peekable();
    while let Some(character) = chars.next() {
        let escaped = character.escape_default();
        let escaped_len = escaped.clone().count();
        if rendered.len() + escaped_len > MAX_RENDERED_BYTES {
            rendered.push_str("...");
            break;
        }
        rendered.extend(escaped);
        if rendered.len() == MAX_RENDERED_BYTES && chars.peek().is_some() {
            rendered.push_str("...");
            break;
        }
    }
    rendered
}

fn validate_header_value(key: &str, value: &str) -> Result<(), String> {
    let invalid_value = || format!("security_headers: '{key}' must be a valid HTTP field value");
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(invalid_value());
    }
    HeaderValue::from_str(value)
        .map(|_| ())
        .map_err(|_| invalid_value())
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "security_headers: unknown configuration key(s) under '{path}': {}",
        unknown.join(", ")
    ))
}

fn parse_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "security_headers: '{key}' must be a boolean, got {other}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn apply_to(config: Value, mut headers: HashMap<String, String>) -> HashMap<String, String> {
        let plugin = SecurityHeaders::new(&config).unwrap();
        plugin.apply(&mut headers);
        headers
    }

    #[test]
    fn secure_defaults_add_and_strip() {
        let headers = apply_to(
            json!({}),
            HashMap::from([
                ("Server".to_string(), "nginx/1.0".to_string()),
                ("X-Powered-By".to_string(), "PHP/8".to_string()),
            ]),
        );
        assert_eq!(
            headers.get("x-content-type-options").map(String::as_str),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("x-frame-options").map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            headers.get("referrer-policy").map(String::as_str),
            Some("strict-origin-when-cross-origin")
        );
        // Fingerprinting headers stripped case-insensitively.
        assert!(headers.keys().all(|k| !k.eq_ignore_ascii_case("server")));
        assert!(
            headers
                .keys()
                .all(|k| !k.eq_ignore_ascii_case("x-powered-by"))
        );
    }

    #[test]
    fn hsts_csp_and_custom_headers_opt_in() {
        let headers = apply_to(
            json!({
                "hsts": { "max_age": 63072000, "preload": true },
                "content_security_policy": "default-src 'self'",
                "set": { "X-Custom": "1" }
            }),
            HashMap::new(),
        );
        assert_eq!(
            headers.get("strict-transport-security").map(String::as_str),
            Some("max-age=63072000; includeSubDomains; preload")
        );
        assert_eq!(
            headers.get("content-security-policy").map(String::as_str),
            Some("default-src 'self'")
        );
        assert_eq!(headers.get("x-custom").map(String::as_str), Some("1"));
    }

    #[test]
    fn override_existing_false_preserves_backend_header() {
        let headers = apply_to(
            json!({ "override_existing": false, "frame_options": "DENY" }),
            HashMap::from([("X-Frame-Options".to_string(), "ALLOW-FROM x".to_string())]),
        );
        // Backend value preserved (case-insensitively) when not overriding.
        assert_eq!(
            find_header_ci(&headers, "x-frame-options"),
            Some("ALLOW-FROM x")
        );
    }

    #[test]
    fn override_existing_true_replaces_backend_header() {
        let headers = apply_to(
            json!({ "frame_options": "DENY" }),
            HashMap::from([("X-Frame-Options".to_string(), "ALLOW-FROM x".to_string())]),
        );
        assert_eq!(
            headers.get("x-frame-options").map(String::as_str),
            Some("DENY")
        );
        // No duplicate case-variant left behind.
        let count = headers
            .keys()
            .filter(|k| k.eq_ignore_ascii_case("x-frame-options"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn disabling_a_default_header() {
        let headers = apply_to(json!({ "frame_options": false }), HashMap::new());
        assert!(!headers.contains_key("x-frame-options"));
        assert_eq!(
            headers.get("x-content-type-options").map(String::as_str),
            Some("nosniff")
        );
    }

    #[test]
    fn header_value_with_crlf_is_rejected() {
        let err =
            SecurityHeaders::new(&json!({ "set": { "X-Bad": "a\r\nInjected: 1" } })).unwrap_err();
        assert!(err.contains("valid HTTP field value"));
    }

    #[test]
    fn no_op_config_is_rejected() {
        // Everything disabled and nothing to remove → no-op, rejected.
        let err = SecurityHeaders::new(&json!({
            "content_type_options": false,
            "frame_options": false,
            "referrer_policy": false,
            "remove": []
        }))
        .unwrap_err();
        assert!(err.contains("no headers"));
    }
}
