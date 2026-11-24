use serde_json::Value;
use std::collections::HashMap;

use crate::plugins::PluginResult;
use crate::util::body_limit::{ContentLength, declared_content_length};

pub trait SizeLimiter {
    fn plugin_name(&self) -> &'static str;

    /// Use `u128` so HTTP plugins backed by `u64` limits and WebSocket frame
    /// checks backed by `usize` can share one comparison path without lossy
    /// casts in the trait API.
    fn max_size_bytes(&self) -> u128;

    fn is_enabled(&self) -> bool {
        self.max_size_bytes() > 0
    }

    fn exceeds_limit(&self, size: u128) -> bool {
        self.is_enabled() && size > self.max_size_bytes()
    }
}

/// Read a required positive integer field, naming the actual fault class.
///
/// Missing, wrong-type, negative, fractional, and zero values are all refused,
/// each with its own reason, so an operator who wrote `"1048576"` or
/// `1048576.0` is told the value has the wrong type rather than that it must be
/// greater than zero. Messages name the field and the JSON type but never echo
/// the supplied value.
pub fn required_positive_u64(
    config: &Value,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<u64, String> {
    match config.get(field) {
        None | Some(Value::Null) => Err(format!("{plugin_name}: `{field}` is required")),
        Some(Value::Number(number)) => match number.as_u64() {
            Some(0) => Err(format!(
                "{plugin_name}: `{field}` must be greater than zero"
            )),
            Some(value) => Ok(value),
            None if number.is_i64() => {
                Err(format!("{plugin_name}: `{field}` must not be negative"))
            }
            None => Err(format!(
                "{plugin_name}: `{field}` must be written as an integer, not a fractional or exponent number"
            )),
        },
        Some(other) => Err(format!(
            "{plugin_name}: `{field}` must be an integer, not {}",
            json_kind(other)
        )),
    }
}

/// Value-free name of a non-numeric JSON value's type, for diagnostics.
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// [`required_positive_u64`] narrowed to `usize`; a value the platform cannot
/// represent is refused rather than truncated.
pub fn required_positive_usize(
    config: &Value,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<usize, String> {
    let value = required_positive_u64(config, field, plugin_name)?;
    usize::try_from(value).map_err(|_| {
        format!("{plugin_name}: `{field}` exceeds the largest size this platform supports")
    })
}

/// Why a `Content-Length` fast path refuses a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentLengthRefusal {
    /// The declared length exceeds `max_bytes`.
    OverLimit(u64),
    /// The field is present but cannot be reduced to one agreed value, so no
    /// bound can be proven from it. Fail closed rather than forwarding a body
    /// whose declared framing the gateway and backend may read differently.
    Ambiguous,
}

/// `Content-Length` overrun check that understands comma-folded repeats.
///
/// Plugin-facing header maps fold repeated fields with `", "`, so a
/// standards-valid `Content-Length: 2048, 2048` (or two identical `2048`
/// fields) reaches plugins as one folded string. Parsing that whole string as a
/// single integer fails and used to read as "no declared length", skipping the
/// bound entirely (`GHSA-xrfj-852f-645j`). Every member is now parsed and must
/// agree; disagreement or malformed members are
/// [`ContentLengthRefusal::Ambiguous`] rather than silently ignored.
pub fn content_length_refusal(
    headers: &HashMap<String, String>,
    max_bytes: u128,
) -> Option<ContentLengthRefusal> {
    match declared_content_length(headers)? {
        ContentLength::Exact(len) => {
            ((len as u128) > max_bytes).then_some(ContentLengthRefusal::OverLimit(len))
        }
        ContentLength::Ambiguous => Some(ContentLengthRefusal::Ambiguous),
    }
}

/// Response-side counterpart of [`content_length_refusal`] that skips bodyless
/// semantics.
///
/// Bodyless semantics (`HEAD`, `1xx`, `204`/`205`/`304`) may advertise a
/// representation `Content-Length` while transferring zero body bytes
/// (RFC 9110 §8.6 / §6.4.1), so neither an oversized value nor an ambiguous fold
/// is a body-size violation there. Body-bearing responses (including `206`) keep
/// exact-boundary enforcement (`Content-Length == max_bytes` passes) and fail
/// closed on an ambiguous fold: a declared length the gateway cannot reduce to
/// one value is exactly the coalescing case that used to bypass the bound
/// (`GHSA-xrfj-852f-645j`).
pub fn transferable_content_length_refusal(
    method: &str,
    status: u16,
    headers: &HashMap<String, String>,
    max_bytes: u128,
) -> Option<ContentLengthRefusal> {
    if super::synthetic_response::synthetic_response_omits_body(method, status) {
        None
    } else {
        content_length_refusal(headers, max_bytes)
    }
}

pub fn rejection_body(error: &str, limit: u128) -> String {
    let escaped_error = match serde_json::to_string(error) {
        Ok(value) => value,
        Err(_) => "\"size limit exceeded\"".to_string(),
    };
    format!(r#"{{"error":{escaped_error},"limit":{limit}}}"#)
}

pub fn reject_with_limit(status_code: u16, error: &'static str, limit: u128) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body: rejection_body(error, limit),
        headers: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct TestLimiter {
        max_size_bytes: u128,
    }

    impl SizeLimiter for TestLimiter {
        fn plugin_name(&self) -> &'static str {
            "test_limiter"
        }

        fn max_size_bytes(&self) -> u128 {
            self.max_size_bytes
        }
    }

    #[test]
    fn size_limiter_zero_limit_disables_checks() {
        let limiter = TestLimiter { max_size_bytes: 0 };

        assert_eq!(limiter.plugin_name(), "test_limiter");
        assert!(!limiter.is_enabled());
        assert!(!limiter.exceeds_limit(1));
    }

    #[test]
    fn size_limiter_uses_strict_greater_than_limit() {
        let limiter = TestLimiter { max_size_bytes: 10 };

        assert!(limiter.is_enabled());
        assert!(!limiter.exceeds_limit(10));
        assert!(limiter.exceeds_limit(11));
    }

    #[test]
    fn required_positive_values_reject_missing_zero_and_wrong_types() {
        let config = json!({
            "u64_ok": 1,
            "usize_ok": 2,
            "zero": 0,
            "string": "3"
        });

        assert_eq!(
            required_positive_u64(&config, "u64_ok", "plugin").expect("positive u64"),
            1
        );
        assert_eq!(
            required_positive_usize(&config, "usize_ok", "plugin").expect("positive usize"),
            2
        );
        assert!(required_positive_u64(&config, "missing", "plugin").is_err());
        assert!(required_positive_u64(&config, "zero", "plugin").is_err());
        assert!(required_positive_usize(&config, "string", "plugin").is_err());
    }

    #[test]
    fn content_length_refusal_parses_only_oversized_numeric_values() {
        let mut headers = HashMap::new();

        assert_eq!(content_length_refusal(&headers, 10), None);

        headers.insert("content-length".to_string(), "10".to_string());
        assert_eq!(content_length_refusal(&headers, 10), None);

        headers.insert("content-length".to_string(), "11".to_string());
        assert_eq!(
            content_length_refusal(&headers, 10),
            Some(ContentLengthRefusal::OverLimit(11))
        );

        // A non-numeric field is not a usable bound: fail closed instead of
        // reading as an absent length.
        headers.insert("content-length".to_string(), "not-a-number".to_string());
        assert_eq!(
            content_length_refusal(&headers, 10),
            Some(ContentLengthRefusal::Ambiguous)
        );
    }

    /// A standards-valid repeated identical `Content-Length` reaches plugins
    /// comma-folded. It must still be compared against the limit rather than
    /// failing to parse and silently skipping the bound.
    #[test]
    fn content_length_refusal_honors_repeated_identical_values() {
        let mut headers = HashMap::new();

        headers.insert("content-length".to_string(), "11, 11".to_string());
        assert_eq!(
            content_length_refusal(&headers, 10),
            Some(ContentLengthRefusal::OverLimit(11))
        );

        // Exact boundary still passes when every member agrees.
        headers.insert("content-length".to_string(), "10, 10".to_string());
        assert_eq!(content_length_refusal(&headers, 10), None);

        // Disagreeing members cannot bound anything.
        headers.insert("content-length".to_string(), "10, 4096".to_string());
        assert_eq!(
            content_length_refusal(&headers, 10),
            Some(ContentLengthRefusal::Ambiguous)
        );
    }

    #[test]
    fn transferable_content_length_skips_bodyless_semantics() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "11".to_string());

        for (method, status) in [("HEAD", 200), ("GET", 304), ("GET", 100), ("GET", 204)] {
            assert_eq!(
                transferable_content_length_refusal(method, status, &headers, 10),
                None,
                "bodyless {method} {status} must not trip a body-size limit"
            );
        }
        // Body-bearing control (including 206) retains exact-boundary enforcement.
        assert_eq!(
            transferable_content_length_refusal("GET", 206, &headers, 10),
            Some(ContentLengthRefusal::OverLimit(11))
        );
        headers.insert("content-length".to_string(), "10".to_string());
        assert_eq!(
            transferable_content_length_refusal("GET", 206, &headers, 10),
            None
        );
    }

    #[test]
    fn rejection_body_escapes_error_text_as_json_string() {
        let raw = "too \"large\"\nwith\u{00}control";
        let body = rejection_body(raw, 123);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("rejection body should be valid JSON");

        assert_eq!(parsed["error"], raw);
        assert_eq!(parsed["limit"], 123);
    }

    #[test]
    fn reject_with_limit_uses_json_rejection_body() {
        match reject_with_limit(413, "payload too large", 4096) {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(status_code, 413);
                assert!(headers.is_empty());
                let parsed: serde_json::Value =
                    serde_json::from_str(&body).expect("body should be valid JSON");
                assert_eq!(parsed["error"], "payload too large");
                assert_eq!(parsed["limit"], 4096);
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }
}
