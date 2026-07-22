use serde_json::Value;
use std::collections::HashMap;

use crate::plugins::PluginResult;

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

pub fn required_positive_u64(
    config: &Value,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<u64, String> {
    let value = config[field].as_u64().unwrap_or(0);

    if value == 0 {
        Err(format!(
            "{plugin_name}: '{field}' is required and must be greater than zero"
        ))
    } else {
        Ok(value)
    }
}

pub fn required_positive_usize(
    config: &Value,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<usize, String> {
    let value = config[field].as_u64().unwrap_or(0) as usize;

    if value == 0 {
        Err(format!(
            "{plugin_name}: '{field}' is required and must be greater than zero"
        ))
    } else {
        Ok(value)
    }
}

pub fn content_length_over_limit(
    headers: &HashMap<String, String>,
    max_bytes: u128,
) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|len| (*len as u128) > max_bytes)
}

/// Content-Length fast-path overrun for responses that actually transfer a body.
///
/// Bodyless semantics (`HEAD`, `1xx`, `204`/`205`/`304`) may advertise a
/// representation `Content-Length` while transferring zero body bytes
/// (RFC 9110 §8.6 / §6.4.1). Those declarations must not trip a body-size
/// limit. Body-bearing responses (including `206`) keep exact-boundary
/// enforcement (`Content-Length == max_bytes` passes).
pub fn transferable_content_length_over_limit(
    method: &str,
    status: u16,
    headers: &HashMap<String, String>,
    max_bytes: u128,
) -> Option<u64> {
    if super::synthetic_response::synthetic_response_omits_body(method, status) {
        None
    } else {
        content_length_over_limit(headers, max_bytes)
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
    fn content_length_over_limit_parses_only_oversized_numeric_values() {
        let mut headers = HashMap::new();

        assert_eq!(content_length_over_limit(&headers, 10), None);

        headers.insert("content-length".to_string(), "10".to_string());
        assert_eq!(content_length_over_limit(&headers, 10), None);

        headers.insert("content-length".to_string(), "11".to_string());
        assert_eq!(content_length_over_limit(&headers, 10), Some(11));

        headers.insert("content-length".to_string(), "not-a-number".to_string());
        assert_eq!(content_length_over_limit(&headers, 10), None);
    }

    #[test]
    fn transferable_content_length_skips_bodyless_semantics() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "11".to_string());

        assert_eq!(
            transferable_content_length_over_limit("HEAD", 200, &headers, 10),
            None
        );
        assert_eq!(
            transferable_content_length_over_limit("GET", 304, &headers, 10),
            None
        );
        assert_eq!(
            transferable_content_length_over_limit("GET", 100, &headers, 10),
            None
        );
        assert_eq!(
            transferable_content_length_over_limit("GET", 204, &headers, 10),
            None
        );
        // Body-bearing control (including 206) retains exact-boundary enforcement.
        assert_eq!(
            transferable_content_length_over_limit("GET", 206, &headers, 10),
            Some(11)
        );
        headers.insert("content-length".to_string(), "10".to_string());
        assert_eq!(
            transferable_content_length_over_limit("GET", 206, &headers, 10),
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
