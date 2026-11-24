//! Typed readers for WAF config values, shared by the root config, custom
//! rules, rule overrides, global exemptions, and stream signatures so every
//! key reports the same diagnostic for the same mistake.
//!
//! Diagnostics name the key in backticks and Debug-escape a rejected JSON
//! value's Display string, per the validation-diagnostics convention.

use serde_json::{Map, Value};

use super::rules::Severity;

pub(super) fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "waf: `{key}` must be a boolean, got {other:?}",
            other = other.to_string()
        )),
    }
}

pub(super) fn optional_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(format!("waf: `{key}` must be non-empty")),
        Some(other) => Err(format!(
            "waf: `{key}` must be a string, got {other:?}",
            other = other.to_string()
        )),
    }
}

pub(super) fn optional_string_vec(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    optional_string_vec_in(object, key, "")
}

/// [`optional_string_vec`] for a key nested under `scope` (for example
/// `global_exemptions.`), which prefixes the key in diagnostics.
pub(super) fn optional_string_vec_in(
    object: &Map<String, Value>,
    key: &str,
    scope: &str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let Some(raw) = value.as_str() else {
                    return Err(format!("waf: `{scope}{key}` entries must be strings"));
                };
                if raw.is_empty() {
                    return Err(format!("waf: `{scope}{key}` entries must be non-empty"));
                }
                parsed.push(raw.to_string());
            }
            Ok(Some(parsed))
        }
        Some(other) => Err(format!(
            "waf: `{scope}{key}` must be an array, got {other:?}",
            other = other.to_string()
        )),
    }
}

pub(super) fn optional_u64(object: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("waf: `{key}` must be a non-negative integer")),
        Some(other) => Err(format!(
            "waf: `{key}` must be an integer, got {other:?}",
            other = other.to_string()
        )),
    }
}

/// [`optional_u64`] narrowed to `T`, refusing a value `T` cannot hold.
fn optional_narrowed<T: TryFrom<u64>>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<T>, String> {
    optional_u64(object, key)?
        .map(|value| T::try_from(value).map_err(|_| format!("waf: `{key}` is too large")))
        .transpose()
}

pub(super) fn optional_u8(object: &Map<String, Value>, key: &str) -> Result<Option<u8>, String> {
    optional_narrowed(object, key)
}

pub(super) fn optional_u16(object: &Map<String, Value>, key: &str) -> Result<Option<u16>, String> {
    optional_narrowed(object, key)
}

pub(super) fn optional_u32(object: &Map<String, Value>, key: &str) -> Result<Option<u32>, String> {
    optional_narrowed(object, key)
}

pub(super) fn optional_usize(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<usize>, String> {
    optional_narrowed(object, key)
}

pub(super) fn parse_severity(raw: &str) -> Result<Severity, String> {
    match raw {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!(
            "waf: severity must be one of info, low, medium, high, critical; got {other:?}"
        )),
    }
}
