use serde_json::Value;

/// Extract values from a claim path, supporting space-delimited strings,
/// arrays of strings, and nested dot-notation paths.
pub fn extract_claim_values(claims: &Value, claim_path: &str) -> Vec<String> {
    let Some(value) = resolve_claim_path(claims, claim_path) else {
        return Vec::new();
    };
    normalize_claim_to_vec(value)
}

/// Extract a single string from a claim path.
pub fn extract_claim_string(claims: &Value, claim_path: &str) -> Option<String> {
    extract_claim_string_exact(claims, claim_path).filter(|value| !value.trim().is_empty())
}

/// Extract a string byte-for-byte, including an explicitly blank value.
///
/// Identity-header resolution uses this to distinguish a missing configured
/// header claim, which falls back to the principal, from a present blank claim,
/// which the authentication transaction deliberately discards.
pub fn extract_claim_string_exact(claims: &Value, claim_path: &str) -> Option<String> {
    resolve_claim_path(claims, claim_path)?
        .as_str()
        .map(ToOwned::to_owned)
}

/// Resolve a dot-notation path through nested JSON.
pub fn resolve_claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = claims;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Parse and validate a dot-path claim configuration value.
pub fn parse_claim_path_value(field: &str, value: &Value, plugin: &str) -> Result<String, String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{plugin}: '{field}' must be a string, got: {value}"))?;
    let path = raw.trim();
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(format!(
            "{plugin}: '{field}' must be a non-empty dot path without empty segments"
        ));
    }
    Ok(path.to_string())
}

fn normalize_claim_to_vec(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => s.split_whitespace().map(ToOwned::to_owned).collect(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}
