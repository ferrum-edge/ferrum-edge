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

/// Escape characters that could cause JSON injection in response bodies.
pub fn html_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_hash_inside_path_segment() {
        let claims = json!({"cnf": {"x5t#S256": "thumbprint"}});
        assert_eq!(
            extract_claim_string(&claims, "cnf.x5t#S256").as_deref(),
            Some("thumbprint")
        );
    }

    #[test]
    fn extracts_space_delimited_and_array_values() {
        let claims = json!({
            "scope": "read write",
            "realm_access": {"roles": ["admin", "editor"]}
        });
        assert_eq!(
            extract_claim_values(&claims, "scope"),
            vec!["read", "write"]
        );
        assert_eq!(
            extract_claim_values(&claims, "realm_access.roles"),
            vec!["admin", "editor"]
        );
    }

    #[test]
    fn rejects_empty_path_segments() {
        let err = parse_claim_path_value("scope_claim", &json!("realm..roles"), "test")
            .expect_err("path should be rejected");
        assert!(err.contains("scope_claim"));
    }
}
