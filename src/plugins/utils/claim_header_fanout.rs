use std::collections::HashMap;

use http::header::HeaderName;
use serde_json::{Map, Value};

use crate::plugins::RequestContext;

use super::claim_resolver::{parse_claim_path_value, resolve_claim_path};

#[derive(Clone, Debug)]
pub struct ClaimHeaderMapping {
    pub claim_path: String,
    pub metadata_key: String,
}

pub fn parse_claim_headers(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    metadata_prefix: &str,
) -> Result<Vec<ClaimHeaderMapping>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("{plugin}: '{field}' must be an object, got: {value}"))?;
    let mut mappings = Vec::with_capacity(object.len());
    for (claim_path, header_value) in object {
        let parsed_claim_path = parse_claim_path_value(
            &format!("{field}.{claim_path}"),
            &Value::String(claim_path.clone()),
            plugin,
        )?;
        let raw_header = header_value.as_str().ok_or_else(|| {
            format!(
                "{plugin}: '{field}.{claim_path}' must be a header name string, got: {header_value}"
            )
        })?;
        let header_name = normalize_allowed_header(raw_header, plugin, field)?;
        let metadata_key = format!("{metadata_prefix}{header_name}");
        mappings.push(ClaimHeaderMapping {
            claim_path: parsed_claim_path,
            metadata_key,
        });
    }
    Ok(mappings)
}

pub fn emit_claim_headers_to_context(
    ctx: &mut RequestContext,
    claims: &Value,
    mappings: &[ClaimHeaderMapping],
    separator: &str,
) {
    for mapping in mappings {
        let Some(value) = claim_value_for_header(claims, &mapping.claim_path, separator) else {
            continue;
        };
        ctx.pending_claim_headers
            .insert(mapping.metadata_key.clone(), value);
    }
}

pub fn apply_claim_headers_from_context(
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
    metadata_prefix: &str,
) {
    let keys: Vec<String> = ctx
        .pending_claim_headers
        .keys()
        .filter(|key| key.starts_with(metadata_prefix))
        .cloned()
        .collect();
    for key in keys {
        let Some(header_name) = key.strip_prefix(metadata_prefix) else {
            continue;
        };
        if let Some(value) = ctx.pending_claim_headers.remove(&key) {
            headers.insert(header_name.to_string(), value);
        }
    }
}

pub fn parse_separator(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
    default_value: &str,
) -> Result<String, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value.to_string());
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{plugin}: '{field}' must be a string, got: {value}"))?;
    if raw.is_empty() {
        return Err(format!("{plugin}: '{field}' must not be empty"));
    }
    Ok(raw.to_string())
}

fn claim_value_for_header(claims: &Value, claim_path: &str, separator: &str) -> Option<String> {
    match resolve_claim_path(claims, claim_path)? {
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => {
            let parts: Vec<&str> = values.iter().filter_map(Value::as_str).collect();
            (!parts.is_empty()).then(|| parts.join(separator))
        }
        _ => None,
    }
}

fn normalize_allowed_header(raw_header: &str, plugin: &str, field: &str) -> Result<String, String> {
    let trimmed = raw_header.trim();
    if trimmed.is_empty() {
        return Err(format!("{plugin}: '{field}' header name must not be empty"));
    }
    let header = HeaderName::from_bytes(trimmed.as_bytes())
        .map_err(|e| format!("{plugin}: '{field}' header name is invalid: {e}"))?
        .as_str()
        .to_string();
    if is_reserved_header(&header) {
        return Err(format!(
            "{plugin}: '{field}' cannot target reserved header '{header}'"
        ));
    }
    Ok(header)
}

pub fn is_reserved_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "x-consumer-username"
            | "x-consumer-custom-id"
            | "host"
            | "connection"
            | "te"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "authorization"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_reserved_header_target() {
        let config = json!({"claim_headers": {"sub": "Authorization"}});
        let err = parse_claim_headers(
            config.as_object().expect("object"),
            "claim_headers",
            "test",
            "test.",
        )
        .expect_err("reserved header should reject");
        assert!(err.contains("reserved"));
    }

    #[test]
    fn emits_string_and_array_claims() {
        let mapping = vec![
            ClaimHeaderMapping {
                claim_path: "email".to_string(),
                metadata_key: "p.x-user-email".to_string(),
            },
            ClaimHeaderMapping {
                claim_path: "roles".to_string(),
                metadata_key: "p.x-user-roles".to_string(),
            },
        ];
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
        emit_claim_headers_to_context(
            &mut ctx,
            &json!({"email": "a@example.com", "roles": ["admin", "editor"]}),
            &mapping,
            ",",
        );
        assert_eq!(
            ctx.pending_claim_headers
                .get("p.x-user-email")
                .map(String::as_str),
            Some("a@example.com")
        );
        assert_eq!(
            ctx.pending_claim_headers
                .get("p.x-user-roles")
                .map(String::as_str),
            Some("admin,editor")
        );
    }
}
