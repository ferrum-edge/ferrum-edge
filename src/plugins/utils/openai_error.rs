//! Shared OpenAI Chat Completions error envelope helpers.

use bytes::Bytes;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::plugins::Plugin;

pub(crate) const OPENAI_INVALID_REQUEST_ERROR: &str = "invalid_request_error";
pub(crate) const OPENAI_CODE_MISSING_API_KEY: &str = "missing_api_key";
pub(crate) const OPENAI_CODE_INVALID_API_KEY: &str = "invalid_api_key";

const SERIALIZE_FAILURE_BODY: &[u8] =
    br#"{"error":{"message":"Failed to serialize error response","type":"server_error","param":null,"code":"internal_error"}}"#;

/// Build the nested OpenAI error object used by `ai_federation` and
/// `ai_stream_router`.
pub(crate) fn openai_error_body(
    message: &str,
    error_type: &str,
    param: Option<&str>,
    code: Option<&str>,
) -> Value {
    json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": param,
            "code": code,
        }
    })
}

/// Serialize [`openai_error_body`] to response bytes. `message` is JSON-escaped
/// by `serde_json`.
pub(crate) fn openai_error_body_bytes(
    message: &str,
    error_type: &str,
    param: Option<&str>,
    code: Option<&str>,
) -> Bytes {
    match serde_json::to_vec(&openai_error_body(message, error_type, param, code)) {
        Ok(bytes) => Bytes::from(bytes),
        Err(_) => Bytes::from_static(SERIALIZE_FAILURE_BODY),
    }
}

/// Read the human-readable message from Ferrum's flat `{"error":"<string>"}`
/// reject body. Returns `None` when the body is not that shape.
pub(crate) fn ferrum_flat_error_message(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("error")
        .and_then(|error| error.as_str())
        .map(str::to_string)
}

/// Whether an effective plugin chain includes an OpenAI-envelope AI gateway
/// plugin whose downstream rejects already speak the nested contract.
pub(crate) fn proxy_has_openai_auth_error_envelope_plugin(plugins: &[Arc<dyn Plugin>]) -> bool {
    plugins
        .iter()
        .any(|plugin| matches!(plugin.name(), "ai_federation" | "ai_stream_router"))
}
