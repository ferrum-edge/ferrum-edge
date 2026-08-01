//! Shared Google Gemini / Vertex `generateContent` protocol helpers.
//!
//! Native Gemini API and Vertex AI streaming both emit
//! `GenerateContentResponse`-shaped JSON (candidates, `finishReason`,
//! `promptFeedback`, `usageMetadata`, `functionCall` parts). Keep the
//! security-relevant mappings in one place so buffered federation and the
//! streaming router cannot drift on finish / safety / usage semantics.
//!
//! These helpers never log or return provider payload bodies, tool arguments,
//! prompts, or credentials — callers must keep diagnostics fixed-cardinality.

use serde_json::Value;

/// Map a Gemini / Vertex `candidates[].finishReason` to an OpenAI Chat
/// Completions `finish_reason`. Unsupported or missing values fail closed.
pub fn map_gemini_finish_reason(native: &str) -> Result<&'static str, &'static str> {
    match native {
        "STOP" | "OTHER" | "FINISH_REASON_UNSPECIFIED" => Ok("stop"),
        "MAX_TOKENS" => Ok("length"),
        "SAFETY"
        | "RECITATION"
        | "LANGUAGE"
        | "BLOCKLIST"
        | "PROHIBITED_CONTENT"
        | "SPII"
        | "MODEL_ARMOR"
        | "MALFORMED_FUNCTION_CALL"
        | "IMAGE_SAFETY"
        | "IMAGE_PROHIBITED_CONTENT"
        | "IMAGE_OTHER"
        | "NO_IMAGE"
        | "IMAGE_RECITATION"
        | "UNEXPECTED_TOOL_CALL" => Ok("content_filter"),
        _ => Err("unsupported Gemini finishReason"),
    }
}

/// Whether `promptFeedback.blockReason` indicates the prompt was blocked.
///
/// Absent `promptFeedback` or an unspecified reason is not a block. Unknown
/// reasons fail closed so a new safety enum cannot silently pass.
pub fn gemini_prompt_feedback_is_blocked(resp: &Value) -> Result<bool, &'static str> {
    let Some(feedback) = resp.get("promptFeedback") else {
        return Ok(false);
    };
    let Some(feedback) = feedback.as_object() else {
        return Err("Gemini promptFeedback must be an object");
    };
    let Some(reason) = feedback.get("blockReason") else {
        return Ok(false);
    };
    match reason.as_str() {
        Some(
            "SAFETY" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "MODEL_ARMOR" | "IMAGE_SAFETY"
            | "JAILBREAK" | "OTHER",
        ) => Ok(true),
        Some("BLOCK_REASON_UNSPECIFIED" | "BLOCKED_REASON_UNSPECIFIED") => Ok(false),
        Some(_) => Err("Gemini promptFeedback has an unsupported blockReason"),
        None => Err("Gemini promptFeedback.blockReason must be a string"),
    }
}

/// Prompt / completion / total token counts from Gemini `usageMetadata`.
///
/// Missing fields are `None` (not invented). Non-integer values fail closed.
pub fn gemini_usage_token_counts(
    resp: &Value,
) -> Result<(Option<u64>, Option<u64>, Option<u64>), &'static str> {
    let Some(usage) = resp.get("usageMetadata") else {
        return Ok((None, None, None));
    };
    let Some(usage) = usage.as_object() else {
        return Err("Gemini usageMetadata must be an object");
    };
    let prompt = optional_u64_field(usage.get("promptTokenCount"), "promptTokenCount")?;
    let completion = optional_u64_field(usage.get("candidatesTokenCount"), "candidatesTokenCount")?;
    let total = optional_u64_field(usage.get("totalTokenCount"), "totalTokenCount")?;
    Ok((prompt, completion, total))
}

fn optional_u64_field(value: Option<&Value>, field: &'static str) -> Result<Option<u64>, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or("Gemini usageMetadata token count must be an unsigned integer"),
        Some(_) => {
            let _ = field;
            Err("Gemini usageMetadata token count must be an unsigned integer")
        }
    }
}

/// Serialize Gemini `functionCall.args` (already an object) to the OpenAI
/// `arguments` JSON string. Never embeds the args into an error message.
pub fn gemini_function_args_to_openai_string(args: &Value) -> Result<String, &'static str> {
    if !args.is_object() {
        return Err("Gemini functionCall args must be an object");
    }
    serde_json::to_string(args).map_err(|_| "Gemini functionCall args could not be serialized")
}

/// True when a streaming / buffered Gemini body looks like a provider terminal
/// error envelope (`{"error":{...}}`) rather than a GenerateContentResponse.
pub fn gemini_response_is_provider_error(resp: &Value) -> bool {
    resp.get("error").is_some_and(|error| error.is_object())
}
