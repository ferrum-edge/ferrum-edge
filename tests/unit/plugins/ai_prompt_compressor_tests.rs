//! Tests for the ai_prompt_compressor plugin.

use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, RequestContext, ai_prompt_compressor::AiPromptCompressor, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, create_test_context};

/// A compressor with a low token floor so tests can use short, readable inputs.
fn compressor(min_content_tokens: u64, ratio: f64) -> AiPromptCompressor {
    AiPromptCompressor::new(&json!({
        "min_content_tokens": min_content_tokens,
        "target_ratio": ratio,
    }))
    .unwrap()
}

fn json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

fn post_ctx(body: &Value) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(body).unwrap(),
    );
    ctx
}

/// A multi-sentence prose paragraph long enough to compress, embedding a URL, a
/// number, an identifier, and a negation to exercise the protected-span and
/// negation-preservation paths.
fn long_prompt_text() -> String {
    "The customer support assistant should always greet the user in a warm and \
     friendly manner before it begins to answer any of their many questions. \
     Please review the documentation at https://example.com/docs/v2 carefully and \
     remember that the account_id field is required. The maximum retry count is \
     4096 and the request must not be rejected when the payload is very large \
     because the downstream service can handle a great deal of concurrent load."
        .to_string()
}

fn chat_body(role: &str, content: &str) -> Value {
    json!({
        "model": "gpt-4o",
        "temperature": 0.7,
        "messages": [{"role": role, "content": content}],
    })
}

async fn transform(plugin: &AiPromptCompressor, body: &Value) -> Option<Value> {
    let bytes = serde_json::to_vec(body).unwrap();
    let headers = json_headers();
    plugin
        .transform_request_body(&bytes, Some("application/json"), &headers)
        .await
        .map(|out| serde_json::from_slice(&out).unwrap())
}

fn first_message_content(body: &Value) -> &str {
    body["messages"][0]["content"].as_str().unwrap()
}

// ─── Plugin basics ──────────────────────────────────────────────────────────

#[test]
fn plugin_metadata_matches_registration() {
    let plugin = AiPromptCompressor::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ai_prompt_compressor");
    assert_eq!(plugin.priority(), priority::AI_PROMPT_COMPRESSOR);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.modifies_request_body());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn default_config_is_valid() {
    assert!(AiPromptCompressor::new(&json!({})).is_ok());
}

#[test]
fn invalid_configs_rejected() {
    for config in [
        json!("not-an-object"),
        json!({"target_ratio": 0}),
        json!({"target_ratio": 1}),
        json!({"target_ratio": 1.5}),
        json!({"target_ratio": -0.2}),
        json!({"target_ratio": "half"}),
        json!({"compress_roles": []}),
        json!({"compress_roles": "user"}),
        json!({"compress_roles": [1, 2]}),
        json!({"min_content_tokens": "lots"}),
        json!({"min_content_tokens": -5}),
        json!({"max_scan_bytes": 0}),
        json!({"max_scan_bytes": "1024"}),
        json!({"preserve_tag": ""}),
        json!({"preserve_tag": "bad tag"}),
        json!({"preserve_tag": "no/slash"}),
    ] {
        assert!(
            AiPromptCompressor::new(&config).is_err(),
            "config should be rejected: {config:?}"
        );
    }
}

#[test]
fn valid_configs_accepted() {
    for config in [
        json!({"target_ratio": 0.3}),
        json!({"compress_roles": ["user", "system"]}),
        json!({"min_content_tokens": 0}),
        json!({"max_scan_bytes": 2048}),
        json!({"preserve_tag": "keep-this_1"}),
    ] {
        assert!(
            AiPromptCompressor::new(&config).is_ok(),
            "config should be accepted: {config:?}"
        );
    }
}

#[test]
fn should_buffer_only_json_post() {
    let plugin = compressor(5, 0.5);
    let ctx = post_ctx(&chat_body("user", "hello"));
    assert!(plugin.should_buffer_request_body(&ctx));

    let mut get_ctx = post_ctx(&chat_body("user", "hello"));
    get_ctx.method = "GET".to_string();
    assert!(!plugin.should_buffer_request_body(&get_ctx));

    let mut text_ctx = post_ctx(&chat_body("user", "hello"));
    text_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(!plugin.should_buffer_request_body(&text_ctx));

    let mut gzip_ctx = post_ctx(&chat_body("user", "hello"));
    gzip_ctx
        .headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    assert!(!plugin.should_buffer_request_body(&gzip_ctx));
}

// ─── Compression behavior ────────────────────────────────────────────────────

#[tokio::test]
async fn compresses_long_user_message() {
    let plugin = compressor(5, 0.5);
    let original = long_prompt_text();
    let body = chat_body("user", &original);

    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.chars().count() < original.chars().count(),
        "compressed content should be shorter"
    );
    // Non-content fields are preserved.
    assert_eq!(out["model"], json!("gpt-4o"));
    assert_eq!(out["temperature"], json!(0.7));
}

#[tokio::test]
async fn short_message_left_untouched_at_default_floor() {
    // Default min_content_tokens (200) leaves a small prompt alone.
    let plugin = AiPromptCompressor::new(&json!({})).unwrap();
    let body = chat_body("user", "Please summarize this short message for me.");
    assert!(
        transform(&plugin, &body).await.is_none(),
        "short content should pass through unchanged"
    );
}

#[tokio::test]
async fn system_role_preserved_by_default() {
    let plugin = compressor(5, 0.4);
    let system_text = long_prompt_text();
    let user_text = long_prompt_text();
    let body = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
    });

    let out = transform(&plugin, &body)
        .await
        .expect("should compress user");
    assert_eq!(
        out["messages"][0]["content"].as_str().unwrap(),
        system_text,
        "system content must be untouched by default"
    );
    assert!(
        out["messages"][1]["content"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            < user_text.chars().count(),
        "user content should be compressed"
    );
}

#[tokio::test]
async fn compress_roles_config_targets_system() {
    let plugin = AiPromptCompressor::new(&json!({
        "compress_roles": ["system"],
        "min_content_tokens": 5,
        "target_ratio": 0.4,
    }))
    .unwrap();
    let system_text = long_prompt_text();
    let user_text = long_prompt_text();
    let body = json!({
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
    });

    let out = transform(&plugin, &body)
        .await
        .expect("should compress system");
    assert!(
        out["messages"][0]["content"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            < system_text.chars().count(),
        "system content should be compressed"
    );
    assert_eq!(
        out["messages"][1]["content"].as_str().unwrap(),
        user_text,
        "user content should be untouched when only system is eligible"
    );
}

#[tokio::test]
async fn preserves_urls_numbers_and_negations() {
    // Aggressive ratio to prove protected spans survive heavy compression.
    let plugin = compressor(5, 0.3);
    let body = chat_body("user", &long_prompt_text());
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("https://example.com/docs/v2"),
        "URL must be preserved verbatim: {compressed:?}"
    );
    assert!(
        compressed.contains("4096"),
        "number must be preserved: {compressed:?}"
    );
    assert!(
        compressed.contains("account_id"),
        "identifier must be preserved: {compressed:?}"
    );
    assert!(
        compressed.contains("not"),
        "negation must be preserved: {compressed:?}"
    );
}

#[tokio::test]
async fn preserves_code_blocks() {
    let plugin = compressor(5, 0.3);
    let content = "Here is a very long explanation about the configuration options that the \
         operator can use to tune the behavior of the system in production. \
         ```json\n{\"retry\": true, \"limit\": 10}\n``` \
         Please make sure to read the whole thing carefully before you continue \
         and then apply the settings that best match your workload requirements."
        .to_string();
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("```json\n{\"retry\": true, \"limit\": 10}\n```"),
        "fenced code block must be preserved verbatim: {compressed:?}"
    );
}

#[tokio::test]
async fn preserve_tag_keeps_span_and_strips_markers() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 5,
        "target_ratio": 0.4,
    }))
    .unwrap();
    let content = "You should compress all of the surrounding filler text that does not \
         really matter very much at all, but <keep>THE ORDER NUMBER IS \
         ABC-9931-XYZ</keep> and everything after it can be shortened as needed \
         because it is just extra padding to exceed the token threshold here."
        .to_string();
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("THE ORDER NUMBER IS ABC-9931-XYZ"),
        "preserved span must survive verbatim: {compressed:?}"
    );
    assert!(
        !compressed.contains("<keep>") && !compressed.contains("</keep>"),
        "preserve markers must be stripped: {compressed:?}"
    );
}

#[tokio::test]
async fn multimodal_text_parts_compressed() {
    let plugin = compressor(5, 0.4);
    let long = long_prompt_text();
    let body = json!({
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": long},
                {"type": "image_url", "image_url": {"url": "https://img.example/x.png"}},
            ],
        }],
    });

    let out = transform(&plugin, &body)
        .await
        .expect("should compress text part");
    let parts = out["messages"][0]["content"].as_array().unwrap();
    assert!(parts[0]["text"].as_str().unwrap().chars().count() < long.chars().count());
    // The non-text part is untouched.
    assert_eq!(parts[1]["type"], json!("image_url"));
    assert_eq!(
        parts[1]["image_url"]["url"],
        json!("https://img.example/x.png")
    );
}

#[tokio::test]
async fn legacy_prompt_field_compressed_for_user() {
    let plugin = compressor(5, 0.4);
    let original = long_prompt_text();
    let body = json!({"model": "gpt-3.5-turbo-instruct", "prompt": original});
    let out = transform(&plugin, &body)
        .await
        .expect("should compress prompt");
    assert!(out["prompt"].as_str().unwrap().chars().count() < original.chars().count());
}

// ─── Passthrough / safety ────────────────────────────────────────────────────

#[tokio::test]
async fn non_json_content_type_passthrough() {
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();
    let headers = HashMap::new();
    assert!(
        plugin
            .transform_request_body(&bytes, Some("text/plain"), &headers)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn content_encoded_body_skipped() {
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(
        plugin
            .transform_request_body(&bytes, Some("application/json"), &headers)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn invalid_json_passthrough() {
    let plugin = compressor(5, 0.5);
    let headers = json_headers();
    assert!(
        plugin
            .transform_request_body(b"{not valid json", Some("application/json"), &headers)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn body_without_messages_passthrough() {
    let plugin = compressor(5, 0.5);
    let body = json!({"model": "gpt-4o", "foo": long_prompt_text()});
    assert!(transform(&plugin, &body).await.is_none());
}

#[tokio::test]
async fn oversized_body_skipped() {
    let plugin = AiPromptCompressor::new(&json!({
        "min_content_tokens": 5,
        "max_scan_bytes": 32,
    }))
    .unwrap();
    let body = chat_body("user", &long_prompt_text());
    assert!(
        transform(&plugin, &body).await.is_none(),
        "body over max_scan_bytes must be skipped"
    );
}

// ─── before_proxy integration ────────────────────────────────────────────────

#[tokio::test]
async fn before_proxy_rewrites_metadata_and_records_stats() {
    let plugin = compressor(5, 0.5);
    let original = long_prompt_text();
    let mut ctx = post_ctx(&chat_body("user", &original));
    let mut headers = json_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let rewritten = ctx.metadata.get("request_body").unwrap();
    let parsed: Value = serde_json::from_str(rewritten).expect("metadata body stays valid JSON");
    assert!(first_message_content(&parsed).chars().count() < original.chars().count());

    let saved: usize = ctx
        .metadata
        .get("ai_prompt_compressor.tokens_saved")
        .expect("tokens_saved recorded")
        .parse()
        .unwrap();
    assert!(saved > 0, "should report a positive token saving");
    assert_eq!(
        ctx.metadata
            .get("ai_prompt_compressor.fields_compressed")
            .map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn before_proxy_leaves_short_body_unchanged() {
    let plugin = AiPromptCompressor::new(&json!({})).unwrap();
    let body = chat_body("user", "just a short question");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let original = ctx.metadata.get("request_body").cloned().unwrap();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert_eq!(ctx.metadata.get("request_body"), Some(&original));
    assert!(
        !ctx.metadata
            .contains_key("ai_prompt_compressor.tokens_saved")
    );
}

#[tokio::test]
async fn before_proxy_skips_get_requests() {
    let plugin = compressor(5, 0.5);
    let body = chat_body("user", &long_prompt_text());
    let mut ctx = post_ctx(&body);
    ctx.method = "GET".to_string();
    let original = ctx.metadata.get("request_body").cloned().unwrap();
    let mut headers = json_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(ctx.metadata.get("request_body"), Some(&original));
}
