//! Tests for the ai_prompt_compressor plugin.

use ferrum_edge::_test_support::{
    ai_prompt_compressor_marker_scan_work_for_test, run_request_body_stage_with_context_for_test,
};
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext,
    ai_prompt_compressor::AiPromptCompressor, compression::CompressionPlugin, priority,
    request_transformer::RequestTransformer,
};
use serde_json::{Value, json};
use serial_test::serial;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::Barrier;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

/// A compressor with a low token floor so tests can use short, readable inputs.
fn compressor(min_content_tokens: u64, ratio: f64) -> AiPromptCompressor {
    AiPromptCompressor::new(&json!({
        "min_content_tokens": min_content_tokens,
        "target_ratio": ratio,
    }))
    .unwrap()
}

/// JSON request headers with explicit compatibility pseudo-headers for the
/// no-context `transform_request_body` hook.
fn json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(":method".to_string(), "POST".to_string());
    headers.insert(":path".to_string(), "/v1/chat/completions".to_string());
    headers
}

fn post_ctx(body: &Value) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/v1/chat/completions".to_string();
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
    transform_at_path(plugin, body, "/v1/chat/completions").await
}

async fn transform_at_path(plugin: &AiPromptCompressor, body: &Value, path: &str) -> Option<Value> {
    let bytes = serde_json::to_vec(body).unwrap();
    let mut headers = json_headers();
    headers.insert(":path".to_string(), path.to_string());
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
    assert!(
        plugin.priority() > priority::COMPRESSION,
        "request decompression must run before prompt compression"
    );
    assert!(
        plugin.priority() < priority::AI_FEDERATION,
        "federated direct dispatch must see plaintext prompt compression metadata"
    );
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.modifies_request_body());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_final_request_body_context());
    assert_eq!(plugin.request_body_buffer_limit(), None);

    let marker_plugin = AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap();
    assert_eq!(marker_plugin.request_body_buffer_limit(), Some(1_048_576));
}

#[test]
fn default_config_is_valid() {
    assert!(AiPromptCompressor::new(&json!({})).is_ok());
}

#[test]
fn invalid_configs_rejected() {
    for config in [
        json!(null),
        json!("not-an-object"),
        json!([]),
        json!({"target_ratio": 0}),
        json!({"target_ratio": 1}),
        json!({"target_ratio": 1.5}),
        json!({"target_ratio": -0.2}),
        json!({"target_ratio": "half"}),
        json!({"compress_roles": []}),
        json!({"compress_roles": [""]}),
        json!({"compress_roles": ["   "]}),
        json!({"compress_roles": "user"}),
        json!({"compress_roles": [1, 2]}),
        json!({"min_content_tokens": "lots"}),
        json!({"min_content_tokens": -5}),
        json!({"max_scan_bytes": 0}),
        json!({"max_scan_bytes": "1024"}),
        json!({"max_scan_bytes": 1_048_577}),
        json!({"min_content_tokens": 131_073}),
        json!({"preserve_tag": ""}),
        json!({"preserve_tag": " keep"}),
        json!({"preserve_tag": "keep "}),
        json!({"preserve_tag": "bad tag"}),
        json!({"preserve_tag": "no/slash"}),
        json!({"preserve_tag": "x".repeat(65)}),
        json!({"request_family": "images"}),
        json!({"request_family": "text_completions", "compress_roles": ["system"]}),
        json!({"compress_role": ["system"]}),
        json!({"target_rato": 0.9}),
        json!({"compress_roles": null}),
        json!({"min_content_tokens": null}),
        json!({"max_scan_bytes": null}),
        json!({"preserve_tag": null}),
        json!({"request_family": null}),
        json!({"request_family": "gemini"}),
        json!({"compress_roles": (0..33).map(|index| format!("role{index}")).collect::<Vec<_>>()}),
        json!({"compress_roles": ["r".repeat(65)]}),
        json!({"min_content_tokens": 200.5}),
        json!({"min_content_tokens": -1.0}),
        json!({"target_max_tokens": 0}),
        json!({"target_max_tokens": 131_073}),
        json!({"target_max_tokens": "lots"}),
        json!({"target_max_tokens": null}),
        json!({"mode": "shadow"}),
        json!({"mode": null}),
        json!({"sample_rate": 0}),
        json!({"sample_rate": -0.5}),
        json!({"sample_rate": 1.01}),
        json!({"sample_rate": null}),
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
        json!({"min_content_tokens": 131_072}),
        json!({"max_scan_bytes": 2048}),
        json!({"preserve_tag": "keep-this_1"}),
        json!({"preserve_tag": "x".repeat(64)}),
        json!({"request_family": "auto"}),
        json!({"request_family": "chat_completions"}),
        json!({"request_family": "text_completions"}),
        json!({"request_family": "text_completions", "compress_roles": [" User "]}),
        json!({"request_family": "responses"}),
        json!({"request_family": "anthropic_messages"}),
        json!({"compress_roles": (0..32).map(|index| format!("role{index}")).collect::<Vec<_>>()}),
        json!({"compress_roles": ["r".repeat(64)]}),
        json!({"min_content_tokens": 200.0}),
        json!({"max_scan_bytes": 2048.0}),
        json!({"target_max_tokens": 1}),
        json!({"target_max_tokens": 8000.0}),
        json!({"target_max_tokens": 131_072}),
        json!({"mode": "enforce"}),
        json!({"mode": "observe"}),
        json!({"sample_rate": 1}),
        json!({"sample_rate": 0.01}),
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

    let mut image_ctx = post_ctx(&json!({"prompt": long_prompt_text()}));
    image_ctx.path = "/v1/images/generations".to_string();
    assert!(
        !plugin.should_buffer_request_body(&image_ctx),
        "auto mode must not buffer unrelated provider operations"
    );

    let fixed = AiPromptCompressor::new(&json!({
        "request_family": "chat_completions"
    }))
    .unwrap();
    let mut custom_ctx = post_ctx(&chat_body("user", &long_prompt_text()));
    custom_ctx.path = "/custom/llm".to_string();
    assert!(
        fixed.should_buffer_request_body(&custom_ctx),
        "a fixed family is the explicit custom-path opt-in"
    );

    let marker_plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "max_scan_bytes": 64
    }))
    .unwrap();
    let mut marker_ctx = post_ctx(&chat_body("user", "<keep>hello</keep>"));
    marker_ctx
        .headers
        .insert("content-length".to_string(), "1000".to_string());
    assert!(
        marker_plugin.should_buffer_request_body(&marker_ctx),
        "marker sanitation must remain buffered above the compression scan cap"
    );
}

// ─── Compression behavior ────────────────────────────────────────────────────

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
async fn preserves_matching_backtick_runs_property() {
    let plugin = compressor(5, 0.2);
    for run_length in 1..=6 {
        let delimiter = "`".repeat(run_length);
        let inner = if run_length == 1 {
            "retryPolicy()"
        } else {
            "retryPolicy(`embedded`)"
        };
        let span = format!("{delimiter}{inner}{delimiter}");
        let content = format!(
            "This deliberately repetitive surrounding explanation contains many ordinary filler \
             words that should be removed aggressively while {span} remains exactly intact and \
             additional descriptive terminology keeps the overall prompt sufficiently long."
        );
        let out = transform(&plugin, &chat_body("user", &content))
            .await
            .expect("surrounding prose should compress");
        let compressed = first_message_content(&out);
        assert!(
            compressed.contains(&span),
            "{run_length}-backtick span changed: {compressed:?}"
        );
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn unmatched_backtick_run_protects_remainder() {
    let plugin = compressor(5, 0.2);
    let protected = "``unclosed retryPolicy(`embedded`) exact tail";
    let content = format!(
        "This surrounding prose has numerous ordinary expendable words for aggressive \
         statistical compression before {protected}"
    );
    let out = transform(&plugin, &chat_body("user", &content))
        .await
        .expect("prefix should compress");
    assert!(first_message_content(&out).contains(protected));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
async fn nested_preserve_spans_flatten_without_marker_leaks() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 5,
        "target_ratio": 0.2
    }))
    .unwrap();
    let protected = "outer <keep>inner</keep> tail";
    let content = format!(
        "This long surrounding explanation contains many ordinary filler words that can be \
         removed safely before <keep>{protected}</keep> and many additional low importance \
         words follow afterward to guarantee a successful statistical reduction."
    );
    let out = transform(&plugin, &chat_body("user", &content))
        .await
        .expect("surrounding text should compress");
    let compressed = first_message_content(&out);

    assert!(compressed.contains("outer inner tail"));
    assert!(!compressed.contains("<keep>"));
    assert!(!compressed.contains("</keep>"));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_marker_cleanup_is_deterministic_property() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200
    }))
    .unwrap();
    for (input, expected) in [
        (
            "<keep>outer <keep>inner</keep> tail</keep>",
            "outer inner tail",
        ),
        ("<keep>one</keep><keep>two</keep>", "onetwo"),
        ("left </keep> right", "left  right"),
        ("<keep>unterminated", "unterminated"),
        ("open <keep></keep> close", "open  close"),
    ] {
        let out = transform(&plugin, &chat_body("user", input))
            .await
            .expect("marker removal is a body rewrite");
        assert_eq!(first_message_content(&out), expected);
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn common_identifiers_and_unicode_numbers_are_verbatim_property() {
    let plugin = compressor(5, 0.1);
    let protected = [
        "4096",
        "١٢٣٤",
        "account_id",
        "retryPolicy",
        "HttpClient",
        "retry-policy",
        "HTTP",
        "(retryPolicy)",
        "配置١٢",
    ];
    let content = format!(
        "Repeated ordinary ordinary prose surrounds {} while extraordinarily descriptive \
         configuration requirements and interoperability terminology create aggressive \
         competition among every unprotected candidate word in this request.",
        protected.join(" ")
    );
    let out = transform(&plugin, &chat_body("user", &content))
        .await
        .expect("ordinary prose should compress");
    let compressed = first_message_content(&out);
    for token in protected {
        assert!(
            compressed.contains(token),
            "protected token {token:?} missing from {compressed:?}"
        );
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn frequency_scoring_is_case_insensitive_without_token_copies() {
    let plugin = compressor(1, 0.25);
    let body = chat_body("user", "account Account account extraordinarily");
    let out = transform(&plugin, &body)
        .await
        .expect("repeated variants should compress");
    let compressed = first_message_content(&out);

    assert_eq!(compressed, "extraordinarily");
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
async fn chat_multimodal_plain_string_parts_are_rejected_consistently() {
    let plugin = compressor(1, 0.4);
    let body = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [long_prompt_text(), {"type": "text", "text": long_prompt_text()}]
        }]
    });

    assert!(
        transform(&plugin, &body).await.is_none(),
        "measurement and mutation walkers must both reject plain strings in chat content arrays"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn legacy_prompt_field_compressed_for_user() {
    let plugin = compressor(5, 0.4);
    let original = long_prompt_text();
    let body = json!({"model": "gpt-3.5-turbo-instruct", "prompt": original});
    let out = transform_at_path(&plugin, &body, "/v1/completions")
        .await
        .expect("should compress prompt");
    assert!(out["prompt"].as_str().unwrap().chars().count() < original.chars().count());
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn request_family_gate_rejects_unrelated_and_ambiguous_shapes() {
    let plugin = compressor(5, 0.4);
    let prompt = long_prompt_text();

    let image = json!({"model": "gpt-image-1", "prompt": prompt});
    assert!(
        transform_at_path(&plugin, &image, "/v1/images/generations")
            .await
            .is_none(),
        "image-generation prompt must pass through"
    );
    assert!(
        transform_at_path(&plugin, &image, "/custom/jobs")
            .await
            .is_none(),
        "arbitrary JSON prompt must pass through"
    );

    let ambiguous = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": long_prompt_text()}],
        "prompt": long_prompt_text()
    });
    assert!(transform(&plugin, &ambiguous).await.is_none());

    let provider_native = json!({
        "model": "claude-compatible",
        "system": "provider-native instruction",
        "messages": [{"role": "user", "content": long_prompt_text()}]
    });
    assert!(transform(&plugin, &provider_native).await.is_none());

    let malformed = json!({
        "model": "gpt-4o",
        "messages": [{"role": 7, "content": long_prompt_text()}]
    });
    assert!(transform(&plugin, &malformed).await.is_none());
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn fixed_family_explicitly_supports_compatible_custom_paths() {
    let auto = compressor(5, 0.4);
    let body = chat_body("user", &long_prompt_text());
    assert!(
        transform_at_path(&auto, &body, "/custom/llm")
            .await
            .is_none()
    );

    let fixed = AiPromptCompressor::new(&json!({
        "request_family": "chat_completions",
        "min_content_tokens": 5,
        "target_ratio": 0.4
    }))
    .unwrap();
    assert!(
        transform_at_path(&fixed, &body, "/custom/llm")
            .await
            .is_some()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn successful_rewrite_reserializes_complete_json_body() {
    let plugin = compressor(5, 0.4);
    let raw = format!(
        "{{\n  \"model\": \"gpt-4o\",\n  \"duplicate\": 1,\n  \"duplicate\": 2,\n  \"metadata\": {{\"escaped\": \"\\u0061\"}},\n  \"messages\": [{{\"role\": \"user\", \"content\": {}}}]\n}}",
        serde_json::to_string(&long_prompt_text()).unwrap()
    );
    let output = plugin
        .transform_request_body(raw.as_bytes(), Some("application/json"), &json_headers())
        .await
        .expect("eligible field should be rewritten");
    let output_text = String::from_utf8(output).unwrap();

    assert_ne!(output_text, raw);
    assert!(!output_text.contains("\n  "));
    assert!(output_text.contains(r#""escaped":"a""#));
    assert_eq!(output_text.matches(r#""duplicate""#).count(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&output_text).unwrap()["duplicate"],
        json!(2)
    );
}

// ─── Passthrough / safety ────────────────────────────────────────────────────

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn non_json_content_type_passthrough() {
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();
    let mut headers = HashMap::new();
    headers.insert(":method".to_string(), "POST".to_string());
    assert!(
        plugin
            .transform_request_body(&bytes, Some("text/plain"), &headers)
            .await
            .is_none()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
async fn body_without_messages_passthrough() {
    let plugin = compressor(5, 0.5);
    let body = json!({"model": "gpt-4o", "foo": long_prompt_text()});
    assert!(transform(&plugin, &body).await.is_none());
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn adversarial_token_and_field_budgets_pass_through() {
    let plugin = compressor(1, 0.5);

    let too_many_units = "x ".repeat(32_769);
    assert!(
        transform(&plugin, &chat_body("user", &too_many_units))
            .await
            .is_none(),
        "token-unit budget must be checked before token allocation"
    );

    let too_many_split_tokens = "a`x`".repeat(32_769);
    assert!(
        transform(&plugin, &chat_body("user", &too_many_split_tokens))
            .await
            .is_none(),
        "backtick splitting must not bypass the emitted-token budget"
    );

    let too_many_parts: Vec<Value> = (0..257)
        .map(|index| json!({"type": "text", "text": format!("field {index} ordinary prose")}))
        .collect();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": too_many_parts}]
    });
    assert!(
        transform(&plugin, &body).await.is_none(),
        "field budget must reject the entire rewrite"
    );

    let too_many_prompt_bytes = "a".repeat(524_289);
    assert!(
        transform(&plugin, &chat_body("user", &too_many_prompt_bytes))
            .await
            .is_none(),
        "eligible prompt bytes have a separate hard ceiling"
    );

    let marker_plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "x",
        "min_content_tokens": 1,
        "target_ratio": 0.5
    }))
    .unwrap();
    let too_many_markers = "a</x>".repeat(1_025);
    let sanitized = transform(&marker_plugin, &chat_body("user", &too_many_markers))
        .await
        .expect("over-budget preserve markers must take the sanitation fallback");
    assert_eq!(
        first_message_content(&sanitized),
        "a".repeat(1_025),
        "marker fallback must remove every configured marker"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_markers_are_stripped_above_each_compression_work_budget() {
    let marker_plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 1,
        "max_scan_bytes": 128,
        "target_ratio": 0.5
    }))
    .unwrap();

    let over_scan = format!(
        "prefix <keep>critical</keep> {}",
        "ordinary filler language ".repeat(20)
    );
    let sanitized = transform(&marker_plugin, &chat_body("user", &over_scan))
        .await
        .expect("body-cap fallback must sanitize markers");
    assert_eq!(
        first_message_content(&sanitized),
        over_scan.replace("<keep>", "").replace("</keep>", "")
    );

    let marker_plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 1,
        "target_ratio": 0.5
    }))
    .unwrap();
    let over_text = format!("<keep>critical</keep>{}", "a".repeat(524_289));
    let sanitized = transform(&marker_plugin, &chat_body("user", &over_text))
        .await
        .expect("eligible-text fallback must sanitize markers");
    assert_eq!(
        first_message_content(&sanitized),
        over_text.replace("<keep>", "").replace("</keep>", "")
    );

    let parts: Vec<Value> = (0..257)
        .map(|index| {
            json!({
                "type": "text",
                "text": if index == 0 {
                    "<keep>critical</keep>".to_string()
                } else {
                    "ordinary prose".to_string()
                }
            })
        })
        .collect();
    let field_body = json!({
        "messages": [{"role": "user", "content": parts}]
    });
    let sanitized = transform(&marker_plugin, &field_body)
        .await
        .expect("field-count fallback must sanitize markers");
    assert_eq!(sanitized["messages"][0]["content"][0]["text"], "critical");
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn decoded_body_above_hard_marker_bound_fails_closed_in_final_hook() {
    let plugin = AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap();
    let body = serde_json::to_vec(&chat_body(
        "user",
        &format!("<keep>critical</keep>{}", "x".repeat(1_048_576)),
    ))
    .unwrap();
    let mut ctx = post_ctx(&chat_body("user", "placeholder"));
    assert!(
        plugin
            .transform_request_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &json_headers(),
            )
            .await
            .is_none()
    );
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &body)
            .await,
        PluginResult::Reject {
            status_code: 413,
            ..
        }
    ));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_split_backticks_use_the_combined_token_work_bound() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 1,
        "target_ratio": 0.2
    }))
    .unwrap();
    let content = format!(
        "`prefix<keep>critical</keep> {} `{}",
        "x ".repeat(18_000),
        "a`x`".repeat(15_000)
    );
    let expected = content.replace("<keep>", "").replace("</keep>", "");
    let sanitized = transform(&plugin, &chat_body("user", &content))
        .await
        .expect("combined token-work overflow must use marker-only fallback");
    assert_eq!(first_message_content(&sanitized), expected);
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn escaped_preserve_markers_are_removed_without_json_canonicalization() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let raw = br#"{ "messages": [{"role":"user","content":"before \u003ckeep\u003ecritical\u003c\/keep\u003e after"}], "n": 1e8 }"#;
    let output = plugin
        .transform_request_body(raw, Some("application/json"), &json_headers())
        .await
        .expect("escaped markers must be sanitized");
    assert_eq!(
        output,
        br#"{ "messages": [{"role":"user","content":"before critical after"}], "n": 1e8 }"#
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_marker_cleanup_never_rewrites_json_member_names() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let raw = br#"{"messages":[{"role":"user","content":"<keep>short</keep>"}],"tool<keep>s":[],"response_format<keep>":{"type":"json_object"}}"#;
    let output = plugin
        .transform_request_body(raw, Some("application/json"), &json_headers())
        .await
        .expect("prompt markers must be sanitized");

    assert_eq!(
        output,
        br#"{"messages":[{"role":"user","content":"short"}],"tool<keep>s":[],"response_format<keep>":{"type":"json_object"}}"#,
        "sanitation must not create backend-visible object members"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_marker_cleanup_preserves_member_name_bytes_across_json_shapes() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let raw = br#"{
  "messages" : [{"role":"user","content":"say \"<keep>short</keep>\\done"}],
  "tool<keep>s" : {
    "quote\"<keep>key" : "<keep>one</keep>",
    "slash\\<keep>key": "\u003ckeep\u003etwo\u003c\/keep\u003e",
    "\u006bey\u003ckeep\u003e": [
      {"nested<keep>" : "<keep>three</keep>"},
      "<keep>array</keep>"
    ]
  },
  "dup<keep>" : "first<keep>value</keep>",
  "dup<keep>" : "second</keep>"
}"#;
    let output = plugin
        .transform_request_body(raw, Some("application/json"), &json_headers())
        .await
        .expect("every JSON string value must be sanitized");

    assert_eq!(
        output,
        br#"{
  "messages" : [{"role":"user","content":"say \"short\\done"}],
  "tool<keep>s" : {
    "quote\"<keep>key" : "one",
    "slash\\<keep>key": "two",
    "\u006bey\u003ckeep\u003e": [
      {"nested<keep>" : "three"},
      "array"
    ]
  },
  "dup<keep>" : "firstvalue",
  "dup<keep>" : "second"
}"#,
        "keys, duplicate members, escapes, whitespace, and nesting must remain byte-exact"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_marker_cleanup_scans_large_literal_unicode_strings_linearly() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let unicode_key = format!("{}<keep>key", "鍵".repeat(32_768));
    let unicode_value = "値".repeat(32_768);
    let raw = format!(
        "{{\"messages\":[{{\"role\":\"user\",\"content\":\"short\"}}],\"{unicode_key}\":\"<keep>{unicode_value}</keep>\"}}"
    );
    let expected = format!(
        "{{\"messages\":[{{\"role\":\"user\",\"content\":\"short\"}}],\"{unicode_key}\":\"{unicode_value}\"}}"
    );

    let output = plugin
        .transform_request_body(raw.as_bytes(), Some("application/json"), &json_headers())
        .await
        .expect("large literal Unicode strings must be sanitized");

    assert_eq!(output, expected.as_bytes());

    let (instrumented_output, utf8_validation_bytes, scalar_scan_bytes) =
        ai_prompt_compressor_marker_scan_work_for_test(raw.as_bytes(), "keep")
            .expect("the instrumented production scanner must sanitize the same body");
    assert_eq!(instrumented_output, expected.as_bytes());
    // The scanner retains a validated `&str`; restoring validation of every
    // remaining non-ASCII suffix would make this count quadratic.
    assert_eq!(
        utf8_validation_bytes,
        raw.len(),
        "UTF-8 validation must examine the bounded body exactly once"
    );
    assert!(
        scalar_scan_bytes <= raw.len().saturating_mul(4),
        "scalar scanner work must remain linear: {scalar_scan_bytes} units for {} input bytes",
        raw.len()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_markers_in_member_names_alone_do_not_trigger_a_rewrite() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let raw = br#"{"messages":[{"role":"user","content":"plain"}],"only<keep>key":1,"\u003ckeep\u003e":2}"#;

    assert!(
        plugin
            .transform_request_body(raw, Some("application/json"), &json_headers())
            .await
            .is_none(),
        "markers confined to member names must leave the original representation untouched"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn malformed_or_truncated_json_never_reaches_member_name_sanitation() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let malformed: &[&[u8]] = &[
        br#"{"messages":[{"role":"user","content":"<keep>value</keep>"}],"unterminated<keep>:"#,
        br#"{"messages":[{"role":"user","content":"<keep>value</keep>"}],"escape\<keep>":"x"}"#,
        br#"{"messages":[{"role":"user","content":"<keep>value</keep>"}],"unicode\u003":"x"}"#,
        br#"{"messages":[{"role":"user","content":"<keep>value</keep>"}],"key":"unterminated<keep>}"#,
        br#"{"messages":[{"role":"user","content":"<keep>value</keep>"}]"#,
    ];

    for raw in malformed {
        assert!(
            plugin
                .transform_request_body(raw, Some("application/json"), &json_headers())
                .await
                .is_none(),
            "malformed input must remain an unchanged passthrough: {:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn exponent_growth_within_hard_output_cap_keeps_successful_compression() {
    let plugin = compressor(5, 0.5);
    let padding = std::iter::repeat_n("1e8", 10_000)
        .collect::<Vec<_>>()
        .join(",");
    let raw = format!(
        r#"{{"padding":[{padding}],"messages":[{{"role":"user","content":{}}}]}}"#,
        serde_json::to_string(&long_prompt_text()).unwrap()
    );
    let output = plugin
        .transform_request_body(raw.as_bytes(), Some("application/json"), &json_headers())
        .await
        .expect("bounded exponent normalization must not abandon compression");
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert!(first_message_content(&parsed).len() < long_prompt_text().len());
    assert!(
        output.len() > raw.len() + 65_536,
        "fixture must exceed the retired 64 KiB lexical-growth allowance"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn output_overflow_falls_back_to_representation_preserving_marker_cleanup() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 5,
        "target_ratio": 0.5
    }))
    .unwrap();
    let padding = std::iter::repeat_n("1e8", 100_000)
        .collect::<Vec<_>>()
        .join(",");
    let prompt = format!("<keep>critical</keep> {}", long_prompt_text());
    let raw = format!(
        r#"{{ "padding": [{padding}], "messages": [{{"role":"user","content":{}}}] }}"#,
        serde_json::to_string(&prompt).unwrap()
    );
    assert!(raw.len() < 1_048_576);
    let output = plugin
        .transform_request_body(raw.as_bytes(), Some("application/json"), &json_headers())
        .await
        .expect("output overflow must retain a marker-safe fallback");
    assert_eq!(
        output,
        raw.replace("<keep>", "")
            .replace("</keep>", "")
            .into_bytes(),
        "fallback must preserve exponent spelling and all unrelated JSON bytes"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn concurrent_saturation_never_turns_markers_into_passthrough() {
    const TASKS: usize = 16;
    let plugin = Arc::new(
        AiPromptCompressor::new(&json!({
            "preserve_tag": "keep",
            "min_content_tokens": 1,
            "target_ratio": 0.5
        }))
        .unwrap(),
    );
    let words = (0..12_000)
        .map(|mut index| {
            let mut suffix = ['a'; 4];
            for character in suffix.iter_mut().rev() {
                *character = char::from(b'a' + (index % 26) as u8);
                index /= 26;
            }
            format!("meaningful{}", suffix.iter().collect::<String>())
        })
        .collect::<Vec<_>>()
        .join(" ");
    let raw = Arc::new(
        serde_json::to_vec(&chat_body(
            "user",
            &format!("<keep>critical</keep> {words}"),
        ))
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(TASKS + 1));
    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let plugin = Arc::clone(&plugin);
        let raw = Arc::clone(&raw);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            plugin
                .transform_request_body(&raw, Some("application/json"), &json_headers())
                .await
                .expect("every admitted marker request must produce sanitized bytes")
        }));
    }
    barrier.wait().await;
    for handle in handles {
        let output = handle.await.unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("<keep>") && !text.contains("</keep>"));
    }
}

// ─── before_proxy integration ────────────────────────────────────────────────

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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
    assert!(ctx.metadata.keys().any(|key| {
        key.starts_with("ai_prompt_compressor.instances.") && key.ends_with(".tokens_saved")
    }));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn auto_family_uses_incoming_path_for_staged_and_recomputed_wire_bodies() {
    let plugin = compressor(5, 0.5);
    let incoming_text = long_prompt_text();
    let incoming_body = chat_body("user", &incoming_text);
    let changed_text = format!(
        "{} {}",
        incoming_text,
        "authoritative transformed representation terminology ".repeat(8)
    );

    for final_body in [incoming_body.clone(), chat_body("user", &changed_text)] {
        let mut ctx = post_ctx(&incoming_body);
        // Public metadata is attacker-influenced plugin state and must never be
        // authoritative for request-family admission.
        ctx.metadata.insert(
            "ai_prompt_compressor.classification_path".to_string(),
            "/v1/images/generations".to_string(),
        );
        let mut headers = json_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

        // Mirrors mesh_route_dispatch applying its staged rewrite after the
        // complete before_proxy chain.
        ctx.path = "/internal/provider/generate".to_string();
        let final_bytes = serde_json::to_vec(&final_body).unwrap();
        let output = plugin
            .transform_request_body_with_context(
                &mut ctx,
                &final_bytes,
                Some("application/json"),
                &headers,
            )
            .await
            .expect("route rewrite must not change auto-family eligibility");
        let parsed: Value = serde_json::from_slice(&output).unwrap();
        assert!(
            first_message_content(&parsed).len() < first_message_content(&final_body).len(),
            "both staged reuse and changed-body recomputation must compress"
        );
        assert!(
            !ctx.metadata
                .contains_key("ai_prompt_compressor.classification_path"),
            "classification state must not survive in public metadata"
        );
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn fixed_family_remains_eligible_across_custom_route_rewrites() {
    let plugin = AiPromptCompressor::new(&json!({
        "request_family": "chat_completions",
        "min_content_tokens": 5,
        "target_ratio": 0.5
    }))
    .unwrap();
    let incoming_body = chat_body("user", &long_prompt_text());
    let mut ctx = post_ctx(&incoming_body);
    ctx.path = "/custom/incoming/chat".to_string();
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    ctx.path = "/custom/backend/generate".to_string();
    let changed_body = chat_body(
        "user",
        &format!(
            "{} {}",
            long_prompt_text(),
            "body transformer output terminology ".repeat(8)
        ),
    );
    let changed_bytes = serde_json::to_vec(&changed_body).unwrap();
    let output = plugin
        .transform_request_body_with_context(
            &mut ctx,
            &changed_bytes,
            Some("application/json"),
            &headers,
        )
        .await
        .expect("fixed family must remain independent of incoming and backend paths");
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert!(first_message_content(&parsed).len() < first_message_content(&changed_body).len());
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn auto_family_does_not_gain_eligibility_from_backend_route_rewrite() {
    let plugin = compressor(5, 0.5);
    let body = chat_body("user", &long_prompt_text());
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    ctx.path = "/custom/incoming/generate".to_string();
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    ctx.path = "/v1/chat/completions".to_string();
    assert!(
        plugin
            .transform_request_body_with_context(
                &mut ctx,
                &raw,
                Some("application/json"),
                &headers,
            )
            .await
            .is_none(),
        "a backend rewrite to a standard path must not admit a custom incoming operation"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn large_metadata_rewrite_still_produces_wire_body_beyond_stage_cap() {
    let plugin = compressor(1, 0.9);
    let words = (0..10_000)
        .map(|mut index| {
            let mut suffix = ['a'; 5];
            for character in suffix.iter_mut().rev() {
                *character = char::from(b'a' + (index % 26) as u8);
                index /= 26;
            }
            format!("meaningful{}", suffix.iter().collect::<String>())
        })
        .collect::<Vec<_>>()
        .join(" ");
    let body = chat_body("user", &words);
    let original = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        ctx.metadata["request_body"].len() > 65_536,
        "fixture must exercise the no-large-private-stage path"
    );
    ctx.path = "/internal/provider/generate".to_string();

    let wire = plugin
        .transform_request_body_with_context(
            &mut ctx,
            &original,
            Some("application/json"),
            &headers,
        )
        .await
        .expect("large unstaged metadata rewrite must recompute for wire dispatch");
    let parsed: Value = serde_json::from_slice(&wire).unwrap();
    assert!(first_message_content(&parsed).len() < words.len());
    assert!(wire.len() > 65_536);
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn final_wire_stats_replace_provisional_metadata_stats() {
    let plugin = compressor(5, 0.5);
    let provisional = long_prompt_text();
    let mut ctx = post_ctx(&chat_body("user", &provisional));
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let final_wire_text = format!(
        "{} {}",
        long_prompt_text(),
        "additional authoritative wire representation terminology ".repeat(8)
    );
    let final_body = serde_json::to_vec(&chat_body("user", &final_wire_text)).unwrap();
    let output = plugin
        .transform_request_body_with_context(
            &mut ctx,
            &final_body,
            Some("application/json"),
            &headers,
        )
        .await
        .expect("the changed final wire body should be compressed");
    assert!(serde_json::from_slice::<Value>(&output).is_ok());

    let expected_original_tokens = final_wire_text.chars().count().div_ceil(4);
    let recorded: usize = ctx.metadata["ai_prompt_compressor.original_tokens"]
        .parse()
        .unwrap();
    assert_eq!(recorded, expected_original_tokens);
    assert_ne!(recorded, provisional.chars().count().div_ceil(4));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn multiple_instances_keep_distinct_final_wire_stats() {
    let first = compressor(5, 0.8);
    let second = compressor(5, 0.5);
    let body = chat_body("user", &long_prompt_text());
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();

    assert_continue(first.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(second.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        !ctx.metadata
            .keys()
            .any(|key| key.contains("classification_path")),
        "shared request-family state must stay out of per-instance metadata"
    );
    ctx.path = "/internal/provider/generate".to_string();
    let first_wire = first
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("first instance should compress");
    let _final_wire = second
        .transform_request_body_with_context(
            &mut ctx,
            &first_wire,
            Some("application/json"),
            &headers,
        )
        .await
        .expect("second instance should compress");

    let per_instance_saved: Vec<&String> = ctx
        .metadata
        .iter()
        .filter(|(key, _)| {
            key.starts_with("ai_prompt_compressor.instances.") && key.ends_with(".tokens_saved")
        })
        .map(|(_, value)| value)
        .collect();
    assert_eq!(per_instance_saved.len(), 2);
    let aggregate: usize = ctx.metadata["ai_prompt_compressor.tokens_saved"]
        .parse()
        .unwrap();
    let per_instance_total: usize = per_instance_saved
        .iter()
        .map(|value| value.parse::<usize>().unwrap())
        .sum();
    assert_eq!(aggregate, per_instance_total);
}

#[test]
fn per_request_metadata_paths_do_not_format_instance_keys() {
    let source = include_str!("../../../src/plugins/ai_prompt_compressor.rs");
    assert!(
        source.contains("metadata_keys: Arc<CompressionMetadataKeys>"),
        "per-instance metadata keys must remain cold-path cached and shared by worker clones"
    );
    let record = source
        .split_once("fn record_stats_metadata(")
        .and_then(|(_, rest)| rest.split_once("fn begin_wire_stats"))
        .map(|(body, _)| body)
        .expect("record_stats_metadata source region");
    let clear = source
        .split_once("fn clear_instance_stats(")
        .and_then(|(_, rest)| rest.split_once("fn metadata_usize"))
        .map(|(body, _)| body)
        .expect("clear_instance_stats source region");
    assert!(!record.contains("format!("));
    assert!(!clear.contains("format!("));
}

#[test]
fn marker_sanitation_admission_never_queues_request_bodies() {
    let source = include_str!("../../../src/plugins/ai_prompt_compressor.rs");
    let admission = source
        .split_once("let marker_permit =")
        .and_then(|(_, rest)| rest.split_once("let compression_permit ="))
        .map(|(body, _)| body)
        .expect("marker sanitation admission source region");
    assert!(admission.contains("try_acquire_owned()"));
    assert!(!admission.contains("acquire_owned().await"));
}

#[test]
fn staged_sanitation_digest_uses_the_hard_body_bound() {
    let source = include_str!("../../../src/plugins/ai_prompt_compressor.rs");
    let digest = source
        .split_once("async fn body_digest(")
        .and_then(|(_, rest)| rest.split_once("/// Shared wire-path compression"))
        .map(|(body, _)| body)
        .expect("staged-body digest source region");
    assert!(digest.contains("if body.len() > HARD_MAX_SCAN_BYTES"));
    assert!(!digest.contains("self.max_scan_bytes"));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn decompressed_gzip_and_brotli_record_authoritative_wire_stats() {
    for encoding in ["gzip", "br"] {
        let decompressor = CompressionPlugin::new(&json!({"decompress_request": true})).unwrap();
        let compressor = compressor(5, 0.5);
        let body = chat_body("user", &long_prompt_text());
        let plaintext = serde_json::to_vec(&body).unwrap();
        let encoded = if encoding == "gzip" {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&plaintext).unwrap();
            encoder.finish().unwrap()
        } else {
            let mut output = Vec::new();
            let params = brotli::enc::BrotliEncoderParams::default();
            brotli::BrotliCompress(&mut &plaintext[..], &mut output, &params).unwrap();
            output
        };

        let mut ctx = post_ctx(&body);
        ctx.metadata.remove("request_body");
        ctx.request_body_bytes = Some(bytes::Bytes::from(encoded.clone()));
        let mut headers = json_headers();
        headers.insert("content-encoding".to_string(), encoding.to_string());

        assert_continue(decompressor.before_proxy(&mut ctx, &mut headers).await);
        assert_continue(compressor.before_proxy(&mut ctx, &mut headers).await);
        ctx.path = "/internal/provider/generate".to_string();
        let decoded = decompressor
            .transform_request_body_with_context(
                &mut ctx,
                &encoded,
                Some("application/json"),
                &headers,
            )
            .await
            .expect("request should decompress");
        let compressed = compressor
            .transform_request_body_with_context(
                &mut ctx,
                &decoded,
                Some("application/json"),
                &headers,
            )
            .await
            .expect("decoded prompt should compress");

        let parsed: Value = serde_json::from_slice(&compressed).unwrap();
        assert!(
            first_message_content(&parsed).chars().count() < long_prompt_text().chars().count()
        );
        assert!(
            ctx.metadata["ai_prompt_compressor.tokens_saved"]
                .parse::<usize>()
                .unwrap()
                > 0
        );
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
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
#[serial(ai_prompt_compressor_budget)]
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

// ─── Codex review regressions ────────────────────────────────────────────────

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn all_verbatim_prompt_does_not_panic() {
    // A long prompt that tokenizes entirely into protected/verbatim tokens has
    // zero scored words; the compressor must not panic on `clamp(1, 0)`.
    let plugin = compressor(5, 0.5);
    let numbers: String = (4000..4080)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let body = chat_body("user", &numbers);
    // No scored words → nothing to drop → passthrough (None), and above all no panic.
    assert!(transform(&plugin, &body).await.is_none());

    let code = format!(
        "```\n{}\n```",
        "let value = compute_widget(config);\n".repeat(20)
    );
    let code_body = chat_body("user", &code);
    assert!(transform(&plugin, &code_body).await.is_none());
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn urls_wrapped_in_punctuation_are_preserved() {
    let plugin = compressor(5, 0.3);
    let content = "Please read the cited references very carefully before answering \
         because they contain the authoritative details, for example \
         (https://example.com/ref/one) and also <https://example.com/ref/two> which \
         must both survive even under an aggressive compression ratio setting."
        .to_string();
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);
    assert!(
        compressed.contains("https://example.com/ref/one"),
        "parenthesized URL must be preserved: {compressed:?}"
    );
    assert!(
        compressed.contains("https://example.com/ref/two"),
        "angle-bracketed URL must be preserved: {compressed:?}"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn mixed_case_url_schemes_are_preserved() {
    let plugin = compressor(5, 0.3);
    let content = "Please read the cited references very carefully before answering \
         because they contain the authoritative details, for example \
         HTTPS://example.com/ref/one and also <HtTp://example.com/ref/two> which \
         must both survive even under an aggressive compression ratio setting."
        .to_string();
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("HTTPS://example.com/ref/one"),
        "uppercase URL scheme must be preserved: {compressed:?}"
    );
    assert!(
        compressed.contains("HtTp://example.com/ref/two"),
        "mixed-case wrapped URL scheme must be preserved: {compressed:?}"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn non_post_body_skipped_by_context_hook() {
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();
    let headers = json_headers();

    let mut put_ctx = create_test_context();
    put_ctx.method = "PUT".to_string();
    assert!(
        plugin
            .transform_request_body_with_context(
                &mut put_ctx,
                &bytes,
                Some("application/json"),
                &headers
            )
            .await
            .is_none(),
        "non-POST bodies must not be compressed even when buffered"
    );

    let mut post_ctx = create_test_context();
    post_ctx.method = "POST".to_string();
    post_ctx.path = "/v1/chat/completions".to_string();
    assert!(
        plugin
            .transform_request_body_with_context(
                &mut post_ctx,
                &bytes,
                Some("application/json"),
                &headers
            )
            .await
            .is_some(),
        "POST bodies are still compressed"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn non_post_method_pseudo_header_skips_base_hook() {
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();
    let mut headers = json_headers();
    headers.insert(":method".to_string(), "PUT".to_string());
    assert!(
        plugin
            .transform_request_body(&bytes, Some("application/json"), &headers)
            .await
            .is_none()
    );
}

#[test]
fn oversized_content_length_skips_buffering() {
    let plugin = AiPromptCompressor::new(&json!({"max_scan_bytes": 100})).unwrap();
    let mut ctx = post_ctx(&chat_body("user", "hello"));
    ctx.headers
        .insert("content-length".to_string(), "1000".to_string());
    assert!(
        !plugin.should_buffer_request_body(&ctx),
        "a declared body over max_scan_bytes should not force buffering"
    );

    ctx.headers
        .insert("content-length".to_string(), "50".to_string());
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "a body within the cap should still buffer"
    );
}

// ─── Codex review round 3 regressions ────────────────────────────────────────

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn no_context_hook_requires_explicit_method_and_path_markers() {
    // The compatibility hook must not infer method or request family.
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();

    let mut no_method = HashMap::new();
    no_method.insert("content-type".to_string(), "application/json".to_string());
    assert!(
        plugin
            .transform_request_body(&bytes, Some("application/json"), &no_method)
            .await
            .is_none(),
        "a missing :method marker must be treated as ineligible"
    );

    let mut no_path = HashMap::new();
    no_path.insert("content-type".to_string(), "application/json".to_string());
    no_path.insert(":method".to_string(), "POST".to_string());
    assert!(
        plugin
            .transform_request_body(&bytes, Some("application/json"), &no_path)
            .await
            .is_none(),
        "a missing :path marker must be treated as ineligible"
    );

    // With both compatibility markers the no-context hook still compresses.
    assert!(
        plugin
            .transform_request_body(&bytes, Some("application/json"), &json_headers())
            .await
            .is_some()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn missing_content_type_is_not_compressed() {
    let plugin = compressor(5, 0.5);
    let bytes = serde_json::to_vec(&chat_body("user", &long_prompt_text())).unwrap();
    let mut headers = HashMap::new();
    headers.insert(":method".to_string(), "POST".to_string());
    // content_type = None must be treated as ineligible.
    assert!(
        plugin
            .transform_request_body(&bytes, None, &headers)
            .await
            .is_none()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_tag_keeps_internal_whitespace_exactly() {
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 5,
        "target_ratio": 0.4,
    }))
    .unwrap();
    // The preserved span has a blank line and leading indentation that must
    // survive byte-for-byte (only the markers are stripped).
    let span = "line one\n\n    line two (indented)";
    let content = format!(
        "Please compress all of this surrounding filler text that does not really \
         matter at all, but keep the block <keep>{span}</keep> exactly as written \
         because it is padding long enough to exceed the token threshold here."
    );
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains(span),
        "preserved span must retain internal whitespace exactly: {compressed:?}"
    );
    assert!(
        !compressed.contains("<keep>") && !compressed.contains("</keep>"),
        "markers must be stripped: {compressed:?}"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn curly_apostrophe_negations_preserved() {
    // U+2019 apostrophes are the norm in text pasted from iOS/Word/LLM output;
    // "don\u{2019}t" must be classified as a negation, not a droppable word.
    let plugin = compressor(5, 0.3);
    let content = "The deployment automation assistant manages many long running \
         production maintenance workflows across several regional clusters every \
         single day and please don\u{2019}t delete the archived customer log files \
         because the compliance retention audit team still needs them available \
         for the quarterly regulatory review process next month."
        .to_string();
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("don\u{2019}t"),
        "curly-apostrophe negation must be kept: {compressed:?}"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn word_following_negation_preserved() {
    // The negated complement must survive with its negation, otherwise a kept
    // "not" re-binds to the following clause and inverts its meaning.
    let plugin = compressor(5, 0.3);
    let content = "The migration assistant coordinates several complicated multi \
         region database replication schedules throughout every operational \
         maintenance window and the standby cluster is not disposable because the \
         disaster recovery certification depends on continuous verified replica \
         availability during the annual failover compliance exercise period."
        .to_string();
    let body = chat_body("user", &content);
    let out = transform(&plugin, &body).await.expect("should compress");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("not disposable"),
        "word following a kept negation must be kept: {compressed:?}"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn preserve_markers_stripped_when_compression_does_not_apply() {
    // Below the token floor, compression is skipped — but gateway-internal
    // preserve markers must still never leak to the provider.
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 200,
        "target_ratio": 0.4,
    }))
    .unwrap();
    let content = "Short prompt with a <keep>protected span</keep> inside.";
    let body = chat_body("user", content);
    let out = transform(&plugin, &body)
        .await
        .expect("markers must be stripped");
    let compressed = first_message_content(&out);

    assert!(
        compressed.contains("protected span"),
        "span text must survive: {compressed:?}"
    );
    assert!(
        !compressed.contains("<keep>") && !compressed.contains("</keep>"),
        "markers must be stripped even without compression: {compressed:?}"
    );
    assert_eq!(
        compressed, "Short prompt with a protected span inside.",
        "only the markers may be removed"
    );
}

// ─── Production-launch review regressions ────────────────────────────────────

fn compressed_content(out: &Value) -> String {
    first_message_content(out).to_string()
}

fn instance_metadata_value<'a>(ctx: &'a RequestContext, suffix: &str) -> Option<&'a str> {
    ctx.metadata
        .iter()
        .find(|(key, _)| {
            key.starts_with("ai_prompt_compressor.instances.") && key.ends_with(suffix)
        })
        .map(|(_, value)| value.as_str())
}

/// `s_k = "<ke" + s_{k-1} + "ep>"` with `s_0 = "<keep>"`: each removal pass
/// deletes exactly the innermost marker and synthesizes the next one.
fn self_synthesizing_marker(depth: usize) -> String {
    let mut marker = "<keep>".to_string();
    for _ in 0..depth {
        marker = format!("<ke{marker}ep>");
    }
    marker
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn uppercase_negations_keep_their_complement() {
    // SOL-1: `NOT` has acronym form; it must still protect the next word.
    let plugin = compressor(0, 0.1);
    let out = transform(
        &plugin,
        &chat_body("user", "DO NOT delete. RESTART extraordinarily"),
    )
    .await
    .expect("prose should compress");
    assert_eq!(compressed_content(&out), "DO NOT delete. RESTART");

    for (input, kept) in [
        (
            "Please DON\u{2019}T delete extraordinarily verbose archives",
            "DON\u{2019}T delete",
        ),
        (
            "Operators NEVER restart extraordinarily verbose clusters",
            "NEVER restart",
        ),
        (
            "Assistants CANNOT disclose extraordinarily confidential credentials",
            "CANNOT disclose",
        ),
        (
            "Operators DON'T restart extraordinarily verbose clusters",
            "DON'T restart",
        ),
    ] {
        let out = transform(&plugin, &chat_body("user", input))
            .await
            .expect("prose should compress");
        let compressed = compressed_content(&out);
        assert!(
            compressed.contains(kept),
            "{kept:?} must survive adjacent in {compressed:?}"
        );
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn conditions_quantifiers_and_number_words_are_critical() {
    // MUSE-3: closed-class scope words are kept at aggressive ratios, and the
    // restrictive connectives keep their complement.
    let plugin = compressor(0, 0.1);
    let out = transform(
        &plugin,
        &chat_body(
            "user",
            "remove exactly three obsolete snapshots unless the administrator explicitly \
             authorizes extended retention",
        ),
    )
    .await
    .expect("prose should compress");
    assert_eq!(compressed_content(&out), "exactly three unless the");

    let out = transform(
        &plugin,
        &chat_body(
            "user",
            "The archived snapshots must be deleted only after compliance verification \
             if every regional infrastructure coordinator approves",
        ),
    )
    .await
    .expect("prose should compress");
    let compressed = compressed_content(&out);
    for kept in ["must", "only after", "if every"] {
        assert!(
            compressed.contains(kept),
            "{kept:?} missing from {compressed:?}"
        );
    }

    // Uppercase restrictive connectives keep their complement too.
    let out = transform(
        &plugin,
        &chat_body("user", "Restart UNLESS maintenance extraordinarily verbose"),
    )
    .await
    .expect("prose should compress");
    assert!(compressed_content(&out).contains("UNLESS maintenance"));
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn marker_removal_reaches_a_fixpoint_on_the_fallback_path() {
    // SOL-2 scenario A: removing an inner marker must not leave a new one.
    let plugin =
        AiPromptCompressor::new(&json!({"preserve_tag": "keep", "max_scan_bytes": 1})).unwrap();
    let out = transform(
        &plugin,
        &chat_body("user", "<ke<keep>ep>secret</ke<keep>ep>"),
    )
    .await
    .expect("markers must be removed");
    assert_eq!(compressed_content(&out), "secret");

    // The escaped spelling synthesizes a literal marker the next pass removes.
    let raw = br#"{"messages":[{"role":"user","content":"<ke\u003ckeep\u003eep>secret"}]}"#;
    let output = plugin
        .transform_request_body(raw, Some("application/json"), &json_headers())
        .await
        .expect("escaped markers must be removed");
    assert_eq!(
        output,
        br#"{"messages":[{"role":"user","content":"secret"}]}"#.to_vec()
    );

    // Below-floor cleanup reaches the same fixpoint.
    let plugin = AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap();
    let nested = format!("{}secret", self_synthesizing_marker(4));
    let out = transform(&plugin, &chat_body("user", &nested))
        .await
        .expect("markers must be removed");
    assert_eq!(compressed_content(&out), "secret");

    // So does genuine statistical compression with a synthesizing marker.
    let plugin = AiPromptCompressor::new(&json!({
        "preserve_tag": "keep",
        "min_content_tokens": 1,
        "target_ratio": 0.5
    }))
    .unwrap();
    let prose = format!(
        "{} {}secret",
        long_prompt_text(),
        self_synthesizing_marker(4)
    );
    let out = transform(&plugin, &chat_body("user", &prose))
        .await
        .expect("statistical compression should apply");
    let compressed = compressed_content(&out);
    assert!(!compressed.contains("<keep>") && !compressed.contains("</keep>"));
    assert!(compressed.contains("secret"));
    assert!(
        compressed.chars().count() < prose.chars().count(),
        "fixture must exercise statistical compression: {compressed:?}"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn unresolvable_marker_synthesis_fails_closed_in_final_hook() {
    // Deeper than the bounded pass count: a residual marker is refused, never
    // forwarded.
    let plugin = AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap();
    let body = chat_body("user", &format!("{}secret", self_synthesizing_marker(20)));
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let headers = json_headers();
    let output = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("bounded passes still rewrite the body");
    assert!(String::from_utf8_lossy(&output).contains("<keep>"));
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &output)
            .await,
        Some(400),
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn later_body_transform_cannot_reintroduce_preserve_markers() {
    // SOL-2 scenario B: a transform ordered after the compressor (here a
    // `request_transformer` placed later, as a priority override would) writes
    // a marker into a string value of the admitted body.
    let compressor =
        std::sync::Arc::new(AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap())
            as std::sync::Arc<dyn Plugin>;
    let body = chat_body("user", "short prompt");
    let raw = serde_json::to_vec(&body).unwrap();
    let headers = json_headers();

    for (value, expected_reject) in [("<keep>critical</keep>", true), ("a < b", false)] {
        let transformer = std::sync::Arc::new(
            RequestTransformer::new(&json!({
                "rules": [{"operation": "add", "target": "body", "key": "note", "value": value}]
            }))
            .unwrap(),
        ) as std::sync::Arc<dyn Plugin>;
        let plugins = vec![std::sync::Arc::clone(&compressor), transformer];
        let mut ctx = post_ctx(&body);
        let (final_body, result) =
            run_request_body_stage_with_context_for_test(&plugins, &mut ctx, &headers, &raw).await;
        assert!(
            String::from_utf8_lossy(&final_body).contains(value),
            "fixture must place the value on the final body"
        );
        if expected_reject {
            assert_reject(result, Some(400));
        } else {
            assert_continue(result);
        }
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn content_encoded_marker_bodies_are_verified_through_the_decoded_view() {
    // MUSE-1: without a configured decompressor, an encoded body is never
    // rewritten, so its decoded view must be verified or refused.
    let plugin =
        std::sync::Arc::new(AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap());
    let plain = AiPromptCompressor::new(&json!({})).unwrap();
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let ctx = {
        let mut ctx = post_ctx(&chat_body("user", "placeholder"));
        ctx.headers
            .insert("content-encoding".to_string(), "gzip".to_string());
        ctx
    };
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "marker instances must buffer encoded candidates for final verification"
    );
    assert!(!plain.should_buffer_request_body(&ctx));
    assert!(plugin.enforces_final_request_body_policy(&ctx, &headers, b"encoded"));
    assert!(!plain.enforces_final_request_body_policy(&ctx, &headers, b"encoded"));
    let mut image_ctx = post_ctx(&chat_body("user", "placeholder"));
    image_ctx.path = "/v1/images/generations".to_string();
    assert!(
        !plugin.enforces_final_request_body_policy(&image_ctx, &headers, b"encoded"),
        "auto mode must not claim unrelated operations"
    );

    let plugins = vec![std::sync::Arc::clone(&plugin) as std::sync::Arc<dyn Plugin>];
    for (content, expected_reject) in [
        ("before <keep>internal instruction</keep> after", true),
        ("an ordinary prompt without markers", false),
    ] {
        let encoded = gzip(&serde_json::to_vec(&chat_body("user", content)).unwrap());
        let mut ctx = post_ctx(&chat_body("user", content));
        ctx.metadata.remove("request_body");
        let (_, result) =
            run_request_body_stage_with_context_for_test(&plugins, &mut ctx, &headers, &encoded)
                .await;
        if expected_reject {
            assert_reject(result, Some(400));
        } else {
            assert_continue(result);
        }
    }
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn final_marker_check_leaves_unadmitted_and_member_name_markers_alone() {
    let plugin = AiPromptCompressor::new(&json!({"preserve_tag": "keep"})).unwrap();
    let headers = json_headers();

    // Markers confined to member names never trigger the check.
    let mut ctx = post_ctx(&chat_body("user", "plain"));
    let raw = br#"{"messages":[{"role":"user","content":"plain"}],"only<keep>key":1}"#;
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, raw)
            .await,
    );

    // An unadmitted shape retains its bytes.
    let mut ctx = post_ctx(&chat_body("user", "plain"));
    let raw = br#"{"model":"gpt-4o","foo":"<keep>value</keep>"}"#;
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, raw)
            .await,
    );

    // Instances without a preserve tag never inspect.
    let plain = AiPromptCompressor::new(&json!({})).unwrap();
    let mut ctx = post_ctx(&chat_body("user", "plain"));
    let raw = br#"{"messages":[{"role":"user","content":"<keep>value</keep>"}]}"#;
    assert_continue(
        plain
            .on_final_request_body_with_context(&mut ctx, &headers, raw)
            .await,
    );

    // Escaped markers in values are still found.
    let mut ctx = post_ctx(&chat_body("user", "plain"));
    let raw = br#"{"messages":[{"role":"user","content":"\u003Ckeep\u003Evalue"}]}"#;
    assert!(
        !raw.contains(&b'<'),
        "fixture must exercise the escaped pre-scan"
    );
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, raw)
            .await,
        Some(400),
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn skipped_statistical_work_is_recorded() {
    // MUSE-2: a skipped compression is observable rather than silent.
    let unsampled = AiPromptCompressor::new(&json!({
        "min_content_tokens": 5,
        "sample_rate": 1e-12
    }))
    .unwrap();
    let body = chat_body("user", &long_prompt_text());
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    assert!(
        unsampled
            .transform_request_body_with_context(
                &mut ctx,
                &raw,
                Some("application/json"),
                &json_headers()
            )
            .await
            .is_none()
    );
    assert_eq!(
        instance_metadata_value(&ctx, ".skipped"),
        Some("not_sampled")
    );

    let capped = AiPromptCompressor::new(&json!({
        "min_content_tokens": 5,
        "max_scan_bytes": 32
    }))
    .unwrap();
    let mut ctx = post_ctx(&body);
    assert!(
        capped
            .transform_request_body_with_context(
                &mut ctx,
                &raw,
                Some("application/json"),
                &json_headers()
            )
            .await
            .is_none()
    );
    assert_eq!(
        instance_metadata_value(&ctx, ".skipped"),
        Some("work_limit")
    );

    // A body too short to reach the floor is an ordinary no-op, not a skip.
    let default_floor = AiPromptCompressor::new(&json!({})).unwrap();
    let short = chat_body("user", "short");
    let mut ctx = post_ctx(&short);
    assert!(
        default_floor
            .transform_request_body_with_context(
                &mut ctx,
                &serde_json::to_vec(&short).unwrap(),
                Some("application/json"),
                &json_headers()
            )
            .await
            .is_none()
    );
    assert_eq!(instance_metadata_value(&ctx, ".skipped"), None);
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn full_sample_rate_always_compresses() {
    let plugin = AiPromptCompressor::new(&json!({
        "min_content_tokens": 5,
        "sample_rate": 1.0
    }))
    .unwrap();
    let body = chat_body("user", &long_prompt_text());
    let mut ctx = post_ctx(&body);
    assert!(
        plugin
            .transform_request_body_with_context(
                &mut ctx,
                &serde_json::to_vec(&body).unwrap(),
                Some("application/json"),
                &json_headers()
            )
            .await
            .is_some()
    );
    assert_eq!(instance_metadata_value(&ctx, ".skipped"), None);
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn target_max_tokens_compresses_only_over_budget_requests() {
    // SOL-3: an aggregate budget leaves fitting requests intact and removes
    // only as much as needed from larger ones.
    let prompt = long_prompt_text();
    let tokens = prompt.chars().count().div_ceil(4);
    let body = chat_body("user", &prompt);

    let roomy = AiPromptCompressor::new(&json!({
        "min_content_tokens": 1,
        "target_ratio": 0.1,
        "target_max_tokens": tokens
    }))
    .unwrap();
    assert!(
        transform(&roomy, &body).await.is_none(),
        "a request within the budget must not be compressed"
    );

    let tight = AiPromptCompressor::new(&json!({
        "min_content_tokens": 1,
        "target_ratio": 0.1,
        "target_max_tokens": tokens * 3 / 4
    }))
    .unwrap();
    let budgeted = transform(&tight, &body)
        .await
        .expect("an over-budget request must compress");
    let ratio_only = transform(&compressor(1, 0.1), &body)
        .await
        .expect("ratio-only compression applies");
    let budgeted_len = first_message_content(&budgeted).chars().count();
    assert!(budgeted_len < prompt.chars().count());
    assert!(
        budgeted_len > first_message_content(&ratio_only).chars().count(),
        "the budget must remove only what is needed, not everything target_ratio allows"
    );

    // The budget is aggregate across eligible fields.
    let two_fields = json!({
        "messages": [
            {"role": "user", "content": prompt},
            {"role": "user", "content": prompt}
        ]
    });
    let per_field_fits = AiPromptCompressor::new(&json!({
        "min_content_tokens": 1,
        "target_max_tokens": tokens + 1
    }))
    .unwrap();
    assert!(
        transform(&per_field_fits, &two_fields).await.is_some(),
        "two fields that each fit can still exceed the aggregate budget"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn observe_mode_records_savings_without_rewriting() {
    // MUSE-6: observe runs the pipeline but forwards the original prompt.
    let observer = AiPromptCompressor::new(&json!({
        "min_content_tokens": 5,
        "mode": "observe"
    }))
    .unwrap();
    let body = chat_body("user", &long_prompt_text());
    let raw = serde_json::to_vec(&body).unwrap();

    let mut ctx = post_ctx(&body);
    let original_metadata_body = ctx.metadata["request_body"].clone();
    let mut headers = json_headers();
    assert_continue(observer.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(ctx.metadata["request_body"], original_metadata_body);
    assert!(
        observer
            .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
            .await
            .is_none(),
        "observe mode must forward the original representation"
    );
    let saved: usize = ctx.metadata["ai_prompt_compressor.observed_tokens_saved"]
        .parse()
        .unwrap();
    assert!(saved > 0);
    assert!(
        !ctx.metadata
            .contains_key("ai_prompt_compressor.tokens_saved")
    );
    assert!(instance_metadata_value(&ctx, ".observed_tokens_saved").is_some());

    // Markers are still removed in observe mode, but nothing is compressed.
    let marker_observer = AiPromptCompressor::new(&json!({
        "min_content_tokens": 5,
        "mode": "observe",
        "preserve_tag": "keep"
    }))
    .unwrap();
    let prompt = format!("<keep>critical</keep> {}", long_prompt_text());
    let out = transform(&marker_observer, &chat_body("user", &prompt))
        .await
        .expect("markers must still be removed");
    assert_eq!(
        compressed_content(&out),
        format!("critical {}", long_prompt_text())
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn responses_family_compresses_instructions_and_message_text_parts() {
    // MUSE-5: OpenAI Responses bodies are a fixed-family opt-in.
    let plugin = AiPromptCompressor::new(&json!({
        "request_family": "responses",
        "compress_roles": ["user", "system"],
        "min_content_tokens": 5,
        "target_ratio": 0.4
    }))
    .unwrap();
    let long = long_prompt_text();
    let body = json!({
        "model": "gpt-4.1",
        "instructions": long,
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": long},
                    {"type": "input_image", "image_url": "https://img.example/x.png"}
                ]
            },
            {"type": "function_call_output", "call_id": "c1", "output": long},
            {"type": "message", "role": "assistant", "content": long}
        ]
    });
    let out = transform_at_path(&plugin, &body, "/v1/responses")
        .await
        .expect("responses body should compress");
    assert!(out["instructions"].as_str().unwrap().len() < long.len());
    assert!(
        out["input"][0]["content"][0]["text"]
            .as_str()
            .unwrap()
            .len()
            < long.len()
    );
    assert_eq!(
        out["input"][0]["content"][1],
        body["input"][0]["content"][1]
    );
    assert_eq!(
        out["input"][1], body["input"][1],
        "non-message items stay intact"
    );
    assert_eq!(
        out["input"][2]["content"], body["input"][2]["content"],
        "ineligible roles stay intact"
    );

    let string_input = json!({"model": "gpt-4.1", "input": long});
    let out = transform_at_path(&plugin, &string_input, "/v1/responses")
        .await
        .expect("string input is user text");
    assert!(out["input"].as_str().unwrap().len() < long.len());

    // `auto` never admits Responses bodies, and the fixed family rejects
    // other shapes.
    assert!(
        transform_at_path(&compressor(5, 0.4), &string_input, "/v1/responses")
            .await
            .is_none()
    );
    assert!(
        transform(&plugin, &chat_body("user", &long))
            .await
            .is_none()
    );
    let malformed = json!({"input": [{"role": "user", "content": [{"type": "input_text"}]}]});
    assert!(
        transform_at_path(&plugin, &malformed, "/v1/responses")
            .await
            .is_none()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn anthropic_messages_family_compresses_system_and_text_blocks() {
    // MUSE-5: Anthropic Messages bodies are a fixed-family opt-in.
    let plugin = AiPromptCompressor::new(&json!({
        "request_family": "anthropic_messages",
        "compress_roles": ["user", "system"],
        "min_content_tokens": 5,
        "target_ratio": 0.4
    }))
    .unwrap();
    let long = long_prompt_text();
    let body = json!({
        "model": "claude-sonnet",
        "max_tokens": 256,
        "system": [{"type": "text", "text": long, "cache_control": {"type": "ephemeral"}}],
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": long},
                {"type": "tool_result", "tool_use_id": "t1", "content": long},
                {"type": "image", "source": {"type": "url", "url": "https://img.example/x.png"}}
            ]
        }]
    });
    let out = transform_at_path(&plugin, &body, "/v1/messages")
        .await
        .expect("anthropic body should compress");
    assert!(out["system"][0]["text"].as_str().unwrap().len() < long.len());
    assert_eq!(
        out["system"][0]["cache_control"],
        json!({"type": "ephemeral"})
    );
    let content = &out["messages"][0]["content"];
    assert!(content[0]["text"].as_str().unwrap().len() < long.len());
    assert_eq!(
        content[1], body["messages"][0]["content"][1],
        "tool results stay intact"
    );
    assert_eq!(content[2], body["messages"][0]["content"][2]);

    let string_system = json!({
        "model": "claude-sonnet",
        "system": long,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let out = transform_at_path(&plugin, &string_system, "/v1/messages")
        .await
        .expect("string system prompt should compress");
    assert!(out["system"].as_str().unwrap().len() < long.len());

    // Without `system` in compress_roles the system prompt is preserved.
    let user_only = AiPromptCompressor::new(&json!({
        "request_family": "anthropic_messages",
        "min_content_tokens": 5,
        "target_ratio": 0.4
    }))
    .unwrap();
    assert!(
        transform_at_path(&user_only, &string_system, "/v1/messages")
            .await
            .is_none()
    );
    // `auto` keeps passing Anthropic-shaped bodies through.
    assert!(
        transform_at_path(&compressor(5, 0.4), &string_system, "/v1/messages")
            .await
            .is_none()
    );
    let with_prompt = json!({"messages": [], "prompt": long});
    assert!(
        transform_at_path(&plugin, &with_prompt, "/v1/messages")
            .await
            .is_none()
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn staged_marker_cleanup_keeps_its_skip_reason_through_the_wire_stage() {
    // PR6854-SOL-2: before_proxy stages a marker-only result skipped for
    // `work_limit`; reusing that stage on the wire must keep the reason.
    let plugin =
        AiPromptCompressor::new(&json!({"preserve_tag": "keep", "max_scan_bytes": 1})).unwrap();
    let body = chat_body("user", "<keep>critical</keep>");
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        instance_metadata_value(&ctx, ".skipped"),
        Some("work_limit")
    );

    let output = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("the staged marker-free body is reused");
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(first_message_content(&parsed), "critical");
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &output)
            .await,
    );
    assert_eq!(
        instance_metadata_value(&ctx, ".skipped"),
        Some("work_limit"),
        "staged reuse must restore the authoritative skip reason"
    );
}

#[tokio::test]
#[serial(ai_prompt_compressor_budget)]
async fn declared_oversized_unbuffered_candidate_records_work_limit() {
    let plugin = AiPromptCompressor::new(&json!({"max_scan_bytes": 100})).unwrap();
    let mut ctx = post_ctx(&chat_body("user", "placeholder"));
    ctx.metadata.remove("request_body");
    ctx.headers
        .insert("content-length".to_string(), "1000".to_string());
    assert!(!plugin.should_buffer_request_body(&ctx));
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        instance_metadata_value(&ctx, ".skipped"),
        Some("work_limit")
    );

    // An unrelated operation path is not a candidate and records nothing.
    let mut other = post_ctx(&chat_body("user", "placeholder"));
    other.metadata.remove("request_body");
    other.path = "/v1/images/generations".to_string();
    other
        .headers
        .insert("content-length".to_string(), "1000".to_string());
    assert_continue(plugin.before_proxy(&mut other, &mut headers).await);
    assert_eq!(instance_metadata_value(&other, ".skipped"), None);
}

#[test]
fn final_marker_verification_moves_the_charged_decoded_view() {
    // PR6854-SOL-3: copying the gate's charged plaintext view out would mint
    // an uncharged duplicate of an attacker-amplified body.
    let source = include_str!("../../../src/plugins/ai_prompt_compressor.rs");
    let verifier = source
        .split_once("async fn verify_final_markers(")
        .and_then(|(_, rest)| rest.split_once("fn verify_final_markers_blocking"))
        .map(|(body, _)| body)
        .expect("final marker verifier source region");
    assert!(verifier.contains("decoded: Option<bytes::Bytes>"));
    assert!(verifier.contains("Some(charged) => charged"));
    assert!(!verifier.contains(".to_vec()"));
    let hook = source
        .split_once("async fn on_final_request_body_with_context(")
        .map(|(_, rest)| rest)
        .expect("final hook source region");
    assert!(hook.contains("inspectable_final_request_body_owned()"));
}
