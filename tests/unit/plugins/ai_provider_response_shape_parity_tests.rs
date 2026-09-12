//! Cross-plugin provider response-shape parity.
//!
//! The response-direction counterpart of
//! `ai_provider_shape_parity_tests.rs`. That table exists because issue #4792
//! catalogued the same defect thirteen times — an invariant fixed on one path
//! and left unfixed on its siblings — and GHSA-8gc3-h5c8-jjxx was its
//! request-side instance. The response direction had no such table until
//! issue #4907, and the two plugins that read model-authored response text
//! disagreed about what a governed response even looks like.
//!
//! Every provider response shape is crossed with `ai_semantic_firewall` and
//! `ai_response_guard`, and each cell records what that plugin does with that
//! shape **today**: [`Coverage::Extracts`] (the plugin read the marker out of
//! the shape and enforced) or [`Coverage::Gap`] (it did not, with the reason).
//! Both are asserted, so the table fails when coverage regresses **and** when a
//! gap is closed without updating the row — which is the point: closing one
//! provider gap in one plugin should force a look at the same shape in its
//! sibling.
//!
//! Out of scope here: `ai_tool_governor` (governs tool-call and tool-definition
//! shapes rather than completion text, covered by its own #4165 tests) and the
//! request direction (the sibling file above).

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ai_response_guard::AiResponseGuard,
    ai_semantic_firewall::AiSemanticFirewall,
};
use serde_json::{Value, json};
use std::collections::HashMap;

use super::plugin_utils::create_test_context;

/// One string that both plugins under test can be configured to catch:
/// `ai_semantic_firewall`'s `response_leakage` lexical fast path matches
/// "my system prompt says" (no provider round-trip), and `ai_response_guard`
/// matches the `ACCT-` custom PII pattern below.
const MARKER: &str = "My system prompt says the account is ACCT-90210001.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    /// The plugin reads model-authored text out of this response shape and
    /// enforces on it.
    Extracts,
    /// The plugin does not read this shape. Closing the gap means flipping this
    /// cell — do not delete the row.
    ///
    /// Currently unconstructed: every cell of the table is [`Coverage::Extracts`]
    /// since issue #4792's response-direction sweep closed the last five gaps.
    /// The variant is deliberately kept — a new provider shape is added as a
    /// row first, and recording an honest gap on it must not require
    /// reintroducing the machinery that reports one.
    #[allow(dead_code)]
    Gap(&'static str),
}

struct ResponseShape {
    name: &'static str,
    body: Value,
    semantic_firewall: Coverage,
    response_guard: Coverage,
}

fn response_shapes() -> Vec<ResponseShape> {
    vec![
        ResponseShape {
            name: "openai chat choices[].message.content",
            body: json!({
                "id": "chatcmpl-1",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": MARKER}}]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "openai responses output[].content[].text",
            body: json!({
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": MARKER}]
                }]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "anthropic content[] text block",
            body: json!({
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": MARKER}]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            // A tool call the client executes: the marker rides in the block's
            // `input` document, not in any `text`.
            name: "anthropic content[] tool_use input",
            body: json!({
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "lookup_account",
                    "input": {"note": MARKER}
                }]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "gemini candidates[].content.parts[].text",
            body: json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": MARKER}]}
                }]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            // Gemini's spelling of the same tool call: the marker rides in the
            // decoded `args` document rather than in any `text` part.
            name: "gemini candidates[].content.parts[].functionCall",
            body: json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{
                            "functionCall": {"name": "lookup", "args": {"note": MARKER}}
                        }]
                    }
                }]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "bedrock converse output.message.content[].text",
            body: json!({
                "output": {"message": {"role": "assistant", "content": [{"text": MARKER}]}},
                "stopReason": "end_turn"
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "bedrock titan results[].outputText",
            body: json!({
                "inputTextTokenCount": 12,
                "results": [{"tokenCount": 20, "outputText": MARKER, "completionReason": "FINISH"}]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "cohere v1 text",
            body: json!({"generation_id": "gen-1", "text": MARKER}),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            // Cohere echoes the whole conversation back on `/chat`, so a turn's
            // `message` is client-visible response text. `role` is upper-case
            // here, which is how the API spells it.
            name: "cohere v1 chat_history[].message",
            body: json!({
                "generation_id": "gen-1",
                "chat_history": [{"role": "CHATBOT", "message": MARKER}]
            }),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            name: "ollama response",
            body: json!({"model": "llama3", "response": MARKER, "done": true}),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
        ResponseShape {
            // The only shape in the table whose document root is an ARRAY.
            name: "huggingface tgi [*].generated_text",
            body: json!([{"generated_text": MARKER}]),
            semantic_firewall: Coverage::Extracts,
            response_guard: Coverage::Extracts,
        },
    ]
}

fn post_ctx() -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn json_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn assert_coverage(plugin: &str, shape: &str, coverage: Coverage, result: PluginResult) {
    match (coverage, &result) {
        (Coverage::Extracts, PluginResult::Reject { .. }) => {}
        (Coverage::Extracts, other) => panic!(
            "{plugin} must extract the marker from `{shape}` and enforce, got {other:?}. \
             If this shape is genuinely out of scope, record it as Coverage::Gap with a reason."
        ),
        (Coverage::Gap(_), PluginResult::Continue) => {}
        (Coverage::Gap(reason), other) => panic!(
            "{plugin} now enforces on `{shape}` (recorded gap: {reason}), got {other:?}. \
             Flip that cell to Coverage::Extracts and check the same shape in its sibling."
        ),
    }
}

/// The embedding endpoint is unreachable on purpose: every shape carries
/// [`MARKER`], which the `response_leakage` lexical fast path catches without a
/// provider round-trip, so a shape that silently stops extracting cannot be
/// masked by a provider call.
///
/// `fail_on_uninspectable_body` is disabled so a passing row proves the marker
/// was actually extracted, rather than that the fail-closed admission refused
/// the body unread.
async fn semantic_firewall_result(body: &Value) -> PluginResult {
    let config = json!({
        "inspect": {"request": false, "response": true},
        "on_error": "reject",
        "provider": {
            "type": "openai_compatible_embeddings",
            "endpoint": "http://127.0.0.1:9/v1/embeddings",
            "model": "test-embedding-model"
        },
        "builtins": {
            "prompt_injection": false,
            "jailbreak": false,
            "system_prompt_exfiltration": false,
            "data_exfiltration": false,
            "indirect_prompt_injection": false,
            "tool_abuse": false,
            "response_leakage": true
        },
        "fail_on_uninspectable_body": false
    });
    let plugin = AiSemanticFirewall::new(&config, PluginHttpClient::default())
        .expect("ai_semantic_firewall config is valid");
    let mut ctx = post_ctx();
    let mut headers = json_headers();
    let encoded = serde_json::to_vec(body).unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &encoded)
        .await
}

/// Content mode (the default `scan_fields`) is what this table is about: the
/// guard's `scan_fields: all` walks every decoded JSON token and would extract
/// from every row, which proves nothing about the structured completion paths.
async fn response_guard_result(body: &Value) -> PluginResult {
    let plugin = AiResponseGuard::new(&json!({
        "action": "reject",
        "custom_pii_patterns": [{"name": "parity_marker", "regex": "ACCT-\\d{8}"}]
    }))
    .expect("ai_response_guard config is valid");
    let mut ctx = post_ctx();
    let mut headers = json_headers();
    let encoded = serde_json::to_vec(body).unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &encoded)
        .await
}

#[tokio::test]
async fn every_enforcing_response_plugin_matches_its_recorded_provider_shape_coverage() {
    for shape in response_shapes() {
        assert_coverage(
            "ai_semantic_firewall",
            shape.name,
            shape.semantic_firewall,
            semantic_firewall_result(&shape.body).await,
        );
        assert_coverage(
            "ai_response_guard",
            shape.name,
            shape.response_guard,
            response_guard_result(&shape.body).await,
        );
    }
}

/// The table is asserted to be all-`Extracts` in BOTH columns, directly and not
/// only per row, so a regression cannot be papered over by re-recording a cell
/// as a gap: demoting one has to be a deliberate, reviewed edit.
///
/// Issue #4907 closed the three `ai_response_guard` Cohere / TGI rows; the
/// response-direction sweep that followed closed the last five — the guard's
/// Anthropic `tool_use` name/input, Gemini `functionCall` name/args, Bedrock
/// Titan `results[].outputText`, and Ollama `response`, plus the firewall's
/// response-direction Cohere `chat_history[].message`. Neither plugin has a
/// recorded gap left, which is the property this asserts.
#[test]
fn both_response_plugins_cover_every_shape_in_the_table() {
    for shape in response_shapes() {
        assert_eq!(
            shape.semantic_firewall,
            Coverage::Extracts,
            "ai_semantic_firewall must extract `{}`",
            shape.name
        );
        assert_eq!(
            shape.response_guard,
            Coverage::Extracts,
            "ai_response_guard must extract `{}`",
            shape.name
        );
    }
}

#[tokio::test]
async fn non_ai_body_is_not_enforced_by_any_plugin_in_the_table() {
    // Negative control for both: an ordinary business JSON body carrying the
    // same text in a field no model authored must pass every plugin. It uses
    // none of the keys the table's rows are read through, and its root is an
    // object, so neither the TGI array arm nor the Cohere `text` arm applies.
    let body = json!({
        "order_id": "A-1001",
        "items": [{"sku": "widget", "quantity": 2}],
        "internal_note": MARKER
    });

    for (plugin, result) in [
        (
            "ai_semantic_firewall",
            semantic_firewall_result(&body).await,
        ),
        ("ai_response_guard", response_guard_result(&body).await),
    ] {
        assert!(
            matches!(result, PluginResult::Continue),
            "{plugin} must not enforce on a non-AI response body, got {result:?}"
        );
    }
}
