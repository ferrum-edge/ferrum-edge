use ferrum_edge::plugins::ai_federation;
use ferrum_edge::plugins::ai_federation::test_helpers;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Config validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_valid_config_openai_provider() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "priority": 1,
            "model_patterns": ["gpt-*"],
            "default_model": "gpt-4o"
        }]
    });
    let http_client = create_test_http_client();
    let result = ai_federation::AiFederation::new(&config, http_client);
    assert!(
        result.is_ok(),
        "valid config should parse: {:?}",
        result.err()
    );
}

#[test]
fn test_valid_config_multiple_providers() {
    let config = json!({
        "providers": [
            {
                "name": "anthropic",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test",
                "priority": 1,
                "model_patterns": ["claude-*"]
            },
            {
                "name": "openai",
                "provider_type": "openai",
                "api_key": "sk-test",
                "priority": 2,
                "model_patterns": ["gpt-*"]
            }
        ],
        "fallback_enabled": true
    });
    let http_client = create_test_http_client();
    assert!(ai_federation::AiFederation::new(&config, http_client).is_ok());
}

#[test]
fn test_empty_providers_array_rejected() {
    let config = json!({ "providers": [] });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("must not be empty"), "got: {err}");
}

#[test]
fn test_missing_providers_rejected() {
    let config = json!({});
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("providers"), "got: {err}");
}

#[test]
fn test_missing_provider_name_rejected() {
    let config = json!({
        "providers": [{
            "provider_type": "openai",
            "api_key": "sk-test"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("missing 'name'"), "got: {err}");
}

#[test]
fn test_missing_provider_type_rejected() {
    let config = json!({
        "providers": [{
            "name": "test",
            "api_key": "sk-test"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("missing 'provider_type'"), "got: {err}");
}

#[test]
fn test_unknown_provider_type_rejected() {
    let config = json!({
        "providers": [{
            "name": "test",
            "provider_type": "unknown_provider",
            "api_key": "test"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("unknown provider_type"), "got: {err}");
}

#[test]
fn test_missing_api_key_rejected() {
    let config = json!({
        "providers": [{
            "name": "test",
            "provider_type": "openai"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("missing 'api_key'"), "got: {err}");
}

#[test]
fn test_azure_missing_resource_rejected() {
    let config = json!({
        "providers": [{
            "name": "azure",
            "provider_type": "azure_openai",
            "api_key": "test-key",
            "azure_deployment": "my-deployment"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("azure_resource"), "got: {err}");
}

#[test]
fn test_azure_missing_deployment_rejected() {
    let config = json!({
        "providers": [{
            "name": "azure",
            "provider_type": "azure_openai",
            "api_key": "test-key",
            "azure_resource": "my-resource"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("azure_deployment"), "got: {err}");
}

#[test]
fn test_google_vertex_missing_project_rejected() {
    let config = json!({
        "providers": [{
            "name": "vertex",
            "provider_type": "google_vertex",
            "google_region": "us-central1",
            "google_service_account_json": r#"{"client_email":"test@test.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\naFDrBz9vFqU4yp5MqOv3atf3MJxEBm3S/5EHJI8k8JR/4Bpg6MBo3+1JWQJUFSBL\nwEFfBa/0iT7FKzO5SIiJBjCPDFlKU7jVrM5N3DkCnJHsfHM4lrMi57rEvTftljMlS\nLq8I7QJULPM3FU7az9XJIL+KpF/cAQ0SO/eBnWMz1E+a1DEvMnHDMHnGPn8VnAPy\njRAQR1S0K+7XEnOOdScGy0mMf27JNGWNHwXcbmpA1EavL5hnhMBRqGW6XNPS4LEBr\nQKI9gFUj+e3F5vQivMITN7ZzQY2BSRBq3S9agQIDAQABAoIBAC5RgZ+bIJOOkAPn\nlrYPWP72a5NI3UEKEKpFynv0FNjg7UlmBP3xAp9acnF/SE1a+4m2D7IU/UJDwIh5f\nk7L8TIMww/+n2FI7MCz8Pd6dGKW8Cdj5O/O+OqPFGrBFMlv8FvL0aDMEawYxDCxKQ\ntfF0N6LJdGPKwVdH4l0KEYFAyVTmwSGONMJRwj/QGMB0mKJNk0YMejREqnTDXBuCR\n7AqVB3Ql0k0B6Mia0qmtKgq0IP4T2/Dw4dGEq7bJsXRmWFClyYzPGuT3MnitryCxk\njmIwDgCJLzL8KDQRFwCrVvpJD/u9lUnYp6DpDMjWkPawBWMRvpR/KkRGpiAlzKBNIn\noYlhAn0CgYEA6Fl3Y7e1Z3k7FdWjREYcf1fSGvJKxX5XF7F0ue/fjsDhwgjousMwi\npXcxMMqyAN7N0nKPtxqnCmlhwJag6YPfcEZBp1a+ZGV3hQP6PnPknpENgvGBeVap0\nWlN5mLBk8MbkCkVJ8VB5jY9XGT7FPh+j9k0R4rYE9OBUPR4y8kY9i0CgYEA5jRnn\naRHXwFwbl1i1aR3IY5TWLDE+VqAHzR9E6I8W6xqvy/yiG4Y6FNIjVKmE7W+DJYZbI\nbvfq9NNW5H/SI2e65vPVOBqIzz3T0l1aV6BM2uUHBim5PwN1jVrjC9PD+VCP3kGE/\nH5PKCl3iL3PF7yY5BndYd0C8+OHj7kIjLjl6q30CgYAhKJb8R/A3diG6rJ0L4cOa\nt0bGnvHMFaCajV5BE0JK/2VN4rMd7PfC4JgTpKBT5Pt9tnYMf/4la3xipNOVLyNYt\nVkWxgmGJKP1Cz2hbAMTE8N+7u2OXn0U/GHKOLbOilwJPFy6mfOBgZ+n4dTYV3xqeJ\ncQ3N7hhqx/RNS+6Xl5XQKBgQC1iWPiTNlkWcSx1yDAFKS1cYpIUhMiJwBSWadR6Ty\nR9gIw5JCbVS+ILiMQ7vJP3v0P1E0dNz6m1y5m5eV8kJGRvdKiLj5p+6xbz7NMfhyM\nH3RkFdj1ij2ySz5mH+gJBECHE8Wnkq/P/m1GYFsmrKm0wCdWtqAEIglI3l5aA8iXo\nKQKBgQC3hm9FDkPb7OkHMBLvWJ5E36k0BG+P0K7PHTY1XRxSdcH4VE+K+1SqqJBuC\nUR3tBavIHUsmKMhO2t2FPRaFNawWQ33XpmE8+0kZMHj5E1l+CdsLXaCI5r4dR/aDfO\nd7YBnCf3B6W3Iq1gBjFfKQ7iLjsYkb2ImLjNPSFMqVXd1C83XQ==\n-----END RSA PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}"#
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("google_project_id"), "got: {err}");
}

#[test]
fn test_bedrock_missing_region_rejected() {
    let config = json!({
        "providers": [{
            "name": "bedrock",
            "provider_type": "aws_bedrock",
            "aws_access_key_id": "AKIA",
            "aws_secret_access_key": "secret"
        }]
    });
    let http_client = create_test_http_client();
    let err = ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("aws_region"), "got: {err}");
}

#[test]
fn test_default_fallback_config() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test"
        }]
    });
    let http_client = create_test_http_client();
    // Should parse with default fallback settings
    assert!(ai_federation::AiFederation::new(&config, http_client).is_ok());
}

#[test]
fn test_custom_timeouts() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "connect_timeout_seconds": 10,
            "read_timeout_seconds": 120
        }]
    });
    let http_client = create_test_http_client();
    assert!(ai_federation::AiFederation::new(&config, http_client).is_ok());
}

// ---------------------------------------------------------------------------
// Glob matching tests
// ---------------------------------------------------------------------------

#[test]
fn test_glob_exact_match() {
    assert!(test_helpers::glob_match("gpt-4o", "gpt-4o"));
    assert!(!test_helpers::glob_match("gpt-4o", "gpt-4o-mini"));
}

#[test]
fn test_glob_trailing_wildcard() {
    assert!(test_helpers::glob_match("gpt-*", "gpt-4o"));
    assert!(test_helpers::glob_match("gpt-*", "gpt-4o-mini"));
    assert!(!test_helpers::glob_match("gpt-*", "claude-3"));
}

#[test]
fn test_glob_leading_wildcard() {
    assert!(test_helpers::glob_match("*-turbo", "gpt-3.5-turbo"));
    assert!(!test_helpers::glob_match("*-turbo", "gpt-3.5-turbo-0125"));
}

#[test]
fn test_glob_middle_wildcard() {
    assert!(test_helpers::glob_match("gpt-*-turbo", "gpt-3.5-turbo"));
    assert!(test_helpers::glob_match("gpt-*-turbo", "gpt-4-turbo"));
    assert!(!test_helpers::glob_match("gpt-*-turbo", "gpt-4o"));
}

#[test]
fn test_glob_multiple_wildcards() {
    assert!(test_helpers::glob_match(
        "*claude*",
        "anthropic.claude-3-sonnet"
    ));
    assert!(test_helpers::glob_match("*claude*", "claude-4-sonnet"));
}

#[test]
fn test_glob_all_wildcard() {
    assert!(test_helpers::glob_match("*", "anything"));
    assert!(test_helpers::glob_match("*", ""));
}

#[test]
fn test_glob_empty_pattern() {
    assert!(test_helpers::glob_match("", ""));
    assert!(!test_helpers::glob_match("", "something"));
}

// ---------------------------------------------------------------------------
// Request translation tests
// ---------------------------------------------------------------------------

fn sample_openai_request() -> Value {
    json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"},
            {"role": "assistant", "content": "Hi there!"},
            {"role": "user", "content": "How are you?"}
        ],
        "max_tokens": 1000,
        "temperature": 0.7,
        "top_p": 0.9,
        "stop": ["END"]
    })
}

#[test]
fn test_translate_openai_compatible() {
    let body = sample_openai_request();
    let (url, headers, body_bytes) =
        test_helpers::translate_request_test("openai", &body, "gpt-4o", &json!({})).unwrap();

    assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/json")
    );

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["model"], "gpt-4o");
    assert!(parsed["messages"].as_array().unwrap().len() == 4);
}

#[test]
fn test_translate_azure_openai() {
    let body = sample_openai_request();
    let provider_config = json!({
        "azure_resource": "my-resource",
        "azure_deployment": "my-deployment",
        "azure_api_version": "2024-06-01"
    });
    let (url, _, body_bytes) =
        test_helpers::translate_request_test("azure_openai", &body, "gpt-4o", &provider_config)
            .unwrap();

    assert!(url.contains("my-resource.openai.azure.com"));
    assert!(url.contains("my-deployment"));
    assert!(url.contains("api-version=2024-06-01"));

    // Azure should strip the model field from body
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(parsed.get("model").is_none());
}

#[test]
fn test_translate_anthropic() {
    let body = sample_openai_request();
    let (url, headers, body_bytes) = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-sonnet-4-20250514",
        &json!({}),
    )
    .unwrap();

    assert_eq!(url, "https://api.anthropic.com/v1/messages");
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "anthropic-version" && v == "2023-06-01")
    );

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["model"], "claude-sonnet-4-20250514");
    assert_eq!(parsed["max_tokens"], 1000);

    // System message should be extracted to top-level "system" field
    assert!(
        parsed["system"]
            .as_str()
            .unwrap()
            .contains("helpful assistant")
    );

    // Messages should only contain user/assistant (no system)
    let msgs = parsed["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3); // user, assistant, user (system removed)
    for msg in msgs {
        assert_ne!(msg["role"], "system");
    }

    // stop → stop_sequences
    assert_eq!(parsed["stop_sequences"], json!(["END"]));
}

#[test]
fn test_translate_gemini() {
    let body = sample_openai_request();
    let (url, _, body_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &json!({}),
    )
    .unwrap();

    assert!(url.contains("generativelanguage.googleapis.com"));
    assert!(url.contains("gemini-2.0-flash"));

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();

    // System should be in systemInstruction
    assert!(parsed.get("systemInstruction").is_some());

    // Contents should map user/assistant messages
    let contents = parsed["contents"].as_array().unwrap();
    assert_eq!(contents.len(), 3); // user, assistant(=model), user
    assert_eq!(contents[1]["role"], "model"); // assistant → model

    // generationConfig
    assert_eq!(parsed["generationConfig"]["maxOutputTokens"], 1000);
    assert_eq!(parsed["generationConfig"]["temperature"], 0.7);
    assert_eq!(parsed["generationConfig"]["topP"], 0.9);
}

#[test]
fn test_translate_google_vertex() {
    let body = sample_openai_request();
    let provider_config = json!({
        "google_project_id": "my-project",
        "google_region": "us-central1"
    });
    let (url, _, _) = test_helpers::translate_request_test(
        "google_vertex",
        &body,
        "gemini-2.0-flash",
        &provider_config,
    )
    .unwrap();

    assert!(url.contains("us-central1-aiplatform.googleapis.com"));
    assert!(url.contains("my-project"));
    assert!(url.contains("gemini-2.0-flash"));
}

#[test]
fn test_translate_bedrock() {
    let body = sample_openai_request();
    let provider_config = json!({ "aws_region": "us-east-1" });
    let (url, _, body_bytes) = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &provider_config,
    )
    .unwrap();

    assert!(url.contains("bedrock-runtime.us-east-1.amazonaws.com"));
    assert!(url.contains("anthropic.claude-3-sonnet-20240229-v1:0"));

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();

    // System should be an array of {text} blocks
    let system = parsed["system"].as_array().unwrap();
    assert_eq!(system[0]["text"], "You are a helpful assistant.");

    // Messages should have content as array of {text} blocks
    let msgs = parsed["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3);
    assert!(msgs[0]["content"][0]["text"].as_str().is_some());

    // inferenceConfig
    assert_eq!(parsed["inferenceConfig"]["maxTokens"], 1000);
}

#[test]
fn test_translate_cohere() {
    let body = sample_openai_request();
    let (url, _, body_bytes) =
        test_helpers::translate_request_test("cohere", &body, "command-r-plus", &json!({}))
            .unwrap();

    assert_eq!(url, "https://api.cohere.com/v2/chat");

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["model"], "command-r-plus");
    // Messages should be preserved (Cohere v2 is OpenAI-compatible for messages)
    assert!(parsed["messages"].as_array().unwrap().len() == 4);
}

#[test]
fn test_translate_with_custom_base_url() {
    let body = sample_openai_request();
    let provider_config = json!({ "base_url": "https://my-proxy.example.com/v1/chat/completions" });
    let (url, _, _) =
        test_helpers::translate_request_test("openai", &body, "gpt-4o", &provider_config).unwrap();

    assert_eq!(url, "https://my-proxy.example.com/v1/chat/completions");
}

#[test]
fn test_translate_missing_messages_error() {
    let body = json!({"model": "test"});
    let result = test_helpers::translate_request_test("anthropic", &body, "claude-3", &json!({}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("messages"));
}

#[test]
fn test_translate_anthropic_default_max_tokens() {
    // When max_tokens is not specified, Anthropic should default to 4096
    let body = json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("anthropic", &body, "claude-3", &json!({})).unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["max_tokens"], 4096);
}

// ---------------------------------------------------------------------------
// Response normalization tests
// ---------------------------------------------------------------------------

#[test]
fn test_normalize_openai_response() {
    let resp = json!({
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15
        }
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, prompt, completion, total) =
        test_helpers::normalize_response_test("openai", 200, &body, "gpt-4o").unwrap();

    assert_eq!(normalized["choices"][0]["message"]["content"], "Hello!");
    assert_eq!(prompt, 10);
    assert_eq!(completion, 5);
    assert_eq!(total, 15);
}

#[test]
fn test_normalize_anthropic_response() {
    let resp = json!({
        "id": "msg_123",
        "type": "message",
        "model": "claude-sonnet-4-20250514",
        "content": [{"type": "text", "text": "Hello from Claude!"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 12,
            "output_tokens": 8
        }
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, prompt, completion, total) =
        test_helpers::normalize_response_test("anthropic", 200, &body, "claude-sonnet-4-20250514")
            .unwrap();

    assert_eq!(normalized["object"], "chat.completion");
    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "Hello from Claude!"
    );
    assert_eq!(normalized["choices"][0]["finish_reason"], "stop");
    assert_eq!(prompt, 12);
    assert_eq!(completion, 8);
    assert_eq!(total, 20);
}

#[test]
fn test_normalize_anthropic_max_tokens_finish() {
    let resp = json!({
        "content": [{"type": "text", "text": "Truncated"}],
        "stop_reason": "max_tokens",
        "usage": {"input_tokens": 5, "output_tokens": 100}
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("anthropic", 200, &body, "claude-3").unwrap();
    assert_eq!(normalized["choices"][0]["finish_reason"], "length");
}

#[test]
fn test_normalize_gemini_response() {
    let resp = json!({
        "candidates": [{
            "content": {
                "parts": [{"text": "Hello from Gemini!"}],
                "role": "model"
            },
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 15,
            "candidatesTokenCount": 10,
            "totalTokenCount": 25
        },
        "modelVersion": "gemini-2.0-flash"
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, prompt, completion, total) =
        test_helpers::normalize_response_test("google_gemini", 200, &body, "gemini-2.0-flash")
            .unwrap();

    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "Hello from Gemini!"
    );
    assert_eq!(normalized["choices"][0]["finish_reason"], "stop");
    assert_eq!(prompt, 15);
    assert_eq!(completion, 10);
    assert_eq!(total, 25);
}

#[test]
fn test_normalize_gemini_safety_filter() {
    let resp = json!({
        "candidates": [{
            "content": {"parts": [{"text": ""}], "role": "model"},
            "finishReason": "SAFETY"
        }],
        "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 0, "totalTokenCount": 5}
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("google_gemini", 200, &body, "gemini-2.0-flash")
            .unwrap();
    assert_eq!(normalized["choices"][0]["finish_reason"], "content_filter");
}

#[test]
fn test_normalize_bedrock_response() {
    let resp = json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "Hello from Bedrock!"}]
            }
        },
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 20,
            "outputTokens": 15,
            "totalTokens": 35
        }
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, prompt, completion, total) = test_helpers::normalize_response_test(
        "aws_bedrock",
        200,
        &body,
        "anthropic.claude-3-sonnet",
    )
    .unwrap();

    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "Hello from Bedrock!"
    );
    assert_eq!(normalized["choices"][0]["finish_reason"], "stop");
    assert_eq!(prompt, 20);
    assert_eq!(completion, 15);
    assert_eq!(total, 35);
}

#[test]
fn test_normalize_cohere_response() {
    let resp = json!({
        "id": "chat-123",
        "model": "command-r-plus",
        "finish_reason": "COMPLETE",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello from Cohere!"}]
        },
        "usage": {
            "tokens": {
                "input_tokens": 8,
                "output_tokens": 6
            }
        }
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, prompt, completion, total) =
        test_helpers::normalize_response_test("cohere", 200, &body, "command-r-plus").unwrap();

    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "Hello from Cohere!"
    );
    assert_eq!(normalized["choices"][0]["finish_reason"], "stop");
    assert_eq!(prompt, 8);
    assert_eq!(completion, 6);
    assert_eq!(total, 14);
}

#[test]
fn test_normalize_error_response() {
    let resp = json!({"error": {"message": "rate limited"}});
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, prompt, completion, total) =
        test_helpers::normalize_response_test("openai", 429, &body, "gpt-4o").unwrap();

    assert!(
        normalized["error"]["message"]
            .as_str()
            .unwrap()
            .contains("429")
    );
    assert_eq!(prompt, 0);
    assert_eq!(completion, 0);
    assert_eq!(total, 0);
}

#[test]
fn test_normalize_missing_token_fields() {
    // OpenAI response without usage field
    let resp = json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}]
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (_, prompt, completion, total) =
        test_helpers::normalize_response_test("openai", 200, &body, "gpt-4o").unwrap();

    assert_eq!(prompt, 0);
    assert_eq!(completion, 0);
    assert_eq!(total, 0);
}

// ---------------------------------------------------------------------------
// All provider types test
// ---------------------------------------------------------------------------

#[test]
fn test_all_openai_compatible_providers() {
    // All these should produce the standard OpenAI URL or their own base URL
    let compatible_providers = vec![
        ("openai", "https://api.openai.com/v1/chat/completions"),
        ("mistral", "https://api.mistral.ai/v1/chat/completions"),
        ("xai", "https://api.x.ai/v1/chat/completions"),
        ("deepseek", "https://api.deepseek.com/v1/chat/completions"),
        ("meta_llama", "https://api.llama.com/v1/chat/completions"),
        (
            "hugging_face",
            "https://router.huggingface.co/v1/chat/completions",
        ),
    ];

    let body = json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    for (provider_type, expected_url) in compatible_providers {
        let (url, _, body_bytes) =
            test_helpers::translate_request_test(provider_type, &body, "test-model", &json!({}))
                .unwrap();
        assert_eq!(url, expected_url, "URL mismatch for {provider_type}");

        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            parsed["model"], "test-model",
            "model mismatch for {provider_type}"
        );
    }
}

// ---------------------------------------------------------------------------
// URL template — built once at config-load time and rendered per-request.
// These tests pin the rendered URLs so the cached-template optimization
// cannot silently change wire-level behavior.
// ---------------------------------------------------------------------------

#[test]
fn test_url_template_azure_openai_is_static() {
    let url = test_helpers::build_provider_url_for_test(
        "azure_openai",
        &json!({
            "azure_resource": "myco",
            "azure_deployment": "prod",
            "azure_api_version": "2024-06-01"
        }),
        "ignored-model-name",
    )
    .unwrap();
    assert_eq!(
        url,
        "https://myco.openai.azure.com/openai/deployments/prod/chat/completions?api-version=2024-06-01"
    );
}

#[test]
fn test_url_template_gemini_embeds_model() {
    let url = test_helpers::build_provider_url_for_test("google_gemini", &json!({}), "gemini-pro")
        .unwrap();
    assert_eq!(
        url,
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    );
}

#[test]
fn test_url_template_vertex_embeds_region_project_and_model() {
    let url = test_helpers::build_provider_url_for_test(
        "google_vertex",
        &json!({
            "google_project_id": "my-proj",
            "google_region": "europe-west1"
        }),
        "gemini-1.5-pro",
    )
    .unwrap();
    assert_eq!(
        url,
        "https://europe-west1-aiplatform.googleapis.com/v1/projects/my-proj/locations/europe-west1/publishers/google/models/gemini-1.5-pro:generateContent"
    );
}

#[test]
fn test_url_template_bedrock_embeds_region_and_model() {
    let url = test_helpers::build_provider_url_for_test(
        "aws_bedrock",
        &json!({"aws_region": "us-west-2"}),
        "anthropic.claude-3-sonnet",
    )
    .unwrap();
    assert_eq!(
        url,
        "https://bedrock-runtime.us-west-2.amazonaws.com/model/anthropic.claude-3-sonnet/converse"
    );
}

#[test]
fn test_url_template_explicit_base_url_overrides_provider_logic() {
    // When the operator supplies `base_url`, the template renders that
    // exact URL regardless of provider type.
    let url = test_helpers::build_provider_url_for_test(
        "azure_openai",
        &json!({"base_url": "https://internal.proxy/v1/chat"}),
        "anything",
    )
    .unwrap();
    assert_eq!(url, "https://internal.proxy/v1/chat");
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn create_test_http_client() -> ferrum_edge::plugins::PluginHttpClient {
    ferrum_edge::plugins::PluginHttpClient::default()
}
