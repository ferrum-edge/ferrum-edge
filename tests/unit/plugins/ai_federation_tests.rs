use ferrum_edge::plugins::ai_federation;
use ferrum_edge::plugins::ai_federation::test_helpers;
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use ferrum_edge::{
    config::{BackendAllowIps, PoolConfig},
    dns::{DnsCache, DnsConfig},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

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
fn test_plugin_metadata_and_warmup_hostnames() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "model_patterns": ["gpt-*"]
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    assert_eq!(plugin.name(), "ai_federation");
    assert_eq!(plugin.priority(), priority::AI_FEDERATION);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.is_auth_plugin());
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["api.openai.com".to_string()]
    );
}

#[test]
fn test_warmup_hostnames_unbrackets_ipv6_base_url() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "base_url": "https://[2001:db8::60]/v1/chat/completions",
            "model_patterns": ["gpt-*"]
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::60".to_string()]);
}

#[test]
fn test_invalid_config_shapes_rejected() {
    let valid_provider = json!({
        "name": "openai",
        "provider_type": "openai",
        "api_key": "sk-test-key"
    });
    for config in [
        json!("bad"),
        json!({"providers": [json!({
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "priority": "1"
        })]}),
        json!({"providers": [json!({
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "model_patterns": ["gpt-*", 123]
        })]}),
        json!({"providers": [json!({
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "model_mapping": {"gpt-4": 123}
        })]}),
        json!({"providers": [valid_provider.clone()], "fallback_enabled": "true"}),
        json!({"providers": [valid_provider.clone()], "fallback_on_network_errors": "false"}),
        json!({"providers": [valid_provider.clone()], "fallback_on_status_codes": "429"}),
        json!({"providers": [valid_provider.clone()], "fallback_on_status_codes": [429, "500"]}),
        json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "multimodal_mode": true
        }]}),
        json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "multimodal_mode": "drop_images"
        }]}),
        json!({"providers": [valid_provider.clone()], "fail_on_missing_model": "true"}),
        json!({"providers": [valid_provider.clone()], "fail_on_no_matching_provider": "true"}),
    ] {
        let result = ai_federation::AiFederation::new(&config, create_test_http_client());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_streaming_config_fields_rejected() {
    let valid_provider = json!({
        "name": "openai",
        "provider_type": "openai",
        "api_key": "sk-test-key"
    });

    for config in [
        json!({"providers": [valid_provider.clone()], "stream": false}),
        json!({"providers": [valid_provider.clone()], "streaming": true}),
        json!({"providers": [valid_provider.clone()], "streaming_enabled": true}),
        json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "stream": true
        }]}),
        json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "enable_streaming": true
        }]}),
    ] {
        let err = ai_federation::AiFederation::new(&config, create_test_http_client())
            .err()
            .unwrap();
        assert!(
            err.contains("streaming") && err.contains("unsupported"),
            "streaming config should be explicitly rejected, got: {err}"
        );
    }
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
// Glob security tightening — `*` must not consume URL-structural separators.
//
// Regression coverage for the URL-injection class where a permissive
// operator pattern (`gemini-*`) would otherwise match a malicious user
// input (`gemini-../foo:streamGenerateContent?key=stolen`) and route it
// to the matching provider.
// ---------------------------------------------------------------------------

#[test]
fn test_glob_wildcard_does_not_cross_path_separator() {
    // Without tightening, `*` would consume `../foo` and the glob would
    // match. With the security fix, `/` inside the wildcard window
    // breaks the match.
    assert!(!test_helpers::glob_match("gemini-*", "gemini-../foo"));
    assert!(!test_helpers::glob_match(
        "gemini-*",
        "gemini-../foo:streamGenerateContent"
    ));
}

#[test]
fn test_glob_wildcard_does_not_cross_query_or_fragment() {
    assert!(!test_helpers::glob_match("gpt-*", "gpt-4o?key=leaked"));
    assert!(!test_helpers::glob_match("gpt-*", "gpt-4o#admin"));
    assert!(!test_helpers::glob_match("claude-*", "claude-3&x=y"));
}

#[test]
fn test_glob_wildcard_does_not_cross_whitespace_or_backslash() {
    assert!(!test_helpers::glob_match("model-*", "model-foo bar"));
    assert!(!test_helpers::glob_match("model-*", "model-foo\\bar"));
    assert!(!test_helpers::glob_match("model-*", "model-foo\nbar"));
}

#[test]
fn test_glob_legitimate_versions_with_dots_and_colons_still_match() {
    // Bedrock-style IDs contain `:` and `.` — both must remain matchable
    // through `*` since they are legal in URL path segments and are
    // load-bearing for AWS model identifiers.
    assert!(test_helpers::glob_match(
        "anthropic.*",
        "anthropic.claude-3-5-sonnet-20240620-v1:0"
    ));
    assert!(test_helpers::glob_match(
        "*claude*",
        "anthropic.claude-3-sonnet"
    ));
    assert!(test_helpers::glob_match("gemini-*", "gemini-1.5-pro"));
}

// ---------------------------------------------------------------------------
// URL-path-component validator (CVE-class: URL injection via `model` field)
// ---------------------------------------------------------------------------

#[test]
fn test_url_model_component_accepts_legit_gemini_names() {
    assert!(test_helpers::is_valid_url_model_component("gemini-1.5-pro"));
    assert!(test_helpers::is_valid_url_model_component("gemini-pro"));
    assert!(test_helpers::is_valid_url_model_component(
        "gemini-2.0-flash"
    ));
}

#[test]
fn test_url_model_component_accepts_legit_bedrock_ids() {
    assert!(test_helpers::is_valid_url_model_component(
        "anthropic.claude-3-5-sonnet-20240620-v1:0"
    ));
    assert!(test_helpers::is_valid_url_model_component(
        "meta.llama3-70b-instruct-v1:0"
    ));
    assert!(test_helpers::is_valid_url_model_component(
        "anthropic.claude-3-sonnet-20240229-v1:0"
    ));
}

#[test]
fn test_url_model_component_rejects_path_traversal() {
    assert!(!test_helpers::is_valid_url_model_component("gemini-../foo"));
    assert!(!test_helpers::is_valid_url_model_component(
        "gemini-../foo:streamGenerateContent"
    ));
    assert!(!test_helpers::is_valid_url_model_component(
        "gemini-../foo:streamGenerateContent?key=stolen"
    ));
    // Even a bare `..` is rejected — both individual `.`s would otherwise
    // pass the per-character allowlist.
    assert!(!test_helpers::is_valid_url_model_component(".."));
    assert!(!test_helpers::is_valid_url_model_component("a..b"));
}

#[test]
fn test_url_model_component_rejects_url_separators() {
    assert!(!test_helpers::is_valid_url_model_component("foo/bar"));
    assert!(!test_helpers::is_valid_url_model_component("foo?x=y"));
    assert!(!test_helpers::is_valid_url_model_component("foo#frag"));
    assert!(!test_helpers::is_valid_url_model_component("foo&x=y"));
    assert!(!test_helpers::is_valid_url_model_component("foo\\bar"));
    assert!(!test_helpers::is_valid_url_model_component("foo bar"));
    assert!(!test_helpers::is_valid_url_model_component("foo\nbar"));
    assert!(!test_helpers::is_valid_url_model_component("foo\tbar"));
}

#[test]
fn test_url_model_component_rejects_empty_string() {
    assert!(!test_helpers::is_valid_url_model_component(""));
}

#[test]
fn test_url_model_component_rejects_unicode_lookalikes() {
    // Non-ASCII characters fall outside the allow-list. Reject so that
    // homoglyph attacks (e.g. Cyrillic `р`) cannot bypass the validator.
    assert!(!test_helpers::is_valid_url_model_component("gpt-4о"));
    assert!(!test_helpers::is_valid_url_model_component("modеl"));
}

#[test]
fn test_provider_embeds_model_in_url_correctness() {
    // Only Gemini, Vertex, and Bedrock embed the resolved model directly
    // in the URL path. Other providers put it in the request body.
    assert!(test_helpers::provider_embeds_model_in_url("google_gemini").unwrap());
    assert!(test_helpers::provider_embeds_model_in_url("google_vertex").unwrap());
    assert!(test_helpers::provider_embeds_model_in_url("aws_bedrock").unwrap());
    assert!(!test_helpers::provider_embeds_model_in_url("openai").unwrap());
    assert!(!test_helpers::provider_embeds_model_in_url("anthropic").unwrap());
    assert!(!test_helpers::provider_embeds_model_in_url("cohere").unwrap());
    assert!(!test_helpers::provider_embeds_model_in_url("azure_openai").unwrap());
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
fn test_flatten_openai_message_text_string_form() {
    let content = json!("plain text");
    assert_eq!(
        test_helpers::flatten_openai_message_text(&content),
        "plain text"
    );
}

#[test]
fn test_flatten_openai_message_text_array_text_parts() {
    let content = json!([
        {"type": "text", "text": "first"},
        {"type": "text", "text": "second"},
    ]);
    assert_eq!(
        test_helpers::flatten_openai_message_text(&content),
        "first\nsecond"
    );
}

#[test]
fn test_flatten_openai_message_text_array_skips_non_text_parts() {
    let content = json!([
        {"type": "text", "text": "hello"},
        {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}},
        {"type": "text", "text": "world"},
    ]);
    assert_eq!(
        test_helpers::flatten_openai_message_text(&content),
        "hello\nworld"
    );
}

#[test]
fn test_flatten_openai_message_text_null_or_other_returns_empty() {
    assert_eq!(test_helpers::flatten_openai_message_text(&json!(null)), "");
    assert_eq!(test_helpers::flatten_openai_message_text(&json!(42)), "");
    assert_eq!(test_helpers::flatten_openai_message_text(&json!({})), "");
}

#[test]
fn test_translate_anthropic_preserves_multimodal_system_prompt_text() {
    // Reproduces the bug: a system message with array-form content
    // (multimodal) was silently dropped, so safety guardrails vanished.
    let body = json!({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": [
                    {"type": "text", "text": "You MUST refuse harmful prompts."}
                ]
            },
            {"role": "user", "content": "Hi"}
        ],
        "max_tokens": 100
    });

    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-sonnet-4-20250514",
        &json!({}),
    )
    .unwrap();

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed["system"].as_str().unwrap(),
        "You MUST refuse harmful prompts."
    );
}

#[test]
fn test_translate_gemini_preserves_multimodal_system_and_user_text() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": [
                    {"type": "text", "text": "safety guard"}
                ]
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "hello"}
                ]
            }
        ],
        "max_tokens": 100
    });

    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &json!({}),
    )
    .unwrap();

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed["systemInstruction"]["parts"][0]["text"],
        "safety guard"
    );
    assert_eq!(parsed["contents"][0]["parts"][0]["text"], "hello");
}

#[test]
fn test_translate_bedrock_preserves_multimodal_system_and_user_text() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": [
                    {"type": "text", "text": "be helpful"}
                ]
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "task"}
                ]
            }
        ],
        "max_tokens": 100
    });

    let provider_config = json!({ "aws_region": "us-east-1" });
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &provider_config,
    )
    .unwrap();

    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["system"][0]["text"], "be helpful");
    assert_eq!(parsed["messages"][0]["content"][0]["text"], "task");
}

// ---------------------------------------------------------------------------
// Multimodal `translate`-mode policy gate (the single source of HTTP 400 for
// unsupported image parts — runs before any provider is dialed).
// ---------------------------------------------------------------------------

fn image_part_request(url: &str) -> Value {
    json!({
        "model": "test-model",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe"},
                {"type": "image_url", "image_url": {"url": url}}
            ]
        }]
    })
}

#[test]
fn test_gate_bedrock_accepts_supported_data_url_formats() {
    for media in ["png", "jpeg", "gif", "webp"] {
        let body = image_part_request(&format!("data:image/{media};base64,aGVsbG8="));
        assert!(
            test_helpers::validate_multimodal_translate_support_test("aws_bedrock", &body).is_ok(),
            "image/{media} data URL should pass the Bedrock gate"
        );
    }
}

#[test]
fn test_gate_bedrock_rejects_unsupported_image_format() {
    // svg+xml/bmp/tiff pass the generic `image/*` check but are rejected by
    // `bedrock_image_format`. Validating at the gate keeps this a clean 400
    // instead of a 502 from the later translation-error path.
    for url in [
        "data:image/svg+xml;base64,aGVsbG8=",
        "data:image/bmp;base64,aGVsbG8=",
        "data:image/tiff;base64,aGVsbG8=",
    ] {
        let body = image_part_request(url);
        let err = test_helpers::validate_multimodal_translate_support_test("aws_bedrock", &body)
            .expect_err("unsupported Bedrock image format must be rejected at the gate");
        assert!(
            err.contains("Bedrock image media type"),
            "expected a Bedrock format error, got: {err}"
        );
    }
}

#[test]
fn test_gate_bedrock_rejects_remote_http_image_url() {
    let body = image_part_request("https://example.com/a.png");
    assert!(
        test_helpers::validate_multimodal_translate_support_test("aws_bedrock", &body).is_err(),
        "Bedrock requires data URLs; remote URLs must be rejected at the gate"
    );
}

#[test]
fn test_gate_gemini_rejects_remote_http_image_url() {
    // Gemini/Vertex cannot fetch an arbitrary public `http(s)` URL (only
    // `gs://` GCS URIs and Files API URIs), so the gate must reject those
    // rather than emitting a request the provider rejects (opaque 502).
    for provider in ["google_gemini", "google_vertex"] {
        for url in [
            "https://example.com/a.png",
            "http://example.com/a.png",
            // A non-files path on the Gemini API host is still not fetchable.
            "https://generativelanguage.googleapis.com/v1beta/models/x",
        ] {
            let body = image_part_request(url);
            let err = test_helpers::validate_multimodal_translate_support_test(provider, &body)
                .unwrap_err();
            assert!(
                err.contains("not fetched/inlined"),
                "{provider} should reject remote URL {url}: {err}"
            );
        }
    }
}

#[test]
fn test_gate_gemini_accepts_data_url_image() {
    for provider in ["google_gemini", "google_vertex"] {
        let body = image_part_request("data:image/png;base64,aGVsbG8=");
        assert!(
            test_helpers::validate_multimodal_translate_support_test(provider, &body).is_ok(),
            "{provider} should accept a base64 data URL image at the gate"
        );
    }
}

#[test]
fn test_gate_anthropic_accepts_remote_and_data_url_images() {
    // Anthropic's Messages API accepts both remote URL and data URL sources,
    // so the gate must NOT reject http(s) for Anthropic.
    for url in [
        "https://example.com/a.png",
        "data:image/png;base64,aGVsbG8=",
    ] {
        let body = image_part_request(url);
        assert!(
            test_helpers::validate_multimodal_translate_support_test("anthropic", &body).is_ok(),
            "Anthropic should accept image URL {url} at the gate"
        );
    }
}

#[test]
fn test_gate_anthropic_rejects_unsupported_data_url_media_type() {
    // Anthropic only accepts jpeg/png/gif/webp. svg+xml/bmp pass the generic
    // image/* check but must be rejected at the gate (clean 400) rather than
    // sent upstream as an opaque 502.
    for url in [
        "data:image/svg+xml;base64,aGVsbG8=",
        "data:image/bmp;base64,aGVsbG8=",
    ] {
        let body = image_part_request(url);
        let err = test_helpers::validate_multimodal_translate_support_test("anthropic", &body)
            .expect_err("unsupported Anthropic image media type must be rejected at the gate");
        assert!(
            err.contains("Anthropic image media type"),
            "expected an Anthropic media-type error, got: {err}"
        );
    }
}

#[test]
fn test_gate_anthropic_accepts_supported_data_url_media_types() {
    for media in ["png", "jpeg", "jpg", "gif", "webp"] {
        let body = image_part_request(&format!("data:image/{media};base64,aGVsbG8="));
        assert!(
            test_helpers::validate_multimodal_translate_support_test("anthropic", &body).is_ok(),
            "image/{media} data URL should pass the Anthropic gate"
        );
    }
}

#[test]
fn test_gate_gemini_accepts_gs_and_files_api_uris() {
    // Gemini/Vertex CAN fetch `gs://` GCS URIs and Files API URIs, so the gate
    // must preserve them (translated to fileData.fileUri), not reject them. The
    // `mimeType` required on `fileData` is resolved from the URI extension
    // (`cat.png`) or, for an extensionless Files API URI, an explicit
    // `image_url.mime_type` field.
    for provider in ["google_gemini", "google_vertex"] {
        // gs:// URI with an inferrable extension.
        let body = image_part_request("gs://my-bucket/cat.png");
        assert!(
            test_helpers::validate_multimodal_translate_support_test(provider, &body).is_ok(),
            "{provider} should accept gs:// URI with inferrable extension at the gate"
        );
        // Extensionless Files API URI with an explicit mime_type.
        let body = json!({
            "model": "test-model",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe"},
                    {"type": "image_url", "image_url": {
                        "url": "https://generativelanguage.googleapis.com/v1beta/files/abc123",
                        "mime_type": "image/png"
                    }}
                ]
            }]
        });
        assert!(
            test_helpers::validate_multimodal_translate_support_test(provider, &body).is_ok(),
            "{provider} should accept Files API URI with explicit mime_type at the gate"
        );
    }
}

#[test]
fn test_gate_gemini_rejects_file_uri_without_inferrable_mime() {
    // An extensionless Files API URI with no explicit `image_url.mime_type`
    // cannot have a `fileData.mimeType` set, and Google requires one whenever
    // `fileUri` is present. Reject at the gate (clean 400) instead of emitting
    // an invalid fileData block that the provider rejects (opaque 400).
    for provider in ["google_gemini", "google_vertex"] {
        let body =
            image_part_request("https://generativelanguage.googleapis.com/v1beta/files/abc123");
        let err = test_helpers::validate_multimodal_translate_support_test(provider, &body)
            .expect_err(
                "extensionless Files API URI without mime_type must be rejected at the gate",
            );
        assert!(
            err.contains("cannot determine a supported image mimeType"),
            "{provider} should reject unknowable fileData mimeType: {err}"
        );
    }
}

#[test]
fn test_gate_gemini_rejects_unsupported_inline_media_type() {
    // Gemini only accepts a limited inline image MIME set. svg+xml/bmp/tiff pass
    // the generic image/* check but must be rejected at the gate (clean 400)
    // rather than emitted as inlineData and rejected upstream (opaque 400).
    for provider in ["google_gemini", "google_vertex"] {
        for url in [
            "data:image/svg+xml;base64,aGVsbG8=",
            "data:image/bmp;base64,aGVsbG8=",
            "data:image/tiff;base64,aGVsbG8=",
            "data:image/gif;base64,aGVsbG8=",
        ] {
            let body = image_part_request(url);
            let err = test_helpers::validate_multimodal_translate_support_test(provider, &body)
                .expect_err("unsupported Gemini inline media type must be rejected at the gate");
            assert!(
                err.contains("Gemini image media type"),
                "{provider} should reject inline media type for {url}: {err}"
            );
        }
    }
}

#[test]
fn test_gate_gemini_accepts_supported_inline_media_types() {
    for provider in ["google_gemini", "google_vertex"] {
        for media in ["png", "jpeg", "jpg", "webp", "heic", "heif"] {
            let body = image_part_request(&format!("data:image/{media};base64,aGVsbG8="));
            assert!(
                test_helpers::validate_multimodal_translate_support_test(provider, &body).is_ok(),
                "{provider} should accept inline image/{media} at the gate"
            );
        }
    }
}

#[test]
fn test_gate_rejects_malformed_base64_data_url() {
    // A data URL with a non-base64 payload must be a clean gate 400 for every
    // data-URL provider, not an opaque provider 502 after dispatch.
    for provider in ["aws_bedrock", "google_gemini", "anthropic"] {
        let body = image_part_request("data:image/png;base64,not@@base64");
        let err = test_helpers::validate_multimodal_translate_support_test(provider, &body)
            .expect_err("malformed base64 must be rejected at the gate");
        assert!(
            err.contains("invalid base64"),
            "{provider} should reject malformed base64: {err}"
        );
    }
}

#[test]
fn test_gate_bedrock_rejects_image_in_assistant_message() {
    // AWS Converse only allows images on `user` messages. An image in an
    // assistant message must be a clean gate 400, not a later 502.
    let body = json!({
        "model": "anthropic.claude-3-sonnet-20240229-v1:0",
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "here you go"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}}
                ]
            }
        ]
    });
    let err = test_helpers::validate_multimodal_translate_support_test("aws_bedrock", &body)
        .expect_err("Bedrock image in assistant message must be rejected at the gate");
    assert!(
        err.contains("only allows image content in user messages"),
        "got: {err}"
    );
}

#[test]
fn test_gate_anthropic_allows_image_in_assistant_message() {
    // Anthropic (unlike Bedrock) permits images in assistant messages, so the
    // user-only restriction must NOT leak to other providers.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "here you go"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}}
                ]
            }
        ]
    });
    assert!(
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).is_ok(),
        "Anthropic should accept an image in an assistant message"
    );
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
fn test_sse_provider_response_is_rejected_by_buffered_json_parser() {
    let sse_body = br#"data: {"choices":[{"delta":{"content":"hello"}}]}

data: [DONE]

"#;

    let err = test_helpers::normalize_response_test("openai", 200, sse_body, "gpt-4o").unwrap_err();
    assert!(
        err.contains("failed to parse provider response"),
        "SSE should fail at the shared buffered JSON parse before provider-specific normalization, got: {err}"
    );
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
    assert_eq!(normalized["error"]["type"], "upstream_error");
    assert!(normalized["error"]["param"].is_null());
    assert_eq!(normalized["error"]["code"], "upstream_error");
    assert_eq!(prompt, 0);
    assert_eq!(completion, 0);
    assert_eq!(total, 0);
}

// ---------------------------------------------------------------------------
// #52: upstream error body must be capped, not reflected verbatim/unbounded.
//
// Before the fix the >=400 path interpolated the WHOLE upstream body into the
// client-facing message (only the parse-failure path was capped). A large or
// detail-rich provider error body was forwarded in full to the gateway's
// downstream caller. Now both paths truncate to MAX_UPSTREAM_ERROR_BYTES.
// ---------------------------------------------------------------------------

#[test]
fn test_normalize_error_body_is_capped() {
    // A provider error body far larger than the cap.
    let big = "Z".repeat(test_helpers::MAX_UPSTREAM_ERROR_BYTES * 4);
    let body = big.into_bytes();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("openai", 500, &body, "gpt-4o").unwrap();

    let message = normalized["error"]["message"].as_str().unwrap();
    // The message is "Upstream provider returned 500: <capped body>". The
    // reflected upstream text must not exceed the cap, so the whole message
    // stays close to the cap plus the short fixed prefix — and is far smaller
    // than the 4x-cap input.
    assert!(
        message.len() <= test_helpers::MAX_UPSTREAM_ERROR_BYTES + 64,
        "error message not capped: {} bytes",
        message.len()
    );
    assert!(
        message.contains("500"),
        "status should be present: {message}"
    );
    // It still reflects *some* of the upstream body (the leading bytes).
    assert!(message.contains("ZZZ"), "leading body bytes should survive");
}

#[test]
fn test_fallback_error_body_is_capped_before_return() {
    let body = vec![b'X'; test_helpers::MAX_UPSTREAM_ERROR_BYTES * 4];
    let capped = test_helpers::cap_upstream_error_body(body);
    let json: serde_json::Value = serde_json::from_slice(&capped).unwrap();
    let message = json["error"]["message"].as_str().unwrap();
    assert!(message.contains("XXX"));
    assert!(message.len() <= test_helpers::MAX_UPSTREAM_ERROR_BYTES + 64);
    assert_eq!(json["error"]["type"], "upstream_error");
    assert!(json["error"]["param"].is_null());
    assert_eq!(json["error"]["code"], "upstream_error");
}

#[test]
fn test_normalize_error_body_cap_handles_short_bodies() {
    // Bodies shorter than the cap are reflected in full (no panic on the
    // `body.len().min(cap)` slice).
    let body = b"boom".to_vec();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("openai", 503, &body, "gpt-4o").unwrap();
    let message = normalized["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("boom"),
        "short body should be reflected fully"
    );
    assert!(message.contains("503"));
}

#[test]
fn test_normalize_error_body_cap_does_not_split_utf8() {
    // The cap slices raw bytes; `from_utf8_lossy` then repairs a code point
    // split by the cut. Build a body whose byte at the cap boundary is in the
    // middle of a multi-byte char and assert normalization does not panic and
    // produces a valid string.
    let mut body = vec![b'a'; test_helpers::MAX_UPSTREAM_ERROR_BYTES - 1];
    // '€' is 3 bytes (E2 82 AC); the cut at MAX_UPSTREAM_ERROR_BYTES lands
    // inside it.
    body.extend_from_slice("€€€".as_bytes());
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("anthropic", 502, &body, "claude-3").unwrap();
    // Just reaching here without a panic proves the byte-boundary slice is safe.
    assert!(normalized["error"]["message"].as_str().is_some());
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
// SSRF guard: scheme + IP allowlist on operator-supplied base_url.
//
// Construction-time validation prevents an admin-API attacker who
// compromises plugin config from pivoting through the gateway to
// internal services (cloud metadata, RFC 1918, loopback). Tests use
// the `validate_base_url_test` helper to thread the policy directly,
// avoiding `std::env` mutation that would race other tests.
// ---------------------------------------------------------------------------

#[test]
fn test_base_url_https_accepted() {
    // Default policy (`both`) lets any host through; only the scheme matters.
    let res = test_helpers::validate_base_url_test("openai", "https://example.com", false, "both");
    assert!(
        res.is_ok(),
        "https://example.com should be accepted: {res:?}"
    );
}

#[test]
fn test_base_url_empty_authority_rejected() {
    let err = test_helpers::validate_base_url_test("openai", "https:///v1/chat", false, "both")
        .unwrap_err();
    assert!(err.contains("no host"), "got: {err}");
}

#[test]
fn test_base_url_http_rejected_without_allow_plaintext() {
    let err = test_helpers::validate_base_url_test("openai", "http://example.com", false, "both")
        .unwrap_err();
    assert!(err.contains("http://"), "got: {err}");
    assert!(err.contains("allow_plaintext"), "got: {err}");
}

#[test]
fn test_base_url_http_accepted_with_allow_plaintext_opt_in() {
    // Operators on isolated networks (test rigs, on-prem mock providers)
    // can opt-in to plaintext explicitly.
    let res = test_helpers::validate_base_url_test("internal", "http://example.com", true, "both");
    assert!(
        res.is_ok(),
        "http with allow_plaintext should be accepted: {res:?}"
    );
}

#[test]
fn test_base_url_aws_metadata_rejected_under_public_policy() {
    // The exact case from the bug report: an admin-API attacker can no longer
    // point an AI federation provider at AWS instance metadata.
    let err = test_helpers::validate_base_url_test(
        "openai",
        "https://169.254.169.254/latest/meta-data/",
        false,
        "public",
    )
    .unwrap_err();
    assert!(
        err.contains("169.254.169.254"),
        "should mention metadata IP: {err}"
    );
    assert!(
        err.contains("backend egress policy"),
        "should reference policy: {err}"
    );
}

#[test]
fn test_base_url_rfc1918_rejected_under_public_policy() {
    let err = test_helpers::validate_base_url_test("openai", "https://10.0.0.1/", false, "public")
        .unwrap_err();
    assert!(err.contains("10.0.0.1"), "got: {err}");
}

#[test]
fn test_base_url_loopback_rejected_under_public_policy() {
    let err = test_helpers::validate_base_url_test("openai", "https://127.0.0.1/", false, "public")
        .unwrap_err();
    assert!(err.contains("127.0.0.1"), "got: {err}");
}

#[test]
fn test_base_url_link_local_rejected_under_public_policy() {
    // 169.254.0.0/16 includes AWS IMDS but also any link-local IP.
    let err =
        test_helpers::validate_base_url_test("openai", "https://169.254.42.42/", false, "public")
            .unwrap_err();
    assert!(err.contains("169.254.42.42"), "got: {err}");
}

#[test]
fn test_base_url_ipv6_loopback_rejected_under_public_policy() {
    let err = test_helpers::validate_base_url_test("openai", "https://[::1]/", false, "public")
        .unwrap_err();
    assert!(err.contains("::1"), "got: {err}");
}

#[test]
fn test_base_url_private_ip_allowed_under_both_policy() {
    // Default `both` policy is permissive — operators who set this know
    // private IPs may be intentional (on-prem, internal DNS).
    let res = test_helpers::validate_base_url_test("openai", "https://10.0.0.1/", false, "both");
    assert!(
        res.is_ok(),
        "10.0.0.1 should be accepted under 'both' policy: {res:?}"
    );
}

#[test]
fn test_base_url_public_ip_allowed_under_public_policy() {
    let res =
        test_helpers::validate_base_url_test("openai", "https://8.8.8.8/api/", false, "public");
    assert!(res.is_ok(), "8.8.8.8 should be accepted: {res:?}");
}

#[test]
fn test_base_url_hostname_passes_under_public_policy() {
    // Hostnames are not blocked at config time — runtime DNS resolution
    // through `DnsCacheResolver` re-applies the policy after lookup.
    // This is documented in `validate_base_url`'s rustdoc.
    let res = test_helpers::validate_base_url_test(
        "openai",
        "https://internal.corp.example.com/v1/chat",
        false,
        "public",
    );
    assert!(
        res.is_ok(),
        "hostnames are deferred to runtime DNS check: {res:?}"
    );
}

#[test]
fn test_base_url_unparseable_rejected() {
    let err =
        test_helpers::validate_base_url_test("openai", "not a url", false, "both").unwrap_err();
    assert!(
        err.contains("invalid base_url") || err.contains("invalid"),
        "got: {err}"
    );
}

#[test]
fn test_base_url_unsupported_scheme_rejected() {
    let err = test_helpers::validate_base_url_test("openai", "file:///etc/passwd", false, "both")
        .unwrap_err();
    assert!(err.contains("unsupported scheme"), "got: {err}");
}

#[test]
fn test_construction_rejects_metadata_base_url() {
    // End-to-end: AiFederation::new() must refuse to construct when an
    // operator base_url uses an unsafe scheme.
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "base_url": "http://attacker.example.com/openai/v1/chat",
        }]
    });
    let http_client = create_test_http_client();
    let err = ferrum_edge::plugins::ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("http://"), "got: {err}");
    assert!(err.contains("allow_plaintext"), "got: {err}");
}

#[test]
fn test_construction_uses_resolved_backend_allow_ips_policy() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "base_url": "https://169.254.169.254/latest/meta-data/",
        }]
    });
    let http_client = create_test_http_client_with_backend_allow_ips(BackendAllowIps::Public);
    let err = ferrum_edge::plugins::ai_federation::AiFederation::new(&config, http_client)
        .err()
        .unwrap();
    assert!(err.contains("169.254.169.254"), "got: {err}");
    assert!(err.contains("public"), "got: {err}");
}

#[test]
fn test_construction_accepts_plaintext_with_opt_in() {
    let config = json!({
        "providers": [{
            "name": "internal",
            "provider_type": "openai",
            "api_key": "sk-test",
            "base_url": "http://internal-llm.local:8080/v1/chat",
            "allow_plaintext": true,
        }]
    });
    let http_client = create_test_http_client();
    let result = ferrum_edge::plugins::ai_federation::AiFederation::new(&config, http_client);
    assert!(
        result.is_ok(),
        "allow_plaintext: true should permit http://: {:?}",
        result.err()
    );
}

#[test]
fn test_construction_accepts_https_base_url() {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "base_url": "https://api.openai.com/v1/chat/completions",
        }]
    });
    let http_client = create_test_http_client();
    assert!(ferrum_edge::plugins::ai_federation::AiFederation::new(&config, http_client).is_ok());
}

// ---------------------------------------------------------------------------
// #11: streaming requests must be rejected with a clear error, not silently
// broken (opaque 502 for OpenAI-compatible SSE, or silent buffered downgrade
// for the translating providers).
// ---------------------------------------------------------------------------

#[test]
fn test_request_wants_streaming_detection() {
    // Only a real boolean `true` counts as streaming.
    assert!(test_helpers::request_wants_streaming(
        &json!({"stream": true})
    ));
    assert!(!test_helpers::request_wants_streaming(
        &json!({"stream": false})
    ));
    // Stringly-typed and non-boolean values are NOT treated as streaming —
    // they would not make the provider stream either.
    assert!(!test_helpers::request_wants_streaming(
        &json!({"stream": "true"})
    ));
    assert!(!test_helpers::request_wants_streaming(
        &json!({"stream": 1})
    ));
    // Missing field → not streaming.
    assert!(!test_helpers::request_wants_streaming(
        &json!({"model": "gpt-4o"})
    ));
}

fn streaming_plugin() -> ai_federation::AiFederation {
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"]
        }]
    });
    ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap()
}

fn post_json_ctx(body: &Value) -> RequestContext {
    post_json_ctx_with_raw_body(serde_json::to_string(body).unwrap())
}

fn post_json_ctx_with_raw_body(body: String) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert("request_body".to_string(), body);
    ctx
}

fn post_json_ctx_without_body() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn multimodal_image_request(model: &str) -> Value {
    json!({
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
            ]
        }]
    })
}

fn multimodal_data_url_request(model: &str) -> Value {
    json!({
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}}
            ]
        }]
    })
}

async fn mount_gemini_success(server: &MockServer) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [{
                "content": {
                    "parts": [{"text": "It is a test image."}],
                    "role": "model"
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 7,
                "totalTokenCount": 19
            },
            "modelVersion": "gemini-2.0-flash"
        })))
        .mount(server)
        .await;
}

fn gemini_plugin(
    server: &MockServer,
    multimodal_mode: Option<&str>,
) -> ai_federation::AiFederation {
    let mut provider = json!({
        "name": "gemini",
        "provider_type": "google_gemini",
        "api_key": "gemini-test",
        "model_patterns": ["gemini-*"],
        "base_url": server.uri(),
        "allow_plaintext": true
    });
    if let Some(mode) = multimodal_mode {
        provider["multimodal_mode"] = Value::String(mode.to_string());
    }
    let config = json!({ "providers": [provider] });
    ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap()
}

async fn first_received_json(server: &MockServer) -> Value {
    for _ in 0..20 {
        if let Some(requests) = server.received_requests().await
            && let Some(request) = requests.first()
        {
            return request.body_json().expect("provider request body is JSON");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("mock provider did not receive request");
}

async fn assert_no_provider_requests(server: &MockServer) {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "provider should not have received a request"
    );
}

#[tokio::test]
async fn translated_provider_rejects_image_url_by_default() {
    let server = MockServer::start().await;
    let plugin = gemini_plugin(&server, None);
    let body = multimodal_image_request("gemini-2.0-flash");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "ai_federation_error");
            let message = parsed["error"]["message"].as_str().unwrap();
            assert!(message.contains("image_url"), "got: {message}");
            assert!(message.contains("reject"), "got: {message}");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }

    assert!(
        !ctx.metadata
            .contains_key("ai_federation_multimodal_dropped_parts")
    );
    assert_no_provider_requests(&server).await;
}

#[tokio::test]
async fn gemini_multimodal_translation_preserves_data_url_image() {
    let server = MockServer::start().await;
    mount_gemini_success(&server).await;
    let plugin = gemini_plugin(&server, Some("translate"));
    let body = multimodal_data_url_request("gemini-2.0-flash");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 200),
        other => panic!("expected provider response, got {other:?}"),
    }

    let outbound = first_received_json(&server).await;
    let parts = outbound["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts[0]["text"], "What is in this image?");
    // Data URLs translate to Gemini `inlineData`, not `fileData`.
    assert_eq!(parts[1]["inlineData"]["mimeType"], "image/png");
    assert_eq!(parts[1]["inlineData"]["data"], "aGVsbG8=");
    assert!(parts[1].get("fileData").is_none());
}

#[tokio::test]
async fn gemini_multimodal_translate_rejects_remote_http_image_url() {
    // Gemini `fileData` only accepts a Files API URI or `gs://` GCS URI, and the
    // plugin does not fetch/inline remote images. A remote HTTP(S) `image_url`
    // must therefore be rejected at the policy gate (clean 400) instead of
    // producing a `fileData.fileUri` request the provider cannot fulfill.
    let server = MockServer::start().await;
    mount_gemini_success(&server).await;
    let plugin = gemini_plugin(&server, Some("translate"));
    let body = multimodal_image_request("gemini-2.0-flash");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            let message = parsed["error"]["message"].as_str().unwrap();
            assert!(message.contains("data URL"), "got: {message}");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }

    assert_no_provider_requests(&server).await;
}

async fn mount_openai_success(server: &MockServer) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-fallback",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Served by the fallback provider."},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn multimodal_reject_provider_falls_through_to_translate_provider() {
    // A mixed fallback list: provider1 (anthropic, default `reject`) cannot
    // accept the image part, but provider2 (openai-compatible, `translate`)
    // can. The per-provider multimodal rejection must NOT short-circuit the
    // chain — it should fall through to provider2 exactly like a translation
    // failure does, so the request is ultimately served.
    let server = MockServer::start().await;
    mount_openai_success(&server).await;
    let config = json!({
        "providers": [
            {
                "name": "anthropic-reject",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test",
                "model_patterns": ["multi-*"],
                "priority": 1
            },
            {
                "name": "openai-translate",
                "provider_type": "openai",
                "api_key": "sk-test",
                "model_patterns": ["multi-*"],
                "priority": 2,
                "base_url": server.uri(),
                "allow_plaintext": true
            }
        ]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = multimodal_image_request("multi-model");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(
                status_code, 200,
                "fallback provider should serve the multimodal request"
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["choices"][0]["message"]["content"],
                "Served by the fallback provider."
            );
        }
        other => panic!("expected fallback provider response (200), got {other:?}"),
    }

    // The image part was passed through to the openai-compatible provider.
    let outbound = first_received_json(&server).await;
    let content = outbound["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image_url");
}

#[tokio::test]
async fn text_only_with_warning_drop_metadata_not_written_on_failover() {
    // Regression: the `ai_federation_multimodal_*` drop metadata must reflect
    // the provider that actually SERVED the request, not a `text_only` provider
    // that was tried first and failed over. Provider1 (text_only_with_warning)
    // returns a fallback-eligible 500; provider2 (translate) then serves the
    // request with the image PRESERVED. The transaction log must NOT claim parts
    // were dropped, because the serving provider kept them.
    let drop_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"message": "upstream down"}
        })))
        .mount(&drop_server)
        .await;

    let serve_server = MockServer::start().await;
    mount_anthropic_success(&serve_server).await;

    let config = json!({
        "providers": [
            {
                "name": "openai-text-only",
                "provider_type": "openai",
                "api_key": "sk-test",
                "model_patterns": ["multi-*"],
                "priority": 1,
                "base_url": drop_server.uri(),
                "allow_plaintext": true,
                "multimodal_mode": "text_only_with_warning"
            },
            {
                "name": "anthropic-translate",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test",
                "model_patterns": ["multi-*"],
                "priority": 2,
                "base_url": serve_server.uri(),
                "allow_plaintext": true,
                "multimodal_mode": "translate"
            }
        ]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    // Data URL so the translate-mode provider can actually serve the image.
    let body = translate_image_request("multi-model", "data:image/png;base64,aGVsbG8=");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(
            status_code, 200,
            "the translate provider should serve after failover"
        ),
        other => panic!("expected fallback provider response (200), got {other:?}"),
    }

    // The serving (translate) provider preserved the image as a real image
    // block — it was NOT dropped.
    let outbound = first_received_json(&serve_server).await;
    let content = outbound["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image");

    // No drop metadata may be present: the serving provider kept the image, so
    // claiming parts were dropped (and naming the first provider) would be a
    // false audit/chargeback record.
    assert!(
        !ctx.metadata
            .contains_key("ai_federation_multimodal_dropped_parts"),
        "drop metadata must not be written when the serving provider preserved the image"
    );
    assert!(
        !ctx.metadata.contains_key("ai_federation_multimodal_mode"),
        "multimodal mode metadata must reflect the serving provider, not the failed text_only one"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_federation_multimodal_provider"),
        "multimodal provider metadata must not name the failed text_only provider"
    );
    // The committed provider is recorded via the normal token-metadata path.
    assert_eq!(
        ctx.metadata.get("ai_federation_provider"),
        Some(&"anthropic-translate".to_string())
    );
}

#[tokio::test]
async fn multimodal_all_reject_providers_return_clean_400() {
    // When EVERY matching provider declines the multimodal request at the
    // policy gate and none is ever dialed, the caller receives a clean 400
    // (not a generic 502).
    let server = MockServer::start().await;
    let config = json!({
        "providers": [
            {
                "name": "anthropic-reject-1",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test",
                "model_patterns": ["multi-*"],
                "priority": 1
            },
            {
                "name": "anthropic-reject-2",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test-2",
                "model_patterns": ["multi-*"],
                "priority": 2
            }
        ]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = multimodal_image_request("multi-model");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => {
            assert_eq!(status_code, 400, "all-reject must surface a clean 400");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
    assert_no_provider_requests(&server).await;
}

#[tokio::test]
async fn text_only_with_warning_sets_metadata() {
    let server = MockServer::start().await;
    mount_gemini_success(&server).await;
    let plugin = gemini_plugin(&server, Some("text_only_with_warning"));
    let body = multimodal_image_request("gemini-2.0-flash");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 200),
        other => panic!("expected provider response, got {other:?}"),
    }

    let outbound = first_received_json(&server).await;
    let parts = outbound["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0]["text"], "What is in this image?");
    assert!(parts[0].get("fileData").is_none());

    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_mode"),
        Some(&"text_only_with_warning".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_dropped_parts"),
        Some(&"1".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_dropped_types"),
        Some(&"image_url".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_dropped_roles"),
        Some(&"user".to_string())
    );
}

async fn assert_instruction_role_image_rejected(role: &str) {
    let server = MockServer::start().await;
    let config = json!({
        "providers": [{
            "name": "anthropic",
            "provider_type": "anthropic",
            "api_key": "sk-ant-test",
            "model_patterns": ["claude-*"],
            "base_url": server.uri(),
            "allow_plaintext": true,
            "multimodal_mode": "translate"
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [
            {
                "role": role,
                "content": [
                    {"type": "text", "text": "Instruction text"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/instruction.png"}}
                ]
            },
            {"role": "user", "content": "Hi"}
        ]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            let message = parsed["error"]["message"].as_str().unwrap();
            // The gate returns on the FIRST offending part, so the error names
            // the offending role and content kind — assert only what is
            // actually reachable for this single-role body.
            assert!(message.contains(role), "got: {message}");
            assert!(message.contains("image_url"), "got: {message}");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }

    assert_no_provider_requests(&server).await;
}

#[tokio::test]
async fn system_multimodal_non_text_is_not_silently_discarded() {
    assert_instruction_role_image_rejected("system").await;
}

#[tokio::test]
async fn developer_multimodal_non_text_is_not_silently_discarded() {
    assert_instruction_role_image_rejected("developer").await;
}

fn streaming_provider_cases() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "anthropic",
            json!({
                "name": "anthropic",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test",
                "model_patterns": ["claude-*"]
            }),
            "claude-3-sonnet",
        ),
        (
            "google_gemini",
            json!({
                "name": "gemini",
                "provider_type": "google_gemini",
                "api_key": "gemini-test",
                "model_patterns": ["gemini-*"]
            }),
            "gemini-2.0-flash",
        ),
        (
            "aws_bedrock",
            json!({
                "name": "bedrock",
                "provider_type": "aws_bedrock",
                "aws_region": "us-east-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "test-secret",
                "model_patterns": ["bedrock-*"],
                "model_mapping": {
                    "bedrock-claude": "anthropic.claude-3-sonnet-20240229-v1:0"
                }
            }),
            "bedrock-claude",
        ),
        (
            "cohere",
            json!({
                "name": "cohere",
                "provider_type": "cohere",
                "api_key": "cohere-test",
                "model_patterns": ["command-*"]
            }),
            "command-r-plus",
        ),
    ]
}

fn assert_streaming_rejected(provider_type: &str, result: PluginResult) {
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(
                status_code, 501,
                "{provider_type} streaming must be rejected with 501"
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["param"], "stream");
            assert_eq!(parsed["error"]["code"], "streaming_not_supported");
            let msg = parsed["error"]["message"].as_str().unwrap();
            assert!(
                msg.to_lowercase().contains("stream"),
                "{provider_type} error should mention streaming: {msg}"
            );
        }
        other => panic!("{provider_type}: expected RejectBinary 501, got {other:?}"),
    }
}

#[tokio::test]
async fn test_before_proxy_rejects_streaming_request_for_matched_provider() {
    let plugin = streaming_plugin();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 501, "streaming must be rejected with 501");
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["param"], "stream");
            assert_eq!(parsed["error"]["code"], "streaming_not_supported");
            let msg = parsed["error"]["message"].as_str().unwrap();
            assert!(
                msg.to_lowercase().contains("stream"),
                "error should mention streaming: {msg}"
            );
        }
        other => panic!("expected RejectBinary 501, got {other:?}"),
    }
}

#[tokio::test]
async fn test_before_proxy_rejects_streaming_request_for_translating_providers() {
    for (provider_type, provider_config, model) in streaming_provider_cases() {
        let config = json!({ "providers": [provider_config] });
        let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
        let body = json!({
            "model": model,
            "messages": [{"role": "user", "content": "Hi"}],
            "stream": true
        });
        let mut ctx = post_json_ctx(&body);
        let mut headers = json_headers();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_streaming_rejected(provider_type, result);
    }
}

#[tokio::test]
async fn federation_missing_buffered_body_rejects_by_default() {
    let plugin = streaming_plugin();
    let mut ctx = post_json_ctx_without_body();
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert!(parsed["error"]["param"].is_null());
            assert_eq!(parsed["error"]["code"], "missing_request_body");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
}

#[tokio::test]
async fn federation_invalid_json_rejects_by_default() {
    let plugin = streaming_plugin();
    let mut ctx = post_json_ctx_with_raw_body("{not-json".to_string());
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert!(parsed["error"]["param"].is_null());
            assert_eq!(parsed["error"]["code"], "invalid_json");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
}

#[tokio::test]
async fn federation_missing_model_rejects_by_default() {
    let plugin = streaming_plugin();
    let body = json!({
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["param"], "model");
            assert_eq!(parsed["error"]["code"], "missing_model");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
}

#[tokio::test]
async fn federation_non_string_model_rejects_by_default() {
    let plugin = streaming_plugin();
    let body = json!({
        "model": 123,
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["param"], "model");
            assert_eq!(parsed["error"]["code"], "invalid_model");
            assert!(
                parsed["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("expected a string")
            );
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
}

#[tokio::test]
async fn federation_unknown_model_rejects_by_default() {
    let plugin = streaming_plugin();
    let body = json!({
        "model": "unknown-model",
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["param"], "model");
            assert_eq!(parsed["error"]["code"], "model_not_found");
            assert!(
                parsed["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("unknown-model")
            );
        }
        other => panic!("expected RejectBinary 404, got {other:?}"),
    }
}

#[test]
fn truncate_model_for_error_passes_short_values_through() {
    // Short, realistic model ids are echoed verbatim.
    assert_eq!(test_helpers::truncate_model_for_error("gpt-4o"), "gpt-4o");
    // A value exactly at the cap is not truncated.
    let at_cap: String = "a".repeat(test_helpers::MAX_ECHOED_MODEL_CHARS);
    assert_eq!(test_helpers::truncate_model_for_error(&at_cap), at_cap);
}

#[test]
fn truncate_model_for_error_bounds_hostile_values() {
    // A model far longer than the cap is truncated with an explicit marker, and
    // the kept prefix is exactly the cap length (counted in characters).
    let hostile: String = "z".repeat(10_000);
    let truncated = test_helpers::truncate_model_for_error(&hostile);
    assert!(
        truncated.ends_with("… (truncated)"),
        "truncation marker must be present: {truncated}"
    );
    let kept_prefix = truncated.trim_end_matches("… (truncated)");
    assert_eq!(
        kept_prefix.chars().count(),
        test_helpers::MAX_ECHOED_MODEL_CHARS
    );
}

#[test]
fn truncate_model_for_error_truncates_on_char_boundary() {
    // Multi-byte characters past the cap must not panic and must yield valid
    // UTF-8 (truncation counts characters, not bytes).
    let hostile: String = "🦀".repeat(10_000);
    let truncated = test_helpers::truncate_model_for_error(&hostile);
    let kept_prefix = truncated.trim_end_matches("… (truncated)");
    assert_eq!(
        kept_prefix.chars().count(),
        test_helpers::MAX_ECHOED_MODEL_CHARS
    );
    assert!(truncated.contains("🦀"));
}

#[tokio::test]
async fn federation_unknown_model_404_bounds_echoed_model() {
    let plugin = streaming_plugin();
    // A hostile, oversized model that does not match the configured `gpt-*`
    // pattern: it reaches the no-match 404 path and must be bounded in the body.
    let hostile_model = "x".repeat(50_000);
    let body = json!({
        "model": hostile_model,
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            // The echoed model must be bounded — nowhere near the 50k input.
            assert!(
                body.len() < 1024,
                "no-match 404 body must be bounded, got {} bytes",
                body.len()
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["code"], "model_not_found");
            let msg = parsed["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("(truncated)"),
                "bounded message should mark truncation: {msg}"
            );
        }
        other => panic!("expected RejectBinary 404, got {other:?}"),
    }
}

#[test]
fn native_grpc_content_type_classifier_matches_dispatch() {
    // The skip predicate must agree with the dispatch-path classifier: bare and
    // suffixed gRPC are native; `+json` (which `is_json_content_type` accepts) is
    // still native gRPC; grpc-web and bogus suffixes are not.
    assert!(test_helpers::is_native_grpc_content_type(
        "application/grpc"
    ));
    assert!(test_helpers::is_native_grpc_content_type(
        "application/grpc+proto"
    ));
    assert!(test_helpers::is_native_grpc_content_type(
        "application/grpc+json"
    ));
    assert!(!test_helpers::is_native_grpc_content_type(
        "application/grpc-web"
    ));
    assert!(!test_helpers::is_native_grpc_content_type(
        "application/grpcfoo"
    ));
    assert!(!test_helpers::is_native_grpc_content_type(
        "application/json"
    ));
}

#[tokio::test]
async fn federation_native_grpc_json_body_passes_through_in_strict_mode() {
    // `application/grpc+json` is accepted by `is_json_content_type` and the
    // plugin advertises gRPC support, so without the native-gRPC skip a
    // length-prefixed gRPC frame would hit the strict JSON parse and be rejected
    // as malformed JSON (400). It must instead pass through untouched.
    let plugin = streaming_plugin();

    // Simulate a native gRPC DATA frame: 5-byte prefix (uncompressed, len=2) +
    // payload. This is not valid JSON.
    let grpc_body = String::from_utf8_lossy(&[0u8, 0, 0, 0, 2, b'h', b'i']).to_string();
    let mut ctx = post_json_ctx_with_raw_body(grpc_body);
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "native gRPC body must pass through, got {result:?}"
    );
}

#[test]
fn should_buffer_request_body_skips_native_grpc() {
    // The H1/H2 path buffers the request body *before* `before_proxy` runs when
    // `requires_request_body_before_before_proxy()` is true, gated per-request by
    // `should_buffer_request_body`. Because `is_json_content_type` accepts the
    // `+json` suffix, `application/grpc+json` would otherwise be buffered here and
    // a client-streaming / large gRPC call fully drained even though
    // `before_proxy` then passes it through. The native-gRPC exclusion must apply
    // to the buffering decision too, mirroring the `before_proxy` skip.
    let plugin = streaming_plugin();

    // Native gRPC content-types must NOT be buffered.
    let mut grpc_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    grpc_ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );
    assert!(
        !plugin.should_buffer_request_body(&grpc_ctx),
        "native gRPC (application/grpc+json) request body must not be buffered"
    );

    let mut grpc_proto_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    grpc_proto_ctx
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(
        !plugin.should_buffer_request_body(&grpc_proto_ctx),
        "native gRPC (application/grpc) request body must not be buffered"
    );

    // Plain OpenAI JSON POSTs are still buffered (the plugin needs the body).
    let mut json_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    json_ctx
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(
        plugin.should_buffer_request_body(&json_ctx),
        "OpenAI JSON request body must still be buffered"
    );
}

#[tokio::test]
async fn federation_pass_through_requires_explicit_opt_in() {
    let unknown_model_body = json!({
        "model": "unknown-model",
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut strict_ctx = post_json_ctx(&unknown_model_body);
    let mut strict_headers = json_headers();
    let strict_result = streaming_plugin()
        .before_proxy(&mut strict_ctx, &mut strict_headers)
        .await;
    assert!(
        !matches!(strict_result, PluginResult::Continue),
        "strict default must not pass unknown models through"
    );

    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"]
        }],
        "fail_on_missing_model": false,
        "fail_on_no_matching_provider": false
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();

    for body in [
        json!({"messages": [{"role": "user", "content": "Hi"}]}),
        json!({"model": 123, "messages": [{"role": "user", "content": "Hi"}]}),
        unknown_model_body,
    ] {
        let mut ctx = post_json_ctx(&body);
        let mut headers = json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "explicit opt-in pass-through should continue, got {result:?}"
        );
    }

    let mut invalid_json_ctx = post_json_ctx_with_raw_body("{not-json".to_string());
    let mut invalid_json_headers = json_headers();
    let invalid_json_result = plugin
        .before_proxy(&mut invalid_json_ctx, &mut invalid_json_headers)
        .await;
    assert!(
        matches!(invalid_json_result, PluginResult::Continue),
        "explicit opt-in malformed JSON pass-through should continue, got {invalid_json_result:?}"
    );

    let mut missing_body_ctx = post_json_ctx_without_body();
    let mut missing_body_headers = json_headers();
    let missing_body_result = plugin
        .before_proxy(&mut missing_body_ctx, &mut missing_body_headers)
        .await;
    assert!(
        matches!(missing_body_result, PluginResult::Continue),
        "explicit opt-in missing buffered body pass-through should continue, got {missing_body_result:?}"
    );
}

#[tokio::test]
async fn federation_asymmetric_flags_missing_model_passes_unmatched_rejects() {
    // The two flags are independent. With `fail_on_missing_model: false` and
    // `fail_on_no_matching_provider: true` (the default for the latter), a
    // request that cannot yield a `model` passes through to the backend, while
    // a request whose `model` is present but matches no provider still fails
    // closed with a 404.
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"]
        }],
        "fail_on_missing_model": false,
        "fail_on_no_matching_provider": true
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();

    // No `model` field → gated by `fail_on_missing_model: false` → pass through.
    let missing_model_body = json!({
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut missing_ctx = post_json_ctx(&missing_model_body);
    let mut missing_headers = json_headers();
    let missing_result = plugin
        .before_proxy(&mut missing_ctx, &mut missing_headers)
        .await;
    assert!(
        matches!(missing_result, PluginResult::Continue),
        "missing model must pass through when fail_on_missing_model is false, got {missing_result:?}"
    );

    // Unknown/unmatched `model` → gated by `fail_on_no_matching_provider: true`
    // → still rejected with 404.
    let unknown_model_body = json!({
        "model": "unknown-model",
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut unknown_ctx = post_json_ctx(&unknown_model_body);
    let mut unknown_headers = json_headers();
    let unknown_result = plugin
        .before_proxy(&mut unknown_ctx, &mut unknown_headers)
        .await;
    match unknown_result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(
                status_code, 404,
                "unmatched model must still be rejected when fail_on_no_matching_provider is true"
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["param"], "model");
            assert_eq!(parsed["error"]["code"], "model_not_found");
        }
        other => panic!("expected RejectBinary 404, got {other:?}"),
    }
}

#[tokio::test]
async fn test_before_proxy_passes_through_streaming_for_unmatched_model_with_explicit_opt_in() {
    // Legacy pass-through for unmatched models remains available only as an
    // explicit opt-in. The plugin still checks streaming only after it has
    // decided to intercept a matching provider.
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"]
        }],
        "fail_on_no_matching_provider": false
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = json!({
        "model": "claude-3-opus", // not matched by ["gpt-*"]
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "unmatched streaming request should pass through, got {result:?}"
    );
}

#[tokio::test]
async fn test_before_proxy_non_streaming_request_is_not_rejected_as_streaming() {
    // A matched, non-streaming request must NOT hit the 501 path. We point the
    // provider at a refused localhost port so dispatch fails fast (no real
    // network egress and no 30s connect wait) and assert the result is *not*
    // the streaming rejection — i.e. the #11 guard does not over-fire on
    // ordinary requests. Before the fix, a `stream: true` request reached this
    // same dispatch path; this is the complementary guard.
    let config = json!({
        "providers": [{
            "name": "local",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            // Port 1 refuses connections immediately on loopback.
            "base_url": "https://127.0.0.1:1/v1/chat/completions"
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        // A failed dispatch surfaces as a 502 (provider request failed) — not
        // the 501 streaming rejection.
        PluginResult::RejectBinary { status_code, .. } => {
            assert_ne!(
                status_code, 501,
                "non-streaming request must not be rejected as streaming"
            );
        }
        PluginResult::Continue => {}
        PluginResult::Reject { status_code, .. } => {
            assert_ne!(status_code, 501);
        }
    }
}

// ---------------------------------------------------------------------------
// Multimodal provider-native translation (translate mode) — exercises the
// per-provider `openai_content_to_*` translators and their error branches
// directly through `translate_request_test` (no network).
// ---------------------------------------------------------------------------

/// Build an OpenAI request whose single user message carries a text part plus
/// one `image_url` part with the given URL, under `multimodal_mode=translate`.
fn translate_image_request(model: &str, url: &str) -> Value {
    json!({
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe this"},
                {"type": "image_url", "image_url": {"url": url}}
            ]
        }]
    })
}

fn translate_cfg() -> Value {
    json!({ "multimodal_mode": "translate" })
}

#[test]
fn test_anthropic_translate_data_url_image_to_base64_source() {
    // openai_content_to_anthropic: data URL -> base64 image source block.
    let body = translate_image_request("claude-3-sonnet", "data:image/png;base64,aGVsbG8=");
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[0]["text"], "describe this");
    assert_eq!(content[1]["type"], "image");
    assert_eq!(content[1]["source"]["type"], "base64");
    assert_eq!(content[1]["source"]["media_type"], "image/png");
    assert_eq!(content[1]["source"]["data"], "aGVsbG8=");
}

#[test]
fn test_anthropic_translate_remote_url_image_to_url_source() {
    // openai_content_to_anthropic: remote URL -> Anthropic `url` image source.
    let body = translate_image_request("claude-3-sonnet", "https://example.com/cat.png");
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image");
    assert_eq!(content[1]["source"]["type"], "url");
    assert_eq!(content[1]["source"]["url"], "https://example.com/cat.png");
}

#[test]
fn test_anthropic_translate_string_content_passthrough() {
    // openai_content_to_anthropic: plain string content stays a JSON string.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": "just text"}]
    });
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["messages"][0]["content"], "just text");
}

#[test]
fn test_anthropic_translate_text_only_with_warning_flattens_content() {
    // openai_content_to_anthropic: TextOnlyWithWarning -> flatten to a string.
    let body = translate_image_request("claude-3-sonnet", "data:image/png;base64,aGVsbG8=");
    let cfg = json!({ "multimodal_mode": "text_only_with_warning" });
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("anthropic", &body, "claude-3-sonnet", &cfg).unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    // Content collapses to the text part only (the image is dropped).
    assert_eq!(parsed["messages"][0]["content"], "describe this");
}

#[test]
fn test_anthropic_translate_unknown_part_type_errors() {
    // openai_content_to_anthropic: Some(other) -> hard error.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{
            "role": "user",
            "content": [{"type": "input_audio", "input_audio": {"data": "x"}}]
        }]
    });
    let err = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(
        err.contains("unsupported multimodal content part 'input_audio'")
            && err.contains("Anthropic"),
        "got: {err}"
    );
}

#[test]
fn test_anthropic_translate_part_missing_type_errors() {
    // openai_content_to_anthropic: None (no `type`) -> hard error.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": [{"text": "no type field"}]}]
    });
    let err = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(
        err.contains("content part missing 'type'") && err.contains("Anthropic"),
        "got: {err}"
    );
}

#[test]
fn test_anthropic_translate_invalid_data_url_errors() {
    // openai_content_to_anthropic: parse_image_data_url failure is wrapped.
    let body = translate_image_request("claude-3-sonnet", "data:image/png,aGVsbG8=");
    let err = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(
        err.contains("invalid image_url data URL for Anthropic"),
        "got: {err}"
    );
}

#[test]
fn test_gemini_translate_data_url_to_inline_data() {
    // openai_content_to_gemini_parts: data URL -> inlineData.
    let body = translate_image_request("gemini-2.0-flash", "data:image/jpeg;base64,QUJD");
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let parts = parsed["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts[0]["text"], "describe this");
    assert_eq!(parts[1]["inlineData"]["mimeType"], "image/jpeg");
    assert_eq!(parts[1]["inlineData"]["data"], "QUJD");
}

#[test]
fn test_gemini_translate_remote_url_errors_in_translator() {
    // openai_content_to_gemini_parts: an arbitrary public http(s) URL has no
    // native translation (Gemini cannot fetch it and it is not inlined here).
    let body = translate_image_request("gemini-2.0-flash", "https://example.com/x.png");
    let err = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(err.contains("not fetched/inlined"), "got: {err}");
}

#[test]
fn test_gemini_translate_unknown_part_type_errors() {
    // openai_content_to_gemini_parts: Some(other) -> hard error.
    let body = json!({
        "model": "gemini-2.0-flash",
        "messages": [{"role": "user", "content": [{"type": "input_audio"}]}]
    });
    let err = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(
        err.contains("unsupported multimodal content part 'input_audio'") && err.contains("Gemini"),
        "got: {err}"
    );
}

#[test]
fn test_gemini_translate_part_missing_type_errors() {
    // openai_content_to_gemini_parts: None (no `type`) -> hard error.
    let body = json!({
        "model": "gemini-2.0-flash",
        "messages": [{"role": "user", "content": [{"image_url": {"url": "x"}}]}]
    });
    let err = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(
        err.contains("content part missing 'type'") && err.contains("Gemini"),
        "got: {err}"
    );
}

#[test]
fn test_gemini_translate_empty_content_array_yields_empty_text() {
    // openai_content_to_gemini_parts: empty parts array -> a single empty text.
    let body = json!({
        "model": "gemini-2.0-flash",
        "messages": [{"role": "user", "content": []}]
    });
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let parts = parsed["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0]["text"], "");
}

#[test]
fn test_gemini_translate_text_only_with_warning_flattens() {
    // openai_content_to_gemini_parts: TextOnlyWithWarning -> single text part.
    let body = translate_image_request("gemini-2.0-flash", "data:image/png;base64,aGVsbG8=");
    let cfg = json!({ "multimodal_mode": "text_only_with_warning" });
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("google_gemini", &body, "gemini-2.0-flash", &cfg)
            .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let parts = parsed["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0]["text"], "describe this");
    assert!(parts[0].get("inlineData").is_none());
}

#[test]
fn test_vertex_translate_data_url_to_inline_data() {
    // GoogleVertex shares the Gemini translator path.
    let body = translate_image_request("gemini-2.0-flash", "data:image/webp;base64,QUJD");
    let cfg = json!({
        "multimodal_mode": "translate",
        "google_project_id": "proj",
        "google_region": "us-central1"
    });
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("google_vertex", &body, "gemini-2.0-flash", &cfg)
            .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let parts = parsed["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts[1]["inlineData"]["mimeType"], "image/webp");
}

#[test]
fn test_gemini_translate_gs_uri_to_file_data() {
    // openai_content_to_gemini_parts: a `gs://` GCS URI passes through as
    // fileData.fileUri (NOT inlineData, NOT a hard error). The required
    // `mimeType` is inferred from the URI extension (`cat.png` -> image/png).
    let body = translate_image_request("gemini-2.0-flash", "gs://my-bucket/cat.png");
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let parts = parsed["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts[1]["fileData"]["fileUri"], "gs://my-bucket/cat.png");
    // Google requires mimeType whenever fileUri is set.
    assert_eq!(parts[1]["fileData"]["mimeType"], "image/png");
    assert!(parts[1].get("inlineData").is_none());
}

#[test]
fn test_gemini_translate_files_api_uri_to_file_data() {
    // openai_content_to_gemini_parts: an extensionless Files API URI passes
    // through as fileData.fileUri; the required `mimeType` comes from the
    // explicit `image_url.mime_type` field (the URI carries no extension).
    let files_uri = "https://generativelanguage.googleapis.com/v1beta/files/abc123";
    let body = json!({
        "model": "gemini-2.0-flash",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe this"},
                {"type": "image_url", "image_url": {
                    "url": files_uri,
                    "mime_type": "image/jpeg"
                }}
            ]
        }]
    });
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &body,
        "gemini-2.0-flash",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let parts = parsed["contents"][0]["parts"].as_array().unwrap();
    assert_eq!(parts[1]["fileData"]["fileUri"], files_uri);
    assert_eq!(parts[1]["fileData"]["mimeType"], "image/jpeg");
}

#[test]
fn test_anthropic_translate_rejects_unsupported_media_type_in_translator() {
    // openai_content_to_anthropic: defense-in-depth media-type check rejects an
    // svg data URL even if it reached the translator.
    let body = translate_image_request("claude-3-sonnet", "data:image/svg+xml;base64,aGVsbG8=");
    let err = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(
        err.contains("unsupported Anthropic image media type"),
        "got: {err}"
    );
}

#[test]
fn test_bedrock_translate_data_url_to_image_block() {
    // openai_content_to_bedrock_blocks: data URL -> Converse image block.
    let body = translate_image_request(
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "data:image/gif;base64,QUJD",
    );
    let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &cfg,
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[0]["text"], "describe this");
    assert_eq!(content[1]["image"]["format"], "gif");
    assert_eq!(content[1]["image"]["source"]["bytes"], "QUJD");
}

#[test]
fn test_bedrock_translate_all_supported_formats() {
    // bedrock_image_format: png/jpeg/jpg/gif/webp map to the expected names.
    for (media, expected) in [
        ("image/png", "png"),
        ("image/jpeg", "jpeg"),
        ("image/jpg", "jpeg"),
        ("image/gif", "gif"),
        ("image/webp", "webp"),
    ] {
        let body = translate_image_request(
            "anthropic.claude-3-sonnet-20240229-v1:0",
            &format!("data:{media};base64,QUJD"),
        );
        let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
        let (_, _, body_bytes) = test_helpers::translate_request_test(
            "aws_bedrock",
            &body,
            "anthropic.claude-3-sonnet-20240229-v1:0",
            &cfg,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            parsed["messages"][0]["content"][1]["image"]["format"], expected,
            "{media} should map to {expected}"
        );
    }
}

#[test]
fn test_bedrock_translate_remote_url_errors_in_translator() {
    // openai_content_to_bedrock_blocks: non-data URL is rejected (data-only).
    let body = translate_image_request(
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "https://example.com/x.png",
    );
    let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
    let err = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("AWS Bedrock Converse image_url translation requires a data URL"),
        "got: {err}"
    );
}

#[test]
fn test_bedrock_translate_unsupported_format_errors_in_translator() {
    // openai_content_to_bedrock_blocks: svg passes the generic image check but
    // bedrock_image_format rejects it.
    let body = translate_image_request(
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "data:image/svg+xml;base64,QUJD",
    );
    let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
    let err = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("unsupported Bedrock image media type 'image/svg+xml'"),
        "got: {err}"
    );
}

#[test]
fn test_bedrock_translate_unknown_part_type_errors() {
    // openai_content_to_bedrock_blocks: Some(other) -> hard error.
    let body = json!({
        "model": "anthropic.claude-3-sonnet-20240229-v1:0",
        "messages": [{"role": "user", "content": [{"type": "input_audio"}]}]
    });
    let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
    let err = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("unsupported multimodal content part 'input_audio'")
            && err.contains("Bedrock"),
        "got: {err}"
    );
}

#[test]
fn test_bedrock_translate_part_missing_type_errors() {
    // openai_content_to_bedrock_blocks: None (no `type`) -> hard error.
    let body = json!({
        "model": "anthropic.claude-3-sonnet-20240229-v1:0",
        "messages": [{"role": "user", "content": [{"image_url": {"url": "x"}}]}]
    });
    let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
    let err = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &cfg,
    )
    .unwrap_err();
    assert!(
        err.contains("content part missing 'type'") && err.contains("Bedrock"),
        "got: {err}"
    );
}

#[test]
fn test_bedrock_translate_empty_content_yields_empty_text() {
    // openai_content_to_bedrock_blocks: empty parts -> single empty text block.
    let body = json!({
        "model": "anthropic.claude-3-sonnet-20240229-v1:0",
        "messages": [{"role": "user", "content": []}]
    });
    let cfg = json!({ "multimodal_mode": "translate", "aws_region": "us-east-1" });
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "aws_bedrock",
        &body,
        "anthropic.claude-3-sonnet-20240229-v1:0",
        &cfg,
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["text"], "");
}

#[test]
fn test_image_url_value_missing_url_errors() {
    // image_url_value: an image_url part with no `image_url.url` is rejected.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": [{"type": "image_url"}]}]
    });
    let err = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap_err();
    assert!(err.contains("image_url.url"), "got: {err}");
}

// ---------------------------------------------------------------------------
// text_only_with_warning translation for OpenAI-compatible / Cohere providers
// (text_only_openai_body) and translate-mode Cohere passthrough.
// ---------------------------------------------------------------------------

#[test]
fn test_openai_text_only_with_warning_flattens_multimodal_content() {
    // translate_openai_compatible + text_only_openai_body: array content with an
    // image is flattened to a plain text string before dispatch.
    let body = translate_image_request("gpt-4o", "data:image/png;base64,aGVsbG8=");
    let cfg = json!({ "multimodal_mode": "text_only_with_warning" });
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("openai", &body, "gpt-4o", &cfg).unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["messages"][0]["content"], "describe this");
}

#[test]
fn test_openai_translate_mode_preserves_multimodal_content() {
    // translate_openai_compatible (translate/default): array content with an
    // image is passed through unchanged (OpenAI is natively multimodal).
    let body = translate_image_request("gpt-4o", "data:image/png;base64,aGVsbG8=");
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("openai", &body, "gpt-4o", &translate_cfg()).unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image_url");
    assert_eq!(
        content[1]["image_url"]["url"],
        "data:image/png;base64,aGVsbG8="
    );
}

#[test]
fn test_cohere_text_only_with_warning_flattens_multimodal_content() {
    // translate_to_cohere + text_only_openai_body: array content flattened.
    let body = translate_image_request("command-r-plus", "data:image/png;base64,aGVsbG8=");
    let cfg = json!({ "multimodal_mode": "text_only_with_warning" });
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("cohere", &body, "command-r-plus", &cfg).unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["messages"][0]["content"], "describe this");
}

#[test]
fn test_cohere_translate_mode_preserves_multimodal_content() {
    // Cohere is treated as a passthrough provider by the gate, so translate mode
    // leaves the OpenAI-style content array intact.
    let body = translate_image_request("command-r-plus", "data:image/png;base64,aGVsbG8=");
    let (_, _, body_bytes) =
        test_helpers::translate_request_test("cohere", &body, "command-r-plus", &translate_cfg())
            .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image_url");
}

// ---------------------------------------------------------------------------
// Translate-mode policy gate (validate_multimodal_translate_support) edge cases:
// scheme validation, malformed data URLs, instruction roles, role gating, and
// passthrough providers.
// ---------------------------------------------------------------------------

#[test]
fn test_gate_anthropic_rejects_unsupported_url_scheme() {
    // validate_openai_image_url: non-http(s)/data scheme is rejected.
    let body = image_part_request("ftp://example.com/a.png");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("scheme 'ftp'"), "got: {err}");
}

#[test]
fn test_gate_anthropic_rejects_malformed_url() {
    // validate_openai_image_url: a non-data, unparseable URL is rejected.
    let body = image_part_request("not a url");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("not a valid URL"), "got: {err}");
}

#[test]
fn test_gate_anthropic_rejects_data_url_without_base64() {
    // parse_image_data_url: data URL must declare ;base64.
    let body = image_part_request("data:image/png,rawbytes");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("base64 encoded"), "got: {err}");
}

#[test]
fn test_gate_anthropic_rejects_data_url_missing_comma() {
    // parse_image_data_url: data URL must have a comma separator.
    let body = image_part_request("data:image/png;base64");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("comma separator"), "got: {err}");
}

#[test]
fn test_gate_anthropic_rejects_data_url_non_image_media() {
    // parse_image_data_url: media type must be image/*.
    let body = image_part_request("data:application/pdf;base64,QUJD");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("is not an image"), "got: {err}");
}

#[test]
fn test_gate_anthropic_rejects_data_url_empty_data() {
    // parse_image_data_url: empty image payload is rejected.
    let body = image_part_request("data:image/png;base64,");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("empty image data"), "got: {err}");
}

#[test]
fn test_gate_anthropic_rejects_data_url_invalid_base64() {
    // parse_image_data_url: non-base64 payload is rejected at the gate so it is
    // a clean 400, not an opaque provider 502.
    let body = image_part_request("data:image/png;base64,not@@base64");
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("invalid base64"), "got: {err}");
}

#[test]
fn test_gate_strips_parameterized_data_url_media_type() {
    // parse_image_data_url: a parameterized media type (image/png;charset=utf-8)
    // is reduced to the bare type so it passes per-provider media-type checks
    // and providers don't receive a parameterized media_type string.
    let body = image_part_request("data:image/png;charset=utf-8;base64,aGVsbG8=");
    assert!(
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).is_ok(),
        "parameterized image/png data URL should pass the Anthropic gate"
    );
    assert!(
        test_helpers::validate_multimodal_translate_support_test("aws_bedrock", &body).is_ok(),
        "parameterized image/png data URL should pass the Bedrock gate"
    );
}

#[test]
fn test_translate_strips_parameterized_media_type_for_anthropic() {
    // openai_content_to_anthropic: the parameterized media type is normalized to
    // the bare `image/png` in the emitted Anthropic source block.
    let body = translate_image_request(
        "claude-3-sonnet",
        "data:image/png;charset=utf-8;base64,aGVsbG8=",
    );
    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "anthropic",
        &body,
        "claude-3-sonnet",
        &translate_cfg(),
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    let content = parsed["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["source"]["media_type"], "image/png");
}

#[test]
fn test_gate_rejects_non_image_part_for_user_role() {
    // validate_multimodal_translate_support: a non-text, non-image part for a
    // user role has no native translation.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{
            "role": "user",
            "content": [{"type": "input_audio", "input_audio": {"data": "x"}}]
        }]
    });
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(
        err.contains("non-text content part 'input_audio' has no provider-native translation"),
        "got: {err}"
    );
}

#[test]
fn test_gate_rejects_non_text_part_for_unsupported_role() {
    // validate_multimodal_translate_support: only user/assistant roles may carry
    // non-text parts (after the instruction-role check).
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{
            "role": "tool",
            "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,QUJD"}}]
        }]
    });
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("not supported for role 'tool'"), "got: {err}");
}

#[test]
fn test_gate_rejects_text_part_missing_text_field() {
    // validate_multimodal_translate_support: a `text` part with no `text` value.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": [{"type": "text"}]}]
    });
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(
        err.contains("text content part missing text field"),
        "got: {err}"
    );
}

#[test]
fn test_gate_passthrough_providers_accept_anything() {
    // validate_multimodal_translate_support: openai-compatible + cohere return
    // Ok early regardless of content (native passthrough).
    let body = json!({
        "model": "x",
        "messages": [{
            "role": "user",
            "content": [{"type": "input_audio", "input_audio": {"data": "x"}}]
        }]
    });
    for provider in ["openai", "cohere"] {
        assert!(
            test_helpers::validate_multimodal_translate_support_test(provider, &body).is_ok(),
            "{provider} should accept any content at the gate"
        );
    }
}

#[test]
fn test_gate_missing_messages_array_errors() {
    // validate_multimodal_translate_support: a non-passthrough provider with no
    // messages array surfaces an error.
    let body = json!({ "model": "claude-3-sonnet" });
    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("messages"), "got: {err}");
}

#[test]
fn test_gate_skips_message_without_array_content() {
    // validate_multimodal_translate_support: a message whose content is a plain
    // string (not an array) is skipped and passes the gate.
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": "plain string"}]
    });
    assert!(test_helpers::validate_multimodal_translate_support_test("anthropic", &body).is_ok());
}

// ---------------------------------------------------------------------------
// before_proxy: Anthropic translate-mode image success end-to-end, and the
// text_only_with_warning fallback-exhaustion (break) path.
// ---------------------------------------------------------------------------

async fn mount_anthropic_success(server: &MockServer) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-sonnet",
            "content": [{"type": "text", "text": "An image of a cat."}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 6}
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn anthropic_translate_data_url_image_reaches_backend() {
    let server = MockServer::start().await;
    mount_anthropic_success(&server).await;
    let config = json!({
        "providers": [{
            "name": "anthropic",
            "provider_type": "anthropic",
            "api_key": "sk-ant-test",
            "model_patterns": ["claude-*"],
            "base_url": server.uri(),
            "allow_plaintext": true,
            "multimodal_mode": "translate"
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = translate_image_request("claude-3-sonnet", "data:image/png;base64,aGVsbG8=");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 200),
        other => panic!("expected provider response, got {other:?}"),
    }

    let outbound = first_received_json(&server).await;
    let content = outbound["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image");
    assert_eq!(content[1]["source"]["type"], "base64");
    assert_eq!(content[1]["source"]["media_type"], "image/png");
    assert_eq!(content[1]["source"]["data"], "aGVsbG8=");
}

#[tokio::test]
async fn text_only_with_warning_records_multiple_part_types_and_roles() {
    // analyze_multimodal_usage: multiple non-text part types across multiple
    // roles are aggregated (sorted CSV) into the dropped-* metadata.
    let server = MockServer::start().await;
    mount_anthropic_success(&server).await;
    let config = json!({
        "providers": [{
            "name": "anthropic",
            "provider_type": "anthropic",
            "api_key": "sk-ant-test",
            "model_patterns": ["claude-*"],
            "base_url": server.uri(),
            "allow_plaintext": true,
            "multimodal_mode": "text_only_with_warning"
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "prior"},
                    {"type": "input_audio", "input_audio": {"data": "x"}}
                ]
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "now"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
                ]
            }
        ]
    });
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 200),
        other => panic!("expected provider response, got {other:?}"),
    }

    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_dropped_parts"),
        Some(&"2".to_string())
    );
    // BTreeSet ordering -> alphabetical CSV.
    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_dropped_types"),
        Some(&"image_url,input_audio".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_dropped_roles"),
        Some(&"assistant,user".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_multimodal_provider"),
        Some(&"anthropic".to_string())
    );
}

#[tokio::test]
async fn multimodal_reject_with_fallback_disabled_returns_400() {
    // before_proxy: fallback disabled + a single reject-mode provider -> the
    // policy gate breaks out of the loop and the exhaustion branch returns 400.
    let server = MockServer::start().await;
    let config = json!({
        "fallback_enabled": false,
        "providers": [{
            "name": "anthropic-reject",
            "provider_type": "anthropic",
            "api_key": "sk-ant-test",
            "model_patterns": ["claude-*"]
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let body = multimodal_image_request("claude-3-sonnet");
    let mut ctx = post_json_ctx(&body);
    let mut headers = json_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            let message = parsed["error"]["message"].as_str().unwrap();
            assert!(message.contains("reject"), "got: {message}");
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
    assert_no_provider_requests(&server).await;
}

// ---------------------------------------------------------------------------
// MultimodalMode config defaults / round-trip via provider construction.
// ---------------------------------------------------------------------------

#[test]
fn test_multimodal_mode_accepts_all_valid_values() {
    for mode in ["reject", "translate", "text_only_with_warning"] {
        let config = json!({
            "providers": [{
                "name": "p",
                "provider_type": "anthropic",
                "api_key": "sk-ant-test",
                "model_patterns": ["claude-*"],
                "multimodal_mode": mode
            }]
        });
        assert!(
            ai_federation::AiFederation::new(&config, create_test_http_client()).is_ok(),
            "multimodal_mode '{mode}' should be accepted"
        );
    }
}

#[test]
fn test_multimodal_mode_rejects_unknown_value() {
    let config = json!({
        "providers": [{
            "name": "p",
            "provider_type": "anthropic",
            "api_key": "sk-ant-test",
            "model_patterns": ["claude-*"],
            "multimodal_mode": "bogus"
        }]
    });
    let err = ai_federation::AiFederation::new(&config, create_test_http_client())
        .err()
        .unwrap();
    assert!(
        err.contains("unknown multimodal_mode 'bogus'"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn create_test_http_client() -> ferrum_edge::plugins::PluginHttpClient {
    ferrum_edge::plugins::PluginHttpClient::default()
}

fn create_test_http_client_with_backend_allow_ips(
    backend_allow_ips: BackendAllowIps,
) -> ferrum_edge::plugins::PluginHttpClient {
    let backend_allow_ips =
        ferrum_edge::config::BackendEgressPolicy::from_allow_ips(backend_allow_ips);
    let dns_config = DnsConfig {
        backend_allow_ips: backend_allow_ips.clone(),
        ..Default::default()
    };
    ferrum_edge::plugins::PluginHttpClient::new(
        &PoolConfig::default(),
        DnsCache::new(dns_config),
        1000,
        0,
        100,
        false,
        None,
        std::sync::Arc::new(Vec::new()),
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        backend_allow_ips,
        std::sync::Arc::new(Vec::new()),
        0,
    )
}
