use bytes::Bytes;
use ferrum_edge::_test_support::set_response_presentation_policy_digest_for_test;
use ferrum_edge::plugins::ai_federation;
use ferrum_edge::plugins::ai_federation::test_helpers;
use ferrum_edge::plugins::ai_token_metrics::AiTokenMetrics;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use ferrum_edge::{
    config::{BackendAllowIps, PoolConfig},
    dns::{DnsCache, DnsConfig},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

async fn run_federation_final_body(
    plugin: &ai_federation::AiFederation,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
) -> PluginResult {
    let body = ctx
        .metadata
        .get("request_body")
        .cloned()
        .unwrap_or_default();
    let mut backend_header_overlay = HashMap::new();
    plugin
        .dispatch_finalized_request_egress(
            ctx,
            headers,
            body.as_bytes(),
            &mut backend_header_overlay,
        )
        .await
}

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
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.needs_final_request_body_context());
    assert!(plugin.requires_final_request_body_before_backend_dispatch());
    assert!(plugin.dispatches_finalized_request_egress());
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
        json!({"providers": [json!({
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "model_patterns": ["gpt-../unsafe"]
        })]}),
        json!({"providers": [json!({
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "model_mapping": {"gpt-../unsafe": "gpt-4o"}
        })]}),
        json!({"providers": [valid_provider.clone()], "fallback_enabled": "true"}),
        json!({"providers": [valid_provider.clone()], "fallback_on_network_errors": "false"}),
        json!({"providers": [valid_provider.clone()], "fallback_on_status_codes": "429"}),
        json!({"providers": [valid_provider.clone()], "fallback_on_status_codes": [429, "500"]}),
        json!({"providers": [valid_provider.clone()], "fallback_on_status_codes": [99]}),
        json!({"providers": [valid_provider.clone()], "fallback_on_status_codes": [600]}),
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
        json!({"providers": [valid_provider.clone(), valid_provider.clone()]}),
        json!({"providers": [{
            "name": "bedrock",
            "provider_type": "aws_bedrock",
            "aws_region": "us-east-1",
            "aws_access_key_id": "test",
            "aws_secret_access_key": "test",
            "default_model": "unsafe/model"
        }]}),
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
fn strict_config_rejects_unknown_root_provider_and_circuit_fields() {
    let provider = json!({
        "name": "openai",
        "provider_type": "openai",
        "api_key": "sk-test"
    });
    for config in [
        json!({"providers": [provider.clone()], "fallback_on_netwrok_errors": true}),
        json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_paterns": ["gpt-*"]
        }]}),
        json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "circuit_breaker": {"failure_treshold": 3}
        }]}),
    ] {
        let error = ai_federation::AiFederation::new(&config, create_test_http_client())
            .err()
            .expect("misspelled configuration must fail closed");
        assert!(error.contains("unknown field"), "got: {error}");
    }
}

#[test]
fn provider_and_serialization_bounds_match_the_security_contract() {
    let (default_provider, max_provider, max_translated, max_oauth) =
        test_helpers::resource_bounds_for_test();
    assert_eq!(default_provider, 8 * 1024 * 1024);
    assert_eq!(max_provider, 64 * 1024 * 1024);
    assert_eq!(max_translated, 64 * 1024 * 1024);
    assert_eq!(max_oauth, 64 * 1024);

    let provider = json!({
        "name": "openai",
        "provider_type": "openai",
        "api_key": "sk-test"
    });
    let plugin = ai_federation::AiFederation::new(
        &json!({"providers": [provider.clone()]}),
        create_test_http_client(),
    )
    .unwrap();
    assert_eq!(
        test_helpers::provider_response_limit_for_test(&plugin, 0),
        Some(default_provider)
    );

    for (limit, expected) in [
        (0, "must be between 1 and 67108864"),
        (67_108_865, "must be between 1 and 67108864"),
    ] {
        let mut bounded = provider.clone();
        bounded["max_response_body_bytes"] = json!(limit);
        let error = ai_federation::AiFederation::new(
            &json!({"providers": [bounded]}),
            create_test_http_client(),
        )
        .err()
        .expect("out-of-range provider response bound must fail closed");
        assert!(error.contains(expected), "got: {error}");
    }
}

#[test]
fn provider_url_credentials_and_endpoint_component_injection_are_rejected() {
    for (base_url, expected) in [
        (
            "https://user:secret@example.com/v1/chat",
            "must not contain URL userinfo",
        ),
        (
            "https://example.com/v1/chat?api_key=secret",
            "must not contain a query string",
        ),
        (
            "https://example.com/v1/chat#secret",
            "must not contain a fragment",
        ),
        (
            "HTTPS://example.com/v1/chat",
            "must use a lowercase explicit",
        ),
    ] {
        let config = json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "base_url": base_url
        }]});
        let error = ai_federation::AiFederation::new(&config, create_test_http_client())
            .err()
            .expect("credential-bearing URL must be rejected");
        assert!(error.contains(expected), "got: {error}");
    }

    let azure = json!({"providers": [{
        "name": "azure",
        "provider_type": "azure_openai",
        "api_key": "secret",
        "azure_resource": "safe.example.com@evil",
        "azure_deployment": "deploy",
        "base_url": "https://example.com/v1/chat"
    }]});
    let azure_error = ai_federation::AiFederation::new(&azure, create_test_http_client())
        .err()
        .expect("unsafe Azure authority component must be rejected");
    assert!(azure_error.contains("azure_resource"), "got: {azure_error}");
    assert!(
        azure_error.contains("ASCII DNS label"),
        "got: {azure_error}"
    );

    let vertex = json!({"providers": [{
        "name": "vertex",
        "provider_type": "google_vertex",
        "google_project_id": "project/../../evil",
        "google_region": "us-central1",
        "google_service_account_json": r#"{
            "client_email":"svc@example.com",
            "private_key":"not-used-during-validation",
            "token_uri":"https://oauth2.googleapis.com/token"
        }"#,
        "base_url": "https://example.com/v1/chat"
    }]});
    let vertex_error = ai_federation::AiFederation::new(&vertex, create_test_http_client())
        .err()
        .expect("unsafe Vertex path component must be rejected");
    assert!(
        vertex_error.contains("google_project_id"),
        "got: {vertex_error}"
    );
    assert!(
        vertex_error.contains("unsafe in a provider endpoint component"),
        "got: {vertex_error}"
    );
}

#[test]
fn google_oauth_token_authority_is_pinned() {
    let config = json!({"providers": [{
        "name": "vertex",
        "provider_type": "google_vertex",
        "google_project_id": "project",
        "google_region": "us-central1",
        "google_service_account_json": r#"{
            "client_email":"svc@example.com",
            "private_key":"not-used-during-validation",
            "token_uri":"https://evil.example/token"
        }"#
    }]});
    let error = ai_federation::AiFederation::new(&config, create_test_http_client())
        .err()
        .expect("untrusted OAuth authority must be rejected");
    assert!(
        error.contains("oauth2.googleapis.com/token"),
        "got: {error}"
    );
}

#[tokio::test]
async fn vertex_oauth_exchange_stops_at_64_kib_and_is_provider_availability_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(64 * 1024 + 1)))
        .mount(&server)
        .await;

    let service_account = json!({
        "client_email": "vertex-test@example.iam.gserviceaccount.com",
        "private_key": include_str!("../../fixtures/test_rsa_private.pem"),
        "token_uri": "https://oauth2.googleapis.com/token"
    })
    .to_string();
    let (message, circuit_failure) = test_helpers::vertex_oauth_exchange_for_test(
        service_account,
        format!("{}/token", server.uri()),
        create_test_http_client(),
    )
    .await
    .expect_err("oversized OAuth response must fail before JSON parsing");

    assert!(
        message.contains("OAuth2 response exceeded 65536 byte limit"),
        "got: {message}"
    );
    assert!(
        circuit_failure,
        "an unavailable provider-owned OAuth dependency should affect provider availability"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    let service_account = json!({
        "client_email": "vertex-test@example.iam.gserviceaccount.com",
        "private_key": include_str!("../../fixtures/test_rsa_private.pem"),
        "token_uri": "https://oauth2.googleapis.com/token"
    })
    .to_string();
    let (message, circuit_failure) = test_helpers::vertex_oauth_local_signing_failure_for_test(
        service_account,
        create_test_http_client(),
    )
    .await
    .expect_err("forced local JWT key failure must fail before OAuth I/O");
    assert!(
        message.contains("invalid RSA private key"),
        "got: {message}"
    );
    assert!(
        !circuit_failure,
        "local configuration/signing failures must not trip provider availability circuits"
    );
    assert!(
        test_helpers::sigv4_local_failure_is_circuit_neutral_for_test(),
        "SigV4 request-build failures must remain provider-circuit neutral"
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
fn openai_compatible_tool_arguments_are_canonicalized_before_dispatch() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Weather?"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_weather",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\",\"city\":\"London\"}"
                    }
                }]
            }
        ]
    });

    let (_, _, body_bytes) =
        test_helpers::translate_request_test("openai", &body, "gpt-4o", &json!({})).unwrap();
    let translated: Value = serde_json::from_slice(&body_bytes).unwrap();
    let arguments = translated["messages"][1]["tool_calls"][0]["function"]["arguments"]
        .as_str()
        .unwrap();

    assert_eq!(arguments, r#"{"city":"London"}"#);
    assert_eq!(
        serde_json::from_str::<Value>(arguments).unwrap(),
        json!({"city": "London"})
    );
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

fn tool_round_trip_request(stop: Value) -> Value {
    json!({
        "model": "tool-model",
        "messages": [
            {"role": "user", "content": "Weather?"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_weather",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            },
            {"role": "tool", "tool_call_id": "call_weather", "content": "{\"temp\":21}"}
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather",
                "parameters": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }
            }
        }],
        "tool_choice": {
            "type": "function",
            "function": {"name": "get_weather"}
        },
        "stop": stop
    })
}

#[test]
fn native_adapters_preserve_tool_call_state_and_scalar_stop() {
    let request = tool_round_trip_request(json!("DONE"));

    let (_, _, anthropic_bytes) =
        test_helpers::translate_request_test("anthropic", &request, "claude-3", &json!({}))
            .unwrap();
    let anthropic: Value = serde_json::from_slice(&anthropic_bytes).unwrap();
    assert_eq!(anthropic["messages"][1]["content"][0]["type"], "tool_use");
    assert_eq!(anthropic["messages"][1]["content"][0]["id"], "call_weather");
    assert_eq!(
        anthropic["messages"][2]["content"][0]["type"],
        "tool_result"
    );
    assert_eq!(anthropic["stop_sequences"], json!(["DONE"]));
    assert_eq!(anthropic["tools"][0]["name"], "get_weather");

    let (_, _, gemini_bytes) = test_helpers::translate_request_test(
        "google_gemini",
        &request,
        "gemini-2.0-flash",
        &json!({}),
    )
    .unwrap();
    let gemini: Value = serde_json::from_slice(&gemini_bytes).unwrap();
    assert_eq!(
        gemini["contents"][1]["parts"][0]["functionCall"]["name"],
        "get_weather"
    );
    assert_eq!(
        gemini["contents"][2]["parts"][0]["functionResponse"]["name"],
        "get_weather"
    );
    assert_eq!(gemini["generationConfig"]["stopSequences"], json!(["DONE"]));

    let (_, _, vertex_bytes) = test_helpers::translate_request_test(
        "google_vertex",
        &request,
        "gemini-2.0-flash",
        &json!({"google_project_id": "test-project", "google_region": "us-central1"}),
    )
    .unwrap();
    let vertex: Value = serde_json::from_slice(&vertex_bytes).unwrap();
    assert_eq!(
        vertex["contents"][1]["parts"][0]["functionCall"]["name"],
        "get_weather"
    );
    assert_eq!(
        vertex["contents"][2]["parts"][0]["functionResponse"]["name"],
        "get_weather"
    );

    let (_, _, bedrock_bytes) = test_helpers::translate_request_test(
        "aws_bedrock",
        &request,
        "anthropic.claude-3",
        &json!({"aws_region": "us-east-1"}),
    )
    .unwrap();
    let bedrock: Value = serde_json::from_slice(&bedrock_bytes).unwrap();
    assert_eq!(
        bedrock["messages"][1]["content"][0]["toolUse"]["toolUseId"],
        "call_weather"
    );
    assert_eq!(
        bedrock["messages"][2]["content"][0]["toolResult"]["toolUseId"],
        "call_weather"
    );
    assert_eq!(bedrock["inferenceConfig"]["stopSequences"], json!(["DONE"]));

    let (_, _, cohere_bytes) =
        test_helpers::translate_request_test("cohere", &request, "command-r", &json!({})).unwrap();
    let cohere: Value = serde_json::from_slice(&cohere_bytes).unwrap();
    assert_eq!(cohere["messages"][1]["tool_calls"][0]["id"], "call_weather");
    assert_eq!(cohere["stop_sequences"], json!(["DONE"]));
    assert!(cohere.get("stop").is_none());
}

#[test]
fn bedrock_tool_choice_none_omits_native_tool_config() {
    let mut request = tool_round_trip_request(json!(["DONE"]));
    request["tool_choice"] = json!("none");

    let (_, _, body_bytes) = test_helpers::translate_request_test(
        "aws_bedrock",
        &request,
        "anthropic.claude-3",
        &json!({"aws_region": "us-east-1"}),
    )
    .unwrap();
    let translated: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(translated.get("toolConfig").is_none());
}

#[test]
fn native_adapters_group_parallel_tool_results_without_losing_ids() {
    let request = json!({
        "model": "tool-model",
        "messages": [
            {"role": "user", "content": "Look up both"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {
                        "id": "call_a",
                        "type": "function",
                        "function": {"name": "lookup_a", "arguments": "{\"q\":\"a\"}"}
                    },
                    {
                        "id": "call_b",
                        "type": "function",
                        "function": {"name": "lookup_b", "arguments": "{\"q\":\"b\"}"}
                    }
                ]
            },
            {"role": "tool", "tool_call_id": "call_a", "content": "{\"value\":1}"},
            {"role": "tool", "tool_call_id": "call_b", "content": "{\"value\":2}"}
        ],
        "tools": [
            {"type": "function", "function": {"name": "lookup_a", "parameters": {"type": "object"}}},
            {"type": "function", "function": {"name": "lookup_b", "parameters": {"type": "object"}}}
        ],
        "tool_choice": "auto"
    });

    let (_, _, anthropic) =
        test_helpers::translate_request_test("anthropic", &request, "claude-3", &json!({}))
            .unwrap();
    let anthropic: Value = serde_json::from_slice(&anthropic).unwrap();
    assert_eq!(anthropic["messages"].as_array().unwrap().len(), 3);
    assert_eq!(
        anthropic["messages"][2]["content"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        anthropic["messages"][2]["content"][0]["tool_use_id"],
        "call_a"
    );
    assert_eq!(
        anthropic["messages"][2]["content"][1]["tool_use_id"],
        "call_b"
    );

    let (_, _, gemini) =
        test_helpers::translate_request_test("google_gemini", &request, "gemini-2", &json!({}))
            .unwrap();
    let gemini: Value = serde_json::from_slice(&gemini).unwrap();
    assert_eq!(gemini["contents"].as_array().unwrap().len(), 3);
    assert_eq!(gemini["contents"][2]["parts"].as_array().unwrap().len(), 2);
    assert_eq!(
        gemini["contents"][2]["parts"][0]["functionResponse"]["name"],
        "lookup_a"
    );
    assert_eq!(
        gemini["contents"][2]["parts"][1]["functionResponse"]["name"],
        "lookup_b"
    );

    let (_, _, bedrock) = test_helpers::translate_request_test(
        "aws_bedrock",
        &request,
        "anthropic.claude-3",
        &json!({"aws_region": "us-east-1"}),
    )
    .unwrap();
    let bedrock: Value = serde_json::from_slice(&bedrock).unwrap();
    assert_eq!(bedrock["messages"].as_array().unwrap().len(), 3);
    assert_eq!(
        bedrock["messages"][2]["content"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        bedrock["messages"][2]["content"][0]["toolResult"]["toolUseId"],
        "call_a"
    );
    assert_eq!(
        bedrock["messages"][2]["content"][1]["toolResult"]["toolUseId"],
        "call_b"
    );
}

#[test]
fn malformed_stop_and_tool_shapes_fail_explicitly() {
    let providers = [
        ("anthropic", json!({})),
        ("google_gemini", json!({})),
        ("google_vertex", json!({})),
        ("aws_bedrock", json!({"aws_region": "us-east-1"})),
        ("cohere", json!({})),
    ];
    for (provider, config) in providers {
        for stop in [
            json!(42),
            json!(["a", "b", "c", "d", "e"]),
            json!(["ok", 3]),
            json!(""),
        ] {
            let request = tool_round_trip_request(stop);
            let error = test_helpers::translate_request_test(provider, &request, "model", &config)
                .unwrap_err();
            assert!(
                error.contains("'stop'") || error.contains("stop sequence"),
                "{provider} rejected through an unexpected path: {error}"
            );
        }
    }

    let mut malformed = tool_round_trip_request(Value::Null);
    malformed["messages"][1]["tool_calls"][0]["function"]["arguments"] = json!("not-json");
    let error =
        test_helpers::translate_request_test("google_gemini", &malformed, "gemini", &json!({}))
            .unwrap_err();
    assert!(
        error.contains("tool_calls[0]") && error.contains("arguments are not valid JSON"),
        "malformed tool arguments rejected through an unexpected path: {error}"
    );
}

#[test]
fn openai_scalar_stop_stays_scalar_while_array_only_providers_wrap_it() {
    let request = tool_round_trip_request(json!("DONE"));

    for (provider, config) in [
        ("openai", json!({})),
        (
            "azure_openai",
            json!({
                "azure_resource": "resource",
                "azure_deployment": "deployment"
            }),
        ),
    ] {
        let (_, _, body) =
            test_helpers::translate_request_test(provider, &request, "model", &config).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["stop"], json!("DONE"), "{provider}");
    }

    for (provider, config, pointer) in [
        ("anthropic", json!({}), "/stop_sequences"),
        (
            "google_gemini",
            json!({}),
            "/generationConfig/stopSequences",
        ),
        (
            "google_vertex",
            json!({}),
            "/generationConfig/stopSequences",
        ),
        (
            "aws_bedrock",
            json!({"aws_region": "us-east-1"}),
            "/inferenceConfig/stopSequences",
        ),
        ("cohere", json!({}), "/stop_sequences"),
    ] {
        let (_, _, body) =
            test_helpers::translate_request_test(provider, &request, "model", &config).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.pointer(pointer), Some(&json!(["DONE"])), "{provider}");
    }
}

#[test]
fn native_stop_fields_preserve_arrays_and_omit_null_or_absent_values() {
    let providers = [
        ("anthropic", json!({}), "/stop_sequences"),
        (
            "google_gemini",
            json!({}),
            "/generationConfig/stopSequences",
        ),
        (
            "google_vertex",
            json!({}),
            "/generationConfig/stopSequences",
        ),
        (
            "aws_bedrock",
            json!({"aws_region": "us-east-1"}),
            "/inferenceConfig/stopSequences",
        ),
        ("cohere", json!({}), "/stop_sequences"),
    ];

    for (provider, config, pointer) in providers {
        let request = tool_round_trip_request(json!(["ONE", "TWO"]));
        let (_, _, body) =
            test_helpers::translate_request_test(provider, &request, "model", &config).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.pointer(pointer), Some(&json!(["ONE", "TWO"])));

        for mut request in [
            tool_round_trip_request(Value::Null),
            tool_round_trip_request(json!("unused")),
        ] {
            if request["stop"].as_str() == Some("unused") {
                request.as_object_mut().unwrap().remove("stop");
            }
            let (_, _, body) =
                test_helpers::translate_request_test(provider, &request, "model", &config).unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert!(body.pointer(pointer).is_none(), "{provider}: {body}");
        }
    }
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
fn openai_filtered_content_and_generated_tool_arguments_are_preserved() {
    let resp = json!({
        "id": "chatcmpl-filter-tools",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": null},
                "finish_reason": "content_filter"
            },
            {
                "index": 1,
                "message": {"role": "assistant"},
                "finish_reason": "content_filter"
            },
            {
                "index": 2,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_partial",
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "arguments": "{\"partial\":"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            },
            {
                "index": 3,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "refusal": "I cannot help with that request."
                },
                "finish_reason": "stop"
            }
        ]
    });
    let body = serde_json::to_vec(&resp).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("openai", 200, &body, "gpt-4o").unwrap();

    assert_eq!(normalized["choices"][0]["finish_reason"], "content_filter");
    assert!(normalized["choices"][0]["message"]["content"].is_null());
    assert_eq!(normalized["choices"][1]["finish_reason"], "content_filter");
    assert!(normalized["choices"][1]["message"].get("content").is_none());
    assert_eq!(
        normalized["choices"][2]["message"]["tool_calls"][0]["function"]["arguments"],
        "{\"partial\":"
    );
    assert_eq!(
        normalized["choices"][3]["message"]["refusal"],
        "I cannot help with that request."
    );
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
        "role": "assistant",
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
        "id": "msg_max",
        "type": "message",
        "role": "assistant",
        "model": "claude-3",
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

    let candidate_blocked = json!({
        "candidates": [
            {
                "content": {"role": "model", "parts": []},
                "finishReason": "SAFETY"
            },
            {"finishReason": "IMAGE_SAFETY"}
        ],
        "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 0, "totalTokenCount": 5}
    });
    let body = serde_json::to_vec(&candidate_blocked).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("google_vertex", 200, &body, "gemini-2.0-flash")
            .unwrap();
    assert_eq!(normalized["choices"][0]["finish_reason"], "content_filter");
    assert_eq!(normalized["choices"][1]["finish_reason"], "content_filter");

    let prompt_blocked = json!({
        "promptFeedback": {"blockReason": "SAFETY"},
        "usageMetadata": {"promptTokenCount": 5, "totalTokenCount": 5}
    });
    let body = serde_json::to_vec(&prompt_blocked).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("google_gemini", 200, &body, "gemini-2.0-flash")
            .unwrap();
    assert_eq!(normalized["choices"][0]["finish_reason"], "content_filter");
    assert!(normalized["choices"][0]["message"]["content"].is_null());
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
fn native_normalizers_preserve_all_supported_blocks_candidates_and_tool_calls() {
    let anthropic = json!({
        "id": "msg_tools",
        "type": "message",
        "role": "assistant",
        "model": "claude-3",
        "content": [
            {"type": "text", "text": "first"},
            {"type": "text", "text": " second"},
            {"type": "tool_use", "id": "call_1", "name": "lookup", "input": {"q": "one"}},
            {"type": "tool_use", "id": "call_2", "name": "lookup", "input": {"q": "two"}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 4, "output_tokens": 5}
    });
    let anthropic_body = serde_json::to_vec(&anthropic).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("anthropic", 200, &anthropic_body, "claude-3")
            .unwrap();
    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "first second"
    );
    assert_eq!(
        normalized["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(normalized["choices"][0]["finish_reason"], "tool_calls");

    let gemini = json!({
        "responseId": "gemini-multi",
        "modelVersion": "gemini-2",
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": "one"}, {"text": " two"}]
                },
                "finishReason": "STOP"
            },
            {
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "tool"},
                        {"functionCall": {"name": "lookup", "args": {"q": "x"}}}
                    ]
                },
                "finishReason": "STOP"
            }
        ]
    });
    let gemini_body = serde_json::to_vec(&gemini).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("google_gemini", 200, &gemini_body, "gemini-2")
            .unwrap();
    assert_eq!(normalized["choices"].as_array().unwrap().len(), 2);
    assert_eq!(normalized["choices"][0]["message"]["content"], "one two");
    assert_eq!(
        normalized["choices"][1]["message"]["tool_calls"][0]["function"]["name"],
        "lookup"
    );

    let (vertex_normalized, _, _, _) =
        test_helpers::normalize_response_test("google_vertex", 200, &gemini_body, "gemini-2")
            .unwrap();
    assert_eq!(vertex_normalized["choices"].as_array().unwrap().len(), 2);
    assert_eq!(
        vertex_normalized["choices"][0]["message"]["content"],
        "one two"
    );
    assert_eq!(
        vertex_normalized["choices"][1]["message"]["tool_calls"][0]["function"]["name"],
        "lookup"
    );

    let bedrock = json!({
        "output": {"message": {"role": "assistant", "content": [
            {"text": "first"},
            {"text": " second"},
            {"toolUse": {"toolUseId": "call_b", "name": "lookup", "input": {"q": "x"}}}
        ]}},
        "stopReason": "tool_use"
    });
    let bedrock_body = serde_json::to_vec(&bedrock).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("aws_bedrock", 200, &bedrock_body, "bedrock-model")
            .unwrap();
    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "first second"
    );
    assert_eq!(
        normalized["choices"][0]["message"]["tool_calls"][0]["id"],
        "call_b"
    );

    let cohere = json!({
        "id": "cohere-tools",
        "model": "command-r",
        "finish_reason": "TOOL_CALL",
        "message": {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "first"},
                {"type": "text", "text": " second"}
            ],
            "tool_calls": [
                {
                    "id": "call_c1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"q\":\"one\"}"}
                },
                {
                    "id": "call_c2",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"q\":\"two\"}"}
                }
            ]
        }
    });
    let cohere_body = serde_json::to_vec(&cohere).unwrap();
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("cohere", 200, &cohere_body, "command-r").unwrap();
    assert_eq!(
        normalized["choices"][0]["message"]["content"],
        "first second"
    );
    assert_eq!(
        normalized["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(normalized["choices"][0]["finish_reason"], "tool_calls");
}

#[test]
fn malformed_provider_success_shapes_are_rejected() {
    for (provider, body) in [
        ("openai", json!({})),
        ("openai", json!({"choices": []})),
        (
            "openai",
            json!({
                "id": "chatcmpl-invalid-refusal",
                "object": "chat.completion",
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": null, "refusal": {}},
                    "finish_reason": "stop"
                }]
            }),
        ),
        (
            "anthropic",
            json!({"type": "message", "role": "assistant", "content": []}),
        ),
        ("google_gemini", json!({"candidates": []})),
        (
            "google_gemini",
            json!({
                "responseId": 42,
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "ok"}]},
                    "finishReason": "STOP"
                }]
            }),
        ),
        ("aws_bedrock", json!({"output": {}})),
        (
            "cohere",
            json!({"id": "x", "message": {"role": "assistant", "content": []}}),
        ),
        (
            "anthropic",
            json!({
                "type": "message",
                "role": "assistant",
                "id": "msg-empty",
                "model": "claude-test",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": ""}]
            }),
        ),
        (
            "google_gemini",
            json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": ""}]},
                    "finishReason": "STOP"
                }]
            }),
        ),
        (
            "aws_bedrock",
            json!({
                "output": {
                    "message": {"role": "assistant", "content": [{"text": ""}]}
                },
                "stopReason": "end_turn"
            }),
        ),
        (
            "cohere",
            json!({
                "id": "cohere-empty",
                "finish_reason": "COMPLETE",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": ""}]
                }
            }),
        ),
    ] {
        let body = serde_json::to_vec(&body).unwrap();
        assert!(
            test_helpers::normalize_response_test(provider, 200, &body, "model").is_err(),
            "{provider} malformed 2xx must not normalize to empty success"
        );
    }
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

#[test]
fn test_normalize_error_body_is_not_reflected() {
    let body = br#"secret provider diagnostic and credential-like detail"#;
    let (normalized, _, _, _) =
        test_helpers::normalize_response_test("openai", 500, body, "gpt-4o").unwrap();

    let message = normalized["error"]["message"].as_str().unwrap();
    assert!(!message.contains("secret provider diagnostic"));
    assert!(message.contains("500"));
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
    assert!(
        err.contains("must use a lowercase explicit https:// or http:// scheme"),
        "got: {err}"
    );
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
    // Stand in for the protocol entry path's plugin-cache presentation digest
    // so dedup can retain a finalized representation under a provable policy.
    set_response_presentation_policy_digest_for_test(&mut ctx, Some([0x5a; 32]));
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.request_body_bytes = Some(Bytes::from(body.clone()));
    ctx.metadata.insert("request_body".to_string(), body);
    ctx
}

fn post_json_ctx_without_body() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat".to_string(),
    );
    set_response_presentation_policy_digest_for_test(&mut ctx, Some([0x5a; 32]));
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["type"], "invalid_request_error");
            assert_eq!(parsed["error"]["code"], "provider_translation_failed");
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
async fn completed_federation_call_publishes_non_replayable_dedup_tombstone() {
    let server = MockServer::start().await;
    mount_openai_success(&server).await;
    let federation_config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            "base_url": server.uri(),
            "allow_plaintext": true
        }]
    });
    let federation =
        ai_federation::AiFederation::new(&federation_config, create_test_http_client()).unwrap();
    let dedup = RequestDeduplication::new(
        &json!({
            "applicable_methods": ["POST"],
            "enforce_required": true
        }),
        create_test_http_client(),
    )
    .unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut headers = json_headers();
    headers.insert(
        "idempotency-key".to_string(),
        "federated-call-1".to_string(),
    );
    let mut first_ctx = post_json_ctx(&request);

    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (status, response_headers, response_body) =
        match run_federation_final_body(&federation, &mut first_ctx, &headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected provider response, got {other:?}"),
        };
    assert_eq!(status, 200);

    // Mirror the core synthetic-response lifecycle: the early final-body pass
    // retains ownership, then the observe-only committed hook publishes a safe
    // completed tombstone after every response decision is final.
    first_ctx.metadata.insert(
        "ferrum:synthetic_short_circuit".to_string(),
        "true".to_string(),
    );
    assert!(matches!(
        dedup
            .on_final_response_body(
                &mut first_ctx,
                status,
                &response_headers,
                response_body.as_ref(),
            )
            .await,
        PluginResult::Continue
    ));
    first_ctx.metadata.remove("ferrum:synthetic_short_circuit");
    dedup
        .on_response_committed(
            &mut first_ctx,
            status,
            &response_headers,
            response_body.as_ref(),
        )
        .await;

    let mut retry_ctx = post_json_ctx(&request);
    let retry = dedup.before_proxy(&mut retry_ctx, &mut headers).await;
    match retry {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 409);
            assert!(String::from_utf8_lossy(&body).contains("cannot be replayed safely"));
        }
        other => panic!("expected completed-operation tombstone, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn prewire_concurrency_rejection_releases_dedup_inflight_marker() {
    let server = MockServer::start().await;
    let federation_config = json!({
        "max_concurrent_requests": 1,
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            "base_url": server.uri(),
            "allow_plaintext": true
        }]
    });
    let federation =
        ai_federation::AiFederation::new(&federation_config, create_test_http_client()).unwrap();
    let dedup = RequestDeduplication::new(
        &json!({
            "applicable_methods": ["POST"],
            "enforce_required": true
        }),
        create_test_http_client(),
    )
    .unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut headers = json_headers();
    headers.insert(
        "idempotency-key".to_string(),
        "federation-concurrency-1".to_string(),
    );
    let mut first_ctx = post_json_ctx(&request);

    assert!(matches!(
        dedup.before_proxy(&mut first_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    test_helpers::close_request_slots_for_test(&federation);
    let (status, response_headers, response_body) =
        match run_federation_final_body(&federation, &mut first_ctx, &headers).await {
            PluginResult::RejectBinary {
                status_code,
                headers,
                body,
            } => (status_code, headers, body),
            other => panic!("expected concurrency rejection, got {other:?}"),
        };
    assert_eq!(status, 503);
    assert_eq!(
        first_ctx
            .metadata
            .get("ferrum:release_dedup_inflight_on_commit"),
        Some(&"true".to_string())
    );
    assert!(
        !first_ctx
            .metadata
            .contains_key("ferrum:external_operation_completed")
    );

    // Non-2xx synthetic responses skip the response-body hook. The committed
    // hook must still release the pre-I/O ownership marker.
    dedup
        .on_response_committed(
            &mut first_ctx,
            status,
            &response_headers,
            response_body.as_ref(),
        )
        .await;

    let mut retry_ctx = post_json_ctx(&request);
    assert!(matches!(
        dedup.before_proxy(&mut retry_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

fn two_provider_config(primary: &MockServer, secondary: &MockServer) -> Value {
    json!({
        "providers": [
            {
                "name": "primary",
                "provider_type": "openai",
                "api_key": "sk-primary",
                "priority": 1,
                "model_patterns": ["gpt-*"],
                "base_url": primary.uri(),
                "allow_plaintext": true
            },
            {
                "name": "secondary",
                "provider_type": "openai",
                "api_key": "sk-secondary",
                "priority": 2,
                "model_patterns": ["gpt-*"],
                "base_url": secondary.uri(),
                "allow_plaintext": true
            }
        ]
    })
}

#[tokio::test]
async fn malformed_success_response_falls_through_to_next_provider() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&primary)
        .await;
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;

    let plugin = ai_federation::AiFederation::new(
        &two_provider_config(&primary, &secondary),
        create_test_http_client(),
    )
    .unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                body["choices"][0]["message"]["content"],
                "Served by the fallback provider."
            );
        }
        other => panic!("expected normalized fallback response, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata.get("ai_federation_provider"),
        Some(&"secondary".to_string())
    );
}

#[tokio::test]
async fn malformed_success_records_original_provider_status_before_normalization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let config = json!({
        "fallback_enabled": false,
        "providers": [{
            "name": "primary",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            "base_url": server.uri(),
            "allow_plaintext": true
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);

    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 502,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("ai_federation_provider"),
        Some(&"primary".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_status"),
        Some(&"200".to_string())
    );
}

#[tokio::test]
async fn normalized_size_failure_preserves_original_provider_status() {
    let server = MockServer::start().await;
    let native = json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{
                    "functionCall": {
                        "name": "lookup",
                        "args": {"quoted": "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""}
                    }
                }]
            },
            "finishReason": "STOP"
        }]
    });
    let native_bytes = serde_json::to_vec(&native).unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(native_bytes.clone()))
        .mount(&server)
        .await;
    let config = json!({
        "fallback_enabled": false,
        "providers": [{
            "name": "gemini",
            "provider_type": "google_gemini",
            "api_key": "gemini-test",
            "model_patterns": ["gemini-*"],
            "base_url": server.uri(),
            "allow_plaintext": true,
            "max_response_body_bytes": native_bytes.len()
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gemini-2",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);

    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "provider_response_too_large");
        }
        other => panic!("expected normalized-size rejection, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata.get("ai_federation_provider"),
        Some(&"gemini".to_string())
    );
    assert_eq!(
        ctx.metadata.get("ai_federation_status"),
        Some(&"200".to_string())
    );
}

#[tokio::test]
async fn invalid_json_sse_and_native_schema_protocol_failures_use_fallback() {
    for (provider_type, malformed_body) in [
        ("openai", "not-json"),
        (
            "openai",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n",
        ),
        ("anthropic", "{}"),
    ] {
        let primary = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(malformed_body))
            .mount(&primary)
            .await;
        let secondary = MockServer::start().await;
        mount_openai_success(&secondary).await;
        let config = json!({"providers": [
            {
                "name": "primary",
                "provider_type": provider_type,
                "api_key": "sk-primary",
                "priority": 1,
                "model_patterns": ["gpt-*"],
                "base_url": primary.uri(),
                "allow_plaintext": true
            },
            {
                "name": "secondary",
                "provider_type": "openai",
                "api_key": "sk-secondary",
                "priority": 2,
                "model_patterns": ["gpt-*"],
                "base_url": secondary.uri(),
                "allow_plaintext": true
            }
        ]});
        let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
        let request = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let mut ctx = post_json_ctx(&request);
        let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
        assert!(
            matches!(
                result,
                PluginResult::RejectBinary {
                    status_code: 200,
                    ..
                }
            ),
            "{provider_type} malformed protocol response should use fallback"
        );
        assert_eq!(primary.received_requests().await.unwrap().len(), 1);
        assert_eq!(secondary.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn proven_pre_wire_connection_failure_uses_network_fallback() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;
    let config = replay_safety_config(&primary_url, &secondary, false);
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
    assert_eq!(secondary.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn provider_redirect_status_and_safe_headers_are_preserved_without_following() {
    let server = MockServer::start().await;
    let location = format!("{}/credential-target", server.uri());
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", location.as_str())
                .insert_header("retry-after", "30")
                .insert_header("x-request-id", "req-safe")
                .insert_header("set-cookie", "secret=session")
                .insert_header("x-evil", "must-not-cross")
                .set_body_json(json!({"redirect": true})),
        )
        .mount(&server)
        .await;
    let config = json!({"providers": [{
        "name": "primary",
        "provider_type": "openai",
        "api_key": "sk-test",
        "model_patterns": ["gpt-*"],
        "base_url": server.uri(),
        "allow_plaintext": true
    }]});
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 302);
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("30"));
            assert_eq!(
                headers.get("x-request-id").map(String::as_str),
                Some("req-safe")
            );
            assert!(!headers.contains_key("location"));
            assert!(!headers.contains_key("set-cookie"));
            assert!(!headers.contains_key("x-evil"));
        }
        other => panic!("expected preserved redirect response, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn successful_provider_status_is_preserved_after_normalization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "chatcmpl-created",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "created"},
                "finish_reason": "stop"
            }]
        })))
        .mount(&server)
        .await;
    let config = json!({"providers": [{
        "name": "primary",
        "provider_type": "openai",
        "api_key": "sk-test",
        "model_patterns": ["gpt-*"],
        "base_url": server.uri(),
        "allow_plaintext": true
    }]});
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 201,
            ..
        }
    ));
}

#[tokio::test]
async fn every_provider_redirect_class_is_preserved_and_never_followed() {
    for (status, body) in [
        (301, "{\"redirect\":true}"),
        (302, "not-json"),
        (307, "{\"redirect\":true}"),
        (308, "not-json"),
    ] {
        let server = MockServer::start().await;
        let location = format!("{}/must-not-be-called", server.uri());
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", location.as_str())
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        let config = json!({"providers": [{
            "name": "primary",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            "base_url": server.uri(),
            "allow_plaintext": true
        }]});
        let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
        let request = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let mut ctx = post_json_ctx(&request);
        let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
        assert!(
            matches!(result, PluginResult::RejectBinary { status_code, .. } if status_code == status),
            "redirect status {status} must be preserved"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn final_and_fallback_exhaustion_responses_preserve_only_safe_headers() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"error": "primary"})))
        .mount(&primary)
        .await;
    let secondary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "45")
                .insert_header("x-ratelimit-remaining-requests", "0")
                .insert_header("openai-request-id", "req-final")
                .insert_header("set-cookie", "provider_secret=value")
                .insert_header("authorization", "Bearer provider-secret")
                .insert_header("x-evil", "must-not-cross")
                .set_body_json(json!({"error": "secondary"})),
        )
        .mount(&secondary)
        .await;
    let config = two_provider_config(&primary, &secondary);
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("45"));
            assert_eq!(
                headers
                    .get("x-ratelimit-remaining-requests")
                    .map(String::as_str),
                Some("0")
            );
            assert_eq!(
                headers.get("openai-request-id").map(String::as_str),
                Some("req-final")
            );
            assert!(!headers.contains_key("set-cookie"));
            assert!(!headers.contains_key("authorization"));
            assert!(!headers.contains_key("x-evil"));
        }
        other => panic!("expected final throttling response, got {other:?}"),
    }
    assert_eq!(primary.received_requests().await.unwrap().len(), 1);
    assert_eq!(secondary.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn provider_response_limit_is_terminal_and_external_io_is_tracked() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(20))
                .insert_header("openai-request-id", "req-oversized")
                .set_body_string("x".repeat(256)),
        )
        .mount(&primary)
        .await;
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;
    let mut config = two_provider_config(&primary, &secondary);
    config["providers"][0]["max_response_body_bytes"] = json!(64);
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => {
            assert_eq!(status_code, 502);
            assert_eq!(
                headers.get("openai-request-id").map(String::as_str),
                Some("req-oversized")
            );
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "provider_response_too_large");
        }
        other => panic!("expected bounded-read rejection, got {other:?}"),
    }
    assert!(
        ctx.plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn open_provider_circuit_skips_unhealthy_primary_on_next_request() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"error": "down"})))
        .mount(&primary)
        .await;
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;
    let mut config = two_provider_config(&primary, &secondary);
    config["providers"][0]["circuit_breaker"] = json!({
        "failure_threshold": 1,
        "cooldown_seconds": 60,
        "success_threshold": 1
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    for attempt in 0..2 {
        let mut ctx = post_json_ctx(&request);
        let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
        assert!(matches!(
            result,
            PluginResult::RejectBinary {
                status_code: 200,
                ..
            }
        ));
        if attempt == 1 {
            assert_eq!(
                ctx.metadata.get("ai_federation_circuit_open_skips"),
                Some(&"1".to_string())
            );
            assert_eq!(
                ctx.metadata.get("ai_federation_circuit_last_provider"),
                Some(&"primary".to_string())
            );
            assert_eq!(
                ctx.metadata.get("ai_federation_circuit_last_state"),
                Some(&"open".to_string())
            );
        }
    }
    assert_eq!(primary.received_requests().await.unwrap().len(), 1);
    assert_eq!(secondary.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn open_primary_circuit_fails_fast_when_fallback_is_disabled() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"error": "down"})))
        .mount(&primary)
        .await;
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;
    let mut config = two_provider_config(&primary, &secondary);
    config["fallback_enabled"] = json!(false);
    config["providers"][0]["circuit_breaker"] = json!({
        "failure_threshold": 1,
        "cooldown_seconds": 60,
        "success_threshold": 1
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    let mut first_ctx = post_json_ctx(&request);
    let first = run_federation_final_body(&plugin, &mut first_ctx, &json_headers()).await;
    assert!(matches!(
        first,
        PluginResult::RejectBinary {
            status_code: 503,
            ..
        }
    ));

    let mut second_ctx = post_json_ctx(&request);
    let second = run_federation_final_body(&plugin, &mut second_ctx, &json_headers()).await;
    match second {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "provider_circuit_open");
        }
        other => panic!("expected disabled-fallback circuit rejection, got {other:?}"),
    }
    assert_eq!(primary.received_requests().await.unwrap().len(), 1);
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

#[test]
fn provider_circuit_threshold_cooldown_and_half_open_recovery_are_deterministic() {
    assert_eq!(
        test_helpers::circuit_transition_sequence_for_test(),
        vec!["closed", "closed", "open", "half_open_probe", "closed"]
    );
}

#[test]
fn provider_circuit_cooldown_uses_the_process_monotonic_clock() {
    let src = include_str!("../../../src/plugins/ai_federation.rs");
    let circuit = src
        .split("struct ProviderCircuit {")
        .nth(1)
        .expect("provider circuit implementation")
        .split("fn add_external_io_elapsed(")
        .next()
        .expect("bounded provider circuit implementation");
    assert!(circuit.contains("open_until_monotonic_ms"));
    assert!(circuit.contains("crate::socket_opts::monotonic_now_ms()"));
    assert!(circuit.contains("saturating_add(1)"));
    assert!(!circuit.contains("SystemTime"));
    assert!(!circuit.contains("UNIX_EPOCH"));
}

#[test]
fn cancelled_half_open_provider_attempt_releases_probe_slot() {
    assert!(test_helpers::cancelled_half_open_probe_is_released_for_test());
}

#[tokio::test]
async fn cancelled_half_open_dispatch_releases_the_real_provider_probe() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let responder_calls = Arc::clone(&calls);
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            if responder_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).set_body_json(json!({"error": "open circuit"}))
            } else {
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(500))
                    .set_body_json(json!({
                        "id": "chatcmpl-recovered",
                        "object": "chat.completion",
                        "model": "gpt-4o",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "recovered"},
                            "finish_reason": "stop"
                        }]
                    }))
            }
        })
        .mount(&server)
        .await;

    let config = json!({"providers": [{
        "name": "primary",
        "provider_type": "openai",
        "api_key": "sk-test",
        "model_patterns": ["gpt-*"],
        "base_url": server.uri(),
        "allow_plaintext": true,
        "circuit_breaker": {
            "failure_threshold": 1,
            "cooldown_seconds": 1,
            "success_threshold": 1
        }
    }]});
    let plugin =
        Arc::new(ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap());
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    let mut first_ctx = post_json_ctx(&request);
    let first = run_federation_final_body(&plugin, &mut first_ctx, &json_headers()).await;
    assert!(matches!(
        first,
        PluginResult::RejectBinary {
            status_code: 503,
            ..
        }
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let cancelled_plugin = Arc::clone(&plugin);
    let cancelled_request = request.clone();
    let cancelled = tokio::spawn(async move {
        let mut ctx = post_json_ctx(&cancelled_request);
        run_federation_final_body(&cancelled_plugin, &mut ctx, &json_headers()).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if calls.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("half-open provider request must start");
    cancelled.abort();
    let _ = cancelled.await;

    let mut recovery_ctx = post_json_ctx(&request);
    let recovery = run_federation_final_body(&plugin, &mut recovery_ctx, &json_headers()).await;
    assert!(matches!(
        recovery,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn completed_half_open_probe_cannot_release_an_active_successor() {
    assert!(
        test_helpers::completed_half_open_probe_does_not_release_successor_for_test(),
        "resolving an earlier probe lease must leave the successor's single half-open slot held"
    );
}

#[tokio::test]
async fn all_open_provider_circuits_fail_fast_and_reload_replaces_state() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"error": "down"})))
        .mount(&primary)
        .await;
    let config = json!({"providers": [{
        "name": "primary",
        "provider_type": "openai",
        "api_key": "sk-test",
        "model_patterns": ["gpt-*"],
        "base_url": primary.uri(),
        "allow_plaintext": true,
        "circuit_breaker": {
            "failure_threshold": 1,
            "cooldown_seconds": 60,
            "success_threshold": 1
        }
    }]});
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();

    let mut first_ctx = post_json_ctx(&request);
    let first = run_federation_final_body(&plugin, &mut first_ctx, &json_headers()).await;
    assert!(matches!(
        first,
        PluginResult::RejectBinary {
            status_code: 503,
            ..
        }
    ));

    let mut second_ctx = post_json_ctx(&request);
    let second = run_federation_final_body(&plugin, &mut second_ctx, &json_headers()).await;
    match second {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "provider_circuit_open");
        }
        other => panic!("expected all-open failure, got {other:?}"),
    }
    assert_eq!(primary.received_requests().await.unwrap().len(), 1);

    let reloaded = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let mut reload_ctx = post_json_ctx(&request);
    let reloaded_result =
        run_federation_final_body(&reloaded, &mut reload_ctx, &json_headers()).await;
    assert!(matches!(
        reloaded_result,
        PluginResult::RejectBinary {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(primary.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn provider_dispatch_uses_authoritative_final_transformed_body() {
    let server = MockServer::start().await;
    mount_openai_success(&server).await;
    let config = json!({"providers": [{
        "name": "openai",
        "provider_type": "openai",
        "api_key": "sk-test",
        "model_patterns": ["gpt-*"],
        "base_url": server.uri(),
        "allow_plaintext": true
    }]});
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let stale = json!({
        "model": "unmatched-stale-model",
        "messages": [{"role": "user", "content": "stale"}]
    });
    let final_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "transformed"}]
    });
    let mut ctx = post_json_ctx(&stale);
    let final_bytes = serde_json::to_vec(&final_body).unwrap();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &final_bytes)
            .await,
        PluginResult::Continue
    ));
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "the ordered final-body hook pass must never perform provider I/O, even if priority_override moves federation ahead of a policy plugin"
    );
    let mut backend_header_overlay = HashMap::new();
    let result = plugin
        .dispatch_finalized_request_egress(
            &mut ctx,
            &json_headers(),
            &final_bytes,
            &mut backend_header_overlay,
        )
        .await;
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
    let outbound = first_received_json(&server).await;
    assert_eq!(outbound["messages"][0]["content"], "transformed");
}

async fn spawn_post_reader_that_closes_without_response() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut chunk = [0_u8; 2048];
        loop {
            let count = stream.read(&mut chunk).await.unwrap_or(0);
            if count == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..count]);
            let Some(header_end) = received.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = std::str::from_utf8(&received[..header_end]).unwrap_or("");
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if received.len() >= header_end + 4 + content_length {
                break;
            }
        }
        // Dropping after the complete POST but before response headers creates
        // an outcome that is deliberately classified as ambiguous.
    });
    (format!("http://{address}"), handle)
}

fn replay_safety_config(primary_url: &str, secondary: &MockServer, allow_ambiguous: bool) -> Value {
    json!({
        "providers": [
            {
                "name": "primary",
                "provider_type": "openai",
                "api_key": "sk-primary",
                "model_patterns": ["gpt-*"],
                "base_url": primary_url,
                "allow_plaintext": true
            },
            {
                "name": "secondary",
                "provider_type": "openai",
                "api_key": "sk-secondary",
                "model_patterns": ["gpt-*"],
                "base_url": secondary.uri(),
                "allow_plaintext": true
            }
        ],
        "fallback_on_ambiguous_errors": allow_ambiguous
    })
}

#[tokio::test]
async fn ambiguous_post_outcome_is_not_replayed_without_explicit_opt_in() {
    let (primary_url, primary) = spawn_post_reader_that_closes_without_response().await;
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;
    let config = replay_safety_config(&primary_url, &secondary, false);
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    primary.await.unwrap();
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "ambiguous_provider_outcome");
        }
        other => panic!("expected ambiguous-outcome failure, got {other:?}"),
    }
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn explicit_ambiguous_replay_opt_in_allows_fallback_provider() {
    let (primary_url, primary) = spawn_post_reader_that_closes_without_response().await;
    let secondary = MockServer::start().await;
    mount_openai_success(&secondary).await;
    let config = replay_safety_config(&primary_url, &secondary, true);
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    primary.await.unwrap();
    assert!(matches!(
        result,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
    assert_eq!(secondary.received_requests().await.unwrap().len(), 1);
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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

    assert!(!ctx.metadata.contains_key("ai_usage_export"));
    let export = ctx
        .authoritative_ai_usage_export()
        .expect("federation usage has typed export provenance");
    assert_eq!(export.provider, "openai");
    assert_eq!(export.prompt_tokens, Some(10));
    assert_eq!(export.completion_tokens, Some(5));
    assert_eq!(export.total_tokens, Some(15));
    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("openai")
    );
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("10")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("5")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("15")
    );

    // The image part was passed through to the openai-compatible provider.
    let outbound = first_received_json(&server).await;
    let content = outbound["messages"][0]["content"].as_array().unwrap();
    assert_eq!(content[1]["type"], "image_url");
}

#[tokio::test]
async fn configured_token_metrics_rates_price_trusted_federation_usage_deterministically() {
    let server = MockServer::start().await;
    mount_openai_success(&server).await;
    let federation = ai_federation::AiFederation::new(
        &json!({"providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            "base_url": server.uri(),
            "allow_plaintext": true
        }]}),
        create_test_http_client(),
    )
    .unwrap();
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = post_json_ctx(&request);
    let result = run_federation_final_body(&federation, &mut ctx, &json_headers()).await;
    let response_body = match result {
        PluginResult::RejectBinary {
            status_code: 200,
            body,
            ..
        } => body,
        other => panic!("expected federated success, got {other:?}"),
    };

    let zeta = AiTokenMetrics::new(&json!({
        "metadata_prefix": "zeta",
        "cost_per_prompt_token": 0.02,
        "cost_per_completion_token": 0.04
    }))
    .unwrap();
    let alpha = AiTokenMetrics::new(&json!({
        "metadata_prefix": "alpha",
        "cost_per_prompt_token": 0.01,
        "cost_per_completion_token": 0.02
    }))
    .unwrap();
    let mismatched = AiTokenMetrics::new(&json!({
        "provider": "anthropic",
        "metadata_prefix": "mismatched",
        "cost_per_prompt_token": 1.0,
        "cost_per_completion_token": 1.0
    }))
    .unwrap();
    ctx.metadata.insert(
        "ferrum:synthetic_short_circuit".to_string(),
        "true".to_string(),
    );
    for metrics in [&zeta, &mismatched, &alpha] {
        metrics
            .on_response_body(&mut ctx, 200, &mut json_headers(), &response_body)
            .await;
    }

    assert_eq!(
        ctx.metadata.get("zeta_estimated_cost").map(String::as_str),
        Some("0.400000")
    );
    assert_eq!(
        ctx.metadata.get("alpha_estimated_cost").map(String::as_str),
        Some("0.200000")
    );
    assert!(!ctx.metadata.contains_key("mismatched_estimated_cost"));
    let export = ctx
        .authoritative_ai_usage_export()
        .expect("federation usage must remain typed and priceable");
    assert_eq!(export.prefix.as_ref(), "alpha");
    assert_eq!(export.provider, "openai");
    assert_eq!(export.prompt_tokens, Some(10));
    assert_eq!(export.completion_tokens, Some(5));
    let cost = export
        .cost
        .expect("configured rates must price federation usage");
    assert_eq!(cost.microunits, 200_000);
    assert_eq!(cost.submicrounits, 0);
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
        let headers = json_headers();

        let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
        assert_streaming_rejected(provider_type, result);
    }
}

#[tokio::test]
async fn matched_request_rejects_non_boolean_stream_shape_before_provider_io() {
    let plugin = streaming_plugin();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": "true"
    });
    let mut ctx = post_json_ctx(&body);
    let result = run_federation_final_body(&plugin, &mut ctx, &json_headers()).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("stream")
            );
        }
        other => panic!("expected invalid stream shape rejection, got {other:?}"),
    }
    assert_eq!(
        ctx.plugin_http_call_ns
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn malformed_content_parts_are_rejected_before_provider_io() {
    let server = MockServer::start().await;
    let config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
            "model_patterns": ["gpt-*"],
            "base_url": server.uri(),
            "allow_plaintext": true
        }]
    });
    let plugin = ai_federation::AiFederation::new(&config, create_test_http_client()).unwrap();

    for content in [
        json!([]),
        json!([123]),
        json!([{}]),
        json!([{"type": "text"}]),
        json!([{"type": "image_url", "image_url": {"url": ""}}]),
        json!([{"type": "input_audio", "input_audio": {"data": "secret"}}]),
    ] {
        let body = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": content}]
        });
        let mut ctx = post_json_ctx(&body);
        match run_federation_final_body(&plugin, &mut ctx, &json_headers()).await {
            PluginResult::RejectBinary {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 400);
                let body: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["error"]["code"], "invalid_request");
            }
            other => panic!("expected malformed content rejection, got {other:?}"),
        }
    }
    assert_no_provider_requests(&server).await;
}

#[tokio::test]
async fn federation_missing_buffered_body_rejects_by_default() {
    let plugin = streaming_plugin();
    let mut ctx = post_json_ctx_without_body();
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
async fn federation_oversized_model_is_rejected_without_echoing_input() {
    let plugin = streaming_plugin();
    let hostile_model = "x".repeat(50_000);
    let body = json!({
        "model": hostile_model,
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut ctx = post_json_ctx(&body);
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(
                body.len() < 1024,
                "invalid-model body must be bounded, got {} bytes",
                body.len()
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["error"]["code"], "invalid_model");
            let msg = parsed["error"]["message"].as_str().unwrap();
            assert!(!msg.contains(&hostile_model));
        }
        other => panic!("expected RejectBinary 400, got {other:?}"),
    }
}

#[tokio::test]
async fn federation_pass_through_requires_explicit_opt_in() {
    let unknown_model_body = json!({
        "model": "unknown-model",
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let mut strict_ctx = post_json_ctx(&unknown_model_body);
    let strict_headers = json_headers();
    let strict_plugin = streaming_plugin();
    let strict_result =
        run_federation_final_body(&strict_plugin, &mut strict_ctx, &strict_headers).await;
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
        let headers = json_headers();
        let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "explicit opt-in pass-through should continue, got {result:?}"
        );
    }

    let mut invalid_json_ctx = post_json_ctx_with_raw_body("{not-json".to_string());
    let invalid_json_headers = json_headers();
    let invalid_json_result =
        run_federation_final_body(&plugin, &mut invalid_json_ctx, &invalid_json_headers).await;
    assert!(
        matches!(invalid_json_result, PluginResult::Continue),
        "explicit opt-in malformed JSON pass-through should continue, got {invalid_json_result:?}"
    );

    let mut missing_body_ctx = post_json_ctx_without_body();
    let missing_body_headers = json_headers();
    let missing_body_result =
        run_federation_final_body(&plugin, &mut missing_body_ctx, &missing_body_headers).await;
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
    let missing_headers = json_headers();
    let missing_result =
        run_federation_final_body(&plugin, &mut missing_ctx, &missing_headers).await;
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
    let unknown_headers = json_headers();
    let unknown_result =
        run_federation_final_body(&plugin, &mut unknown_ctx, &unknown_headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
fn test_multimodal_rejection_details_bound_client_controlled_values() {
    let long_role = format!("tool{}TAIL", "r".repeat(256));
    let long_type = format!("input_audio{}TAIL", "t".repeat(256));
    let body = json!({
        "model": "claude-3-sonnet",
        "messages": [{
            "role": long_role,
            "content": [{"type": long_type, "input_audio": {"data": "x"}}]
        }]
    });

    let err =
        test_helpers::validate_multimodal_translate_support_test("anthropic", &body).unwrap_err();
    assert!(err.contains("<truncated:"), "got: {err}");
    assert!(!err.contains("TAIL"), "got: {err}");

    let (types, roles) = test_helpers::multimodal_usage_csv_for_test(&body);
    assert!(types.contains("<truncated:"), "got: {types}");
    assert!(roles.contains("<truncated:"), "got: {roles}");
    assert!(!types.contains("TAIL"), "got: {types}");
    assert!(!roles.contains("TAIL"), "got: {roles}");
}

#[test]
fn test_gemini_remote_url_rejection_bounds_echoed_url() {
    let long_url = format!("https://example.test/{}TAIL.png", "a".repeat(512));
    let body = json!({
        "model": "gemini-2.0-flash",
        "messages": [{
            "role": "user",
            "content": [{"type": "image_url", "image_url": {"url": long_url}}]
        }]
    });

    let err = test_helpers::validate_multimodal_translate_support_test("google_gemini", &body)
        .unwrap_err();
    assert!(err.contains("<truncated:"), "got: {err}");
    assert!(!err.contains("TAIL.png"), "got: {err}");
    assert!(
        err.len() < 512,
        "error should stay bounded, got {} bytes",
        err.len()
    );
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
    let headers = json_headers();

    let result = run_federation_final_body(&plugin, &mut ctx, &headers).await;
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
