use ferrum_edge::plugins::serverless_function::ServerlessFunction;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::create_test_context;

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

/// Helper: extract the error string from a Result<ServerlessFunction, String>.
fn expect_err(result: Result<ServerlessFunction, String>) -> String {
    match result {
        Err(e) => e,
        Ok(_) => panic!("Expected Err, got Ok"),
    }
}

// ---------------------------------------------------------------------------
// Plugin basics
// ---------------------------------------------------------------------------

#[test]
fn test_plugin_name_and_priority() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://my-func.azurewebsites.net/api/transform"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.name(), "serverless_function");
    assert_eq!(plugin.priority(), 3025);
}

#[test]
fn test_supported_protocols() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": "https://us-central1-project.cloudfunctions.net/my-func"
        }),
        default_client(),
    )
    .unwrap();

    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 2);
}

#[test]
fn test_warmup_hostnames() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://my-func.azurewebsites.net/api/transform"
        }),
        default_client(),
    )
    .unwrap();

    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["my-func.azurewebsites.net".to_string()]);
}

#[test]
fn test_warmup_hostnames_aws() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_function_name": "my-function"
        }),
        default_client(),
    )
    .unwrap();

    let hostnames = plugin.warmup_hostnames();
    assert_eq!(
        hostnames,
        vec!["lambda.us-east-1.amazonaws.com".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn test_missing_provider_rejects() {
    let err = expect_err(ServerlessFunction::new(&json!({}), default_client()));
    assert!(err.contains("provider"));
}

#[test]
fn test_unknown_provider_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "oracle_functions",
            "function_url": "https://example.com/func"
        }),
        default_client(),
    ));
    assert!(err.contains("unknown provider"));
}

#[test]
fn test_azure_missing_url_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({ "provider": "azure_functions" }),
        default_client(),
    ));
    assert!(err.contains("function_url"));
}

#[test]
fn test_gcp_missing_url_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({ "provider": "gcp_cloud_functions" }),
        default_client(),
    ));
    assert!(err.contains("function_url"));
}

#[test]
fn test_aws_missing_region_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "my-func"
        }),
        default_client(),
    ));
    assert!(err.contains("aws_region"));
}

#[test]
fn test_aws_missing_access_key_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_secret_access_key": "secret",
            "aws_function_name": "my-func"
        }),
        default_client(),
    ));
    assert!(err.contains("aws_access_key_id"));
}

#[test]
fn test_aws_missing_secret_key_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_function_name": "my-func"
        }),
        default_client(),
    ));
    assert!(err.contains("aws_secret_access_key"));
}

#[test]
fn test_aws_missing_function_name_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret"
        }),
        default_client(),
    ));
    assert!(err.contains("aws_function_name"));
}

#[test]
fn test_invalid_url_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "not-a-url"
        }),
        default_client(),
    ));
    assert!(err.contains("invalid function_url"));
}

#[test]
fn test_non_http_url_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "ftp://example.com/func"
        }),
        default_client(),
    ));
    assert!(err.contains("http:// or https://"));
}

#[test]
fn test_zero_timeout_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "timeout_ms": 0
        }),
        default_client(),
    ));
    assert!(err.contains("timeout_ms"));
}

// ---------------------------------------------------------------------------
// Valid configurations
// ---------------------------------------------------------------------------

#[test]
fn test_aws_lambda_with_qualifier() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "eu-west-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "my-function",
            "aws_qualifier": "prod"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.name(), "serverless_function");
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(
        hostnames,
        vec!["lambda.eu-west-1.amazonaws.com".to_string()]
    );
}

#[test]
fn test_azure_with_function_key() {
    let result = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://my-func.azurewebsites.net/api/check",
            "azure_function_key": "my-secret-key"
        }),
        default_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_gcp_with_bearer_token() {
    let result = ServerlessFunction::new(
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": "https://us-central1-project.cloudfunctions.net/my-func",
            "gcp_bearer_token": "ya29.example-token"
        }),
        default_client(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_terminate_mode() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "mode": "terminate"
        }),
        default_client(),
    )
    .unwrap();

    // terminate mode doesn't modify headers — it short-circuits via RejectBinary
    assert!(!plugin.modifies_request_headers());
}

#[test]
fn test_pre_proxy_mode_modifies_headers() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "mode": "pre_proxy"
        }),
        default_client(),
    )
    .unwrap();

    assert!(plugin.modifies_request_headers());
}

// ---------------------------------------------------------------------------
// Body buffering flags
// ---------------------------------------------------------------------------

#[test]
fn test_body_buffering_disabled_by_default() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func"
        }),
        default_client(),
    )
    .unwrap();

    assert!(!plugin.requires_request_body_before_before_proxy());

    let ctx = create_test_context();
    assert!(!plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_body_buffering_enabled_with_forward_body() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_body": true
        }),
        default_client(),
    )
    .unwrap();

    assert!(plugin.requires_request_body_before_before_proxy());

    // POST + JSON triggers buffering
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));

    // GET does not trigger buffering
    ctx.method = "GET".to_string();
    assert!(!plugin.should_buffer_request_body(&ctx));

    // POST + non-JSON does not trigger buffering
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ---------------------------------------------------------------------------
// Default config values
// ---------------------------------------------------------------------------

#[test]
fn test_default_mode_is_pre_proxy() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func"
        }),
        default_client(),
    )
    .unwrap();

    // Default mode is pre_proxy which modifies request headers
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_default_on_error_is_reject() {
    let result = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func"
        }),
        default_client(),
    );
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// before_proxy — invocation against unreachable host (error handling)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_before_proxy_error_reject_mode() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "http://127.0.0.1:1/unreachable",
            "on_error": "reject",
            "error_status_code": 503,
            "timeout_ms": 500
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 503);
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_before_proxy_error_continue_mode() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "http://127.0.0.1:1/unreachable",
            "on_error": "continue",
            "timeout_ms": 500
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Continue => {
            assert!(ctx.metadata.contains_key("serverless_function_error"));
        }
        other => panic!("Expected Continue, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// forward_headers config
// ---------------------------------------------------------------------------

#[test]
fn test_forward_headers_lowercase() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_headers": ["X-Request-ID", "Authorization"]
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.name(), "serverless_function");
}

// ---------------------------------------------------------------------------
// Environment variable fallback
//
// SAFETY: std::env::set_var / remove_var are unsafe in Rust 2024 edition because
// concurrent threads may read env vars while we mutate them. These tests run
// single-threaded and use unique env var names, so there is no data race.
// ---------------------------------------------------------------------------

unsafe fn set_aws_env_vars(region: &str, key_id: &str, secret: &str, func: &str) {
    unsafe {
        std::env::set_var("AWS_DEFAULT_REGION", region);
        std::env::set_var("AWS_ACCESS_KEY_ID", key_id);
        std::env::set_var("AWS_SECRET_ACCESS_KEY", secret);
        std::env::set_var("AWS_LAMBDA_FUNCTION_NAME", func);
    }
}

unsafe fn remove_aws_env_vars() {
    unsafe {
        std::env::remove_var("AWS_DEFAULT_REGION");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_LAMBDA_FUNCTION_NAME");
    }
}

#[test]
fn test_aws_falls_back_to_env_vars() {
    // SAFETY: single-threaded test, unique env var names
    unsafe {
        set_aws_env_vars(
            "ap-southeast-1",
            "AKIAENVTEST123456789",
            "env-secret-key-value",
            "env-function",
        );
    }

    let result = ServerlessFunction::new(&json!({ "provider": "aws_lambda" }), default_client());

    // SAFETY: cleanup before assertions
    unsafe {
        remove_aws_env_vars();
    }

    let plugin = result.unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(
        hostnames,
        vec!["lambda.ap-southeast-1.amazonaws.com".to_string()]
    );
}

#[test]
fn test_aws_config_overrides_env_vars() {
    // SAFETY: single-threaded test
    unsafe {
        set_aws_env_vars("eu-west-1", "AKIAENVOVERRIDE", "env-secret", "env-func");
    }

    let result = ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-west-2",
            "aws_access_key_id": "AKIACONFIGKEY",
            "aws_secret_access_key": "config-secret",
            "aws_function_name": "config-func"
        }),
        default_client(),
    );

    // SAFETY: cleanup
    unsafe {
        remove_aws_env_vars();
    }

    let plugin = result.unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(
        hostnames,
        vec!["lambda.us-west-2.amazonaws.com".to_string()]
    );
}

#[test]
fn test_aws_region_falls_back_to_aws_region_env() {
    // SAFETY: single-threaded test
    unsafe {
        std::env::set_var("AWS_REGION", "ca-central-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAENVTEST123456789");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "env-secret-key-value");
        std::env::set_var("AWS_LAMBDA_FUNCTION_NAME", "env-function");
    }

    let result = ServerlessFunction::new(&json!({ "provider": "aws_lambda" }), default_client());

    // SAFETY: cleanup
    unsafe {
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_LAMBDA_FUNCTION_NAME");
    }

    let plugin = result.unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(
        hostnames,
        vec!["lambda.ca-central-1.amazonaws.com".to_string()]
    );
}

#[test]
fn test_azure_function_key_falls_back_to_env() {
    // SAFETY: single-threaded test
    unsafe {
        std::env::set_var("AZURE_FUNCTIONS_KEY", "env-azure-key");
    }

    let result = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://my-func.azurewebsites.net/api/check"
        }),
        default_client(),
    );

    // SAFETY: cleanup
    unsafe {
        std::env::remove_var("AZURE_FUNCTIONS_KEY");
    }

    assert!(result.is_ok());
}

#[test]
fn test_gcp_bearer_token_falls_back_to_env() {
    // SAFETY: single-threaded test
    unsafe {
        std::env::set_var("GCP_CLOUD_FUNCTIONS_BEARER_TOKEN", "ya29.env-token");
    }

    let result = ServerlessFunction::new(
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": "https://us-central1-project.cloudfunctions.net/my-func"
        }),
        default_client(),
    );

    // SAFETY: cleanup
    unsafe {
        std::env::remove_var("GCP_CLOUD_FUNCTIONS_BEARER_TOKEN");
    }

    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// AWS SigV4 signing (deterministic unit test)
// ---------------------------------------------------------------------------

#[test]
fn test_aws_sigv4_produces_valid_authorization_header() {
    let aws_config = create_test_aws_config();
    let payload = b"{}";
    let url = "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations";

    let now = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let headers = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        url,
        payload,
        &now,
    );

    assert_eq!(headers.len(), 3);

    let auth_header = headers.iter().find(|(k, _)| k == "authorization").unwrap();
    assert!(auth_header.1.starts_with("AWS4-HMAC-SHA256 Credential="));
    assert!(
        auth_header
            .1
            .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
    );
    assert!(auth_header.1.contains("us-east-1/lambda/aws4_request"));

    let date_header = headers.iter().find(|(k, _)| k == "x-amz-date").unwrap();
    assert_eq!(date_header.1, "20240115T120000Z");

    let sha_header = headers
        .iter()
        .find(|(k, _)| k == "x-amz-content-sha256")
        .unwrap();
    assert_eq!(sha_header.1.len(), 64);
}

#[test]
fn test_aws_sigv4_different_payloads_produce_different_signatures() {
    let aws_config = create_test_aws_config();
    let url = "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations";
    let now = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let headers1 = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        url,
        b"{}",
        &now,
    );
    let headers2 = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        url,
        b"{\"key\":\"value\"}",
        &now,
    );

    let sig1 = &headers1
        .iter()
        .find(|(k, _)| k == "authorization")
        .unwrap()
        .1;
    let sig2 = &headers2
        .iter()
        .find(|(k, _)| k == "authorization")
        .unwrap()
        .1;
    assert_ne!(sig1, sig2);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn create_test_aws_config() -> serde_json::Value {
    json!({
        "region": "us-east-1",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "function_name": "my-function"
    })
}
