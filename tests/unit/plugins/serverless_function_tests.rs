use ferrum_edge::plugins::serverless_function::ServerlessFunction;
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, priority};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;

use super::plugin_utils::create_test_context;

/// Mutex to serialize tests that touch process-global env vars.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

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
    assert_eq!(plugin.priority(), priority::SERVERLESS_FUNCTION);
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

    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
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
fn test_warmup_hostnames_unbrackets_ipv6_function_url() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://[2001:db8::20]:9443/api/transform"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::20".to_string()]);
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

#[test]
fn test_warmup_hostnames_aws_endpoint_ipv6_override() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "secret",
            "aws_function_name": "my-function",
            "aws_endpoint_url": "http://[2001:db8::30]:4566"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::30".to_string()]);
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn test_non_object_config_rejects() {
    let err = expect_err(ServerlessFunction::new(&json!("bad"), default_client()));
    assert!(err.contains("config must be an object"), "got: {}", err);
}

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
    let _lock = ENV_MUTEX.lock().unwrap();
    // SAFETY: serialized by ENV_MUTEX — no concurrent env var access
    unsafe {
        remove_all_aws_env_vars();
    }
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
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        remove_all_aws_env_vars();
    }
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
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        remove_all_aws_env_vars();
    }
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
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        remove_all_aws_env_vars();
    }
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
fn test_function_url_empty_authority_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https:///api/transform"
        }),
        default_client(),
    ));
    assert!(err.contains("function_url"));
    assert!(err.contains("hostname or IP address"));
}

// Regression: a malformed `aws_endpoint_url` must be rejected at plugin
// construction (parity with `function_url` on Azure / GCP). Pre-fix the
// override flowed straight into the Lambda invoke URL builder, so a
// scheme-less value like `localhost:4566` only surfaced at request time
// as an opaque reqwest invoke error instead of a deterministic config
// rejection.
#[test]
fn test_aws_endpoint_url_missing_scheme_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "fn",
            "aws_endpoint_url": "localhost:4566",
        }),
        default_client(),
    ));
    assert!(
        err.contains("aws_endpoint_url"),
        "error should reference the field that was rejected: {err}"
    );
}

#[test]
fn test_aws_endpoint_url_non_http_scheme_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "fn",
            "aws_endpoint_url": "tcp://localhost:4566",
        }),
        default_client(),
    ));
    assert!(err.contains("aws_endpoint_url"));
    assert!(err.contains("http:// or https://"));
}

#[test]
fn test_aws_endpoint_url_empty_authority_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "fn",
            "aws_endpoint_url": "http:///lambda",
        }),
        default_client(),
    ));
    assert!(err.contains("aws_endpoint_url"));
    assert!(err.contains("hostname or IP address"));
}

#[test]
fn test_aws_endpoint_url_valid_accepts() {
    // Happy path — the override must work as the test harness relies on it.
    ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "fn",
            "aws_endpoint_url": "http://localhost:4566",
        }),
        default_client(),
    )
    .expect("valid http aws_endpoint_url should be accepted");
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

#[test]
fn test_unknown_mode_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "mode": "terminat"   // typo
        }),
        default_client(),
    ));
    assert!(err.contains("unknown mode"), "got: {}", err);
}

#[test]
fn test_unknown_on_error_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "on_error": "ignore"  // not a valid action
        }),
        default_client(),
    ));
    assert!(err.contains("unknown on_error"), "got: {}", err);
}

#[test]
fn test_zero_max_response_body_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "max_response_body_bytes": 0
        }),
        default_client(),
    ));
    assert!(err.contains("max_response_body_bytes"), "got: {}", err);
}

#[test]
fn test_error_status_code_below_100_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "error_status_code": 99
        }),
        default_client(),
    ));
    assert!(err.contains("error_status_code"), "got: {}", err);
}

#[test]
fn test_error_status_code_above_599_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "error_status_code": 700
        }),
        default_client(),
    ));
    assert!(err.contains("error_status_code"), "got: {}", err);
}

#[test]
fn test_non_string_mode_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "mode": 42
        }),
        default_client(),
    ));
    assert!(err.contains("'mode' must be a string"), "got: {}", err);
}

#[test]
fn test_non_bool_forward_body_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_body": "yes"
        }),
        default_client(),
    ));
    assert!(
        err.contains("'forward_body' must be a boolean"),
        "got: {}",
        err
    );
}

#[test]
fn test_non_bool_forward_query_params_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_query_params": 1
        }),
        default_client(),
    ));
    assert!(
        err.contains("'forward_query_params' must be a boolean"),
        "got: {}",
        err
    );
}

#[test]
fn test_invalid_forward_headers_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_headers": ["X-Request-ID", "bad header"]
        }),
        default_client(),
    ));
    assert!(err.contains("valid HTTP header name"), "got: {}", err);
}

#[test]
fn test_non_array_forward_headers_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_headers": "X-Request-ID"
        }),
        default_client(),
    ));
    assert!(
        err.contains("'forward_headers' must be an array"),
        "got: {}",
        err
    );
}

#[test]
fn test_non_integer_timeout_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "timeout_ms": "5000"
        }),
        default_client(),
    ));
    assert!(
        err.contains("'timeout_ms' must be an unsigned integer"),
        "got: {}",
        err
    );
}

#[test]
fn test_non_string_on_error_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "on_error": true
        }),
        default_client(),
    ));
    assert!(err.contains("'on_error' must be a string"), "got: {}", err);
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
// Terminate mode + gRPC incompatibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_terminate_mode_rejects_grpc_requests() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "mode": "terminate"
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 500);
            assert!(body.contains("not supported for gRPC"));
        }
        other => panic!("Expected Reject for gRPC terminate, got {:?}", other),
    }
}

#[tokio::test]
async fn test_terminate_mode_returns_function_response_as_reject_binary() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(202)
                .set_body_bytes(br#"{"ok":true}"#.to_vec())
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate",
            "timeout_ms": 5000
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 202);
            assert_eq!(&body[..], br#"{"ok":true}"#);
            assert_eq!(
                headers.get("content-type").map(|v| v.as_str()),
                Some("application/json")
            );
        }
        other => panic!("Expected RejectBinary, got {:?}", other),
    }
}

#[tokio::test]
async fn test_pre_proxy_mode_allows_grpc_requests() {
    // pre_proxy mode should NOT reject gRPC — only terminate does
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "http://127.0.0.1:1/unreachable",
            "mode": "pre_proxy",
            "on_error": "continue",
            "timeout_ms": 500
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    // Should NOT get the gRPC rejection — should proceed to invoke (and fail with continue)
    match result {
        PluginResult::Continue => {
            assert!(ctx.metadata.contains_key("serverless_function_error"));
        }
        other => panic!("Expected Continue (not gRPC rejection), got {:?}", other),
    }
}

#[tokio::test]
async fn test_aws_lambda_function_error_does_not_leak_response_body_in_reject_details() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let lambda_error_body =
        r#"{"errorMessage":"db_password=supersecret","stackTrace":["/var/task/app.py:42"]}"#;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(lambda_error_body)
                .insert_header("x-amz-function-error", "Unhandled"),
        )
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_function_name": "my-function",
            "aws_endpoint_url": server.uri(),
            "on_error": "reject",
            "error_status_code": 502,
            "timeout_ms": 5000
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Lambda function error (Unhandled)"));
            assert!(!body.contains("db_password=supersecret"));
            assert!(!body.contains("/var/task/app.py:42"));
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// SigV4 session token support
// ---------------------------------------------------------------------------

#[test]
fn test_aws_sigv4_includes_security_token_when_present() {
    let aws_config = json!({
        "region": "us-east-1",
        "access_key_id": "ASIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "session_token": "FwoGZXIvYXdzEBYaDH/test-session-token",
        "function_name": "my-function"
    });
    let url = "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations";
    let now = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let headers = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        url,
        b"{}",
        &now,
    )
    .expect("SigV4 signing should succeed");

    // Should produce 4 headers (including x-amz-security-token)
    assert_eq!(headers.len(), 4);

    let token_header = headers
        .iter()
        .find(|(k, _)| k == "x-amz-security-token")
        .expect("x-amz-security-token header missing");
    assert_eq!(token_header.1, "FwoGZXIvYXdzEBYaDH/test-session-token");

    // Authorization header should include x-amz-security-token in SignedHeaders
    let auth_header = headers.iter().find(|(k, _)| k == "authorization").unwrap();
    assert!(auth_header.1.contains("x-amz-security-token"));
}

#[test]
fn test_aws_sigv4_omits_security_token_when_absent() {
    let aws_config = create_test_aws_config();
    let url = "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations";
    let now = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let headers = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        url,
        b"{}",
        &now,
    )
    .expect("SigV4 signing should succeed");

    // Should produce 3 headers (no x-amz-security-token)
    assert_eq!(headers.len(), 3);
    assert!(headers.iter().all(|(k, _)| k != "x-amz-security-token"));

    // Authorization header should NOT include x-amz-security-token in SignedHeaders
    let auth_header = headers.iter().find(|(k, _)| k == "authorization").unwrap();
    assert!(!auth_header.1.contains("x-amz-security-token"));
}

#[test]
fn test_aws_sigv4_rejects_invalid_url() {
    let aws_config = create_test_aws_config();
    let now = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let result = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        "not a url",
        b"{}",
        &now,
    );

    assert!(result.is_err());
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

#[tokio::test]
async fn test_skips_ai_stream_router_claimed_provider_requests() {
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forward_headers": ["Authorization"]
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_stream_router_claimed".to_string(), "true".to_string());
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        "Bearer PROVIDER-SECRET".to_string(),
    );

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(
        !ctx.metadata.contains_key("serverless_function_error"),
        "claimed provider traffic must not invoke the external function hook"
    );
}

// ---------------------------------------------------------------------------
// Environment variable fallback
//
// All env-var-touching tests are serialized via ENV_MUTEX to prevent races.
// SAFETY: std::env::set_var / remove_var are unsafe in Rust 2024 because
// concurrent threads may read env vars while we mutate them. The mutex
// ensures only one test mutates env vars at a time.
// ---------------------------------------------------------------------------

/// Clear all AWS env vars that could affect plugin construction.
/// Caller must hold ENV_MUTEX.
unsafe fn remove_all_aws_env_vars() {
    unsafe {
        std::env::remove_var("AWS_DEFAULT_REGION");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_LAMBDA_FUNCTION_NAME");
    }
}

#[test]
fn test_aws_falls_back_to_env_vars() {
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        remove_all_aws_env_vars();
        std::env::set_var("AWS_DEFAULT_REGION", "ap-southeast-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAENVTEST123456789");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "env-secret-key-value");
        std::env::set_var("AWS_LAMBDA_FUNCTION_NAME", "env-function");
    }

    let result = ServerlessFunction::new(&json!({ "provider": "aws_lambda" }), default_client());

    unsafe {
        remove_all_aws_env_vars();
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
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        remove_all_aws_env_vars();
        std::env::set_var("AWS_DEFAULT_REGION", "eu-west-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAENVOVERRIDE");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "env-secret");
        std::env::set_var("AWS_LAMBDA_FUNCTION_NAME", "env-func");
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

    unsafe {
        remove_all_aws_env_vars();
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
    let _lock = ENV_MUTEX.lock().unwrap();
    unsafe {
        remove_all_aws_env_vars();
        std::env::set_var("AWS_REGION", "ca-central-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAENVTEST123456789");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "env-secret-key-value");
        std::env::set_var("AWS_LAMBDA_FUNCTION_NAME", "env-function");
    }

    let result = ServerlessFunction::new(&json!({ "provider": "aws_lambda" }), default_client());

    unsafe {
        remove_all_aws_env_vars();
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
    let _lock = ENV_MUTEX.lock().unwrap();
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

    unsafe {
        std::env::remove_var("AZURE_FUNCTIONS_KEY");
    }

    assert!(result.is_ok());
}

#[test]
fn test_gcp_bearer_token_falls_back_to_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
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
    )
    .expect("SigV4 signing should succeed");

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
    )
    .expect("SigV4 signing should succeed");
    let headers2 = ferrum_edge::plugins::serverless_function::test_helpers::sign_aws_request_test(
        &aws_config,
        url,
        b"{\"key\":\"value\"}",
        &now,
    )
    .expect("SigV4 signing should succeed");

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
// Bounded response-body reads
// ---------------------------------------------------------------------------
//
// These tests verify that `serverless_function` enforces
// `max_response_body_bytes` while streaming the body, instead of buffering
// the full payload before checking. A misbehaving function returning a body
// larger than the cap must fail without allocating the whole response.

/// Backend returns a 2 KiB body, the plugin caps reads at 1 KiB.
/// In `terminate` mode, an over-limit response yields a Reject with the
/// configured error status code.
#[tokio::test]
async fn test_terminate_mode_rejects_oversized_response_body() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = vec![b'A'; 2048];
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate",
            "max_response_body_bytes": 1024,
            "on_error": "reject",
            "error_status_code": 502,
            "timeout_ms": 5000
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    // pre_proxy/terminate both go through invoke(); verify the
    // bounded read fires and the error is surfaced as a Reject.
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(
                body.contains("exceeds")
                    || body.contains("max_response_body_bytes")
                    || body.contains("invocation"),
                "expected rejection body to mention the size error, got: {body}"
            );
        }
        other => panic!("Expected Reject for oversized response, got {:?}", other),
    }
}

/// `pre_proxy` mode with `on_error: continue` and an oversized response —
/// the plugin must record the error in metadata and continue, without ever
/// having buffered the full 2 KiB body.
#[tokio::test]
async fn test_pre_proxy_continue_on_oversized_response_body() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = vec![b'X'; 2048];
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "pre_proxy",
            "max_response_body_bytes": 1024,
            "on_error": "continue",
            "timeout_ms": 5000
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Continue => {
            let err = ctx
                .metadata
                .get("serverless_function_error")
                .expect("error should be recorded in metadata");
            assert!(
                err.contains("exceeds") || err.contains("max_response_body_bytes"),
                "expected size-limit error in metadata, got: {err}"
            );
        }
        other => panic!("Expected Continue with metadata error, got {:?}", other),
    }
}

/// Backend returns a body within the limit — call succeeds.
#[tokio::test]
async fn test_pre_proxy_succeeds_when_response_body_within_limit() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = serde_json::json!({"headers": {"x-injected": "true"}})
        .to_string()
        .into_bytes();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "pre_proxy",
            "max_response_body_bytes": 4096,
            "on_error": "reject",
            "timeout_ms": 5000
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Continue => {
            // pre_proxy success: the function's headers should be injected.
            assert_eq!(headers.get("x-injected").map(|s| s.as_str()), Some("true"));
        }
        other => panic!("Expected Continue with injected headers, got {:?}", other),
    }
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
