use bytes::Bytes;
use ferrum_edge::plugins::serverless_function::{ServerlessFunction, redact_serverless_url};
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, priority};
use serde_json::{Value, json};
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
    for config in [Value::Null, json!("bad"), json!([]), json!(42)] {
        let err = expect_err(ServerlessFunction::new(&config, default_client()));
        assert!(err.contains("config must be an object"), "got: {err}");
    }
}

#[test]
fn test_unknown_fields_are_rejected_deterministically() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "forwad_body": true,
            "z_future_field": false
        }),
        default_client(),
    ));
    assert!(err.contains("forwad_body, z_future_field"), "got: {err}");
}

#[test]
fn test_explicit_null_is_rejected_instead_of_defaulted() {
    for field in [
        "provider",
        "function_url",
        "mode",
        "aws_region",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_function_name",
        "aws_session_token",
        "aws_qualifier",
        "aws_endpoint_url",
        "azure_function_key",
        "gcp_bearer_token",
        "forward_body",
        "forward_headers",
        "forward_query_params",
        "timeout_ms",
        "max_response_body_bytes",
        "on_error",
        "error_status_code",
    ] {
        let mut config = json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func"
        });
        config[field] = Value::Null;
        let err = expect_err(ServerlessFunction::new(&config, default_client()));
        assert!(err.contains(field), "field={field}, got: {err}");
        assert!(
            err.contains("must not be null"),
            "field={field}, got: {err}"
        );
    }
}

#[test]
fn test_function_urls_reject_userinfo_without_echoing_credentials() {
    let secret = "url-password-do-not-echo";
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("https://trigger:{secret}@example.com/api/run")
        }),
        default_client(),
    ));
    assert!(err.contains("must not contain URL userinfo"));
    assert!(
        !err.contains(secret),
        "credential leaked in config error: {err}"
    );
}

#[test]
fn test_function_urls_reject_fragments_that_clients_do_not_send() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": "https://example.com/api/run#credential"
        }),
        default_client(),
    ));
    assert!(
        err.contains("must not contain a URL fragment"),
        "got: {err}"
    );
    assert!(
        !err.contains("credential"),
        "fragment leaked in config error: {err}"
    );
}

#[test]
fn test_function_url_diagnostic_form_redacts_path_and_query_credentials() {
    let raw = "https://functions.example/private/signed-secret?code=query-secret";
    let diagnostic = redact_serverless_url(raw);
    assert_eq!(
        diagnostic,
        "https://functions.example/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert!(!diagnostic.contains("signed-secret"));
    assert!(!diagnostic.contains("query-secret"));
}

#[test]
fn test_aws_endpoint_override_rejects_non_origin_components() {
    for (endpoint, expected_error) in [
        ("https://example.com/lambda", "must be an HTTP(S) origin"),
        (
            "https://example.com?token=secret",
            "must be an HTTP(S) origin",
        ),
        (
            "https://example.com#fragment",
            "must not contain a URL fragment",
        ),
    ] {
        let err = expect_err(ServerlessFunction::new(
            &json!({
                "provider": "aws_lambda",
                "aws_region": "us-east-1",
                "aws_access_key_id": "AKIATEST",
                "aws_secret_access_key": "secret",
                "aws_function_name": "fn",
                "aws_endpoint_url": endpoint
            }),
            default_client(),
        ));
        assert!(err.contains(expected_error), "got: {err}");
    }
}

#[test]
fn test_final_error_status_boundaries_are_accepted() {
    for status in [400, 599] {
        ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": "https://example.com/func",
                "error_status_code": status
            }),
            default_client(),
        )
        .unwrap_or_else(|error| panic!("status={status} should be accepted: {error}"));
    }
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
fn test_aws_rejects_invalid_ignored_function_url() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "aws_lambda",
            "function_url": "not-a-url",
            "aws_region": "us-east-1",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret",
            "aws_function_name": "my-func"
        }),
        default_client(),
    ));
    assert!(err.contains("invalid function_url"), "got: {err}");
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
fn test_error_status_code_below_400_rejects() {
    for status in [100, 199, 399] {
        let err = expect_err(ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": "https://example.com/func",
                "error_status_code": status
            }),
            default_client(),
        ));
        assert!(
            err.contains("error_status_code"),
            "status={status}, got: {err}"
        );
    }
}

#[test]
fn test_error_status_code_above_599_rejects() {
    let err = expect_err(ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/func",
            "error_status_code": 600
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

    // Every method and representation is buffered losslessly.
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));

    assert!(plugin.needs_request_body_bytes());
    assert!(!plugin.needs_request_body_text());

    ctx.method = "GET".to_string();
    assert!(plugin.should_buffer_request_body(&ctx));

    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));
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
            assert_eq!(
                ctx.metadata
                    .get("serverless_function.standalone.error_class")
                    .map(String::as_str),
                Some("invocation_failed")
            );
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
async fn test_terminate_rejects_out_of_range_function_status() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(600).set_body_string("non-final"))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate",
            "error_status_code": 502
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();

    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("invalid_function_status"));
            assert!(!body.contains("non-final"));
        }
        other => panic!("out-of-range function status must fail, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("serverless_function.standalone.status")
            .map(String::as_str),
        Some("600")
    );
}

#[tokio::test]
async fn test_pre_proxy_redirect_is_not_approval_and_is_not_followed() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/policy"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/redirect-target", server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/redirect-target"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/policy", server.uri()),
            "mode": "pre_proxy",
            "on_error": "reject",
            "error_status_code": 503
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
            assert_eq!(status_code, 503);
            assert!(body.contains("function_non_success_status"));
            assert!(!body.contains("redirect-target"));
        }
        other => panic!("redirect must use fail-closed policy, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        ctx.metadata
            .get("serverless_function.standalone.status")
            .map(String::as_str),
        Some("302")
    );
}

#[tokio::test]
async fn test_pre_proxy_redirect_continue_records_only_scoped_diagnostics() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/moved"))
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": format!("{}/signed/path?token=query-secret", server.uri()),
            "on_error": "continue"
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("serverless_function.standalone.error_class")
            .map(String::as_str),
        Some("function_non_success_status")
    );
    assert!(ctx.metadata.iter().all(|(key, value)| {
        !key.contains("query-secret")
            && !value.contains("query-secret")
            && !key.contains("signed/path")
            && !value.contains("signed/path")
    }));
}

#[tokio::test]
async fn test_pre_proxy_4xx_and_5xx_use_configured_final_error_status() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for (function_status, expected_status) in [(401, "401"), (503, "503")] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(function_status)
                    .set_body_string("untrusted function error details"),
            )
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": format!("{}/policy", server.uri()),
                "error_status_code": 502
            }),
            default_client(),
        )
        .unwrap();
        let mut ctx = create_test_context();

        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 502);
                assert!(body.contains("function_non_success_status"));
                assert!(!body.contains("untrusted function error details"));
            }
            other => panic!("status={function_status} must fail closed, got {other:?}"),
        }
        assert_eq!(
            ctx.metadata
                .get("serverless_function.standalone.status")
                .map(String::as_str),
            Some(expected_status)
        );
    }
}

#[tokio::test]
async fn test_terminate_forwards_safe_headers_and_preserves_repeated_cookies() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(302)
                .set_body_string("redirect")
                .insert_header("location", "/next")
                .insert_header("retry-after", "30")
                .insert_header("etag", "\"version-1\"")
                .insert_header("connection", "x-function-internal")
                .insert_header("x-function-internal", "must-strip")
                .insert_header("x-amz-request-id", "provider-control")
                .insert_header("x-api-key", "response-secret")
                .append_header("set-cookie", "a=1; Path=/")
                .append_header("set-cookie", "b=2; Path=/"),
        )
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate"
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();

    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 302);
            assert_eq!(&body[..], b"redirect");
            assert_eq!(headers.get("location").map(String::as_str), Some("/next"));
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("30"));
            assert_eq!(
                headers.get("etag").map(String::as_str),
                Some("\"version-1\"")
            );
            assert_eq!(
                headers.get("set-cookie").map(String::as_str),
                Some("a=1; Path=/\nb=2; Path=/")
            );
            for stripped in [
                "connection",
                "content-length",
                "x-function-internal",
                "x-amz-request-id",
                "x-api-key",
            ] {
                assert!(
                    !headers.contains_key(stripped),
                    "header survived: {stripped}"
                );
            }
        }
        other => panic!("expected terminal function response, got {other:?}"),
    }
}

#[tokio::test]
async fn test_terminate_strips_redirects_that_expose_signed_function_destination() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for case in [
        "relative-query",
        "absolute-destination",
        "scheme-relative",
        "decoded-path",
        "copied-path-other-host",
        "descendant-path-other-host",
        "prefixed-path-other-host",
        "nested-double-encoded",
        "nested-depth-budget",
        "nested-over-decode-budget",
        "destination-over-decode-budget",
        "nested-path-encoded",
        "copied-query-other-host",
        "renamed-query-other-host",
        "copied-query-path-other-host",
        "copied-query-path-parameter",
        "copied-query-encoded-path-delimiter",
        "key-only-query-renamed-value",
        "key-only-query-copied-key",
        "key-only-query-path",
        "key-only-query-fragment",
        "query-key-with-value-renamed-value",
        "query-key-with-value-copied-key",
        "query-key-with-value-path",
        "query-key-with-value-fragment",
        "query-key-with-value-nested",
        "query-value-with-key-renamed-value",
        "literal-plus-encoded-candidate",
        "encoded-plus-literal-candidate",
        "fragment-query-scalar",
        "fragment-query-pair-scalar",
        "fragment-path-scalar",
        "fragment-double-encoded",
        "malformed",
        "userinfo",
        "benign-relative",
        "benign-same-origin",
        "benign-external",
        "benign-external-label",
        "benign-path-lookalike",
        "benign-query-value-lookalike",
        "benign-query-path-lookalike",
        "benign-query-path-parameter-lookalike",
        "benign-key-only-query-lookalike",
        "benign-query-key-with-value-lookalike",
        "benign-query-value-with-key-lookalike",
        "benign-plus-space-distinct",
        "benign-fragment-lookalike",
        "benign-fragment-label",
    ] {
        let server = MockServer::start().await;
        let function_url = match case {
            "destination-over-decode-budget" => {
                let mut path = "signed/trigger".to_string();
                for _ in 0..12 {
                    path = url::form_urlencoded::byte_serialize(path.as_bytes()).collect();
                }
                format!("{}/{path}?code=secret%2Fvalue", server.uri())
            }
            "literal-plus-encoded-candidate" => {
                format!("{}/signed%2Ftrigger?code=token+part", server.uri())
            }
            "encoded-plus-literal-candidate" => {
                format!("{}/signed%2Ftrigger?code=token%2Bpart", server.uri())
            }
            "benign-plus-space-distinct" => {
                format!("{}/signed%2Ftrigger?code=token%20part", server.uri())
            }
            "key-only-query-renamed-value"
            | "key-only-query-copied-key"
            | "key-only-query-path"
            | "key-only-query-fragment"
            | "benign-key-only-query-lookalike" => {
                format!("{}/signed%2Ftrigger?SIGNED_TOKEN=", server.uri())
            }
            "query-key-with-value-renamed-value"
            | "query-key-with-value-copied-key"
            | "query-key-with-value-path"
            | "query-key-with-value-fragment"
            | "query-key-with-value-nested"
            | "query-value-with-key-renamed-value"
            | "benign-query-key-with-value-lookalike"
            | "benign-query-value-with-key-lookalike" => {
                format!("{}/signed%2Ftrigger?SIGNED_TOKEN=1", server.uri())
            }
            _ => format!("{}/signed%2Ftrigger?code=secret%2Fvalue", server.uri()),
        };
        let location = match case {
            "relative-query" => "?code=secret%2Fvalue".to_string(),
            "absolute-destination" => function_url.clone(),
            "scheme-relative" => function_url
                .strip_prefix("http:")
                .expect("wiremock URI uses HTTP")
                .to_string(),
            "decoded-path" => {
                format!("{}/signed/trigger?unrelated=1", server.uri())
            }
            "copied-path-other-host" => {
                "https://redirect.example/signed/trigger?unrelated=1".to_string()
            }
            "descendant-path-other-host" => {
                "https://redirect.example/signed/trigger/continue?unrelated=1".to_string()
            }
            "prefixed-path-other-host" => {
                "https://redirect.example/collect/signed/trigger?unrelated=1".to_string()
            }
            "nested-double-encoded" => {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(function_url.as_bytes()).collect();
                let double_encoded: String =
                    url::form_urlencoded::byte_serialize(encoded.as_bytes()).collect();
                format!("https://redirect.example/continue?next={double_encoded}")
            }
            "nested-depth-budget" => {
                let deepest = format!("https://third.example/three?next={function_url}");
                let middle = format!("https://second.example/two?next={deepest}");
                format!("https://redirect.example/one?next={middle}")
            }
            "nested-over-decode-budget" => {
                let mut encoded = function_url.clone();
                for _ in 0..12 {
                    encoded = url::form_urlencoded::byte_serialize(encoded.as_bytes()).collect();
                }
                format!("https://redirect.example/continue?next={encoded}")
            }
            "destination-over-decode-budget" => "/next".to_string(),
            "nested-path-encoded" => {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(function_url.as_bytes()).collect();
                format!("https://redirect.example/{encoded}")
            }
            "copied-query-other-host" => {
                "https://redirect.example/next?code=secret%2Fvalue".to_string()
            }
            "renamed-query-other-host" => {
                "https://redirect.example/next?leak=secret%2Fvalue".to_string()
            }
            "copied-query-path-other-host" => "https://redirect.example/secret/value".to_string(),
            "copied-query-path-parameter" => {
                "https://redirect.example/next;leak=secret/value".to_string()
            }
            "copied-query-encoded-path-delimiter" => {
                "https://redirect.example/next%3Fleak%3Dsecret/value".to_string()
            }
            "key-only-query-renamed-value" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN".to_string()
            }
            "key-only-query-copied-key" => {
                "https://redirect.example/next?SIGNED_TOKEN=other".to_string()
            }
            "key-only-query-path" => {
                "https://redirect.example/next;leak=SIGNED_TOKEN".to_string()
            }
            "key-only-query-fragment" => {
                "https://redirect.example/#leak=SIGNED_TOKEN".to_string()
            }
            "query-key-with-value-renamed-value" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN".to_string()
            }
            "query-key-with-value-copied-key" => {
                "https://redirect.example/next?SIGNED_TOKEN=other".to_string()
            }
            "query-key-with-value-path" => {
                "https://redirect.example/next;leak=SIGNED_TOKEN".to_string()
            }
            "query-key-with-value-fragment" => {
                "https://redirect.example/#leak=SIGNED_TOKEN".to_string()
            }
            "query-key-with-value-nested" => {
                "https://redirect.example/next?next=https%3A%2F%2Fattacker.example%2F%3Fleak%3DSIGNED_TOKEN"
                    .to_string()
            }
            "query-value-with-key-renamed-value" => {
                "https://redirect.example/next?leak=1".to_string()
            }
            "literal-plus-encoded-candidate" => {
                "https://redirect.example/next?leak=token%2Bpart".to_string()
            }
            "encoded-plus-literal-candidate" => {
                "https://redirect.example/next?leak=token+part".to_string()
            }
            "fragment-query-scalar" => "https://redirect.example/#secret/value".to_string(),
            "fragment-query-pair-scalar" => {
                "https://redirect.example/#leak=secret/value".to_string()
            }
            "fragment-path-scalar" => "https://redirect.example/#signed/trigger".to_string(),
            "fragment-double-encoded" => "https://redirect.example/#secret%252Fvalue".to_string(),
            "malformed" => "http://[signed%2Ftrigger?code=secret%2Fvalue".to_string(),
            "userinfo" => "https://user:password@redirect.example/next".to_string(),
            "benign-relative" => "/next".to_string(),
            "benign-same-origin" => format!("{}/safe?label=other", server.uri()),
            "benign-external" => "https://redirect.example/next?label=other".to_string(),
            "benign-external-label" => {
                "https://redirect.example/next?label=signed/trigger".to_string()
            }
            "benign-path-lookalike" => {
                "https://redirect.example/signed/triggered?label=other".to_string()
            }
            "benign-query-value-lookalike" => {
                "https://redirect.example/next?leak=secret%2Fvalue-extra".to_string()
            }
            "benign-query-path-lookalike" => {
                "https://redirect.example/secret/value-extra".to_string()
            }
            "benign-query-path-parameter-lookalike" => {
                "https://redirect.example/next;leak=secret/value-extra".to_string()
            }
            "benign-key-only-query-lookalike" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN_EXTRA".to_string()
            }
            "benign-query-key-with-value-lookalike" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN_EXTRA".to_string()
            }
            "benign-query-value-with-key-lookalike" => {
                "https://redirect.example/next?leak=10".to_string()
            }
            "benign-plus-space-distinct" => {
                "https://redirect.example/next?leak=token+part".to_string()
            }
            "benign-fragment-lookalike" => {
                "https://redirect.example/#secret/value-extra".to_string()
            }
            "benign-fragment-label" => "https://redirect.example/#release-notes".to_string(),
            _ => unreachable!(),
        };
        let should_strip = !case.starts_with("benign-");

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(302)
                    .set_body_string("redirect")
                    .insert_header("location", location.as_str()),
            )
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": function_url,
                "mode": "terminate"
            }),
            default_client(),
        )
        .unwrap();
        let mut ctx = create_test_context();

        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::RejectBinary { headers, .. } => {
                if should_strip {
                    assert!(
                        !headers.contains_key("location"),
                        "credential-bearing Location survived case {case}: {headers:?}"
                    );
                } else {
                    assert_eq!(
                        headers.get("location").map(String::as_str),
                        Some(location.as_str()),
                        "benign Location changed in case {case}"
                    );
                }
            }
            other => panic!("expected terminal redirect for case {case}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_terminate_strips_unsafe_url_headers_for_root_function_destination() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for case in [
        "location-userinfo",
        "content-location-userinfo",
        "refresh-userinfo",
        "link-userinfo",
        "location-malformed",
        "location-malformed-percent",
        "location-invalid-percent-utf8",
        "content-location-malformed-percent",
        "content-location-invalid-percent-utf8",
        "refresh-malformed-percent",
        "refresh-invalid-percent-utf8",
        "link-malformed-percent",
        "link-invalid-percent-utf8",
        "location-percent-budget",
        "link-malformed",
        "link-target-budget",
        "benign-location",
        "benign-link",
    ] {
        let server = MockServer::start().await;
        let (header, value, should_strip) = match case {
            "location-userinfo" => (
                "location",
                "https://user:password@redirect.example/next".to_string(),
                true,
            ),
            "content-location-userinfo" => (
                "content-location",
                "https://user:password@redirect.example/content".to_string(),
                true,
            ),
            "refresh-userinfo" => (
                "refresh",
                "0; url=https://user:password@redirect.example/next".to_string(),
                true,
            ),
            "link-userinfo" => (
                "link",
                "<https://user:password@redirect.example/next>; rel=\"next\"".to_string(),
                true,
            ),
            "location-malformed" => ("location", "http://[invalid".to_string(), true),
            "location-malformed-percent" => ("location", "/next%zz".to_string(), true),
            "location-invalid-percent-utf8" => ("location", "/next%FF".to_string(), true),
            "content-location-malformed-percent" => {
                ("content-location", "/content%zz".to_string(), true)
            }
            "content-location-invalid-percent-utf8" => {
                ("content-location", "/content%FF".to_string(), true)
            }
            "refresh-malformed-percent" => ("refresh", "0; url=/next%zz".to_string(), true),
            "refresh-invalid-percent-utf8" => ("refresh", "0; url=/next%FF".to_string(), true),
            "link-malformed-percent" => ("link", "</next%zz>; rel=\"next\"".to_string(), true),
            "link-invalid-percent-utf8" => ("link", "</next%FF>; rel=\"next\"".to_string(), true),
            "location-percent-budget" => {
                let mut encoded = "https://redirect.example/next".to_string();
                for _ in 0..12 {
                    encoded = url::form_urlencoded::byte_serialize(encoded.as_bytes()).collect();
                }
                ("location", encoded, true)
            }
            "link-malformed" => (
                "link",
                "<https://redirect.example/next; rel=\"next\"".to_string(),
                true,
            ),
            "link-target-budget" => (
                "link",
                (0..33)
                    .map(|index| format!("</safe/{index}>; rel=\"item\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                true,
            ),
            "benign-location" => (
                "location",
                "https://redirect.example/next".to_string(),
                false,
            ),
            "benign-link" => (
                "link",
                "<https://redirect.example/next>; rel=\"next\"".to_string(),
                false,
            ),
            _ => unreachable!(),
        };

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).insert_header(header, value.as_str()))
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": format!("{}/", server.uri()),
                "mode": "terminate"
            }),
            default_client(),
        )
        .unwrap();
        let mut ctx = create_test_context();

        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::RejectBinary { headers, .. } => {
                if should_strip {
                    assert!(
                        !headers.contains_key(header),
                        "unsafe {header} survived root destination case {case}: {headers:?}"
                    );
                } else {
                    assert_eq!(
                        headers.get(header).map(String::as_str),
                        Some(value.as_str()),
                        "benign {header} changed in root destination case {case}"
                    );
                }
            }
            other => panic!("expected terminal response for case {case}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_terminate_strips_destination_exposure_from_url_valued_headers() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for case in [
        "content-location-absolute",
        "content-location-relative",
        "content-location-encoded",
        "content-location-query-key",
        "refresh-absolute",
        "refresh-relative",
        "refresh-encoded",
        "refresh-query-key",
        "refresh-bare-absolute",
        "refresh-bare-relative",
        "refresh-bare-path-segment",
        "refresh-bare-encoded",
        "refresh-malformed-target",
        "link-absolute",
        "link-relative",
        "link-query-key",
        "link-multiple-targets",
        "link-target-budget",
        "link-malformed",
        "benign-content-location",
        "benign-refresh",
        "benign-refresh-bare-target",
        "benign-refresh-delay-only",
        "benign-refresh-non-url-directive",
        "benign-link-multiple-targets",
        "benign-link-label",
        "benign-link-path-lookalike",
    ] {
        let server = MockServer::start().await;
        let function_url = format!("{}/signed%2Ftrigger?code=secret%2Fvalue", server.uri());
        let encoded_function_url: String =
            url::form_urlencoded::byte_serialize(function_url.as_bytes()).collect();
        let (header, value, should_strip) = match case {
            "content-location-absolute" => {
                ("content-location", function_url.clone(), true)
            }
            "content-location-relative" => (
                "content-location",
                "/signed%2Ftrigger?code=secret%2Fvalue".to_string(),
                true,
            ),
            "content-location-encoded" => {
                ("content-location", encoded_function_url.clone(), true)
            }
            "content-location-query-key" => (
                "content-location",
                "https://redirect.example/next?leak=code".to_string(),
                true,
            ),
            "refresh-absolute" => {
                ("refresh", format!("0; URL=\"{function_url}\""), true)
            }
            "refresh-relative" => (
                "refresh",
                "0;url=/signed%2Ftrigger?code=secret%2Fvalue".to_string(),
                true,
            ),
            "refresh-encoded" => {
                ("refresh", format!("0; url={encoded_function_url}"), true)
            }
            "refresh-query-key" => (
                "refresh",
                "0; url=https://redirect.example/next?leak=code".to_string(),
                true,
            ),
            "refresh-bare-absolute" => {
                ("refresh", format!("0; {function_url}"), true)
            }
            "refresh-bare-relative" => (
                "refresh",
                "0; /signed%2Ftrigger?code=secret%2Fvalue".to_string(),
                true,
            ),
            "refresh-bare-path-segment" => {
                ("refresh", "0; secret/value".to_string(), true)
            }
            "refresh-bare-encoded" => {
                ("refresh", format!("0; {encoded_function_url}"), true)
            }
            "refresh-malformed-target" => {
                ("refresh", format!("0; url=\"{function_url}"), true)
            }
            "link-absolute" => {
                ("link", format!("<{function_url}>; rel=\"next\""), true)
            }
            "link-relative" => (
                "link",
                "</signed%2Ftrigger?code=secret%2Fvalue>; rel=\"next\"".to_string(),
                true,
            ),
            "link-query-key" => (
                "link",
                "<https://redirect.example/next?leak=code>; rel=\"next\"".to_string(),
                true,
            ),
            "link-multiple-targets" => (
                "link",
                format!("</safe>; rel=\"prev\", <{function_url}>; rel=\"next\""),
                true,
            ),
            "link-target-budget" => (
                "link",
                (0..33)
                    .map(|index| format!("</safe/{index}>; rel=\"item\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                true,
            ),
            "link-malformed" => (
                "link",
                format!("</safe>; title=\"unterminated, <{function_url}>; rel=next"),
                true,
            ),
            "benign-content-location" => {
                ("content-location", "/safe?label=other".to_string(), false)
            }
            "benign-refresh" => {
                ("refresh", "5; URL = '/safe?label=other'".to_string(), false)
            }
            "benign-refresh-bare-target" => (
                "refresh",
                "5; https://redirect.example/safe?label=other".to_string(),
                false,
            ),
            "benign-refresh-delay-only" => ("refresh", "5".to_string(), false),
            "benign-refresh-non-url-directive" => {
                ("refresh", "not-a-delay; token=value".to_string(), false)
            }
            "benign-link-multiple-targets" => (
                "link",
                "</safe>; rel=\"prev\", <https://redirect.example/next?label=other>; rel=\"next\"; title=\"a,b\""
                    .to_string(),
                false,
            ),
            "benign-link-label" => (
                "link",
                format!("</safe>; title=\"{function_url}\""),
                false,
            ),
            "benign-link-path-lookalike" => (
                "link",
                "<https://redirect.example/signed/triggered?label=other>; rel=\"next\""
                    .to_string(),
                false,
            ),
            _ => unreachable!(),
        };

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("function-response")
                    .insert_header(header, value.as_str()),
            )
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": function_url,
                "mode": "terminate"
            }),
            default_client(),
        )
        .unwrap();
        let mut ctx = create_test_context();

        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::RejectBinary { headers, .. } => {
                if should_strip {
                    assert!(
                        !headers.contains_key(header),
                        "credential-bearing {header} survived case {case}: {headers:?}"
                    );
                } else {
                    assert_eq!(
                        headers.get(header).map(String::as_str),
                        Some(value.as_str()),
                        "benign {header} changed in case {case}"
                    );
                }
            }
            other => panic!("expected terminal response for case {case}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_terminate_preserves_head_no_body_semantics() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("function-body")
                .insert_header("etag", "\"head-version\""),
        )
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate"
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "HEAD".to_string();

    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert!(body.is_empty());
            assert_eq!(
                headers.get("etag").map(String::as_str),
                Some("\"head-version\"")
            );
            assert!(!headers.contains_key("content-length"));
        }
        other => panic!("expected HEAD terminal response, got {other:?}"),
    }
}

#[tokio::test]
async fn test_terminate_strips_body_from_no_content_statuses() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for status in [204, 205, 304] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string("forbidden-status-body")
                    .insert_header("etag", "\"status-version\""),
            )
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": format!("{}/func", server.uri()),
                "mode": "terminate"
            }),
            default_client(),
        )
        .unwrap();

        match plugin
            .before_proxy(&mut create_test_context(), &mut HashMap::new())
            .await
        {
            PluginResult::RejectBinary {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(status_code, status);
                assert!(body.is_empty(), "status {status} retained a body");
                assert_eq!(
                    headers.get("etag").map(String::as_str),
                    Some("\"status-version\"")
                );
                assert!(!headers.contains_key("content-length"));
            }
            other => panic!("expected terminal status {status}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_forward_body_is_binary_safe_for_non_post_methods() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "forward_body": true,
            "on_error": "continue"
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "PATCH".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );
    ctx.request_body_bytes = Some(Bytes::from_static(&[0xff, 0x00, 0x41]));

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Continue
    ));
    let requests = server.received_requests().await.unwrap();
    let payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["method"], "PATCH");
    assert_eq!(payload["body"], "/wBB");
    assert_eq!(payload["body_encoding"], "base64");
}

#[tokio::test]
async fn test_forward_body_preserves_exact_utf8_bytes_for_json_text_and_empty_bodies() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "forward_body": true
        }),
        default_client(),
    )
    .unwrap();

    let governed_json = "{\n  \"dup\": 1,\n  \"dup\": 2,\n  \"number\": 1e+02\n}\n";
    let mut json_ctx = create_test_context();
    json_ctx.method = "PATCH".to_string();
    json_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    json_ctx.request_body_bytes = Some(Bytes::copy_from_slice(governed_json.as_bytes()));
    let mut active_headers = HashMap::new();
    active_headers.insert("content-type".to_string(), "application/json".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut json_ctx, &mut active_headers)
            .await,
        PluginResult::Continue
    ));

    let governed_text = "  preserve me exactly  \n";
    let mut text_ctx = create_test_context();
    text_ctx.method = "PUT".to_string();
    text_ctx.request_body_bytes = Some(Bytes::copy_from_slice(governed_text.as_bytes()));
    assert!(matches!(
        plugin
            .before_proxy(&mut text_ctx, &mut HashMap::new())
            .await,
        PluginResult::Continue
    ));

    let mut empty_ctx = create_test_context();
    empty_ctx.method = "POST".to_string();
    empty_ctx.request_body_bytes = Some(Bytes::new());
    assert!(matches!(
        plugin
            .before_proxy(&mut empty_ctx, &mut HashMap::new())
            .await,
        PluginResult::Continue
    ));

    let requests = server.received_requests().await.unwrap();
    let json_payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let text_payload: Value = serde_json::from_slice(&requests[1].body).unwrap();
    let empty_payload: Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(json_payload["body"], governed_json);
    assert_eq!(json_payload["body_encoding"], "utf8");
    assert!(json_payload["body"].is_string());
    assert_eq!(text_payload["body"], governed_text);
    assert_eq!(text_payload["body_encoding"], "utf8");
    assert_eq!(empty_payload["body"], "");
    assert_eq!(empty_payload["body_encoding"], "utf8");
}

#[tokio::test]
async fn test_encoded_or_unavailable_body_fails_before_external_egress() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "forward_body": true,
            "on_error": "continue"
        }),
        default_client(),
    )
    .unwrap();

    let mut encoded_ctx = create_test_context();
    encoded_ctx.request_body_bytes = Some(Bytes::from_static(b"opaque"));
    let mut active_headers = std::mem::take(&mut encoded_ctx.headers);
    active_headers.insert("content-encoding".to_string(), "gzip".to_string());
    match plugin
        .before_proxy(&mut encoded_ctx, &mut active_headers)
        .await
    {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("encoded_request_body_unsupported"));
        }
        other => panic!("encoded body must fail closed, got {other:?}"),
    }

    let mut unavailable_ctx = create_test_context();
    unavailable_ctx.method = "POST".to_string();
    match plugin
        .before_proxy(&mut unavailable_ctx, &mut HashMap::new())
        .await
    {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("request_body_unavailable"));
        }
        other => panic!("unavailable body must fail closed, got {other:?}"),
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_ambiguous_query_fails_before_external_egress() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "forward_query_params": true,
            "on_error": "continue"
        }),
        default_client(),
    )
    .unwrap();
    assert!(!plugin.requires_decoded_query_params());

    for (raw_query, expected_code) in [
        ("role=user&role=admin", "duplicate_query_parameter"),
        ("name=alice+bob", "ambiguous_query_encoding"),
        ("name=%FF", "invalid_query_encoding"),
        ("name=%ZZ", "invalid_query_encoding"),
    ] {
        let mut ctx = create_test_context();
        ctx.set_raw_query_string(raw_query.to_string());
        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::Reject { body, .. } => assert!(body.contains(expected_code)),
            other => panic!("query={raw_query} must fail closed, got {other:?}"),
        }
    }

    let mut materialized_only = create_test_context();
    materialized_only
        .query_params
        .insert("role".to_string(), "admin".to_string());
    match plugin
        .before_proxy(&mut materialized_only, &mut HashMap::new())
        .await
    {
        PluginResult::Reject { body, .. } => assert!(body.contains("raw_query_unavailable")),
        other => panic!("materialized-only query must fail closed, got {other:?}"),
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_unambiguous_query_is_decoded_once_for_function_payload() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "forward_query_params": true
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();
    ctx.set_raw_query_string("name=alice%20bob&literal=%2B".to_string());

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Continue
    ));
    let requests = server.received_requests().await.unwrap();
    let payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["query_params"]["name"], "alice bob");
    assert_eq!(payload["query_params"]["literal"], "+");
}

#[tokio::test]
async fn test_secret_bearing_url_never_reaches_client_or_metadata() {
    let secret = "reusable-trigger-secret";
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": format!("http://127.0.0.1:1/private/{secret}?code={secret}"),
            "on_error": "reject",
            "timeout_ms": 100
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = create_test_context();

    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::Reject { body, .. } => {
            assert!(!body.contains(secret), "secret leaked to client: {body}");
            assert!(body.contains("invocation_failed"));
        }
        other => panic!("expected opaque invocation error, got {other:?}"),
    }
    assert!(
        ctx.metadata
            .iter()
            .all(|(key, value)| !key.contains(secret) && !value.contains(secret))
    );
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
            assert!(
                ctx.metadata
                    .contains_key("serverless_function.standalone.error_class")
            );
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
            assert!(body.contains("lambda_function_error"));
            assert!(!body.contains("Unhandled"));
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
        !ctx.metadata
            .contains_key("serverless_function.standalone.error_class"),
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
            assert!(body.contains("response_body_too_large"));
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
            let error_class = ctx
                .metadata
                .get("serverless_function.standalone.error_class")
                .expect("error should be recorded in metadata");
            assert_eq!(error_class, "response_body_too_large");
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
