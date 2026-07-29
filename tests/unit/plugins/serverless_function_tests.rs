use bytes::Bytes;
use ferrum_edge::plugins::serverless_function::{ServerlessFunction, redact_serverless_url};
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, priority};
use serde_json::{Value, json};
use std::collections::HashMap;

use super::plugin_utils::{create_test_context, normalize_compressed_request_for_plugin_test};

/// Mutex to serialize tests that touch process-global env vars.
///
/// This is the single process-wide lock, not a file-private one. These tests
/// write `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_DEFAULT_REGION`, which
/// the AWS secret-backend tests in `unit::secrets::aws_tests` read through the
/// SDK's credential chain, so the two suites must serialize against each other.
use crate::unit::env_lock::ENV_LOCK as ENV_MUTEX;

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
fn test_explicit_null_diagnostics_distinguish_required_and_optional_fields() {
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
        if matches!(field, "provider" | "function_url") {
            assert!(
                err.contains("is required"),
                "required field={field}, got: {err}"
            );
            assert!(
                !err.contains("omit the field"),
                "required field received optional guidance: field={field}, got: {err}"
            );
        } else {
            assert!(
                err.contains("omit the field instead"),
                "optional field={field}, got: {err}"
            );
            assert!(
                !err.contains("is required"),
                "optional field received required guidance: field={field}, got: {err}"
            );
        }
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
// Terminate mode + native gRPC unary contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_terminate_mode_rejects_grpc_web_requests() {
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
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 500);
            assert!(body.contains("does not support gRPC-Web"));
        }
        other => panic!("Expected Reject for gRPC-Web terminate, got {:?}", other),
    }
}

/// Negative control for the ordering hazard: `grpc_web` (priority 260) rewrites
/// `content-type` to `application/grpc` long before `serverless_function`
/// (3025) runs, so a translated browser request reaches `before_proxy` looking
/// exactly like native gRPC. Header inspection alone would frame a native unary
/// response for a client that can only read gRPC-Web body-framed trailers.
#[tokio::test]
async fn test_terminate_mode_rejects_translated_grpc_web_requests() {
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
    ferrum_edge::_test_support::retain_grpc_web_client_content_type_for_test(
        &mut ctx,
        "application/grpc-web+proto",
    );
    // The rewrite `grpc_web` already performed on both header views.
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
            assert!(body.contains("does not support gRPC-Web"));
        }
        other => panic!(
            "Expected Reject for translated gRPC-Web terminate, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_terminate_mode_frames_native_grpc_unary_response() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let protobuf = b"\x08\x01";
    let message_base64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, protobuf);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "grpc_status": 0,
            "grpc_message": "ok",
            "message_base64": message_base64,
            "trailers": { "x-function": "terminate" }
        })))
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
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let (reject_body, reject_headers) = match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("0"));
            assert_eq!(headers.get("grpc-message").map(String::as_str), Some("ok"));
            assert_eq!(
                headers.get("x-function").map(String::as_str),
                Some("terminate")
            );
            let framed = frame_terminate_message(protobuf);
            assert_eq!(body, framed);
            (body, headers)
        }
        other => panic!(
            "Expected RejectBinary framed gRPC response, got {:?}",
            other
        ),
    };

    // End-to-end state transition: the provenance the plugin stamped is what
    // authorizes the shared normalizer to emit DATA + terminal trailers, and the
    // emitter-side predicate every gRPC writer reads agrees.
    let normalized = ferrum_edge::_test_support::normalize_reject_response_with_context(
        &ctx,
        http::StatusCode::OK,
        &reject_body,
        &reject_headers,
        true,
    );
    assert_eq!(normalized.body, reject_body.as_ref());
    let emitted_trailers = ferrum_edge::_test_support::framed_unary_reject_trailers(&normalized)
        .expect("plugin-stamped provenance must authorize DATA + trailers");
    assert_eq!(
        emitted_trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        emitted_trailers.get("grpc-message").map(String::as_str),
        Some("ok")
    );
    assert_eq!(
        emitted_trailers.get("x-function").map(String::as_str),
        Some("terminate")
    );
    assert!(
        !normalized.headers.contains_key("x-function"),
        "custom terminal metadata belongs in trailers, not the HEADERS block"
    );
}

#[tokio::test]
async fn test_terminate_mode_native_grpc_malformed_contract_fails_closed() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate",
            "timeout_ms": 5000,
            "on_error": "continue"
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("invalid_grpc_terminate_response"));
        }
        other => panic!("Expected fail-closed Reject, got {:?}", other),
    }
}

#[test]
fn test_native_grpc_terminate_contract_rejects_streaming_and_reserved_trailers() {
    let streaming_err =
        ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test(
            200,
            br#"{"grpc_status":0,"streaming":true}"#,
            1024,
        )
        .unwrap_err();
    assert!(streaming_err.contains("uncompressed unary"));

    let reserved_err =
        ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test(
            200,
            br#"{"grpc_status":0,"trailers":{"grpc-status":"9"}}"#,
            1024,
        )
        .unwrap_err();
    assert!(reserved_err.contains("protocol-owned"));
}

fn framed_grpc_terminate_reject_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("grpc-status".to_string(), "0".to_string());
    headers.insert("x-custom".to_string(), "trail".to_string());
    headers
}

fn framed_grpc_terminate_trailers() -> HashMap<String, String> {
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    trailers.insert("x-custom".to_string(), "trail".to_string());
    trailers
}

fn frame_terminate_message(message: &[u8]) -> Bytes {
    ferrum_edge::plugins::serverless_function::test_helpers::frame_uncompressed_unary_grpc_message_test(
        message,
    )
    .unwrap()
}

#[test]
fn test_normalize_reject_preserves_framed_unary_grpc_body() {
    use ferrum_edge::_test_support::{
        framed_unary_reject_trailers, normalize_reject_response_with_context,
        set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let framed = frame_terminate_message(b"hello");
    let headers = framed_grpc_terminate_reject_headers();

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        &framed,
        framed_grpc_terminate_trailers(),
    );

    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &framed, &headers, true);
    assert_eq!(normalized.http_status, StatusCode::OK);
    assert_eq!(normalized.body, framed.as_ref());
    assert_eq!(normalized.grpc_status, Some(0));
    assert_eq!(
        normalized.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert!(!normalized.headers.contains_key("grpc-status"));
    assert_eq!(
        normalized
            .grpc_trailers
            .get("grpc-status")
            .map(String::as_str),
        Some("0")
    );
    assert_eq!(
        normalized.grpc_trailers.get("x-custom").map(String::as_str),
        Some("trail")
    );

    // The emitter-side decision every gRPC reject writer shares — the H1/H2
    // body builder, the direct-H3 writer, and both H3 cross-protocol writers.
    // `Some` is what makes DATA + terminal trailers legal to write; a writer
    // that emitted DATA while dropping these would produce a stream with no
    // terminal metadata.
    let emitted_trailers =
        framed_unary_reject_trailers(&normalized).expect("framed unary reject must carry trailers");
    assert_eq!(emitted_trailers, normalized.grpc_trailers);
    assert_eq!(
        emitted_trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
}

/// GHSA-5fp3-pp5p-c4gh compatibility: the authorized terminate frame must reach
/// the wire representation as the SAME shared allocation the plugin authored,
/// not a copy of it. The reject-normalization boundary is where the two
/// behaviors meet — provenance decides that DATA is legal, and the shared-`Bytes`
/// migration decides that emitting it costs a refcount bump rather than a
/// full-body copy. A 256 KiB message makes a regression an unmistakable pointer
/// change rather than an allocator coincidence.
#[test]
fn test_framed_unary_reject_shares_the_authored_frame_allocation() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_bytes_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let message = Bytes::from(vec![0xa7u8; 256 * 1024]);
    let framed = frame_terminate_message(&message);
    let framed_ptr = framed.as_ptr() as usize;
    let headers = framed_grpc_terminate_reject_headers();

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        &framed,
        framed_grpc_terminate_trailers(),
    );

    let normalized = normalize_reject_response_bytes_with_context(
        &ctx,
        StatusCode::OK,
        framed.clone(),
        &headers,
        true,
    );

    assert_eq!(normalized.body.len(), framed.len());
    assert_eq!(
        normalized.body.as_ptr() as usize,
        framed_ptr,
        "the authorized terminate frame must be shared, not copied, into the reject representation"
    );
    assert_eq!(
        normalized
            .grpc_trailers
            .get("grpc-status")
            .map(String::as_str),
        Some("0"),
        "sharing the frame must not cost the mandatory terminal trailers"
    );
}

/// Source canary for the direct-H3 framed writer: it rebuilds its own response
/// from the raw reject map, so it is the one emitter that can silently
/// reintroduce a per-reject copy at the QUIC boundary while every shared helper
/// stays clean.
#[test]
fn test_h3_framed_unary_writer_moves_the_shared_frame_to_quic() {
    let server = include_str!("../../../src/http3/server.rs");
    let start = server
        .find("async fn send_h3_reject_flavor_aware_with_header_state(")
        .expect("direct-H3 flavor-aware reject writer must remain present");
    let tail = &server[start..];
    let end = tail
        .find("pub(crate) fn h3_framed_unary_initial_response(")
        .expect("direct-H3 writer boundary must remain present");
    let writer = &tail[..end];

    assert!(
        writer.contains("http_body: Bytes,"),
        "the direct-H3 reject writer must accept the owned shared body"
    );
    assert!(
        writer.contains("stream.send_data(framed_body).await?;"),
        "the authorized terminate frame must be moved into QUIC send_data"
    );
    assert!(
        !writer.contains("copy_from_slice"),
        "the direct-H3 reject writer must not copy the authorized terminate frame"
    );
    assert!(
        writer.contains("stream.send_trailers(trailers).await?;"),
        "framed unary DATA must still be followed by the terminal trailers block"
    );
}

#[test]
fn test_h3_framed_unary_reject_emits_each_cookie_as_a_separate_header() {
    let mut headers = framed_grpc_terminate_reject_headers();
    headers.insert(
        "Set-Cookie".to_string(),
        "a=1; Path=/\nb=2; Path=/".to_string(),
    );

    let emitted = ferrum_edge::_test_support::h3_framed_unary_response_headers_for_test(&headers)
        .expect("H3 framed unary response headers");
    let cookies = emitted
        .get_all(http::header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("ASCII cookie"))
        .collect::<Vec<_>>();

    assert_eq!(cookies, vec!["a=1; Path=/", "b=2; Path=/"]);
}

/// Provenance, not shape, authorizes a body on a native gRPC rejection. An
/// unrelated plugin can produce a reject whose body is a byte-perfect
/// uncompressed unary frame and whose headers claim `application/grpc` +
/// `grpc-status`; it must still normalize to trailers-only so an untrusted body
/// is never reflected onto the wire.
#[test]
fn test_normalize_reject_without_provenance_stays_trailers_only() {
    use ferrum_edge::_test_support::{
        framed_unary_reject_trailers, normalize_reject_response_with_context,
    };
    use http::StatusCode;

    let framed = frame_terminate_message(b"hello");
    let headers = framed_grpc_terminate_reject_headers();
    let ctx = create_test_context();

    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &framed, &headers, true);
    assert!(
        normalized.body.is_empty(),
        "an unauthorized reject must not reflect a body onto a native gRPC stream"
    );
    assert!(normalized.grpc_trailers.is_empty());
    assert_eq!(
        normalized.headers.get("grpc-status").map(String::as_str),
        Some("0"),
        "trailers-only rejects keep terminal metadata in the HEADERS block"
    );
    assert!(framed_unary_reject_trailers(&normalized).is_none());
}

/// Byte-exact provenance: a decorator that rewrites the reject body after
/// `serverless_function` stamped its frame — and any later unrelated rejection
/// on the same request — falls back to trailers-only.
#[test]
fn test_normalize_reject_provenance_is_byte_exact() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let authored = frame_terminate_message(b"hello");
    let rewritten = frame_terminate_message(b"tampered");
    let headers = framed_grpc_terminate_reject_headers();

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        &authored,
        framed_grpc_terminate_trailers(),
    );

    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &rewritten, &headers, true);
    assert!(
        normalized.body.is_empty(),
        "a body that is not the authored frame must not be preserved"
    );
    assert!(normalized.grpc_trailers.is_empty());

    // Dropping the body is not enough. The authored reject headers still carry
    // the contract's `grpc-status: 0`, so an unguarded fallback would emit an
    // empty Trailers-Only SUCCESS and silently turn a successful unary response
    // into "the RPC returned nothing". Invalidated authorization fails closed.
    assert_eq!(
        normalized.grpc_status,
        Some(13),
        "an invalidated framed terminate authorization must fail closed, not report OK"
    );
    assert_eq!(
        normalized.headers.get("grpc-status").map(String::as_str),
        Some("13")
    );
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("gateway: authorized gRPC terminate response was invalidated")
    );
}

/// A response-body policy rejection replaces the authorized representation and
/// selects its own status. Failing closed must not flatten that into a generic
/// INTERNAL — the client has to see the rejection's real gRPC error even though
/// the stale contract `grpc-status: 0` is still sitting in the header map.
#[test]
fn test_normalize_reject_invalidated_by_body_policy_keeps_rejection_status() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let authored = frame_terminate_message(b"hello");
    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        &authored,
        framed_grpc_terminate_trailers(),
    );

    // What `rebuild_plugin_rejection_response_headers` leaves behind when a
    // body guardrail replaces the synthetic response: a new HTTP status over a
    // header map that may still carry the contract's terminal metadata.
    let headers = framed_grpc_terminate_reject_headers();
    let normalized = normalize_reject_response_with_context(
        &ctx,
        StatusCode::FORBIDDEN,
        br#"{"error":"blocked"}"#,
        &headers,
        true,
    );
    assert!(normalized.body.is_empty());
    assert!(normalized.grpc_trailers.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(7),
        "a body-policy rejection must normalize to PERMISSION_DENIED, not OK and not INTERNAL"
    );
}

/// Stale provenance must not be inheritable. A later, unrelated rejection that
/// happens to carry the same bytes still selects its own HTTP status, and the
/// authorization is bound to the status the contract authored as well as to the
/// frame — so the original successful trailers can never ride out on it.
#[test]
fn test_normalize_reject_stale_provenance_is_not_inherited() {
    use ferrum_edge::_test_support::{
        framed_unary_reject_trailers, normalize_reject_response_with_context,
        set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let authored = frame_terminate_message(b"hello");
    let headers = framed_grpc_terminate_reject_headers();

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        &authored,
        framed_grpc_terminate_trailers(),
    );

    let normalized = normalize_reject_response_with_context(
        &ctx,
        StatusCode::INTERNAL_SERVER_ERROR,
        &authored,
        &headers,
        true,
    );
    assert!(
        normalized.body.is_empty(),
        "byte equality alone must not re-authorize a rejection the contract did not author"
    );
    assert!(framed_unary_reject_trailers(&normalized).is_none());
    assert_eq!(normalized.grpc_status, Some(13));
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("gateway: authorized gRPC terminate response was invalidated")
    );
}

// ---------------------------------------------------------------------------
// Shared response-body policy lifecycle over the framed terminate contract.
//
// The framed native-gRPC terminate representation is the only gRPC
// short-circuit that puts real bytes on the wire, so it is the only one the
// shared body lifecycle (`on_response_body`, representation admission,
// transforms, `on_final_response_body`) can govern. These assert the PRODUCTION
// gate, so a regression that silently skips configured gRPC response validators
// cannot pass.
// ---------------------------------------------------------------------------

fn response_body_buffering_plugin() -> Vec<std::sync::Arc<dyn Plugin>> {
    vec![std::sync::Arc::new(
        ferrum_edge::plugins::ai_token_metrics::AiTokenMetrics::new(&json!({})).unwrap(),
    )]
}

fn grpc_terminate_context_with_frame(frame: &[u8]) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    ferrum_edge::_test_support::set_serverless_terminate_response_for_test(&mut ctx, true);
    // Production stamps the authored representation for BOTH terminate shapes.
    // An empty `frame` is the status-only contract: it authors no DATA, but the
    // provenance still records the authored status and terminal metadata.
    ferrum_edge::_test_support::set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        frame,
        framed_grpc_terminate_trailers(),
    );
    ctx
}

/// The terminal metadata a status-only contract (`grpc_status: 5`, no
/// `message_base64`) authors: no DATA, a real gRPC error status.
fn status_only_grpc_terminate_trailers() -> HashMap<String, String> {
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "5".to_string());
    trailers.insert("grpc-message".to_string(), "not found".to_string());
    trailers
}

#[test]
fn test_authorized_grpc_terminate_frame_runs_response_body_lifecycle() {
    use ferrum_edge::_test_support::synthetic_response_body_hooks_apply_for_test;

    let framed = frame_terminate_message(b"hello");
    let ctx = grpc_terminate_context_with_frame(&framed);
    let plugins = response_body_buffering_plugin();

    assert!(
        synthetic_response_body_hooks_apply_for_test(200, true, &framed, &plugins, &ctx),
        "the validated native-gRPC terminate representation must run the shared response-body \
         policy lifecycle; skipping it bypasses configured gRPC response validators/limits"
    );
}

#[test]
fn test_ordinary_grpc_reject_still_skips_response_body_lifecycle() {
    use ferrum_edge::_test_support::synthetic_response_body_hooks_apply_for_test;

    let framed = frame_terminate_message(b"hello");
    let plugins = response_body_buffering_plugin();

    // No terminate provenance at all: an ordinary gRPC reject is trailers-only,
    // so there is nothing for a body validator to inspect.
    let mut ctx = create_test_context();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    assert!(!synthetic_response_body_hooks_apply_for_test(
        200, true, &framed, &plugins, &ctx
    ));

    // Terminate provenance present, but these are not the authored bytes — the
    // carve-out is provenance, never shape.
    let ctx = grpc_terminate_context_with_frame(&framed);
    let other = frame_terminate_message(b"tampered");
    assert!(!synthetic_response_body_hooks_apply_for_test(
        200, true, &other, &plugins, &ctx
    ));

    // Same bytes, but not the status the contract authored.
    assert!(!synthetic_response_body_hooks_apply_for_test(
        500, true, &framed, &plugins, &ctx
    ));
}

/// The authorization is native-gRPC only. A non-gRPC request keeps the ordinary
/// HTTP representation rather than being reinterpreted as a framed unary reply.
#[test]
fn test_normalize_reject_provenance_does_not_apply_to_non_grpc() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let framed = frame_terminate_message(b"hello");
    let headers = framed_grpc_terminate_reject_headers();

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        &framed,
        framed_grpc_terminate_trailers(),
    );

    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &framed, &headers, false);
    assert_eq!(normalized.body, framed.as_ref());
    assert!(normalized.grpc_trailers.is_empty());
    assert_eq!(normalized.grpc_status, None);
}

/// A terminate contract that asks for a status-only reply frames nothing, so its
/// authorized representation IS trailers-only — and the terminal metadata the
/// client sees comes from the validated contract, not from the reject header map
/// (which here still carries an unrelated `grpc-status: 0`).
#[tokio::test]
async fn test_terminate_mode_status_only_grpc_response_is_trailers_only() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "grpc_status": 5,
            "grpc_message": "not found"
        })))
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
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary { body, headers, .. } => {
            assert!(body.is_empty(), "status-only contract frames no DATA");
            assert_eq!(headers.get("grpc-status").map(String::as_str), Some("5"));
        }
        other => panic!("Expected RejectBinary, got {:?}", other),
    }

    // The status-only contract stamps provenance too — with an EMPTY frame, so
    // it can never authorize DATA.
    let authored = ferrum_edge::_test_support::serverless_grpc_terminate_frame_for_test(&ctx)
        .expect("status-only terminate must stamp its authored representation");
    assert!(
        authored.0.is_empty(),
        "the status-only contract authors no frame"
    );
    assert_eq!(authored.1.get("grpc-status").map(String::as_str), Some("5"));

    let normalized = ferrum_edge::_test_support::normalize_reject_response_with_context(
        &ctx,
        http::StatusCode::OK,
        b"",
        &framed_grpc_terminate_reject_headers(),
        true,
    );
    assert!(normalized.body.is_empty());
    assert!(normalized.grpc_trailers.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(5),
        "the unchanged status-only reply must carry the CONTRACT's status, not the \
         `grpc-status: 0` sitting in the decorated reject header map"
    );
    assert_eq!(normalized.grpc_message.as_deref(), Some("not found"));
}

/// The status-only contract authors no DATA, so nothing may put DATA back on the
/// stream. A body a response transform introduced is not the authorized
/// representation, and the contract's own `grpc-status` must not ride out with
/// it as an empty Trailers-Only success either.
#[test]
fn test_normalize_reject_status_only_with_unauthored_body_fails_closed() {
    use ferrum_edge::_test_support::{
        framed_unary_reject_trailers, normalize_reject_response_with_context,
        set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let mut ctx = create_test_context();
    // A status-only contract that reported success — the dangerous case: a
    // silent fallback would emit `grpc-status: 0` with the body dropped.
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    set_serverless_grpc_terminate_frame_for_test(&mut ctx, b"", trailers);

    let injected = frame_terminate_message(b"injected");
    let normalized = normalize_reject_response_with_context(
        &ctx,
        StatusCode::OK,
        &injected,
        &framed_grpc_terminate_reject_headers(),
        true,
    );
    assert!(
        normalized.body.is_empty(),
        "the status-only contract authored no DATA, so no body may be emitted"
    );
    assert!(framed_unary_reject_trailers(&normalized).is_none());
    assert_eq!(
        normalized.grpc_status,
        Some(13),
        "an unauthored body invalidates the status-only representation and must fail closed"
    );
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("gateway: authorized gRPC terminate response was invalidated")
    );
}

/// A body policy that replaces a status-only terminate reply selects its own
/// status; failing closed must surface that status rather than the contract's
/// residual `grpc-status: 0`.
#[test]
fn test_normalize_reject_status_only_invalidated_by_status_change_fails_closed() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let mut ctx = create_test_context();
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    set_serverless_grpc_terminate_frame_for_test(&mut ctx, b"", trailers);

    let normalized = normalize_reject_response_with_context(
        &ctx,
        StatusCode::FORBIDDEN,
        b"",
        &framed_grpc_terminate_reject_headers(),
        true,
    );
    assert!(normalized.body.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(7),
        "a replacement rejection keeps its own status, never the contract's OK"
    );
}

/// A status-only record whose own terminal metadata no longer proves a status
/// cannot authorize anything: it is an invalidation like any other, not a
/// fallback to the mutable reject header map.
#[test]
fn test_normalize_reject_status_only_unparsable_status_fails_closed() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let mut ctx = create_test_context();
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "not-a-number".to_string());
    set_serverless_grpc_terminate_frame_for_test(&mut ctx, b"", trailers);

    let normalized = normalize_reject_response_with_context(
        &ctx,
        StatusCode::OK,
        b"",
        &framed_grpc_terminate_reject_headers(),
        true,
    );
    assert_eq!(
        normalized.grpc_status,
        Some(13),
        "an unprovable status-only record must fail closed, not inherit the header map's OK"
    );
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("gateway: authorized gRPC terminate response was invalidated")
    );
}

/// The status-only representation reaches the shared response-body policy
/// lifecycle only through the explicit zero-byte inspection gate, and neither a
/// body the contract never authored nor a status it never authored opens it.
#[test]
fn test_status_only_terminate_response_body_lifecycle_gate() {
    use ferrum_edge::_test_support::synthetic_response_body_hooks_apply_for_test;

    let mut ctx = create_test_context();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    ferrum_edge::_test_support::set_serverless_terminate_response_for_test(&mut ctx, true);
    ferrum_edge::_test_support::set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        b"",
        status_only_grpc_terminate_trailers(),
    );
    let plugins = response_body_buffering_plugin();

    // Bytes the contract did not author are not the terminate representation.
    let injected = frame_terminate_message(b"injected");
    assert!(!synthetic_response_body_hooks_apply_for_test(
        200, true, &injected, &plugins, &ctx
    ));

    // Neither is the authored empty body under a status the contract never
    // authored.
    assert!(!synthetic_response_body_hooks_apply_for_test(
        500, true, b"", &plugins, &ctx
    ));

    // The authored status-only representation itself still has to clear the
    // explicit zero-byte inspection gate; a plugin that only asked for ordinary
    // response-body buffering does not open it.
    assert!(!synthetic_response_body_hooks_apply_for_test(
        200, true, b"", &plugins, &ctx
    ));
}

// ---------------------------------------------------------------------------
// Terminal-metadata correctness for the terminate contract: case-insensitive
// trailer names, the percent-encoded `grpc-message` wire form, preserved
// omission of an optional message, and complete restore/removal of authored
// terminal metadata across the shared emitter-facing result.
// ---------------------------------------------------------------------------

/// HTTP/gRPC metadata names are case-insensitive; JSON object members are not.
/// Two members differing only in case are therefore the same trailer, and
/// letting both through would emit whichever the map iterated last — losing an
/// authored value nondeterministically.
#[test]
fn test_native_grpc_terminate_rejects_case_equivalent_trailer_names() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    const MAX_BODY: usize = 1024 * 1024;

    let clashing = json!({
        "grpc_status": 0,
        "trailers": { "X-Foo": "first", "x-foo": "second" }
    });
    let body = serde_json::to_vec(&clashing).unwrap();
    let err = build(200, &body, MAX_BODY).unwrap_err();
    assert!(err.contains("x-foo"), "field-specific detail: {err}");
    assert!(err.contains("case-insensitive"), "explains the rule: {err}");

    // Distinct names are still accepted, and mixed-case authored input is
    // normalized to the lowercase wire form.
    let distinct = json!({
        "grpc_status": 0,
        "trailers": { "X-Foo": "first", "X-Bar": "second" }
    });
    let body = serde_json::to_vec(&distinct).unwrap();
    let (_, _, headers) = build(200, &body, MAX_BODY).unwrap();
    assert_eq!(headers.get("x-foo").map(String::as_str), Some("first"));
    assert_eq!(headers.get("x-bar").map(String::as_str), Some("second"));
}

/// The terminate contract is parsed with `serde_json`, which keeps the LAST of
/// duplicate object members; other parsers keep the FIRST
/// (`GHSA-c78j-5w9p-cpq6`, CWE-436). The gateway authors terminal status and
/// trailers from that collapsed view and then binds them as provenance, so an
/// ambiguous document must be refused rather than resolved. Screening runs on
/// the RAW bytes with the shared bounded `json_dup_keys` scanner, before
/// `serde_json` ever sees them.
#[test]
fn test_native_grpc_terminate_rejects_duplicate_json_members() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_error_code_test as build_code;
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    const MAX_BODY: usize = 1024 * 1024;

    // A member name spelled with a JSON `u`-escape for the code point of `s`.
    // It DECODES to `grpc_status`, so it is the same member as the one before
    // it even though the two spellings share no bytes — the case a scanner that
    // compared raw names would miss. Assembled at runtime so the escape cannot
    // be collapsed by source-level processing.
    let escaped_status = format!("grpc_{}u0073tatus", '\\');
    assert_eq!(
        escaped_status.len(),
        "grpc_status".len() + 5,
        "the member name must carry the six-byte escape, not a decoded 's'"
    );
    let escaped_duplicate = format!(r#"{{"grpc_status": 0, "{escaped_status}": 7}}"#);

    // Byte-identical duplicate: `serde_json` silently keeps `7`, while a
    // first-wins parser reading the same bytes sees the successful `0`.
    let repeated = r#"{"grpc_status": 0, "grpc_status": 7}"#;
    // Nested: a duplicate inside the `trailers` object is equally ambiguous and
    // equally reaches the authored terminal metadata.
    let nested = r#"{"grpc_status": 0, "trailers": {"x-a": "1", "x-a": "2"}}"#;

    let ambiguous = [
        ("byte-identical", repeated),
        ("escaped-equivalent", escaped_duplicate.as_str()),
        ("nested-trailers", nested),
    ];

    for (label, document) in ambiguous {
        let detail = build(200, document.as_bytes(), MAX_BODY)
            .err()
            .unwrap_or_else(|| panic!("{label}: an ambiguous contract must be refused"));
        assert!(
            detail.contains("duplicate object member names"),
            "{label}: fixed-cardinality reason expected, got {detail:?}"
        );
        // The diagnostic is fixed-cardinality and must never echo any byte of
        // the inspected document — not a member name, not a value.
        for echoed in ["grpc_status", "trailers", "x-a", "u0073"] {
            assert!(
                !detail.contains(echoed),
                "{label}: diagnostic echoed body content {echoed:?}: {detail:?}"
            );
        }
        // Fail closed under the same client-visible class as every other
        // malformed-contract refusal, so no new error surface is introduced.
        let code = build_code(200, document.as_bytes(), MAX_BODY)
            .err()
            .unwrap_or_else(|| panic!("{label}: expected a refusal code"));
        assert_eq!(code, "invalid_grpc_terminate_response", "{label}");
    }

    // Ordinary malformed bytes are NOT reclassified: the screen stays silent and
    // the pre-existing malformed-body diagnostic still applies.
    let malformed = build(200, b"{\"grpc_status\": ", MAX_BODY).unwrap_err();
    assert!(
        malformed.contains("must be a JSON object"),
        "malformed input keeps its existing diagnostic, got {malformed:?}"
    );

    // An unambiguous contract is unaffected.
    let clean = serde_json::to_vec(&json!({
        "grpc_status": 0,
        "trailers": {"x-a": "first", "x-b": "second"}
    }))
    .unwrap();
    let (_, _, headers) = build(200, &clean, MAX_BODY).unwrap();
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("0"));
    assert_eq!(headers.get("x-a").map(String::as_str), Some("first"));
}

/// Hostile or compromised function output can put near-body-sized keys, control
/// characters, and arbitrarily many unknown members into the terminate JSON.
/// Operator diagnostics must stay bounded, single-line, and free of value/body
/// echo while keeping field-specific refusals under the fixed client-visible
/// class.
#[test]
fn test_native_grpc_terminate_bounds_hostile_operator_diagnostics() {
    use ferrum_edge::plugins::serverless_function::test_helpers::{
        MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS_TEST as MAX_NAME,
        MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS_TEST as MAX_DETAIL,
        MAX_GRPC_TERMINATE_UNKNOWN_FIELD_SAMPLE_TEST as MAX_SAMPLE,
        build_native_grpc_terminate_response_error_code_test as build_code,
        build_native_grpc_terminate_response_test as build,
    };

    const MAX_BODY: usize = 1024 * 1024;
    // Pin the ceilings so a silent widen cannot regress the log-bound contract.
    assert_eq!(MAX_DETAIL, 256);
    assert_eq!(MAX_NAME, 64);
    assert_eq!(MAX_SAMPLE, 3);

    // Very long unknown key: fragment and complete diagnostic stay capped.
    let long_key = format!("x{}", "a".repeat(8 * 1024));
    let long_body =
        format!(r#"{{"grpc_status":0,"{long_key}":"BODY_ECHO_MARKER_SHOULD_NOT_APPEAR"}}"#);
    let detail = build(200, long_body.as_bytes(), MAX_BODY).unwrap_err();
    assert!(
        detail.chars().count() <= MAX_DETAIL,
        "complete diagnostic exceeds {MAX_DETAIL}: len={}",
        detail.chars().count()
    );
    assert!(
        !detail.contains('\n') && !detail.contains('\r'),
        "diagnostic must be single-line: {detail:?}"
    );
    assert!(
        !detail.contains("BODY_ECHO_MARKER_SHOULD_NOT_APPEAR"),
        "must never echo field values: {detail:?}"
    );
    assert!(
        !detail.contains(&"a".repeat(MAX_NAME + 1)),
        "displayed field-name fragment must be capped: {detail:?}"
    );
    assert!(
        detail.contains("unknown gRPC terminate response field"),
        "keeps the unknown-field refusal: {detail:?}"
    );
    assert_eq!(
        build_code(200, long_body.as_bytes(), MAX_BODY).unwrap_err(),
        "invalid_grpc_terminate_response"
    );

    // Newline/control characters in an unknown key and in an invalid trailer
    // name must render as single-line escapes, never as raw control bytes.
    let mut control_unknown = serde_json::Map::new();
    control_unknown.insert("grpc_status".to_string(), json!(0));
    control_unknown.insert(
        "bad\nkey\u{7}'fake\u{2028}line\u{2029}paragraph".to_string(),
        json!("VALUE_MUST_NOT_ECHO"),
    );
    let control_unknown = serde_json::to_vec(&Value::Object(control_unknown)).unwrap();
    let detail = build(200, &control_unknown, MAX_BODY).unwrap_err();
    assert!(
        !detail.contains('\n')
            && !detail.contains('\r')
            && !detail.contains('\u{7}')
            && !detail.contains('\u{2028}')
            && !detail.contains('\u{2029}'),
        "raw control bytes must not reach the diagnostic: {detail:?}"
    );
    assert!(
        detail.contains("\\n")
            && detail.contains("\\u{0007}")
            && detail.contains("\\'fake")
            && detail.contains("\\u{2028}")
            && detail.contains("\\u{2029}"),
        "controls, delimiters, and Unicode separators must be escaped for operators: {detail:?}"
    );
    assert!(
        !detail.contains("VALUE_MUST_NOT_ECHO"),
        "must never echo values: {detail:?}"
    );
    assert_eq!(
        build_code(200, &control_unknown, MAX_BODY).unwrap_err(),
        "invalid_grpc_terminate_response"
    );

    let mut control_trailer = serde_json::Map::new();
    control_trailer.insert("grpc_status".to_string(), json!(0));
    let mut trailers = serde_json::Map::new();
    trailers.insert(
        "bad\nname".to_string(),
        json!("TRAILER_VALUE_MUST_NOT_ECHO"),
    );
    control_trailer.insert("trailers".to_string(), Value::Object(trailers));
    let control_trailer = serde_json::to_vec(&Value::Object(control_trailer)).unwrap();
    let detail = build(200, &control_trailer, MAX_BODY).unwrap_err();
    assert!(
        !detail.contains('\n') && !detail.contains('\r'),
        "trailer-name diagnostic must be single-line: {detail:?}"
    );
    assert!(
        detail.contains("\\n"),
        "newline in trailer name must be escaped: {detail:?}"
    );
    assert!(
        !detail.contains("TRAILER_VALUE_MUST_NOT_ECHO"),
        "must never echo trailer values: {detail:?}"
    );
    assert!(
        detail.chars().count() <= MAX_DETAIL,
        "trailer-name diagnostic exceeds bound: {detail:?}"
    );
    assert_eq!(
        build_code(200, &control_trailer, MAX_BODY).unwrap_err(),
        "invalid_grpc_terminate_response"
    );

    // Many unknown keys: sample + count only; later names and all values stay out.
    let mut many = serde_json::Map::new();
    many.insert("grpc_status".to_string(), json!(0));
    for i in 0..32 {
        many.insert(
            format!("zz_unknown_{i:02}"),
            json!(format!("secret-value-{i}-must-not-echo")),
        );
    }
    // Lexicographically first unknowns under sorted Map iteration are the
    // zz_unknown_00.. samples; a later distinctive name must not appear once
    // the sample is full.
    many.insert(
        "zz_unknown_99_late".to_string(),
        json!("LATE_VALUE_MUST_NOT_ECHO"),
    );
    let many_body = serde_json::to_vec(&Value::Object(many)).unwrap();
    let detail = build(200, &many_body, MAX_BODY).unwrap_err();
    assert!(
        detail.contains("(33)") || detail.contains(&format!("({})", 33)),
        "reports the total unknown count: {detail:?}"
    );
    assert!(
        detail.contains('…') || detail.contains(", …"),
        "marks that the sample is truncated: {detail:?}"
    );
    // At most MAX_SAMPLE unknown name fragments appear.
    let sampled = (0..32)
        .filter(|i| detail.contains(&format!("zz_unknown_{i:02}")))
        .count();
    assert!(
        sampled <= MAX_SAMPLE,
        "sampled {sampled} names, cap is {MAX_SAMPLE}: {detail:?}"
    );
    assert!(
        !detail.contains("zz_unknown_99_late"),
        "must not join the unbounded inventory: {detail:?}"
    );
    for i in 0..32 {
        assert!(
            !detail.contains(&format!("secret-value-{i}-must-not-echo")),
            "must never echo values: {detail:?}"
        );
    }
    assert!(!detail.contains("LATE_VALUE_MUST_NOT_ECHO"));
    assert!(
        detail.chars().count() <= MAX_DETAIL,
        "many-unknown diagnostic exceeds bound: len={}",
        detail.chars().count()
    );
    assert!(
        !detail.contains('\n') && !detail.contains('\r'),
        "many-unknown diagnostic must be single-line"
    );
    assert_eq!(
        build_code(200, &many_body, MAX_BODY).unwrap_err(),
        "invalid_grpc_terminate_response"
    );
}

/// Custom trailers are gRPC metadata, not arbitrary HTTP fields. Enforce the
/// protocol's narrower name/value grammar and binary-metadata encoding before
/// the response is authorized to reach a native gRPC stream.
#[test]
fn test_native_grpc_terminate_validates_custom_grpc_metadata() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    const MAX_BODY: usize = 1024 * 1024;
    for (trailers, expected) in [
        (json!({"x!http-only": "value"}), "metadata name alphabet"),
        (json!({"x-text": "café"}), "valid gRPC ASCII value"),
        (json!({"x-custom-bin": "not base64!"}), "standard base64"),
    ] {
        let body = serde_json::to_vec(&json!({
            "grpc_status": 0,
            "trailers": trailers
        }))
        .unwrap();
        let error = build(200, &body, MAX_BODY).unwrap_err();
        assert!(
            error.contains(expected),
            "expected {expected:?} in diagnostic, got {error:?}"
        );
    }

    for encoded in ["AAECAw==", "AAECAw"] {
        let body = serde_json::to_vec(&json!({
            "grpc_status": 0,
            "trailers": {"x-custom-bin": encoded}
        }))
        .unwrap();
        let (_, _, headers) = build(200, &body, MAX_BODY).unwrap();
        assert_eq!(
            headers.get("x-custom-bin").map(String::as_str),
            Some(encoded)
        );
    }
}

/// `grpc_message` is authored as human-readable text, but the wire field is
/// `Percent-Encoded` per the gRPC HTTP mapping. Emitting the raw text would put
/// a bare `%` (which clients decode as an escape introducer) and raw non-ASCII
/// bytes into a field whose grammar forbids both.
#[test]
fn test_native_grpc_terminate_percent_encodes_grpc_message() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    fn emitted_message(message: &str) -> String {
        let contract = json!({ "grpc_status": 9, "grpc_message": message });
        let body = serde_json::to_vec(&contract).unwrap();
        let (_, _, headers) = build(200, &body, 1024 * 1024).unwrap();
        headers.get("grpc-message").cloned().unwrap()
    }

    // A literal percent sign must not reach the client as an escape introducer.
    assert_eq!(emitted_message("100% failed"), "100%25 failed");
    // Bytes the grammar allows unescaped stay literal: %x20-%x24 and %x26-%x7E.
    assert_eq!(emitted_message("ok: a-b_c~d!\"#$&/"), "ok: a-b_c~d!\"#$&/");
    // Non-ASCII is encoded per UTF-8 byte with uppercase hex.
    assert_eq!(emitted_message("héllo"), "h%C3%A9llo");
    assert_eq!(emitted_message("なし"), "%E3%81%AA%E3%81%97");
    // Control bytes the CR/LF sanitizer does not cover are encoded rather than
    // silently dropped at trailer construction.
    assert_eq!(emitted_message("a\u{7}b"), "a%07b");
    assert_eq!(emitted_message("del\u{7f}"), "del%7F");
    // CR/LF normalization stays deterministic and runs BEFORE encoding, so a
    // newline becomes a literal space rather than `%0A`.
    assert_eq!(emitted_message("line\r\none"), "line  one");
    assert_eq!(emitted_message("  padded  "), "padded");
}

/// The advertised 8 KiB trailer wire ceiling is measured on the ENCODED value.
/// Percent-encoding expands a byte threefold, so bounding the pre-encoding
/// string would have admitted roughly 24 KiB onto the wire.
#[test]
fn test_native_grpc_terminate_bounds_encoded_grpc_message() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;
    use ferrum_edge::plugins::serverless_function::test_helpers::percent_encode_grpc_message_test as encode;

    const WIRE_CAP: usize = 8 * 1024;
    const MAX_BODY: usize = 1024 * 1024;

    // Each `%` encodes to three bytes; the `a` padding keeps the encoded value
    // exactly at the ceiling.
    let at_cap = format!("{}{}", "%".repeat(WIRE_CAP / 3), "a".repeat(WIRE_CAP % 3));
    assert_eq!(encode(&at_cap).len(), WIRE_CAP);
    let contract = json!({ "grpc_status": 0, "grpc_message": at_cap });
    let body = serde_json::to_vec(&contract).unwrap();
    let (_, _, headers) = build(200, &body, MAX_BODY).unwrap();
    assert_eq!(headers.get("grpc-message").map(String::len), Some(WIRE_CAP));

    // One more source character crosses the ceiling even though the authored
    // string is barely a third of it.
    let over_cap = format!("{at_cap}a");
    assert!(over_cap.len() < WIRE_CAP, "pre-image is under the cap");
    let contract = json!({ "grpc_status": 0, "grpc_message": over_cap });
    let body = serde_json::to_vec(&contract).unwrap();
    let err = build(200, &body, MAX_BODY).unwrap_err();
    assert!(err.contains("grpc_message"), "field-specific detail: {err}");
    assert!(err.contains("percent-encoded"), "names the encoding: {err}");
}

/// Per-field charge an H2 peer applies to a header list (RFC 9113 §6.5.2) and
/// an H3 peer applies to a field section (RFC 9114 §4.2.2): name + value + 32.
const TERMINATE_FIELD_OVERHEAD: usize = 32;
/// Aggregate budget for the complete terminal metadata block.
const TERMINATE_BLOCK_BUDGET: usize = 16 * 1024;

/// Charge a built terminal metadata map exactly the way the peer does.
fn terminate_block_charge(fields: &HashMap<String, String>) -> usize {
    fields
        .iter()
        .map(|(name, value)| name.len() + value.len() + TERMINATE_FIELD_OVERHEAD)
        .sum()
}

/// The two fields every terminate contract emits regardless of what it authored.
fn terminate_block_base_charge() -> usize {
    let content_type = "content-type".len() + "application/grpc".len() + TERMINATE_FIELD_OVERHEAD;
    let grpc_status = "grpc-status".len() + "0".len() + TERMINATE_FIELD_OVERHEAD;
    content_type + grpc_status
}

/// Build `count` distinct, individually valid custom trailers whose combined
/// header-list charge is exactly `charge`. Every value stays far below the 8 KiB
/// per-value ceiling, so only the aggregate bound can refuse them.
fn aggregate_terminate_trailers(count: usize, charge: usize) -> HashMap<String, String> {
    assert!(count > 0);
    let names: Vec<String> = (0..count).map(|i| format!("x-t{i:02}")).collect();
    let fixed: usize = names
        .iter()
        .map(|name| name.len() + TERMINATE_FIELD_OVERHEAD)
        .sum();
    let value_bytes = charge
        .checked_sub(fixed)
        .expect("requested charge must cover names and per-field overhead");
    let each = value_bytes / count;
    let mut trailers = HashMap::new();
    for (index, name) in names.iter().enumerate() {
        let len = if index + 1 == count {
            value_bytes - each * (count - 1)
        } else {
            each
        };
        assert!(
            len <= 8 * 1024,
            "each generated trailer must stay under the per-value ceiling"
        );
        trailers.insert(name.clone(), "a".repeat(len));
    }
    assert_eq!(terminate_block_charge(&trailers), charge);
    trailers
}

/// The per-value 8 KiB ceiling and the 32-entry count cap each bound ONE
/// dimension. Neither bounds the block a peer must actually accept: 32
/// individually valid 8 KiB trailers are ~256 KiB of terminal metadata, past any
/// header-list size an H2/H3 client is obliged to accept and held in memory
/// until emission. The complete block is therefore charged the way the peer
/// charges it — names + values + 32 bytes per field.
#[test]
fn test_native_grpc_terminate_bounds_aggregate_terminal_block() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_error_code_test as build_code;
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    const MAX_BODY: usize = 1024 * 1024;
    const COUNT: usize = 32;

    // Exactly on the budget: accepted, with the count cap fully used and every
    // value roughly a twentieth of the per-value ceiling.
    let custom_charge = TERMINATE_BLOCK_BUDGET - terminate_block_base_charge();
    let trailers = aggregate_terminate_trailers(COUNT, custom_charge);
    let body = serde_json::to_vec(&json!({ "grpc_status": 0, "trailers": trailers })).unwrap();
    let (_, _, headers) = build(200, &body, MAX_BODY).unwrap();
    assert_eq!(headers.len(), COUNT + 2);
    assert_eq!(
        terminate_block_charge(&headers),
        TERMINATE_BLOCK_BUDGET,
        "the accepted block sits exactly on the aggregate budget"
    );

    // One byte more. Still 32 entries, still every value far under 8 KiB — the
    // per-entry and count limits cannot see this, only the aggregate one can.
    let mut over = trailers.clone();
    let (name, value) = over
        .iter()
        .next()
        .map(|(name, value)| (name.clone(), value.clone()))
        .unwrap();
    over.insert(name, format!("{value}a"));
    let body = serde_json::to_vec(&json!({ "grpc_status": 0, "trailers": over })).unwrap();
    let err = build(200, &body, MAX_BODY).unwrap_err();
    assert!(
        err.contains("aggregate"),
        "names the aggregate budget: {err}"
    );
    assert!(
        !err.contains("aaaa") && !err.contains("x-t"),
        "the diagnostic never echoes trailer names or values: {err}"
    );
    assert_eq!(
        build_code(200, &body, MAX_BODY).unwrap_err(),
        "invalid_grpc_terminate_response",
        "an over-budget block fails closed under the existing fixed class"
    );
}

/// Protocol-owned terminal metadata shares the one block with custom trailers,
/// so it is charged there too. A custom set that fits on its own must stop
/// fitting once the contract also authors `grpc-message` and
/// `grpc-status-details-bin`.
#[test]
fn test_native_grpc_terminate_aggregate_budget_counts_protocol_owned_metadata() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    const MAX_BODY: usize = 1024 * 1024;
    const COUNT: usize = 32;

    let message_charge = "grpc-message".len() + "ok".len() + TERMINATE_FIELD_OVERHEAD;
    let custom_charge = TERMINATE_BLOCK_BUDGET - terminate_block_base_charge() - message_charge;
    let trailers = aggregate_terminate_trailers(COUNT, custom_charge);

    // The custom trailers alone leave exactly one `grpc-message` of headroom.
    let alone = serde_json::to_vec(&json!({ "grpc_status": 0, "trailers": trailers })).unwrap();
    let (_, _, headers) = build(200, &alone, MAX_BODY).unwrap();
    assert_eq!(
        terminate_block_charge(&headers),
        TERMINATE_BLOCK_BUDGET - message_charge
    );

    // Spending that headroom on the protocol-owned message lands exactly on the
    // budget.
    let contract = json!({ "grpc_status": 0, "grpc_message": "ok", "trailers": trailers });
    let with_message = serde_json::to_vec(&contract).unwrap();
    let (_, _, headers) = build(200, &with_message, MAX_BODY).unwrap();
    assert_eq!(headers.get("grpc-message").map(String::as_str), Some("ok"));
    assert_eq!(terminate_block_charge(&headers), TERMINATE_BLOCK_BUDGET);

    // Adding `grpc-status-details-bin` on top crosses it, even though that value
    // is a handful of bytes and every per-entry check still passes.
    let contract = json!({
        "grpc_status": 0,
        "grpc_message": "ok",
        "status_details_base64": "AAECAw==",
        "trailers": trailers
    });
    let with_details = serde_json::to_vec(&contract).unwrap();
    let err = build(200, &with_details, MAX_BODY).unwrap_err();
    assert!(
        err.contains("aggregate"),
        "names the aggregate budget: {err}"
    );
}

/// An over-budget contract must fail closed all the way out: no framed provenance
/// is stamped, so nothing authorizes DATA + plugin-authored trailers on the gRPC
/// stream, and the client sees the fixed rejection class instead.
#[tokio::test]
async fn test_terminate_mode_over_budget_trailers_never_receive_framed_provenance() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Twice the aggregate budget, assembled entirely from individually valid
    // 1 KiB trailers within the 32-entry count cap.
    let trailers = aggregate_terminate_trailers(32, 2 * TERMINATE_BLOCK_BUDGET);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "grpc_status": 0,
            "message_base64": "",
            "trailers": trailers
        })))
        .mount(&server)
        .await;

    // `on_error: continue` is the permissive policy; a refused terminate contract
    // must still not fall through to the backend.
    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate",
            "timeout_ms": 5000,
            "max_response_body_bytes": 1048576,
            "on_error": "continue"
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("invalid_grpc_terminate_response"));
            assert!(
                !body.contains("aaaa") && !body.contains("x-t"),
                "the client-visible reject never reflects the function's trailers"
            );
        }
        other => panic!("Expected fail-closed Reject, got {:?}", other),
    }

    assert!(
        ferrum_edge::_test_support::serverless_grpc_terminate_frame_for_test(&ctx).is_none(),
        "a refused contract must not stamp provenance authorizing framed output"
    );
}

/// The authored terminal metadata of a status-only contract that used every
/// optional field.
fn status_only_full_terminate_trailers() -> HashMap<String, String> {
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    trailers.insert("grpc-message".to_string(), "all%20good".to_string());
    trailers.insert(
        "grpc-status-details-bin".to_string(),
        "AAECAw==".to_string(),
    );
    trailers.insert("x-tenant".to_string(), "acme".to_string());
    trailers
}

/// `grpc_message` is optional. A status-only success must not gain an invented
/// error string, and neither must a nonzero contract that deliberately omitted
/// one. Omission is also not represented by an empty `grpc-message` field.
#[test]
fn test_status_only_terminate_preserves_omitted_grpc_message() {
    use ferrum_edge::_test_support::{
        h3_reject_log_signal_for_test, normalize_reject_response_with_context,
        set_serverless_grpc_terminate_frame_for_test, status_only_grpc_terminate_signal_for_test,
    };
    use http::StatusCode;

    for status in [0u32, 5u32] {
        let mut ctx = create_test_context();
        let mut trailers = HashMap::new();
        trailers.insert("grpc-status".to_string(), status.to_string());
        set_serverless_grpc_terminate_frame_for_test(&mut ctx, b"", trailers);

        // The decorated reject header map carries terminal metadata the
        // contract never authored; none of it may be promoted onto the
        // contract's own status.
        let mut headers = framed_grpc_terminate_reject_headers();
        headers.insert("grpc-message".to_string(), "decorator text".to_string());
        headers.insert(
            "grpc-status-details-bin".to_string(),
            "ZGVjb3JhdG9y".to_string(),
        );

        let normalized =
            normalize_reject_response_with_context(&ctx, StatusCode::OK, b"", &headers, true);
        assert_eq!(normalized.grpc_status, Some(status));
        assert_eq!(
            normalized.grpc_message, None,
            "an omitted grpc_message stays omitted for status {status}"
        );
        assert!(
            !normalized.headers.contains_key("grpc-message"),
            "omission is not represented by an empty grpc-message field"
        );
        assert!(
            !normalized.headers.contains_key("grpc-status-details-bin"),
            "a decorator cannot inject terminal metadata the contract never authored"
        );

        // The direct-H3 writer consumes exactly this shared result, so agreeing
        // here is what keeps the two emitters aligned.
        let shared = status_only_grpc_terminate_signal_for_test(&ctx, StatusCode::OK, b"");
        let shared = shared.unwrap();
        assert_eq!(shared.0, status);
        assert_eq!(shared.1, None, "the shared emitter result omits it too");

        let (log_status, logged_grpc_status, logged_grpc_message) =
            h3_reject_log_signal_for_test(&mut ctx, StatusCode::OK, b"", &headers);
        assert_eq!(log_status, 200);
        assert_eq!(logged_grpc_status, Some(status.to_string()));
        assert_eq!(
            logged_grpc_message, None,
            "H3 logging must preserve the same message omission as the wire"
        );
    }
}

/// An intact status-only reply emits the COMPLETE authored terminal metadata,
/// restored from the validated provenance. Non-terminal decoration may remain
/// in the initial response headers, but a decorator can neither alter, drop,
/// nor inject contract terminal metadata.
#[test]
fn test_status_only_terminate_restores_complete_authored_metadata() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
        status_only_grpc_terminate_signal_for_test,
    };
    use http::StatusCode;

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        b"",
        status_only_full_terminate_trailers(),
    );

    // A decorator rewrote every terminal key and added an ordinary header.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("grpc-status".to_string(), "13".to_string());
    headers.insert("grpc-message".to_string(), "decorator text".to_string());
    headers.insert(
        "grpc-status-details-bin".to_string(),
        "ZGVjb3JhdG9y".to_string(),
    );
    headers.insert("x-tenant".to_string(), "attacker".to_string());
    headers.insert("x-decorated".to_string(), "kept".to_string());

    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, b"", &headers, true);

    assert_eq!(normalized.grpc_status, Some(0));
    assert_eq!(normalized.grpc_message.as_deref(), Some("all%20good"));
    assert_eq!(
        normalized.headers.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        normalized.headers.get("grpc-message").map(String::as_str),
        Some("all%20good")
    );
    assert_eq!(
        normalized
            .headers
            .get("grpc-status-details-bin")
            .map(String::as_str),
        Some("AAECAw=="),
        "details-bin is restored from the contract, never read out of the decorated map"
    );
    assert_eq!(
        normalized.headers.get("x-tenant").map(String::as_str),
        Some("acme"),
        "an authored custom trailer is restored, not the decorator's replacement"
    );
    assert_eq!(
        normalized.headers.get("x-decorated").map(String::as_str),
        Some("kept"),
        "non-terminal decoration is left alone"
    );

    // The direct-H3 writer builds its header block from this same result.
    let shared = status_only_grpc_terminate_signal_for_test(&ctx, StatusCode::OK, b"");
    let shared = shared.unwrap();
    assert_eq!(shared.0, 0);
    assert_eq!(shared.1.as_deref(), Some("all%20good"));
    assert_eq!(
        shared.2,
        vec![
            (
                "grpc-status-details-bin".to_string(),
                "AAECAw==".to_string()
            ),
            ("x-tenant".to_string(), "acme".to_string()),
        ],
        "sorted, and limited to authored terminal metadata beyond status/message"
    );
}

/// Invalidating a status-only contract discards EVERY terminal key it authored.
/// Pairing the replacement nonzero status with the original
/// `grpc-status-details-bin` would describe the successful response the client
/// is not receiving, and the contract's custom trailers would misattribute the
/// replacement error.
#[test]
fn test_invalidated_status_only_terminate_drops_all_authored_metadata() {
    use ferrum_edge::_test_support::{
        h3_reject_log_signal_for_test, normalize_reject_response_with_context,
        set_serverless_grpc_terminate_frame_for_test, status_only_grpc_terminate_signal_for_test,
    };
    use http::StatusCode;

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(
        &mut ctx,
        b"",
        status_only_full_terminate_trailers(),
    );

    // The authored terminal metadata is sitting in the reject header map, as it
    // is on the real path.
    let mut headers = status_only_full_terminate_trailers();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("x-decorated".to_string(), "kept".to_string());

    // A body the contract never authored invalidates the representation.
    let injected = frame_terminate_message(b"injected");
    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &injected, &headers, true);

    assert!(normalized.body.is_empty());
    assert_eq!(normalized.grpc_status, Some(13));
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("gateway: authorized gRPC terminate response was invalidated")
    );
    assert!(
        !normalized.headers.contains_key("grpc-status-details-bin"),
        "a stale details-bin encoding the original SUCCESS must not ride out beside \
         the replacement error"
    );
    assert!(
        !normalized.headers.contains_key("x-tenant"),
        "the contract's custom trailers must not leak into the replacement"
    );
    assert_eq!(
        normalized.headers.get("x-decorated").map(String::as_str),
        Some("kept"),
        "only the contract's OWN terminal keys are discarded"
    );

    let invalidated = status_only_grpc_terminate_signal_for_test(&ctx, StatusCode::OK, &injected);
    assert!(invalidated.is_none());

    let (log_status, logged_grpc_status, logged_grpc_message) =
        h3_reject_log_signal_for_test(&mut ctx, StatusCode::OK, &injected, &headers);
    assert_eq!(log_status, 200);
    assert_eq!(logged_grpc_status.as_deref(), Some("13"));
    assert_eq!(
        logged_grpc_message.as_deref(),
        Some("gateway: authorized gRPC terminate response was invalidated"),
        "H3 logging must record the fail-closed wire signal, not the stale authored success"
    );
}

/// Direct-H3 reject logging must agree with the wire normalizer on an intact
/// framed terminate response, and must do so through the shared borrowed
/// predicate rather than a full-body copy of the authorized frame.
#[test]
fn test_h3_reject_log_framed_terminate_matches_wire_signal() {
    use ferrum_edge::_test_support::{
        h3_reject_log_signal_for_test, normalize_reject_response_with_context,
        set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    // A multi-KiB frame makes a reintroduced full-body copy in the log path
    // materially expensive; the behavioral pin is log/wire agreement, and the
    // static source test forbids `Bytes::copy_from_slice(http_body)` there.
    let message = vec![0xab; 64 * 1024];
    let framed = frame_terminate_message(&message);
    let mut trailers = framed_grpc_terminate_trailers();
    trailers.insert("grpc-message".to_string(), "ok%20done".to_string());

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(&mut ctx, &framed, trailers);

    let mut headers = framed_grpc_terminate_reject_headers();
    headers.insert("grpc-message".to_string(), "ok%20done".to_string());

    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &framed, &headers, true);
    assert_eq!(normalized.grpc_status, Some(0));
    assert_eq!(normalized.grpc_message.as_deref(), Some("ok%20done"));
    assert_eq!(normalized.body.as_ref(), framed.as_ref());

    let (log_status, logged_grpc_status, logged_grpc_message) =
        h3_reject_log_signal_for_test(&mut ctx, StatusCode::OK, &framed, &headers);
    assert_eq!(log_status, 200);
    assert_eq!(
        logged_grpc_status.as_deref(),
        Some("0"),
        "H3 logging must record the same grpc-status the wire emits"
    );
    assert_eq!(
        logged_grpc_message.as_deref(),
        normalized.grpc_message.as_deref(),
        "H3 logging must record the same sanitized grpc-message the wire emits"
    );
}

/// The same complete removal applies when a FRAMED contract is invalidated: at
/// that point the reject header map still holds the contract's terminal
/// metadata, so a plain fallback would leak it beside the replacement error.
#[test]
fn test_invalidated_framed_terminate_drops_all_authored_metadata() {
    use ferrum_edge::_test_support::{
        normalize_reject_response_with_context, set_serverless_grpc_terminate_frame_for_test,
    };
    use http::StatusCode;

    let framed = frame_terminate_message(b"hello");
    let mut authored = framed_grpc_terminate_trailers();
    authored.insert(
        "grpc-status-details-bin".to_string(),
        "AAECAw==".to_string(),
    );

    let mut ctx = create_test_context();
    set_serverless_grpc_terminate_frame_for_test(&mut ctx, &framed, authored.clone());

    let mut headers = authored;
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("x-decorated".to_string(), "kept".to_string());

    // A response-body transform rewrote the authorized frame.
    let rewritten = frame_terminate_message(b"rewritten");
    let normalized =
        normalize_reject_response_with_context(&ctx, StatusCode::OK, &rewritten, &headers, true);

    assert!(normalized.body.is_empty());
    assert_eq!(normalized.grpc_status, Some(13));
    assert!(
        !normalized.headers.contains_key("grpc-status-details-bin"),
        "the successful contract's details-bin must not survive its invalidation"
    );
    assert!(
        !normalized.headers.contains_key("x-custom"),
        "the contract's custom trailers must not leak into the replacement"
    );
    assert_eq!(
        normalized.headers.get("x-decorated").map(String::as_str),
        Some("kept")
    );
}

/// A mutable `content-type` must not opt a plain HTTP request into the
/// native-gRPC terminate contract.
///
/// `request_transformer` runs before `serverless_function` and can rewrite the
/// effective `content-type` to `application/grpc`. The frontend stamped this
/// request as Plain at intake, and the reject finalizer, the H1/H2 body builder,
/// and the H3 writers all still treat it as ordinary HTTP — so authoring a
/// framed unary response here would put a gRPC frame on an HTTP response.
#[tokio::test]
async fn test_terminate_mode_ignores_rewritten_content_type_on_plain_request() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "grpc_status": 0,
            "message_base64": "CAE="
        })))
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

    // Frontend classification stays Plain (the `create_test_context` default);
    // only the live header was rewritten, exactly as a prior transformer hook
    // would leave it.
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary { body, headers, .. } => {
            assert!(
                !headers.contains_key("grpc-status"),
                "a Plain request must not receive protocol-owned gRPC terminal metadata"
            );
            assert_ne!(
                headers.get("content-type").map(String::as_str),
                Some("application/grpc"),
                "a Plain request must not be relabelled as native gRPC"
            );
            assert!(
                body.starts_with(b"{"),
                "the ordinary HTTP terminate path returns the function body verbatim"
            );
        }
        other => panic!("Expected ordinary HTTP terminate RejectBinary, got {other:?}"),
    }

    let minted = ferrum_edge::_test_support::serverless_grpc_terminate_frame_for_test(&ctx);
    assert!(
        minted.is_none(),
        "no framed-unary provenance may be minted for a Plain request"
    );
}

/// The mirror of the case above: the stamped native-gRPC flavor is what counts,
/// so a prior hook that removed or rewrote the live `content-type` cannot take a
/// genuine gRPC request off the terminate contract.
#[tokio::test]
async fn test_terminate_mode_uses_stamped_grpc_flavor_despite_header_rewrite() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let protobuf = b"\x08\x01";
    let message_base64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, protobuf);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "grpc_status": 0,
            "message_base64": message_base64
        })))
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
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::config::types::HttpFlavor::Grpc,
    );
    // A prior hook replaced the live header; the intake classification stands.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            assert_eq!(body, frame_terminate_message(protobuf));
        }
        other => panic!("Expected framed native-gRPC RejectBinary, got {other:?}"),
    }
}

/// Every dedicated terminal value is bound by the advertised 8 KiB **wire**
/// ceiling, measured after sanitization and after base64 re-encoding.
#[test]
fn test_native_grpc_terminate_bounds_dedicated_terminal_values() {
    use ferrum_edge::plugins::serverless_function::test_helpers::build_native_grpc_terminate_response_test as build;

    const WIRE_CAP: usize = 8 * 1024;
    // Base64 emits four characters per three input bytes, so this is the
    // largest decoded `grpc-status-details-bin` whose wire value still fits.
    const DETAILS_DECODED_CAP: usize = WIRE_CAP / 4 * 3;
    // Generous body ceiling: these bounds must bite on their own rather than
    // being masked by `max_response_body_bytes`.
    const MAX_BODY: usize = 1024 * 1024;

    let message_at_cap = "a".repeat(WIRE_CAP);
    let (_, _, headers) = build(
        200,
        serde_json::to_vec(&json!({ "grpc_status": 0, "grpc_message": message_at_cap }))
            .unwrap()
            .as_slice(),
        MAX_BODY,
    )
    .expect("a grpc_message exactly at the wire cap is accepted");
    assert_eq!(headers.get("grpc-message").map(String::len), Some(WIRE_CAP));

    let message_over_cap = "a".repeat(WIRE_CAP + 1);
    let err = build(
        200,
        serde_json::to_vec(&json!({ "grpc_status": 0, "grpc_message": message_over_cap }))
            .unwrap()
            .as_slice(),
        MAX_BODY,
    )
    .expect_err("one byte over the wire cap is refused");
    assert!(err.contains("grpc_message"), "field-specific detail: {err}");
    assert!(err.contains(&WIRE_CAP.to_string()), "cap in detail: {err}");

    let details_at_cap = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        vec![0xABu8; DETAILS_DECODED_CAP],
    );
    let (_, _, headers) = build(
        200,
        serde_json::to_vec(&json!({
            "grpc_status": 0,
            "status_details_base64": details_at_cap
        }))
        .unwrap()
        .as_slice(),
        MAX_BODY,
    )
    .expect("status details whose re-encoded value is exactly at the cap are accepted");
    assert_eq!(
        headers.get("grpc-status-details-bin").map(String::len),
        Some(WIRE_CAP),
        "the accepted boundary case re-encodes to exactly the wire ceiling"
    );

    // One decoded byte more expands to 8196 base64 characters — the regression
    // this bound closes, since a decoded-byte cap of 8 KiB would have admitted
    // a ~10.9 KiB trailer value.
    let details_over_cap = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        vec![0xABu8; DETAILS_DECODED_CAP + 1],
    );
    let err = build(
        200,
        serde_json::to_vec(&json!({
            "grpc_status": 0,
            "status_details_base64": details_over_cap
        }))
        .unwrap()
        .as_slice(),
        MAX_BODY,
    )
    .expect_err("base64 expansion past the wire cap is refused");
    assert!(
        err.contains("status_details_base64"),
        "field-specific detail: {err}"
    );
    assert!(
        err.contains("grpc-status-details-bin"),
        "the violated ceiling is named: {err}"
    );
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

/// `forward_headers` reads only the effective `before_proxy` header view.
///
/// GHSA-99wm-qwwv-33v9 scope: an earlier plugin that removed a gateway-owned
/// destination — an unfilled `claim_headers` target, or `authorization` under
/// `strip_authorization_on_success` — must not have the client's original value
/// resurrected out of the pristine ingress map and handed to the function.
#[tokio::test]
async fn test_forward_headers_never_resurrect_stripped_client_values() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"{}".to_vec()))
        .mount(&server)
        .await;

    let plugin = ServerlessFunction::new(
        &json!({
            "provider": "azure_functions",
            "function_url": format!("{}/func", server.uri()),
            "mode": "terminate",
            "forward_headers": ["x-authenticated-email", "authorization", "x-request-id"]
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    // Pristine ingress: the client supplied a gateway-owned claim destination
    // and a bearer credential.
    ctx.headers.insert(
        "x-authenticated-email".to_string(),
        "attacker@example.test".to_string(),
    );
    ctx.headers.insert(
        "authorization".to_string(),
        "Bearer client-token".to_string(),
    );

    // Effective view after an auth plugin sanitized its owned destination and
    // stripped the credential it consumed.
    let mut headers = HashMap::from([("x-request-id".to_string(), "req-1".to_string())]);
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 1, "the function must have been invoked");
    let payload: Value = serde_json::from_slice(&requests[0].body).expect("json payload");
    let forwarded = payload
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    assert_eq!(
        forwarded.get("x-request-id").and_then(Value::as_str),
        Some("req-1"),
        "headers present in the effective view are still forwarded: {forwarded:?}"
    );
    assert!(
        !forwarded.contains_key("x-authenticated-email"),
        "a sanitized gateway-owned destination must not be re-read from client input: \
         {forwarded:?}"
    );
    assert!(
        !forwarded.contains_key("authorization"),
        "a stripped credential must not be re-read from client input: {forwarded:?}"
    );
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
        "nested-path-after-base-directory",
        "copied-query-other-host",
        "renamed-query-other-host",
        "copied-query-path-other-host",
        "copied-query-path-parameter",
        "copied-query-encoded-path-delimiter",
        "copied-signed-path-query-value",
        "copied-signed-path-query-key",
        "copied-signed-path-query-value-encoded",
        "key-only-query-renamed-value",
        "key-only-query-copied-key",
        "key-only-query-path",
        "key-only-query-fragment",
        "valued-query-key-renamed-value",
        "valued-query-key-copied-key",
        "valued-query-key-path",
        "valued-query-key-fragment",
        "valued-query-key-slash-boundaries",
        "valued-query-key-slash-boundaries-path",
        "query-value-leading-slash-path",
        "query-value-trailing-slash",
        "query-value-trailing-slash-path",
        "query-value-slash-only",
        "query-value-slash-only-root-path",
        "query-value-slash-only-nonroot-path",
        "authority-query-value",
        "authority-query-key",
        "authority-query-idna",
        "authority-query-port",
        "authority-query-default-https-port",
        "authority-query-default-network-port",
        "query-value-scheme",
        "query-key-scheme",
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
        "benign-signed-path-query-value-lookalike",
        "benign-key-only-query-lookalike",
        "benign-leading-slash-scalar-suffix-lookalike",
        "benign-trailing-slash-scalar-prefix-lookalike",
        "benign-trailing-slash-scalar-without-slash",
        "benign-authority-label-lookalike",
        "benign-authority-substring",
        "benign-nested-path-after-base-directory",
        "benign-authority-default-port-lookalike",
        "benign-scheme-lookalike",
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
            "valued-query-key-renamed-value"
            | "valued-query-key-copied-key"
            | "valued-query-key-path"
            | "valued-query-key-fragment" => {
                format!("{}/signed%2Ftrigger?SIGNED_TOKEN=1", server.uri())
            }
            "valued-query-key-slash-boundaries" | "valued-query-key-slash-boundaries-path" => {
                format!("{}/signed%2Ftrigger?%2FSIGNED%2F=1", server.uri())
            }
            "query-value-leading-slash-path" | "benign-leading-slash-scalar-suffix-lookalike" => {
                format!("{}/signed%2Ftrigger?code=%2Fsigned", server.uri())
            }
            "query-value-trailing-slash"
            | "query-value-trailing-slash-path"
            | "benign-trailing-slash-scalar-prefix-lookalike"
            | "benign-trailing-slash-scalar-without-slash" => {
                format!("{}/signed%2Ftrigger?code=secret%2F", server.uri())
            }
            "query-value-slash-only"
            | "query-value-slash-only-root-path"
            | "query-value-slash-only-nonroot-path" => {
                format!("{}/signed%2Ftrigger?code=%2F", server.uri())
            }
            "authority-query-value"
            | "benign-authority-label-lookalike"
            | "benign-authority-substring" => {
                format!("{}/signed%2Ftrigger?code=signedtoken", server.uri())
            }
            "authority-query-key" => {
                format!("{}/signed%2Ftrigger?signedkey=1", server.uri())
            }
            "authority-query-idna" => {
                format!("{}/signed%2Ftrigger?code=b%C3%BCcher", server.uri())
            }
            "authority-query-port" => {
                format!("{}/signed%2Ftrigger?code=18443", server.uri())
            }
            "authority-query-default-https-port" | "benign-authority-default-port-lookalike" => {
                format!("{}/signed%2Ftrigger?code=443", server.uri())
            }
            "authority-query-default-network-port" => {
                format!("{}/signed%2Ftrigger?code=80", server.uri())
            }
            "query-value-scheme" | "benign-scheme-lookalike" => {
                format!("{}/signed%2Ftrigger?code=secret", server.uri())
            }
            "query-key-scheme" => {
                format!("{}/signed%2Ftrigger?secret=1", server.uri())
            }
            "nested-path-after-base-directory" | "benign-nested-path-after-base-directory" => {
                format!("{}/api/signed?code=secret", server.uri())
            }
            "copied-signed-path-query-value"
            | "copied-signed-path-query-key"
            | "copied-signed-path-query-value-encoded"
            | "benign-signed-path-query-value-lookalike" => {
                format!("{}/api/signed-token", server.uri())
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
            "nested-path-after-base-directory" => {
                url::form_urlencoded::byte_serialize(function_url.as_bytes()).collect()
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
            "copied-signed-path-query-value" => {
                "https://redirect.example/next?leak=api/signed-token".to_string()
            }
            "copied-signed-path-query-key" => {
                "https://redirect.example/next?api/signed-token=other".to_string()
            }
            "copied-signed-path-query-value-encoded" => {
                "https://redirect.example/next?leak=api%252Fsigned-token".to_string()
            }
            "key-only-query-renamed-value" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN".to_string()
            }
            "key-only-query-copied-key" => {
                "https://redirect.example/next?SIGNED_TOKEN=other".to_string()
            }
            "key-only-query-path" => "https://redirect.example/next;leak=SIGNED_TOKEN".to_string(),
            "key-only-query-fragment" => "https://redirect.example/#leak=SIGNED_TOKEN".to_string(),
            "valued-query-key-renamed-value" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN".to_string()
            }
            "valued-query-key-copied-key" => {
                "https://redirect.example/next?SIGNED_TOKEN=other".to_string()
            }
            "valued-query-key-path" => {
                "https://redirect.example/next;leak=SIGNED_TOKEN".to_string()
            }
            "valued-query-key-fragment" => {
                "https://redirect.example/#leak=SIGNED_TOKEN".to_string()
            }
            "valued-query-key-slash-boundaries" => {
                "https://redirect.example/next?leak=%2FSIGNED%2F".to_string()
            }
            "valued-query-key-slash-boundaries-path" => {
                "https://redirect.example/prefix/SIGNED/suffix".to_string()
            }
            "query-value-leading-slash-path" => {
                "https://redirect.example/prefix/signed".to_string()
            }
            "query-value-trailing-slash" => {
                "https://redirect.example/next?leak=secret%2F".to_string()
            }
            "query-value-trailing-slash-path" => {
                "https://redirect.example/prefix/secret/suffix".to_string()
            }
            "query-value-slash-only" => "https://redirect.example/next?leak=%2F".to_string(),
            "query-value-slash-only-root-path" => "https://redirect.example/".to_string(),
            "query-value-slash-only-nonroot-path" => "https://redirect.example/next".to_string(),
            "authority-query-value" => "https://signedtoken.attacker.example/next".to_string(),
            "authority-query-key" => "https://signedkey.attacker.example/next".to_string(),
            "authority-query-idna" => "https://xn--bcher-kva.attacker.example/next".to_string(),
            "authority-query-port" => "https://attacker.example:18443/next".to_string(),
            "authority-query-default-https-port" => "https://attacker.example:443/next".to_string(),
            "authority-query-default-network-port" => "//attacker.example:80/next".to_string(),
            "query-value-scheme" | "query-key-scheme" => {
                "SeCrEt://attacker.example/next".to_string()
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
            "benign-same-origin" => format!("{}/safe?other=1", server.uri()),
            "benign-external" => "https://redirect.example/next?other=1".to_string(),
            "benign-external-label" => {
                // A path-shaped but non-matching query value (lookalike of the
                // signed path `signed/trigger`) must remain observable. An exact
                // copy of the signed path is a renamed disclosure and is covered
                // by `copied-signed-path-query-value`.
                "https://redirect.example/next?label=signed/trigger-extra".to_string()
            }
            "benign-path-lookalike" => {
                "https://redirect.example/signed/triggered?other=1".to_string()
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
            "benign-signed-path-query-value-lookalike" => {
                "https://redirect.example/next?leak=api/signed-token-extra".to_string()
            }
            "benign-key-only-query-lookalike" => {
                "https://redirect.example/next?leak=SIGNED_TOKEN_EXTRA".to_string()
            }
            "benign-leading-slash-scalar-suffix-lookalike" => {
                "https://redirect.example/prefix/signed_extra".to_string()
            }
            "benign-trailing-slash-scalar-prefix-lookalike" => {
                "https://redirect.example/prefixsecret/suffix".to_string()
            }
            "benign-trailing-slash-scalar-without-slash" => {
                "https://redirect.example/next;leak=secret".to_string()
            }
            "benign-authority-label-lookalike" => {
                "https://signedtoken-extra.attacker.example/next".to_string()
            }
            "benign-authority-substring" => {
                "https://prefixsignedtoken.attacker.example/next".to_string()
            }
            "benign-nested-path-after-base-directory" => {
                let benign = "https://redirect.example/safe?other=1";
                url::form_urlencoded::byte_serialize(benign.as_bytes()).collect()
            }
            "benign-authority-default-port-lookalike" => {
                "https://attacker.example:8443/next".to_string()
            }
            "benign-scheme-lookalike" => "secrets://attacker.example/next".to_string(),
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
        "refresh-absolute",
        "refresh-comma-absolute",
        "refresh-whitespace-url",
        "refresh-whitespace-bare-absolute",
        "refresh-repeated-separators",
        "refresh-relative",
        "refresh-encoded",
        "refresh-bare-absolute",
        "refresh-bare-relative",
        "refresh-bare-path-segment",
        "refresh-bare-encoded",
        "refresh-malformed-target",
        "link-absolute",
        "link-relative",
        "link-multiple-targets",
        "link-target-budget",
        "link-malformed",
        "content-location-query-trailing-slash",
        "refresh-query-trailing-slash",
        "link-query-trailing-slash",
        "benign-content-location",
        "benign-refresh",
        "benign-refresh-comma",
        "benign-refresh-bare-target",
        "benign-refresh-whitespace-bare-target",
        "benign-refresh-delay-only",
        "benign-refresh-separator-only",
        "benign-refresh-non-url-directive",
        "benign-link-multiple-targets",
        "benign-link-label",
        "benign-link-path-lookalike",
    ] {
        let server = MockServer::start().await;
        let function_url = if case.ends_with("query-trailing-slash") {
            format!("{}/signed%2Ftrigger?code=secret%2F", server.uri())
        } else {
            format!("{}/signed%2Ftrigger?code=secret%2Fvalue", server.uri())
        };
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
            "refresh-absolute" => {
                ("refresh", format!("0; URL=\"{function_url}\""), true)
            }
            "refresh-comma-absolute" => {
                ("refresh", format!("0, url={function_url}"), true)
            }
            "refresh-whitespace-url" => {
                ("refresh", format!("0 \t url={function_url}"), true)
            }
            "refresh-whitespace-bare-absolute" => {
                ("refresh", format!("0\t{function_url}"), true)
            }
            "refresh-repeated-separators" => (
                "refresh",
                format!("0 \t, ; \t url={function_url}"),
                true,
            ),
            "refresh-relative" => (
                "refresh",
                "0;url=/signed%2Ftrigger?code=secret%2Fvalue".to_string(),
                true,
            ),
            "refresh-encoded" => {
                ("refresh", format!("0; url={encoded_function_url}"), true)
            }
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
            "content-location-query-trailing-slash" => (
                "content-location",
                "https://redirect.example/safe?leak=secret%2F".to_string(),
                true,
            ),
            "refresh-query-trailing-slash" => (
                "refresh",
                "0; url=https://redirect.example/safe?leak=secret%2F".to_string(),
                true,
            ),
            "link-query-trailing-slash" => (
                "link",
                "<https://redirect.example/safe?leak=secret%2F>; rel=\"next\"".to_string(),
                true,
            ),
            "benign-content-location" => {
                ("content-location", "/safe?other=1".to_string(), false)
            }
            "benign-refresh" => {
                ("refresh", "5; URL = '/safe?other=1'".to_string(), false)
            }
            "benign-refresh-comma" => {
                ("refresh", "5, url=/safe?other=1".to_string(), false)
            }
            "benign-refresh-bare-target" => (
                "refresh",
                "5; https://redirect.example/safe?other=1".to_string(),
                false,
            ),
            "benign-refresh-whitespace-bare-target" => (
                "refresh",
                "5 https://redirect.example/safe?other=1".to_string(),
                false,
            ),
            "benign-refresh-delay-only" => ("refresh", "5".to_string(), false),
            "benign-refresh-separator-only" => ("refresh", "5 \t, ;".to_string(), false),
            "benign-refresh-non-url-directive" => {
                ("refresh", "not-a-delay; token=value".to_string(), false)
            }
            "benign-link-multiple-targets" => (
                "link",
                "</safe>; rel=\"prev\", <https://redirect.example/next?other=1>; rel=\"next\"; title=\"a,b\""
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
                "<https://redirect.example/signed/triggered?other=1>; rel=\"next\""
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
async fn test_terminate_rejects_repeated_singleton_url_headers() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Each line is safe in isolation, but the old `", "` fold synthesized
    // the protected `alpha, omega` scalar for a downstream URI parser.
    for (header, first, second) in [
        ("location", "alpha", "omega"),
        ("content-location", "alpha", "omega"),
        ("refresh", "0; alpha", "omega"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header(header, first)
                    .append_header(header, second),
            )
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": format!("{}/signed/trigger?code=alpha%2C%20omega", server.uri()),
                "mode": "terminate"
            }),
            default_client(),
        )
        .unwrap();
        let mut ctx = create_test_context();

        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::RejectBinary { headers, .. } => assert!(
                !headers.contains_key(header),
                "repeated singleton {header} survived: {headers:?}"
            ),
            other => panic!("expected terminal response for {header}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_terminate_revalidates_combined_link_headers() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for should_strip in [false, true] {
        let server = MockServer::start().await;
        let (first, second) = if should_strip {
            (
                (0..16)
                    .map(|index| format!("</first/{index}>; rel=\"item\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                (0..17)
                    .map(|index| format!("</second/{index}>; rel=\"item\""))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        } else {
            (
                "</safe/one>; rel=\"prev\"".to_string(),
                "<https://redirect.example/safe/two>; rel=\"next\"".to_string(),
            )
        };
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("link", first.as_str())
                    .append_header("link", second.as_str()),
            )
            .mount(&server)
            .await;
        let plugin = ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": format!("{}/signed/trigger?code=secret", server.uri()),
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
                        !headers.contains_key("link"),
                        "combined Link target budget was not enforced: {headers:?}"
                    );
                } else {
                    let expected = format!("{first}, {second}");
                    assert_eq!(
                        headers.get("link").map(String::as_str),
                        Some(expected.as_str())
                    );
                }
            }
            other => panic!("expected terminal Link response, got {other:?}"),
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
            // HEAD keeps representation Content-Length while omitting content.
            assert_eq!(
                headers.get("content-length").map(String::as_str),
                Some("13")
            );
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
async fn test_forward_body_preserves_exact_bytes_and_active_content_type() {
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

    let mut text_ctx = create_test_context();
    text_ctx.method = "POST".to_string();
    text_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    let duplicate_key_json = br#"{ "trusted": 1e0, "trusted": 2 }"#;
    text_ctx.request_body_bytes = Some(Bytes::from_static(duplicate_key_json));
    let mut transformed_headers = HashMap::new();
    transformed_headers.insert("content-type".to_string(), "application/json".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut text_ctx, &mut transformed_headers)
            .await,
        PluginResult::Continue
    ));

    let mut json_ctx = create_test_context();
    json_ctx.method = "POST".to_string();
    json_ctx.headers.insert(
        "content-type".to_string(),
        "application/problem+json; charset=utf-8".to_string(),
    );
    json_ctx.request_body_bytes = Some(Bytes::from_static(br#"{"trusted":true}"#));
    let mut transformed_headers = HashMap::new();
    transformed_headers.insert("content-type".to_string(), "text/plain".to_string());
    assert!(matches!(
        plugin
            .before_proxy(&mut json_ctx, &mut transformed_headers)
            .await,
        PluginResult::Continue
    ));

    let requests = server.received_requests().await.unwrap();
    let text_payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let json_payload: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        text_payload["body"].as_str(),
        Some(std::str::from_utf8(duplicate_key_json).unwrap())
    );
    assert_eq!(text_payload["body_encoding"], "utf8");
    assert_eq!(text_payload["body_content_type"], "application/json");
    assert_eq!(json_payload["body"], r#"{"trusted":true}"#);
    assert_eq!(json_payload["body_encoding"], "utf8");
    assert_eq!(json_payload["body_content_type"], "text/plain");
}

#[tokio::test]
async fn configured_decompression_exposes_plaintext_before_serverless_dispatch() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(2)
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
    let plaintext = br#"{"decision":"deny","reason":"sensitive"}"#;

    for encoding in ["gzip", "br"] {
        let (mut ctx, mut headers, _) = normalize_compressed_request_for_plugin_test(
            "application/json",
            "/serverless",
            encoding,
            plaintext,
        )
        .await;
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        let payload: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(payload["body"], std::str::from_utf8(plaintext).unwrap());
        assert_eq!(payload["body_encoding"], "utf8");
        assert_eq!(payload["body_content_type"], "application/json");
    }
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
async fn test_original_content_encoding_marker_fails_before_external_egress() {
    // Mirror of `ORIGIN_ENCODED_REQUEST_METADATA_KEY` (pub(crate) in proxy). A
    // header-only request_transformer that removed/renamed Content-Encoding
    // before this plugin leaves the transformed header map identity-clean, but
    // the init-time marker preserves the original non-identity coding.
    const ORIGIN_ENCODED_REQUEST_METADATA_KEY: &str = "ferrum:origin_encoded_request";

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

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.request_body_bytes = Some(Bytes::from_static(b"opaque-compressed"));
    // The live header map carries NO content-encoding (a transformer stripped
    // it), yet the original request declared one — captured in the marker.
    ctx.metadata.insert(
        ORIGIN_ENCODED_REQUEST_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("encoded_request_body_unsupported"));
        }
        other => panic!("stripped-but-original encoding must fail closed, got {other:?}"),
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_query_transform_is_forwarded_in_function_payload() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
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

    let mut ctx = create_test_context();
    // Simulate request_transformer publishing an ordered outbound query after
    // removing a credential and updating a page parameter.
    ctx.set_raw_query_string("access_token=secret&page=1&keep=1".to_string());
    ctx.publish_transformed_query(
        "page=2&keep=1".to_string(),
        [
            ("page".to_string(), "2".to_string()),
            ("keep".to_string(), "1".to_string()),
        ]
        .into_iter()
        .collect(),
    );
    ctx.metadata.insert(
        "ferrum:query_params_transformed".to_string(),
        "true".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "canonical outbound query must be forwardable, got {result:?}"
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let params = body["query_params"].as_object().unwrap();
    assert_eq!(params.get("page").and_then(|v| v.as_str()), Some("2"));
    assert_eq!(params.get("keep").and_then(|v| v.as_str()), Some("1"));
    assert!(
        !params.contains_key("access_token"),
        "removed credential must not appear in function payload"
    );
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
async fn test_query_forwarding_omits_only_credentials_marked_for_backend_stripping() {
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
    ctx.set_raw_query_string(
        "api_key=first-secret&keep=visible%20value&API_KEY=case-visible&api%5Fkey=second-secret&api_key_suffix=visible-suffix&note=api_key&flag"
            .to_string(),
    );
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Continue
    ));
    let requests = server.received_requests().await.unwrap();
    let payload: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let serialized_payload = serde_json::to_string(&payload).unwrap();
    assert!(!serialized_payload.contains("first-secret"));
    assert!(!serialized_payload.contains("second-secret"));
    let params = payload["query_params"].as_object().unwrap();
    assert_eq!(params.len(), 5);
    assert_eq!(
        params.get("keep").and_then(Value::as_str),
        Some("visible value")
    );
    assert_eq!(
        params.get("API_KEY").and_then(Value::as_str),
        Some("case-visible")
    );
    assert_eq!(
        params.get("api_key_suffix").and_then(Value::as_str),
        Some("visible-suffix")
    );
    assert_eq!(params.get("note").and_then(Value::as_str), Some("api_key"));
    assert_eq!(params.get("flag").and_then(Value::as_str), Some(""));
    assert!(!params.contains_key("api_key"));

    let mut duplicate_ctx = create_test_context();
    duplicate_ctx.set_raw_query_string(
        "api_key=hidden&role=user&api%5Fkey=also-hidden&r%6Fle=admin".to_string(),
    );
    duplicate_ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );
    match plugin
        .before_proxy(&mut duplicate_ctx, &mut HashMap::new())
        .await
    {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("duplicate_query_parameter"));
        }
        other => panic!("allowed duplicate names must still fail closed, got {other:?}"),
    }

    let mut invalid_encoding_ctx = create_test_context();
    invalid_encoding_ctx.set_raw_query_string("api_key=hidden&visible=%FF".to_string());
    invalid_encoding_ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );
    match plugin
        .before_proxy(&mut invalid_encoding_ctx, &mut HashMap::new())
        .await
    {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("invalid_query_encoding"));
        }
        other => panic!("hostile encoding must still fail closed, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let _lock = ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
