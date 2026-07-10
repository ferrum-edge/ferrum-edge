//! Serverless Function Plugin
//!
//! Calls serverless functions on AWS Lambda, Azure Functions, or Google Cloud
//! Functions as part of the proxy pipeline. Supports two modes:
//!
//! - **pre_proxy**: Invoke the function with request context, use the response
//!   to inject/modify headers before the request is proxied to the backend.
//! - **terminate**: Invoke the function and return its response directly to the
//!   client, bypassing backend proxying entirely.
//!
//! ## Providers
//!
//! - **AWS Lambda**: Uses the Lambda Invoke API with SigV4 request signing.
//!   Requires `aws_region`, `aws_access_key_id`, `aws_secret_access_key`,
//!   and `aws_function_name`.
//! - **Azure Functions**: Calls the function's HTTP trigger URL with optional
//!   function key authentication via `x-functions-key` header.
//! - **GCP Cloud Functions**: Calls the function's HTTPS trigger URL with
//!   optional bearer token authentication.
//!
//! ## Environment Variable Fallback
//!
//! Cloud credential fields fall back to well-known environment variables when
//! not set in the plugin config. Config values always take precedence.
//!
//! | Config Field | Env Var Fallback |
//! |---|---|
//! | `aws_region` | `AWS_DEFAULT_REGION`, then `AWS_REGION` |
//! | `aws_access_key_id` | `AWS_ACCESS_KEY_ID` |
//! | `aws_secret_access_key` | `AWS_SECRET_ACCESS_KEY` |
//! | `aws_function_name` | `AWS_LAMBDA_FUNCTION_NAME` |
//! | `aws_session_token` | `AWS_SESSION_TOKEN` |
//! | `azure_function_key` | `AZURE_FUNCTIONS_KEY` |
//! | `gcp_bearer_token` | `GCP_CLOUD_FUNCTIONS_BEARER_TOKEN` |
//!
//! These env vars may themselves be resolved by the gateway's external secret
//! resolution system (Vault, AWS Secrets Manager, etc.) via the `_VAULT`,
//! `_AWS`, `_AZURE`, `_GCP`, `_FILE`, or `_ENV` suffixes.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "provider": "aws_lambda",
//!   "mode": "pre_proxy",
//!   "function_url": "https://my-func.azurewebsites.net/api/transform",
//!   "aws_region": "us-east-1",
//!   "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
//!   "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//!   "aws_function_name": "my-function",
//!   "aws_qualifier": "$LATEST",
//!   "azure_function_key": "my-function-key",
//!   "gcp_bearer_token": "ya29.example-token",
//!   "forward_body": true,
//!   "forward_headers": ["x-request-id", "authorization"],
//!   "forward_query_params": true,
//!   "timeout_ms": 5000,
//!   "max_response_body_bytes": 10485760,
//!   "on_error": "reject",
//!   "error_status_code": 502
//! }
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info, warn};
use url::{Host, Url};

use super::utils::aws_sigv4;
use super::utils::response_body::{
    BoundedReadError, parse_max_response_body_bytes, read_response_body_bounded,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

/// Cloud provider for the serverless function.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Provider {
    AwsLambda,
    AzureFunctions,
    GcpCloudFunctions,
}

/// What to do with the function's response.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InvocationMode {
    /// Call function, inject response headers, continue proxying.
    PreProxy,
    /// Call function, return its response directly to the client.
    Terminate,
}

/// What to do when the function call fails.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorAction {
    Continue,
    Reject,
}

/// AWS Lambda–specific configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AwsLambdaConfig {
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    function_name: String,
    qualifier: Option<String>,
}

pub struct ServerlessFunction {
    http_client: PluginHttpClient,
    provider: Provider,
    mode: InvocationMode,
    /// For Azure/GCP: the user-supplied URL. For AWS: the computed Lambda Invoke API URL.
    function_url: String,
    function_hostname: Option<String>,
    aws_config: Option<AwsLambdaConfig>,
    azure_function_key: Option<String>,
    gcp_authorization_header: Option<String>,
    forward_body: bool,
    forward_headers: Vec<String>,
    forward_query_params: bool,
    timeout_ms: u64,
    max_response_body_bytes: usize,
    on_error: ErrorAction,
    error_status_code: u16,
    /// Pre-computed: plugin needs request body buffered.
    requires_body: bool,
}

impl ServerlessFunction {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("serverless_function: config must be an object".to_string());
        }

        let provider = match config["provider"].as_str() {
            Some("aws_lambda") => Provider::AwsLambda,
            Some("azure_functions") => Provider::AzureFunctions,
            Some("gcp_cloud_functions") => Provider::GcpCloudFunctions,
            Some(other) => {
                return Err(format!(
                    "serverless_function: unknown provider '{}' — must be 'aws_lambda', \
                     'azure_functions', or 'gcp_cloud_functions'",
                    other
                ));
            }
            None => {
                return Err(
                    "serverless_function: 'provider' is required — must be 'aws_lambda', \
                     'azure_functions', or 'gcp_cloud_functions'"
                        .to_string(),
                );
            }
        };

        // Strict mode validation. Silently defaulting an unknown value (e.g.
        // a typo'd "terminat") to `pre_proxy` would mask configuration errors
        // and silently change semantic intent.
        let mode = match config.get("mode") {
            Some(Value::String(s)) => match s.as_str() {
                "pre_proxy" => InvocationMode::PreProxy,
                "terminate" => InvocationMode::Terminate,
                other => {
                    return Err(format!(
                        "serverless_function: unknown mode '{other}' (expected 'pre_proxy' or 'terminate')"
                    ));
                }
            },
            Some(Value::Null) | None => InvocationMode::PreProxy,
            Some(_) => {
                return Err("serverless_function: 'mode' must be a string".to_string());
            }
        };

        let forward_body = optional_bool(config, "forward_body")?.unwrap_or(false);
        let forward_query_params = optional_bool(config, "forward_query_params")?.unwrap_or(false);

        let forward_headers = parse_forward_headers(config)?;

        let timeout_ms = optional_u64(config, "timeout_ms")?.unwrap_or(5000);
        if timeout_ms == 0 {
            return Err("serverless_function: timeout_ms must be > 0".to_string());
        }

        let max_response_body_bytes = parse_max_response_body_bytes(
            config,
            "serverless_function",
            "max_response_body_bytes",
            10 * 1024 * 1024,
        )?;

        // Strict `on_error` validation — a typo here changes whether a function
        // failure rejects the request or silently continues, so silent
        // defaulting is unacceptable.
        let on_error = match config.get("on_error") {
            Some(Value::String(s)) => match s.as_str() {
                "reject" => ErrorAction::Reject,
                "continue" => ErrorAction::Continue,
                other => {
                    return Err(format!(
                        "serverless_function: unknown on_error '{other}' (expected 'reject' or 'continue')"
                    ));
                }
            },
            Some(Value::Null) | None => ErrorAction::Reject,
            Some(_) => {
                return Err("serverless_function: 'on_error' must be a string".to_string());
            }
        };

        let raw_status = optional_u64(config, "error_status_code")?.unwrap_or(502);
        if !(100..=599).contains(&raw_status) {
            return Err(format!(
                "serverless_function: error_status_code must be in range 100-599 (got {raw_status})"
            ));
        }
        let error_status_code = raw_status as u16;

        // Provider-specific config + URL construction.
        // Config fields take precedence; well-known env vars are used as fallback.
        let (function_url, aws_config, azure_function_key, gcp_authorization_header) =
            match &provider {
                Provider::AwsLambda => {
                    let region = optional_config_string(config, "aws_region")?
                        .or_else(|| env_non_empty("AWS_DEFAULT_REGION"))
                        .or_else(|| env_non_empty("AWS_REGION"))
                        .ok_or_else(|| {
                            "serverless_function: 'aws_region' is required for aws_lambda \
                         (or set AWS_DEFAULT_REGION / AWS_REGION env var)"
                                .to_string()
                        })?;

                    let access_key_id = optional_config_string(config, "aws_access_key_id")?
                        .or_else(|| env_non_empty("AWS_ACCESS_KEY_ID"))
                        .ok_or_else(|| {
                            "serverless_function: 'aws_access_key_id' is required for aws_lambda \
                         (or set AWS_ACCESS_KEY_ID env var)"
                                .to_string()
                        })?;

                    let secret_access_key = optional_config_string(
                        config,
                        "aws_secret_access_key",
                    )?
                    .or_else(|| env_non_empty("AWS_SECRET_ACCESS_KEY"))
                    .ok_or_else(|| {
                        "serverless_function: 'aws_secret_access_key' is required for aws_lambda \
                             (or set AWS_SECRET_ACCESS_KEY env var)"
                            .to_string()
                    })?;

                    let function_name = optional_config_string(config, "aws_function_name")?
                        .or_else(|| env_non_empty("AWS_LAMBDA_FUNCTION_NAME"))
                        .ok_or_else(|| {
                            "serverless_function: 'aws_function_name' is required for aws_lambda \
                         (or set AWS_LAMBDA_FUNCTION_NAME env var)"
                                .to_string()
                        })?;

                    let session_token = optional_config_string(config, "aws_session_token")?
                        .or_else(|| env_non_empty("AWS_SESSION_TOKEN"));

                    let qualifier = optional_config_string(config, "aws_qualifier")?;

                    // Optional override for the AWS Lambda endpoint base URL.
                    // Defaults to the public Lambda endpoint for the region.
                    // Primarily used by integration tests against a mock
                    // server; supports LocalStack / VPC-internal Lambda endpoints
                    // too. Must be a fully-formed http(s) URL with no path.
                    //
                    // Validate at plugin construction (same `validate_function_url`
                    // used by the Azure/GCP `function_url` paths) so a malformed
                    // value — e.g. `localhost:4566` without a scheme, or
                    // `tcp://…` — surfaces as a deterministic startup/config
                    // error instead of a per-request invoke failure later.
                    let endpoint_override = optional_config_string(config, "aws_endpoint_url")?
                        .or_else(|| env_non_empty("AWS_LAMBDA_ENDPOINT_URL"));
                    if let Some(ref endpoint) = endpoint_override {
                        validate_http_url_field(endpoint, "aws_endpoint_url")?;
                    }

                    // Log which values came from env vars (without leaking secrets)
                    if config["aws_region"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .is_none()
                    {
                        info!("serverless_function: aws_region resolved from environment variable");
                    }
                    if config["aws_access_key_id"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .is_none()
                    {
                        info!(
                            "serverless_function: aws_access_key_id resolved from environment variable"
                        );
                    }

                    // Build the Lambda Invoke API URL. `aws_endpoint_url`
                    // (or `AWS_LAMBDA_ENDPOINT_URL`) overrides the public
                    // Lambda host so tests and on-prem/LocalStack deployments
                    // can route invocations to a mock or VPC-internal endpoint.
                    let base = endpoint_override
                        .as_deref()
                        .map(|s| s.trim_end_matches('/').to_string())
                        .unwrap_or_else(|| format!("https://lambda.{region}.amazonaws.com"));
                    let mut url =
                        format!("{base}/2015-03-31/functions/{function_name}/invocations");
                    if let Some(ref q) = qualifier {
                        url.push_str("?Qualifier=");
                        url.push_str(&aws_sigv4::uri_encode(q, true));
                    }

                    let aws_cfg = AwsLambdaConfig {
                        region,
                        access_key_id,
                        secret_access_key,
                        session_token,
                        function_name,
                        qualifier,
                    };

                    (url, Some(aws_cfg), None, None)
                }
                Provider::AzureFunctions => {
                    let url = optional_config_string(config, "function_url")?.ok_or_else(|| {
                        "serverless_function: 'function_url' is required for azure_functions"
                            .to_string()
                    })?;

                    validate_function_url(&url)?;

                    let key = optional_config_string(config, "azure_function_key")?
                        .or_else(|| env_non_empty("AZURE_FUNCTIONS_KEY"));
                    if config["azure_function_key"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .is_none()
                        && key.is_some()
                    {
                        info!(
                            "serverless_function: azure_function_key resolved from AZURE_FUNCTIONS_KEY env var"
                        );
                    }

                    (url, None, key, None)
                }
                Provider::GcpCloudFunctions => {
                    let url = optional_config_string(config, "function_url")?.ok_or_else(|| {
                        "serverless_function: 'function_url' is required for gcp_cloud_functions"
                            .to_string()
                    })?;

                    validate_function_url(&url)?;

                    let token = optional_config_string(config, "gcp_bearer_token")?
                        .or_else(|| env_non_empty("GCP_CLOUD_FUNCTIONS_BEARER_TOKEN"));
                    if config["gcp_bearer_token"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .is_none()
                        && token.is_some()
                    {
                        info!(
                            "serverless_function: gcp_bearer_token resolved from GCP_CLOUD_FUNCTIONS_BEARER_TOKEN env var"
                        );
                    }

                    let authorization_header = token.map(|token| {
                        let mut value = String::with_capacity("Bearer ".len() + token.len());
                        value.push_str("Bearer ");
                        value.push_str(&token);
                        value
                    });

                    (url, None, None, authorization_header)
                }
            };

        // Extract hostname for DNS warmup
        let function_hostname = Url::parse(&function_url)
            .ok()
            .and_then(|u| http_url_hostname(&u, "function_url").ok());

        let requires_body = forward_body;

        Ok(Self {
            http_client,
            provider,
            mode,
            function_url,
            function_hostname,
            aws_config,
            azure_function_key,
            gcp_authorization_header,
            forward_body,
            forward_headers,
            forward_query_params,
            timeout_ms,
            max_response_body_bytes,
            on_error,
            error_status_code,
            requires_body,
        })
    }

    /// Build the JSON payload sent to the serverless function.
    fn build_invocation_payload(
        &self,
        ctx: &RequestContext,
        proxy_headers: &HashMap<String, String>,
    ) -> Value {
        let mut payload = serde_json::Map::new();

        payload.insert("method".into(), Value::String(ctx.method.clone()));
        payload.insert("path".into(), Value::String(ctx.path.clone()));
        payload.insert("client_ip".into(), Value::String(ctx.client_ip.clone()));

        if let Some(ref consumer) = ctx.identified_consumer {
            payload.insert(
                "consumer_username".into(),
                Value::String(consumer.username.clone()),
            );
        }

        if let Some(ref identity) = ctx.authenticated_identity {
            payload.insert(
                "authenticated_identity".into(),
                Value::String(identity.clone()),
            );
        }

        // Forward selected headers
        if !self.forward_headers.is_empty() {
            let mut headers_map = serde_json::Map::new();
            for key in &self.forward_headers {
                // Check both proxy headers and original request headers
                if let Some(val) = proxy_headers.get(key).or_else(|| ctx.headers.get(key)) {
                    headers_map.insert(key.clone(), Value::String(val.clone()));
                }
            }
            if !headers_map.is_empty() {
                payload.insert("headers".into(), Value::Object(headers_map));
            }
        }

        // Forward query params
        if self.forward_query_params && !ctx.query_params.is_empty() {
            let params: serde_json::Map<String, Value> = ctx
                .query_params
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            payload.insert("query_params".into(), Value::Object(params));
        }

        // Forward request body
        if self.forward_body
            && let Some(body) = ctx.metadata.get("request_body")
        {
            // Try to parse as JSON for structured forwarding, otherwise send as string
            if let Ok(json_body) = serde_json::from_str::<Value>(body) {
                payload.insert("body".into(), json_body);
            } else {
                payload.insert("body".into(), Value::String(body.clone()));
            }
        }

        Value::Object(payload)
    }

    /// Invoke the serverless function and return (status_code, headers, body_bytes).
    async fn invoke(
        &self,
        payload: &Value,
        ctx: &RequestContext,
    ) -> Result<(u16, HashMap<String, String>, Bytes), String> {
        let payload_bytes = serde_json::to_vec(payload)
            .map_err(|e| format!("serverless_function: failed to serialize payload: {e}"))?;

        let mut req_builder = self
            .http_client
            .get()
            .post(&self.function_url)
            .header("content-type", "application/json")
            .timeout(std::time::Duration::from_millis(self.timeout_ms));

        // Provider-specific auth
        match &self.provider {
            Provider::AwsLambda => {
                if let Some(ref aws) = self.aws_config {
                    let now = Utc::now();
                    let auth_headers =
                        sign_aws_request(aws, &self.function_url, &payload_bytes, &now)?;
                    for (k, v) in &auth_headers {
                        req_builder = req_builder.header(k.as_str(), v.as_str());
                    }
                }
            }
            Provider::AzureFunctions => {
                if let Some(ref key) = self.azure_function_key {
                    req_builder = req_builder.header("x-functions-key", key.as_str());
                }
            }
            Provider::GcpCloudFunctions => {
                if let Some(ref auth_header) = self.gcp_authorization_header {
                    req_builder = req_builder.header("authorization", auth_header.as_str());
                }
            }
        }

        let request = req_builder.body(payload_bytes);

        let response = self
            .http_client
            .execute_tracked(request, "serverless_function", &ctx.plugin_http_call_ns)
            .await
            .map_err(|e| format!("serverless_function: invocation failed: {e}"))?;

        let status = response.status().as_u16();

        let response_headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
            .collect();

        // Stream the response body with a hard cap. Calling `.bytes().await`
        // would buffer the whole payload before any size check fires — a
        // misbehaving function could exhaust gateway memory regardless of
        // `max_response_body_bytes`. The bounded reader aborts the stream as
        // soon as the running total crosses the limit.
        let body = read_response_body_bounded(response, self.max_response_body_bytes)
            .await
            .map_err(|e| match e {
                BoundedReadError::LimitExceeded { .. } => format!("serverless_function: {e}"),
                BoundedReadError::Stream(_) => {
                    format!("serverless_function: failed to read response body: {e}")
                }
            })?;

        // AWS Lambda returns HTTP 200 even on function errors, signaling via
        // X-Amz-Function-Error header. Treat this as an invocation failure.
        if self.provider == Provider::AwsLambda
            && let Some(error_type) = response_headers.get("x-amz-function-error")
        {
            return Err(format!(
                "serverless_function: Lambda function error ({})",
                error_type,
            ));
        }

        Ok((status, response_headers, body))
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("serverless_function: '{key}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("serverless_function: '{key}' must be an unsigned integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "serverless_function: '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_config_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok((!value.is_empty()).then(|| value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("serverless_function: '{key}' must be a string")),
    }
}

fn env_non_empty(env_var: &str) -> Option<String> {
    std::env::var(env_var).ok().filter(|s| !s.is_empty())
}

fn parse_forward_headers(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("forward_headers") else {
        return Ok(Vec::new());
    };

    let Value::Array(headers) = value else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err("serverless_function: 'forward_headers' must be an array".to_string());
    };

    let mut parsed = Vec::with_capacity(headers.len());
    for (idx, header) in headers.iter().enumerate() {
        let name = header.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
            format!("serverless_function: forward_headers[{idx}] must be a non-empty string")
        })?;
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            format!("serverless_function: forward_headers[{idx}] is not a valid HTTP header name")
        })?;
        parsed.push(name.to_ascii_lowercase());
    }

    Ok(parsed)
}

/// Escape special characters for safe JSON string interpolation.
fn escape_json_string(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            ch if ch < '\u{20}' => {
                escaped.push_str("\\u00");
                let byte = ch as u8;
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

/// Validate a function URL (Azure/GCP `function_url`).
fn validate_function_url(url: &str) -> Result<(), String> {
    validate_http_url_field(url, "function_url")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serverless_escape_json_string_round_trips_control_characters() {
        let raw = "invoke failed\"\n<script>\u{00}\u{1f}\\";
        let body = format!(r#"{{"details":"{}"}}"#, escape_json_string(raw));
        let parsed: Value =
            serde_json::from_str(&body).expect("escaped serverless error should be valid JSON");

        assert_eq!(parsed["details"], raw);
        assert!(!escape_json_string(raw).chars().any(|ch| ch < '\u{20}'));
    }
}

/// Shared HTTP(S) URL validator for `function_url` (Azure/GCP) and the AWS
/// Lambda `aws_endpoint_url` override. Surfaces the field name in the error
/// so operators see exactly which config key was rejected.
fn validate_http_url_field(url: &str, field: &str) -> Result<(), String> {
    let parsed =
        Url::parse(url).map_err(|e| format!("serverless_function: invalid {field}: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "serverless_function: {field} must use http:// or https:// (got '{scheme}')"
            ));
        }
    }

    if !has_non_empty_authority(url) {
        return Err(format!(
            "serverless_function: {field} must include a hostname or IP address"
        ));
    }
    http_url_hostname(&parsed, field)?;

    Ok(())
}

fn http_url_hostname(parsed: &Url, field: &str) -> Result<String, String> {
    let host = parsed.host().ok_or_else(|| {
        format!("serverless_function: {field} must include a hostname or IP address")
    })?;

    Ok(match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn has_non_empty_authority(url: &str) -> bool {
    let Some((_, after_scheme)) = url.split_once(':') else {
        return false;
    };
    let Some(authority_and_path) = after_scheme.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    authority_end > 0
}

fn contains_json_ascii(value: &str) -> bool {
    value
        .as_bytes()
        .windows(b"json".len())
        .any(|window| window.eq_ignore_ascii_case(b"json"))
}

fn starts_with_grpc_content_type(value: &str) -> bool {
    value
        .as_bytes()
        .get(..b"application/grpc".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"application/grpc"))
}

// ---------------------------------------------------------------------------
// AWS SigV4 request signing — delegates to shared utils::aws_sigv4 module
// ---------------------------------------------------------------------------

/// Sign an AWS Lambda Invoke API request using SigV4.
/// Returns the headers that must be added to the request.
fn sign_aws_request(
    aws: &AwsLambdaConfig,
    url_str: &str,
    payload: &[u8],
    now: &chrono::DateTime<Utc>,
) -> Result<Vec<(String, String)>, String> {
    let config = aws_sigv4::AwsSigV4Config {
        region: aws.region.clone(),
        access_key_id: aws.access_key_id.clone(),
        secret_access_key: aws.secret_access_key.clone(),
        session_token: aws.session_token.clone(),
    };
    aws_sigv4::sign_request(
        &config,
        "lambda",
        "POST",
        url_str,
        "application/json",
        payload,
        now,
    )
}

/// Test helpers — exposed for unit tests.
#[doc(hidden)]
#[allow(dead_code)]
pub mod test_helpers {
    use super::*;

    /// Expose SigV4 signing for deterministic unit testing.
    /// `aws_config` is a JSON object with `region`, `access_key_id`, `secret_access_key`,
    /// `function_name`.
    pub fn sign_aws_request_test(
        aws_config: &Value,
        url: &str,
        payload: &[u8],
        now: &chrono::DateTime<Utc>,
    ) -> Result<Vec<(String, String)>, String> {
        let config = aws_sigv4::AwsSigV4Config {
            region: aws_config["region"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            access_key_id: aws_config["access_key_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            secret_access_key: aws_config["secret_access_key"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            session_token: aws_config["session_token"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
        };
        aws_sigv4::sign_request(
            &config,
            "lambda",
            "POST",
            url,
            "application/json",
            payload,
            now,
        )
    }
}

#[async_trait]
impl Plugin for ServerlessFunction {
    fn name(&self) -> &str {
        "serverless_function"
    }

    fn priority(&self) -> u16 {
        super::priority::SERVERLESS_FUNCTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.mode == InvocationMode::PreProxy
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.requires_body
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.requires_body
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| contains_json_ascii(ct))
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.function_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx
            .metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str)
            == Some("true")
        {
            return PluginResult::Continue;
        }

        // Terminate mode is incompatible with gRPC: the gateway normalizes
        // RejectBinary into trailers-only gRPC errors, dropping the body.
        // Fail clearly rather than silently losing the function response.
        if self.mode == InvocationMode::Terminate {
            let is_grpc = headers
                .get("content-type")
                .is_some_and(|ct| starts_with_grpc_content_type(ct));
            if is_grpc {
                warn!(
                    "serverless_function: terminate mode is not supported for gRPC requests — \
                     the gateway normalizes plugin rejects into trailers-only gRPC errors"
                );
                return PluginResult::Reject {
                    status_code: 500,
                    body: r#"{"error":"serverless_function terminate mode is not supported for gRPC"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        }

        let payload = self.build_invocation_payload(ctx, headers);

        let (status, response_headers, body) = match self.invoke(&payload, ctx).await {
            Ok(result) => result,
            Err(err) => {
                warn!("serverless_function: {}", err);
                return match self.on_error {
                    ErrorAction::Continue => {
                        ctx.metadata
                            .insert("serverless_function_error".to_string(), err.clone());
                        PluginResult::Continue
                    }
                    ErrorAction::Reject => PluginResult::Reject {
                        status_code: self.error_status_code,
                        body: format!(
                            r#"{{"error":"serverless function invocation failed","details":"{}"}}"#,
                            escape_json_string(&err)
                        ),
                        headers: HashMap::new(),
                    },
                };
            }
        };

        match self.mode {
            InvocationMode::Terminate => {
                // Return the function's response directly to the client
                debug!(
                    "serverless_function: terminate mode — returning function response (status {})",
                    status
                );
                let mut resp_headers = HashMap::new();
                // Forward content-type from function response
                if let Some(ct) = response_headers.get("content-type") {
                    resp_headers.insert("content-type".to_string(), ct.clone());
                }
                PluginResult::RejectBinary {
                    status_code: status,
                    body,
                    headers: resp_headers,
                }
            }
            InvocationMode::PreProxy => {
                // Check for function-level rejection
                if status >= 400 {
                    warn!(
                        "serverless_function: function returned status {} in pre_proxy mode",
                        status
                    );
                    return match self.on_error {
                        ErrorAction::Continue => {
                            ctx.metadata.insert(
                                "serverless_function_status".to_string(),
                                status.to_string(),
                            );
                            PluginResult::Continue
                        }
                        ErrorAction::Reject => PluginResult::Reject {
                            status_code: status,
                            body: String::from_utf8_lossy(&body).into_owned(),
                            headers: HashMap::new(),
                        },
                    };
                }

                // Parse the response body as JSON to extract headers to inject
                if let Ok(resp_json) = serde_json::from_slice::<Value>(&body) {
                    // Inject headers from response: { "headers": { "X-Custom": "value" } }
                    if let Some(header_map) = resp_json.get("headers").and_then(|h| h.as_object()) {
                        for (key, val) in header_map {
                            if let Some(v) = val.as_str() {
                                headers.insert(key.to_ascii_lowercase(), v.to_string());
                            }
                        }
                    }

                    // Store metadata from response: { "metadata": { "key": "value" } }
                    if let Some(meta_map) = resp_json.get("metadata").and_then(|m| m.as_object()) {
                        for (key, val) in meta_map {
                            if let Some(v) = val.as_str() {
                                let mut metadata_key =
                                    String::with_capacity("serverless_".len() + key.len());
                                metadata_key.push_str("serverless_");
                                metadata_key.push_str(key);
                                ctx.metadata.insert(metadata_key, v.to_string());
                            }
                        }
                    }
                }

                PluginResult::Continue
            }
        }
    }
}
