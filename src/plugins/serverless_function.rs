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
use base64::Engine as _;
use bytes::Bytes;
use chrono::Utc;
use http::header::{HeaderName, HeaderValue};
use percent_encoding::percent_decode_str;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{debug, info, warn};
use url::{Host, Url};

use super::utils::aws_sigv4;
use super::utils::response_body::{
    BoundedReadError, parse_max_response_body_bytes, read_response_body_bounded,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const ALLOWED_CONFIG_FIELDS: &[&str] = &[
    "provider",
    "mode",
    "function_url",
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
];

const DEFAULT_INSTANCE_ID: &str = "standalone";

#[derive(Debug)]
struct InvocationFailure {
    code: &'static str,
    operator_detail: String,
    must_reject: bool,
}

impl InvocationFailure {
    fn new(code: &'static str, operator_detail: impl Into<String>) -> Self {
        Self {
            code,
            operator_detail: operator_detail.into(),
            must_reject: false,
        }
    }

    fn governed_input(code: &'static str, operator_detail: impl Into<String>) -> Self {
        Self {
            code,
            operator_detail: operator_detail.into(),
            must_reject: true,
        }
    }
}

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
#[derive(Clone)]
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
    /// Parsed destination used to prevent signed path/query credentials from
    /// returning to clients through function-controlled URL-valued headers.
    function_destination: FunctionDestination,
    /// Credential-safe structural form used in every diagnostic and client error path.
    function_display_url: String,
    function_hostname: Option<String>,
    metadata_prefix: String,
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
        Self::new_with_instance_id(config, http_client, DEFAULT_INSTANCE_ID)
    }

    pub(crate) fn new_with_instance_id(
        config: &Value,
        http_client: PluginHttpClient,
        instance_id: &str,
    ) -> Result<Self, String> {
        let config_object = config
            .as_object()
            .ok_or_else(|| "serverless_function: config must be an object".to_string())?;

        let mut unknown_fields: Vec<&str> = config_object
            .keys()
            .map(String::as_str)
            .filter(|key| !ALLOWED_CONFIG_FIELDS.contains(key))
            .collect();
        unknown_fields.sort_unstable();
        if !unknown_fields.is_empty() {
            return Err(format!(
                "serverless_function: unknown configuration field(s): {}",
                unknown_fields.join(", ")
            ));
        }
        if let Some((key, _)) = config_object.iter().find(|(_, value)| value.is_null()) {
            return Err(format!(
                "serverless_function: '{key}' must not be null; omit the field to use its default"
            ));
        }

        let provider = match config.get("provider").and_then(Value::as_str) {
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
            None => InvocationMode::PreProxy,
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
            None => ErrorAction::Reject,
            Some(_) => {
                return Err("serverless_function: 'on_error' must be a string".to_string());
            }
        };

        let raw_status = optional_u64(config, "error_status_code")?.unwrap_or(502);
        if !(400..=599).contains(&raw_status) {
            return Err(format!(
                "serverless_function: error_status_code must be in range 400-599 (got {raw_status})"
            ));
        }
        let error_status_code = raw_status as u16;

        // Validate `function_url` whenever it is supplied, including for AWS
        // Lambda where invocation uses a derived URL. This keeps runtime
        // admission aligned with the OpenAPI field schema instead of silently
        // accepting an invalid value only because this provider ignores it.
        let configured_function_url = match config.get("function_url") {
            Some(Value::String(url)) => {
                validate_function_url(url)?;
                Some(url.clone())
            }
            None => None,
            Some(_) => {
                return Err("serverless_function: 'function_url' must be a string".to_string());
            }
        };

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
                        validate_aws_endpoint_url(endpoint)?;
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
                    let url = configured_function_url.ok_or_else(|| {
                        "serverless_function: 'function_url' is required for azure_functions"
                            .to_string()
                    })?;

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
                    let url = configured_function_url.ok_or_else(|| {
                        "serverless_function: 'function_url' is required for gcp_cloud_functions"
                            .to_string()
                    })?;

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
        let function_destination = FunctionDestination::new(&function_url)?;
        let function_display_url = redact_serverless_url(&function_url);
        let metadata_prefix = format!(
            "serverless_function.{}.",
            encode_metadata_segment(instance_id)
        );

        let requires_body = forward_body;

        Ok(Self {
            http_client,
            provider,
            mode,
            function_url,
            function_destination,
            function_display_url,
            function_hostname,
            metadata_prefix,
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
    ) -> Result<Value, InvocationFailure> {
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
        if self.forward_query_params {
            let params = unambiguous_query_params(ctx)?;
            if !params.is_empty() {
                payload.insert("query_params".into(), Value::Object(params));
            }
        }

        // Forward request body
        if self.forward_body {
            reject_encoded_request_body(proxy_headers)?;
            let empty_body = Bytes::new();
            let body = if let Some(body) = ctx.request_body_bytes.as_ref() {
                body
            } else if !crate::proxy::request_may_have_body(&ctx.method, proxy_headers) {
                &empty_body
            } else {
                return Err(InvocationFailure::governed_input(
                    "request_body_unavailable",
                    "governed request body was unavailable before function invocation",
                ));
            };
            // `body` is the authoritative representation of the exact bytes
            // that remain eligible for backend dispatch. Keep JSON as text:
            // parsing it here would collapse duplicate keys and normalize
            // whitespace or lexical number forms before the external decision
            // while the unchanged bytes continue downstream. The explicit
            // encoding makes every UTF-8, binary, and empty representation
            // unambiguous without retaining a second structured body copy.
            if let Ok(text) = std::str::from_utf8(body) {
                payload.insert("body".into(), Value::String(text.to_string()));
                payload.insert("body_encoding".into(), Value::String("utf8".into()));
            } else {
                payload.insert(
                    "body".into(),
                    Value::String(base64::engine::general_purpose::STANDARD.encode(body)),
                );
                payload.insert("body_encoding".into(), Value::String("base64".into()));
            }
        }

        Ok(Value::Object(payload))
    }

    /// Invoke the serverless function and return (status_code, headers, body_bytes).
    async fn invoke(
        &self,
        payload: &Value,
        ctx: &RequestContext,
    ) -> Result<(u16, HashMap<String, String>, Bytes), InvocationFailure> {
        let payload_bytes = serde_json::to_vec(payload).map_err(|_| {
            InvocationFailure::new(
                "payload_serialization_failed",
                "failed to serialize function payload",
            )
        })?;

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
                        sign_aws_request(aws, &self.function_url, &payload_bytes, &now).map_err(
                            |_| {
                                InvocationFailure::new(
                                    "request_signing_failed",
                                    "failed to sign AWS Lambda invocation",
                                )
                            },
                        )?;
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
            .execute_redacted_tracked(
                request,
                "serverless_function",
                &self.function_display_url,
                &ctx.plugin_http_call_ns,
            )
            .await
            .map_err(|detail| InvocationFailure::new("invocation_failed", detail))?;

        let status = response.status().as_u16();
        let lambda_function_error = self.provider == Provider::AwsLambda
            && response.headers().contains_key("x-amz-function-error");
        // Only terminate mode can return function response headers. Avoid the
        // filtering and destination-inspection work for pre_proxy responses,
        // whose JSON body alone supplies request-header candidates/metadata.
        let response_headers = if self.mode == InvocationMode::Terminate {
            sanitize_function_response_headers(response.headers(), &self.function_destination)
        } else {
            HashMap::new()
        };

        // Stream the response body with a hard cap. Calling `.bytes().await`
        // would buffer the whole payload before any size check fires — a
        // misbehaving function could exhaust gateway memory regardless of
        // `max_response_body_bytes`. The bounded reader aborts the stream as
        // soon as the running total crosses the limit.
        let body = read_response_body_bounded(response, self.max_response_body_bytes)
            .await
            .map_err(|error| match error {
                BoundedReadError::LimitExceeded { .. } => InvocationFailure::new(
                    "response_body_too_large",
                    "function response exceeded max_response_body_bytes",
                ),
                BoundedReadError::Stream(_) => InvocationFailure::new(
                    "response_body_read_failed",
                    "failed to read function response body",
                ),
            })?;

        // AWS Lambda returns HTTP 200 even on function errors, signaling via
        // X-Amz-Function-Error header. Treat this as an invocation failure.
        if lambda_function_error {
            return Err(InvocationFailure::new(
                "lambda_function_error",
                "AWS Lambda reported a function error",
            ));
        }

        Ok((status, response_headers, body))
    }

    fn metadata_key(&self, suffix: &str) -> String {
        let mut key = String::with_capacity(self.metadata_prefix.len() + suffix.len());
        key.push_str(&self.metadata_prefix);
        key.push_str(suffix);
        key
    }

    fn record_failure(&self, ctx: &mut RequestContext, failure: &InvocationFailure) {
        ctx.metadata
            .insert(self.metadata_key("error_class"), failure.code.to_string());
    }

    fn failure_result(&self, ctx: &mut RequestContext, failure: InvocationFailure) -> PluginResult {
        warn!(
            error_class = failure.code,
            destination = %self.function_display_url,
            detail = %failure.operator_detail,
            "serverless_function invocation failed"
        );
        self.record_failure(ctx, &failure);
        if self.on_error == ErrorAction::Continue && !failure.must_reject {
            PluginResult::Continue
        } else {
            PluginResult::Reject {
                status_code: self.error_status_code,
                body: format!(
                    r#"{{"error":"serverless function invocation failed","code":"{}"}}"#,
                    failure.code
                ),
                headers: HashMap::new(),
            }
        }
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err(format!("serverless_function: '{key}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("serverless_function: '{key}' must be an unsigned integer")),
        None => Ok(None),
        Some(_) => Err(format!(
            "serverless_function: '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_config_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok((!value.is_empty()).then(|| value.clone())),
        None => Ok(None),
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

/// Validate a function URL (Azure/GCP `function_url`).
fn validate_function_url(url: &str) -> Result<(), String> {
    validate_http_url_field(url, "function_url")
}

/// Shared HTTP(S) URL validator for `function_url` (Azure/GCP) and the AWS
/// Lambda `aws_endpoint_url` override. Surfaces the field name in the error
/// so operators see exactly which config key was rejected.
fn validate_http_url_field(url: &str, field: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|_| format!("serverless_function: invalid {field}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(format!(
                "serverless_function: {field} must use http:// or https://"
            ));
        }
    }

    if !has_non_empty_authority(url) {
        return Err(format!(
            "serverless_function: {field} must include a hostname or IP address"
        ));
    }
    http_url_hostname(&parsed, field)?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "serverless_function: {field} must not contain URL userinfo; use the provider credential fields"
        ));
    }
    if parsed.fragment().is_some() {
        return Err(format!(
            "serverless_function: {field} must not contain a URL fragment"
        ));
    }

    Ok(())
}

fn validate_aws_endpoint_url(url: &str) -> Result<(), String> {
    validate_http_url_field(url, "aws_endpoint_url")?;
    let parsed =
        Url::parse(url).map_err(|_| "serverless_function: invalid aws_endpoint_url".to_string())?;
    if parsed.path() != "/" || parsed.query().is_some() {
        return Err(
            "serverless_function: aws_endpoint_url must be an HTTP(S) origin without a path, query, or fragment"
                .to_string(),
        );
    }
    Ok(())
}

/// Return a credential-safe structural URL suitable for logs, diagnostics, and
/// admin projections. Paths and queries can carry signed trigger credentials,
/// so only the origin is retained verbatim.
pub fn redact_serverless_url(url: &str) -> String {
    let Ok(parsed) = Url::parse(url) else {
        return "[REDACTED_URL]".to_string();
    };
    let mut redacted = parsed.origin().ascii_serialization();
    if parsed.path() != "/" {
        redacted.push_str("/[REDACTED_PATH]");
    }
    if parsed.query().is_some() {
        redacted.push_str("?[REDACTED_QUERY]");
    }
    redacted
}

fn encode_metadata_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn reject_encoded_request_body(headers: &HashMap<String, String>) -> Result<(), InvocationFailure> {
    if let Some(encoding) = headers.get("content-encoding")
        && !encoding.trim().eq_ignore_ascii_case("identity")
    {
        return Err(InvocationFailure::governed_input(
            "encoded_request_body_unsupported",
            "governed request body used a non-identity content-encoding",
        ));
    }
    Ok(())
}

fn unambiguous_query_params(
    ctx: &RequestContext,
) -> Result<serde_json::Map<String, Value>, InvocationFailure> {
    let mut ordered = BTreeMap::new();
    if let Some(raw_query) = ctx.raw_query_string() {
        for pair in raw_query.split('&').filter(|pair| !pair.is_empty()) {
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            if raw_key.contains('+') || raw_value.contains('+') {
                return Err(InvocationFailure::governed_input(
                    "ambiguous_query_encoding",
                    "query forwarding rejected a raw '+' character",
                ));
            }
            if !has_valid_percent_triplets(raw_key) || !has_valid_percent_triplets(raw_value) {
                return Err(InvocationFailure::governed_input(
                    "invalid_query_encoding",
                    "query forwarding rejected malformed percent encoding",
                ));
            }
            let key = percent_decode_str(raw_key).decode_utf8().map_err(|_| {
                InvocationFailure::governed_input(
                    "invalid_query_encoding",
                    "query parameter name was not valid percent-encoded UTF-8",
                )
            })?;
            let value = percent_decode_str(raw_value).decode_utf8().map_err(|_| {
                InvocationFailure::governed_input(
                    "invalid_query_encoding",
                    "query parameter value was not valid percent-encoded UTF-8",
                )
            })?;
            if ordered
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(InvocationFailure::governed_input(
                    "duplicate_query_parameter",
                    "query forwarding rejected a duplicate decoded parameter name",
                ));
            }
        }
    } else if !ctx.query_params.is_empty() {
        return Err(InvocationFailure::governed_input(
            "raw_query_unavailable",
            "query parameters were materialized without their original encoded representation",
        ));
    }
    Ok(ordered
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect())
}

fn has_valid_percent_triplets(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

#[derive(Clone)]
struct FunctionDestination {
    url: Url,
    sensitive_path: Option<String>,
    sensitive_query_pairs: Vec<(String, String)>,
    has_unresolved_encoding: bool,
}

impl FunctionDestination {
    fn new(raw: &str) -> Result<Self, String> {
        let url = Url::parse(raw)
            .map_err(|_| "serverless_function: invalid function destination URL".to_string())?;
        let mut has_unresolved_encoding = false;
        let sensitive_path = if url.path() != "/" && !url.path().is_empty() {
            let decoded = decode_percent_layers(url.path());
            has_unresolved_encoding |= !decoded.fully_decoded;
            Some(decoded.value)
        } else {
            None
        };
        let (sensitive_query_pairs, query_has_unresolved_encoding) = decoded_url_query_pairs(&url);
        has_unresolved_encoding |= query_has_unresolved_encoding;
        Ok(Self {
            url,
            sensitive_path,
            sensitive_query_pairs,
            has_unresolved_encoding,
        })
    }

    fn uri_reference_exposes_destination(&self, reference: &str) -> bool {
        // If the accepted destination itself exceeds the bounded decoding
        // budget, no function-controlled URL-valued header can be proven
        // credential free. Keep accepting the provider URL, but strip such
        // response headers fail closed.
        if self.has_unresolved_encoding {
            return true;
        }
        self.uri_reference_exposes_destination_inner(reference, 0)
    }

    fn uri_reference_exposes_destination_inner(&self, reference: &str, depth: usize) -> bool {
        // A signed destination makes an unparseable URI reference unsafe:
        // Ferrum cannot prove that an encoded credential is absent, so fail
        // closed by removing the field. Valid benign relative/absolute
        // references remain eligible below.
        let decoded_reference = decode_percent_layers(reference);
        if !decoded_reference.fully_decoded {
            return true;
        }
        let Some(candidate) = self
            .url
            .join(reference)
            .ok()
            .or_else(|| self.url.join(&decoded_reference.value).ok())
        else {
            return true;
        };

        // Do not forward redirect userinfo supplied by a function. It is both a
        // credential-bearing URI surface and unnecessary for identifying a
        // benign redirect destination.
        if !candidate.username().is_empty() || candidate.password().is_some() {
            return true;
        }

        let (candidate_pairs, query_has_unresolved_encoding) = decoded_url_query_pairs(&candidate);
        if query_has_unresolved_encoding {
            return true;
        }

        let candidate_path = decode_percent_layers(candidate.path());
        if !candidate_path.fully_decoded {
            return true;
        }
        let candidate_path = candidate_path.value;
        let exposes_signed_path = self
            .sensitive_path
            .as_deref()
            .is_some_and(|path| path_contains_segment_sequence(&candidate_path, path));
        // A signed path is credential material even if the function copies it
        // onto another authority. Restricting this comparison to same-origin
        // references would disclose path-embedded tokens through an attacker-
        // controlled host. Match the complete configured path at segment
        // boundaries anywhere in the candidate: adding a prefix or descendant
        // segment does not stop the signed path from being echoed, while
        // lookalikes such as `/signed/triggered` remain distinct.
        if exposes_signed_path {
            return true;
        }

        // Query credentials can also be copied into an attacker-controlled
        // redirect path or path parameter. Match complete URI components so a
        // value such as `secret/value` is blocked at `/secret/value`,
        // `/next;leak=secret/value`, and `/next?leak=secret/value`, while
        // `/secret/value-extra` remains distinct.
        if self
            .sensitive_query_scalars()
            .any(|value| uri_component_contains_sequence(&candidate_path, value))
        {
            return true;
        }

        // Query credentials are unsafe even when copied onto another host,
        // path, or parameter name. Compare decoded pairs and protected scalar
        // components exactly so reordering, renaming, key/value swapping, and
        // ordinary percent-encoding changes cannot evade the check without
        // introducing substring false positives.
        if candidate_pairs.iter().any(|candidate| {
            self.sensitive_query_pairs
                .iter()
                .any(|sensitive| candidate == sensitive)
                || self
                    .sensitive_query_scalars()
                    .any(|component| candidate.0 == component || candidate.1 == component)
        }) {
            return true;
        }

        // URL-bearing fields commonly embed their next destination as an
        // encoded query value or fragment. Inspect those URI references
        // recursively, but only when they are syntactically URI-like: treating
        // every scalar as a relative path would remove benign values such as
        // `https://example.test/next?label=signed/trigger`. When a structural
        // reference remains at the depth boundary, fail closed rather than
        // silently treating uninspected nesting as safe.
        for (key, value) in &candidate_pairs {
            if self.nested_reference_exposes_destination(nested_uri_reference(key), depth)
                || self.nested_reference_exposes_destination(nested_uri_reference(value), depth)
            {
                return true;
            }
        }
        if self
            .nested_reference_exposes_destination(nested_path_uri_reference(&candidate_path), depth)
        {
            return true;
        }
        if let Some(fragment) = candidate.fragment() {
            let decoded_fragment = decode_percent_layers(fragment);
            if !decoded_fragment.fully_decoded {
                return true;
            }
            // Fragments are client-visible to the destination page even when
            // they are scalar rather than URI-shaped. Compare their decoded
            // content directly at URI-component boundaries before the nested
            // reference check so `#secret/value` and
            // `#leak=secret/value` cannot expose a signed query value (and the
            // same applies to a configured signed path).
            if self
                .sensitive_path
                .as_deref()
                .is_some_and(|path| uri_component_contains_sequence(&decoded_fragment.value, path))
                || self
                    .sensitive_query_scalars()
                    .any(|value| uri_component_contains_sequence(&decoded_fragment.value, value))
            {
                return true;
            }
            if self.nested_reference_exposes_destination(
                nested_uri_reference(&decoded_fragment.value),
                depth,
            ) {
                return true;
            }
        }

        false
    }

    /// Credential-bearing scalar components from the configured query.
    ///
    /// Every non-empty key and value is independently sensitive. Selecting
    /// only the value for an ordinary pair would let a credential-bearing key
    /// escape under another name; selecting only the key for a key-only form
    /// would create the inverse gap.
    fn sensitive_query_scalars(&self) -> impl Iterator<Item = &str> {
        self.sensitive_query_pairs
            .iter()
            .flat_map(|(key, value)| [key.as_str(), value.as_str()])
            .filter(|component| !component.is_empty())
    }

    fn nested_reference_exposes_destination(&self, reference: Option<&str>, depth: usize) -> bool {
        let Some(reference) = reference else {
            return false;
        };
        depth >= MAX_NESTED_DESTINATION_DEPTH
            || self.uri_reference_exposes_destination_inner(reference, depth + 1)
    }

    fn response_header_exposes_destination(
        &self,
        kind: UrlValuedResponseHeader,
        value: &str,
    ) -> bool {
        if value.len() > MAX_URL_VALUED_RESPONSE_HEADER_BYTES {
            return true;
        }
        match kind {
            UrlValuedResponseHeader::Location | UrlValuedResponseHeader::ContentLocation => {
                self.uri_reference_exposes_destination(value)
            }
            UrlValuedResponseHeader::Refresh => match refresh_uri_reference(value) {
                Ok(Some(reference)) => self.uri_reference_exposes_destination(reference),
                Ok(None) => false,
                Err(()) => true,
            },
            UrlValuedResponseHeader::Link => self.link_header_exposes_destination(value),
        }
    }

    fn link_header_exposes_destination(&self, value: &str) -> bool {
        let bytes = value.as_bytes();
        let mut cursor = 0;
        let mut targets = 0;

        loop {
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if cursor == bytes.len() {
                return true;
            }
            if bytes[cursor] != b'<' {
                return true;
            }
            let target_start = cursor + 1;
            let Some(relative_end) = value[target_start..].find('>') else {
                return true;
            };
            let target_end = target_start + relative_end;
            targets += 1;
            if targets > MAX_LINK_HEADER_TARGETS
                || self.uri_reference_exposes_destination(&value[target_start..target_end])
            {
                return true;
            }

            cursor = target_end + 1;
            let mut quoted = false;
            let mut escaped = false;
            let mut has_next_target = false;
            while cursor < bytes.len() {
                let byte = bytes[cursor];
                if quoted {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        quoted = false;
                    }
                } else if byte == b'"' {
                    quoted = true;
                } else if byte == b',' {
                    cursor += 1;
                    has_next_target = true;
                    break;
                } else if byte == b'<' {
                    return true;
                }
                cursor += 1;
            }
            if quoted || escaped {
                return true;
            }
            if cursor == bytes.len() {
                return has_next_target;
            }
        }
    }
}

fn nested_uri_reference(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    // An encoded absolute URL embedded in a path commonly appears as
    // `/https://host/...` after decoding. Remove only that transport slash;
    // ordinary absolute-path references retain their leading slash.
    if let Some(without_slash) = trimmed.strip_prefix('/')
        && (has_ascii_case_insensitive_prefix(without_slash, "http://")
            || has_ascii_case_insensitive_prefix(without_slash, "https://"))
    {
        return Some(without_slash);
    }

    (has_ascii_case_insensitive_prefix(trimmed, "http://")
        || has_ascii_case_insensitive_prefix(trimmed, "https://")
        || trimmed.starts_with("//")
        || trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('?')
        || trimmed.starts_with('#'))
    .then_some(trimmed)
}

fn decoded_url_query_pairs(url: &Url) -> (Vec<(String, String)>, bool) {
    let mut pairs = Vec::new();
    let mut has_unresolved_encoding = false;
    for pair in url
        .query()
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        // A URL query is not necessarily form data. Decode percent escapes
        // without translating a literal '+' to a space so signed tokens that
        // contain '+' compare consistently with their `%2B` representation.
        let key = decode_percent_layers(key);
        let value = decode_percent_layers(value);
        has_unresolved_encoding |= !key.fully_decoded || !value.fully_decoded;
        pairs.push((key.value, value.value));
    }
    (pairs, has_unresolved_encoding)
}

fn path_contains_segment_sequence(candidate: &str, sensitive: &str) -> bool {
    if sensitive.is_empty() {
        return false;
    }
    candidate.match_indices(sensitive).any(|(index, _)| {
        let end = index + sensitive.len();
        let starts_at_boundary = sensitive.starts_with('/')
            || index == 0
            || candidate.as_bytes().get(index - 1) == Some(&b'/');
        let ends_at_boundary = sensitive.ends_with('/')
            || end == candidate.len()
            || candidate.as_bytes().get(end) == Some(&b'/');
        starts_at_boundary && ends_at_boundary
    })
}

fn uri_component_contains_sequence(candidate: &str, sensitive: &str) -> bool {
    if sensitive.is_empty() {
        return false;
    }
    let component = sensitive.trim_matches('/');
    if component.is_empty() {
        // A non-empty configured scalar made entirely of slashes cannot be
        // distinguished from URI structure after decoding. Match its exact
        // slash sequence instead of silently dropping it from the sensitive
        // set.
        return candidate.contains(sensitive);
    }
    candidate.match_indices(component).any(|(index, _)| {
        let end = index + component.len();
        let starts_at_boundary = index == 0
            || candidate
                .as_bytes()
                .get(index - 1)
                .copied()
                .is_some_and(is_uri_component_boundary);
        let ends_at_boundary = end == candidate.len()
            || candidate
                .as_bytes()
                .get(end)
                .copied()
                .is_some_and(is_uri_component_boundary);
        starts_at_boundary && ends_at_boundary
    })
}

fn is_uri_component_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn nested_path_uri_reference(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let without_slash = trimmed.strip_prefix('/')?;
    (has_ascii_case_insensitive_prefix(without_slash, "http://")
        || has_ascii_case_insensitive_prefix(without_slash, "https://"))
    .then_some(without_slash)
}

fn has_ascii_case_insensitive_prefix(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

const MAX_REDIRECT_PERCENT_DECODE_LAYERS: usize = 8;
const MAX_NESTED_DESTINATION_DEPTH: usize = 2;
const MAX_URL_VALUED_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_LINK_HEADER_TARGETS: usize = 32;

#[derive(Clone, Copy)]
enum UrlValuedResponseHeader {
    Location,
    ContentLocation,
    Refresh,
    Link,
}

impl UrlValuedResponseHeader {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "location" => Some(Self::Location),
            "content-location" => Some(Self::ContentLocation),
            "refresh" => Some(Self::Refresh),
            "link" => Some(Self::Link),
            _ => None,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Location => 0,
            Self::ContentLocation => 1,
            Self::Refresh => 2,
            Self::Link => 3,
        }
    }
}

fn refresh_uri_reference(value: &str) -> Result<Option<&str>, ()> {
    let Some((_, directive)) = value.split_once(';') else {
        return Ok(None);
    };
    let directive = directive.trim();
    if !has_ascii_case_insensitive_prefix(directive, "url") {
        // Some Refresh consumers accept a bare URI after the semicolon even
        // without `url=`. Any non-empty scalar is also a valid relative URI
        // reference, so inspect it as a target; benign extensions still pass
        // when they do not expose the signed destination.
        if directive.is_empty() {
            return Err(());
        }
        return Ok(Some(directive));
    }
    let after_name = &directive["url".len()..];
    if after_name
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
    {
        return Ok(Some(directive));
    }
    let Some(target) = after_name.trim_start().strip_prefix('=') else {
        return Err(());
    };
    let target = target.trim();
    if target.is_empty() {
        return Err(());
    }
    if matches!(target.as_bytes()[0], b'\'' | b'"') {
        let quote = target.as_bytes()[0];
        if target.len() < 2 || target.as_bytes()[target.len() - 1] != quote {
            return Err(());
        }
        let unquoted = &target[1..target.len() - 1];
        if unquoted.is_empty() || unquoted.as_bytes().contains(&quote) {
            return Err(());
        }
        Ok(Some(unquoted))
    } else {
        Ok(Some(target))
    }
}

struct DecodedPercentLayers {
    value: String,
    fully_decoded: bool,
}

fn decode_percent_layers(value: &str) -> DecodedPercentLayers {
    let mut decoded = value.to_string();
    for _ in 0..MAX_REDIRECT_PERCENT_DECODE_LAYERS {
        let Some(next) = strictly_decode_percent_layer(&decoded) else {
            return DecodedPercentLayers {
                value: decoded,
                fully_decoded: false,
            };
        };
        if next == decoded {
            return DecodedPercentLayers {
                value: decoded,
                fully_decoded: true,
            };
        }
        decoded = next;
    }
    let Some(next) = strictly_decode_percent_layer(&decoded) else {
        return DecodedPercentLayers {
            value: decoded,
            fully_decoded: false,
        };
    };
    DecodedPercentLayers {
        fully_decoded: next == decoded,
        value: decoded,
    }
}

fn strictly_decode_percent_layer(value: &str) -> Option<String> {
    if !has_valid_percent_triplets(value) {
        return None;
    }
    percent_decode_str(value)
        .decode_utf8()
        .ok()
        .map(|decoded| decoded.into_owned())
}

fn sanitize_function_response_headers(
    headers: &http::HeaderMap,
    function_destination: &FunctionDestination,
) -> HashMap<String, String> {
    let connection_listed: HashSet<HeaderName> =
        crate::proxy::headers::parse_connection_listed_headers(headers)
            .into_iter()
            .collect();
    let mut safe = HashMap::new();
    let mut destination_header_blocked = [false; 4];
    for (name, value) in headers {
        let lower = name.as_str();
        if connection_listed.contains(name)
            || crate::proxy::headers::is_backend_response_strip_header(lower)
            || is_protocol_managed_or_unsafe_response_header(lower)
        {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        if let Some(kind) = UrlValuedResponseHeader::from_name(lower) {
            let index = kind.index();
            if destination_header_blocked[index]
                || function_destination.response_header_exposes_destination(kind, value)
            {
                safe.remove(lower);
                destination_header_blocked[index] = true;
                continue;
            }
        }
        if lower == "set-cookie" {
            crate::proxy::headers::append_set_cookie_header(&mut safe, value.to_string());
        } else {
            safe.entry(lower.to_string())
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(value);
                })
                .or_insert_with(|| value.to_string());
        }
    }
    safe
}

fn is_protocol_managed_or_unsafe_response_header(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "authorization"
            | "proxy-authorization"
            | "authentication-info"
            | "proxy-authentication-info"
            | "cookie"
            | "x-api-key"
            | "x-functions-key"
            | "alt-svc"
            | "server"
            | "via"
            | "cf-ray"
    ) || name.starts_with("x-amz-")
        || name.starts_with("x-goog-")
        || name.starts_with("x-functions-")
        || name.starts_with("x-ms-")
        || name.starts_with("x-azure-")
        || name.starts_with("x-cloud-")
        || name.starts_with("x-envoy-")
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

    fn egresses_request_body_before_finalization(&self) -> bool {
        self.forward_body
    }

    fn requires_prior_request_deduplication(&self) -> bool {
        self.mode == InvocationMode::Terminate
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    fn deferred_before_proxy_may_change_routing_headers(&self) -> bool {
        self.mode == InvocationMode::PreProxy
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.requires_body
    }

    fn should_buffer_request_body(&self, _ctx: &RequestContext) -> bool {
        self.requires_body
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.requires_body
    }

    fn needs_request_body_text(&self) -> bool {
        false
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

        let payload = match self.build_invocation_payload(ctx, headers) {
            Ok(payload) => payload,
            Err(failure) => return self.failure_result(ctx, failure),
        };

        if self.mode == InvocationMode::Terminate {
            // The request_deduplication plugin uses this private provenance to
            // distinguish an attempted externally executing terminal response
            // from other synthetic short-circuits that must not be cached.
            // Set it only after all plugin-local fail-closed inspection passes.
            ctx.serverless_external_side_effect_owners
                .extend(ctx.request_deduplication_states.keys().copied());
        }

        let (status, response_headers, body) = match self.invoke(&payload, ctx).await {
            Ok(result) => result,
            Err(failure) => return self.failure_result(ctx, failure),
        };
        ctx.metadata
            .insert(self.metadata_key("status"), status.to_string());

        match self.mode {
            InvocationMode::Terminate => {
                if !(200..=599).contains(&status) {
                    return self.failure_result(
                        ctx,
                        InvocationFailure::new(
                            "invalid_function_status",
                            format!("function returned non-final status {status}"),
                        ),
                    );
                }
                // Return the function's response directly to the client
                debug!(
                    "serverless_function: terminate mode — returning function response (status {})",
                    status
                );
                let body = if ctx.method.eq_ignore_ascii_case("HEAD")
                    || matches!(status, 204 | 205 | 304)
                {
                    Bytes::new()
                } else {
                    body
                };
                PluginResult::RejectBinary {
                    status_code: status,
                    body,
                    headers: response_headers,
                }
            }
            InvocationMode::PreProxy => {
                // Only a 2xx function response is an affirmative pre-proxy
                // decision. Redirects are deliberately not followed by the
                // shared client and cannot become implicit approval.
                if !(200..=299).contains(&status) {
                    return self.failure_result(
                        ctx,
                        InvocationFailure::new(
                            "function_non_success_status",
                            format!("function returned non-2xx status {status} in pre_proxy mode"),
                        ),
                    );
                }

                // Parse the response body as JSON to extract headers to inject
                if let Ok(resp_json) = serde_json::from_slice::<Value>(&body) {
                    // Inject headers from response: { "headers": { "X-Custom": "value" } }
                    if let Some(header_map) = resp_json.get("headers").and_then(|h| h.as_object()) {
                        let mut candidates = HashMap::new();
                        for (key, val) in header_map {
                            let Some(value) = val.as_str() else {
                                continue;
                            };
                            let Ok(name) = HeaderName::from_bytes(key.as_bytes()) else {
                                continue;
                            };
                            if HeaderValue::from_str(value).is_err() {
                                continue;
                            }
                            candidates.insert(name.as_str().to_string(), value.to_string());
                        }
                        let connection_listed: HashSet<String> =
                            crate::proxy::headers::parse_connection_listed_from_str_map(
                                &candidates,
                            )
                            .into_iter()
                            .collect();
                        for (key, value) in candidates {
                            if connection_listed.contains(&key)
                                || crate::proxy::headers::is_backend_request_strip_header(&key)
                            {
                                continue;
                            }
                            headers.insert(key, value);
                        }
                    }

                    // Store metadata from response: { "metadata": { "key": "value" } }
                    if let Some(meta_map) = resp_json.get("metadata").and_then(|m| m.as_object()) {
                        for (key, val) in meta_map {
                            if let Some(value) = val.as_str() {
                                let suffix = format!("metadata.{}", encode_metadata_segment(key));
                                ctx.metadata
                                    .insert(self.metadata_key(&suffix), value.to_string());
                            }
                        }
                    }
                }

                PluginResult::Continue
            }
        }
    }
}
