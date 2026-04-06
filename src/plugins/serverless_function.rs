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
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use url::Url;

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
    gcp_bearer_token: Option<String>,
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

        let mode = match config["mode"].as_str().unwrap_or("pre_proxy") {
            "terminate" => InvocationMode::Terminate,
            _ => InvocationMode::PreProxy,
        };

        let forward_body = config["forward_body"].as_bool().unwrap_or(false);
        let forward_query_params = config["forward_query_params"].as_bool().unwrap_or(false);

        let forward_headers: Vec<String> = config["forward_headers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        let timeout_ms = config["timeout_ms"].as_u64().unwrap_or(5000);
        if timeout_ms == 0 {
            return Err("serverless_function: timeout_ms must be > 0".to_string());
        }

        let max_response_body_bytes = config["max_response_body_bytes"]
            .as_u64()
            .unwrap_or(10 * 1024 * 1024) as usize;

        let on_error = match config["on_error"].as_str().unwrap_or("reject") {
            "continue" => ErrorAction::Continue,
            _ => ErrorAction::Reject,
        };

        let error_status_code = config["error_status_code"].as_u64().unwrap_or(502).min(599) as u16;

        // Provider-specific config + URL construction.
        // Config fields take precedence; well-known env vars are used as fallback.
        let (function_url, aws_config, azure_function_key, gcp_bearer_token) = match &provider {
            Provider::AwsLambda => {
                let region = config_or_env(&config["aws_region"], "AWS_DEFAULT_REGION")
                    .or_else(|| config_or_env(&Value::Null, "AWS_REGION"))
                    .ok_or_else(|| {
                        "serverless_function: 'aws_region' is required for aws_lambda \
                         (or set AWS_DEFAULT_REGION / AWS_REGION env var)"
                            .to_string()
                    })?;

                let access_key_id =
                    config_or_env(&config["aws_access_key_id"], "AWS_ACCESS_KEY_ID").ok_or_else(
                        || {
                            "serverless_function: 'aws_access_key_id' is required for aws_lambda \
                         (or set AWS_ACCESS_KEY_ID env var)"
                                .to_string()
                        },
                    )?;

                let secret_access_key = config_or_env(
                    &config["aws_secret_access_key"],
                    "AWS_SECRET_ACCESS_KEY",
                )
                .ok_or_else(|| {
                    "serverless_function: 'aws_secret_access_key' is required for aws_lambda \
                             (or set AWS_SECRET_ACCESS_KEY env var)"
                        .to_string()
                })?;

                let function_name =
                    config_or_env(&config["aws_function_name"], "AWS_LAMBDA_FUNCTION_NAME")
                        .ok_or_else(|| {
                            "serverless_function: 'aws_function_name' is required for aws_lambda \
                         (or set AWS_LAMBDA_FUNCTION_NAME env var)"
                                .to_string()
                        })?;

                let session_token =
                    config_or_env(&config["aws_session_token"], "AWS_SESSION_TOKEN");

                let qualifier = config["aws_qualifier"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from);

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

                // Build the Lambda Invoke API URL
                let mut url = format!(
                    "https://lambda.{}.amazonaws.com/2015-03-31/functions/{}/invocations",
                    region, function_name
                );
                if let Some(ref q) = qualifier {
                    url.push_str("?Qualifier=");
                    url.push_str(&uri_encode(q, true));
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
                let url = config["function_url"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        "serverless_function: 'function_url' is required for azure_functions"
                            .to_string()
                    })?
                    .to_string();

                validate_function_url(&url)?;

                let key = config_or_env(&config["azure_function_key"], "AZURE_FUNCTIONS_KEY");
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
                let url = config["function_url"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        "serverless_function: 'function_url' is required for gcp_cloud_functions"
                            .to_string()
                    })?
                    .to_string();

                validate_function_url(&url)?;

                let token = config_or_env(
                    &config["gcp_bearer_token"],
                    "GCP_CLOUD_FUNCTIONS_BEARER_TOKEN",
                );
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

                (url, None, None, token)
            }
        };

        // Extract hostname for DNS warmup
        let function_hostname = Url::parse(&function_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from));

        let requires_body = forward_body;

        Ok(Self {
            http_client,
            provider,
            mode,
            function_url,
            function_hostname,
            aws_config,
            azure_function_key,
            gcp_bearer_token,
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
    ) -> Result<(u16, HashMap<String, String>, Vec<u8>), String> {
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
                        sign_aws_request(aws, &self.function_url, &payload_bytes, &now);
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
                if let Some(ref token) = self.gcp_bearer_token {
                    req_builder = req_builder.header("authorization", format!("Bearer {}", token));
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

        let body = response
            .bytes()
            .await
            .map_err(|e| format!("serverless_function: failed to read response body: {e}"))?;

        if body.len() > self.max_response_body_bytes {
            return Err(format!(
                "serverless_function: response body size {} exceeds max_response_body_bytes {}",
                body.len(),
                self.max_response_body_bytes,
            ));
        }

        // AWS Lambda returns HTTP 200 even on function errors, signaling via
        // X-Amz-Function-Error header. Treat this as an invocation failure.
        if self.provider == Provider::AwsLambda
            && let Some(error_type) = response_headers.get("x-amz-function-error")
        {
            return Err(format!(
                "serverless_function: Lambda function error ({}): {}",
                error_type,
                String::from_utf8_lossy(&body),
            ));
        }

        Ok((status, response_headers, body.to_vec()))
    }
}

/// Resolve a config field with env var fallback.
/// Config value takes precedence; if absent or empty, fall back to the named env var.
fn config_or_env(config_value: &Value, env_var: &str) -> Option<String> {
    config_value
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| std::env::var(env_var).ok().filter(|s| !s.is_empty()))
}

/// Escape special characters for safe JSON string interpolation.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}

/// Validate a function URL (Azure/GCP).
fn validate_function_url(url: &str) -> Result<(), String> {
    let parsed =
        Url::parse(url).map_err(|e| format!("serverless_function: invalid function_url: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "serverless_function: function_url must use http:// or https:// (got '{scheme}')"
            ));
        }
    }

    if parsed.host_str().is_none() {
        return Err(
            "serverless_function: function_url must include a hostname or IP address".to_string(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// AWS SigV4 request signing
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

/// URI-encode a string per AWS SigV4 rules.
/// When `encode_slash` is false, forward slashes are preserved (for URI paths).
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b'/' if !encode_slash => {
                result.push('/');
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// SHA-256 hash of data, returned as lowercase hex.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// HMAC-SHA256 keyed hash.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the SigV4 signing key: HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
fn derive_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Sign an AWS Lambda Invoke API request using SigV4.
/// Returns the headers that must be added to the request.
fn sign_aws_request(
    aws: &AwsLambdaConfig,
    url_str: &str,
    payload: &[u8],
    now: &chrono::DateTime<Utc>,
) -> Vec<(String, String)> {
    let service = "lambda";
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed_url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };

    let host = match parsed_url.host_str() {
        Some(h) => h.to_string(),
        None => return Vec::new(),
    };

    let canonical_uri = uri_encode(parsed_url.path(), false);
    let canonical_querystring = parsed_url.query().unwrap_or("");

    let payload_hash = sha256_hex(payload);

    // Canonical headers (must be sorted alphabetically by header name).
    // When a session token is present, x-amz-security-token is included.
    let (canonical_headers, signed_headers) = if aws.session_token.is_some() {
        (
            format!(
                "content-type:application/json\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\nx-amz-security-token:{}\n",
                host,
                payload_hash,
                amz_date,
                aws.session_token.as_deref().unwrap_or_default()
            ),
            "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        )
    } else {
        (
            format!(
                "content-type:application/json\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                host, payload_hash, amz_date
            ),
            "content-type;host;x-amz-content-sha256;x-amz-date",
        )
    };

    let canonical_request = format!(
        "POST\n{}\n{}\n{}\n{}\n{}",
        canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash
    );

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, aws.region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        credential_scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let signing_key = derive_signing_key(&aws.secret_access_key, &date_stamp, &aws.region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        aws.access_key_id, credential_scope, signed_headers, signature
    );

    let mut headers = vec![
        ("authorization".to_string(), authorization),
        ("x-amz-date".to_string(), amz_date),
        ("x-amz-content-sha256".to_string(), payload_hash),
    ];

    if let Some(ref token) = aws.session_token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }

    headers
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
    ) -> Vec<(String, String)> {
        let cfg = AwsLambdaConfig {
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
            function_name: aws_config["function_name"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            qualifier: None,
        };
        sign_aws_request(&cfg, url, payload, now)
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
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
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
        // Terminate mode is incompatible with gRPC: the gateway normalizes
        // RejectBinary into trailers-only gRPC errors, dropping the body.
        // Fail clearly rather than silently losing the function response.
        if self.mode == InvocationMode::Terminate {
            let is_grpc = headers
                .get("content-type")
                .is_some_and(|ct| ct.starts_with("application/grpc"));
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
                    body: body.into(),
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
                            body: String::from_utf8(body).unwrap_or_default(),
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
                                ctx.metadata
                                    .insert(format!("serverless_{}", key), v.to_string());
                            }
                        }
                    }
                }

                PluginResult::Continue
            }
        }
    }
}
