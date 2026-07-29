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

/// Maximum custom trailer entries accepted from a gRPC terminate function
/// response. Protocol-owned `grpc-status` / `grpc-message` /
/// `grpc-status-details-bin` are counted separately via dedicated fields.
const MAX_GRPC_TERMINATE_CUSTOM_TRAILERS: usize = 32;
/// Per-trailer **wire** value byte cap. Bounds one field only; the size of the
/// block a peer must accept is bounded separately by
/// [`MAX_GRPC_TERMINATE_TERMINAL_BLOCK_BYTES`].
///
/// This bound is applied to the bytes that actually reach the trailer block,
/// after sanitization and after any re-encoding — not to some pre-image of
/// them. `grpc_message` is therefore bounded here rather than only by
/// `max_response_body_bytes` (which can be many MiB), and
/// `status_details_base64` is bounded by its re-encoded base64 length rather
/// than by the decoded byte count that base64 expands 4/3 beyond.
const MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES: usize = 8 * 1024;
/// Largest decoded `grpc-status-details-bin` payload whose standard-base64
/// re-encoding still fits [`MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES`]. Base64
/// emits four characters per three input bytes, so the decoded ceiling is
/// three quarters of the wire ceiling.
const MAX_GRPC_TERMINATE_STATUS_DETAILS_DECODED_BYTES: usize =
    MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES / 4 * 3;
/// Per-field accounting overhead an HTTP/2 peer adds when charging a header
/// list against `SETTINGS_MAX_HEADER_LIST_SIZE` (RFC 9113 §6.5.2: name length +
/// value length + 32). HTTP/3 charges the same shape for a field section
/// against `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2), so one constant
/// covers both wire protocols this contract can terminate on.
const GRPC_TERMINATE_HEADER_FIELD_OVERHEAD_BYTES: usize = 32;
/// Aggregate ceiling for the COMPLETE terminal metadata block the contract
/// authors — every emitted field, not one value at a time.
///
/// [`MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES`] alone bounds only a single field.
/// With [`MAX_GRPC_TERMINATE_CUSTOM_TRAILERS`] custom entries plus the
/// protocol-owned `grpc-message` / `grpc-status-details-bin`, a contract could
/// authorize ~256 KiB of trailer values and still pass every per-entry check —
/// far beyond any header-list size a peer is obliged to accept, and retained in
/// memory until emission. The block is therefore charged as a whole.
///
/// 16 KiB is the established repository floor for this resource: proxy H2
/// listeners never advertise a `SETTINGS_MAX_HEADER_LIST_SIZE` below
/// `MIN_H2_HEADER_LIST_SIZE` (16 KiB, `src/proxy/mod.rs`), while the configured
/// header budget defaults to 32 KiB (`FERRUM_MAX_HEADER_SIZE_BYTES`) and the
/// admin listener advertises 64 KiB. Staying at the smallest of those keeps an
/// accepted terminal block deliverable on every H2/H3 client Ferrum expects,
/// rather than accepted here and reset by the peer.
const MAX_GRPC_TERMINATE_TERMINAL_BLOCK_BYTES: usize = 16 * 1024;
/// Allowed top-level keys in the terminate-mode native-gRPC JSON contract.
const GRPC_TERMINATE_RESPONSE_FIELDS: &[&str] = &[
    "grpc_status",
    "grpc_message",
    "message_base64",
    "status_details_base64",
    "trailers",
];
/// Max characters of one function-controlled field-name fragment rendered into
/// an operator diagnostic. A hostile key must not dominate the log line.
const MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS: usize = 64;
/// Max characters of a complete terminate-contract operator diagnostic. Caps
/// the log record even when several field fragments are present.
const MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS: usize = 256;
/// How many unknown top-level member names may appear in the diagnostic sample.
/// The full inventory is never collected or joined solely for logging.
const MAX_GRPC_TERMINATE_UNKNOWN_FIELD_SAMPLE: usize = 3;

#[derive(Debug)]
struct InvocationFailure {
    code: &'static str,
    operator_detail: String,
    must_reject: bool,
    /// True when the failure is proven to have occurred before any request bytes
    /// could reach the function: payload serialization, provider request signing,
    /// or a transport class that never went on the wire (connect refused/timeout,
    /// DNS, TLS, pool/port exhaustion, or an egress-policy denial). Such a failure
    /// caused no external side effect, so a terminate-mode dedup owner marked in
    /// anticipation of the call must be released rather than retained until TTL.
    /// Defaults to `false` so ambiguous/post-wire outcomes stay fail-closed.
    proven_pre_wire: bool,
}

impl InvocationFailure {
    fn new(code: &'static str, operator_detail: impl Into<String>) -> Self {
        Self {
            code,
            operator_detail: operator_detail.into(),
            must_reject: false,
            proven_pre_wire: false,
        }
    }

    /// A failure proven to have occurred before any request reached the function.
    fn pre_wire(code: &'static str, operator_detail: impl Into<String>) -> Self {
        Self {
            code,
            operator_detail: operator_detail.into(),
            must_reject: false,
            proven_pre_wire: true,
        }
    }

    fn governed_input(code: &'static str, operator_detail: impl Into<String>) -> Self {
        Self {
            code,
            operator_detail: operator_detail.into(),
            must_reject: true,
            // Governed-input rejections happen in `build_invocation_payload`,
            // before the outbound call, so no external side effect can exist.
            proven_pre_wire: true,
        }
    }

    fn with_pre_wire(mut self, proven_pre_wire: bool) -> Self {
        self.proven_pre_wire = proven_pre_wire;
        self
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

fn parse_invocation_mode(config: &Value) -> Result<InvocationMode, String> {
    match config.get("mode") {
        Some(Value::String(s)) => match s.as_str() {
            "pre_proxy" => Ok(InvocationMode::PreProxy),
            "terminate" => Ok(InvocationMode::Terminate),
            other => Err(format!(
                "serverless_function: unknown mode '{other}' (expected 'pre_proxy' or 'terminate')"
            )),
        },
        None => Ok(InvocationMode::PreProxy),
        Some(_) => Err("serverless_function: 'mode' must be a string".to_string()),
    }
}

/// Parse only the static capabilities used by cross-plugin composition
/// admission. This deliberately does not resolve provider credentials or any
/// node-local environment values.
pub(crate) fn security_composition_capabilities(config: &Value) -> Result<(bool, bool), String> {
    if !config.is_object() {
        return Err("serverless_function: config must be an object".to_string());
    }
    let mode = parse_invocation_mode(config)?;
    let forward_body = optional_bool(config, "forward_body")?.unwrap_or(false);
    Ok((forward_body, mode == InvocationMode::Terminate))
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
            let is_required = key == "provider"
                || (key == "function_url"
                    && matches!(
                        config_object.get("provider").and_then(Value::as_str),
                        Some("azure_functions") | Some("gcp_cloud_functions")
                    ));
            let detail = if is_required {
                "is required and must not be null"
            } else {
                "must not be null; omit the field instead"
            };
            return Err(format!("serverless_function: '{key}' {detail}"));
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
        let mode = parse_invocation_mode(config)?;

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
                // Read only the effective `before_proxy` header map. Falling
                // back to `ctx.headers` would resurrect field lines an earlier
                // `before_proxy` plugin deliberately removed — `authorization`
                // under `strip_authorization_on_success`, or a gateway-owned
                // `claim_headers` destination whose claim was absent — and hand
                // that client-supplied value to the function as if the gateway
                // had asserted it. `ctx.headers` is the pristine ingress map and
                // is never the outbound view; on the no-clone path the handler
                // has already moved it into `proxy_headers`.
                if let Some(val) = proxy_headers.get(key) {
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
            reject_encoded_request_body(ctx, proxy_headers)?;
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
            // Keep a single authoritative, lossless body representation. JSON
            // parsing here would collapse duplicate object members and rewrite
            // lexical number/whitespace forms before the external policy sees
            // them, while the unchanged bytes continue to the backend. Valid
            // UTF-8 has a unique byte encoding, so a JSON string round-trip is
            // lossless; arbitrary bytes use base64. Always emit the encoding,
            // and carry the active hook Content-Type separately as an
            // interpretation hint rather than letting it change the bytes.
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
            if let Some(content_type) = proxy_headers.get("content-type") {
                payload.insert(
                    "body_content_type".into(),
                    Value::String(content_type.clone()),
                );
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
            InvocationFailure::pre_wire(
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
                                InvocationFailure::pre_wire(
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
            .execute_redacted_tracked_classified(
                request,
                "serverless_function",
                &self.function_display_url,
                &ctx.plugin_http_call_ns,
            )
            .await
            .map_err(|failure| {
                // `request_reached_wire` is the authoritative provider-I/O
                // boundary: a false value proves no request bytes reached the
                // function (request-build failure, connect refused/timeout, DNS,
                // TLS, pool/port exhaustion, or an egress-policy denial), so the
                // dedup owner can be released instead of retained. A true value
                // (timeout after send, reset mid-response, etc.) is an ambiguous
                // outcome and stays fail-closed.
                InvocationFailure::new(
                    "invocation_failed",
                    format!("{} invoking serverless function", failure.error_class),
                )
                .with_pre_wire(!failure.request_reached_wire)
            })?;

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

    fn pre_invocation_failure_result(
        &self,
        ctx: &mut RequestContext,
        failure: InvocationFailure,
    ) -> PluginResult {
        let result = self.failure_result(ctx, failure);
        if !matches!(&result, PluginResult::Continue) {
            ctx.serverless_pre_invocation_rejection_owners
                .extend(ctx.request_deduplication_states.keys().copied());
        }
        result
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

fn reject_encoded_request_body(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> Result<(), InvocationFailure> {
    // The buffered body in `ctx.request_body_bytes` is the ORIGINAL client body,
    // so its content coding is described by the ORIGINAL request headers. A
    // header-only `request_transformer` (priority 3000) that removed or renamed
    // `Content-Encoding` before this serverless egress (priority 3025) leaves the
    // transformed `headers` map identity-clean while the compressed bytes remain;
    // the init-time marker preserves that original state so the boundary cannot be
    // bypassed by an earlier header transform.
    if ctx
        .metadata
        .contains_key(crate::proxy::ORIGIN_ENCODED_REQUEST_METADATA_KEY)
    {
        return Err(InvocationFailure::governed_input(
            "encoded_request_body_unsupported",
            "governed request body used a non-identity content-encoding",
        ));
    }
    if let Some(encoding) = headers.get("content-encoding")
        && crate::proxy::content_encoding_declares_non_identity(encoding)
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
    // Start from the same canonical backend-visible query primary dispatch
    // uses: transformer-published outbound query (when present) composed with
    // authentication-owned credential strips. That representation already
    // honors operator query transforms without resurrecting stripped secrets.
    let mut ordered = BTreeMap::new();
    let effective_query = crate::proxy::effective_backend_query_string(ctx);
    if !effective_query.is_empty() {
        for pair in effective_query.split('&').filter(|pair| !pair.is_empty()) {
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
    } else if ctx.raw_query_string().is_none()
        && ctx.outbound_query_string().is_none()
        && !ctx.query_params.is_empty()
    {
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
    sensitive_authority_scalars: Vec<String>,
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
        let sensitive_authority_scalars = normalized_authority_scalar_forms(&sensitive_query_pairs);
        has_unresolved_encoding |= query_has_unresolved_encoding;
        Ok(Self {
            url,
            sensitive_path,
            sensitive_query_pairs,
            sensitive_authority_scalars,
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

        // URL normalization removes an explicit default port (`:443` for
        // HTTPS and `:80` for HTTP). Inspect the supplied authority before
        // normalization so a protected query scalar cannot be hidden there.
        let exposes_explicit_port_scalar = explicit_uri_authority_port(reference)
            .into_iter()
            .chain(explicit_uri_authority_port(&decoded_reference.value))
            .any(|port| self.sensitive_query_scalars().any(|value| value == port));
        if exposes_explicit_port_scalar {
            return true;
        }

        // A function can exfiltrate a DNS-compatible signed query component
        // through the authority even when the path/query/fragment are benign.
        // URL parsing lowercases ASCII domains and IDNA-normalizes Unicode, so
        // compare both original and normalized scalar forms at complete
        // hostname-label (or IP-segment) boundaries.
        let exposes_host_scalar = candidate.host_str().is_some_and(|host| {
            self.sensitive_authority_scalars
                .iter()
                .any(|value| authority_contains_scalar_sequence(host, value))
        });
        let exposes_port_scalar = candidate.port().is_some_and(|port| {
            let port = port.to_string();
            self.sensitive_query_scalars()
                .any(|value| value == port.as_str())
        });
        if exposes_host_scalar || exposes_port_scalar {
            return true;
        }

        // A protected query component can itself be a syntactically valid URI
        // scheme. URL parsing normalizes schemes to ASCII lowercase, so compare
        // exact components case-insensitively instead of allowing a function to
        // echo a signed scalar as `secret://attacker.example`.
        if self
            .sensitive_query_scalars()
            .any(|value| value.eq_ignore_ascii_case(candidate.scheme()))
        {
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
                || self.sensitive_path.as_deref().is_some_and(|path| {
                    let protected_path = path.trim_matches('/');
                    !protected_path.is_empty()
                        && (candidate.0 == protected_path || candidate.1 == protected_path)
                })
        }) {
            return true;
        }

        // URL-bearing fields commonly embed their next destination in an
        // encoded query value, path segment, or fragment. Inspect those URI
        // references recursively, but only when they are syntactically
        // URI-like: treating every scalar as a relative path would remove
        // benign lookalike values such as
        // `https://example.test/next?label=signed/trigger-extra` that resemble
        // but do not match the signed destination. (An exact copy of the signed
        // path into a query scalar is already blocked above as a renamed
        // disclosure.) When a structural reference remains at the depth
        // boundary, fail closed rather than silently treating uninspected
        // nesting as safe.
        for (key, value) in &candidate_pairs {
            if self.nested_reference_exposes_destination(nested_uri_reference(key), depth)
                || self.nested_reference_exposes_destination(nested_uri_reference(value), depth)
            {
                return true;
            }
        }
        let mut nested_path_references = 0;
        for reference in nested_path_uri_references(&candidate_path) {
            nested_path_references += 1;
            if nested_path_references > MAX_NESTED_PATH_URI_REFERENCES
                || self.nested_reference_exposes_destination(Some(reference), depth)
            {
                return true;
            }
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
            if self.sensitive_path.as_deref().is_some_and(|path| {
                // Path-edge slashes are structural delimiters, unlike the
                // slash bytes retained in protected query scalars. Omit
                // them only for this scalar-fragment path comparison so
                // both `#signed/trigger` and `#/signed/trigger` remain
                // governed without weakening query-scalar matching.
                uri_component_contains_sequence(&decoded_fragment.value, path.trim_matches('/'))
            }) || self
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
    /// Both non-empty sides are protected. Although many signed URLs carry the
    /// secret in a value, providers can place credential material in a query
    /// key even when that key also has a value (for example
    /// `?SIGNED_TOKEN=1`). Choosing only one side would let a redirect copy the
    /// other into a renamed key, value, path, or fragment. Slashes are data in
    /// these decoded scalars and must remain intact for exact comparison.
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

fn normalized_authority_scalar_forms(pairs: &[(String, String)]) -> Vec<String> {
    let mut forms = Vec::new();
    let mut seen = HashSet::new();
    for component in pairs
        .iter()
        .flat_map(|(key, value)| [key.as_str(), value.as_str()])
        .filter(|component| !component.is_empty())
    {
        for form in [
            Some(component.to_string()),
            normalized_authority_scalar(component),
        ]
        .into_iter()
        .flatten()
        {
            let dedup_key = form.to_ascii_lowercase();
            if seen.insert(dedup_key) {
                forms.push(form);
            }
        }
    }
    forms
}

fn normalized_authority_scalar(value: &str) -> Option<String> {
    Some(match Host::parse(value).ok()? {
        Host::Domain(hostname) => hostname,
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn authority_contains_scalar_sequence(candidate: &str, sensitive: &str) -> bool {
    let candidate = candidate.as_bytes();
    let sensitive = sensitive.as_bytes();
    if sensitive.is_empty() || sensitive.len() > candidate.len() {
        return false;
    }

    candidate
        .windows(sensitive.len())
        .enumerate()
        .any(|(index, window)| {
            if !window.eq_ignore_ascii_case(sensitive) {
                return false;
            }
            let end = index + sensitive.len();
            let starts_at_boundary = sensitive
                .first()
                .copied()
                .is_some_and(is_authority_scalar_boundary)
                || index == 0
                || candidate
                    .get(index - 1)
                    .copied()
                    .is_some_and(is_authority_scalar_boundary);
            let ends_at_boundary = sensitive
                .last()
                .copied()
                .is_some_and(is_authority_scalar_boundary)
                || end == candidate.len()
                || candidate
                    .get(end)
                    .copied()
                    .is_some_and(is_authority_scalar_boundary);
            starts_at_boundary && ends_at_boundary
        })
}

fn is_authority_scalar_boundary(byte: u8) -> bool {
    matches!(byte, b'.' | b':' | b'[' | b']')
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
    candidate.match_indices(sensitive).any(|(index, _)| {
        let end = index + sensitive.len();
        let starts_at_boundary = sensitive.starts_with('/')
            || index == 0
            || candidate
                .as_bytes()
                .get(index - 1)
                .copied()
                .is_some_and(is_uri_component_boundary);
        let ends_at_boundary = sensitive.ends_with('/')
            || end == candidate.len()
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

fn nested_path_uri_references(value: &str) -> impl Iterator<Item = &str> {
    value.char_indices().filter_map(move |(index, _)| {
        let reference = &value[index..];
        let starts_at_boundary = index == 0
            || value
                .as_bytes()
                .get(index - 1)
                .copied()
                .is_some_and(is_uri_component_boundary);
        (starts_at_boundary
            && (has_ascii_case_insensitive_prefix(reference, "http://")
                || has_ascii_case_insensitive_prefix(reference, "https://")))
        .then_some(reference)
    })
}

fn explicit_uri_authority_port(value: &str) -> Option<&str> {
    let value = value.trim();
    let authority_and_suffix = if let Some(authority) = value.strip_prefix("//") {
        authority
    } else {
        let scheme_end = value.find(':')?;
        let scheme = &value[..scheme_end];
        if !is_valid_uri_scheme(scheme)
            || !value
                .get(scheme_end..)
                .is_some_and(|suffix| suffix.starts_with("://"))
        {
            return None;
        }
        value.get(scheme_end + "://".len()..)?
    };
    let authority_end = authority_and_suffix
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_suffix.len());
    let authority = &authority_and_suffix[..authority_end];
    let host_and_port = authority.rsplit('@').next()?;
    let port = if let Some(bracketed) = host_and_port.strip_prefix('[') {
        let closing_bracket = bracketed.find(']')? + 1;
        host_and_port
            .get(closing_bracket + 1..)?
            .strip_prefix(':')?
    } else {
        host_and_port.rsplit_once(':')?.1
    };
    (!port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())).then_some(port)
}

fn is_valid_uri_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
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
const MAX_NESTED_PATH_URI_REFERENCES: usize = 32;

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

    fn allows_combined_values(self) -> bool {
        matches!(self, Self::Link)
    }
}

fn is_refresh_delay_separator(character: char) -> bool {
    matches!(character, ';' | ',') || character.is_ascii_whitespace()
}

fn refresh_uri_reference(value: &str) -> Result<Option<&str>, ()> {
    let value = value.trim_start_matches(|character: char| character.is_ascii_whitespace());
    let Some(separator) = value.find(is_refresh_delay_separator) else {
        return Ok(None);
    };
    // The browser Refresh algorithm accepts semicolon, comma, or ASCII
    // whitespace after the leading delay. Consume a repeated separator run
    // conservatively so it cannot hide a client-visible destination.
    let directive = value[separator..]
        .trim_start_matches(is_refresh_delay_separator)
        .trim();
    if directive.is_empty() {
        return Ok(None);
    }
    if !has_ascii_case_insensitive_prefix(directive, "url") {
        // Refresh consumers accept a bare URI after the delay separator even
        // without `url=`. Any non-empty scalar is also a valid relative URI
        // reference, so inspect it as a target; benign extensions still pass
        // when they do not expose the signed destination.
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
    let mut safe: HashMap<String, String> = HashMap::new();
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
            if safe.contains_key(lower) {
                // Location, Content-Location, and Refresh are singleton
                // fields. Folding duplicate lines can synthesize a new URI
                // scalar that neither original line exposed, so fail closed.
                // Link is list-valued; preserve it only after validating the
                // exact combined field that Ferrum will return downstream.
                let combined_is_unsafe = if kind.allows_combined_values() {
                    match safe.get_mut(lower) {
                        Some(existing) => {
                            existing.push_str(", ");
                            existing.push_str(value);
                            function_destination.response_header_exposes_destination(kind, existing)
                        }
                        None => true,
                    }
                } else {
                    true
                };
                if combined_is_unsafe {
                    safe.remove(lower);
                    destination_header_blocked[index] = true;
                }
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

fn request_content_type<'a>(
    headers: &'a HashMap<String, String>,
    ctx: &'a RequestContext,
) -> Option<&'a str> {
    headers
        .get("content-type")
        .map(String::as_str)
        .or_else(|| ctx.headers.get("content-type").map(String::as_str))
}

/// True when the frontend classified this request as native gRPC.
///
/// The request-scoped flavor is the ONLY classification used here. Production
/// frontends stamp `RequestContext::request_http_flavor` once at intake, and
/// every downstream consumer of the framed terminate contract — the reject
/// finalizer's `is_grpc_request`, the H1/H2 body builder, and the H3 writers —
/// keys off that same intake decision. The live effective `content-type` is
/// mutable: `request_transformer` runs before this plugin and can rewrite a
/// Plain request's `content-type` to `application/grpc`. Honouring that would
/// make `serverless_function` author a framed unary response for a request the
/// frontend and finalizer still treat as ordinary HTTP, so the header is not
/// consulted.
///
/// gRPC-Web is a separate question with the opposite problem — see
/// [`is_grpc_web_terminate_request`], where the live header is *insufficient*
/// rather than untrustworthy.
fn is_native_grpc_terminate_request(ctx: &RequestContext) -> bool {
    ctx.is_native_grpc_request()
}

/// True when the client spoke gRPC-Web, including after translation.
///
/// The live `content-type` alone cannot answer this: `grpc_web` (priority 260)
/// runs its `on_request_received` / `before_proxy` well ahead of this plugin
/// (3025) and rewrites both `ctx.headers` and the effective header view to
/// `application/grpc`, so a translated browser request is indistinguishable
/// from native gRPC by header inspection at this point. The request-scoped
/// markers are the authoritative signal — the translation claim
/// (`request_is_grpc_web_translated`) and the retained client representation
/// used by pass-through deployments that omit the plugin
/// (`client_uses_grpc_web`) — and neither is derivable from client input.
fn is_grpc_web_terminate_request(headers: &HashMap<String, String>, ctx: &RequestContext) -> bool {
    if crate::plugins::grpc_web::request_is_grpc_web_translated(ctx)
        || crate::plugins::grpc_web::client_uses_grpc_web(ctx)
    {
        return true;
    }
    request_content_type(headers, ctx)
        .is_some_and(crate::plugins::grpc_web::is_grpc_web_content_type)
}

fn sanitize_grpc_terminate_message(message: &str) -> String {
    message
        .chars()
        .map(|c| if matches!(c, '\r' | '\n') { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Render a function-controlled field name for an operator diagnostic: control
/// characters, Unicode line separators, and the surrounding quote delimiter
/// become single-line escapes, and the displayed fragment is capped at
/// [`MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS`].
fn render_grpc_terminate_diagnostic_field_name(name: &str) -> String {
    let mut out = String::new();
    let mut displayed = 0usize;
    for ch in name.chars() {
        let segment = match ch {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            '\'' => "\\'".to_string(),
            '\\' => "\\\\".to_string(),
            '\u{2028}' => "\\u{2028}".to_string(),
            '\u{2029}' => "\\u{2029}".to_string(),
            c if c.is_control() => format!("\\u{{{:04x}}}", c as u32),
            c => c.to_string(),
        };
        let segment_chars = segment.chars().count();
        if displayed.saturating_add(segment_chars) > MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS
        {
            if displayed < MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS {
                out.push('…');
            }
            break;
        }
        displayed = displayed.saturating_add(segment_chars);
        out.push_str(&segment);
    }
    out
}

/// Bound a terminate-contract operator detail to a single line of at most
/// [`MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS`] characters.
fn bound_grpc_terminate_operator_detail(detail: String) -> String {
    let single_line: String = detail
        .chars()
        .map(|c| {
            if matches!(c, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let char_count = single_line.chars().count();
    if char_count <= MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS {
        return single_line;
    }
    let keep = MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS.saturating_sub(1);
    let truncated: String = single_line.chars().take(keep).collect();
    format!("{truncated}…")
}

/// Fail-closed terminate-contract refusal under the fixed client-visible class.
/// The operator detail is bounded and single-line; the client only sees `code`.
fn invalid_grpc_terminate_response(operator_detail: impl Into<String>) -> InvocationFailure {
    InvocationFailure::new(
        "invalid_grpc_terminate_response",
        bound_grpc_terminate_operator_detail(operator_detail.into()),
    )
}

/// Diagnostic for unknown top-level contract members: a deterministic bounded
/// sample plus a count, never an unbounded joined inventory of names.
/// Returns `None` when every member is recognized.
fn unknown_grpc_terminate_fields_detail<'a>(
    unknown_keys: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let mut unknown_count = 0usize;
    let mut sample: Vec<&'a str> = Vec::with_capacity(MAX_GRPC_TERMINATE_UNKNOWN_FIELD_SAMPLE);
    for key in unknown_keys {
        unknown_count += 1;
        if sample.len() < MAX_GRPC_TERMINATE_UNKNOWN_FIELD_SAMPLE {
            sample.push(key);
        }
    }
    if unknown_count == 0 {
        return None;
    }
    let mut rendered = String::from("unknown gRPC terminate response field(s) (");
    rendered.push_str(&unknown_count.to_string());
    rendered.push_str("): ");
    for (index, key) in sample.iter().enumerate() {
        if index > 0 {
            rendered.push_str(", ");
        }
        rendered.push('\'');
        rendered.push_str(&render_grpc_terminate_diagnostic_field_name(key));
        rendered.push('\'');
    }
    if unknown_count > sample.len() {
        rendered.push_str(", …");
    }
    Some(rendered)
}

/// Encode a sanitized status message into the canonical `grpc-message` wire
/// form required by the gRPC HTTP/2 mapping:
///
/// ```text
/// Status-Message         = Percent-Encoded
/// Percent-Encoded        = 1*(Percent-Byte-Unescaped / Percent-Encoded-Byte)
/// Percent-Byte-Unescaped = %x20-%x24 / %x26-%x7E
/// Percent-Encoded-Byte   = "%" 2HEXDIG
/// ```
///
/// Bytes the grammar allows unescaped stay literal. `%` (0x25) is escaped so an
/// author's literal percent sign cannot be decoded by the client as an escape,
/// and every byte outside `0x20..=0x7E` — ASCII controls the CR/LF sanitizer
/// does not cover, `DEL`, and each UTF-8 continuation byte of a non-ASCII
/// character — is escaped as `%XX`. Hex digits are uppercase, matching the
/// canonical form other gRPC implementations emit.
///
/// The result is pure printable ASCII, so it is a valid HTTP field value by
/// construction, contains no CR/LF, and is a fixed point of the gateway's
/// downstream `sanitize_grpc_message` (the input was already trimmed, so no
/// leading/trailing space survives to be trimmed again). That is what keeps the
/// emitted value byte-stable across the H1/H2 normalizer and both H3 writers.
fn percent_encode_grpc_message(message: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(message.len());
    for &byte in message.as_bytes() {
        if matches!(byte, 0x20..=0x24 | 0x26..=0x7e) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
            encoded.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
        }
    }
    encoded
}

/// Frame one uncompressed unary gRPC DATA message: flag(0) + BE length + bytes.
fn frame_uncompressed_unary_grpc_message(message: &[u8]) -> Result<Bytes, String> {
    let len = u32::try_from(message.len()).map_err(|_| {
        "serverless_function: gRPC terminate message exceeds u32 length".to_string()
    })?;
    let mut framed = Vec::with_capacity(5 + message.len());
    framed.push(0);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(Bytes::from(framed))
}

/// Decode a standard-base64 contract field under a decoded-byte ceiling.
///
/// `limit_label` names the ceiling that was violated so an operator can tell a
/// `max_response_body_bytes` overrun apart from a trailer-value overrun without
/// reading the source.
fn decode_bounded_base64_field(
    value: &str,
    field: &str,
    max_decoded_bytes: usize,
    limit_label: &str,
) -> Result<Vec<u8>, String> {
    // Reject standard/base64url alphabet waste that would decode far beyond the
    // ceiling before allocating the decoded buffer.
    let approx_decoded = value.len().saturating_mul(3) / 4;
    if approx_decoded > max_decoded_bytes.saturating_add(3) {
        return Err(format!(
            "serverless_function: gRPC terminate '{field}' exceeds {limit_label}"
        ));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| {
            format!("serverless_function: gRPC terminate '{field}' must be standard base64")
        })?;
    if decoded.len() > max_decoded_bytes {
        return Err(format!(
            "serverless_function: gRPC terminate '{field}' exceeds {limit_label}"
        ));
    }
    Ok(decoded)
}

fn is_reserved_grpc_terminate_trailer_name(name: &str) -> bool {
    crate::proxy::grpc_proxy::is_reserved_grpc_terminal_metadata(name)
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("grpc-encoding")
        || name.eq_ignore_ascii_case("grpc-accept-encoding")
}

/// Charge a built terminate field map the way an H2/H3 peer charges a header
/// list: name bytes + value bytes + per-field overhead, over every field.
///
/// Returns `None` on arithmetic overflow so the caller fails closed rather than
/// wrapping into an apparently small total.
fn grpc_terminate_terminal_block_bytes(fields: &HashMap<String, String>) -> Option<usize> {
    let mut total: usize = 0;
    for (name, value) in fields {
        total = total
            .checked_add(name.len())?
            .checked_add(value.len())?
            .checked_add(GRPC_TERMINATE_HEADER_FIELD_OVERHEAD_BYTES)?;
    }
    Some(total)
}

/// Parse the terminate-mode native-gRPC JSON contract and build the client
/// RejectBinary parts (HTTP 200 + `application/grpc` + framed unary body /
/// trailers-only signalling).
///
/// Contract (fail-closed, unknown fields rejected):
/// ```json
/// {
///   "grpc_status": 0,
///   "grpc_message": "optional",
///   "message_base64": "optional raw protobuf bytes",
///   "status_details_base64": "optional grpc-status-details-bin",
///   "trailers": { "x-custom": "value" }
/// }
/// ```
///
/// The gateway owns framing and reserved terminal metadata. Compression and
/// streaming forms are rejected explicitly.
///
/// The raw bytes are screened with the shared bounded duplicate-member scanner
/// ([`crate::util::json_dup_keys`], advisory `GHSA-c78j-5w9p-cpq6`) BEFORE
/// `serde_json` collapses them. `serde_json` keeps the LAST of duplicate object
/// members, so without this screen a function response carrying
/// `"grpc_status": 0` twice — or spelling one of them with a `\u` escape, or
/// duplicating a member of the nested `trailers` object — would have the
/// gateway author a terminal status/trailer set that a first-wins parser reading
/// the same bytes never agrees with. That authored representation is exactly
/// what `FramedGrpcUnaryProvenance` then binds and emits as trailers, so the
/// ambiguity must be refused rather than resolved.
fn build_native_grpc_terminate_response(
    function_http_status: u16,
    body: &[u8],
    max_response_body_bytes: usize,
) -> Result<(u16, Bytes, HashMap<String, String>), InvocationFailure> {
    if !(200..=299).contains(&function_http_status) {
        return Err(InvocationFailure::new(
            "invalid_grpc_terminate_status",
            format!(
                "gRPC terminate requires a 2xx function HTTP status, got {function_http_status}"
            ),
        ));
    }

    // Screen the RAW bytes before `serde_json` collapses duplicate members. The
    // scanner walks nested objects under explicit budgets and compares DECODED
    // member names, so an escaped-equivalent spelling and a duplicate inside
    // `trailers` are both caught; budget exhaustion fails closed as well.
    // Ordinary malformed bytes report nothing here and keep the existing
    // malformed-body diagnostic below.
    //
    // `reason` is one of a fixed set of `&'static str` values and never contains
    // any byte of the inspected document, so this stays operator-safe even
    // though the function response is attacker-influencable through the request.
    if let Some(reason) = crate::util::json_dup_keys::slice_ambiguity(body) {
        return Err(invalid_grpc_terminate_response(format!(
            "gRPC terminate function response is ambiguous: {reason}"
        )));
    }

    let parsed: Value = serde_json::from_slice(body).map_err(|_| {
        invalid_grpc_terminate_response("gRPC terminate function response must be a JSON object")
    })?;
    let object = parsed.as_object().ok_or_else(|| {
        invalid_grpc_terminate_response("gRPC terminate function response must be a JSON object")
    })?;

    // Reject unsupported streaming / compression contract shapes explicitly
    // before the generic unknown-field diagnostic so operators get a precise
    // reason rather than a field-list error.
    if object.contains_key("streaming")
        || object.contains_key("messages")
        || object.contains_key("grpc_encoding")
        || object.contains_key("message_compressed")
        || object.contains_key("compression")
    {
        return Err(InvocationFailure::new(
            "unsupported_grpc_terminate_encoding",
            "gRPC terminate supports only uncompressed unary responses",
        ));
    }

    // Never collect/sort/join an unbounded inventory of unknown names solely for
    // logging. serde_json::Map iterates in sorted key order, so the first
    // sample slots are deterministic; only a bounded sample plus a count is
    // rendered, and each name fragment is escaped/capped.
    if let Some(detail) = unknown_grpc_terminate_fields_detail(
        object
            .keys()
            .map(String::as_str)
            .filter(|key| !GRPC_TERMINATE_RESPONSE_FIELDS.contains(key)),
    ) {
        return Err(invalid_grpc_terminate_response(detail));
    }

    let grpc_status = object
        .get("grpc_status")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_grpc_terminate_response(
                "gRPC terminate response requires integer 'grpc_status'",
            )
        })?;
    if grpc_status > u64::from(u32::MAX) {
        return Err(invalid_grpc_terminate_response(
            "gRPC terminate 'grpc_status' is out of range",
        ));
    }
    let grpc_status = grpc_status as u32;

    let grpc_message = match object.get("grpc_message") {
        None => None,
        Some(Value::String(message)) => {
            // The contract documents `grpc_message` as human-readable text, but
            // the wire field is `Percent-Encoded` per the gRPC HTTP mapping.
            // Normalize CR/LF deterministically first, then encode; emitting the
            // raw text would put a bare `%` (which clients decode as an escape)
            // and raw non-ASCII bytes into a field whose grammar forbids both.
            let sanitized = sanitize_grpc_terminate_message(message);
            if sanitized.is_empty() {
                None
            } else {
                let encoded = percent_encode_grpc_message(&sanitized);
                // `grpc_message` becomes a terminal trailer value, so it is
                // bound by the same advertised wire ceiling every other trailer
                // value is. Without this it inherits only
                // `max_response_body_bytes` — many MiB on a default deployment —
                // and a single status message could dominate the TRAILERS block.
                // The check is on the ENCODED bytes because those are what reach
                // the wire: percent-encoding expands a byte threefold, so
                // bounding the pre-encoding string would admit a ~24 KiB field.
                if encoded.len() > MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES {
                    return Err(invalid_grpc_terminate_response(format!(
                        "gRPC terminate 'grpc_message' exceeds {MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES} bytes once percent-encoded"
                    )));
                }
                // Custom trailers are field-value validated below; hold the
                // protocol-owned message to the same bar. Percent-encoding
                // already guarantees printable ASCII, so this cannot fire today
                // — it is retained so a future change to the encoder fails
                // closed here rather than silently dropping `grpc-message` at
                // trailer construction, where `HeaderValue::from_str` errors are
                // discarded.
                if HeaderValue::from_str(&encoded).is_err() {
                    return Err(invalid_grpc_terminate_response(
                        "gRPC terminate 'grpc_message' is not a valid HTTP field value",
                    ));
                }
                Some(encoded)
            }
        }
        Some(_) => {
            return Err(invalid_grpc_terminate_response(
                "gRPC terminate 'grpc_message' must be a string",
            ));
        }
    };

    // Message bytes are raw protobuf (not length-prefixed). Frame overhead is 5
    // bytes; keep the framed unary payload within max_response_body_bytes.
    let max_message_bytes = max_response_body_bytes.saturating_sub(5);
    let message_bytes = match object.get("message_base64") {
        None => None,
        Some(Value::String(encoded)) => {
            if encoded.is_empty() {
                Some(Vec::new())
            } else {
                Some(
                    decode_bounded_base64_field(
                        encoded,
                        "message_base64",
                        max_message_bytes,
                        "max_response_body_bytes",
                    )
                    .map_err(invalid_grpc_terminate_response)?,
                )
            }
        }
        Some(_) => {
            return Err(invalid_grpc_terminate_response(
                "gRPC terminate 'message_base64' must be a string",
            ));
        }
    };

    let status_details = match object.get("status_details_base64") {
        None => None,
        Some(Value::String(encoded)) => {
            if encoded.is_empty() {
                None
            } else {
                // The ceiling is on the re-encoded wire value, so the decoded
                // ceiling is scaled down by base64's 4/3 expansion. Bounding the
                // decoded bytes at the wire cap instead would admit a ~10.9 KiB
                // trailer value.
                let details_limit_label = format!(
                    "the {MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES}-byte \
                     grpc-status-details-bin trailer value ceiling"
                );
                let decoded = decode_bounded_base64_field(
                    encoded,
                    "status_details_base64",
                    MAX_GRPC_TERMINATE_STATUS_DETAILS_DECODED_BYTES,
                    &details_limit_label,
                )
                .map_err(invalid_grpc_terminate_response)?;
                // grpc-status-details-bin is a binary trailer; re-encode the
                // validated bytes so only well-formed base64 reaches the wire.
                let reencoded = base64::engine::general_purpose::STANDARD.encode(decoded);
                // Belt-and-braces on the value that is actually emitted: the
                // decoded ceiling above is derived from this one, so a future
                // change to either constant cannot silently widen the wire cap.
                if reencoded.len() > MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES {
                    return Err(invalid_grpc_terminate_response(format!(
                        "gRPC terminate 'status_details_base64' re-encodes to more than \
                         {MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES} bytes"
                    )));
                }
                Some(reencoded)
            }
        }
        Some(_) => {
            return Err(invalid_grpc_terminate_response(
                "gRPC terminate 'status_details_base64' must be a string",
            ));
        }
    };

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert("grpc-status".to_string(), grpc_status.to_string());
    if let Some(message) = grpc_message {
        response_headers.insert("grpc-message".to_string(), message);
    }
    if let Some(details) = status_details {
        response_headers.insert("grpc-status-details-bin".to_string(), details);
    }

    if let Some(trailers_value) = object.get("trailers") {
        let trailers = trailers_value.as_object().ok_or_else(|| {
            invalid_grpc_terminate_response(
                "gRPC terminate 'trailers' must be an object of string values",
            )
        })?;
        if trailers.len() > MAX_GRPC_TERMINATE_CUSTOM_TRAILERS {
            return Err(invalid_grpc_terminate_response(format!(
                "gRPC terminate 'trailers' exceeds {MAX_GRPC_TERMINATE_CUSTOM_TRAILERS} entries"
            )));
        }
        // HTTP/gRPC metadata names are case-insensitive, so `X-Foo` and `x-foo`
        // are the SAME trailer. JSON object members are not: both survive
        // parsing as distinct keys and would collapse on insertion, silently
        // emitting whichever the map iterated last. That is nondeterministic
        // (map order) and loses an authored value, so reject it with a
        // field-specific diagnostic instead.
        //
        // Deliberately scoped to case folding: the shared `json_dup_keys` screen
        // at the top of this function already refused every JSON-level duplicate
        // member name (including this nested `trailers` object), so what remains
        // here is the HTTP-specific collision that JSON considers two distinct
        // members.
        let mut seen_trailer_names: HashSet<String> = HashSet::with_capacity(trailers.len());
        for (name, value) in trailers {
            let displayed_name = render_grpc_terminate_diagnostic_field_name(name);
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                invalid_grpc_terminate_response(format!(
                    "gRPC terminate trailer name '{displayed_name}' is not a valid HTTP field name"
                ))
            })?;
            let lower = header_name.as_str();
            let displayed_lower = render_grpc_terminate_diagnostic_field_name(lower);
            if !crate::plugins::grpc_web::is_grpc_metadata_name(lower) {
                return Err(invalid_grpc_terminate_response(format!(
                    "gRPC terminate trailer name '{displayed_name}' is outside the gRPC metadata name alphabet"
                )));
            }
            if !seen_trailer_names.insert(lower.to_string()) {
                return Err(invalid_grpc_terminate_response(format!(
                    "gRPC terminate 'trailers' declares '{displayed_lower}' more than once; \
                     trailer names are case-insensitive"
                )));
            }
            if is_reserved_grpc_terminate_trailer_name(lower) {
                return Err(invalid_grpc_terminate_response(format!(
                    "gRPC terminate trailer '{displayed_lower}' is protocol-owned; use the dedicated contract fields"
                )));
            }
            let value = value.as_str().ok_or_else(|| {
                invalid_grpc_terminate_response(format!(
                    "gRPC terminate trailer '{displayed_lower}' must be a string"
                ))
            })?;
            if value.len() > MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES {
                return Err(invalid_grpc_terminate_response(format!(
                    "gRPC terminate trailer '{displayed_lower}' exceeds {MAX_GRPC_TERMINATE_TRAILER_VALUE_BYTES} bytes"
                )));
            }
            if !crate::plugins::grpc_web::is_valid_trailer_value(value)
                || HeaderValue::from_str(value).is_err()
            {
                return Err(invalid_grpc_terminate_response(format!(
                    "gRPC terminate trailer '{displayed_lower}' is not a valid gRPC ASCII value"
                )));
            }
            if lower.ends_with("-bin") && !crate::plugins::grpc_web::is_base64_metadata_value(value)
            {
                return Err(invalid_grpc_terminate_response(format!(
                    "gRPC terminate binary trailer '{displayed_lower}' must contain standard base64, with or without padding"
                )));
            }
            // Values are validated above and never interpolated into diagnostics.
            response_headers.insert(lower.to_string(), value.to_string());
        }
    }

    // Aggregate bound on the COMPLETE terminal metadata block. Per-entry and
    // per-count limits above bound one field and the field count; neither bounds
    // the block a peer actually has to accept. `response_headers` is exactly what
    // both authored shapes emit — the framed shape sends it as trailers, the
    // status-only shape as a Trailers-Only HEADERS block — so charging the map
    // here covers both. The gateway's own `content-type` is charged too: it
    // shares that single block in the trailers-only shape, and counting it is
    // the conservative direction.
    //
    // The diagnostic is fixed text: it names no trailer, echoes no value, and so
    // cannot leak attacker- or function-supplied material into operator logs.
    let block_bytes = grpc_terminate_terminal_block_bytes(&response_headers).ok_or_else(|| {
        invalid_grpc_terminate_response(
            "gRPC terminate terminal metadata block size is not representable",
        )
    })?;
    if block_bytes > MAX_GRPC_TERMINATE_TERMINAL_BLOCK_BYTES {
        return Err(invalid_grpc_terminate_response(format!(
            "gRPC terminate terminal metadata exceeds the {MAX_GRPC_TERMINATE_TERMINAL_BLOCK_BYTES}-byte \
             aggregate header-list budget (names + values + 32 bytes per field)"
        )));
    }

    let framed_body = match message_bytes {
        Some(message) => frame_uncompressed_unary_grpc_message(&message)
            .map_err(invalid_grpc_terminate_response)?,
        None => Bytes::new(),
    };
    if framed_body.len() > max_response_body_bytes {
        return Err(invalid_grpc_terminate_response(
            "framed gRPC terminate response exceeds max_response_body_bytes",
        ));
    }

    Ok((200, framed_body, response_headers))
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

    pub fn frame_uncompressed_unary_grpc_message_test(message: &[u8]) -> Result<Bytes, String> {
        frame_uncompressed_unary_grpc_message(message)
    }

    /// The canonical `grpc-message` percent encoder, so the wire form asserted
    /// by tests is the one the plugin actually emits.
    pub fn percent_encode_grpc_message_test(message: &str) -> String {
        percent_encode_grpc_message(message)
    }

    pub fn build_native_grpc_terminate_response_test(
        function_http_status: u16,
        body: &[u8],
        max_response_body_bytes: usize,
    ) -> Result<(u16, Bytes, HashMap<String, String>), String> {
        build_native_grpc_terminate_response(function_http_status, body, max_response_body_bytes)
            .map_err(|failure| failure.operator_detail)
    }

    /// The failure CODE for a refused terminate contract. That code — not the
    /// operator detail — is the only thing `failure_result` puts in the
    /// client-visible reject body, so a test that pins the fail-closed class
    /// must assert on it rather than on the log-only diagnostic.
    pub fn build_native_grpc_terminate_response_error_code_test(
        function_http_status: u16,
        body: &[u8],
        max_response_body_bytes: usize,
    ) -> Result<(), &'static str> {
        build_native_grpc_terminate_response(function_http_status, body, max_response_body_bytes)
            .map(|_| ())
            .map_err(|failure| failure.code)
    }

    /// Complete operator-diagnostic character ceiling for terminate-contract
    /// refusals. Pinned by hostile-input diagnostic tests.
    pub const MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS_TEST: usize =
        MAX_GRPC_TERMINATE_OPERATOR_DETAIL_CHARS;

    /// Per field-name fragment character ceiling inside those diagnostics.
    pub const MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS_TEST: usize =
        MAX_GRPC_TERMINATE_DIAGNOSTIC_FIELD_NAME_CHARS;

    /// Maximum unknown top-level names sampled into the diagnostic.
    pub const MAX_GRPC_TERMINATE_UNKNOWN_FIELD_SAMPLE_TEST: usize =
        MAX_GRPC_TERMINATE_UNKNOWN_FIELD_SAMPLE;
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

        // Terminate + gRPC-Web is unsupported: gRPC-Web framing/trailer encoding
        // is owned by the grpc_web plugin, and RejectBinary normalization cannot
        // synthesize a correct browser-facing response from the unary contract.
        if self.mode == InvocationMode::Terminate && is_grpc_web_terminate_request(headers, ctx) {
            warn!(
                "serverless_function: terminate mode does not support gRPC-Web requests — \
                 use native application/grpc or HTTP terminate"
            );
            ctx.serverless_pre_invocation_rejection_owners
                .extend(ctx.request_deduplication_states.keys().copied());
            return PluginResult::Reject {
                status_code: 500,
                body: r#"{"error":"serverless_function terminate mode does not support gRPC-Web"}"#
                    .to_string(),
                headers: HashMap::new(),
            };
        }

        let native_grpc_terminate =
            self.mode == InvocationMode::Terminate && is_native_grpc_terminate_request(ctx);

        let payload = match self.build_invocation_payload(ctx, headers) {
            Ok(payload) => payload,
            Err(failure) => return self.pre_invocation_failure_result(ctx, failure),
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
            Err(failure) if failure.proven_pre_wire => {
                // The outbound request never reached the function, so no external
                // side effect occurred. Undo the anticipatory terminate-mode
                // side-effect provenance and release the dedup marker like any
                // other pre-invocation rejection, so an identical retry can
                // proceed instead of being blocked/replayed until inflight_ttl.
                let owners: Vec<u64> = ctx.request_deduplication_states.keys().copied().collect();
                for owner in owners {
                    ctx.serverless_external_side_effect_owners.remove(&owner);
                }
                return self.pre_invocation_failure_result(ctx, failure);
            }
            Err(failure) => return self.failure_result(ctx, failure),
        };
        ctx.metadata
            .insert(self.metadata_key("status"), status.to_string());

        match self.mode {
            InvocationMode::Terminate => {
                if native_grpc_terminate {
                    match build_native_grpc_terminate_response(
                        status,
                        &body,
                        self.max_response_body_bytes,
                    ) {
                        Ok((status_code, framed_body, grpc_headers)) => {
                            debug!(
                                "serverless_function: terminate mode — returning framed unary gRPC response"
                            );
                            ctx.serverless_terminate_response = true;
                            // Byte-exact provenance for the ONE rejection that
                            // may keep a body on a native gRPC stream, together
                            // with the terminal metadata that is allowed to
                            // reach the client as trailers.
                            //
                            // An empty `framed_body` is the status-only contract
                            // shape: it authors NO frame, so this provenance can
                            // never authorize DATA (`authorized_trailers`
                            // refuses an empty frame). It is still recorded,
                            // because the authored status + terminal metadata
                            // are what let the normalizer tell an *unchanged*
                            // status-only reply (legitimately trailers-only)
                            // apart from one a response-body policy rewrote or
                            // re-statused. Without it, an invalidated
                            // status-only contract falls back to the mutable
                            // reject header map and can ship the contract's
                            // `grpc-status: 0` as an empty Trailers-Only
                            // success.
                            let trailers = grpc_headers
                                .iter()
                                .filter(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
                                .map(|(name, value)| (name.clone(), value.clone()))
                                .collect();
                            let authored = crate::plugins::ServerlessGrpcTerminateFrame {
                                http_status: status_code,
                                frame: framed_body.clone(),
                                trailers,
                            };
                            ctx.serverless_grpc_terminate_frame =
                                Some(std::sync::Arc::new(authored));
                            return PluginResult::RejectBinary {
                                status_code,
                                body: framed_body,
                                headers: grpc_headers,
                            };
                        }
                        Err(mut failure) => {
                            // Malformed/oversized/unsupported function output is
                            // not a faithful client representation; never continue
                            // to the backend with on_error=continue.
                            failure.must_reject = true;
                            return self.failure_result(ctx, failure);
                        }
                    }
                }

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
                // Every valid terminate response is application-owned content,
                // including redirects and errors. Mark it for the shared
                // synthetic body lifecycle so configured response transforms
                // and successful-response guardrails are not limited to the
                // ordinary synthetic-2xx gate. Replays are already stored after
                // this lifecycle and deliberately do not set the marker again.
                ctx.serverless_terminate_response = true;
                let mut response_headers = response_headers;
                let omit_body =
                    crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire(
                        &ctx.method,
                        status,
                        &mut response_headers,
                        body.len(),
                    );
                PluginResult::RejectBinary {
                    status_code: status,
                    body: if omit_body { Bytes::new() } else { body },
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
