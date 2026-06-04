//! A2A Gateway plugin.
//!
//! Provides transparent observability and light policy enforcement for
//! Agent-to-Agent protocol traffic over HTTP JSON-RPC, HTTP+JSON/REST, and
//! gRPC. The plugin does not own A2A task state or route between agents in V1.

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use tracing::warn;
use url::Url;

use super::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext};

const DEFAULT_ENDPOINT_PATH: &str = "/a2a";
const DEFAULT_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const DEFAULT_PROTOCOL_VERSION: &str = "0.3.0";
const DEFAULT_VERSION_HEADER: &str = "A2A-Version";
const DEFAULT_MAX_DETECTION_BODY_BYTES: u64 = 1024 * 1024;
const DEFAULT_GRPC_SERVICE: &str = "lf.a2a.v1.A2AService";

const JSONRPC_METHODS: &[&str] = &[
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/list",
    "tasks/cancel",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
    "agent/getCard",
    "agent/getExtendedAgentCard",
    "agent/getAuthenticatedExtendedCard",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum A2aBinding {
    JsonRpc,
    Rest,
    Grpc,
}

impl A2aBinding {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "jsonrpc" | "json-rpc" => Ok(Self::JsonRpc),
            "rest" | "http_json" | "http+json" => Ok(Self::Rest),
            "grpc" => Ok(Self::Grpc),
            other => Err(format!(
                "a2a_gateway: detection.bindings entries must be jsonrpc, rest, or grpc, got {other:?}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::JsonRpc => "jsonrpc",
            Self::Rest => "rest",
            Self::Grpc => "grpc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAction {
    Allow,
    Deny,
}

impl PolicyAction {
    fn parse(value: &str, field: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "a2a_gateway: '{field}' must be allow or deny, got {other:?}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone)]
struct A2aEndpointConfig {
    path: String,
    agent_card_path: String,
    protocol_versions: Vec<String>,
    grpc_services: HashSet<String>,
}

#[derive(Debug, Clone)]
struct A2aDetectionConfig {
    bindings: HashSet<A2aBinding>,
    version_header: String,
    max_request_body_size: u64,
    allow_unknown_methods_with_version_header: bool,
    strip_accept_encoding: bool,
}

#[derive(Debug, Clone)]
struct A2aDiscoveryConfig {
    rewrite_agent_card_urls: bool,
    public_base_url: Option<String>,
    trust_forwarded_headers: bool,
}

#[derive(Debug, Clone)]
struct A2aObservabilityConfig {
    emit_metadata: bool,
    log_payloads: bool,
    max_payload_size: usize,
}

#[derive(Debug, Clone)]
struct A2aPolicyConfig {
    default_action: PolicyAction,
    methods: HashMap<String, PolicyAction>,
}

#[derive(Debug, Clone)]
struct A2aEnvelope {
    id: Option<Value>,
    method: Option<String>,
    jsonrpc: Option<String>,
    is_request: bool,
    is_error: bool,
}

#[derive(Debug, Clone)]
struct A2aDetection {
    binding: A2aBinding,
    method: String,
    jsonrpc_id: Option<Value>,
    task_id_hint: Option<String>,
    streaming_hint: bool,
    is_agent_card: bool,
    oversized_body: bool,
}

pub struct A2aGateway {
    enabled: bool,
    endpoint: A2aEndpointConfig,
    detection: A2aDetectionConfig,
    discovery: A2aDiscoveryConfig,
    observability: A2aObservabilityConfig,
    policy: A2aPolicyConfig,
}

impl A2aGateway {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "a2a_gateway: config must be an object".to_string())?;
        let enabled = optional_bool(object, "enabled")?.unwrap_or(true);
        let mode = optional_string(object, "mode")?.unwrap_or("transparent_proxy");
        if mode != "transparent_proxy" {
            return Err(format!(
                "a2a_gateway: 'mode' must be transparent_proxy in V1, got {mode:?}"
            ));
        }
        let endpoint = parse_endpoint(object)?;
        let detection = parse_detection(object)?;
        let discovery = parse_discovery(object)?;
        let observability = parse_observability(object)?;
        let policy = parse_policy(object)?;
        Ok(Self {
            enabled,
            endpoint,
            detection,
            discovery,
            observability,
            policy,
        })
    }

    fn request_body<'a>(&self, ctx: &'a RequestContext) -> Option<&'a [u8]> {
        ctx.request_body_bytes
            .as_ref()
            .map(|body| body.as_ref())
            .or_else(|| ctx.metadata.get("request_body").map(|body| body.as_bytes()))
    }

    fn maybe_detect(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if self.detection.bindings.contains(&A2aBinding::Grpc)
            && let Some(detection) = self.detect_grpc(ctx, headers)
        {
            return Some(detection);
        }
        if self.detection.bindings.contains(&A2aBinding::Rest)
            && let Some(detection) = self.detect_rest(ctx)
        {
            return Some(detection);
        }
        if self.detection.bindings.contains(&A2aBinding::JsonRpc)
            && let Some(detection) = self.detect_jsonrpc(ctx, headers)
        {
            return Some(detection);
        }
        None
    }

    fn detect_jsonrpc(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if !ctx.method.eq_ignore_ascii_case("POST") || ctx.path != self.endpoint.path {
            return None;
        }
        if !content_type_is_json(headers) {
            return None;
        }
        let body = self.request_body(ctx)?;
        if self.detection.max_request_body_size > 0
            && body.len() as u64 > self.detection.max_request_body_size
        {
            warn!(
                body_size = body.len(),
                max_request_body_size = self.detection.max_request_body_size,
                "Skipping A2A JSON-RPC detection because request body exceeds plugin detection limit"
            );
            if self.policy_requires_inspection() {
                return Some(A2aDetection {
                    binding: A2aBinding::JsonRpc,
                    method: "unknown".to_string(),
                    jsonrpc_id: None,
                    task_id_hint: None,
                    streaming_hint: false,
                    is_agent_card: false,
                    oversized_body: true,
                });
            }
            return None;
        }
        let value: Value = serde_json::from_slice(body).ok()?;
        let envelope = parse_jsonrpc_envelope(&value).ok()?;
        if envelope.jsonrpc.as_deref() != Some("2.0") || !envelope.is_request {
            return None;
        }
        let method = envelope.method.unwrap_or_else(|| "unknown".to_string());
        let canonical_method = canonical_a2a_method(&method);
        let accepted_unknown = self.detection.allow_unknown_methods_with_version_header
            && header_value(headers, &self.detection.version_header).is_some();
        if canonical_method.is_none() && !accepted_unknown {
            return None;
        }
        let metric_method = canonical_method.unwrap_or("unknown").to_string();
        let is_agent_card = is_agent_card_method(&metric_method);
        Some(A2aDetection {
            binding: A2aBinding::JsonRpc,
            streaming_hint: is_streaming_method(&metric_method),
            method: metric_method,
            jsonrpc_id: envelope.id,
            task_id_hint: extract_task_id_from_request(&value),
            is_agent_card,
            oversized_body: false,
        })
    }

    fn detect_rest(&self, ctx: &RequestContext) -> Option<A2aDetection> {
        let method = ctx.method.as_str();
        let path = ctx.path.as_str();
        if path.ends_with(&self.endpoint.agent_card_path) && method.eq_ignore_ascii_case("GET") {
            return Some(A2aDetection {
                binding: A2aBinding::Rest,
                method: "agent/getCard".to_string(),
                jsonrpc_id: None,
                task_id_hint: None,
                streaming_hint: false,
                is_agent_card: true,
                oversized_body: false,
            });
        }
        let rest = self.rest_suffix(path)?;
        let (operation, task_id, streaming) = match_rest_operation(method, rest)?;
        Some(A2aDetection {
            binding: A2aBinding::Rest,
            method: operation.to_string(),
            jsonrpc_id: None,
            task_id_hint: task_id,
            streaming_hint: streaming,
            is_agent_card: matches!(
                operation,
                "agent/getCard"
                    | "agent/getExtendedAgentCard"
                    | "agent/getAuthenticatedExtendedCard"
            ),
            oversized_body: false,
        })
    }

    fn detect_grpc(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<A2aDetection> {
        if !is_grpc_request(headers) {
            return None;
        }
        let normalized = ctx.path.strip_prefix('/').unwrap_or(ctx.path.as_str());
        let (service, grpc_method) = normalized.split_once('/')?;
        if !self.endpoint.grpc_services.contains(service) {
            return None;
        }
        let (operation, streaming) = grpc_operation(grpc_method)?;
        Some(A2aDetection {
            binding: A2aBinding::Grpc,
            method: operation.to_string(),
            jsonrpc_id: None,
            task_id_hint: None,
            streaming_hint: streaming,
            is_agent_card: operation == "agent/getCard",
            oversized_body: false,
        })
    }

    fn emit_base_metadata(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        detection: &A2aDetection,
    ) {
        ctx.a2a_gateway_detected = true;
        ctx.a2a_gateway_binding = Some(detection.binding.as_str());
        ctx.a2a_gateway_is_agent_card = detection.is_agent_card;
        ctx.a2a_gateway_streaming = detection.streaming_hint;

        if !self.observability.emit_metadata {
            return;
        }
        ctx.metadata
            .insert("a2a.enabled".to_string(), "true".to_string());
        ctx.metadata
            .insert("a2a.mode".to_string(), "transparent_proxy".to_string());
        ctx.metadata.insert(
            "a2a.binding".to_string(),
            detection.binding.as_str().to_string(),
        );
        ctx.metadata
            .insert("a2a.method".to_string(), detection.method.clone());
        ctx.metadata.insert(
            "a2a.streaming".to_string(),
            detection.streaming_hint.to_string(),
        );
        ctx.metadata
            .entry("a2a.policy_decision".to_string())
            .or_insert_with(|| "allow".to_string());
        if let Some(version) = header_value(headers, &self.detection.version_header)
            .or_else(|| self.endpoint.protocol_versions.first().map(String::as_str))
        {
            ctx.metadata
                .insert("a2a.protocol_version".to_string(), version.to_string());
        }
        if let Some(task_id) = detection.task_id_hint.as_deref() {
            ctx.metadata
                .insert("a2a.task_id".to_string(), task_id.to_string());
        }
    }

    fn policy_action(&self, method: &str) -> PolicyAction {
        self.policy
            .methods
            .get(method)
            .copied()
            .unwrap_or(self.policy.default_action)
    }

    fn policy_requires_inspection(&self) -> bool {
        self.policy.default_action == PolicyAction::Deny
            || self
                .policy
                .methods
                .values()
                .any(|action| *action == PolicyAction::Deny)
    }

    fn rest_suffix<'a>(&self, path: &'a str) -> Option<&'a str> {
        let endpoint_path = self.endpoint.path.trim_end_matches('/');
        if endpoint_path.is_empty() || endpoint_path == "/" {
            return normalized_rest_path(path).is_some().then_some(path);
        }
        path.strip_prefix(endpoint_path)
            .filter(|suffix| normalized_rest_path(suffix).is_some())
    }

    fn should_capture_http_response(&self, ctx: &RequestContext) -> bool {
        if is_grpc_request(&ctx.headers) {
            return false;
        }
        ctx.a2a_gateway_detected
            && !ctx.a2a_gateway_streaming
            && (self.observability.emit_metadata
                || (self.discovery.rewrite_agent_card_urls && ctx.a2a_gateway_is_agent_card))
    }

    fn public_base_url(
        &self,
        ctx: &RequestContext,
        response_headers: &HashMap<String, String>,
    ) -> Option<String> {
        if let Some(configured) = self.discovery.public_base_url.as_deref() {
            return Some(configured.trim_end_matches('/').to_string());
        }
        if !self.discovery.trust_forwarded_headers {
            return None;
        }
        let proto = header_value(&ctx.headers, "x-forwarded-proto").unwrap_or_else(|| {
            if ctx.frontend_sni_hostname.is_some() {
                "https"
            } else {
                "http"
            }
        });
        let host = header_value(&ctx.headers, "x-forwarded-host")
            .or_else(|| header_value(&ctx.headers, "host"))
            .or_else(|| header_value(response_headers, "host"))?;
        forwarded_public_base_url(proto, host)
    }
}

#[async_trait]
impl Plugin for A2aGateway {
    fn name(&self) -> &str {
        "a2a_gateway"
    }

    fn priority(&self) -> u16 {
        super::priority::A2A_GATEWAY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.enabled && self.detection.strip_accept_encoding
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.enabled && self.detection.bindings.contains(&A2aBinding::JsonRpc)
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.enabled && self.detection.bindings.contains(&A2aBinding::JsonRpc)
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.enabled
            && self.detection.bindings.contains(&A2aBinding::JsonRpc)
            && ctx.method.eq_ignore_ascii_case("POST")
            && ctx.path == self.endpoint.path
            && content_type_is_json(&ctx.headers)
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.enabled && (self.discovery.rewrite_agent_card_urls || self.observability.emit_metadata)
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.enabled && self.should_capture_http_response(ctx)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
    ) -> bool {
        if content_type.is_some_and(is_event_stream_content_type) {
            return false;
        }
        self.should_buffer_response_body(ctx)
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled {
            return PluginResult::Continue;
        }
        let Some(detection) = self.maybe_detect(ctx, headers) else {
            return PluginResult::Continue;
        };
        self.emit_base_metadata(ctx, headers, &detection);
        if detection.oversized_body && self.policy_requires_inspection() {
            if self.observability.emit_metadata {
                ctx.metadata
                    .insert("a2a.policy_decision".to_string(), "deny".to_string());
                ctx.metadata.insert(
                    "a2a.error".to_string(),
                    "request_body_too_large".to_string(),
                );
            }
            return oversized_jsonrpc_response(&detection);
        }
        let action = self.policy_action(&detection.method);
        if self.observability.emit_metadata {
            ctx.metadata.insert(
                "a2a.policy_decision".to_string(),
                action.as_str().to_string(),
            );
        }
        if action == PolicyAction::Deny {
            return deny_response(&detection);
        }
        if self.detection.strip_accept_encoding
            && (detection.is_agent_card
                || (self.observability.emit_metadata && !detection.streaming_hint))
        {
            remove_header(headers, "accept-encoding");
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled || !ctx.a2a_gateway_detected {
            return PluginResult::Continue;
        }
        if response_headers
            .get("content-type")
            .is_some_and(|value| is_event_stream_content_type(value))
        {
            ctx.a2a_gateway_streaming = true;
            if self.observability.emit_metadata {
                ctx.metadata
                    .insert("a2a.streaming".to_string(), "true".to_string());
                let latency = Utc::now()
                    .signed_duration_since(ctx.timestamp_received)
                    .num_milliseconds()
                    .max(0);
                ctx.metadata
                    .insert("a2a.ttfb_ms".to_string(), latency.to_string());
            }
        }
        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.enabled || !ctx.a2a_gateway_detected {
            return PluginResult::Continue;
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("a2a.response_body_size".to_string(), body.len().to_string());
            if self.observability.log_payloads && body.len() <= self.observability.max_payload_size
            {
                ctx.metadata.insert(
                    "a2a.payload.response".to_string(),
                    String::from_utf8_lossy(body).to_string(),
                );
            }
        }
        if !response_headers
            .get("content-type")
            .is_none_or(|value| content_type_value_is_json(value))
        {
            return PluginResult::Continue;
        }
        let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
            return PluginResult::Continue;
        };
        if self.observability.emit_metadata {
            emit_response_metadata(ctx, &value);
        }
        if !self.discovery.rewrite_agent_card_urls || !ctx.a2a_gateway_is_agent_card {
            return PluginResult::Continue;
        }
        let Some(public_base) = self.public_base_url(ctx, response_headers) else {
            return PluginResult::Continue;
        };
        let agent_card_path = if ctx.path.ends_with(&self.endpoint.agent_card_path) {
            ctx.path.as_str()
        } else {
            self.endpoint.agent_card_path.as_str()
        };
        if !rewrite_agent_card_response(
            &mut value,
            &public_base,
            &self.endpoint.path,
            agent_card_path,
        ) {
            return PluginResult::Continue;
        }
        let mut headers = response_headers.clone();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.remove("content-length");
        headers.remove("Content-Length");
        PluginResult::Reject {
            status_code: response_status,
            body: value.to_string(),
            headers,
        }
    }
}

fn parse_endpoint(object: &Map<String, Value>) -> Result<A2aEndpointConfig, String> {
    let endpoint = optional_object(object, "endpoint")?;
    let path = optional_string_from_object(endpoint, "path")?
        .unwrap_or_else(|| DEFAULT_ENDPOINT_PATH.to_string());
    validate_path(&path, "endpoint.path")?;
    let agent_card_path = optional_string_from_object(endpoint, "agent_card_path")?
        .unwrap_or_else(|| DEFAULT_AGENT_CARD_PATH.to_string());
    validate_path(&agent_card_path, "endpoint.agent_card_path")?;
    let protocol_versions = optional_string_vec_from_object(endpoint, "protocol_versions")?
        .unwrap_or_else(|| vec![DEFAULT_PROTOCOL_VERSION.to_string()]);
    if protocol_versions.is_empty() {
        return Err("a2a_gateway: 'endpoint.protocol_versions' must not be empty".to_string());
    }
    if protocol_versions
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(
            "a2a_gateway: 'endpoint.protocol_versions' entries must not be empty".to_string(),
        );
    }
    let grpc_services = optional_string_vec_from_object(endpoint, "grpc_services")?
        .unwrap_or_else(|| vec![DEFAULT_GRPC_SERVICE.to_string()]);
    if grpc_services.is_empty() {
        return Err("a2a_gateway: 'endpoint.grpc_services' must not be empty".to_string());
    }
    let mut grpc_service_set = HashSet::with_capacity(grpc_services.len());
    for service in grpc_services {
        validate_grpc_service(&service)?;
        if !grpc_service_set.insert(service.clone()) {
            return Err(format!(
                "a2a_gateway: duplicate endpoint.grpc_services entry {service:?}"
            ));
        }
    }
    Ok(A2aEndpointConfig {
        path,
        agent_card_path,
        protocol_versions,
        grpc_services: grpc_service_set,
    })
}

fn parse_detection(object: &Map<String, Value>) -> Result<A2aDetectionConfig, String> {
    let detection = optional_object(object, "detection")?;
    let bindings = optional_string_vec_from_object(detection, "bindings")?.unwrap_or_else(|| {
        vec![
            "jsonrpc".to_string(),
            "rest".to_string(),
            "grpc".to_string(),
        ]
    });
    if bindings.is_empty() {
        return Err("a2a_gateway: 'detection.bindings' must not be empty".to_string());
    }
    let mut binding_set = HashSet::with_capacity(bindings.len());
    for binding in bindings {
        binding_set.insert(A2aBinding::parse(&binding)?);
    }
    let version_header = optional_string_from_object(detection, "version_header")?
        .unwrap_or_else(|| DEFAULT_VERSION_HEADER.to_string());
    validate_header_name(&version_header, "detection.version_header")?;
    let max_request_body_size = optional_u64_from_object(detection, "max_request_body_size")?
        .unwrap_or(DEFAULT_MAX_DETECTION_BODY_BYTES);
    Ok(A2aDetectionConfig {
        bindings: binding_set,
        version_header,
        max_request_body_size,
        allow_unknown_methods_with_version_header: optional_bool_from_object(
            detection,
            "allow_unknown_methods_with_version_header",
        )?
        .unwrap_or(true),
        strip_accept_encoding: optional_bool_from_object(detection, "strip_accept_encoding")?
            .unwrap_or(true),
    })
}

fn parse_discovery(object: &Map<String, Value>) -> Result<A2aDiscoveryConfig, String> {
    let discovery = optional_object(object, "discovery")?;
    let public_base_url = optional_string_from_object(discovery, "public_base_url")?;
    if let Some(url) = public_base_url.as_deref() {
        validate_public_base_url(url)?;
    }
    Ok(A2aDiscoveryConfig {
        rewrite_agent_card_urls: optional_bool_from_object(discovery, "rewrite_agent_card_urls")?
            .unwrap_or(true),
        public_base_url,
        trust_forwarded_headers: optional_bool_from_object(discovery, "trust_forwarded_headers")?
            .unwrap_or(false),
    })
}

fn parse_observability(object: &Map<String, Value>) -> Result<A2aObservabilityConfig, String> {
    let observability = optional_object(object, "observability")?;
    let max_payload_size = optional_u64_from_object(observability, "max_payload_size")?
        .unwrap_or(DEFAULT_MAX_DETECTION_BODY_BYTES);
    let max_payload_size = usize::try_from(max_payload_size)
        .map_err(|_| "a2a_gateway: 'observability.max_payload_size' is too large".to_string())?;
    if max_payload_size == 0 {
        return Err(
            "a2a_gateway: 'observability.max_payload_size' must be greater than zero".to_string(),
        );
    }
    Ok(A2aObservabilityConfig {
        emit_metadata: optional_bool_from_object(observability, "emit_metadata")?.unwrap_or(true),
        log_payloads: optional_bool_from_object(observability, "log_payloads")?.unwrap_or(false),
        max_payload_size,
    })
}

fn parse_policy(object: &Map<String, Value>) -> Result<A2aPolicyConfig, String> {
    let policy = optional_object(object, "policy")?;
    let default_action = PolicyAction::parse(
        optional_string_from_object(policy, "default_action")?
            .as_deref()
            .unwrap_or("allow"),
        "policy.default_action",
    )?;
    let mut methods = HashMap::new();
    if let Some(methods_value) = policy.and_then(|policy| policy.get("methods")) {
        if methods_value.is_null() {
            return Ok(A2aPolicyConfig {
                default_action,
                methods,
            });
        }
        let methods_object = methods_value
            .as_object()
            .ok_or_else(|| "a2a_gateway: 'policy.methods' must be an object".to_string())?;
        for (method, value) in methods_object {
            let canonical_method = canonical_policy_method(method)
                .ok_or_else(|| format!("a2a_gateway: unsupported policy method name {method:?}"))?;
            let object = value.as_object().ok_or_else(|| {
                format!("a2a_gateway: policy.methods[{method:?}] must be an object")
            })?;
            let action = PolicyAction::parse(
                optional_string(object, "action")?.ok_or_else(|| {
                    format!("a2a_gateway: policy.methods[{method:?}].action is required")
                })?,
                &format!("policy.methods[{method:?}].action"),
            )?;
            if methods
                .insert(canonical_method.to_string(), action)
                .is_some()
            {
                return Err(format!(
                    "a2a_gateway: duplicate policy method name {canonical_method:?}"
                ));
            }
        }
    }
    Ok(A2aPolicyConfig {
        default_action,
        methods,
    })
}

fn parse_jsonrpc_envelope(value: &Value) -> Result<A2aEnvelope, ()> {
    let object = value.as_object().ok_or(())?;
    Ok(A2aEnvelope {
        id: object.get("id").cloned(),
        method: object
            .get("method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        jsonrpc: object
            .get("jsonrpc")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        is_request: object.contains_key("method"),
        is_error: object.contains_key("error"),
    })
}

fn deny_response(detection: &A2aDetection) -> PluginResult {
    match detection.binding {
        A2aBinding::JsonRpc => PluginResult::Reject {
            status_code: 200,
            body: json!({
                "jsonrpc": "2.0",
                "id": detection.jsonrpc_id.clone().unwrap_or(Value::Null),
                "error": {
                    "code": -32001,
                    "message": "A2A method denied by gateway policy",
                    "data": {
                        "gateway": "a2a_gateway",
                        "method": detection.method
                    }
                }
            })
            .to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        },
        A2aBinding::Rest => PluginResult::Reject {
            status_code: 403,
            body: json!({
                "error": "A2A method denied by gateway policy",
                "method": detection.method
            })
            .to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        },
        A2aBinding::Grpc => PluginResult::Reject {
            status_code: 403,
            body: "A2A method denied by gateway policy".to_string(),
            headers: HashMap::new(),
        },
    }
}

fn oversized_jsonrpc_response(detection: &A2aDetection) -> PluginResult {
    PluginResult::Reject {
        status_code: 413,
        body: json!({
            "jsonrpc": "2.0",
            "id": detection.jsonrpc_id.clone().unwrap_or(Value::Null),
            "error": {
                "code": -32013,
                "message": "A2A request body exceeds gateway detection limit",
                "data": {
                    "gateway": "a2a_gateway",
                    "method": detection.method
                }
            }
        })
        .to_string(),
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    }
}

fn match_rest_operation(method: &str, rest: &str) -> Option<(&'static str, Option<String>, bool)> {
    let rest = normalized_rest_path(rest)?;
    if method.eq_ignore_ascii_case("POST") && rest == "message:send" {
        return Some(("message/send", None, false));
    }
    if method.eq_ignore_ascii_case("POST") && rest == "message:stream" {
        return Some(("message/stream", None, true));
    }
    if method.eq_ignore_ascii_case("GET") && rest == "card" {
        return Some(("agent/getAuthenticatedExtendedCard", None, false));
    }
    if method.eq_ignore_ascii_case("GET") && rest == "extendedAgentCard" {
        return Some(("agent/getExtendedAgentCard", None, false));
    }
    if (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST"))
        && rest == "tasks"
    {
        return Some(("tasks/list", None, false));
    }
    if let Some(task_id) = rest
        .strip_prefix("tasks/")
        .and_then(|tail| tail.strip_suffix(":cancel"))
        && method.eq_ignore_ascii_case("POST")
        && is_simple_path_id(task_id)
    {
        return Some(("tasks/cancel", Some(task_id.to_string()), false));
    }
    if let Some(task_id) = rest
        .strip_prefix("tasks/")
        .and_then(|tail| tail.strip_suffix(":subscribe"))
        && (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST"))
        && is_simple_path_id(task_id)
    {
        return Some(("tasks/resubscribe", Some(task_id.to_string()), true));
    }
    if let Some(parent) = rest.strip_suffix("/pushNotificationConfigs")
        && let Some(task_id) = parent.strip_prefix("tasks/")
        && is_simple_path_id(task_id)
    {
        if method.eq_ignore_ascii_case("GET") {
            return Some((
                "tasks/pushNotificationConfig/list",
                Some(task_id.to_string()),
                false,
            ));
        }
        if method.eq_ignore_ascii_case("POST") {
            return Some((
                "tasks/pushNotificationConfig/set",
                Some(task_id.to_string()),
                false,
            ));
        }
    }
    if let Some(tail) = rest.strip_prefix("tasks/")
        && let Some((task_id, rest_tail)) = tail.split_once("/pushNotificationConfigs/")
        && is_simple_path_id(task_id)
        && is_simple_path_id(rest_tail)
    {
        if method.eq_ignore_ascii_case("GET") {
            return Some((
                "tasks/pushNotificationConfig/get",
                Some(task_id.to_string()),
                false,
            ));
        }
        if method.eq_ignore_ascii_case("DELETE") {
            return Some((
                "tasks/pushNotificationConfig/delete",
                Some(task_id.to_string()),
                false,
            ));
        }
    }
    if let Some(task_id) = rest.strip_prefix("tasks/")
        && method.eq_ignore_ascii_case("GET")
        && is_simple_path_id(task_id)
        && !task_id.ends_with(":cancel")
        && !task_id.ends_with(":subscribe")
    {
        return Some(("tasks/get", Some(task_id.to_string()), false));
    }
    None
}

fn normalized_rest_path(rest: &str) -> Option<&str> {
    let rest = rest.strip_prefix('/')?;
    let rest = strip_optional_rest_version(rest);
    if is_a2a_rest_route(rest) {
        return Some(rest);
    }
    let (_tenant, tail) = rest.split_once('/')?;
    let tail = strip_optional_rest_version(tail);
    is_a2a_rest_route(tail).then_some(tail)
}

fn strip_optional_rest_version(rest: &str) -> &str {
    rest.strip_prefix("v1/").unwrap_or(rest)
}

fn is_a2a_rest_route(rest: &str) -> bool {
    matches!(
        rest,
        "message:send" | "message:stream" | "card" | "extendedAgentCard" | "tasks"
    ) || rest.starts_with("tasks/")
}

fn is_simple_path_id(value: &str) -> bool {
    !value.is_empty() && !value.contains('/')
}

fn grpc_operation(method: &str) -> Option<(&'static str, bool)> {
    match method {
        "SetTaskPushNotificationConfig" => Some(("tasks/pushNotificationConfig/set", false)),
        _ => canonical_a2a_method(method).map(|method| (method, is_streaming_method(method))),
    }
}

fn is_streaming_method(method: &str) -> bool {
    matches!(method, "message/stream" | "tasks/resubscribe")
}

fn is_agent_card_method(method: &str) -> bool {
    matches!(
        method,
        "agent/getCard" | "agent/getExtendedAgentCard" | "agent/getAuthenticatedExtendedCard"
    )
}

fn canonical_policy_method(method: &str) -> Option<&'static str> {
    if method == "unknown" {
        Some("unknown")
    } else {
        canonical_a2a_method(method)
    }
}

fn canonical_a2a_method(method: &str) -> Option<&'static str> {
    if let Some(canonical) = JSONRPC_METHODS
        .iter()
        .copied()
        .find(|canonical| *canonical == method)
    {
        return Some(canonical);
    }
    match method {
        "SendMessage" => Some("message/send"),
        "SendStreamingMessage" => Some("message/stream"),
        "GetTask" => Some("tasks/get"),
        "ListTasks" => Some("tasks/list"),
        "CancelTask" => Some("tasks/cancel"),
        "SubscribeToTask" | "TaskSubscription" => Some("tasks/resubscribe"),
        "CreateTaskPushNotificationConfig" | "CreateTaskPushNotification" => {
            Some("tasks/pushNotificationConfig/set")
        }
        "GetTaskPushNotificationConfig" | "GetTaskPushNotification" => {
            Some("tasks/pushNotificationConfig/get")
        }
        "ListTaskPushNotificationConfigs"
        | "ListTaskPushNotificationConfig"
        | "ListTaskPushNotification" => Some("tasks/pushNotificationConfig/list"),
        "DeleteTaskPushNotificationConfig" | "DeleteTaskPushNotification" => {
            Some("tasks/pushNotificationConfig/delete")
        }
        "GetAgentCard" => Some("agent/getCard"),
        "GetExtendedAgentCard" => Some("agent/getExtendedAgentCard"),
        "GetAuthenticatedExtendedCard" => Some("agent/getAuthenticatedExtendedCard"),
        _ => None,
    }
}

fn extract_task_id_from_request(value: &Value) -> Option<String> {
    string_at_any_path(
        value,
        &[
            &["params", "taskId"],
            &["params", "task_id"],
            &["params", "id"],
            &["params", "task", "id"],
            &["params", "message", "taskId"],
            &["params", "message", "task_id"],
        ],
    )
    .or_else(|| task_name_at_any_path(value, &[&["params", "name"], &["params", "task", "name"]]))
}

fn emit_response_metadata(ctx: &mut RequestContext, value: &Value) {
    if let Ok(envelope) = parse_jsonrpc_envelope(value)
        && envelope.is_error
        && let Some(error) = value.get("error")
    {
        if let Some(code) = error.get("code").and_then(Value::as_i64) {
            ctx.metadata
                .insert("a2a.error".to_string(), code.to_string());
        } else if let Some(message) = error.get("message").and_then(Value::as_str) {
            ctx.metadata
                .insert("a2a.error".to_string(), message.to_string());
        }
    }
    if let Some(task_id) = extract_task_id_from_response(ctx.a2a_gateway_binding, value) {
        ctx.metadata.insert("a2a.task_id".to_string(), task_id);
    }
    if let Some(context_id) = extract_context_id_from_response(ctx.a2a_gateway_binding, value) {
        ctx.metadata
            .insert("a2a.context_id".to_string(), context_id);
    }
    if let Some(state) = find_task_state(value) {
        ctx.metadata.insert("a2a.task_state".to_string(), state);
    }
}

fn extract_task_id_from_response(binding: Option<&str>, value: &Value) -> Option<String> {
    let common_id_paths: &[&[&str]] = &[
        &["result", "taskId"],
        &["result", "task_id"],
        &["result", "id"],
        &["result", "task", "id"],
        &["task", "id"],
    ];
    let rest_id_paths: &[&[&str]] = &[&["taskId"], &["task_id"], &["id"]];
    string_at_any_path(value, common_id_paths)
        .or_else(|| (binding == Some("rest")).then(|| string_at_any_path(value, rest_id_paths))?)
        .or_else(|| {
            task_name_at_any_path(
                value,
                &[
                    &["result", "name"],
                    &["result", "task", "name"],
                    &["task", "name"],
                ],
            )
        })
        .or_else(|| {
            (binding == Some("rest")).then(|| task_name_at_any_path(value, &[&["name"]]))?
        })
}

fn extract_context_id_from_response(binding: Option<&str>, value: &Value) -> Option<String> {
    let common_paths: &[&[&str]] = &[
        &["result", "contextId"],
        &["result", "context_id"],
        &["result", "task", "contextId"],
        &["result", "task", "context_id"],
        &["task", "contextId"],
        &["task", "context_id"],
    ];
    let rest_paths: &[&[&str]] = &[&["contextId"], &["context_id"]];
    string_at_any_path(value, common_paths)
        .or_else(|| (binding == Some("rest")).then(|| string_at_any_path(value, rest_paths))?)
}

fn string_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        get_path(value, path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn task_name_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        get_path(value, path)
            .and_then(Value::as_str)
            .and_then(task_id_from_name)
    })
}

fn find_task_state(value: &Value) -> Option<String> {
    let candidates = [
        &["result", "status", "state"][..],
        &["result", "task", "status", "state"][..],
        &["result", "statusUpdate", "status", "state"][..],
        &["result", "status_update", "status", "state"][..],
        &["task", "status", "state"][..],
        &["statusUpdate", "status", "state"][..],
        &["status_update", "status", "state"][..],
        &["status", "state"][..],
    ];
    for path in candidates {
        if let Some(state) = get_path(value, path).and_then(Value::as_str) {
            return Some(normalize_task_state(state));
        }
    }
    None
}

fn get_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn task_id_from_name(value: &str) -> Option<String> {
    value
        .strip_prefix("tasks/")
        .filter(|task_id| !task_id.is_empty() && !task_id.contains('/'))
        .map(ToOwned::to_owned)
}

fn normalize_task_state(value: &str) -> String {
    let mut state = value.to_ascii_lowercase();
    if let Some(stripped) = state.strip_prefix("task_state_") {
        state = stripped.to_string();
    }
    state = state.replace('_', "-");
    if state == "cancelled" {
        "canceled".to_string()
    } else if state.is_empty() {
        "unknown".to_string()
    } else {
        state
    }
}

fn looks_like_agent_card(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    (object.contains_key("url")
        || object.contains_key("additionalInterfaces")
        || object.contains_key("additional_interfaces")
        || object.contains_key("supportedInterfaces")
        || object.contains_key("supported_interfaces"))
        && (object.contains_key("name") || object.contains_key("description"))
}

fn rewrite_agent_card_response(
    value: &mut Value,
    public_base: &str,
    endpoint_path: &str,
    agent_card_path: &str,
) -> bool {
    if looks_like_agent_card(value) {
        return rewrite_agent_card_urls(value, public_base, endpoint_path, agent_card_path);
    }
    let Some(result) = value.get_mut("result") else {
        return false;
    };
    if !looks_like_agent_card(result) {
        return false;
    }
    rewrite_agent_card_urls(result, public_base, endpoint_path, agent_card_path)
}

fn rewrite_agent_card_urls(
    value: &mut Value,
    public_base: &str,
    endpoint_path: &str,
    agent_card_path: &str,
) -> bool {
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    let preferred_transport = object
        .get("preferredTransport")
        .or_else(|| object.get("preferred_transport"))
        .and_then(Value::as_str);
    if should_rewrite_transport(preferred_transport)
        && let Some(url) = object.get_mut("url")
    {
        changed |= rewrite_url_value(url, public_base, endpoint_path);
    }
    for key in [
        "additionalInterfaces",
        "additional_interfaces",
        "supportedInterfaces",
        "supported_interfaces",
    ] {
        if let Some(Value::Array(interfaces)) = object.get_mut(key) {
            for interface in interfaces {
                let Some(interface_object) = interface.as_object_mut() else {
                    continue;
                };
                if !should_rewrite_transport(interface_transport(interface_object)) {
                    continue;
                }
                if let Some(url) = interface_object.get_mut("url") {
                    changed |= rewrite_url_value(url, public_base, endpoint_path);
                }
            }
        }
    }
    if object.get("agentCardUrl").is_some() {
        object.insert(
            "agentCardUrl".to_string(),
            Value::String(format!(
                "{}{}",
                public_base.trim_end_matches('/'),
                agent_card_path
            )),
        );
        changed = true;
    }
    if changed {
        object.remove("signatures");
    }
    changed
}

fn interface_transport(interface: &Map<String, Value>) -> Option<&str> {
    interface
        .get("transport")
        .or_else(|| interface.get("protocolBinding"))
        .or_else(|| interface.get("protocol_binding"))
        .and_then(Value::as_str)
}

fn should_rewrite_transport(transport: Option<&str>) -> bool {
    let Some(transport) = transport else {
        return true;
    };
    let normalized: String = transport
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    normalized == "jsonrpc"
}

fn rewrite_url_value(value: &mut Value, public_base: &str, path: &str) -> bool {
    if !value.is_string() {
        return false;
    }
    let new_url = format!("{}{}", public_base.trim_end_matches('/'), path);
    if value.as_str() == Some(new_url.as_str()) {
        return false;
    }
    *value = Value::String(new_url);
    true
}

fn forwarded_public_base_url(proto: &str, host: &str) -> Option<String> {
    let scheme = normalized_public_scheme(first_header_token(proto))?;
    let host = first_header_token(host);
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'\\' | b'@'))
    {
        return None;
    }
    let candidate = format!("{scheme}://{host}");
    let parsed = Url::parse(&candidate).ok()?;
    if parsed.scheme() != scheme
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return None;
    }
    Some(candidate)
}

fn first_header_token(value: &str) -> &str {
    value.split(',').next().unwrap_or(value).trim()
}

fn normalized_public_scheme(value: &str) -> Option<&'static str> {
    let scheme = value.trim_end_matches(':');
    if scheme.eq_ignore_ascii_case("http") {
        Some("http")
    } else if scheme.eq_ignore_ascii_case("https") {
        Some("https")
    } else {
        None
    }
}

fn content_type_is_json(headers: &HashMap<String, String>) -> bool {
    header_value(headers, "content-type").is_none_or(content_type_value_is_json)
}

fn content_type_value_is_json(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or(value).trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type.eq_ignore_ascii_case("application/json-rpc")
        || media_type
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

fn is_event_stream_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .eq_ignore_ascii_case("text/event-stream")
}

fn is_grpc_request(headers: &HashMap<String, String>) -> bool {
    header_value(headers, "content-type").is_some_and(|value| {
        crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes())
    })
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

fn remove_header(headers: &mut HashMap<String, String>, name: &str) {
    headers.retain(|key, _| !key.eq_ignore_ascii_case(name));
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be an object, got {other}"
        )),
    }
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a boolean, got {other}"
        )),
    }
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a string, got {other}"
        )),
    }
}

fn optional_string_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a string, got {other}"
        )),
    }
}

fn optional_bool_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<bool>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a boolean, got {other}"
        )),
    }
}

fn optional_u64_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<u64>, String> {
    match object.and_then(|object| object.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("a2a_gateway: '{key}' must be a positive integer"))
            .map(Some),
        Some(other) => Err(format!(
            "a2a_gateway: '{key}' must be a positive integer, got {other}"
        )),
    }
}

fn optional_string_vec_from_object(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = object.and_then(|object| object.get(key)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let array = value
        .as_array()
        .ok_or_else(|| format!("a2a_gateway: '{key}' must be an array"))?;
    let mut values = Vec::with_capacity(array.len());
    for (idx, item) in array.iter().enumerate() {
        values.push(
            item.as_str()
                .ok_or_else(|| format!("a2a_gateway: '{key}[{idx}]' must be a string"))?
                .to_string(),
        );
    }
    Ok(Some(values))
}

fn validate_path(path: &str, field: &str) -> Result<(), String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(format!("a2a_gateway: '{field}' must be a non-empty path"));
    }
    Ok(())
}

fn validate_header_name(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("a2a_gateway: '{field}' must not be empty"));
    }
    http::header::HeaderName::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| {
            format!("a2a_gateway: '{field}' must be a valid HTTP header name, got {value:?}")
        })
}

fn validate_public_base_url(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value)
        .map_err(|error| format!("a2a_gateway: discovery.public_base_url invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(
            "a2a_gateway: discovery.public_base_url scheme must be http or https".to_string(),
        );
    }
    if parsed.host_str().is_none() {
        return Err("a2a_gateway: discovery.public_base_url missing host".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "a2a_gateway: discovery.public_base_url must not contain credentials".to_string(),
        );
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(
            "a2a_gateway: discovery.public_base_url must not contain query or fragment".to_string(),
        );
    }
    Ok(())
}

fn validate_grpc_service(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value
            .split('.')
            .any(|part| part.is_empty() || !is_valid_grpc_identifier(part))
    {
        return Err(format!(
            "a2a_gateway: endpoint.grpc_services entries must be valid gRPC service names, got {value:?}"
        ));
    }
    Ok(())
}

fn is_valid_grpc_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
