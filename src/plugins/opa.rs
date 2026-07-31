//! Open Policy Agent (OPA) authorization plugin.
//!
//! Delegates HTTP request authorization to OPA's Data API by POSTing an
//! `input` document to `/v1/data/{policy_path}` during the `authorize` phase.
//! The plugin fails closed by default, bounds policy responses, and redacts
//! sensitive client headers and query credentials before forwarding request
//! context to OPA.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Serialize;
use serde::ser::SerializeMap;
use serde_json::{Map, Value};
use tracing::{info, warn};
use url::{Host, Url};

use crate::retry::classify_reqwest_error;

use super::utils::query::{CanonicalQuery, canonical_query_for_policy};
use super::utils::response_body::{
    BoundedReadError, parse_max_response_body_bytes, read_response_body_bounded,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const DEFAULT_TIMEOUT_MS: u64 = 1000;
const MAX_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_DENY_STATUS: u16 = 403;
const DEFAULT_DENY_BODY: &str = r#"{"error":"forbidden by policy"}"#;
const DEFAULT_FAIL_CLOSED_STATUS: u16 = 503;
const DEFAULT_FAIL_CLOSED_BODY: &str = r#"{"error":"authorization service unavailable"}"#;
const OPA_DATA_PREFIX: &str = "/v1/data/";
const OPA_CONFIG_KEYS: &[&str] = &[
    "opa_host",
    "policy_path",
    "headers",
    "timeout_ms",
    "max_response_bytes",
    "fail_open",
    "fail_closed",
    "deny_status",
    "deny_body",
    "deny_headers",
    "fail_closed_status",
    "fail_closed_body",
    "fail_closed_headers",
    "decision_pointer",
    "include_method",
    "include_path",
    "include_query",
    "include_query_credentials",
    "include_headers",
    "include_body",
    "max_body_bytes",
    "include_consumer",
    "include_client_ip",
    "include_service",
    "query_ambiguity_policy",
    "redact_headers",
    "redact_query_keys",
];

#[derive(Serialize)]
struct OpaDecisionPayload<'a> {
    input: OpaInputPayload<'a>,
}

struct OpaInputPayload<'a> {
    fields: Map<String, Value>,
    body: Option<OpaBody<'a>>,
}

enum OpaBody<'a> {
    Text(&'a str),
    Base64(String),
    Null,
}

impl Serialize for OpaInputPayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let body_field_count = if self.body.is_some() { 1 } else { 0 };
        let mut map = serializer.serialize_map(Some(self.fields.len() + body_field_count))?;
        for (key, value) in &self.fields {
            map.serialize_entry(key, value)?;
        }
        match self.body.as_ref() {
            Some(OpaBody::Text(body)) => map.serialize_entry("body", body)?,
            Some(OpaBody::Base64(body)) => map.serialize_entry("body_base64", body)?,
            Some(OpaBody::Null) => map.serialize_entry("body", &Value::Null)?,
            None => {}
        }
        map.end()
    }
}

pub struct Opa {
    http_client: PluginHttpClient,
    decision_url: String,
    decision_hostname: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    timeout: Duration,
    max_response_bytes: usize,
    fail_open: bool,
    deny_status: u16,
    deny_body: String,
    deny_headers: HashMap<String, String>,
    fail_closed_status: u16,
    fail_closed_body: String,
    fail_closed_headers: HashMap<String, String>,
    decision_pointer: Vec<String>,
    include_method: bool,
    include_path: bool,
    include_query: bool,
    include_query_credentials: bool,
    include_headers: bool,
    include_body: bool,
    max_body_bytes: usize,
    include_consumer: bool,
    include_client_ip: bool,
    include_service: bool,
    query_ambiguity_policy: QueryAmbiguityPolicy,
    redact_headers: HashSet<String>,
    redact_query_keys: HashSet<String>,
}

/// What to do when the request query cannot be reduced to one decoded view
/// that OPA and the backend are guaranteed to read identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryAmbiguityPolicy {
    /// Deny the request before calling OPA. Default: a policy decision must
    /// never be made on a value different from the one the backend executes.
    Reject,
    /// Call OPA anyway and let Rego decide, using the ordered occurrence list
    /// in `input.query_pairs` plus the `input.query_ambiguity` classifications.
    /// `input.query` is omitted for an ambiguous query so no rule can read a
    /// flat value the backend may not execute.
    ///
    /// Omission is not itself a denial, and this mode moves that decision to
    /// the operator by design: an `allow` rule that reads `input.query`
    /// becomes undefined and denies, but the deny-list idiom
    /// (`deny { input.query.x == "bad" }` with `allow { not deny }`) leaves
    /// `deny` undefined and therefore allows. A `delegate` policy must deny
    /// on a non-empty `input.query_ambiguity` it does not handle.
    Delegate,
}

impl QueryAmbiguityPolicy {
    fn parse(object: &Map<String, Value>) -> Result<Self, String> {
        match parse_optional_string(object, "query_ambiguity_policy")?.as_deref() {
            None | Some("reject") => Ok(Self::Reject),
            Some("delegate") => Ok(Self::Delegate),
            Some(_) => Err(
                "opa: 'query_ambiguity_policy' must be one of 'reject' or 'delegate'".to_string(),
            ),
        }
    }
}

impl Opa {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "opa: config must be a JSON object".to_string())?;
        reject_unknown_keys(object)?;

        let (decision_url, decision_hostname) = parse_decision_endpoint(object)?;
        if decision_url.starts_with("https://") {
            info!(
                plugin = "opa",
                scheme = "https",
                "OPA HTTPS decision endpoint uses global TLS trust configuration"
            );
        }
        let custom_headers = parse_header_map(object, "headers", "opa")?;
        let timeout_ms = parse_optional_u64(object, "timeout_ms")?.unwrap_or(DEFAULT_TIMEOUT_MS);
        if timeout_ms == 0 {
            return Err("opa: 'timeout_ms' must be greater than zero".to_string());
        }
        let timeout_ms = timeout_ms.min(MAX_TIMEOUT_MS);
        let max_response_bytes = parse_max_response_body_bytes(
            config,
            "opa",
            "max_response_bytes",
            DEFAULT_MAX_RESPONSE_BYTES,
        )?;
        let max_body_bytes =
            parse_max_response_body_bytes(config, "opa", "max_body_bytes", DEFAULT_MAX_BODY_BYTES)?;
        let fail_open = parse_fail_open(object)?;
        let deny_status = parse_response_status(object, "deny_status", DEFAULT_DENY_STATUS)?;
        let deny_body = parse_optional_string(object, "deny_body")?
            .unwrap_or_else(|| DEFAULT_DENY_BODY.to_string());
        let deny_headers = parse_string_header_map(object, "deny_headers", "opa")?;
        let fail_closed_status =
            parse_response_status(object, "fail_closed_status", DEFAULT_FAIL_CLOSED_STATUS)?;
        let fail_closed_body = parse_optional_string(object, "fail_closed_body")?
            .unwrap_or_else(|| DEFAULT_FAIL_CLOSED_BODY.to_string());
        let fail_closed_headers = parse_string_header_map(object, "fail_closed_headers", "opa")?;
        let decision_pointer = parse_decision_pointer(object)?;
        let redact_headers = parse_redact_headers(object)?;
        let redact_query_keys = parse_redact_query_keys(object)?;

        Ok(Self {
            http_client,
            decision_url,
            decision_hostname,
            custom_headers,
            timeout: Duration::from_millis(timeout_ms),
            max_response_bytes,
            fail_open,
            deny_status,
            deny_body,
            deny_headers,
            fail_closed_status,
            fail_closed_body,
            fail_closed_headers,
            decision_pointer,
            include_method: parse_optional_bool(object, "include_method")?.unwrap_or(true),
            include_path: parse_optional_bool(object, "include_path")?.unwrap_or(true),
            include_query: parse_optional_bool(object, "include_query")?.unwrap_or(true),
            include_query_credentials: parse_optional_bool(object, "include_query_credentials")?
                .unwrap_or(false),
            include_headers: parse_optional_bool(object, "include_headers")?.unwrap_or(true),
            include_body: parse_optional_bool(object, "include_body")?.unwrap_or(false),
            max_body_bytes,
            include_consumer: parse_optional_bool(object, "include_consumer")?.unwrap_or(true),
            include_client_ip: parse_optional_bool(object, "include_client_ip")?.unwrap_or(true),
            include_service: parse_optional_bool(object, "include_service")?.unwrap_or(true),
            query_ambiguity_policy: QueryAmbiguityPolicy::parse(object)?,
            redact_headers,
            redact_query_keys,
        })
    }

    fn build_input(
        &self,
        ctx: &mut RequestContext,
        query: Option<&CanonicalQuery>,
    ) -> Map<String, Value> {
        let mut input = Map::new();

        if self.include_method {
            input.insert("method".to_string(), Value::String(ctx.method.clone()));
        }
        if self.include_path {
            input.insert("path".to_string(), Value::String(ctx.path.clone()));
        }
        if let Some(query) = query {
            // `input.query` is the convenient flat view and is emitted only
            // when the canonical decoding is the one the backend must also
            // read. For an ambiguous query it is omitted entirely, so a Rego
            // rule can never read from it a value the backend does not
            // execute — the whole of both advisories. Under `delegate` the
            // policy itself must still deny on a non-empty
            // `input.query_ambiguity`; see `QueryAmbiguityPolicy::Delegate`.
            if query.is_unambiguous() {
                input.insert("query".to_string(), self.query_map_input(ctx, query));
            }
            // The ordered occurrence-complete representation and the ambiguity
            // classifications are always present, so a policy that opts into
            // `query_ambiguity_policy: delegate` can validate the query
            // against its own backend's duplicate/plus contract.
            input.insert(
                "query_pairs".to_string(),
                self.query_pairs_input(ctx, query),
            );
            input.insert(
                "query_ambiguity".to_string(),
                Value::Array(
                    query
                        .ambiguities()
                        .iter()
                        .map(|ambiguity| Value::String(ambiguity.reason().to_string()))
                        .collect(),
                ),
            );
        }
        if self.include_headers {
            ctx.materialize_headers();
            input.insert("headers".to_string(), self.header_input(ctx));
        }
        if self.include_client_ip {
            input.insert(
                "client_ip".to_string(),
                Value::String(ctx.client_ip.clone()),
            );
        }
        if self.include_service {
            input.insert("service".to_string(), self.service_input(ctx));
        }
        if self.include_consumer {
            input.insert("consumer".to_string(), self.consumer_input(ctx));
        }
        input
    }

    /// Flat decoded `name -> value` view. Only built for an unambiguous
    /// canonical query, where each name occurs exactly once.
    fn query_map_input(&self, ctx: &RequestContext, query: &CanonicalQuery) -> Value {
        let mut map = Map::with_capacity(query.len());
        for param in query.params() {
            if self.query_key_is_redacted(ctx, &param.name) {
                continue;
            }
            map.insert(param.name.clone(), Value::String(param.value.clone()));
        }
        Value::Object(map)
    }

    /// Ordered occurrence view: every pair in wire order, with the
    /// bare-parameter bit that distinguishes `?flag` from `?flag=`. Credential
    /// redaction applies here exactly as it does to the flat map, so opting
    /// into `delegate` never widens what OPA is told. Non-UTF-8 components are
    /// lossy-decoded and carry an explicit ambiguity classification; Rego must
    /// reject that class when it needs exact bytes.
    fn query_pairs_input(&self, ctx: &RequestContext, query: &CanonicalQuery) -> Value {
        let mut pairs = Vec::with_capacity(query.len());
        for param in query.params() {
            if self.query_key_is_redacted(ctx, &param.name) {
                continue;
            }
            let mut entry = Map::with_capacity(3);
            entry.insert("name".to_string(), Value::String(param.name.clone()));
            entry.insert("value".to_string(), Value::String(param.value.clone()));
            entry.insert("bare".to_string(), Value::Bool(param.bare));
            pairs.push(Value::Object(entry));
        }
        Value::Array(pairs)
    }

    fn query_key_is_redacted(&self, ctx: &RequestContext, key: &str) -> bool {
        self.redact_query_keys
            .iter()
            .any(|redacted| redacted.eq_ignore_ascii_case(key))
            || (!self.include_query_credentials
                && (is_default_sensitive_query_key(key)
                    || query_key_marked_as_credential(ctx, key)))
    }

    fn header_input(&self, ctx: &RequestContext) -> Value {
        let mut headers = Map::with_capacity(ctx.headers.len());
        for (name, value) in &ctx.headers {
            let lower = name.to_ascii_lowercase();
            if self.redact_headers.contains(&lower) || ctx.request_header_requires_redaction(&lower)
            {
                continue;
            }
            headers.insert(lower, Value::String(value.clone()));
        }
        Value::Object(headers)
    }

    fn service_input(&self, ctx: &RequestContext) -> Value {
        let Some(proxy) = ctx.matched_proxy.as_ref() else {
            return Value::Null;
        };

        let mut service = Map::new();
        service.insert("id".to_string(), Value::String(proxy.id.clone()));
        if let Some(name) = proxy.name.as_ref() {
            service.insert("name".to_string(), Value::String(name.clone()));
        }
        service.insert(
            "backend_host".to_string(),
            Value::String(proxy.backend_host.clone()),
        );
        service.insert(
            "backend_port".to_string(),
            Value::Number(serde_json::Number::from(proxy.backend_port)),
        );
        if let Some(listen_path) = proxy.listen_path.as_ref() {
            service.insert(
                "listen_path".to_string(),
                Value::String(listen_path.clone()),
            );
        }
        Value::Object(service)
    }

    fn consumer_input(&self, ctx: &RequestContext) -> Value {
        if let Some(consumer) = ctx.identified_consumer.as_ref() {
            let mut value = Map::new();
            value.insert("id".to_string(), Value::String(consumer.id.clone()));
            value.insert(
                "username".to_string(),
                Value::String(consumer.username.clone()),
            );
            value.insert(
                "acl_groups".to_string(),
                Value::Array(
                    consumer
                        .acl_groups
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            if let Some(custom_id) = consumer.custom_id.as_ref() {
                value.insert("custom_id".to_string(), Value::String(custom_id.clone()));
            }
            return Value::Object(value);
        }

        if let Some(identity) = ctx.authenticated_identity.as_ref() {
            let mut value = Map::new();
            value.insert("identity".to_string(), Value::String(identity.clone()));
            if let Some(auth_method) = ctx.auth_method {
                value.insert(
                    "auth_method".to_string(),
                    Value::String(auth_method.to_string()),
                );
            }
            return Value::Object(value);
        }

        Value::Null
    }

    fn body_input<'a>(&self, ctx: &'a RequestContext) -> Option<OpaBody<'a>> {
        if !self.include_body {
            return None;
        }

        if let Some(bytes) = ctx.request_body_bytes.as_ref() {
            if let Ok(body) = std::str::from_utf8(bytes) {
                return Some(OpaBody::Text(body));
            } else {
                return Some(OpaBody::Base64(
                    base64::engine::general_purpose::STANDARD.encode(bytes),
                ));
            }
        }

        if let Some(body) = ctx.metadata.get("request_body") {
            Some(OpaBody::Text(body))
        } else {
            Some(OpaBody::Null)
        }
    }

    fn evaluate(&self, body: &Value) -> PluginResult {
        let Some(decision) = self.decision_value(body) else {
            return self.reject_policy_denial();
        };

        if decision.as_bool() == Some(true) {
            return PluginResult::Continue;
        }

        if decision
            .as_object()
            .and_then(|object| object.get("allow"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            return PluginResult::Continue;
        }

        self.reject_policy_denial()
    }

    fn decision_value<'a>(&self, body: &'a Value) -> Option<&'a Value> {
        let mut current = body;
        for segment in &self.decision_pointer {
            current = current.get(segment)?;
        }
        Some(current)
    }

    fn on_error(&self, reason: &'static str, detail: String) -> PluginResult {
        warn!(
            plugin = "opa",
            reason = reason,
            detail = %detail,
            "OPA authorization decision failed"
        );
        if self.fail_open {
            PluginResult::Continue
        } else {
            self.reject_fail_closed()
        }
    }

    fn reject_policy_denial(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: self.deny_status,
            body: self.deny_body.clone(),
            headers: self.deny_headers.clone(),
        }
    }

    fn reject_fail_closed(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: self.fail_closed_status,
            body: self.fail_closed_body.clone(),
            headers: self.fail_closed_headers.clone(),
        }
    }
}

#[async_trait]
impl Plugin for Opa {
    fn name(&self) -> &str {
        "opa"
    }

    fn priority(&self) -> u16 {
        super::priority::OPA
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Decode the backend-bound query representation at the OPA hook,
        // including authentication-owned strips, instead of the lossy shared
        // map. A deliberately later request_transformer remains a separate
        // ordered operation (advisories GHSA-j2j6-f9c7-hh85,
        // GHSA-gr4p-3qw3-87r5).
        let query = self.include_query.then(|| canonical_query_for_policy(ctx));

        if let Some(query) = query.as_ref()
            && let Some(ambiguity) = query.first_ambiguity()
            && self.query_ambiguity_policy == QueryAmbiguityPolicy::Reject
        {
            // The reason is a fixed-cardinality token; query bytes are
            // attacker-controlled and may carry credentials, so they are never
            // logged here.
            warn!(
                plugin = "opa",
                reason = "ambiguous_query",
                ambiguity = ambiguity.reason(),
                "Rejecting request whose query cannot be decoded to one value OPA and the backend both read"
            );
            return self.reject_policy_denial();
        }

        let input = self.build_input(ctx, query.as_ref());
        let payload = OpaDecisionPayload {
            input: OpaInputPayload {
                fields: input,
                body: self.body_input(ctx),
            },
        };
        let mut request = self
            .http_client
            .get()
            .post(&self.decision_url)
            .timeout(self.timeout)
            .json(&payload);
        for (name, value) in &self.custom_headers {
            request = request.header(name.clone(), value.clone());
        }

        match self
            .http_client
            .execute_tracked(request, "opa", &ctx.plugin_http_call_ns)
            .await
        {
            Ok(response) if response.status().is_success() => {
                if response
                    .content_length()
                    .is_some_and(|length| length > self.max_response_bytes as u64)
                {
                    return self.on_error(
                        "opa_response_too_large",
                        format!(
                            "declared response length exceeds {} bytes",
                            self.max_response_bytes
                        ),
                    );
                }

                match read_response_body_bounded(response, self.max_response_bytes).await {
                    Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(body) => self.evaluate(&body),
                        Err(error) => self.on_error("opa_response_parse_failed", error.to_string()),
                    },
                    Err(BoundedReadError::LimitExceeded { .. }) => self.on_error(
                        "opa_response_too_large",
                        format!(
                            "response exceeded configured {} byte limit",
                            self.max_response_bytes
                        ),
                    ),
                    Err(BoundedReadError::Stream(error)) => self.on_error(
                        "opa_response_read_failed",
                        classify_reqwest_error(&error).to_string(),
                    ),
                }
            }
            Ok(response) => self.on_error(
                "opa_non_success_status",
                response.status().as_u16().to_string(),
            ),
            Err(error) => self.on_error(
                "opa_call_failed",
                classify_reqwest_error(&error).to_string(),
            ),
        }
    }

    fn requires_request_body_before_authorize(&self) -> bool {
        self.include_body
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.include_body
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.include_body
    }

    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn request_body_buffer_limit(&self) -> Option<usize> {
        self.include_body.then_some(self.max_body_bytes)
    }

    /// OPA's own decision no longer reads `ctx.query_params` — it decodes the
    /// forwarded query itself, identically on H1/H2/H3. This stays true so a
    /// proxy configured with OPA keeps exposing the decoded shared map to the
    /// other plugins in its chain, rather than flipping H3 back to raw values.
    fn requires_decoded_query_params(&self) -> bool {
        self.include_query
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.decision_hostname.clone()]
    }
}

fn parse_decision_endpoint(object: &Map<String, Value>) -> Result<(String, String), String> {
    let opa_host = required_string(object, "opa_host")?;
    let parsed =
        Url::parse(opa_host).map_err(|error| format!("opa: invalid 'opa_host': {error}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "opa: 'opa_host' must use http:// or https:// (got '{scheme}')"
            ));
        }
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "opa: 'opa_host' must not include credentials; configure OPA auth with 'headers'"
                .to_string(),
        );
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("opa: 'opa_host' must not include query or fragment components".to_string());
    }

    let host = parsed
        .host()
        .ok_or_else(|| "opa: 'opa_host' must include a hostname or IP address".to_string())?;
    let hostname = match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };

    let policy_path = required_string(object, "policy_path")?;
    validate_policy_path(policy_path)?;

    let decision_url = format!(
        "{}{}{}",
        opa_host.trim_end_matches('/'),
        OPA_DATA_PREFIX,
        policy_path
    );
    Url::parse(&decision_url)
        .map_err(|error| format!("opa: invalid decision URL from opa_host/policy_path: {error}"))?;

    Ok((decision_url, hostname))
}

fn validate_policy_path(policy_path: &str) -> Result<(), String> {
    if policy_path.is_empty() {
        return Err("opa: 'policy_path' must not be empty".to_string());
    }
    if policy_path.starts_with('/') {
        return Err("opa: 'policy_path' must not start with '/'".to_string());
    }
    if policy_path.contains('?') || policy_path.contains('#') {
        return Err("opa: 'policy_path' must not contain '?' or '#'".to_string());
    }
    if policy_path.contains('%') {
        return Err("opa: 'policy_path' must not contain percent-encoding".to_string());
    }
    if policy_path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(
            "opa: 'policy_path' must not contain empty, '.', or '..' path segments".to_string(),
        );
    }
    Ok(())
}

fn parse_fail_open(object: &Map<String, Value>) -> Result<bool, String> {
    let fail_open = parse_optional_bool(object, "fail_open")?;
    let fail_closed = parse_optional_bool(object, "fail_closed")?;
    match (fail_open, fail_closed) {
        (Some(_), Some(_)) => {
            Err("opa: configure only one of 'fail_open' or 'fail_closed'".to_string())
        }
        (Some(value), None) => Ok(value),
        (None, Some(value)) => Ok(!value),
        (None, None) => Ok(false),
    }
}

fn reject_unknown_keys(object: &Map<String, Value>) -> Result<(), String> {
    for key in object.keys() {
        if !OPA_CONFIG_KEYS.contains(&key.as_str()) {
            return Err(format!("opa: unknown config key '{key}'"));
        }
    }
    Ok(())
}

fn parse_decision_pointer(object: &Map<String, Value>) -> Result<Vec<String>, String> {
    let Some(value) = object.get("decision_pointer") else {
        return Ok(vec!["result".to_string()]);
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: 'decision_pointer' must be an array of strings".to_string())?;
    let mut pointer = Vec::with_capacity(array.len());
    for (idx, value) in array.iter().enumerate() {
        let segment = value
            .as_str()
            .ok_or_else(|| format!("opa: 'decision_pointer[{idx}]' must be a string"))?;
        pointer.push(segment.to_string());
    }
    Ok(pointer)
}

fn parse_redact_headers(object: &Map<String, Value>) -> Result<HashSet<String>, String> {
    let mut headers = default_redact_headers();
    let Some(value) = object.get("redact_headers") else {
        return Ok(headers);
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: 'redact_headers' must be an array of strings".to_string())?;
    for (idx, value) in array.iter().enumerate() {
        let header = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("opa: 'redact_headers[{idx}]' must be a non-empty string"))?;
        let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
            format!("opa: invalid redact_headers[{idx}] header name '{header}': {error}")
        })?;
        headers.insert(header_name.as_str().to_string());
    }
    Ok(headers)
}

fn parse_redact_query_keys(object: &Map<String, Value>) -> Result<HashSet<String>, String> {
    let Some(value) = object.get("redact_query_keys") else {
        return Ok(HashSet::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| "opa: 'redact_query_keys' must be an array of strings".to_string())?;
    let mut keys = HashSet::with_capacity(array.len());
    for (idx, value) in array.iter().enumerate() {
        let key = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("opa: 'redact_query_keys[{idx}]' must be a non-empty string"))?;
        keys.insert(key.to_ascii_lowercase());
    }
    Ok(keys)
}

fn is_default_sensitive_query_key(key: &str) -> bool {
    [
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "bearer_token",
        "id_token",
        "jwt",
        "key",
        "token",
    ]
    .iter()
    .any(|sensitive| sensitive.eq_ignore_ascii_case(key))
}

fn query_key_marked_as_credential(ctx: &RequestContext, query_key: &str) -> bool {
    ctx.metadata.keys().any(|metadata_key| {
        metadata_key
            .strip_prefix(super::utils::token_extract::QUERY_CREDENTIAL_METADATA_PREFIX)
            .or_else(|| {
                metadata_key
                    .strip_prefix(super::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX)
            })
            .is_some_and(|credential_key| credential_key.eq_ignore_ascii_case(query_key))
    })
}

fn default_redact_headers() -> HashSet<String> {
    [
        "authorization",
        "proxy-authorization",
        "cookie",
        "api-key",
        "x-api-key",
        "x-goog-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-forwarded-authorization",
        "x-loadtesting-key",
        "x-loadtesting-fanout",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn parse_header_map(
    object: &Map<String, Value>,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let Some(value) = object.get(field) else {
        return Ok(Vec::new());
    };
    let map = value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: '{field}' must be an object"))?;
    let mut headers = Vec::with_capacity(map.len());
    for (key, value) in map {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: {field}['{key}'] must be a string"))?;
        let header_name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|error| format!("{plugin_name}: invalid {field} name '{key}': {error}"))?;
        if field == "headers" && header_name == CONTENT_TYPE {
            return Err(format!(
                "{plugin_name}: '{field}' must not include 'content-type'; OPA decision requests are always sent as JSON"
            ));
        }
        let header_value = HeaderValue::from_str(value).map_err(|error| {
            format!("{plugin_name}: invalid {field} value for '{key}': {error}")
        })?;
        headers.retain(|(existing, _)| *existing != header_name);
        headers.push((header_name, header_value));
    }
    Ok(headers)
}

/// Parse an operator-configured CLIENT RESPONSE header map (`deny_headers`,
/// `fail_closed_headers`).
///
/// Both maps are installed verbatim onto a `PluginResult::Reject`, so their
/// names are arbitrary response-header destinations. Protocol-managed framing /
/// connection-control names are rejected at construction with the shared
/// case-insensitive predicate: the gateway's final wire boundary owns
/// `Content-Length` and the hop-by-hop set, and a configured value there is an
/// unverifiable framing claim rather than a policy header. Names are validated
/// `HeaderName`s from the compiled-in closed set by the time they are echoed, so
/// the diagnostic identifies the setting without reflecting hostile input.
fn parse_string_header_map(
    object: &Map<String, Value>,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<HashMap<String, String>, String> {
    let mut parsed = HashMap::new();
    let Some(value) = object.get(field) else {
        return Ok(parsed);
    };
    let map = value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: '{field}' must be an object"))?;
    parsed.reserve(map.len());
    for (key, value) in map {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: {field}['{key}'] must be a string"))?;
        let header_name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|error| format!("{plugin_name}: invalid {field} name '{key}': {error}"))?;
        if crate::proxy::headers::is_protocol_managed_plugin_response_destination(
            header_name.as_str(),
        ) {
            return Err(format!(
                "{plugin_name}: {field} name '{}' is protocol-managed (hop-by-hop or framing) and \
                 cannot be configured; the gateway derives Content-Length from the reject body and \
                 strips Connection/Transfer-Encoding/Trailer/Upgrade at the final response \
                 boundary",
                header_name.as_str()
            ));
        }
        HeaderValue::from_str(value).map_err(|error| {
            format!("{plugin_name}: invalid {field} value for '{key}': {error}")
        })?;
        parsed.insert(header_name.as_str().to_string(), value.to_string());
    }
    Ok(parsed)
}

fn parse_response_status(
    object: &Map<String, Value>,
    field: &'static str,
    default_status: u16,
) -> Result<u16, String> {
    let status = parse_optional_u16(object, field)?.unwrap_or(default_status);
    if !(400..=599).contains(&status) {
        return Err(format!("opa: '{field}' must be in the 4xx or 5xx range"));
    }
    Ok(status)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("opa: '{field}' is required and must be a non-empty string"))
}

fn parse_optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("opa: '{field}' must be a string"))
        })
        .transpose()
}

fn parse_optional_bool(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("opa: '{field}' must be a boolean"))
        })
        .transpose()
}

fn parse_optional_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("opa: '{field}' must be an unsigned integer"))
        })
        .transpose()
}

fn parse_optional_u16(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<u16>, String> {
    object
        .get(field)
        .map(|value| {
            let raw = value
                .as_u64()
                .ok_or_else(|| format!("opa: '{field}' must be an unsigned integer"))?;
            u16::try_from(raw).map_err(|_| format!("opa: '{field}' is too large"))
        })
        .transpose()
}
