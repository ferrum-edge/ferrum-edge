//! `mesh_route_dispatch` — rewrites the routing decision per request based on
//! method/header/query-param predicates.
//!
//! This plugin closes the Istio `VirtualService.http[].match` header/method
//! gap without extending the `Proxy` schema with new routing dimensions. One
//! `Proxy` is emitted per `(hosts, listen_path)` group; the per-match
//! conditions (method, headers, query params) become `mesh_route_dispatch`
//! rules attached as a proxy-scoped plugin. At request time the plugin walks
//! its rule list and — when a rule matches — sets one or more of
//! `RequestContext.route_override_{upstream_id, backend_host, backend_port, resolved_tls}`
//! and optionally publishes per-rule
//! `route_override_{request,response}_transform` lists for the request /
//! response transformer plugins to apply after their own static rules.
//! The dispatch path picks those up after the `before_proxy` phase via
//! `RequestContext::apply_route_overrides`, which bakes the overrides into a
//! fresh `Arc<Proxy>` so every downstream pool key, capability-registry
//! lookup, circuit-breaker target key, and URL construction sees the
//! effective destination.
//! When multiple plugin instances run on one proxy, each matching instance
//! replaces the complete override destination set by earlier instances; a
//! non-matching instance leaves any prior override intact. Per-rule
//! `backend_tls` is intentionally direct-backend-only. `upstream_id`
//! destinations inherit TLS material from the referenced `Upstream` (including
//! mesh `DestinationRule` TLS projection), so per-canary TLS for upstream
//! overrides should be modeled as distinct upstream resources.
//!
//! The plugin intentionally runs after authentication, authorization, and
//! rate limiting. Those admission decisions use the public listener proxy
//! identity; only downstream `before_proxy` plugins and backend dispatch see
//! the effective override destination. Node-waypoint Service egress with
//! scoped mesh policies is the exception: `mesh_authz` stamps the authorized
//! Service upstream, and this plugin rejects any matching rule that would
//! rewrite that request to a different upstream or direct backend. WebSocket
//! support applies to the HTTP upgrade handshake destination only — once
//! upgraded, a WebSocket connection stays pinned to that backend and is not
//! re-routed per frame.
//! HBONE CONNECT traffic now flows through the standard `before_proxy` chain
//! before the HBONE relay branch in `proxy/mod.rs`, so this plugin can
//! match on the outer CONNECT request (method, headers, query params) and
//! set `route_override_*` fields that `handle_hbone_request` consumes via
//! `apply_route_overrides_with_upstreams`. Once the upgrade succeeds, the
//! HBONE tunnel is a transparent TCP relay — inner H2 frames are not
//! re-classified per stream, mirroring the post-upgrade WebSocket pinning.
//!
//! ## Wire compatibility
//!
//! Old data planes that lack this plugin will receive a `create_plugin`
//! warning and skip the instance, preserving the existing "drop the
//! header/method match" behavior. The CP can emit the plugin instances
//! unconditionally — they're a no-op on old binaries.
//! `retry_disabled` / `timeout_disabled` are intentionally build-out-era
//! additive config: older DPs that do know this plugin but do not know those
//! fields will ignore them, so operators must upgrade DPs before relying on
//! collapsed routes that clear inherited retry or timeout policy.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::config::types::{
    BackendTlsConfig, BackoffStrategy, MAX_BACKEND_HOST_LENGTH,
    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES, RetryConfig,
    normalize_backend_tls_san_allow_list_entry, validate_backend_tls_san_allow_list_entry,
    validate_backend_tls_sni,
};
use crate::plugins::fault_injection::{
    CLIENT_GONE_STATUS, FaultDelayDisposition, ROUTE_FAULT_INJECTED_METADATA_KEY,
    is_native_grpc_request, run_http_fault_delay,
};
use crate::plugins::mesh::authz::{
    NODE_WAYPOINT_AUTHORIZED_BACKEND_ALIASES_METADATA, NODE_WAYPOINT_AUTHORIZED_BACKEND_METADATA,
    NODE_WAYPOINT_AUTHORIZED_UPSTREAM_ID_METADATA, NODE_WAYPOINT_SCOPED_AUTHZ_ACTIVE_METADATA,
};
use crate::plugins::utils::fault_roll::{FaultRoller, MAX_FAULT_DELAY_MS};
use crate::plugins::utils::query::{CanonicalQuery, canonical_query_for_policy};
use crate::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, RouteHeaderTransformRule, parse_route_header_transforms,
};
use crate::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, priority,
};

/// Top-level config for the plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRouteDispatchConfig {
    /// Ordered list of rules. First match wins; rules with no match criteria
    /// are rejected at config-load time to avoid silently-overriding catch-alls.
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    /// When `true`, requests that match no rule are rejected with 404 instead
    /// of falling through to the proxy's default backend. The Istio
    /// VirtualService translator sets this so a route with `match.method=GET`
    /// does not serve POST traffic via the proxy's default backend (which
    /// would silently violate VS match semantics). Defaults to `false` for
    /// operators who configure the plugin directly as a soft override.
    #[serde(default)]
    pub reject_unmatched: bool,
}

impl MeshRouteDispatchConfig {
    pub fn from_value(config: &Value) -> Result<Self, String> {
        serde_json::from_value(config.clone())
            .map_err(|e| format!("mesh_route_dispatch config: {e}"))
    }

    pub fn from_value_normalized(config: &Value) -> Result<Self, String> {
        let mut parsed = Self::from_value(config)?;
        parsed.normalize_and_validate()?;
        Ok(parsed)
    }

    pub fn references_upstream_id(&self, upstream_id: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.destination.upstream_id.as_deref() == Some(upstream_id))
    }

    fn normalize_and_validate(&mut self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err("mesh_route_dispatch.rules cannot be empty".to_string());
        }
        for (idx, rule) in self.rules.iter_mut().enumerate() {
            normalize_header_match_keys(idx, &mut rule.match_.headers)?;
            // Empty match is normally rejected because it would silently
            // shadow later rules. The exception is a "route-action catch-all":
            // a rule emitted by the K8s VirtualService translator for a
            // URI-only `match.uri` whose http[] carries header transforms
            // or route-local fault injection.
            // Such a rule has no routing effect (its destination is the
            // proxy's default) but carries per-rule actions.
            // `rule_matches` treats empty match as "match all" only when
            // route-local actions are present, so this stays a no-op for any other
            // operator config.
            let has_route_actions = !rule.request_transform.is_empty()
                || !rule.response_transform.is_empty()
                || rule.fault.is_some()
                || rule.rewrite.is_some()
                || rule.redirect.is_some();
            if rule.match_.is_empty() && !has_route_actions {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].match requires at least one of \
                     methods / headers / query_params / authority / source_namespace / uri \
                     (an empty match would silently never fire, contradicting \
                     first-match-wins semantics)"
                ));
            }
            normalize_source_namespace(idx, &mut rule.match_.source_namespace)?;
            // A redirect rule answers the request itself, so it does not need a
            // backend destination. Every other rule must override the proxy's
            // destination (or carry the proxy's default for an action-only
            // catch-all) or it would be a no-op.
            if rule.destination.is_empty() && rule.redirect.is_none() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination requires upstream_id or \
                     a direct backend override (backend_host and backend_port); backend_tls \
                     may only accompany a direct backend"
                ));
            }
            if rule.retry.is_some() && rule.retry_disabled {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}] cannot set both retry and retry_disabled"
                ));
            }
            if rule.timeout_ms.is_some() && rule.timeout_disabled {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}] cannot set both timeout_ms and timeout_disabled"
                ));
            }
            if let Some(retry) = &rule.retry
                && let Err(errors) = retry.validate_fields()
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].retry: {}",
                    errors.join("; ")
                ));
            }
            if let Some(port) = rule.destination.backend_port
                && port == 0
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_port must be non-zero"
                ));
            }
            if let Some(host) = rule.destination.backend_host.as_mut() {
                let trimmed = host.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not be empty"
                    ));
                }
                if trimmed.len() > MAX_BACKEND_HOST_LENGTH {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not exceed {MAX_BACKEND_HOST_LENGTH} characters"
                    ));
                }
                if trimmed.contains("://") {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not contain a scheme"
                    ));
                }
                if trimmed.chars().any(char::is_whitespace) {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not contain whitespace"
                    ));
                }
                *host = trimmed.to_ascii_lowercase();
            }
            let has_backend_host = rule.destination.backend_host.is_some();
            let has_backend_port = rule.destination.backend_port.is_some();
            if rule.destination.upstream_id.is_some()
                && (has_backend_host || has_backend_port || rule.destination.backend_tls.is_some())
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.upstream_id cannot be \
                     combined with backend_host / backend_port / backend_tls"
                ));
            }
            if has_backend_host != has_backend_port {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_host and \
                     backend_port must be set together for direct-backend overrides"
                ));
            }
            if rule.destination.backend_tls.is_some() && !(has_backend_host && has_backend_port) {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_tls requires \
                     backend_host and backend_port so TLS overrides only apply to a direct backend"
                ));
            }
            rule.destination.node_waypoint_backend_match_key = rule
                .destination
                .backend_host
                .as_deref()
                .zip(rule.destination.backend_port)
                .and_then(|(host, port)| node_waypoint_backend_metadata_value(host, port));
            if let Some(tls) = rule.destination.backend_tls.as_mut() {
                normalize_and_validate_backend_tls(idx, tls)?;
            }
            if let Some(fault) = rule.fault.as_ref() {
                validate_fault_action(idx, fault)?;
            }
            if let Some(rewrite) = rule.rewrite.as_mut() {
                validate_and_normalize_rewrite(idx, rewrite)?;
            }
            if let Some(redirect) = rule.redirect.as_mut() {
                validate_and_normalize_redirect(idx, redirect)?;
            }
            rule.fault_roller = if rule.fault.is_some() {
                Some(Arc::new(FaultRoller::new()))
            } else {
                None
            };
            rule.request_transform_compiled =
                compile_transform_field(idx, "request_transform", &rule.request_transform)?;
            rule.response_transform_compiled =
                compile_transform_field(idx, "response_transform", &rule.response_transform)?;
            rule.methods_compiled = compile_method_matchers(idx, &rule.match_.methods)?;
            rule.headers_compiled = compile_header_matchers(idx, &rule.match_.headers)?;
            rule.authority_compiled =
                compile_authority_matcher(idx, rule.match_.authority.as_ref())?;
            rule.uri_compiled =
                compile_uri_matcher(idx, &rule.match_.uri, rule.match_.ignore_uri_case)?;
        }
        Ok(())
    }
}

fn validate_fault_action(rule_idx: usize, fault: &FaultActionConfig) -> Result<(), String> {
    if fault.delay.is_none() && fault.abort.is_none() {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].fault must contain at least one of \
             'delay' or 'abort'"
        ));
    }
    if let Some(delay) = fault.delay.as_ref() {
        if delay.duration_ms == 0 {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].fault.delay.duration_ms must be > 0"
            ));
        }
        if delay.duration_ms > MAX_FAULT_DELAY_MS {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].fault.delay.duration_ms must be \
                 <= {MAX_FAULT_DELAY_MS} (1 minute), got {}",
                delay.duration_ms
            ));
        }
        validate_fault_percentage(rule_idx, "fault.delay.percentage", delay.percentage)?;
    }
    if let Some(abort) = fault.abort.as_ref() {
        if !(200..=599).contains(&abort.status_code) {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].fault.abort.status_code must be \
                 200-599, got {}",
                abort.status_code
            ));
        }
        validate_fault_percentage(rule_idx, "fault.abort.percentage", abort.percentage)?;
        if let Some(code) = abort.grpc_status
            && code > 16
        {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].fault.abort.grpc_status must be \
                 0-16, got {code}"
            ));
        }
    }
    Ok(())
}

fn validate_fault_percentage(
    rule_idx: usize,
    field_name: &str,
    percentage: f64,
) -> Result<(), String> {
    if !percentage.is_finite() {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].{field_name} must be a finite number"
        ));
    }
    if !(0.0..=100.0).contains(&percentage) {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].{field_name} must be in [0.0, 100.0], \
             got {percentage}"
        ));
    }
    if percentage == 0.0 {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].{field_name} must be > 0.0 (a 0% \
             fault would be a no-op; omit the action to disable it instead)"
        ));
    }
    Ok(())
}

/// Reject a string that would let an attacker (or a buggy CP) smuggle a CR/LF
/// into a request line or a response header. Path and authority overrides
/// flow into the backend request line / `Host` header and the redirect
/// `Location` header respectively, so a raw CR/LF would split the message.
fn reject_crlf(rule_idx: usize, field: &str, value: &str) -> Result<(), String> {
    if value.contains(['\r', '\n']) {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].{field} must not contain CR or LF"
        ));
    }
    Ok(())
}

fn validate_and_normalize_rewrite(
    rule_idx: usize,
    rewrite: &mut RouteRewriteConfig,
) -> Result<(), String> {
    if rewrite.is_empty() {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].rewrite must set at least one of \
             'uri' or 'authority'"
        ));
    }
    if let Some(uri) = rewrite.uri.as_deref() {
        if uri.is_empty() {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].rewrite.uri must not be empty"
            ));
        }
        reject_crlf(rule_idx, "rewrite.uri", uri)?;
    }
    if let Some(authority) = rewrite.authority.as_mut() {
        if authority.is_empty() {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].rewrite.authority must not be empty"
            ));
        }
        reject_crlf(rule_idx, "rewrite.authority", authority)?;
        if authority.chars().any(char::is_whitespace) {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].rewrite.authority must not contain whitespace"
            ));
        }
    }
    if let Some(prefix) = rewrite.match_prefix.as_deref()
        && prefix.is_empty()
    {
        // An empty match_prefix would be a degenerate "strip nothing" prefix
        // rewrite — treat as "no prefix" by clearing it so the hot path takes
        // the whole-path replacement branch.
        rewrite.match_prefix = None;
    }
    Ok(())
}

fn validate_and_normalize_redirect(
    rule_idx: usize,
    redirect: &mut RouteRedirectConfig,
) -> Result<(), String> {
    if !(300..=399).contains(&redirect.redirect_code) {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].redirect.redirect_code must be 300-399, got {}",
            redirect.redirect_code
        ));
    }
    if let Some(uri) = redirect.uri.as_deref() {
        if uri.is_empty() {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].redirect.uri must not be empty"
            ));
        }
        reject_crlf(rule_idx, "redirect.uri", uri)?;
    }
    if let Some(prefix) = redirect.match_prefix.as_deref()
        && prefix.is_empty()
    {
        redirect.match_prefix = None;
    }
    if let Some(authority) = redirect.authority.as_mut() {
        if authority.is_empty() {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].redirect.authority must not be empty"
            ));
        }
        reject_crlf(rule_idx, "redirect.authority", authority)?;
        if authority.chars().any(char::is_whitespace) {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].redirect.authority must not contain whitespace"
            ));
        }
    }
    if redirect.port == Some(0) {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].redirect.port must be in the 1-65535 range"
        ));
    }
    if redirect.port.is_some() && redirect.derive_port.is_some() {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].redirect.port and redirect.derive_port \
             are mutually exclusive"
        ));
    }
    if let Some(scheme) = redirect.scheme.as_mut() {
        *scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].redirect.scheme must be 'http' or 'https'"
            ));
        }
    }
    Ok(())
}

fn compile_transform_field(
    rule_idx: usize,
    field: &str,
    raw: &[RawRouteHeaderTransformRule],
) -> Result<Option<Arc<Vec<RouteHeaderTransformRule>>>, String> {
    if raw.is_empty() {
        return Ok(None);
    }
    let context = format!("mesh_route_dispatch.rules[{rule_idx}].{field}");
    let parsed = parse_route_header_transforms(raw, &context)?;
    // Response route overrides share the response_transformer write surface:
    // reject protocol-managed destinations so a VirtualService header modifier
    // cannot reintroduce Connection/Transfer-Encoding/Content-Length after the
    // origin strip. Request transforms keep their existing contract.
    if field == "response_transform" {
        for (idx, rule) in parsed.iter().enumerate() {
            match rule.operation {
                crate::plugins::utils::route_header_transform::RouteHeaderTransformOp::Remove => {}
                crate::plugins::utils::route_header_transform::RouteHeaderTransformOp::Add
                | crate::plugins::utils::route_header_transform::RouteHeaderTransformOp::Update => {
                    if crate::proxy::headers::is_protocol_managed_plugin_response_destination(
                        &rule.key,
                    ) {
                        return Err(format!(
                            "{context}[{idx}].key '{}' is protocol-managed (hop-by-hop or framing) \
                             and cannot be a response_transform destination",
                            rule.key
                        ));
                    }
                }
            }
        }
    }
    Ok(Some(Arc::new(parsed)))
}

/// Route-local retry wire shape. `RetryConfig` is also deserialized from
/// persisted proxy retry JSON, where unknown-field compatibility is broader;
/// keep the strict boundary local to mesh route policy instead of changing
/// every shared deserialization path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteRetryConfig {
    #[serde(default = "route_default_max_retries")]
    max_retries: u32,
    #[serde(default)]
    retryable_status_codes: Vec<u16>,
    #[serde(default = "route_default_retryable_methods")]
    retryable_methods: Vec<String>,
    #[serde(default)]
    backoff: RouteBackoffStrategy,
    #[serde(default = "route_default_true")]
    retry_on_connect_failure: bool,
}

/// Externally tagged route-local backoff. Serde JSON enforces a single variant
/// key, and each newtype payload is independently closed below; the enum-level
/// attribute also records the strict boundary if its representation evolves.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum RouteBackoffStrategy {
    Fixed(RouteFixedBackoff),
    Exponential(RouteExponentialBackoff),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFixedBackoff {
    delay_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteExponentialBackoff {
    base_ms: u64,
    max_ms: u64,
}

impl Default for RouteBackoffStrategy {
    fn default() -> Self {
        Self::Fixed(RouteFixedBackoff { delay_ms: 100 })
    }
}

impl From<RouteBackoffStrategy> for BackoffStrategy {
    fn from(value: RouteBackoffStrategy) -> Self {
        match value {
            RouteBackoffStrategy::Fixed(config) => Self::Fixed {
                delay_ms: config.delay_ms,
            },
            RouteBackoffStrategy::Exponential(config) => Self::Exponential {
                base_ms: config.base_ms,
                max_ms: config.max_ms,
            },
        }
    }
}

impl From<RouteRetryConfig> for RetryConfig {
    fn from(value: RouteRetryConfig) -> Self {
        Self {
            max_retries: value.max_retries,
            retryable_status_codes: value.retryable_status_codes,
            retryable_methods: value.retryable_methods,
            backoff: value.backoff.into(),
            retry_on_connect_failure: value.retry_on_connect_failure,
        }
    }
}

fn route_default_max_retries() -> u32 {
    RetryConfig::default().max_retries
}

fn route_default_retryable_methods() -> Vec<String> {
    RetryConfig::default().retryable_methods
}

fn route_default_true() -> bool {
    true
}

fn deserialize_route_retry<'de, D>(deserializer: D) -> Result<Option<RetryConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<RouteRetryConfig>::deserialize(deserializer).map(|retry| retry.map(RetryConfig::from))
}

/// Route-local backend TLS wire shape for the same reason as
/// `RouteRetryConfig`: strict route policy must not silently accept typos, but
/// the shared runtime type has other compatibility-sensitive input surfaces.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteBackendTlsConfig {
    #[serde(default)]
    client_cert_path: Option<String>,
    #[serde(default)]
    client_key_path: Option<String>,
    #[serde(default)]
    server_ca_cert_path: Option<String>,
    #[serde(default = "route_default_true")]
    verify_server_cert: bool,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    san_allow_list: Vec<String>,
}

impl From<RouteBackendTlsConfig> for BackendTlsConfig {
    fn from(value: RouteBackendTlsConfig) -> Self {
        Self {
            client_cert_path: value.client_cert_path,
            client_key_path: value.client_key_path,
            server_ca_cert_path: value.server_ca_cert_path,
            verify_server_cert: value.verify_server_cert,
            sni: value.sni,
            san_allow_list: value.san_allow_list,
            san_allow_list_key_digest: None,
        }
    }
}

fn deserialize_route_backend_tls<'de, D>(
    deserializer: D,
) -> Result<Option<BackendTlsConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<RouteBackendTlsConfig>::deserialize(deserializer)
        .map(|tls| tls.map(BackendTlsConfig::from))
}

fn normalize_and_validate_backend_tls(
    rule_idx: usize,
    tls: &mut BackendTlsConfig,
) -> Result<(), String> {
    for (field, path) in [
        ("client_cert_path", tls.client_cert_path.as_deref()),
        ("client_key_path", tls.client_key_path.as_deref()),
        ("server_ca_cert_path", tls.server_ca_cert_path.as_deref()),
    ] {
        if path.is_some_and(str::is_empty) {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.{field} \
                 must not be empty"
            ));
        }
    }

    let has_client_cert = tls.client_cert_path.is_some();
    let has_client_key = tls.client_key_path.is_some();
    if has_client_cert != has_client_key {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.client_cert_path \
             and client_key_path must be set together"
        ));
    }

    if let Some(sni) = tls.sni.as_mut() {
        validate_backend_tls_sni(sni).map_err(|e| {
            format!("mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.sni: {e}")
        })?;
        *sni = sni.to_ascii_lowercase();
    }

    if tls.san_allow_list.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.san_allow_list \
             must not have more than {MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES} entries (got {})",
            tls.san_allow_list.len()
        ));
    }
    for (san_idx, san) in tls.san_allow_list.iter_mut().enumerate() {
        validate_backend_tls_san_allow_list_entry(san).map_err(|e| {
            format!(
                "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.san_allow_list[{san_idx}]: {e}"
            )
        })?;
        normalize_backend_tls_san_allow_list_entry(san);
    }
    tls.recompute_san_digest();

    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// Match criteria — all configured fields must match for the rule to fire.
    #[serde(default, rename = "match")]
    pub match_: MatchCriteria,
    /// What to override on a matching request. At least one override field
    /// MUST be set unless the rule carries a `redirect` (which answers the
    /// request itself and needs no backend); otherwise the rule would be a
    /// no-op. Defaults to empty so a redirect-only rule can omit it.
    #[serde(default)]
    pub destination: RouteDestination,
    /// Override the proxy's backend response/read timeout for this rule.
    /// Istio `VirtualService.http[].timeout` is projected here when route
    /// candidates are collapsed into a shared Ferrum proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Explicitly clear the selected proxy's backend response/read timeout
    /// for this rule. Translator-generated collapsed rules use this when the
    /// source VirtualService route omits `timeout`, because Istio's default is
    /// timeout-disabled and the selected fallback proxy may carry a timeout.
    #[serde(default, skip_serializing_if = "is_false")]
    pub timeout_disabled: bool,
    /// Override the proxy's retry policy for this rule.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_route_retry"
    )]
    pub retry: Option<RetryConfig>,
    /// Explicitly clear the selected proxy's retry policy for this rule.
    /// Translator-generated collapsed rules use this to prevent a later
    /// fallback route's retry policy from leaking onto an earlier route.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retry_disabled: bool,
    /// Optional request-header transforms applied by `request_transformer`
    /// after its own static rules when this rule matches. Projects Istio
    /// `VirtualService.http[].headers.request.{set,add,remove}` onto each
    /// emitted dispatch rule. Operators may also configure these directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_transform: Vec<RawRouteHeaderTransformRule>,
    /// Optional response-header transforms applied by `response_transformer`
    /// after its own static rules when this rule matches. Counterpart to
    /// `request_transform`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_transform: Vec<RawRouteHeaderTransformRule>,
    /// Optional per-rule fault action. Mirrors the proxy-scoped
    /// `fault_injection` plugin's `delay` / `abort` shape but applies only
    /// when this dispatch rule matches the request. Used by the K8s
    /// VirtualService translator to project `http[].fault` onto each
    /// emitted dispatch rule so fault-carrying routes can be collapsed
    /// with sibling routes without a fail-closed escape hatch.
    ///
    /// **RTDS scope:** the percentages baked into a per-rule fault are
    /// NOT runtime-tunable via the GAP-3E RTDS keys
    /// `ferrum.fault_injection.<scope>.{abort,delay}_percent` — those keys
    /// apply only to `fault_injection` plugin instances configured with
    /// `runtime_overlay_scope`. Operators who need RTDS-driven fault
    /// percentages should use a global / proxy-scoped `fault_injection`
    /// plugin instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<FaultActionConfig>,
    /// Optional per-rule URI / authority rewrite. Projects Istio
    /// `VirtualService.http[].rewrite` onto each emitted dispatch rule so a
    /// rewriting route can be collapsed with sibling routes onto one Ferrum
    /// proxy without rewriting the siblings' traffic. Applied when the rule
    /// matches and no redirect fires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<RouteRewriteConfig>,
    /// Optional per-rule HTTP redirect. Projects Istio
    /// `VirtualService.http[].redirect` onto each emitted dispatch rule. When
    /// the rule matches, the request is short-circuited with a 3xx +
    /// `Location` response and never reaches a backend. Takes precedence over
    /// `rewrite` and the route-override destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RouteRedirectConfig>,
    /// Per-rule fault roller. Constructed at config-load time whenever
    /// `fault` is `Some` so the request hot path does one atomic counter
    /// increment + two SplitMix finalizations per fault decision. `None` when
    /// the rule carries no fault. The `apply_fault_action` helper falls back
    /// to a throwaway `FaultRoller::new()` if this is somehow unset on a
    /// fault-carrying rule — defense in depth for hand-constructed
    /// `RouteRule` literals in tests.
    #[serde(skip)]
    fault_roller: Option<Arc<FaultRoller>>,
    /// Pre-compiled `request_transform` rules, built during normalize so the
    /// hot path clones an `Arc` pointer (not the rule list) on every match.
    /// `None` when `request_transform` is empty.
    #[serde(skip)]
    request_transform_compiled: Option<Arc<Vec<RouteHeaderTransformRule>>>,
    /// Pre-compiled `response_transform` rules; counterpart to
    /// `request_transform_compiled`.
    #[serde(skip)]
    response_transform_compiled: Option<Arc<Vec<RouteHeaderTransformRule>>>,
    /// Pre-compiled per-method matchers built during normalize. `Regex`
    /// values are compiled here, not per request — the hot path only does
    /// `matchers.iter().any(|m| m.matches(ctx.method.as_str()))`. Empty when
    /// `match.methods` is empty (no method restriction).
    #[serde(skip)]
    methods_compiled: Vec<MethodMatcher>,
    /// Pre-compiled per-header matchers built during normalize. `Regex`
    /// values are compiled here, not per request — the hot path only does
    /// `HashMap::get(name).is_some_and(|v| matcher.matches(v))`.
    /// Empty when `match.headers` is empty.
    #[serde(skip)]
    headers_compiled: HashMap<String, HeaderMatcher>,
    /// Pre-compiled `match.authority` matcher built during normalize. `Regex`
    /// values are compiled here, not per request — the hot path resolves the
    /// request's raw `Host`/`:authority` once and runs the compiled
    /// matcher. `None` when `match.authority` is unset (no authority
    /// restriction). Istio `HTTPMatchRequest.authority` is exactly one
    /// predicate per rule, so this is `Option<_>` (not `Vec<_>`).
    #[serde(skip)]
    authority_compiled: Option<AuthorityMatcher>,
    /// Pre-compiled URI matcher built during normalize. When the rule has no
    /// `match.uri` predicate this stays `None` and the hot path skips URI
    /// evaluation entirely (preserving the legacy behavior of routing solely
    /// by the proxy's `listen_path`). When set, the matcher already carries
    /// the case-folded operand (exact / prefix) or the compiled operator
    /// regex, so the hot path is one allocation-free compare against
    /// `ctx.path`.
    #[serde(skip)]
    uri_compiled: Option<UriMatcher>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchCriteria {
    /// HTTP methods (any-of). Empty = no method restriction. Each entry is
    /// one of:
    ///
    /// - a plain string — interpreted as an `Exact` match (back-compat with
    ///   the original `Vec<String>` shape);
    /// - an object with exactly one of `exact` / `prefix` / `regex` — the
    ///   Istio `StringMatch` shape, projected from VirtualService translation.
    ///
    /// HTTP methods are conventionally uppercase ASCII (RFC 9110 §9.1). The
    /// translator preserves operator casing on the wire. The plugin uppercases
    /// `prefix` patterns at compile time; `regex` patterns remain verbatim and
    /// must span the full request method. `Exact` keeps the operator's literal
    /// casing to preserve the existing `method_match_is_case_sensitive`
    /// contract.
    ///
    /// Regexes compile at config-load time (cold path); the hot path reads
    /// the pre-compiled `Regex` from the rule's `methods_compiled` slot.
    #[serde(default)]
    pub methods: Vec<MethodMatchOp>,
    /// Header matches (all-of). Header names are case-insensitive. The value
    /// shape is one of:
    ///
    /// - a plain string — interpreted as an `Exact` match (back-compat with
    ///   the original `HashMap<String, String>` shape);
    /// - an object with exactly one of `exact` / `prefix` / `regex` — the
    ///   Istio `StringMatch` shape, projected from VirtualService translation.
    ///
    /// Regexes compile at config-load time (cold path); the hot path reads
    /// the pre-compiled `Regex` from the rule's `headers_compiled` slot.
    #[serde(default)]
    pub headers: HashMap<String, HeaderMatchOp>,
    /// Query parameter equality matches (all-of). Names and values match
    /// exactly after percent-decoding the backend-bound query representation
    /// available at this dispatch hook, including authentication-owned
    /// credential strips and any priority-overridden query transformer that
    /// already ran. A later route/request transform remains an intentional,
    /// separately ordered operation.
    ///
    /// A request whose query cannot be decoded to one such value is rejected
    /// with 400 before any rule is evaluated: a repeated or percent-encoded
    /// duplicate name, a literal `+` (RFC 3986 plus vs form-urlencoded space),
    /// malformed percent-encoding, or a non-UTF-8 decoding. See
    /// [`crate::plugins::utils::query::CanonicalQuery`].
    #[serde(default)]
    pub query_params: HashMap<String, String>,
    /// Source workload Kubernetes namespace (exact match). Resolved from the
    /// peer's SPIFFE ID per the Istio convention
    /// `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>` via
    /// [`SpiffeId::namespace`](crate::identity::SpiffeId::namespace).
    ///
    /// The Istio CRD models `HTTPMatchRequest.sourceNamespace` as an
    /// exact-only string (no `prefix`/`regex` arms), so this field is a plain
    /// `Option<String>` rather than a `StringMatch` enum — adding more arms
    /// later would silently shadow operator intent. Matches are
    /// case-sensitive: Kubernetes namespace names are lowercase per RFC 1123,
    /// so any operator-provided casing is preserved verbatim and a
    /// `"Prod"` predicate will not match a SPIFFE ID encoding `ns/prod`.
    ///
    /// `None` = no source-namespace restriction. The predicate also fails to
    /// match (returns `false`) when the request carries no resolved peer
    /// SPIFFE identity (non-mesh request, or the source workload is outside
    /// the mesh trust domain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_namespace: Option<String>,
    /// Optional `:authority` / `Host` predicate. The shape mirrors Istio's
    /// `HTTPMatchRequest.authority` (`exact` / `prefix` / `regex`); the
    /// translator projects exactly that. Distinct from VirtualService-level
    /// `hosts`, which gates which proxy admits a request — this is a
    /// per-rule predicate evaluated AFTER routing has picked the proxy. The
    /// hot path compares the request's `Host`/`:authority` value as presented
    /// by the client:
    ///
    /// - `exact` / `prefix` patterns are case-sensitive, per Istio
    ///   `StringMatch` semantics;
    /// - `regex` patterns are NOT folded — operators who want
    ///   case-insensitivity should write `(?i)` in their pattern.
    ///
    /// `None` = no authority restriction (any host permitted by the proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<AuthorityMatchOp>,
    /// Optional URI predicate (Istio `StringMatch` shape — one of `exact` /
    /// `prefix` / `regex`). Routing-to-this-rule is normally selected by the
    /// proxy's `listen_path`; an explicit `uri` predicate is only set when
    /// the rule needs additional URI evaluation at the dispatch layer, e.g.,
    /// VirtualService `match[].ignoreUriCase: true`. In that case the
    /// translator widens the proxy's `listen_path` to a case-insensitive
    /// regex for exact/prefix URI matches (so both casings reach the proxy)
    /// and emits this predicate here so the original Istio match precision is
    /// preserved. Regex URI matches are not affected by `ignore_uri_case`.
    ///
    /// `None` (the legacy shape) preserves "no URI re-evaluation in the
    /// plugin"; the proxy's `listen_path` already gates the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<UriMatchOp>,
    /// When `true`, the URI predicate above (and any URI evaluation at this
    /// rule) folds ASCII case before comparing. Mirrors Istio's
    /// `HTTPMatchRequest.ignoreUriCase` semantics: only the URI predicate is
    /// affected (not headers / methods / authority / etc.), and only ASCII
    /// case is folded. Non-ASCII bytes match byte-for-byte. The plugin
    /// rejects `ignore_uri_case: true` when no `uri` predicate is set,
    /// because the flag would have no observable effect (catches a likely
    /// operator misconfiguration at config-load time).
    #[serde(default, skip_serializing_if = "is_false")]
    pub ignore_uri_case: bool,
}

impl MatchCriteria {
    fn is_empty(&self) -> bool {
        self.methods.is_empty()
            && self.headers.is_empty()
            && self.query_params.is_empty()
            && self.source_namespace.is_none()
            && self.authority.is_none()
            && self.uri.is_none()
    }
}

/// `:authority` / `Host` match operator. Mirrors Istio's `StringMatch` shape
/// (one of `exact` / `prefix` / `regex`), with an extra wire-compat arm for a
/// legacy plain-string form interpreted as `Exact`. The plain-string form is
/// not emitted by the K8s VirtualService translator but is accepted so
/// operators may hand-author a config without learning the tagged shape.
///
/// Serde-untagged so JSON round-trips byte-identical for both shapes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorityMatchOp {
    /// Back-compat form: bare string, interpreted as `Exact`.
    Legacy(String),
    /// Tagged form: `{ "exact" | "prefix" | "regex": "..." }`.
    Tagged(AuthorityStringMatch),
}

/// Tagged `StringMatch` for `:authority` / `Host` — exactly one of `exact`,
/// `prefix`, or `regex` may be present. `deny_unknown_fields` rejects typos
/// like `{"prefiks": "..."}` at config-load time rather than silently
/// ignoring them. Serde's externally-tagged enum representation also rejects
/// shapes that carry more than one operator (e.g.,
/// `{"exact": "a", "prefix": "b"}`), so Istio's "exactly one predicate"
/// contract is enforced at deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityStringMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// Compiled hot-path representation of an `AuthorityMatchOp`. Regexes are
/// stored as `Regex` (compiled once at config load); exact/prefix keep the
/// operator string verbatim because Istio `StringMatch` exact/prefix matching
/// is case-sensitive. `Clone` is cheap because the `regex` crate's `Regex` is
/// `Arc`-backed internally and clones are refcount bumps, not pattern
/// recompiles.
#[derive(Debug, Clone)]
pub(crate) enum AuthorityMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl AuthorityMatcher {
    fn matches(&self, authority: &str) -> bool {
        match self {
            AuthorityMatcher::Exact(expected) => authority == expected.as_str(),
            AuthorityMatcher::Prefix(prefix) => authority.starts_with(prefix.as_str()),
            AuthorityMatcher::Regex(re) => re.is_match(authority),
        }
    }
}

/// Per-method match operator. Mirrors the Istio `StringMatch` shape (one of
/// `exact` / `prefix` / `regex`), with an extra wire-compat arm for the
/// legacy plain-string form (`["GET", "POST"]` → two `Exact` entries).
///
/// Serde-untagged so JSON round-trips byte-identical for both shapes:
/// a plain-string method entry deserializes (and re-serializes) as the legacy
/// form; the tagged form deserializes (and re-serializes) as the
/// `StringMatch` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MethodMatchOp {
    /// Back-compat form: bare string, interpreted as `Exact`.
    Legacy(String),
    /// Tagged form: `{ "exact" | "prefix" | "regex": "..." }`.
    Tagged(MethodStringMatch),
}

/// Tagged `StringMatch` for HTTP method matchers — exactly one of `exact`,
/// `prefix`, or `regex` may be present. `deny_unknown_fields` rejects e.g.
/// typos like `{"prefiks": "..."}` at config-load time rather than silently
/// ignoring them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MethodStringMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// Compiled hot-path representation of a `MethodMatchOp`. Regexes are stored
/// as `Regex` (compiled once at config load); exact/prefix keep an owned
/// `String` value. `Clone` is cheap because the `regex` crate's `Regex` is
/// `Arc`-backed internally and clones are refcount bumps, not pattern
/// recompiles.
///
/// `Prefix` is uppercased at compile time (methods are conventionally
/// uppercase ASCII per RFC 9110 §9.1). Regex patterns are embedded verbatim
/// inside absolute input anchors and must span the full method. `Exact` retains
/// the operator's casing exactly so `method_match_is_case_sensitive` stays
/// truthful — operators who write `"get"` continue to match only literal
/// `"get"` requests, never `"GET"`.
#[derive(Debug, Clone)]
pub(crate) enum MethodMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl MethodMatcher {
    fn matches(&self, method: &str) -> bool {
        match self {
            MethodMatcher::Exact(expected) => method == expected.as_str(),
            MethodMatcher::Prefix(prefix) => method.starts_with(prefix.as_str()),
            MethodMatcher::Regex(re) => re.is_match(method),
        }
    }
}

/// Per-header match operator. Mirrors the Istio `StringMatch` shape (one of
/// `exact` / `prefix` / `regex`), with an extra wire-compat arm for the
/// legacy plain-string form (`{"x-canary": "v2"}` → `Exact("v2")`).
///
/// Serde-untagged so JSON round-trips byte-identical for both shapes:
/// a plain-string header value deserializes (and re-serializes) as the legacy
/// form; the tagged form deserializes (and re-serializes) as the
/// `StringMatch` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderMatchOp {
    /// Back-compat form: bare string, interpreted as `Exact`.
    Legacy(String),
    /// Tagged form: `{ "exact" | "prefix" | "regex": "..." }`.
    Tagged(HeaderStringMatch),
}

/// Tagged `StringMatch` for headers — exactly one of `exact`, `prefix`, or
/// `regex` may be present. `deny_unknown_fields` rejects e.g. typos like
/// `{"prefiks": "..."}` at config-load time rather than silently ignoring them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderStringMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// Compiled hot-path representation of a `HeaderMatchOp`. Regexes are stored
/// as `Regex` (compiled once at config load); exact/prefix keep the borrowed
/// reference into the original config string. `Clone` is cheap because the
/// `regex` crate's `Regex` is `Arc`-backed internally and clones are
/// refcount bumps, not pattern recompiles.
#[derive(Debug, Clone)]
pub(crate) enum HeaderMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl HeaderMatcher {
    fn matches(&self, value: &str) -> bool {
        match self {
            HeaderMatcher::Exact(expected) => value == expected.as_str(),
            HeaderMatcher::Prefix(prefix) => value.starts_with(prefix.as_str()),
            HeaderMatcher::Regex(re) => re.is_match(value),
        }
    }
}

/// Per-URI match operator. Mirrors the Istio `StringMatch` shape (one of
/// `exact` / `prefix` / `regex`). Unlike header / method matchers, there is
/// no legacy bare-string back-compat arm because the URI predicate was not
/// previously expressible on `MatchCriteria` — `mesh_route_dispatch` rules
/// inherited URI selection from the parent proxy's `listen_path`. New
/// callers MUST use the tagged form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UriMatchOp {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// Compiled hot-path representation of a `UriMatchOp`. `Exact` / `Prefix`
/// store the operand (lowercased at compile time when `ignore_uri_case`); the
/// hot path uses `eq_ignore_ascii_case` / a manual byte-level prefix compare
/// so it never allocates. `Regex` stores a pre-compiled operator regex. Istio
/// documents `ignoreUriCase` as exact/prefix-only, so regex URI matches are not
/// rewritten by the flag. The `regex` crate's `Regex` is `Arc`-backed
/// internally — `Clone` is a refcount bump.
#[derive(Debug, Clone)]
pub(crate) enum UriMatcher {
    /// Exact-path equality. `case_insensitive` controls whether the hot path
    /// compares with `eq_ignore_ascii_case` (true) or `==` (false).
    Exact {
        value: String,
        case_insensitive: bool,
    },
    /// Path-prefix match. Same case-insensitive flag semantics as `Exact`.
    /// Hot path does a byte-level `starts_with` (case-sensitive) or a manual
    /// case-folded scan; both stay allocation-free.
    Prefix {
        value: String,
        case_insensitive: bool,
    },
    /// Compiled operator regex. `ignore_uri_case` does not affect this arm.
    Regex(Regex),
}

impl UriMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            UriMatcher::Exact {
                value,
                case_insensitive,
            } => {
                if *case_insensitive {
                    path.eq_ignore_ascii_case(value)
                } else {
                    path == value.as_str()
                }
            }
            UriMatcher::Prefix {
                value,
                case_insensitive,
            } => {
                if *case_insensitive {
                    starts_with_ignore_ascii_case(path, value)
                } else {
                    path.starts_with(value.as_str())
                }
            }
            UriMatcher::Regex(re) => re.is_match(path),
        }
    }
}

/// Compile a regex that can match only the complete input. Anchoring at the
/// cold config boundary avoids relying on the first leftmost alternative from
/// `Regex::find`, which may be a shorter prefix even when a later alternative
/// spans the whole input. The operator pattern stays in its own non-capturing
/// group so inline flags and alternation retain their original semantics.
fn compile_full_match_regex(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!(r"\A(?:{pattern})\z"))
}

/// Allocation-free byte-level case-insensitive `starts_with`. ASCII fold
/// only: non-ASCII bytes match byte-for-byte (matches Istio's semantics and
/// is documented as such in the operator-facing docs). Returns `false` when
/// `path` is shorter than `prefix`.
fn starts_with_ignore_ascii_case(path: &str, prefix: &str) -> bool {
    let path_bytes = path.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    if path_bytes.len() < prefix_bytes.len() {
        return false;
    }
    // `u8::eq_ignore_ascii_case` is a one-instruction compare that handles
    // ASCII upper / lower folding; non-ASCII bytes compare byte-for-byte.
    // Faster than `make_ascii_lowercase`-then-compare and never allocates.
    path_bytes
        .iter()
        .zip(prefix_bytes.iter())
        .all(|(p, q)| p.eq_ignore_ascii_case(q))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDestination {
    /// Override the proxy's `upstream_id`. Wins over `proxy.upstream_id`
    /// at upstream-target selection time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    /// Override the proxy's `backend_host`. Wins over `proxy.backend_host`.
    /// Pool keys partition by the effective host, so two rules with
    /// different `backend_host` values get distinct backend connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_host: Option<String>,
    /// Override the proxy's `backend_port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_port: Option<u16>,
    /// Override the proxy's resolved backend TLS materials when the rule
    /// routes to a direct backend that uses different mTLS settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_route_backend_tls"
    )]
    pub backend_tls: Option<BackendTlsConfig>,
    /// Trusted translator marker for destinations that enter NodeWaypoint
    /// Service authz. When scoped NodeWaypoint authz ran but did not stamp an
    /// authorized destination, matching this rule must fail closed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_node_waypoint_authz: bool,
    /// Canonical direct-backend key compared against the NodeWaypoint authz
    /// stamp. Built once during config normalization so the request path can
    /// borrow it without lowercasing or formatting on every match.
    #[serde(skip)]
    node_waypoint_backend_match_key: Option<String>,
}

impl RouteDestination {
    fn is_empty(&self) -> bool {
        self.upstream_id.is_none()
            && self.backend_host.is_none()
            && self.backend_port.is_none()
            && self.backend_tls.is_none()
    }
}

fn reject_node_waypoint_authz_destination_override(
    ctx: &RequestContext,
    destination: &RouteDestination,
) -> Option<PluginResult> {
    let authorized_upstream_id = ctx
        .metadata
        .get(NODE_WAYPOINT_AUTHORIZED_UPSTREAM_ID_METADATA);
    let authorized_backend = ctx.metadata.get(NODE_WAYPOINT_AUTHORIZED_BACKEND_METADATA);
    let authorized_backend_aliases = ctx
        .metadata
        .get(NODE_WAYPOINT_AUTHORIZED_BACKEND_ALIASES_METADATA);
    if authorized_upstream_id.is_none() && authorized_backend.is_none() {
        if destination.requires_node_waypoint_authz
            && !destination.is_empty()
            && ctx
                .metadata
                .get(NODE_WAYPOINT_SCOPED_AUTHZ_ACTIVE_METADATA)
                .is_some_and(|value| value == "true")
        {
            return Some(PluginResult::Reject {
                status_code: 403,
                body:
                    "node-waypoint mesh authorization requires an authorized destination before route override"
                        .to_string(),
                headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
            });
        }
        return None;
    }
    if destination.is_empty() {
        return None;
    }
    if let Some(authorized_upstream_id) = authorized_upstream_id
        && destination.upstream_id.as_deref() == Some(authorized_upstream_id.as_str())
        && destination.backend_host.is_none()
        && destination.backend_port.is_none()
        && destination.backend_tls.is_none()
    {
        return None;
    }
    if let Some(authorized_backend) = authorized_backend
        && destination.upstream_id.is_none()
        && let Some(destination_backend) = destination.node_waypoint_backend_match_key.as_deref()
        && (destination_backend == authorized_backend.as_str()
            || node_waypoint_backend_metadata_contains(
                authorized_backend_aliases.map(String::as_str),
                destination_backend,
            ))
    {
        return None;
    }
    Some(PluginResult::Reject {
        status_code: 403,
        body:
            "node-waypoint mesh authorization forbids route override to an unauthorized destination"
                .to_string(),
        headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
    })
}

fn node_waypoint_backend_metadata_value(host: &str, port: u16) -> Option<String> {
    if port == 0 {
        return None;
    }
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then(|| format!("{host}|{port}"))
}

fn node_waypoint_backend_metadata_contains(values: Option<&str>, backend: &str) -> bool {
    values
        .into_iter()
        .flat_map(|values| values.split(','))
        .any(|value| value.trim() == backend)
}

/// Per-rule fault action carried by a single [`RouteRule`]. Projects Istio
/// `VirtualService.http[].fault` onto the matching dispatch rule so a
/// fault-carrying route does not have to spin up a separate proxy-scoped
/// `fault_injection` plugin (which previously fail-closed any
/// fault-carrying route that had to be collapsed with sibling routes
/// because the plugin's per-proxy granularity was coarser than the
/// per-rule semantics Istio specifies).
///
/// At least one of `delay` / `abort` must be present; an empty fault
/// object is rejected at config-load time.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FaultActionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<FaultDelayConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort: Option<FaultAbortConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FaultDelayConfig {
    /// How long to delay when the percentile roll hits, in milliseconds.
    /// Bounded to `[1, 60_000]` (1 ms to 1 minute) so a misconfigured
    /// fault can't wedge a proxy forever.
    pub duration_ms: u64,
    /// Percent of matching requests that trigger the delay. Range
    /// `(0.0, 100.0]`. `0.0` is rejected at config-load time because it
    /// would be a no-op.
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FaultAbortConfig {
    /// HTTP status code returned to the client. `200..=599`.
    pub status_code: u16,
    /// Percent of matching requests that trigger the abort. Range
    /// `(0.0, 100.0]`.
    pub percentage: f64,
    /// Optional gRPC status code (`0..=16`) — emitted only when the immutable
    /// pre-plugin request flavor is native gRPC. Plain HTTP, WebSocket, and
    /// gRPC-Web requests never receive a stray `grpc-status` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_status: Option<u32>,
    /// Optional response body. Empty when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Per-rule URI / authority rewrite carried by a single [`RouteRule`].
/// Projects Istio `VirtualService.http[].rewrite` onto the matching dispatch
/// rule so a rewriting route does not have to spin up a separate
/// proxy-scoped transformer instance (which would rewrite traffic for every
/// route collapsed onto the same Ferrum proxy, not just the matched route).
///
/// At least one of `uri` / `authority` must be present; an empty rewrite is
/// rejected at config-load time.
///
/// **Semantics** (matching Istio):
///
/// - `uri` rewrites the request path forwarded to the backend. When the rule's
///   `match.uri` is a `prefix`, only the matched prefix is replaced (the
///   `match_prefix` field carries the literal prefix to strip). For exact /
///   regex matches — and for rules without a `match.uri` (URI selection came
///   from the proxy's `listen_path`) — the whole path is replaced.
/// - `authority` rewrites the `Host` / `:authority` header forwarded to the
///   backend.
///
/// The rewrite is applied AFTER any route override destination is chosen, so a
/// canary route can both re-target an upstream and rewrite the path it sees.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteRewriteConfig {
    /// Replacement request path (or path prefix when `match_prefix` is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Replacement `Host` / `:authority` value forwarded to the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// When the source `match.uri` was a `prefix`, the literal prefix the
    /// translator matched. The hot path strips this prefix from the request
    /// path and prepends `uri`, mirroring Istio's prefix-rewrite semantics.
    /// `None` (exact / regex match, or no `match.uri`) means `uri` replaces
    /// the whole path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_prefix: Option<String>,
}

impl RouteRewriteConfig {
    fn is_empty(&self) -> bool {
        self.uri.is_none() && self.authority.is_none()
    }
}

/// Per-rule HTTP redirect carried by a single [`RouteRule`]. Projects Istio
/// `VirtualService.http[].redirect` onto the matching dispatch rule. When the
/// rule matches, the plugin short-circuits the dispatch chain with a redirect
/// response (3xx + `Location`) and the request never reaches a backend.
///
/// If `uri` / `authority` / `port` / `derive_port` / `scheme` are all unset,
/// the redirect keeps the original request URL and only changes the status
/// code. `redirect_code` defaults to 301 and is constrained to the 3xx range.
///
/// `port` and `derive_port` are mutually exclusive (Istio `HTTPRedirect`
/// oneof). Scheme-default ports (`80`/`http`, `443`/`https`) are omitted from
/// the rendered authority.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteRedirectConfig {
    /// Replacement path for the `Location` header. When unset, the request's
    /// own path is preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// When set, only this matched request-path prefix is replaced by `uri`
    /// and the remainder of the original request path is preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_prefix: Option<String>,
    /// Replacement authority (host[:port]) for the `Location` header. When
    /// unset, the request's own `Host` / `:authority` is preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// Replacement authority port for the `Location` header. When `authority`
    /// is unset this preserves the request host and swaps only the port.
    /// Mutually exclusive with [`Self::derive_port`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Dynamically derive the `Location` authority port (Istio `derivePort`).
    /// Mutually exclusive with [`Self::port`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derive_port: Option<RedirectDerivePort>,
    /// Replacement scheme (`http` / `https`) for the `Location` header. When
    /// unset, the request's own frontend scheme is preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// HTTP redirect status code. Defaults to 301. Constrained to `300..=399`.
    #[serde(default = "default_redirect_code")]
    pub redirect_code: u16,
}

/// Istio `HTTPRedirect.RedirectPortSelection` projected onto
/// [`RouteRedirectConfig::derive_port`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedirectDerivePort {
    /// Use the scheme default port (`80` for `http`, `443` for `https`),
    /// including when `scheme` is also overridden on the same redirect.
    #[serde(rename = "FROM_PROTOCOL_DEFAULT")]
    FromProtocolDefault,
    /// Use the trusted frontend listener port that accepted the request
    /// (`RequestContext::frontend_listen_port`). Spoofable forwarding headers
    /// such as `X-Forwarded-Port` / `Forwarded` are never consulted.
    /// When capture rewrote the accept socket, the original-destination port
    /// (`RequestContext::orig_dst`) is preferred over the capture listener.
    #[serde(rename = "FROM_REQUEST_PORT")]
    FromRequestPort,
}

fn default_redirect_code() -> u16 {
    301
}

#[derive(Debug)]
pub struct MeshRouteDispatch {
    config: MeshRouteDispatchConfig,
    aggregate_reject_unmatched: AtomicBool,
    /// Whether any rule declares a `query_params` predicate. Precomputed at
    /// config load so the hot path never rescans the rule list, and so a
    /// dispatch config that does not route on the query costs nothing.
    has_query_predicates: bool,
}

impl MeshRouteDispatch {
    pub fn new(config: &serde_json::Value) -> Result<Self, String> {
        let parsed = MeshRouteDispatchConfig::from_value_normalized(config)?;
        let has_query_predicates = parsed
            .rules
            .iter()
            .any(|rule| !rule.match_.query_params.is_empty());
        Ok(Self {
            config: parsed,
            aggregate_reject_unmatched: AtomicBool::new(false),
            has_query_predicates,
        })
    }

    /// Public for tests.
    #[cfg(test)]
    pub fn rules(&self) -> &[RouteRule] {
        &self.config.rules
    }
}

/// Validate the optional `match.source_namespace` predicate. The Istio CRD
/// shape is `HTTPMatchRequest.sourceNamespace: string` (exact-only); the
/// translator projects exactly that. An empty string would silently match
/// every workload that has any encoded namespace (a `""` predicate against
/// `extract_namespace(...).is_some_and(|ns| ns == "")` would only match a
/// degenerate SPIFFE ID, but the operator clearly meant to gate by a real
/// namespace), so we reject the empty case at config-load time rather than
/// shipping a never-firing rule. Patterns are preserved verbatim — Kubernetes
/// namespace names are lowercase per RFC 1123, so any operator casing that
/// would not match the SPIFFE encoding is the operator's bug, not a silent
/// fold the gateway should hide.
fn normalize_source_namespace(
    rule_idx: usize,
    source_namespace: &mut Option<String>,
) -> Result<(), String> {
    let Some(ns) = source_namespace.as_mut() else {
        return Ok(());
    };
    if ns.is_empty() {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].match.source_namespace must not be empty"
        ));
    }
    if ns.chars().any(char::is_whitespace) {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].match.source_namespace must not contain whitespace"
        ));
    }
    Ok(())
}

/// Compile the optional `match.authority` predicate once, at config load.
/// Regex compilation is the cold-path work; the request hot path only calls
/// `AuthorityMatcher::matches`. Invalid regex (or an empty pattern after the
/// operator-provided string) is a hard error from `Plugin::new()`, per
/// CLAUDE.md's "no Ok-with-runtime-panic" plugin-config-validation rule.
///
/// Istio models `authority` as a `StringMatch`. Exact and prefix matches are
/// case-sensitive and compare the request authority as presented, including
/// an explicit port when the client sent one. Regex patterns are likewise not
/// folded — operators who want case-insensitivity should write `(?i)` in the
/// pattern.
fn compile_authority_matcher(
    rule_idx: usize,
    authority: Option<&AuthorityMatchOp>,
) -> Result<Option<AuthorityMatcher>, String> {
    let Some(op) = authority else {
        return Ok(None);
    };
    let matcher = match op {
        AuthorityMatchOp::Legacy(value) => {
            if value.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.authority must not be empty"
                ));
            }
            AuthorityMatcher::Exact(value.clone())
        }
        AuthorityMatchOp::Tagged(AuthorityStringMatch::Exact(value)) => {
            if value.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.authority.exact must not be empty"
                ));
            }
            AuthorityMatcher::Exact(value.clone())
        }
        AuthorityMatchOp::Tagged(AuthorityStringMatch::Prefix(prefix)) => {
            if prefix.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.authority.prefix must not be \
                     empty (every authority would match — likely a misconfiguration)"
                ));
            }
            AuthorityMatcher::Prefix(prefix.clone())
        }
        AuthorityMatchOp::Tagged(AuthorityStringMatch::Regex(pattern)) => {
            if pattern.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.authority.regex must not be empty"
                ));
            }
            let re = compile_full_match_regex(pattern).map_err(|e| {
                format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.authority.regex is invalid: {e}"
                )
            })?;
            AuthorityMatcher::Regex(re)
        }
    };
    Ok(Some(matcher))
}

/// Compile the optional URI predicate into its hot-path representation.
///
/// `ignore_uri_case` is a rule-level flag mirroring Istio's
/// `HTTPMatchRequest.ignoreUriCase` — it folds ASCII case for the URI
/// predicate only (not headers / methods / authority). For `Exact` and
/// `Prefix` the operand is lowercased at compile time so the hot-path
/// compare can stay byte-level (the path is matched via `eq_ignore_ascii_case`
/// / manual case-folded prefix scan — both allocation-free). Regex URI matches
/// keep their operator regex unchanged because Istio documents
/// `ignoreUriCase` as exact/prefix-only; operators who want case-insensitive
/// regex matching can write `(?i)` themselves.
///
/// Invalid regex (or an empty pattern after the operator-provided string) is
/// a hard error from `Plugin::new()`, per CLAUDE.md's
/// "no Ok-with-runtime-panic" plugin-config-validation rule. The function
/// also rejects `ignore_uri_case: true` when no URI predicate is present —
/// the flag would have no observable effect and is almost always a
/// misconfiguration.
fn compile_uri_matcher(
    rule_idx: usize,
    uri: &Option<UriMatchOp>,
    ignore_uri_case: bool,
) -> Result<Option<UriMatcher>, String> {
    let Some(uri) = uri else {
        if ignore_uri_case {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].match.ignore_uri_case=true requires a \
                 uri predicate (exact / prefix / regex); without one the flag would have no \
                 effect"
            ));
        }
        return Ok(None);
    };
    let matcher = match uri {
        UriMatchOp::Exact(value) => {
            if value.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.uri.exact must not be empty"
                ));
            }
            let value = if ignore_uri_case {
                value.to_ascii_lowercase()
            } else {
                value.clone()
            };
            UriMatcher::Exact {
                value,
                case_insensitive: ignore_uri_case,
            }
        }
        UriMatchOp::Prefix(value) => {
            if value.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.uri.prefix must not be empty \
                     (every path would match — likely a misconfiguration)"
                ));
            }
            let value = if ignore_uri_case {
                value.to_ascii_lowercase()
            } else {
                value.clone()
            };
            UriMatcher::Prefix {
                value,
                case_insensitive: ignore_uri_case,
            }
        }
        UriMatchOp::Regex(pattern) => {
            if pattern.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{rule_idx}].match.uri.regex must not be empty"
                ));
            }
            let re = compile_full_match_regex(pattern).map_err(|e| {
                format!("mesh_route_dispatch.rules[{rule_idx}].match.uri.regex is invalid: {e}")
            })?;
            UriMatcher::Regex(re)
        }
    };
    Ok(Some(matcher))
}

fn normalize_header_match_keys(
    rule_idx: usize,
    headers: &mut HashMap<String, HeaderMatchOp>,
) -> Result<(), String> {
    if headers.is_empty() {
        return Ok(());
    }

    let mut normalized = HashMap::with_capacity(headers.len());
    for (name, expected) in std::mem::take(headers) {
        let key = name.to_ascii_lowercase();
        if normalized.insert(key.clone(), expected).is_some() {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].match.headers contains duplicate \
                 header `{key}` after ASCII case normalization"
            ));
        }
    }
    *headers = normalized;
    Ok(())
}

/// Compile each per-method matcher once, at config load. Regex compilation is
/// the cold-path work; absolute anchors make the request hot path one
/// `Regex::is_match` call.
/// Invalid regex (or an empty pattern after the operator-provided string) is a
/// hard error from `Plugin::new()`, per CLAUDE.md's "no Ok-with-runtime-panic"
/// plugin-config-validation rule.
///
/// HTTP methods are conventionally uppercase ASCII (RFC 9110 §9.1). `Prefix`
/// patterns are uppercased here at compile time so the hot path can do a
/// single case-sensitive compare against the request method. Regex patterns
/// are embedded verbatim between full-input anchors because changing their
/// casing can rewrite regex syntax (for example `\d` -> `\D`). `Exact`
/// deliberately preserves the operator's casing so the existing
/// `method_match_is_case_sensitive` test continues to pass (operators who
/// write `"get"` continue to match only literal `"get"` requests).
fn compile_method_matchers(
    rule_idx: usize,
    methods: &[MethodMatchOp],
) -> Result<Vec<MethodMatcher>, String> {
    let mut compiled = Vec::with_capacity(methods.len());
    for (op_idx, op) in methods.iter().enumerate() {
        let matcher = match op {
            MethodMatchOp::Legacy(value) => MethodMatcher::Exact(value.clone()),
            MethodMatchOp::Tagged(MethodStringMatch::Exact(value)) => {
                MethodMatcher::Exact(value.clone())
            }
            MethodMatchOp::Tagged(MethodStringMatch::Prefix(prefix)) => {
                if prefix.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.methods[{op_idx}].prefix \
                         must not be empty (every method would match — likely a misconfiguration)"
                    ));
                }
                MethodMatcher::Prefix(prefix.to_ascii_uppercase())
            }
            MethodMatchOp::Tagged(MethodStringMatch::Regex(pattern)) => {
                if pattern.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.methods[{op_idx}].regex \
                         must not be empty"
                    ));
                }
                let re = compile_full_match_regex(pattern).map_err(|e| {
                    format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.methods[{op_idx}].regex \
                         is invalid: {e}"
                    )
                })?;
                MethodMatcher::Regex(re)
            }
        };
        compiled.push(matcher);
    }
    Ok(compiled)
}

/// Compile each per-header matcher once, at config load. Regex compilation is
/// the cold-path work; absolute anchors make the request hot path one
/// `Regex::is_match` call.
/// Invalid regex (or an empty pattern after the operator-provided string) is a
/// hard error from `Plugin::new()`, per CLAUDE.md's "no Ok-with-runtime-panic"
/// plugin-config-validation rule.
fn compile_header_matchers(
    rule_idx: usize,
    headers: &HashMap<String, HeaderMatchOp>,
) -> Result<HashMap<String, HeaderMatcher>, String> {
    let mut compiled = HashMap::with_capacity(headers.len());
    for (name, op) in headers {
        let matcher = match op {
            HeaderMatchOp::Legacy(value) => HeaderMatcher::Exact(value.clone()),
            HeaderMatchOp::Tagged(HeaderStringMatch::Exact(value)) => {
                HeaderMatcher::Exact(value.clone())
            }
            HeaderMatchOp::Tagged(HeaderStringMatch::Prefix(prefix)) => {
                if prefix.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.headers[`{name}`].prefix \
                         must not be empty (every value would match — likely a misconfiguration)"
                    ));
                }
                HeaderMatcher::Prefix(prefix.clone())
            }
            HeaderMatchOp::Tagged(HeaderStringMatch::Regex(pattern)) => {
                if pattern.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.headers[`{name}`].regex \
                         must not be empty"
                    ));
                }
                let re = compile_full_match_regex(pattern).map_err(|e| {
                    format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.headers[`{name}`].regex \
                         is invalid: {e}"
                    )
                })?;
                HeaderMatcher::Regex(re)
            }
        };
        compiled.insert(name.clone(), matcher);
    }
    Ok(compiled)
}

#[async_trait]
impl Plugin for MeshRouteDispatch {
    fn name(&self) -> &str {
        "mesh_route_dispatch"
    }

    fn priority(&self) -> u16 {
        priority::MESH_ROUTE_DISPATCH
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        // Istio `VirtualService.http[]` covers HTTP, gRPC, and WebSocket
        // upgrade requests. The dispatch shadow runs on all three before
        // backend selection, so the override channel applies uniformly.
        // Defaulting to HTTP-only would silently drop predicates for
        // gRPC and WS — the plugin would never run on those protocols.
        HTTP_FAMILY_PROTOCOLS
    }

    /// Query predicates are evaluated against the canonical decoding of the
    /// forwarded query, not `ctx.query_params`, so routing is already
    /// H1/H2/H3-identical. This stays keyed on query predicates so the shared
    /// map other plugins on the proxy see is decoded whenever this plugin
    /// routes on the query.
    fn requires_decoded_query_params(&self) -> bool {
        self.has_query_predicates
    }

    fn modifies_request_headers(&self) -> bool {
        // An Istio `rewrite.authority` writes the new authority into the
        // forwarded `Host` header. The dispatcher must therefore route the
        // before_proxy phase through its cloned-header path so the mutation
        // reaches the backend request. Header / method matching, route
        // overrides, fault, redirect, and path rewrite never touch the header
        // map, so this stays `false` for the common case (zero-allocation hot
        // path preserved).
        self.config
            .rules
            .iter()
            .any(|rule| rule.rewrite.as_ref().is_some_and(|r| r.authority.is_some()))
    }

    fn modifies_request_destination(&self) -> bool {
        true
    }

    fn enable_deferred_unmatched_rejection(&self) {
        self.aggregate_reject_unmatched
            .store(true, Ordering::Relaxed);
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Read the PRIVATE typed claim, not the public
        // `ai_stream_router_claimed` metadata key: mesh dispatch rewrites
        // `route_override_*`, so a later plugin deleting that observability
        // marker must not be able to move a request whose provider credential
        // is already committed onto a different backend
        // (`GHSA-xhp5-hqj8-3mwg`).
        if ctx.has_ai_stream_router_claim() {
            return PluginResult::Continue;
        }
        // Query predicates select a backend, so they are a security decision.
        // Decode the exact bytes this request will forward and fail closed if
        // that decoding is not the one the backend is guaranteed to read —
        // otherwise a route can be selected under `tenant=admin` while the
        // application executes `tenant=victim` (advisories
        // GHSA-j2j6-f9c7-hh85, GHSA-gr4p-3qw3-87r5). A dispatch config with no
        // query predicates never reaches this and is completely unaffected.
        let canonical_query = if self.has_query_predicates {
            let query = canonical_query_for_policy(ctx);
            if let Some(ambiguity) = query.first_ambiguity() {
                // Fixed-cardinality reason only — the query is
                // attacker-controlled and may carry credentials.
                warn!(
                    plugin = "mesh_route_dispatch",
                    reason = "ambiguous_query",
                    ambiguity = ambiguity.reason(),
                    "Refusing to route on a query that the backend is not guaranteed to decode identically"
                );
                return reject_ambiguous_query_result();
            }
            Some(query)
        } else {
            None
        };
        for rule in &self.config.rules {
            if rule_matches(rule, ctx, headers, canonical_query.as_ref()) {
                ctx.mesh_route_dispatch_matched = true;
                // Per-rule redirect (Istio `http[].redirect`): answer the
                // request ourselves with a 3xx + `Location`. Highest
                // precedence — a redirect short-circuits before fault and
                // before any route override, because the request never
                // reaches a backend.
                if let Some(redirect) = rule.redirect.as_ref() {
                    return build_redirect_response(ctx, headers, redirect);
                }
                // Per-rule fault action: fire BEFORE setting any route
                // override on the context. If the fault aborts, the
                // request never reaches backend dispatch so the override
                // would be wasted work — and skipping the assignment
                // keeps `ctx.route_override_*` untouched (mirroring the
                // proxy-scoped `fault_injection` plugin's behaviour where
                // an aborted request never reaches the route override
                // stage).
                if let Some(fault) = rule.fault.as_ref()
                    && let Some(result) = apply_fault_action(ctx, rule, fault).await
                {
                    return result;
                }
                if let Some(result) =
                    reject_node_waypoint_authz_destination_override(ctx, &rule.destination)
                {
                    return result;
                }
                // Route overrides are a whole-destination decision, not a
                // field-wise merge. If an earlier plugin instance matched,
                // this matching instance intentionally replaces all four
                // fields; if this instance does not match, any earlier
                // override remains in place for soft/fallback composition.
                ctx.route_override_upstream_id = rule.destination.upstream_id.clone();
                ctx.route_override_backend_host = rule.destination.backend_host.clone();
                ctx.route_override_backend_port = rule.destination.backend_port;
                ctx.route_override_resolved_tls = rule.destination.backend_tls.clone();
                // `timeout_disabled: true` (with `timeout_ms = None`) maps to
                // `Some(0)`: the proxy hot path interprets `backend_read_timeout_ms == 0`
                // as "no timeout" (see `proxy/mod.rs` and `proxy/tcp_proxy.rs` —
                // every dispatch site guards on `backend_read_timeout_ms > 0`). The
                // explicit `Some(0)` is necessary to override an inherited proxy-level
                // timeout; leaving the field `None` would fall back to that inherited
                // value, which is the opposite of the operator's intent.
                ctx.route_override_backend_read_timeout_ms =
                    if rule.timeout_ms.is_some() || rule.timeout_disabled {
                        Some(rule.timeout_ms.unwrap_or(0))
                    } else {
                        None
                    };
                ctx.route_override_retry = if rule.retry.is_some() || rule.retry_disabled {
                    Some(rule.retry.clone())
                } else {
                    None
                };
                // Per-rule header transforms: publish the pre-compiled Arc
                // so request_transformer / response_transformer can apply
                // them after their own static rules. Cloning an Arc is one
                // atomic refcount bump — cheaper than rebuilding the rule
                // list on every match.
                ctx.route_override_request_transform =
                    rule.request_transform_compiled.as_ref().map(Arc::clone);
                ctx.route_override_response_transform =
                    rule.response_transform_compiled.as_ref().map(Arc::clone);
                // Per-rule rewrite (Istio `http[].rewrite`): rebase the path /
                // authority forwarded to the backend. A non-matching later
                // instance must not stomp this, so — like the destination
                // overrides above — a matching instance sets BOTH fields
                // (clearing any prior rewrite that no longer applies).
                if let Some(rewrite) = rule.rewrite.as_ref() {
                    ctx.route_override_path = rewrite.uri.as_deref().map(|uri| {
                        rewrite_request_path(
                            ctx.path.as_str(),
                            uri,
                            rewrite.match_prefix.as_deref(),
                        )
                    });
                    // Authority rewrite rebases the forwarded `Host` header.
                    // Writing it into the live header map plus stamping
                    // `route_override_authority` (which flips
                    // `preserve_host_header` on the effective proxy in
                    // `apply_route_overrides_inner`) makes every backend
                    // dispatch path forward the rewritten authority.
                    if let Some(authority) = rewrite.authority.as_deref() {
                        headers.insert("host".to_string(), authority.to_string());
                        ctx.route_override_authority = Some(authority.to_string());
                    } else {
                        ctx.route_override_authority = None;
                        restore_original_host(ctx, headers);
                    }
                } else {
                    ctx.route_override_path = None;
                    ctx.route_override_authority = None;
                    restore_original_host(ctx, headers);
                }
                return PluginResult::Continue;
            }
        }
        if self.config.reject_unmatched {
            // Istio VirtualService.http[].match semantics: a route gated by
            // `method`/`headers`/`queryParams` must NOT serve requests that
            // miss those predicates. Without this, the proxy's default
            // backend would receive traffic the operator explicitly excluded
            // (e.g., a GET-only canary route serving POST). 404 matches
            // Envoy's behavior when no Istio route matches a request.
            if self.aggregate_reject_unmatched.load(Ordering::Relaxed) {
                ctx.mesh_route_dispatch_reject_unmatched = true;
                return PluginResult::Continue;
            }
            return reject_unmatched_result();
        }
        PluginResult::Continue
    }
}

/// Fail-closed answer for a request whose query cannot be decoded to one value
/// both this dispatcher and the backend must read. 400 rather than 404: the
/// request itself is unprocessable, and a 404 would be indistinguishable from
/// an ordinary no-route-matched outcome.
pub(crate) fn reject_ambiguous_query_result() -> PluginResult {
    PluginResult::Reject {
        status_code: 400,
        body: "ambiguous query parameters for mesh_route_dispatch predicates".to_string(),
        headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
    }
}

pub(crate) fn reject_unmatched_result() -> PluginResult {
    PluginResult::Reject {
        status_code: 404,
        body: "no route matched mesh_route_dispatch predicates".to_string(),
        headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Compute the path forwarded to the backend for an Istio `rewrite.uri`.
///
/// When `match_prefix` is set (the source `match.uri` was a `prefix`), only
/// that matched prefix is replaced by `replacement` and the remainder of the
/// request path is preserved — mirroring Istio / Envoy `prefix_rewrite`. Any
/// query string already lives in `ctx.query_params` / the dispatch
/// `query_string`, so this operates on the path component only.
///
/// When `match_prefix` is `None` (exact / regex match, or no `match.uri`)
/// the whole path is replaced.
fn rewrite_request_path(
    original_path: &str,
    replacement: &str,
    match_prefix: Option<&str>,
) -> String {
    let Some(prefix) = match_prefix else {
        return replacement.to_string();
    };
    // Strip the matched prefix and keep the remainder. The proxy `listen_path`
    // already gated the request to this prefix, so the literal `strip_prefix`
    // is the steady state. If it fails, the request can only have reached this
    // rule via a case-folded (`ignoreUriCase`) match where the byte prefix
    // differs in ASCII case — fall back to a case-insensitive length-strip so
    // the path tail is preserved (e.g. a `/Api` prefix-rewrite of `/api/users`
    // yields `/v2/users`, not a bare `/v2`). Only a genuine non-match (no
    // case-insensitive prefix either) collapses to `replacement`.
    let tail = match original_path.strip_prefix(prefix) {
        Some(tail) => tail,
        None => match original_path.get(..prefix.len()) {
            Some(head) if head.eq_ignore_ascii_case(prefix) => &original_path[prefix.len()..],
            _ => return replacement.to_string(),
        },
    };
    // Join `replacement` + `tail` without doubling or dropping a `/`.
    let mut out = String::with_capacity(replacement.len() + tail.len() + 1);
    out.push_str(replacement);
    if tail.is_empty() {
        return out;
    }
    let repl_slash = replacement.ends_with('/');
    let tail_slash = tail.starts_with('/');
    if repl_slash && tail_slash {
        out.push_str(&tail[1..]);
    } else if !repl_slash && !tail_slash {
        out.push('/');
        out.push_str(tail);
    } else {
        out.push_str(tail);
    }
    out
}

/// Re-sync the forwarded `Host` header to the original client value, undoing a
/// `Host` rewrite that a PRIOR `mesh_route_dispatch` instance on this proxy may
/// have written into the shared header map. A later rule that keeps the original
/// authority must not let a previous instance's rewritten `Host` leak into
/// `X-Forwarded-Host` / `Forwarded` (which backend dispatch builds from
/// `headers["host"]`).
///
/// The original `Host` is sourced from `ctx.headers`, NOT from the `headers`
/// parameter: the handler threads ONE shared cloned map through every instance
/// sequentially, so the `headers` param may already hold an earlier instance's
/// rewritten value, whereas `ctx.headers` is untouched on this path. This is
/// only reachable on the modify-headers (clone) path — `modifies_request_headers`
/// is `true` iff some rule carries an authority rewrite, and that path clones
/// `ctx.headers` rather than `mem::take`-ing it. When no instance rewrites, the
/// handler `mem::take`s `ctx.headers` (leaving it empty) AND no `Host` rewrite
/// ever happened, so the guard below skips the (unnecessary) restore.
fn restore_original_host(ctx: &RequestContext, headers: &mut HashMap<String, String>) {
    if ctx.headers.is_empty() {
        // No-modify path: ctx.headers was mem::take'n empty and nothing rewrote
        // Host. Touching `headers` here would wrongly drop the original Host.
        return;
    }
    match ctx.headers.get("host") {
        Some(original) => {
            headers.insert("host".to_string(), original.clone());
        }
        None => {
            // Client sent no Host but a prior instance injected one — drop it.
            headers.remove("host");
        }
    }
}

/// Build the 3xx redirect response for a matching `redirect` rule. The
/// `Location` header is assembled from the request's own scheme / authority /
/// path, with each component overridden when the redirect config sets it.
/// CR/LF were rejected at config-load time, so the resulting header value is
/// safe to emit.
fn build_redirect_response(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    redirect: &RouteRedirectConfig,
) -> PluginResult {
    let scheme = redirect.scheme.as_deref().unwrap_or_else(|| {
        ctx.metadata
            .get("ferrum.frontend_scheme")
            .map(String::as_str)
            .unwrap_or("http")
    });
    let authority = redirect.authority.as_deref().or_else(|| {
        headers
            .get("host")
            .or_else(|| headers.get(":authority"))
            .map(String::as_str)
    });
    let authority =
        authority.map(
            |authority| match resolve_redirect_authority_port(ctx, redirect, scheme) {
                Some(port) => authority_with_redirect_port(authority, port, scheme),
                None => authority.to_string(),
            },
        );
    let path = redirect
        .uri
        .as_deref()
        .map(|uri| rewrite_request_path(&ctx.path, uri, redirect.match_prefix.as_deref()))
        .unwrap_or_else(|| ctx.path.clone());

    // Istio/Envoy preserve the original request query string on redirect by
    // default (Envoy `RedirectAction.strip_query` defaults to `false`), unless
    // the redirect URI supplies its own query. Mirror that so query-dependent
    // redirects (auth callbacks, etc.) keep their parameters — without this a
    // request to `/old?token=abc` would redirect to `/new`, losing `?token=abc`.
    let query_suffix = if path.contains('?') {
        // The redirect URI carried its own query — respect it, don't duplicate.
        String::new()
    } else {
        match ctx.raw_query_string() {
            Some(q) if !q.is_empty() => format!("?{q}"),
            _ => String::new(),
        }
    };

    // Build an absolute Location when we know the authority; otherwise fall
    // back to a path-only (origin-relative) redirect, which every compliant
    // user agent resolves against the request URL.
    let location = match authority {
        Some(authority) => format!("{scheme}://{authority}{path}{query_suffix}"),
        None => format!("{path}{query_suffix}"),
    };

    let mut reject_headers = HashMap::with_capacity(2);
    reject_headers.insert("location".to_string(), location);
    reject_headers.insert("content-type".to_string(), "text/plain".to_string());
    PluginResult::Reject {
        status_code: redirect.redirect_code,
        body: String::new(),
        headers: reject_headers,
    }
}

/// Resolve the authority port for a redirect `Location`.
///
/// Precedence mirrors Istio's `HTTPRedirect` oneof: an explicit `port` wins,
/// otherwise `derive_port` selects the scheme default or the trusted request
/// port. Spoofable client headers (`X-Forwarded-Port`, `Forwarded`) are never
/// used as port provenance.
fn resolve_redirect_authority_port(
    ctx: &RequestContext,
    redirect: &RouteRedirectConfig,
    scheme: &str,
) -> Option<u16> {
    if let Some(port) = redirect.port {
        return Some(port);
    }
    match redirect.derive_port {
        Some(RedirectDerivePort::FromProtocolDefault) => Some(scheme_default_redirect_port(scheme)),
        Some(RedirectDerivePort::FromRequestPort) => trusted_request_port(ctx),
        None => None,
    }
}

/// Trusted port the client intended to reach for `FROM_REQUEST_PORT`.
///
/// Prefer the kernel/conntrack original destination when capture rewrote the
/// accept socket (sidecar/ambient), then fall back to the frontend listener
/// port (gateways and direct dials). Never consult forwarding headers.
fn trusted_request_port(ctx: &RequestContext) -> Option<u16> {
    ctx.orig_dst
        .map(|addr| addr.port())
        .or(ctx.frontend_listen_port)
}

fn scheme_default_redirect_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    }
}

fn authority_with_port(authority: &str, port: u16) -> String {
    if let Some(bracketed_end) = authority.strip_prefix('[').and_then(|rest| rest.find(']')) {
        let end = bracketed_end + 1;
        return format!("{}:{port}", &authority[..=end]);
    }
    if authority.matches(':').count() == 1
        && let Some((host, existing_port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && existing_port.parse::<u16>().is_ok()
    {
        return format!("{host}:{port}");
    }
    format!("{authority}:{port}")
}

fn authority_with_redirect_port(authority: &str, port: u16, scheme: &str) -> String {
    if redirect_port_is_scheme_default(port, scheme) {
        return authority_without_port(authority);
    }
    authority_with_port(authority, port)
}

fn redirect_port_is_scheme_default(port: u16, scheme: &str) -> bool {
    (port == 80 && scheme.eq_ignore_ascii_case("http"))
        || (port == 443 && scheme.eq_ignore_ascii_case("https"))
}

fn authority_without_port(authority: &str) -> String {
    if let Some(bracketed_end) = authority.strip_prefix('[').and_then(|rest| rest.find(']')) {
        let end = bracketed_end + 1;
        return authority[..=end].to_string();
    }
    if authority.matches(':').count() == 1
        && let Some((host, existing_port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && existing_port.parse::<u16>().is_ok()
    {
        return host.to_string();
    }
    authority.to_string()
}

/// Apply the per-rule fault action when the rule matched. Returns `Some` to
/// short-circuit the dispatch chain (delay/abort fired) or `None` to fall
/// through to the normal route-override path.
///
/// The fault decision is one paired `FaultRoller::roll_pair` call (one
/// atomic increment + two domain-separated SplitMix finalizations). When both
/// delay and abort trigger, the delay runs first, then the abort fires —
/// matching the proxy-scoped `fault_injection` plugin's ordering so the two
/// surfaces stay semantically identical.
///
/// Guards against double-faulting when a global / proxy-scoped
/// `fault_injection` plugin (priority 2940, runs before
/// `mesh_route_dispatch` at 2995) has already injected a fault on this
/// request — in that case the metadata key `fault_injected` is set and
/// this helper returns `None` so the route override still applies but no
/// second fault is stacked.
async fn apply_fault_action(
    ctx: &mut RequestContext,
    rule: &RouteRule,
    fault: &FaultActionConfig,
) -> Option<PluginResult> {
    if ctx.metadata.contains_key("fault_injected") {
        return None;
    }
    // Defensive fallback to a throwaway roller protects `RouteRule`
    // literals constructed outside `normalize_and_validate` (e.g. tests
    // that build a `RouteRule` directly). The constructor populates
    // `fault_roller` whenever `fault` is `Some`, so steady-state always
    // hits the `Some(roller)` arm without allocation.
    let outcome = match rule.fault_roller.as_ref() {
        Some(roller) => roller.roll_pair(
            fault.delay.as_ref().map(|d| d.percentage),
            fault.abort.as_ref().map(|a| a.percentage),
        ),
        None => FaultRoller::new().roll_pair(
            fault.delay.as_ref().map(|d| d.percentage),
            fault.abort.as_ref().map(|a| a.percentage),
        ),
    };

    if !outcome.delay_triggered && !outcome.abort_triggered {
        return None;
    }

    // Mark before any sleeps so a priority-overridden proxy-scoped
    // `fault_injection` instance that runs later skips its own decision.
    ctx.metadata
        .insert("fault_injected".to_string(), "true".to_string());
    ctx.metadata.insert(
        ROUTE_FAULT_INJECTED_METADATA_KEY.to_string(),
        "true".to_string(),
    );

    if outcome.delay_triggered
        && let Some(delay) = fault.delay.as_ref()
    {
        // Same retention bounds as the proxy-scoped `fault_injection` plugin:
        // shared process-wide delayed-work budget, shutdown cancellation, and
        // the frontend's peer-gone watch when one is available.
        let disposition = run_http_fault_delay(ctx, delay.duration_ms).await;
        if matches!(disposition, FaultDelayDisposition::ClientGone) {
            // Client transport is gone — do not fall through to the route
            // override and dial a backend for an unread response.
            return Some(PluginResult::Reject {
                status_code: CLIENT_GONE_STATUS,
                body: String::new(),
                headers: HashMap::new(),
            });
        }
    }

    if outcome.abort_triggered
        && let Some(abort) = fault.abort.as_ref()
    {
        let mut reject_headers = HashMap::new();
        // gRPC-only: emit `grpc-status` so the proxy's trailers-only
        // normalization in `proxy/mod.rs` can turn the rejection into a
        // proper `application/grpc` trailers-only response. Plain HTTP
        // requests on the same rule never receive a stray header.
        if let Some(grpc_status) = abort.grpc_status
            && is_native_grpc_request(ctx)
        {
            reject_headers.insert("grpc-status".to_string(), grpc_status.to_string());
        }
        return Some(PluginResult::Reject {
            status_code: abort.status_code,
            body: abort.body.clone().unwrap_or_default(),
            headers: reject_headers,
        });
    }

    // Delay fired but abort did not (or abort wasn't configured) — fall
    // through to normal route-override processing so the request still
    // dispatches.
    None
}

fn rule_matches(
    rule: &RouteRule,
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    canonical_query: Option<&CanonicalQuery>,
) -> bool {
    let m = &rule.match_;
    if m.is_empty() {
        // Empty match means "match all". `normalize_and_validate` accepts
        // this only when the rule carries route-local actions — that narrow
        // shape comes from the K8s VirtualService translator's catch-all
        // rule for URI-only matches. `compile_transform_field` returns
        // `None` for empty input, so an `Arc` is only present when there is
        // at least one rule to apply.
        return rule.request_transform_compiled.is_some()
            || rule.response_transform_compiled.is_some()
            || rule.fault.is_some()
            || rule.rewrite.is_some()
            || rule.redirect.is_some();
    }
    // URI predicate (when set): evaluate first because it cheaply rejects
    // requests that the broader (case-insensitive) `listen_path` lets
    // through. The compiled matcher already carries the case-folding
    // contract, so this stays allocation-free.
    if let Some(uri_matcher) = rule.uri_compiled.as_ref()
        && !uri_matcher.matches(ctx.path.as_str())
    {
        return false;
    }
    // Method match: any-of across the compiled matchers. Matchers are
    // pre-compiled (regex included) at config load — the hot path is one
    // pass over the matcher slice with a case-sensitive compare per entry.
    if !rule.methods_compiled.is_empty()
        && !rule
            .methods_compiled
            .iter()
            .any(|matcher| matcher.matches(ctx.method.as_str()))
    {
        return false;
    }
    // `before_proxy` receives the in-flight header map; `ctx.headers`
    // may have been moved out by the dispatcher. Config header names are
    // normalized at construction time and matchers are pre-compiled
    // (regex included) — the hot path is one HashMap lookup plus the
    // matcher op per configured header.
    for (name, matcher) in &rule.headers_compiled {
        match headers.get(name.as_str()) {
            Some(actual) if matcher.matches(actual) => {}
            _ => return false,
        }
    }
    if !m.query_params.is_empty() {
        // The caller supplies the canonical query whenever any rule declares a
        // query predicate, and has already failed the request closed if that
        // decoding was ambiguous. An absent view here means no rule declared a
        // predicate, so a rule that does declare one cannot match.
        let Some(query) = canonical_query else {
            return false;
        };
        for (name, expected) in &m.query_params {
            match query.get(name.as_str()) {
                Some(actual) if actual == expected => {}
                _ => return false,
            }
        }
    }
    if let Some(expected_ns) = m.source_namespace.as_deref() {
        // Source workload namespace is encoded in the peer's SPIFFE ID via
        // the Istio convention `spiffe://<td>/ns/<ns>/sa/<sa>`. The
        // identity is populated by the `spiffe_identity` plugin during
        // `on_request_received` (priority 940), well before this plugin
        // runs in `before_proxy` (priority 2995), so a populated
        // `ctx.peer_spiffe_id` is the steady state for mesh requests.
        //
        // Outside mesh mode — or when the source workload presents no
        // SPIFFE-bearing certificate — there is no identity to match
        // against. Treat that as "no match" so the predicate fails
        // closed under `reject_unmatched: true` rather than silently
        // matching every request that happens to lack a peer identity.
        // `SpiffeId::namespace` reuses the same path-segment walk that
        // `mesh_authz` uses for `namespace_pattern` matching, so the
        // two surfaces never disagree on what `ns/<value>` means.
        let Some(peer_ns) = ctx
            .peer_spiffe_id
            .as_ref()
            .and_then(crate::identity::SpiffeId::namespace)
        else {
            return false;
        };
        if peer_ns != expected_ns {
            return false;
        }
    }
    if let Some(matcher) = rule.authority_compiled.as_ref() {
        // Read the request's `Host` from the in-flight header map. The routing
        // layer in `proxy/mod.rs` synthesizes `Host` from HTTP/2/3 `:authority`
        // before `before_proxy` runs, so the `host` lookup covers the steady
        // state. Keep `:authority` as a defensive fallback for direct tests or
        // future call sites that invoke the plugin before that synthesis.
        //
        // Do not route-normalize here. Istio `authority` is a `StringMatch`;
        // exact/prefix comparisons are case-sensitive and include an explicit
        // port when the client sent one.
        let Some(authority) = headers.get("host").or_else(|| headers.get(":authority")) else {
            return false;
        };
        if !matcher.matches(authority) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with(method: &str, path: &str) -> RequestContext {
        RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            path.to_string(),
        )
    }

    #[test]
    fn rejects_empty_rules() {
        let err = MeshRouteDispatch::new(&json!({"rules": []})).unwrap_err();
        assert!(err.contains("cannot be empty"), "got: {err}");
    }

    #[test]
    fn rejects_rule_with_empty_match_criteria() {
        // A rule with `match: {}` would never fire (defense-in-depth in
        // `rule_matches`) but accepting it would let operator misconfig
        // silently disable header/method routing without an error.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {}, "destination": {"upstream_id": "x"}}]
        }))
        .unwrap_err();
        assert!(err.contains("match requires at least one"), "got: {err}");
    }

    #[test]
    fn rejects_rule_with_missing_match_field() {
        // Omitting `match` entirely is also caught (defaults to empty
        // MatchCriteria via `#[serde(default)]`).
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"destination": {"upstream_id": "x"}}]
        }))
        .unwrap_err();
        assert!(err.contains("match requires at least one"), "got: {err}");
    }

    #[test]
    fn normalizes_header_match_keys_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();

        assert!(
            plugin.rules()[0].match_.headers.contains_key("x-canary"),
            "configured header keys should be normalized once, not per request"
        );
    }

    #[test]
    fn rejects_duplicate_header_matches_after_normalization() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2", "x-canary": "v3"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap_err();

        assert!(err.contains("duplicate header"), "got: {err}");
    }

    #[test]
    fn rejects_timeout_ms_with_timeout_disabled() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "timeout_ms": 250,
                "timeout_disabled": true
            }]
        }))
        .unwrap_err();

        assert!(
            err.contains("cannot set both timeout_ms and timeout_disabled"),
            "got: {err}"
        );
    }

    #[test]
    fn declares_http_family_protocols() {
        // Istio VirtualService.http[] covers HTTP/gRPC/WebSocket. The
        // plugin must apply to all three or it silently drops predicates
        // for non-plain-HTTP requests.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        let protocols = plugin.supported_protocols();
        assert!(protocols.contains(&ProxyProtocol::Http));
        assert!(protocols.contains(&ProxyProtocol::Grpc));
        assert!(protocols.contains(&ProxyProtocol::WebSocket));
    }

    #[test]
    fn rejects_destination_with_no_override_fields() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "destination": {}}]
        }))
        .unwrap_err();
        assert!(err.contains("upstream_id"), "got: {err}");
        assert!(err.contains("direct backend"), "got: {err}");
        assert!(err.contains("backend_tls"), "got: {err}");
    }

    #[test]
    fn rejects_destination_with_zero_port() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "destination": {"backend_port": 0}}]
        }))
        .unwrap_err();
        assert!(err.contains("non-zero"), "got: {err}");
    }

    #[test]
    fn rejects_destination_with_empty_backend_host() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "", "backend_port": 443}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("backend_host must not be empty"), "got: {err}");
    }

    #[test]
    fn normalizes_direct_backend_host_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "  Canary.SVC.Cluster.Local  ", "backend_port": 443}
            }]
        }))
        .unwrap();

        assert_eq!(
            plugin.rules()[0].destination.backend_host.as_deref(),
            Some("canary.svc.cluster.local")
        );
    }

    #[test]
    fn rejects_backend_host_without_backend_port() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "canary.svc"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn rejects_backend_port_without_backend_host() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_port": 9090}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn rejects_upstream_id_combined_with_direct_backend() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "upstream_id": "canary",
                    "backend_host": "canary.svc",
                    "backend_port": 9090
                }
            }]
        }))
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "got: {err}");
    }

    #[test]
    fn rejects_backend_tls_client_cert_without_key() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {"client_cert_path": "/certs/client.pem"}
                }
            }]
        }))
        .unwrap_err();

        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn normalizes_backend_tls_identity_fields_and_recomputes_san_digest() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {
                        "sni": "Reviews.Mesh.Internal",
                        "san_allow_list": [
                            "Ratings.Mesh.Internal",
                            "spiffe://cluster.local/ns/default/sa/reviews",
                            "10.0.0.8"
                        ]
                    }
                }
            }]
        }))
        .unwrap();

        let tls = plugin.rules()[0]
            .destination
            .backend_tls
            .as_ref()
            .expect("backend_tls override");
        assert_eq!(tls.sni.as_deref(), Some("reviews.mesh.internal"));
        assert_eq!(
            tls.san_allow_list,
            vec![
                "ratings.mesh.internal".to_string(),
                "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                "10.0.0.8".to_string(),
            ]
        );
        assert_eq!(
            tls.san_allow_list_key_digest,
            BackendTlsConfig::compute_san_digest(&tls.san_allow_list),
            "route-local backend_tls must be ready for pool-key emission"
        );
    }

    #[test]
    fn rejects_backend_tls_invalid_sni_and_san_allow_list() {
        let sni_err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {"sni": "10.0.0.8"}
                }
            }]
        }))
        .unwrap_err();
        assert!(sni_err.contains("backend_tls.sni"), "got: {sni_err}");

        let san_err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {"san_allow_list": ["https://not-spiffe.example"]}
                }
            }]
        }))
        .unwrap_err();
        assert!(
            san_err.contains("backend_tls.san_allow_list[0]"),
            "got: {san_err}"
        );
    }

    #[test]
    fn rejects_backend_tls_without_direct_backend() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_tls": {"verify_server_cert": false}
                }
            }]
        }))
        .unwrap_err();
        assert!(err.contains("requires"), "got: {err}");
        assert!(err.contains("backend_host"), "got: {err}");
        assert!(err.contains("backend_port"), "got: {err}");
    }

    #[test]
    fn rejects_upstream_id_combined_with_backend_tls() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "upstream_id": "canary",
                    "backend_tls": {"verify_server_cert": false}
                }
            }]
        }))
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "got: {err}");
    }

    #[tokio::test]
    async fn method_match_routes_to_override_upstream() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn method_match_can_clear_backend_read_timeout() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "timeout_disabled": true
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
        assert_eq!(ctx.route_override_backend_read_timeout_ms, Some(0));
    }

    #[tokio::test]
    async fn method_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn method_match_is_case_sensitive() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["get"]},
                "destination": {"upstream_id": "lowercase"}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());

        let mut ctx = ctx_with("get", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("lowercase"));
    }

    #[tokio::test]
    async fn method_regex_preserves_escape_semantics() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^POST\\d$"}]},
                "destination": {"upstream_id": "digits-only"}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("POST1", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            ctx.route_override_upstream_id.as_deref(),
            Some("digits-only")
        );

        let mut ctx = ctx_with("POSTA", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn header_match_routes_to_canary() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2"}},
                "destination": {"backend_host": "canary.svc", "backend_port": 9090}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("canary.svc")
        );
        assert_eq!(ctx.route_override_backend_port, Some(9090));
    }

    #[tokio::test]
    async fn header_absence_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-canary": "v2"}},
                "destination": {"backend_host": "canary.svc", "backend_port": 9090}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_backend_host.is_none());
    }

    #[tokio::test]
    async fn header_value_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-canary": "v2"}},
                "destination": {"backend_host": "canary.svc", "backend_port": 9090}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v1".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_backend_host.is_none());
    }

    #[tokio::test]
    async fn method_and_header_must_both_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["POST"], "headers": {"x-canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        // Method matches, header missing
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Header matches, method wrong
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Both match
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [
                {"match": {"methods": ["GET"]}, "destination": {"upstream_id": "first"}},
                {"match": {"methods": ["GET"]}, "destination": {"upstream_id": "second"}}
            ]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("first"));
    }

    #[tokio::test]
    async fn later_plugin_match_replaces_prior_route_overrides() {
        let upstream_plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "first"}
            }]
        }))
        .unwrap();
        let direct_backend_plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "direct.svc", "backend_port": 8081}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = upstream_plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("first"));

        let _ = direct_backend_plugin
            .before_proxy(&mut ctx, &mut headers)
            .await;
        assert!(ctx.route_override_upstream_id.is_none());
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("direct.svc")
        );
        assert_eq!(ctx.route_override_backend_port, Some(8081));
    }

    #[tokio::test]
    async fn query_param_match_routes() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"query_params": {"variant": "beta"}},
                "destination": {"upstream_id": "beta-upstream"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        // Predicates read the forwarded query, not the lossy shared map.
        ctx.set_raw_query_string("variant=beta".to_string());
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            ctx.route_override_upstream_id.as_deref(),
            Some("beta-upstream")
        );
    }

    #[test]
    fn requires_decoded_query_params_for_query_rules_only() {
        let method_only = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        assert!(
            !method_only.requires_decoded_query_params(),
            "method/header-only routing must not change HTTP/3 query-param materialization"
        );

        let query_rule = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"query_params": {"variant": "beta"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        assert!(query_rule.requires_decoded_query_params());
    }

    #[tokio::test]
    async fn reject_unmatched_returns_404_when_no_rule_matches() {
        // VirtualService semantics: a `match: method=GET` rule must NOT
        // forward POST traffic to the proxy's default backend. With
        // `reject_unmatched: true`, the plugin short-circuits with 404.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }],
            "reject_unmatched": true,
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(status_code, 404);
                assert!(body.contains("no route matched"), "got: {body}");
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some("text/plain")
                );
            }
            other => panic!("expected Reject 404, got {other:?}"),
        }
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn reject_unmatched_continues_when_rule_matches() {
        // `reject_unmatched: true` must NOT reject matching requests —
        // it only fires when every rule misses.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }],
            "reject_unmatched": true,
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn reject_unmatched_default_false_preserves_fall_through() {
        // Operators configuring the plugin directly (without VirtualService
        // translation) keep today's soft-override behavior unless they
        // explicitly opt in. This protects non-mesh consumers from a
        // breaking semantic change.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn rule_with_request_transform_publishes_arc_on_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"},
                    {"operation": "add",    "target": "header", "key": "X-Trace", "value": "y"},
                    {"operation": "remove", "target": "header", "key": "X-Debug"},
                ]
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        let arc = ctx
            .route_override_request_transform
            .expect("request_transform must be published on match");
        assert_eq!(arc.len(), 3);
        assert!(ctx.route_override_response_transform.is_none());
    }

    #[tokio::test]
    async fn rule_with_response_transform_publishes_arc_on_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "response_transform": [
                    {"operation": "update", "target": "header", "key": "X-Backend", "value": "v1"},
                ]
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_request_transform.is_none());
        let arc = ctx
            .route_override_response_transform
            .expect("response_transform must be published on match");
        assert_eq!(arc.len(), 1);
    }

    #[tokio::test]
    async fn non_matching_rule_does_not_publish_transforms() {
        // A rule with transforms that does not match must not leak its Arcs
        // onto the context (would be applied to the wrong route).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"},
                ]
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_request_transform.is_none());
    }

    #[test]
    fn rejects_invalid_request_transform_rule_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Inject",
                     "value": "good\r\nX-Injected: 1"}
                ]
            }]
        }))
        .unwrap_err();
        assert!(err.contains("request_transform"), "got: {err}");
        assert!(err.contains("CR or LF"), "got: {err}");
    }

    #[tokio::test]
    async fn empty_match_with_transforms_matches_all() {
        // Translator-generated catch-all for URI-only VirtualService routes:
        // empty match + transforms must publish the transform Arc on every
        // request (the proxy's listen_path filter already gates traffic).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "destination": {"backend_host": "v1.svc", "backend_port": 8080},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"}
                ]
            }]
        }))
        .unwrap();

        for method in ["GET", "POST", "DELETE"] {
            let mut ctx = ctx_with(method, "/v1/anything");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert!(
                ctx.route_override_request_transform.is_some(),
                "empty-match catch-all must fire for {method}"
            );
        }
    }

    #[test]
    fn rejects_empty_match_without_route_actions() {
        // The empty-match exception is narrow: only allowed when route-local
        // actions are present. A rule with empty match AND no route actions is
        // still rejected (it would shadow later rules otherwise).
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {}, "destination": {"upstream_id": "x"}}]
        }))
        .unwrap_err();
        assert!(err.contains("match requires at least one"), "got: {err}");
    }

    #[tokio::test]
    async fn empty_match_with_fault_matches_all() {
        // Translator-generated catch-all for URI-only VirtualService routes:
        // the proxy's listen_path filter gates traffic, while the dispatch
        // rule carries the per-route fault action.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "destination": {"backend_host": "v1.svc", "backend_port": 8080},
                "fault": {"abort": {"status_code": 503, "percentage": 100.0}}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/v1/anything");
        let mut headers = HashMap::new();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 503),
            other => panic!("expected 503 reject, got: {other:?}"),
        }
        assert_eq!(
            ctx.metadata.get("fault_injected").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn rejects_request_transform_with_unknown_operation_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "rename", "target": "header", "key": "X", "value": "Y"}
                ]
            }]
        }))
        .unwrap_err();
        assert!(err.contains("request_transform"), "got: {err}");
        assert!(err.contains("add/update/remove"), "got: {err}");
    }

    // ── MethodMatchOp (exact / prefix / regex) ────────────────────────────
    //
    // T1-B.2: VirtualService translation can emit prefix/regex method
    // matchers; the plugin compiles regex at config-load time and the hot
    // path stays one pass over the compiled matcher slice per request.
    // Methods are conventionally uppercase ASCII (RFC 9110 §9.1) — prefix
    // and regex inputs are uppercased at compile time so the matcher does a
    // single case-sensitive compare against the request method without
    // per-request casing work.

    #[test]
    fn accepts_legacy_bare_string_method_entry_as_exact() {
        // Back-compat: a bare string is the existing wire shape — must keep
        // round-tripping byte-identical and evaluate as `Exact`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let compiled = &plugin.rules()[0].methods_compiled;
        assert_eq!(compiled.len(), 1);
        match &compiled[0] {
            MethodMatcher::Exact(v) => assert_eq!(v, "GET"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_tagged_exact_method_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"exact": "GET"}]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Exact(v) => assert_eq!(v, "GET"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_prefix_method_match_at_load_and_uppercases_pattern() {
        // The translator preserves operator casing on the wire, but the
        // hot-path compare is case-sensitive: uppercase the prefix at
        // compile time so `"po"` matches `"POST"` / `"PUT"` like the
        // operator intended without per-request casing.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": "po"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Prefix(p) => assert_eq!(p, "PO"),
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn regex_method_match_compiles_verbatim_at_load() {
        // PR #1026 reverted the regex-uppercasing-at-load behaviour because it
        // rewrites escape sequences (`\d` -> `\D`, etc.). Regex patterns are
        // now compiled verbatim. `Prefix` continues to uppercase so the hot
        // path stays case-sensitive against uppercase methods.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(POST|PUT|PATCH)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Regex(re) => {
                assert!(re.is_match("POST"));
                assert!(re.is_match("PUT"));
                assert!(re.is_match("PATCH"));
                assert!(!re.is_match("GET"));
                assert!(
                    !re.is_match("post"),
                    "regex pattern keeps operator casing — hot path is case-sensitive"
                );
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn lowercase_regex_method_match_does_not_match_uppercase_method() {
        // Counter-test to the above: operators who write a lowercase regex
        // must understand it won't match the (uppercase) request methods.
        // We don't reject such patterns at load — the operator may want to
        // route on a non-standard lowercase method — but we document the
        // expectation here so a future change that re-introduces silent
        // uppercasing is caught by CI.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(post|put|patch)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Regex(re) => {
                assert!(!re.is_match("POST"));
                assert!(re.is_match("post"));
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_regex_method_match_at_load() {
        // CLAUDE.md "Plugin Config Validation": invalid regex MUST be a hard
        // error from `Plugin::new()`, never `Ok` with a runtime panic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "["}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("invalid"), "got: {err}");
        assert!(err.contains("methods[0]"), "got: {err}");
        assert!(err.contains("regex"), "got: {err}");
    }

    #[test]
    fn rejects_empty_regex_method_match_at_load() {
        // An empty regex (`""`) matches every method, which is almost always
        // a misconfiguration. Fail loud instead of silently widening traffic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": ""}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("regex"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_prefix_method_match_at_load() {
        // An empty prefix matches every method, see regex rationale above.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": ""}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("prefix"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_method_match_operator_at_load() {
        // `deny_unknown_fields` on `MethodStringMatch` catches typos like
        // `{"prefiks": "..."}` at load time so we never compile and ship a
        // rule that silently never fires.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefiks": "PO"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("mesh_route_dispatch") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn regex_method_match_routes_when_method_matches() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(POST|PUT|PATCH)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        for method in ["POST", "PUT", "PATCH"] {
            let mut ctx = ctx_with(method, "/api");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("writes"),
                "regex must match {method}"
            );
        }
    }

    #[tokio::test]
    async fn regex_method_match_falls_through_when_method_does_not_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(POST|PUT|PATCH)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn prefix_method_match_routes_when_method_starts_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": "PO"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        for method in ["POST", "POLL"] {
            let mut ctx = ctx_with(method, "/api");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("writes"),
                "prefix must match {method}"
            );
        }
    }

    #[tokio::test]
    async fn prefix_method_match_falls_through_when_method_does_not_start_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": "PO"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn mixed_exact_prefix_regex_methods_are_anyed() {
        // Any-of semantics across mixed matcher kinds — a single method match
        // is enough for the rule to fire. Mirrors Istio's `method` predicate
        // (Istio expresses any-of via sibling `match[]` entries; mesh_route
        // _dispatch collapses sibling entries onto one rule when they share
        // the URI scope, so we accept any-of in one rule too).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "methods": [
                        "GET",
                        {"prefix": "PO"},
                        {"regex": "^DELE.*$"}
                    ]
                },
                "destination": {"upstream_id": "any-match"}
            }]
        }))
        .unwrap();

        for method in ["GET", "POST", "POLL", "DELETE"] {
            let mut ctx = ctx_with(method, "/api");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("any-match"),
                "{method} should match one of the matchers"
            );
        }

        // None match → no override.
        let mut ctx = ctx_with("OPTIONS", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[test]
    fn legacy_and_tagged_method_form_round_trip_through_serde() {
        // The schema must keep the two wire shapes byte-stable so existing
        // configs deserialize unchanged.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "methods": [
                        "GET",
                        {"regex": "^(POST|PUT)$"}
                    ]
                },
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();

        // The compiled hot-path representation reflects each form correctly.
        let compiled = &plugin.rules()[0].methods_compiled;
        assert_eq!(compiled.len(), 2);
        match &compiled[0] {
            MethodMatcher::Exact(v) => assert_eq!(v, "GET"),
            other => panic!("expected Exact for legacy form, got {other:?}"),
        }
        match &compiled[1] {
            MethodMatcher::Regex(_) => {}
            other => panic!("expected Regex for tagged form, got {other:?}"),
        }

        // The serialized JSON for the raw `MatchCriteria.methods` list keeps
        // the bare string vs object distinction the operator wrote.
        let raw = serde_json::to_value(&plugin.rules()[0].match_.methods).unwrap();
        let arr = raw.as_array().expect("methods array");
        assert_eq!(arr.len(), 2);
        assert!(arr[0].is_string());
        assert_eq!(arr[0].as_str(), Some("GET"));
        assert!(arr[1].is_object());
        assert_eq!(arr[1]["regex"].as_str(), Some("^(POST|PUT)$"));
    }

    // ── HeaderMatchOp (exact / prefix / regex) ────────────────────────────
    //
    // T1-B.1: VirtualService translation can emit prefix/regex header
    // matchers; the plugin compiles regex at config-load time and the hot
    // path stays one HashMap lookup plus the matcher op per header.

    #[test]
    fn accepts_legacy_bare_string_header_value_as_exact() {
        // Back-compat: a bare string is the existing wire shape — must keep
        // round-tripping byte-identical and evaluate as `Exact`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let compiled = &plugin.rules()[0].headers_compiled;
        match compiled.get("x-canary") {
            Some(HeaderMatcher::Exact(v)) => assert_eq!(v, "v2"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_tagged_exact_header_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": {"exact": "v2"}}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0].headers_compiled.get("x-canary") {
            Some(HeaderMatcher::Exact(v)) => assert_eq!(v, "v2"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_prefix_header_match_at_load_and_compiles_no_regex() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tenant": {"prefix": "admin-"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0].headers_compiled.get("x-tenant") {
            Some(HeaderMatcher::Prefix(p)) => assert_eq!(p, "admin-"),
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn accepts_regex_header_match_at_load_and_compiles_once() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"regex": "^(gold|platinum)$"}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0].headers_compiled.get("x-tier") {
            Some(HeaderMatcher::Regex(re)) => {
                assert!(re.is_match("gold"));
                assert!(re.is_match("platinum"));
                assert!(!re.is_match("silver"));
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_regex_header_match_at_load() {
        // CLAUDE.md "Plugin Config Validation": invalid regex MUST be a hard
        // error from `Plugin::new()`, never `Ok` with a runtime panic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"regex": "["}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("invalid"), "got: {err}");
        assert!(err.contains("x-tier"), "got: {err}");
        assert!(err.contains("regex"), "got: {err}");
    }

    #[test]
    fn rejects_empty_regex_header_match_at_load() {
        // An empty regex (`""`) matches every value, which is almost always
        // a misconfiguration. Fail loud instead of silently widening traffic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"regex": ""}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("regex"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_prefix_header_match_at_load() {
        // An empty prefix matches every value, see regex rationale above.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"prefix": ""}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("prefix"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_header_match_operator_at_load() {
        // `deny_unknown_fields` on `HeaderStringMatch` catches typos like
        // `{"prefiks": "..."}` at load time so we never compile and ship a
        // rule that silently never fires.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"prefiks": "admin-"}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("mesh_route_dispatch") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn regex_header_match_routes_when_value_matches() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tier": {"regex": "^admin-.*$"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tier".to_string(), "admin-east".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn regex_header_match_falls_through_when_value_does_not_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tier": {"regex": "^admin-.*$"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tier".to_string(), "user-east".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn regex_header_match_does_not_allow_substring_overmatch() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"authorization": {"regex": "Bearer .+"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([(
            "authorization".to_string(),
            "Basic x, Bearer token".to_string(),
        )]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn prefix_header_match_routes_when_value_starts_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tenant": {"prefix": "admin-"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tenant".to_string(), "admin-acme".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn prefix_header_match_falls_through_when_value_does_not_start_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tenant": {"prefix": "admin-"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tenant".to_string(), "user-acme".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn mixed_exact_prefix_regex_headers_are_anded() {
        // All-of semantics across mixed matcher kinds: each header must
        // independently match. A miss on any one means the rule does not
        // fire — matches Istio's `headers` map semantics.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "headers": {
                        "x-canary": {"exact": "v2"},
                        "x-tenant": {"prefix": "admin-"},
                        "x-tier": {"regex": "^(gold|platinum)$"}
                    }
                },
                "destination": {"upstream_id": "all-match"}
            }]
        }))
        .unwrap();

        // All match → route override applies.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([
            ("x-canary".to_string(), "v2".to_string()),
            ("x-tenant".to_string(), "admin-acme".to_string()),
            ("x-tier".to_string(), "gold".to_string()),
        ]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("all-match"));

        // Regex miss → fall-through.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([
            ("x-canary".to_string(), "v2".to_string()),
            ("x-tenant".to_string(), "admin-acme".to_string()),
            ("x-tier".to_string(), "silver".to_string()),
        ]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());

        // Prefix miss → fall-through.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([
            ("x-canary".to_string(), "v2".to_string()),
            ("x-tenant".to_string(), "user-acme".to_string()),
            ("x-tier".to_string(), "gold".to_string()),
        ]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[test]
    fn legacy_and_tagged_header_form_round_trip_through_serde() {
        // The schema must keep the two wire shapes byte-stable so existing
        // configs deserialize unchanged.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "headers": {
                        "x-canary": "v2",
                        "x-tier": {"regex": "^(gold|platinum)$"}
                    }
                },
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();

        // The compiled hot-path representation reflects each form correctly.
        let compiled = &plugin.rules()[0].headers_compiled;
        match compiled.get("x-canary") {
            Some(HeaderMatcher::Exact(v)) => assert_eq!(v, "v2"),
            other => panic!("expected Exact for legacy form, got {other:?}"),
        }
        match compiled.get("x-tier") {
            Some(HeaderMatcher::Regex(_)) => {}
            other => panic!("expected Regex for tagged form, got {other:?}"),
        }

        // The serialized JSON for the raw `MatchCriteria.headers` map keeps
        // the bare string vs object distinction the operator wrote.
        let raw = serde_json::to_value(&plugin.rules()[0].match_.headers).unwrap();
        assert!(raw["x-canary"].is_string());
        assert!(raw["x-tier"].is_object());
        assert_eq!(raw["x-tier"]["regex"].as_str(), Some("^(gold|platinum)$"));
    }

    // -- source_namespace matcher (T1-B.4) ----------------------------------
    //
    // VirtualService `match[].sourceNamespace` is now a first-class
    // mesh_route_dispatch predicate. The hot path reads `ctx.peer_spiffe_id`
    // (populated by the `spiffe_identity` plugin at priority 940, before
    // mesh_route_dispatch runs at 2995) and extracts the namespace via
    // `SpiffeId::namespace` — the same path-segment walk that `mesh_authz`
    // uses for `namespace_pattern`, so the two surfaces cannot disagree.
    // Istio models `sourceNamespace` as exact-only (no prefix/regex arms in
    // the CRD), so the schema is `Option<String>` rather than a tagged enum.
    use crate::identity::SpiffeId;

    fn ctx_with_peer(method: &str, path: &str, spiffe_id: Option<&str>) -> RequestContext {
        let mut ctx = ctx_with(method, path);
        ctx.peer_spiffe_id = spiffe_id.map(|id| SpiffeId::new(id).expect("valid spiffe id"));
        ctx
    }

    #[test]
    fn accepts_source_namespace_only_match_at_load() {
        // A rule whose only predicate is `source_namespace` must load —
        // `MatchCriteria::is_empty()` returns false because the field is set.
        // Without that update, the rule would hit the "empty match requires
        // transforms" error and silently never compile.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        assert_eq!(
            plugin.rules()[0].match_.source_namespace.as_deref(),
            Some("prod")
        );
    }

    #[test]
    fn rejects_empty_source_namespace_at_load() {
        // An empty string would only match a degenerate SPIFFE ID with an
        // `ns/` segment that has no value (which the SPIFFE parser already
        // rejects). Operators clearly meant a real namespace; treat empty as
        // a config error rather than shipping a never-firing rule.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": ""},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("source_namespace"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_source_namespace_containing_whitespace_at_load() {
        // K8s namespace names are RFC 1123 lowercase identifiers — no
        // whitespace is ever legitimate, and a stray space would silently
        // never match. Reject at load so the operator sees the typo.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod env"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("source_namespace"), "got: {err}");
        assert!(err.contains("whitespace"), "got: {err}");
    }

    #[tokio::test]
    async fn source_namespace_match_routes_request() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with_peer(
            "GET",
            "/api",
            Some("spiffe://cluster.local/ns/prod/sa/billing"),
        );
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[tokio::test]
    async fn source_namespace_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with_peer(
            "GET",
            "/api",
            Some("spiffe://cluster.local/ns/staging/sa/billing"),
        );
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn source_namespace_match_is_case_sensitive() {
        // Kubernetes namespace names are RFC 1123 lowercase, and SPIFFE IDs
        // encode them literally. An uppercase predicate against a lowercase
        // SPIFFE namespace must NOT match — folding case would silently
        // accept operator typos.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "PROD"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with_peer(
            "GET",
            "/api",
            Some("spiffe://cluster.local/ns/prod/sa/billing"),
        );
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn missing_peer_identity_does_not_match_source_namespace() {
        // No peer SPIFFE ID → no source namespace → match returns false.
        // The predicate fails closed under `reject_unmatched: true` rather
        // than silently matching every request that happens to lack a peer
        // identity. Non-mesh requests and clients that present non-SPIFFE
        // certs both land here.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with_peer("GET", "/api", None);
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn peer_identity_without_ns_segment_does_not_match_source_namespace() {
        // A SPIFFE ID with no `ns/<value>` segment (operator using a
        // non-Istio identity layout) cannot resolve a workload namespace.
        // `SpiffeId::namespace()` returns `None`; the predicate must treat
        // that as "no match" rather than panicking or matching accidentally.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with_peer("GET", "/api", Some("spiffe://cluster.local/sa/billing"));
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn source_namespace_and_method_must_both_match() {
        // All-of semantics across distinct predicate kinds — source_namespace
        // is ANDed with method/headers/queryParams. Mirrors Istio's
        // `HTTPMatchRequest` semantics where every field is conjunctive.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "methods": ["POST"],
                    "source_namespace": "prod"
                },
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        // Right method, wrong namespace.
        let mut ctx = ctx_with_peer(
            "POST",
            "/api",
            Some("spiffe://cluster.local/ns/staging/sa/billing"),
        );
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Right namespace, wrong method.
        let mut ctx = ctx_with_peer(
            "GET",
            "/api",
            Some("spiffe://cluster.local/ns/prod/sa/billing"),
        );
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Both match.
        let mut ctx = ctx_with_peer(
            "POST",
            "/api",
            Some("spiffe://cluster.local/ns/prod/sa/billing"),
        );
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[tokio::test]
    async fn reject_unmatched_returns_404_when_source_namespace_does_not_match() {
        // End-to-end: under `reject_unmatched: true` (the VS translator
        // default), a source_namespace-only rule that does not match the
        // peer identity must 404 instead of falling through to the default
        // backend. This is the fail-closed VirtualService semantic.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"source_namespace": "prod"},
                "destination": {"upstream_id": "internal"}
            }],
            "reject_unmatched": true
        }))
        .unwrap();
        let mut ctx = ctx_with_peer(
            "GET",
            "/api",
            Some("spiffe://cluster.local/ns/staging/sa/billing"),
        );
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 404),
            other => panic!("expected 404 reject, got: {other:?}"),
        }
    }

    #[test]
    fn source_namespace_round_trips_through_serde() {
        // The field uses `#[serde(default, skip_serializing_if = "Option::is_none")]`,
        // so configs without `source_namespace` round-trip without the key
        // appearing in their serialized form. Configs with it round-trip
        // byte-stable as a plain string.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [
                {
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "no-ns"}
                },
                {
                    "match": {"source_namespace": "prod"},
                    "destination": {"upstream_id": "with-ns"}
                }
            ]
        }))
        .unwrap();
        let rendered_no_ns =
            serde_json::to_value(&plugin.rules()[0].match_).expect("serialize match");
        assert!(
            rendered_no_ns.get("source_namespace").is_none(),
            "missing source_namespace must round-trip absent, got: {rendered_no_ns}"
        );
        let rendered_with_ns =
            serde_json::to_value(&plugin.rules()[1].match_).expect("serialize match");
        assert_eq!(
            rendered_with_ns["source_namespace"].as_str(),
            Some("prod"),
            "string source_namespace must round-trip verbatim, got: {rendered_with_ns}"
        );
    }

    // -- AuthorityMatchOp (exact / prefix / regex) -----------------------------
    //
    // T1-B.3: VirtualService translation can emit an `authority` predicate per
    // rule; the plugin compiles the regex at config-load time and the hot path
    // resolves the request's raw `Host`/`:authority` once and runs the
    // compiled matcher. Istio `StringMatch` semantics are case-sensitive for
    // `exact` and `prefix`; explicit request ports are part of the value.
    // `Regex` patterns are also kept verbatim — operators who want
    // case-insensitivity should write `(?i)` in the pattern.
    //
    // The match is a per-rule predicate; VirtualService-level `hosts` is the
    // proxy-admission gate and is unchanged by this PR.
    fn ctx_for_authority() -> RequestContext {
        ctx_with("GET", "/api")
    }

    fn host_headers(host: &str) -> HashMap<String, String> {
        HashMap::from([("host".to_string(), host.to_string())])
    }

    #[test]
    fn accepts_tagged_exact_authority_match_verbatim_at_load() {
        // Istio `StringMatch.exact` is case-sensitive, so operator-provided
        // casing is preserved and compared against the raw request authority.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "API.example.COM"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0]
            .authority_compiled
            .as_ref()
            .expect("authority must compile")
        {
            AuthorityMatcher::Exact(v) => assert_eq!(v, "API.example.COM"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_legacy_bare_string_authority_as_exact() {
        // Hand-authored plugin configs may carry the bare-string shape
        // (`{"authority": "api.example.com"}`). The K8s translator emits
        // tagged forms; accepting bare strings keeps the schema friendly
        // for direct operator use.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": "API.example.COM"},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0]
            .authority_compiled
            .as_ref()
            .expect("authority must compile")
        {
            AuthorityMatcher::Exact(v) => assert_eq!(v, "API.example.COM"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_prefix_authority_match_verbatim_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"prefix": "API."}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0]
            .authority_compiled
            .as_ref()
            .expect("authority must compile")
        {
            AuthorityMatcher::Prefix(p) => assert_eq!(p, "API."),
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn accepts_regex_authority_match_at_load_without_folding_pattern() {
        // Regex is NOT folded — operators who want case-insensitivity write
        // `(?i)` in the pattern. The matcher input is the raw request
        // authority, so a pattern that targets lowercase letters remains
        // case-sensitive.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": "^api\\.(prod|staging)\\.example\\.com$"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0]
            .authority_compiled
            .as_ref()
            .expect("authority must compile")
        {
            AuthorityMatcher::Regex(re) => {
                assert!(re.is_match("api.prod.example.com"));
                assert!(re.is_match("api.staging.example.com"));
                assert!(!re.is_match("api.example.com"));
                assert!(
                    !re.is_match("API.PROD.EXAMPLE.COM"),
                    "regex deliberately keeps operator pattern verbatim — \
                     operators who want case-insensitivity write `(?i)` themselves"
                );
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_regex_authority_at_load() {
        // CLAUDE.md "Plugin Config Validation": invalid regex MUST be a
        // hard error from `Plugin::new()`, never `Ok` with a runtime panic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": "["}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("authority"), "got: {err}");
        assert!(err.contains("regex"), "got: {err}");
        assert!(err.contains("invalid"), "got: {err}");
    }

    #[test]
    fn rejects_empty_regex_authority_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": ""}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("authority"), "got: {err}");
        assert!(err.contains("regex"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_prefix_authority_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"prefix": ""}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("authority"), "got: {err}");
        assert!(err.contains("prefix"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_exact_authority_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": ""}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("authority"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_authority_match_operator_at_load() {
        // `deny_unknown_fields` on `AuthorityStringMatch` catches typos like
        // `{"prefiks": "..."}` at load time so we never compile and ship a
        // rule that silently never fires.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"prefiks": "api."}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("mesh_route_dispatch") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_multiple_authority_operators_in_one_match() {
        // Istio's `HTTPMatchRequest.authority` allows exactly one operator
        // per predicate. Serde's externally-tagged enum representation
        // enforces single-key shapes, so a config that tries to combine
        // `exact` and `prefix` is rejected at load time rather than
        // silently honoring only one.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com", "prefix": "api."}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("mesh_route_dispatch"), "got: {err}");
    }

    #[test]
    fn authority_only_match_is_not_empty() {
        // A rule whose only predicate is `authority` must be accepted at
        // load time — `MatchCriteria::is_empty()` returns false because
        // authority is set. Without this guard, an authority-only rule
        // would hit the "empty match requires transforms" error and never
        // load.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        assert!(plugin.rules()[0].authority_compiled.is_some());
    }

    #[tokio::test]
    async fn exact_authority_match_routes_request() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("api.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[tokio::test]
    async fn exact_authority_match_includes_request_port() {
        // Istio authority matching is a raw StringMatch over Host/:authority;
        // explicit request ports are part of the matched value.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com:8443"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("api.example.com:8443");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[tokio::test]
    async fn exact_authority_without_port_does_not_match_port_bearing_host() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("api.example.com:8443");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn exact_authority_match_is_case_sensitive() {
        // Istio StringMatch exact/prefix predicates are case-sensitive even
        // for authority. Host routing normalization is not reused here.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("API.EXAMPLE.COM");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn exact_authority_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("other.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn missing_host_header_does_not_match_authority_predicate() {
        // No `Host` header → no authority to compare against → match
        // returns false. The default-route-falls-through behavior depends
        // on `reject_unmatched`; here we just verify the predicate.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn malformed_host_header_does_not_match_authority_predicate() {
        // The predicate is a raw StringMatch. Malformed authority shapes are
        // not normalized or rejected by this plugin; they simply compare as
        // ordinary strings and therefore do not match this exact operand.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"exact": "api.example.com"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("::1");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn prefix_authority_match_routes_request() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"prefix": "api."}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        for host in ["api.example.com", "api.staging.example.com"] {
            let mut ctx = ctx_for_authority();
            let mut headers = host_headers(host);
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("internal"),
                "prefix must match {host}"
            );
        }
    }

    #[tokio::test]
    async fn prefix_authority_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"prefix": "api."}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("admin.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn regex_authority_match_routes_request() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": "^api\\.(prod|staging)\\.example\\.com$"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        for host in ["api.prod.example.com", "api.staging.example.com"] {
            let mut ctx = ctx_for_authority();
            let mut headers = host_headers(host);
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("internal"),
                "regex must match {host}"
            );
        }
    }

    #[tokio::test]
    async fn regex_authority_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": "^api\\.(prod|staging)\\.example\\.com$"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("api.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn regex_authority_requires_full_string_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": "internal"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("not-internal.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());

        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("internal");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[tokio::test]
    async fn case_insensitive_regex_via_inline_flag_matches_uppercase_request() {
        // Operators who want case-insensitivity write `(?i)` themselves —
        // this is the documented contract for StringMatch regex predicates.
        // The test verifies the contract works end-to-end on a mixed-case
        // pattern and a differently-cased raw request authority.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"authority": {"regex": "(?i)^API\\.example\\.com$"}},
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_for_authority();
        let mut headers = host_headers("api.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[tokio::test]
    async fn authority_and_method_must_both_match() {
        // All-of semantics across distinct predicate kinds — authority is
        // ANDed with method/headers/queryParams. Mirrors Istio's
        // `HTTPMatchRequest` semantics where every field is conjunctive.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "methods": ["POST"],
                    "authority": {"exact": "api.example.com"}
                },
                "destination": {"upstream_id": "internal"}
            }]
        }))
        .unwrap();
        // Right method, wrong authority.
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = host_headers("other.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Right authority, wrong method.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = host_headers("api.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Both match.
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = host_headers("api.example.com");
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("internal"));
    }

    #[test]
    fn legacy_and_tagged_authority_form_round_trip_through_serde() {
        // The schema must keep the two wire shapes byte-stable so existing
        // hand-authored configs deserialize unchanged.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [
                {
                    "match": {"authority": "api.example.com"},
                    "destination": {"upstream_id": "legacy"}
                },
                {
                    "match": {"authority": {"prefix": "admin."}},
                    "destination": {"upstream_id": "tagged"}
                }
            ]
        }))
        .unwrap();

        let raw_legacy = serde_json::to_value(&plugin.rules()[0].match_.authority).unwrap();
        assert!(
            raw_legacy.is_string(),
            "legacy bare-string form must round-trip as a string, got: {raw_legacy}"
        );
        assert_eq!(raw_legacy.as_str(), Some("api.example.com"));

        let raw_tagged = serde_json::to_value(&plugin.rules()[0..2][1].match_.authority).unwrap();
        assert!(
            raw_tagged.is_object(),
            "tagged form must round-trip as an object, got: {raw_tagged}"
        );
        assert_eq!(raw_tagged["prefix"].as_str(), Some("admin."));
    }

    // ── UriMatchOp + ignore_uri_case (T1-B.5) ─────────────────────────────
    //
    // Istio `HTTPMatchRequest.ignoreUriCase: true` folds ASCII case for
    // exact/prefix URI predicates only (not headers / methods / authority,
    // and not regex). The plugin pre-folds literal operands at compile time
    // so the hot path uses `eq_ignore_ascii_case` / a byte-level manual
    // prefix scan — both allocation-free. Regex URIs keep the operator's
    // pattern verbatim.

    #[test]
    fn accepts_uri_exact_match_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"exact": "/api"}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].uri_compiled {
            Some(UriMatcher::Exact {
                value,
                case_insensitive,
            }) => {
                assert_eq!(value, "/api");
                assert!(!case_insensitive);
            }
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_uri_prefix_match_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": "/api"}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].uri_compiled {
            Some(UriMatcher::Prefix {
                value,
                case_insensitive,
            }) => {
                assert_eq!(value, "/api");
                assert!(!case_insensitive);
            }
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn accepts_uri_regex_match_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"regex": "^/api/v[0-9]+"}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].uri_compiled {
            Some(UriMatcher::Regex(re)) => {
                assert!(re.is_match("/api/v1"));
                assert!(!re.is_match("/API/v1"), "case-sensitive without flag");
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn uri_exact_with_ignore_uri_case_pre_folds_operand() {
        // Pre-fold at compile time: store the lowercased operand. Hot path
        // uses `eq_ignore_ascii_case` which is symmetric, so the pre-fold is
        // a micro-opt rather than a correctness requirement — but the
        // compiled form should still carry the lowercased value (visible in
        // debug output / introspection).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"exact": "/Api"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].uri_compiled {
            Some(UriMatcher::Exact {
                value,
                case_insensitive,
            }) => {
                assert_eq!(value, "/api", "pre-folded lowercase at compile time");
                assert!(*case_insensitive);
            }
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn uri_prefix_with_ignore_uri_case_pre_folds_operand() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": "/Api"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].uri_compiled {
            Some(UriMatcher::Prefix {
                value,
                case_insensitive,
            }) => {
                assert_eq!(value, "/api", "pre-folded lowercase at compile time");
                assert!(*case_insensitive);
            }
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn uri_regex_with_ignore_uri_case_keeps_regex_case_sensitive() {
        // Istio documents `ignoreUriCase` as exact/prefix-only. Regex
        // operands keep their operator-supplied case behavior.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"regex": "^/api/v[0-9]+"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].uri_compiled {
            Some(UriMatcher::Regex(re)) => {
                assert!(re.is_match("/api/v1"));
                assert!(!re.is_match("/API/v1"));
                assert!(!re.is_match("/Api/V2"));
                assert!(!re.is_match("/store/v1"));
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn uri_regex_with_inline_case_flag_still_matches_when_ignore_uri_case_true() {
        // Operator-supplied `(?i)` patterns should compile + match even when
        // the ignored exact/prefix-only flag is present.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"regex": "(?i)^/api"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        if let Some(UriMatcher::Regex(re)) = &plugin.rules()[0].uri_compiled {
            assert!(re.is_match("/API"));
        } else {
            panic!("expected Regex");
        }
    }

    #[test]
    fn rejects_ignore_uri_case_without_uri_predicate_at_load() {
        // The flag would be a no-op without a URI predicate — fail loud
        // instead of silently accepting a misconfiguration.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"ignore_uri_case": true, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("ignore_uri_case"), "got: {err}");
        assert!(err.contains("uri predicate"), "got: {err}");
    }

    #[test]
    fn rejects_empty_uri_exact_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"exact": ""}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("uri.exact"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_uri_prefix_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": ""}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("uri.prefix"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_uri_regex_at_load() {
        // CLAUDE.md "Plugin Config Validation": invalid regex MUST be a hard
        // error from `Plugin::new()`, never `Ok` with a runtime panic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"regex": "["}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("uri.regex"), "got: {err}");
        assert!(err.contains("invalid"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_uri_match_operator_at_load() {
        // `deny_unknown_fields` on `UriMatchOp` catches typos like
        // `{"prefiks": "..."}` at load time so we never compile and ship a
        // rule that silently never fires.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefiks": "/api"}, "methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("mesh_route_dispatch") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn uri_match_with_ignore_uri_case_routes_for_both_casings() {
        // Hot-path contract: the same dispatch rule matches `/api/users`
        // AND `/API/users` AND `/Api/Users` when `ignore_uri_case: true`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": "/Api"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        for path in ["/api/users", "/API/users", "/Api/Users", "/api"] {
            let mut ctx = ctx_with("GET", path);
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("canary"),
                "case-insensitive prefix must match {path}"
            );
        }
    }

    #[tokio::test]
    async fn uri_match_without_ignore_uri_case_is_case_sensitive() {
        // Defense in depth: without the flag, the URI predicate matches
        // case-sensitively even if the proxy's listen_path admitted the
        // request via some upstream rewrite.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": "/Api"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api/users");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            ctx.route_override_upstream_id.is_none(),
            "case-sensitive prefix must NOT match /api when matcher is /Api"
        );
    }

    #[tokio::test]
    async fn uri_match_with_ignore_uri_case_does_not_widen_non_ascii() {
        // ASCII-only fold: non-ASCII bytes match byte-for-byte. The matcher
        // `/café` stays distinct from `/CAFé` because only the leading
        // ASCII bytes get case-folded; the `é` (0xC3 0xA9 in UTF-8) is
        // byte-equal in both, and `c` ≡ `C` under fold. So this case
        // actually MATCHES — let's pick a more discriminating example.
        //
        // `é` (U+00E9) lowercase vs `É` (U+00C9) uppercase. The ASCII-only
        // fold does NOT equate these — a path with `/É` does NOT match a
        // prefix `/é` even with `ignore_uri_case: true`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": "/é"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();

        // ASCII fold leaves `é` alone, so `/é/foo` matches and `/É/foo`
        // does NOT. This deterministic behavior is what we promise in
        // docs — operators on non-ASCII paths should not expect Unicode
        // case folding.
        let mut ctx = ctx_with("GET", "/é/foo");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            ctx.route_override_upstream_id.as_deref(),
            Some("x"),
            "non-ASCII bytes must match byte-for-byte (matcher matches itself)"
        );

        let mut ctx = ctx_with("GET", "/É/foo");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            ctx.route_override_upstream_id.is_none(),
            "ASCII fold does NOT equate é (U+00E9) and É (U+00C9) — \
             non-ASCII bytes compare byte-for-byte"
        );
    }

    #[tokio::test]
    async fn uri_match_with_ignore_uri_case_combined_with_other_predicates() {
        // All-of: URI fold AND header AND method must all hold for the
        // rule to fire.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "uri": {"prefix": "/Api"},
                    "ignore_uri_case": true,
                    "methods": ["POST"],
                    "headers": {"x-canary": "v2"}
                },
                "destination": {"upstream_id": "all-match"}
            }]
        }))
        .unwrap();

        // All three match.
        let mut ctx = ctx_with("POST", "/api/items");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("all-match"));

        // URI matches case-insensitively but method wrong.
        let mut ctx = ctx_with("GET", "/api/items");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());

        // URI fold misses (different prefix), method/header right.
        let mut ctx = ctx_with("POST", "/store/items");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn uri_exact_with_ignore_uri_case_rejects_longer_path() {
        // Exact != prefix: `/Api` exact does NOT match `/api/users` even
        // case-insensitively — exact is a full-equality match.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"exact": "/Api"}, "ignore_uri_case": true},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/API");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("x"));

        let mut ctx = ctx_with("GET", "/api/users");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            ctx.route_override_upstream_id.is_none(),
            "exact match must not admit longer paths"
        );
    }

    #[tokio::test]
    async fn uri_match_without_other_predicates_evaluates_uri_only() {
        // Schema: a URI predicate alone is sufficient — the empty-match
        // rejection only fires when methods/headers/query_params/uri are
        // ALL empty.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"uri": {"prefix": "/api"}},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api/users");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("x"));
    }

    #[test]
    fn legacy_match_criteria_without_uri_field_round_trips() {
        // Wire compat: existing configs that don't carry `uri` / `ignore_uri_case`
        // continue to deserialize cleanly. Serialization skips the empty
        // fields so the JSON shape stays byte-stable for downstream tooling.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let raw = serde_json::to_value(&plugin.rules()[0].match_).unwrap();
        assert!(raw.get("uri").is_none(), "uri must be omitted when absent");
        assert!(
            raw.get("ignore_uri_case").is_none(),
            "ignore_uri_case=false must be omitted from the wire form"
        );
    }

    // -- Per-rule fault action -------------------------------------------

    #[test]
    fn rejects_empty_fault_action() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("at least one of 'delay' or 'abort'"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_zero_delay_duration() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"delay": {"duration_ms": 0, "percentage": 50.0}}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("duration_ms must be > 0"), "got: {err}");
    }

    #[test]
    fn rejects_delay_duration_above_one_minute() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"delay": {"duration_ms": 60_001, "percentage": 50.0}}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("duration_ms must be"), "got: {err}");
    }

    #[test]
    fn rejects_zero_percentage() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {"status_code": 503, "percentage": 0.0}}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("must be > 0.0"), "got: {err}");
    }

    #[test]
    fn rejects_out_of_range_status_code() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {"status_code": 700, "percentage": 50.0}}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("status_code must be 200-599"), "got: {err}");
    }

    #[test]
    fn rejects_out_of_range_grpc_status() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {
                    "status_code": 503,
                    "percentage": 50.0,
                    "grpc_status": 17
                }}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("grpc_status must be 0-16"), "got: {err}");
    }

    #[tokio::test]
    async fn full_abort_rejects_request() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {"status_code": 503, "percentage": 100.0}}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject { status_code, .. } => {
                assert_eq!(status_code, 503);
            }
            other => panic!("expected reject, got {other:?}"),
        }
        // Route override never applies when the request is aborted.
        assert!(ctx.route_override_upstream_id.is_none());
        // Mark for downstream guards.
        assert_eq!(
            ctx.metadata.get("fault_injected").map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn full_abort_emits_grpc_status_only_for_grpc_requests() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["POST", "GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {
                    "status_code": 200,
                    "percentage": 100.0,
                    "grpc_status": 14
                }}
            }]
        }))
        .unwrap();

        // Plain HTTP: no grpc-status header.
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                headers: resp_headers,
                ..
            } => {
                assert!(
                    !resp_headers.contains_key("grpc-status"),
                    "plain HTTP must not receive grpc-status header"
                );
            }
            other => panic!("expected reject, got {other:?}"),
        }

        // gRPC: grpc-status header present.
        let mut ctx = ctx_with("POST", "/svc/Method");
        ctx.set_request_http_flavor(crate::config::types::HttpFlavor::Grpc);
        let mut headers =
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                headers: resp_headers,
                ..
            } => {
                assert_eq!(
                    resp_headers.get("grpc-status").map(String::as_str),
                    Some("14")
                );
            }
            other => panic!("expected reject, got {other:?}"),
        }

        // WebSocket takes precedence over a hostile native-gRPC media type.
        let mut ctx = ctx_with("GET", "/socket");
        ctx.set_request_http_flavor(crate::config::types::HttpFlavor::WebSocket);
        let mut headers =
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                headers: resp_headers,
                ..
            } => {
                assert!(
                    !resp_headers.contains_key("grpc-status"),
                    "WebSocket requests must not receive grpc-status"
                );
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn translated_grpc_web_request_is_not_treated_as_native_grpc() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["POST"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {
                    "status_code": 200,
                    "percentage": 100.0,
                    "grpc_status": 14
                }}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/svc/Method");
        ctx.headers = HashMap::from([(
            "content-type".to_string(),
            "application/grpc-web+proto".to_string(),
        )]);
        let grpc_web = crate::plugins::grpc_web::GrpcWebPlugin::new(&json!({})).unwrap();
        assert!(matches!(
            grpc_web.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ));
        let mut headers = ctx.headers.clone();
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/grpc")
        );
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                headers: resp_headers,
                ..
            } => {
                assert!(
                    !resp_headers.contains_key("grpc-status"),
                    "gRPC-Web requests are handled by the gRPC-Web bridge, \
                     not the trailer-based gRPC path; do not stamp grpc-status"
                );
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn full_delay_only_falls_through_to_override() {
        // 100% delay with a tiny duration. Since `tokio::time::sleep(1ms)`
        // is functionally instant under the test runtime, this confirms the
        // delay path doesn't accidentally also reject.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"delay": {"duration_ms": 1, "percentage": 100.0}}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        // Route override DOES apply when there's no abort — the request
        // dispatches normally after the delay.
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn fault_skipped_when_prior_plugin_already_injected() {
        // A global / proxy-scoped `fault_injection` plugin running before
        // this one (priority 2940 vs 2995) sets `fault_injected=true` on
        // ctx.metadata. The per-rule fault must then no-op to avoid
        // stacking a second delay + abort.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {"status_code": 503, "percentage": 100.0}}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        ctx.metadata
            .insert("fault_injected".to_string(), "true".to_string());
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        // No second abort fires; the route override still applies so the
        // canary upstream still gets the matched request.
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn proxy_delay_followed_by_route_fault_does_not_stack() {
        let proxy_fault = crate::plugins::fault_injection::FaultInjectionPlugin::new(&json!({
            "delay": {"duration_ms": 1, "percentage": 100.0}
        }))
        .unwrap();
        let route = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"abort": {"status_code": 503, "percentage": 100.0}}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();

        assert!(matches!(
            proxy_fault.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            route.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
        assert!(!ctx.metadata.contains_key(ROUTE_FAULT_INJECTED_METADATA_KEY));
        assert_eq!(
            ctx.metadata.get("fault_type").map(String::as_str),
            Some("delay")
        );
    }

    #[tokio::test]
    async fn route_source_marker_suppresses_later_proxy_fault_surface() {
        let route = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "fault": {"delay": {"duration_ms": 1, "percentage": 100.0}}
            }]
        }))
        .unwrap();
        let later = crate::plugins::fault_injection::FaultInjectionPlugin::new(&json!({
            "abort": {"status_code": 503, "percentage": 100.0}
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();

        assert!(matches!(
            route.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(ctx.metadata.contains_key(ROUTE_FAULT_INJECTED_METADATA_KEY));
        assert!(matches!(
            later.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }

    #[tokio::test]
    async fn fault_does_not_fire_on_unmatched_rules() {
        // First-match-wins: if a method=POST rule has a fault but the
        // request is GET, the fault must not fire from a later rule that
        // happens to match.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [
                {
                    "match": {"methods": ["POST"]},
                    "destination": {"upstream_id": "fault-target"},
                    "fault": {"abort": {"status_code": 503, "percentage": 100.0}}
                },
                {
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "safe-target"}
                }
            ]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.route_override_upstream_id.as_deref(),
            Some("safe-target")
        );
        assert!(!ctx.metadata.contains_key("fault_injected"));
    }

    // ── rewrite / redirect ────────────────────────────────────────────────

    #[test]
    fn rewrite_request_path_replaces_whole_path_without_prefix() {
        assert_eq!(rewrite_request_path("/api/users", "/v2", None), "/v2");
    }

    #[test]
    fn rewrite_request_path_strips_matched_prefix() {
        // Istio prefix-rewrite: `match.prefix=/api` + `rewrite.uri=/v2` turns
        // `/api/users` into `/v2/users`.
        assert_eq!(
            rewrite_request_path("/api/users", "/v2", Some("/api")),
            "/v2/users"
        );
    }

    #[test]
    fn rewrite_request_path_joins_without_doubling_slash() {
        assert_eq!(
            rewrite_request_path("/api/users", "/v2/", Some("/api")),
            "/v2/users"
        );
        assert_eq!(
            rewrite_request_path("/apiusers", "/v2", Some("/api")),
            "/v2/users"
        );
        // Empty tail keeps the replacement verbatim.
        assert_eq!(rewrite_request_path("/api", "/v2", Some("/api")), "/v2");
    }

    #[test]
    fn rewrite_request_path_case_insensitive_prefix_preserves_tail() {
        // ignoreUriCase: the proxy matched `/api/users` to a `/Api` prefix
        // rule, so the byte prefix differs only in ASCII case. The tail must be
        // preserved (Istio prefix-rewrite → `/v2/users`), not collapsed to a
        // bare `/v2`.
        assert_eq!(
            rewrite_request_path("/api/users", "/v2", Some("/Api")),
            "/v2/users"
        );
        // A genuine non-match (not even case-insensitive) still replaces whole.
        assert_eq!(
            rewrite_request_path("/other/users", "/v2", Some("/Api")),
            "/v2"
        );
    }

    #[tokio::test]
    async fn rewrite_uri_sets_route_override_path() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "rewrite": {"uri": "/v2", "match_prefix": "/api"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api/users");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_path.as_deref(), Some("/v2/users"));
        assert!(ctx.route_override_authority.is_none());
    }

    #[tokio::test]
    async fn rewrite_authority_sets_host_header_and_override() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "rewrite": {"authority": "internal.example.com"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("host".to_string(), "public.example.com".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            headers.get("host").map(String::as_str),
            Some("internal.example.com")
        );
        assert_eq!(
            ctx.route_override_authority.as_deref(),
            Some("internal.example.com")
        );
        // No `uri` in the rewrite, so the path is untouched.
        assert!(ctx.route_override_path.is_none());
    }

    #[tokio::test]
    async fn later_instance_without_authority_restores_original_host() {
        // Clone-path scenario: because an authority-rewrite instance is present
        // the handler clones ctx.headers (never mem::take's it), and threads one
        // shared header map through both instances. ctx.headers holds the
        // original client Host throughout.
        let mut ctx = ctx_with("GET", "/api");
        ctx.headers = host_headers("public.example.com");
        let mut headers = host_headers("public.example.com");

        // Instance A rewrites the authority and matches.
        let plugin_a = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "internal"},
                "rewrite": {"authority": "internal.example.com"}
            }]
        }))
        .unwrap();
        let _ = plugin_a.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            headers.get("host").map(String::as_str),
            Some("internal.example.com")
        );

        // Instance B matches but does NOT rewrite the authority.
        let plugin_b = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "other"}
            }]
        }))
        .unwrap();
        let _ = plugin_b.before_proxy(&mut ctx, &mut headers).await;

        // The stale rewritten authority must not linger in the shared map (it
        // would leak into X-Forwarded-Host / Forwarded); Host is restored to the
        // original client value, and the override is cleared.
        assert_eq!(
            headers.get("host").map(String::as_str),
            Some("public.example.com")
        );
        assert!(ctx.route_override_authority.is_none());
    }

    #[test]
    fn restore_original_host_is_noop_when_ctx_headers_empty() {
        // No-modify (mem::take) path: ctx.headers is empty. The restore must NOT
        // touch the header map — nothing rewrote Host on this path, so the
        // `headers` param already holds the original.
        let mut ctx = ctx_with("GET", "/api");
        ctx.headers.clear();
        let mut headers = host_headers("public.example.com");
        restore_original_host(&ctx, &mut headers);
        assert_eq!(
            headers.get("host").map(String::as_str),
            Some("public.example.com")
        );
    }

    #[tokio::test]
    async fn non_matching_rewrite_does_not_set_override() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "rewrite": {"uri": "/v2"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_path.is_none());
    }

    #[test]
    fn declares_modifies_request_headers_only_for_authority_rewrite() {
        let authority_rewrite = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "rewrite": {"authority": "internal.svc"}
            }]
        }))
        .unwrap();
        assert!(authority_rewrite.modifies_request_headers());

        let path_rewrite = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "rewrite": {"uri": "/v2"}
            }]
        }))
        .unwrap();
        assert!(
            !path_rewrite.modifies_request_headers(),
            "a path-only rewrite must not force the cloned-header dispatch path"
        );
    }

    #[tokio::test]
    async fn redirect_short_circuits_with_absolute_location() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "redirect": {"uri": "/new", "authority": "elsewhere.example.com", "redirect_code": 308}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/old");
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        let mut headers = HashMap::new();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 308);
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://elsewhere.example.com/new")
                );
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some("text/plain")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
        // A redirect must not leave a route override behind.
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn redirect_match_prefix_preserves_path_suffix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "redirect": {
                    "uri": "/new",
                    "match_prefix": "/old",
                    "authority": "elsewhere.example.com",
                    "redirect_code": 302
                }
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/old/item");
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        let mut headers = HashMap::new();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://elsewhere.example.com/new/item")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_preserves_original_query_string() {
        // Istio/Envoy keep the request query on redirect unless the redirect
        // URI supplies its own. `/old?token=abc` -> `/new?token=abc`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "redirect": {"uri": "/new", "authority": "elsewhere.example.com"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/old");
        ctx.set_raw_query_string("token=abc".to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        let mut headers = HashMap::new();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://elsewhere.example.com/new?token=abc")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_uri_query_takes_precedence_over_request_query() {
        // When the redirect URI carries its own query, the original request
        // query is NOT appended (no duplicate `?`).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "redirect": {"uri": "/new?x=1", "authority": "elsewhere.example.com"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/old");
        ctx.set_raw_query_string("token=abc".to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        let mut headers = HashMap::new();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://elsewhere.example.com/new?x=1")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_preserves_request_path_and_authority_when_unset() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"scheme": "https"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/keep/me");
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
        let mut headers = HashMap::from([("host".to_string(), "site.example.com".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 301, "default redirect code is 301");
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com/keep/me")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_port_preserves_request_host_and_replaces_existing_port() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"scheme": "https", "port": 8443}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/keep/me");
        let mut headers =
            HashMap::from([("host".to_string(), "site.example.com:8080".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com:8443/keep/me")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_scheme_default_port_strips_existing_request_port() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"scheme": "https", "port": 443}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/keep/me");
        let mut headers = HashMap::from([("host".to_string(), "site.example.com:80".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com/keep/me")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_port_preserves_bracketed_ipv6_host() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"scheme": "https", "port": 8443}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/v6");
        let mut headers = HashMap::from([("host".to_string(), "[2001:db8::1]:8080".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://[2001:db8::1]:8443/v6")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_derive_port_from_protocol_default_strips_non_default_request_port() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {
                    "scheme": "https",
                    "derive_port": "FROM_PROTOCOL_DEFAULT"
                }
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/secure");
        let mut headers =
            HashMap::from([("host".to_string(), "site.example.com:8080".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com/secure")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_derive_port_from_request_port_uses_frontend_listen_port() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {
                    "scheme": "https",
                    "derive_port": "FROM_REQUEST_PORT"
                }
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/foo");
        ctx.frontend_listen_port = Some(8080);
        // Spoofable forwarding headers must never win over the trusted listener port.
        let mut headers = HashMap::from([
            ("host".to_string(), "site.example.com".to_string()),
            ("x-forwarded-port".to_string(), "65535".to_string()),
            (
                "forwarded".to_string(),
                "for=1.2.3.4;host=evil;proto=https;port=65535".to_string(),
            ),
        ]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com:8080/foo")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_derive_port_from_request_port_prefers_orig_dst_over_listener() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {
                    "scheme": "https",
                    "derive_port": "FROM_REQUEST_PORT"
                }
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/foo");
        // Capture listener (:15006) must not win over the original destination.
        ctx.frontend_listen_port = Some(15006);
        ctx.orig_dst = Some("10.0.0.5:9090".parse().unwrap());
        let mut headers = HashMap::from([
            ("host".to_string(), "site.example.com".to_string()),
            ("x-forwarded-port".to_string(), "65535".to_string()),
        ]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com:9090/foo")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_derive_port_from_request_port_canonicalizes_scheme_default() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"derive_port": "FROM_REQUEST_PORT"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/foo");
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
        ctx.frontend_listen_port = Some(80);
        let mut headers =
            HashMap::from([("host".to_string(), "site.example.com:8080".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("http://site.example.com/foo")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_derive_port_from_request_port_preserves_bracketed_ipv6() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {
                    "scheme": "https",
                    "derive_port": "FROM_REQUEST_PORT"
                }
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/v6");
        ctx.frontend_listen_port = Some(8443);
        let mut headers = HashMap::from([("host".to_string(), "[2001:db8::1]".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://[2001:db8::1]:8443/v6")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[test]
    fn rejects_redirect_port_and_derive_port_together() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"port": 8443, "derive_port": "FROM_REQUEST_PORT"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("port and redirect.derive_port are mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_redirect_derive_port() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "redirect": {"derive_port": "FROM_X_FORWARDED_PORT"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("derive_port") || err.contains("unknown variant"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn redirect_falls_back_to_relative_location_without_authority() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{ "match": {}, "redirect": {"uri": "/relative"} }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/old");
        let mut headers = HashMap::new();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject { headers, .. } => {
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("/relative")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_rewrite() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "destination": {"upstream_id": "x"}, "rewrite": {}}]
        }))
        .unwrap_err();
        assert!(err.contains("rewrite must set at least one"), "got: {err}");
    }

    #[tokio::test]
    async fn redirect_status_only_preserves_request_url() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "redirect": {"redirect_code": 302}}]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/keep/me");
        ctx.set_raw_query_string("token=abc".to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        let mut headers = HashMap::from([("host".to_string(), "site.example.com".to_string())]);
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 302);
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://site.example.com/keep/me?token=abc")
                );
            }
            other => panic!("expected redirect Reject, got {other:?}"),
        }
    }

    #[test]
    fn rejects_redirect_code_out_of_range() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "redirect": {"uri": "/x", "redirect_code": 404}}]
        }))
        .unwrap_err();
        assert!(err.contains("redirect_code must be 300-399"), "got: {err}");
    }

    #[test]
    fn rejects_crlf_in_rewrite_uri() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "rewrite": {"uri": "/x\r\nInjected: 1"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("must not contain CR or LF"), "got: {err}");
    }

    #[test]
    fn redirect_rule_does_not_require_destination() {
        // A redirect rule answers the request itself, so it is valid with no
        // backend destination.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "redirect": {"uri": "/new"}}]
        }));
        assert!(
            plugin.is_ok(),
            "redirect rule must not need a destination: {plugin:?}"
        );
    }

    #[test]
    fn default_redirect_code_is_301_via_serde() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {}, "redirect": {"uri": "/new"}}]
        }))
        .unwrap();
        assert_eq!(
            plugin.rules()[0]
                .redirect
                .as_ref()
                .expect("redirect")
                .redirect_code,
            301
        );
    }
}
