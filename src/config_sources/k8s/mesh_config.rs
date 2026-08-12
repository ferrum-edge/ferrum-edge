use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::modes::mesh::config::{
    MAX_MESH_EXT_AUTHZ_PROVIDERS, MESH_EXT_AUTHZ_DEFAULT_TIMEOUT_MS,
    MESH_EXT_AUTHZ_MAX_REQUEST_BODY_BYTES, MESH_EXT_AUTHZ_MAX_TIMEOUT_MS, MeshExtAuthzBodyCheck,
    MeshExtAuthzHeader, MeshExtAuthzProvider, TracingProvider, sanitize_mesh_ext_authz_diagnostic,
    validate_mesh_ext_authz_forwarded_header, validate_mesh_ext_authz_mutable_header,
};

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, K8sTranslationOptions, invalid_resource,
    string_field,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct MeshConfigProviderRegistry {
    tracing_providers: HashMap<String, TracingProvider>,
    /// extensionProvider names declared in meshConfig that Ferrum does not
    /// translate to a tracing provider — either non-tracing types
    /// (`prometheus`, `stackdriver`, future Istio additions), admitted
    /// `envoyExtAuthzHttp` providers (which are tracked separately for CUSTOM
    /// authz but are still "not tracing"), or a recognised tracing key Ferrum
    /// can't yet emit. Tracked so Telemetry resolution can distinguish "name
    /// not in meshConfig" from "name in meshConfig but not a tracing type
    /// Ferrum supports".
    non_tracing_provider_names: HashSet<String>,
    default_tracing_provider_names: Vec<String>,
    /// Admitted `envoyExtAuthzHttp` providers, keyed by `name` (issue #3235).
    ///
    /// Retained — not merely counted — because an `AuthorizationPolicy` with
    /// `action: CUSTOM` needs the provider's endpoint, transport, timeout, and
    /// header/body contract at runtime, and resolving it later (post-admission)
    /// would mean an accepted CUSTOM policy could turn out to be inert.
    ext_authz_providers: HashMap<String, MeshExtAuthzProvider>,
    /// Names declared as an ext-auth provider variant Ferrum refuses to
    /// implement (today: `envoyExtAuthzGrpc`). Tracked separately from
    /// `non_tracing_provider_names` so a CUSTOM policy naming one gets a
    /// field-specific "declared but unsupported" diagnostic instead of the
    /// generic "not declared" one.
    unsupported_ext_authz_provider_names: HashSet<String>,
}

impl MeshConfigProviderRegistry {
    pub(crate) fn tracing_provider(&self, name: &str) -> Option<&TracingProvider> {
        self.tracing_providers.get(name)
    }

    pub(crate) fn is_known_non_tracing_provider(&self, name: &str) -> bool {
        self.non_tracing_provider_names.contains(name)
    }

    pub(crate) fn default_tracing_provider_names(&self) -> &[String] {
        &self.default_tracing_provider_names
    }

    /// Resolve an `AuthorizationPolicy` `spec.provider.name` against the
    /// admitted ext-auth providers.
    pub(crate) fn ext_authz_provider(&self, name: &str) -> Option<&MeshExtAuthzProvider> {
        self.ext_authz_providers.get(name)
    }

    /// Whether `name` was declared as an ext-auth provider variant Ferrum
    /// deliberately refuses (as opposed to not being declared at all).
    pub(crate) fn is_unsupported_ext_authz_provider(&self, name: &str) -> bool {
        self.unsupported_ext_authz_provider_names.contains(name)
    }

    fn merge_from(&mut self, parsed: ParsedMeshConfig, warnings: &mut Vec<String>) {
        for (name, provider) in parsed.registry.tracing_providers {
            self.non_tracing_provider_names.remove(&name);
            self.tracing_providers.insert(name, provider);
        }
        for name in parsed.registry.non_tracing_provider_names {
            if !self.tracing_providers.contains_key(&name) {
                self.non_tracing_provider_names.insert(name);
            }
        }
        for (name, provider) in parsed.registry.ext_authz_providers {
            self.unsupported_ext_authz_provider_names.remove(&name);
            self.ext_authz_providers.insert(name, provider);
        }
        for name in parsed.registry.unsupported_ext_authz_provider_names {
            if !self.ext_authz_providers.contains_key(&name) {
                self.unsupported_ext_authz_provider_names.insert(name);
            }
        }
        if !parsed.registry.default_tracing_provider_names.is_empty() {
            self.default_tracing_provider_names = parsed.registry.default_tracing_provider_names;
        }
        warnings.extend(parsed.warnings);
    }
}

#[derive(Debug, Clone, Default)]
struct ParsedMeshConfig {
    registry: MeshConfigProviderRegistry,
    warnings: Vec<String>,
}

pub(crate) fn is_root_namespace_config_map(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> bool {
    object.kind == "ConfigMap" && object.metadata.namespace == options.istio_root_namespace
}

pub(crate) fn is_istio_mesh_config_map(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> bool {
    is_root_namespace_config_map(options, object) && object.metadata.name == "istio"
}

pub(crate) fn collect(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let Some(raw_mesh_config) = mesh_config_yaml(object) else {
        acc.warnings.push(format!(
            "Ignoring ConfigMap {}/{} as meshConfig source because data.mesh is missing",
            object.metadata.namespace, object.metadata.name
        ));
        return Ok(());
    };
    if raw_mesh_config.trim().is_empty() {
        return Ok(());
    }
    let parsed =
        parse_mesh_config(raw_mesh_config).map_err(|message| invalid_resource(object, message))?;
    acc.mesh_config_registry
        .merge_from(parsed, &mut acc.warnings);
    Ok(())
}

fn mesh_config_yaml(object: &K8sObject) -> Option<&str> {
    object
        .spec
        .get("data")
        .and_then(|data| data.get("mesh"))
        .and_then(Value::as_str)
}

fn parse_mesh_config(raw: &str) -> Result<ParsedMeshConfig, String> {
    let value: Value = serde_yaml::from_str(raw)
        .map_err(|error| format!("ConfigMap data.mesh is not valid MeshConfig YAML: {error}"))?;
    let mut parsed = ParsedMeshConfig::default();
    collect_extension_providers(&value, &mut parsed)?;
    collect_default_providers(&value, &mut parsed)?;
    Ok(parsed)
}

fn collect_extension_providers(value: &Value, parsed: &mut ParsedMeshConfig) -> Result<(), String> {
    let Some(extension_providers) = value.get("extensionProviders") else {
        return Ok(());
    };
    let providers = extension_providers
        .as_array()
        .ok_or_else(|| "meshConfig.extensionProviders must be an array".to_string())?;
    for entry in providers {
        let Some(name) = trimmed_string(entry, "name") else {
            parsed.warnings.push(
                "meshConfig.extensionProviders[] entry without a non-empty name skipped"
                    .to_string(),
            );
            continue;
        };
        match tracing_provider_from_extension(&name, entry)? {
            ExtensionProviderKind::Tracing(provider) => {
                parsed.registry.non_tracing_provider_names.remove(&name);
                if parsed
                    .registry
                    .tracing_providers
                    .insert(name.clone(), provider)
                    .is_some()
                {
                    parsed.warnings.push(format!(
                        "meshConfig.extensionProviders duplicate tracing provider '{name}' replaced by later definition"
                    ));
                }
            }
            ExtensionProviderKind::ExtAuthz(provider) => {
                // An ext-auth provider is also, from Telemetry's point of view,
                // a declared-but-not-tracing name. Keep both classifications so
                // Telemetry resolution's "declared vs not declared" distinction
                // is unchanged by issue #3235.
                if !parsed.registry.tracing_providers.contains_key(&name) {
                    parsed
                        .registry
                        .non_tracing_provider_names
                        .insert(name.clone());
                }
                parsed
                    .registry
                    .unsupported_ext_authz_provider_names
                    .remove(&name);
                // A duplicate ext-auth provider name is REJECTED, not
                // last-wins: two differing definitions leave which endpoint a
                // CUSTOM policy delegates to dependent on document order, and
                // an authorization delegation must never be ambiguous. An
                // exactly identical redefinition is harmless and admitted.
                if let Some(existing) = parsed.registry.ext_authz_providers.get(&name)
                    && existing != provider.as_ref()
                {
                    return Err(format!(
                        "meshConfig.extensionProviders declares external authorization provider '{}' more than once with different configuration",
                        sanitize_mesh_ext_authz_diagnostic(&name)
                    ));
                }
                parsed
                    .registry
                    .ext_authz_providers
                    .insert(name.clone(), *provider);
                if parsed.registry.ext_authz_providers.len() > MAX_MESH_EXT_AUTHZ_PROVIDERS {
                    return Err(format!(
                        "meshConfig.extensionProviders declares more than {MAX_MESH_EXT_AUTHZ_PROVIDERS} external authorization providers"
                    ));
                }
            }
            ExtensionProviderKind::UnsupportedExtAuthz => {
                if !parsed.registry.tracing_providers.contains_key(&name) {
                    parsed
                        .registry
                        .non_tracing_provider_names
                        .insert(name.clone());
                }
                if !parsed.registry.ext_authz_providers.contains_key(&name) {
                    parsed
                        .registry
                        .unsupported_ext_authz_provider_names
                        .insert(name);
                }
            }
            ExtensionProviderKind::NonTracing => {
                if !parsed.registry.tracing_providers.contains_key(&name) {
                    parsed.registry.non_tracing_provider_names.insert(name);
                }
            }
        }
    }
    Ok(())
}

fn collect_default_providers(value: &Value, parsed: &mut ParsedMeshConfig) -> Result<(), String> {
    let Some(default_providers) = value.get("defaultProviders") else {
        return Ok(());
    };
    let Some(tracing) = default_providers.get("tracing") else {
        return Ok(());
    };
    let providers = tracing
        .as_array()
        .ok_or_else(|| "meshConfig.defaultProviders.tracing must be an array".to_string())?;
    parsed.registry.default_tracing_provider_names = providers
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    Ok(())
}

/// Outcome of classifying a single `meshConfig.extensionProviders[]` entry.
/// `Tracing` carries a translated provider; `NonTracing` means the entry has a
/// recognisable non-tracing/non-ext-authz shape (e.g., `prometheus`,
/// `stackdriver`, a future Istio tracing key Ferrum doesn't translate, or a
/// typo'd block name) so the registry can still remember the *name* and let
/// Telemetry resolution distinguish "name not declared" from "name declared
/// but Ferrum can't translate it as tracing". `envoyExtAuthzHttp` is
/// `ExtAuthz`, not `NonTracing`.
enum ExtensionProviderKind {
    Tracing(TracingProvider),
    /// An admitted `envoyExtAuthzHttp` external authorization provider
    /// (issue #3235). Boxed so the enum stays small — the ext-auth shape is
    /// much larger than a `TracingProvider`.
    ExtAuthz(Box<MeshExtAuthzProvider>),
    /// An ext-auth provider variant Ferrum deliberately refuses to implement
    /// (`envoyExtAuthzGrpc`). The NAME is remembered so a CUSTOM policy that
    /// binds it gets a specific "declared but unsupported" diagnostic instead
    /// of a misleading "not declared".
    UnsupportedExtAuthz,
    NonTracing,
}

fn tracing_provider_from_extension(
    name: &str,
    entry: &Value,
) -> Result<ExtensionProviderKind, String> {
    if let Some(config) = object_field(entry, "envoyExtAuthzHttp")? {
        validate_ext_authz_provider_entry_shape(name, entry, "envoyExtAuthzHttp")?;
        return Ok(ExtensionProviderKind::ExtAuthz(Box::new(
            envoy_ext_authz_http_provider(name, config)?,
        )));
    }
    if object_field(entry, "envoyExtAuthzGrpc")?.is_some() {
        validate_ext_authz_provider_entry_shape(name, entry, "envoyExtAuthzGrpc")?;
        // Deliberate, documented gap: the Envoy gRPC check API
        // (`envoy.service.auth.v3.Authorization`) carries attributes Ferrum
        // does not model, and an approximation would silently change what an
        // operator's policy authorizes. Refusing the NAME here makes every
        // CUSTOM policy that binds it fail closed with a precise diagnostic,
        // which is strictly safer than admitting an inert provider.
        return Ok(ExtensionProviderKind::UnsupportedExtAuthz);
    }
    if let Some(config) = object_field(entry, "zipkin")? {
        return Ok(ExtensionProviderKind::Tracing(zipkin_provider(
            name, config,
        )?));
    }
    if let Some(config) = object_field(entry, "datadog")? {
        return Ok(ExtensionProviderKind::Tracing(datadog_provider(
            name, config,
        )?));
    }
    if let Some(config) = object_field(entry, "lightstep")? {
        return Ok(ExtensionProviderKind::Tracing(lightstep_provider(
            name, config,
        )?));
    }
    if let Some(config) = object_field(entry, "opentelemetry")? {
        return Ok(ExtensionProviderKind::Tracing(opentelemetry_provider(
            name, config,
        )?));
    }
    Ok(ExtensionProviderKind::NonTracing)
}

/// Enforce the protobuf oneof shape on an ext-authz provider entry.
///
/// The embedded meshConfig YAML does not pass through Kubernetes structural
/// schema validation. If an entry carries both `envoyExtAuthzHttp` and another
/// provider variant (or a typo'd sibling field), selecting the first known key
/// would silently change which authorization service Ferrum enforces. Once an
/// ext-authz variant is present, the only legal top-level keys are its `name`
/// and that one variant.
fn validate_ext_authz_provider_entry_shape(
    name: &str,
    entry: &Value,
    selected_variant: &str,
) -> Result<(), String> {
    let Some(object) = entry.as_object() else {
        return Err("meshConfig.extensionProviders[] entry must be an object".to_string());
    };
    for key in object.keys() {
        if key != "name" && key != selected_variant {
            return Err(format!(
                "meshConfig.extensionProviders '{}' {selected_variant} entry does not support sibling field '{}'; extension provider variants are mutually exclusive",
                sanitize_mesh_ext_authz_diagnostic(name),
                sanitize_mesh_ext_authz_diagnostic(key)
            ));
        }
    }
    Ok(())
}

fn zipkin_provider(name: &str, config: &Value) -> Result<TracingProvider, String> {
    if let Some(url) = trimmed_string(config, "url") {
        return Ok(TracingProvider::Zipkin { url });
    }
    let mut url = service_endpoint(config, name, "zipkin", 9411)?;
    let path = trimmed_string(config, "path").unwrap_or_else(|| "/api/v2/spans".to_string());
    if path.starts_with('/') {
        url.push_str(&path);
    } else {
        url.push('/');
        url.push_str(&path);
    }
    Ok(TracingProvider::Zipkin { url })
}

fn datadog_provider(name: &str, config: &Value) -> Result<TracingProvider, String> {
    let agent_url = trimmed_string_aliased(config, "agentUrl", &["agent_url"])
        .map(Ok)
        .unwrap_or_else(|| service_endpoint(config, name, "datadog", 8126))?;
    let service = trimmed_string_aliased(config, "serviceName", &["service_name"]);
    Ok(TracingProvider::Datadog { agent_url, service })
}

fn lightstep_provider(name: &str, config: &Value) -> Result<TracingProvider, String> {
    let collector_url = trimmed_string_aliased(config, "collectorUrl", &["collector_url"])
        .map(Ok)
        .unwrap_or_else(|| {
            service_endpoint_with_default_scheme(config, name, "lightstep", 443, "https")
        })?;
    let Some(access_token_env) =
        trimmed_string_aliased(config, "accessTokenEnv", &["access_token_env"])
    else {
        return Err(format!(
            "meshConfig.extensionProviders '{name}' lightstep provider requires accessTokenEnv"
        ));
    };
    Ok(TracingProvider::Lightstep {
        collector_url,
        access_token_env,
    })
}

/// Keys Ferrum models on an `envoyExtAuthzHttp` provider.
///
/// The set is CLOSED on purpose. An unrecognised key is refused rather than
/// ignored: every field in Istio's ext-auth provider changes what the check
/// authorizes (or what the provider may rewrite), so silently dropping one
/// would admit a policy that enforces something other than what the operator
/// wrote. `scheme` is a Ferrum addition — Istio derives the ext-auth transport
/// from the destination's own mesh configuration, which Ferrum's direct
/// provider dial does not go through, so the operator must state it.
const EXT_AUTHZ_HTTP_KEYS: &[&str] = &[
    "service",
    "port",
    "scheme",
    "timeout",
    "pathPrefix",
    "failOpen",
    "statusOnError",
    "includeRequestHeadersInCheck",
    "includeAdditionalHeadersInCheck",
    "includeRequestBodyInCheck",
    "headersToUpstreamOnAllow",
    "headersToDownstreamOnDeny",
    "headersToDownstreamOnAllow",
];

const EXT_AUTHZ_BODY_KEYS: &[&str] = &["maxRequestBytes", "allowPartialMessage", "packAsBytes"];

/// Translate one `meshConfig.extensionProviders[].envoyExtAuthzHttp` entry.
///
/// Every diagnostic names the exact field and never echoes an unbounded
/// operator value (a provider endpoint or additional-header value can embed a
/// credential).
fn envoy_ext_authz_http_provider(
    name: &str,
    config: &Value,
) -> Result<MeshExtAuthzProvider, String> {
    let display = sanitize_mesh_ext_authz_diagnostic(name);
    reject_unknown_provider_keys(&display, "envoyExtAuthzHttp", config, EXT_AUTHZ_HTTP_KEYS)?;

    let Some(service) = optional_ext_authz_string(&display, config, "service")? else {
        return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp requires service"
        ));
    };
    let Some(port) = optional_u16(config, "port")? else {
        return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp requires port"
        ));
    };
    let tls = match optional_ext_authz_string(&display, config, "scheme")?.as_deref() {
        None | Some("http") => false,
        Some("https") => true,
        Some(_) => {
            return Err(format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp scheme must be 'http' or 'https'"
            ));
        }
    };
    let timeout_ms = match config.get("timeout") {
        Some(value) => parse_ext_authz_timeout_ms(&display, value)?,
        None => MESH_EXT_AUTHZ_DEFAULT_TIMEOUT_MS,
    };
    if timeout_ms == 0 || timeout_ms > MESH_EXT_AUTHZ_MAX_TIMEOUT_MS {
        return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp timeout must be between 1ms and {MESH_EXT_AUTHZ_MAX_TIMEOUT_MS}ms"
        ));
    }
    let path_prefix = match optional_ext_authz_string(&display, config, "pathPrefix")? {
        Some(prefix) if prefix.starts_with('/') => Some(prefix),
        Some(_) => {
            return Err(format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp pathPrefix must start with '/'"
            ));
        }
        None => None,
    };
    let fail_open = optional_bool(config, "failOpen")?.unwrap_or(false);
    let status_on_error = parse_ext_authz_status_on_error(&display, config)?;

    let include_request_headers_in_check = ext_authz_header_list(
        &display,
        "includeRequestHeadersInCheck",
        config,
        validate_mesh_ext_authz_forwarded_header,
    )?;
    let headers_to_upstream_on_allow = ext_authz_header_list(
        &display,
        "headersToUpstreamOnAllow",
        config,
        validate_mesh_ext_authz_mutable_header,
    )?;
    let headers_to_downstream_on_deny = ext_authz_header_list(
        &display,
        "headersToDownstreamOnDeny",
        config,
        validate_mesh_ext_authz_mutable_header,
    )?;
    let headers_to_downstream_on_allow = ext_authz_header_list(
        &display,
        "headersToDownstreamOnAllow",
        config,
        validate_mesh_ext_authz_mutable_header,
    )?;
    let include_additional_headers_in_check = ext_authz_additional_headers(&display, config)?;
    let include_request_body_in_check = ext_authz_body_check(&display, config)?;

    let provider = MeshExtAuthzProvider {
        name: name.to_string(),
        service,
        port,
        tls,
        path_prefix,
        timeout_ms,
        fail_open,
        status_on_error,
        include_request_headers_in_check,
        include_additional_headers_in_check,
        include_request_body_in_check,
        headers_to_upstream_on_allow,
        headers_to_downstream_on_deny,
        headers_to_downstream_on_allow,
    };
    // One shared fail-closed contract for every source (K8s, native/file, xDS
    // carrier). Translating here and validating with the same function keeps
    // the three boundaries from drifting.
    provider
        .validate()
        .map_err(|error| format!("meshConfig.{error}"))?;
    Ok(provider)
}

/// Parse an optional string field on the security-sensitive ext-authz block.
///
/// The generic meshConfig string helper intentionally treats a non-string as
/// absent for older best-effort telemetry providers. That is not safe here:
/// silently defaulting `scheme` or dropping `pathPrefix` changes where an
/// authorization decision is sent. Null/empty keeps protobuf's ordinary
/// "unset" semantics; every other non-string shape is refused by field name.
fn optional_ext_authz_string(
    display: &str,
    config: &Value,
    field: &str,
) -> Result<Option<String>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let value = value.trim();
            Ok((!value.is_empty()).then(|| value.to_string()))
        }
        Some(_) => Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp {field} must be a string"
        )),
    }
}

fn reject_unknown_provider_keys(
    display: &str,
    block: &str,
    config: &Value,
    allowed: &[&str],
) -> Result<(), String> {
    let Some(object) = config.as_object() else {
        return Ok(());
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "meshConfig.extensionProviders '{display}' {block} does not support field '{}'; Ferrum refuses unmodelled ext-authz fields rather than silently ignoring them",
                sanitize_mesh_ext_authz_diagnostic(key)
            ));
        }
    }
    Ok(())
}

/// Parse `envoyExtAuthzHttp.statusOnError`.
///
/// Upstream Istio's `EnvoyExternalAuthorizationHttpProvider` documents this as
/// an HTTP status STRING (it is an `envoy.type.v3.StatusCode` enum name in
/// Envoy, surfaced by Istio as the decimal status text), so a decimal string is
/// the real operator input shape. A JSON integer is accepted too because it is
/// the shape a hand-authored Ferrum mesh document naturally carries, and the
/// internal representation stays numeric either way. Anything else — an enum
/// NAME, a float, a non-numeric string, or a status outside 4xx/5xx — is
/// refused with a field-shaped diagnostic rather than defaulted, because a
/// silently defaulted `statusOnError` changes what a fail-closed denial looks
/// like to the client.
fn parse_ext_authz_status_on_error(display: &str, config: &Value) -> Result<u16, String> {
    let invalid = || {
        format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp statusOnError must be a 4xx or 5xx HTTP status, written as a decimal string such as \"403\" (an integer is also accepted)"
        )
    };
    let status = match config.get("statusOnError") {
        None | Some(Value::Null) => return Ok(403),
        Some(Value::String(raw)) => raw.trim().parse::<u16>().map_err(|_| invalid())?,
        Some(Value::Number(raw)) => {
            let value = raw.as_u64().ok_or_else(invalid)?;
            u16::try_from(value).map_err(|_| invalid())?
        }
        Some(_) => return Err(invalid()),
    };
    if !(400..=599).contains(&status) {
        return Err(invalid());
    }
    Ok(status)
}

/// Parse a protobuf-Duration-shaped ext-auth timeout (`"0.25s"`, `"2s"`,
/// `"500ms"`) or a plain number of seconds.
fn parse_ext_authz_timeout_ms(display: &str, value: &Value) -> Result<u64, String> {
    let invalid = || {
        format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp timeout must be a duration such as '0.5s', '250ms', or a number of seconds"
        )
    };
    if let Some(seconds) = value.as_f64() {
        // Reject non-finite first; RangeInclusive::contains is only for the
        // closed [0, 3600] seconds contract once the value is known finite.
        if !seconds.is_finite() || !(0.0..=3600.0).contains(&seconds) {
            return Err(invalid());
        }
        return Ok((seconds * 1000.0).round() as u64);
    }
    let raw = value.as_str().ok_or_else(invalid)?.trim();
    let (number, multiplier) = if let Some(rest) = raw.strip_suffix("ms") {
        (rest, 1.0_f64)
    } else if let Some(rest) = raw.strip_suffix('s') {
        (rest, 1000.0_f64)
    } else {
        (raw, 1000.0_f64)
    };
    let parsed: f64 = number.trim().parse().map_err(|_| invalid())?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(invalid());
    }
    let millis = parsed * multiplier;
    if millis > 3_600_000.0 {
        return Err(invalid());
    }
    Ok(millis.round() as u64)
}

fn ext_authz_header_list(
    display: &str,
    field: &str,
    config: &Value,
    validator: fn(&str) -> Result<String, String>,
) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let entries = value.as_array().ok_or_else(|| {
        format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp {field} must be an array"
        )
    })?;
    let mut names = Vec::with_capacity(entries.len());
    for entry in entries {
        let raw = entry.as_str().ok_or_else(|| {
            format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp {field} entries must be strings"
            )
        })?;
        // Istio permits `*`-suffixed prefix matches here. Ferrum refuses them:
        // a prefix rule cannot be shown to exclude the reserved / hop-by-hop /
        // identity headers the exact-name allowlist protects, so admitting one
        // would silently widen what a provider may read or rewrite.
        if raw.contains('*') {
            return Err(format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp {field} does not support wildcard entries; list exact header names"
            ));
        }
        let normalized = validator(raw).map_err(|error| {
            format!("meshConfig.extensionProviders '{display}' envoyExtAuthzHttp {field} {error}")
        })?;
        if !names.contains(&normalized) {
            names.push(normalized);
        }
    }
    Ok(names)
}

fn ext_authz_additional_headers(
    display: &str,
    config: &Value,
) -> Result<Vec<MeshExtAuthzHeader>, String> {
    let Some(value) = config.get("includeAdditionalHeadersInCheck") else {
        return Ok(Vec::new());
    };
    let object = value.as_object().ok_or_else(|| {
        format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeAdditionalHeadersInCheck must be a map"
        )
    })?;
    let mut headers = Vec::with_capacity(object.len());
    for (key, raw) in object {
        let name = validate_mesh_ext_authz_forwarded_header(key).map_err(|error| {
            format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeAdditionalHeadersInCheck {error}"
            )
        })?;
        let header_value = raw.as_str().ok_or_else(|| {
            format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeAdditionalHeadersInCheck values must be strings"
            )
        })?;
        headers.push(MeshExtAuthzHeader {
            name,
            value: header_value.to_string(),
        });
    }
    headers.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(headers)
}

fn ext_authz_body_check(
    display: &str,
    config: &Value,
) -> Result<Option<MeshExtAuthzBodyCheck>, String> {
    let Some(value) = object_field(config, "includeRequestBodyInCheck")? else {
        return Ok(None);
    };
    reject_unknown_provider_keys(
        display,
        "envoyExtAuthzHttp includeRequestBodyInCheck",
        value,
        EXT_AUTHZ_BODY_KEYS,
    )?;
    if optional_bool(value, "packAsBytes")?.unwrap_or(false) {
        // `packAsBytes` changes the check payload encoding for the gRPC check
        // API only. Ferrum performs an HTTP check, so honouring the flag is
        // impossible and ignoring it would change what the provider inspects.
        return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeRequestBodyInCheck.packAsBytes is only meaningful for the gRPC check API and is not supported"
        ));
    }
    let max_request_bytes = match value.get("maxRequestBytes") {
        Some(raw) => raw.as_u64().ok_or_else(|| {
            format!(
                "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeRequestBodyInCheck.maxRequestBytes must be an integer"
            )
        })?,
        None => return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeRequestBodyInCheck requires maxRequestBytes"
        )),
    };
    if max_request_bytes == 0 || max_request_bytes > MESH_EXT_AUTHZ_MAX_REQUEST_BODY_BYTES as u64 {
        return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeRequestBodyInCheck.maxRequestBytes must be between 1 and {MESH_EXT_AUTHZ_MAX_REQUEST_BODY_BYTES}"
        ));
    }
    // Deliberate, documented narrowing (see `MeshExtAuthzProvider::validate`):
    // Envoy's partial-message mode checks a bounded prefix and still forwards
    // the complete body upstream. Ferrum's authorize-phase body IS the buffer
    // the proxy forwards, so it returns 413 at `maxRequestBytes` instead. An
    // accepted-but-unreachable flag would be worse than this refusal.
    if optional_bool(value, "allowPartialMessage")?.unwrap_or(false) {
        return Err(format!(
            "meshConfig.extensionProviders '{display}' envoyExtAuthzHttp includeRequestBodyInCheck.allowPartialMessage is not supported: Ferrum checks the complete buffered body and returns 413 at maxRequestBytes instead of checking a truncated prefix"
        ));
    }
    Ok(Some(MeshExtAuthzBodyCheck {
        max_request_bytes: max_request_bytes as usize,
        allow_partial_message: false,
    }))
}

fn optional_bool(value: &Value, field: &str) -> Result<Option<bool>, String> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(format!(
            "meshConfig.extensionProviders[].{field} must be a boolean"
        )),
    }
}

fn opentelemetry_provider(name: &str, config: &Value) -> Result<TracingProvider, String> {
    let endpoint = trimmed_string(config, "endpoint")
        .map(Ok)
        .unwrap_or_else(|| service_endpoint(config, name, "opentelemetry", 4317))?;
    Ok(TracingProvider::OpenTelemetry { endpoint })
}

fn service_endpoint(
    config: &Value,
    provider_name: &str,
    provider_kind: &str,
    default_port: u16,
) -> Result<String, String> {
    service_endpoint_with_default_scheme(config, provider_name, provider_kind, default_port, "http")
}

fn service_endpoint_with_default_scheme(
    config: &Value,
    provider_name: &str,
    provider_kind: &str,
    default_port: u16,
    default_scheme: &str,
) -> Result<String, String> {
    let Some(service) = trimmed_string(config, "service") else {
        return Err(format!(
            "meshConfig.extensionProviders '{provider_name}' {provider_kind} provider requires service or an explicit endpoint URL"
        ));
    };
    let port = optional_u16(config, "port")?.unwrap_or(default_port);
    let scheme = trimmed_string(config, "scheme").unwrap_or_else(|| default_scheme.to_string());
    Ok(format!("{scheme}://{service}:{port}"))
}

fn object_field<'a>(value: &'a Value, field: &str) -> Result<Option<&'a Value>, String> {
    let Some(field_value) = value.get(field) else {
        return Ok(None);
    };
    if field_value.is_object() {
        Ok(Some(field_value))
    } else {
        Err(format!(
            "meshConfig.extensionProviders[].{field} must be an object"
        ))
    }
}

fn optional_u16(value: &Value, field: &str) -> Result<Option<u16>, String> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    let Some(port) = raw.as_u64() else {
        return Err(format!(
            "meshConfig.extensionProviders[].{field} must be an integer"
        ));
    };
    if port == 0 || port > u16::MAX as u64 {
        return Err(format!(
            "meshConfig.extensionProviders[].{field} must be between 1 and 65535 (got {port})"
        ));
    }
    Ok(Some(port as u16))
}

fn trimmed_string(value: &Value, field: &str) -> Option<String> {
    string_field(value, field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn trimmed_string_aliased(value: &Value, field: &str, aliases: &[&str]) -> Option<String> {
    trimmed_string(value, field).or_else(|| {
        aliases
            .iter()
            .find_map(|alias| trimmed_string(value, alias))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> ParsedMeshConfig {
        parse_mesh_config(raw).expect("mesh config parses")
    }

    #[test]
    fn parses_realistic_extension_providers_and_defaults() {
        let parsed = parse(
            r#"
defaultProviders:
  tracing:
  - zipkin-prod
extensionProviders:
- name: zipkin-prod
  zipkin:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
- name: otel-prod
  opentelemetry:
    service: otel-collector.istio-system.svc.cluster.local
    port: 4318
- name: datadog-prod
  datadog:
    agentUrl: http://datadog-agent.istio-system:8126
    serviceName: reviews
"#,
        );

        assert_eq!(
            parsed.registry.default_tracing_provider_names(),
            &["zipkin-prod".to_string()]
        );
        assert_eq!(
            parsed.registry.tracing_provider("zipkin-prod"),
            Some(&TracingProvider::Zipkin {
                url: "http://zipkin.istio-system.svc.cluster.local:9411/api/v2/spans".to_string(),
            })
        );
        assert_eq!(
            parsed.registry.tracing_provider("otel-prod"),
            Some(&TracingProvider::OpenTelemetry {
                endpoint: "http://otel-collector.istio-system.svc.cluster.local:4318".to_string(),
            })
        );
        assert_eq!(
            parsed.registry.tracing_provider("datadog-prod"),
            Some(&TracingProvider::Datadog {
                agent_url: "http://datadog-agent.istio-system:8126".to_string(),
                service: Some("reviews".to_string()),
            })
        );
    }

    #[test]
    fn skips_non_tracing_extension_providers() {
        // Use a genuinely non-tracing, non-ext-authz provider kind. An
        // `envoyExtAuthzHttp` entry is no longer "skipped" — issue #3235
        // admits it as CUSTOM authz config and fail-closes plaintext
        // non-loopback HTTP — so this fixture must stay on an unrelated
        // extensionProviders shape.
        let parsed = parse(
            r#"
extensionProviders:
- name: prometheus
  prometheus: {}
"#,
        );

        assert!(
            parsed.registry.tracing_providers.is_empty(),
            "non-tracing providers must not enter tracing registry"
        );
        assert!(
            parsed.registry.ext_authz_providers.is_empty(),
            "non-ext-authz providers must not enter the ext-authz registry"
        );
        assert!(
            parsed.registry.is_known_non_tracing_provider("prometheus"),
            "non-tracing provider name must be remembered so Telemetry resolution \
             can distinguish 'name not declared' from 'declared but not tracing'"
        );
        assert!(
            parsed.warnings.is_empty(),
            "no warnings expected: {:?}",
            parsed.warnings
        );
    }

    #[test]
    fn tracing_entry_overrides_non_tracing_classification_when_same_name() {
        // Operator typo'd a zipkin block on the first entry, fixed it on the
        // second with the same name. The fixed tracing entry must win, and the
        // name must no longer be tracked as non-tracing.
        let parsed = parse(
            r#"
extensionProviders:
- name: my-zipkin
  zipkinn:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
- name: my-zipkin
  zipkin:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
"#,
        );
        assert!(
            parsed.registry.tracing_provider("my-zipkin").is_some(),
            "later tracing entry must override earlier non-tracing classification"
        );
        assert!(
            !parsed.registry.is_known_non_tracing_provider("my-zipkin"),
            "name must not remain in non-tracing set after a tracing entry promotes it"
        );
    }

    #[test]
    fn duplicate_tracing_provider_in_same_config_map_warns_once() {
        // Two entries with the same name in one ConfigMap. Only the
        // pre-merge dup detector should fire; the cross-ConfigMap merge_from
        // path must not emit a second identical warning.
        let parsed = parse(
            r#"
extensionProviders:
- name: zipkin-prod
  zipkin:
    service: zipkin-a.istio-system.svc.cluster.local
    port: 9411
- name: zipkin-prod
  zipkin:
    service: zipkin-b.istio-system.svc.cluster.local
    port: 9411
"#,
        );
        let dup_count = parsed
            .warnings
            .iter()
            .filter(|warning| warning.contains("duplicate tracing provider 'zipkin-prod'"))
            .count();
        assert_eq!(
            dup_count, 1,
            "exactly one dup warning expected, got {dup_count}: {:?}",
            parsed.warnings
        );
    }

    #[test]
    fn rejects_invalid_default_provider_shape() {
        let err = parse_mesh_config(
            r#"
defaultProviders:
  tracing: zipkin-prod
"#,
        )
        .expect_err("invalid default provider shape fails closed");

        assert!(err.contains("defaultProviders.tracing"));
    }

    #[test]
    fn rejects_invalid_yaml_with_actionable_message() {
        // Operator types a stray tab / mis-indents the file — surface a
        // message that names the field so the reconciler skip-retries log
        // points at the right spot.
        let err = parse_mesh_config("not: valid: yaml")
            .expect_err("invalid YAML must fail closed instead of silently emptying the registry");
        assert!(
            err.contains("ConfigMap data.mesh"),
            "error must name data.mesh so operators know where to look, got: {err}"
        );
    }

    #[test]
    fn lightstep_defaults_service_endpoint_to_https() {
        let parsed = parse(
            r#"
extensionProviders:
- name: lightstep-prod
  lightstep:
    service: collector.lightstep.svc.cluster.local
    accessTokenEnv: LIGHTSTEP_ACCESS_TOKEN
"#,
        );

        assert_eq!(
            parsed.registry.tracing_provider("lightstep-prod"),
            Some(&TracingProvider::Lightstep {
                collector_url: "https://collector.lightstep.svc.cluster.local:443".to_string(),
                access_token_env: "LIGHTSTEP_ACCESS_TOKEN".to_string(),
            })
        );
    }
}
