use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::modes::mesh::config::TracingProvider;

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, K8sTranslationOptions, invalid_resource,
    string_field,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct MeshConfigProviderRegistry {
    tracing_providers: HashMap<String, TracingProvider>,
    /// extensionProvider names declared in meshConfig that Ferrum does not
    /// translate to a tracing provider — either non-tracing types
    /// (`envoyExtAuthzHttp`, `prometheus`, future Istio additions) or a
    /// recognised tracing key Ferrum can't yet emit. Tracked so Telemetry
    /// resolution can distinguish "name not in meshConfig" from
    /// "name in meshConfig but not a tracing type Ferrum supports".
    non_tracing_provider_names: HashSet<String>,
    default_tracing_provider_names: Vec<String>,
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
/// recognisable shape (e.g., `envoyExtAuthzHttp`, `prometheus`, `stackdriver`,
/// a future Istio tracing key Ferrum doesn't translate, or a typo'd block
/// name) so the registry can still remember the *name* and let Telemetry
/// resolution distinguish "name not declared" from "name declared but Ferrum
/// can't translate it as tracing".
enum ExtensionProviderKind {
    Tracing(TracingProvider),
    NonTracing,
}

fn tracing_provider_from_extension(
    name: &str,
    entry: &Value,
) -> Result<ExtensionProviderKind, String> {
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
        let parsed = parse(
            r#"
extensionProviders:
- name: ext-authz
  envoyExtAuthzHttp:
    service: authz.default.svc.cluster.local
    port: 9000
"#,
        );

        assert!(
            parsed.registry.tracing_providers.is_empty(),
            "non-tracing providers must not enter tracing registry"
        );
        assert!(
            parsed.registry.is_known_non_tracing_provider("ext-authz"),
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
