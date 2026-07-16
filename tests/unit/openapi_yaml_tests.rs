use regex::Regex;
use serde::Deserialize;
use serde_json::json;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

const OPENAPI_HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

fn get_path<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for key in path {
        current = current
            .get(Value::String((*key).to_string()))
            .unwrap_or_else(|| panic!("missing OpenAPI path component: {key}"));
    }
    current
}

#[derive(Default)]
struct SerdeStructFieldCollector {
    fields: BTreeSet<String>,
}

// A derived `Deserialize` implementation passes its complete accepted field
// list to `deserialize_struct` before reading any values. Capture that list so
// new/renamed Rust fields fail parity without maintaining a second Rust-field
// manifest in this test.
impl<'de> serde::Deserializer<'de> for &mut SerdeStructFieldCollector {
    type Error = serde::de::value::Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::Error::custom("expected a derived struct"))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.fields
            .extend(fields.iter().map(|field| (*field).to_string()));
        Err(serde::de::Error::custom("field inventory collected"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map enum identifier ignored_any
    }
}

fn serde_struct_field_names<T>() -> BTreeSet<String>
where
    T: for<'de> Deserialize<'de>,
{
    let mut collector = SerdeStructFieldCollector::default();
    let _ = T::deserialize(&mut collector);
    assert!(
        !collector.fields.is_empty(),
        "{} did not deserialize through deserialize_struct",
        std::any::type_name::<T>()
    );
    collector.fields
}

fn schema_property_names(
    spec: &serde_json::Value,
    schema_label: &str,
    properties_pointer: &str,
) -> BTreeSet<String> {
    spec.pointer(properties_pointer)
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("{schema_label} must define object properties"))
        .keys()
        .cloned()
        .collect()
}

fn assert_serde_schema_field_parity<T>(
    spec: &serde_json::Value,
    schema_label: &str,
    properties_pointer: &str,
    intentionally_undocumented: &[&str],
    schema_only: &[&str],
) where
    T: for<'de> Deserialize<'de>,
{
    let mut serde_fields = serde_struct_field_names::<T>();
    let mut schema_fields = schema_property_names(spec, schema_label, properties_pointer);

    for field in intentionally_undocumented {
        assert!(
            serde_fields.remove(*field),
            "stale undocumented-field exception {schema_label}.{field}"
        );
    }
    for field in schema_only {
        assert!(
            schema_fields.remove(*field),
            "stale schema-only exception {schema_label}.{field}"
        );
    }

    assert_eq!(
        serde_fields,
        schema_fields,
        "Serde/OpenAPI field inventory drift for {schema_label} ({})",
        std::any::type_name::<T>()
    );
}

fn assert_serde_component_field_parity<T>(
    spec: &serde_json::Value,
    component: &str,
    intentionally_undocumented: &[&str],
    schema_only: &[&str],
) where
    T: for<'de> Deserialize<'de>,
{
    assert_serde_schema_field_parity::<T>(
        spec,
        component,
        &format!("/components/schemas/{component}/properties"),
        intentionally_undocumented,
        schema_only,
    );
}

#[test]
fn typed_component_properties_match_serde_field_inventories() {
    use ferrum_edge::config::types::{
        ActiveHealthCheck, BackendTlsConfig, CircuitBreakerConfig, ConsulConfig, Consumer,
        DnsSdConfig, HashOnCookieConfig, HealthCheckConfig, KubernetesConfig, LocalityDistribute,
        LocalityFailover, MeshSdConfig, PassiveHealthCheck, PluginAssociation, PluginConfig, Proxy,
        RetryConfig, ServiceDiscoveryConfig, SubsetDefinition, SubsetTrafficPolicy,
        TcpKeepaliveCfg, Upstream, UpstreamLocalityLbSetting, UpstreamPortOverride, UpstreamTarget,
    };
    use ferrum_edge::modes::mesh::config::MeshTrafficPolicyTls;
    use ferrum_edge::modes::mesh::slice::{MeshEgressScopeResource, MeshEgressScopeSnapshot};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    macro_rules! check {
        ($type:ty, $component:literal) => {
            assert_serde_component_field_parity::<$type>(&spec, $component, &[], &[])
        };
        ($type:ty, $component:literal, rust_only = [$($rust_only:literal),* $(,)?], schema_only = [$($schema_only:literal),* $(,)?]) => {
            assert_serde_component_field_parity::<$type>(
                &spec,
                $component,
                &[$($rust_only),*],
                &[$($schema_only),*],
            )
        };
    }

    macro_rules! check_at {
        ($type:ty, $schema_label:literal, $properties_pointer:literal) => {
            assert_serde_schema_field_parity::<$type>(
                &spec,
                $schema_label,
                $properties_pointer,
                &[],
                &[],
            )
        };
    }

    check!(Proxy, "Proxy");
    check!(Consumer, "Consumer");
    check!(PluginConfig, "PluginConfig");
    check!(PluginAssociation, "PluginAssociation");
    check!(Upstream, "Upstream");
    check!(UpstreamTarget, "UpstreamTarget");
    check!(SubsetDefinition, "SubsetDefinition");
    check!(SubsetTrafficPolicy, "SubsetTrafficPolicy");
    check!(UpstreamPortOverride, "UpstreamPortOverride");
    check!(TcpKeepaliveCfg, "TcpKeepaliveCfg");
    check!(UpstreamLocalityLbSetting, "UpstreamLocalityLbSetting");
    check!(LocalityDistribute, "LocalityDistribute");
    check!(LocalityFailover, "LocalityFailover");
    check!(MeshTrafficPolicyTls, "MeshTrafficPolicyTls");
    check!(BackendTlsConfig, "BackendTlsConfig");
    check!(HealthCheckConfig, "HealthCheckConfig");
    check!(ActiveHealthCheck, "ActiveHealthCheck");
    check!(PassiveHealthCheck, "PassiveHealthCheck");
    check!(HashOnCookieConfig, "HashOnCookieConfig");
    check!(ServiceDiscoveryConfig, "ServiceDiscoveryConfig");
    check_at!(
        DnsSdConfig,
        "ServiceDiscoveryConfig.dns_sd",
        "/components/schemas/ServiceDiscoveryConfig/properties/dns_sd/properties"
    );
    check_at!(
        KubernetesConfig,
        "ServiceDiscoveryConfig.kubernetes",
        "/components/schemas/ServiceDiscoveryConfig/properties/kubernetes/properties"
    );
    check_at!(
        ConsulConfig,
        "ServiceDiscoveryConfig.consul",
        "/components/schemas/ServiceDiscoveryConfig/properties/consul/properties"
    );
    check_at!(
        MeshSdConfig,
        "ServiceDiscoveryConfig.mesh",
        "/components/schemas/ServiceDiscoveryConfig/properties/mesh/properties"
    );
    check!(CircuitBreakerConfig, "CircuitBreakerConfig");
    check!(RetryConfig, "RetryConfig");
    check!(MeshEgressScopeSnapshot, "MeshEgressScopeSnapshot");
    check!(MeshEgressScopeResource, "MeshEgressScopeResource");
}

#[test]
fn mtls_auth_schemas_match_runtime_contract() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let credential = &spec["components"]["schemas"]["MtlsAuthCredential"];
    assert_eq!(credential["additionalProperties"], false);
    assert_eq!(credential["required"], json!(["identity"]));
    assert_eq!(credential["properties"]["identity"]["minLength"], 1);
    let credential_description = credential["properties"]["identity"]["description"]
        .as_str()
        .expect("identity description");
    assert!(credential_description.contains("`cert_field`"));
    assert!(!credential_description.contains("identity_source"));
    assert!(credential_description.contains("first matching value"));
    assert!(credential_description.contains("ASCII case-insensitive"));

    let config = &spec["components"]["schemas"]["MtlsAuthConfig"];
    assert_eq!(config["additionalProperties"], false);
    assert_eq!(config["properties"]["allowed_issuers"]["minItems"], 1);
    assert_eq!(
        config["properties"]["allowed_issuers"]["items"]["required"],
        json!(["ca_certificate_pem"])
    );
    assert_eq!(
        config["properties"]["allowed_issuers"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        config["properties"]["allowed_ca_fingerprints_sha256"]["minItems"],
        1
    );
    let description = config["description"]
        .as_str()
        .expect("mtls config description");
    for protocol in [
        "HTTP/1.1",
        "HTTP/2",
        "HTTP/3",
        "gRPC",
        "WebSocket",
        "TCP+TLS",
        "UDP+DTLS",
    ] {
        assert!(
            description.contains(protocol),
            "missing protocol {protocol}"
        );
    }
}

#[test]
fn auth_mode_and_basic_credential_response_contracts_are_truthful() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let auth_mode = spec["components"]["schemas"]["AuthMode"]["description"]
        .as_str()
        .expect("AuthMode description");
    let scoped_scheme_contract = "For `basic_auth` and the Bearer-token mechanisms `jwt_auth`, \
                                  `jwks_auth`, and `oauth2_introspection`, a foreign \
                                  `Authorization` scheme is skipped; other mechanisms are not \
                                  covered by this guarantee.";
    let normalized_auth_mode = auth_mode.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_auth_mode.contains(scoped_scheme_contract));
    assert!(normalized_auth_mode.contains("Any rejection returned by a plugin is terminal"));
    assert!(normalized_auth_mode.contains("run sequentially until one succeeds"));
    assert!(normalized_auth_mode.contains("server rejection takes precedence"));

    let plugin_docs = include_str!("../../docs/plugins.md");
    assert!(plugin_docs.contains(scoped_scheme_contract));

    let basic_roundtrip_contract = "When `basicauth` is omitted from the request, an existing \
                                    Basic credential type is preserved; use `DELETE \
                                    /consumers/{id}/credentials/basicauth` to remove it.";
    let consumer_update = spec["paths"]["/consumers/{id}"]["put"]["description"]
        .as_str()
        .expect("Consumer update description");
    assert!(consumer_update.contains(basic_roundtrip_contract));
    let admin_docs = include_str!("../../docs/admin_api.md");
    assert!(admin_docs.contains(basic_roundtrip_contract));

    let consumer_credentials =
        &spec["components"]["schemas"]["Consumer"]["properties"]["credentials"];
    let credentials_description = consumer_credentials["description"]
        .as_str()
        .expect("Consumer credentials description");
    assert!(credentials_description.contains("responses omit `basicauth` entirely"));

    let password_hash =
        &spec["components"]["schemas"]["BasicAuthCredential"]["properties"]["password_hash"];
    assert_eq!(password_hash["pattern"], "^hmac_sha256:[0-9a-f]{64}$");
    assert!(password_hash.get("writeOnly").is_none());

    let password = &spec["components"]["schemas"]["BasicAuthCredential"]["properties"]["password"];
    let password_pattern = password["pattern"].as_str().expect("password pattern");
    assert_eq!(password_pattern, r"^[^\x00-\x08\x0B\x0C\x0E-\x1F]*$");
    let password_pattern = Regex::new(password_pattern).expect("password pattern compiles");
    assert!(!password_pattern.is_match("embedded\0null"));
    assert!(password_pattern.is_match("tabs\tand\nnewlines\rremain valid"));

    let plugin_config = &spec["components"]["schemas"]["PluginConfig"];
    let config_description = plugin_config["properties"]["config"]["description"]
        .as_str()
        .expect("PluginConfig config description");
    assert!(config_description.contains("Disabled plugin configs are stored without construction"));
    assert!(config_description.contains("Enabling performs full validation"));

    let audit_diff_description = spec["components"]["schemas"]["AuditEvent"]["properties"]["diff"]
        ["description"]
        .as_str()
        .expect("AuditEvent diff description");
    assert!(audit_diff_description.contains("stable `[REDACTED]` marker"));
    assert!(audit_diff_description.contains("never values, entry fields, shape, or count"));

    assert_eq!(
        spec["paths"]["/batch"]["post"]["responses"]["500"]["$ref"],
        "#/components/responses/InternalServerError"
    );
}

fn normalized_path_template(path: &str) -> String {
    static PATH_PARAMETER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\{[^}]+\}").expect("path-template regex compiles"));
    PATH_PARAMETER.replace_all(path, "{}").into_owned()
}

fn openapi_operations(spec: &serde_json::Value) -> BTreeSet<(String, String)> {
    let paths = spec["paths"]
        .as_object()
        .expect("OpenAPI paths is an object");
    let mut operations = BTreeSet::new();

    for (path, path_item) in paths {
        let path_item = path_item
            .as_object()
            .unwrap_or_else(|| panic!("path item {path} is an object"));
        for method in OPENAPI_HTTP_METHODS {
            if path_item.contains_key(*method) {
                operations.insert((method.to_ascii_uppercase(), normalized_path_template(path)));
            }
        }
    }

    operations
}

fn implemented_admin_operations() -> BTreeSet<(String, String)> {
    let source = include_str!("../../src/admin/mod.rs");
    let match_arm =
        Regex::new(r#"\(Method::(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS),\s*\[([^\]]*)\]\)"#)
            .expect("admin match-arm regex compiles");
    let direct_guard =
        Regex::new(r#"if\s+path\s*==\s*"([^"]+)"\s*&&\s*method\s*==\s*Method::([A-Z]+)"#)
            .expect("direct-route regex compiles");
    let mut operations = BTreeSet::new();

    for captures in match_arm.captures_iter(source) {
        let method = captures[1].to_string();
        let segments = captures[2]
            .split(',')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                if let Some(literal) = segment
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                {
                    return literal;
                }

                static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
                    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")
                        .expect("Rust identifier regex compiles")
                });
                assert!(
                    IDENTIFIER.is_match(segment),
                    "unsupported admin route pattern segment `{segment}`; update the inventory parser explicitly"
                );
                "{}"
            })
            .collect::<Vec<_>>();
        operations.insert((method, format!("/{}", segments.join("/"))));
    }

    for captures in direct_guard.captures_iter(source) {
        operations.insert((captures[2].to_string(), captures[1].to_string()));
    }

    // These probe handlers intentionally run before method-based dispatch.
    // Keep their intended public GET contract explicit so adding another
    // method-agnostic direct handler requires a conscious test update.
    for path in ["/live", "/health", "/status"] {
        assert!(source.contains(&format!("path == \"{path}\"")));
        operations.insert(("GET".to_string(), path.to_string()));
    }

    operations
}

#[test]
fn every_documented_operation_matches_an_admin_dispatch_route() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    assert_eq!(
        openapi_operations(&spec),
        implemented_admin_operations(),
        "OpenAPI and src/admin/mod.rs method/path inventories diverged"
    );
}

fn collect_openapi_inventory(
    value: &serde_json::Value,
    refs: &mut BTreeSet<String>,
    deprecated_nullable_paths: &mut Vec<String>,
    path: &str,
) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}/{key}");
                if key == "$ref" {
                    refs.insert(
                        child
                            .as_str()
                            .unwrap_or_else(|| panic!("$ref at {child_path} is a string"))
                            .to_string(),
                    );
                }
                if key == "nullable" {
                    deprecated_nullable_paths.push(child_path.clone());
                }
                collect_openapi_inventory(child, refs, deprecated_nullable_paths, &child_path);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                collect_openapi_inventory(
                    child,
                    refs,
                    deprecated_nullable_paths,
                    &format!("{path}/{index}"),
                );
            }
        }
        _ => {}
    }
}

#[test]
fn openapi_inventory_has_unique_operations_resolved_refs_and_no_orphan_schemas() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut operation_ids = Vec::new();

    for (path, path_item) in spec["paths"].as_object().expect("paths is an object") {
        let path_item = path_item
            .as_object()
            .unwrap_or_else(|| panic!("path item {path} is an object"));
        for method in OPENAPI_HTTP_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            operation_ids.push(
                operation["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} is missing operationId"))
                    .to_string(),
            );
            assert!(
                operation["responses"]
                    .as_object()
                    .is_some_and(|value| !value.is_empty()),
                "{method} {path} must document at least one response"
            );
        }
    }

    let unique_operation_ids: BTreeSet<_> = operation_ids.iter().collect();
    assert_eq!(
        operation_ids.len(),
        unique_operation_ids.len(),
        "operationId values must be unique"
    );

    let mut refs = BTreeSet::new();
    let mut deprecated_nullable_paths = Vec::new();
    collect_openapi_inventory(&spec, &mut refs, &mut deprecated_nullable_paths, "");
    assert!(
        deprecated_nullable_paths.is_empty(),
        "OpenAPI 3.1 must use native null unions instead of nullable: {deprecated_nullable_paths:?}"
    );

    for reference in &refs {
        let pointer = reference
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("external OpenAPI reference is unsupported: {reference}"));
        assert!(
            spec.pointer(pointer).is_some(),
            "unresolved OpenAPI reference: {reference}"
        );
    }

    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("component schemas is an object");
    let mut path_refs = BTreeSet::new();
    let mut ignored_nullable_paths = Vec::new();
    collect_openapi_inventory(
        &spec["paths"],
        &mut path_refs,
        &mut ignored_nullable_paths,
        "/paths",
    );
    let mut pending_refs: Vec<_> = path_refs.into_iter().collect();
    let mut reachable_refs = BTreeSet::new();
    while let Some(reference) = pending_refs.pop() {
        if !reachable_refs.insert(reference.clone()) {
            continue;
        }
        let pointer = reference
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("external OpenAPI reference is unsupported: {reference}"));
        let referenced_value = spec
            .pointer(pointer)
            .unwrap_or_else(|| panic!("unresolved OpenAPI reference: {reference}"));
        let mut nested_refs = BTreeSet::new();
        collect_openapi_inventory(
            referenced_value,
            &mut nested_refs,
            &mut ignored_nullable_paths,
            pointer,
        );
        pending_refs.extend(nested_refs);
    }

    let referenced_schemas: BTreeSet<_> = reachable_refs
        .iter()
        .filter_map(|reference| {
            reference
                .strip_prefix("#/components/schemas/")
                .and_then(|suffix| suffix.split('/').next())
        })
        .collect();
    let orphan_schemas: Vec<_> = schemas
        .keys()
        .filter(|schema| !referenced_schemas.contains(schema.as_str()))
        .collect();
    assert!(
        orphan_schemas.is_empty(),
        "unreferenced component schemas: {orphan_schemas:?}"
    );

    for schema_name in schemas.keys() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("#/components/schemas/{schema_name}"),
            "components": spec["components"].clone()
        });
        jsonschema::draft202012::options()
            .build(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} schema compiles: {error}"));
    }
}

#[test]
fn waf_scoring_weights_reject_unknown_severities() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let weights = get_path(
        &spec,
        &[
            "components",
            "schemas",
            "WafPluginConfig",
            "properties",
            "scoring",
            "properties",
            "weights",
        ],
    );

    assert_eq!(
        weights
            .get(Value::String("additionalProperties".to_string()))
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn access_control_schema_matches_runtime_validation() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AccessControlConfig")
        .expect("missing AccessControlConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AccessControlConfig schema compiles");

    for config in [
        json!({"allowed_consumers": ["alice"]}),
        json!({"disallowed_consumers": ["bad"], "allow_authenticated_identity": true}),
        json!({"allow_authenticated_identity": true}),
        json!({"allow_authenticated_identity": true, "allowed_consumers": []}),
        json!({"allowed_consumers": ["  alice  "]}),
        // U+FEFF ZWNBSP is not in Rust's Unicode White_Space set.
        json!({"allowed_consumers": ["\u{feff}"]}),
        json!({"disallowed_consumers": ["\u{feff}"]}),
        json!({"allowed_groups": ["\u{feff}"]}),
        json!({"disallowed_groups": ["\u{feff}"]}),
        json!({"allowed_consumers": ["é".repeat(255)]}),
        json!({"allowed_groups": ["é".repeat(255)]}),
        json!({"disallowed_groups": ["é".repeat(255)]}),
        json!({
            "disallowed_consumers": ["é".repeat(4096)],
            "allow_authenticated_identity": true
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
        assert!(
            ferrum_edge::plugins::validate_plugin_config("access_control", &config).is_ok(),
            "runtime should accept schema-valid config: {config}"
        );
    }

    for config in [
        json!({}),
        json!({"allowed_consumer": ["alice"]}),
        json!({"allowed_consumers": [], "allowed_groups": []}),
        json!({"allowed_consumers": ["alice"], "allow_authenticated_identity": true}),
        json!({"allowed_groups": ["engineering"], "allow_authenticated_identity": true}),
        json!({"allowed_consumers": [""]}),
        json!({"disallowed_consumers": [""]}),
        json!({"allowed_groups": [""]}),
        json!({"disallowed_groups": [""]}),
        json!({"allowed_consumers": ["   "]}),
        json!({"disallowed_consumers": ["\t"]}),
        json!({"allowed_groups": ["\n"]}),
        json!({"disallowed_groups": ["   "]}),
        // U+0085 NEL is in Rust's Unicode White_Space set.
        json!({"allowed_consumers": ["\u{0085}"]}),
        json!({"disallowed_consumers": ["\u{0085}"]}),
        json!({"allowed_groups": ["\u{0085}"]}),
        json!({"disallowed_groups": ["\u{0085}"]}),
        json!({"allowed_consumers": ["a".repeat(256)]}),
        json!({
            "disallowed_consumers": ["a".repeat(4097)],
            "allow_authenticated_identity": true
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
        assert!(
            ferrum_edge::plugins::validate_plugin_config("access_control", &config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }
}

#[test]
fn grpc_method_router_schema_matches_runtime_validation() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/GrpcMethodRouterConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("GrpcMethodRouterConfig schema compiles");

    for config in [
        json!({"allow_methods": []}),
        json!({"deny_methods": ["pkg.Service/Denied"]}),
        json!({"deny_methods": [" /pkg.Service/Denied "]}),
        json!({
            "method_rate_limits": {
                "/pkg.Service/Call": {"max_requests": 1, "window_seconds": 60}
            }
        }),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379/0",
            "redis_key_prefix": "ferrum:grpc",
            "redis_pool_size": 1,
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 1
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({}),
        json!({"deny_methods": []}),
        json!({"method_rate_limits": {}}),
        json!({"deny_methods": ["not-a-grpc-method"]}),
        json!({"deny_methods": ["pkg.Service/Method", "pkg.Service/Method"]}),
        json!({
            "method_rate_limits": {
                "pkg.Service/Call/Extra": {"max_requests": 1, "window_seconds": 60}
            }
        }),
        json!({
            "method_rate_limits": {
                "pkg.Service/Call": {"max_requests": 0, "window_seconds": 60}
            }
        }),
        json!({"deny_methods": ["pkg.Service/Denied"], "sync_mode": "redis"}),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": ""
        }),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": "http://localhost:6379"
        }),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_key_prefix": ""
        }),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_pool_size": 0
        }),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_connect_timeout_seconds": 0
        }),
        json!({
            "deny_methods": ["pkg.Service/Denied"],
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_health_check_interval_seconds": 0
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

#[test]
fn key_auth_location_schema_matches_runtime_whitespace_contract() {
    use ferrum_edge::plugins::key_auth::KeyAuth;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/KeyAuthConfig")
        .expect("missing KeyAuthConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("KeyAuthConfig schema compiles");

    for (key_location, expected_valid) in [
        ("header:X-API-Key", true),
        ("header:X-Tenant_Key~V2", true),
        ("query:api_key", true),
        ("query:tenant-key.v2", true),
        (" header:X-API-Key", false),
        ("header:X-API-Key ", false),
        ("header: X-API-Key", false),
        ("query: api_key", false),
        ("query:api_key ", false),
        ("query:   ", false),
        ("query:tenant key", false),
    ] {
        let config = json!({"key_location": key_location});
        let schema_valid = validator.validate(&config).is_ok();
        let runtime_valid = KeyAuth::new(&config).is_ok();
        assert_eq!(
            schema_valid, expected_valid,
            "unexpected OpenAPI result for {key_location:?}"
        );
        assert_eq!(
            runtime_valid, expected_valid,
            "unexpected runtime result for {key_location:?}"
        );
        assert_eq!(
            schema_valid, runtime_valid,
            "OpenAPI/runtime key_location drift for {key_location:?}"
        );
    }
}

#[test]
fn ldap_auth_schema_matches_runtime_invariants() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for config in [
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "starttls": true
        }),
        json!({
            "ldap_url": "ldap://directory.example.test:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "allow_plaintext": true
        }),
        json!({
            "ldap_url": "ldap://127.0.0.1:389",
            "bind_dn_template": "uid={username},dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldap://LOCALHOST:389",
            "bind_dn_template": "uid={username},dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "secret"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "required_groups": ["admins"]
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": "(member={user_dn})",
            "required_groups": ["admins"],
            "connect_timeout_seconds": 300,
            "request_timeout_seconds": 300,
            "max_concurrent_requests": 1024,
            "cache_ttl_seconds": 86400,
            "max_cache_entries": 1
        }),
    ] {
        assert_component_validity(&spec, "LdapAuthConfig", &config, true);
    }

    for config in [
        json!({"ldap_url": "ldaps://ldap.example.com:636"}),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid=static,dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid=static)",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "secret"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "required_groups": ["admins"]
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": "(cn=admins)",
            "required_groups": ["admins"]
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "starttls": true
        }),
        json!({
            "ldap_url": "ldap://directory.example.test:389",
            "bind_dn_template": "uid={username},dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldaps://admin:secret@ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "connect_timeout_seconds": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "request_timeout_seconds": 301
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "max_concurrent_requests": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "cache_ttl_seconds": 86401
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "max_cache_entries": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "required_group": ["admins"]
        }),
    ] {
        assert_component_validity(&spec, "LdapAuthConfig", &config, false);
    }
}

#[test]
fn ldap_dial_policy_documentation_matches_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/LdapAuthConfig")
        .expect("LdapAuthConfig exists");
    let schema_description = schema["description"]
        .as_str()
        .expect("LdapAuthConfig description");
    let url_description = schema["properties"]["ldap_url"]["description"]
        .as_str()
        .expect("ldap_url description");
    assert!(schema_description.contains("uncached A+AAAA lookup"));
    assert!(schema_description.contains("TLS/SNI verification"));
    assert!(url_description.contains("policy-screens all A/AAAA candidates"));

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("**Dial-time DNS and egress policy:**"));
    assert!(guide.contains("screened again immediately before its TCP dial"));
    assert!(guide.contains("service-account and end-user connections"));
}

#[test]
fn ldap_cache_documentation_and_openapi_defaults_match_runtime_constants() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/LdapAuthConfig/properties")
        .expect("LdapAuthConfig properties exist");
    assert_eq!(
        schema["cache_ttl_seconds"]["default"],
        json!(ferrum_edge::plugins::ldap_auth::LDAP_AUTH_DEFAULT_CACHE_TTL_SECONDS)
    );
    assert_eq!(
        schema["cache_ttl_seconds"]["maximum"],
        json!(ferrum_edge::plugins::ldap_auth::LDAP_AUTH_MAX_CACHE_TTL_SECONDS)
    );
    assert_eq!(
        schema["max_cache_entries"]["default"],
        json!(ferrum_edge::plugins::ldap_auth::LDAP_AUTH_DEFAULT_MAX_CACHE_ENTRIES)
    );

    let guide = include_str!("../../docs/cache_management.md");
    assert!(guide.contains("**Default limit:** 10,000 entries. Caching is disabled by default."));
    assert!(guide.contains("`cache_ttl_seconds` (default `0`, disabled; maximum `86,400`"));
    assert!(guide.contains("`max_cache_entries` (default `10,000`)"));
    assert!(guide.contains("| `ldap_auth` | `max_cache_entries` | `10000` |"));
    assert!(guide.contains("| `ldap_auth` | `cache_ttl_seconds` | `0` |"));
}

#[test]
fn jwks_auth_schema_and_cache_guide_match_runtime_contract() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/JwksAuthConfig")
        .expect("JwksAuthConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["providers"]["items"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        schema["properties"]["providers"]["items"]["properties"]["from_headers"]["items"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        schema["properties"]["jwks_refresh_interval_secs"]["default"],
        json!(ferrum_edge::plugins::jwks_auth::DEFAULT_JWKS_REFRESH_INTERVAL_SECS)
    );
    assert_eq!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_jti_cache_max_entries"]["default"],
        json!(ferrum_edge::plugins::jwks_auth::DEFAULT_DPOP_JTI_CACHE_MAX_ENTRIES)
    );

    let guide = include_str!("../../docs/cache_management.md");
    assert!(guide.contains("`jwks_refresh_interval_secs`, default `900` seconds"));
    assert!(guide.contains("| `jwks_auth` | `jwks_refresh_interval_secs` | `900` |"));
    assert!(!guide.contains("| `jwks_auth` | `cache_ttl_seconds`"));
}

#[test]
fn ai_tool_governor_schema_matches_runtime_invariants() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/AiToolGovernorConfig"
    });
    schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("AiToolGovernorConfig schema compiles");

    for config in [
        json!({
            "enabled": false,
            "mode": "ignored-invalid-mode",
            "default_action": "ignored-invalid-action",
            "tools": {"": {"action": "ignored-invalid-action"}},
            "inspect": "ignored-invalid-inspection",
            "approval": "ignored-invalid-approval"
        }),
        json!({"default_action": "deny", "tools": {}}),
        json!({"tools": {"search": {"action": "allow"}}}),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "required_args": ["query"],
                    "blocked_arg_patterns": [{"name": "secret", "regex": "secret"}]
                }
            }
        }),
        json!({
            "default_action": "allow",
            "tools": {"deploy": {"action": "require_approval"}},
            "inspect": {"request_tool_definitions": true, "response_tool_calls": false}
        }),
        json!({
            "mode": "dry_run",
            "tools": {"deploy": {"action": "require_approval"}}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "https://approval.example/decide"}
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({
            "tools": {"search": {"action": "allow"}},
            "inspect": {
                "request_tool_definitions": false,
                "response_tool_calls": false,
                "streaming_response_tool_calls": false,
                "mcp_tool_calls": false,
                "a2a_methods": false
            }
        }),
        json!({"default_action": "allow"}),
        json!({"default_action": "allow", "tools": {}}),
        json!({"tools": {"": {"action": "deny"}}}),
        json!({"tools": {"search": {"action": "redact_args"}}}),
        json!({
            "tools": {"search": {"action": "redact_args", "blocked_arg_patterns": []}}
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "", "regex": "secret"}]
                }
            }
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "secret", "regex": ""}]
                }
            }
        }),
        json!({"tools": {"deploy": {"action": "require_approval"}}}),
        json!({"default_action": "require_approval", "tools": {}}),
        json!({"tools": {"search": {"action": "allow", "required_args": [""]}}}),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": ""}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "ftp://approval.example/decide"}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "https:///decide"}
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

fn plugin_config_schema_mapping(spec: &serde_json::Value) -> BTreeMap<String, String> {
    let all_of = spec
        .pointer("/components/schemas/PluginConfig/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("PluginConfig allOf should be an array");

    let mut mapping = BTreeMap::new();
    for entry in all_of {
        let plugin_name = entry
            .pointer("/if/properties/plugin_name/const")
            .and_then(serde_json::Value::as_str)
            .expect("PluginConfig conditional should name a plugin");
        let schema_ref = entry
            .pointer("/then/properties/config/$ref")
            .and_then(serde_json::Value::as_str)
            .expect("PluginConfig conditional should constrain config");

        assert!(
            mapping
                .insert(plugin_name.to_string(), schema_ref.to_string())
                .is_none(),
            "duplicate PluginConfig schema conditional for {plugin_name}"
        );
    }

    mapping
}

#[test]
fn plugin_config_schema_maps_every_builtin_plugin() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let custom_plugins: BTreeSet<_> = ferrum_edge::custom_plugins::custom_plugin_names()
        .into_iter()
        .collect();
    let builtins: BTreeSet<_> = ferrum_edge::plugins::available_plugins()
        .into_iter()
        .filter(|name| !custom_plugins.contains(name))
        .collect();

    let mapping = plugin_config_schema_mapping(&spec);
    let documented: BTreeSet<_> = mapping.keys().map(String::as_str).collect();

    assert_eq!(
        documented, builtins,
        "PluginConfig schema conditionals should cover every built-in plugin"
    );
    assert!(
        !mapping.contains_key("semantic_ai_firewall"),
        "undocumented ai_semantic_firewall alias must not re-enter OpenAPI"
    );

    for (plugin_name, schema_ref) in mapping {
        let schema_name = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        let pointer = format!("/components/schemas/{schema_name}");
        assert!(
            spec.pointer(&pointer).is_some(),
            "PluginConfig ref for {plugin_name} points to missing schema {schema_name}"
        );
    }
}

#[test]
fn plugin_config_schema_applies_plugin_specific_config() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/PluginConfig"
    });
    schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());

    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("PluginConfig schema compiles");
    let plugin_config =
        |plugin_name: &str, config: Option<serde_json::Value>| -> serde_json::Value {
            let mut value = json!({
                "plugin_name": plugin_name,
                "scope": "global",
                "enabled": true
            });
            if let Some(config) = config {
                value
                    .as_object_mut()
                    .expect("plugin config should be object")
                    .insert("config".to_string(), config);
            }
            value
        };

    let valid = json!({
        "plugin_name": "ws_message_size_limiting",
        "scope": "global",
        "enabled": true,
        "config": {"max_frame_bytes": 1024}
    });
    assert!(validator.validate(&valid).is_ok(), "config should be valid");

    let invalid = json!({
        "plugin_name": "ws_message_size_limiting",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert!(
        validator.validate(&invalid).is_err(),
        "ws_message_size_limiting should require max_frame_bytes through PluginConfig"
    );

    for (plugin_name, config) in [
        ("bot_detection", json!({})),
        ("udp_rate_limiting", json!({"datagrams_per_second": 100})),
        (
            "fault_injection",
            json!({"abort": {"status_code": 503, "percentage": 5.0}}),
        ),
        ("ai_rate_limiter", json!({"token_limit": 100000})),
        ("ai_request_guard", json!({"max_tokens_limit": 2048})),
        ("ai_response_guard", json!({"require_json": true})),
        ("ai_semantic_firewall", json!({"enabled": false})),
        (
            "ai_semantic_firewall",
            json!({
                "provider": {
                    "type": "openai_compatible_embeddings",
                    "endpoint": "https://embeddings.example/v1"
                }
            }),
        ),
    ] {
        let value = plugin_config(plugin_name, Some(config));
        assert!(
            validator.validate(&value).is_ok(),
            "{plugin_name} config should be valid: {value}"
        );
    }

    for (plugin_name, config) in [
        ("bot_detection", None),
        ("bot_detection", Some(serde_json::Value::Null)),
        ("bot_detection", Some(json!([]))),
        ("udp_rate_limiting", None),
        ("udp_rate_limiting", Some(json!({}))),
        ("fault_injection", None),
        ("fault_injection", Some(json!({}))),
        ("ai_rate_limiter", None),
        ("ai_rate_limiter", Some(json!({}))),
        ("ai_rate_limiter", Some(json!({"token_limit": 0}))),
        ("ai_request_guard", None),
        ("ai_request_guard", Some(json!({}))),
        ("ai_request_guard", Some(json!({"allowed_models": []}))),
        (
            "ai_request_guard",
            Some(json!({"require_user_field": false})),
        ),
        (
            "ai_request_guard",
            Some(json!({"max_messages": 10, "max_message": 10})),
        ),
        ("ai_response_guard", None),
        ("ai_response_guard", Some(json!({}))),
        ("ai_response_guard", Some(json!({"require_json": false}))),
        ("ai_response_guard", Some(json!({"blocked_phrases": []}))),
        ("ai_semantic_firewall", None),
        ("ai_semantic_firewall", Some(json!({}))),
    ] {
        let value = plugin_config(plugin_name, config);
        assert!(
            validator.validate(&value).is_err(),
            "{plugin_name} config should be invalid: {value}"
        );
    }

    let custom = json!({
        "plugin_name": "custom_observer",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert!(
        validator.validate(&custom).is_ok(),
        "custom plugins should keep generic PluginConfig config shape"
    );
}

#[tokio::test]
async fn runtime_valid_builtin_plugin_fixtures_match_their_openapi_schemas() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mapping = plugin_config_schema_mapping(&spec);
    let mut exercised = 0usize;

    for (plugin_name, schema_ref) in mapping {
        let config = super::plugins::minimal_plugin_config(&plugin_name);
        let Ok(Some(_plugin)) = ferrum_edge::plugins::create_plugin(&plugin_name, &config) else {
            continue;
        };
        let component = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        assert_component_validity(&spec, component, &config, true);
        exercised += 1;
    }

    assert!(
        exercised >= 50,
        "expected broad plugin-schema coverage, exercised only {exercised} built-ins"
    );
}

#[tokio::test]
async fn optional_builtin_plugin_fields_match_runtime_and_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mapping = plugin_config_schema_mapping(&spec);
    let fixtures = [
        (
            "body_validator",
            json!({"grpc_max_decompressed_size_bytes": 0}),
        ),
        (
            "load_testing",
            json!({
                "key": "test-key",
                "concurrent_clients": 1,
                "duration_seconds": 1,
                "max_response_body_bytes": 1024
            }),
        ),
        (
            "request_mirror",
            json!({"mirror_host": "mirror.example", "max_in_flight": 8}),
        ),
        (
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "x-audit",
                    "value": "enabled"
                }],
                "runtime_overlay_scope": "ferrum.transform.request",
                "default_enabled": false
            }),
        ),
        (
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "x-audit",
                    "value": "enabled"
                }],
                "runtime_overlay_scope": "ferrum.transform.response",
                "default_enabled": false
            }),
        ),
        (
            "fault_injection",
            json!({
                "abort": {"status_code": 503, "percentage": 1.0},
                "runtime_overlay_scope": "checkout"
            }),
        ),
        (
            "serverless_function",
            json!({
                "provider": "aws_lambda",
                "aws_region": "us-east-1",
                "aws_access_key_id": "test-access-key",
                "aws_secret_access_key": "test-secret-key",
                "aws_function_name": "test-function",
                "aws_endpoint_url": "http://127.0.0.1:4566"
            }),
        ),
        (
            "mesh_authz",
            json!({
                "mesh_policies": [],
                "per_pod_policy_scoping": true,
                "ambient_udp_source_scoping": true,
                "cluster_domain": "cluster.local",
                "cluster_domains": ["cluster.local", "cluster.internal"],
                "node_waypoint_route_upstreams": [{
                    "id": "istio-vs-upstream-reviews",
                    "namespace": "ferrum",
                    "targets": [{
                        "host": "10.0.0.10",
                        "port": 8080,
                        "service_namespace": "ferrum",
                        "service_name": "reviews",
                        "service_port": 80
                    }]
                }]
            }),
        ),
    ];

    for (plugin_name, optional_fields) in fixtures {
        let mut config = super::plugins::minimal_plugin_config(plugin_name);
        let config_object = config
            .as_object_mut()
            .unwrap_or_else(|| panic!("minimal {plugin_name} config is not an object"));
        config_object.extend(
            optional_fields
                .as_object()
                .unwrap_or_else(|| panic!("optional {plugin_name} fields are not an object"))
                .clone(),
        );
        let created = ferrum_edge::plugins::create_plugin(plugin_name, &config)
            .unwrap_or_else(|error| panic!("runtime rejected {plugin_name} fixture: {error}"));
        assert!(created.is_some(), "missing built-in plugin {plugin_name}");
        let schema_ref = mapping
            .get(plugin_name)
            .unwrap_or_else(|| panic!("missing OpenAPI mapping for {plugin_name}"));
        let component = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        assert_component_validity(&spec, component, &config, true);
    }

    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({"provider": "azure_functions"}),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({"provider": "gcp_cloud_functions", "function_url": "ftp://functions.example"}),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "aws_lambda",
            "aws_endpoint_url": "ftp://lambda.example"
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "aws_lambda",
            "function_url": "not-a-url"
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "azure_functions",
            "function_url": "https:///api/transform"
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "aws_lambda",
            "aws_endpoint_url": "http:///lambda"
        }),
        false,
    );

    for component in ["RequestTransformerConfig", "ResponseTransformerConfig"] {
        assert_component_validity(
            &spec,
            component,
            &json!({
                "rules": [{"operation": "remove", "key": "x-review-pin"}],
                "runtime_overlay_scope": " \t "
            }),
            false,
        );
    }

    for invalid_scope in [json!(""), json!(" \t "), json!(42), json!(true)] {
        assert_component_validity(
            &spec,
            "FaultInjectionConfig",
            &json!({
                "abort": {"status_code": 503, "percentage": 1.0},
                "runtime_overlay_scope": invalid_scope
            }),
            false,
        );
    }
    assert_component_validity(
        &spec,
        "FaultInjectionConfig",
        &json!({
            "abort": {"status_code": 503, "percentage": 1.0},
            "runtime_overlay_scope": null
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "FaultInjectionConfig",
        &json!({"delay": {"duration_ms": 60_000, "percentage": f64::from_bits(1)}}),
        true,
    );
    assert_component_validity(
        &spec,
        "FaultInjectionConfig",
        &json!({"delay": {"duration_ms": 60_001, "percentage": 1.0}}),
        false,
    );
    for valid in [
        json!({
            "abort": null,
            "delay": {"duration_ms": 1, "percentage": 1.0}
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 1.0},
            "delay": null
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 1.0},
            "delay": {"duration_ms": 1, "percentage": 1.0}
        }),
    ] {
        assert_component_validity(&spec, "FaultInjectionConfig", &valid, true);
    }
    for invalid in [
        json!({"abort": null}),
        json!({"delay": null}),
        json!({"abort": null, "delay": null}),
    ] {
        assert_component_validity(&spec, "FaultInjectionConfig", &invalid, false);
    }
}

fn assert_component_validity(
    spec: &serde_json::Value,
    component: &str,
    instance: &serde_json::Value,
    expected_valid: bool,
) {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/components/schemas/{component}"),
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .unwrap_or_else(|error| panic!("{component} schema compiles: {error}"));
    let actual_valid = validator.validate(instance).is_ok();
    assert_eq!(
        actual_valid, expected_valid,
        "unexpected {component} validation result for {instance}"
    );
}

#[tokio::test]
async fn loki_logging_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::loki_logging::{
        LOKI_DEFAULT_BUFFER_MAX_BYTES, LOKI_DEFAULT_MAX_ENTRY_BYTES, LOKI_LOGGING_CONFIG_KEYS,
        LOKI_MAX_BUFFER_MAX_BYTES, LOKI_MAX_CUSTOM_HEADER_NAME_BYTES, LOKI_MAX_MAX_ENTRY_BYTES,
        LOKI_MAX_RETRIES, LOKI_MAX_RETRY_DELAY_MS, LokiLogging,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/LokiLoggingConfig")
        .expect("LokiLoggingConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["labels"]["additionalProperties"]["type"],
        "string"
    );
    assert!(schema["properties"]["custom_headers"]["additionalProperties"].is_object());

    let documented = schema["properties"]
        .as_object()
        .expect("Loki properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = LOKI_LOGGING_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "Loki runtime/OpenAPI key drift");
    assert_eq!(
        schema["properties"]["max_entry_bytes"]["default"],
        json!(LOKI_DEFAULT_MAX_ENTRY_BYTES)
    );
    assert_eq!(
        schema["properties"]["max_entry_bytes"]["maximum"],
        json!(LOKI_MAX_MAX_ENTRY_BYTES)
    );
    assert_eq!(
        schema["properties"]["buffer_max_bytes"]["default"],
        json!(LOKI_DEFAULT_BUFFER_MAX_BYTES)
    );
    assert_eq!(
        schema["properties"]["buffer_max_bytes"]["maximum"],
        json!(LOKI_MAX_BUFFER_MAX_BYTES)
    );
    assert_eq!(
        schema["properties"]["max_retries"]["maximum"],
        json!(LOKI_MAX_RETRIES)
    );
    assert_eq!(
        schema["properties"]["retry_delay_ms"]["maximum"],
        json!(LOKI_MAX_RETRY_DELAY_MS)
    );
    assert_eq!(
        schema["properties"]["custom_headers"]["propertyNames"]["maxLength"],
        json!(LOKI_MAX_CUSTOM_HEADER_NAME_BYTES)
    );

    let valid = json!({
        "endpoint_url": "HTTPS://logs.example.com/loki/api/v1/push?tenant=dynamic",
        "authorization_header": "Bearer test",
        "custom_headers": {"X-Scope-OrgID": "tenant-a", "X-Dynamic": "value"},
        "labels": {"service": "edge", "tenant_name": "tenant-a"},
        "include_proxy_id_label": false,
        "include_status_class_label": true,
        "gzip": false,
        "batch_size": 10000,
        "flush_interval_ms": 100,
        "buffer_capacity": 1000000,
        "max_entry_bytes": LOKI_MAX_MAX_ENTRY_BYTES,
        "buffer_max_bytes": LOKI_MAX_BUFFER_MAX_BYTES,
        "max_retries": LOKI_MAX_RETRIES,
        "retry_delay_ms": LOKI_MAX_RETRY_DELAY_MS,
        "schema": {}
    });
    assert_component_validity(&spec, "LokiLoggingConfig", &valid, true);
    assert!(LokiLogging::new(&valid, PluginHttpClient::default()).is_ok());
    let valid_minima = json!({
        "endpoint_url": "http://127.0.0.1:3100/loki/api/v1/push",
        "labels": {"_a": ""},
        "batch_size": 1,
        "flush_interval_ms": 100,
        "buffer_capacity": 1,
        "max_entry_bytes": 2048,
        "buffer_max_bytes": 2048,
        "max_retries": 0,
        "retry_delay_ms": 1
    });
    assert_component_validity(&spec, "LokiLoggingConfig", &valid_minima, true);
    assert!(LokiLogging::new(&valid_minima, PluginHttpClient::default()).is_ok());

    let mut invalid = vec![
        json!({"endpoint_url": "https://logs.example.com/push", "endpont_url": "typo"}),
        json!({"endpoint_url": "https://user:secret@logs.example.com/push"}),
        json!({"endpoint_url": "https://logs.example.com/push", "labels": {"__tenant": "x"}}),
        json!({"endpoint_url": "https://logs.example.com/push", "labels": {"ferrum_emitter": "x"}}),
        json!({"endpoint_url": "https://logs.example.com/push", "labels": {"tenant": "x".repeat(2049)}}),
        json!({"endpoint_url": "https://logs.example.com/push", "authorization_header": "   "}),
        json!({"endpoint_url": "https://logs.example.com/push", "authorization_header": " Bearer test"}),
        json!({"endpoint_url": "https://logs.example.com/push", "authorization_header": "Bearer test\t"}),
        json!({"endpoint_url": "https://logs.example.com/push", "custom_headers": {"Bad Header": "x"}}),
        json!({"endpoint_url": "https://logs.example.com/push", "custom_headers": {"X-Bad": "bad\nvalue"}}),
        json!({"endpoint_url": "https://logs.example.com/push", "batch_size": 10001}),
        json!({"endpoint_url": "https://logs.example.com/push", "flush_interval_ms": 99}),
        json!({"endpoint_url": "https://logs.example.com/push", "buffer_capacity": 1000001}),
        json!({"endpoint_url": "https://logs.example.com/push", "max_retries": 11}),
        json!({"endpoint_url": "https://logs.example.com/push", "retry_delay_ms": 0}),
        json!({"endpoint_url": "https://logs.example.com/push", "max_entry_bytes": 1023}),
        json!({"endpoint_url": "https://logs.example.com/push", "buffer_max_bytes": 268435457}),
    ];
    let oversized_header_name = "x".repeat(LOKI_MAX_CUSTOM_HEADER_NAME_BYTES + 1);
    let mut oversized_headers = serde_json::Map::new();
    oversized_headers.insert(oversized_header_name, json!("value"));
    invalid.push(json!({
        "endpoint_url": "https://logs.example.com/push",
        "custom_headers": oversized_headers
    }));
    for key in LOKI_LOGGING_CONFIG_KEYS {
        let mut config = json!({"endpoint_url": "https://logs.example.com/push"});
        config
            .as_object_mut()
            .expect("config object")
            .insert((*key).to_string(), serde_json::Value::Null);
        invalid.push(config);
    }
    for config in invalid {
        assert_component_validity(&spec, "LokiLoggingConfig", &config, false);
        assert!(
            LokiLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid Loki config: {config}"
        );
    }
}

#[test]
fn ip_restriction_schema_matches_the_strict_runtime_shape() {
    use ferrum_edge::plugins::ip_restriction::IpRestriction;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let component = &spec["components"]["schemas"]["IpRestrictionConfig"];
    assert_eq!(component["additionalProperties"], false);
    assert_eq!(component["anyOf"][0]["properties"]["allow"]["minItems"], 1);
    assert_eq!(component["anyOf"][1]["properties"]["deny"]["minItems"], 1);
    let description = component["description"]
        .as_str()
        .expect("IpRestrictionConfig has a description");
    assert!(description.contains("canonical unsigned decimal"));
    assert!(description.contains("mapped CIDRs accept only `/96`-`/128`"));

    for config in [
        json!({"allow": ["10.0.0.0/8"]}),
        json!({"allow": [], "deny": ["192.0.2.0/24"]}),
        json!({"allow": ["2001:db8::/32"], "deny": [], "mode": "deny_first"}),
    ] {
        assert_component_validity(&spec, "IpRestrictionConfig", &config, true);
        assert!(
            IpRestriction::new(&config).is_ok(),
            "runtime rejected schema-valid strict config: {config}"
        );
    }

    for config in [
        json!(null),
        json!([]),
        json!({}),
        json!({"allow": [], "deny": []}),
        json!({"allow": null, "deny": ["192.0.2.0/24"]}),
        json!({"allow": ["10.0.0.0/8"], "deny": null}),
        json!({"allow": ["10.0.0.0/8"], "mode": null}),
        json!({"allow": ["10.0.0.0/8"], "mod": "deny_first"}),
        json!({"alow": ["10.0.0.0/8"], "deny": ["192.0.2.0/24"]}),
        json!({"allow": "10.0.0.0/8"}),
        json!({"allow": [""]}),
        json!({"allow": ["   "]}),
    ] {
        assert_component_validity(&spec, "IpRestrictionConfig", &config, false);
        assert!(
            IpRestriction::new(&config).is_err(),
            "runtime accepted schema-invalid strict config: {config}"
        );
    }
}

#[test]
fn cors_schema_matches_strict_runtime_and_istio_projection_surface() {
    use ferrum_edge::plugins::cors::CorsPlugin;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/CorsConfig")
        .expect("CorsConfig schema");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["allowed_origins"]));
    assert_eq!(
        schema["properties"]["unmatched_preflights"]["enum"],
        json!(["forward", "ignore"])
    );

    let cases = [
        (json!({"allowed_origins": ["*"]}), true),
        (json!({"allowed_origins": ["*.example.com"]}), true),
        (
            json!({"allowed_origins": ["https://app.example:443"]}),
            true,
        ),
        (
            json!({"allowed_origins": ["HTTPS://BÜCHER.EXAMPLE:443"]}),
            true,
        ),
        (json!({"allowed_origins": [{"exact": "*"}]}), true),
        (
            json!({
                "allowed_origins": ["https://app.example"],
                "allowed_methods": [],
                "allowed_headers": [],
                "unmatched_preflights": "forward"
            }),
            true,
        ),
        (json!({}), false),
        (json!(true), false),
        (json!({"origins": ["*"]}), false),
        (json!({"allowed_origins": null}), false),
        (json!({"allowed_origins": ["not-an-origin"]}), false),
        (
            json!({"allowed_origins": ["https://app.example/path"]}),
            false,
        ),
        (
            json!({"allowed_origins": [{"exact": "*.example.com"}]}),
            false,
        ),
        (
            json!({"allowed_origins": ["*"], "allowed_methods": []}),
            false,
        ),
        (json!({"allowed_origins": ["*"], "max_age": -1}), false),
        (
            json!({
                "allowed_origins": ["*"],
                "unmatched_preflights": "FORWARD"
            }),
            false,
        ),
        (
            json!({
                "allowed_origins": ["*"],
                "unmatched_preflights": "forward",
                "preflight_continue": false
            }),
            false,
        ),
    ];
    for (config, expected) in cases {
        assert_component_validity(&spec, "CorsConfig", &config, expected);
        assert_eq!(
            CorsPlugin::new(&config).is_ok(),
            expected,
            "runtime/schema drift for {config}"
        );
    }
}

#[test]
fn workload_metrics_schema_documents_runtime_tag_limits() {
    use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let properties = spec
        .pointer("/components/schemas/WorkloadMetricsConfig/properties")
        .expect("WorkloadMetricsConfig properties exist");

    for field in ["custom_tags", "custom_header_tags"] {
        assert_eq!(properties[field]["maxProperties"], json!(32));
        let description = properties[field]["description"]
            .as_str()
            .expect("custom tag description");
        assert!(
            description.contains("32 distinct tag names combined"),
            "{field} must document the combined runtime cap"
        );
    }

    let operation_value = properties
        .pointer("/metrics/properties/tag_overrides/items/properties/operation/properties/value")
        .expect("metric set operation value schema exists");
    assert_eq!(operation_value["maxLength"], json!(256));
    let value_description = operation_value["description"]
        .as_str()
        .expect("metric value description");
    assert!(value_description.contains("256 UTF-8 bytes"));
    assert!(value_description.contains("counts Unicode characters"));

    let ascii_256 = "x".repeat(256);
    let ascii_257 = "x".repeat(257);
    let metric_config = |value: &str| {
        json!({
            "metrics": {
                "tag_overrides": [{
                    "name": "source_workload",
                    "operation": {"type": "set", "value": value}
                }]
            }
        })
    };
    assert_component_validity(
        &spec,
        "WorkloadMetricsConfig",
        &metric_config(&ascii_256),
        true,
    );
    assert!(WorkloadMetrics::new(&metric_config(&ascii_256)).is_ok());
    assert_component_validity(
        &spec,
        "WorkloadMetricsConfig",
        &metric_config(&ascii_257),
        false,
    );
    assert!(WorkloadMetrics::new(&metric_config(&ascii_257)).is_err());

    // JSON Schema maxLength counts characters, whereas runtime admission is
    // deliberately stricter for multibyte input and counts encoded bytes.
    let multibyte_over_256_bytes = "é".repeat(129);
    assert_component_validity(
        &spec,
        "WorkloadMetricsConfig",
        &metric_config(&multibyte_over_256_bytes),
        true,
    );
    assert!(WorkloadMetrics::new(&metric_config(&multibyte_over_256_bytes)).is_err());

    let custom_tags: serde_json::Map<String, serde_json::Value> = (0..16)
        .map(|index| (format!("literal_{index}"), json!("value")))
        .collect();
    let custom_header_tags: serde_json::Map<String, serde_json::Value> = (0..16)
        .map(|index| (format!("header_{index}"), json!("x-tag")))
        .collect();
    let combined_32 = json!({
        "custom_tags": custom_tags,
        "custom_header_tags": custom_header_tags,
    });
    assert_component_validity(&spec, "WorkloadMetricsConfig", &combined_32, true);
    assert!(WorkloadMetrics::new(&combined_32).is_ok());

    let mut combined_33 = combined_32;
    combined_33["custom_header_tags"]
        .as_object_mut()
        .expect("custom_header_tags object")
        .insert("header_16".to_string(), json!("x-tag"));
    // The per-map OpenAPI bounds cannot express a sum across two objects; the
    // property descriptions carry that contract and runtime rejects the union.
    assert_component_validity(&spec, "WorkloadMetricsConfig", &combined_33, true);
    assert!(WorkloadMetrics::new(&combined_33).is_err());
}

#[test]
fn opa_schema_matches_runtime_validation_contract() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let component = spec
        .pointer("/components/schemas/OpaPluginConfig")
        .expect("OpaPluginConfig component exists");

    assert_eq!(component.get("additionalProperties"), Some(&json!(false)));
    assert!(
        component
            .pointer("/properties/timeout_ms/maximum")
            .is_none(),
        "runtime accepts positive timeout_ms values above 30000 and clamps the effective timeout"
    );

    let base = json!({
        "opa_host": "http://opa.internal:8181",
        "policy_path": "ferrum/authz/allow",
        "timeout_ms": 45000,
        "max_response_bytes": 262144,
        "headers": {"X-OPA-Tenant": "blue"},
        "deny_headers": {"X-Policy": "denied"},
        "include_body": true,
        "max_body_bytes": 1048576,
        "redact_query_keys": ["session_id"],
    });
    assert_component_validity(&spec, "OpaPluginConfig", &base, true);

    let mut unknown = base.clone();
    unknown
        .as_object_mut()
        .expect("OPA test config is an object")
        .insert("decision_pointr".to_string(), json!(["result", "allow"]));
    assert_component_validity(&spec, "OpaPluginConfig", &unknown, false);

    for field in ["max_response_bytes", "max_body_bytes"] {
        let mut zero = base.clone();
        zero.as_object_mut()
            .expect("OPA test config is an object")
            .insert(field.to_string(), json!(0));
        assert_component_validity(&spec, "OpaPluginConfig", &zero, false);
    }
}

#[test]
fn upstream_runtime_serialization_is_covered_by_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let upstream: ferrum_edge::config::types::Upstream = serde_json::from_value(json!({
        "targets": [{
            "host": "backend.example",
            "port": 8443,
            "weight": 2,
            "tags": {"version": "v1"},
            "locality": "us-east/us-east-1/a",
            "path": "/api"
        }],
        "service_discovery": {
            "provider": "dns_sd",
            "dns_sd": {"service_name": "_https._tcp.backend.example"}
        },
        "subsets": [{
            "name": "v1",
            "labels": {"version": "v1"},
            "traffic_policy": {
                "load_balancer_algorithm": "consistent_hashing",
                "hash_on": "header:x-tenant",
                "tls": {
                    "mode": "simple",
                    "sni": "backend.example"
                },
                "connect_timeout_ms": 750,
                "passive_health_check": {}
            }
        }],
        "port_overrides": {
            "8443": {
                "connect_timeout_ms": 500,
                "algorithm": "least_connections",
                "hash_on": "ip",
                "passive_health_check": {},
                "locality_lb_setting": {
                    "enabled": true,
                    "distribute": [{
                        "from": "us-east/us-east-1/a",
                        "to": {"us-east": 90, "us-west": 10}
                    }]
                },
                "max_connections": 100,
                "tcp_keepalive": {"time_seconds": 30, "interval_seconds": 10, "probes": 3},
                "http_max_requests_per_connection": 1000,
                "http_idle_timeout_ms": 30000,
                "h2_max_concurrent_streams": 128,
                "tls": {},
                "h2_upgrade_policy": "UPGRADE",
                "max_retries": 2,
                "http1_max_pending_requests": 64
            }
        },
        "source_locality": "us-east/us-east-1/a",
        "locality_lb_strict": true,
        "locality_lb_setting": {
            "enabled": true,
            "failover": [{"from": "us-east", "to": "us-west"}]
        }
    }))
    .expect("representative upstream deserializes");
    let serialized = serde_json::to_value(upstream).expect("upstream serializes");
    assert!(
        serialized
            .pointer("/subsets/0/traffic_policy/tls/subject_alt_names")
            .is_none(),
        "empty subject_alt_names must be omitted by MeshTrafficPolicyTls serialization"
    );

    assert_component_validity(&spec, "Upstream", &serialized, true);
}

#[test]
fn config_schemas_reject_nulls_that_rust_does_not_accept() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for (component, instance) in [
        (
            "Proxy",
            json!({"id": null, "backend_host": "backend", "backend_port": 443}),
        ),
        ("Consumer", json!({"username": null})),
        (
            "PluginConfig",
            json!({"plugin_name": null, "scope": "global", "enabled": true}),
        ),
        ("PluginAssociation", json!({"plugin_config_id": null})),
        ("UpstreamTarget", json!({"host": null, "port": 443})),
        ("ActiveHealthCheck", json!({"http_path": null})),
    ] {
        assert_component_validity(&spec, component, &instance, false);
    }

    assert_component_validity(
        &spec,
        "Proxy",
        &json!({"id": "", "backend_host": "", "backend_port": 0}),
        true,
    );
}

#[test]
fn service_discovery_schema_matches_provider_validation_and_serialization() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let provider_guards = spec
        .pointer("/components/schemas/ServiceDiscoveryConfig/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("service discovery provider guards are an array");
    let guarded_providers: BTreeSet<_> = provider_guards
        .iter()
        .map(|guard| {
            assert_eq!(
                guard["if"]["required"],
                json!(["provider"]),
                "each provider conditional must require the discriminator"
            );
            guard["if"]["properties"]["provider"]["const"]
                .as_str()
                .expect("provider guard has a string const")
        })
        .collect();
    assert_eq!(
        guarded_providers,
        BTreeSet::from(["consul", "dns_sd", "kubernetes", "mesh"])
    );

    assert_component_validity(
        &spec,
        "ServiceDiscoveryConfig",
        &json!({
            "provider": "dns_sd",
            "dns_sd": {"service_name": "_http._tcp.backend.example"},
            "kubernetes": null,
            "consul": null,
            "mesh": null,
            "default_weight": 1
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ServiceDiscoveryConfig",
        &json!({"provider": "dns_sd", "dns_sd": null}),
        false,
    );
    assert_component_validity(
        &spec,
        "ServiceDiscoveryConfig",
        &json!({"provider": "consul", "consul": {"address": "http://consul:8500"}}),
        false,
    );
}

#[test]
fn mesh_and_overload_runtime_snapshots_are_covered_by_openapi() {
    use ferrum_edge::modes::mesh::runtime::MeshEgressScopeHealth;
    use ferrum_edge::modes::mesh::slice::{MeshEgressScopeResource, MeshEgressScopeSnapshot};
    use ferrum_edge::overload::{
        ActionSnapshot, ConnPressure, FdPressure, NodeWaypointDropSnapshot, OverloadLevel,
        OverloadSnapshot, PressureSnapshot, ReqPressure,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let resource = MeshEgressScopeResource {
        namespace: "ferrum".to_string(),
        name: "reviews".to_string(),
        hosts: vec!["reviews.ferrum.svc.cluster.local".to_string()],
        ports: vec![8080],
    };
    let scope = MeshEgressScopeSnapshot {
        sidecar_enforced: true,
        dry_run: false,
        sidecar_applied: true,
        sidecar_admitted_services: 1,
        sidecar_denied_services: 0,
        destination_rules: vec![resource.clone()],
        sidecar_admitted_destination_rules: 1,
        sidecar_denied_destination_rules: 0,
        services: vec![resource],
        service_entries: Vec::new(),
        known_destinations: vec!["reviews.ferrum.svc.cluster.local:8080".to_string()],
    };
    let health = MeshEgressScopeHealth {
        sidecar_admitted_services: 1,
        sidecar_denied_services: 0,
    };
    let egress_response = json!({
        "namespace": "ferrum",
        "scope": scope,
        "health": health
    });
    assert_component_validity(&spec, "MeshEgressScopeResponse", &egress_response, true);
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "mesh": {"egress_scope": health}
        }),
        true,
    );

    let mut overload = serde_json::to_value(OverloadSnapshot {
        level: OverloadLevel::Normal,
        draining: false,
        active_connections: 2,
        active_requests: 1,
        red_drop_probability_pct: 0.0,
        port_exhaustion_events: 0,
        node_waypoint_drops: NodeWaypointDropSnapshot {
            cookie_unavailable: 1,
            unknown_cookie: 2,
            missing_pod_uid: 3,
            missing_workload_hash: 4,
            unknown_pod: 5,
            hash_mismatch: 6,
        },
        pressure: PressureSnapshot {
            file_descriptors: FdPressure {
                current: 10,
                max: 100,
                ratio: 0.1,
            },
            connections: ConnPressure {
                current: 2,
                max: 100,
                ratio: 0.02,
            },
            requests: ReqPressure {
                current: 1,
                max: 100,
                ratio: 0.01,
            },
            event_loop_latency_us: 50,
        },
        actions: ActionSnapshot {
            disable_keepalive: false,
            reject_new_connections: false,
            reject_new_requests: false,
        },
    })
    .expect("overload snapshot serializes");
    overload
        .as_object_mut()
        .expect("overload snapshot is an object")
        .insert(
            "stream_listeners".to_string(),
            json!({
                "dtls_demux_sessions_total": 0,
                "dtls_demux_sessions": [],
                "bind_failures_total": 0,
                "bind_failures": []
            }),
        );
    assert_component_validity(&spec, "OverloadSnapshot", &overload, true);
}

#[test]
fn no_proxy_runtime_metrics_snapshot_is_covered_by_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let snapshot = ferrum_edge::runtime_metrics::build_snapshot("node_agent", None);
    let serialized = serde_json::to_value(snapshot).expect("runtime metrics snapshot serializes");

    assert_component_validity(&spec, "RuntimeMetricsSnapshot", &serialized, true);
}

#[test]
fn ai_prompt_shield_schema_matches_runtime_validation() {
    use ferrum_edge::plugins::ai_prompt_shield::AiPromptShield;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let pattern_schema = spec
        .pointer("/components/schemas/AiPromptShieldConfig/properties/patterns")
        .expect("missing ai_prompt_shield patterns schema");
    let enum_names: BTreeSet<&str> = pattern_schema["items"]["enum"]
        .as_array()
        .expect("patterns.items.enum must be an array")
        .iter()
        .map(|value| value.as_str().expect("built-in enum names must be strings"))
        .collect();
    let expected_names: BTreeSet<&str> = [
        "ssn",
        "credit_card",
        "email",
        "phone_us",
        "api_key",
        "aws_key",
        "ip_address",
        "iban",
    ]
    .into_iter()
    .collect();
    assert_eq!(enum_names, expected_names);
    let description = pattern_schema["description"]
        .as_str()
        .expect("patterns description must list built-ins");
    for name in &expected_names {
        assert!(
            description.contains(name),
            "patterns description omits built-in {name}"
        );
    }

    for config in [
        json!({}),
        json!({"patterns": ["email"], "max_scan_bytes": 1}),
        json!({
            "patterns": [],
            "custom_patterns": [{"name": "account", "regex": "ACCT-[0-9]+"}]
        }),
    ] {
        assert_component_validity(&spec, "AiPromptShieldConfig", &config, true);
        assert!(
            AiPromptShield::new(&config).is_ok(),
            "runtime should accept schema-valid config: {config}"
        );
    }

    for config in [
        json!({"patterns": ["not_a_builtin"]}),
        json!({"patterns": [], "custom_patterns": []}),
        json!({"patterns": []}),
        json!({"max_scan_bytes": 0}),
        json!({"patterns": ["email"], "scan_field": "all"}),
    ] {
        assert_component_validity(&spec, "AiPromptShieldConfig", &config, false);
        assert!(
            AiPromptShield::new(&config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }
}

#[test]
fn jwt_auth_schema_rejects_unknown_config_keys() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/JwtAuthConfig")
        .expect("missing JwtAuthConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("JwtAuthConfig schema compiles");

    assert!(
        validator
            .validate(&json!({"audiences": ["payments-api"]}))
            .is_ok()
    );
    for config in [
        json!({"audience": ["payments-api"]}),
        json!({"expected_issue": "https://issuer.example"}),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "schema should reject unknown jwt_auth key: {config}"
        );
    }
}

#[test]
fn adaptive_concurrency_schema_rejects_unknown_config_keys() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AdaptiveConcurrencyConfig")
        .expect("missing AdaptiveConcurrencyConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AdaptiveConcurrencyConfig schema compiles");

    assert!(
        validator
            .validate(&json!({"key_by": "backend_target", "max_limit": 32}))
            .is_ok()
    );
    assert!(
        validator.validate(&json!({"max_limt": 32})).is_err(),
        "schema must reject unknown adaptive_concurrency policy keys"
    );
}

#[test]
fn adaptive_concurrency_schema_documents_generation_handoff_exceptions() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AdaptiveConcurrencyConfig")
        .expect("missing AdaptiveConcurrencyConfig schema");

    let shadow_description = schema
        .pointer("/properties/shadow_mode/description")
        .and_then(serde_json::Value::as_str)
        .expect("shadow_mode description should be present");
    assert!(
        shadow_description.contains("structural generation handoff")
            && shadow_description.contains("still fail closed"),
        "shadow_mode must document the structural handoff exception"
    );

    let header_description = schema
        .pointer("/properties/expose_headers/description")
        .and_then(serde_json::Value::as_str)
        .expect("expose_headers description should be present");
    assert!(
        header_description.contains("genuine per-target limit rejections")
            && header_description.contains("Generation-handoff rejections omit"),
        "expose_headers must document generation-handoff omission"
    );
}

#[test]
fn mesh_route_dispatch_runtime_and_openapi_contracts_match() {
    use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let representative = json!({
        "rules": [
            {
                "match": {
                    "methods": [{"regex": "GET|POST"}],
                    "uri": {"regex": "/api/[a-z]+"}
                },
                "destination": {
                    "backend_host": "api.internal.example",
                    "backend_port": 8443,
                    "backend_tls": {
                        "client_cert_path": "/tls/client.pem",
                        "client_key_path": "/tls/client.key",
                        "server_ca_cert_path": "/tls/ca.pem",
                        "verify_server_cert": true,
                        "sni": "api.internal.example",
                        "san_allow_list": ["api.internal.example"]
                    },
                    "requires_node_waypoint_authz": true
                },
                "timeout_ms": 1500,
                "retry": {
                    "max_retries": 2,
                    "retryable_status_codes": [502],
                    "retryable_methods": ["GET"],
                    "backoff": {"fixed": {"delay_ms": 25}},
                    "retry_on_connect_failure": true
                },
                "request_transform": [
                    {
                        "operation": "add",
                        "target": "header",
                        "key": "x-route",
                        "value": "api"
                    },
                    {"operation": "remove", "key": "x-internal"}
                ],
                "response_transform": [{
                    "operation": "update",
                    "key": "x-served-by",
                    "value": "edge"
                }],
                "fault": {"delay": {"duration_ms": 1, "percentage": 1.0}},
                "rewrite": {"uri": "/v2", "match_prefix": "/api"}
            },
            {
                "match": {"methods": ["HEAD"]},
                "redirect": {"redirect_code": 308}
            },
            {
                "match": {"methods": ["PUT"]},
                "destination": {"upstream_id": "fallback"},
                "timeout_ms": null,
                "timeout_disabled": true,
                "retry": null,
                "retry_disabled": true
            }
        ],
        "reject_unmatched": true
    });

    assert_component_validity(&spec, "MeshRouteDispatchConfig", &representative, true);
    MeshRouteDispatch::new(&representative).expect("representative config is runtime-valid");

    let tiny_fault = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "api"},
            "fault": {"abort": {
                "status_code": 503,
                "percentage": f64::from_bits(1)
            }}
        }]
    });
    assert_component_validity(&spec, "MeshRouteDispatchConfig", &tiny_fault, true);
    MeshRouteDispatch::new(&tiny_fault).expect("tiny positive percentage is runtime-valid");

    let overlong_fault = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "api"},
            "fault": {"delay": {"duration_ms": 60_001, "percentage": 1.0}}
        }]
    });
    assert_component_validity(&spec, "MeshRouteDispatchConfig", &overlong_fault, false);
    assert!(MeshRouteDispatch::new(&overlong_fault).is_err());

    let documented_old_transform = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "api"},
            "request_transform": [{"op": "update", "key": "x-route", "value": "api"}]
        }]
    });
    assert_component_validity(
        &spec,
        "MeshRouteDispatchConfig",
        &documented_old_transform,
        false,
    );
    assert!(MeshRouteDispatch::new(&documented_old_transform).is_err());

    for invalid_transform in [
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "request_transform": [{"operation": "add", "key": "x-route"}]
            }]
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "request_transform": [{
                    "operation": "remove",
                    "key": "x-route",
                    "value": "unexpected"
                }]
            }]
        }),
    ] {
        assert_component_validity(&spec, "MeshRouteDispatchConfig", &invalid_transform, false);
        assert!(MeshRouteDispatch::new(&invalid_transform).is_err());
    }

    // The runtime shared types keep their broader compatibility for other
    // deserialization paths, while mesh_route_dispatch exposes strict
    // route-local schemas and rejects nested policy typos.
    for invalid_route_policy in [
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "api.internal",
                    "backend_port": 443,
                    "backend_tls": {"client_certpath": "/tls/client.pem"}
                }
            }]
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "retry": {"max_retry": 2}
            }]
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "retry": {"backoff": {"fixed": {"delay_ms": 25, "delay_millis": 25}}}
            }]
        }),
    ] {
        assert_component_validity(
            &spec,
            "MeshRouteDispatchConfig",
            &invalid_route_policy,
            false,
        );
        assert!(MeshRouteDispatch::new(&invalid_route_policy).is_err());
    }

    let status_only_redirect = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "redirect": {"redirect_code": 308}
        }]
    });
    assert_component_validity(
        &spec,
        "MeshRouteDispatchConfig",
        &status_only_redirect,
        true,
    );
    MeshRouteDispatch::new(&status_only_redirect).expect("status-only redirects are runtime-valid");
}

#[test]
fn oidc_relying_party_schema_matches_strict_runtime_surface() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/OidcRelyingPartyConfig")
        .expect("missing OidcRelyingPartyConfig schema");
    assert_eq!(schema["additionalProperties"], false);

    let provider = &schema["properties"]["providers"]["items"];
    assert_eq!(provider["additionalProperties"], false);
    let provider_fields: BTreeSet<_> = provider["properties"]
        .as_object()
        .expect("provider properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        provider_fields,
        BTreeSet::from([
            "audiences",
            "authorization_endpoint",
            "callback_path",
            "claim_headers",
            "client_auth",
            "client_id",
            "consumer_header_claim",
            "consumer_identity_claim",
            "discovery_url",
            "end_session_endpoint",
            "id_token_clock_skew_secs",
            "issuer",
            "jwks_uri",
            "logout_path",
            "post_logout_redirect_uri",
            "redirect_uri",
            "required_roles",
            "required_scopes",
            "role_claim",
            "scope_claim",
            "scopes",
            "token_endpoint",
            "userinfo_endpoint",
        ])
    );
    assert!(
        provider["properties"]
            .get("post_logout_redirect_uri")
            .is_some()
    );
    assert_eq!(
        provider["properties"]["id_token_clock_skew_secs"]["default"],
        60
    );
    assert_eq!(
        provider["properties"]["client_auth"]["additionalProperties"],
        false
    );

    let session = &schema["properties"]["session"];
    assert_eq!(session["additionalProperties"], false);
    assert!(session["properties"].get("redis_url").is_none());
    let session_fields: BTreeSet<_> = session["properties"]
        .as_object()
        .expect("session properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        session_fields,
        BTreeSet::from([
            "cookie_name",
            "domain",
            "encryption_secret",
            "encryption_secret_previous",
            "http_only",
            "idle_ttl_secs",
            "max_cookie_bytes",
            "path",
            "same_site",
            "secure",
            "store",
            "ttl_secs",
        ])
    );

    let behavior = &schema["properties"]["behavior"];
    assert_eq!(behavior["additionalProperties"], false);
    let behavior_fields: BTreeSet<_> = behavior["properties"]
        .as_object()
        .expect("behavior properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        behavior_fields,
        BTreeSet::from([
            "challenge_api_status",
            "challenge_html_status",
            "html_accept_substrings",
            "post_login_default_path",
            "post_login_redirect_param",
            "refresh_skew_secs",
            "rp_initiated_logout",
            "state_cache_max_entries",
            "state_cache_max_entries_per_source",
            "state_ttl_secs",
            "trusted_redirect_hosts",
        ])
    );
    assert_eq!(
        behavior["properties"]["state_cache_max_entries"]["default"],
        10_000
    );
    assert_eq!(
        behavior["properties"]["state_cache_max_entries_per_source"]["default"],
        32
    );
}

#[test]
fn ai_response_guard_schema_matches_strict_runtime_constraints() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiResponseGuardConfig")
        .expect("AiResponseGuardConfig component exists");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["pii_patterns"]["items"]["enum"],
        json!([
            "ssn",
            "credit_card",
            "email",
            "phone_us",
            "api_key",
            "aws_key",
            "ip_address",
            "iban"
        ])
    );
    assert_eq!(schema["properties"]["max_scan_bytes"]["minimum"], 1);
    assert_eq!(schema["properties"]["max_completion_length"]["minimum"], 0);
    for pointer in [
        "/properties/blocked_phrases/items/minLength",
        "/properties/required_fields/items/minLength",
        "/properties/custom_pii_patterns/items/properties/name/minLength",
        "/properties/custom_pii_patterns/items/properties/regex/minLength",
        "/properties/blocked_patterns/items/properties/name/minLength",
        "/properties/blocked_patterns/items/properties/regex/minLength",
    ] {
        assert_eq!(
            schema.pointer(pointer),
            Some(&json!(1)),
            "missing {pointer}"
        );
    }
    assert_eq!(
        schema["properties"]["custom_pii_patterns"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["blocked_patterns"]["items"]["additionalProperties"],
        false
    );

    for valid in [
        json!({"pii_patterns": ["email"], "max_scan_bytes": 1}),
        json!({"require_json": true, "max_completion_length": 0}),
        json!({"blocked_phrases": ["x"]}),
        json!({"required_fields": ["x"]}),
        json!({"custom_pii_patterns": [{"name": "x", "regex": "x"}]}),
        json!({"blocked_patterns": [{"name": "x", "regex": "x"}]}),
    ] {
        assert_component_validity(&spec, "AiResponseGuardConfig", &valid, true);
    }

    for invalid in [
        json!({"pii_patterns": ["not-real"]}),
        json!({"pii_patterns": ["email"], "max_scan_bytes": 0}),
        json!({"require_json": true, "max_completion_length": -1}),
        json!({"blocked_phrases": [""]}),
        json!({"required_fields": [""]}),
        json!({"custom_pii_patterns": [{"name": "", "regex": "x"}]}),
        json!({"custom_pii_patterns": [{"name": "x", "regex": ""}]}),
        json!({"blocked_patterns": [{"name": "", "regex": "x"}]}),
        json!({"blocked_patterns": [{"name": "x", "regex": ""}]}),
        json!({"require_json": true, "pii_pattern": ["email"]}),
        json!({
            "custom_pii_patterns": [{"name": "x", "regex": "x", "enabled": true}]
        }),
        json!({
            "blocked_patterns": [{"name": "x", "regex": "x", "enabled": true}]
        }),
    ] {
        assert_component_validity(&spec, "AiResponseGuardConfig", &invalid, false);
    }
}

#[test]
fn security_headers_schema_rejects_unknown_top_level_and_hsts_keys() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/SecurityHeadersConfig")
        .expect("SecurityHeadersConfig component exists");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["hsts"]["oneOf"][3]["additionalProperties"],
        false
    );
    assert_component_validity(
        &spec,
        "SecurityHeadersConfig",
        &json!({
            "hsts": { "max_age": 300 },
            "set": { "X!#$%&'*+.^_`|~Policy": "one\ttwo" },
            "remove": ["X!Policy"]
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "SecurityHeadersConfig",
        &json!({ "fram_options": false }),
        false,
    );
    assert_component_validity(
        &spec,
        "SecurityHeadersConfig",
        &json!({ "hsts": { "include_subdomain": true } }),
        false,
    );
    assert_component_validity(
        &spec,
        "SecurityHeadersConfig",
        &json!({ "set": { "X Policy": "on" } }),
        false,
    );
    assert_component_validity(
        &spec,
        "SecurityHeadersConfig",
        &json!({ "set": { "X-Policy": "one\u{0001}two" } }),
        false,
    );
    for non_ascii_value in [
        json!({ "content_type_options": "caf\u{00e9}" }),
        json!({ "frame_options": "caf\u{00e9}" }),
        json!({ "referrer_policy": "caf\u{00e9}" }),
        json!({ "hsts": "caf\u{00e9}" }),
        json!({ "content_security_policy": "caf\u{00e9}" }),
        json!({ "permissions_policy": "caf\u{00e9}" }),
        json!({ "set": { "X-Policy": "caf\u{00e9}" } }),
    ] {
        assert_component_validity(&spec, "SecurityHeadersConfig", &non_ascii_value, false);
    }
}

#[test]
fn bot_detection_schema_matches_strict_runtime_and_documented_contract() {
    use ferrum_edge::plugins::bot_detection::{BOT_DETECTION_CONFIG_KEYS, BotDetection};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/BotDetectionConfig")
        .expect("BotDetectionConfig component exists");

    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    let schema_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("BotDetectionConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_fields: BTreeSet<_> = BOT_DETECTION_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(schema_fields, runtime_fields);

    assert_eq!(
        schema["properties"]["blocked_patterns"]["type"],
        json!(["array", "null"])
    );
    assert_eq!(
        schema["properties"]["allow_list"]["type"],
        json!(["array", "null"])
    );
    assert_eq!(
        schema["properties"]["allow_missing_user_agent"]["type"],
        json!(["boolean", "null"])
    );
    assert_eq!(
        schema["properties"]["custom_response_code"]["type"],
        json!(["integer", "null"])
    );
    assert_eq!(schema["properties"]["custom_response_code"]["minimum"], 400);
    assert_eq!(schema["properties"]["custom_response_code"]["maximum"], 599);

    for valid in [
        json!({}),
        json!({
            "blocked_patterns": [" FerrumAuditCrawler "],
            "allow_list": ["TrustedBot"],
            "allow_missing_user_agent": false,
            "custom_response_code": 451
        }),
        json!({
            "blocked_patterns": null,
            "allow_list": null,
            "allow_missing_user_agent": null,
            "custom_response_code": null
        }),
        json!({"blocked_patterns": [], "allow_missing_user_agent": false}),
        json!({"custom_response_code": 400}),
        json!({"custom_response_code": 403.0}),
        json!({"custom_response_code": 599}),
        // U+FEFF ZWNBSP is not in Rust's Unicode White_Space set.
        json!({"blocked_patterns": ["\u{feff}"]}),
        json!({"allow_list": ["\u{feff}"]}),
    ] {
        assert_component_validity(&spec, "BotDetectionConfig", &valid, true);
        BotDetection::new(&valid)
            .unwrap_or_else(|error| panic!("schema-valid config {valid} failed runtime: {error}"));
    }

    for invalid in [
        serde_json::Value::Null,
        json!([]),
        json!("config"),
        json!({"blocked_paterns": ["FerrumAuditCrawler"]}),
        json!({
            "blocked_patterns": ["FerrumAuditCrawler"],
            "allow_missing_useragent": false
        }),
        json!({"allowlist": ["TrustedBot"]}),
        json!({"custom_reponse_code": 451}),
        json!({"allow_missing_useragent": false}),
        json!({"blocked_patterns": "FerrumAuditCrawler"}),
        json!({"blocked_patterns": [42]}),
        json!({"blocked_patterns": [""]}),
        json!({"blocked_patterns": [" \t "]}),
        // U+0085 NEL is in Rust's Unicode White_Space set.
        json!({"blocked_patterns": ["\u{0085}"]}),
        json!({"allow_list": "TrustedBot"}),
        json!({"allow_list": [false]}),
        json!({"allow_list": ["\n"]}),
        json!({"allow_list": ["\u{0085}"]}),
        json!({"allow_missing_user_agent": "false"}),
        json!({"custom_response_code": "451"}),
        json!({"custom_response_code": 451.5}),
        json!({"blocked_patterns": []}),
        json!({"blocked_patterns": [], "allow_missing_user_agent": true}),
        json!({"blocked_patterns": [], "allow_missing_user_agent": null}),
        json!({"custom_response_code": -1}),
        json!({"custom_response_code": 100}),
        json!({"custom_response_code": 199}),
        json!({"custom_response_code": 204}),
        json!({"custom_response_code": 205}),
        json!({"custom_response_code": 304}),
        json!({"custom_response_code": 399}),
        json!({"custom_response_code": 600}),
        json!({"custom_response_code": 1e100}),
    ] {
        assert_component_validity(&spec, "BotDetectionConfig", &invalid, false);
        assert!(
            BotDetection::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("Configuration must be a top-level object."));
    assert!(guide.contains("unknown keys are rejected instead of falling back to defaults"));
    assert!(guide.contains("Only 400–599 is accepted"));
    assert!(guide.contains("never reflect the client-controlled User-Agent"));
    assert!(guide.contains("Native gRPC rejections instead use an empty-body HTTP 200"));
}
