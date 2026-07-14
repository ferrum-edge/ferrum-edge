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
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({}),
        json!({"allowed_consumer": ["alice"]}),
        json!({"allowed_consumers": [], "allowed_groups": []}),
        json!({"allowed_consumers": ["alice"], "allow_authenticated_identity": true}),
        json!({"allowed_groups": ["engineering"], "allow_authenticated_identity": true}),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
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
