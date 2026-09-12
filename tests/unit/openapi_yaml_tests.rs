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

fn operation_parameter<'a>(
    spec: &'a serde_json::Value,
    parameters_pointer: &str,
    name: &str,
) -> &'a serde_json::Value {
    spec.pointer(parameters_pointer)
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing parameter array at {parameters_pointer}"))
        .iter()
        .find(|parameter| parameter.get("name").and_then(serde_json::Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("missing `{name}` parameter at {parameters_pointer}"))
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
fn admin_pagination_schema_matches_runtime_bounds_and_coercion() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let shared_offset = spec
        .pointer("/components/parameters/PaginationOffset/schema")
        .expect("shared pagination offset schema");
    assert_eq!(shared_offset["minimum"], json!(0));
    assert_eq!(shared_offset["maximum"], json!(i64::MAX));
    assert_eq!(shared_offset["format"], json!("int64"));

    let shared_limit = spec
        .pointer("/components/parameters/PaginationLimit/schema")
        .expect("shared pagination limit schema");
    assert_eq!(shared_limit["minimum"], json!(0));
    assert_eq!(shared_limit["maximum"], json!(u64::MAX));
    assert_eq!(shared_limit["default"], json!(100));

    let api_spec_parameters = "/paths/~1api-specs/get/parameters";
    let api_spec_limit = operation_parameter(&spec, api_spec_parameters, "limit");
    assert_eq!(api_spec_limit["schema"]["minimum"], json!(0));
    assert_eq!(api_spec_limit["schema"]["maximum"], json!(u64::MAX));
    assert_eq!(api_spec_limit["schema"]["default"], json!(50));
    let api_spec_offset = operation_parameter(&spec, api_spec_parameters, "offset");
    assert_eq!(api_spec_offset["schema"]["minimum"], json!(0));
    assert_eq!(api_spec_offset["schema"]["maximum"], json!(u32::MAX));

    let audit_offset = operation_parameter(&spec, "/paths/~1audit/get/parameters", "offset");
    assert_eq!(audit_offset["schema"]["minimum"], json!(0));
    assert_eq!(audit_offset["schema"]["maximum"], json!(u32::MAX));

    let api_spec_response = spec
        .pointer("/components/schemas/ApiSpecListResponse")
        .expect("API-spec list response schema");
    assert!(
        api_spec_response["required"]
            .as_array()
            .is_some_and(|required| required.contains(&json!("total")))
    );
    assert_eq!(
        api_spec_response["properties"]["total"]["minimum"],
        json!(0)
    );

    // GET /namespaces consumes the shared pagination contract: the shared
    // offset/limit parameters by reference and the data/pagination envelope.
    let namespaces_parameters = spec
        .pointer("/paths/~1namespaces/get/parameters")
        .and_then(serde_json::Value::as_array)
        .expect("namespaces parameter array");
    for shared in ["PaginationOffset", "PaginationLimit"] {
        let expected_ref = format!("#/components/parameters/{shared}");
        assert!(
            namespaces_parameters.iter().any(|parameter| parameter
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                == Some(expected_ref.as_str())),
            "GET /namespaces must reference the shared {shared} parameter"
        );
    }
    let namespaces_response = spec
        .pointer("/paths/~1namespaces/get/responses/200/content/application~1json/schema")
        .expect("namespaces 200 schema");
    assert_eq!(
        namespaces_response["required"],
        json!(["data", "pagination"])
    );
    assert_eq!(
        namespaces_response["properties"]["pagination"]["$ref"],
        json!("#/components/schemas/Pagination")
    );
    assert_eq!(
        namespaces_response["properties"]["data"]["items"]["type"],
        json!("string")
    );
}

#[test]
fn transaction_log_schema_closed_object_keys_match_openapi() {
    use ferrum_edge::plugins::transaction_log_schema::TRANSACTION_LOG_SCHEMA_CONFIG_KEYS;
    use ferrum_edge::plugins::utils::log_schema::{
        DERIVED_FIELD_KEYS, METADATA_POLICY_KEYS, SUMMARY_LOG_SCHEMA_KEYS,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    for (label, pointer, runtime_keys) in [
        (
            "TransactionLogSchemaConfig",
            "/components/schemas/TransactionLogSchemaConfig/properties",
            TRANSACTION_LOG_SCHEMA_CONFIG_KEYS,
        ),
        (
            "SummaryLogSchema",
            "/components/schemas/SummaryLogSchema/properties",
            SUMMARY_LOG_SCHEMA_KEYS,
        ),
        (
            "SummaryLogSchema.derived_fields[]",
            "/components/schemas/SummaryLogSchema/properties/derived_fields/items/properties",
            DERIVED_FIELD_KEYS,
        ),
        (
            "SummaryLogSchema.metadata",
            "/components/schemas/SummaryLogSchema/properties/metadata/properties",
            METADATA_POLICY_KEYS,
        ),
    ] {
        let runtime: BTreeSet<String> = runtime_keys.iter().map(|key| (*key).to_string()).collect();
        assert_eq!(runtime, schema_property_names(&spec, label, pointer));
    }

    for pointer in [
        "/components/schemas/TransactionLogSchemaConfig/additionalProperties",
        "/components/schemas/SummaryLogSchema/additionalProperties",
        "/components/schemas/SummaryLogSchema/properties/derived_fields/items/additionalProperties",
        "/components/schemas/SummaryLogSchema/properties/metadata/additionalProperties",
    ] {
        assert_eq!(spec.pointer(pointer), Some(&serde_json::Value::Bool(false)));
    }
}

#[test]
fn transaction_log_schema_openapi_matches_constructor_admission() {
    use ferrum_edge::plugins::validate_plugin_config;

    // Issue #5168: the document admitted schema shapes the constructor
    // rejects — empty names, empty list entries / rename targets / derived
    // names / static keys, null static values, duplicate `order` entries, and
    // control characters in a metadata prefix — so schema-driven tooling
    // approved configurations that fail at load. Both surfaces must agree.
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/TransactionLogSchemaConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("TransactionLogSchemaConfig schema compiles");

    for config in [
        json!({ "schemas": {} }),
        json!({ "schemas": { "": {} } }),
        json!({ "schemas": { "basic": { "omit": [""] } } }),
        json!({ "schemas": { "basic": { "rename": { "proxy_id": "" } } } }),
        json!({ "schemas": { "basic": { "rename": { "": "route_id" } } } }),
        json!({ "schemas": { "basic": { "order": ["*", "*"] } } }),
        json!({ "schemas": { "basic": { "static_fields": { "stamp": null } } } }),
        json!({ "schemas": { "basic": { "static_fields": { "": "v1" } } } }),
        json!({
            "schemas": { "basic": { "derived_fields": [{ "name": "", "kind": "outcome" }] } }
        }),
        json!({
            "schemas": { "basic": { "metadata": { "mode": "flatten", "prefix": "bad\u{1}" } } }
        }),
        json!({ "schemas": { "basic": { "metadata": { "mode": "nested", "prefix": 3 } } } }),
        json!({
            "schemas": { "basic": { "metadata": { "mode": "omit", "on_collision": "bad" } } }
        }),
    ] {
        let documented = validator.validate(&config);
        let runtime = validate_plugin_config("transaction_log_schema", &config);
        assert!(documented.is_err(), "schema should reject: {config}");
        assert!(runtime.is_err(), "runtime should reject: {config}");
    }

    for config in [
        json!({ "schemas": { "basic": {} } }),
        json!({
            "schemas": {
                "basic": {
                    "summary_type": "http",
                    "omit": ["request_user_agent"],
                    "rename": { "proxy_id": "route_id" },
                    "order": ["route_id", "*"],
                    "static_fields": { "env": "production" },
                    "derived_fields": [{ "name": "outcome", "kind": "outcome" }],
                    "metadata": { "mode": "flatten", "prefix": "meta_" },
                    "timestamp_format": "epoch_ms"
                }
            }
        }),
    ] {
        let documented = validator.validate(&config);
        let runtime = validate_plugin_config("transaction_log_schema", &config);
        assert!(documented.is_ok(), "schema should accept: {config}");
        assert!(runtime.is_ok(), "runtime should accept: {config}");
    }

    // Non-global scope is rejected by the admin write path, so the
    // `PluginConfig` branch must not admit it either.
    let plugin_branch = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/PluginConfig",
        "components": spec["components"].clone()
    });
    let plugin_validator = jsonschema::draft202012::options()
        .build(&plugin_branch)
        .expect("PluginConfig schema compiles");
    let mut plugin = json!({
        "plugin_name": "transaction_log_schema",
        "scope": "global",
        "enabled": true,
        "config": { "schemas": { "basic": {} } }
    });
    assert!(plugin_validator.validate(&plugin).is_ok());
    plugin["scope"] = json!("proxy_group");
    assert!(plugin_validator.validate(&plugin).is_err());
}

#[test]
fn api_chargeback_sink_schema_matches_constructor_admission() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::api_chargeback_sink::ApiChargebackSink;
    use ferrum_edge::plugins::transaction_log_schema::TransactionLogSchema;
    use ferrum_edge::plugins::utils::log_schema::{CHARGE_EVENT_FIELDS, registry};

    // Issue #5393: keep the shared log-schema constraints, then narrow only
    // the sink's projection to the charge-event family used by its constructor.
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/ApiChargebackSinkConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("ApiChargebackSinkConfig schema compiles");
    let shared_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/SummaryLogSchema",
        "components": spec["components"].clone()
    });
    let shared_validator = jsonschema::draft202012::options()
        .build(&shared_schema)
        .expect("SummaryLogSchema schema compiles");
    let base = json!({
        "clickhouse": { "url": "https://clickhouse.example:8443" },
        "spool": { "enabled": false },
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }]
    });
    let http_client = PluginHttpClient::default();
    let assert_admission = |config: &serde_json::Value, expected: bool| {
        let documented = validator.validate(config);
        let runtime = ApiChargebackSink::new(config, http_client.clone(), "ferrum");
        assert_eq!(
            documented.is_ok(),
            expected,
            "unexpected schema admission for {config}: {documented:?}"
        );
        assert_eq!(
            runtime.is_ok(),
            expected,
            "unexpected constructor admission for {config}: {:?}",
            runtime.err()
        );
    };
    assert_admission(&base, true);

    for projection in [
        json!({ "summary_type": "http" }),
        json!({ "summary_type": "stream" }),
        json!({ "summary_type": "both" }),
        json!({ "timestamp_format": "rfc3339" }),
        json!({ "timestamp_format": "epoch_ms" }),
        json!({ "timestamp_format": "epoch_s" }),
        json!({ "metadata": {} }),
        json!({ "metadata": { "mode": "nested" } }),
        json!({ "metadata": { "mode": "omit" } }),
        json!({ "metadata": { "mode": "flatten" } }),
        json!({ "derived_fields": [{ "name": "host", "kind": "backend_host" }] }),
    ] {
        assert!(
            shared_validator.validate(&projection).is_ok(),
            "other logging families retain support for {projection}"
        );
        let mut config = base.clone();
        config["schema"] = projection;
        assert_admission(&config, false);
    }

    for projection in [
        json!({}),
        json!({ "order": ["*"] }),
        json!({ "omit": ["node_id", "node_id"] }),
        json!({
            "omit": ["node_id", "pricing_version"],
            "rename": { "proxy_id": "route_key", "charge_total": "amount" },
            "order": ["amount", "record_kind", "*"],
            "static_fields": { "ledger": "prod", "shard": 3 },
            "derived_fields": [
                { "name": "status_group", "kind": "status_class" },
                { "name": "record_kind", "kind": "summary_kind" },
                { "name": "call_outcome", "kind": "outcome" }
            ]
        }),
    ] {
        let mut config = base.clone();
        config["schema"] = projection;
        assert_admission(&config, true);
    }

    for projection in [
        json!(null),
        json!([]),
        json!({ "summary_type": null }),
        json!({ "timestamp_format": null }),
        json!({ "metadata": null }),
        json!({ "unknown": true }),
        json!({ "omit": [""] }),
        json!({ "omit": ["latency_total_ms"] }),
        json!({ "rename": { "backend_target": "backend" } }),
        json!({ "rename": { "proxy_id": "" } }),
        json!({ "order": ["*", "*"] }),
        json!({ "static_fields": { "stamp": null } }),
        json!({ "static_fields": { "": "v1" } }),
        json!({ "derived_fields": [{ "name": "", "kind": "outcome" }] }),
        json!({ "derived_fields": [{ "name": "result", "kind": "unknown" }] }),
        json!({ "derived_fields": [{ "name": "result", "kind": "outcome", "extra": 1 }] }),
    ] {
        let mut config = base.clone();
        config["schema"] = projection;
        assert_admission(&config, false);
    }

    let documented_fields: BTreeSet<&str> = spec
        .pointer("/components/schemas/ApiChargebackSinkLogField/enum")
        .and_then(serde_json::Value::as_array)
        .expect("charge-event field inventory")
        .iter()
        .map(|field| field.as_str().expect("field name"))
        .collect();
    let runtime_fields: BTreeSet<&str> =
        CHARGE_EVENT_FIELDS.iter().map(|field| field.name).collect();
    assert_eq!(documented_fields, runtime_fields);
    for field in runtime_fields {
        for projection in [
            json!({ "omit": [field] }),
            json!({ "rename": { (field): "projected_value" } }),
        ] {
            let mut config = base.clone();
            config["schema"] = projection;
            assert_admission(&config, true);
        }
    }

    for reference in [json!(""), json!(null), json!(7), json!({}), json!([])] {
        let mut config = base.clone();
        config["schema_ref"] = reference;
        assert_admission(&config, false);
    }
    for projection in [json!({}), json!(null)] {
        for reference in [json!("portable"), json!(null)] {
            let mut config = base.clone();
            config["schema"] = projection.clone();
            config["schema_ref"] = reference;
            assert_admission(&config, false);
        }
    }

    // A reference is only a string in OpenAPI. Its definition must pass the
    // same family checks when resolved; staging keeps the live registry intact.
    let definitions = json!({
        "schemas": {
            "portable": { "rename": { "proxy_id": "route_key" }, "order": ["*"] },
            "summary": { "summary_type": "both" },
            "timestamp": { "timestamp_format": "rfc3339" },
            "metadata": { "metadata": { "mode": "nested" } },
            "backend": { "derived_fields": [{ "name": "host", "kind": "backend_host" }] },
            "summary_field": { "omit": ["latency_total_ms"] }
        }
    });
    registry::begin_reload().expect("begin isolated schema staging");
    let registered = TransactionLogSchema::new(&definitions);
    let results: Vec<_> = [
        ("portable", true),
        ("summary", false),
        ("timestamp", false),
        ("metadata", false),
        ("backend", false),
        ("summary_field", false),
        ("missing", false),
    ]
    .into_iter()
    .map(|(name, expected)| {
        let mut config = base.clone();
        config["schema_ref"] = json!(name);
        let documented = validator.validate(&config).is_ok();
        let runtime = ApiChargebackSink::new(&config, http_client.clone(), "ferrum");
        (name, expected, documented, runtime)
    })
    .collect();
    registry::abort_reload().expect("discard isolated schema staging");
    assert!(registered.is_ok(), "portable definitions must compile");
    for (name, expected, documented, runtime) in results {
        assert!(documented, "nonempty reference is schema-valid: {name}");
        assert_eq!(
            runtime.is_ok(),
            expected,
            "unexpected resolved admission for {name}: {:?}",
            runtime.err()
        );
    }
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
    // `Consumer` is an allOf composition over `ConsumerBase` plus the
    // surface-specific credentials map; the serde field inventory is checked
    // against the flat base schema, and the credentials wiring is covered by
    // `consumer_credential_surface_schemas_match_runtime_redaction` below.
    check!(
        Consumer,
        "ConsumerBase",
        rust_only = ["credentials"],
        schema_only = []
    );
    // Properties live on PluginConfigBase; PluginConfig/Create/Replace compose
    // presence requirements on top of that shared bag.
    check!(PluginConfig, "PluginConfigBase");
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

    let consumer_credentials = &spec["components"]["schemas"]["ConsumerCredentialsRedacted"];
    let credentials_description = consumer_credentials["description"]
        .as_str()
        .expect("ConsumerCredentialsRedacted description");
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

    let plugin_config = &spec["components"]["schemas"]["PluginConfigBase"];
    let config_description = plugin_config["properties"]["config"]["description"]
        .as_str()
        .expect("PluginConfigBase config description");
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

#[test]
fn consumer_credential_surface_schemas_match_runtime_redaction() {
    use ferrum_edge::config::types::{Consumer, redact_consumer_credentials};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let password_hash = format!("hmac_sha256:{}", "a".repeat(64));
    let jwt_secret = "j".repeat(32);
    let hmac_secret = "h".repeat(32);
    let stored_consumer = json!({
        "id": "consumer-1",
        "username": "alice",
        "namespace": "ferrum",
        "custom_id": "ext-123",
        "credentials": {
            "keyauth": [{"key": "live-api-key"}],
            "basicauth": [{"password_hash": password_hash}],
            "jwt": [{"secret": jwt_secret}],
            "hmac_auth": [{"secret": hmac_secret}],
            "mtls_auth": [{"identity": "client.example.com"}],
            "custom_auth": [{
                "api_token": "custom-secret-must-only-appear-in-backup",
                "metadata": {"nested_secret": "also-backup-only"}
            }]
        },
        "acl_groups": ["engineering"],
        "created_at": "2026-01-02T03:04:05Z",
        "updated_at": "2026-01-02T03:04:05Z"
    });
    let consumer: Consumer =
        serde_json::from_value(stored_consumer).expect("stored consumer deserializes");

    // The runtime redacted output must validate against the ordinary Consumer
    // surface and carry the exact placeholders the schema encodes.
    let redacted = serde_json::to_value(redact_consumer_credentials(&consumer))
        .expect("redacted consumer serializes");
    let redacted_credentials = &redacted["credentials"];
    assert!(redacted_credentials.get("basicauth").is_none());
    for (cred_type, field) in [
        ("keyauth", "key"),
        ("jwt", "secret"),
        ("hmac_auth", "secret"),
    ] {
        assert_eq!(
            redacted_credentials[cred_type][0][field],
            json!("[REDACTED]"),
            "{cred_type} entries must carry the exact redaction placeholder"
        );
    }
    assert_eq!(
        redacted_credentials["mtls_auth"][0]["identity"],
        json!("client.example.com"),
        "non-secret mtls identity stays visible"
    );
    assert!(
        redacted_credentials.get("custom_auth").is_none(),
        "ordinary responses must omit unknown/custom credential values"
    );
    assert!(
        !redacted
            .to_string()
            .contains("custom-secret-must-only-appear-in-backup")
    );
    assert_component_validity(&spec, "Consumer", &redacted, true);

    // Legacy known entries are projected to their exact safe response shape:
    // extra JWT fields are dropped and the secret is replaced, so historical
    // stored data cannot violate the closed response schema or disclose values.
    let legacy_consumer: Consumer = serde_json::from_value(json!({
        "username": "legacy",
        "credentials": {
            "jwt": [{
                "secret": "legacy-secret-that-must-not-escape",
                "algorithm": "HS256",
                "private_metadata": {"recovery_token": "must-not-escape"}
            }]
        }
    }))
    .expect("legacy Consumer shape still deserializes from generic stored credentials");
    let legacy_redacted = serde_json::to_value(redact_consumer_credentials(&legacy_consumer))
        .expect("legacy redacted Consumer serializes");
    assert_eq!(
        legacy_redacted["credentials"]["jwt"],
        json!([{"secret": "[REDACTED]"}])
    );
    assert!(!legacy_redacted.to_string().contains("must-not-escape"));
    assert_component_validity(&spec, "Consumer", &legacy_redacted, true);

    // The unredacted stored shape must not validate against the redacted
    // surface: `basicauth` is forbidden and the placeholders are exact.
    let stored_value = serde_json::to_value(&consumer).expect("stored consumer serializes");
    assert_component_validity(&spec, "Consumer", &stored_value, false);

    // The backup surface accepts the canonical stored values; the restore
    // surface additionally accepts plaintext passwords.
    assert_component_validity(&spec, "ConsumerBackup", &stored_value, true);
    assert_component_validity(&spec, "ConsumerRestore", &stored_value, true);
    assert!(
        stored_value["credentials"]["custom_auth"][0]["api_token"]
            .as_str()
            .is_some(),
        "backup serialization must preserve custom credentials"
    );
    let plaintext_basic = json!({
        "username": "alice",
        "credentials": {"basicauth": [{"password": "correct horse battery staple"}]}
    });
    assert_component_validity(&spec, "ConsumerRestore", &plaintext_basic, true);
    assert_component_validity(&spec, "ConsumerBackup", &plaintext_basic, false);

    // The request surface accepts canonical credential input and rejects
    // shapes the runtime validation also rejects (unknown entry fields,
    // ambiguous basic auth fields, missing secret material) as well as the
    // redaction placeholders for length-bounded secret types.
    let valid_create = json!({
        "username": "alice",
        "credentials": {
            "keyauth": [{"key": "live-api-key"}],
            "basicauth": [{"password": "correct horse battery staple"}],
            "jwt": [{"secret": jwt_secret}],
            "hmac_auth": [{"secret": hmac_secret}],
            "mtls_auth": [{"identity": "client.example.com"}]
        }
    });
    assert_component_validity(&spec, "ConsumerCreate", &valid_create, true);
    let custom_credential_input = json!({
        "username": "custom-client",
        "credentials": {
            "custom_auth": [{"api_token": "write-and-backup-contract-remains-unredacted"}]
        }
    });
    for surface in ["ConsumerCreate", "ConsumerBackup", "ConsumerRestore"] {
        assert_component_validity(&spec, surface, &custom_credential_input, true);
    }
    assert_component_validity(&spec, "Consumer", &custom_credential_input, false);

    // Consumer JWT credentials have exactly one supported algorithm/key form:
    // an HS256 shared secret. The input, backup, and restore surfaces all
    // accept that canonical form, while the ordinary response accepts only
    // the runtime's exact redaction placeholder.
    let jwt_input = json!({"secret": jwt_secret});
    let jwt_redacted = json!({"secret": "[REDACTED]"});
    let valid_runtime_jwt: Consumer = serde_json::from_value(json!({
        "username": "alice",
        "credentials": {"jwt": [jwt_input]}
    }))
    .expect("valid JWT Consumer deserializes");
    assert!(
        valid_runtime_jwt.validate_fields().is_ok(),
        "the positive OpenAPI JWT form must pass runtime validation"
    );
    for component in ["JwtCredential", "JwtCredentialBackup"] {
        assert_component_validity(&spec, component, &jwt_input, true);
        assert_component_validity(&spec, component, &jwt_redacted, false);
    }
    assert_component_validity(&spec, "JwtCredentialRedacted", &jwt_redacted, true);
    assert_component_validity(&spec, "JwtCredentialRedacted", &jwt_input, false);
    for surface in ["ConsumerCreate", "ConsumerBackup", "ConsumerRestore"] {
        assert_component_validity(
            &spec,
            surface,
            &json!({"username": "alice", "credentials": {"jwt": [jwt_input]}}),
            true,
        );
    }
    assert_component_validity(
        &spec,
        "Consumer",
        &json!({"username": "alice", "credentials": {"jwt": [jwt_redacted]}}),
        true,
    );
    for supported_secret in [
        "🔐".repeat(32),
        "j".repeat(4096),
        format!("{}\t\n\r", "j".repeat(32)),
    ] {
        let supported = json!({"secret": supported_secret});
        let supported_runtime_jwt: Consumer = serde_json::from_value(json!({
            "username": "alice",
            "credentials": {"jwt": [supported]}
        }))
        .expect("supported JWT Consumer deserializes");
        assert!(supported_runtime_jwt.validate_fields().is_ok());
        assert_component_validity(&spec, "JwtCredential", &supported, true);
        assert_component_validity(&spec, "JwtCredentialBackup", &supported, true);
    }

    // Every credential maximum uses JSON Schema/Rust Unicode character
    // semantics, not UTF-8 byte length. The known non-JWT input and backup
    // components must accept 4096 multibyte characters and reject 4097.
    for (component, field) in [
        ("BasicAuthCredential", "password"),
        ("KeyAuthCredential", "key"),
        ("KeyAuthCredentialBackup", "key"),
        ("HmacAuthCredential", "secret"),
        ("HmacAuthCredentialBackup", "secret"),
        ("MtlsAuthCredential", "identity"),
    ] {
        assert_component_validity(&spec, component, &json!({(field): "🔐".repeat(4096)}), true);
        assert_component_validity(
            &spec,
            component,
            &json!({(field): "🔐".repeat(4097)}),
            false,
        );
    }
    for (component, field) in [
        ("KeyAuthCredential", "key"),
        ("KeyAuthCredentialBackup", "key"),
        ("MtlsAuthCredential", "identity"),
    ] {
        assert_component_validity(
            &spec,
            component,
            &json!({(field): format!("valid-value{}", '\u{0001}')}),
            false,
        );
    }
    for component in ["HmacAuthCredential", "HmacAuthCredentialBackup"] {
        assert_component_validity(
            &spec,
            component,
            &json!({"secret": format!("{}{}", "h".repeat(31), " ".repeat(64))}),
            false,
        );
        assert_component_validity(
            &spec,
            component,
            &json!({"secret": format!("{}{}", "h".repeat(32), '\u{0001}')}),
            false,
        );
    }
    let hmac_backup_description = spec["components"]["schemas"]["HmacAuthCredentialBackup"]
        ["properties"]["secret"]["description"]
        .as_str()
        .expect("HmacAuthCredentialBackup.secret description");
    assert!(hmac_backup_description.contains("at least 32 non-whitespace characters"));

    // Algorithm selectors and asymmetric/JWKS key material are not Consumer
    // JWT credential forms. jwt_auth always verifies HS256 with `secret`;
    // RSA/EC/JWKS verification belongs to the separate jwks_auth plugin.
    for unsupported in [
        json!({}),
        json!({"secret": null}),
        json!({"secret": 42}),
        json!({"secret": "short"}),
        json!({"secret": "🔐".repeat(31)}),
        json!({"secret": format!("{}{}", "j".repeat(32), '\u{0001}')}),
        json!({"secret": "j".repeat(4097)}),
        json!({"secret": "j".repeat(32), "algorithm": "HS256"}),
        json!({
            "secret": "j".repeat(32),
            "algorithm": "RS256",
            "public_key": "pem"
        }),
        json!({"secret": "j".repeat(32), "jwks": {"keys": []}}),
        json!({
            "secret": "j".repeat(32),
            "jwks_uri": "https://issuer.example/jwks.json"
        }),
    ] {
        let invalid_runtime_jwt: Consumer = serde_json::from_value(json!({
            "username": "alice",
            "credentials": {"jwt": [unsupported]}
        }))
        .expect("unsupported JWT Consumer still deserializes into the generic credential model");
        assert!(
            invalid_runtime_jwt.validate_fields().is_err(),
            "an unsupported OpenAPI JWT form must also fail runtime validation: {unsupported}"
        );
        for component in [
            "JwtCredential",
            "JwtCredentialBackup",
            "JwtCredentialRedacted",
        ] {
            assert_component_validity(&spec, component, &unsupported, false);
        }
        for surface in [
            "ConsumerCreate",
            "ConsumerBackup",
            "ConsumerRestore",
            "Consumer",
        ] {
            assert_component_validity(
                &spec,
                surface,
                &json!({"username": "alice", "credentials": {"jwt": [unsupported]}}),
                false,
            );
        }
    }

    for (component, instance) in [
        (
            "ConsumerCreate",
            json!({"username": "alice", "credentials": {"basicauth": [{"username": "alice"}]}}),
        ),
        (
            "ConsumerCreate",
            json!({"username": "alice", "credentials": {"basicauth": [{"password": "x", "password_hash": password_hash}]}}),
        ),
        (
            "ConsumerCreate",
            json!({"username": "alice", "credentials": {"basicauth": [{"password": "s3cret", "username": "alice"}]}}),
        ),
        (
            "ConsumerCreate",
            json!({"username": "alice", "credentials": {"jwt": [{"secret": "[REDACTED]"}]}}),
        ),
        (
            "ConsumerCreate",
            json!({"username": "alice", "credentials": {"hmac_auth": [{"secret": "[REDACTED]"}]}}),
        ),
        (
            "ConsumerBackup",
            json!({"username": "alice", "credentials": {"jwt": [{"secret": "[REDACTED]"}]}}),
        ),
        (
            "ConsumerBackup",
            json!({"username": "alice", "credentials": {"basicauth": [{"password_hash": "hmac_sha256:deadbeef"}]}}),
        ),
        (
            "ConsumerRestore",
            json!({"username": "alice", "credentials": {"hmac_auth": [{"secret": "short"}]}}),
        ),
    ] {
        assert_component_validity(&spec, component, &instance, false);
    }

    // The redacted surface forbids `basicauth` outright.
    assert_eq!(
        spec.pointer("/components/schemas/ConsumerCredentialsRedacted/properties/basicauth"),
        Some(&json!(false))
    );
    assert_eq!(
        spec.pointer("/components/schemas/ConsumerCredentialsRedacted/additionalProperties"),
        Some(&json!(false))
    );

    // Response and backup credential schemas never mark fields writeOnly, and
    // the redacted placeholder constants match the runtime-emitted marker.
    for component in [
        "ConsumerCredentialsRedacted",
        "ConsumerCredentialsBackup",
        "ConsumerCredentialsRestore",
        "KeyAuthCredentialRedacted",
        "JwtCredentialRedacted",
        "HmacAuthCredentialRedacted",
        "KeyAuthCredentialBackup",
        "JwtCredentialBackup",
        "HmacAuthCredentialBackup",
        "BasicAuthCredentialStored",
    ] {
        let definition = &spec["components"]["schemas"][component];
        assert!(definition.is_object(), "{component} must exist");
        assert!(
            !definition.to_string().contains("writeOnly"),
            "{component} is a response/backup surface and must not mark fields writeOnly"
        );
    }
    for (component, field) in [
        ("KeyAuthCredentialRedacted", "key"),
        ("JwtCredentialRedacted", "secret"),
        ("HmacAuthCredentialRedacted", "secret"),
    ] {
        assert_eq!(
            spec["components"]["schemas"][component]["properties"][field]["const"],
            json!("[REDACTED]"),
            "{component}.{field} must encode the exact runtime placeholder"
        );
    }

    // Each Consumer surface composes ConsumerBase with its own credentials map.
    for (surface, credentials_schema) in [
        ("Consumer", "ConsumerCredentialsRedacted"),
        ("ConsumerCreate", "ConsumerCredentialsInput"),
        ("ConsumerUpdate", "ConsumerCredentialsUpdateInput"),
        ("ConsumerBackup", "ConsumerCredentialsBackup"),
        ("ConsumerRestore", "ConsumerCredentialsRestore"),
    ] {
        let all_of = spec["components"]["schemas"][surface]["allOf"]
            .as_array()
            .unwrap_or_else(|| panic!("{surface} composes its credentials map via allOf"));
        assert_eq!(
            all_of[0]["$ref"],
            json!("#/components/schemas/ConsumerBase"),
            "{surface} must compose ConsumerBase"
        );
        assert_eq!(
            all_of[1]["properties"]["credentials"]["$ref"],
            json!(format!("#/components/schemas/{credentials_schema}")),
            "{surface} must wire {credentials_schema}"
        );
        assert_eq!(
            spec["components"]["schemas"][surface]["unevaluatedProperties"], false,
            "{surface} must mirror Consumer's deny_unknown_fields contract"
        );
        // Closed request/response/backup/restore surfaces must reject unknown
        // top-level fields the same way runtime `Consumer` serde does.
        for unknown_payload in [
            json!({"username": "alice", "unknown_top_level": true}),
            json!({"username": "alice", "unexpected": 1}),
        ] {
            assert_component_validity(&spec, surface, &unknown_payload, false);
            let serde_unknown = serde_json::from_value::<Consumer>(unknown_payload.clone());
            assert!(
                serde_unknown.is_err(),
                "Consumer serde must reject unknown fields for {unknown_payload}"
            );
        }
    }

    let credential_input = &spec["components"]["schemas"]["ConsumerCredentialInput"];
    assert!(credential_input.get("discriminator").is_none());
    assert!(
        credential_input["description"]
            .as_str()
            .expect("ConsumerCredentialInput description")
            .contains("cannot condition a request-body schema on a path parameter")
    );

    // Every operation references the correct surface schema.
    let paths = &spec["paths"];
    assert_eq!(
        paths["/consumers"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["data"]["items"]["$ref"],
        json!("#/components/schemas/Consumer")
    );
    assert_eq!(
        paths["/consumers"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/ConsumerCreate")
    );
    assert_eq!(
        paths["/consumers"]["post"]["responses"]["201"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/Consumer")
    );
    let consumer_id = &paths["/consumers/{id}"];
    assert_eq!(
        consumer_id["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/Consumer")
    );
    assert_eq!(
        consumer_id["put"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/ConsumerUpdate"),
        "PUT must use the update surface that also accepts `[REDACTED]` round-trip entries"
    );
    assert_eq!(
        consumer_id["put"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/Consumer")
    );
    let credentials = &paths["/consumers/{consumer_id}/credentials/{cred_type}"];
    let put_body = &credentials["put"]["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(
        put_body["oneOf"][0]["$ref"],
        json!("#/components/schemas/ConsumerCredentialInput")
    );
    assert_eq!(
        put_body["oneOf"][1]["items"]["$ref"],
        json!("#/components/schemas/ConsumerCredentialInput")
    );
    assert_eq!(
        credentials["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/ConsumerCredentialInput")
    );
    // PUT/POST advertise only built-in credential types; DELETE stays broad so
    // path-safe custom types remain removable. Path-level parameters must not
    // also declare `cred_type` (that would conflict with the per-operation
    // overrides).
    assert!(
        credentials["parameters"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|parameter| parameter["name"] != "cred_type"),
        "shared path parameters must not declare cred_type when operations override it"
    );
    let built_in_enum = json!(["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"]);
    assert_eq!(
        spec["components"]["schemas"]["BuiltInCredentialType"]["enum"], built_in_enum,
        "BuiltInCredentialType must match ALLOWED_CREDENTIAL_TYPES"
    );
    for operation in ["put", "post"] {
        assert_eq!(
            credentials[operation]["parameters"][0]["name"],
            json!("cred_type"),
            "credential {operation} must override cred_type"
        );
        assert_eq!(
            credentials[operation]["parameters"][0]["schema"]["$ref"],
            json!("#/components/schemas/BuiltInCredentialType"),
            "credential {operation} must advertise only built-in types"
        );
        assert_eq!(
            credentials[operation]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            json!("#/components/schemas/Consumer"),
            "credential {operation} returns the redacted Consumer surface"
        );
    }
    assert_eq!(
        credentials["delete"]["parameters"][0]["schema"]["$ref"],
        json!("#/components/schemas/CredentialTypeName"),
        "credential DELETE must keep the broader path-safe CredentialTypeName"
    );
    assert_eq!(
        paths["/consumers/{consumer_id}/credentials/{cred_type}/{index}"]["parameters"]
            .as_array()
            .expect("indexed credential path parameters")
            .iter()
            .find(|parameter| parameter["name"] == "cred_type")
            .expect("indexed credential path declares cred_type")["schema"]["$ref"],
        json!("#/components/schemas/BuiltInCredentialType"),
        "indexed credential DELETE is built-in-only, matching runtime"
    );
    assert_eq!(
        paths["/consumers/{consumer_id}/credentials/{cred_type}/{index}"]["delete"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["$ref"],
        json!("#/components/schemas/Consumer")
    );
    assert_eq!(
        spec.pointer("/components/schemas/BatchCreateRequest/properties/consumers/items/$ref"),
        Some(&json!("#/components/schemas/ConsumerCreate"))
    );
    assert_eq!(
        spec.pointer("/components/schemas/BatchCreateRequest/additionalProperties"),
        Some(&json!(false)),
        "POST /batch envelope must reject unknown top-level keys"
    );
    assert_eq!(
        spec.pointer("/components/schemas/BackupResponse/properties/consumers/items/$ref"),
        Some(&json!("#/components/schemas/ConsumerBackup"))
    );
    assert_eq!(
        spec.pointer("/components/schemas/RestoreRequest/properties/consumers/items/$ref"),
        Some(&json!("#/components/schemas/ConsumerRestore"))
    );
}

#[test]
fn proxy_create_schema_requires_upstream_or_direct_backend() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let choices = spec
        .pointer("/components/schemas/ProxyCreate/allOf/1/anyOf")
        .and_then(serde_json::Value::as_array)
        .expect("ProxyCreate must require an upstream or direct backend");

    assert_eq!(choices[0]["required"], json!(["upstream_id"]));
    assert_eq!(
        choices[0]["properties"]["upstream_id"]["minLength"],
        json!(1)
    );
    assert_eq!(
        choices[1]["required"],
        json!(["backend_host", "backend_port"])
    );
    assert_eq!(
        choices[1]["properties"]["backend_host"]["minLength"],
        json!(1)
    );
    assert_eq!(
        choices[1]["properties"]["backend_port"]["minimum"],
        json!(1)
    );
}

/// The documented read-modify-write flow tells a client it may PUT back a
/// `Consumer` response it never held the secrets for, so the PUT request schema
/// must accept the exact `[REDACTED]` projection the server emits while create,
/// batch, and restore stay strict. `[REDACTED]` is simultaneously reserved as a
/// stored value, and credential type keys must stay path-safe so every stored
/// type remains addressable by the DELETE credential route.
#[test]
fn consumer_update_surface_accepts_redaction_placeholders_and_reserves_them() {
    use ferrum_edge::config::types::Consumer;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let jwt_secret = "j".repeat(32);
    let hmac_secret = "h".repeat(32);
    let redacted_response_body = json!({
        "username": "alice",
        "credentials": {
            "keyauth": [{"key": "[REDACTED]"}],
            "jwt": [{"secret": "[REDACTED]"}],
            "hmac_auth": [{"secret": "[REDACTED]"}],
            "mtls_auth": [{"identity": "client.example.com"}]
        }
    });
    // The server's own redacted response is a valid update body, and is still
    // rejected by the strict create/batch and restore surfaces.
    assert_component_validity(&spec, "ConsumerUpdate", &redacted_response_body, true);
    for strict in ["ConsumerCreate", "ConsumerRestore", "ConsumerBackup"] {
        assert_component_validity(&spec, strict, &redacted_response_body, false);
    }

    // Real values still validate on the update surface, so rotation by PUT is
    // expressible in the same schema.
    let real_values = json!({
        "username": "alice",
        "credentials": {
            "keyauth": [{"key": "live-api-key"}],
            "jwt": [{"secret": jwt_secret}],
            "hmac_auth": [{"secret": hmac_secret}]
        }
    });
    assert_component_validity(&spec, "ConsumerUpdate", &real_values, true);
    assert_component_validity(&spec, "ConsumerCreate", &real_values, true);

    // The two `oneOf` branches must stay mutually exclusive, which requires
    // real keyauth input and backup schemas to exclude the placeholder
    // explicitly. Redacted/update-marker alternatives keep accepting it.
    for real_keyauth in ["KeyAuthCredential", "KeyAuthCredentialBackup"] {
        assert_component_validity(&spec, real_keyauth, &json!({"key": "[REDACTED]"}), false);
        assert_eq!(
            spec["components"]["schemas"][real_keyauth]["properties"]["key"]["not"]["const"],
            json!("[REDACTED]"),
            "{real_keyauth}.key must reserve the redaction marker"
        );
    }
    for update in [
        "KeyAuthCredentialUpdate",
        "JwtCredentialUpdate",
        "HmacAuthCredentialUpdate",
    ] {
        let field = if update.starts_with("KeyAuth") {
            "key"
        } else {
            "secret"
        };
        assert_component_validity(&spec, update, &json!({(field): "[REDACTED]"}), true);
    }
    assert_component_validity(
        &spec,
        "KeyAuthCredentialRedacted",
        &json!({"key": "[REDACTED]"}),
        true,
    );

    // `[REDACTED]` is reserved at runtime on every write surface, including the
    // update surface, which only accepts it as a marker the server replaces
    // before validation, and restore/backup payloads that carry real keys.
    let placeholder_consumer: Consumer = serde_json::from_value(json!({
        "username": "alice",
        "credentials": {"keyauth": [{"key": "[REDACTED]"}]}
    }))
    .expect("placeholder Consumer deserializes");
    let errors = placeholder_consumer
        .validate_fields()
        .expect_err("the reserved redaction placeholder is not a storable key");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("reserved redaction placeholder")),
        "expected a reserved-placeholder rejection, got {errors:?}"
    );
    assert_component_validity(
        &spec,
        "ConsumerRestore",
        &json!({
            "username": "alice",
            "credentials": {"keyauth": [{"key": "[REDACTED]"}]}
        }),
        false,
    );

    // Credential type keys are one path-safe URI segment on every input
    // surface, so a hidden custom type cannot be created at an address the
    // DELETE credential route cannot express.
    for unsafe_key in [
        "custom/auth",
        "custom%2Fauth",
        "",
        "custom auth",
        "custom.auth",
        "..",
    ] {
        let instance = json!({
            "username": "alice",
            "credentials": {(unsafe_key): [{"token": "value"}]}
        });
        for surface in ["ConsumerCreate", "ConsumerUpdate", "ConsumerRestore"] {
            assert_component_validity(&spec, surface, &instance, false);
        }
        let consumer: Consumer =
            serde_json::from_value(instance).expect("Consumer with a custom key deserializes");
        assert!(
            consumer.validate_fields().is_err(),
            "runtime must reject the non-path-safe credential type {unsafe_key:?}"
        );
    }

    // A previously valid, path-safe custom type keeps working end to end.
    let custom = json!({
        "username": "alice",
        "credentials": {"custom_auth-2": [{"api_token": "opaque-value"}]}
    });
    for surface in ["ConsumerCreate", "ConsumerUpdate", "ConsumerRestore"] {
        assert_component_validity(&spec, surface, &custom, true);
    }
    let custom_consumer: Consumer =
        serde_json::from_value(custom).expect("custom-credential Consumer deserializes");
    custom_consumer
        .validate_fields()
        .expect("a path-safe custom credential type stays valid");
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

/// Admin operations that can return `408 Request Timeout` when
/// `FERRUM_ADMIN_BODY_READ_TIMEOUT_SECONDS` expires.
///
/// Shared-gate members mirror `body_consuming_route_role` in
/// `src/admin/mod.rs`. `POST`/`PUT /api-specs` collect through their own
/// handlers with the same deadline and must stay in this set even though they
/// are not admitted by that table. Action routes that never buffer a body
/// (for example `POST /admin/tls/rotate/{surface}`) must not appear here.
fn admin_body_timeout_408_inventory() -> BTreeSet<(String, String)> {
    const OPS: &[(&str, &str)] = &[
        ("POST", "/proxies"),
        ("PUT", "/proxies/{id}"),
        ("POST", "/consumers"),
        ("PUT", "/consumers/{id}"),
        ("POST", "/consumers/{consumer_id}/credentials/{cred_type}"),
        ("PUT", "/consumers/{consumer_id}/credentials/{cred_type}"),
        ("POST", "/plugins/config"),
        ("PUT", "/plugins/config/{id}"),
        ("POST", "/upstreams"),
        ("PUT", "/upstreams/{id}"),
        ("POST", "/gateway-trust-bundles"),
        ("PUT", "/gateway-trust-bundles/{id}"),
        ("POST", "/namespaces"),
        ("PUT", "/namespaces/{name}"),
        ("POST", "/batch"),
        ("POST", "/restore"),
        ("POST", "/mesh/egress-scope/test"),
        ("POST", "/admin/tls/acme/certificates"),
        ("PUT", "/admin/tls/acme/certificates/{id}"),
        ("POST", "/admin/tls/acme/renew/{id}"),
        ("POST", "/admin/tls/acme/orders"),
        ("POST", "/admin/tls/acme/orders/{id}/finalize"),
        ("POST", "/admin/tls/certificates"),
        ("PUT", "/admin/tls/certificates/{id}"),
        ("POST", "/admin/tls/ca-bundles"),
        ("PUT", "/admin/tls/ca-bundles/{id}"),
        ("POST", "/admin/tls/crls"),
        ("PUT", "/admin/tls/crls/{id}"),
        ("POST", "/admin/tls/ocsp-responses"),
        ("PUT", "/admin/tls/ocsp-responses/{id}"),
        ("POST", "/admin/tls/jwks"),
        ("PUT", "/admin/tls/jwks/{id}"),
        ("POST", "/admin/tls/validate"),
        ("POST", "/api-specs"),
        ("PUT", "/api-specs/{id}"),
    ];
    OPS.iter()
        .map(|(method, path)| ((*method).to_string(), (*path).to_string()))
        .collect()
}

fn openapi_request_timeout_operations(spec: &serde_json::Value) -> BTreeSet<(String, String)> {
    let paths = spec["paths"]
        .as_object()
        .expect("OpenAPI paths is an object");
    let mut operations = BTreeSet::new();

    for (path, path_item) in paths {
        let path_item = path_item
            .as_object()
            .unwrap_or_else(|| panic!("path item {path} is an object"));
        for method in OPENAPI_HTTP_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            let Some(response) = operation["responses"].get("408") else {
                continue;
            };
            assert_eq!(
                response.get("$ref").and_then(|value| value.as_str()),
                Some("#/components/responses/RequestTimeout"),
                "{method} {path} documents 408 without #/components/responses/RequestTimeout"
            );
            operations.insert((method.to_ascii_uppercase(), path.clone()));
        }
    }

    operations
}

/// Parse `body_consuming_route_role` match arms into normalized `(METHOD, path)`
/// pairs (`{param}` → `{}`) so the pin cannot drift from the runtime gate.
fn shared_body_gate_operations_from_source() -> BTreeSet<(String, String)> {
    let source = include_str!("../../src/admin/mod.rs");
    let start = source
        .find("fn body_consuming_route_role")
        .expect("body_consuming_route_role must exist");
    let after = &source[start..];
    let end = after
        .find("\nfn tls_route_required_role")
        .expect("tls_route_required_role must follow body_consuming_route_role");
    let gate = &after[..end];

    let arm = Regex::new(
        r#"(?x)
        (?:^|\n)\s*
        ((?:\[[^\]]+\])(?:\s*\|\s*\[[^\]]+\])*)
        (?:\s+if\s+(is_post|is_put))?
        \s*=>
        "#,
    )
    .expect("body-gate arm regex compiles");

    let mut operations = BTreeSet::new();
    for captures in arm.captures_iter(gate) {
        let patterns = captures[1].to_string();
        let methods: &[&str] = match captures.get(2).map(|value| value.as_str()) {
            Some("is_post") => &["POST"],
            Some("is_put") => &["PUT"],
            None => &["POST", "PUT"],
            Some(other) => panic!("unsupported body-gate method guard `{other}`"),
        };

        for pattern in patterns.split('|').map(str::trim) {
            let inner = pattern
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or_else(|| panic!("body-gate pattern must be a slice: {pattern}"));
            let mut segments = Vec::new();
            for part in inner.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if part == "_" {
                    segments.push("{}");
                    continue;
                }
                let literal = part
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("unsupported body-gate segment `{part}`"));
                segments.push(literal);
            }
            let path = format!("/{}", segments.join("/"));
            for method in methods {
                operations.insert(((*method).to_string(), path.clone()));
            }
        }
    }

    assert!(
        !operations.is_empty(),
        "body_consuming_route_role parser found no body-consuming arms"
    );
    operations
}

fn normalized_operation_set(operations: &BTreeSet<(String, String)>) -> BTreeSet<(String, String)> {
    operations
        .iter()
        .map(|(method, path)| (method.clone(), normalized_path_template(path)))
        .collect()
}

#[test]
fn admin_body_timeout_routes_document_request_timeout_in_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let pinned = admin_body_timeout_408_inventory();
    let documented = openapi_request_timeout_operations(&spec);
    assert_eq!(
        documented, pinned,
        "OpenAPI RequestTimeout (408) inventory drifted from the admin body-timeout route pin"
    );

    let mut expected_from_runtime = shared_body_gate_operations_from_source();
    // `/api-specs` uses the shared deadline via its own collectors, not the
    // shared `body_bytes` gate.
    expected_from_runtime.insert(("POST".to_string(), "/api-specs".to_string()));
    expected_from_runtime.insert(("PUT".to_string(), "/api-specs/{}".to_string()));

    assert_eq!(
        normalized_operation_set(&documented),
        expected_from_runtime,
        "runtime body-consuming inventory (shared gate + api-specs) drifted from OpenAPI 408 docs"
    );

    let api_specs_source = include_str!("../../src/admin/api_specs/handlers.rs");
    assert!(
        api_specs_source.contains("ApiSpecError::BodyTimeout")
            && api_specs_source.contains("collect_body_with_limits"),
        "api-specs must keep the shared body-read deadline that OpenAPI documents as 408"
    );
}

/// Store-backed TLS/ACME admin operations that can return `500 Internal Server Error`
/// when a shared managed or ACME store is unavailable, unreadable, misconfigured,
/// or when an offloaded store write cannot complete.
fn admin_tls_store_backed_500_operation_ids() -> BTreeSet<&'static str> {
    const OPS: &[&str] = &[
        "listAcmeCertificates",
        "importAcmeCertificate",
        "getAcmeCertificate",
        "updateAcmeCertificate",
        "deleteAcmeCertificate",
        "listAcmeOrders",
        "createAcmeOrder",
        "listAcmeAccounts",
        "renewAcmeCertificate",
        "getAcmeOrder",
        "deleteAcmeOrder",
        "finalizeAcmeOrder",
        "listManagedTlsCertificates",
        "createManagedTlsCertificate",
        "getManagedTlsCertificate",
        "updateManagedTlsCertificate",
        "deleteManagedTlsCertificate",
        "listManagedTlsCaBundles",
        "createManagedTlsCaBundle",
        "getManagedTlsCaBundle",
        "updateManagedTlsCaBundle",
        "deleteManagedTlsCaBundle",
        "listManagedTlsCrls",
        "createManagedTlsCrl",
        "getManagedTlsCrl",
        "updateManagedTlsCrl",
        "deleteManagedTlsCrl",
        "listManagedTlsOcspResponses",
        "createManagedTlsOcspResponse",
        "getManagedTlsOcspResponse",
        "updateManagedTlsOcspResponse",
        "deleteManagedTlsOcspResponse",
        "listManagedTlsJwks",
        "createManagedTlsJwks",
        "getManagedTlsJwks",
        "updateManagedTlsJwks",
        "deleteManagedTlsJwks",
    ];
    OPS.iter().copied().collect()
}

/// TLS admin operations that never consult the managed/ACME stores and must not
/// document a store-backed `500`.
fn admin_tls_non_store_operation_ids() -> BTreeSet<&'static str> {
    const OPS: &[&str] = &[
        "listTlsInventory",
        "listTlsEvents",
        "forceRotateTlsSurface",
        "validateTlsMaterial",
    ];
    OPS.iter().copied().collect()
}

fn openapi_operation_by_id<'a>(
    spec: &'a serde_json::Value,
    operation_id: &str,
) -> (&'a str, &'a str, &'a serde_json::Value) {
    for (path, path_item) in spec["paths"].as_object().expect("paths is an object") {
        let path_item = path_item
            .as_object()
            .unwrap_or_else(|| panic!("path item {path} is an object"));
        for method in OPENAPI_HTTP_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            if operation["operationId"].as_str() == Some(operation_id) {
                return (method, path.as_str(), operation);
            }
        }
    }
    panic!("operationId `{operation_id}` not found in openapi.yaml");
}

#[test]
fn admin_tls_store_backed_operations_document_internal_server_error() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for operation_id in admin_tls_store_backed_500_operation_ids() {
        let (method, path, operation) = openapi_operation_by_id(&spec, operation_id);
        assert_eq!(
            operation["responses"]["500"]["$ref"], "#/components/responses/InternalServerError",
            "{method} {path} ({operation_id}) must document InternalServerError"
        );
    }

    for operation_id in admin_tls_non_store_operation_ids() {
        let (method, path, operation) = openapi_operation_by_id(&spec, operation_id);
        assert!(
            operation["responses"].get("500").is_none(),
            "{method} {path} ({operation_id}) must not document a store-backed 500"
        );
    }
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
    let yaml: Value = serde_yaml::from_str(include_str!("../../openapi.yaml"))
        .expect("openapi.yaml parses without duplicate mapping keys");
    let spec = serde_json::to_value(yaml).expect("openapi.yaml is JSON-compatible");
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
fn waf_schema_rejects_unknown_keys_and_keeps_intentional_open_maps() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for schema in [
        "WafPluginConfig",
        "WafStreamConfig",
        "WafStreamSignature",
        "WafRule",
        "WafExemptions",
    ] {
        assert_eq!(
            spec["components"]["schemas"][schema]["additionalProperties"],
            json!(false),
            "{schema} must reject unknown properties"
        );
    }

    assert_eq!(
        spec["components"]["schemas"]["WafPluginConfig"]["properties"]["scoring"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        spec["components"]["schemas"]["WafRule"]["properties"]["conditions"]["additionalProperties"],
        json!(false)
    );

    // Intentionally open operator-defined maps.
    assert!(
        spec["components"]["schemas"]["WafPluginConfig"]["properties"]["rule_modes"]
            .get("additionalProperties")
            .is_some_and(|v| v != &json!(false)),
        "rule_modes must remain an open rule-id map"
    );
    assert!(
        spec["components"]["schemas"]["WafPluginConfig"]["properties"]["rule_overrides"]
            .get("additionalProperties")
            .is_some_and(|v| v.is_object()),
        "rule_overrides must remain an open rule-id map of closed objects"
    );
    assert_eq!(
        spec["components"]["schemas"]["WafPluginConfig"]["properties"]["rule_overrides"]["additionalProperties"]
            ["additionalProperties"],
        json!(false),
        "rule_overrides values must be closed"
    );
    assert!(
        spec["components"]["schemas"]["WafRule"]["properties"]["conditions"]["properties"]
            ["headers"]
            .get("additionalProperties")
            .is_some_and(|v| v != &json!(false)),
        "conditions.headers must remain an open header-name map"
    );
    assert!(
        spec["components"]["schemas"]["WafExemptions"]["properties"]["header_present"]
            .get("additionalProperties")
            .is_some_and(|v| v != &json!(false)),
        "global_exemptions.header_present must remain an open header-name map"
    );

    let root = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/WafPluginConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&root)
        .expect("WafPluginConfig schema compiles");
    assert!(
        validator
            .validate(&json!({
                "mode": "enforce",
                "default_rule_action": "enforce",
                "rule_modes": { "FE-XSS-001": "enforce" },
                "global_exemptions": { "header_present": { "x-skip-waf": null } }
            }))
            .is_ok()
    );
    assert!(
        validator
            .validate(&json!({ "default_rule_actoin": "enforce" }))
            .is_err(),
        "schema must reject top-level enforcement typo"
    );
    assert!(
        validator
            .validate(&json!({
                "stream": { "tcp_require_tsl": true }
            }))
            .is_err(),
        "schema must reject stream guard typo"
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

    let plugin_docs = include_str!("../../docs/plugins.md");
    assert!(
        plugin_docs.contains("at most 255 Unicode characters"),
        "access_control docs must state the 255-character username and group limits"
    );
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

/// Issue #5004: `RateLimitingConfig` / `RateLimitingRuleConfig` must admit
/// exactly what the constructor admits, so schema-driven editors and clients do
/// not disagree with file/admin admission. Table-driven both ways; the three
/// rules JSON Schema cannot express are asserted explicitly as residuals rather
/// than implied to be parity.
#[test]
fn rate_limiting_schema_and_runtime_admission_agree() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/RateLimitingConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("RateLimitingConfig schema compiles");

    for config in [
        // Baseline.
        json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 2}]}),
        // `null` is the same as omitting the dimension, and the parser
        // normalizes ASCII case on limit_by / sync_mode / scope.
        json!({
            "limit_by": null,
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 2}]
        }),
        json!({
            "limit_by": "IP",
            "sync_mode": "LOCAL",
            "limits": [{"scope": "DEFAULT", "window_seconds": 60, "max_requests": 2}]
        }),
        json!({
            "limit_by": "spiffe",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        // Consumer-scoped rules alongside the required default rule.
        json!({
            "limit_by": "consumer",
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 1000}
            ]
        }),
        // The exact documented Redis example (docs/plugins.md).
        json!({
            "limit_by": "consumer",
            "expose_headers": true,
            "sync_mode": "redis",
            "redis_url": "redis://redis-host:6379/0",
            "redis_tls": true,
            "redis_key_prefix": "myapp:rate_limiting",
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {
                    "scope": "consumers",
                    "consumers": ["premium-app", "partner-app"],
                    "requests_per_minute": 1000
                },
                {
                    "scope": "consumers",
                    "consumers": ["batch-worker"],
                    "window_seconds": 60,
                    "max_requests": 250
                }
            ]
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "schema should accept: {config}"
        );
        assert!(
            ferrum_edge::plugins::validate_plugin_config("rate_limiting", &config).is_ok(),
            "runtime should accept schema-valid config: {config}"
        );
    }

    for config in [
        // No `scope: default` rule at all.
        json!({
            "limit_by": "consumer",
            "limits": [{"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 1}]
        }),
        // Two default rules.
        json!({
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {"scope": "default", "requests_per_minute": 10}
            ]
        }),
        // A consumers rule without `limit_by: consumer` (explicit and implied).
        json!({
            "limit_by": "ip",
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 10}
            ]
        }),
        json!({
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 10}
            ]
        }),
        // `limit_by: null` means `ip`, so it is not a consumer dimension either.
        json!({
            "limit_by": null,
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 10}
            ]
        }),
        // One identity repeated inside a single consumers rule.
        json!({
            "limit_by": "consumer",
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {
                    "scope": "consumers",
                    "consumers": ["alice", "alice"],
                    "requests_per_minute": 10
                }
            ]
        }),
        // Centralized mode without an endpoint.
        json!({
            "sync_mode": "redis",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        // Latent/explicit Redis scalars the constructor bounds.
        json!({
            "redis_key_prefix": "",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        json!({
            "redis_connect_timeout_seconds": 0,
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        json!({
            "redis_connect_timeout_seconds": -1,
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        json!({
            "redis_health_check_interval_seconds": 0,
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        // Issue #5005: an unusable database selector.
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/banana",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "schema should reject: {config}"
        );
        assert!(
            ferrum_edge::plugins::validate_plugin_config("rate_limiting", &config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }

    // Documented residuals: the constructor is stricter than any JSON Schema
    // can be here, so these are refused at admission and accepted by the
    // schema. Both halves are asserted so a future schema tightening (or a
    // constructor relaxation) has to update this list deliberately.
    for config in [
        // One identity named in two *different* consumers rules.
        json!({
            "limit_by": "consumer",
            "limits": [
                {"scope": "default", "requests_per_minute": 100},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 10},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_minute": 20}
            ]
        }),
        // An out-of-range TCP port in redis_url.
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:99999/0",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "documented residual must still be schema-valid: {config}"
        );
        assert!(
            ferrum_edge::plugins::validate_plugin_config("rate_limiting", &config).is_err(),
            "documented residual must be refused at admission: {config}"
        );
    }

    let plugin_docs = include_str!("../../docs/plugins.md");
    assert!(
        plugin_docs.contains("Three residual rules JSON Schema cannot express"),
        "rate_limiting docs must state which admission rules the schema cannot express"
    );
}

#[test]
fn rate_limiting_config_schema_requires_redis_pool_size_minimum() {
    // Issue #2304: redis_pool_size remains operator-facing and must advertise
    // minimum: 1 in OpenAPI to match RedisConfig admission (rejects 0).
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/RateLimitingConfig")
        .expect("RateLimitingConfig component exists");
    assert_eq!(schema["properties"]["redis_pool_size"]["minimum"], json!(1));
    assert_eq!(schema["properties"]["redis_pool_size"]["default"], json!(4));

    // Named consumers from the issue scope also keep the field with minimum ≥ 1.
    for schema_name in ["GraphqlConfig", "GrpcMethodRouterConfig"] {
        let consumer = spec
            .pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("{schema_name} component exists"));
        assert_eq!(
            consumer["properties"]["redis_pool_size"]["minimum"],
            json!(1),
            "{schema_name} must keep redis_pool_size.minimum=1"
        );
    }
}

/// GHSA-q3p3-94cj-8wh6 / GHSA-q97w-jvf6-q254 /
/// GHSA-5h4h-3qcv-f3rw / GHSA-jjjw-rqjm-fvf3: rate-limiter components must
/// expose closed root objects and bounded numeric ranges that match the runtime
/// allowlists, so a typo or an extreme value is rejected by schema-driven
/// authoring tools and admission.
#[test]
fn rate_limiter_configs_are_closed_and_bounded_in_openapi() {
    use ferrum_edge::plugins::ai_rate_limiter::AI_RATE_LIMITER_CONFIG_KEYS;
    use ferrum_edge::plugins::grpc_method_router::GRPC_METHOD_ROUTER_CONFIG_KEYS;
    use ferrum_edge::plugins::rate_limiting::RATE_LIMITING_CONFIG_KEYS;
    use ferrum_edge::plugins::udp_rate_limiting::UDP_RATE_LIMITING_CONFIG_KEYS;
    use ferrum_edge::plugins::utils::rate_limit::{
        MAX_RATE_LIMIT_MAX_REQUESTS, MAX_RATE_LIMIT_WINDOW_SECONDS,
    };
    use ferrum_edge::plugins::ws_rate_limiting::WS_RATE_LIMITING_CONFIG_KEYS;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for (schema_name, runtime_keys) in [
        ("RateLimitingConfig", RATE_LIMITING_CONFIG_KEYS),
        ("GrpcMethodRouterConfig", GRPC_METHOD_ROUTER_CONFIG_KEYS),
        ("UdpRateLimitingConfig", UDP_RATE_LIMITING_CONFIG_KEYS),
        ("AiRateLimiterConfig", AI_RATE_LIMITER_CONFIG_KEYS),
        ("WsRateLimitingConfig", WS_RATE_LIMITING_CONFIG_KEYS),
    ] {
        let schema = spec
            .pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("{schema_name} component exists"));
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{schema_name} must be a closed object"
        );
        let schema_fields: BTreeSet<_> = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema_name} properties"))
            .keys()
            .map(String::as_str)
            .collect();
        let runtime_fields: BTreeSet<_> = runtime_keys.iter().copied().collect();
        assert_eq!(
            schema_fields, runtime_fields,
            "{schema_name} OpenAPI/runtime key drift"
        );
    }

    let window_max = json!(MAX_RATE_LIMIT_WINDOW_SECONDS);
    let requests_max = json!(MAX_RATE_LIMIT_MAX_REQUESTS);
    for pointer in [
        "/components/schemas/RateLimitingRuleConfig/properties/window_seconds/maximum",
        "/components/schemas/UdpRateLimitingConfig/properties/window_seconds/maximum",
        "/components/schemas/AiRateLimiterConfig/properties/window_seconds/maximum",
        "/components/schemas/GraphqlRateSpec/properties/window_seconds/maximum",
        "/components/schemas/RateSpec/properties/window_seconds/maximum",
    ] {
        assert_eq!(
            spec.pointer(pointer),
            Some(&window_max),
            "{pointer} must advertise the runtime window bound"
        );
    }
    for pointer in [
        "/components/schemas/RateLimitingRuleConfig/properties/max_requests/maximum",
        "/components/schemas/RateLimitingRuleConfig/properties/requests_per_second/maximum",
        "/components/schemas/RateLimitingRuleConfig/properties/requests_per_minute/maximum",
        "/components/schemas/RateLimitingRuleConfig/properties/requests_per_hour/maximum",
        "/components/schemas/GraphqlRateSpec/properties/max_requests/maximum",
        "/components/schemas/RateSpec/properties/max_requests/maximum",
    ] {
        assert_eq!(
            spec.pointer(pointer),
            Some(&requests_max),
            "{pointer} must advertise the runtime request-cap bound"
        );
    }
}

const REDIS_URL_DATABASE_SELECTOR_PATTERN: &str =
    r"^rediss?://[^/?#\s]+(?:/\d{0,10})?(?:\?[^\s#]*)?$";

fn plugin_docs_section<'a>(plugin_docs: &'a str, plugin_name: &str) -> &'a str {
    plugin_docs
        .split(&format!("### `{plugin_name}`"))
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .unwrap_or_else(|| panic!("{plugin_name} docs section"))
}

fn component_validator(spec: &serde_json::Value, schema_name: &str) -> jsonschema::Validator {
    let validator_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/components/schemas/{schema_name}"),
        "components": spec["components"].clone()
    });
    jsonschema::draft202012::options()
        .build(&validator_schema)
        .unwrap_or_else(|error| panic!("{schema_name} schema compiles: {error}"))
}

fn assert_schema_and_constructor(
    validator: &jsonschema::Validator,
    plugin_name: &str,
    name: &str,
    config: &serde_json::Value,
    schema_valid: bool,
    constructor_valid: bool,
) {
    assert_eq!(
        validator.validate(config).is_ok(),
        schema_valid,
        "{plugin_name} {name}: unexpected schema result for {config}"
    );
    match (
        ferrum_edge::plugins::create_plugin(plugin_name, config),
        constructor_valid,
    ) {
        (Ok(Some(_)), true) | (Err(_), false) => {}
        (Ok(None), _) => panic!("{plugin_name} {name}: factory returned None"),
        (Ok(Some(_)), false) => {
            panic!("{plugin_name} {name}: constructor accepted {config}")
        }
        (Err(err), true) => {
            panic!("{plugin_name} {name}: constructor rejected {config}: {err}")
        }
    }
}

fn redis_sync_mode_guard<'a>(
    schema: &'a serde_json::Value,
    schema_name: &str,
) -> &'a serde_json::Value {
    schema["allOf"]
        .as_array()
        .unwrap_or_else(|| panic!("{schema_name} allOf"))
        .iter()
        .find(|guard| {
            guard["if"]["properties"]["sync_mode"]["pattern"] == json!("^[rR][eE][dD][iI][sS]$")
        })
        .unwrap_or_else(|| panic!("{schema_name} sync_mode=redis conditional guard"))
}

/// Issue #5358 / #5360: `WsRateLimitingConfig` must admit the same configs the
/// constructor admits, except arithmetic burst/refill residuals the schema
/// cannot express. `redis_key_prefix` must not promise shared instance budgets.
#[test]
fn ws_rate_limiting_schema_matches_constructor_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/WsRateLimitingConfig")
        .expect("WsRateLimitingConfig component exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["sync_mode"]["pattern"],
        json!("^([lL][oO][cC][aA][lL]|[rR][eE][dD][iI][sS])$")
    );
    assert!(schema["properties"]["sync_mode"].get("enum").is_none());
    assert_eq!(
        schema["properties"]["redis_key_prefix"]["minLength"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_connect_timeout_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_connect_timeout_seconds"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    assert_eq!(
        schema["properties"]["redis_health_check_interval_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_health_check_interval_seconds"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    let redis_guard = redis_sync_mode_guard(schema, "WsRateLimitingConfig");
    assert_eq!(redis_guard["if"]["required"], json!(["sync_mode"]));
    assert_eq!(redis_guard["then"]["required"], json!(["redis_url"]));

    let prefix_description = schema["properties"]["redis_key_prefix"]["description"]
        .as_str()
        .expect("redis_key_prefix description");
    assert!(
        prefix_description.contains("per-instance UUID"),
        "redis_key_prefix must describe the instance UUID that partitions keys"
    );
    assert!(
        !prefix_description.contains("every instance configured with the same prefix increments"),
        "redis_key_prefix must not promise shared per-connection budgets"
    );

    let docs = plugin_docs_section(include_str!("../../docs/plugins.md"), "ws_rate_limiting");
    assert!(
        docs.contains("per-instance UUID"),
        "docs/plugins.md ws_rate_limiting section must describe instance UUID isolation"
    );
    assert!(
        !docs.contains(
            "setting it explicitly is the documented opt-in for a deliberately shared budget"
        ),
        "docs/plugins.md ws_rate_limiting must not promise shared instance budgets"
    );
    assert!(
        docs.contains("Parsed case-insensitively"),
        "docs/plugins.md ws_rate_limiting must document sync_mode case folding"
    );

    let validator = component_validator(&spec, "WsRateLimitingConfig");
    let accepted = [
        json!({}),
        json!({"frames_per_second": 50, "burst_size": 100}),
        json!({"sync_mode": "LOCAL"}),
        json!({
            "sync_mode": "REDIS",
            "redis_url": "redis://cache.internal:6379/0"
        }),
        json!({
            "frames_per_second": 50,
            "burst_size": 100,
            "close_reason": "Rate limit exceeded",
            "sync_mode": "redis",
            "redis_url": "redis://redis-host:6379/2"
        }),
        json!({"close_reason": "レート制限"}),
    ];
    for config in &accepted {
        assert_schema_and_constructor(
            &validator,
            "ws_rate_limiting",
            "accepted",
            config,
            true,
            true,
        );
    }

    let rejected = [
        json!({"sync_mode": "redis"}),
        json!({"redis_key_prefix": ""}),
        json!({"redis_health_check_interval_seconds": 0}),
        json!({"redis_health_check_interval_seconds": -1}),
        json!({"redis_connect_timeout_seconds": 0}),
        json!({"frames_per_second": 0}),
        json!({"sync_mode": "mysql"}),
        json!({"frames_per_secod": 10}),
    ];
    for config in &rejected {
        assert_schema_and_constructor(
            &validator,
            "ws_rate_limiting",
            "rejected",
            config,
            false,
            false,
        );
    }

    // Integer-multiple / refill-window constraints stay constructor-only.
    assert_schema_and_constructor(
        &validator,
        "ws_rate_limiting",
        "non-integral burst residual",
        &json!({"frames_per_second": 3, "burst_size": 10}),
        true,
        false,
    );
    assert_schema_and_constructor(
        &validator,
        "ws_rate_limiting",
        "refill window residual",
        &json!({"frames_per_second": 1, "burst_size": 4000}),
        true,
        false,
    );
}

/// Issue #5317: `AiRateLimiterConfig` must admit exactly what the constructor
/// admits — the unsigned bounds on `token_limit` and the Redis durations, the
/// non-empty key prefix, the `sync_mode: redis` → `redis_url` dependency, and
/// the case/whitespace-normalized `provider` / `sync_mode` spellings.
///
/// One residual stays constructor-only: a `token_limit` ABOVE `u64::MAX`. The
/// schema publishes `maximum: 18446744073709551615`, but a JSON parser that
/// normalizes an out-of-range integer literal to `f64` cannot distinguish it
/// from the bound itself, so the case is not asserted through this validator.
#[test]
fn ai_rate_limiter_schema_matches_constructor_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiRateLimiterConfig")
        .expect("AiRateLimiterConfig component exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(schema["properties"]["token_limit"]["minimum"], json!(1));
    assert_eq!(
        schema["properties"]["token_limit"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    assert_eq!(
        schema["properties"]["sync_mode"]["pattern"],
        json!("^([lL][oO][cC][aA][lL]|[rR][eE][dD][iI][sS])$")
    );
    assert!(schema["properties"]["sync_mode"].get("enum").is_none());
    assert_eq!(
        schema["properties"]["redis_key_prefix"]["minLength"],
        json!(1)
    );
    for duration in [
        "redis_connect_timeout_seconds",
        "redis_health_check_interval_seconds",
    ] {
        assert_eq!(
            schema["properties"][duration]["minimum"],
            json!(1),
            "{duration} must publish the constructor's positive bound"
        );
        assert_eq!(
            schema["properties"][duration]["maximum"].as_f64(),
            Some(u64::MAX as f64),
            "{duration} must publish the constructor's unsigned ceiling"
        );
    }
    let redis_guard = redis_sync_mode_guard(schema, "AiRateLimiterConfig");
    assert_eq!(redis_guard["if"]["required"], json!(["sync_mode"]));
    assert_eq!(redis_guard["then"]["required"], json!(["redis_url"]));

    let docs = plugin_docs_section(include_str!("../../docs/plugins.md"), "ai_rate_limiter");
    assert!(
        docs.contains("parsed case-insensitively"),
        "docs/plugins.md ai_rate_limiter must document sync_mode case folding"
    );
    assert!(
        docs.contains("positive unsigned 64-bit integer"),
        "docs/plugins.md ai_rate_limiter must document the positive duration bounds"
    );

    let validator = component_validator(&spec, "AiRateLimiterConfig");
    let accepted = [
        json!({"token_limit": 100}),
        json!({"token_limit": 1, "window_seconds": 2678400}),
        json!({"token_limit": 100, "provider": " OPENAI "}),
        json!({"token_limit": 100, "provider": "OpenAi"}),
        json!({"token_limit": 100, "sync_mode": "LOCAL"}),
        json!({"token_limit": 100, "redis_key_prefix": "shared"}),
        json!({"token_limit": 100, "redis_connect_timeout_seconds": 1}),
        json!({"token_limit": 100, "redis_health_check_interval_seconds": 1}),
        json!({
            "token_limit": 500000,
            "window_seconds": 3600,
            "count_mode": "total_tokens",
            "limit_by": "consumer",
            "expose_headers": true,
            "on_unmetered_response": "charge_estimate",
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_failure_policy": "fail_closed"
        }),
    ];
    for config in &accepted {
        assert_schema_and_constructor(
            &validator,
            "ai_rate_limiter",
            "accepted",
            config,
            true,
            true,
        );
    }

    let rejected = [
        json!({}),
        json!({"token_limit": 0}),
        json!({"token_limit": -1}),
        json!({"token_limit": 100, "window_seconds": 2678401}),
        json!({"token_limit": 100, "provider": "gemini"}),
        json!({"token_limit": 100, "sync_mode": "database"}),
        json!({"token_limit": 100, "sync_mode": "redis"}),
        json!({"token_limit": 100, "redis_key_prefix": ""}),
        json!({"token_limit": 100, "redis_connect_timeout_seconds": 0}),
        json!({"token_limit": 100, "redis_connect_timeout_seconds": -1}),
        json!({"token_limit": 100, "redis_health_check_interval_seconds": 0}),
        json!({"token_limit": 100, "redis_health_check_interval_seconds": -1}),
        json!({"token_limit": 100, "count_mode": "completion_token"}),
        json!({"token_limit": 100, "toke_limit": 100}),
    ];
    for config in &rejected {
        assert_schema_and_constructor(
            &validator,
            "ai_rate_limiter",
            "rejected",
            config,
            false,
            false,
        );
    }
}

/// Issue #5359 / #5361: `UdpRateLimitingConfig` must require Redis URLs, bound
/// numeric fields, accept case-normalized sync_mode, and describe per-second
/// rates rather than per-window caps.
#[test]
fn udp_rate_limiting_schema_matches_constructor_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/UdpRateLimitingConfig")
        .expect("UdpRateLimitingConfig component exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["sync_mode"]["pattern"],
        json!("^([lL][oO][cC][aA][lL]|[rR][eE][dD][iI][sS])$")
    );
    assert!(schema["properties"]["sync_mode"].get("enum").is_none());
    assert_eq!(
        schema["properties"]["redis_key_prefix"]["minLength"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_connect_timeout_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_connect_timeout_seconds"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    assert_eq!(
        schema["properties"]["redis_health_check_interval_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_health_check_interval_seconds"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    assert_eq!(
        schema["properties"]["datagrams_per_second"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    assert_eq!(
        schema["properties"]["bytes_per_second"]["maximum"].as_f64(),
        Some(u64::MAX as f64),
    );
    let redis_guard = redis_sync_mode_guard(schema, "UdpRateLimitingConfig");
    assert_eq!(redis_guard["if"]["required"], json!(["sync_mode"]));
    assert_eq!(redis_guard["then"]["required"], json!(["redis_url"]));

    for field in ["datagrams_per_second", "bytes_per_second"] {
        let description = schema["properties"][field]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{field} description"));
        assert!(
            description.contains("per second"),
            "{field} must be documented as a per-second rate"
        );
        assert!(
            description.contains("× window_seconds") || description.contains("* window_seconds"),
            "{field} must give rate × window_seconds as the effective cap"
        );
        assert!(
            !description.contains("Maximum datagrams per `window_seconds`")
                && !description.contains("Maximum bytes per `window_seconds`"),
            "{field} must not label the input rate as a per-window cap"
        );
    }

    let docs = plugin_docs_section(include_str!("../../docs/plugins.md"), "udp_rate_limiting");
    assert!(
        docs.contains("Sustained datagram rate per second"),
        "docs/plugins.md udp_rate_limiting must describe a per-second datagram rate"
    );
    assert!(
        docs.contains("Sustained payload-byte rate per second"),
        "docs/plugins.md udp_rate_limiting must describe a per-second byte rate"
    );
    assert!(
        !docs.contains("Maximum datagrams per `window_seconds`"),
        "docs/plugins.md must not label datagrams_per_second as a per-window cap"
    );
    assert!(
        docs.contains("window_seconds: 4"),
        "docs/plugins.md udp_rate_limiting must include a non-unit-window example"
    );
    assert!(
        docs.contains("Parsed case-insensitively"),
        "docs/plugins.md udp_rate_limiting must document sync_mode case folding"
    );

    let validator = component_validator(&spec, "UdpRateLimitingConfig");
    let accepted = [
        json!({"datagrams_per_second": 1}),
        json!({"bytes_per_second": 1}),
        json!({"datagrams_per_second": 1000, "bytes_per_second": 1048576}),
        json!({"datagrams_per_second": 1, "sync_mode": "LOCAL"}),
        json!({
            "datagrams_per_second": 1,
            "sync_mode": "REDIS",
            "redis_url": "redis://cache.internal:6379/0"
        }),
        json!({"datagrams_per_second": 1, "window_seconds": 4}),
        json!({
            "datagrams_per_second": 1000,
            "bytes_per_second": 1048576,
            "window_seconds": 4
        }),
    ];
    for config in &accepted {
        assert_schema_and_constructor(
            &validator,
            "udp_rate_limiting",
            "accepted",
            config,
            true,
            true,
        );
    }

    let rejected = [
        json!({}),
        json!({"datagrams_per_second": 1, "sync_mode": "redis"}),
        json!({"datagrams_per_second": 1, "redis_key_prefix": ""}),
        json!({"datagrams_per_second": 1, "redis_connect_timeout_seconds": 0}),
        json!({"datagrams_per_second": 1, "redis_health_check_interval_seconds": 0}),
        json!({"datagrams_per_second": 1, "redis_health_check_interval_seconds": -1}),
        json!({"datagrams_per_second": 1, "window_seconds": 2678401}),
        json!({"datagrams_per_second": 1, "sync_mdoe": "redis"}),
    ];
    for config in &rejected {
        assert_schema_and_constructor(
            &validator,
            "udp_rate_limiting",
            "rejected",
            config,
            false,
            false,
        );
    }

    // Checked rate × window overflow stays constructor-only.
    assert_schema_and_constructor(
        &validator,
        "udp_rate_limiting",
        "rate-window overflow residual",
        &json!({"datagrams_per_second": u64::MAX, "window_seconds": 2}),
        true,
        false,
    );
}

/// Issue #5394: the four Redis-backed rate-limit components publish the
/// constructor's numeric database-selector rule on `redis_url`.
#[test]
fn redis_url_database_selector_schema_matches_constructor_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let expected_pattern = json!(REDIS_URL_DATABASE_SELECTOR_PATTERN);
    let plugin_docs = include_str!("../../docs/plugins.md");
    for (schema_name, plugin_name, redis_config) in [
        (
            "RateLimitingConfig",
            "rate_limiting",
            json!({
                "limits": [{"scope": "default", "requests_per_minute": 10}],
                "sync_mode": "redis"
            }),
        ),
        (
            "AiRateLimiterConfig",
            "ai_rate_limiter",
            json!({"token_limit": 1000, "sync_mode": "redis"}),
        ),
        (
            "WsRateLimitingConfig",
            "ws_rate_limiting",
            json!({"sync_mode": "redis"}),
        ),
        (
            "UdpRateLimitingConfig",
            "udp_rate_limiting",
            json!({"datagrams_per_second": 1, "sync_mode": "redis"}),
        ),
    ] {
        let schema = spec
            .pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("{schema_name} component exists"));
        assert_eq!(
            schema["properties"]["redis_url"]["pattern"], expected_pattern,
            "{schema_name} redis_url pattern must admit only numeric database selectors"
        );
        let description = schema["properties"]["redis_url"]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{schema_name} redis_url description"));
        assert!(
            description.contains("2147483647"),
            "{schema_name} redis_url must document the i32 database-selector ceiling"
        );
        let docs = plugin_docs_section(plugin_docs, plugin_name);
        assert!(
            docs.contains("2147483647"),
            "docs/plugins.md {plugin_name} redis_url row must document the selector ceiling"
        );

        let validator = component_validator(&spec, schema_name);
        let mut accepted = redis_config.clone();
        accepted["redis_url"] = json!("redis://cache.internal:6379/0");
        assert!(
            validator.validate(&accepted).is_ok(),
            "{schema_name} must accept a numeric database selector: {accepted}"
        );
        let mut ceiling = redis_config.clone();
        ceiling["redis_url"] = json!("redis://cache.internal:6379/2147483647");
        assert!(
            validator.validate(&ceiling).is_ok(),
            "{schema_name} must accept the i32 selector ceiling: {ceiling}"
        );
        let mut no_path = redis_config.clone();
        no_path["redis_url"] = json!("redis://cache.internal:6379");
        assert!(
            validator.validate(&no_path).is_ok(),
            "{schema_name} must accept a URL with no database path: {no_path}"
        );

        for (name, url) in [
            ("non-numeric", "redis://cache.internal:6379/banana"),
            ("multi-segment", "redis://cache.internal:6379/0/1"),
            ("eleven-digit", "redis://cache.internal:6379/21474836480"),
        ] {
            let mut rejected = redis_config.clone();
            rejected["redis_url"] = json!(url);
            assert!(
                validator.validate(&rejected).is_err(),
                "{schema_name} must reject {name} database selector: {rejected}"
            );
        }
    }
}

#[test]
fn graphql_config_schema_matches_runtime_validation() {
    use ferrum_edge::plugins::create_plugin;
    use ferrum_edge::plugins::graphql::GRAPHQL_CONFIG_KEYS;
    use ferrum_edge::plugins::utils::rate_limit::{
        MAX_RATE_LIMIT_MAX_REQUESTS, MAX_RATE_LIMIT_WINDOW_SECONDS,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/GraphqlConfig")
        .expect("GraphqlConfig component exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["type_rate_limits"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        spec.pointer("/components/schemas/GraphqlRateSpec/additionalProperties"),
        Some(&json!(false))
    );
    assert_eq!(
        spec.pointer("/components/schemas/RateSpec/additionalProperties"),
        Some(&json!(false)),
        "the gRPC runtime now rejects unknown per-method spec keys, so RateSpec must be closed too"
    );
    assert_eq!(
        schema["properties"]["type_rate_limits"]["properties"]
            .as_object()
            .expect("type_rate_limits properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["query", "mutation", "subscription"])
    );
    assert_eq!(
        schema["properties"]["operation_rate_limits"]["propertyNames"]["pattern"],
        json!("^[A-Za-z_][A-Za-z0-9_]*$")
    );
    assert_eq!(schema["properties"]["redis_pool_size"]["minimum"], 1);
    assert_eq!(
        schema["properties"]["redis_url"]["pattern"],
        json!("^rediss?://[^/?#\\s]+(?:/[^?#\\s]*)?(?:\\?[^\\s#]*)?$")
    );
    assert_eq!(
        schema["properties"]["redis_connect_timeout_seconds"]["minimum"],
        1
    );
    assert_eq!(
        schema["properties"]["redis_health_check_interval_seconds"]["minimum"],
        1
    );
    assert_eq!(
        spec.pointer("/components/schemas/GraphqlRateSpec/properties/max_requests/minimum"),
        Some(&json!(1))
    );

    // Issue #5129: the three u32 policy limits carry their runtime range, so a
    // schema-driven authoring tool refuses exactly what the constructor refuses.
    for field in ["max_depth", "max_complexity", "max_aliases"] {
        assert_eq!(
            schema["properties"][field]["minimum"],
            json!(0),
            "{field} must advertise the unsigned floor"
        );
        assert_eq!(
            schema["properties"][field]["maximum"],
            json!(u32::MAX),
            "{field} must advertise the 32-bit ceiling"
        );
    }

    let schema_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("GraphqlConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_fields: BTreeSet<_> = GRAPHQL_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(
        schema_fields, runtime_fields,
        "graphql OpenAPI/runtime key drift"
    );
    for key in REDIS_PLUGIN_CONFIG_KEYS {
        assert!(
            GRAPHQL_CONFIG_KEYS.contains(key),
            "GRAPHQL_CONFIG_KEYS must include Redis key {key}"
        );
    }

    let plugin_docs = include_str!("../../docs/plugins.md");
    let docs = plugin_docs
        .split("### `graphql`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("graphql docs section");
    for key in GRAPHQL_CONFIG_KEYS {
        assert!(
            docs.contains(&format!("`{key}`")),
            "docs/plugins.md graphql section missing `{key}`"
        );
    }
    assert!(docs.contains("Unknown top-level keys are rejected"));
    assert!(docs.contains("valid GraphQL Names"));
    assert!(docs.contains("`2`, not `2.0`"));
    assert!(docs.contains("validated even while `sync_mode` is `local`"));
    // Issue #5129 / #5133: the operator-facing table states the enforced ranges
    // for the u32 policy limits and for both rate-entry fields.
    assert!(
        docs.contains(&format!("`0..={}`", u32::MAX)),
        "docs/plugins.md graphql section must document the u32 policy-limit range"
    );
    assert!(
        docs.contains(&format!("`1..={MAX_RATE_LIMIT_MAX_REQUESTS}`")),
        "docs/plugins.md graphql section must document the max_requests ceiling"
    );
    assert!(
        docs.contains(&format!("`1..={MAX_RATE_LIMIT_WINDOW_SECONDS}`")),
        "docs/plugins.md graphql section must document the window_seconds ceiling"
    );

    let validator_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/GraphqlConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&validator_schema)
        .expect("GraphqlConfig schema compiles");

    let accepted = [
        json!({"max_depth": 5}),
        json!({"max_complexity": 100}),
        json!({"max_aliases": 3}),
        // Issue #5129 boundaries: zero and u32::MAX are admitted by both.
        json!({"max_depth": 0}),
        json!({"max_complexity": 0}),
        json!({"max_aliases": 0}),
        json!({"max_depth": 4294967295u32}),
        json!({"max_complexity": 4294967295u32}),
        json!({"max_aliases": 4294967295u32}),
        json!({"introspection_allowed": false}),
        json!({"type_rate_limits": {"query": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"type_rate_limits": {
            "query": {"max_requests": 10, "window_seconds": 60},
            "mutation": {"max_requests": 5, "window_seconds": 60},
            "subscription": {"max_requests": 2, "window_seconds": 60}
        }}),
        json!({"operation_rate_limits": {"getUser": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"operation_rate_limits": {"_internal": {"max_requests": 1, "window_seconds": 60}}}),
        json!({
            "type_rate_limits": {
                "query": { "max_requests": 10, "window_seconds": 60 }
            },
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_pool_size": 1,
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 1
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "local",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_tls": false,
            "redis_pool_size": 1
        }),
    ];
    for config in &accepted {
        assert!(
            validator.validate(config).is_ok(),
            "config should be schema-valid: {config}"
        );
        assert!(
            create_plugin("graphql", config).is_ok(),
            "config should be runtime-valid: {config}"
        );
    }

    let rejected = [
        // Issue #2496 reproduction shapes
        json!({}),
        json!({"type_rate_limits": {"other": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"operation_rate_limits": {"bad-name": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"type_rate_limits": {"query": {"max_requests": 0, "window_seconds": 60}}}),
        json!({"max_depth": 5, "sync_mode": "redis"}),
        // Effective-rule and closed-object residuals
        json!({"introspection_allowed": true}),
        json!({"type_rate_limits": {}}),
        json!({"operation_rate_limits": {}}),
        json!({"type_rate_limits": {"Query": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"max_depth": 5, "limit_by": "IP"}),
        json!({"max_depth": 5, "limit_by": null}),
        json!({"max_depth": 5, "sync_mode": "REDIS", "redis_url": "redis://localhost:6379"}),
        json!({"max_depth": 5, "sync_mode": null}),
        json!({"max_depth": 5, "sync_mode": 1}),
        json!({"max_depth": 5, "sync_mode": "local", "redis_url": "garbage"}),
        json!({"max_depth": 5, "sync_mode": "local", "redis_tls": "yes"}),
        json!({"max_depth": 5, "sync_mode": "local", "redis_pool_size": 0}),
        json!({"operation_rate_limits": {"": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"type_rate_limits": {"query": {"max_requests": 1, "window_seconds": 60, "burst": 2}}}),
        json!({"max_depth": 5, "introspection_allowd": false}),
        // Issue #5129 boundaries: below zero and above u32::MAX are refused by both.
        json!({"max_depth": -1}),
        json!({"max_complexity": -1}),
        json!({"max_aliases": -1}),
        json!({"max_depth": 4294967296u64}),
        json!({"max_complexity": 4294967296u64}),
        json!({"max_aliases": 4294967296u64}),
        json!({"max_depth": 5, "sync_mdoe": "redis", "redis_url": "redis://localhost:6379/0"}),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": ""
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": "http://localhost:6379"
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": "rediss://localhost:6380/0#insecure"
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "local",
            "redis_url": "rediss://localhost:6380/0#insecure"
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_key_prefix": ""
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_pool_size": 0
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_connect_timeout_seconds": 0
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379",
            "redis_health_check_interval_seconds": 0
        }),
    ];
    for config in &rejected {
        assert!(
            validator.validate(config).is_err(),
            "config should be schema-invalid: {config}"
        );
        assert!(
            create_plugin("graphql", config).is_err(),
            "config should be runtime-invalid: {config}"
        );
    }
}

#[test]
fn request_deduplication_schema_matches_runtime_validation() {
    use ferrum_edge::plugins::create_plugin;
    use ferrum_edge::plugins::request_deduplication::{
        REQUEST_DEDUPLICATION_CONFIG_KEYS, REQUEST_DEDUPLICATION_POLICY_CONFIG_KEYS,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/RequestDeduplicationConfig")
        .expect("RequestDeduplicationConfig component exists");

    // Issue #2604: the published schema must reject the same malformed
    // configurations the runtime constructor rejects.
    assert_eq!(schema["properties"]["header_name"]["minLength"], json!(1));
    assert_eq!(
        schema["properties"]["header_name"]["pattern"],
        json!("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    );
    assert_eq!(
        schema["properties"]["applicable_methods"]["minItems"],
        json!(1)
    );
    // Issue #5070: the runtime trims each method before validating it, so the
    // published item pattern tolerates exactly that padding.
    assert_eq!(
        schema["properties"]["applicable_methods"]["items"]["pattern"],
        json!("^\\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+\\s*$")
    );
    assert_eq!(
        schema["properties"]["redis_key_prefix"]["minLength"],
        json!(1)
    );
    assert_eq!(schema["properties"]["redis_pool_size"]["minimum"], json!(1));
    assert_eq!(
        schema["properties"]["redis_connect_timeout_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["redis_health_check_interval_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(schema["properties"]["redis_url"]["minLength"], json!(1));
    assert_eq!(
        schema["properties"]["redis_url"]["pattern"],
        json!("^rediss?://[^/?#\\s]+(?:/[^?#\\s]*)?(?:\\?[^\\s#]*)?$")
    );
    // Issue #5070: the runtime lowercases `sync_mode` before comparing it, so
    // the conditional selects on the same case-insensitive value rather than a
    // `const` that would refuse a valid `"REDIS"` deployment's `redis_url`.
    let redis_guard = schema["allOf"]
        .as_array()
        .expect("RequestDeduplicationConfig allOf")
        .iter()
        .find(|guard| {
            guard["if"]["properties"]["sync_mode"]["pattern"] == json!("^[Rr][Ee][Dd][Ii][Ss]$")
        })
        .expect("sync_mode=redis conditional guard");
    assert_eq!(redis_guard["if"]["required"], json!(["sync_mode"]));
    assert_eq!(redis_guard["then"]["required"], json!(["redis_url"]));

    // GHSA-h2c3-j3cm-7ghh: the published schema closes the root object and
    // refuses Redis-only fields outside Redis mode, matching the runtime
    // allowlist exactly.
    assert_eq!(schema["additionalProperties"], json!(false));
    for redis_only in [
        "redis_url",
        "redis_tls",
        "redis_key_prefix",
        "redis_pool_size",
        "redis_connect_timeout_seconds",
        "redis_health_check_interval_seconds",
        "redis_username",
        "redis_password",
        "on_redis_unavailable",
    ] {
        assert_eq!(
            redis_guard["else"]["properties"][redis_only],
            json!(false),
            "{redis_only} must be refused outside sync_mode=redis"
        );
    }

    // Issue #5070: explicit null is rejected by the constructor
    // (`'anonymous_caller_scope' must be a string`), so the property is not
    // nullable, and the enum carries the alias spelling the shared parser
    // accepts.
    assert_eq!(
        schema["properties"]["anonymous_caller_scope"]["type"],
        json!("string")
    );
    assert_eq!(
        schema["properties"]["anonymous_caller_scope"]["enum"],
        json!(["caller_address", "caller-address", "shared"])
    );

    // Issue #5070: every bounded unsigned field publishes the u64 ceiling the
    // constructor enforces, so an oversized value is refused by both.
    for bounded in [
        "ttl_seconds",
        "inflight_ttl_seconds",
        "max_entries",
        "max_entry_size_bytes",
        "max_total_size_bytes",
    ] {
        assert_eq!(schema["properties"][bounded]["minimum"], json!(1));
        assert_eq!(
            schema["properties"][bounded]["maximum"].as_f64(),
            Some(u64::MAX as f64),
            "{bounded} must publish the unsigned 64-bit ceiling"
        );
    }

    // Issue #5070: JSON Schema `enum` cannot express case-insensitivity, so the
    // two normalized-value properties must SAY so rather than silently
    // disagreeing with admission.
    for normalized in ["sync_mode", "anonymous_caller_scope"] {
        let description = schema["properties"][normalized]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{normalized} carries a description"));
        assert!(
            description.contains("case-insensitiv"),
            "{normalized} must document the runtime normalization the enum cannot express"
        );
    }

    // GHSA-h2c3-j3cm-7ghh: the runtime allowlist, the published schema, and the
    // documented parameter table must name exactly the same keys.
    let schema_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("RequestDeduplicationConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_fields: BTreeSet<_> = REQUEST_DEDUPLICATION_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(
        schema_fields, runtime_fields,
        "request_deduplication OpenAPI/runtime key drift"
    );
    for key in REDIS_PLUGIN_CONFIG_KEYS {
        assert!(
            REQUEST_DEDUPLICATION_CONFIG_KEYS.contains(key),
            "REQUEST_DEDUPLICATION_CONFIG_KEYS must include Redis key {key}"
        );
    }
    assert_eq!(
        REQUEST_DEDUPLICATION_CONFIG_KEYS.len(),
        REQUEST_DEDUPLICATION_POLICY_CONFIG_KEYS.len() + REDIS_PLUGIN_CONFIG_KEYS.len(),
        "the closed allowlist must be exactly policy keys plus shared Redis keys"
    );

    let plugin_docs = include_str!("../../docs/plugins.md");
    let docs = plugin_docs
        .split("### `request_deduplication`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("request_deduplication docs section");
    for key in REQUEST_DEDUPLICATION_CONFIG_KEYS {
        assert!(
            docs.contains(&format!("`{key}`")),
            "docs/plugins.md request_deduplication section missing `{key}`"
        );
    }
    assert!(docs.contains("Unknown top-level keys are rejected"));

    let validator_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/RequestDeduplicationConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&validator_schema)
        .expect("RequestDeduplicationConfig schema compiles");

    let accepted = [
        json!({}),
        json!({"header_name": "X-Idempotency-Key"}),
        json!({"applicable_methods": ["GET", "POST"]}),
        json!({"applicable_methods": ["get"]}),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_key_prefix": "ferrum:dedup",
            "redis_pool_size": 1,
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 1
        }),
        json!({
            "sync_mode": "redis",
            "redis_url": "rediss://cache.internal:6390"
        }),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379",
            "on_redis_unavailable": "local_only"
        }),
        // Issue #5070: the constructor trims each method, accepts the hyphen
        // spelling of the anonymous scope, and requires `redis_url` under a
        // case-insensitive `sync_mode` — all now expressible in the schema.
        json!({"applicable_methods": [" POST "]}),
        json!({"anonymous_caller_scope": "caller_address"}),
        json!({"anonymous_caller_scope": "caller-address"}),
        json!({"anonymous_caller_scope": "shared"}),
    ];
    for config in &accepted {
        assert!(
            validator.validate(config).is_ok(),
            "config should be schema-valid: {config}"
        );
        assert!(
            create_plugin("request_deduplication", config).is_ok(),
            "config should be runtime-valid: {config}"
        );
    }

    // Issue #2604 reproduction shapes: every case is rejected by both the
    // published schema and the runtime constructor.
    let rejected = [
        json!({"header_name": "not a header"}),
        json!({"header_name": ""}),
        json!({"header_name": null}),
        json!({"applicable_methods": []}),
        json!({"applicable_methods": ["bad method"]}),
        json!({"applicable_methods": [""]}),
        json!({"applicable_methods": null}),
        json!({"sync_mode": "redis"}),
        json!({"sync_mode": "redis", "redis_url": ""}),
        json!({"sync_mode": "redis", "redis_url": "https://example.invalid"}),
        json!({"sync_mode": "redis", "redis_url": "rediss://cache.internal:6380/0#insecure"}),
        json!({"sync_mode": "redis", "redis_url": null}),
        json!({"sync_mode": "local", "redis_url": "https://example.invalid"}),
        json!({"sync_mode": "local", "redis_url": "redis://"}),
        // GHSA-h2c3-j3cm-7ghh reproduction shapes: misspelled policy keys and
        // Redis-only fields outside Redis mode.
        json!({"enforce_requred": true}),
        json!({"sync_mod": "redis", "redis_url": "redis://cache.internal:6379"}),
        json!({"scope_by_consumers": false}),
        json!({"sync_mode": "local", "redis_url": "redis://cache.internal:6379"}),
        json!({"redis_key_prefix": "ferrum:dedup"}),
        json!({"on_redis_unavailable": "local_only"}),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379",
            "on_redis_unavailable": "fallback"
        }),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://host:6379",
            "redis_key_prefix": ""
        }),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://host:6379",
            "redis_pool_size": 0
        }),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://host:6379",
            "redis_connect_timeout_seconds": 0
        }),
        json!({
            "sync_mode": "redis",
            "redis_url": "redis://host:6379",
            "redis_health_check_interval_seconds": 0
        }),
        // Issue #5070: explicit null is not "omitted", an unknown scope is
        // refused, and the bounded unsigned fields refuse zero.
        json!({"anonymous_caller_scope": null}),
        json!({"anonymous_caller_scope": "everyone"}),
        json!({"ttl_seconds": 0}),
        json!({"inflight_ttl_seconds": 0}),
        json!({"max_entries": 0}),
        json!({"max_entry_size_bytes": 0}),
        json!({"max_total_size_bytes": 0}),
    ];
    for config in &rejected {
        assert!(
            validator.validate(config).is_err(),
            "config should be schema-invalid: {config}"
        );
        assert!(
            create_plugin("request_deduplication", config).is_err(),
            "config should be runtime-invalid: {config}"
        );
    }

    // Issue #5070, documented limitation: JSON Schema cannot express the
    // runtime's case-insensitive, whitespace-trimming enum parsing. These two
    // shapes are admitted by the gateway and refused by a strict validator;
    // both property descriptions say so (asserted above). Pinned here so the
    // divergence stays a known, described one instead of silent drift.
    for config in [
        json!({"sync_mode": "LOCAL"}),
        json!({"anonymous_caller_scope": " SHARED "}),
    ] {
        assert!(
            create_plugin("request_deduplication", &config).is_ok(),
            "the gateway normalizes {config}"
        );
        assert!(
            validator.validate(&config).is_err(),
            "the schema cannot express the normalization for {config}"
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
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        json!({
            "ldap_url": "ldap://ldap.example.com:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "starttls": true
        }),
        json!({
            "ldap_url": "ldap://directory.example.test:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "allow_plaintext": true
        }),
        json!({
            "ldap_url": "ldap://127.0.0.1:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        json!({
            "ldap_url": "ldap://LOCALHOST:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "canonical_identity_attribute": "uid",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "required_groups": ["admins"]
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
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
            "bind_dn_template": "uid=static,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
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
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "secret"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "search_filter": "(uid={username})"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com"
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
            "canonical_identity_attribute": "uid",
            "required_groups": ["admins"]
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "group_base_dn": "ou=groups,dc=example,dc=com",
            "group_filter": "(cn=admins)",
            "required_groups": ["admins"]
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "starttls": true
        }),
        json!({
            "ldap_url": "ldap://directory.example.test:389",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        json!({
            "ldap_url": "ldaps://admin:secret@ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "connect_timeout_seconds": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "request_timeout_seconds": 301
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "max_concurrent_requests": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "cache_ttl_seconds": 86401
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "max_cache_entries": 0
        }),
        json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},dc=example,dc=com",
            "canonical_identity_attribute": "uid",
            "required_group": ["admins"]
        }),
    ] {
        assert_component_validity(&spec, "LdapAuthConfig", &config, false);
    }
}

#[test]
fn ldap_auth_value_constraints_match_runtime_admission() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::ldap_auth::LdapAuth;

    fn merge(base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
        let mut config = base;
        let object = config.as_object_mut().expect("config object");
        for (key, value) in extra.as_object().expect("extra object") {
            object.insert(key.clone(), value.clone());
        }
        config
    }

    fn direct_bind(extra: serde_json::Value) -> serde_json::Value {
        let base = json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        });
        merge(base, extra)
    }

    fn search_bind(extra: serde_json::Value) -> serde_json::Value {
        let base = json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "search_base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "canonical_identity_attribute": "uid",
            "service_account_dn": "cn=admin,dc=example,dc=com",
            "service_account_password": "service-secret"
        });
        merge(base, extra)
    }

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/LdapAuthConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("LdapAuthConfig schema compiles");

    // Value-level admission probed in issue #5038. RFC 4515 filter syntax is
    // deliberately absent from this table: the grammar is not expressible as a
    // `pattern`, so filter syntax stays an admission-only rule.
    let admitted = vec![
        // A password is opaque: it is taken verbatim, never trimmed.
        search_bind(json!({"service_account_password": "  padded  "})),
        direct_bind(json!({"max_cache_entries": 1_000_000})),
        // An empty userinfo carries no credential.
        direct_bind(json!({"ldap_url": "ldaps://@localhost"})),
        direct_bind(json!({"ldap_url": "ldaps://[2001:db8::50]:636"})),
        direct_bind(json!({"hide_credentials": false})),
    ];
    let refused = vec![
        // Whitespace-only identifiers trim to empty.
        direct_bind(json!({"canonical_identity_attribute": "  "})),
        direct_bind(json!({"group_attribute": "  "})),
        direct_bind(json!({"group_filter": "  "})),
        search_bind(json!({"service_account_dn": "  "})),
        search_bind(json!({"search_base_dn": "  "})),
        direct_bind(json!({"group_base_dn": "  ", "required_groups": ["a"]})),
        direct_bind(json!({"group_base_dn": "ou=g,dc=e", "required_groups": ["  "]})),
        search_bind(json!({"service_account_password": ""})),
        // Every resource knob is bounded.
        direct_bind(json!({"max_cache_entries": 1_000_001})),
        // A hostname is required and an explicit port must fit in 16 bits.
        direct_bind(json!({"ldap_url": "ldaps://"})),
        direct_bind(json!({"ldap_url": "ldaps://localhost:65536"})),
        // The scheme is case-sensitive and the value is never trimmed.
        direct_bind(json!({"ldap_url": "  ldap://127.0.0.1:389  "})),
        direct_bind(json!({"ldap_url": "LDAP://127.0.0.1:389"})),
        direct_bind(json!({"ldap_url": "ldaps://admin:secret@localhost"})),
        direct_bind(json!({"hide_credentials": "yes"})),
    ];

    for config in admitted {
        assert!(
            validator.validate(&config).is_ok(),
            "OpenAPI must admit {config}"
        );
        assert!(
            LdapAuth::new(&config, PluginHttpClient::default()).is_ok(),
            "runtime must admit {config}"
        );
    }
    for config in refused {
        assert!(
            validator.validate(&config).is_err(),
            "OpenAPI must refuse {config}"
        );
        assert!(
            LdapAuth::new(&config, PluginHttpClient::default()).is_err(),
            "runtime must refuse {config}"
        );
    }
}

#[test]
fn ai_federation_schema_publishes_security_fields_and_rejects_unknown_keys() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiFederationConfig")
        .expect("missing AiFederationConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AiFederationConfig schema compiles");

    let provider_properties = schema
        .pointer("/properties/providers/items/properties")
        .expect("missing provider properties");
    assert_eq!(provider_properties["allow_plaintext"]["default"], false);
    assert_eq!(
        provider_properties["max_response_body_bytes"]["default"],
        8_388_608
    );
    assert_eq!(provider_properties["max_response_body_bytes"]["minimum"], 1);
    assert_eq!(
        provider_properties["max_response_body_bytes"]["maximum"],
        67_108_864
    );
    assert!(provider_properties.get("circuit_breaker").is_some());

    // Issue #3298: the streaming opt-in is a closed object whose event ceiling
    // matches the runtime bounds exactly.
    let streaming = schema
        .pointer("/properties/streaming")
        .expect("missing streaming block");
    assert_eq!(streaming["additionalProperties"], false);
    assert_eq!(streaming["properties"]["enabled"]["default"], false);
    let (default_event_bytes, min_event_bytes, max_event_bytes, max_read_timeout_seconds) =
        ferrum_edge::plugins::ai_federation::test_helpers::streaming_bounds_for_test();
    assert_eq!(
        streaming["properties"]["max_event_bytes"]["default"],
        default_event_bytes
    );
    assert_eq!(
        streaming["properties"]["max_event_bytes"]["minimum"],
        min_event_bytes
    );
    assert_eq!(
        streaming["properties"]["max_event_bytes"]["maximum"],
        max_event_bytes
    );
    // The streaming-only whole-exchange override is published with the same
    // bounds the runtime enforces, and `0` (unbounded) is representable.
    assert_eq!(
        streaming["properties"]["read_timeout_seconds"]["minimum"],
        0
    );
    assert_eq!(
        streaming["properties"]["read_timeout_seconds"]["maximum"],
        max_read_timeout_seconds
    );
    // The published streaming key set must equal the runtime allowlist exactly,
    // so a schema-only key can never be accepted by the spec and rejected at
    // load (and vice versa).
    let mut published_streaming_keys: Vec<String> = streaming["properties"]
        .as_object()
        .expect("streaming properties must be an object")
        .keys()
        .cloned()
        .collect();
    published_streaming_keys.sort();
    let mut runtime_streaming_keys: Vec<String> =
        ferrum_edge::plugins::ai_federation::test_helpers::streaming_config_keys_for_test()
            .iter()
            .map(|key| (*key).to_string())
            .collect();
    runtime_streaming_keys.sort();
    assert_eq!(published_streaming_keys, runtime_streaming_keys);

    let valid = json!({
        "providers": [{
            "name": "local-openai",
            "provider_type": "openai",
            "api_key": "test",
            "base_url": "http://127.0.0.1:8080/v1/chat/completions",
            "allow_plaintext": true,
            "max_response_body_bytes": 1048576,
            "circuit_breaker": {
                "failure_threshold": 2,
                "cooldown_seconds": 10,
                "success_threshold": 1
            }
        }],
        "fallback_on_protocol_errors": true,
        "fallback_on_ambiguous_errors": false,
        "max_concurrent_requests": 32
    });
    assert!(validator.validate(&valid).is_ok());

    for status in 200..300 {
        let mut committed_fallback = valid.clone();
        committed_fallback["fallback_on_status_codes"] = json!([429, status]);
        assert!(validator.validate(&committed_fallback).is_err());
    }
    let mut rejection_fallback = valid.clone();
    rejection_fallback["fallback_on_status_codes"] = json!([100, 199, 300, 429, 599]);
    assert!(validator.validate(&rejection_fallback).is_ok());

    for invalid in [
        json!({"providers": [{"name": "p", "provider_type": "openai"}], "fallback_on_netwrok_errors": true}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "model_paterns": []}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "circuit_breaker": {"failure_treshold": 2}}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "base_url": "http://127.0.0.1/v1/chat"}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "model_mapping": {"gpt-../unsafe": "gpt-4o"}}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "max_response_body_bytes": 0}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "max_response_body_bytes": 67_108_865}]}),
        // Issue #5260: the component used to admit configurations the
        // constructor rejects, so `validate` reported success for a file that
        // could never load. An empty or absent static credential is a
        // configuration error for every provider type that reads one.
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": ""}]}),
        json!({"providers": [{"name": "p", "provider_type": "anthropic"}]}),
        json!({"providers": [{"name": "p", "provider_type": "google_vertex", "google_project_id": "proj", "google_region": "us-central1", "google_service_account_json": ""}]}),
        // Providers that interpolate the resolved model into the endpoint path
        // restrict every provider-native model identifier to a safe URL path
        // component.
        json!({"providers": [{"name": "p", "provider_type": "google_gemini", "api_key": "test", "default_model": "family/model"}]}),
        json!({"providers": [{"name": "p", "provider_type": "aws_bedrock", "aws_region": "us-east-1", "model_mapping": {"gpt-4o": "family/model"}}]}),
        // The endpoint path components exclude the traversal sequence exactly
        // as `validate_url_path_component` does at load.
        json!({"providers": [{"name": "p", "provider_type": "azure_openai", "api_key": "test", "azure_resource": "res", "azure_deployment": "v..1"}]}),
        json!({"providers": [{"name": "p", "provider_type": "azure_openai", "api_key": "test", "azure_resource": "res", "azure_deployment": "dep", "azure_api_version": "v..1"}]}),
        json!({"providers": [{"name": "p", "provider_type": "google_vertex", "google_project_id": "a..b", "google_region": "us-central1", "google_service_account_json": "{}"}]}),
    ] {
        assert!(
            validator.validate(&invalid).is_err(),
            "schema accepted {invalid}"
        );
    }

    // The tightening must not reject what the constructor accepts: the model
    // component rule is provider-conditional, and the credential rule does not
    // apply to the two provider types that never read `api_key`.
    for accepted in [
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "default_model": "family/model"}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "model_mapping": {"gpt-4o": "family/model"}}]}),
        json!({"providers": [{"name": "b", "provider_type": "aws_bedrock", "aws_region": "us-east-1"}]}),
        json!({"providers": [{"name": "v", "provider_type": "google_vertex", "google_project_id": "proj", "google_region": "us-central1", "google_service_account_json": "{}"}]}),
        json!({"providers": [{"name": "g", "provider_type": "google_gemini", "api_key": "test", "default_model": "gemini-1.5-pro"}]}),
    ] {
        assert!(
            validator.validate(&accepted).is_ok(),
            "schema rejected {accepted}"
        );
    }

    // Issue #5262: a completed 2xx that cannot be normalized is terminal, so
    // the component overview must not still promise priority fallback for it.
    let description = schema["description"]
        .as_str()
        .expect("AiFederationConfig must document itself");
    assert!(
        !description.contains("malformed provider success responses"),
        "AiFederationConfig still promises fallback after a completed malformed success"
    );
    assert!(
        description.contains("response_normalization_failed"),
        "AiFederationConfig must state that a completed 2xx normalization failure is terminal"
    );
}

#[test]
fn ai_stream_router_schema_rejects_unknown_keys_and_matches_runtime_surface() {
    use ferrum_edge::plugins::ai_stream_router::{
        AI_STREAM_ROUTER_CONFIG_KEYS, AI_STREAM_ROUTER_PROVIDER_KEYS,
    };
    use std::collections::BTreeSet;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiStreamRouterConfig")
        .expect("missing AiStreamRouterConfig schema");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["providers"]["items"]["additionalProperties"],
        false
    );
    // Issue #3328: the `fallback` block is rejected at admission, so it must
    // not exist in the published schema either. `additionalProperties: false`
    // above then makes the spec reject it exactly as the constructor does.
    assert!(
        schema["properties"].get("fallback").is_none(),
        "openapi.yaml still publishes an ai_stream_router 'fallback' block"
    );

    let root_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("root properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_root_fields = AI_STREAM_ROUTER_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(root_fields, runtime_root_fields, "root key drift");

    let provider_fields: BTreeSet<_> = schema["properties"]["providers"]["items"]["properties"]
        .as_object()
        .expect("provider properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_provider_fields = AI_STREAM_ROUTER_PROVIDER_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        provider_fields, runtime_provider_fields,
        "provider key drift"
    );

    let description = schema["description"].as_str().expect("description");
    assert!(description.contains("unknown root and provider fields are rejected"));
    assert!(description.contains("FailClosed"));
    // The published contract must state the rejection, not a reserved policy.
    assert!(
        description.contains("`fallback` config block is REJECTED at admission"),
        "schema description must document the fallback rejection contract"
    );
    assert!(
        !description.contains("fallback_attempts is always 0"),
        "schema description still advertises an inert fallback_attempts counter"
    );

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("**Strict configuration admission.**"));
    assert!(guide.contains("config.enabeld"));
    assert!(guide.contains("FailClosed"));

    assert_component_validity(
        &spec,
        "AiStreamRouterConfig",
        &json!({
            "enabled": true,
            "providers": [{
                "name": "openai",
                "provider_type": "openai",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "api_key": "sk-test",
                "model_patterns": ["gpt-*"],
                "priority": 1,
                "inherit_backend_tls": false
            }]
        }),
        true,
    );
    for invalid in [
        json!({"enabeld": false, "providers": [{"name": "p", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"], "inherit_backend_tl": true}]}),
        // Issue #3328: a well-formed fallback policy is refused by the spec,
        // matching the constructor's fail-closed admission.
        json!({"providers": [{"name": "p", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]}], "fallback": {"enabled": true, "on_connect_error": true, "on_5xx_before_first_byte": true, "max_attempts": 2}}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]}], "fallback": {}}),
    ] {
        assert_component_validity(&spec, "AiStreamRouterConfig", &invalid, false);
    }

    // Issue #5303: the component must accept nothing the constructor rejects,
    // and must accept the explicit nulls the constructor reads as omission.
    let provider_with = |overrides: serde_json::Value| {
        let mut provider = json!({
            "name": "p",
            "provider_type": "openai",
            "endpoint": "https://a.example.com/v1",
            "api_key": "k",
            "model_patterns": ["gpt-*"]
        });
        if let (Some(base), Some(extra)) = (provider.as_object_mut(), overrides.as_object()) {
            for (key, value) in extra {
                base.insert(key.clone(), value.clone());
            }
        }
        json!({ "providers": [provider] })
    };

    for valid in [
        // Every optional field the constructor treats as omitted when null.
        json!({
            "enabled": null,
            "fail_on_missing_model": null,
            "fail_on_no_matching_provider": null,
            "inject_usage_options": null,
            "normalize_response_stream": null,
            "providers": [{
                "name": "p",
                "provider_type": "anthropic",
                "endpoint": "https://a.example.com/v1",
                "api_key": "k",
                "model_patterns": ["claude-*"],
                "priority": null,
                "allow_plaintext": null,
                "anthropic_version": null,
                "inherit_backend_tls": null
            }]
        }),
        // Plaintext with the opt-in the constructor requires.
        provider_with(json!({
            "endpoint": "http://internal.example.com/v1",
            "allow_plaintext": true
        })),
        provider_with(json!({"priority": 4294967295u64})),
    ] {
        assert_component_validity(&spec, "AiStreamRouterConfig", &valid, true);
    }

    for invalid in [
        provider_with(json!({"priority": 4294967296u64})),
        provider_with(json!({"name": ""})),
        provider_with(json!({"api_key": ""})),
        provider_with(json!({"model_patterns": [""]})),
        provider_with(json!({"endpoint": "not-url"})),
        provider_with(json!({"endpoint": "ftp://api.example.com/a"})),
        // HTTP without the plaintext opt-in, and with it explicitly disabled.
        provider_with(json!({"endpoint": "http://internal.example.com/v1"})),
        provider_with(json!({
            "endpoint": "http://internal.example.com/v1",
            "allow_plaintext": false
        })),
    ] {
        assert_component_validity(&spec, "AiStreamRouterConfig", &invalid, false);
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
    assert_eq!(
        schema["max_cache_entries"]["maximum"],
        json!(ferrum_edge::plugins::ldap_auth::LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT)
    );

    let guide = include_str!("../../docs/cache_management.md");
    assert!(guide.contains("**Default limit:** 10,000 entries. Caching is disabled by default."));
    assert!(guide.contains("`cache_ttl_seconds` (default `0`, disabled; maximum `86,400`"));
    assert!(guide.contains("`max_cache_entries` (default `10,000`; maximum `1,000,000`)"));
    assert!(guide.contains("| `ldap_auth` | `max_cache_entries` | `10000` |"));
    assert!(guide.contains("| `ldap_auth` | `cache_ttl_seconds` | `0` |"));
}

#[test]
fn oauth2_introspection_cache_schema_and_docs_match_runtime_constants() {
    use ferrum_edge::plugins::utils::introspection_cache::{
        DEFAULT_MAX_CACHE_ENTRIES, DEFAULT_MAX_CACHE_ENTRY_BYTES, DEFAULT_MAX_CACHE_TOTAL_BYTES,
        HARD_MAX_CACHE_ENTRIES, HARD_MAX_CACHE_ENTRY_BYTES, HARD_MAX_CACHE_TOTAL_BYTES,
        MIN_MAX_CACHE_ENTRIES, MIN_MAX_CACHE_ENTRY_BYTES, MIN_MAX_CACHE_TOTAL_BYTES,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let properties = spec
        .pointer(
            "/components/schemas/Oauth2IntrospectionConfig/properties/providers/items/properties",
        )
        .expect("OAuth2 introspection provider properties exist");
    for (field, default, minimum, maximum) in [
        (
            "max_cache_entries",
            DEFAULT_MAX_CACHE_ENTRIES,
            MIN_MAX_CACHE_ENTRIES,
            HARD_MAX_CACHE_ENTRIES,
        ),
        (
            "max_cache_entry_bytes",
            DEFAULT_MAX_CACHE_ENTRY_BYTES,
            MIN_MAX_CACHE_ENTRY_BYTES,
            HARD_MAX_CACHE_ENTRY_BYTES,
        ),
        (
            "max_cache_total_bytes",
            DEFAULT_MAX_CACHE_TOTAL_BYTES,
            MIN_MAX_CACHE_TOTAL_BYTES,
            HARD_MAX_CACHE_TOTAL_BYTES,
        ),
    ] {
        assert_eq!(properties[field]["default"], json!(default));
        assert_eq!(properties[field]["minimum"], json!(minimum));
        assert_eq!(properties[field]["maximum"], json!(maximum));
    }

    let cache_guide = include_str!("../../docs/cache_management.md");
    assert!(
        cache_guide
            .contains("| `oauth2_introspection` | `providers[].max_cache_entries` | `10000` |")
    );
    assert!(
        cache_guide
            .contains("| `oauth2_introspection` | `providers[].max_cache_entry_bytes` | `16384` |")
    );
    assert!(
        cache_guide.contains(
            "| `oauth2_introspection` | `providers[].max_cache_total_bytes` | `16777216` |"
        )
    );
}

/// `/health` publishes the shared single-use replay authority aggregate
/// (issues #3834 / #3837). The schema must stay in exact parity with what the
/// runtime serializes, and must stay two fixed-cardinality counters: the
/// aggregate is the authenticated readiness surface, so its shape may not grow
/// with configuration.
#[test]
fn health_shared_replay_authority_aggregate_matches_the_runtime_snapshot() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/SharedReplayAuthorityHealth")
        .expect("SharedReplayAuthorityHealth exists");

    let rendered = serde_json::to_value(
        ferrum_edge::plugins::utils::replay_authority::shared_health_snapshot(),
    )
    .expect("the aggregate serializes");
    let runtime_fields: std::collections::BTreeSet<String> = rendered
        .as_object()
        .expect("the aggregate is an object")
        .keys()
        .cloned()
        .collect();
    let schema_fields: std::collections::BTreeSet<String> = schema["properties"]
        .as_object()
        .expect("the schema declares properties")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        runtime_fields, schema_fields,
        "openapi.yaml must match the serialized aggregate exactly"
    );
    assert_eq!(
        schema_fields.len(),
        2,
        "the readiness aggregate must stay fixed-cardinality"
    );
    assert_eq!(
        schema["required"],
        json!(["shared_authorities", "shared_authorities_unavailable"])
    );

    // `/health` references it, and only on the detailed tier.
    let health = spec
        .pointer("/components/schemas/HealthResponse")
        .expect("HealthResponse exists");
    assert_eq!(
        health["properties"]["replay_authority"]["$ref"],
        json!("#/components/schemas/SharedReplayAuthorityHealth")
    );
    let description = health["description"]
        .as_str()
        .expect("HealthResponse documents its tiering");
    assert!(
        description.contains("replay_authority"),
        "the detailed-tier field list must name the aggregate: {description}"
    );

    // A `shared` policy has no local fallback, so an unavailable backend is a
    // readiness failure rather than a coarse degradation.
    let ready = health["properties"]["ready"]["description"]
        .as_str()
        .expect("`ready` is documented");
    assert!(
        ready.contains("replay authority"),
        "`ready` must document the shared replay dependency: {ready}"
    );
}

/// `hmac_auth`'s configuration root became a closed key set with the
/// single-use replay work (issues #3834 / #3837), so it now carries the same
/// obligation every other closed plugin root does: exact parity with an
/// `additionalProperties: false` OpenAPI schema. Without this guard a new
/// runtime key silently becomes an undocumented field the Admin API rejects,
/// or a documented field the runtime refuses.
#[test]
fn hmac_auth_config_root_is_closed_and_matches_openapi() {
    use ferrum_edge::plugins::hmac_auth::HMAC_AUTH_CONFIG_KEYS;
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/HmacAuthConfig")
        .expect("HmacAuthConfig component exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let schema_fields: BTreeSet<&str> = schema["properties"]
        .as_object()
        .expect("HmacAuthConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    // The runtime allowlist is the plugin's own keys unioned with the shared
    // Redis connectivity keys that back `replay_scope: shared`.
    let runtime_fields: BTreeSet<&str> = HMAC_AUTH_CONFIG_KEYS
        .iter()
        .chain(REDIS_PLUGIN_CONFIG_KEYS.iter())
        .copied()
        .collect();
    assert_eq!(schema_fields, runtime_fields, "HmacAuthConfig key drift");

    // The replay scope has no default in either surface: an operator must
    // declare whether process-local replay state is sufficient, and a schema
    // default would reinstate silent per-replica replay.
    assert_eq!(
        schema["properties"]["replay_scope"]["enum"],
        json!(["process", "shared"])
    );
    assert!(schema["properties"]["replay_scope"]["default"].is_null());
    assert_eq!(
        schema["properties"]["clock_skew_seconds"]["maximum"],
        json!(ferrum_edge::plugins::hmac_auth::MAX_HMAC_CLOCK_SKEW_SECONDS)
    );
    assert_eq!(
        schema["properties"]["replay_max_entries"]["default"],
        json!(ferrum_edge::plugins::hmac_auth::DEFAULT_HMAC_REPLAY_MAX_ENTRIES)
    );
}

/// Issue #5001: key-set parity is not acceptance parity. `HmacAuthConfig` had
/// no conditional constraints at all, so schema-based tooling approved
/// deployments the gateway refuses to start with — an empty configuration,
/// unsafe v1 without its acknowledgement, v2 without a replay scope, and every
/// impossible Redis/scope pairing. This is the real schema-vs-runtime
/// acceptance matrix.
#[test]
fn hmac_auth_schema_acceptance_matches_runtime_admission() {
    use ferrum_edge::plugins::create_plugin;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let validator_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/HmacAuthConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&validator_schema)
        .expect("HmacAuthConfig schema compiles");

    let redis_url = "redis://127.0.0.1:6379/0";
    let accepted = [
        json!({"replay_scope": "process"}),
        json!({"replay_scope": "process", "clock_skew_seconds": 60}),
        json!({"replay_scope": "process", "replay_max_entries": 1}),
        json!({"replay_scope": "process", "sync_mode": "local"}),
        json!({"signing_profile": "ferrum-hmac-v2", "replay_scope": "process"}),
        json!({
            "signing_profile": "ferrum-hmac-v2",
            "replay_scope": "process",
            "allow_unsafe_replayable_v1": false
        }),
        json!({"signing_profile": "ferrum-hmac-v1", "allow_unsafe_replayable_v1": true}),
        json!({
            "replay_scope": "shared",
            "sync_mode": "redis",
            "redis_url": redis_url
        }),
    ];
    for config in &accepted {
        assert!(
            validator.validate(config).is_ok(),
            "config should be schema-valid: {config}"
        );
        assert!(
            create_plugin("hmac_auth", config).is_ok(),
            "config should be runtime-valid: {config}"
        );
    }

    let rejected = [
        // Profile / acknowledgement / scope admission (the #5001 matrix).
        json!({}),
        json!({"clock_skew_seconds": 60}),
        json!({"signing_profile": "ferrum-hmac-v1"}),
        json!({"signing_profile": "ferrum-hmac-v1", "allow_unsafe_replayable_v1": false}),
        json!({
            "signing_profile": "ferrum-hmac-v1",
            "allow_unsafe_replayable_v1": true,
            "replay_scope": "process"
        }),
        json!({"replay_scope": "process", "allow_unsafe_replayable_v1": true}),
        json!({"replay_scope": "shared"}),
        json!({"replay_scope": "shared", "sync_mode": "redis"}),
        json!({"replay_scope": "process", "sync_mode": "redis", "redis_url": redis_url}),
        json!({
            "signing_profile": "ferrum-hmac-v1",
            "allow_unsafe_replayable_v1": true,
            "sync_mode": "redis",
            "redis_url": redis_url
        }),
        // Scalar spellings: the enums are exact on both surfaces.
        json!({"replay_scope": " PROCESS "}),
        json!({"replay_scope": "Process"}),
        json!({"replay_scope": "process", "signing_profile": " ferrum-hmac-v2 "}),
        json!({"replay_scope": "process", "signing_profile": "FERRUM-HMAC-V2"}),
        json!({
            "replay_scope": "shared",
            "sync_mode": "REDIS",
            "redis_url": redis_url
        }),
        // Types, bounds, and the closed key set.
        json!({"replay_scope": "process", "replay_max_entries": 0}),
        json!({"replay_scope": "process", "clock_skew_seconds": 0}),
        json!({"replay_scope": "process", "clock_skew_seconds": 301}),
        json!({"replay_scope": true}),
        json!({"replay_scope": "process", "replay_scop": "shared"}),
        json!({"replay_scope": "process", "require_digest": true}),
    ];
    for config in &rejected {
        assert!(
            validator.validate(config).is_err(),
            "config should be schema-invalid: {config}"
        );
        assert!(
            create_plugin("hmac_auth", config).is_err(),
            "config should be runtime-invalid: {config}"
        );
    }
}

/// The enclosing `PluginConfig` branch must demand `config` too: an omitted
/// `config` defaults to null and `HmacAuth::build` refuses a non-object.
#[test]
fn hmac_auth_plugin_config_branch_requires_a_config_object() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let branch = spec
        .pointer("/components/schemas/PluginConfigBase/allOf/0/then/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("enabled PluginConfigBase allOf")
        .iter()
        .find(|entry| {
            entry.pointer("/if/properties/plugin_name/const") == Some(&json!("hmac_auth"))
        })
        .expect("hmac_auth PluginConfig branch");

    assert_eq!(branch.pointer("/then/required"), Some(&json!(["config"])));
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
        schema["properties"]["jwks_refresh_interval_secs"]["maximum"],
        json!(ferrum_edge::plugins::jwks_auth::MAX_JWKS_REFRESH_INTERVAL_SECS)
    );
    assert_eq!(
        schema["properties"]["jwks_max_stale_seconds"]["default"],
        json!(ferrum_edge::plugins::jwks_auth::DEFAULT_JWKS_MAX_STALE_SECONDS)
    );
    assert_eq!(
        schema["properties"]["jwks_max_stale_seconds"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["jwks_max_stale_seconds"]["maximum"],
        json!(ferrum_edge::plugins::jwks_auth::MAX_JWKS_MAX_STALE_SECONDS)
    );
    assert_eq!(
        schema["properties"]["providers"]["items"]["properties"]["jwks_max_stale_seconds"]["maximum"],
        json!(ferrum_edge::plugins::jwks_auth::MAX_JWKS_MAX_STALE_SECONDS)
    );
    assert_eq!(
        schema["properties"]["kid_miss_refresh_cooldown_seconds"]["default"],
        json!(ferrum_edge::plugins::jwks_auth::DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS)
    );
    assert_eq!(
        schema["properties"]["kid_miss_refresh_cooldown_seconds"]["maximum"],
        json!(ferrum_edge::plugins::jwks_auth::MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS)
    );
    // Zero must stay admissible: it is the documented way to disable the
    // on-demand refetch, not an invalid value.
    assert_eq!(
        schema["properties"]["kid_miss_refresh_cooldown_seconds"]["minimum"],
        json!(0)
    );
    assert_eq!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_replay_max_entries"]["default"],
        json!(ferrum_edge::plugins::jwks_auth::DEFAULT_DPOP_REPLAY_MAX_ENTRIES)
    );
    // The DPoP replay scope has no default: an operator must declare whether
    // process-local replay state is sufficient. A schema default here would
    // reinstate silent per-replica replay.
    assert_eq!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_replay_scope"]["enum"],
        json!(["process", "shared"])
    );
    assert!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_replay_scope"]["default"]
            .is_null()
    );
    assert_eq!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_clock_skew_secs"]["maximum"],
        json!(ferrum_edge::plugins::utils::dpop::MAX_DPOP_CLOCK_SKEW_SECS)
    );
    // The removed replay knobs must not reappear: retention is a fixed horizon
    // derived from the clock-skew ceiling, not a configured value.
    assert!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_jti_ttl_secs"].is_null()
    );
    assert!(
        schema["properties"]["providers"]["items"]["properties"]["dpop_jti_cache_max_entries"]
            .is_null()
    );

    let guide = include_str!("../../docs/cache_management.md");
    assert!(guide.contains("`jwks_refresh_interval_secs`, default `900` seconds"));
    assert!(guide.contains("| `jwks_auth` | `jwks_refresh_interval_secs` | `900` |"));
    assert!(guide.contains("`jwks_max_stale_seconds` (default `3600`"));
    assert!(guide.contains("maximum `86400`"));
    assert!(guide.contains("`0` is invalid"));
    assert!(guide.contains("| `jwks_auth` | `jwks_max_stale_seconds` | `3600` |"));
    assert!(guide.contains("| `jwks_auth` | `kid_miss_refresh_cooldown_seconds` | `30` |"));
    assert!(!guide.contains("| `jwks_auth` | `cache_ttl_seconds`"));
}

#[test]
fn ai_tool_governor_schema_matches_runtime_invariants() {
    use ferrum_edge::plugins::ai_tool_governor::{
        AI_TOOL_GOVERNOR_APPROVAL_KEYS, AI_TOOL_GOVERNOR_BLOCKED_PATTERN_KEYS,
        AI_TOOL_GOVERNOR_CONFIG_KEYS, AI_TOOL_GOVERNOR_INSPECT_KEYS,
        AI_TOOL_GOVERNOR_OBSERVABILITY_KEYS, AI_TOOL_GOVERNOR_RESPONSE_KEYS,
        AI_TOOL_GOVERNOR_TOOL_POLICY_KEYS,
    };

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

    let enabled = &spec["components"]["schemas"]["AiToolGovernorEnabledConfig"];
    assert_eq!(enabled["additionalProperties"], json!(false));
    assert_eq!(
        enabled["properties"]["inspect"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        enabled["properties"]["approval"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        enabled["properties"]["response"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        enabled["properties"]["observability"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        enabled["properties"]["tools"]["additionalProperties"]["additionalProperties"],
        json!(false),
        "per-tool policy objects must be closed"
    );
    assert_eq!(
        enabled["properties"]["tools"]["additionalProperties"]["properties"]["blocked_arg_patterns"]
            ["items"]["additionalProperties"],
        json!(false)
    );
    assert!(
        enabled["properties"]["tools"]["additionalProperties"]["properties"]["json_schema"]
            .get("additionalProperties")
            .is_none(),
        "json_schema must remain an intentionally open map"
    );

    let runtime_root: BTreeSet<&str> = AI_TOOL_GOVERNOR_CONFIG_KEYS.iter().copied().collect();
    let schema_root: BTreeSet<&str> = enabled["properties"]
        .as_object()
        .expect("enabled properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(runtime_root, schema_root, "root key drift");
    assert_eq!(
        AI_TOOL_GOVERNOR_INSPECT_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        enabled["properties"]["inspect"]["properties"]
            .as_object()
            .expect("inspect properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        AI_TOOL_GOVERNOR_TOOL_POLICY_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        enabled["properties"]["tools"]["additionalProperties"]["properties"]
            .as_object()
            .expect("tool policy properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        AI_TOOL_GOVERNOR_BLOCKED_PATTERN_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        enabled["properties"]["tools"]["additionalProperties"]["properties"]
            ["blocked_arg_patterns"]["items"]["properties"]
            .as_object()
            .expect("blocked pattern properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        AI_TOOL_GOVERNOR_APPROVAL_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        enabled["properties"]["approval"]["properties"]
            .as_object()
            .expect("approval properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        AI_TOOL_GOVERNOR_RESPONSE_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        enabled["properties"]["response"]["properties"]
            .as_object()
            .expect("response properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        AI_TOOL_GOVERNOR_OBSERVABILITY_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        enabled["properties"]["observability"]["properties"]
            .as_object()
            .expect("observability properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );

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
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {
                "endpoint_url": "https://approval.example/decide",
                "timeout_ms": 30000
            }
        }),
        json!({
            "tools": {
                "custom.tool": {
                    "action": "allow",
                    "json_schema": {
                        "type": "object",
                        "$comment": "open schema keywords remain allowed",
                        "unevaluatedProperties": false
                    }
                }
            }
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    assert_eq!(
        enabled["properties"]["approval"]["properties"]["timeout_ms"]["maximum"],
        json!(30000)
    );
    assert_eq!(
        enabled["properties"]["response"]["properties"]["redaction_placeholder"]["maxLength"],
        json!(256)
    );
    let placeholder_desc = enabled["properties"]["response"]["properties"]["redaction_placeholder"]
        ["description"]
        .as_str()
        .unwrap_or("");
    assert!(
        placeholder_desc.contains("Unicode characters") && placeholder_desc.contains("UTF-8 byte"),
        "redaction_placeholder must document OpenAPI character vs runtime byte caps: {placeholder_desc}"
    );
    assert_eq!(
        enabled["properties"]["tools"]["additionalProperties"]["properties"]["blocked_arg_patterns"]
            ["maxItems"],
        json!(32)
    );
    assert_eq!(
        enabled["properties"]["tools"]["additionalProperties"]["properties"]["blocked_arg_patterns"]
            ["items"]["properties"]["name"]["maxLength"],
        json!(256)
    );
    let pattern_name_desc = enabled["properties"]["tools"]["additionalProperties"]["properties"]
        ["blocked_arg_patterns"]["items"]["properties"]["name"]["description"]
        .as_str()
        .unwrap_or("");
    assert!(
        pattern_name_desc.contains("Unicode characters")
            && pattern_name_desc.contains("UTF-8 byte"),
        "blocked_arg_patterns[].name must document OpenAPI character vs runtime byte caps: {pattern_name_desc}"
    );
    let action_desc = enabled["properties"]["tools"]["additionalProperties"]["properties"]
        ["action"]["description"]
        .as_str()
        .unwrap_or("");
    assert!(
        action_desc.contains("64 concrete tool calls"),
        "action description must surface the unconditional 64-call batch bound: {action_desc}"
    );

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
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {
                "endpoint_url": "https://approval.example/decide",
                "timeout_ms": 30001
            }
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "secret", "regex": "secret"}]
                }
            },
            "response": { "redaction_placeholder": "X".repeat(257) }
        }),
        json!({"tools": {"search": {"action": "allow"}}, "modde": "enforce"}),
        json!({
            "enabled": false,
            "required_arg": ["ticket_id"]
        }),
        json!({
            "tools": {
                "search": {
                    "action": "allow",
                    "required_arg": ["q"]
                }
            }
        }),
        json!({
            "tools": {
                "search": {
                    "action": "allow",
                    "blocked_arg_patterns": [{"name": "secret", "regex": "x", "flagss": "i"}]
                }
            }
        }),
        json!({
            "tools": {"search": {"action": "allow"}},
            "inspect": {"response_tool_calls": true, "response_tool_call": true}
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

fn plugin_config_schema_mapping(spec: &serde_json::Value) -> BTreeMap<String, String> {
    let base_all_of = spec
        .pointer("/components/schemas/PluginConfigBase/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("PluginConfigBase allOf should be an array");
    assert!(
        base_all_of.len() >= 2,
        "PluginConfigBase must gate construction and keep the prometheus_metrics scope guard"
    );
    let enabled_gate = &base_all_of[0];
    assert_eq!(
        enabled_gate.pointer("/if/properties/enabled/not/const"),
        Some(&json!(false)),
        "plugin-specific construction schemas must not apply when enabled is false"
    );
    assert_eq!(
        base_all_of[1].pointer("/if/properties/plugin_name/const"),
        Some(&json!("prometheus_metrics")),
        "disabled prometheus_metrics must still require global scope"
    );
    assert_eq!(
        base_all_of[1].pointer("/then/properties/scope/const"),
        Some(&json!("global")),
        "disabled prometheus_metrics must still require global scope"
    );

    let all_of = enabled_gate
        .pointer("/then/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("enabled PluginConfigBase conditionals should be an array");

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
        "config": {"max_frame_bytes": 1024, "max_message_bytes": 4096}
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

    let invalid_message_limit = plugin_config(
        "ws_message_size_limiting",
        Some(json!({"max_frame_bytes": 1024, "max_message_bytes": 0})),
    );
    assert!(
        validator.validate(&invalid_message_limit).is_err(),
        "ws_message_size_limiting should reject a zero max_message_bytes"
    );

    let empty_termination = plugin_config("request_termination", Some(json!({})));
    assert!(
        validator.validate(&empty_termination).is_ok(),
        "empty request_termination config remains the maintenance-mode default"
    );
    let omitted_termination = plugin_config("request_termination", None);
    assert!(
        validator.validate(&omitted_termination).is_err(),
        "enabled request_termination rows must require config"
    );

    for (plugin_name, config) in [
        ("correlation_id", json!({})),
        ("security_headers", json!({})),
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
        ("correlation_id", None),
        ("correlation_id", Some(serde_json::Value::Null)),
        ("correlation_id", Some(json!([]))),
        ("correlation_id", Some(json!({"echo_downsteam": false}))),
        ("security_headers", None),
        ("security_headers", Some(serde_json::Value::Null)),
        (
            "security_headers",
            Some(json!({"set": {"Content-Length": "ordinary"}})),
        ),
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

/// Issue #4996: shared PluginConfig/Create/Replace must admit the same null,
/// disabled, and POST-default bodies as `validate_plugin_config_definition`
/// and PUT's explicit `enabled` presence check, without loosening enabled
/// construction or PUT replace semantics.
#[test]
fn plugin_config_shared_schema_matches_admin_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    assert_eq!(
        spec["paths"]["/plugins/config"]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"],
        json!("#/components/schemas/PluginConfigCreate")
    );
    assert_eq!(
        spec["paths"]["/plugins/config/{id}"]["put"]["requestBody"]["content"]["application/json"]
            ["schema"]["$ref"],
        json!("#/components/schemas/PluginConfigReplace")
    );
    assert_eq!(
        spec["components"]["schemas"]["BatchCreateRequest"]["properties"]["plugin_configs"]["items"]
            ["$ref"],
        json!("#/components/schemas/PluginConfigCreate")
    );
    assert_eq!(
        spec["components"]["schemas"]["PluginConfigBase"]["properties"]["config"]["type"],
        json!(["object", "null"])
    );
    assert_eq!(
        spec["components"]["schemas"]["PluginConfigCreate"]["allOf"][1]["required"],
        json!(["plugin_name", "scope"])
    );
    assert_eq!(
        spec["components"]["schemas"]["PluginConfigReplace"]["allOf"][1]["required"],
        json!(["plugin_name", "scope", "enabled"])
    );
    assert_eq!(
        spec["components"]["schemas"]["PluginConfig"]["allOf"][1]["required"],
        json!(["plugin_name", "scope", "enabled"])
    );

    let stdout_null = json!({
        "plugin_name": "stdout_logging",
        "scope": "global",
        "enabled": true,
        "config": null
    });
    assert_component_validity(&spec, "PluginConfigCreate", &stdout_null, true);
    assert_component_validity(&spec, "PluginConfig", &stdout_null, true);
    assert_component_validity(&spec, "PluginConfigReplace", &stdout_null, true);

    let disabled_http_logging = json!({
        "plugin_name": "http_logging",
        "scope": "global",
        "enabled": false,
        "config": {}
    });
    assert_component_validity(&spec, "PluginConfigCreate", &disabled_http_logging, true);
    assert_component_validity(&spec, "PluginConfig", &disabled_http_logging, true);
    assert_component_validity(&spec, "PluginConfigReplace", &disabled_http_logging, true);

    let post_defaults = json!({
        "plugin_name": "stdout_logging",
        "scope": "global",
        "config": {}
    });
    assert_component_validity(&spec, "PluginConfigCreate", &post_defaults, true);
    assert_component_validity(&spec, "PluginConfig", &post_defaults, false);
    assert_component_validity(&spec, "PluginConfigReplace", &post_defaults, false);

    let enabled_http_logging_missing_endpoint = json!({
        "plugin_name": "http_logging",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert_component_validity(
        &spec,
        "PluginConfigCreate",
        &enabled_http_logging_missing_endpoint,
        false,
    );
    assert_component_validity(
        &spec,
        "PluginConfig",
        &enabled_http_logging_missing_endpoint,
        false,
    );

    let object_only_null = json!({
        "plugin_name": "http_logging",
        "scope": "global",
        "enabled": true,
        "config": null
    });
    assert_component_validity(&spec, "PluginConfigCreate", &object_only_null, false);
    assert_component_validity(&spec, "PluginConfigReplace", &object_only_null, false);

    let mut missing_config = json!({
        "plugin_name": "http_logging",
        "scope": "global"
    });
    assert_component_validity(&spec, "PluginConfigCreate", &missing_config, false);
    missing_config["enabled"] = json!(false);
    for component in ["PluginConfigCreate", "PluginConfig", "PluginConfigReplace"] {
        assert_component_validity(&spec, component, &missing_config, true);
    }

    for plugin_name in ["prometheus_metrics", "mtls_auth", "compression"] {
        let body = json!({
            "plugin_name": plugin_name,
            "scope": "global",
            "enabled": true,
            "config": null
        });
        assert_component_validity(&spec, "PluginConfigCreate", &body, true);
    }

    // Generic scope restrictions still apply when construction is skipped.
    for plugin_name in ["prometheus_metrics", "transaction_log_schema"] {
        let mut body = json!({
            "plugin_name": plugin_name,
            "scope": "global",
            "enabled": false,
            "config": {}
        });
        for component in ["PluginConfigCreate", "PluginConfig", "PluginConfigReplace"] {
            assert_component_validity(&spec, component, &body, true);
        }
        body["scope"] = json!("proxy_group");
        for component in ["PluginConfigCreate", "PluginConfig", "PluginConfigReplace"] {
            assert_component_validity(&spec, component, &body, false);
        }
    }
}

#[test]
fn geo_restriction_schema_matches_strict_runtime_contract() {
    use ferrum_edge::plugins::geo_restriction::GeoRestriction;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/GeoRestrictionConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("GeoRestrictionConfig schema compiles");

    let fixtures = [
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["ad", "cA", "xK", "Zw"]
            }),
            true,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": [],
                "deny_countries": ["CN"]
            }),
            true,
        ),
        (json!({"db_path": "/nonexistent/country.mmdb"}), false),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": [],
                "deny_countries": []
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["US"],
                "deny_countries": ["CN"]
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["USA"]
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": [" US "]
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["ZZ"]
            }),
            false,
        ),
        (json!({"db_path": " \t ", "allow_countries": ["US"]}), false),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["US"],
                "on_lookup_failur": "deny"
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": null
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["US"],
                "inject_headers": null
            }),
            false,
        ),
        (
            json!({
                "db_path": "/nonexistent/country.mmdb",
                "allow_countries": ["US"],
                "on_lookup_failure": null
            }),
            false,
        ),
    ];

    for (config, expected_valid) in fixtures {
        let schema_valid = validator.validate(&config).is_ok();
        let runtime_valid = GeoRestriction::new(&config).is_ok();
        assert_eq!(
            schema_valid, expected_valid,
            "unexpected GeoRestrictionConfig schema result for {config}"
        );
        assert_eq!(
            runtime_valid, expected_valid,
            "unexpected geo_restriction runtime result for {config}"
        );
    }

    let mut supported_code_count = 0;
    for first in b'A'..=b'Z' {
        for second in b'A'..=b'Z' {
            let code = String::from_utf8(vec![first, second]).expect("ASCII country code");
            let lowercase = code.to_ascii_lowercase();
            let mixed_case =
                String::from_utf8(vec![first.to_ascii_lowercase(), second]).expect("ASCII code");
            let mut assignment_supported = None;
            for candidate in [code.clone(), lowercase, mixed_case] {
                let config = json!({
                    "db_path": "/nonexistent/country.mmdb",
                    "allow_countries": [candidate.clone()],
                    "on_lookup_failure": "deny"
                });
                let schema_valid = validator.validate(&config).is_ok();
                let runtime_valid = GeoRestriction::new(&config).is_ok();
                assert_eq!(
                    schema_valid, runtime_valid,
                    "schema/runtime country assignment mismatch for {candidate}"
                );
                if let Some(expected) = assignment_supported {
                    assert_eq!(
                        runtime_valid, expected,
                        "country assignment must be case-insensitive for {candidate}"
                    );
                } else {
                    assignment_supported = Some(runtime_valid);
                }
            }
            if assignment_supported == Some(true) {
                supported_code_count += 1;
            }
        }
    }
    // 249 currently assigned ISO codes plus MaxMind's XK extension.
    assert_eq!(supported_code_count, 250);
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
                "key": "test-load-key-0123456789abcdef!!",
                "concurrent_clients": 1,
                "duration_seconds": 1,
                "gateway_port": 8000,
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
        &json!({
            "provider": "azure_functions",
            "function_url": "https://functions.example/run",
            "forwad_body": true
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "azure_functions",
            "function_url": "https://functions.example/run",
            "mode": null
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "azure_functions",
            "function_url": "https://functions.example/run",
            "error_status_code": 399
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "azure_functions",
            "function_url": "https://functions.example/run",
            "error_status_code": 400
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "azure_functions",
            "function_url": "https://user:password@functions.example/run"
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "gcp_cloud_functions",
            "function_url": "https://functions.example/run#credential"
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "aws_lambda",
            "aws_endpoint_url": "https://lambda.example/not-an-origin"
        }),
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
                "rules": [{
                    "operation": "remove",
                    "target": "header",
                    "key": "x-review-pin"
                }],
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

#[test]
fn request_transformer_schema_matches_runtime_target_and_value_contract() {
    use ferrum_edge::plugins::request_transformer::RequestTransformer;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let rules_items = spec
        .pointer("/components/schemas/RequestTransformerConfig/properties/rules/items")
        .expect("RequestTransformerConfig.rules.items exists");
    assert!(
        rules_items.get("oneOf").is_some(),
        "request_transformer rules must be target-discriminated oneOf variants"
    );
    assert_eq!(
        rules_items["discriminator"]["propertyName"],
        json!("target")
    );

    for (variant, expected_target) in [
        ("RequestTransformerHeaderRule", "header"),
        ("RequestTransformerQueryRule", "query"),
        ("RequestTransformerBodyRule", "body"),
    ] {
        let schema = spec
            .pointer(&format!("/components/schemas/{variant}"))
            .unwrap_or_else(|| panic!("{variant} schema exists"));
        let required = schema["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{variant}.required is an array"));
        assert!(
            required.iter().any(|value| value == "target"),
            "{variant} must require target"
        );
        assert_eq!(
            schema["properties"]["target"]["const"],
            json!(expected_target)
        );
        assert!(
            schema["properties"]["target"].get("default").is_none(),
            "{variant}.target must not advertise a default"
        );
    }

    assert_eq!(
        spec.pointer("/components/schemas/RequestTransformerHeaderRule/properties/value/type")
            .expect("header value type"),
        &json!("string")
    );
    assert_eq!(
        spec.pointer("/components/schemas/RequestTransformerQueryRule/properties/value/type")
            .expect("query value type"),
        &json!("string")
    );
    assert!(
        spec.pointer("/components/schemas/RequestTransformerBodyRule/properties/value/type")
            .is_none(),
        "body value must remain unconstrained JSON (including null)"
    );

    for component in [
        "RequestTransformerConfig",
        "RequestTransformerHeaderRule",
        "RequestTransformerQueryRule",
        "RequestTransformerBodyRule",
    ] {
        assert_eq!(
            spec.pointer(&format!(
                "/components/schemas/{component}/additionalProperties"
            ))
            .unwrap_or_else(|| panic!("{component}.additionalProperties")),
            &json!(false),
            "{component} must reject unknown properties"
        );
    }

    let runtime_overlay = spec
        .pointer("/components/schemas/RequestTransformerConfig/properties/runtime_overlay_scope")
        .expect("runtime_overlay_scope remains published");
    assert_eq!(runtime_overlay["type"], json!(["string", "null"]));
    assert_eq!(runtime_overlay["minLength"], json!(1));
    assert_eq!(runtime_overlay["pattern"], json!("\\S"));
    assert_eq!(
        spec.pointer("/components/schemas/RequestTransformerConfig/properties/default_enabled")
            .expect("default_enabled remains published")["default"],
        json!(true)
    );

    // Every optional field whose constructor treats explicit `null` as absent
    // must admit `null` in the schema too.
    for field in [
        "apply_route_overrides",
        "default_enabled",
        "runtime_overlay_resolved_enabled",
    ] {
        let property = spec
            .pointer(&format!(
                "/components/schemas/RequestTransformerConfig/properties/{field}"
            ))
            .unwrap_or_else(|| panic!("{field} remains published"));
        assert_eq!(
            property["type"],
            json!(["boolean", "null"]),
            "{field} must admit the explicit null the constructor accepts"
        );
    }

    // The no-effect config is rejected by the schema, not only by the
    // constructor: either a non-empty `rules` array or the route-only opt-in.
    assert!(
        spec.pointer("/components/schemas/RequestTransformerConfig/anyOf")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|branches| branches.len() == 2),
        "RequestTransformerConfig must model non-empty rules vs route-only opt-in"
    );

    // Per-operation field sets ARE expressible in Draft 2020-12, and every rule
    // variant composes the one shared contract.
    let contract = json!("#/components/schemas/TransformerOperationFieldExactness");
    for variant in [
        "RequestTransformerHeaderRule",
        "RequestTransformerQueryRule",
        "RequestTransformerBodyRule",
    ] {
        let composed = spec
            .pointer(&format!("/components/schemas/{variant}/allOf"))
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("{variant} must compose the operation contract"));
        assert!(
            composed.iter().any(|branch| branch["$ref"] == contract),
            "{variant} must reference the shared operation-field contract"
        );
    }

    for config in [
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue"
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue"
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "header",
                "key": "X-Internal"
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "body",
                "key": "enabled",
                "value": true
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "body",
                "key": "count",
                "value": 42
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "body",
                "key": "optional_field",
                "value": null
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "body",
                "key": "meta",
                "value": {"a": 1}
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "body",
                "key": "tags",
                "value": ["a", "b"]
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "x-audit",
                "value": "enabled"
            }],
            "runtime_overlay_scope": "internal",
            "default_enabled": false
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Edge",
                "value": "tab\there"
            }]
        }),
        // Route-only opt-in: the translator-owned consumer carries no static
        // rules at all.
        json!({"apply_route_overrides": true}),
        json!({"rules": [], "apply_route_overrides": true}),
        // Explicit `null` on a field the constructor treats as absent.
        json!({
            "rules": [{"operation": "remove", "target": "header", "key": "x-audit"}],
            "default_enabled": null
        }),
        json!({
            "rules": [{"operation": "remove", "target": "header", "key": "x-audit"}],
            "apply_route_overrides": null,
            "runtime_overlay_scope": null,
            "runtime_overlay_resolved_enabled": null
        }),
        // A numeric segment is an ordinary array index for add/update/remove.
        json!({
            "rules": [{
                "operation": "update",
                "target": "body",
                "key": "items.0.name",
                "value": "first"
            }]
        }),
        // An ESCAPED numeric segment is a literal key, so rename still accepts it.
        json!({
            "rules": [{
                "operation": "rename",
                "target": "body",
                "key": "counts\\.0",
                "new_key": "counts_first"
            }]
        }),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "body",
                "key": "user.old",
                "new_key": "user.new"
            }]
        }),
    ] {
        assert_component_validity(&spec, "RequestTransformerConfig", &config, true);
        assert!(
            RequestTransformer::new(&config).is_ok(),
            "runtime rejected OpenAPI-valid request_transformer config: {config}"
        );
    }

    for config in [
        json!({
            "rules": [{
                "operation": "add",
                "key": "X-Color",
                "value": "blue"
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": true
            }]
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": 1
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "header",
                "key": "x-review-pin"
            }],
            "runtime_overlay_scope": " \t "
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue"
            }],
            "runtime_overlay_scpoe": "internal"
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "vaule": "green"
            }]
        }),
        // A config with no effect.
        json!({}),
        json!({"rules": []}),
        json!({"apply_route_overrides": false}),
        json!({"apply_route_overrides": null}),
        // Per-operation required / forbidden properties, for every target.
        json!({"rules": [{"operation": "update", "target": "header", "key": "x-audit"}]}),
        json!({"rules": [{"operation": "add", "target": "query", "key": "audit"}]}),
        json!({"rules": [{"operation": "add", "target": "body", "key": "audit"}]}),
        json!({"rules": [{"operation": "rename", "target": "header", "key": "x-old"}]}),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "header",
                "key": "x-audit",
                "value": "unused"
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "query",
                "key": "audit",
                "new_key": "moved"
            }]
        }),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": "blue"
            }]
        }),
        // Operation-incompatible extras are rejected by PRESENCE, so an explicit
        // `null` fails exactly as a string would — body rules included.
        json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": null
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "body",
                "key": "secret",
                "new_key": null
            }]
        }),
        json!({
            "rules": [{
                "operation": "update",
                "target": "body",
                "key": "state",
                "value": "public",
                "new_key": null
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "body",
                "key": "secret",
                "value": null
            }]
        }),
        // Header field-name grammar.
        json!({"rules": [{"operation": "remove", "target": "header", "key": "bad name"}]}),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "bad name"
            }]
        }),
        // CR / LF in query strings is request-target injection.
        json!({
            "rules": [{
                "operation": "add",
                "target": "query",
                "key": "audit",
                "value": "yes\r\nx: 1"
            }]
        }),
        // Array indices are not renameable.
        json!({
            "rules": [{
                "operation": "rename",
                "target": "body",
                "key": "items.0",
                "new_key": "first"
            }]
        }),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "body",
                "key": "first",
                "new_key": "items.0"
            }]
        }),
    ] {
        assert_component_validity(&spec, "RequestTransformerConfig", &config, false);
        assert!(
            RequestTransformer::new(&config).is_err(),
            "runtime accepted OpenAPI-invalid request_transformer config: {config}"
        );
    }
}

#[test]
fn response_transformer_schema_matches_runtime_target_and_value_contract() {
    use ferrum_edge::plugins::response_transformer::ResponseTransformer;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let rules_items = spec
        .pointer("/components/schemas/ResponseTransformerConfig/properties/rules/items")
        .expect("ResponseTransformerConfig.rules.items exists");
    assert!(
        rules_items.get("oneOf").is_some(),
        "response_transformer rules must be target-discriminated oneOf variants"
    );
    assert_eq!(
        rules_items["discriminator"]["propertyName"],
        json!("target")
    );

    for (variant, expected_target) in [
        ("ResponseTransformerHeaderRule", "header"),
        ("ResponseTransformerBodyRule", "body"),
    ] {
        let schema = spec
            .pointer(&format!("/components/schemas/{variant}"))
            .unwrap_or_else(|| panic!("{variant} schema exists"));
        let required = schema["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{variant}.required is an array"));
        assert!(
            required.iter().any(|value| value == "target"),
            "{variant} must require target"
        );
        assert_eq!(
            schema["properties"]["target"]["const"],
            json!(expected_target)
        );
        assert!(
            schema["properties"]["target"].get("default").is_none(),
            "{variant}.target must not advertise a default"
        );
    }

    assert_eq!(
        spec.pointer("/components/schemas/ResponseTransformerHeaderRule/properties/value/type")
            .expect("header value type"),
        &json!("string")
    );
    assert!(
        spec.pointer("/components/schemas/ResponseTransformerBodyRule/properties/value/type")
            .is_none(),
        "body value must remain unconstrained JSON (including null)"
    );

    for component in [
        "ResponseTransformerConfig",
        "ResponseTransformerHeaderRule",
        "ResponseTransformerBodyRule",
    ] {
        assert_eq!(
            spec.pointer(&format!(
                "/components/schemas/{component}/additionalProperties"
            ))
            .unwrap_or_else(|| panic!("{component}.additionalProperties")),
            &json!(false),
            "{component} must reject unknown properties"
        );
    }

    let runtime_overlay = spec
        .pointer("/components/schemas/ResponseTransformerConfig/properties/runtime_overlay_scope")
        .expect("runtime_overlay_scope remains published");
    assert_eq!(runtime_overlay["type"], json!(["string", "null"]));
    assert_eq!(runtime_overlay["minLength"], json!(1));
    assert_eq!(runtime_overlay["pattern"], json!("\\S"));
    assert_eq!(
        spec.pointer("/components/schemas/ResponseTransformerConfig/properties/default_enabled")
            .expect("default_enabled remains published")["default"],
        json!(true)
    );

    for field in [
        "apply_route_overrides",
        "default_enabled",
        "runtime_overlay_resolved_enabled",
    ] {
        let property = spec
            .pointer(&format!(
                "/components/schemas/ResponseTransformerConfig/properties/{field}"
            ))
            .unwrap_or_else(|| panic!("{field} remains published"));
        assert_eq!(
            property["type"],
            json!(["boolean", "null"]),
            "{field} must admit the explicit null the constructor accepts"
        );
    }

    assert!(
        spec.pointer("/components/schemas/ResponseTransformerConfig/anyOf")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|branches| branches.len() == 2),
        "ResponseTransformerConfig must model non-empty rules vs route-only opt-in"
    );

    let contract = json!("#/components/schemas/TransformerOperationFieldExactness");
    for variant in [
        "ResponseTransformerHeaderRule",
        "ResponseTransformerBodyRule",
    ] {
        let composed = spec
            .pointer(&format!("/components/schemas/{variant}/allOf"))
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("{variant} must compose the operation contract"));
        assert!(
            composed.iter().any(|branch| branch["$ref"] == contract),
            "{variant} must reference the shared operation-field contract"
        );
    }

    for config in [
        json!({
            "rules": [{
                "operation": "add", "target": "header", "key": "X-Color", "value": "blue"
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove", "target": "header", "key": "X-Internal"
            }]
        }),
        json!({
            "rules": [{
                "operation": "add", "target": "body", "key": "enabled", "value": true
            }]
        }),
        json!({
            "rules": [{
                "operation": "add", "target": "body", "key": "optional", "value": null
            }],
            "runtime_overlay_scope": "internal",
            "default_enabled": false
        }),
        json!({
            "rules": [{
                "operation": "add", "target": "header", "key": "X-Edge", "value": "tab\there"
            }]
        }),
        json!({"apply_route_overrides": true}),
        json!({"rules": [], "apply_route_overrides": true}),
        json!({
            "rules": [{"operation": "remove", "target": "header", "key": "X-Internal"}],
            "apply_route_overrides": null,
            "runtime_overlay_scope": null,
            "default_enabled": null,
            "runtime_overlay_resolved_enabled": null
        }),
        // Set-Cookie is renameable neither way, but every other operation on it
        // stays available.
        json!({"rules": [{"operation": "remove", "target": "header", "key": "Set-Cookie"}]}),
        json!({
            "rules": [{
                "operation": "add", "target": "header", "key": "Set-Cookie", "value": "a=1"
            }]
        }),
        json!({"rules": [{"operation": "remove", "target": "body", "key": "items.0"}]}),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "body",
                "key": "counts\\.0",
                "new_key": "counts_first"
            }]
        }),
    ] {
        assert_component_validity(&spec, "ResponseTransformerConfig", &config, true);
        assert!(
            ResponseTransformer::new(&config).is_ok(),
            "runtime rejected OpenAPI-valid response_transformer config: {config}"
        );
    }

    for config in [
        json!({
            "rules": [{"operation": "add", "key": "X-Color", "value": "blue"}]
        }),
        json!({
            "rules": [{
                "operation": "add", "target": "header", "key": "X-Color", "value": true
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove", "target": "header", "key": "x-review-pin"
            }],
            "runtime_overlay_scope": " \t "
        }),
        json!({
            "rules": [{
                "operation": "add", "target": "header", "key": "X-Color", "value": "blue"
            }],
            "runtime_overlay_scpoe": "internal"
        }),
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "vaule": "green"
            }]
        }),
        json!({}),
        json!({"rules": []}),
        json!({"apply_route_overrides": false}),
        json!({"rules": [{"operation": "update", "target": "header", "key": "x-audit"}]}),
        json!({"rules": [{"operation": "add", "target": "body", "key": "audit"}]}),
        json!({"rules": [{"operation": "rename", "target": "header", "key": "x-old"}]}),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "header",
                "key": "x-audit",
                "value": "unused"
            }]
        }),
        json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": null
            }]
        }),
        json!({
            "rules": [{
                "operation": "remove",
                "target": "body",
                "key": "secret",
                "new_key": null
            }]
        }),
        json!({
            "rules": [{
                "operation": "update",
                "target": "body",
                "key": "state",
                "value": "public",
                "new_key": null
            }]
        }),
        json!({"rules": [{"operation": "remove", "target": "header", "key": "bad name"}]}),
        // Set-Cookie's newline-joined multi-value encoding is name-bound.
        json!({
            "rules": [{
                "operation": "rename",
                "target": "header",
                "key": "Set-Cookie",
                "new_key": "X-Cookies"
            }]
        }),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "header",
                "key": "X-Cookies",
                "new_key": "SET-COOKIE"
            }]
        }),
        json!({
            "rules": [{
                "operation": "rename",
                "target": "body",
                "key": "items.0",
                "new_key": "first"
            }]
        }),
    ] {
        assert_component_validity(&spec, "ResponseTransformerConfig", &config, false);
        assert!(
            ResponseTransformer::new(&config).is_err(),
            "runtime accepted OpenAPI-invalid response_transformer config: {config}"
        );
    }
}

#[test]
fn body_validator_grpc_max_decompressed_size_bytes_stays_in_openapi_docs_and_runtime() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let property = spec
        .pointer(
            "/components/schemas/BodyValidatorConfig/properties/grpc_max_decompressed_size_bytes",
        )
        .expect("BodyValidatorConfig must publish grpc_max_decompressed_size_bytes");
    assert_eq!(property["type"], json!("integer"));
    assert_eq!(property["format"], json!("uint64"));
    assert_eq!(property["minimum"], json!(0));
    assert!(
        property.get("default").is_none(),
        "environment-derived omission semantics cannot be represented by a static OpenAPI default"
    );

    let description = property["description"]
        .as_str()
        .expect("grpc_max_decompressed_size_bytes description");
    for contract in [
        "`0` disables the decompressed cap",
        "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
        "parses as an unsigned integer",
        "10 MiB",
        "request and response",
        "No static OpenAPI default",
    ] {
        assert!(
            description.contains(contract),
            "BodyValidatorConfig.grpc_max_decompressed_size_bytes description missing `{contract}`"
        );
    }

    // Each instance carries a rule-bearing key: the schema now refuses a
    // configuration with no validation rule at all, exactly as the constructor
    // does (issue #5122).
    assert_component_validity(
        &spec,
        "BodyValidatorConfig",
        &json!({"validate_xml": true, "grpc_max_decompressed_size_bytes": 0}),
        true,
    );
    assert_component_validity(
        &spec,
        "BodyValidatorConfig",
        &json!({"validate_xml": true, "grpc_max_decompressed_size_bytes": -1}),
        false,
    );
    assert_component_validity(
        &spec,
        "BodyValidatorConfig",
        &json!({"validate_xml": true, "grpc_max_decompressed_size_bytes": "10"}),
        false,
    );

    let plugin_docs = include_str!("../../docs/plugins.md");
    let docs = plugin_docs
        .split("### `body_validator`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("body_validator docs section");
    assert!(
        docs.contains("`grpc_max_decompressed_size_bytes`"),
        "docs/plugins.md body_validator section missing `grpc_max_decompressed_size_bytes`"
    );
    for contract in [
        "`0` disables the decompressed cap",
        "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
        "parses as an unsigned integer",
        "10 MiB",
        "request and response",
    ] {
        assert!(
            docs.contains(contract),
            "docs/plugins.md body_validator section missing `{contract}`"
        );
    }

    let runtime = include_str!("../../src/plugins/body_validator.rs");
    assert!(
        runtime.contains("optional_usize(config, \"grpc_max_decompressed_size_bytes\")?"),
        "runtime must keep accepting grpc_max_decompressed_size_bytes"
    );
    assert!(
        runtime.contains("fn default_grpc_max_decompressed_size_bytes"),
        "runtime must keep environment-derived omission fallback"
    );
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
fn stdout_logging_schema_rejects_unknown_outer_and_filter_keys() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for valid in [
        serde_json::Value::Null,
        json!({}),
        json!({"filter": null}),
        json!({"filter": {"status_code_min": 500, "errors_only": true}}),
        json!({"filter": {"status_code_max": 599}}),
        json!({"filter": {"min_latency_ms": 250}}),
        json!({"filter": {"errors_only": false}}),
        json!({"filter": {"expression": {"op": "errors_only"}}}),
        json!({"schema": {}}),
        json!({"schema_ref": "common"}),
    ] {
        assert_component_validity(&spec, "StdoutLoggingConfig", &valid, true);
    }
    for invalid in [
        json!({"filters": {"errors_only": true}}),
        json!({"log_level": "info"}),
        json!({"filter": {"error_only": true}}),
        json!({"filter": {"min_latency_msec": 100}}),
        json!({
            "filter": {
                "expression": {"op": "errors_only"},
                "status_code_min": 500
            }
        }),
        json!({
            "filter": {
                "expression": {"op": "errors_only"},
                "status_code_max": 599
            }
        }),
        json!({
            "filter": {
                "expression": {"op": "errors_only"},
                "min_latency_ms": 10
            }
        }),
        json!({
            "filter": {
                "expression": {"op": "errors_only"},
                "errors_only": false
            }
        }),
        json!({"schema": {}, "schema_ref": "known"}),
    ] {
        assert_component_validity(&spec, "StdoutLoggingConfig", &invalid, false);
    }
}

#[test]
fn http_logging_schema_rejects_unknown_keys_and_invalid_endpoints() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/HttpLoggingConfig")
        .expect("HttpLoggingConfig exists");
    assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));
    assert_eq!(schema.get("required"), Some(&json!(["endpoint_url"])));

    let endpoint = "http://127.0.0.1:29001/ingest";
    for valid in [
        json!({"endpoint_url": endpoint}),
        json!({"endpoint_url": "http://[::1]/logs"}),
        json!({"endpoint_url": "HTTP://localhost:9200/logs"}),
        json!({
            "endpoint_url": endpoint,
            "custom_headers": {
                "Authorization": "Bearer token",
                "X-Custom": "x",
                "authorization": "Bearer other"
            }
        }),
        json!({"endpoint_url": endpoint, "schema": {}}),
        json!({"endpoint_url": endpoint, "schema_ref": "known"}),
    ] {
        assert_component_validity(&spec, "HttpLoggingConfig", &valid, true);
    }
    for invalid in [
        json!({"endpoint_url": endpoint, "typo": 1}),
        json!({"endpoint_url": ""}),
        json!({"endpoint_url": "ftp://localhost"}),
        json!({"endpoint_url": "http:///ingest"}),
        json!({"endpoint_url": "http://user:pass@localhost"}),
        json!({
            "endpoint_url": endpoint,
            "custom_headers": {"bad name": "x"}
        }),
        json!({
            "endpoint_url": endpoint,
            "custom_headers": {"X-Token": "bad\r\nvalue"}
        }),
        json!({
            "endpoint_url": endpoint,
            "schema": {},
            "schema_ref": "known"
        }),
    ] {
        assert_component_validity(&spec, "HttpLoggingConfig", &invalid, false);
    }
}

#[test]
fn kafka_logging_schema_rejects_unknown_root_keys_and_is_closed() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/KafkaLoggingConfig")
        .expect("KafkaLoggingConfig exists");
    assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));

    assert_eq!(
        schema["properties"]["flush_timeout_seconds"]["maximum"],
        json!(300)
    );
    assert_eq!(
        schema["properties"]["max_entry_bytes"]["default"],
        json!(65536)
    );
    assert_eq!(
        schema["properties"]["max_entry_bytes"]["maximum"],
        json!(1048576)
    );
    assert_eq!(
        schema["properties"]["buffer_max_bytes"]["default"],
        json!(16777216)
    );
    assert_eq!(
        schema["properties"]["buffer_max_bytes"]["maximum"],
        json!(268435456)
    );
    assert_eq!(
        schema["properties"]["security_protocol"]["default"],
        json!("plaintext")
    );
    assert_eq!(schema["properties"]["topic"]["maxLength"], json!(249));
    assert_eq!(
        schema["properties"]["message_timeout_ms"]["maximum"],
        json!(2147483647)
    );

    for valid in [
        json!({"broker_list": "localhost:9092", "topic": "logs"}),
        json!({
            "broker_list": "localhost:9092",
            "topic": "logs",
            "security_protocol": "ssl",
            "buffer_capacity": 1000,
            "max_entry_bytes": 65536,
            "buffer_max_bytes": 16777216,
            "flush_timeout_seconds": 5
        }),
        json!({
            "broker_list": "localhost:9092",
            "topic": "logs",
            "flush_timeout_seconds": 300
        }),
        json!({
            "broker_list": "localhost:9092",
            "topic": "logs",
            "security_protocol": "sasl_ssl",
            "ssl_ca_location": "/etc/ferrum/ca.pem",
            "sasl_mechanism": "PLAIN",
            "sasl_username": "alice",
            "sasl_password": "secret"
        }),
    ] {
        assert_component_validity(&spec, "KafkaLoggingConfig", &valid, true);
    }
    for invalid in [
        json!({"broker_list": "localhost:9092", "topic": "logs", "security_protcol": "ssl"}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "unknown": true}),
        json!({"topic": "logs"}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "buffer_capacity": 0}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "flush_timeout_seconds": 0}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "flush_timeout_seconds": 301}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "max_entry_bytes": 0}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "buffer_max_bytes": 0}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "ssl_no_verify": false}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "security_protocol": "ssl", "sasl_mechanism": "PLAIN"}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "security_protocol": "sasl_plaintext", "ssl_ca_location": "/etc/ferrum/ca.pem"}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "security_protocol": "sasl_ssl", "sasl_username": "alice"}),
        json!({"broker_list": "localhost:9092", "topic": "logs", "security_protocol": "ssl", "ssl_certificate_location": "/etc/ferrum/client.pem"}),
    ] {
        assert_component_validity(&spec, "KafkaLoggingConfig", &invalid, false);
    }
}

/// The retained-byte lease and the `key_field: none` partitioning contract must
/// not drift back to their pre-#5218 / pre-#5219 text on any operator surface.
///
/// Both claims were stale in opposite directions: the budget was described as
/// released at `send`, when it is held through terminal delivery; and `none` was
/// described as round-robin, when it simply omits the key and lets librdkafka's
/// own (sticky, consistent-random) partitioner choose.
#[test]
fn kafka_logging_operator_surfaces_describe_the_implemented_behavior() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/KafkaLoggingConfig")
        .expect("KafkaLoggingConfig exists");
    let plugin_docs = include_str!("../../docs/plugins.md");
    let kafka_section = plugin_docs
        .split_once("### `kafka_logging`")
        .and_then(|(_, rest)| rest.split_once("\n### "))
        .map(|(section, _)| section)
        .expect("docs/plugins.md has a bounded kafka_logging section");

    let buffer_description = schema["properties"]["buffer_max_bytes"]["description"]
        .as_str()
        .expect("buffer_max_bytes description");
    assert!(
        buffer_description.contains("NOT released when librdkafka send returns"),
        "the OpenAPI budget description must state that the lease survives handoff"
    );
    assert!(
        !buffer_description.contains("Bytes are released when librdkafka send returns"),
        "the OpenAPI budget description must not claim release at handoff"
    );
    assert!(
        kafka_section.contains("The charge is **not** released when `send` returns"),
        "docs/plugins.md must state that the lease survives handoff"
    );
    assert!(
        !kafka_section.contains("Bytes release when librdkafka `send` returns"),
        "docs/plugins.md must not claim release at handoff"
    );

    let key_field_description = schema["properties"]["key_field"]["description"]
        .as_str()
        .expect("key_field description");
    assert!(
        key_field_description.contains("consistent_random"),
        "the OpenAPI key_field description must name the librdkafka partitioner"
    );
    assert!(
        !key_field_description.contains("round-robin"),
        "the OpenAPI key_field description must not promise round-robin"
    );
    assert!(
        kafka_section.contains("consistent_random"),
        "docs/plugins.md must name the librdkafka partitioner for key_field none"
    );
    assert!(
        !kafka_section.contains("round-robin"),
        "docs/plugins.md must not promise round-robin partition assignment"
    );

    // The retained-bytes gauge HELP is published from the contract inventory.
    for surface in [
        include_str!("../../docs/prometheus_metrics.md"),
        include_str!("../../docs/prometheus_metric_contract.json"),
    ] {
        assert!(
            !surface.contains("awaiting librdkafka admission"),
            "the retained-bytes gauge must not describe a userspace-only budget"
        );
    }
}

/// The component must admit exactly what `KafkaLogging::new` admits (#5217).
///
/// Every syntactic case below was reproduced against the constructor; a client
/// generated from this schema has to reach the same verdict, or preflight is
/// useless. Two constraints stay deliberately outside the schema because JSON
/// Schema cannot express them: `buffer_max_bytes >= max_entry_bytes` (an
/// unrestricted sibling-number comparison) and whether a `schema_ref` names a
/// schema some `transaction_log_schema` plugin actually registered. Both are
/// stated in the component descriptions instead.
#[test]
fn kafka_logging_schema_matches_runtime_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let long_topic = "a".repeat(249);
    let too_long_topic = "a".repeat(250);
    let base = |extra: serde_json::Value| -> serde_json::Value {
        let mut config = json!({"broker_list": "127.0.0.1:9092", "topic": "audit-logs"});
        for (key, value) in extra.as_object().expect("overrides are an object") {
            config[key] = value.clone();
        }
        config
    };

    for valid in [
        base(json!({"topic": long_topic})),
        base(json!({"topic": "a.b_c-d"})),
        base(json!({"topic": "..."})),
        base(json!({"message_timeout_ms": 0})),
        base(json!({"message_timeout_ms": 2147483647})),
        base(json!({"schema_ref": "named"})),
        base(json!({"producer_config": {"linger.ms": "50"}})),
        base(json!({"producer_config": {"queue.buffering.max.messages": "100000"}})),
        base(json!({"producer_config": {"queue.buffering.max.kbytes": "262144"}})),
        base(json!({"producer_config": {"message.max.bytes": "4194304"}})),
        base(json!({
            "security_protocol": "ssl",
            "producer_config": {"ssl.cipher.suites": "DEFAULT"}
        })),
        base(json!({
            "security_protocol": "sasl_ssl",
            "sasl_username": " padded ",
            "sasl_password": " padded ",
            "producer_config": {"sasl.kerberos.service.name": "kafka"}
        })),
    ] {
        assert_component_validity(&spec, "KafkaLoggingConfig", &valid, true);
    }

    for invalid in [
        // Kafka topic syntax (#5213).
        base(json!({"topic": "."})),
        base(json!({"topic": ".."})),
        base(json!({"topic": "bad/name"})),
        base(json!({"topic": "bad name"})),
        base(json!({"topic": too_long_topic})),
        // Runtime integer bounds and the non-empty schema reference (#5217).
        base(json!({"message_timeout_ms": -1})),
        base(json!({"message_timeout_ms": 2147483648u64})),
        base(json!({"schema_ref": ""})),
        base(json!({"schema": {}, "schema_ref": "named"})),
        // Normalized enum spellings the constructor refuses (#5217).
        base(json!({"security_protocol": "PLAINTEXT"})),
        base(json!({"key_field": " none "})),
        base(json!({"acks": " 1 "})),
        base(json!({"compression": " gzip "})),
        // producer_config refusals, namespaces, and budgets (#5215, #5217).
        base(json!({"producer_config": {"security.protocol": "ssl"}})),
        base(json!({"producer_config": {"sasl.password": "secret"}})),
        base(json!({"producer_config": {"transactional.id": "audit"}})),
        base(json!({"producer_config": {"queue.buffering.max.messages": "100001"}})),
        base(json!({"producer_config": {"queue.buffering.max.messages": "0"}})),
        base(json!({"producer_config": {"queue.buffering.max.kbytes": "262145"}})),
        base(json!({"producer_config": {"message.max.bytes": "4194305"}})),
        base(json!({"producer_config": {"ssl.cipher.suites": "DEFAULT"}})),
        base(json!({"producer_config": {"sasl.kerberos.service.name": "kafka"}})),
    ] {
        assert_component_validity(&spec, "KafkaLoggingConfig", &invalid, false);
    }
}

#[test]
fn correlation_id_runtime_and_openapi_contracts_match() {
    use ferrum_edge::plugins::correlation_id::CorrelationId;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for valid in [
        json!({}),
        json!({"header_name": "x-request-id", "echo_downstream": false}),
        json!({"header_name": "X-Correlation-ID", "echo_downstream": true}),
        json!({"header_name": " X-Trimmed-ID "}),
        json!({"header_name": "\u{0085}x-audit\u{0085}"}),
        json!({"header_name": "a".repeat(65_535)}),
        json!({"header_name": null, "echo_downstream": null}),
    ] {
        assert_component_validity(&spec, "CorrelationIdConfig", &valid, true);
        CorrelationId::new(&valid)
            .unwrap_or_else(|error| panic!("schema-valid config {valid} failed runtime: {error}"));
    }

    for invalid in [
        serde_json::Value::Null,
        json!([]),
        json!("config"),
        json!(42),
        json!(true),
        json!({"echo_downsteam": false}),
        json!({"header_name": "x:request-id"}),
        json!({"header_name": "\u{feff}x-audit\u{feff}"}),
        json!({"header_name": "a".repeat(65_536)}),
        json!({"header_name": 42}),
        json!({"echo_downstream": "true"}),
        json!({"header_name": "API-Key"}),
        json!({"header_name": "Authentication-Info"}),
        json!({"header_name": "Authorization"}),
        json!({"header_name": "Connection"}),
        json!({"header_name": " Connection "}),
        json!({"header_name": "Content-Encoding"}),
        json!({"header_name": "Content-Length"}),
        json!({"header_name": "Cookie"}),
        json!({"header_name": " eARLY-dATA "}),
        json!({"header_name": " eXPECT "}),
        json!({"header_name": " fORWARDED "}),
        json!({"header_name": "Grpc-Message"}),
        json!({"header_name": "Grpc-Status"}),
        json!({"header_name": "Grpc-Status-Details-Bin"}),
        json!({"header_name": "Host"}),
        json!({"header_name": "Keep-Alive"}),
        json!({"header_name": "Proxy-Authenticate"}),
        json!({"header_name": "Proxy-Authentication-Info"}),
        json!({"header_name": "Proxy-Authorization"}),
        json!({"header_name": "Proxy-Connection"}),
        json!({"header_name": "X-Forwarded-Host"}),
        json!({"header_name": " x-FORWARDED-proto "}),
        json!({"header_name": "Sec-WebSocket-Accept"}),
        json!({"header_name": "Sec-WebSocket-Extensions"}),
        json!({"header_name": "Sec-WebSocket-Key"}),
        json!({"header_name": "Sec-WebSocket-Protocol"}),
        json!({"header_name": "Sec-WebSocket-Version"}),
        json!({"header_name": "Set-Cookie"}),
        json!({"header_name": "TE"}),
        json!({"header_name": "Traceparent"}),
        json!({"header_name": "Tracestate"}),
        json!({"header_name": "Trailer"}),
        json!({"header_name": "Transfer-Encoding"}),
        json!({"header_name": "Upgrade"}),
        json!({"header_name": "vIA"}),
        json!({"header_name": "WWW-Authenticate"}),
        json!({"header_name": "X-API-Key"}),
        json!({"header_name": "X-Auth-Token"}),
        json!({"header_name": "X-CSRF-Token"}),
        json!({"header_name": "X-Ferrum-Original-Content-Encoding"}),
        json!({"header_name": "X-Forwarded-Authorization"}),
        json!({"header_name": "X-Forwarded-For"}),
        json!({"header_name": "X-Goog-API-Key"}),
        json!({"header_name": "x-gRPC-wEB-mODE"}),
        json!({"header_name": "X-XSRF-Token"}),
    ] {
        assert_component_validity(&spec, "CorrelationIdConfig", &invalid, false);
        assert!(
            CorrelationId::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let header_name_schema = spec
        .pointer("/components/schemas/CorrelationIdConfig/properties/header_name")
        .expect("correlation header_name schema exists");
    for exclusion_pointer in ["/not", "/allOf/0/not"] {
        let exclusion = header_name_schema
            .pointer(exclusion_pointer)
            .unwrap_or_else(|| panic!("correlation exclusion {exclusion_pointer} exists"));
        let validator = jsonschema::draft202012::options()
            .build(exclusion)
            .unwrap_or_else(|error| panic!("correlation exclusion compiles: {error}"));
        for reserved in [
            json!(" Early-Data "),
            json!(" Traceparent "),
            json!("Tracestate"),
            json!("X-Ferrum-Original-Content-Encoding"),
            json!("x-gRPC-wEB-mODE"),
        ] {
            assert!(
                validator.validate(&reserved).is_ok(),
                "correlation exclusion {exclusion_pointer} missed {reserved}"
            );
        }
    }
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
    assert_eq!(schema["properties"]["flush_interval_ms"]["maximum"], 600000);
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
        "flush_interval_ms": 600000,
        "buffer_capacity": 1000000,
        "max_entry_bytes": LOKI_MAX_MAX_ENTRY_BYTES,
        "buffer_max_bytes": LOKI_MAX_BUFFER_MAX_BYTES,
        "max_retries": LOKI_MAX_RETRIES,
        "retry_delay_ms": LOKI_MAX_RETRY_DELAY_MS,
        "schema": {}
    });
    assert_component_validity(&spec, "LokiLoggingConfig", &valid, true);
    assert!(LokiLogging::new(&valid, PluginHttpClient::default()).is_ok());
    assert_component_validity(
        &spec,
        "PluginConfig",
        &json!({
            "plugin_name": "loki_logging",
            "scope": "global",
            "enabled": true,
            "config": valid
        }),
        true,
    );
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

    let url_whitespace = json!({
        "endpoint_url": " http://127.0.0.1:3100/push "
    });
    assert_component_validity(&spec, "LokiLoggingConfig", &url_whitespace, true);
    assert!(LokiLogging::new(&url_whitespace, PluginHttpClient::default()).is_ok());
    let unicode_header = json!({
        "endpoint_url": "http://127.0.0.1:3100/loki/api/v1/push",
        "custom_headers": {"X-Example": "café"}
    });
    assert_component_validity(&spec, "LokiLoggingConfig", &unicode_header, true);
    assert!(LokiLogging::new(&unicode_header, PluginHttpClient::default()).is_ok());

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
        json!({"endpoint_url": "https://logs.example.com/push", "flush_interval_ms": 600001}),
        json!({"endpoint_url": "https://logs.example.com/push", "buffer_capacity": 1000001}),
        json!({"endpoint_url": "https://logs.example.com/push", "max_retries": 11}),
        json!({"endpoint_url": "https://logs.example.com/push", "retry_delay_ms": 0}),
        json!({"endpoint_url": "https://logs.example.com/push", "max_entry_bytes": 1023}),
        json!({"endpoint_url": "https://logs.example.com/push", "buffer_max_bytes": 268435457}),
        json!({
            "endpoint_url": "http://127.0.0.1:3100/loki/api/v1/push",
            "schema": {},
            "schema_ref": "example"
        }),
        json!({
            "endpoint_url": "http://127.0.0.1:3100/loki/api/v1/push",
            "schema_ref": ""
        }),
        json!({"endpoint_url": "http://127.0.0.1:99999/push"}),
        json!({
            "endpoint_url": "http://127.0.0.1:3100/loki/api/v1/push",
            "buffer_max_bytes": 1024
        }),
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
        assert_component_validity(
            &spec,
            "PluginConfig",
            &json!({
                "plugin_name": "loki_logging",
                "scope": "global",
                "enabled": true,
                "config": config.clone()
            }),
            false,
        );
        assert!(
            LokiLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid Loki config: {config}"
        );
    }
}

#[tokio::test]
async fn ws_logging_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::ws_logging::{
        WS_DEFAULT_BUFFER_MAX_BYTES, WS_DEFAULT_MAX_ENTRY_BYTES, WS_LOGGING_CONFIG_KEYS,
        WS_MAX_BUFFER_MAX_BYTES, WS_MAX_MAX_ENTRY_BYTES, WsLogging,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/WsLoggingConfig")
        .expect("WsLoggingConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(schema["properties"]["endpoint_url"]["minLength"], 1);
    assert_eq!(schema["properties"]["schema_ref"]["minLength"], 1);
    assert_eq!(
        schema["allOf"][0]["not"]["required"],
        json!(["schema", "schema_ref"])
    );
    let budget_desc = schema["properties"]["buffer_max_bytes"]["description"]
        .as_str()
        .unwrap_or("");
    assert!(
        budget_desc.contains("2 * (max_entry_bytes + 1)") && budget_desc.contains("Runtime"),
        "buffer_max_bytes must document the sibling-field runtime bound: {budget_desc}"
    );

    let documented = schema["properties"]
        .as_object()
        .expect("WsLogging properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = WS_LOGGING_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "ws_logging runtime/OpenAPI key drift");
    assert_eq!(
        schema["properties"]["max_entry_bytes"]["default"],
        json!(WS_DEFAULT_MAX_ENTRY_BYTES)
    );
    assert_eq!(
        schema["properties"]["max_entry_bytes"]["maximum"],
        json!(WS_MAX_MAX_ENTRY_BYTES)
    );
    assert_eq!(
        schema["properties"]["buffer_max_bytes"]["default"],
        json!(WS_DEFAULT_BUFFER_MAX_BYTES)
    );
    assert_eq!(
        schema["properties"]["buffer_max_bytes"]["maximum"],
        json!(WS_MAX_BUFFER_MAX_BYTES)
    );

    let valid = json!({
        "endpoint_url": "WS://127.0.0.1:39999/ingest",
        "batch_size": 50,
        "flush_interval_ms": 1000,
        "buffer_capacity": 10000,
        "max_entry_bytes": WS_DEFAULT_MAX_ENTRY_BYTES,
        "buffer_max_bytes": WS_DEFAULT_BUFFER_MAX_BYTES,
        "schema": {}
    });
    assert_component_validity(&spec, "WsLoggingConfig", &valid, true);
    assert!(WsLogging::new(&valid, PluginHttpClient::default()).is_ok());
    let valid_minima = json!({"endpoint_url": "ws://127.0.0.1:39999/ingest"});
    assert_component_validity(&spec, "WsLoggingConfig", &valid_minima, true);
    assert!(WsLogging::new(&valid_minima, PluginHttpClient::default()).is_ok());

    let runtime_and_schema_invalid = [
        json!({"endpoint_url": "ws://127.0.0.1:39999/ingest", "unexpected": true}),
        json!({"endpoint_url": ""}),
        json!({"endpoint_url": "http://127.0.0.1:39999/ingest"}),
        json!({"endpoint_url": "ws://user:password@127.0.0.1:39999/ingest"}),
        json!({"endpoint_url": "ws:///ingest"}),
        json!({
            "endpoint_url": "ws://127.0.0.1:39999/ingest",
            "schema": {},
            "schema_ref": "example"
        }),
        json!({"endpoint_url": "ws://127.0.0.1:39999/ingest", "schema_ref": ""}),
        json!({"endpoint_url": "ws://127.0.0.1:39999/ingest", "batch_size": 0}),
        json!({"endpoint_url": "ws://127.0.0.1:39999/ingest", "flush_interval_ms": 99}),
    ];
    for config in runtime_and_schema_invalid {
        assert_component_validity(&spec, "WsLoggingConfig", &config, false);
        assert!(
            WsLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid ws_logging config: {config}"
        );
    }

    // Sibling-field arithmetic cannot be expressed in standard JSON Schema.
    let runtime_only = json!({
        "endpoint_url": "ws://127.0.0.1:39999/ingest",
        "max_entry_bytes": 65536,
        "buffer_max_bytes": 2050
    });
    assert_component_validity(&spec, "WsLoggingConfig", &runtime_only, true);
    assert!(
        WsLogging::new(&runtime_only, PluginHttpClient::default()).is_err(),
        "runtime must still reject a buffer below 2 * (max_entry_bytes + 1)"
    );
}

#[tokio::test]
async fn statsd_logging_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::statsd_logging::{STATSD_LOGGING_CONFIG_KEYS, StatsdLogging};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/StatsdLoggingConfig")
        .expect("StatsdLoggingConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["global_tags"]["additionalProperties"]["type"], "string",
        "global_tags must remain an intentionally open string map"
    );
    assert_eq!(
        schema["properties"]["global_tags"]["propertyNames"]["pattern"],
        "^(?!(namespace|method|status_class|status|grpc_status|proxy|protocol|error_class|error|cause|direction|body_outcome|body_error|result|io_side)$)[A-Za-z_][A-Za-z0-9_.-]*$",
        "global_tags keys must encode the runtime ASCII tag-key grammar and reserved-name exclusion"
    );
    assert_eq!(
        schema["properties"]["global_tags"]["propertyNames"]["maxLength"], 64,
        "global_tags key ceiling must match the runtime 64-byte ASCII limit"
    );
    let prefix_desc = schema["properties"]["prefix"]["description"]
        .as_str()
        .unwrap_or("");
    assert!(
        prefix_desc.contains("UTF-8 bytes") && prefix_desc.contains("sanitization"),
        "prefix description must document the runtime post-sanitization byte cap: {prefix_desc}"
    );

    let documented = schema["properties"]
        .as_object()
        .expect("Statsd properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = STATSD_LOGGING_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "StatsD runtime/OpenAPI key drift");

    let plugin_docs = include_str!("../../docs/plugins.md");
    let statsd_docs = plugin_docs
        .split("### `statsd_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("statsd_logging docs section");
    for key in STATSD_LOGGING_CONFIG_KEYS {
        assert!(
            statsd_docs.contains(&format!("`{key}`")),
            "docs/plugins.md statsd section missing `{key}`"
        );
    }
    assert!(statsd_docs.contains("OptionalFailOpen"));
    assert!(statsd_docs.contains("max_retries"));
    assert!(statsd_docs.contains("retry_delay_ms"));

    let valid = json!({
        "host": "statsd.example.test",
        "port": 9125,
        "prefix": "edge.prod",
        "global_tags": {"env": "prod", "region": "us-east-1"},
        "flush_interval_ms": 500,
        "buffer_capacity": 10000,
        "max_batch_lines": 50,
        "max_retries": 0,
        "retry_delay_ms": 0,
        "schema": {
            "summary_type": "both",
            "rename": {"proxy_id": "route_id"}
        }
    });
    assert_component_validity(&spec, "StatsdLoggingConfig", &valid, true);
    assert!(StatsdLogging::new(&valid, PluginHttpClient::default()).is_ok());
    assert_component_validity(
        &spec,
        "PluginConfig",
        &json!({
            "plugin_name": "statsd_logging",
            "scope": "global",
            "enabled": true,
            "config": valid
        }),
        true,
    );

    let valid_minima = json!({"host": "127.0.0.1"});
    assert_component_validity(&spec, "StatsdLoggingConfig", &valid_minima, true);
    assert!(StatsdLogging::new(&valid_minima, PluginHttpClient::default()).is_ok());

    let prefix_padded = json!({
        "host": "127.0.0.1",
        "prefix": format!(" {} ", "a".repeat(256))
    });
    assert_component_validity(&spec, "StatsdLoggingConfig", &prefix_padded, true);
    assert!(StatsdLogging::new(&prefix_padded, PluginHttpClient::default()).is_ok());

    let runtime_and_schema_invalid = [
        json!({"host": "statsd.example.test", "prot": 9125}),
        json!({"host": "statsd.example.test", "prefx": "edge.prod"}),
        json!({"host": "statsd.example.test", "global_tgas": {"env": "prod"}}),
        json!({"host": "statsd.example.test", "schema_reff": "redacted-summary"}),
        json!({"host": "statsd.example.test", "max_retrie": 5}),
        json!({"host": "statsd.example.test", "aaa_extra": 1, "zzz_extra": 2}),
        json!({}),
        json!({"host": "statsd.example.test", "port": 0}),
        json!({"host": "statsd.example.test", "port": 65536}),
        json!({"host": "statsd.example.test", "global_tags": {"env": true}}),
        json!({"host": "statsd.example.test", "global_tags": {"evil\nkey": "x"}}),
        json!({"host": "statsd.example.test", "global_tags": {" env ": "prod"}}),
        json!({"host": "statsd.example.test", "global_tags": {"1bad": "x"}}),
        json!({"host": "statsd.example.test", "global_tags": { ("k".repeat(65)): "x" }}),
        json!({"host": "statsd.example.test", "prefix": null}),
        json!({"host": "statsd.example.test", "global_tags": null}),
        json!({"host": "statsd.example.test", "schema": null}),
        json!({"host": null}),
        json!({"host": "statsd.example.test", "schema": {}, "schema_ref": "example"}),
        json!({"host": "statsd.example.test", "schema_ref": ""}),
        json!({"host": ""}),
        json!({"host": "127.0.0.1:8125"}),
        json!({"host": "statsd.example.test", "prefix": ""}),
        json!({"host": "127.0.0.1", "global_tags": {"method": "example"}}),
        json!({"host": "127.0.0.1", "buffer_max_bytes": 2050}),
    ];
    for config in runtime_and_schema_invalid {
        assert_component_validity(&spec, "StatsdLoggingConfig", &config, false);
        assert_component_validity(
            &spec,
            "PluginConfig",
            &json!({
                "plugin_name": "statsd_logging",
                "scope": "global",
                "enabled": true,
                "config": config.clone()
            }),
            false,
        );
        assert!(
            StatsdLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid StatsD config: {config}"
        );
    }

    // OpenAPI rejects typed nulls on every declared property. Shared batch
    // admission (#2562) now rejects null/wrong-type/out-of-range batching
    // fields at construction as well.
    for key in STATSD_LOGGING_CONFIG_KEYS {
        let mut config = json!({"host": "statsd.example.test"});
        config
            .as_object_mut()
            .expect("config object")
            .insert((*key).to_string(), serde_json::Value::Null);
        assert_component_validity(&spec, "StatsdLoggingConfig", &config, false);
        assert!(
            StatsdLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime must reject explicit null for `{key}`"
        );
    }

    assert_eq!(schema["properties"]["max_batch_lines"]["minimum"], 1);
    assert_eq!(schema["properties"]["max_batch_lines"]["maximum"], 10000);
    assert_eq!(schema["properties"]["buffer_capacity"]["minimum"], 1);
    assert_eq!(schema["properties"]["buffer_capacity"]["maximum"], 1000000);
    assert_eq!(schema["properties"]["flush_interval_ms"]["maximum"], 600000);
    assert_eq!(schema["properties"]["max_retries"]["maximum"], 10);
    assert_eq!(schema["properties"]["retry_delay_ms"]["maximum"], 60000);

    for config in [
        json!({"host": "statsd.example.test", "max_batch_lines": 0}),
        json!({"host": "statsd.example.test", "max_batch_lines": 10001}),
        json!({"host": "statsd.example.test", "buffer_capacity": 0}),
        json!({"host": "statsd.example.test", "flush_interval_ms": 49}),
        json!({"host": "statsd.example.test", "flush_interval_ms": 600001}),
        json!({"host": "statsd.example.test", "max_retries": 11}),
        json!({"host": "statsd.example.test", "retry_delay_ms": 60001}),
        json!({"host": "statsd.example.test", "flush_interval_ms": "60000"}),
        json!({"host": "statsd.example.test", "buffer_capacity": false}),
        json!({"host": "statsd.example.test", "max_batch_lines": []}),
    ] {
        assert_component_validity(&spec, "StatsdLoggingConfig", &config, false);
        assert!(
            StatsdLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted invalid StatsD batching config: {config}"
        );
    }
}

#[tokio::test]
async fn tcp_logging_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::tcp_logging::{TCP_LOGGING_CONFIG_KEYS, TcpLogging};

    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/TcpLoggingConfig")
        .expect("TcpLoggingConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(schema["properties"]["connect_timeout_ms"]["minimum"], 100);
    assert_eq!(schema["properties"]["connect_timeout_ms"]["maximum"], 60000);
    assert_eq!(schema["properties"]["write_timeout_ms"]["minimum"], 100);
    assert_eq!(schema["properties"]["write_timeout_ms"]["maximum"], 60000);
    assert_eq!(schema["properties"]["write_timeout_ms"]["default"], 5000);
    assert_eq!(
        schema["properties"]["tls_server_name"]["pattern"],
        r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?\.?|[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)$",
    );
    let connect_desc = schema["properties"]["connect_timeout_ms"]["description"]
        .as_str()
        .expect("connect_timeout_ms description");
    assert!(
        connect_desc.to_ascii_lowercase().contains("tls"),
        "connect_timeout_ms must document TLS handshake coverage"
    );

    let documented = schema["properties"]
        .as_object()
        .expect("TcpLogging properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = TCP_LOGGING_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "tcp_logging runtime/OpenAPI key drift");

    let plugin_docs = include_str!("../../docs/plugins.md");
    let tcp_docs = plugin_docs
        .split("### `tcp_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("tcp_logging docs section");
    for key in TCP_LOGGING_CONFIG_KEYS {
        assert!(
            tcp_docs.contains(&format!("`{key}`")),
            "docs/plugins.md tcp_logging section missing `{key}`"
        );
    }
    assert!(tcp_docs.contains("KeepLastKnownGood"));
    assert!(tcp_docs.contains("at-least-once"));
    assert!(
        tcp_docs.contains("268435456") || tcp_docs.contains("256 MiB"),
        "tcp_logging docs must name the 256 MiB buffer_max_bytes ceiling"
    );
    assert!(
        tcp_docs.contains("ssl_enabled"),
        "Logstash TLS instructions must use ssl_enabled"
    );
    assert!(
        !tcp_docs.contains("ssl_enable =>"),
        "removed Logstash ssl_enable option must not remain in tcp_logging docs"
    );

    let valid = json!({
        "host": "logs.example.com",
        "port": 6514,
        "tls": true,
        "tls_server_name": "logs.example.com",
        "batch_size": 50,
        "flush_interval_ms": 1000,
        "max_retries": 3,
        "retry_delay_ms": 1000,
        "buffer_capacity": 10000,
        "connect_timeout_ms": 5000,
        "write_timeout_ms": 5000
    });
    assert_component_validity(&spec, "TcpLoggingConfig", &valid, true);
    assert!(TcpLogging::new(&valid, PluginHttpClient::default()).is_ok());

    let valid_ipv6_identity = json!({
        "host": "logs.example.com",
        "port": 6514,
        "tls": true,
        "tls_server_name": "2001:db8::1"
    });
    assert_component_validity(&spec, "TcpLoggingConfig", &valid_ipv6_identity, true);
    assert!(TcpLogging::new(&valid_ipv6_identity, PluginHttpClient::default()).is_ok());

    let valid_minima = json!({"host": "127.0.0.1", "port": 5140});
    assert_component_validity(&spec, "TcpLoggingConfig", &valid_minima, true);
    assert!(TcpLogging::new(&valid_minima, PluginHttpClient::default()).is_ok());

    let padded_host = json!({"host": " 127.0.0.1 ", "port": 5140});
    assert_component_validity(&spec, "TcpLoggingConfig", &padded_host, true);
    assert!(
        TcpLogging::new(&padded_host, PluginHttpClient::default()).is_ok(),
        "runtime trims surrounding host whitespace"
    );

    for tls_server_name in ["localhost.", "log_sink.local"] {
        let config = json!({
            "host": "127.0.0.1",
            "port": 6514,
            "tls": true,
            "tls_server_name": tls_server_name
        });
        assert_component_validity(&spec, "TcpLoggingConfig", &config, true);
        assert!(
            TcpLogging::new(&config, PluginHttpClient::default()).is_ok(),
            "rustls-accepted TLS identity {tls_server_name} must admit"
        );
    }

    let runtime_and_schema_invalid = [
        json!({"host": "logs.example.com", "port": 6514, "tlls": true}),
        json!({"host": "logs.example.com", "port": 6514, "write_timeot_ms": 1000}),
        json!({"host": "logs.example.com", "port": 6514, "aaa_extra": 1, "zzz_extra": 2}),
        json!({"host": "logs.example.com"}),
        json!({"port": 6514}),
        json!({"host": "logs.example.com", "port": 0}),
        json!({"host": "logs.example.com", "port": 65536}),
        json!({"host": "logs.example.com", "port": 6514, "tls": null}),
        json!({"host": "logs.example.com", "port": 6514, "write_timeout_ms": 50}),
        json!({"host": "logs.example.com", "port": 6514, "connect_timeout_ms": 50}),
        json!({"host": "logs.example.com", "port": 6514, "write_timeout_ms": 60001}),
        json!({"host": "logs.example.com", "port": 6514, "connect_timeout_ms": 60001}),
        json!({
            "host": "logs.example.com",
            "port": 6514,
            "tls_server_name": "logs.example.com"
        }),
        json!({
            "host": "logs.example.com",
            "port": 6514,
            "tls": false,
            "tls_server_name": "logs.example.com"
        }),
        json!({"host": "logs.example.com", "port": 6514, "tls": true, "tls_server_name": " logs.example.com"}),
        json!({"host": "logs.example.com", "port": 6514, "tls": true, "tls_server_name": "logs.example.com "}),
        json!({"host": "http://localhost", "port": 5140}),
        json!({"host": "localhost:9000", "port": 5140}),
        json!({
            "host": "127.0.0.1",
            "port": 45123,
            "schema": {"static_fields": {"audit": "ok"}},
            "schema_ref": "audit"
        }),
        json!({"host": "127.0.0.1", "port": 45123, "buffer_max_bytes": 2050}),
        json!({"host": "[localhost]", "port": 5140}),
    ];
    for config in runtime_and_schema_invalid {
        assert_component_validity(&spec, "TcpLoggingConfig", &config, false);
        assert!(
            TcpLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid tcp_logging config: {config}"
        );
    }

    for tls_server_name in [
        "https://logs.example.com",
        "logs.example.com/path",
        "logs.example.com?token=secret",
        "logs.example.com#fragment",
        "user@logs.example.com",
        "logs.example.com:6514",
    ] {
        let config = json!({
            "host": "logs.example.com",
            "port": 6514,
            "tls": true,
            "tls_server_name": tls_server_name
        });
        assert_component_validity(&spec, "TcpLoggingConfig", &config, false);
        assert!(
            TcpLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid TLS server name: {tls_server_name}"
        );
    }

    // OpenAPI rejects typed nulls on every declared property. Unknown-key
    // closure is the TCP portion of GHSA-7fgr-gqg5-xj6c under test here.
    for key in TCP_LOGGING_CONFIG_KEYS {
        let mut config = json!({"host": "logs.example.com", "port": 6514});
        config
            .as_object_mut()
            .expect("config object")
            .insert((*key).to_string(), serde_json::Value::Null);
        assert_component_validity(&spec, "TcpLoggingConfig", &config, false);
    }
}

#[test]
fn udp_logging_schema_matches_runtime_admission() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::udp_logging::{UDP_LOGGING_CONFIG_KEYS, UdpLogging};
    use ferrum_edge::plugins::validate_plugin_config;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/UdpLoggingConfig")
        .expect("UdpLoggingConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let documented = schema["properties"]
        .as_object()
        .expect("UdpLogging properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = UDP_LOGGING_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "udp_logging runtime/OpenAPI key drift");

    let plugin_docs = include_str!("../../docs/plugins.md");
    let udp_docs = plugin_docs
        .split("### `udp_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("udp_logging docs section");
    for key in UDP_LOGGING_CONFIG_KEYS {
        assert!(
            udp_docs.contains(&format!("`{key}`")),
            "docs/plugins.md udp_logging section missing `{key}`"
        );
    }
    assert!(
        udp_docs.contains("268435456") || udp_docs.contains("256 MiB"),
        "udp_logging docs must name the 256 MiB buffer_max_bytes ceiling"
    );

    let valid = json!({"host": "127.0.0.1", "port": 45123});
    assert_component_validity(&spec, "UdpLoggingConfig", &valid, true);
    assert!(UdpLogging::new(&valid, PluginHttpClient::default()).is_ok());
    validate_plugin_config("udp_logging", &valid).expect("shared validation accepts minima");

    let padded_host = json!({"host": " 127.0.0.1 ", "port": 45123});
    assert_component_validity(&spec, "UdpLoggingConfig", &padded_host, true);
    validate_plugin_config("udp_logging", &padded_host)
        .expect("shared validation trims host whitespace");
    assert!(
        UdpLogging::new(&padded_host, PluginHttpClient::default()).is_ok(),
        "constructor trims host whitespace"
    );

    let runtime_and_schema_invalid = [
        json!({"host": "http://localhost", "port": 45123}),
        json!({"host": "localhost:9000", "port": 45123}),
        json!({"host": "[localhost]", "port": 45123}),
        json!({
            "host": "127.0.0.1",
            "port": 45123,
            "schema": {"static_fields": {"audit": "ok"}},
            "schema_ref": "audit"
        }),
        json!({
            "host": "127.0.0.1",
            "port": 45123,
            "dtls": true,
            "dtls_ca_cert_path": " "
        }),
        json!({"host": "127.0.0.1", "port": 45123, "buffer_max_bytes": 2050}),
        json!({"host": "127.0.0.1", "port": 45123, "max_entry_bytes": 0}),
        json!({"host": "127.0.0.1", "port": 45123, "max_entry_bytes": null}),
        json!({"host": "127.0.0.1", "port": 45123, "max_entry_bytes": "65536"}),
        json!({"host": "127.0.0.1", "port": 45123, "buffer_max_bytes": 268435457}),
    ];
    for config in runtime_and_schema_invalid {
        assert_component_validity(&spec, "UdpLoggingConfig", &config, false);
        assert!(
            UdpLogging::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid udp_logging config: {config}"
        );
        assert!(
            validate_plugin_config("udp_logging", &config).is_err(),
            "shared validation accepted OpenAPI-invalid udp_logging config: {config}"
        );
    }

    let valid_explicit_min_pair = json!({
        "host": "127.0.0.1",
        "port": 45123,
        "max_entry_bytes": 1024,
        "buffer_max_bytes": 2050
    });
    assert_component_validity(&spec, "UdpLoggingConfig", &valid_explicit_min_pair, true);
    validate_plugin_config("udp_logging", &valid_explicit_min_pair)
        .expect("explicit minimum byte pair must validate");
    assert!(
        UdpLogging::new(&valid_explicit_min_pair, PluginHttpClient::default()).is_ok(),
        "explicit minimum byte pair must construct"
    );

    let valid_max_pair = json!({
        "host": "127.0.0.1",
        "port": 45123,
        "max_entry_bytes": 1048576,
        "buffer_max_bytes": 268435456
    });
    assert_component_validity(&spec, "UdpLoggingConfig", &valid_max_pair, true);
    validate_plugin_config("udp_logging", &valid_max_pair)
        .expect("maximum byte pair must validate");
}

#[test]
fn request_mirror_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::request_mirror::{REQUEST_MIRROR_CONFIG_KEYS, RequestMirror};
    use ferrum_edge::plugins::{PluginHttpClient, validate_plugin_config};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/RequestMirrorConfig")
        .expect("RequestMirrorConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let documented = schema["properties"]
        .as_object()
        .expect("RequestMirrorConfig properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = REQUEST_MIRROR_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        documented, runtime,
        "request_mirror runtime/OpenAPI key drift"
    );

    let plugin_docs = include_str!("../../docs/plugins.md");
    let mirror_docs = plugin_docs
        .split("### `request_mirror`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("request_mirror docs section");
    for key in REQUEST_MIRROR_CONFIG_KEYS {
        assert!(
            mirror_docs.contains(&format!("`{key}`")),
            "docs/plugins.md request_mirror section missing `{key}`"
        );
    }
    assert!(mirror_docs.contains("KeepLastKnownGood"));
    assert!(mirror_docs.contains("allowed-key"));

    let valid = json!({
        "mirror_host": "mirror.local",
        "mirror_protocol": "https",
        "percentage": 0,
        "mirror_request_body": false
    });
    assert_component_validity(&spec, "RequestMirrorConfig", &valid, true);
    assert!(
        RequestMirror::new(&valid, PluginHttpClient::default()).is_ok(),
        "valid request_mirror config must construct"
    );
    assert!(validate_plugin_config("request_mirror", &valid).is_ok());

    let typo = json!({
        "mirror_host": "mirror.local",
        "mirror_protcol": "https",
        "percentage": 0,
        "mirror_request_body": false
    });
    assert_component_validity(&spec, "RequestMirrorConfig", &typo, false);
    let err = match RequestMirror::new(&typo, PluginHttpClient::default()) {
        Ok(_) => panic!("misspelled protocol key must fail admission"),
        Err(err) => err,
    };
    assert!(err.contains("mirror_protcol"), "got: {err}");
    assert!(err.contains("allowed keys"), "got: {err}");
    validate_plugin_config("request_mirror", &typo).expect_err("shared admission must reject typo");

    // Issue #5152: the component schema is compared against ACTUAL constructor
    // admission, not just against the key inventory. Every case below must be
    // accepted (or rejected) by both, so a schema-backed editor cannot reject a
    // valid nullable/defaulted config or approve a malformed host, an
    // incomplete credential-forwarding opt-in, or an invalid policy list.
    let shared_client = PluginHttpClient::default();
    let mut accepted: Vec<serde_json::Value> = vec![
        // Minimal, plus both documented examples.
        json!({"mirror_host": "127.0.0.1"}),
        json!({
            "mirror_host": "shadow.internal",
            "mirror_port": 8443,
            "mirror_protocol": "https",
            "percentage": 50.0,
            "mirror_request_body": true,
            "max_in_flight": 64,
            "max_retained_request_body_bytes": 33554432,
            "max_mirrored_request_body_bytes": 4194304
        }),
        json!({
            "mirror_host": "mirror.example.com",
            "mirror_port": 8080,
            "mirror_protocol": "https",
            "mirror_path": "/shadow",
            "percentage": 100.0,
            "mirror_request_body": true,
            "max_response_body_bytes": 1048576
        }),
        // The runtime lowercases the protocol, so uppercase is the same setting.
        json!({"mirror_host": "127.0.0.1", "mirror_protocol": "HTTPS"}),
        json!({"mirror_host": "[2001:db8::10]"}),
        // Paired, fail-closed credential-forwarding opt-ins.
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": ["authorization"]
        }),
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_query": true,
            "forward_sensitive_query_allowlist": ["access_token"]
        }),
        json!({"mirror_host": "127.0.0.1", "sensitive_header_patterns": ["x-vault-"]}),
        json!({"mirror_host": "127.0.0.1", "percentage": 0}),
        json!({"mirror_host": "127.0.0.1", "mirror_path": ""}),
    ];
    // Every optional scalar and list accepts an explicit JSON null (the runtime
    // treats null as omitted), so the schema must not reject it by type.
    for key in REQUEST_MIRROR_CONFIG_KEYS
        .iter()
        .filter(|key| **key != "mirror_host")
    {
        let mut config = json!({"mirror_host": "127.0.0.1"});
        config
            .as_object_mut()
            .expect("config object")
            .insert((*key).to_string(), serde_json::Value::Null);
        accepted.push(config);
    }

    let rejected: Vec<serde_json::Value> = vec![
        json!({"mirror_host": "127.0.0.1", "mirror_protocol": "ftp"}),
        // Host admission: a bare host only.
        json!({"mirror_host": ""}),
        json!({"mirror_host": " "}),
        json!({"mirror_host": "https://example.test"}),
        json!({"mirror_host": "example.test:80"}),
        json!({"mirror_host": null}),
        // Half an opt-in is a configuration error, never a partial grant.
        json!({"mirror_host": "127.0.0.1", "forward_sensitive_headers": true}),
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": []
        }),
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_header_allowlist": ["authorization"]
        }),
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": ["auth token"]
        }),
        json!({"mirror_host": "127.0.0.1", "forward_sensitive_query": true}),
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_query_allowlist": ["access_token"]
        }),
        // Operator pattern lists reject blank entries.
        json!({"mirror_host": "127.0.0.1", "sensitive_header_patterns": [" "]}),
        json!({"mirror_host": "127.0.0.1", "sensitive_query_patterns": [""]}),
        // Numeric bounds.
        json!({"mirror_host": "127.0.0.1", "max_in_flight": 0}),
        json!({"mirror_host": "127.0.0.1", "max_response_body_bytes": 0}),
        json!({"mirror_host": "127.0.0.1", "mirror_timeout_ms": 0}),
        json!({"mirror_host": "127.0.0.1", "mirror_timeout_ms": 300001}),
        json!({"mirror_host": "127.0.0.1", "mirror_path": "/a?b"}),
    ];

    for config in &accepted {
        assert_component_validity(&spec, "RequestMirrorConfig", config, true);
        assert!(
            RequestMirror::new(config, shared_client.clone()).is_ok(),
            "runtime must accept the schema-valid config {config}"
        );
    }
    for config in &rejected {
        assert_component_validity(&spec, "RequestMirrorConfig", config, false);
        assert!(
            RequestMirror::new(config, shared_client.clone()).is_err(),
            "runtime must reject the schema-invalid config {config}"
        );
    }

    // Documented, deliberate schema limitations: these runtime rules compare
    // sibling values or inspect a JSON number's lexical form, which Draft
    // 2020-12 cannot express. The component description names each one.
    for runtime_only_rejection in [
        // The allowlist entry is a valid header name but is not a header the
        // deny-by-default policy strips.
        json!({
            "mirror_host": "127.0.0.1",
            "forward_sensitive_headers": true,
            "forward_sensitive_header_allowlist": ["x-page"]
        }),
        // An explicit per-body ceiling above the (defaulted) aggregate budget.
        json!({
            "mirror_host": "127.0.0.1",
            "max_mirrored_request_body_bytes": 67108865
        }),
        // A whole-valued float is not an integer literal.
        json!({"mirror_host": "127.0.0.1", "max_response_body_bytes": 1.0}),
    ] {
        assert!(
            RequestMirror::new(&runtime_only_rejection, shared_client.clone()).is_err(),
            "runtime must still reject {runtime_only_rejection}"
        );
    }
}

#[tokio::test]
async fn load_testing_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::load_testing::{
        LOAD_TESTING_CONFIG_KEYS, LoadTesting, MAX_GATEWAY_ADDRESSES, MIN_TRIGGER_KEY_LEN,
    };

    let env = crate::unit::env_lock::EnvGuard::new(&["FERRUM_PROXY_HTTP_PORT"]);
    env.unset("FERRUM_PROXY_HTTP_PORT");

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/LoadTestingConfig")
        .expect("LoadTestingConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let documented = schema["properties"]
        .as_object()
        .expect("LoadTesting properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = LOAD_TESTING_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        documented, runtime,
        "load_testing runtime/OpenAPI key drift"
    );

    let plugin_docs = include_str!("../../docs/plugins.md");
    let load_testing_docs = plugin_docs
        .split("### `load_testing`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("load_testing docs section");
    for key in LOAD_TESTING_CONFIG_KEYS {
        assert!(
            load_testing_docs.contains(&format!("`{key}`")),
            "docs/plugins.md load_testing section missing `{key}`"
        );
    }
    assert!(load_testing_docs.contains("KeepLastKnownGood"));
    assert!(load_testing_docs.contains("Unknown top-level keys"));
    assert_eq!(
        schema["properties"]["gateway_addresses"]["maxItems"],
        json!(MAX_GATEWAY_ADDRESSES),
        "OpenAPI maxItems must match runtime MAX_GATEWAY_ADDRESSES"
    );
    assert_eq!(
        schema["properties"]["gateway_addresses"]["minItems"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["gateway_addresses"]["uniqueItems"],
        json!(true)
    );
    assert_eq!(
        schema["properties"]["gateway_addresses"]["items"]["minLength"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["key"]["minLength"],
        json!(MIN_TRIGGER_KEY_LEN),
        "OpenAPI minLength must match runtime MIN_TRIGGER_KEY_LEN"
    );
    assert_eq!(
        schema["properties"]["key"]["pattern"],
        json!("^[!-~][ -~]*[!-~]$"),
        "OpenAPI pattern must match runtime printable-ASCII header-value admission"
    );

    let valid = json!({
        "key": "test-load-key-0123456789abcdef!!",
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "ramp": true,
        "request_timeout_ms": 5000,
        "max_response_body_bytes": 2048,
        "gateway_port": 8443,
        "gateway_tls": true,
        "gateway_tls_no_verify": true,
        "gateway_addresses": ["https://10.0.0.2:8443"]
    });
    assert_component_validity(&spec, "LoadTestingConfig", &valid, true);
    assert!(LoadTesting::new(&valid, PluginHttpClient::default()).is_ok());

    let valid_internal_space = json!({
        "key": "test load key 0123456789abcdef!!",
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000
    });
    assert_component_validity(&spec, "LoadTestingConfig", &valid_internal_space, true);
    assert!(LoadTesting::new(&valid_internal_space, PluginHttpClient::default()).is_ok());

    let valid_minima = json!({
        "key": "test-load-key-0123456789abcdef!!",
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    assert_component_validity(&spec, "LoadTestingConfig", &valid_minima, true);
    assert!(LoadTesting::new(&valid_minima, PluginHttpClient::default()).is_ok());

    let valid_null_defaults = json!({
        "key": "null-defaults-key-0123456789abcdef!",
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "ramp": null,
        "request_timeout_ms": null,
        "max_response_body_bytes": null,
        "gateway_port": null,
        "gateway_tls": null,
        "gateway_tls_no_verify": null,
        "gateway_addresses": null
    });
    assert_component_validity(&spec, "LoadTestingConfig", &valid_null_defaults, true);
    assert!(LoadTesting::new(&valid_null_defaults, PluginHttpClient::default()).is_ok());

    let runtime_and_schema_invalid = [
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "request_timeot_ms": 5000
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "rmap": true,
            "gateway_adresses": ["https://10.0.0.2:8443"]
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "aaa_extra": 1,
            "zzz_extra": 2
        }),
        json!({}),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 0,
            "duration_seconds": 1
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 0
        }),
        json!({
            "key": "short-key",
            "concurrent_clients": 1,
            "duration_seconds": 1
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "request_timeout_ms": 60001
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 0
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_addresses": (0..33)
                .map(|i| format!("https://10.0.0.{}:8443", i + 2))
                .collect::<Vec<_>>()
        }),
        json!({
            "key": "😀".repeat(32),
            "concurrent_clients": 1,
            "duration_seconds": 1
        }),
        json!({
            "key": " test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!! ",
            "concurrent_clients": 1,
            "duration_seconds": 1
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_addresses": []
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_addresses": [""]
        }),
        json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_addresses": [
                "https://10.0.0.2:8443",
                "https://10.0.0.2:8443"
            ]
        }),
    ];
    for config in runtime_and_schema_invalid {
        assert_component_validity(&spec, "LoadTestingConfig", &config, false);
        assert!(
            LoadTesting::new(&config, PluginHttpClient::default()).is_err(),
            "runtime accepted OpenAPI-invalid load_testing config: {config}"
        );
    }

    let empty_key = json!({
        "key": "",
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    assert_component_validity(&spec, "LoadTestingConfig", &empty_key, false);
    assert!(
        LoadTesting::new(&empty_key, PluginHttpClient::default()).is_err(),
        "runtime must still reject empty key"
    );
}

#[tokio::test]
async fn compression_schema_matches_strict_runtime_config_contract() {
    use ferrum_edge::plugins::compression::{COMPRESSION_CONFIG_KEYS, CompressionPlugin};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/CompressionConfig")
        .expect("CompressionConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let documented = schema["properties"]
        .as_object()
        .expect("Compression properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = COMPRESSION_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "compression runtime/OpenAPI key drift");

    let plugin_docs = include_str!("../../docs/plugins.md");
    let compression_docs = plugin_docs
        .split("### `compression`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("compression docs section");
    for key in COMPRESSION_CONFIG_KEYS {
        assert!(
            compression_docs.contains(&format!("`{key}`")),
            "docs/plugins.md compression section missing `{key}`"
        );
    }
    assert!(compression_docs.contains("Strict config validation"));
    assert!(compression_docs.contains("KeepLastKnownGood"));
    assert!(compression_docs.contains("disable_on_etag"));
    assert!(
        compression_docs.contains("**Multiple instances:**"),
        "compression docs must describe multi-instance first-wins ownership"
    );
    let description = schema["description"].as_str().unwrap_or("");
    assert!(
        description.contains("Multiple effective instances compose with first-wins ownership"),
        "CompressionConfig OpenAPI description must document multi-instance ownership"
    );

    let valid = json!({
        "algorithms": ["gzip", "br"],
        "brotli_quality": 4,
        "content_types": ["application/json"],
        "decompress_request": false,
        "gzip_level": 6,
        "max_decompressed_request_size": 10_485_760,
        "min_content_length": 256,
        "remove_accept_encoding": true
    });
    assert_component_validity(&spec, "CompressionConfig", &valid, true);
    assert!(CompressionPlugin::new(&valid).is_ok());
    assert!(CompressionPlugin::new(&json!({})).is_ok());
    assert_component_validity(&spec, "CompressionConfig", &json!({}), true);
    let zero_gzip_level = json!({"gzip_level": 0});
    assert_component_validity(&spec, "CompressionConfig", &zero_gzip_level, true);
    assert!(CompressionPlugin::new(&zero_gzip_level).is_ok());

    // Boundary values: 0, 1, and 9 are accepted by both schema and runtime;
    // 10 is the first rejected value (just above the maximum of 9).
    for level in [1u64, 9] {
        let config = json!({"gzip_level": level});
        assert_component_validity(&spec, "CompressionConfig", &config, true);
        assert!(
            CompressionPlugin::new(&config).is_ok(),
            "runtime must accept gzip_level {level}"
        );
    }
    let rejected = json!({"gzip_level": 10});
    assert_component_validity(&spec, "CompressionConfig", &rejected, false);
    assert!(
        CompressionPlugin::new(&rejected).is_err(),
        "runtime must reject gzip_level 10"
    );

    for config in [
        json!({"min_content_lenght": 4096}),
        json!({"gzip_leveel": 1}),
        json!({"remove_accept_encodng": false}),
        json!({"aaa_extra": 1, "zzz_extra": 2}),
        json!({"disable_on_etag": false}),
    ] {
        assert_component_validity(&spec, "CompressionConfig", &config, false);
        assert!(
            CompressionPlugin::new(&config).is_err(),
            "runtime accepted OpenAPI-invalid compression config: {config}"
        );
    }

    // Constructor admission is the source of truth; the schema previously
    // ACCEPTED each of these while `validate` exited 1 (issue #5095), and
    // accepted content-type rules the matcher can never equal (issue #5096).
    for config in [
        json!({"algorithms": []}),
        json!({"content_types": []}),
        json!({"content_types": [""]}),
        json!({"content_types": ["\u{e9}"]}),
        json!({"content_types": [" "]}),
        json!({"content_types": ["application/json; charset=utf-8"]}),
        json!({"content_types": ["application/json "]}),
        json!({"content_types": null}),
        json!({"min_content_length": -1}),
        json!({"max_decompressed_request_size": 0}),
        json!({"max_decompressed_request_size": 33_554_433}),
        json!({"brotli_quality": 12}),
    ] {
        assert_component_validity(&spec, "CompressionConfig", &config, false);
        assert!(
            CompressionPlugin::new(&config).is_err(),
            "runtime accepted a config the schema now rejects: {config}"
        );
    }

    // A `min_content_length` past `u64::MAX` is runtime-rejected (it is not an
    // unsigned integer any more). The schema's `maximum` cannot bind it: the
    // value only survives JSON parsing as an `f64`, and `u64::MAX` rounds to the
    // same `f64`, so this stays a runtime-only assertion rather than a parity
    // case that would silently depend on float behaviour.
    let past_u64: serde_json::Value =
        serde_json::from_str(r#"{"min_content_length": 18446744073709551616}"#)
            .expect("oversized literal parses");
    assert!(
        CompressionPlugin::new(&past_u64).is_err(),
        "runtime must reject a min_content_length past u64::MAX"
    );

    // Explicit null is "omitted" for every optional field the constructor reads
    // through its `optional_*` helpers. `content_types` is deliberately NOT one
    // of them, and is covered above.
    for field in [
        "algorithms",
        "min_content_length",
        "max_decompressed_request_size",
        "gzip_level",
        "brotli_quality",
        "remove_accept_encoding",
        "decompress_request",
    ] {
        let mut object = serde_json::Map::new();
        object.insert(field.to_string(), serde_json::Value::Null);
        let config = serde_json::Value::Object(object);
        assert_component_validity(&spec, "CompressionConfig", &config, true);
        assert!(
            CompressionPlugin::new(&config).is_ok(),
            "runtime must treat an explicit null {field} as omitted"
        );
    }

    // Values both surfaces must keep accepting, so the tightened bounds did not
    // over-constrain the documented shapes.
    for config in [
        json!({"content_types": ["application/vnd.api+json", "text/csv"]}),
        json!({"min_content_length": 0}),
        json!({"max_decompressed_request_size": 1}),
        json!({"max_decompressed_request_size": 33_554_432}),
        json!({"brotli_quality": 11}),
    ] {
        assert_component_validity(&spec, "CompressionConfig", &config, true);
        assert!(
            CompressionPlugin::new(&config).is_ok(),
            "runtime rejected a schema-valid compression config: {config}"
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
        json!({"allow": ["0.0.0.0/0", "255.255.255.255/32"]}),
        json!({"allow": ["::/0", "2001:db8::1/128"]}),
        json!({"allow": ["::ffff:127.0.0.1/96", "::ffff:127.0.0.1/128"]}),
        json!({"allow": [" [::1] ", " fe80::1%eth0/64 "]}),
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
        json!({"allow": ["not-an-ip"]}),
        json!({"allow": ["300.1.1.1"]}),
        json!({"allow": ["127.0.0.1/33"]}),
        json!({"allow": ["::/129"]}),
        json!({"allow": ["::ffff:127.0.0.1/95"]}),
        json!({"allow": ["010.1.2.3"]}),
        json!({"allow": ["+10.1.2.3"]}),
    ] {
        assert_component_validity(&spec, "IpRestrictionConfig", &config, false);
        assert!(
            IpRestriction::new(&config).is_err(),
            "runtime accepted schema-invalid strict config: {config}"
        );
    }
}

#[test]
fn grpc_web_schema_matches_the_strict_runtime_shape() {
    use ferrum_edge::plugins::grpc_web::{GRPC_WEB_CONFIG_KEYS, GrpcWebPlugin};
    use std::collections::BTreeSet;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let component = &spec["components"]["schemas"]["GrpcWebConfig"];
    assert_eq!(component["additionalProperties"], false);
    assert_eq!(component["type"], "object");
    assert!(
        component.get("nullable").is_none(),
        "GrpcWebConfig must not mark null as accepted"
    );
    let description = component["description"]
        .as_str()
        .expect("GrpcWebConfig has a description");
    assert!(description.contains("not null"));
    assert!(description.contains("Unknown keys are rejected"));

    let documented = component["properties"]
        .as_object()
        .expect("GrpcWebConfig properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime = GRPC_WEB_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented, runtime, "grpc_web runtime/OpenAPI key drift");

    for config in [
        json!({}),
        json!({"expose_headers": ["x-request-id"]}),
        json!({"expose_headers": []}),
        // Field-level parity (issue #5134): the constructor treats an explicit
        // null as the empty list and trims ASCII OWS off each item, and the
        // schema has to say the same thing.
        json!({"expose_headers": null}),
        json!({"expose_headers": [" X-Ok "]}),
        json!({"expose_headers": ["custom-header-bin", "x-request-id"]}),
        // Names differing only in case are accepted and collapse to one entry.
        json!({"expose_headers": ["X-Request-Id", "x-request-id"]}),
    ] {
        assert_component_validity(&spec, "GrpcWebConfig", &config, true);
        assert!(
            GrpcWebPlugin::new(&config).is_ok(),
            "runtime rejected schema-valid grpc_web config: {config}"
        );
    }

    for config in [
        json!(null),
        json!([]),
        json!("expose_headers"),
        json!(1),
        json!(true),
        json!({"expose_header": ["x-request-id"]}),
        json!({"expose_headers": ["x-request-id"], "extra": true}),
        // Item constraints the schema previously did not model at all.
        json!({"expose_headers": [""]}),
        json!({"expose_headers": ["   "]}),
        json!({"expose_headers": ["bad name"]}),
        json!({"expose_headers": ["bad:name"]}),
        json!({"expose_headers": ["x-request-id\r\nx-injected"]}),
        json!({"expose_headers": [1]}),
    ] {
        assert_component_validity(&spec, "GrpcWebConfig", &config, false);
        assert!(
            GrpcWebPlugin::new(&config).is_err(),
            "runtime accepted schema-invalid grpc_web config: {config}"
        );
    }

    let plugin_docs = include_str!("../../docs/plugins.md");
    let grpc_web_docs = plugin_docs
        .split("### `grpc_web`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("grpc_web docs section");
    assert!(grpc_web_docs.contains("`null` is not an alias for `{}`"));
    assert!(grpc_web_docs.contains("KeepLastKnownGood"));
    assert!(
        grpc_web_docs.contains("HTTP-to-gRPC client mapping"),
        "grpc_web docs must describe non-gRPC HTTP status synthesis"
    );
    assert!(
        grpc_web_docs.contains("Multiple instances:"),
        "grpc_web docs must describe multi-instance ownership and expose_headers union"
    );
    assert!(
        description.contains("HTTP-to-gRPC client mapping"),
        "GrpcWebConfig OpenAPI description must document status synthesis"
    );
    assert!(
        description.contains("not rewritten to 200"),
        "GrpcWebConfig OpenAPI description must document client-visible HTTP status contract"
    );
    assert!(
        description.contains("Multiple effective instances"),
        "GrpcWebConfig OpenAPI description must document multi-instance translation ownership"
    );
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

    let oversized_matcher = "a".repeat(513);
    let too_many_matchers: Vec<serde_json::Value> = (0..65)
        .map(|i| json!({"exact": format!("https://app{i}.example.com")}))
        .collect();
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
        // Issue #3254: the Istio object `exact` matcher is LITERAL, so a
        // wildcard-shaped or noncanonical value is representable (and matches
        // only itself) rather than rejected. The NATIVE plain-string form above
        // keeps its own stricter origin/wildcard grammar.
        (
            json!({"allowed_origins": [{"exact": "*.example.com"}]}),
            true,
        ),
        (
            json!({"allowed_origins": [{"exact": "https://app.example.com:443"}]}),
            true,
        ),
        (json!({"allowed_origins": [{"exact": "   "}]}), false),
        // Issue #3253: explicit byte / count bounds, enforced by BOTH the
        // schema and the runtime.
        (
            json!({"allowed_origins": [{"exact": &oversized_matcher}]}),
            false,
        ),
        (
            json!({"allowed_origins": [{"prefix": &oversized_matcher}]}),
            false,
        ),
        (
            json!({"allowed_origins": [{"regex": &oversized_matcher}]}),
            false,
        ),
        (json!({"allowed_origins": too_many_matchers}), false),
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

    for field in ["custom_tags", "custom_header_tags", "custom_env_tags"] {
        assert_eq!(properties[field]["maxProperties"], json!(32));
        let description = properties[field]["description"]
            .as_str()
            .expect("custom tag description");
        assert!(
            description.contains("32 distinct tag names"),
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

    let tag_overrides = properties
        .pointer("/metrics/properties/tag_overrides")
        .expect("metric tag overrides schema exists");
    assert_eq!(tag_overrides["maxItems"], json!(128));
    let override_description = tag_overrides["description"]
        .as_str()
        .expect("metric tag overrides description");
    assert!(override_description.contains("16384 encoded bytes"));

    let cel_description = tag_overrides
        .pointer("/items/properties/operation/properties/cel/description")
        .and_then(|value| value.as_str())
        .expect("metric tag CEL description");
    assert!(cel_description.contains("512-byte UTF-8 limit"));
    assert!(cel_description.contains("counts Unicode characters"));

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
    // The per-map OpenAPI bounds cannot express a sum across these objects; the
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
    let default_redact_headers = component
        .pointer("/properties/redact_headers/default")
        .and_then(serde_json::Value::as_array)
        .expect("OPA redact_headers default is an array");
    for reserved in ["x-loadtesting-key", "x-loadtesting-fanout"] {
        assert!(
            default_redact_headers
                .iter()
                .any(|header| header.as_str() == Some(reserved)),
            "OPA OpenAPI defaults must redact reserved load-testing header {reserved}"
        );
    }

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

    // The query-ambiguity posture is fail-closed by default and its value set
    // is closed, matching `QueryAmbiguityPolicy::parse` (advisories
    // GHSA-j2j6-f9c7-hh85, GHSA-gr4p-3qw3-87r5).
    assert_eq!(
        component.pointer("/properties/query_ambiguity_policy/default"),
        Some(&json!("reject"))
    );
    assert_eq!(
        component.pointer("/properties/query_ambiguity_policy/enum"),
        Some(&json!(["reject", "delegate"]))
    );
    for (value, valid) in [("reject", true), ("delegate", true), ("allow", false)] {
        let mut policy = base.clone();
        policy
            .as_object_mut()
            .expect("OPA test config is an object")
            .insert("query_ambiguity_policy".to_string(), json!(value));
        assert_component_validity(&spec, "OpaPluginConfig", &policy, valid);
    }

    for field in ["max_response_bytes", "max_body_bytes"] {
        let mut zero = base.clone();
        zero.as_object_mut()
            .expect("OPA test config is an object")
            .insert(field.to_string(), json!(0));
        assert_component_validity(&spec, "OpaPluginConfig", &zero, false);
    }
}

#[test]
fn grpc_deadline_schema_matches_runtime_validation_contract() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let component = spec
        .pointer("/components/schemas/GrpcDeadlineConfig")
        .expect("GrpcDeadlineConfig component exists");
    assert_eq!(component.get("additionalProperties"), Some(&json!(false)));
    let reject_description = component
        .pointer("/properties/reject_no_deadline/description")
        .and_then(serde_json::Value::as_str)
        .expect("reject_no_deadline description exists");
    for contract in ["Native H2/H3", "HTTP 200", "trailers-only", "grpc-status"] {
        assert!(
            reject_description.contains(contract),
            "missing native gRPC wire contract `{contract}`"
        );
    }

    let parity_cases = [
        (json!({}), false),
        (json!({"max_deadline_ms": 0}), false),
        (json!({"default_deadline_ms": 0}), false),
        (json!({"max_deadline_ms": null}), false),
        (json!({"reject_no_deadline": null}), false),
        (json!({"max_deadline_ms": "5000"}), false),
        (json!({"reject_no_deadline": 1}), false),
        (json!({"reject_no_deadline": false}), false),
        (json!({"subtract_gateway_processing": false}), false),
        (
            json!({"max_deadline_ms": 30000, "reject_no_deadine": true}),
            false,
        ),
        (json!({"max_deadline_ms": 30000}), true),
        (json!({"default_deadline_ms": 5000}), true),
        (json!({"reject_no_deadline": true}), true),
        (json!({"subtract_gateway_processing": true}), true),
        (
            json!({
                "max_deadline_ms": 30000,
                "default_deadline_ms": 5000,
                "subtract_gateway_processing": true,
                "reject_no_deadline": true
            }),
            true,
        ),
    ];
    for (config, expected_valid) in parity_cases {
        assert_component_validity(&spec, "GrpcDeadlineConfig", &config, expected_valid);
        let runtime_valid = ferrum_edge::plugins::create_plugin("grpc_deadline", &config).is_ok();
        assert_eq!(
            runtime_valid, expected_valid,
            "runtime/schema parity drift for {config}"
        );
    }

    let cross_field = json!({"max_deadline_ms": 5000, "default_deadline_ms": 60000});
    let runtime_error = ferrum_edge::plugins::create_plugin("grpc_deadline", &cross_field)
        .err()
        .expect("runtime rejects default above max");
    assert!(runtime_error.contains("cannot exceed"));
    assert!(
        component
            .get("description")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|description| {
                description.contains("default_deadline_ms must be less than or equal")
                    && description.contains("runtime validation")
            }),
        "OpenAPI must document the dynamic cross-field rule JSON Schema cannot compare"
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
                "h2_upgrade_policy": "DO_NOT_UPGRADE",
                "max_retries": 2,
                "http1_max_pending_requests": 7,
                "http2_max_requests": 32,
                "h2_max_concurrent_streams": 16,
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
                "tcp_idle_timeout_seconds": 3600,
                "http_max_requests_per_connection": 1000,
                "http_idle_timeout_ms": 30000,
                "http2_max_requests": 256,
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
    use ferrum_edge::modes::mesh::node_waypoint_observability::{
        NodeWaypointAssertedIdentitySnapshot, NodeWaypointDestinationPolicySnapshot,
        NodeWaypointHboneHandshakeSnapshot, NodeWaypointObservabilitySnapshot,
    };
    use ferrum_edge::modes::mesh::runtime::MeshEgressScopeHealth;
    use ferrum_edge::modes::mesh::slice::{MeshEgressScopeResource, MeshEgressScopeSnapshot};
    use ferrum_edge::overload::{
        ActionSnapshot, ConnPressure, FdPressure, NodeWaypointDropSnapshot, OverloadLevel,
        OverloadSnapshot, PressureSnapshot, ReqPressure,
    };
    use ferrum_edge::proxy::udp_placement_migration::{
        UdpMigrationFailureReason, UdpMigrationStatusPhase, UdpMigrationStatusSnapshot,
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
    // Build from the REAL snapshot type, not a hand-written literal: a serde
    // field rename in `node_waypoint_observability` must fail this parity gate
    // instead of silently diverging from the published OpenAPI schema.
    let node_waypoint_observability = NodeWaypointObservabilitySnapshot {
        enabled: true,
        hbone_handshakes: NodeWaypointHboneHandshakeSnapshot {
            inbound_tls_success: 1,
            inbound_tls_failure: 2,
            inbound_connect_success: 3,
            inbound_connect_failure: 4,
            outbound_dial_success: 5,
            outbound_dial_failure: 6,
        },
        asserted_identity: NodeWaypointAssertedIdentitySnapshot {
            accepted: 1,
            rejected_untrusted_assertor: 2,
            rejected_assertion_out_of_scope: 3,
            rejected_trust_domain_mismatch: 0,
            rejected_unauthenticated_hbone: 0,
            rejected_malformed: 0,
            rejected_stale_or_unknown: 0,
        },
        destination_policy_rejections: NodeWaypointDestinationPolicySnapshot {
            authz_deny: 1,
            scope_missing: 0,
            destination_scope_missing: 0,
            relay_destination_denied: 0,
        },
        missing_destination_metadata: 1,
        plaintext_fallback_attempts: 1,
    };
    let udp_placement_migration = UdpMigrationStatusSnapshot {
        enabled: true,
        phase: UdpMigrationStatusPhase::CleaningPodNetns,
        outstanding: 2,
        failure_reason: UdpMigrationFailureReason::GateAcknowledgementMissing,
        established_adoption: false,
        adoption_proof: ferrum_edge::proxy::udp_placement_migration::UdpAdoptionProof::None,
    };
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "mesh": {
                "egress_scope": health,
                "node_waypoint_observability": node_waypoint_observability,
                "config_stream": null
            }
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "mesh": {
                "egress_scope": health,
                "node_waypoint_observability": node_waypoint_observability,
                "config_stream": null,
                "udp_placement_migration": udp_placement_migration
            }
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "mesh": {
                "egress_scope": {
                    "sidecar_admitted_services": 1,
                    "sidecar_denied_services": 0
                }
            }
        }),
        false,
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
                enforced: true,
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
                "frontend_dtls_reload": {
                    "generation": 0,
                    "last_swapped_listeners": 0,
                    "last_success_unix": null,
                    "last_failure_unix": null,
                    "last_outcome": "none"
                },
                "bind_failures_total": 0,
                "bind_failures": []
            }),
        );
    assert_component_validity(&spec, "OverloadSnapshot", &overload, true);
}

#[test]
fn health_failover_topology_and_admin_writes_openapi_parity() {
    // Issue #3001: authenticated /health exposes failover_topology and
    // admin_writes_enabled reflects failover write gating.
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let topology = json!({
        "primary_active": false,
        "allow_writes": false,
        "opt_in_writes_enabled_during_window": false,
        "primary_failback_fenced": false,
        "failover_since_unix_ms": 1_700_000_000_000u64,
        "active_url_redacted": "sqlite:///tmp/failover.db"
    });
    assert_component_validity(&spec, "DatabaseFailoverTopology", &topology, true);

    let health = json!({
        "status": "degraded",
        "ready": true,
        "admin_writes_enabled": false,
        "database": {
            "status": "connected",
            "type": "sqlite",
            "failover_topology": topology
        }
    });
    assert_component_validity(&spec, "HealthResponse", &health, true);

    let jwks_trust = json!({
        "fresh": 1,
        "grace": 0,
        "expired": 0,
        "max_age_seconds": {
            "fresh": 12,
            "grace": 0,
            "expired": 0
        }
    });
    assert_component_validity(&spec, "JwksTrustHealthSnapshot", &jwks_trust, true);
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "jwks_trust": jwks_trust
        }),
        true,
    );
    let jwks_trust_desc = spec["components"]["schemas"]["JwksTrustHealthSnapshot"]["description"]
        .as_str()
        .expect("JwksTrustHealthSnapshot description");
    assert!(
        jwks_trust_desc.contains("active remote")
            && jwks_trust_desc.contains("never")
            && (jwks_trust_desc.contains("kid") || jwks_trust_desc.contains("`kid`")),
        "jwks_trust schema must document active-remote fixed-cardinality redaction"
    );

    let admin_writes = spec["components"]["schemas"]["HealthResponse"]["properties"]
        ["admin_writes_enabled"]["description"]
        .as_str()
        .expect("admin_writes_enabled description");
    assert!(
        admin_writes.contains("FERRUM_DB_FAILOVER_ALLOW_WRITES")
            || admin_writes.contains("failover"),
        "admin_writes_enabled must document failover write blocking"
    );
    assert!(
        admin_writes.contains("config-database")
            || admin_writes.contains("config-store")
            || admin_writes.contains("managed TLS"),
        "admin_writes_enabled must clarify it is the config-database mutation signal, not managed TLS/ACME"
    );

    let topology_desc = spec["components"]["schemas"]["DatabaseFailoverTopology"]["description"]
        .as_str()
        .expect("DatabaseFailoverTopology description");
    assert!(
        topology_desc.contains("divergence-risk") || topology_desc.contains("divergence"),
        "topology schema must document opt-in divergence-risk contract"
    );
    assert!(
        topology_desc.contains("fences") && topology_desc.contains("restarted after operator"),
        "topology schema must document the process-local failback fence"
    );
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
    let schema = spec
        .pointer("/components/schemas/AiPromptShieldConfig")
        .expect("missing AiPromptShieldConfig schema");
    let schema_description = schema["description"]
        .as_str()
        .expect("AiPromptShieldConfig description");
    assert!(
        schema_description.contains("HTTP-only"),
        "OpenAPI must advertise HTTP-only attachment for ai_prompt_shield"
    );
    assert!(
        schema_description.contains("Native gRPC is unsupported"),
        "OpenAPI must reject the inert native-gRPC support claim"
    );

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
        // A `custom_patterns` entry is as closed as the top level: an
        // unsupported nested member is refused by both surfaces, not read as
        // name/regex and dropped.
        json!({
            "patterns": [],
            "custom_patterns": [{"name": "account", "regex": "ACCT-[0-9]+", "note": "x"}]
        }),
        // The published `name` bound and the constructor's agree.
        json!({
            "patterns": [],
            "custom_patterns": [{"name": "n".repeat(200), "regex": "ACCT-[0-9]+"}]
        }),
    ] {
        assert_component_validity(&spec, "AiPromptShieldConfig", &config, false);
        assert!(
            AiPromptShield::new(&config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }

    // `max_scan_bytes` publishes an explicit numeric domain whose bound every
    // JSON number representation holds exactly, so the component and the
    // constructor reach the same verdict at, just above, and far above it.
    // Written through `from_str` because `json!` would need the literals to fit
    // a Rust integer type.
    for (raw, expected_valid) in [
        (r#"{"max_scan_bytes":9007199254740991}"#, true),
        (r#"{"max_scan_bytes":1024.0}"#, true),
        (r#"{"max_scan_bytes":9007199254740992}"#, false),
        (r#"{"max_scan_bytes":18446744073709551616}"#, false),
        (r#"{"max_scan_bytes":1024.5}"#, false),
    ] {
        let config: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        assert_component_validity(&spec, "AiPromptShieldConfig", &config, expected_valid);
        assert_eq!(
            AiPromptShield::new(&config).is_ok(),
            expected_valid,
            "component and constructor must agree on {raw}"
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
fn prometheus_metrics_config_is_closed_and_bounds_unsigned_timing_fields() {
    use ferrum_edge::plugins::prometheus_metrics::PrometheusMetrics;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/PrometheusMetricsConfig")
        .expect("PrometheusMetricsConfig component exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let schema_fields: BTreeSet<&str> = schema["properties"]
        .as_object()
        .expect("PrometheusMetricsConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        schema_fields,
        BTreeSet::from([
            "cache_invalidation_min_age_ms",
            "mesh_series_budget_per_family",
            "render_cache_ttl_seconds",
            "stale_entry_ttl_seconds",
        ])
    );
    assert!(
        !schema_fields.contains("schema") && !schema_fields.contains("schema_ref"),
        "schema/schema_ref must not be accepted properties"
    );

    let uint64_max = json!(u64::MAX);
    for field in [
        "render_cache_ttl_seconds",
        "stale_entry_ttl_seconds",
        "cache_invalidation_min_age_ms",
    ] {
        assert_eq!(schema["properties"][field]["format"], json!("uint64"));
        assert_eq!(schema["properties"][field]["minimum"], json!(0));
        assert_eq!(schema["properties"][field]["maximum"], uint64_max);
    }
    assert_eq!(
        schema["properties"]["mesh_series_budget_per_family"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["mesh_series_budget_per_family"]["maximum"],
        json!(1_000_000)
    );

    for config in [
        serde_json::Value::Null,
        json!({}),
        json!({"render_cache_ttl_seconds": 0}),
        json!({"render_cache_ttl_seconds": u64::MAX}),
        json!({"stale_entry_ttl_seconds": u64::MAX}),
        json!({"cache_invalidation_min_age_ms": u64::MAX}),
        json!({"mesh_series_budget_per_family": 1}),
        json!({"mesh_series_budget_per_family": 1_000_000}),
    ] {
        assert_component_validity(&spec, "PrometheusMetricsConfig", &config, true);
        PrometheusMetrics::new(&config, "ferrum")
            .unwrap_or_else(|err| panic!("constructor must accept {config}: {err}"));
    }

    for config in [
        json!({"render_cache_ttl_secnds": 10}),
        json!({"schema": {}}),
        json!({"schema_ref": "x"}),
        json!({"render_cache_ttl_seconds": -1}),
        json!({"stale_entry_ttl_seconds": -1}),
        json!({"cache_invalidation_min_age_ms": -1}),
        json!({"mesh_series_budget_per_family": 0}),
        json!({"mesh_series_budget_per_family": 1_000_001}),
    ] {
        assert_component_validity(&spec, "PrometheusMetricsConfig", &config, false);
        assert!(
            PrometheusMetrics::new(&config, "ferrum").is_err(),
            "constructor must reject {config}"
        );
    }

    let over = serde_json::from_str("18446744073709551616")
        .expect("u64::MAX+1 must parse as a JSON number");
    let mut over_range = json!({});
    over_range
        .as_object_mut()
        .expect("object")
        .insert("render_cache_ttl_seconds".to_string(), over);
    assert_component_validity(&spec, "PrometheusMetricsConfig", &over_range, false);
}

#[test]
fn proxy_alerts_schema_rejects_unknown_keys_and_keeps_open_maps() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsConfig"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsQuietHourWindow"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsRecovery"]["additionalProperties"],
        json!(false)
    );
    for channel in [
        "ProxyAlertsSlackChannel",
        "ProxyAlertsTeamsChannel",
        "ProxyAlertsDiscordChannel",
        "ProxyAlertsWebhookChannel",
        "ProxyAlertsEmailChannel",
    ] {
        assert_eq!(
            spec["components"]["schemas"][channel]["additionalProperties"],
            json!(false),
            "{channel} must be closed"
        );
    }
    for rule in [
        "ProxyAlertsErrorRateRule",
        "ProxyAlertsStatusCodeCountRule",
        "ProxyAlertsLatencyPercentileRule",
        "ProxyAlertsErrorClassRule",
        "ProxyAlertsStreamDisconnectCauseRule",
        "ProxyAlertsGrpcStatusCountRule",
        "ProxyAlertsGrpcStatusRateRule",
    ] {
        assert_eq!(
            spec["components"]["schemas"][rule]["unevaluatedProperties"],
            json!(false),
            "{rule} must close composed properties"
        );
    }
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsChannel"]["discriminator"]["propertyName"],
        json!("type")
    );
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsRule"]["discriminator"]["propertyName"],
        json!("type")
    );
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsWebhookChannel"]["properties"]["headers"]["additionalProperties"],
        json!({"type": "string"})
    );

    let valid = json!({
        "channels": {
            "team-alpha_42": {
                "type": "webhook",
                "url": "https://example.com/hooks",
                "headers": {
                    "X-Custom-Trace": "abc",
                    "X-Routing-Key": "rk"
                },
                "body_template": "{\"ok\":true}"
            }
        },
        "rules": [{
            "name": "errors",
            "type": "error_rate",
            "status_codes": [500],
            "threshold_percent": 5.0,
            "channels": ["team-alpha_42"]
        }]
    });
    assert_component_validity(&spec, "ProxyAlertsConfig", &valid, true);

    // Email channel (issue #3329): TLS-only closed variant.
    let email_config = |channel: serde_json::Value| {
        json!({
            "channels": { "ops_email": channel },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops_email"]
            }]
        })
    };
    assert_component_validity(
        &spec,
        "ProxyAlertsConfig",
        &email_config(json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "tls_mode": "starttls",
            "username_env": "FERRUM_ALERT_SMTP_USERNAME",
            "password_env": "FERRUM_ALERT_SMTP_PASSWORD",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"],
            "subject_template": "[${severity}] ${title}",
            "body_template": "${body}"
        })),
        true,
    );
    for invalid_email in [
        // Unknown key.
        json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"],
            "smtp_hostt": "typo.example.com"
        }),
        // Plaintext is not an accepted posture.
        json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "tls_mode": "none",
            "from": "ferrum@example.com",
            "to": ["oncall@example.com"]
        }),
        // Recipients are required and bounded below by one.
        json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "from": "ferrum@example.com",
            "to": []
        }),
        // Missing required `from`.
        json!({
            "type": "email",
            "smtp_host": "smtp.example.com",
            "to": ["oncall@example.com"]
        }),
    ] {
        assert_component_validity(
            &spec,
            "ProxyAlertsConfig",
            &email_config(invalid_email),
            false,
        );
    }

    for (field, value) in [
        ("default_cooldown_seconds", json!(0)),
        ("default_cooldown_seconds", json!(86_401)),
        ("default_min_request_count", json!(0)),
        ("default_window_seconds", json!(4)),
        ("default_window_seconds", json!(3_601)),
        ("default_resolved_window_seconds", json!(4)),
        ("default_resolved_window_seconds", json!(86_401)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert_component_validity(&spec, "ProxyAlertsConfig", &invalid, false);
    }

    for invalid in [
        json!({
            "enabledd": false,
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        json!({
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x",
                    "channel_overide": "#alerts"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        json!({
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "threshold_count": 10,
                "channels": ["ops"]
            }]
        }),
        json!({
            "quiet_hours_utc": [{"from": "23:00", "to": "06:00", "weekdayss": [0]}],
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        json!({
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"],
                "recovery": {"resolved_window_second": 300}
            }]
        }),
    ] {
        assert_component_validity(&spec, "ProxyAlertsConfig", &invalid, false);
    }

    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsRule"]["oneOf"][0]["$ref"],
        json!("#/components/schemas/ProxyAlertsDisabledDraftRule")
    );
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsDisabledDraftRule"]["properties"]["enabled"]["const"],
        json!(false)
    );
    assert_eq!(
        spec["components"]["schemas"]["ProxyAlertsRuleCommon"]["properties"]["enabled"]["enum"],
        json!([true])
    );

    // Disabled drafts may carry incomplete/unknown fields.
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "enabled": false,
            "type": "error_rate",
            "unknown_draft_field": 1,
            "status_codes": "not-an-array"
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsConfig",
        &json!({
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "enabled": false,
                "unknown_draft_field": true
            }]
        }),
        false,
    );
    let mut valid_with_disabled_draft = valid.clone();
    valid_with_disabled_draft["rules"]
        .as_array_mut()
        .expect("rules fixture is an array")
        .insert(
            0,
            json!({
                "enabled": false,
                "unknown_draft_field": true
            }),
        );
    assert_component_validity(&spec, "ProxyAlertsConfig", &valid_with_disabled_draft, true);
    // Active rules remain closed and require the selected variant shape.
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "name": "errors",
            "type": "error_rate",
            "status_codes": [500],
            "threshold_percent": 5.0,
            "channels": ["ops"],
            "extra": true
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "enabled": true,
            "name": "errors",
            "type": "error_rate",
            "status_codes": [500],
            "threshold_percent": 5.0,
            "channels": ["ops"]
        }),
        true,
    );
    // A complete active-shaped object with enabled:false must not be ambiguous.
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "enabled": false,
            "name": "errors",
            "type": "error_rate",
            "status_codes": [500],
            "threshold_percent": 5.0,
            "channels": ["ops"]
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsConfig",
        &json!({
            "enabled": "false",
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsConfig",
        &json!({
            "quiet_hours_utc": null,
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsConfig",
        &json!({
            "max_concurrent_dispatches": 0,
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "name": "grpc_unavailable",
            "type": "grpc_status_count",
            "grpc_statuses": [14, "OTHER"],
            "threshold_count": 10,
            "channels": ["ops"]
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "name": "grpc_error_rate",
            "type": "grpc_status_rate",
            "grpc_statuses": [0, 14, 16],
            "threshold_percent": 5.0,
            "min_request_count": 20,
            "channels": ["ops"]
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "name": "grpc_bad",
            "type": "grpc_status_count",
            "grpc_statuses": [17],
            "threshold_count": 1,
            "channels": ["ops"]
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "name": "grpc_http_bleed",
            "type": "grpc_status_count",
            "grpc_statuses": [14],
            "status_codes": [500],
            "threshold_count": 1,
            "channels": ["ops"]
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "ProxyAlertsRule",
        &json!({
            "name": "grpc_lowercase_other",
            "type": "grpc_status_count",
            "grpc_statuses": ["other"],
            "threshold_count": 1,
            "channels": ["ops"]
        }),
        false,
    );
}

fn proxy_alerts_channel_config(channel: serde_json::Value) -> serde_json::Value {
    json!({
        "channels": { "ops": channel },
        "rules": [{
            "name": "r",
            "type": "status_code_count",
            "status_codes": [500],
            "threshold_count": 1,
            "channels": ["ops"]
        }]
    })
}

fn proxy_alerts_rule_config(rule: serde_json::Value) -> serde_json::Value {
    json!({
        "channels": {
            "ops": {
                "type": "webhook",
                "url": "http://127.0.0.1:54321/",
                "body_template": "{}"
            }
        },
        "rules": [rule]
    })
}

fn assert_proxy_alerts_schema_and_constructor(
    validator: &jsonschema::Validator,
    name: &str,
    config: &serde_json::Value,
    schema_valid: bool,
    constructor_valid: bool,
) {
    assert_eq!(
        validator.validate(config).is_ok(),
        schema_valid,
        "{name}: unexpected schema result for {config}"
    );
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(config);
    match (parsed, constructor_valid) {
        (Ok(_), true) | (Err(_), false) => {}
        (Ok(_), false) => panic!("{name}: constructor accepted {config}"),
        (Err(err), true) => panic!("{name}: constructor rejected {config}: {err}"),
    }
}

#[test]
fn proxy_alerts_schema_matches_constructor_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let description = spec["components"]["schemas"]["ProxyAlertsConfig"]["description"]
        .as_str()
        .expect("ProxyAlertsConfig description");
    for contract in [
        "OptionalFailOpen",
        "HTTP 400",
        "delivery_retry_max_ms >= delivery_retry_base_ms",
        "UTF-8 byte",
        "case-insensitive",
        "ferrum-edge validate",
    ] {
        assert!(
            description.contains(contract),
            "ProxyAlertsConfig description missing `{contract}`"
        );
    }

    let docs = include_str!("../../docs/proxy_alerts.md");
    let plugins_docs = include_str!("../../docs/plugins.md");
    let notifications_docs = include_str!("../../docs/notifications.md");
    for (path, text, needle) in [
        ("docs/proxy_alerts.md", docs, "OptionalFailOpen"),
        ("docs/proxy_alerts.md", docs, "ferrum-edge validate"),
        ("docs/proxy_alerts.md", docs, "constructor-only"),
        ("docs/plugins.md", plugins_docs, "OptionalFailOpen"),
        (
            "docs/notifications.md",
            notifications_docs,
            "case-insensitive",
        ),
        (
            "docs/notifications.md",
            notifications_docs,
            "character ceiling",
        ),
    ] {
        assert!(text.contains(needle), "{path} missing `{needle}`");
    }

    assert_eq!(
        spec.pointer(
            "/components/schemas/ProxyAlertsConfig/properties/max_concurrent_dispatches/maximum",
        )
        .and_then(serde_json::Value::as_u64),
        Some(4_294_967_295)
    );
    let method_schema = spec
        .pointer("/components/schemas/ProxyAlertsWebhookChannel/properties/method")
        .expect("webhook method schema");
    assert!(
        method_schema.get("enum").is_none(),
        "webhook method must not be an uppercase-only enum"
    );
    assert_eq!(
        method_schema["pattern"],
        json!("^[Pp][Oo][Ss][Tt]$|^[Pp][Uu][Tt]$|^[Pp][Aa][Tt][Cc][Hh]$")
    );
    assert_eq!(
        spec.pointer("/components/schemas/ProxyAlertsEmailChannel/allOf")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2),
        "email channel must encode username/password pairing"
    );

    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/ProxyAlertsConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .unwrap_or_else(|error| panic!("ProxyAlertsConfig schema compiles: {error}"));

    let webhook = json!({
        "type": "webhook",
        "url": "http://127.0.0.1:54321/",
        "body_template": "{}"
    });
    let mut method_post = webhook.clone();
    method_post["method"] = json!("post");
    let mut method_patch = webhook.clone();
    method_patch["method"] = json!("pAtCh");
    let mut empty_url = webhook.clone();
    empty_url["url"] = json!("");
    let mut ftp_url = webhook.clone();
    ftp_url["url"] = json!("ftp://example.test/");
    let mut empty_url_env = webhook.clone();
    empty_url_env
        .as_object_mut()
        .expect("webhook object")
        .remove("url");
    empty_url_env["url_env"] = json!("");
    let mut unbalanced = webhook.clone();
    unbalanced["body_template"] = json!("${");

    let email = json!({
        "type": "email",
        "smtp_host": "smtp.example.com",
        "from": "ferrum@example.com",
        "to": ["oncall@example.com"]
    });
    let mut email_username_only = email.clone();
    email_username_only["username"] = json!("alerts");
    let mut email_empty_subject = email.clone();
    email_empty_subject["subject_template"] = json!("");
    let mut email_empty_host = email.clone();
    email_empty_host["smtp_host"] = json!("");
    let mut email_dots = email.clone();
    email_dots["from"] = json!("a..b@example.test");
    let mut email_long_subject = email.clone();
    email_long_subject["subject_template"] = json!("é".repeat(600));

    let mut too_many_dispatches = proxy_alerts_channel_config(webhook.clone());
    too_many_dispatches["max_concurrent_dispatches"] = json!(4_294_967_296_u64);
    let mut retry_inversion = proxy_alerts_channel_config(webhook.clone());
    retry_inversion["delivery_retry_base_ms"] = json!(2000);
    retry_inversion["delivery_retry_max_ms"] = json!(100);

    let cases: [(&str, serde_json::Value, bool, bool); 25] = [
        (
            "minimal webhook",
            proxy_alerts_channel_config(webhook.clone()),
            true,
            true,
        ),
        (
            "method post",
            proxy_alerts_channel_config(method_post),
            true,
            true,
        ),
        (
            "method pAtCh",
            proxy_alerts_channel_config(method_patch),
            true,
            true,
        ),
        (
            "slack",
            proxy_alerts_channel_config(json!({
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/services/x/y/z"
            })),
            true,
            true,
        ),
        (
            "teams",
            proxy_alerts_channel_config(json!({
                "type": "teams",
                "webhook_url": "https://outlook.office.com/webhook/x"
            })),
            true,
            true,
        ),
        (
            "discord",
            proxy_alerts_channel_config(json!({
                "type": "discord",
                "webhook_url": "https://discord.com/api/webhooks/x"
            })),
            true,
            true,
        ),
        (
            "email",
            proxy_alerts_channel_config(email.clone()),
            true,
            true,
        ),
        (
            "error_rate",
            proxy_alerts_rule_config(json!({
                "name": "r",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            })),
            true,
            true,
        ),
        (
            "latency_percentile",
            proxy_alerts_rule_config(json!({
                "name": "r",
                "type": "latency_percentile",
                "metric": "backend_total_ms",
                "percentile": 95,
                "threshold_ms": 1500,
                "channels": ["ops"]
            })),
            true,
            true,
        ),
        (
            "error_class",
            proxy_alerts_rule_config(json!({
                "name": "r",
                "type": "error_class",
                "classes": ["connection_refused"],
                "threshold_count": 1,
                "channels": ["ops"]
            })),
            true,
            true,
        ),
        (
            "stream_disconnect_cause",
            proxy_alerts_rule_config(json!({
                "name": "r",
                "type": "stream_disconnect_cause",
                "causes": ["backend_error"],
                "threshold_count": 1,
                "channels": ["ops"]
            })),
            true,
            true,
        ),
        (
            "grpc_status_count",
            proxy_alerts_rule_config(json!({
                "name": "r",
                "type": "grpc_status_count",
                "grpc_statuses": [14, "OTHER"],
                "threshold_count": 1,
                "channels": ["ops"]
            })),
            true,
            true,
        ),
        (
            "grpc_status_rate",
            proxy_alerts_rule_config(json!({
                "name": "r",
                "type": "grpc_status_rate",
                "grpc_statuses": [14],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            })),
            true,
            true,
        ),
        (
            "disabled draft",
            json!({
                "channels": {
                    "ops": {
                        "type": "webhook",
                        "url": "http://127.0.0.1:54321/",
                        "body_template": "{}"
                    }
                },
                "rules": [
                    { "enabled": false, "unknown_draft_field": true },
                    {
                        "name": "r",
                        "type": "status_code_count",
                        "status_codes": [500],
                        "threshold_count": 1,
                        "channels": ["ops"]
                    }
                ]
            }),
            true,
            true,
        ),
        (
            "empty url",
            proxy_alerts_channel_config(empty_url),
            false,
            false,
        ),
        (
            "ftp url",
            proxy_alerts_channel_config(ftp_url),
            false,
            false,
        ),
        (
            "empty url_env",
            proxy_alerts_channel_config(empty_url_env),
            false,
            false,
        ),
        (
            "email username without password",
            proxy_alerts_channel_config(email_username_only),
            false,
            false,
        ),
        (
            "empty subject_template",
            proxy_alerts_channel_config(email_empty_subject),
            false,
            false,
        ),
        (
            "empty smtp_host",
            proxy_alerts_channel_config(email_empty_host),
            false,
            false,
        ),
        (
            "repeated local-part dots",
            proxy_alerts_channel_config(email_dots),
            false,
            false,
        ),
        (
            "max_concurrent_dispatches exceeds u32",
            too_many_dispatches,
            false,
            false,
        ),
        (
            "unbalanced webhook placeholder",
            proxy_alerts_channel_config(unbalanced),
            true,
            false,
        ),
        (
            "email subject byte bound",
            proxy_alerts_channel_config(email_long_subject),
            true,
            false,
        ),
        (
            "delivery retry sibling comparison",
            retry_inversion,
            true,
            false,
        ),
    ];

    for (name, config, schema_ok, constructor_ok) in cases {
        assert_proxy_alerts_schema_and_constructor(
            &validator,
            name,
            &config,
            schema_ok,
            constructor_ok,
        );
    }
}

#[test]
fn ai_prompt_compressor_runtime_and_openapi_contracts_match() {
    use ferrum_edge::plugins::ai_prompt_compressor::AiPromptCompressor;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiPromptCompressorConfig")
        .expect("missing AiPromptCompressorConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AiPromptCompressorConfig schema compiles");
    assert_eq!(schema["additionalProperties"], json!(false));

    let schema_fields: BTreeSet<String> = schema["properties"]
        .as_object()
        .expect("config properties")
        .keys()
        .cloned()
        .collect();
    let runtime_fields: BTreeSet<String> = [
        "compress_roles",
        "target_ratio",
        "min_content_tokens",
        "max_scan_bytes",
        "preserve_tag",
        "request_family",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(schema_fields, runtime_fields);

    for config in [
        json!({}),
        json!({"compress_roles": ["user", "system"]}),
        json!({"target_ratio": 0.25}),
        json!({"min_content_tokens": 131072}),
        json!({"max_scan_bytes": 1048576}),
        json!({"preserve_tag": "keep-this_1"}),
        json!({"preserve_tag": "x".repeat(64)}),
        json!({"request_family": "chat_completions"}),
        json!({"request_family": "text_completions", "compress_roles": [" User "]}),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "schema rejected {config}"
        );
        assert!(
            AiPromptCompressor::new(&config).is_ok(),
            "runtime rejected {config}"
        );
    }

    for config in [
        json!(null),
        json!({"compress_role": ["system"]}),
        json!({"target_ratio": null}),
        json!({"min_content_tokens": null}),
        json!({"max_scan_bytes": 1048577}),
        json!({"min_content_tokens": 131073}),
        json!({"preserve_tag": null}),
        json!({"preserve_tag": "x".repeat(65)}),
        json!({"request_family": "images"}),
        json!({"request_family": "text_completions", "compress_roles": ["system"]}),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "schema admitted {config}"
        );
        assert!(
            AiPromptCompressor::new(&config).is_err(),
            "runtime admitted {config}"
        );
    }
}

#[test]
fn ai_token_metrics_runtime_and_openapi_contracts_match() {
    use ferrum_edge::plugins::ai_token_metrics::AiTokenMetrics;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiTokenMetricsConfig")
        .expect("missing AiTokenMetricsConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AiTokenMetricsConfig schema compiles");
    assert_eq!(schema["additionalProperties"], json!(false));

    for config in [
        json!({}),
        json!({"provider": "openai"}),
        json!({"provider": "google"}),
        json!({"metadata_prefix": "tenant.ai_1"}),
        json!({"buffer_streaming_responses": true}),
        json!({"cost_per_prompt_token": 0.000003}),
        json!({"cost_per_prompt_token": 18_446_744_073_709.55}),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "schema rejected {config}"
        );
        assert!(
            AiTokenMetrics::new(&config).is_ok(),
            "runtime rejected {config}"
        );
    }

    for config in [
        json!({"providre": "openai"}),
        json!({"provider": "unknown"}),
        json!({"provider": "OpenAI"}),
        json!({"provider": " openai"}),
        json!({"metadata_prefix": "not allowed"}),
        json!({"metadata_prefix": " ai"}),
        json!({"metadata_prefix": "x".repeat(65)}),
        json!({"cost_per_prompt_token": -1}),
        json!({"cost_per_prompt_token": 18_446_744_073_710.0}),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "schema accepted {config}"
        );
        assert!(
            AiTokenMetrics::new(&config).is_err(),
            "runtime accepted {config}"
        );
    }
}

#[tokio::test]
async fn ai_transcript_audit_schema_matches_runtime_unknown_key_contract() {
    use ferrum_edge::plugins::ai_transcript_audit::{
        AI_TRANSCRIPT_AUDIT_CAPTURE_KEYS, AI_TRANSCRIPT_AUDIT_CONFIG_KEYS,
        AI_TRANSCRIPT_AUDIT_CUSTOM_PATTERN_KEYS, AI_TRANSCRIPT_AUDIT_LIMITS_KEYS,
        AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS, AI_TRANSCRIPT_AUDIT_REDACTION_KEYS,
        AI_TRANSCRIPT_AUDIT_SAMPLING_KEYS, AI_TRANSCRIPT_AUDIT_SINK_KEYS, AiTranscriptAudit,
    };
    use ferrum_edge::plugins::utils::PluginHttpClient;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiTranscriptAuditConfig")
        .expect("missing AiTranscriptAuditConfig schema");
    assert_eq!(schema["additionalProperties"], json!(false));
    for nested in [
        "capture",
        "sampling",
        "redaction",
        "limits",
        "privacy",
        "sink",
    ] {
        assert_eq!(
            schema["properties"][nested]["additionalProperties"],
            json!(false),
            "{nested} must close unknown keys"
        );
    }
    assert_eq!(
        schema["properties"]["redaction"]["properties"]["custom_patterns"]["items"]["additionalProperties"],
        json!(false)
    );
    assert!(
        schema["properties"]["sink"]["properties"]["custom_headers"]["additionalProperties"]
            .is_object(),
        "custom_headers must remain a free-form string map"
    );

    let documented_root = schema["properties"]
        .as_object()
        .expect("root properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime_root = AI_TRANSCRIPT_AUDIT_CONFIG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(documented_root, runtime_root, "root key drift");

    let nested_parity = [
        ("capture", AI_TRANSCRIPT_AUDIT_CAPTURE_KEYS),
        ("sampling", AI_TRANSCRIPT_AUDIT_SAMPLING_KEYS),
        ("redaction", AI_TRANSCRIPT_AUDIT_REDACTION_KEYS),
        ("limits", AI_TRANSCRIPT_AUDIT_LIMITS_KEYS),
        ("privacy", AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS),
        ("sink", AI_TRANSCRIPT_AUDIT_SINK_KEYS),
    ];
    for (nested, runtime_keys) in nested_parity {
        let documented = schema["properties"][nested]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{nested} properties"))
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let runtime = runtime_keys.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(documented, runtime, "{nested} key drift");
    }
    let documented_patterns =
        schema["properties"]["redaction"]["properties"]["custom_patterns"]["items"]["properties"]
            .as_object()
            .expect("custom pattern properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
    let runtime_patterns = AI_TRANSCRIPT_AUDIT_CUSTOM_PATTERN_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        documented_patterns, runtime_patterns,
        "custom_patterns key drift"
    );

    let http_client = PluginHttpClient::default();
    let parity_cases = [
        (
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest",
                    "custom_headers": {"Authorization": "Bearer ${secret:AUDIT_TOKEN}"},
                    "flush_interval_ms": 600000,
                    "retry_delay_ms": 250
                },
                "capture": null,
                "privacy": null
            }),
            true,
        ),
        (
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest",
                    "flush_interval_ms": 600001
                }
            }),
            false,
        ),
        (
            json!({
                "privacy": {"include_consumer_usernme": false},
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest"
                }
            }),
            false,
        ),
        (
            json!({
                "capture": {"respose": false},
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest"
                }
            }),
            false,
        ),
        (
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest",
                    "on_sink_eror": "reject"
                }
            }),
            false,
        ),
        (
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest",
                    "on_buffer_ful": "reject"
                }
            }),
            false,
        ),
        (
            json!({
                "limits": { "max_request_bytes": 1048576 },
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest"
                }
            }),
            true,
        ),
        (
            json!({
                "limits": { "max_request_bytes": 1048577 },
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest"
                }
            }),
            false,
        ),
    ];
    for (config, expected_valid) in parity_cases {
        assert_component_validity(&spec, "AiTranscriptAuditConfig", &config, expected_valid);
        let runtime_valid = AiTranscriptAudit::new(&config, http_client.clone()).is_ok();
        assert_eq!(
            runtime_valid, expected_valid,
            "runtime/schema parity drift for {config}"
        );
    }
}

/// Table-driven component-versus-constructor contract for every admission rule
/// the component can express (issue #5273).
///
/// The unknown-key test above proves the two key SETS agree; this one proves
/// the two ADMISSION decisions agree for the type, null, enum, non-empty,
/// conditional, numeric, and string-grammar constraints.
///
/// Descriptor-file dependencies are deliberately kept out: `grpc.descriptor_path`
/// points at a path that does not exist, which the constructor treats as
/// "enrollment retained, body excerpts omitted" rather than a config error, so
/// these cases compare schema against shape and never against node-local file
/// state.
#[tokio::test]
async fn ai_transcript_audit_schema_matches_runtime_admission_contract() {
    use ferrum_edge::plugins::ai_transcript_audit::AiTranscriptAudit;
    use ferrum_edge::plugins::utils::PluginHttpClient;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let http_client = PluginHttpClient::default();

    // The minimum admissible sink, plus whatever a case overrides on it.
    let sink = |extra: serde_json::Value| {
        let overlay = extra.as_object().expect("sink overlay is an object");
        let mut base = json!({"endpoint_url": "https://audit.example.com/ingest"});
        for (key, value) in overlay {
            base[key] = value.clone();
        }
        base
    };
    // A single-method gRPC enrollment whose descriptor is intentionally absent.
    let grpc = |method: serde_json::Value| {
        json!({
            "descriptor_path": "/nonexistent/ferrum-ai-transcript-audit-descriptor.bin",
            "methods": {"/test.Greeter/SayHello": method}
        })
    };
    // 8 code points, 16 UTF-8 bytes: admitted under a byte-counted minimum,
    // refused under the character-counted one the schema and the constructor
    // now agree on.
    let short_multibyte_secret = "\u{00e9}".repeat(8);

    let cases: Vec<(&str, serde_json::Value, bool)> = vec![
        // ---- null keeps the documented default for every fixed scalar ----
        (
            "mode null",
            json!({
                "mode": null,
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "capture.request null",
            json!({
                "capture": {"request": null},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "sink.on_sink_error null",
            json!({
                "sink": sink(json!({"on_sink_error": null}))
            }),
            true,
        ),
        (
            "limits.max_entry_bytes null",
            json!({
                "limits": {"max_entry_bytes": null},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "privacy.path_mode null",
            json!({
                "privacy": {"path_mode": null},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "redaction.builtins null",
            json!({
                "redaction": {"builtins": null},
                "sink": sink(json!({}))
            }),
            true,
        ),
        // ---- null is a TYPE ERROR where the runtime has no default path ----
        (
            "sink null",
            json!({
                "sink": null
            }),
            false,
        ),
        (
            "sink.batch_size null",
            json!({
                "sink": sink(json!({"batch_size": null}))
            }),
            false,
        ),
        (
            "sink.custom_headers null",
            json!({
                "sink": sink(json!({"custom_headers": null}))
            }),
            false,
        ),
        (
            "redaction.custom_patterns null",
            json!({
                "redaction": {"custom_patterns": null},
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "grpc null",
            json!({
                "grpc": null,
                "sink": sink(json!({}))
            }),
            false,
        ),
        // ---- capture.streaming_response accepts the string spellings ----
        (
            "streaming_response 'true'",
            json!({
                "capture": {"streaming_response": "true"},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "streaming_response 'false'",
            json!({
                "capture": {"streaming_response": "false"},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "streaming_response 'sampled'",
            json!({
                "capture": {"streaming_response": "sampled"},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "streaming_response 'maybe'",
            json!({
                "capture": {"streaming_response": "maybe"},
                "sink": sink(json!({}))
            }),
            false,
        ),
        // ---- full_body needs the explicit unredacted-capture opt-in ----
        (
            "full_body without opt-in",
            json!({
                "mode": "full_body",
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "full_body with opt-in",
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "sink": sink(json!({}))
            }),
            true,
        ),
        // ---- at least one capture direction must stay enabled ----
        (
            "every capture direction off",
            json!({
                "capture": {
                    "request": false,
                    "response": false,
                    "streaming_response": false
                },
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "request+response off, streaming defaulted off",
            json!({
                "capture": {"request": false, "response": false},
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "request+response off, streaming on",
            json!({
                "capture": {
                    "request": false,
                    "response": false,
                    "streaming_response": true
                },
                "sink": sink(json!({}))
            }),
            true,
        ),
        // ---- an emptied pattern set is a silent pass-through redactor ----
        (
            "empty pattern set in redacted_body",
            json!({
                "redaction": {"builtins": []},
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "empty pattern set in metadata_only",
            json!({
                "mode": "metadata_only",
                "redaction": {"builtins": []},
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "empty builtins with a custom pattern",
            json!({
                "redaction": {
                    "builtins": [],
                    "custom_patterns": [{"name": "ticket", "regex": "T-[0-9]+"}]
                },
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "empty pattern set in hash_only",
            json!({
                "mode": "hash_only",
                "redaction": {"builtins": []},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "empty pattern set in hash_only under path_mode redact",
            json!({
                "mode": "hash_only",
                "redaction": {"builtins": []},
                "privacy": {"path_mode": "redact"},
                "sink": sink(json!({}))
            }),
            false,
        ),
        // ---- the hash_secret minimum is counted in CHARACTERS ----
        (
            "hash_secret of 16 characters",
            json!({
                "redaction": {"hash_secret": "fleet-stable-key"},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "hash_secret of 8 characters / 16 bytes",
            json!({
                "redaction": {"hash_secret": short_multibyte_secret},
                "sink": sink(json!({}))
            }),
            false,
        ),
        // ---- numeric and string grammar ----
        (
            "max_records_per_minute at the u64 ceiling",
            json!({
                "sampling": {"max_records_per_minute": u64::MAX},
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "negative max_records_per_minute",
            json!({
                "sampling": {"max_records_per_minute": -1},
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "ftp collector scheme",
            json!({
                "sink": sink(json!({"endpoint_url": "ftp://audit.example.com/ingest"}))
            }),
            false,
        ),
        (
            "uppercase https collector scheme",
            json!({
                "sink": sink(json!({"endpoint_url": "HTTPS://audit.example.com/ingest"}))
            }),
            true,
        ),
        (
            "empty collector url",
            json!({
                "sink": sink(json!({"endpoint_url": ""}))
            }),
            false,
        ),
        // ---- gRPC method shape ----
        (
            "duplicate grpc text_fields",
            json!({
                "grpc": grpc(json!({
                    "request_type": "test.Hello",
                    "text_fields": ["name", "name"]
                })),
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "distinct grpc text_fields",
            json!({
                "grpc": grpc(json!({
                    "request_type": "test.Hello",
                    "text_fields": ["name"]
                })),
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "null grpc text_fields",
            json!({
                "grpc": grpc(json!({
                    "request_type": "test.Hello",
                    "text_fields": null
                })),
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "empty grpc text_fields",
            json!({
                "grpc": grpc(json!({
                    "request_type": "test.Hello",
                    "text_fields": []
                })),
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "grpc method with only a null request_type",
            json!({
                "grpc": grpc(json!({"request_type": null})),
                "sink": sink(json!({}))
            }),
            false,
        ),
        (
            "grpc method with a null request_type and a real response_type",
            json!({
                "grpc": grpc(json!({
                    "request_type": null,
                    "response_type": "test.Reply"
                })),
                "sink": sink(json!({}))
            }),
            true,
        ),
        (
            "grpc max_messages null",
            json!({
                "grpc": {
                    "descriptor_path": "/nonexistent/ferrum-descriptor.bin",
                    "methods": {"/test.Greeter/SayHello": {"request_type": "test.Hello"}},
                    "max_messages": null
                },
                "sink": sink(json!({}))
            }),
            true,
        ),
    ];

    for (label, config, expected_valid) in cases {
        assert_component_validity(&spec, "AiTranscriptAuditConfig", &config, expected_valid);
        let runtime_valid = AiTranscriptAudit::new(&config, http_client.clone()).is_ok();
        assert_eq!(
            runtime_valid, expected_valid,
            "runtime/schema admission drift for {label}: {config}"
        );
    }

    // Checks ordinary JSON Schema cannot express. The component documents each
    // of these as runtime-only; the contract here is that the schema stays
    // permissive while the constructor still refuses, so a schema-driven editor
    // never blocks a valid config and never claims one of these is admissible.
    let runtime_only: Vec<(&str, serde_json::Value)> = vec![
        (
            "max_entry_bytes below the worst-case serialized-record contract",
            json!({
                "limits": {"max_entry_bytes": 1},
                "sink": sink(json!({}))
            }),
        ),
        (
            "buffer_max_bytes below the max_entry_bytes retained charge",
            json!({
                "limits": {"max_entry_bytes": 16777216, "buffer_max_bytes": 65536},
                "sink": sink(json!({}))
            }),
        ),
        (
            "capture limits over the cross-field aggregate",
            json!({
                "limits": {
                    "max_request_bytes": 1048576,
                    "max_response_bytes": 1048576,
                    "max_stream_capture_bytes": 1048576
                },
                "sink": sink(json!({}))
            }),
        ),
        (
            "custom pattern that is not a valid Rust regex",
            json!({
                "redaction": {"custom_patterns": [{"name": "bad", "regex": "([a-z"}]},
                "sink": sink(json!({}))
            }),
        ),
        (
            "cleartext collector without the loopback opt-in",
            json!({
                "sink": sink(json!({"endpoint_url": "http://127.0.0.1:9000/ingest"}))
            }),
        ),
        (
            "cleartext non-loopback collector with the loopback opt-in",
            json!({
                "sink": sink(json!({
                    "endpoint_url": "http://audit.example.com/ingest",
                    "allow_insecure_loopback": true
                }))
            }),
        ),
        (
            "collector url carrying userinfo credentials",
            json!({
                "sink": sink(json!({"endpoint_url": "https://u:p@audit.example.com/x"}))
            }),
        ),
        (
            "sink header template referencing the process environment",
            json!({
                "sink": sink(json!({"custom_headers": {"X-A": "${FERRUM_DB_URL}"}}))
            }),
        ),
        (
            "two grpc method keys that normalize to one path",
            json!({
                "grpc": {
                    "descriptor_path": "/nonexistent/ferrum-descriptor.bin",
                    "methods": {
                        "/test.Greeter/SayHello": {"request_type": "test.Hello"},
                        "test.Greeter/SayHello": {"request_type": "test.Hello"}
                    }
                },
                "sink": sink(json!({}))
            }),
        ),
        (
            "grpc text_fields that differ only by segment whitespace",
            json!({
                "grpc": grpc(json!({
                    "request_type": "test.Hello",
                    "text_fields": ["outer.name", "outer . name"]
                })),
                "sink": sink(json!({}))
            }),
        ),
    ];

    for (label, config) in runtime_only {
        assert_component_validity(&spec, "AiTranscriptAuditConfig", &config, true);
        assert!(
            AiTranscriptAudit::new(&config, http_client.clone()).is_err(),
            "runtime must still refuse the documented runtime-only check {label}: {config}"
        );
    }
}

/// `grpc.max_message_bytes` / `grpc.max_messages` carry immutable deployment
/// maxima. The decoded-byte scan budget bounds decoded payload, not frame
/// count, so an unbounded `max_messages` would let a body of legal zero-length
/// frames drive an unbounded frame vector. Schema `maximum` and the runtime
/// ceilings must agree, and both must accept exactly the bound and refuse one
/// above it.
#[tokio::test]
async fn ai_transcript_audit_grpc_frame_budgets_are_bounded_in_openapi() {
    use ferrum_edge::plugins::ai_transcript_audit::{
        AiTranscriptAudit, HARD_MAX_GRPC_MAX_MESSAGE_BYTES, HARD_MAX_GRPC_MAX_MESSAGES,
    };
    use ferrum_edge::plugins::utils::PluginHttpClient;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let grpc_properties = spec
        .pointer("/components/schemas/AiTranscriptAuditConfig/properties/grpc/properties")
        .expect("missing AiTranscriptAuditConfig grpc properties");

    for (field, hard_max) in [
        ("max_message_bytes", HARD_MAX_GRPC_MAX_MESSAGE_BYTES),
        ("max_messages", HARD_MAX_GRPC_MAX_MESSAGES),
    ] {
        assert_eq!(
            grpc_properties[field]["maximum"],
            json!(hard_max),
            "grpc.{field} schema maximum must match the runtime deployment ceiling"
        );
        assert_eq!(grpc_properties[field]["minimum"], json!(1));
    }

    let descriptor_path = format!(
        "{}/tests/fixtures/test_validator.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    let http_client = PluginHttpClient::default();
    let config = |field: &str, value: usize| {
        let mut config = json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/ingest"
            },
            "grpc": {
                "descriptor_path": descriptor_path,
                "methods": {
                    "/test.Greeter/SayHello": {"request_type": "test.HelloRequest"}
                }
            }
        });
        config["grpc"][field] = json!(value);
        config
    };

    for (field, hard_max) in [
        ("max_message_bytes", HARD_MAX_GRPC_MAX_MESSAGE_BYTES),
        ("max_messages", HARD_MAX_GRPC_MAX_MESSAGES),
    ] {
        for (value, expected_valid) in [(hard_max, true), (hard_max + 1, false)] {
            let instance = config(field, value);
            assert_component_validity(&spec, "AiTranscriptAuditConfig", &instance, expected_valid);
            assert_eq!(
                AiTranscriptAudit::new(&instance, http_client.clone()).is_ok(),
                expected_valid,
                "runtime/schema parity drift for grpc.{field} = {value}"
            );
        }
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

    for field in [
        "max_tracked_keys",
        "min_limit",
        "initial_limit",
        "max_limit",
        "min_samples",
        "increase_step",
    ] {
        assert_eq!(
            schema["properties"][field]["maximum"],
            json!(u64::MAX),
            "{field} must publish the u64 maximum"
        );
        assert_eq!(schema["properties"][field]["format"], json!("uint64"));
        let mut at_max = serde_json::Map::new();
        at_max.insert(field.to_string(), json!(u64::MAX));
        assert_component_validity(
            &spec,
            "AdaptiveConcurrencyConfig",
            &serde_json::Value::Object(at_max),
            true,
        );
        let above_json = format!(r#"{{"{field}": 18446744073709551616}}"#);
        let above = serde_json::from_str(&above_json)
            .unwrap_or_else(|error| panic!("{field} 2^64 JSON number parses: {error}"));
        assert_component_validity(&spec, "AdaptiveConcurrencyConfig", &above, false);
        let mut admitted = json!({
            "min_limit": 1,
            "initial_limit": 32,
            "max_limit": 1024,
            "max_tracked_keys": 10000,
            "min_samples": 20,
            "increase_step": 1
        });
        admitted[field] = json!(u64::MAX);
        if matches!(field, "min_limit" | "initial_limit") {
            admitted["initial_limit"] = json!(u64::MAX);
            admitted["max_limit"] = json!(u64::MAX);
        }
        ferrum_edge::plugins::validate_plugin_config("adaptive_concurrency", &admitted)
            .unwrap_or_else(|error| panic!("{field}=u64::MAX must be admitted: {error}"));
        assert!(
            ferrum_edge::plugins::validate_plugin_config("adaptive_concurrency", &above).is_err(),
            "{field} above u64 must be rejected at runtime"
        );
    }
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
                "destination": {
                    "backend_host": "api.internal",
                    "backend_port": 443,
                    "backend_tls": {"verify_server_certificate": false}
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
                "retry": {"retry_on_connect_failur": false}
            }]
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "retry": {"backoff": {"fixed": {"delay_ms": 25, "delay_millis": 25}}}
            }]
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "retry": {
                    "backoff": {
                        "exponential": {"base_ms": 10, "max_ms": 100, "max_millis": 100}
                    }
                }
            }]
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "retry": {
                    "backoff": {
                        "exponentiall": {"base_ms": 10, "max_ms": 100}
                    }
                }
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

    assert_eq!(
        spec.pointer("/components/schemas/MeshRouteRetryConfig/additionalProperties"),
        Some(&json!(false)),
        "MeshRouteRetryConfig must stay closed"
    );
    assert_eq!(
        spec.pointer("/components/schemas/MeshRouteBackendTlsConfig/additionalProperties"),
        Some(&json!(false)),
        "MeshRouteBackendTlsConfig must stay closed"
    );
    assert_eq!(
        spec.pointer("/components/schemas/MeshRouteBackoffStrategy/oneOf/0/additionalProperties"),
        Some(&json!(false)),
        "fixed backoff wrapper must stay closed"
    );
    assert_eq!(
        spec.pointer("/components/schemas/MeshRouteBackoffStrategy/oneOf/1/additionalProperties"),
        Some(&json!(false)),
        "exponential backoff wrapper must stay closed"
    );
    assert_eq!(
        spec.pointer(
            "/components/schemas/MeshRouteBackoffStrategy/oneOf/0/properties/fixed/additionalProperties"
        ),
        Some(&json!(false)),
        "fixed backoff payload must stay closed"
    );
    assert_eq!(
        spec.pointer(
            "/components/schemas/MeshRouteBackoffStrategy/oneOf/1/properties/exponential/additionalProperties"
        ),
        Some(&json!(false)),
        "exponential backoff payload must stay closed"
    );

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

    // Component/runtime parity corpus (issue #5374): tagged match cardinality,
    // accepted optional nulls, constructor normalization, destination /
    // backend-TLS pairing, and numeric boundaries. Every entry must get the
    // SAME verdict from the JSON Schema component and from the constructor.
    fn parity_rule(patch: serde_json::Value) -> serde_json::Value {
        let mut rule = json!({
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "api.internal", "backend_port": 8443}
        });
        if let (Some(base), Some(fields)) = (rule.as_object_mut(), patch.as_object()) {
            for (key, value) in fields {
                base.insert(key.clone(), value.clone());
            }
        }
        json!({"rules": [rule]})
    }

    for (label, config, accepted) in [
        (
            "methods_no_operator",
            parity_rule(json!({"match": {"methods": [{}]}})),
            false,
        ),
        (
            "methods_two_operators",
            parity_rule(json!({"match": {"methods": [{"exact": "GET", "prefix": "G"}]}})),
            false,
        ),
        (
            "methods_empty_exact",
            parity_rule(json!({"match": {"methods": [{"exact": ""}]}})),
            false,
        ),
        (
            "methods_space_in_exact",
            parity_rule(json!({"match": {"methods": ["GET POST"]}})),
            false,
        ),
        (
            "methods_lowercase_exact",
            parity_rule(json!({"match": {"methods": ["get"]}})),
            true,
        ),
        (
            "methods_extension_exact",
            parity_rule(json!({"match": {"methods": [{"exact": "M-SEARCH"}]}})),
            true,
        ),
        (
            "methods_regex_is_not_a_token",
            parity_rule(json!({"match": {"methods": [{"regex": "^GET POST$"}]}})),
            true,
        ),
        (
            "headers_no_operator",
            parity_rule(json!({"match": {"headers": {"x-a": {}}}})),
            false,
        ),
        (
            "headers_invalid_name",
            parity_rule(json!({"match": {"headers": {"x bad": "v"}}})),
            false,
        ),
        (
            "headers_empty_name",
            parity_rule(json!({"match": {"headers": {"": "v"}}})),
            false,
        ),
        (
            "match_uri_null",
            parity_rule(json!({"match": {"methods": ["GET"], "uri": null}})),
            true,
        ),
        (
            "match_authority_null",
            parity_rule(json!({"match": {"methods": ["GET"], "authority": null}})),
            true,
        ),
        (
            "match_source_namespace_empty",
            parity_rule(json!({"match": {"source_namespace": ""}})),
            false,
        ),
        (
            "match_ignore_uri_case_without_uri",
            parity_rule(json!({"match": {"methods": ["GET"], "ignore_uri_case": true}})),
            false,
        ),
        (
            "rule_fault_null_is_accepted",
            parity_rule(json!({"fault": null})),
            true,
        ),
        (
            "rule_rewrite_null_is_accepted",
            parity_rule(json!({"rewrite": null})),
            true,
        ),
        (
            "rule_redirect_null_is_accepted",
            parity_rule(json!({"redirect": null})),
            true,
        ),
        (
            "fault_delay_null_with_abort",
            parity_rule(json!({"fault": {
                "delay": null,
                "abort": {"status_code": 503, "percentage": 1.0}
            }})),
            true,
        ),
        (
            "fault_abort_grpc_status_null",
            parity_rule(json!({"fault": {"abort": {
                "status_code": 503,
                "percentage": 1.0,
                "grpc_status": null
            }}})),
            true,
        ),
        (
            "destination_backend_port_overflow",
            parity_rule(json!({"destination": {
                "backend_host": "api.internal",
                "backend_port": 65536
            }})),
            false,
        ),
        (
            "destination_host_without_port",
            parity_rule(json!({"destination": {"backend_host": "api.internal"}})),
            false,
        ),
        (
            "destination_port_without_host",
            parity_rule(json!({"destination": {"backend_port": 8443}})),
            false,
        ),
        (
            "destination_upstream_with_direct_backend",
            parity_rule(json!({"destination": {
                "upstream_id": "api",
                "backend_host": "api.internal",
                "backend_port": 8443
            }})),
            false,
        ),
        (
            "destination_empty",
            parity_rule(json!({"destination": {}})),
            false,
        ),
        (
            "destination_backend_host_with_embedded_port",
            parity_rule(json!({"destination": {
                "backend_host": "api.internal:8443",
                "backend_port": 8443
            }})),
            false,
        ),
        (
            "destination_backend_host_bare_ipv6",
            parity_rule(json!({"destination": {"backend_host": "::1", "backend_port": 8443}})),
            true,
        ),
        (
            "destination_backend_host_bracketed_ipv6",
            parity_rule(json!({"destination": {
                "backend_host": "[2001:db8::1]",
                "backend_port": 8443
            }})),
            true,
        ),
        (
            "backend_tls_client_cert_without_key",
            parity_rule(json!({"destination": {
                "backend_host": "api.internal",
                "backend_port": 8443,
                "backend_tls": {"client_cert_path": "/tls/client.pem"}
            }})),
            false,
        ),
        (
            "backend_tls_without_direct_backend",
            parity_rule(json!({"destination": {
                "upstream_id": "api",
                "backend_tls": {"sni": "api.internal"}
            }})),
            false,
        ),
        (
            "timeout_ms_negative",
            parity_rule(json!({"timeout_ms": -1})),
            false,
        ),
        (
            "timeout_ms_zero_is_no_timeout",
            parity_rule(json!({"timeout_ms": 0})),
            true,
        ),
        (
            "retry_max_retries_over_bound",
            parity_rule(json!({"retry": {"max_retries": 999}})),
            false,
        ),
        (
            "retry_status_code_below_bound",
            parity_rule(json!({"retry": {"retryable_status_codes": [99]}})),
            false,
        ),
        (
            "retry_methods_lowercase_normalize",
            parity_rule(json!({"retry": {"retryable_methods": ["get"]}})),
            true,
        ),
        (
            "retry_backoff_over_bound",
            parity_rule(json!({"retry": {"backoff": {"fixed": {"delay_ms": 300_001}}}})),
            false,
        ),
        (
            "redirect_scheme_uppercase_normalize",
            parity_rule(json!({"redirect": {"scheme": "HTTPS"}})),
            true,
        ),
        (
            "redirect_scheme_unsupported",
            parity_rule(json!({"redirect": {"scheme": "ftp"}})),
            false,
        ),
        (
            "redirect_port_with_derive_port",
            parity_rule(json!({"redirect": {
                "port": 8443,
                "derive_port": "FROM_REQUEST_PORT"
            }})),
            false,
        ),
        (
            "minimal_redirect_rule",
            json!({"rules": [{"redirect": {}}]}),
            true,
        ),
        (
            "empty_match_without_route_action",
            json!({"rules": [{"destination": {"upstream_id": "api"}}]}),
            false,
        ),
        (
            "action_only_catch_all",
            json!({"rules": [{
                "match": {},
                "destination": {"backend_host": "v1.svc", "backend_port": 8080},
                "fault": {"abort": {"status_code": 503, "percentage": 100.0}}
            }]}),
            true,
        ),
    ] {
        assert_component_validity(&spec, "MeshRouteDispatchConfig", &config, accepted);
        assert_eq!(
            MeshRouteDispatch::new(&config).is_ok(),
            accepted,
            "runtime disagreed with the component schema for {label}"
        );
    }
}

#[test]
fn mtls_dns_admission_mutations_document_conflict_responses() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    for pointer in [
        "/paths/~1proxies/post/responses/409",
        "/paths/~1proxies~1{id}/put/responses/409",
        "/paths/~1proxies~1{id}/delete/responses/409",
        "/paths/~1consumers/post/responses/409",
        "/paths/~1consumers~1{id}/put/responses/409",
        "/paths/~1consumers~1{id}/delete/responses/409",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}/put/responses/409",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}/post/responses/409",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}/delete/responses/409",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}~1{index}/delete/responses/409",
        "/paths/~1plugins~1config/post/responses/409",
        "/paths/~1plugins~1config~1{id}/put/responses/409",
        "/paths/~1plugins~1config~1{id}/delete/responses/409",
        "/paths/~1api-specs/post/responses/409",
        "/paths/~1api-specs~1{id}/put/responses/409",
        "/paths/~1api-specs~1{id}/delete/responses/409",
    ] {
        assert!(
            spec.pointer(pointer).is_some(),
            "mTLS DNS admission mutation is missing 409 response: {pointer}"
        );
    }
}

#[test]
fn delete_proxy_cleanup_orphaned_upstream_query_has_openapi_parity() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let param = spec
        .pointer("/components/parameters/CleanupOrphanedUpstream")
        .expect("CleanupOrphanedUpstream parameter");
    assert_eq!(param["name"], "cleanup_orphaned_upstream");
    assert_eq!(param["in"], "query");
    assert_eq!(param["required"], false);
    assert_eq!(param["schema"]["type"], "boolean");
    assert_eq!(param["schema"]["default"], true);
    let param_desc = param["description"]
        .as_str()
        .expect("cleanup_orphaned_upstream description");
    assert!(
        param_desc.contains("false") && param_desc.contains("400"),
        "parameter must document the opt-out and the 400: {param_desc}"
    );

    let delete = spec
        .pointer("/paths/~1proxies~1{id}/delete")
        .expect("DELETE /proxies/{id}");
    let params = delete["parameters"]
        .as_array()
        .expect("DELETE /proxies/{id} parameters");
    assert!(
        params.iter().any(|parameter| {
            parameter["$ref"] == "#/components/parameters/CleanupOrphanedUpstream"
        }),
        "DELETE /proxies/{{id}} must declare cleanup_orphaned_upstream: {params:?}"
    );
    let desc = delete["description"]
        .as_str()
        .expect("DELETE /proxies/{id} description");
    assert!(
        desc.contains("cleanup_orphaned_upstream=false") && desc.contains("409"),
        "DELETE /proxies/{{id}} must document the opt-out and the DELETE /upstreams 409 pair: {desc}"
    );
    let four_hundred = delete["responses"]["400"]["description"]
        .as_str()
        .expect("DELETE /proxies/{id} 400 description");
    assert!(
        four_hundred.contains("cleanup_orphaned_upstream"),
        "DELETE /proxies/{{id}} 400 must name the strict-parse flag: {four_hundred}"
    );

    let upstream_desc = spec["paths"]["/upstreams/{id}"]["delete"]["description"]
        .as_str()
        .expect("DELETE /upstreams/{id} description");
    assert!(
        upstream_desc
            .contains("Upstream is referenced by one or more proxies and cannot be deleted"),
        "DELETE /upstreams/{{id}} must name the proxy-reference 409: {upstream_desc}"
    );
    assert!(
        upstream_desc.contains("cleanup_orphaned_upstream=false"),
        "DELETE /upstreams/{{id}} must point at the proxy-delete opt-out: {upstream_desc}"
    );
}

#[test]
fn admin_referential_delete_conflicts_have_openapi_parity() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let consumer_409 = spec
        .pointer("/paths/~1consumers~1{id}/delete/responses/409")
        .expect("DELETE /consumers/{id} must document 409");
    let consumer_desc = consumer_409["description"]
        .as_str()
        .expect("DELETE /consumers/{id} 409 description");
    assert!(
        consumer_desc.contains(
            "Consumer is referenced by one or more access_control plugin_configs and cannot be deleted"
        ),
        "DELETE /consumers/{{id}} 409 must name the access_control error string: {consumer_desc}"
    );

    let upstream_409 = spec
        .pointer("/paths/~1upstreams~1{id}/delete/responses/409")
        .expect("DELETE /upstreams/{id} must document 409");
    let upstream_desc = upstream_409["description"]
        .as_str()
        .expect("DELETE /upstreams/{id} 409 description");
    assert!(
        upstream_desc
            .contains("Upstream is referenced by one or more proxies and cannot be deleted"),
        "DELETE /upstreams/{{id}} 409 must name the proxy-reference error string: {upstream_desc}"
    );
    assert!(
        upstream_desc.contains(
            "Upstream is referenced by a mesh_route_dispatch plugin_config and cannot be deleted"
        ),
        "DELETE /upstreams/{{id}} 409 must name the mesh_route_dispatch error string: {upstream_desc}"
    );

    let proxy_desc = spec["paths"]["/proxies/{id}"]["delete"]["description"]
        .as_str()
        .expect("DELETE /proxies/{id} description");
    assert!(
        proxy_desc.contains("hand-owned") && proxy_desc.contains("orphan-cleaned"),
        "DELETE /proxies/{{id}} must document hand-owned upstream orphan cleanup: {proxy_desc}"
    );
}

#[test]
fn plugin_graph_delete_rejections_have_openapi_parity() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for pointer in [
        "/paths/~1proxies~1{id}/delete/responses/400",
        "/paths/~1plugins~1config~1{id}/delete/responses/400",
    ] {
        let response = spec
            .pointer(pointer)
            .unwrap_or_else(|| panic!("plugin-graph DELETE is missing 400 response: {pointer}"));
        assert_eq!(
            response["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Error"
        );
        assert!(
            response["description"]
                .as_str()
                .is_some_and(|description| description.contains("plugin-composition"))
        );
    }

    let api_spec_response = spec
        .pointer("/paths/~1api-specs~1{id}/delete/responses/422")
        .expect("API-spec DELETE is missing 422 response");
    assert_eq!(
        api_spec_response["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/ApiSpecValidationError"
    );
    assert!(
        api_spec_response["description"]
            .as_str()
            .is_some_and(|description| description.contains("plugin-composition"))
    );

    let resource_types = spec
        .pointer(
            "/components/schemas/ApiSpecValidationError/properties/failures/items/properties/resource_type/enum",
        )
        .and_then(serde_json::Value::as_array)
        .expect("API-spec validation resource types");
    assert!(resource_types.contains(&json!("plugin_composition")));
    assert!(resource_types.contains(&json!("upstream_graph")));
}

#[test]
fn namespace_admission_contention_is_documented_as_retryable() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    for pointer in [
        "/paths/~1batch/post/responses/503",
        "/paths/~1proxies/post/responses/503",
        "/paths/~1proxies~1{id}/put/responses/503",
        "/paths/~1proxies~1{id}/delete/responses/503",
        "/paths/~1consumers/post/responses/503",
        "/paths/~1consumers~1{id}/put/responses/503",
        "/paths/~1consumers~1{id}/delete/responses/503",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}/put/responses/503",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}/post/responses/503",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}/delete/responses/503",
        "/paths/~1consumers~1{consumer_id}~1credentials~1{cred_type}~1{index}/delete/responses/503",
        "/paths/~1plugins~1config/post/responses/503",
        "/paths/~1plugins~1config~1{id}/put/responses/503",
        "/paths/~1plugins~1config~1{id}/delete/responses/503",
        "/paths/~1upstreams/post/responses/503",
        "/paths/~1upstreams~1{id}/put/responses/503",
        "/paths/~1upstreams~1{id}/delete/responses/503",
        "/paths/~1api-specs/post/responses/503",
        "/paths/~1api-specs~1{id}/put/responses/503",
        "/paths/~1api-specs~1{id}/delete/responses/503",
        // Registry CRUD takes the same namespace-admission lease (issue #3955).
        "/paths/~1namespaces~1{name}/put/responses/503",
        "/paths/~1namespaces~1{name}/delete/responses/503",
    ] {
        assert_eq!(
            spec.pointer(pointer)
                .and_then(|value| value.get("$ref"))
                .and_then(serde_json::Value::as_str),
            Some("#/components/responses/NamespaceAdmissionUnavailable"),
            "namespace mutation is missing retryable 503 response: {pointer}"
        );
    }

    assert_eq!(
        spec.pointer("/paths/~1namespaces/post/responses/503/$ref")
            .and_then(serde_json::Value::as_str),
        Some("#/components/responses/NamespaceAdmissionPreCommitUnavailable"),
        "namespace create must use the cursor-free admission response"
    );

    let response = spec
        .pointer("/components/responses/NamespaceAdmissionUnavailable")
        .expect("missing namespace-admission response component");
    assert_eq!(response["headers"]["Retry-After"]["required"], false);
    assert_eq!(response["headers"]["Retry-After"]["schema"]["example"], 1);
    assert_eq!(
        response["content"]["application/json"]["example"]["error"],
        "Namespace mutation is temporarily unavailable; retry later"
    );
}

/// Namespace registry mutations need multi-document transactions, so a
/// standalone MongoDB deployment refuses them before mutating anything
/// (issue #3955). The refusal must be documented on all three write
/// operations, together with the `500` every persistence failure can produce.
#[test]
fn namespace_registry_mutations_document_atomicity_refusal_and_server_error() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for pointer in [
        "/paths/~1namespaces/post/responses",
        "/paths/~1namespaces~1{name}/put/responses",
        "/paths/~1namespaces~1{name}/delete/responses",
    ] {
        let responses = spec
            .pointer(pointer)
            .unwrap_or_else(|| panic!("missing namespace responses: {pointer}"));
        assert_eq!(
            responses["501"]["$ref"],
            "#/components/responses/NamespaceRegistryAtomicityUnsupported",
            "namespace mutation is missing the standalone-MongoDB refusal: {pointer}"
        );
        assert_eq!(
            responses["500"]["$ref"], "#/components/responses/InternalServerError",
            "namespace mutation is missing the persistence-failure 500: {pointer}"
        );
    }

    let response = spec
        .pointer("/components/responses/NamespaceRegistryAtomicityUnsupported")
        .expect("namespace registry atomicity refusal component");
    assert_eq!(
        response["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/NamespaceRegistryUnsupportedResponse"
    );
    let schema = spec
        .pointer("/components/schemas/NamespaceRegistryUnsupportedResponse")
        .expect("namespace registry atomicity refusal schema");
    assert_eq!(schema["required"], json!(["error", "detail"]));
}

#[test]
fn namespace_body_routes_document_payload_too_large() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for pointer in [
        "/paths/~1namespaces/post/responses/413",
        "/paths/~1namespaces~1{name}/put/responses/413",
    ] {
        assert_eq!(
            spec.pointer(pointer)
                .and_then(|value| value.get("$ref"))
                .and_then(serde_json::Value::as_str),
            Some("#/components/responses/PayloadTooLarge"),
            "bounded namespace request body is missing its documented 413: {pointer}"
        );
    }
}

#[test]
fn proxy_delete_documents_atomicity_refusal_for_standalone_mongodb() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let response = spec
        .pointer("/paths/~1proxies~1{id}/delete/responses/501")
        .expect("proxy DELETE is missing standalone MongoDB atomicity refusal");
    assert_eq!(
        response["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/ProxyDeleteAtomicityFailureResponse"
    );
    let schema = spec
        .pointer("/components/schemas/ProxyDeleteAtomicityFailureResponse")
        .expect("proxy delete atomicity refusal schema");
    assert_eq!(schema["required"], json!(["error", "detail"]));
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
            "hide_session_cookie",
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
fn transaction_debugger_schema_matches_closed_runtime_surface() {
    use ferrum_edge::plugins::transaction_debugger::{
        DEFAULT_BODY_CAPTURE_BYTES, MAX_BODY_CAPTURE_BYTES, TRANSACTION_DEBUGGER_CONFIG_KEYS,
        TransactionDebugger,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/TransactionDebuggerConfig")
        .expect("missing TransactionDebuggerConfig schema");

    assert_eq!(schema["additionalProperties"], false);
    let properties: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("transaction debugger properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime: BTreeSet<_> = TRANSACTION_DEBUGGER_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(properties, runtime, "OpenAPI/runtime key drift");

    for field in ["max_request_body_bytes", "max_response_body_bytes"] {
        assert_eq!(
            schema["properties"][field]["default"],
            json!(DEFAULT_BODY_CAPTURE_BYTES),
            "{field} default drift"
        );
        assert_eq!(
            schema["properties"][field]["maximum"],
            json!(MAX_BODY_CAPTURE_BYTES),
            "{field} maximum drift"
        );
        assert_eq!(schema["properties"][field]["minimum"], json!(1));
    }
    for field in ["log_request_body", "log_response_body"] {
        assert_eq!(schema["properties"][field]["default"], json!(false));
    }
    let header_items = &schema["properties"]["redacted_headers"]["items"];
    assert_eq!(header_items["minLength"], json!(1));
    assert_eq!(
        header_items["pattern"],
        json!("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    );
    let body_field_items = &schema["properties"]["redacted_body_fields"]["items"];
    assert_eq!(body_field_items["minLength"], json!(1));
    assert!(
        body_field_items.get("maxLength").is_none() || body_field_items["maxLength"].is_null(),
        "maxLength must not reject names that are 128 characters after trim"
    );
    assert_eq!(
        body_field_items["pattern"],
        json!("^\\s*\\S(?:[\\s\\S]{0,126}\\S)?\\s*$")
    );
    let admission_rules = schema["allOf"]
        .as_array()
        .expect("TransactionDebuggerConfig admission allOf");
    assert_eq!(admission_rules.len(), 4);

    let description = schema["description"]
        .as_str()
        .expect("TransactionDebuggerConfig description");
    for contract in [
        "never forces an ineligible message to buffer",
        "text/event-stream",
        "application/grpc",
        "redacted",
        "truncated",
        // The capture allow-list, the actual-length recheck, and the
        // fail-closed structured-body handling are security contracts, not
        // prose: they must stay mirrored in the published schema.
        "Content-Length is only an admission screen",
        "over_capture_limit",
        "XML and GraphQL are excluded",
    ] {
        assert!(
            description.contains(contract),
            "description missing `{contract}`"
        );
    }
    for withdrawn in ["application/xml", "application/graphql,", "+xml"] {
        assert!(
            !description.contains(withdrawn),
            "description still advertises withdrawn capturable media type `{withdrawn}`"
        );
    }

    let plugin_docs = include_str!("../../docs/plugins.md");
    for key in TRANSACTION_DEBUGGER_CONFIG_KEYS {
        assert!(
            plugin_docs.contains(&format!("`{key}`")),
            "docs/plugins.md transaction_debugger section missing `{key}`"
        );
    }
    for contract in [
        "<non-utf8-body-omitted>",
        "<malformed-structured-body-omitted>",
        "<over-capture-limit-body-omitted>",
        "over_capture_limit",
        "unknown_length",
        "typed request provenance",
        "metadata: {mode: omit}",
        "default unprojected",
    ] {
        assert!(
            plugin_docs.contains(contract),
            "docs/plugins.md missing transaction_debugger contract `{contract}`"
        );
    }
    assert!(
        !plugin_docs.contains("The plugin never dumps the complete metadata map."),
        "docs must not claim schema diagnostics omit the metadata map"
    );

    // Instance-based schema/runtime parity for constructor admission.
    let padded_body_field = format!(" {} ", "x".repeat(128));
    for valid in [
        json!({}),
        json!({"redacted_headers": []}),
        json!({"redacted_headers": ["x-internal-id"]}),
        json!({"redacted_body_fields": []}),
        json!({"schema": {}}),
        json!({
            "log_request_body": true,
            "redacted_body_fields": ["demo"]
        }),
        json!({
            "log_request_body": true,
            "log_response_body": true,
            "max_request_body_bytes": 256,
            "max_response_body_bytes": 256
        }),
        json!({
            "log_request_body": true,
            "redacted_body_fields": [padded_body_field]
        }),
    ] {
        assert_component_validity(&spec, "TransactionDebuggerConfig", &valid, true);
        TransactionDebugger::new(&valid)
            .unwrap_or_else(|error| panic!("schema-valid config {valid} failed runtime: {error}"));
    }
    // Named-schema existence is config-graph validation, not this component.
    assert_component_validity(
        &spec,
        "TransactionDebuggerConfig",
        &json!({"schema_ref": "absent"}),
        true,
    );

    for invalid in [
        json!({"max_request_body_bytes": 256}),
        json!({"log_response_body": false, "max_response_body_bytes": 256}),
        json!({"redacted_body_fields": ["demo"]}),
        json!({"redacted_headers": [""]}),
        json!({"redacted_headers": ["invalid header"]}),
        json!({"schema": {}, "schema_ref": "absent"}),
        json!({"unknown": true}),
        json!({"log_request_body": null}),
        json!({"log_request_body": true, "max_request_body_bytes": 0}),
        json!({"log_request_body": true, "max_request_body_bytes": 8193}),
        json!({
            "log_request_body": true,
            "redacted_body_fields": ["x".repeat(129)]
        }),
    ] {
        assert_component_validity(&spec, "TransactionDebuggerConfig", &invalid, false);
        assert!(
            TransactionDebugger::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }
}

#[test]
fn ws_frame_logging_schema_matches_runtime_admission_contract() {
    use ferrum_edge::plugins::ws_frame_logging::{
        DEFAULT_LOG_LEVEL, MAX_PAYLOAD_PREVIEW_BYTES, WS_FRAME_LOGGING_CONFIG_KEYS,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/WsFrameLoggingConfig")
        .expect("WsFrameLoggingConfig exists");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["log_level"]["default"],
        json!(DEFAULT_LOG_LEVEL)
    );
    assert_eq!(
        schema["properties"]["log_level"]["enum"],
        json!(["trace", "debug", "info", "warn"])
    );
    assert_eq!(
        schema["properties"]["payload_preview_bytes"]["maximum"],
        json!(MAX_PAYLOAD_PREVIEW_BYTES)
    );
    assert_eq!(
        schema["properties"]["payload_preview_bytes"]["minimum"],
        json!(0)
    );

    let documented: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime: BTreeSet<_> = WS_FRAME_LOGGING_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(documented, runtime, "OpenAPI/runtime key drift");

    let description = schema["description"]
        .as_str()
        .expect("WsFrameLoggingConfig description");
    for contract in [
        "OptionalFailOpen",
        "FERRUM_LOG_LEVEL=warn",
        "HTTP 400",
        "stricter than `warn`",
        "not clamped",
        "requires_ws_frame_hooks",
        "raw-copy tunnel",
    ] {
        assert!(
            description.contains(contract),
            "description missing `{contract}`"
        );
    }

    for valid in [
        json!({}),
        json!({"log_level": "warn"}),
        json!({"log_level": "info"}),
        json!({
            "include_payload_preview": true,
            "payload_preview_bytes": MAX_PAYLOAD_PREVIEW_BYTES
        }),
        json!({
            "include_payload_preview": false,
            "payload_preview_bytes": 0
        }),
    ] {
        assert_component_validity(&spec, "WsFrameLoggingConfig", &valid, true);
    }
    for invalid in [
        json!({"log_levle": "debug"}),
        json!({"log_level": "error"}),
        json!({"log_level": null}),
        json!({"payload_preview_bytes": MAX_PAYLOAD_PREVIEW_BYTES + 1}),
        json!({"include_payload_preview": true, "payload_preview_bytes": 0}),
        json!({"include_payload_preview": null}),
    ] {
        assert_component_validity(&spec, "WsFrameLoggingConfig", &invalid, false);
    }

    let plugin_config_desc = spec
        .pointer("/components/schemas/PluginConfigBase/properties/config/description")
        .and_then(|v| v.as_str())
        .expect("PluginConfigBase.config description");
    assert!(
        plugin_config_desc.contains("OptionalFailOpen"),
        "generic PluginConfig.config must document OptionalFailOpen omission"
    );
    assert!(
        plugin_config_desc.contains("HTTP 400"),
        "generic PluginConfig.config must distinguish strict Admin admission"
    );
    assert!(plugin_config_desc.contains("ws_frame_logging"));

    let plugin_docs = include_str!("../../docs/plugins.md");
    let docs_section = plugin_docs
        .split("### `ws_frame_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("ws_frame_logging docs section");
    for contract in [
        "HTTP 400",
        "stricter than `warn`",
        "diagnostic can repeat",
        "OptionalFailOpen",
    ] {
        assert!(
            docs_section.contains(contract),
            "ws_frame_logging docs missing `{contract}`"
        );
    }
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
    assert_eq!(
        schema["properties"]["grpc"]["properties"]["methods"]["propertyNames"]["pattern"],
        json!(
            r"^\s*/?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/[A-Za-z_][A-Za-z0-9_]*\s*$"
        )
    );
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
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/etc/ferrum/d.bin",
                "methods": {"/a.B/C": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/etc/ferrum/d.bin",
                "max_message_bytes": 1024,
                "max_messages": 4,
                "methods": {"/a.B/C": {"response_type": "a.R", "text_fields": ["x.y"]}}
            }
        }),
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
        // gRPC block is closed and both of its required fields are load-bearing.
        json!({"pii_patterns": ["email"], "grpc": {}}),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"methods": {"/a.B/C": {"response_type": "a.R"}}}
        }),
        json!({"pii_patterns": ["email"], "grpc": {"descriptor_path": "/d.bin"}}),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"descriptor_path": "/d.bin", "methods": {}}
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "method": {"/a.B/C": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"/a.B/C": {"response_type": "a.R", "fields": ["x"]}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"/a.B/C": {"text_fields": ["x"]}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "max_messages": 0,
                "methods": {"/a.B/C": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"/a..B/C": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"/1Service/Method": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"/a.B/C?x=1": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"not-a-path": {"response_type": "a.R"}}
            }
        }),
        // Runtime trims these three string surfaces and rejects an empty
        // result. The published schema must not advertise whitespace-only
        // values as admissible.
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": " \t ",
                "methods": {"/a.B/C": {"response_type": "a.R"}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {"/a.B/C": {"response_type": "\n "}}
            }
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/d.bin",
                "methods": {
                    "/a.B/C": {
                        "response_type": "a.R",
                        "text_fields": [" \r\n "]
                    }
                }
            }
        }),
    ] {
        assert_component_validity(&spec, "AiResponseGuardConfig", &invalid, false);
    }
}

#[test]
fn security_headers_schema_rejects_unknown_top_level_and_hsts_keys() {
    use ferrum_edge::plugins::security_headers::SecurityHeaders;

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

    for valid in [
        json!({}),
        json!({"override_existing": null}),
        json!({"hsts": {"max_age": null, "include_subdomains": null, "preload": null}}),
        json!({"hsts": {"max_age": u64::MAX}}),
    ] {
        assert_component_validity(&spec, "SecurityHeadersConfig", &valid, true);
        SecurityHeaders::new(&valid).unwrap_or_else(|error| {
            panic!("schema-valid security_headers config {valid} failed runtime: {error}")
        });
    }

    for invalid in [
        json!({"set": {"Content-Length": "ordinary"}}),
        json!({"set": {"Connection": "close"}}),
        json!({"set": {"Keep-Alive": "timeout=5"}}),
        json!({"set": {"Proxy-Authenticate": "Basic"}}),
        json!({"set": {"Proxy-Connection": "close"}}),
        json!({"set": {"TE": "trailers"}}),
        json!({"set": {"Trailer": "X-Checksum"}}),
        json!({"set": {"Transfer-Encoding": "chunked"}}),
        json!({"set": {"Upgrade": "websocket"}}),
        json!({
            "content_type_options": false,
            "frame_options": false,
            "referrer_policy": false,
            "remove": []
        }),
        json!({
            "content_type_options": "",
            "frame_options": "",
            "referrer_policy": "",
            "remove": null
        }),
    ] {
        assert_component_validity(&spec, "SecurityHeadersConfig", &invalid, false);
        assert!(
            SecurityHeaders::new(&invalid).is_err(),
            "schema-invalid security_headers config passed runtime: {invalid}"
        );
    }

    assert_eq!(
        schema["properties"]["hsts"]["oneOf"][3]["properties"]["max_age"]["maximum"],
        json!(u64::MAX)
    );
    let above_hsts = serde_json::from_str(r#"{"hsts":{"max_age":18446744073709551616}}"#)
        .expect("2^64 JSON number parses");
    assert_component_validity(&spec, "SecurityHeadersConfig", &above_hsts, false);
    assert!(
        SecurityHeaders::new(&above_hsts).is_err(),
        "hsts.max_age above u64 must be rejected at runtime"
    );
    assert!(
        SecurityHeaders::new(&json!({"hsts": {"max_age": 1.0}})).is_err(),
        "hsts.max_age JSON floats must be rejected at runtime"
    );
}

#[test]
fn admin_metrics_openapi_accepts_typed_mode_breaker_and_health_fixtures() {
    use ferrum_edge::admin::metrics::{
        ADMIN_METRICS_MODES, AdminMetricsUnhealthyTarget, contract_fixtures,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let docs = include_str!("../../docs/admin_metrics.md");
    let mode_enum = spec
        .pointer("/components/schemas/AdminMetricsGateway/properties/mode/enum")
        .expect("AdminMetricsGateway.mode enum");
    assert_eq!(
        mode_enum,
        &json!(["database", "file", "cp", "dp", "mesh", "node_agent"])
    );
    let config_source_status_enum = spec
        .pointer("/components/schemas/AdminMetricsGateway/properties/config_source_status/enum")
        .expect("AdminMetricsGateway.config_source_status enum");
    assert_eq!(
        config_source_status_enum,
        &json!(["online", "offline", "n/a"])
    );
    assert!(
        docs.contains("\"offline\"")
            && docs.contains("db_available")
            && docs.contains("no DB-backed config source"),
        "docs/admin_metrics.md must document online/offline/n/a via db_available"
    );
    for mode in ADMIN_METRICS_MODES {
        assert!(
            docs.contains(mode),
            "docs/admin_metrics.md must document mode {mode}"
        );
    }

    let breaker = spec
        .pointer("/components/schemas/AdminMetricsCircuitBreaker/properties/target")
        .expect("circuit breaker target property");
    assert!(breaker.get("type").is_some());
    assert!(
        docs.contains("per-target (upstream)") && docs.contains("direct-backend (per-proxy)"),
        "docs must describe direct vs per-target breaker semantics"
    );

    let unhealthy = spec
        .pointer("/components/schemas/AdminMetricsUnhealthyTarget")
        .expect("AdminMetricsUnhealthyTarget component");
    assert_eq!(
        unhealthy["properties"]["type"]["enum"],
        json!(["active", "passive"])
    );
    assert!(docs.contains("`type` is `passive`"));
    assert!(docs.contains("`type` is `active`"));

    for fixture in contract_fixtures() {
        let instance = serde_json::to_value(&fixture).expect("fixture serializes");
        assert_component_validity(&spec, "AdminMetrics", &instance, true);
    }

    // Conditional semantics: passive requires proxy_id; active requires upstream_id.
    assert_component_validity(
        &spec,
        "AdminMetricsUnhealthyTarget",
        &serde_json::to_value(AdminMetricsUnhealthyTarget::active(
            "ferrum",
            "upstream-a",
            "10.0.0.1:80",
            1,
        ))
        .expect("active"),
        true,
    );
    assert_component_validity(
        &spec,
        "AdminMetricsUnhealthyTarget",
        &serde_json::to_value(AdminMetricsUnhealthyTarget::passive(
            "ferrum",
            "proxy-a",
            "10.0.0.1:80",
            1,
        ))
        .expect("passive"),
        true,
    );
    assert_component_validity(
        &spec,
        "AdminMetricsUnhealthyTarget",
        &json!({
            "namespace": "ferrum",
            "target": "10.0.0.1:80",
            "type": "passive",
            "since_epoch_ms": 1
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "AdminMetricsUnhealthyTarget",
        &json!({
            "proxy_id": "proxy-a",
            "target": "10.0.0.1:80",
            "type": "active",
            "since_epoch_ms": 1
        }),
        false,
    );
    assert_component_validity(
        &spec,
        "AdminMetricsGateway",
        &json!({
            "mode": "injector",
            "ferrum_version": "0.0.0",
            "uptime_seconds": 0,
            "total_requests": 0,
            "status_codes_total": {},
            "requests_per_second": 0,
            "status_codes_per_second": {},
            "metrics_window_seconds": 0,
            "proxy_count": 0,
            "consumer_count": 0,
            "upstream_count": 0,
            "plugin_config_count": 0
        }),
        false,
    );
}

#[test]
fn tcp_connection_throttle_schema_docs_and_source_share_the_lifecycle_contract() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/TcpConnectionThrottleConfig")
        .expect("TcpConnectionThrottleConfig component exists");
    let schema_text = serde_json::to_string(schema).unwrap();
    let plugin_docs = include_str!("../../docs/plugins.md");
    let cache_docs = include_str!("../../docs/cache_management.md");
    let source = include_str!("../../src/plugins/tcp_connection_throttle.rs");
    let metrics_source = include_str!("../../src/admin/metrics.rs");

    assert_eq!(schema["additionalProperties"], false);
    assert_component_validity(
        &spec,
        "TcpConnectionThrottleConfig",
        &json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
        true,
    );
    assert_component_validity(
        &spec,
        "TcpConnectionThrottleConfig",
        &json!({"max_connections_per_key": 1, "cleanup_intervl_seconds": 60}),
        false,
    );
    assert_component_validity(
        &spec,
        "TcpConnectionThrottleConfig",
        &json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 86401}),
        false,
    );
    assert_eq!(
        schema["properties"]["max_connections_per_key"]["maximum"],
        json!(u64::MAX)
    );
    assert_component_validity(
        &spec,
        "TcpConnectionThrottleConfig",
        &json!({"max_connections_per_key": u64::MAX}),
        true,
    );
    let above = serde_json::from_str(r#"{"max_connections_per_key": 18446744073709551616}"#)
        .expect("2^64 JSON number parses");
    assert_component_validity(&spec, "TcpConnectionThrottleConfig", &above, false);
    ferrum_edge::plugins::validate_plugin_config(
        "tcp_connection_throttle",
        &json!({"max_connections_per_key": u64::MAX}),
    )
    .expect("u64::MAX connection limit must be admitted");
    assert!(
        ferrum_edge::plugins::validate_plugin_config("tcp_connection_throttle", &above).is_err(),
        "connection limit above u64 must be rejected at runtime"
    );
    for text in [schema_text.as_str(), plugin_docs, cache_docs] {
        assert!(
            text.contains("process-local"),
            "missing process-local scope"
        );
        assert!(
            text.contains("residual"),
            "missing residual sweep semantics"
        );
        assert!(text.contains("inline"), "missing inline removal semantics");
    }
    assert!(schema_text.contains("UDP/DTLS"));
    assert!(plugin_docs.contains("attachment to any other protocol is rejected"));
    assert!(source.contains("DashMap::with_shard_amount"));
    assert!(source.contains("entry.remove()"));
    assert!(!source.contains("tcp_connection_throttle.key"));
    assert!(metrics_source.contains(r#"enforcement_scope: "process_local""#));
    assert!(metrics_source.contains(r#"replica_limit_behavior: "configured_limit_per_replica""#));

    let status_schema = spec
        .pointer("/components/schemas/AdminMetricsTcpConnectionThrottle")
        .expect("AdminMetricsTcpConnectionThrottle component exists");
    assert_eq!(
        status_schema["properties"]["enforcement_scope"]["enum"][0],
        "process_local"
    );
    assert_eq!(
        status_schema["properties"]["replica_limit_behavior"]["enum"][0],
        "configured_limit_per_replica"
    );
}

#[test]
fn spec_expose_schema_matches_strict_runtime_null_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::spec_expose::SpecExpose;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/SpecExposeConfig")
        .expect("SpecExposeConfig component exists");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["spec_url"]));
    assert_eq!(
        schema["properties"]["spec_url"]["pattern"],
        r"^\s*https?://[^/@?#]+(?:[/?#].*)?\s*$"
    );
    assert_eq!(
        schema["properties"]["content_type"]["pattern"],
        r"^[\u0009\u0020-\u007E]*[!-~][\u0009\u0020-\u007E]*$"
    );
    assert_eq!(
        schema["properties"]["cache_ttl_seconds"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schema["properties"]["max_response_body_bytes"]["maximum"],
        json!(u64::MAX)
    );
    for (field, scalar_type) in [
        ("content_type", "string"),
        ("tls_no_verify", "boolean"),
        ("cache_ttl_seconds", "integer"),
        ("max_response_body_bytes", "integer"),
    ] {
        assert_eq!(
            schema["properties"][field]["type"],
            json!([scalar_type, "null"]),
            "{field} must document the runtime's explicit-null default"
        );
    }

    assert_component_validity(
        &spec,
        "SpecExposeConfig",
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": null,
            "tls_no_verify": null,
            "cache_ttl_seconds": null,
            "max_response_body_bytes": null
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "SpecExposeConfig",
        &json!({ "spec_url": " https://example.com/spec " }),
        true,
    );
    SpecExpose::new(
        &json!({ "spec_url": " https://example.com/spec " }),
        PluginHttpClient::default(),
    )
    .expect("trimmed spec_url must remain accepted");

    for invalid in [
        json!({"spec_url": "https://example.com/openapi.yaml", "tls_no_verfy": true}),
        json!({"spec_url": "https://example.com/openapi.yaml", "content_type": 7}),
        json!({"spec_url": "https://example.com/openapi.yaml", "tls_no_verify": "false"}),
        json!({"spec_url": "https://example.com/openapi.yaml", "cache_ttl_seconds": -1}),
        json!({"spec_url": "https://example.com/openapi.yaml", "cache_ttl_seconds": 1e20}),
        json!({"spec_url": "https://example.com/openapi.yaml", "max_response_body_bytes": 0}),
        json!({"spec_url": "https://example.com/openapi.yaml", "max_response_body_bytes": 1e20}),
        json!({"spec_url": "https://example.com/openapi.yaml", "content_type": "   "}),
        json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": "application/yaml\r\nx-bad: yes"
        }),
        json!({"spec_url": "ftp://example.com/openapi.yaml"}),
        json!({"spec_url": "https:///openapi.yaml"}),
        json!({"spec_url": "https://user:pass@example.com/openapi.yaml"}),
        json!({"spec_url": "not a url"}),
    ] {
        assert_component_validity(&spec, "SpecExposeConfig", &invalid, false);
        assert!(
            SpecExpose::new(&invalid, PluginHttpClient::default()).is_err(),
            "schema-invalid spec_expose config unexpectedly passed runtime: {invalid}"
        );
    }

    let plugin_docs = include_str!("../../docs/plugins.md");
    assert!(plugin_docs.contains("must be nonempty after trim"));
    assert!(plugin_docs.contains("Must be greater than zero"));
    assert!(plugin_docs.contains("decoded to identity"));
    assert!(plugin_docs.contains("reject-path `after_proxy`"));
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

#[test]
fn fault_injection_schema_matches_runtime_contract() {
    use ferrum_edge::plugins::fault_injection::FaultInjectionPlugin;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let scope_pattern = spec
        .pointer(
            "/components/schemas/FaultInjectionConfig/properties/runtime_overlay_scope/pattern",
        )
        .and_then(serde_json::Value::as_str)
        .expect("runtime_overlay_scope pattern");
    assert!(
        scope_pattern.contains("\\u0085") || scope_pattern.contains('\u{0085}'),
        "scope pattern must encode Rust White_Space including U+0085, got {scope_pattern}"
    );
    assert!(
        !scope_pattern.contains("\\S"),
        "scope pattern must not use ECMAScript \\S: {scope_pattern}"
    );

    let body_type = spec
        .pointer("/components/schemas/FaultInjectionConfig/properties/abort/properties/body/type")
        .expect("abort.body type");
    assert!(
        body_type.as_array().is_some_and(|types| {
            types.iter().any(|value| value == "string") && types.iter().any(|value| value == "null")
        }),
        "abort.body must accept string or null, got {body_type}"
    );

    for valid in [
        json!({"abort": {"status_code": 503, "percentage": 100, "body": null}}),
        json!({"abort": {"status_code": 503, "percentage": 100, "body": ""}}),
        json!({"abort": {"status_code": 503, "percentage": 100}}),
        json!({"abort": {"status_code": 503, "percentage": 100, "body": "fault injected"}}),
        json!({
            "abort": {"status_code": 503, "percentage": 100},
            "runtime_overlay_scope": "checkout"
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 100},
            "runtime_overlay_scope": "\u{FEFF}"
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 100},
            "runtime_overlay_scope": null
        }),
        serde_json::from_str(r#"{"abort":{"status_code":503.0,"percentage":100}}"#)
            .expect("integral status"),
        serde_json::from_str(r#"{"delay":{"duration_ms":80.0,"percentage":100}}"#)
            .expect("integral duration"),
        serde_json::from_str(
            r#"{"abort":{"status_code":503,"percentage":100,"grpc_status":14.0}}"#,
        )
        .expect("integral grpc status"),
    ] {
        assert_component_validity(&spec, "FaultInjectionConfig", &valid, true);
        FaultInjectionPlugin::new(&valid)
            .unwrap_or_else(|error| panic!("schema-valid config {valid} failed runtime: {error}"));
    }

    for invalid in [
        json!({"abort": {"status_code": 503, "percentage": 100, "body": 1}}),
        json!({
            "abort": {"status_code": 503, "percentage": 100},
            "runtime_overlay_scope": "\u{0085}"
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 100},
            "runtime_overlay_scope": "\u{00A0}"
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 100},
            "runtime_overlay_scope": " \t "
        }),
        serde_json::from_str(r#"{"abort":{"status_code":503.1,"percentage":100}}"#)
            .expect("fractional status"),
    ] {
        assert_component_validity(&spec, "FaultInjectionConfig", &invalid, false);
        assert!(
            FaultInjectionPlugin::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("abort.body: null"));
    assert!(guide.contains("application/json"));
    assert!(guide.contains("text/plain"));
}

#[test]
fn request_termination_schema_matches_strict_runtime_contract() {
    use ferrum_edge::plugins::request_termination::{
        REQUEST_TERMINATION_CONFIG_KEYS, REQUEST_TERMINATION_TRIGGER_KEYS, RequestTermination,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/RequestTerminationConfig")
        .expect("RequestTerminationConfig component exists");

    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    let schema_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("RequestTerminationConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_fields: BTreeSet<_> = REQUEST_TERMINATION_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(schema_fields, runtime_fields);

    assert_eq!(schema["properties"]["status_code"]["minimum"], 200);
    assert_eq!(schema["properties"]["status_code"]["maximum"], 599);
    assert!(
        schema["properties"]["body"].get("default").is_none(),
        "body must not default to empty string — omission and \"\" differ at runtime"
    );
    assert_eq!(
        schema["properties"]["trigger"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["trigger"]["oneOf"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "trigger schema must encode the path-prefix and header alternatives"
    );
    let trigger_fields: BTreeSet<_> = schema["properties"]["trigger"]["properties"]
        .as_object()
        .expect("trigger properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_trigger: BTreeSet<_> = REQUEST_TERMINATION_TRIGGER_KEYS.iter().copied().collect();
    assert_eq!(trigger_fields, runtime_trigger);

    let request_termination_branch = spec
        .pointer("/components/schemas/PluginConfigBase/allOf/0/then/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("enabled PluginConfigBase allOf")
        .iter()
        .find(|entry| {
            entry
                .pointer("/if/properties/plugin_name/const")
                .and_then(serde_json::Value::as_str)
                == Some("request_termination")
        })
        .expect("request_termination PluginConfig branch");
    assert_eq!(
        request_termination_branch.pointer("/then/required"),
        Some(&json!(["config"]))
    );

    let status_desc = schema["properties"]["status_code"]["description"]
        .as_str()
        .unwrap_or_default();
    // Contract: out-of-range/informational statuses are rejected (not silently
    // coerced); 204/205/304 intentionally coerce the body to empty.
    assert!(status_desc.contains("rejected"));
    assert!(status_desc.contains("rather than coerced"));
    assert!(
        status_desc.contains("204")
            && status_desc.contains("205")
            && status_desc.contains("304")
            && status_desc.contains("empty body"),
        "status_code description must document no-body status empty-body coercion: {status_desc}"
    );
    let content_desc = schema["properties"]["content_type"]["description"]
        .as_str()
        .unwrap_or_default();
    assert!(content_desc.contains("+json") || content_desc.contains("structured"));
    assert!(
        content_desc.contains("not by arbitrary substring match"),
        "content_type description must document exact/suffix classification (not arbitrary substring): {content_desc}"
    );
    let message_desc = schema["properties"]["message"]["description"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message_desc.contains("unambiguous JSON") || message_desc.contains("parsed value"),
        "message description must document JSON passthrough: {message_desc}"
    );
    assert!(
        message_desc.contains("envelope") && message_desc.contains("fail safe"),
        "message description must document malformed-JSON envelope fail-safe: {message_desc}"
    );

    for valid in [
        json!({}),
        json!({"status_code": 451, "message": "unavailable"}),
        json!({"status_code": 204}),
        json!({"status_code": 204, "body": ""}),
        json!({"body": "", "message": "ignored"}),
        json!({
            "status_code": 403,
            "content_type": "application/hal+json",
            "trigger": {"path_prefix": "/admin"}
        }),
        json!({
            "trigger": {"header": "x-maintenance", "header_value": "1"}
        }),
        json!({
            "content_type": "application/json",
            "message": "{\"error\":\"scheduled-maintenance\"}"
        }),
        json!({
            "content_type": "application/json",
            "message": "{invalid"
        }),
        json!({"trigger": {"path_prefix": "*"}}),
        json!({"trigger": {"path_prefix": "/"}}),
        json!({
            "content_type": "application/xml",
            "body": "<ok/>",
            "message": "\u{0001}"
        }),
        serde_json::from_str(r#"{"status_code":503.0}"#).expect("integral JSON number"),
    ] {
        assert_component_validity(&spec, "RequestTerminationConfig", &valid, true);
        RequestTermination::new(&valid)
            .unwrap_or_else(|error| panic!("schema-valid config {valid} failed runtime: {error}"));
    }

    for invalid in [
        serde_json::Value::Null,
        json!([]),
        json!("enabled"),
        json!({"triger": {"path_prefix": "/admin"}}),
        json!({"status_code": 100}),
        json!({"status_code": 101}),
        json!({"status_code": 700}),
        json!({"status_code": null}),
        json!({"content_type": null}),
        json!({"content_type": ""}),
        json!({"content_type": "   "}),
        json!({"body": null}),
        json!({"message": null}),
        json!({"trigger": null}),
        json!({"trigger": {"path_prefix": null}}),
        json!({"trigger": {"path_prefix": ""}}),
        json!({"trigger": {"path_prefix": "admin"}}),
        json!({"trigger": {"path_prefix": "/a?b"}}),
        json!({"trigger": {"path_prefix": "/admin "}}),
        json!({"trigger": {"path_prefix": "/a/../b"}}),
        json!({"trigger": {"header": null}}),
        json!({"trigger": {"header": ""}}),
        json!({"trigger": {"header": "invalid name"}}),
        json!({"trigger": {"header": "x-policy", "header_value": null}}),
        json!({"trigger": {}}),
        json!({"trigger": {"path_prefix": "/a", "header": "x-policy"}}),
        json!({"trigger": {"path_prefix": "/a", "header_value": "1"}}),
        json!({"trigger": {"header_value": "1"}}),
        json!({"trigger": {"path_prefix": "/a", "extra": true}}),
        json!({"unknown": true}),
        json!({"status_code": 204, "body": "x"}),
        json!({"content_type": "application/xml", "message": "\u{0001}"}),
    ] {
        assert_component_validity(&spec, "RequestTerminationConfig", &invalid, false);
        assert!(
            RequestTermination::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("Configuration must be a top-level object."));
    assert!(guide.contains("unknown top-level or nested `trigger` keys are rejected"));
    assert!(guide.contains("explicit `null` is rejected for every property"));
    assert!(guide.contains("an empty trigger or a detached `header_value` is rejected"));
    assert!(guide.contains("`body: \"\"`"));
    assert!(guide.contains("XML 1.0"));
    assert!(guide.contains("individual field line"));
    assert!(guide.contains("unambiguous JSON value"));
    assert!(guide.contains("fail safe into that envelope"));
    assert!(guide.contains(r#"message: '{"error":"scheduled-maintenance"}'"#));
    assert!(guide.contains("trailers-only"));
    assert!(guide.contains("INTERNAL"));
    assert!(guide.contains("query delimiter"));
}

#[test]
fn response_caching_schema_matches_strict_runtime_contract() {
    use ferrum_edge::plugins::response_caching::{RESPONSE_CACHING_CONFIG_KEYS, ResponseCaching};
    use ferrum_edge::plugins::validate_plugin_config;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/ResponseCachingConfig")
        .expect("ResponseCachingConfig component exists");

    assert_eq!(schema["additionalProperties"], false);
    let schema_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("ResponseCachingConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_fields: BTreeSet<_> = RESPONSE_CACHING_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(
        schema_fields, runtime_fields,
        "response_caching OpenAPI/runtime key drift"
    );

    // Issue #2454: the published schema must express the runtime value domain.
    assert_eq!(schema["properties"]["max_entries"]["minimum"], json!(1));
    assert_eq!(
        schema["properties"]["max_entry_size_bytes"]["minimum"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["max_total_size_bytes"]["minimum"],
        json!(1)
    );
    // Issue #5144: `format: uint64` asserts no bound under Draft 2020-12, so
    // every unsigned field carries its explicit range. ttl_seconds keeps a zero
    // minimum because the runtime accepts 0.
    assert_eq!(schema["properties"]["ttl_seconds"]["minimum"], json!(0));
    assert_eq!(
        schema["properties"]["ttl_seconds"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schema["properties"]["max_entries"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schema["properties"]["max_entry_size_bytes"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schema["properties"]["max_total_size_bytes"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schema["properties"]["cacheable_methods"]["minItems"],
        json!(1)
    );
    // Issue #5144: the runtime admits only case-insensitive GET/HEAD, not every
    // RFC 9110 method token.
    assert_eq!(
        schema["properties"]["cacheable_methods"]["items"]["pattern"],
        json!("^([Gg][Ee][Tt]|[Hh][Ee][Aa][Dd])$")
    );
    // Issue #5144: `anonymous_caller_scope` is trimmed and ASCII-lowercased,
    // and `caller-address` is an accepted alias, so a canonical-only enum
    // rejected values the constructor admits.
    assert!(
        schema["properties"]["anonymous_caller_scope"]["enum"].is_null(),
        "a canonical-only enum cannot describe the normalized scope domain"
    );
    assert!(
        schema["properties"]["anonymous_caller_scope"]["pattern"].is_string(),
        "anonymous_caller_scope must publish its accepted spellings"
    );
    assert_eq!(
        schema["properties"]["cacheable_status_codes"]["minItems"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["cacheable_status_codes"]["items"]["minimum"],
        json!(200)
    );
    assert_eq!(
        schema["properties"]["cacheable_status_codes"]["items"]["maximum"],
        json!(599)
    );
    // GHSA-v7fj-73gm-h625: 206 and 304 have caching semantics the plugin does
    // not implement, so the schema must refuse them the same way the runtime
    // constructor does.
    assert_eq!(
        schema["properties"]["cacheable_status_codes"]["items"]["not"]["enum"],
        json!([206, 304])
    );
    assert_eq!(
        schema["properties"]["vary_by_headers"]["items"]["pattern"],
        json!("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    );

    let plugin_docs = include_str!("../../docs/plugins.md");
    let docs = plugin_docs
        .split("### `response_caching`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("response_caching docs section");
    for key in RESPONSE_CACHING_CONFIG_KEYS {
        assert!(
            docs.contains(&format!("`{key}`")),
            "docs/plugins.md response_caching section missing `{key}`"
        );
    }
    assert!(docs.contains("KeepLastKnownGood"));
    assert!(docs.contains("Unknown keys are rejected"));
    assert!(
        docs.contains("response_caching.<instance_id>"),
        "docs must describe per-instance request-staging isolation"
    );
    assert!(
        schema["description"]
            .as_str()
            .is_some_and(|d| d.contains("response_caching.<instance_id>")),
        "OpenAPI ResponseCachingConfig must describe per-instance staging isolation"
    );

    for valid in [
        json!({}),
        json!({"ttl_seconds": 60}),
        // Zero TTL remains supported by the runtime.
        json!({"ttl_seconds": 0}),
        // Positive capacity boundary values.
        json!({"max_entries": 1, "max_entry_size_bytes": 1, "max_total_size_bytes": 1}),
        // Method casing is accepted and uppercased by the runtime.
        json!({"cacheable_methods": ["get"]}),
        json!({"cacheable_methods": ["Head"]}),
        // Issue #5144: the normalized/alias scope spellings the constructor
        // admits must validate too.
        json!({"anonymous_caller_scope": "caller_address"}),
        json!({"anonymous_caller_scope": "caller-address"}),
        json!({"anonymous_caller_scope": " SHARED "}),
        json!({"anonymous_caller_scope": "Shared"}),
        // Status-code boundary values (1xx / 206 / 304 are excluded below).
        json!({"cacheable_status_codes": [200, 599]}),
        // An explicitly empty Vary list is accepted (no extra key dimensions).
        json!({"vary_by_headers": []}),
        json!({
            "ttl_seconds": 60,
            "max_entries": 100,
            "max_entry_size_bytes": 1024,
            "max_total_size_bytes": 4096,
            "cacheable_methods": ["GET", "HEAD"],
            "cacheable_status_codes": [200, 404],
            "respect_cache_control": true,
            "respect_no_cache": false,
            "vary_by_headers": ["x-tenant"],
            "cache_key_include_query": true,
            "cache_key_include_consumer": true,
            "add_cache_status_header": true,
            "invalidate_on_unsafe_methods": false
        }),
    ] {
        assert_component_validity(&spec, "ResponseCachingConfig", &valid, true);
        ResponseCaching::new(&valid)
            .unwrap_or_else(|error| panic!("schema-valid config {valid} failed runtime: {error}"));
        validate_plugin_config("response_caching", &valid).unwrap_or_else(|error| {
            panic!("shared admission rejected schema-valid {valid}: {error}")
        });
    }

    for invalid in [
        json!({"vary_by_header": ["x-tenant"]}),
        json!({"cache_key_include_consumr": true}),
        json!({"cache_key_include_quer": false}),
        json!({"respect_cache_contro": true}),
        json!({"respect_no_cach": true}),
        json!({"cacheable_status_code": [200]}),
        json!({"cacheable_method": ["GET"]}),
        json!({"ttl_second": 60}),
        json!({"max_entrie": 10}),
        json!({"max_entry_size_byte": 1024}),
        json!({"max_total_size_byte": 4096}),
        json!({"add_cache_status_heade": true}),
        json!({"invalidate_on_unsafe_method": true}),
        json!({
            "ttl_seconds": 60,
            "aaa_extra": true,
            "zzz_extra": false
        }),
        // Issue #2454 reproduction shapes: values the runtime constructor
        // rejects must also fail schema validation.
        json!({"max_entries": 0}),
        json!({"max_entry_size_bytes": 0}),
        json!({"max_total_size_bytes": 0}),
        json!({"cacheable_methods": []}),
        json!({"cacheable_methods": [""]}),
        json!({"cacheable_methods": ["bad method"]}),
        json!({"cacheable_status_codes": []}),
        json!({"cacheable_status_codes": [99]}),
        json!({"cacheable_status_codes": [600]}),
        // GHSA-v7fj-73gm-h625: interim, partial, and validator-only statuses
        // must fail admission in both the schema and the runtime constructor.
        json!({"cacheable_status_codes": [100]}),
        json!({"cacheable_status_codes": [199]}),
        json!({"cacheable_status_codes": [206]}),
        json!({"cacheable_status_codes": [304]}),
        json!({"cacheable_status_codes": [200, 206]}),
        json!({"vary_by_headers": [""]}),
        json!({"vary_by_headers": ["bad header"]}),
        // Issue #5144: body-bearing and non-retrieval methods are refused by
        // the constructor and must fail the schema too.
        json!({"cacheable_methods": ["POST"]}),
        json!({"cacheable_methods": ["OPTIONS"]}),
        json!({"cacheable_methods": ["GET", "POST"]}),
        // Negative and out-of-u64 unsigned scalars.
        json!({"ttl_seconds": -1}),
        json!({"max_entries": -1}),
        json!({"max_entry_size_bytes": -1}),
        json!({"max_total_size_bytes": -1}),
        // An unknown scope spelling stays refused by both.
        json!({"anonymous_caller_scope": "caller address"}),
        json!({"anonymous_caller_scope": "callerAddress"}),
        json!({"anonymous_caller_scope": ""}),
    ] {
        assert_component_validity(&spec, "ResponseCachingConfig", &invalid, false);
        assert!(
            ResponseCaching::new(&invalid).is_err(),
            "runtime accepted OpenAPI-invalid response_caching config: {invalid}"
        );
        assert!(
            validate_plugin_config("response_caching", &invalid).is_err(),
            "shared admission accepted OpenAPI-invalid response_caching config: {invalid}"
        );
    }

    // Issue #5144: an unsigned value beyond u64 cannot be written with `json!`,
    // so it is parsed from its literal wire form. JSON numbers that large are
    // carried as doubles, so the case is taken a full binade past u64::MAX
    // rather than at 2^64, where the two are indistinguishable in double
    // precision.
    for literal in [
        r#"{"ttl_seconds": 36893488147419103232}"#,
        r#"{"max_entries": 36893488147419103232}"#,
        r#"{"max_entry_size_bytes": 36893488147419103232}"#,
        r#"{"max_total_size_bytes": 36893488147419103232}"#,
    ] {
        let invalid: serde_json::Value =
            serde_json::from_str(literal).expect("oversized unsigned literal parses");
        assert_component_validity(&spec, "ResponseCachingConfig", &invalid, false);
        assert!(
            ResponseCaching::new(&invalid).is_err(),
            "runtime accepted an out-of-u64 response_caching value: {literal}"
        );
        assert!(
            validate_plugin_config("response_caching", &invalid).is_err(),
            "shared admission accepted an out-of-u64 response_caching value: {literal}"
        );
    }

    // Runtime scalar helpers treat null as "use default"; OpenAPI must expose
    // the same contract. Collection fields remain strict non-null arrays.
    for key in [
        "ttl_seconds",
        "max_entries",
        "max_entry_size_bytes",
        "max_total_size_bytes",
        "respect_cache_control",
        "respect_no_cache",
        "cache_key_include_query",
        "cache_key_include_consumer",
        "add_cache_status_header",
        "invalidate_on_unsafe_methods",
    ] {
        let mut config = json!({});
        config
            .as_object_mut()
            .expect("config object")
            .insert(key.to_string(), serde_json::Value::Null);
        assert_component_validity(&spec, "ResponseCachingConfig", &config, true);
        ResponseCaching::new(&config)
            .unwrap_or_else(|error| panic!("nullable scalar {key} failed runtime: {error}"));
    }
    for key in [
        "cacheable_methods",
        "cacheable_status_codes",
        "vary_by_headers",
    ] {
        let mut config = json!({});
        config
            .as_object_mut()
            .expect("config object")
            .insert(key.to_string(), serde_json::Value::Null);
        assert_component_validity(&spec, "ResponseCachingConfig", &config, false);
        assert!(
            ResponseCaching::new(&config).is_err(),
            "non-null list field {key} accepted null"
        );
    }
}

#[test]
fn response_mock_schema_matches_strict_runtime_contract() {
    use ferrum_edge::plugins::response_mock::{
        RESPONSE_MOCK_CONFIG_KEYS, RESPONSE_MOCK_RULE_KEYS, ResponseMock,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/ResponseMockConfig")
        .expect("ResponseMockConfig component exists");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["rules"]));
    let schema_fields: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("ResponseMockConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_fields: BTreeSet<_> = RESPONSE_MOCK_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(schema_fields, runtime_fields);

    let rule = &schema["properties"]["rules"]["items"];
    assert_eq!(rule["additionalProperties"], false);
    assert_eq!(rule["required"], json!(["path"]));
    let rule_fields: BTreeSet<_> = rule["properties"]
        .as_object()
        .expect("ResponseMock rule properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_rule_fields: BTreeSet<_> = RESPONSE_MOCK_RULE_KEYS.iter().copied().collect();
    assert_eq!(rule_fields, runtime_rule_fields);

    assert_eq!(rule["properties"]["path"]["minLength"], 1);
    assert_eq!(rule["properties"]["method"]["minLength"], 1);
    assert_eq!(
        rule["properties"]["method"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        rule["properties"]["method"]["pattern"],
        "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
    );
    let status_one_of = rule["properties"]["status_code"]["oneOf"]
        .as_array()
        .expect("status_code oneOf");
    assert_eq!(status_one_of.len(), 3);
    assert_eq!(status_one_of[0]["type"], "null");
    assert_eq!(status_one_of[1]["const"], 101);
    assert_eq!(status_one_of[2]["minimum"], 200);
    assert_eq!(status_one_of[2]["maximum"], 599);
    assert_eq!(
        rule["properties"]["headers"]["type"],
        json!(["object", "null"])
    );
    assert_eq!(
        rule["properties"]["headers"]["propertyNames"]["pattern"],
        "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
    );
    assert!(
        rule["properties"]["headers"]["propertyNames"]["not"]["pattern"]
            .as_str()
            .expect("protocol-managed header exclusion")
            .contains("[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]")
    );
    assert_eq!(
        rule["properties"]["headers"]["additionalProperties"]["type"],
        "string"
    );
    assert_eq!(
        rule["properties"]["body"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        rule["properties"]["delay_ms"]["type"],
        json!(["integer", "null"])
    );
    assert_eq!(rule["properties"]["delay_ms"]["minimum"], 0);
    assert_eq!(rule["properties"]["delay_ms"]["maximum"], 3600000);
    assert_eq!(
        schema["properties"]["passthrough_on_no_match"]["type"],
        json!(["boolean", "null"])
    );

    let description = schema["description"].as_str().expect("description");
    assert!(description.contains("exact (`=`)"));
    assert!(description.contains("host-only"));
    assert!(description.contains("WebSocket"));
    assert!(description.contains("frame stream"));
    assert!(
        description.contains("Native gRPC") && description.contains("unsupported"),
        "ResponseMockConfig must document native gRPC exclusion: {description}"
    );
    assert!(
        description.contains("204")
            && description.contains("205")
            && description.contains("304")
            && description.contains("HEAD"),
        "ResponseMockConfig must document HEAD/no-body wire constraints: {description}"
    );
    let status_desc = rule["properties"]["status_code"]["description"]
        .as_str()
        .expect("status_code description");
    assert!(
        status_desc.contains("informational") && status_desc.contains("rejected"),
        "status_code must document informational rejection: {status_desc}"
    );
    assert!(
        status_desc.contains("101") && status_desc.contains("200–599"),
        "status_code must document 101 + final range: {status_desc}"
    );
    assert!(
        status_desc.contains("ordinary HTTP request") && status_desc.contains("500"),
        "status_code must document the non-WebSocket 101 failure: {status_desc}"
    );
    let body_desc = rule["properties"]["body"]["description"]
        .as_str()
        .expect("body description");
    assert!(
        body_desc.contains("HEAD")
            && body_desc.contains("204")
            && body_desc.contains("Content-Length"),
        "body must document HEAD/no-body wire semantics: {body_desc}"
    );
    assert!(
        rule["properties"]["path"]["description"]
            .as_str()
            .expect("path description")
            .contains("exact (`=`)")
    );
    assert!(
        rule["properties"]["method"]["description"]
            .as_str()
            .expect("method description")
            .contains("HTTP method token")
    );

    for valid in [
        json!({"rules": [{"path": "/health", "body": "ok"}]}),
        json!({
            "passthrough_on_no_match": true,
            "rules": [{
                "method": "GET",
                "path": "/users",
                "status_code": 101,
                "headers": {"x-mock": "true", "content-type": "text/plain"},
                "body": "ok",
                "delay_ms": 0
            }]
        }),
        json!({
            "passthrough_on_no_match": null,
            "rules": [{
                "method": null,
                "path": "/",
                "status_code": null,
                "headers": null,
                "body": null,
                "delay_ms": null
            }]
        }),
        json!({
            "rules": [{
                "path": "/api/v1",
                "status_code": 599,
                "body": "exact-listen-path"
            }]
        }),
        json!({
            "rules": [{
                "path": "/empty",
                "status_code": 204,
                "body": "must-not-be-sent"
            }]
        }),
        json!({"rules": [{"path": "/", "delay_ms": 3600000}]}),
    ] {
        assert_component_validity(&spec, "ResponseMockConfig", &valid, true);
        assert!(
            ResponseMock::new(&valid).is_ok(),
            "schema-valid config unexpectedly failed runtime: {valid}"
        );
    }

    for invalid in [
        json!({
            "passthrough_on_no_mach": true,
            "rules": [{"path": "/health", "body": "ok"}]
        }),
        json!({
            "rules": [{"path": "/health", "status_cod": 503, "body": "unavailable"}]
        }),
        json!({"rules": [{"path": "", "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "method": "", "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "method": "BAD METHOD", "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 99, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 100, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 103, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 199, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 600, "body": "ok"}]}),
        json!({"rules": [{"path": "/", "delay_ms": -1}]}),
        json!({"rules": [{"path": "/", "delay_ms": 3600001}]}),
        json!({"rules": [{"body": "missing-path"}]}),
        json!({"rules": []}),
        json!({}),
        json!({
            "rules": [{
                "path": "/health",
                "headers": {"x-mock": 42}
            }]
        }),
        json!({
            "rules": [{
                "path": "/",
                "headers": {"Content-Length": "3"}
            }]
        }),
        json!({
            "rules": [{
                "path": "/",
                "headers": {"connection": "close"}
            }]
        }),
    ] {
        assert_component_validity(&spec, "ResponseMockConfig", &invalid, false);
        assert!(
            ResponseMock::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("Exact (`=/api/v1`)"));
    assert!(guide.contains("Host-only"));
    assert!(guide.contains("WebSocket handshake contract"));
    assert!(guide.contains("never establishes an upgraded frame stream"));
    assert!(guide.contains("Unknown top-level and per-rule keys are rejected"));
    assert!(guide.contains("Omitted or explicit `null`"));
    assert!(guide.contains("0`–`3600000"));
    assert!(guide.contains("Status / body wire semantics"));
    assert!(guide.contains("informational statuses"));
    assert!(guide.contains("Native gRPC exclusion"));
    assert!(guide.contains("native gRPC unsupported"));

    let features = include_str!("../../FEATURES.md");
    assert!(
        features.contains("relative only for prefix"),
        "FEATURES.md must qualify prefix-only relative mock paths"
    );
    assert!(
        features.contains("host-only"),
        "FEATURES.md must mention host-only full-path matching"
    );

    let matrix = include_str!("../../docs/plugin_execution_order.md");
    assert!(
        matrix.contains(
            "| `response_mock` | ✓ | | ✓ | | | Short-circuits HTTP and WebSocket upgrade handshakes"
        ),
        "protocol matrix must mark HTTP+WebSocket support and exclude native gRPC for response_mock"
    );
}

#[test]
fn ai_semantic_cache_schema_matches_runtime_unknown_key_contract() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::ai_semantic_cache::{
        AI_SEMANTIC_CACHE_CONFIG_KEYS, AI_SEMANTIC_CACHE_ROOT_POLICY_KEYS,
        AI_SEMANTIC_CACHE_SEMANTIC_POLICY_KEYS, AiSemanticCache,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiSemanticCacheConfig")
        .expect("AiSemanticCacheConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));

    let documented: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("AiSemanticCacheConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime: BTreeSet<_> = AI_SEMANTIC_CACHE_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(documented, runtime, "OpenAPI/runtime key drift");

    let grouped: BTreeSet<_> = AI_SEMANTIC_CACHE_ROOT_POLICY_KEYS
        .iter()
        .chain(AI_SEMANTIC_CACHE_SEMANTIC_POLICY_KEYS.iter())
        .chain(REDIS_PLUGIN_CONFIG_KEYS.iter())
        .chain(std::iter::once(&"redis_integrity_key"))
        .copied()
        .collect();
    assert_eq!(
        grouped, runtime,
        "documented key groups must equal the closed root allowlist"
    );

    let description = schema["description"]
        .as_str()
        .expect("AiSemanticCacheConfig description");
    assert!(description.contains("Unknown root"));
    assert!(description.contains("KeepLastKnownGood"));
    assert!(
        description.contains("ai_semantic_cache.<instance_id>"),
        "OpenAPI AiSemanticCacheConfig must describe per-instance staging isolation"
    );

    assert_component_validity(
        &spec,
        "AiSemanticCacheConfig",
        &json!({"ttl_seconds": 60, "cache_multimodal": "reject"}),
        true,
    );
    for invalid in [
        json!({"ttl_second": 60}),
        json!({"cache_multimoda": "reject"}),
        json!({"scope_by_consumr": false}),
        json!({"semantic_similarity_enable": true}),
        json!({"sync_mod": "redis"}),
        json!({"redis_ur": "redis://127.0.0.1:6379/0"}),
    ] {
        assert_component_validity(&spec, "AiSemanticCacheConfig", &invalid, false);
        assert!(
            AiSemanticCache::new(&invalid, PluginHttpClient::default()).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `ai_semantic_cache`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("ai_semantic_cache docs section");
    for key in AI_SEMANTIC_CACHE_CONFIG_KEYS {
        assert!(
            section.contains(&format!("`{key}`")),
            "docs/plugins.md ai_semantic_cache section missing `{key}`"
        );
    }
    assert!(section.contains("KeepLastKnownGood"));
    assert!(section.contains("unknown retention"));
    assert!(
        section.contains("ai_semantic_cache.<instance_id>"),
        "docs must describe per-instance request-staging isolation"
    );
    assert_eq!(
        schema["properties"]["semantic_vector_max_candidates"]["maximum"],
        json!(1024),
        "OpenAPI maximum must match the runtime HNSW candidate hard cap"
    );
    assert_eq!(
        schema["properties"]["semantic_vector_max_candidates"]["minimum"],
        json!(1),
        "OpenAPI minimum must match positive candidate admission"
    );
    assert!(
        section.contains("Hard maximum 1024"),
        "docs must advertise the semantic_vector_max_candidates hard maximum"
    );
    assert!(
        AiSemanticCache::new(
            &json!({
                "semantic_similarity_enabled": true,
                "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
                "semantic_vector_max_candidates": 1024,
            }),
            PluginHttpClient::default(),
        )
        .is_ok(),
        "OpenAPI maximum must be runtime-admissible"
    );
    assert!(
        AiSemanticCache::new(
            &json!({
                "semantic_similarity_enabled": true,
                "semantic_embedding_endpoint": "http://127.0.0.1:9/embeddings",
                "semantic_vector_max_candidates": 1025,
            }),
            PluginHttpClient::default(),
        )
        .is_err(),
        "values above the OpenAPI maximum must fail runtime admission"
    );
}

#[test]
fn ai_semantic_cache_openapi_redis_key_prefix_matches_runtime_namespace_default() {
    use ferrum_edge::config::types::DEFAULT_NAMESPACE;
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::ai_semantic_cache::AI_SEMANTIC_CACHE_DEFAULT_REDIS_KEY_SUFFIX;
    use ferrum_edge::plugins::utils::redis_rate_limiter::RedisConfig;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let prop = spec
        .pointer("/components/schemas/AiSemanticCacheConfig/properties/redis_key_prefix")
        .expect("AiSemanticCacheConfig.redis_key_prefix exists");

    // Namespace dependence cannot be expressed as a static OpenAPI default;
    // advertising one previously caused schema-driven clients to send
    // `ferrum:ai_semantic_cache` while omitted configs used `ferrum:ai_cache`.
    assert!(
        prop.get("default").is_none(),
        "redis_key_prefix must not advertise a static OpenAPI default; got {:?}",
        prop.get("default")
    );

    let description = prop["description"]
        .as_str()
        .expect("redis_key_prefix description");
    assert!(
        description.contains("{FERRUM_NAMESPACE}:ai_cache"),
        "OpenAPI must document the namespace-derived runtime default"
    );
    assert!(
        description.contains("ferrum:ai_cache"),
        "OpenAPI must state the default-namespace example accurately"
    );
    assert!(
        !description.contains("ai_semantic_cache"),
        "stale OpenAPI prefix ferrum:ai_semantic_cache must not remain in the description"
    );

    let http_client = PluginHttpClient::default();
    let namespace = http_client.namespace();
    assert_eq!(namespace, DEFAULT_NAMESPACE);
    assert_eq!(AI_SEMANTIC_CACHE_DEFAULT_REDIS_KEY_SUFFIX, "ai_cache");
    let expected_default = format!("{namespace}:{AI_SEMANTIC_CACHE_DEFAULT_REDIS_KEY_SUFFIX}");
    assert_eq!(expected_default, "ferrum:ai_cache");

    let redis = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0"
        }),
        &expected_default,
    )
    .expect("valid redis config")
    .expect("redis mode enabled");
    assert_eq!(
        redis.key_prefix, expected_default,
        "omitted redis_key_prefix must use the namespace-derived default"
    );

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `ai_semantic_cache`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("ai_semantic_cache docs section");
    assert!(
        section.contains("`\"{FERRUM_NAMESPACE}:ai_cache\"`")
            || section.contains("`{FERRUM_NAMESPACE}:ai_cache`"),
        "docs/plugins.md must keep the namespace-derived redis_key_prefix default"
    );
    assert!(
        section.contains("`ferrum:ai_cache`") || section.contains("ferrum:ai_cache"),
        "docs/plugins.md must keep the default-namespace redis_key_prefix example"
    );
    assert!(
        !section.contains("ferrum:ai_semantic_cache"),
        "docs must not advertise the stale OpenAPI prefix"
    );
}

#[test]
fn api_chargeback_schema_closes_unknown_keys() {
    use ferrum_edge::plugins::api_chargeback::API_CHARGEBACK_CONFIG_KEYS;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/ApiChargebackConfig")
        .expect("ApiChargebackConfig exists");
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["pricing_tiers"]["items"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        schema["properties"]["bandwidth_pricing"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        schema["properties"]["stream_connection_pricing"]["additionalProperties"],
        json!(false)
    );

    let documented: BTreeSet<_> = schema["properties"]
        .as_object()
        .expect("ApiChargebackConfig properties")
        .keys()
        .map(String::as_str)
        .collect();
    let runtime: BTreeSet<_> = API_CHARGEBACK_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(
        documented, runtime,
        "ApiChargebackConfig OpenAPI/runtime key drift"
    );

    let tier_props: BTreeSet<_> = schema["properties"]["pricing_tiers"]["items"]["properties"]
        .as_object()
        .expect("pricing_tiers item properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        tier_props,
        BTreeSet::from(["status_codes", "price_per_call"])
    );

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `api_chargeback`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("api_chargeback docs section");
    assert!(
        section.contains("Unknown top-level keys") || section.contains("unknown top-level keys"),
        "docs/plugins.md api_chargeback section must note unknown-key rejection"
    );
    assert!(
        section.contains("bandwith_pricing") || section.contains("silently"),
        "docs/plugins.md api_chargeback section must warn about misspelled pricing dimensions"
    );
}

#[test]
fn ai_rate_limiter_token_limit_required_without_default_contract() {
    use ferrum_edge::plugins::{PluginHttpClient, ai_rate_limiter::AiRateLimiter};

    // Contract (#2263): `token_limit` is required at runtime and must not publish
    // a misleading OpenAPI/docs default of 100000.
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AiRateLimiterConfig")
        .expect("AiRateLimiterConfig schema");

    assert_eq!(schema["required"], json!(["token_limit"]));
    assert!(
        schema["properties"]["token_limit"].get("default").is_none(),
        "token_limit must not publish a default — runtime requires the field"
    );
    let description = schema["properties"]["token_limit"]["description"]
        .as_str()
        .unwrap_or_default();
    assert!(
        description.to_ascii_lowercase().contains("required"),
        "OpenAPI description must label token_limit as required: {description}"
    );

    let err = AiRateLimiter::new(&json!({}), PluginHttpClient::default())
        .err()
        .expect("empty ai_rate_limiter config must fail");
    assert!(
        err.contains("token_limit"),
        "runtime must reject missing token_limit: {err}"
    );
    AiRateLimiter::new(&json!({"token_limit": 100000}), PluginHttpClient::default())
        .expect("explicit token_limit must construct");

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `ai_rate_limiter`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("ai_rate_limiter docs section");
    assert!(
        section.contains("| `token_limit` | Integer | *(required)* |"),
        "docs must label token_limit as required"
    );
    assert!(
        !section.contains("| `token_limit` | Integer | `100000` |"),
        "docs must not claim a 100000 default for token_limit"
    );
}

/// GHSA-8f27-23x9-f825: the published contract must state the HTTP-only
/// applicability rather than implying the limiter enforces native gRPC budgets.
#[test]
fn ai_rate_limiter_advertises_http_only_protocol_contract() {
    use ferrum_edge::plugins::{
        Plugin, PluginHttpClient, ProxyProtocol, ai_rate_limiter::AiRateLimiter,
    };

    let plugin =
        AiRateLimiter::new(&json!({"token_limit": 1000}), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let description = spec["components"]["schemas"]["AiRateLimiterConfig"]["description"]
        .as_str()
        .expect("AiRateLimiterConfig description");
    assert!(
        description.contains("HTTP-only"),
        "OpenAPI must advertise HTTP-only attachment for ai_rate_limiter: {description}"
    );
    assert!(
        description.contains("Native gRPC is unsupported"),
        "OpenAPI must retract the inert native-gRPC support claim: {description}"
    );

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `ai_rate_limiter`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("ai_rate_limiter docs section");
    assert!(
        section.contains("**This plugin is HTTP-only.**"),
        "docs must declare the HTTP-only protocol scope"
    );
    assert!(
        section.contains("**gRPC-Web is also unsupported.**"),
        "docs must state that framed gRPC-Web is not charged as JSON AI traffic"
    );

    let order = include_str!("../../docs/plugin_execution_order.md");
    assert!(
        order.contains("| `ai_rate_limiter` | ✓ | | | | |"),
        "protocol matrix row must show HTTP only for ai_rate_limiter"
    );
}

#[test]
fn ai_rate_limiter_provider_enum_matches_runtime() {
    use ferrum_edge::plugins::{PluginHttpClient, ai_rate_limiter::AiRateLimiter};

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/AiRateLimiterConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("AiRateLimiterConfig schema compiles");

    let provider_schema =
        spec["components"]["schemas"]["AiRateLimiterConfig"]["properties"]["provider"].clone();
    // Issue #5317: the constructor trims Unicode whitespace and lower-cases the
    // value, which an `enum` cannot express — it rejected normalized spellings
    // the gateway admits. The accepted-spelling pattern replaces it.
    assert!(
        provider_schema.get("enum").is_none(),
        "provider must publish an accepted-spelling pattern, not a canonical-only enum"
    );
    assert!(
        provider_schema["pattern"].is_string(),
        "provider must publish an accepted-spelling pattern"
    );

    let enum_values = [
        "auto",
        "openai",
        "anthropic",
        "google",
        "cohere",
        "mistral",
        "bedrock",
        "tgi",
    ];
    for supported in &enum_values {
        let config = json!({ "token_limit": 100000, "provider": supported });
        assert!(
            validator.validate(&config).is_ok(),
            "provider '{supported}' should be accepted by the schema"
        );
        AiRateLimiter::new(&config, PluginHttpClient::default())
            .unwrap_or_else(|err| panic!("runtime must accept provider '{supported}': {err}"));
    }

    // Normalized spellings the constructor admits must validate too.
    for normalized in &[" OPENAI ", "OpenAi", "\tTgi\n", "  bedrock"] {
        let config = json!({ "token_limit": 100000, "provider": normalized });
        assert!(
            validator.validate(&config).is_ok(),
            "normalized provider '{normalized}' should be accepted by the schema"
        );
        AiRateLimiter::new(&config, PluginHttpClient::default())
            .unwrap_or_else(|err| panic!("runtime must accept provider '{normalized}': {err}"));
    }

    for rejected in &[
        "gemini",
        "vertex",
        "openai_compatible",
        "gpt",
        "",
        " ",
        "open ai",
    ] {
        let config = json!({ "token_limit": 100000, "provider": rejected });
        assert!(
            validator.validate(&config).is_err(),
            "provider '{rejected}' should be rejected by the schema"
        );
        let err = AiRateLimiter::new(&config, PluginHttpClient::default())
            .err()
            .unwrap_or_else(|| panic!("runtime must reject provider '{rejected}'"));
        assert!(
            err.contains("provider"),
            "runtime error for '{rejected}' should mention provider: {err}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `ai_rate_limiter`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("ai_rate_limiter docs section");
    assert!(
        section.contains("`google`"),
        "docs must clarify Gemini/Vertex payloads use google"
    );
    assert!(
        section.contains("`bedrock`"),
        "docs must enumerate bedrock as an accepted provider"
    );
    assert!(
        section.contains("`tgi`"),
        "docs must enumerate tgi as an accepted provider (GHSA-rxj9-f483-g53f)"
    );
}

#[test]
fn body_validator_schema_is_closed_and_matches_the_runtime_key_set() {
    use ferrum_edge::plugins::body_validator::{
        BODY_VALIDATOR_CONFIG_KEYS, BODY_VALIDATOR_PROTOBUF_METHOD_KEYS,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/BodyValidatorConfig")
        .expect("BodyValidatorConfig schema");

    // Unknown keys must be refused by the published schema too, not just the
    // runtime constructor (GHSA-w7x7-ppx9-5v74).
    assert_eq!(schema["additionalProperties"], json!(false));

    let method_entry = schema
        .pointer("/properties/protobuf_method_messages/additionalProperties")
        .expect("protobuf_method_messages value schema");
    assert_eq!(method_entry["additionalProperties"], json!(false));

    // Runtime allow-list ↔ OpenAPI property parity, so a typo cannot drift
    // back in through either side alone.
    let mut documented: Vec<String> = schema["properties"]
        .as_object()
        .expect("BodyValidatorConfig properties")
        .keys()
        .cloned()
        .collect();
    let mut runtime: Vec<String> = BODY_VALIDATOR_CONFIG_KEYS
        .iter()
        .map(|key| (*key).to_string())
        .collect();
    documented.sort();
    runtime.sort();
    assert_eq!(
        documented, runtime,
        "BodyValidatorConfig properties must match the runtime allow-list"
    );

    let mut documented: Vec<String> = method_entry["properties"]
        .as_object()
        .expect("protobuf method entry properties")
        .keys()
        .cloned()
        .collect();
    let mut runtime: Vec<String> = BODY_VALIDATOR_PROTOBUF_METHOD_KEYS
        .iter()
        .map(|key| (*key).to_string())
        .collect();
    documented.sort();
    runtime.sort();
    assert_eq!(
        documented, runtime,
        "protobuf method entry keys must match the runtime allow-list"
    );

    assert_eq!(
        schema["properties"]["json_schema_draft"]["enum"],
        json!(["draft2020-12", "draft7"])
    );
}

/// Issue #5122: the published `BodyValidatorConfig` schema must accept exactly
/// the configurations the runtime constructor admits.
///
/// Two node-local dependencies stay runtime-only and are deliberately not
/// represented statically: the descriptor file must exist, and every configured
/// message type must resolve inside it. Everything else — rule presence,
/// non-empty schemas/strings/map entries, unsigned bounds, media-type and
/// Clark-notation shape, and gRPC method-path selectors — is asserted in both
/// directions so a generated client cannot build a configuration the gateway
/// then refuses.
#[test]
fn body_validator_schema_admits_exactly_what_the_constructor_admits() {
    use ferrum_edge::plugins::body_validator::BodyValidator;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for config in [
        // No validation rule at all.
        json!({}),
        json!({"validate_xml": false}),
        json!({"response_validate_xml": false}),
        json!({"required_fields": []}),
        // Present but unusable rule values.
        json!({"json_schema": {}}),
        json!({"response_json_schema": {}}),
        json!({"required_fields": [""]}),
        json!({"response_required_fields": [""]}),
        json!({"required_xml_elements": ["two words"]}),
        json!({"required_xml_elements": ["{unclosed"]}),
        json!({"response_required_xml_elements": ["two words"]}),
        // Out-of-domain integers.
        json!({"validate_xml": true, "xml_max_entities": -1}),
        json!({"validate_xml": true, "grpc_max_decompressed_size_bytes": -1}),
        // Malformed media types.
        json!({"validate_xml": true, "content_types": ["application"]}),
        json!({"validate_xml": true, "content_types": [""]}),
        json!({"validate_xml": true, "response_content_types": ["json"]}),
        // Protobuf cross-field shape.
        json!({"protobuf_request_type": "audit.Message"}),
        json!({"protobuf_response_type": "audit.Message"}),
        json!({"protobuf_descriptor_path": ""}),
        json!({"protobuf_descriptor_path": "/srv/audit.bin"}),
        json!({
            "protobuf_descriptor_path": "/srv/audit.bin",
            "protobuf_method_messages": {}
        }),
        json!({
            "protobuf_descriptor_path": "/srv/audit.bin",
            "protobuf_method_messages": {"/audit.Service/Echo": {}}
        }),
        json!({
            "protobuf_descriptor_path": "/srv/audit.bin",
            "protobuf_method_messages": {
                "audit.Service/Echo": {"request": "audit.Message"}
            }
        }),
    ] {
        assert!(
            BodyValidator::validate_config(&config).is_err(),
            "runtime admission must reject {config}"
        );
        assert_component_validity(&spec, "BodyValidatorConfig", &config, false);
    }

    for config in [
        json!({"validate_xml": true}),
        json!({"response_validate_xml": true}),
        json!({"required_fields": ["name"]}),
        json!({"response_required_fields": ["id"]}),
        json!({"json_schema": {"type": "object"}}),
        json!({"response_json_schema": {"type": "object"}}),
        json!({"required_xml_elements": ["item", "{}item"]}),
        json!({"response_required_xml_elements": ["{urn:x}item"]}),
        // An empty media list means "every valid media type", and an explicit
        // zero cap disables the decompressed ceiling; both must survive.
        json!({"validate_xml": true, "content_types": []}),
        json!({"validate_xml": true, "xml_max_entities": 0}),
        json!({
            "validate_xml": true,
            "content_types": ["application/json; charset=utf-8"]
        }),
        json!({
            "protobuf_descriptor_path": "/srv/audit.bin",
            "protobuf_request_type": "audit.Message"
        }),
        json!({
            "protobuf_descriptor_path": "/srv/audit.bin",
            "protobuf_response_type": "audit.Message"
        }),
        json!({
            "protobuf_descriptor_path": "/srv/audit.bin",
            "protobuf_method_messages": {
                "/audit.Service/Echo": {"request": "audit.Message"}
            }
        }),
    ] {
        BodyValidator::validate_config(&config)
            .unwrap_or_else(|error| panic!("runtime must accept {config}: {error}"));
        assert_component_validity(&spec, "BodyValidatorConfig", &config, true);
    }
}

/// Advisory GHSA-8594-2xhc-8g38: the observability sinks whose endpoint may
/// embed a reusable credential must document that contract, and the
/// `insert_query_params` credential-name rejection must be stated in the spec
/// the same way the runtime enforces it.
///
/// The runtime side of this pairing lives in
/// `tests/unit/plugins/api_chargeback_sink_tests.rs`
/// (`insert_query_params_reject_credential_bearing_names`); together they keep
/// schema prose and validation from drifting apart.
#[test]
fn observability_sink_endpoint_schemas_document_credential_redaction() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let http_logging = spec
        .pointer("/components/schemas/HttpLoggingConfig/properties/endpoint_url/description")
        .and_then(|value| value.as_str())
        .expect("http_logging endpoint_url description");
    let transcript = spec
        .pointer(
            "/components/schemas/AiTranscriptAuditConfig/properties/sink/properties/endpoint_url/description",
        )
        .and_then(|value| value.as_str())
        .expect("ai_transcript_audit sink.endpoint_url description");

    for (plugin, description) in [
        ("http_logging", http_logging),
        ("ai_transcript_audit", transcript),
    ] {
        assert!(
            description.to_ascii_lowercase().contains("userinfo"),
            "{plugin} endpoint_url must document userinfo rejection: {description}"
        );
        assert!(
            description.contains("/redacted"),
            "{plugin} endpoint_url must document the structurally redacted diagnostic form: {description}"
        );
    }

    let params = spec
        .pointer(
            "/components/schemas/ApiChargebackSinkConfig/properties/clickhouse/properties/insert_query_params/description",
        )
        .and_then(|value| value.as_str())
        .expect("api_chargeback_sink insert_query_params description");
    // Exact names and substring markers rejected by `validate_query_params`.
    for rejected in [
        "user",
        "password",
        "access_token",
        "session_id",
        "apikey",
        "api_key",
        "credential",
        "passwd",
        "secret",
        "token",
    ] {
        assert!(
            params.contains(rejected),
            "insert_query_params description must name the rejected `{rejected}`: {params}"
        );
    }
    assert!(
        params.contains("password_ref"),
        "insert_query_params description must point at the supported channel: {params}"
    );
    assert!(
        params.contains("/redacted"),
        "insert_query_params description must document the redacted diagnostic form: {params}"
    );
    assert!(
        params.contains("every durable request") && params.contains("user/profile default"),
        "insert_query_params description must document the profile-default durability pin: {params}"
    );
}

/// Config-database mutations that complete through
/// `AdminState::complete_live_config_mutation_after_commit` after a durable
/// commit. Mapped from the boxed helper call sites (CRUD, credentials, batch,
/// restore, API specs) plus `complete_namespace_registry_mutation` (served
/// rename / cascade delete). `createNamespace` is excluded: it writes no
/// `config_changes` row and never waits. Namespace mutations stay on the
/// synchronous path and do not accept `?apply=async`.
///
/// `(operation_id, synchronous success statuses, documents deferred 202)`
const LIVE_APPLIED_CONFIG_MUTATIONS: &[(&str, &[&str], bool)] = &[
    ("batchCreate", &["201"], true),
    ("restoreConfig", &["200"], true),
    ("createProxy", &["201"], true),
    ("updateProxy", &["200"], true),
    ("deleteProxy", &["204"], true),
    ("createConsumer", &["201"], true),
    ("updateConsumer", &["200"], true),
    ("deleteConsumer", &["204"], true),
    ("updateConsumerCredentials", &["200"], true),
    ("appendConsumerCredential", &["200"], true),
    ("deleteConsumerCredentials", &["204"], true),
    ("deleteConsumerCredentialByIndex", &["200"], true),
    ("createPluginConfig", &["201"], true),
    ("updatePluginConfig", &["200"], true),
    ("deletePluginConfig", &["204"], true),
    ("createUpstream", &["201"], true),
    ("updateUpstream", &["200"], true),
    ("deleteUpstream", &["204"], true),
    ("createGatewayTrustBundle", &["201"], true),
    ("updateGatewayTrustBundle", &["200"], true),
    ("deleteGatewayTrustBundle", &["204"], true),
    ("submitApiSpec", &["201"], true),
    ("replaceApiSpec", &["200"], true),
    ("deleteApiSpec", &["204"], true),
    ("updateNamespace", &["200"], false),
    ("deleteNamespace", &["204"], false),
];

const CONFIG_CURSOR_HEADER_REF: &str = "#/components/headers/X-Ferrum-Config-Cursor";
const LIVE_APPLY_MODE_PARAM_REF: &str = "#/components/parameters/LiveApplyMode";

fn resolve_openapi_value<'a>(
    spec: &'a serde_json::Value,
    value: &'a serde_json::Value,
) -> &'a serde_json::Value {
    match value.get("$ref").and_then(serde_json::Value::as_str) {
        Some(reference) => {
            let pointer = reference.strip_prefix('#').unwrap_or_else(|| {
                panic!("external OpenAPI reference is unsupported: {reference}")
            });
            spec.pointer(pointer)
                .unwrap_or_else(|| panic!("unresolved OpenAPI reference: {reference}"))
        }
        None => value,
    }
}

fn response_declares_config_cursor_header(
    spec: &serde_json::Value,
    response: &serde_json::Value,
) -> bool {
    let resolved = resolve_openapi_value(spec, response);
    match resolved.pointer("/headers/X-Ferrum-Config-Cursor") {
        Some(header) => {
            header.get("$ref").and_then(serde_json::Value::as_str) == Some(CONFIG_CURSOR_HEADER_REF)
        }
        None => false,
    }
}

fn operation_references_live_apply_mode(operation: &serde_json::Value) -> bool {
    operation["parameters"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|parameter| parameter["$ref"] == LIVE_APPLY_MODE_PARAM_REF)
}

/// Generated clients must see the optional covering cursor on every response
/// that `complete_live_config_mutation_after_commit` can return: synchronous
/// 2xx, deferred 202, and the committed-but-not-live 503. Pre-commit 503
/// families use cursor-free response components; unrelated 503 routes must
/// not claim the header.
#[test]
fn live_applied_mutations_declare_config_cursor_on_success_deferred_and_committed_503() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let header = spec
        .pointer("/components/headers/X-Ferrum-Config-Cursor")
        .expect("X-Ferrum-Config-Cursor header component");
    assert_eq!(header["required"], false);

    let service_unavailable = spec
        .pointer("/components/responses/ServiceUnavailable")
        .expect("ServiceUnavailable response component");
    assert!(
        !response_declares_config_cursor_header(&spec, service_unavailable),
        "ServiceUnavailable is the pre-commit write-gate 503 and must not declare the cursor"
    );

    let mut table_ids = BTreeSet::new();
    let mut expected_live_apply_ops = BTreeSet::new();
    for (operation_id, success_statuses, documents_deferred_202) in LIVE_APPLIED_CONFIG_MUTATIONS {
        assert!(
            table_ids.insert(*operation_id),
            "duplicate live-applied mutation operationId `{operation_id}`"
        );
        if *documents_deferred_202 {
            expected_live_apply_ops.insert(*operation_id);
        }

        let (method, path, operation) = openapi_operation_by_id(&spec, operation_id);
        let responses = operation["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("{method} {path} responses is an object"));

        for status in *success_statuses {
            let response = responses.get(*status).unwrap_or_else(|| {
                panic!("{method} {path} ({operation_id}) missing success status {status}")
            });
            assert!(
                response_declares_config_cursor_header(&spec, response),
                "{method} {path} ({operation_id}) {status} must declare {CONFIG_CURSOR_HEADER_REF}"
            );
        }

        let response_503 = responses.get("503").unwrap_or_else(|| {
            panic!("{method} {path} ({operation_id}) missing committed-not-live 503")
        });
        assert!(
            response_declares_config_cursor_header(&spec, response_503),
            "{method} {path} ({operation_id}) 503 must declare {CONFIG_CURSOR_HEADER_REF}"
        );

        if *documents_deferred_202 {
            assert!(
                operation_references_live_apply_mode(operation),
                "{method} {path} ({operation_id}) must accept LiveApplyMode"
            );
            let response_202 = responses
                .get("202")
                .unwrap_or_else(|| panic!("{method} {path} ({operation_id}) missing deferred 202"));
            assert!(
                response_declares_config_cursor_header(&spec, response_202),
                "{method} {path} ({operation_id}) 202 must declare {CONFIG_CURSOR_HEADER_REF}"
            );
        } else {
            assert!(
                !operation_references_live_apply_mode(operation),
                "{method} {path} ({operation_id}) must not accept LiveApplyMode"
            );
            assert!(
                responses.get("202").is_none(),
                "{method} {path} ({operation_id}) must not document deferred 202"
            );
        }
    }

    let mut documented_live_apply_ops = BTreeSet::new();
    for (path, path_item) in spec["paths"].as_object().expect("paths is an object") {
        let path_item = path_item
            .as_object()
            .unwrap_or_else(|| panic!("path item {path} is an object"));
        for method in OPENAPI_HTTP_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            if !operation_references_live_apply_mode(operation) {
                continue;
            }
            let operation_id = operation["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} is missing operationId"));
            documented_live_apply_ops.insert(operation_id);
        }
    }
    assert_eq!(
        documented_live_apply_ops, expected_live_apply_ops,
        "LiveApplyMode operations drifted from the mapped live-apply helper surface"
    );

    let (_, _, create_namespace) = openapi_operation_by_id(&spec, "createNamespace");
    assert!(
        !response_declares_config_cursor_header(&spec, &create_namespace["responses"]["201"]),
        "POST /namespaces does not wait on live-apply and must not declare the cursor on 201"
    );
    assert!(
        !response_declares_config_cursor_header(&spec, &create_namespace["responses"]["503"]),
        "POST /namespaces cannot commit a live-applied generation and must not declare the cursor on 503"
    );

    for operation_id in ["listProxies", "getProxy", "listApiSpecs", "getHealth"] {
        let (method, path, operation) = openapi_operation_by_id(&spec, operation_id);
        let Some(response_503) = operation["responses"].get("503") else {
            panic!("{method} {path} ({operation_id}) expected an unrelated 503");
        };
        assert!(
            !response_declares_config_cursor_header(&spec, response_503),
            "{method} {path} ({operation_id}) 503 is not a live-apply outcome and must not declare the cursor"
        );
    }
}

/// Issue #4525 closed the four `src/plugins/mesh/` plugin roots against
/// unknown keys. Each now carries the same obligation every other closed
/// plugin root does: an `additionalProperties: false` schema whose declared
/// properties are exactly the runtime allowlist. Without this guard a new
/// runtime key silently becomes an undocumented field the Admin API rejects,
/// or a documented field the runtime refuses — and mesh slice apply would
/// fail closed on the injected config.
#[test]
fn mesh_plugin_config_roots_are_closed_and_match_openapi() {
    use ferrum_edge::plugins::mesh::authz::MESH_AUTHZ_CONFIG_KEYS;
    use ferrum_edge::plugins::mesh::bpf_metrics::MESH_BPF_METRICS_CONFIG_KEYS;
    use ferrum_edge::plugins::mesh::workload_metrics::WORKLOAD_METRICS_CONFIG_KEYS;

    // `mesh_outbound_registry` closes its root with
    // `#[serde(deny_unknown_fields)]` on `OutboundRegistryConfig`, so its
    // key set is the struct's serde field names rather than a const.
    const MESH_OUTBOUND_REGISTRY_FIELDS: &[&str] = &[
        "registry",
        "reject_status",
        "outbound_listen_ports",
        "namespace",
    ];

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for (schema_name, runtime_keys) in [
        ("MeshAuthzConfig", MESH_AUTHZ_CONFIG_KEYS),
        ("WorkloadMetricsConfig", WORKLOAD_METRICS_CONFIG_KEYS),
        ("MeshOutboundRegistryConfig", MESH_OUTBOUND_REGISTRY_FIELDS),
        ("MeshBpfMetricsConfig", MESH_BPF_METRICS_CONFIG_KEYS),
    ] {
        let schema = spec
            .pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("{schema_name} component exists"));
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{schema_name} must reject undeclared properties"
        );

        let schema_fields: BTreeSet<&str> = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema_name} properties"))
            .keys()
            .map(String::as_str)
            .collect();
        let runtime_fields: BTreeSet<&str> = runtime_keys.iter().copied().collect();
        assert_eq!(schema_fields, runtime_fields, "{schema_name} key drift");
    }
}

/// Issues #5380–#5383: `__mesh_bpf_metrics` OpenAPI and docs must match
/// constructor admission. The constructor is the source of truth.
#[test]
fn mesh_bpf_metrics_schema_matches_constructor_admission() {
    use ferrum_edge::plugins::mesh::bpf_metrics::{
        DEFAULT_METRIC_PREFIX, MESH_BPF_METRICS_CONFIG_KEYS, MeshBpfMetrics,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/MeshBpfMetricsConfig")
        .expect("MeshBpfMetricsConfig component exists");
    let description = schema["description"]
        .as_str()
        .expect("MeshBpfMetricsConfig description");
    for contract in [
        "OptionalFailOpen",
        "scope: global",
        "ferrum_mesh_bpf",
        "Non-object configs",
        "trimmed",
    ] {
        assert!(
            description.contains(contract),
            "MeshBpfMetricsConfig description missing `{contract}`"
        );
    }

    assert_eq!(
        schema["type"],
        json!(["object", "null", "string", "array", "number", "boolean"])
    );
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["prefix"]["pattern"],
        json!(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*$")
    );
    assert_eq!(
        schema["properties"]["prefix"]["default"],
        json!(DEFAULT_METRIC_PREFIX)
    );
    assert_eq!(MESH_BPF_METRICS_CONFIG_KEYS, ["prefix"].as_slice());

    let bpf_branch = spec
        .pointer("/components/schemas/PluginConfigBase/allOf/0/then/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("enabled PluginConfigBase allOf")
        .iter()
        .find(|entry| {
            entry
                .pointer("/if/properties/plugin_name/const")
                .and_then(serde_json::Value::as_str)
                == Some("__mesh_bpf_metrics")
        })
        .expect("__mesh_bpf_metrics PluginConfig branch");
    assert_eq!(
        bpf_branch.pointer("/then/properties/scope/const"),
        Some(&json!("global"))
    );

    let component_cases = [
        (json!({}), true),
        (json!({"prefix": "tenantA_bpf"}), true),
        (json!({"prefix": " tenantA_bpf "}), true),
        (json!({"prefix": "\ttenantB_bpf\n"}), true),
        (json!({"prefix": "_leading_underscore"}), true),
        (serde_json::Value::Null, true),
        (json!("ignored"), true),
        (json!([]), true),
        (json!(7), true),
        (json!(false), true),
        (json!({"prefix": ""}), false),
        (json!({"prefix": "  "}), false),
        (json!({"prefix": "1tenant_bpf"}), false),
        (json!({"prefix": "with spaces"}), false),
        (json!({"prefix": "tenant-A"}), false),
        (json!({"prefix": "tenantA.bpf"}), false),
        (json!({"prefix": 7}), false),
        (json!({"prefix": null}), false),
        (json!({"prefix": ["tenantA_bpf"]}), false),
        (json!({"prefx": "tenantA_bpf"}), false),
        (json!({"prefix": "tenantA_bpf", "extra": true}), false),
    ];
    for (config, expected_valid) in component_cases {
        assert_component_validity(&spec, "MeshBpfMetricsConfig", &config, expected_valid);
        let constructed = MeshBpfMetrics::new(&config);
        assert_eq!(
            constructed.is_ok(),
            expected_valid,
            "constructor disagrees with MeshBpfMetricsConfig for {config}: {:?}",
            constructed.err()
        );
    }

    let wrapper_cases = [
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "global",
                "enabled": true,
                "config": {}
            }),
            true,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "global",
                "enabled": true,
                "config": {"prefix": "tenantA_bpf"}
            }),
            true,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "global",
                "enabled": true,
                "config": {"prefix": " tenantA_bpf "}
            }),
            true,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "proxy",
                "enabled": true,
                "proxy_id": "http",
                "config": {}
            }),
            false,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "proxy_group",
                "enabled": true,
                "config": {}
            }),
            false,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "proxy",
                "enabled": false,
                "proxy_id": "http",
                "config": {}
            }),
            true,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "global",
                "enabled": true,
                "config": {"prefx": "x"}
            }),
            false,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "global",
                "enabled": true,
                "config": {"prefix": "  "}
            }),
            false,
        ),
        (
            json!({
                "plugin_name": "__mesh_bpf_metrics",
                "scope": "global",
                "enabled": true,
                "config": null
            }),
            true,
        ),
    ];
    for (instance, expected_valid) in wrapper_cases {
        assert_component_validity(&spec, "PluginConfig", &instance, expected_valid);
    }

    // POST's omitted enabled field defaults to true, so the global-scope
    // restriction must run through the shared construction gate as well.
    let mut post_defaults = json!({
        "plugin_name": "__mesh_bpf_metrics",
        "scope": "global",
        "config": null
    });
    assert_component_validity(&spec, "PluginConfigCreate", &post_defaults, true);
    post_defaults["scope"] = json!("proxy_group");
    assert_component_validity(&spec, "PluginConfigCreate", &post_defaults, false);

    let plugins_docs = include_str!("../../docs/plugins.md");
    let section = plugins_docs
        .split("### `__mesh_bpf_metrics`")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("__mesh_bpf_metrics docs section");
    for needle in [
        "| `prefix` | String | `ferrum_mesh_bpf` |",
        "`str::trim`",
        "[A-Za-z_][A-Za-z0-9_]*",
        "OptionalFailOpen",
        "scope: global",
        "prefix: tenantA_bpf",
        "no declared length limit",
    ] {
        assert!(
            section.contains(needle),
            "docs/plugins.md __mesh_bpf_metrics section missing `{needle}`"
        );
    }

    let mesh_docs = include_str!("../../docs/mesh.md");
    for needle in [
        "capped exponential backoff",
        "1s, 2s, 4s, 8s, 16s, and 30s",
        "does not stop the consumer",
        "never start the consumer task",
        "`str::trim`",
        "[A-Za-z_][A-Za-z0-9_]*",
        "default `ferrum_mesh_bpf`",
    ] {
        assert!(
            mesh_docs.contains(needle),
            "docs/mesh.md missing `{needle}`"
        );
    }
    assert!(
        !mesh_docs.contains("the consumer logs one info line at startup and exits"),
        "docs/mesh.md must not claim a missing pin stops the consumer"
    );
}

/// Issues #5111–#5115: size-limiting plugin configs are closed objects whose
/// integer size fields advertise an enforceable uint64 maximum. `format: uint64`
/// alone does not constrain Draft 2020-12 validators.
#[test]
fn size_limiting_plugin_configs_are_closed_and_bounded_in_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let uint64_max = json!(u64::MAX);
    for (schema_name, runtime_keys, size_fields) in [
        (
            "RequestSizeLimitingConfig",
            &["max_bytes"][..],
            &["max_bytes"][..],
        ),
        (
            "ResponseSizeLimitingConfig",
            &["max_bytes", "require_buffered_check"][..],
            &["max_bytes"][..],
        ),
        (
            "WsMessageSizeLimitingConfig",
            &["close_reason", "max_frame_bytes", "max_message_bytes"][..],
            &["max_frame_bytes", "max_message_bytes"][..],
        ),
    ] {
        let schema = spec
            .pointer(&format!("/components/schemas/{schema_name}"))
            .unwrap_or_else(|| panic!("{schema_name} component exists"));
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{schema_name} must reject unknown properties"
        );

        let schema_fields: BTreeSet<&str> = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema_name} properties"))
            .keys()
            .map(String::as_str)
            .collect();
        let runtime_fields: BTreeSet<&str> = runtime_keys.iter().copied().collect();
        assert_eq!(schema_fields, runtime_fields, "{schema_name} key drift");

        for field in size_fields {
            assert_eq!(
                schema["properties"][field]["minimum"],
                json!(1),
                "{schema_name}.{field} must be a positive integer"
            );
            assert_eq!(
                schema["properties"][field]["maximum"], uint64_max,
                "{schema_name}.{field} must advertise the uint64 upper bound"
            );
            assert_eq!(
                schema["properties"][field]["format"],
                json!("uint64"),
                "{schema_name}.{field} stays uint64"
            );
        }

        let mut component_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("#/components/schemas/{schema_name}")
        });
        component_schema
            .as_object_mut()
            .expect("schema should be object")
            .insert("components".to_string(), spec["components"].clone());
        let component_validator = jsonschema::draft202012::options()
            .build(&component_schema)
            .unwrap_or_else(|error| panic!("{schema_name} schema compiles: {error}"));

        let minimal = match schema_name {
            "RequestSizeLimitingConfig" | "ResponseSizeLimitingConfig" => {
                json!({"max_bytes": 1})
            }
            "WsMessageSizeLimitingConfig" => json!({"max_frame_bytes": 1}),
            _ => unreachable!(),
        };
        assert!(
            component_validator.validate(&minimal).is_ok(),
            "{schema_name} must accept the documented minimal config: {minimal}"
        );

        let mut unknown = minimal.clone();
        unknown
            .as_object_mut()
            .expect("minimal config is an object")
            .insert("max_bytez".to_string(), json!(64));
        assert!(
            component_validator.validate(&unknown).is_err(),
            "{schema_name} must reject an unknown key: {unknown}"
        );

        let at_max = {
            let mut at_max = minimal.clone();
            for field in size_fields {
                at_max
                    .as_object_mut()
                    .expect("minimal config is an object")
                    .insert((*field).to_string(), json!(u64::MAX));
            }
            at_max
        };
        assert!(
            component_validator.validate(&at_max).is_ok(),
            "{schema_name} must accept u64::MAX: {at_max}"
        );

        let over = serde_json::from_str("18446744073709551616")
            .expect("u64::MAX+1 must parse as a JSON number");
        let mut over_range = minimal.clone();
        over_range
            .as_object_mut()
            .expect("minimal config is an object")
            .insert(size_fields[0].to_string(), over);
        assert!(
            component_validator.validate(&over_range).is_err(),
            "{schema_name} must reject u64::MAX+1: {over_range}"
        );
    }

    let mut plugin_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/PluginConfig"
    });
    plugin_schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());
    let plugin_validator = jsonschema::draft202012::options()
        .build(&plugin_schema)
        .expect("PluginConfig schema compiles");

    let plugin_config = |plugin_name: &str, config: serde_json::Value| -> serde_json::Value {
        json!({
            "plugin_name": plugin_name,
            "scope": "global",
            "enabled": true,
            "config": config
        })
    };

    for (plugin_name, minimal) in [
        ("request_size_limiting", json!({"max_bytes": 1})),
        ("response_size_limiting", json!({"max_bytes": 1})),
        ("ws_message_size_limiting", json!({"max_frame_bytes": 1})),
    ] {
        assert!(
            plugin_validator
                .validate(&plugin_config(plugin_name, minimal.clone()))
                .is_ok(),
            "{plugin_name} PluginConfig branch must accept the documented minimal config"
        );

        let mut unknown = minimal.clone();
        unknown
            .as_object_mut()
            .expect("minimal config is an object")
            .insert("max_bytez".to_string(), json!(64));
        assert!(
            plugin_validator
                .validate(&plugin_config(plugin_name, unknown))
                .is_err(),
            "{plugin_name} PluginConfig branch must reject an unknown key"
        );

        let mut at_max = minimal.clone();
        let size_field = if plugin_name == "ws_message_size_limiting" {
            "max_frame_bytes"
        } else {
            "max_bytes"
        };
        at_max
            .as_object_mut()
            .expect("minimal config is an object")
            .insert(size_field.to_string(), json!(u64::MAX));
        assert!(
            plugin_validator
                .validate(&plugin_config(plugin_name, at_max))
                .is_ok(),
            "{plugin_name} PluginConfig branch must accept u64::MAX"
        );

        let over = serde_json::from_str("18446744073709551616")
            .expect("u64::MAX+1 must parse as a JSON number");
        let mut over_range = minimal;
        over_range
            .as_object_mut()
            .expect("minimal config is an object")
            .insert(size_field.to_string(), over);
        assert!(
            plugin_validator
                .validate(&plugin_config(plugin_name, over_range))
                .is_err(),
            "{plugin_name} PluginConfig branch must reject u64::MAX+1"
        );
    }
}

/// Three-way parity for the `ai_semantic_firewall` extraction-path allowlist.
///
/// The same list exists in three places — the Rust constants that
/// `validate_extraction_paths` admits and `extract_known_path` dispatches on,
/// the `enum` + `default` arrays `openapi.yaml` publishes, and the
/// "Supported provider shapes" tables in `docs/plugins.md`. A provider shape
/// added to the code but not the schema is silently unconfigurable, and one
/// added to the schema but not the code is accepted at config load and then
/// extracts nothing — the exact silent-bypass class GHSA-8gc3-h5c8-jjxx was.
/// Order is asserted too, so the published defaults stay the declared defaults.
#[test]
fn ai_semantic_firewall_extraction_paths_match_openapi_and_docs() {
    let (request_paths, response_paths) =
        ferrum_edge::_test_support::ai_semantic_firewall_extraction_paths_for_test();

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let extraction = spec
        .pointer("/components/schemas/AiSemanticFirewallConfig/properties/extraction/properties")
        .expect("AiSemanticFirewallConfig extraction properties");

    for (field, runtime) in [
        ("request_json_paths", request_paths),
        ("response_json_paths", response_paths),
    ] {
        let expected: Vec<serde_json::Value> = runtime
            .iter()
            .map(|path| serde_json::Value::String((*path).to_string()))
            .collect();
        let enum_values = extraction[field]["items"]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{field} items.enum"));
        assert_eq!(
            enum_values, &expected,
            "{field} enum must equal the runtime allowlist, in order"
        );
        let defaults = extraction[field]["default"]
            .as_array()
            .unwrap_or_else(|| panic!("{field} default"));
        assert_eq!(
            defaults, &expected,
            "{field} default must equal the runtime default set, in order"
        );
    }

    let plugin_docs = include_str!("../../docs/plugins.md");
    for path in request_paths.iter().chain(response_paths.iter()) {
        assert!(
            plugin_docs.contains(&format!("`{path}`")),
            "docs/plugins.md must document the supported extraction path {path}"
        );
    }
}

/// Issue #5022: `JwtAuthConfig` must reject exactly what `JwtAuth::new` rejects.
/// Schema-driven tooling previously approved configurations `ferrum-edge
/// validate` and the admin API refuse.
#[test]
fn jwt_auth_schema_matches_runtime_admission() {
    use ferrum_edge::plugins::jwt_auth::JwtAuth;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let accepted = [
        json!({}),
        json!({"token_lookup": "header:Authorization"}),
        json!({"token_lookup": "header:X-Token"}),
        json!({"token_lookup": "query:token"}),
        json!({"consumer_claim_field": "client_id"}),
        json!({"expected_issuer": "https://issuer.example"}),
        json!({"expected_issuers": ["https://issuer.example"]}),
        json!({"audiences": ["payments-api"]}),
        json!({"leeway_secs": 300}),
        json!({"require_exp": false, "require_nbf": true}),
    ];
    for config in &accepted {
        assert_component_validity(&spec, "JwtAuthConfig", config, true);
        assert!(
            JwtAuth::new(config).is_ok(),
            "runtime should accept schema-valid config: {config}"
        );
    }

    let rejected = [
        json!({"token_lookup": "foo"}),
        json!({"token_lookup": "header:   "}),
        json!({"token_lookup": "header:x bad"}),
        json!({"token_lookup": " header:Authorization"}),
        json!({"token_lookup": "query:a b"}),
        json!({"token_lookup": ""}),
        json!({"consumer_claim_field": ""}),
        json!({"expected_issuer": ""}),
        json!({"expected_issuer": "https://a", "expected_issuers": ["https://b"]}),
        json!({"expected_issuers": [""]}),
        json!({"audiences": [""]}),
        json!({"leeway_secs": -1}),
        json!({"leeway_secs": 301}),
        json!({"audience": ["payments-api"]}),
    ];
    for config in &rejected {
        assert_component_validity(&spec, "JwtAuthConfig", config, false);
        assert!(
            JwtAuth::new(config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }
}

/// Issue #5023: `JwksAuthConfig` must encode the constructor's structural and
/// cross-field admission rules. The two rules JSON Schema cannot practically
/// express — the closed reserved-destination list for `output_claim_headers`
/// and `jwks_refresh_interval_secs` <= the effective `jwks_max_stale_seconds` —
/// are stated in the property descriptions instead and are deliberately absent
/// from the rejected set below.
#[test]
fn jwks_auth_schema_matches_runtime_admission() {
    const JWKS_URI: &str = "https://idp.example.com/jwks";
    const DISCOVERY_URL: &str = "https://idp.example.com/.well-known/openid-configuration";
    const ISSUER: &str = "https://idp.example.com";

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let inline = || json!({"keys": []});
    // One remote provider plus the supplied per-provider overrides.
    let remote = |extra: serde_json::Value| {
        let mut provider = json!({"jwks_uri": JWKS_URI});
        merge_into_object(&mut provider, &extra);
        json!({"providers": [provider]})
    };
    // One inline provider plus the supplied per-provider overrides.
    let local = |extra: serde_json::Value| {
        let mut provider = json!({"jwks": inline()});
        merge_into_object(&mut provider, &extra);
        json!({"providers": [provider]})
    };

    let accepted = [
        remote(json!({})),
        remote(json!({"issuer": ISSUER})),
        remote(json!({"from_headers": [{"name": "x-token", "prefix": null}]})),
        remote(json!({"from_headers": [{"name": "x-token", "prefix": "Token "}]})),
        remote(json!({"from_params": ["token"]})),
        remote(json!({"required_scopes": ["admin"], "scope_claim": "realm.scope"})),
        remote(json!({"jwks_max_stale_seconds": 600})),
        remote(json!({"output_claim_headers": [{"header": "x-claim", "claim": "sub"}]})),
        local(json!({})),
        json!({"providers": [{"discovery_url": DISCOVERY_URL}]}),
        json!({"providers": [{"jwks_uri": "http://127.0.0.1:9000/jwks"}]}),
        json!({"providers": [{"jwks_uri": "http://localhost:9000/jwks"}]}),
        local(json!({
            "issuer": ISSUER,
            "require_dpop": true,
            "dpop_replay_scope": "process"
        })),
    ];
    for config in &accepted {
        assert_component_validity(&spec, "JwksAuthConfig", config, true);
    }

    let rejected = [
        json!({"providers": []}),
        json!({"providers": [{}]}),
        remote(json!({"scope_claim": "a..b"})),
        remote(json!({"role_claim": ".roles"})),
        remote(json!({"claim_headers_separator": ""})),
        remote(json!({"required_scopes": [""]})),
        remote(json!({"from_headers": [{"name": "x token"}]})),
        remote(json!({"output_claim_headers": [{"header": "x bad", "claim": "sub"}]})),
        remote(json!({"discovery_url": DISCOVERY_URL})),
        remote(json!({"jwks": inline()})),
        json!({"providers": [{"jwks_uri": "not a url"}]}),
        json!({"providers": [{"jwks_uri": "http://idp.example.com/jwks"}]}),
        json!({"providers": [{"jwks_uri": "https://u:p@idp.example.com/jwks"}]}),
        local(json!({"jwks_max_stale_seconds": 600})),
        local(json!({"require_dpop": true})),
        local(json!({"issuer": ISSUER, "require_dpop": true})),
        local(json!({"dpop_replay_scope": "process"})),
        json!({"providers": [{"jwks_uri": JWKS_URI}], "scope_claim": "a..b"}),
        json!({"providers": [{"jwks_uri": JWKS_URI}], "claim_headers_separator": ""}),
    ];
    for config in &rejected {
        assert_component_validity(&spec, "JwksAuthConfig", config, false);
        assert!(
            ferrum_edge::plugins::validate_plugin_config("jwks_auth", config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }
}

/// Shallow-merge every member of `extra` into the `target` JSON object.
fn merge_into_object(target: &mut serde_json::Value, extra: &serde_json::Value) {
    let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) else {
        panic!("merge_into_object expects two JSON objects");
    };
    for (key, value) in extra {
        target.insert(key.clone(), value.clone());
    }
}

/// Bidirectional parity for `ai_semantic_firewall`: the published component and
/// the constructor must return the SAME verdict, so a schema-validating client
/// can preflight a configuration `ferrum-edge validate` will accept.
#[test]
fn ai_semantic_firewall_schema_matches_runtime_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    const ENDPOINT: &str = "http://127.0.0.1:1/v1/embeddings";
    let provider = json!({"type": "openai_compatible_embeddings", "endpoint": ENDPOINT});

    let accepted = [
        json!({"provider": provider}),
        json!({"enabled": false}),
        json!({"provider": provider, "enabled": false}),
        json!({
            "provider": provider,
            "inspect": {"request": false, "response": true},
            "builtins": {"response_leakage": true}
        }),
        // An empty extraction list is fine while no rule in that direction runs.
        json!({
            "provider": provider,
            "inspect": {"request": false, "response": true},
            "extraction": {"request_json_paths": []}
        }),
        // Ids and examples are trimmed, so padded text is admissible.
        json!({
            "provider": provider,
            "custom_rules": [{"id": " a ", "examples": [" reference "]}]
        }),
        json!({
            "provider": provider,
            "builtins": {"prompt_injection": {"examples_mode": "replace", "examples": ["x"]}}
        }),
        json!({"provider": provider, "streaming_response": "inspect", "streaming": {}}),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"window": "tokens", "tokenizer": "chars4", "max_window_tokens": 2}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"max_hold_ms": 100, "on_hold_timeout": "on_error"}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"enforcement": "detect", "max_hold_ms": 100, "on_hold_timeout": "forward"}
        }),
    ];
    for config in &accepted {
        assert_component_validity(&spec, "AiSemanticFirewallConfig", config, true);
        assert!(
            ferrum_edge::plugins::validate_plugin_config("ai_semantic_firewall", config).is_ok(),
            "runtime should accept schema-valid config: {config}"
        );
    }

    let rejected = [
        json!({"provider": provider, "inspect": {"request": false, "response": false}}),
        json!({"provider": provider, "builtins": {}}),
        // Request-only rules with request inspection disabled.
        json!({
            "provider": provider,
            "inspect": {"request": false, "response": true},
            "builtins": {"prompt_injection": true}
        }),
        json!({"provider": provider, "extraction": {"request_json_paths": []}}),
        // provider.type is an exact one-value vocabulary: no aliases, no padding.
        json!({"provider": {"type": "openai_compatible", "endpoint": ENDPOINT}}),
        json!({"provider": {"type": "openai-compatible", "endpoint": ENDPOINT}}),
        json!({"provider": {"type": " openai_compatible_embeddings ", "endpoint": ENDPOINT}}),
        json!({"provider": provider, "custom_rules": [{"id": " ", "examples": ["reference"]}]}),
        json!({"provider": provider, "custom_rules": [{"id": "a", "examples": [" "]}]}),
        json!({
            "provider": provider,
            "builtins": {"prompt_injection": {"examples_mode": "replace"}}
        }),
        json!({"provider": provider, "streaming": {}}),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"window": "tokens"}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"tokenizer": "chars4"}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"overlap_bytes": -1}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"on_hold_timeout": "on_error"}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"enforcement": "detect", "max_hold_ms": 100, "on_hold_timeout": "cut"}
        }),
        // A disabled instance still validates the blocks it carries.
        json!({"provider": {"type": "bogus"}, "enabled": false}),
        // Materializing an advertised default must never invalidate a config:
        // these two token-only fields therefore carry no schema default.
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"max_window_tokens": 256}
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"overlap_tokens": 32}
        }),
    ];
    for config in &rejected {
        assert_component_validity(&spec, "AiSemanticFirewallConfig", config, false);
        assert!(
            ferrum_edge::plugins::validate_plugin_config("ai_semantic_firewall", config).is_err(),
            "runtime should reject schema-invalid config: {config}"
        );
    }

    // Cross-field numeric comparisons and id uniqueness are NOT expressible in
    // standard JSON Schema. The component describes them; the constructor is
    // the only gate. Keep this list in sync with that description.
    let constructor_only = [
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {
                "window": "tokens",
                "tokenizer": "chars4",
                "max_window_tokens": 2,
                "overlap_tokens": 32
            }
        }),
        json!({
            "provider": provider,
            "streaming_response": "inspect",
            "streaming": {"max_window_bytes": 64, "overlap_bytes": 128}
        }),
        json!({
            "provider": provider,
            "custom_rules": [
                {"id": "dup", "examples": ["a"]},
                {"id": "dup", "examples": ["b"]}
            ]
        }),
    ];
    for config in &constructor_only {
        assert_component_validity(&spec, "AiSemanticFirewallConfig", config, true);
        assert!(
            ferrum_edge::plugins::validate_plugin_config("ai_semantic_firewall", config).is_err(),
            "constructor must still reject what the schema cannot express: {config}"
        );
    }
}

/// One table, both directions: every row must be admitted — or refused — by
/// the published component and by the constructor alike.
///
/// The component is what generated clients, config forms, and external
/// validation tooling enforce, so a row either side accepts alone is a config
/// an operator can be told is valid and then cannot start (issue #5013).
#[test]
fn oauth2_introspection_schema_and_constructor_admit_the_same_configs() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::oauth2_introspection::Oauth2Introspection;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    // Every provider override the constructor accepts must be representable.
    let provider_properties = spec
        .pointer(
            "/components/schemas/Oauth2IntrospectionConfig/properties/providers/items/properties",
        )
        .and_then(serde_json::Value::as_object)
        .expect("OAuth2 introspection provider properties exist");
    for field in [
        "token_hint_param",
        "scope_claim",
        "role_claim",
        "consumer_identity_claim",
        "consumer_header_claim",
    ] {
        assert!(
            provider_properties.contains_key(field),
            "the provider schema must declare the accepted key {field}"
        );
    }

    // Loopback endpoints keep `client_auth.method: none` admissible, so the
    // rows below isolate the field under test.
    let loopback = "http://127.0.0.1:32123/introspect";
    let provider = |patch: serde_json::Value| -> serde_json::Value {
        let mut object = json!({
            "introspection_endpoint": loopback,
            "client_auth": {"method": "none"}
        });
        let object_map = object.as_object_mut().expect("provider object");
        for (key, value) in patch.as_object().expect("patch object") {
            object_map.insert(key.clone(), value.clone());
        }
        json!({"providers": [object]})
    };

    let cases = [
        ("minimal loopback provider", provider(json!({})), true),
        (
            "documented https example",
            json!({"providers": [{
                "introspection_endpoint": "https://idp.example.com/oauth2/introspect",
                "issuer": "https://idp.example.com/",
                "audiences": ["api://edge"],
                "client_auth": {
                    "method": "client_secret_basic",
                    "client_id": "ferrum-edge",
                    "client_secret": "introspection-client-secret"
                },
                "required_scopes": ["orders:read"],
                "claim_headers": {"sub": "X-Authenticated-Subject"}
            }]}),
            true,
        ),
        ("empty provider", json!({"providers": [{}]}), false),
        (
            "both endpoints",
            json!({"providers": [{
                "introspection_endpoint": loopback,
                "discovery_url": "http://127.0.0.1:32123/.well-known/openid-configuration",
                "client_auth": {"method": "none"}
            }]}),
            false,
        ),
        (
            "discovery only",
            json!({"providers": [{
                "discovery_url": "http://127.0.0.1:32123/.well-known/openid-configuration",
                "client_auth": {"method": "none"}
            }]}),
            true,
        ),
        (
            "client_auth omitted",
            json!({"providers": [{"introspection_endpoint": loopback}]}),
            false,
        ),
        (
            "client_secret_basic without credentials",
            json!({"providers": [{
                "introspection_endpoint": loopback,
                "client_auth": {"method": "client_secret_basic"}
            }]}),
            false,
        ),
        (
            "unused client_auth key of the wrong type",
            json!({"providers": [{
                "introspection_endpoint": loopback,
                "client_auth": {"method": "none", "client_secret": 123}
            }]}),
            false,
        ),
        (
            "timeout below range",
            provider(json!({"request_timeout_ms": 99})),
            false,
        ),
        (
            "timeout zero",
            provider(json!({"request_timeout_ms": 0})),
            false,
        ),
        (
            "timeout above range",
            provider(json!({"request_timeout_ms": 30001})),
            false,
        ),
        (
            "timeout in range",
            provider(json!({"request_timeout_ms": 5000})),
            true,
        ),
        (
            "positive TTL above range",
            provider(json!({"positive_cache_ttl_secs": 86401})),
            false,
        ),
        (
            "positive TTL disabled",
            provider(json!({"positive_cache_ttl_secs": 0})),
            true,
        ),
        (
            "negative TTL above range",
            provider(json!({"negative_cache_ttl_secs": 301})),
            false,
        ),
        ("blank issuer", provider(json!({"issuer": ""})), false),
        (
            "blank audience",
            provider(json!({"audiences": [""]})),
            false,
        ),
        (
            "blank query location",
            provider(json!({"from_params": [""]})),
            false,
        ),
        (
            "claim path with an empty segment",
            provider(json!({"scope_claim": "x..y"})),
            false,
        ),
        (
            "claim header targeting a reserved name",
            provider(json!({"claim_headers": {"sub": "authorization"}})),
            false,
        ),
        (
            "claim header with an invalid name",
            provider(json!({"claim_headers": {"sub": "bad header"}})),
            false,
        ),
        (
            "token location with an invalid header name",
            provider(json!({"from_headers": [{"name": "bad header"}]})),
            false,
        ),
        (
            "token location with a null prefix",
            provider(json!({"from_headers": [{"name": "x-token", "prefix": null}]})),
            true,
        ),
        (
            "blank token hint",
            provider(json!({"token_hint_param": ""})),
            false,
        ),
        (
            "null token hint",
            provider(json!({"token_hint_param": null})),
            true,
        ),
        (
            "token hint",
            provider(json!({"token_hint_param": "access_token"})),
            true,
        ),
        (
            "unsupported endpoint scheme",
            provider(json!({"introspection_endpoint": "file:///tmp/x"})),
            false,
        ),
        (
            "unparseable endpoint",
            provider(json!({"introspection_endpoint": "nonsense"})),
            false,
        ),
        (
            "empty endpoint",
            provider(json!({"introspection_endpoint": ""})),
            false,
        ),
        (
            "unknown provider key",
            provider(json!({"introspection_endpoiint": loopback})),
            false,
        ),
        (
            "blank global claim path",
            json!({"providers": [{
                "introspection_endpoint": loopback,
                "client_auth": {"method": "none"}
            }], "scope_claim": ""}),
            false,
        ),
    ];

    for (label, config, expected_valid) in cases {
        assert_component_validity(&spec, "Oauth2IntrospectionConfig", &config, expected_valid);
        let constructed = Oauth2Introspection::new(&config, PluginHttpClient::default());
        assert_eq!(
            constructed.is_ok(),
            expected_valid,
            "{label}: constructor disagrees with the component; error: {:?}",
            constructed.err()
        );
    }
}

/// The OPA counterpart of the table above (issue #5058).
///
/// `max_cache_total_bytes`-style cross-field rules stay runtime-only and are
/// documented rather than modelled; every row here is expressible in both.
#[test]
fn opa_schema_and_constructor_admit_the_same_configs() {
    use ferrum_edge::plugins::PluginHttpClient;
    use ferrum_edge::plugins::opa::Opa;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let base = |patch: serde_json::Value| -> serde_json::Value {
        let mut config = json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": "ferrum/authz/allow"
        });
        let config_map = config.as_object_mut().expect("config object");
        for (key, value) in patch.as_object().expect("patch object") {
            config_map.insert(key.clone(), value.clone());
        }
        config
    };

    let cases = [
        ("minimal", base(json!({})), true),
        (
            "null response ceiling",
            base(json!({"max_response_bytes": null})),
            true,
        ),
        (
            "null body ceiling",
            base(json!({"max_body_bytes": null})),
            true,
        ),
        (
            "zero response ceiling",
            base(json!({"max_response_bytes": 0})),
            false,
        ),
        (
            "zero body ceiling",
            base(json!({"max_body_bytes": 0})),
            false,
        ),
        (
            "both fail-posture flags",
            base(json!({"fail_open": false, "fail_closed": true})),
            false,
        ),
        ("fail_open alone", base(json!({"fail_open": true})), true),
        (
            "fail_closed alone",
            base(json!({"fail_closed": true})),
            true,
        ),
        (
            "timeout above the clamp",
            base(json!({"timeout_ms": 30001})),
            true,
        ),
        ("empty policy path", base(json!({"policy_path": ""})), false),
        (
            "absolute policy path",
            base(json!({"policy_path": "/audit/allow"})),
            false,
        ),
        (
            "empty policy segment",
            base(json!({"policy_path": "audit//allow"})),
            false,
        ),
        (
            "percent-encoded policy path",
            base(json!({"policy_path": "audit%2Fallow"})),
            false,
        ),
        (
            "policy path with a query",
            base(json!({"policy_path": "audit/allow?x=y"})),
            false,
        ),
        (
            "policy path with a fragment",
            base(json!({"policy_path": "audit/allow#x"})),
            false,
        ),
        (
            "dot policy segment",
            base(json!({"policy_path": "a/./b"})),
            false,
        ),
        (
            "unsupported host scheme",
            base(json!({"opa_host": "ftp://localhost"})),
            false,
        ),
        (
            "host with a query",
            base(json!({"opa_host": "http://127.0.0.1:8181?x=y"})),
            false,
        ),
        (
            "host with credentials",
            base(json!({"opa_host": "http://user:pass@127.0.0.1:8181"})),
            false,
        ),
        (
            "host with a base path",
            base(json!({"opa_host": "http://127.0.0.1:8181/base"})),
            true,
        ),
        (
            "outbound content-type override",
            base(json!({"headers": {"Content-Type": "text/plain"}})),
            false,
        ),
        (
            "invalid outbound header name",
            base(json!({"headers": {"Bad Header": "x"}})),
            false,
        ),
        (
            "protocol-managed deny header",
            base(json!({"deny_headers": {"Content-Length": "3"}})),
            false,
        ),
        (
            "protocol-managed fail-closed header",
            base(json!({"fail_closed_headers": {"Connection": "close"}})),
            false,
        ),
        (
            "ordinary deny header",
            base(json!({"deny_headers": {"X-Policy": "denied"}})),
            true,
        ),
        (
            "blank redaction name",
            base(json!({"redact_headers": [""]})),
            false,
        ),
        (
            "invalid redaction name",
            base(json!({"redact_headers": ["Bad Header"]})),
            false,
        ),
        (
            "unknown key",
            base(json!({"decision_pointr": ["result"]})),
            false,
        ),
    ];

    for (label, config, expected_valid) in cases {
        assert_component_validity(&spec, "OpaPluginConfig", &config, expected_valid);
        let constructed = Opa::new(&config, PluginHttpClient::default());
        assert_eq!(
            constructed.is_ok(),
            expected_valid,
            "{label}: constructor disagrees with the component; error: {:?}",
            constructed.err()
        );
    }
}

/// The `MeshAuthzConfig` component must agree with what the plugin constructor
/// actually admits — both directions. A schema that accepts a document the
/// gateway rejects sends operators into a failed reload; one that rejects a
/// supported document blocks a valid policy. The cases below are the ones the
/// audit found disagreeing (issue #5066).
#[test]
fn mesh_authz_component_matches_runtime_admission() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    let policy = |rules: serde_json::Value| {
        json!({
            "name": "deny-admin",
            "namespace": "default",
            "scope": {"kind": "mesh_wide"},
            "rules": rules,
        })
    };
    let deny_admin = json!([{"action": "deny", "to": [{"paths": ["/admin/*"]}]}]);
    let custom = json!([{"action": {"custom": {"provider": "ext"}}}]);
    let no_action = json!([{"to": [{"paths": ["/admin/*"]}]}]);
    let rule_typo = json!([{"action": "deny", "not_path": ["/a"]}]);
    let match_typo = json!([{"action": "deny", "to": [{"not_path": ["/a"]}]}]);

    for valid in [
        // An omitted `config:` block deserializes to null for every plugin.
        serde_json::Value::Null,
        json!({}),
        json!({"trust_domain_aliases": null}),
        json!({"trust_domain_aliases": ["cluster.local"]}),
        json!({"trusted_hbone_assertors": null}),
        json!({"trusted_hbone_assertors": []}),
        json!({"trusted_hbone_assertors": ["ztunnel", "waypoint"]}),
        json!({"trusted_hbone_assertors": [{"assertor": "waypoint", "scope": null}]}),
        // The constructor trims the scope value, exactly as it trims the
        // assertor; the schema expresses that with a pattern, not an enum.
        json!({"trusted_hbone_assertors": [{"assertor": "waypoint", "scope": " same_namespace "}]}),
        json!({"trusted_hbone_assertors": [
            {"assertor": "spiffe://cluster.local/ns/istio-system/sa/ztunnel", "scope": "mesh_wide"}
        ]}),
        json!({"mesh_policies": []}),
        json!({"mesh_policies": [policy(deny_admin)]}),
        json!({"mesh_policies": [policy(custom)]}),
        json!({"mesh_policies": [{
            "name": "scoped", "namespace": "default",
            "scope": {"kind": "workload_selector", "selector": {"labels": {"app": "api"}}},
        }]}),
        json!({"node_waypoint_route_upstreams": [
            {"id": "u", "namespace": "default", "targets": [{"host": "h", "port": 8080}]}
        ]}),
    ] {
        assert_component_validity(&spec, "MeshAuthzConfig", &valid, true);
    }

    for invalid in [
        // A non-object root builds a policy-free instance that allows
        // everything, so it is refused rather than degraded.
        json!(7),
        json!("mesh_policies"),
        json!([]),
        // Unknown root key (the #4525 contract, kept).
        json!({"mesh_policy": []}),
        // A policy document with no identity or scope.
        json!({"mesh_policies": [{}]}),
        // `action` is required on every rule.
        json!({"mesh_policies": [policy(no_action)]}),
        // Closed grammar at each nesting level.
        json!({"mesh_policies": [policy(rule_typo)]}),
        json!({"mesh_policies": [policy(match_typo)]}),
        json!({"mesh_policies": [{
            "name": "scoped", "namespace": "default",
            "scope": {"kind": "workload_selector", "selector": {"labelz": {}}},
        }]}),
        // Wrong-typed scoping flag: silently reading it as false would
        // re-enable the construction-time scope filter on a node waypoint.
        json!({"per_pod_policy_scoping": "true"}),
        json!({"ambient_udp_source_scoping": 1}),
        // Grant exclusivity and the exact-SPIFFE requirement for mesh_wide.
        json!({"trusted_hbone_assertors": [
            {"assertor": "waypoint", "asserts": [], "scope": "same_namespace"}
        ]}),
        json!({"trusted_hbone_assertors": [{"assertor": "waypoint", "scope": "mesh_wide"}]}),
        // Trust-domain grammar.
        json!({"trust_domain_aliases": ["not/a/domain"]}),
        // uint16 has a numeric ceiling, not just a format hint.
        json!({"node_waypoint_route_upstreams": [
            {"id": "u", "namespace": "default", "targets": [{"host": "h", "port": 65536}]}
        ]}),
    ] {
        assert_component_validity(&spec, "MeshAuthzConfig", &invalid, false);
    }
}

/// `mesh_authz` is a public built-in that appears in `/plugins`, the execution
/// order table, and the protocol matrix, so the public guide must carry its
/// configuration and behavior reference (issue #5065).
#[test]
fn mesh_authz_public_guide_documents_its_configuration_contract() {
    let guide = include_str!("../../docs/plugins.md");
    assert!(
        guide.contains("### `mesh_authz`"),
        "docs/plugins.md must carry a mesh_authz section"
    );

    let section = guide
        .split("### `mesh_authz`")
        .nth(1)
        .expect("mesh_authz section")
        .split("\n### ")
        .next()
        .expect("mesh_authz section body");

    // Every accepted root key, including the injection-only ones an operator
    // will see echoed back by `GET /plugins`.
    for key in [
        "mesh_slice",
        "mesh_policies",
        "namespace",
        "labels",
        "per_pod_policy_scoping",
        "ambient_udp_source_scoping",
        "trust_domain_aliases",
        "trusted_hbone_assertors",
        "cluster_domain",
        "cluster_domains",
        "node_waypoint_route_upstreams",
    ] {
        assert!(
            section.contains(&format!("`{key}`")),
            "docs/plugins.md mesh_authz section must document `{key}`"
        );
    }

    for contract in [
        "2075",
        "FailClosed",
        "implicit-deny",
        "**Strict configuration admission.**",
        "**Trusted identity is required.**",
    ] {
        assert!(
            section.contains(contract),
            "docs/plugins.md mesh_authz section must state: {contract}"
        );
    }
}

/// The CUSTOM outcome vocabulary in `docs/mesh.md` must stay in lock-step with
/// the closed reason enum (issue #5068). The exhaustive match makes a NEW
/// reason a compile error here rather than a silently undocumented label, and
/// the assertions pin BOTH the metric labels and the finer per-request reason
/// tokens the metric folds into them.
#[test]
fn mesh_custom_authorization_outcome_documentation_matches_the_reason_enum() {
    use ferrum_edge::plugins::mesh::ext_authz::MeshExtAuthzReason as Reason;

    // The `outcome` metric label `record()` folds each reason into.
    let metric_outcome = |reason: Reason| -> &'static str {
        match reason {
            Reason::Allowed => "allowed",
            Reason::DeniedByProvider => "denied_by_provider",
            Reason::ProviderUnbound => "provider_unbound",
            Reason::ProviderError => "provider_error",
            Reason::ProviderConflict => "provider_conflict",
            Reason::Unexecutable => "unexecutable",
            Reason::Timeout => "timeout",
            Reason::TransportError | Reason::RequestBuildFailed => "transport_error",
            Reason::ResponseTooLarge | Reason::ResponseReadFailed => "response_refused",
            Reason::BodyUnavailable => "body_unavailable",
            Reason::BodyTooLarge => "body_too_large",
            Reason::ConcurrencyExhausted => "concurrency_exhausted",
        }
    };

    let reasons = [
        Reason::Allowed,
        Reason::DeniedByProvider,
        Reason::ProviderUnbound,
        Reason::ProviderError,
        Reason::ProviderConflict,
        Reason::Unexecutable,
        Reason::Timeout,
        Reason::TransportError,
        Reason::RequestBuildFailed,
        Reason::ResponseTooLarge,
        Reason::ResponseReadFailed,
        Reason::BodyUnavailable,
        Reason::BodyTooLarge,
        Reason::ConcurrencyExhausted,
    ];

    let mesh_docs = include_str!("../../docs/mesh.md");
    let mut outcomes: BTreeSet<&'static str> = BTreeSet::new();
    for reason in reasons {
        let token = reason.as_str();
        assert!(
            mesh_docs.contains(&format!("`{token}`")),
            "docs/mesh.md must document the reason token `{token}`"
        );
        outcomes.insert(metric_outcome(reason));
    }

    assert_eq!(outcomes.len(), 12, "the outcome label set is twelve values");
    for outcome in &outcomes {
        assert!(
            mesh_docs.contains(&format!("| `{outcome}` |")),
            "docs/mesh.md outcome table must carry a row for `{outcome}`"
        );
    }
    assert!(
        !mesh_docs.contains("`response_refused`, `body_unavailable`"),
        "docs/mesh.md must not restate the outcome set as a prose list that can drift"
    );
}

/// The CUSTOM failure reference must not promise `failOpen` for the refusals
/// that are decided without a provider, and must not describe cancellation as
/// producing an allow (issue #5069).
#[test]
fn mesh_custom_authorization_failure_documentation_matches_the_runtime() {
    let mesh_docs = include_str!("../../docs/mesh.md");

    assert!(
        mesh_docs.contains("**unconditional fixed `403` refusals**"),
        "docs/mesh.md must document the unbound-provider / absent-executor refusal"
    );
    assert!(
        mesh_docs.contains("it never synthesizes an allow"),
        "docs/mesh.md must describe cancellation as ending the request"
    );
    assert!(
        !mesh_docs.contains("and task cancellation are all failed checks"),
        "docs/mesh.md must not restate the corrected fail-open claim"
    );
    assert!(
        mesh_docs.contains("capped at **128 process-wide**"),
        "docs/mesh.md must state the shared process-wide check budget"
    );
}

/// Issues #5176, #5177, #5178, #5181, #5189: the published
/// `serverless_function` grammar and the constructor's admission rules must
/// describe the same set of accepted configurations.
#[test]
fn serverless_function_schema_matches_runtime_admission() {
    use ferrum_edge::plugins::create_plugin;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let properties = spec
        .pointer("/components/schemas/ServerlessFunctionConfig/properties")
        .expect("ServerlessFunctionConfig properties exist");

    fn compile_pattern(value: &serde_json::Value) -> Regex {
        let raw = value["pattern"].as_str().expect("published pattern");
        Regex::new(raw).expect("published pattern compiles")
    }
    let pattern_for = |field: &str| compile_pattern(&properties[field]);

    // Issue #5177: `format: uint64` is not an assertion, so the ceiling the
    // runtime can actually represent must be published as `maximum`.
    for field in ["timeout_ms", "max_response_body_bytes"] {
        assert_eq!(
            properties[field]["maximum"].as_u64(),
            Some(u64::MAX),
            "{field} must publish the u64 ceiling"
        );
        assert_eq!(properties[field]["minimum"].as_u64(), Some(1), "{field}");
    }

    // Issue #5176: `forward_headers` entries are HTTP field-name tokens.
    let header_item = &properties["forward_headers"]["items"];
    assert_eq!(header_item["minLength"].as_u64(), Some(1));
    let header_pattern = compile_pattern(header_item);
    assert!(header_pattern.is_match("x-request-id"));
    assert!(header_pattern.is_match("X-Request-ID"));
    assert!(!header_pattern.is_match(""));
    assert!(!header_pattern.is_match("bad header"));
    assert!(!header_pattern.is_match("bad:header"));

    // Issue #5189: a credential must be representable as an HTTP field value.
    for field in ["azure_function_key", "gcp_bearer_token"] {
        let pattern = pattern_for(field);
        assert!(pattern.is_match("ordinary-credential=="), "{field}");
        assert!(!pattern.is_match("audit\ncredential"), "{field}");
        assert!(!pattern.is_match("audit\rcredential"), "{field}");
        assert!(!pattern.is_match("audit\u{0}credential"), "{field}");
        assert!(!pattern.is_match("audit\u{7f}credential"), "{field}");
    }

    // Issue #5181: the Lambda Invoke identifier grammars.
    assert_eq!(
        properties["aws_function_name"]["maxLength"].as_u64(),
        Some(170)
    );
    assert_eq!(properties["aws_qualifier"]["maxLength"].as_u64(), Some(128));
    let name_pattern = pattern_for("aws_function_name");
    for accepted in [
        "my-function",
        "my_function.v2",
        "my-function:prod",
        "my-function:$LATEST",
        "123456789012:function:my-function",
        "arn:aws:lambda:us-east-1:123456789012:function:my-function",
        "arn:aws-cn:lambda:cn-north-1:123456789012:function:my-function:prod",
    ] {
        assert!(name_pattern.is_match(accepted), "name={accepted}");
    }
    for rejected in [" ", "my function", "my/function", "my-function:bad alias"] {
        assert!(!name_pattern.is_match(rejected), "name={rejected:?}");
    }
    let qualifier_pattern = pattern_for("aws_qualifier");
    for accepted in ["$LATEST", "prod", "1", "blue-green_2"] {
        assert!(qualifier_pattern.is_match(accepted), "qualifier={accepted}");
    }
    for rejected in ["not a qualifier", "bad/alias", ""] {
        assert!(
            !qualifier_pattern.is_match(rejected),
            "qualifier={rejected:?}"
        );
    }

    // Issue #5178: one lexical URL contract for both URL-valued fields.
    let url_pattern = pattern_for("function_url");
    for accepted in [
        "http://127.0.0.1/a%20b",
        "https://functions.example/api/transform",
        "https://functions.example:65535/api/transform",
        "https://[2001:db8::1]:8443/api/transform",
        "http://127.0.0.1:0/pre",
    ] {
        assert!(url_pattern.is_match(accepted), "url={accepted}");
    }
    for rejected in [
        "https://:1234",
        "https://127.0.0.1:65536/pre",
        "http://127.0.0.1/a b",
        "http://user:pass@127.0.0.1/pre",
        "https://functions.example/api#fragment",
    ] {
        assert!(!url_pattern.is_match(rejected), "url={rejected}");
    }
    let endpoint_pattern = pattern_for("aws_endpoint_url");
    for accepted in ["http://localhost:4566", "http://localhost:4566/"] {
        assert!(endpoint_pattern.is_match(accepted), "endpoint={accepted}");
    }
    for rejected in [
        "https://example.com/lambda",
        "https://example.com?token=secret",
        "https://:1234",
        "https://127.0.0.1:65536",
    ] {
        assert!(!endpoint_pattern.is_match(rejected), "endpoint={rejected}");
    }

    // Runtime parity for the same inputs: every schema rejection above is also
    // a constructor rejection, and the accepted base configuration builds.
    let base = json!({
        "provider": "azure_functions",
        "function_url": "http://127.0.0.1:45678/pre"
    });
    assert!(create_plugin("serverless_function", &base).is_ok());
    for extra in [
        json!({"function_url": "https://:1234"}),
        json!({"function_url": "https://127.0.0.1:65536/pre"}),
        json!({"function_url": "http://127.0.0.1/a b"}),
        json!({"forward_headers": [""]}),
        json!({"forward_headers": ["bad header"]}),
        json!({"azure_function_key": "audit\ncredential"}),
        json!({"gcp_bearer_token": "audit\ncredential"}),
        json!({"aws_function_name": "bad name"}),
        json!({"aws_qualifier": "not a qualifier"}),
        json!({"aws_endpoint_url": "https://example.com/lambda"}),
    ] {
        let mut config = base.clone();
        merge_into_object(&mut config, &extra);
        assert!(
            create_plugin("serverless_function", &config).is_err(),
            "runtime must reject the schema-invalid config: {config}"
        );
    }
}

/// Issue #5239: the `ApiChargebackConfig` component must reject exactly what the
/// constructor rejects — no-op pricing, blank currency, out-of-range or
/// duplicate status codes, negative timer/budget values, simultaneous `schema`
/// and `schema_ref`, and projection features the billing-row record family
/// cannot express.
#[test]
fn api_chargeback_schema_admits_only_constructible_configs() {
    use ferrum_edge::plugins::api_chargeback::ApiChargeback;

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/ApiChargebackConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("ApiChargebackConfig schema compiles");

    // The minimal effective configuration: a nonempty tier counts even at a
    // zero price, because an explicitly zero-priced tier still meters calls.
    let base = json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0}]});
    let with = |patch: serde_json::Value| -> serde_json::Value {
        let mut config = base.clone();
        let object = config.as_object_mut().expect("base is an object");
        for (key, value) in patch.as_object().expect("patch is an object") {
            object.insert(key.clone(), value.clone());
        }
        config
    };
    let accept = |config: serde_json::Value| {
        assert!(
            validator.validate(&config).is_ok(),
            "OpenAPI must admit {config}"
        );
        ApiChargeback::new(&config, "ferrum")
            .unwrap_or_else(|err| panic!("runtime must admit {config}: {err}"));
    };
    let reject = |config: serde_json::Value| {
        assert!(
            validator.validate(&config).is_err(),
            "OpenAPI must reject {config}"
        );
        assert!(
            ApiChargeback::new(&config, "ferrum").is_err(),
            "runtime must reject {config}"
        );
    };

    let documented_per_call = json!({
        "currency": "USD",
        "pricing_tiers": [
            {"status_codes": [200, 201, 202, 204], "price_per_call": 0.00001},
            {"status_codes": [301, 302], "price_per_call": 0.000005}
        ]
    });
    let documented_combined = json!({
        "currency": "USD",
        "pricing_tiers": [
            {"status_codes": [200, 201, 202, 204], "price_per_call": 0.00001}
        ],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000000001,
            "price_per_byte_received": 0.0000000002
        },
        "stream_connection_pricing": {"price_per_connection": 0.0005}
    });
    let supported_derived = json!({
        "schema": {"derived_fields": [{"name": "row_kind", "kind": "summary_kind"}]}
    });

    accept(base.clone());
    accept(json!({"bandwidth_pricing": {"price_per_byte_sent": 0.01}}));
    accept(json!({"bandwidth_pricing": {"price_per_byte_received": 0.02}}));
    accept(json!({"stream_connection_pricing": {"price_per_connection": 5}}));
    accept(json!({"pricing_tiers": [{"status_codes": [100, 599], "price_per_call": 1}]}));
    accept(documented_per_call);
    accept(documented_combined);
    accept(with(json!({"schema": {"omit": ["proxy_name"]}})));
    accept(with(
        json!({"schema": {"rename": {"total_calls": "calls"}}}),
    ));
    accept(with(supported_derived));

    let unrepresentable_derived = json!({
        "schema": {"derived_fields": [{"name": "host", "kind": "backend_host"}]}
    });

    // No effective pricing: the plugin would record nothing.
    reject(json!({}));
    reject(json!({"bandwidth_pricing": {}}));
    reject(json!({"bandwidth_pricing": {"price_per_byte_sent": 0}}));
    reject(json!({"stream_connection_pricing": {"price_per_connection": 0}}));
    reject(json!({"pricing_tiers": []}));
    // Currency is trimmed and must not be empty.
    reject(with(json!({"currency": ""})));
    reject(with(json!({"currency": " \t "})));
    // Status codes must be real HTTP statuses, distinct within a tier.
    reject(json!({"pricing_tiers": [{"status_codes": [99], "price_per_call": 1}]}));
    reject(json!({"pricing_tiers": [{"status_codes": [600], "price_per_call": 1}]}));
    reject(json!({"pricing_tiers": [{"status_codes": [200, 200], "price_per_call": 1}]}));
    // Timer / budget knobs are unsigned 64-bit integers.
    reject(with(json!({"render_cache_ttl_seconds": -1})));
    reject(with(json!({"stale_entry_ttl_seconds": -1})));
    reject(with(json!({"cache_invalidation_min_age_ms": -1})));
    reject(with(json!({"cleanup_interval_seconds": -1})));
    reject(with(json!({"max_entries": 0})));
    reject(with(json!({"max_retained_bytes": 0})));
    // Projection surface: mutually exclusive, and narrowed to the billing row.
    reject(with(json!({"schema": {}, "schema_ref": "missing"})));
    reject(with(json!({"schema": {"order": ["proxy_id"]}})));
    reject(with(json!({"schema": {"summary_type": "http"}})));
    reject(with(json!({"schema": {"timestamp_format": "epoch_ms"}})));
    reject(with(json!({"schema": {"metadata": {"mode": "omit"}}})));
    reject(with(json!({"schema": {"omit": ["response_status_code"]}})));
    reject(with(json!({"schema": {"rename": {"client_ip": "ip"}}})));
    reject(with(unrepresentable_derived));

    // Constraints that stay runtime-only must be documented as such rather than
    // silently missing from the component.
    let component = spec
        .pointer("/components/schemas/ApiChargebackConfig")
        .expect("ApiChargebackConfig exists");
    let description = component["description"].as_str().expect("a description");
    assert!(
        description.contains("Runtime-only admission"),
        "the component must name the constraints JSON Schema cannot express"
    );

    let guide = include_str!("../../docs/plugins.md");
    let section = guide
        .split("### `api_chargeback`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("api_chargeback docs section");
    assert!(
        section.contains("Precise admission rules"),
        "docs/plugins.md must state the exact admission rules"
    );
    assert!(
        section.contains("unsigned 64-bit integer"),
        "docs/plugins.md must state the unsigned bound on the timer knobs"
    );
}
