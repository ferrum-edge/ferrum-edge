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
        spec.pointer("/components/schemas/BackupResponse/properties/consumers/items/$ref"),
        Some(&json!("#/components/schemas/ConsumerBackup"))
    );
    assert_eq!(
        spec.pointer("/components/schemas/RestoreRequest/properties/consumers/items/$ref"),
        Some(&json!("#/components/schemas/ConsumerRestore"))
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

#[test]
fn graphql_config_schema_matches_runtime_validation() {
    use ferrum_edge::plugins::create_plugin;
    use ferrum_edge::plugins::graphql::GRAPHQL_CONFIG_KEYS;
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
    assert_eq!(
        schema["properties"]["applicable_methods"]["items"]["pattern"],
        json!("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
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
    let redis_guard = schema["allOf"]
        .as_array()
        .expect("RequestDeduplicationConfig allOf")
        .iter()
        .find(|guard| guard["if"]["properties"]["sync_mode"]["const"] == json!("redis"))
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

    for invalid in [
        json!({"providers": [{"name": "p", "provider_type": "openai"}], "fallback_on_netwrok_errors": true}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "model_paterns": []}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "circuit_breaker": {"failure_treshold": 2}}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "base_url": "http://127.0.0.1/v1/chat"}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "model_mapping": {"gpt-../unsafe": "gpt-4o"}}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "max_response_body_bytes": 0}]}),
        json!({"providers": [{"name": "p", "provider_type": "openai", "api_key": "test", "max_response_body_bytes": 67_108_865}]}),
    ] {
        assert!(
            validator.validate(&invalid).is_err(),
            "schema accepted {invalid}"
        );
    }
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

    for (plugin_name, config) in [
        ("correlation_id", json!({})),
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
    assert_eq!(runtime_overlay["type"], json!("string"));
    assert_eq!(runtime_overlay["minLength"], json!(1));
    assert_eq!(runtime_overlay["pattern"], json!("\\S"));
    assert_eq!(
        spec.pointer("/components/schemas/RequestTransformerConfig/properties/default_enabled")
            .expect("default_enabled remains published")["default"],
        json!(true)
    );

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
    ] {
        assert_component_validity(&spec, "RequestTransformerConfig", &config, false);
        assert!(
            RequestTransformer::new(&config).is_err(),
            "runtime accepted OpenAPI-invalid request_transformer config: {config}"
        );
    }

    // Operation-incompatible extras are known OpenAPI properties but still fail
    // runtime construction (schema cannot encode per-operation field sets).
    let incompatible = json!({
        "rules": [{
            "operation": "update",
            "target": "header",
            "key": "X-Color",
            "value": "blue",
            "new_key": "X-Ignored"
        }]
    });
    assert_component_validity(&spec, "RequestTransformerConfig", &incompatible, true);
    assert!(
        RequestTransformer::new(&incompatible).is_err(),
        "runtime must reject operation-incompatible header fields: {incompatible}"
    );
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
    assert_eq!(runtime_overlay["type"], json!("string"));
    assert_eq!(runtime_overlay["minLength"], json!(1));
    assert_eq!(runtime_overlay["pattern"], json!("\\S"));
    assert_eq!(
        spec.pointer("/components/schemas/ResponseTransformerConfig/properties/default_enabled")
            .expect("default_enabled remains published")["default"],
        json!(true)
    );

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
    ] {
        assert_component_validity(&spec, "ResponseTransformerConfig", &config, false);
        assert!(
            ResponseTransformer::new(&config).is_err(),
            "runtime accepted OpenAPI-invalid response_transformer config: {config}"
        );
    }

    // Operation-incompatible extras are known OpenAPI properties but still fail
    // runtime construction (schema cannot encode per-operation field sets).
    let incompatible = json!({
        "rules": [{
            "operation": "update",
            "target": "header",
            "key": "X-Color",
            "value": "blue",
            "new_key": "X-Ignored"
        }]
    });
    assert_component_validity(&spec, "ResponseTransformerConfig", &incompatible, true);
    assert!(
        ResponseTransformer::new(&incompatible).is_err(),
        "runtime must reject operation-incompatible header fields: {incompatible}"
    );
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

    assert_component_validity(
        &spec,
        "BodyValidatorConfig",
        &json!({"grpc_max_decompressed_size_bytes": 0}),
        true,
    );
    assert_component_validity(
        &spec,
        "BodyValidatorConfig",
        &json!({"grpc_max_decompressed_size_bytes": -1}),
        false,
    );
    assert_component_validity(
        &spec,
        "BodyValidatorConfig",
        &json!({"grpc_max_decompressed_size_bytes": "10"}),
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
        json!({"schema_ref": "common"}),
    ] {
        assert_component_validity(&spec, "StdoutLoggingConfig", &valid, true);
    }
    for invalid in [
        json!({"filters": {"errors_only": true}}),
        json!({"log_level": "info"}),
        json!({"filter": {"error_only": true}}),
        json!({"filter": {"min_latency_msec": 100}}),
    ] {
        assert_component_validity(&spec, "StdoutLoggingConfig", &invalid, false);
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
        json!({"endpoint_url": "https://logs.example.com/push", "flush_interval_ms": 600001}),
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
        "^[A-Za-z_][A-Za-z0-9_.-]*$",
        "global_tags keys must encode the runtime ASCII tag-key grammar"
    );
    assert_eq!(
        schema["properties"]["global_tags"]["propertyNames"]["maxLength"], 64,
        "global_tags key ceiling must match the runtime 64-byte ASCII limit"
    );
    let prefix_desc = schema["properties"]["prefix"]["description"]
        .as_str()
        .unwrap_or("");
    assert!(
        prefix_desc.contains("Unicode characters") && prefix_desc.contains("UTF-8 bytes"),
        "prefix description must distinguish OpenAPI character maxLength from runtime byte cap: {prefix_desc}"
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

    let valid_minima = json!({"host": "127.0.0.1"});
    assert_component_validity(&spec, "StatsdLoggingConfig", &valid_minima, true);
    assert!(StatsdLogging::new(&valid_minima, PluginHttpClient::default()).is_ok());

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
    ];
    for config in runtime_and_schema_invalid {
        assert_component_validity(&spec, "StatsdLoggingConfig", &config, false);
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
        r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)$",
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
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "mesh": {
                "egress_scope": health,
                "node_waypoint_observability": node_waypoint_observability
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
    ] {
        assert_eq!(
            spec.pointer(pointer)
                .and_then(|value| value.get("$ref"))
                .and_then(serde_json::Value::as_str),
            Some("#/components/responses/NamespaceAdmissionUnavailable"),
            "namespace mutation is missing retryable 503 response: {pointer}"
        );
    }

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
    let body_field_items = &schema["properties"]["redacted_body_fields"]["items"];
    assert_eq!(body_field_items["minLength"], json!(1));
    assert_eq!(body_field_items["maxLength"], json!(128));
    assert_eq!(body_field_items["pattern"], json!("\\S"));

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
    ] {
        assert!(
            plugin_docs.contains(contract),
            "docs/plugins.md missing transaction_debugger contract `{contract}`"
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
        .pointer("/components/schemas/PluginConfig/properties/config/description")
        .and_then(|v| v.as_str())
        .expect("PluginConfig.config description");
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
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/SpecExposeConfig")
        .expect("SpecExposeConfig component exists");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["spec_url"]));
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
    for invalid in [
        json!({"spec_url": "https://example.com/openapi.yaml", "tls_no_verfy": true}),
        json!({"spec_url": "https://example.com/openapi.yaml", "content_type": 7}),
        json!({"spec_url": "https://example.com/openapi.yaml", "tls_no_verify": "false"}),
        json!({"spec_url": "https://example.com/openapi.yaml", "cache_ttl_seconds": -1}),
        json!({"spec_url": "https://example.com/openapi.yaml", "max_response_body_bytes": 0}),
    ] {
        assert_component_validity(&spec, "SpecExposeConfig", &invalid, false);
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

    for valid in [
        json!({}),
        json!({"status_code": 451, "message": "unavailable"}),
        json!({"status_code": 204}),
        json!({"body": "", "message": "ignored"}),
        json!({
            "status_code": 403,
            "content_type": "application/hal+json",
            "trigger": {"path_prefix": "/admin"}
        }),
        json!({
            "trigger": {"header": "x-maintenance", "header_value": "1"}
        }),
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
        json!({"body": null}),
        json!({"message": null}),
        json!({"trigger": null}),
        json!({"trigger": {"path_prefix": null}}),
        json!({"trigger": {"header": null}}),
        json!({"trigger": {"header": "x-policy", "header_value": null}}),
        json!({"trigger": {}}),
        json!({"trigger": {"path_prefix": "/a", "header": "x-policy"}}),
        json!({"trigger": {"path_prefix": "/a", "header_value": "1"}}),
        json!({"trigger": {"header_value": "1"}}),
        json!({"trigger": {"path_prefix": "/a", "extra": true}}),
        json!({"unknown": true}),
    ] {
        assert_component_validity(&spec, "RequestTerminationConfig", &invalid, false);
        assert!(
            RequestTermination::new(&invalid).is_err(),
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    // Runtime contracts deliberately left to construction-time validation.
    for runtime_only in [
        json!({"status_code": 204, "body": "x"}),
        json!({"content_type": "application/xml", "message": "\u{0001}"}),
    ] {
        assert!(
            RequestTermination::new(&runtime_only).is_err(),
            "runtime must reject {runtime_only}"
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
    // ttl_seconds intentionally has no minimum: the runtime accepts 0.
    assert!(schema["properties"]["ttl_seconds"]["minimum"].is_null());
    assert_eq!(
        schema["properties"]["cacheable_methods"]["minItems"],
        json!(1)
    );
    assert_eq!(
        schema["properties"]["cacheable_methods"]["items"]["pattern"],
        json!("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
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
        // Extension-method casing is accepted and uppercased by the runtime.
        json!({"cacheable_methods": ["get"]}),
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
    assert_eq!(rule["properties"]["status_code"]["minimum"], 100);
    assert_eq!(rule["properties"]["status_code"]["maximum"], 599);
    assert_eq!(
        rule["properties"]["headers"]["additionalProperties"]["type"],
        "string"
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
        json!({"rules": [{"path": "/health", "status_code": 99, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 100, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 103, "body": "ok"}]}),
        json!({"rules": [{"path": "/health", "status_code": 600, "body": "ok"}]}),
        json!({"rules": [{"body": "missing-path"}]}),
        json!({"rules": []}),
        json!({}),
        json!({
            "rules": [{
                "path": "/health",
                "headers": {"x-mock": 42}
            }]
        }),
    ] {
        // OpenAPI keeps minimum 100 / maximum 599; runtime rejects unsupported
        // informational statuses (100, 102–199) as the authoritative boundary.
        let runtime_err = ResponseMock::new(&invalid).is_err();
        if invalid
            .pointer("/rules/0/status_code")
            .and_then(|v| v.as_u64())
            .is_some_and(|code| matches!(code, 100 | 103))
        {
            assert!(
                runtime_err,
                "informational status must fail runtime: {invalid}"
            );
            continue;
        }
        assert_component_validity(&spec, "ResponseMockConfig", &invalid, false);
        assert!(
            runtime_err,
            "schema-invalid config unexpectedly passed runtime: {invalid}"
        );
    }

    let guide = include_str!("../../docs/plugins.md");
    assert!(guide.contains("Exact (`=/api/v1`)"));
    assert!(guide.contains("Host-only"));
    assert!(guide.contains("WebSocket handshake contract"));
    assert!(guide.contains("never establishes an upgraded frame stream"));
    assert!(guide.contains("Unknown top-level and per-rule keys are rejected"));
    assert!(guide.contains("Status / body wire semantics"));
    assert!(guide.contains("informational statuses"));
    assert!(guide.contains("Native gRPC exclusion"));
    assert!(guide.contains("native gRPC unsupported"));

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
    let enum_values: Vec<String> = provider_schema["enum"]
        .as_array()
        .expect("provider enum must be present")
        .iter()
        .map(|v| v.as_str().expect("enum entry is string").to_string())
        .collect();
    assert_eq!(
        enum_values,
        vec![
            "auto",
            "openai",
            "anthropic",
            "google",
            "cohere",
            "mistral",
            "bedrock",
            // Native Hugging Face TGI (GHSA-rxj9-f483-g53f): its authoritative
            // counts live under `details`, not a `usage` container, so it needs
            // its own provider value rather than the OpenAI vocabulary.
            "tgi"
        ],
        "provider enum must match the runtime accepted set"
    );

    for supported in &enum_values {
        let config = json!({ "token_limit": 100000, "provider": supported });
        assert!(
            validator.validate(&config).is_ok(),
            "provider '{supported}' should be accepted by the schema"
        );
        AiRateLimiter::new(&config, PluginHttpClient::default())
            .unwrap_or_else(|err| panic!("runtime must accept provider '{supported}': {err}"));
    }

    for rejected in &["gemini", "vertex", "openai_compatible", "gpt", ""] {
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
        "docs must enumerate tgi as an accepted provider"
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
}
