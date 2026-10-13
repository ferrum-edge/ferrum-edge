//! Default-deny guard for the plugin material registry
//! (`src/admin/crud/scoped_references.rs`).
//!
//! Namespace-bounded operators may introduce a plugin field that makes the
//! gateway read a file, credential or native module with its own identity
//! only through that registry. A built-in plugin schema field whose name looks
//! path-, file-, certificate-, key-, module- or library-shaped must therefore be
//! either registered or explicitly reviewed as non-material. A new such field
//! fails this test until it is classified.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const SENSITIVE_TOKENS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "dir",
    "location",
    "cert",
    "certs",
    "certificate",
    "certificates",
    "key",
    "pem",
    "keystore",
    "truststore",
    "module",
    "library",
    "libraries",
    "provider",
    "providers",
    "engine",
    "kinit",
    "keytab",
    "ca",
];

fn is_sensitive(name: &str) -> bool {
    name.split('_').any(|token| {
        let token = token.to_ascii_lowercase();
        SENSITIVE_TOKENS.contains(&token.as_str())
            || token
                .strip_prefix("pkcs")
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
    })
}

fn openapi() -> Value {
    serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses")
}

/// `plugin_name` -> config schema name, from the `PluginConfigBase` if/then arms.
fn plugin_config_schemas(spec: &Value) -> BTreeMap<String, String> {
    fn visit(node: &Value, out: &mut BTreeMap<String, String>) {
        match node {
            Value::Object(object) => {
                let plugin = node["if"]["properties"]["plugin_name"]["const"].as_str();
                let schema = node["then"]["properties"]["config"]["$ref"].as_str();
                if let (Some(plugin), Some(schema)) = (plugin, schema) {
                    let name = schema.rsplit('/').next().expect("schema ref name");
                    out.insert(plugin.to_string(), name.to_string());
                }
                for child in object.values() {
                    visit(child, out);
                }
            }
            Value::Array(items) => {
                for child in items {
                    visit(child, out);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeMap::new();
    visit(&spec["components"]["schemas"]["PluginConfigBase"], &mut out);
    out
}

/// Every property path of a schema, and those whose name is sensitive.
fn walk(
    schemas: &Value,
    schema: &Value,
    prefix: &str,
    seen: &[String],
    all: &mut BTreeSet<String>,
    hits: &mut BTreeSet<String>,
) {
    let Some(object) = schema.as_object() else {
        return;
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().expect("schema ref name");
        if seen.iter().any(|visited| visited == name) {
            return;
        }
        let mut next = seen.to_vec();
        next.push(name.to_string());
        walk(schemas, &schemas[name], prefix, &next, all, hits);
        return;
    }
    for combinator in ["allOf", "oneOf", "anyOf"] {
        if let Some(variants) = object.get(combinator).and_then(Value::as_array) {
            for variant in variants {
                walk(schemas, variant, prefix, seen, all, hits);
            }
        }
    }
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            all.insert(path.clone());
            if is_sensitive(name) {
                hits.insert(path.clone());
            }
            walk(schemas, property, &path, seen, all, hits);
        }
    }
    if let Some(items) = object.get("items").filter(|items| items.is_object()) {
        walk(schemas, items, &format!("{prefix}[]"), seen, all, hits);
    }
    if let Some(additional) = object
        .get("additionalProperties")
        .filter(|additional| additional.is_object())
    {
        walk(schemas, additional, &format!("{prefix}.*"), seen, all, hits);
    }
}

fn normalize(path: &str) -> &str {
    path.strip_suffix("[]").unwrap_or(path)
}

#[test]
fn every_path_shaped_builtin_plugin_field_is_classified() {
    let spec = openapi();
    let schemas = &spec["components"]["schemas"];
    let plugin_schemas = plugin_config_schemas(&spec);
    assert!(
        plugin_schemas.len() > 50,
        "the PluginConfigBase plugin_name -> config mapping must be found: {plugin_schemas:?}"
    );

    let mut classified: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (plugin, path, _) in ferrum_edge::_test_support::scoped_plugin_registry_for_test() {
        classified
            .entry(plugin)
            .or_default()
            .insert(normalize(path));
    }
    for (plugin, path) in ferrum_edge::_test_support::reviewed_non_material_plugin_fields_for_test()
    {
        classified
            .entry(plugin)
            .or_default()
            .insert(normalize(path));
    }

    let mut unclassified = Vec::new();
    let mut stale = Vec::new();
    for (plugin, schema) in &plugin_schemas {
        let mut all = BTreeSet::new();
        let mut hits = BTreeSet::new();
        walk(
            schemas,
            &schemas[schema.as_str()],
            "",
            std::slice::from_ref(schema),
            &mut all,
            &mut hits,
        );
        let known = classified.get(plugin.as_str()).cloned().unwrap_or_default();
        for hit in &hits {
            if !known.contains(hit.as_str()) {
                unclassified.push(format!("{plugin}: {hit}"));
            }
        }
        for path in known {
            if !all.contains(path) {
                stale.push(format!("{plugin}: {path}"));
            }
        }
    }
    for plugin in classified.keys() {
        if !plugin_schemas.contains_key(*plugin) {
            stale.push(format!("{plugin}: (no plugin config schema)"));
        }
    }
    assert!(
        unclassified.is_empty(),
        "classify these plugin fields in src/admin/crud/scoped_references.rs \
         (PLUGIN_SCOPED_FIELDS when the gateway reads a file, credential or native \
         module with its own identity, otherwise REVIEWED_NON_MATERIAL_FIELDS): \
         {unclassified:#?}"
    );
    assert!(
        stale.is_empty(),
        "registry entries that match no schema field: {stale:#?}"
    );
}

#[test]
fn every_registered_plugin_is_a_builtin() {
    let builtins: BTreeSet<&str> = ferrum_edge::plugins::BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|registration| registration.name)
        .collect();
    for (plugin, path, _) in ferrum_edge::_test_support::scoped_plugin_registry_for_test() {
        assert!(builtins.contains(plugin), "{plugin}: {path}");
    }
}

#[test]
fn registry_extracts_concrete_field_paths_and_unsafe_open_map_keys() {
    let references = ferrum_edge::_test_support::plugin_scoped_references_for_test(
        "mesh_route_dispatch",
        &json!({"rules": [
            {"destination": {"backend_host": "a"}},
            {"destination": {"backend_tls": {
                "client_cert_path": "/c.pem",
                "server_ca_cert_path": "system://"
            }}}
        ]}),
    );
    assert_eq!(
        references,
        vec![
            (
                "config.rules[1].destination.backend_tls.client_cert_path".to_string(),
                "/c.pem".to_string(),
                "tls"
            ),
            (
                "config.rules[1].destination.backend_tls.server_ca_cert_path".to_string(),
                "system://".to_string(),
                "tls"
            ),
        ]
    );

    let references = ferrum_edge::_test_support::plugin_scoped_references_for_test(
        "soap_ws_security",
        &json!({"x509_signature": {"trusted_certs": ["/a.pem", "k8s://ns/s#tls.crt"]}}),
    );
    let paths: Vec<_> = references
        .iter()
        .map(|(path, _, _)| path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "config.x509_signature.trusted_certs[0]",
            "config.x509_signature.trusted_certs[1]"
        ]
    );

    let references = ferrum_edge::_test_support::plugin_scoped_references_for_test(
        "kafka_logging",
        &json!({
            "ssl_ca_location": "/etc/ca.pem",
            "producer_config": {
                "linger.ms": "5",
                "Compression.Type": "lz4",
                "ssl.providers": "legacy",
                "plugin.library.paths": "/tmp/x.so",
                "sasl.kerberos.kinit.cmd": "id"
            }
        }),
    );
    let mut paths: Vec<_> = references
        .iter()
        .map(|(path, _, class)| (path.as_str(), *class))
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            (
                "config.producer_config.plugin.library.paths",
                "gateway_only"
            ),
            (
                "config.producer_config.sasl.kerberos.kinit.cmd",
                "gateway_only"
            ),
            ("config.producer_config.ssl.providers", "gateway_only"),
            ("config.ssl_ca_location", "gateway_only"),
        ]
    );

    assert!(
        ferrum_edge::_test_support::plugin_scoped_references_for_test(
            "cors",
            &json!({"allowed_origins": ["https://a.example"]})
        )
        .is_empty()
    );
}

/// No native `producer_config` key (issue #6539) may be on the tenant-safe
/// list: a namespace-bounded operator stays refused even on a node that sets
/// `FERRUM_KAFKA_ALLOW_NATIVE_CONFIG=true`.
#[test]
fn kafka_native_producer_keys_are_never_tenant_safe() {
    for (key, effect) in ferrum_edge::_test_support::kafka_native_producer_keys_for_test() {
        assert!(!effect.is_empty(), "{key}: the refusal must say why");
        let references = ferrum_edge::_test_support::plugin_scoped_references_for_test(
            "kafka_logging",
            &json!({"producer_config": {*key: "x"}}),
        );
        assert_eq!(
            references,
            vec![(
                format!("config.producer_config.{key}"),
                "x".to_string(),
                "gateway_only"
            )],
            "{key} must stay refused for namespace-bounded operators"
        );
    }
}
