use ferrum_edge::config::config_backup::load_config_backup;
use ferrum_edge::config::types::CURRENT_CONFIG_VERSION;
use serde_json::json;
use std::io::Write;

fn administrative_backup() -> serde_json::Value {
    json!({
        "version": CURRENT_CONFIG_VERSION,
        "ferrum_version": "test",
        "exported_at": "2026-09-08T00:00:00Z",
        "source": "database",
        "counts": {},
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [],
        "api_specs": {"section_version": "2", "items": []},
        "gateway_trust_bundles": []
    })
}

#[test]
fn backup_envelope_is_not_a_runtime_trust_or_spec_authority() {
    let mut value = administrative_backup();
    // Bootstrap neither interprets nor applies these admin-only sections.
    value["gateway_trust_bundles"] = json!([{"namespace": "tenant-a", "bundle": "stale"}]);
    value["api_specs"] = json!({"unrelated_schema": {"private_key": "test-only"}});
    let (_tmp, path) = write_tmp_file(&value.to_string());
    let loaded = load_config_backup(&path, "tenant-a").unwrap().unwrap();
    assert!(loaded.gateway_trust_bundles.is_empty());
    assert!(loaded.trust_bundles.is_none());
    assert_eq!(loaded.known_namespaces, ["tenant-a"]);
}

#[test]
fn backup_envelope_keeps_version_and_runtime_schema_checks() {
    for (field, invalid) in [
        ("version", json!("999999")),
        ("unexpected_runtime_field", json!(true)),
        ("proxies", json!("not-an-array")),
    ] {
        let mut value = administrative_backup();
        value[field] = invalid;
        let (_tmp, path) = write_tmp_file(&value.to_string());
        assert!(load_config_backup(&path, "ferrum").is_err(), "{field}");
    }
}

#[test]
fn backup_consumer_admission_matches_sorted_database_quarantine_after_projection() {
    let mut value = administrative_backup();
    value["consumers"] = json!([
        {"id": "z", "username": "shared", "namespace": "tenant-a"},
        {"id": "a", "username": "shared", "namespace": "tenant-a"},
        {"id": "b", "username": "independent", "custom_id": "b", "namespace": "tenant-a"},
        {"id": "a", "username": "shared", "namespace": "tenant-b"}
    ]);
    let (_tmp, path) = write_tmp_file(&value.to_string());
    let loaded = load_config_backup(&path, "tenant-a").unwrap().unwrap();
    assert_eq!(
        loaded
            .consumers
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert!(loaded.validate_unique_consumer_identities().is_ok());
    let foreign = load_config_backup(&path, "tenant-b").unwrap().unwrap();
    assert_eq!(foreign.consumers.len(), 1);
    assert_eq!(foreign.consumers[0].namespace, "tenant-b");
}

#[test]
fn backup_rejects_duplicate_resource_ids_before_quarantine() {
    let mut value = administrative_backup();
    value["consumers"] = json!([
        {"id": "same", "username": "first"},
        {"id": "same", "username": "second"}
    ]);
    let (_tmp, path) = write_tmp_file(&value.to_string());
    assert!(
        load_config_backup(&path, "ferrum")
            .unwrap_err()
            .to_string()
            .contains("duplicate resource ID")
    );
}

#[test]
fn backup_rejects_malformed_consumer_credentials_without_echoing_values() {
    for credentials in [
        json!({"keyauth": {"key": "credential-canary"}}),
        json!({"keyauth": ["credential-canary"]}),
        json!({"jwt": [{"secret": "short-credential-canary"}]}),
        json!({"jwt": [{
            "secret": "a-valid-test-secret-with-at-least-32-chars",
            "private_key": "credential-canary"
        }]}),
        json!({"keyauth": [{"key": "[REDACTED]"}]}),
    ] {
        let mut value = administrative_backup();
        value["consumers"] = json!([{"id": "c", "username": "user", "credentials": credentials}]);
        let (_tmp, path) = write_tmp_file(&value.to_string());
        let error = load_config_backup(&path, "ferrum").unwrap_err().to_string();
        assert!(error.contains("consumer validation"));
        assert!(!error.contains("credential-canary"));
        assert!(!error.contains("private_key"));
    }
}

#[test]
fn backup_preserves_canonical_secrets_and_custom_schema_fields() {
    let credentials = json!({
        "jwt": [{"secret": "a-valid-test-secret-with-at-least-32-chars"}],
        "keyauth": [{"key": "first-key"}, {"key": "rotation-key"}],
        "custom": [{"schema": {"private_key": {"type": "string"}}}]
    });
    let mut value = administrative_backup();
    value["consumers"] = json!([{"id": "c", "username": "user", "credentials": credentials}]);
    let (_tmp, path) = write_tmp_file(&value.to_string());
    let loaded = load_config_backup(&path, "ferrum").unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&loaded.consumers[0].credentials).unwrap(),
        credentials
    );
}

#[test]
fn backup_quarantines_identity_conflicts_while_file_admission_still_rejects() {
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::config::file_loader::load_config_from_file;
    use ferrum_edge::config::types::GatewayConfig;

    for (first_field, second_field) in [
        ("username", "username"),
        ("id", "username"),
        ("username", "custom_id"),
        ("custom_id", "custom_id"),
    ] {
        let mut first = json!({"id": "a", "username": "alice"});
        let mut second = json!({"id": "z", "username": "zoe"});
        for consumer in [&mut first, &mut second] {
            consumer["created_at"] = json!("2026-09-08T00:00:00Z");
            consumer["updated_at"] = json!("2026-09-08T00:00:00Z");
        }
        first[first_field] = json!("a");
        second[second_field] = json!("a");
        let value = json!({
            "version": CURRENT_CONFIG_VERSION, "proxies": [],
            "plugin_configs": [], "upstreams": [], "consumers": [first, second]
        });
        let mut database_candidate: GatewayConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            database_candidate
                .quarantine_colliding_consumer_identities()
                .len(),
            1
        );
        let (_tmp, path) = write_tmp_file(&value.to_string());
        let loaded = load_config_backup(&path, "ferrum").unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&loaded.consumers).unwrap(),
            serde_json::to_value(&database_candidate.consumers).unwrap()
        );
        let error =
            load_config_from_file(&path, 30, &BackendEgressPolicy::unrestricted(), "ferrum")
                .unwrap_err();
        assert!(error.to_string().contains("consumer identity"));
    }
}

#[test]
fn backup_rejects_oversized_files_before_reading_them() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.as_file().set_len(64 * 1024 * 1024 + 1).unwrap();
    let error = load_config_backup(tmp.path().to_str().unwrap(), "ferrum").unwrap_err();
    assert!(error.to_string().contains("maximum supported size"));
}

#[test]
fn backup_rejects_duplicate_credentials_inside_the_served_namespace() {
    let mut value = administrative_backup();
    value["consumers"] = json!([
        {"id": "a", "username": "alice", "credentials": {"keyauth": [{"key": "same-test-key"}]}},
        {"id": "b", "username": "bob", "credentials": {"keyauth": [{"key": "same-test-key"}]}}
    ]);
    let (_tmp, path) = write_tmp_file(&value.to_string());
    let error = load_config_backup(&path, "ferrum").unwrap_err().to_string();
    assert!(error.contains("duplicate credential"));
    assert!(!error.contains("same-test-key"));
}

fn write_tmp_file(content: &str) -> (tempfile::NamedTempFile, String) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(content.as_bytes()).unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    (tmp, path)
}

#[test]
fn test_load_config_backup_valid_json() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "proxy-1",
            "name": "test-proxy",
            "listen_path": "/api",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_scheme": "http"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path, "ferrum")
        .expect("valid backup must succeed")
        .expect("valid backup must return Some");
    assert_eq!(loaded.proxies.len(), 1);
    assert_eq!(loaded.proxies[0].id, "proxy-1");
    assert_eq!(loaded.proxies[0].listen_path.as_deref(), Some("/api"));
    assert_eq!(loaded.proxies[0].backend_host, "localhost");
    assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);
}

#[test]
fn test_load_config_backup_file_not_found() {
    let result = load_config_backup("/tmp/nonexistent-ferrum-backup-12345.json", "ferrum")
        .expect("missing file is Ok(None), not Err");
    assert!(result.is_none(), "should return None for missing file");
}

#[test]
fn test_load_config_backup_invalid_json() {
    let (_tmp, path) = write_tmp_file("{ not valid json }}}");
    let err =
        load_config_backup(&path, "ferrum").expect_err("invalid JSON must be Err, not Ok(None)");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to parse config backup"),
        "parse failure must be actionable, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_read_failure_is_not_missing() {
    let directory = tempfile::tempdir().expect("temp directory");
    let err = load_config_backup(
        directory
            .path()
            .to_str()
            .expect("temporary directory path must be UTF-8"),
        "ferrum",
    )
    .expect_err("a configured path that cannot be read as a file must be Err");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to read config backup"),
        "read failure must be actionable, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_empty_config() {
    let json = r#"{
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path, "ferrum")
        .expect("empty valid backup must succeed")
        .expect("empty valid backup must return Some");
    assert!(loaded.proxies.is_empty());
    assert!(loaded.consumers.is_empty());
    assert!(loaded.upstreams.is_empty());
}

#[test]
fn test_load_config_backup_stream_proxy_has_no_listen_path() {
    // Stream proxies route on listen_port and never carry a listen_path.
    // The loader accepts backups that omit the field entirely — serde(default)
    // deserializes to None.
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "tcp-proxy-1",
            "name": "tcp-test",
            "backend_host": "10.0.0.1",
            "backend_port": 5432,
            "backend_scheme": "tcp",
            "listen_port": 9999
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path, "ferrum")
        .expect("stream proxy backup must succeed")
        .expect("stream proxy backup must return Some");
    assert_eq!(
        loaded.proxies[0].listen_path, None,
        "stream proxy backups must deserialize to listen_path=None"
    );
    assert_eq!(loaded.proxies[0].listen_port, Some(9999));
}

#[test]
fn test_load_config_backup_preserves_every_resource_in_the_active_namespace() {
    // The loader filters to the serving namespace, so this asserts the other
    // half of that contract: nothing the active namespace owns is dropped.
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "namespace": "tenant-a",
                "listen_path": "/one",
                "backend_host": "host1",
                "backend_port": 3000,
                "backend_scheme": "http"
            },
            {
                "id": "p2",
                "name": "proxy-two",
                "namespace": "tenant-a",
                "listen_path": "/two",
                "backend_host": "host2",
                "backend_port": 3001,
                "backend_scheme": "http"
            }
        ],
        "consumers": [{
            "id": "c1",
            "username": "user1",
            "custom_id": "cust1",
            "namespace": "tenant-a"
        }],
        "plugin_configs": [{
            "id": "pc1",
            "plugin_name": "key_auth",
            "namespace": "tenant-a",
            "scope": "global",
            "config": {},
            "enabled": false
        }],
        "upstreams": [{
            "id": "u1",
            "name": "upstream-1",
            "namespace": "tenant-a",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        }]
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path, "tenant-a")
        .expect("multi-resource backup must succeed")
        .expect("multi-resource backup must return Some");
    assert_eq!(loaded.proxies.len(), 2);
    assert_eq!(loaded.consumers.len(), 1);
    assert_eq!(loaded.plugin_configs.len(), 1);
    assert_eq!(loaded.upstreams.len(), 1);
    assert_eq!(loaded.consumers[0].username, "user1");
    assert_eq!(loaded.upstreams[0].name, Some("upstream-1".into()));
}

#[test]
fn test_load_config_backup_empty_file() {
    let (_tmp, path) = write_tmp_file("");
    let err =
        load_config_backup(&path, "ferrum").expect_err("empty file must be Err, not Ok(None)");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to parse config backup"),
        "empty-file parse failure must be actionable, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_invalid_regex_listen_path() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "bad-regex",
            "name": "bad-regex",
            "listen_path": "~(invalid[regex",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_scheme": "http"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path, "ferrum").expect_err("invalid regex must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        msg.contains("invalid regex listen_path"),
        "must name the regex failure, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_duplicate_listen_path() {
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "listen_path": "/same",
                "backend_host": "host1",
                "backend_port": 3000,
                "backend_scheme": "http"
            },
            {
                "id": "p2",
                "name": "proxy-two",
                "listen_path": "/same",
                "backend_host": "host2",
                "backend_port": 3001,
                "backend_scheme": "http"
            }
        ],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err =
        load_config_backup(&path, "ferrum").expect_err("duplicate listen path must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        msg.contains("/same") || msg.to_lowercase().contains("duplicate"),
        "must identify the duplicate listen path, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_dangling_upstream_reference() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "p1",
            "name": "proxy-one",
            "listen_path": "/api",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_scheme": "http",
            "upstream_id": "missing-upstream"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err =
        load_config_backup(&path, "ferrum").expect_err("dangling upstream_id must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        msg.contains("non-existent upstream_id") && msg.contains("missing-upstream"),
        "must name the dangling reference, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_accepts_current_version_integer_form() {
    let json = format!(
        r#"{{
        "version": {},
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }}"#,
        CURRENT_CONFIG_VERSION
    );

    let (_tmp, path) = write_tmp_file(&json);
    let loaded = load_config_backup(&path, "ferrum")
        .expect("integer current version must succeed")
        .expect("integer current version must return Some");
    assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);
}

#[test]
fn test_load_config_backup_rejects_unsupported_version() {
    let json = r#"{
        "version": "0",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err =
        load_config_backup(&path, "ferrum").expect_err("unsupported version must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("version")
            && (msg.contains("No config migration path") || msg.contains("unsupported version")),
        "must report unsupported version without legacy shims, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_missing_version() {
    let json = r#"{
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path, "ferrum").expect_err("missing version must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("version"),
        "must mention missing version, got: {msg}"
    );
}

#[test]
fn backup_bootstrap_uses_rejecting_runtime_contract_not_node_local_files() {
    let source = include_str!("../../../src/config/config_backup.rs");
    assert!(
        source.contains("collect_rejecting_runtime_config_errors"),
        "backup bootstrap must run the shared rejecting runtime contract"
    );
    assert!(
        source.contains("normalize_fields()"),
        "backup bootstrap must normalize before validation"
    );
    assert!(
        source.contains("resolve_upstream_tls()"),
        "backup bootstrap must resolve upstream TLS before validation"
    );
    assert!(
        !source.contains("validate_plugin_file_dependencies"),
        "backup bootstrap must keep node-local plugin file checks separate"
    );
    assert!(
        source.contains("CURRENT_CONFIG_VERSION") && source.contains("migrate_in_memory"),
        "backup bootstrap must validate/migrate version under the build-out policy"
    );

    let database = include_str!("../../../src/modes/database.rs");
    let backup_start = database
        .find("match load_config_backup(path, &env_config.namespace)")
        .expect("database mode must call load_config_backup");
    let reserved_ports = database[backup_start..]
        .find("validate_stream_proxy_port_conflicts")
        .map(|offset| backup_start + offset)
        .expect("reserved-port check follows backup load");
    assert!(
        database[backup_start..reserved_ports].contains("Ok(Some(cfg))"),
        "database mode must only serve Ok(Some) backup snapshots"
    );
    assert!(
        database[backup_start..reserved_ports].contains("was rejected"),
        "database mode must surface actionable backup rejection errors"
    );
}

/// Two-namespace backup fixture: an all-namespace administrative export of the
/// kind an operator can legitimately provision as `FERRUM_DB_CONFIG_BACKUP_PATH`.
///
/// `tenant-a` and `tenant-b` deliberately collide on `listen_path`, proxy name
/// and upstream name, because those are `(namespace, value)`-scoped everywhere
/// else: the collision must not reject the candidate for either namespace.
///
/// The plugin configs are `enabled: false` so the fixture exercises the
/// namespace projection without also dragging in the plugin-construction gate,
/// which is covered by its own tests.
const TWO_NAMESPACE_BACKUP: &str = r#"{
    "version": "1",
    "known_namespaces": ["tenant-a", "tenant-b"],
    "proxies": [
        {
            "id": "proxy-a",
            "name": "shared-name",
            "namespace": "tenant-a",
            "listen_path": "/shared",
            "backend_host": "a.internal",
            "backend_port": 8080,
            "backend_scheme": "http"
        },
        {
            "id": "proxy-b",
            "name": "shared-name",
            "namespace": "tenant-b",
            "listen_path": "/shared",
            "backend_host": "b.internal",
            "backend_port": 8080,
            "backend_scheme": "http"
        }
    ],
    "consumers": [
        {
            "id": "consumer-a",
            "username": "alice",
            "namespace": "tenant-a",
            "credentials": {"keyauth": [{"key": "key-alpha"}]}
        },
        {
            "id": "consumer-b",
            "username": "bob",
            "namespace": "tenant-b",
            "credentials": {"keyauth": [{"key": "key-bravo"}]}
        }
    ],
    "plugin_configs": [
        {
            "id": "plugin-a",
            "plugin_name": "key_auth",
            "namespace": "tenant-a",
            "scope": "global",
            "config": {},
            "enabled": false
        },
        {
            "id": "plugin-b",
            "plugin_name": "key_auth",
            "namespace": "tenant-b",
            "scope": "global",
            "config": {},
            "enabled": false
        }
    ],
    "upstreams": [
        {
            "id": "upstream-a",
            "name": "shared-upstream",
            "namespace": "tenant-a",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        },
        {
            "id": "upstream-b",
            "name": "shared-upstream",
            "namespace": "tenant-b",
            "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]
        }
    ]
}"#;

#[test]
fn multi_namespace_backup_serves_only_the_configured_namespace() {
    let (_tmp, path) = write_tmp_file(TWO_NAMESPACE_BACKUP);
    let loaded = load_config_backup(&path, "tenant-a")
        .expect("a multi-namespace export must be a usable startup backup")
        .expect("existing backup must return Some");

    assert_eq!(loaded.proxies.len(), 1, "one namespace's proxies only");
    assert_eq!(loaded.proxies[0].id, "proxy-a");
    assert_eq!(loaded.consumers.len(), 1);
    assert_eq!(loaded.consumers[0].id, "consumer-a");
    assert_eq!(loaded.plugin_configs.len(), 1);
    assert_eq!(loaded.plugin_configs[0].id, "plugin-a");
    assert_eq!(loaded.upstreams.len(), 1);
    assert_eq!(loaded.upstreams[0].id, "upstream-a");
    assert!(
        loaded.gateway_trust_bundles.is_empty(),
        "trust material is never carried by a backup file"
    );

    // The foreign tenant's credential must not be reachable at all.
    let serialized = serde_json::to_string(&loaded).expect("candidate must serialize");
    assert!(
        !serialized.contains("key-bravo") && !serialized.contains("bob"),
        "no tenant-b consumer or credential may survive the filter"
    );
    assert!(
        !serialized.contains("b.internal") && !serialized.contains("10.0.0.2"),
        "no tenant-b backend or upstream target may survive the filter"
    );

    // The discovered namespace set is a count-only diagnostic; it must never be
    // served back as this gateway's namespace list.
    assert_eq!(loaded.known_namespaces, vec!["tenant-a".to_string()]);
}

#[test]
fn multi_namespace_backup_serves_the_other_namespace_symmetrically() {
    let (_tmp, path) = write_tmp_file(TWO_NAMESPACE_BACKUP);
    let loaded = load_config_backup(&path, "tenant-b")
        .expect("the same file must load for either namespace")
        .expect("existing backup must return Some");

    assert_eq!(loaded.proxies.len(), 1);
    assert_eq!(loaded.proxies[0].id, "proxy-b");
    assert_eq!(loaded.consumers.len(), 1);
    assert_eq!(loaded.consumers[0].id, "consumer-b");
    assert_eq!(loaded.upstreams.len(), 1);
    assert_eq!(loaded.upstreams[0].id, "upstream-b");
}

#[test]
fn cross_namespace_duplicate_listen_paths_do_not_reject_the_backup() {
    // Before the projection existed this file rejected outright: the
    // cross-resource validators saw two proxies on `/shared`. Filtering first is
    // what makes a legitimate all-namespace export usable.
    let (_tmp, path) = write_tmp_file(TWO_NAMESPACE_BACKUP);
    let loaded = load_config_backup(&path, "tenant-a")
        .expect("cross-namespace duplicates must not reject the candidate")
        .expect("existing backup must return Some");
    assert_eq!(loaded.proxies[0].listen_path.as_deref(), Some("/shared"));
}

#[test]
fn duplicate_listen_paths_inside_the_active_namespace_still_reject() {
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "namespace": "tenant-a",
                "listen_path": "/same",
                "backend_host": "host1",
                "backend_port": 3000,
                "backend_scheme": "http"
            },
            {
                "id": "p2",
                "name": "proxy-two",
                "namespace": "tenant-a",
                "listen_path": "/same",
                "backend_host": "host2",
                "backend_port": 3001,
                "backend_scheme": "http"
            },
            {
                "id": "p3",
                "name": "proxy-three",
                "namespace": "tenant-b",
                "listen_path": "/same",
                "backend_host": "host3",
                "backend_port": 3002,
                "backend_scheme": "http"
            }
        ],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path, "tenant-a")
        .expect_err("a duplicate inside the active namespace must still reject");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        !msg.contains("proxy-three") && !msg.contains("host3"),
        "the rejection must not name another tenant's resources, got: {msg}"
    );
}

#[test]
fn backup_with_no_resources_in_the_active_namespace_is_empty_but_valid() {
    let (_tmp, path) = write_tmp_file(TWO_NAMESPACE_BACKUP);
    let loaded = load_config_backup(&path, "tenant-c")
        .expect("an unknown namespace must not be an error")
        .expect("existing backup must return Some");

    assert!(loaded.proxies.is_empty());
    assert!(loaded.consumers.is_empty());
    assert!(loaded.plugin_configs.is_empty());
    assert!(loaded.upstreams.is_empty());
    assert_eq!(
        loaded.known_namespaces,
        vec!["tenant-c".to_string()],
        "a namespace with nothing in the file must never inherit a foreign one"
    );
}

#[test]
fn backup_load_without_a_serving_namespace_fails_closed() {
    let (_tmp, path) = write_tmp_file(TWO_NAMESPACE_BACKUP);
    let err = load_config_backup(&path, "")
        .expect_err("an empty serving namespace must be a startup error");
    let msg = err.to_string();
    assert!(
        msg.contains("serving namespace") && msg.contains("FERRUM_NAMESPACE"),
        "the failure must be actionable, got: {msg}"
    );
}

#[test]
fn backup_rejection_text_never_carries_the_payload_or_foreign_names() {
    // A backup that is runtime-fatal for the ACTIVE namespace: the error must
    // describe that failure without echoing the file or the other tenant.
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "namespace": "tenant-a",
                "listen_path": "/api",
                "backend_host": "localhost",
                "backend_port": 3000,
                "backend_scheme": "http",
                "upstream_id": "missing-upstream"
            }
        ],
        "consumers": [
            {
                "id": "consumer-b",
                "username": "bob",
                "namespace": "tenant-b",
                "credentials": {"keyauth": [{"key": "key-bravo"}]}
            }
        ],
        "plugin_configs": [],
        "upstreams": [
            {
                "id": "upstream-b",
                "name": "secret-upstream",
                "namespace": "tenant-b",
                "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]
            }
        ]
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path, "tenant-a").expect_err("dangling reference must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    // Deliberately excludes short tokens like the username: the message embeds
    // the randomly named temporary backup path, and a 3-character needle could
    // match it by chance. The distinctive tokens below cannot.
    for forbidden in ["key-bravo", "secret-upstream", "10.0.0.2", "tenant-b"] {
        assert!(
            !msg.contains(forbidden),
            "backup rejection leaked '{forbidden}': {msg}"
        );
    }
}

#[test]
fn backup_bootstrap_projects_the_namespace_before_it_validates() {
    // Ordering is the whole point: filtering after validation would reject a
    // legitimate multi-namespace export on a cross-namespace duplicate, and
    // filtering after the return would serve another tenant's resources.
    let source = include_str!("../../../src/config/config_backup.rs");
    let filter = source
        .find("retain_namespace(config, namespace, NamespaceRetention::SERVING)")
        .expect("the backup loader must project onto the serving namespace");
    let validate = source
        .find("collect_rejecting_runtime_config_errors(&config)")
        .expect("the backup loader must run the rejecting runtime contract");
    assert!(
        filter < validate,
        "the namespace projection must run before the rejecting runtime contract"
    );
    assert!(
        source.contains("fn load_config_backup(\n    path: &str,\n    namespace: &str,\n)"),
        "the backup loader must require a serving namespace argument"
    );
}
