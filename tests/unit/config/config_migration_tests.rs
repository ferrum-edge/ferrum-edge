//! Tests for config migration module

use ferrum_edge::config::config_migration::ConfigMigrator;

#[test]
fn test_migrate_value_already_current() {
    let mut value = serde_json::json!({
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });

    let steps = ConfigMigrator::migrate_value(&mut value, "1").unwrap();
    assert_eq!(steps, 0);
}

#[test]
fn test_migrate_value_no_version_defaults_to_1() {
    let mut value = serde_json::json!({
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });

    // Since current version is "1" and default is "1", no migration needed
    let steps = ConfigMigrator::migrate_value(&mut value, "1").unwrap();
    assert_eq!(steps, 0);
}

#[test]
fn test_detect_version_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let version = ConfigMigrator::detect_version(config_path.to_str().unwrap()).unwrap();
    assert_eq!(version, "1");
}

#[test]
fn test_detect_version_defaults_to_1_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let version = ConfigMigrator::detect_version(config_path.to_str().unwrap()).unwrap();
    assert_eq!(version, "1");
}

#[test]
fn test_migrate_file_no_migration_needed() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let result = ConfigMigrator::migrate_file(config_path.to_str().unwrap()).unwrap();
    assert_eq!(result.migrations_applied, 0);
    assert!(result.backup_path.is_none());
}
