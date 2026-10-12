//! Tests for config migration module

use ferrum_edge::config::config_migration::ConfigMigrator;
use ferrum_edge::config::types::CURRENT_CONFIG_VERSION;

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
fn test_migrate_value_no_version_is_rejected() {
    let mut value = serde_json::json!({
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });

    let err = ConfigMigrator::migrate_value(&mut value, "1").unwrap_err();
    assert!(err.to_string().contains("version"));
}

#[test]
fn test_migrate_value_unknown_source_version_is_rejected() {
    let mut value = serde_json::json!({
        "version": "0",
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });
    let original = value.clone();

    let err = ConfigMigrator::migrate_value(&mut value, CURRENT_CONFIG_VERSION).unwrap_err();

    assert!(
        err.to_string()
            .contains("No config migration path from version (<redacted scalar>)")
    );
    assert_eq!(value, original);
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
fn test_detect_version_from_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    std::fs::write(
        &config_path,
        r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[]}"#,
    )
    .unwrap();

    let version = ConfigMigrator::detect_version(config_path.to_str().unwrap()).unwrap();
    assert_eq!(version, "1");
}

#[test]
fn test_detect_version_rejects_absent_version() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let err = ConfigMigrator::detect_version(config_path.to_str().unwrap()).unwrap_err();
    assert!(err.to_string().contains("version"));
}

#[test]
fn test_detect_version_rejects_alias_before_later_malformation_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        concat!(
            "version: &private-version \"1\"\n",
            "copy: *private-version\n",
            "broken: [migration-secret\n",
        ),
    )
    .unwrap();

    let err = ConfigMigrator::detect_version(config_path.to_str().unwrap()).unwrap_err();
    let rendered = err.to_string();
    assert_eq!(
        rendered,
        "YAML document containing aliases is malformed or unsupported"
    );
    assert!(!rendered.contains("private-version"));
    assert!(!rendered.contains("migration-secret"));
}

#[test]
fn test_detect_version_rejects_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("missing.yaml");

    let err = ConfigMigrator::detect_version(config_path.to_str().unwrap()).unwrap_err();

    assert!(err.to_string().contains("Configuration file not found"));
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

#[test]
fn test_migrate_file_json_no_migration_needed_does_not_rewrite_or_backup() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    let content = r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[]}"#;
    std::fs::write(&config_path, content).unwrap();

    let result = ConfigMigrator::migrate_file(config_path.to_str().unwrap()).unwrap();

    assert_eq!(result.from_version, CURRENT_CONFIG_VERSION);
    assert_eq!(result.to_version, CURRENT_CONFIG_VERSION);
    assert_eq!(result.migrations_applied, 0);
    assert!(result.backup_path.is_none());
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);
}

#[test]
fn test_migrate_file_rejects_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("missing.yaml");

    let err = ConfigMigrator::migrate_file(config_path.to_str().unwrap()).unwrap_err();

    assert!(err.to_string().contains("Configuration file not found"));
}

#[test]
fn test_migrate_file_rejects_unreachable_version_without_backup_or_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let content = "version: \"0\"\nproxies: []\nconsumers: []\nplugin_configs: []\n";
    std::fs::write(&config_path, content).unwrap();

    let err = ConfigMigrator::migrate_file(config_path.to_str().unwrap()).unwrap_err();

    assert!(
        err.to_string()
            .contains("No config migration path from version (<redacted scalar>)")
    );
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);
    let backup_count = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".backup."))
        .count();
    assert_eq!(backup_count, 0);
}

#[test]
fn test_migrate_in_memory_current_version_is_noop() {
    let mut value = serde_json::json!({
        "version": CURRENT_CONFIG_VERSION,
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });
    let original = value.clone();

    let steps = ConfigMigrator::migrate_in_memory(&mut value).unwrap();

    assert_eq!(steps, 0);
    assert_eq!(value, original);
}

#[test]
fn test_migrate_in_memory_rejects_missing_version() {
    let mut value = serde_json::json!({
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });

    let err = ConfigMigrator::migrate_in_memory(&mut value).unwrap_err();

    assert!(err.to_string().contains("version"));
}

#[test]
fn test_migrate_in_memory_rejects_unreachable_version_without_mutation() {
    let mut value = serde_json::json!({
        "version": "0",
        "proxies": [],
        "consumers": [],
        "plugin_configs": []
    });
    let original = value.clone();

    let err = ConfigMigrator::migrate_in_memory(&mut value).unwrap_err();

    assert!(
        err.to_string()
            .contains("No config migration path from version (<redacted scalar>)")
    );
    assert_eq!(value, original);
}

#[test]
fn test_plan_migration_steps_current_version_is_noop() {
    let steps =
        ConfigMigrator::plan_migration_steps(CURRENT_CONFIG_VERSION, CURRENT_CONFIG_VERSION)
            .unwrap();
    assert_eq!(steps, 0);
}

#[test]
fn test_plan_migration_steps_rejects_unreachable_version() {
    let err = ConfigMigrator::plan_migration_steps("0", CURRENT_CONFIG_VERSION).unwrap_err();
    assert!(
        err.to_string()
            .contains("No config migration path from version (<redacted scalar>)")
    );
}

#[test]
fn test_plan_file_current_version_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let content = "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n";
    std::fs::write(&config_path, content).unwrap();

    let plan = ConfigMigrator::plan_file(config_path.to_str().unwrap()).unwrap();

    assert_eq!(plan.from_version, CURRENT_CONFIG_VERSION);
    assert_eq!(plan.to_version, CURRENT_CONFIG_VERSION);
    assert_eq!(plan.migrations_applied, 0);
    assert!(plan.backup_path.is_none());
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);
}

#[test]
fn test_plan_file_rejects_unreachable_version_like_real_migration() {
    for (name, content) in [
        (
            "config.yaml",
            "version: \"0\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
        ),
        (
            "config.json",
            r#"{"version":"0","proxies":[],"consumers":[],"plugin_configs":[]}"#,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(name);
        std::fs::write(&config_path, content).unwrap();
        let path = config_path.to_str().unwrap();

        let dry_err = ConfigMigrator::plan_file(path).unwrap_err();
        let real_err = ConfigMigrator::migrate_file(path).unwrap_err();

        assert_eq!(dry_err.to_string(), real_err.to_string());
        assert!(
            dry_err
                .to_string()
                .contains("No config migration path from version (<redacted scalar>)")
        );
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);
        let backup_count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".backup."))
            .count();
        assert_eq!(backup_count, 0);
    }
}
