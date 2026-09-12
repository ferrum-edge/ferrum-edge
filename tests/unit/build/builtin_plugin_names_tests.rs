//! Regression coverage for built-in/custom plugin name collision checks in
//! `build.rs` (issue #4759).

use std::collections::BTreeSet;
use std::path::Path;

#[allow(dead_code)]
mod builtin_plugin_names {
    include!("../../../build/builtin_plugin_names.rs");
}

#[test]
fn parsed_builtin_names_match_runtime_registry() {
    use ferrum_edge::plugins::BUILTIN_PLUGIN_REGISTRATIONS;

    let parsed =
        builtin_plugin_names::builtin_plugin_names_from_mod_rs(Path::new("src/plugins/mod.rs"))
            .expect("parse built-in plugin names from src/plugins/mod.rs");

    let registry: BTreeSet<_> = BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|registration| registration.name)
        .collect();
    let parsed_set: BTreeSet<_> = parsed.iter().map(String::as_str).collect();

    assert_eq!(
        parsed_set, registry,
        "build.rs built-in inventory must stay set-equal with BUILTIN_PLUGIN_REGISTRATIONS"
    );
}

#[test]
fn collision_errors_name_file_and_builtin() {
    let builtin_names = BTreeSet::from(["cors".to_string()]);
    let plugin_sources = vec![(
        "cors".to_string(),
        Path::new("custom_plugins/cors.rs").to_path_buf(),
    )];

    let errors =
        builtin_plugin_names::format_builtin_name_collision_errors(&plugin_sources, &builtin_names);

    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("custom_plugins/cors.rs"));
    assert!(errors[0].contains("shadows built-in plugin \"cors\""));
}

#[test]
fn build_script_rejects_builtin_name_collisions_after_discovery() {
    let build = include_str!("../../../build.rs");
    let discovery = build
        .find("let mut plugin_sources: Vec<(String, PathBuf)> = Vec::new();")
        .expect("build.rs must discover custom plugin sources");
    let collision_check = build
        .find("format_builtin_name_collision_errors")
        .expect("build.rs must reject custom plugins that shadow built-in names");
    let sort = build
        .find("plugin_sources.sort_by(|a, b| a.0.cmp(&b.0));")
        .expect("build.rs must sort discovered plugin sources");

    assert!(
        discovery < collision_check && collision_check < sort,
        "built-in collision check must run after discovery and before registry generation"
    );
    assert!(
        build.contains("cargo:rerun-if-changed=src/plugins/mod.rs"),
        "build.rs must rebuild when built-in plugin inventory changes"
    );
}
