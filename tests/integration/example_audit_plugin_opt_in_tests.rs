//! Packaging / opt-in contracts for `example_audit_plugin`.
//!
//! Issue #2595: pedagogical examples must not alter the default production
//! plugin registry or schema. They live under `custom_plugins/examples/` and
//! require an explicit `FERRUM_CUSTOM_PLUGINS` listing (CI sets this for tests).

use std::fs;
use std::path::Path;

#[test]
fn example_sources_live_outside_production_discovery_directory() {
    assert!(
        Path::new("custom_plugins/examples/example_audit_plugin.rs").is_file(),
        "example_audit_plugin must live under custom_plugins/examples/"
    );
    assert!(
        Path::new("custom_plugins/examples/example_plugin.rs").is_file(),
        "example_plugin must live under custom_plugins/examples/"
    );
    assert!(
        !Path::new("custom_plugins/example_audit_plugin.rs").is_file(),
        "example_audit_plugin must not sit in the default auto-discovery directory"
    );
    assert!(
        !Path::new("custom_plugins/example_plugin.rs").is_file(),
        "example_plugin must not sit in the default auto-discovery directory"
    );
}

#[test]
fn build_script_requires_explicit_opt_in_for_examples() {
    let build = include_str!("../../build.rs");
    assert!(
        build.contains("custom_plugins/examples")
            || build.contains("examples_dir")
            || build.contains("examples"),
        "build.rs must know about the examples directory"
    );
    assert!(
        build.contains("FERRUM_CUSTOM_PLUGINS"),
        "build.rs must honor FERRUM_CUSTOM_PLUGINS"
    );
    assert!(
        build.contains("example_path") && build.contains("examples_dir.join"),
        "build.rs must resolve opted-in names from the examples directory"
    );
    assert!(
        build.contains("lists unknown plugin stem") || build.contains("unknown plugin stem(s)"),
        "build.rs must fail closed on unresolved FERRUM_CUSTOM_PLUGINS stems"
    );
}

fn rust_plugin_stems(dir: &Path) -> Vec<String> {
    let mut stems: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .filter(|stem| {
                        !stem.is_empty()
                            && stem
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    })
                    .map(str::to_string)
            } else {
                None
            }
        })
        .collect();
    stems.sort_unstable();
    stems
}

/// Resolve the directory the composite action discovers for pedagogical stems.
///
/// setup-rust-ci builds `FERRUM_CUSTOM_PLUGINS` via shell (`$plugins`), so the
/// effective examples list is the `*.rs` stems under the glob the action loops.
fn setup_rust_ci_examples_discovery_dir(action: &str) -> &Path {
    action
        .lines()
        .find_map(|line| {
            let trimmed = line.trim_start();
            let rest = trimmed.strip_prefix("for source in ")?;
            let glob = rest.split_whitespace().next()?.trim_end_matches(';');
            let dir = glob.strip_suffix("/*.rs")?;
            // Pedagogical opt-in must come from an examples/ tree, not production.
            if dir.contains("examples") {
                Some(Path::new(dir))
            } else {
                None
            }
        })
        .expect(
            "setup-rust-ci must discover FERRUM_CUSTOM_PLUGINS example stems via \
             a `for source in <examples-dir>/*.rs` loop",
        )
}

#[test]
fn setup_rust_ci_custom_plugins_list_matches_examples_directory() {
    // Guard against drifting the shared composite action's effective
    // FERRUM_CUSTOM_PLUGINS examples list away from custom_plugins/examples/*.rs
    // (F16). The action exports via `$plugins`, so parse its discovery glob and
    // compare that directory's stems to the canonical examples tree.
    let action = include_str!("../../.github/actions/setup-rust-ci/action.yml");
    assert!(
        action.contains("custom_plugins/*.rs"),
        "setup-rust-ci must auto-include production custom_plugins/*.rs stems"
    );
    assert!(
        action
            .lines()
            .any(|line| line.contains("FERRUM_CUSTOM_PLUGINS=") && line.contains("GITHUB_ENV")),
        "setup-rust-ci must export FERRUM_CUSTOM_PLUGINS to GITHUB_ENV"
    );
    // Empty-list and identifier checks keep `$plugins` interpolation from
    // writing a blank or injectable GITHUB_ENV value.
    assert!(
        action.contains("resolved to an empty list"),
        "setup-rust-ci must fail closed when FERRUM_CUSTOM_PLUGINS would be empty"
    );
    assert!(
        action.contains("invalid custom plugin stem") || action.contains("*[!A-Za-z0-9_]*"),
        "setup-rust-ci must reject non-identifier plugin stems before GITHUB_ENV write"
    );

    let configured_examples_dir = setup_rust_ci_examples_discovery_dir(action);
    let mut listed = rust_plugin_stems(configured_examples_dir);
    listed.sort_unstable();

    let mut on_disk = rust_plugin_stems(Path::new("custom_plugins/examples"));
    on_disk.sort_unstable();
    assert!(
        !on_disk.is_empty(),
        "custom_plugins/examples must contain at least one pedagogical plugin stem"
    );

    assert_eq!(
        listed,
        on_disk,
        "setup-rust-ci FERRUM_CUSTOM_PLUGINS must list every custom_plugins/examples/*.rs stem"
    );
}

#[test]
fn default_collector_excludes_example_when_not_compiled() {
    // When CI opts examples in, the collector includes them; when a default
    // production artifact is built without FERRUM_CUSTOM_PLUGINS, it must not.
    // This test asserts the runtime registry matches that build-time choice and
    // that migration collection cannot invent example schema without the plugin.
    let names = ferrum_edge::custom_plugins::custom_plugin_names();
    let migrations = ferrum_edge::custom_plugins::collect_all_custom_plugin_migrations();
    let registered = names.contains(&"example_audit_plugin");
    let collected = migrations
        .iter()
        .any(|(name, _)| *name == "example_audit_plugin");
    assert_eq!(
        registered, collected,
        "migration collection must match registry membership for example_audit_plugin"
    );
    if !registered {
        assert!(
            migrations
                .iter()
                .all(|(name, _)| *name != "example_audit_plugin"),
            "unconfigured/default artifact must not contribute example_audit_plugin migrations"
        );
    }
}

#[test]
fn dockerfile_does_not_force_example_opt_in() {
    let dockerfile = include_str!("../../Dockerfile");
    assert!(
        !dockerfile.contains("FERRUM_CUSTOM_PLUGINS"),
        "Dockerfile must leave FERRUM_CUSTOM_PLUGINS unset so examples stay out of images"
    );
}
