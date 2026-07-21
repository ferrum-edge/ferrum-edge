use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/ferrum.proto");
    println!("cargo:rerun-if-changed=proto/envoy/service/discovery/v3/discovery.proto");
    println!("cargo:rerun-if-changed=proto/envoy/service/runtime/v3/rtds.proto");
    println!("cargo:rerun-if-changed=proto/health.proto");
    println!("cargo:rerun-if-changed=proto/workload_api.proto");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/ferrum.proto"], &["proto/"])?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // The vendored xDS proto intentionally declares minimal `Any` and
        // `Status` shims in the Envoy package instead of importing
        // google.protobuf.Any / google.rpc.Status. They are wire-compatible
        // for the Phase B fields Ferrum consumes; avoid "fixing" this unless
        // the translator layer also switches to the full upstream protos.
        .compile_protos(
            &["proto/envoy/service/discovery/v3/discovery.proto"],
            &["proto/"],
        )?;

    // GAP-3E: RTDS resources are carried by the same ADS stream as the
    // standard xDS types. The vendored Runtime proto inlines a minimal
    // google.protobuf.Struct shim (field numbers preserved) so Phase B
    // builds stay self-contained, matching the discovery.proto Any/Status
    // pattern.
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&["proto/envoy/service/runtime/v3/rtds.proto"], &["proto/"])?;

    tonic_prost_build::compile_protos("proto/health.proto")?;

    // SPIFFE Workload API — vendored proto compiled with both client and
    // server stubs. Ferrum supports being either the workload calling a SPIRE
    // agent (client) or the in-process SVID issuer for local workloads (server).
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/workload_api.proto"], &["proto/"])?;

    // ── Auto-discover custom plugins ────────────────────────────────────
    //
    // Production discovery: `custom_plugins/*.rs` (excluding mod.rs).
    // Pedagogical examples live under `custom_plugins/examples/` and are
    // compiled only when explicitly listed in `FERRUM_CUSTOM_PLUGINS`.
    //
    // When `FERRUM_CUSTOM_PLUGINS` is unset, every production-directory file
    // is included. When set, only the listed stems are included
    // (resolved from the production directory first, then examples/).

    let custom_dir = Path::new("custom_plugins");
    let examples_dir = custom_dir.join("examples");
    let out_dir = env::var("OUT_DIR")?;

    let filter: Option<Vec<String>> = env::var("FERRUM_CUSTOM_PLUGINS").ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });

    let mut plugin_sources: Vec<(String, PathBuf)> = Vec::new();

    if custom_dir.is_dir() {
        for entry in fs::read_dir(custom_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| {
                        format!(
                            "custom plugin source name must be valid UTF-8: {}",
                            path.display()
                        )
                    })?
                    .to_string();
                if stem == "mod" {
                    continue;
                }
                if let Some(ref allowed) = filter
                    && !allowed.contains(&stem)
                {
                    continue;
                }
                plugin_sources.push((stem, path));
            }
        }
    }

    // Opt-in examples from custom_plugins/examples/{name}.rs
    if let Some(ref allowed) = filter {
        for name in allowed {
            if plugin_sources.iter().any(|(stem, _)| stem == name) {
                continue;
            }
            let example_path = examples_dir.join(format!("{name}.rs"));
            if example_path.is_file() {
                plugin_sources.push((name.clone(), example_path));
            }
        }

        // Fail closed on typos / renamed stems so a successful build cannot
        // silently omit a requested plugin (and its migrations).
        let unresolved: Vec<&str> = allowed
            .iter()
            .filter(|name| !plugin_sources.iter().any(|(stem, _)| stem == *name))
            .map(|name| name.as_str())
            .collect();
        if !unresolved.is_empty() {
            panic!(
                "FERRUM_CUSTOM_PLUGINS lists unknown plugin stem(s): {}. \
                 Expected a file in custom_plugins/{{stem}}.rs or \
                 custom_plugins/examples/{{stem}}.rs.",
                unresolved.join(", ")
            );
        }
    }

    plugin_sources.sort_by(|a, b| a.0.cmp(&b.0));
    let plugin_names: Vec<String> = plugin_sources.iter().map(|(n, _)| n.clone()).collect();

    // Tell dependents (and rustc) which opt-in examples were compiled so tests
    // can avoid compile-time paths into absent modules.
    println!("cargo::rustc-check-cfg=cfg(custom_plugin_example_audit_plugin)");
    if plugin_names
        .iter()
        .any(|name| name == "example_audit_plugin")
    {
        println!("cargo:rustc-cfg=custom_plugin_example_audit_plugin");
    }

    // Generate module declarations with absolute #[path] attributes so the
    // compiler finds the source files in custom_plugins/ (not in OUT_DIR).
    let mut mods = String::new();
    for (name, plugin_path) in &plugin_sources {
        let abs = fs::canonicalize(plugin_path)?;
        let path_str = abs.display().to_string().replace('\\', "/");
        mods.push_str(&format!("#[path = \"{}\"]\npub mod {};\n", path_str, name));
    }
    fs::write(Path::new(&out_dir).join("custom_plugin_mods.rs"), &mods)?;

    // Detect which plugins define a `plugin_migrations()` function.
    // We do a simple text search for the function signature in each source file.
    let mut plugins_with_migrations: Vec<String> = Vec::new();
    for (name, plugin_path) in &plugin_sources {
        if let Ok(source) = fs::read_to_string(plugin_path)
            && source.contains("fn plugin_migrations()")
        {
            plugins_with_migrations.push(name.clone());
        }
    }

    // Generate factory and discovery functions
    use std::fmt::Write;
    let mut registry = String::new();
    writeln!(
        registry,
        "/// Create a custom plugin instance by name (auto-generated by build.rs)."
    )?;
    writeln!(registry, "pub fn create_custom_plugin(")?;
    // Zero-plugin builds must not trip clippy unused_variables on the
    // documented `cargo clippy --lib -D warnings` gate.
    if plugin_names.is_empty() {
        writeln!(registry, "    _name: &str,")?;
        writeln!(registry, "    _config: &serde_json::Value,")?;
        writeln!(
            registry,
            "    _http_client: crate::plugins::PluginHttpClient,"
        )?;
    } else {
        writeln!(registry, "    name: &str,")?;
        writeln!(registry, "    config: &serde_json::Value,")?;
        writeln!(
            registry,
            "    http_client: crate::plugins::PluginHttpClient,"
        )?;
    }
    writeln!(
        registry,
        ") -> Result<Option<std::sync::Arc<dyn crate::plugins::Plugin>>, String> {{"
    )?;
    if plugin_names.is_empty() {
        // Parameters are underscore-prefixed above; keep a trivial body.
        writeln!(registry, "    let _ = (_name, _config, _http_client);")?;
        writeln!(registry, "    Ok(None)")?;
    } else {
        writeln!(registry, "    match name {{")?;
        for name in &plugin_names {
            writeln!(
                registry,
                "        \"{}\" => {}::create_plugin(config, http_client),",
                name, name
            )?;
        }
        writeln!(registry, "        _ => Ok(None),")?;
        writeln!(registry, "    }}")?;
    }
    writeln!(registry, "}}")?;
    writeln!(registry)?;

    // Always-available accessor so unit tests can assert the SQLite pragma
    // contract without a compile-time path into the optional example module.
    writeln!(
        registry,
        "/// Returns the example_audit_plugin SQLite connect pragmas when that \
         example is compiled in; otherwise `None`."
    )?;
    // Consumed only by test targets; dead code in the bin target.
    writeln!(registry, "#[allow(dead_code)]")?;
    writeln!(
        registry,
        "pub fn example_audit_sqlite_connect_pragmas() -> Option<&'static [&'static str]> {{"
    )?;
    if plugin_names
        .iter()
        .any(|name| name == "example_audit_plugin")
    {
        writeln!(
            registry,
            "    Some(example_audit_plugin::SQLITE_AUDIT_CONNECT_PRAGMAS)"
        )?;
    } else {
        writeln!(registry, "    None")?;
    }
    writeln!(registry, "}}")?;
    writeln!(registry)?;
    writeln!(
        registry,
        "/// Returns custom plugin failure policy metadata by name (auto-generated by build.rs)."
    )?;
    if plugin_names.is_empty() {
        writeln!(
            registry,
            "pub fn custom_plugin_failure_policy(_name: &str) -> Option<crate::plugins::PluginFailurePolicy> {{"
        )?;
        writeln!(registry, "    None")?;
    } else {
        writeln!(
            registry,
            "pub fn custom_plugin_failure_policy(name: &str) -> Option<crate::plugins::PluginFailurePolicy> {{"
        )?;
        writeln!(registry, "    match name {{")?;
        for name in &plugin_names {
            writeln!(
                registry,
                "        \"{}\" => Some({}::failure_policy()),",
                name, name
            )?;
        }
        writeln!(registry, "        _ => None,")?;
        writeln!(registry, "    }}")?;
    }
    writeln!(registry, "}}")?;
    writeln!(registry)?;
    writeln!(
        registry,
        "/// Returns the names of all registered custom plugins (auto-generated by build.rs)."
    )?;
    writeln!(
        registry,
        "pub fn custom_plugin_names() -> Vec<&'static str> {{"
    )?;
    writeln!(registry, "    vec![")?;
    for name in &plugin_names {
        writeln!(registry, "        \"{}\",", name)?;
    }
    writeln!(registry, "    ]")?;
    writeln!(registry, "}}")?;
    writeln!(registry)?;

    // Generate migration collector for custom plugins that define plugin_migrations()
    writeln!(
        registry,
        "/// Collects database migrations from all custom plugins that define them (auto-generated by build.rs)."
    )?;
    writeln!(
        registry,
        "pub fn collect_all_custom_plugin_migrations() -> Vec<(&'static str, Vec<crate::config::migrations::CustomPluginMigration>)> {{"
    )?;
    writeln!(registry, "    vec![")?;
    for name in &plugins_with_migrations {
        writeln!(
            registry,
            "        (\"{}\", {}::plugin_migrations()),",
            name, name
        )?;
    }
    writeln!(registry, "    ]")?;
    writeln!(registry, "}}")?;

    fs::write(
        Path::new(&out_dir).join("custom_plugin_registry.rs"),
        &registry,
    )?;

    // Expose the build target triple so the CLI can print it at runtime.
    println!(
        "cargo:rustc-env=TARGET={}",
        env::var("TARGET").unwrap_or_default()
    );

    // Re-run build script when custom_plugins/ changes
    println!("cargo:rerun-if-changed=custom_plugins/");
    println!("cargo:rerun-if-env-changed=FERRUM_CUSTOM_PLUGINS");

    Ok(())
}
