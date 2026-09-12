use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const BUILTIN_REGISTRATIONS_MARKER: &str =
    "pub const BUILTIN_PLUGIN_REGISTRATIONS: &[PluginRegistration] = &[";

/// Parse built-in plugin names from the `BUILTIN_PLUGIN_REGISTRATIONS` block in
/// `src/plugins/mod.rs`. This is the single inventory `build.rs` uses to reject
/// custom plugin stems that would shadow a built-in.
pub fn parse_builtin_plugin_names_from_registrations_source(
    source: &str,
) -> Result<Vec<String>, String> {
    let start = source
        .find(BUILTIN_REGISTRATIONS_MARKER)
        .ok_or_else(|| format!("{BUILTIN_REGISTRATIONS_MARKER} not found in source"))?;
    let body_start = start + BUILTIN_REGISTRATIONS_MARKER.len();
    let body = &source[body_start..];
    let end = body
        .find("];")
        .ok_or("BUILTIN_PLUGIN_REGISTRATIONS block not terminated")?;
    let block = &body[..end];

    let mut names = Vec::new();
    let mut search = block;
    while let Some(pos) = search.find("builtin_plugin(") {
        search = &search[pos + "builtin_plugin(".len()..];
        search = search.trim_start();
        if !search.starts_with('"') {
            return Err("expected string literal after builtin_plugin(".to_string());
        }
        let name_end = search[1..]
            .find('"')
            .ok_or_else(|| "unterminated built-in plugin name".to_string())?;
        names.push(search[1..1 + name_end].to_string());
        search = &search[1 + name_end + 1..];
    }

    if names.is_empty() {
        return Err("no built-in plugin names parsed from BUILTIN_PLUGIN_REGISTRATIONS".to_string());
    }

    Ok(names)
}

pub fn builtin_plugin_names_from_mod_rs(mod_rs_path: &Path) -> Result<Vec<String>, String> {
    let source = fs::read_to_string(mod_rs_path)
        .map_err(|error| format!("failed to read {}: {error}", mod_rs_path.display()))?;
    parse_builtin_plugin_names_from_registrations_source(&source)
}

pub fn builtin_plugin_name_set_from_mod_rs(mod_rs_path: &Path) -> Result<BTreeSet<String>, String> {
    Ok(builtin_plugin_names_from_mod_rs(mod_rs_path)?.into_iter().collect())
}

/// Returns one error message per custom plugin whose stem shadows a built-in.
pub fn format_builtin_name_collision_errors(
    plugin_sources: &[(String, PathBuf)],
    builtin_names: &BTreeSet<String>,
) -> Vec<String> {
    plugin_sources
        .iter()
        .filter(|(stem, _)| builtin_names.contains(stem))
        .map(|(stem, path)| {
            format!(
                "custom plugin file {} shadows built-in plugin \"{}\"",
                path.display(),
                stem
            )
        })
        .collect()
}
