//! Registry-driven unknown-root-key guard for every built-in plugin.
//!
//! `.claude/rules/plugins.md` requires plugin `config` objects to be closed.
//! Before issue #4525 that property was asserted only per plugin, in 66
//! separate test files — which is exactly how the four plugins under
//! `src/plugins/mesh/` were swept past by #4405 / #4409 → #4420 and kept
//! accepting typos. A `mesh_authz` whose policy key was misspelled built an
//! instance with zero policies and therefore ALLOWED every request.
//!
//! This module iterates `BUILTIN_PLUGIN_REGISTRATIONS` itself, so a newly
//! registered plugin is covered the moment it is added, without anyone
//! remembering to write a per-plugin case.
//!
//! Hosted CI is the gate for this file; it is not run on developer hosts.
//! If this sweep turns up a plugin outside `src/plugins/mesh/` that also
//! accepts unknown root keys, the correct response is a follow-up fix on that
//! plugin — not an entry in [`KNOWN_OPEN_CONFIGS`].

use ferrum_edge::plugins::{BUILTIN_PLUGIN_REGISTRATIONS, validate_plugin_config};
use serde_json::Value;

use super::minimal_plugin_config;

/// Root key injected into each plugin's minimal config. Deliberately ugly so
/// it cannot collide with a real schema field or a near-miss suggestion.
const PROBE_KEY: &str = "__ferrum_unknown_key_probe__";

/// Plugins exempted from the closed-config property.
///
/// This list MUST stay empty. A name here is a fail-open — the plugin would
/// silently accept operator typos, and typos in security-relevant keys change
/// enforcement (see the `mesh_authz` case in the module docs) — not an
/// exemption for a plugin whose schema is merely "flexible". If a plugin
/// cannot close its root today, fix the plugin.
const KNOWN_OPEN_CONFIGS: &[&str] = &[];

#[test]
fn every_builtin_plugin_rejects_an_unknown_root_config_key() {
    let mut accepted: Vec<&str> = Vec::new();
    // Plugins whose minimal config is not currently valid on its own (for
    // example one that needs an environment secret). Their rejection of the
    // probed config is still required, but it is not *proof* that the probe
    // caused it, so they are reported rather than silently counted as covered.
    let mut unproven: Vec<&str> = Vec::new();

    for registration in BUILTIN_PLUGIN_REGISTRATIONS {
        let name = registration.name;
        if KNOWN_OPEN_CONFIGS.contains(&name) {
            continue;
        }

        let minimal = minimal_plugin_config(name);
        let baseline = validate_plugin_config(name, &minimal);

        let mut probed = minimal.clone();
        let Some(object) = probed.as_object_mut() else {
            panic!("minimal_plugin_config({name}) must be a JSON object");
        };
        object.insert(PROBE_KEY.to_string(), Value::Bool(true));

        // When the baseline is valid, the probe is the ONLY difference between
        // the two calls, so an `Err` here is proof the unknown key caused it —
        // no assertion on the diagnostic's wording is needed (each plugin's own
        // test owns that; the four mesh plugins closed by #4525 assert it in
        // `mesh_plugins_tests.rs`).
        if validate_plugin_config(name, &probed).is_ok() {
            accepted.push(name);
        } else if baseline.is_err() {
            unproven.push(name);
        }
    }

    assert!(
        accepted.is_empty(),
        "these built-in plugins accept an unknown root config key \
         (a misspelled security-relevant key silently changes enforcement): {accepted:?}"
    );
    // Not a failure: recorded so a shrinking proof surface is visible in the
    // job log rather than silent.
    if !unproven.is_empty() {
        eprintln!(
            "note: unknown-key coverage is unproven for these plugins because their \
             minimal config is not valid on its own: {unproven:?}"
        );
    }
}

/// Wordings of the private unknown-key checkers that issue #7151 replaced with
/// `crate::util::unknown_keys::reject_unknown_keys`. A plugin that rebuilds its
/// own checker tends to reuse one of them (or retype the shared helper's own
/// wording), and its operators then lose the shared diagnostic: every unknown
/// key reported, sorted, path-qualified, with a "did you mean" suggestion.
const PRIVATE_CHECKER_WORDINGS: &[&str] = &[
    "unknown configuration key(s)",
    "unknown config key",
    "unknown config field",
    "unknown configuration field",
    "unknown configuration property",
    "unknown configuration keys",
    "unsupported configuration key",
    "unsupported issuer field",
    "contains unknown field",
    "unknown property in",
];

#[test]
fn plugin_sources_use_the_shared_unknown_key_helper() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/plugins");
    let mut pending = vec![root];
    let mut offenders = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src/plugins") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read plugin source");
            // Inline test modules may quote the wording in assertions.
            let production = source
                .split_once("#[cfg(test)]\nmod tests")
                .map_or(source.as_str(), |(production, _)| production);
            for (index, line) in production.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                if let Some(wording) = PRIVATE_CHECKER_WORDINGS
                    .iter()
                    .find(|wording| line.contains(**wording))
                {
                    offenders.push(format!(
                        "{}:{}: {wording:?}",
                        path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                            .unwrap_or(&path)
                            .display(),
                        index + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "plugin config objects must reject unknown keys through \
         `crate::util::unknown_keys::reject_unknown_keys`, not a private checker: {offenders:#?}"
    );
}
