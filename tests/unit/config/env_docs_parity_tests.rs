//! DOC-03: public FERRUM_* inventory ↔ docs/configuration.md ↔ ferrum.conf.
//!
//! Uses the complete sorted inventory in
//! [`ferrum_edge::config::public_env_inventory::PUBLIC_FERRUM_ENV_SETTINGS`],
//! then fails closed when any non-exempt setting lacks a canonical docs table
//! row or a `ferrum.conf` template assignment. A separate guard requires every
//! production `EnvConfig` acceptance key to appear in that inventory.
//! Membership checks are order-independent.

use std::collections::BTreeSet;

use ferrum_edge::config::public_env_inventory::{
    PLUGIN_SECRET_EXAMPLE_ENV, PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS, PUBLIC_FERRUM_ENV_SETTINGS,
    TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV, is_public_ferrum_env_coverage_exempt,
    is_recognized_ferrum_setting,
};
use ferrum_edge::plugins::utils::plugin_secret_env::{
    PLUGIN_SECRET_ENV_PREFIX, is_plugin_secret_env_name,
};

/// Prefix of the dynamic `ai_transcript_audit` sink-secret namespace, mirrored
/// from `src/plugins/ai_transcript_audit.rs::SINK_SECRET_ENV_PREFIX`.
const TRANSCRIPT_SINK_SECRET_ENV_PREFIX: &str = "FERRUM_TRANSCRIPT_SINK_SECRET_";

const ENV_CONFIG_SOURCE: &str = include_str!("../../../src/config/env_config.rs");
const CONFIGURATION_MD: &str = include_str!("../../../docs/configuration.md");
const FERRUM_CONF: &str = include_str!("../../../ferrum.conf");
const HARDENING_MD: &str = include_str!("../../../docs/hardening.md");

/// Production `env_config.rs` only — truncate at the first `#[cfg(test)]` so
/// macro sample keys such as `FERRUM_SAMPLE_*` and other test helpers are
/// excluded. Includes free functions and `impl` bodies above that boundary.
fn production_env_config_source() -> &'static str {
    match ENV_CONFIG_SOURCE.find("#[cfg(test)]") {
        Some(idx) => &ENV_CONFIG_SOURCE[..idx],
        None => ENV_CONFIG_SOURCE,
    }
}

fn is_ferrum_env_key(key: &str) -> bool {
    key.starts_with("FERRUM_")
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Extract quoted `FERRUM_*` string literals from production `EnvConfig`
/// acceptance sites. Requires a preceding `=` / `(` / `,` so comment prose is
/// ignored. This is a focused EnvConfig-source guard, not a brittle
/// repository-wide regex sweep.
fn extract_env_config_keys(source: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i + 8 < bytes.len() {
        if bytes[i] == b'"' && source[i + 1..].starts_with("FERRUM_") {
            let key_start = i + 1;
            let mut key_end = key_start;
            while key_end < bytes.len()
                && (bytes[key_end].is_ascii_uppercase()
                    || bytes[key_end].is_ascii_digit()
                    || bytes[key_end] == b'_')
            {
                key_end += 1;
            }
            if key_end < bytes.len() && bytes[key_end] == b'"' {
                let key = &source[key_start..key_end];
                if is_ferrum_env_key(key) {
                    let line_start = source[..i].rfind('\n').map(|n| n + 1).unwrap_or(0);
                    let prefix = source[line_start..i].trim_end();
                    if prefix.ends_with('=') || prefix.ends_with('(') || prefix.ends_with(',') {
                        keys.insert(key.to_string());
                    }
                }
                i = key_end + 1;
                continue;
            }
        }
        i += 1;
    }
    keys
}

fn env_config_accepted_keys() -> BTreeSet<String> {
    let mut keys = extract_env_config_keys(production_env_config_source());
    // OperatingMode is resolved before the env_config! blocks but is a public
    // accepted setting with its own docs/template surfaces.
    keys.insert("FERRUM_MODE".to_string());
    keys
}

fn public_inventory() -> BTreeSet<String> {
    PUBLIC_FERRUM_ENV_SETTINGS
        .iter()
        .map(|key| (*key).to_string())
        .collect()
}

fn docs_table_keys(docs: &str) -> BTreeSet<&str> {
    let mut keys = BTreeSet::new();
    for line in docs.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('|') {
            continue;
        }
        let Some(after_pipe) = trimmed.strip_prefix('|') else {
            continue;
        };
        let cell = after_pipe.trim_start();
        let Some(rest) = cell.strip_prefix('`') else {
            continue;
        };
        let Some(end) = rest.find('`') else {
            continue;
        };
        let key = &rest[..end];
        if is_ferrum_env_key(key) {
            keys.insert(key);
        }
    }
    keys
}

fn ferrum_conf_assignment_keys(conf: &str) -> BTreeSet<&str> {
    let mut keys = BTreeSet::new();
    for line in conf.lines() {
        // Require the template style `KEY =` (space before `=`). That matches
        // the dominant ferrum.conf form and rejects prose mentions such as
        // `FERRUM_K8S_WATCH_ISTIO_CRDS=true` embedded in comments.
        let trimmed = line.trim_start().trim_start_matches('#').trim_start();
        let Some(eq) = trimmed.find(" =") else {
            continue;
        };
        let key = trimmed[..eq].trim();
        if is_ferrum_env_key(key) {
            keys.insert(key);
        }
    }
    keys
}

#[test]
fn public_inventory_and_exemptions_are_sorted_and_unique() {
    assert!(
        PUBLIC_FERRUM_ENV_SETTINGS
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "PUBLIC_FERRUM_ENV_SETTINGS must be strictly sorted unique keys"
    );
    assert!(
        PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS must be strictly sorted unique keys"
    );
}

/// The dynamic `ai_transcript_audit` sink-secret namespace has no fixed key
/// set, so the generic docs/template sweep cannot discover it. Pin its
/// representative key so removing the namespace from the inventory — or
/// dropping its docs row / `ferrum.conf` assignment — fails closed here.
#[test]
fn transcript_sink_secret_namespace_has_canonical_inventory_surface() {
    assert!(
        TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV.starts_with(TRANSCRIPT_SINK_SECRET_ENV_PREFIX),
        "`{TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV}` must live under the \
         `{TRANSCRIPT_SINK_SECRET_ENV_PREFIX}` namespace resolved by ai_transcript_audit"
    );
    assert!(
        is_ferrum_env_key(TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV),
        "the documented example key must be an exact-key form (no `<NAME>` placeholder), \
         otherwise the docs/ferrum.conf extractors silently skip it"
    );
    assert!(
        public_inventory().contains(TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV),
        "`{TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV}` must stay in PUBLIC_FERRUM_ENV_SETTINGS as the \
         canonical representative of the `{TRANSCRIPT_SINK_SECRET_ENV_PREFIX}<NAME>` namespace"
    );
    assert!(
        !is_public_ferrum_env_coverage_exempt(TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV),
        "the transcript sink-secret namespace must keep real docs/template coverage, \
         not a coverage exemption"
    );
    assert!(
        docs_table_keys(CONFIGURATION_MD).contains(TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV),
        "docs/configuration.md needs a canonical `{TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV}` table row"
    );
    assert!(
        ferrum_conf_assignment_keys(FERRUM_CONF).contains(TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV),
        "ferrum.conf needs a `{TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV} = ...` template assignment"
    );
}

/// The dynamic plugin-config secret namespace likewise has no fixed key set.
/// Pin its representative key so removing the namespace from the inventory —
/// or dropping its docs row / `ferrum.conf` assignment — fails closed here,
/// and so the settings-file recognizer and the plugin resolver agree on it.
#[test]
fn plugin_secret_namespace_has_canonical_inventory_surface() {
    assert!(
        PLUGIN_SECRET_EXAMPLE_ENV.starts_with(PLUGIN_SECRET_ENV_PREFIX),
        "`{PLUGIN_SECRET_EXAMPLE_ENV}` must live under `{PLUGIN_SECRET_ENV_PREFIX}`"
    );
    assert!(
        is_plugin_secret_env_name(PLUGIN_SECRET_EXAMPLE_ENV),
        "the example key must be a name the plugin resolver admits"
    );
    assert!(
        is_ferrum_env_key(PLUGIN_SECRET_EXAMPLE_ENV),
        "the documented example key must be an exact-key form (no `<NAME>` placeholder), \
         otherwise the docs/ferrum.conf extractors silently skip it"
    );
    assert!(
        public_inventory().contains(PLUGIN_SECRET_EXAMPLE_ENV),
        "`{PLUGIN_SECRET_EXAMPLE_ENV}` must stay in PUBLIC_FERRUM_ENV_SETTINGS"
    );
    assert!(
        !is_public_ferrum_env_coverage_exempt(PLUGIN_SECRET_EXAMPLE_ENV),
        "the plugin-secret namespace must keep real docs/template coverage"
    );
    assert!(
        docs_table_keys(CONFIGURATION_MD).contains(PLUGIN_SECRET_EXAMPLE_ENV),
        "docs/configuration.md needs a canonical `{PLUGIN_SECRET_EXAMPLE_ENV}` table row"
    );
    assert!(
        ferrum_conf_assignment_keys(FERRUM_CONF).contains(PLUGIN_SECRET_EXAMPLE_ENV),
        "ferrum.conf needs a `{PLUGIN_SECRET_EXAMPLE_ENV} = ...` template assignment"
    );
    assert!(
        is_recognized_ferrum_setting("FERRUM_PLUGIN_SECRET_ANY_NAME_7"),
        "settings-file parsing must recognize the whole namespace"
    );
    assert!(
        !is_recognized_ferrum_setting("FERRUM_PLUGIN_SECRET_lower"),
        "settings-file parsing must use the resolver's name grammar"
    );
}

#[test]
fn inventory_includes_all_env_config_accepted_keys() {
    let inventory = public_inventory();
    let accepted = env_config_accepted_keys();
    assert!(
        accepted.len() > 100,
        "EnvConfig acceptance extraction unexpectedly small ({}); parser likely broke",
        accepted.len()
    );

    let missing: Vec<&String> = accepted.difference(&inventory).collect();
    assert!(
        missing.is_empty(),
        "production EnvConfig-accepted FERRUM_* keys missing from PUBLIC_FERRUM_ENV_SETTINGS:\n  {}",
        missing
            .iter()
            .map(|key| key.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn public_ferrum_env_settings_have_docs_table_and_ferrum_conf_coverage() {
    let inventory = public_inventory();
    assert!(
        inventory.len() > 100,
        "inventory unexpectedly small ({}); PUBLIC_FERRUM_ENV_SETTINGS likely empty",
        inventory.len()
    );

    // Exemptions must themselves be inventory members (stale allowlist guard).
    for key in PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS {
        assert!(
            inventory.contains(*key),
            "exemption `{key}` is not part of the public inventory; remove it or add the setting"
        );
    }

    let docs_keys = docs_table_keys(CONFIGURATION_MD);
    let conf_keys = ferrum_conf_assignment_keys(FERRUM_CONF);

    let mut missing_docs = Vec::new();
    let mut missing_conf = Vec::new();
    for key in &inventory {
        if is_public_ferrum_env_coverage_exempt(key) {
            continue;
        }
        if !docs_keys.contains(key.as_str()) {
            missing_docs.push(key.clone());
        }
        if !conf_keys.contains(key.as_str()) {
            missing_conf.push(key.clone());
        }
    }

    assert!(
        missing_docs.is_empty(),
        "public FERRUM_* settings missing from docs/configuration.md variable tables:\n  {}",
        missing_docs.join("\n  ")
    );
    assert!(
        missing_conf.is_empty(),
        "public FERRUM_* settings missing from ferrum.conf template assignments (`KEY = ...`):\n  {}",
        missing_conf.join("\n  ")
    );
}

/// Extract every `FERRUM_*` token that appears anywhere in a document, using
/// the same key shape as `is_ferrum_env_key`. Prose, tables, and fenced blocks
/// are all scanned: the hardening guide names settings in all three.
fn prose_ferrum_env_tokens(text: &str) -> BTreeSet<&str> {
    let mut keys = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Compare on the byte slice: `i` walks every byte, and slicing `text`
        // inside a multi-byte character (an em dash in prose) would panic.
        // `i` and `end` below always land on ASCII bytes, so the final `&str`
        // slice is on char boundaries.
        if !bytes[i..].starts_with(b"FERRUM_") {
            i += 1;
            continue;
        }
        // Only start a token at a boundary so `X_FERRUM_FOO` is not split.
        if i > 0 {
            let prev = bytes[i - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                i += 1;
                continue;
            }
        }
        let mut end = i;
        while end < bytes.len()
            && (bytes[end].is_ascii_uppercase()
                || bytes[end].is_ascii_digit()
                || bytes[end] == b'_')
        {
            end += 1;
        }
        let key = &text[i..end];
        if is_ferrum_env_key(key) {
            keys.insert(key);
        }
        i = end;
    }
    keys
}

/// The hardening guide is a checklist of links, so every `FERRUM_*` it names
/// must be a real public setting. A rename that misses the guide leaves an
/// operator configuring a variable the binary ignores.
#[test]
fn hardening_guide_only_names_public_ferrum_settings() {
    let inventory = public_inventory();
    let named = prose_ferrum_env_tokens(HARDENING_MD);
    assert!(
        named.len() > 20,
        "hardening guide token extraction unexpectedly small ({}); parser or guide likely broke",
        named.len()
    );

    let unknown: Vec<&&str> = named
        .iter()
        .filter(|key| !inventory.contains(**key))
        .collect();
    assert!(
        unknown.is_empty(),
        "the hardening guide names a variable that is not a public setting — either the guide \
         is wrong or the variable was renamed:\n  {}",
        unknown
            .iter()
            .map(|key| **key)
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}
