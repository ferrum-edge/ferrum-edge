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
    PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS, PUBLIC_FERRUM_ENV_SETTINGS,
    TRANSCRIPT_SINK_SECRET_EXAMPLE_ENV, is_public_ferrum_env_coverage_exempt,
};

/// Prefix of the dynamic `ai_transcript_audit` sink-secret namespace, mirrored
/// from `src/plugins/ai_transcript_audit.rs::SINK_SECRET_ENV_PREFIX`.
const TRANSCRIPT_SINK_SECRET_ENV_PREFIX: &str = "FERRUM_TRANSCRIPT_SINK_SECRET_";

const ENV_CONFIG_SOURCE: &str = include_str!("../../../src/config/env_config.rs");
const CONFIGURATION_MD: &str = include_str!("../../../docs/configuration.md");
const FERRUM_CONF: &str = include_str!("../../../ferrum.conf");

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
