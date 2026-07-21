//! DOC-03: EnvConfig ↔ docs/configuration.md ↔ ferrum.conf coverage contract.
//!
//! Assembles one public inventory from production `EnvConfig` parse sites plus
//! [`ferrum_edge::config::public_env_inventory::EXTRA_PUBLIC_FERRUM_ENV_SETTINGS`],
//! then fails closed when any non-exempt setting lacks a canonical docs table
//! row or a `ferrum.conf` template assignment. Membership is order-independent.

use std::collections::BTreeSet;

use ferrum_edge::config::public_env_inventory::{
    EXTRA_PUBLIC_FERRUM_ENV_SETTINGS, PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS,
    is_public_ferrum_env_coverage_exempt,
};

const ENV_CONFIG_SOURCE: &str = include_str!("../../../src/config/env_config.rs");
const CONFIGURATION_MD: &str = include_str!("../../../docs/configuration.md");
const FERRUM_CONF: &str = include_str!("../../../ferrum.conf");

/// Production `impl EnvConfig` body only — excludes `#[cfg(test)]` helpers and
/// macro unit-test sample keys such as `FERRUM_SAMPLE_*`.
fn production_env_config_source() -> &'static str {
    let impl_start = ENV_CONFIG_SOURCE
        .find("impl EnvConfig {")
        .expect("EnvConfig impl block");
    let test_mod = ENV_CONFIG_SOURCE[impl_start..]
        .find("#[cfg(test)]\nmod tests {")
        .expect("EnvConfig inline test module boundary");
    &ENV_CONFIG_SOURCE[impl_start..impl_start + test_mod]
}

fn is_ferrum_env_key(key: &str) -> bool {
    key.starts_with("FERRUM_")
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Extract quoted `FERRUM_*` string literals from production `EnvConfig` parse
/// sites. Requires a preceding `=` / `(` so comment prose is ignored.
fn extract_env_config_keys(source: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i + 8 < bytes.len() {
        // Find `"FERRUM_`
        if bytes[i] == b'"'
            && source[i + 1..].starts_with("FERRUM_")
        {
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
                    // Confirm this looks like a parse-site literal rather than
                    // a random quoted mention in a comment: look back for `=`
                    // or `(` on the same line.
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

fn env_config_public_keys() -> BTreeSet<String> {
    let mut keys = extract_env_config_keys(production_env_config_source());
    // OperatingMode is resolved before the env_config! blocks but is a public
    // accepted setting with its own docs/template surfaces.
    keys.insert("FERRUM_MODE".to_string());
    keys
}

fn public_inventory() -> BTreeSet<String> {
    let mut keys = env_config_public_keys();
    for key in EXTRA_PUBLIC_FERRUM_ENV_SETTINGS {
        keys.insert((*key).to_string());
    }
    keys
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
fn extra_public_inventory_is_sorted_and_unique() {
    assert!(
        EXTRA_PUBLIC_FERRUM_ENV_SETTINGS
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "EXTRA_PUBLIC_FERRUM_ENV_SETTINGS must be strictly sorted unique keys"
    );
    assert!(
        PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS must be strictly sorted unique keys"
    );
}

#[test]
fn public_ferrum_env_settings_have_docs_table_and_ferrum_conf_coverage() {
    let inventory = public_inventory();
    assert!(
        inventory.len() > 100,
        "inventory unexpectedly small ({}); extraction likely broke",
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
