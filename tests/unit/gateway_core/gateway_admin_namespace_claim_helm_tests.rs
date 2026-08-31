//! Static Helm/chart contract coverage for issue #4456.
//!
//! `ferrum-gateway` must expose `admin.requireNamespaceClaim` alongside the
//! existing `cp.requireNamespaceClaim` tenancy pair. Hosted CI still runs `helm
//! template` end-to-end; these tests pin the chart source without a local
//! `helm` binary.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-gateway")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-gateway/{rel}: {e}");
    })
}

/// The YAML block under a top-level `key:`, ending at the next top-level key.
///
/// A fixed character window is not usable here: the `admin:` block carries
/// long explanatory comments, so a byte budget silently truncates before the
/// value under test and the assertion fails for the wrong reason.
fn top_level_block<'a>(values: &'a str, key: &str) -> &'a str {
    let header = format!("\n{key}:");
    let start = values
        .find(&header)
        .map(|idx| idx + 1)
        .or_else(|| values.starts_with(&header[1..]).then_some(0))
        .unwrap_or_else(|| panic!("values.yaml must declare {key}"));
    let rest = &values[start..];
    let end = rest
        .match_indices('\n')
        .find(|(idx, _)| {
            let line = rest[idx + 1..].split('\n').next().unwrap_or("");
            !line.is_empty() && !line.starts_with([' ', '\t', '#'])
        })
        .map(|(idx, _)| idx + 1)
        .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn values_default_admin_require_namespace_claim_off() {
    let values = read("values.yaml");
    let block = top_level_block(&values, "admin");
    assert!(
        block.contains("requireNamespaceClaim: false"),
        "admin.requireNamespaceClaim must default to false"
    );
}

#[test]
fn schema_exposes_admin_require_namespace_claim() {
    let schema = read("values.schema.json");
    let admin = schema
        .split("\"admin\":")
        .nth(1)
        .and_then(|rest| rest.split("\"grpc\":").next())
        .expect("values.schema.json must declare admin before grpc");
    assert!(
        admin.contains("\"requireNamespaceClaim\"") && admin.contains("\"boolean\""),
        "values.schema.json must declare admin.requireNamespaceClaim as boolean"
    );
}

#[test]
fn reserved_env_includes_admin_require_namespace_claim() {
    let helpers = read("templates/_helpers.tpl");
    let reserved = helpers
        .split("{{- define \"ferrum-gateway.reservedEnv\" -}}")
        .nth(1)
        .and_then(|rest| rest.split("{{- end -}}").next())
        .expect("ferrum-gateway.reservedEnv define");
    assert!(
        reserved.contains("FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM"),
        "reservedEnv must include FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM so env/extraEnv \
         cannot desync it"
    );
}

#[test]
fn mode_env_renders_admin_require_namespace_claim_outside_cp_gate() {
    let helpers = read("templates/_helpers.tpl");
    let mode_env = helpers
        .split("{{- define \"ferrum-gateway.modeEnv\" -}}")
        .nth(1)
        .and_then(|rest| rest.split("{{- define ").next())
        .expect("ferrum-gateway.modeEnv define");
    let admin_claim = mode_env
        .find("- name: FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM")
        .expect("modeEnv must render FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM");
    let cp_gate = mode_env
        .find("{{- if eq $mode \"cp\" }}")
        .expect("modeEnv must gate cp-only settings");
    assert!(
        admin_claim < cp_gate,
        "admin.requireNamespaceClaim must render for every admin-serving mode, not only cp"
    );
    assert!(
        mode_env.contains(".Values.admin.requireNamespaceClaim")
            && mode_env.contains("value: \"true\""),
        "modeEnv must gate admin claim emission on admin.requireNamespaceClaim=true"
    );
}
