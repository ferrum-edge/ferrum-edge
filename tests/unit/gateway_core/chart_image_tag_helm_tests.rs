//! Static Helm/chart contract coverage for image tag drift (issue #4440).
//!
//! These tests assert both charts derive their default image tag from
//! `Chart.appVersion` and stay aligned with `Cargo.toml`, without requiring a
//! local `helm` binary.

const CARGO_TOML: &str = include_str!("../../../Cargo.toml");
const GATEWAY_CHART_YAML: &str = include_str!("../../../charts/ferrum-gateway/Chart.yaml");
const MESH_CHART_YAML: &str = include_str!("../../../charts/ferrum-mesh/Chart.yaml");
const GATEWAY_HELPERS: &str = include_str!("../../../charts/ferrum-gateway/templates/_helpers.tpl");
const MESH_HELPERS: &str = include_str!("../../../charts/ferrum-mesh/templates/_helpers.tpl");
const GATEWAY_VALUES: &str = include_str!("../../../charts/ferrum-gateway/values.yaml");
const MESH_VALUES: &str = include_str!("../../../charts/ferrum-mesh/values.yaml");

fn parse_cargo_version() -> String {
    for line in CARGO_TOML.lines() {
        if let Some(rest) = line.strip_prefix("version = ") {
            return rest.trim().trim_matches('"').to_string();
        }
    }
    panic!("Cargo.toml: missing version field");
}

fn parse_chart_app_version(chart_yaml: &str, chart_path: &str) -> String {
    for line in chart_yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("appVersion:") {
            return rest.trim().trim_matches('"').to_string();
        }
    }
    panic!("{chart_path}: missing appVersion field");
}

#[test]
fn chart_app_versions_match_cargo_toml() {
    let cargo_version = parse_cargo_version();
    let gateway = parse_chart_app_version(GATEWAY_CHART_YAML, "charts/ferrum-gateway/Chart.yaml");
    let mesh = parse_chart_app_version(MESH_CHART_YAML, "charts/ferrum-mesh/Chart.yaml");

    assert_eq!(
        gateway, mesh,
        "charts/ferrum-gateway/Chart.yaml appVersion ({gateway}) must match \
         charts/ferrum-mesh/Chart.yaml appVersion ({mesh})"
    );
    assert_eq!(
        gateway, cargo_version,
        "charts/ferrum-gateway/Chart.yaml appVersion ({gateway}) must match \
         Cargo.toml version ({cargo_version})"
    );
}

#[test]
fn gateway_image_tag_defaults_from_chart_app_version() {
    assert!(
        GATEWAY_HELPERS.contains("default .Chart.AppVersion"),
        "charts/ferrum-gateway/templates/_helpers.tpl must default image.tag from \
         .Chart.AppVersion"
    );
    assert!(
        !GATEWAY_HELPERS.contains("define \"ferrum-gateway.validateImageTag\""),
        "charts/ferrum-gateway/templates/_helpers.tpl must not fail render on unset image.tag"
    );
    assert!(
        !GATEWAY_VALUES.contains("tag: \"0.9.0\""),
        "charts/ferrum-gateway/values.yaml must not hard-code a version literal as the \
         default image tag"
    );
}

#[test]
fn mesh_image_tag_defaults_from_chart_app_version() {
    assert!(
        MESH_HELPERS.contains("default .Chart.AppVersion"),
        "charts/ferrum-mesh/templates/_helpers.tpl must default image.tag from \
         .Chart.AppVersion"
    );
    assert!(
        !MESH_HELPERS.contains("define \"ferrum-mesh.validateImageTag\""),
        "charts/ferrum-mesh/templates/_helpers.tpl must not fail render on unset image.tag"
    );
    assert!(
        !MESH_VALUES.contains("tag: \"0.9.0\""),
        "charts/ferrum-mesh/values.yaml must not hard-code 0.9.0 as the default image tag"
    );
}

#[test]
fn mesh_workloads_use_image_helper_not_raw_tag() {
    for (rel, template) in [
        (
            "templates/injector-deployment.yaml",
            include_str!("../../../charts/ferrum-mesh/templates/injector-deployment.yaml"),
        ),
        (
            "templates/control-plane-deployment.yaml",
            include_str!("../../../charts/ferrum-mesh/templates/control-plane-deployment.yaml"),
        ),
        (
            "templates/east-west-gateway-deployment.yaml",
            include_str!("../../../charts/ferrum-mesh/templates/east-west-gateway-deployment.yaml"),
        ),
    ] {
        assert!(
            template.contains("include \"ferrum-mesh.image\" ."),
            "{rel} must render image through ferrum-mesh.image helper"
        );
        assert!(
            !template.contains(".Values.image.tag }}"),
            "{rel} must not reference .Values.image.tag directly"
        );
    }
}
