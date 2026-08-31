//! Static Helm/chart contract coverage for issue #4384.
//!
//! `ferrum-gateway` mode=cp must not inherit the binary's in-cluster default
//! (`FERRUM_K8S_CONTROLLER_ENABLED=true` when `KUBERNETES_SERVICE_HOST` is set)
//! because the chart renders no ClusterRole. Hosted CI still runs `helm
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

fn read_ci() -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml"),
    )
    .expect("read .github/workflows/ci.yml")
}

#[test]
fn values_default_k8s_controller_off() {
    let values = read("values.yaml");
    let idx = values
        .find("k8sController:")
        .expect("values.yaml must declare k8sController");
    let window = &values[idx..values.len().min(idx + 120)];
    assert!(
        window.contains("enabled: false"),
        "k8sController.enabled must default to false"
    );
    assert!(
        values.contains("ferrum-mesh chart") && values.contains("control-plane-rbac.yaml"),
        "values.yaml must point operators at ferrum-mesh RBAC"
    );
}

#[test]
fn schema_exposes_k8s_controller_enabled() {
    let schema = read("values.schema.json");
    assert!(
        schema.contains("\"k8sController\"") && schema.contains("\"enabled\""),
        "values.schema.json must declare k8sController.enabled"
    );
    assert!(
        schema.contains("fails render") && schema.contains("ferrum-mesh"),
        "schema must document that enabled=true fails and points at ferrum-mesh"
    );
}

#[test]
fn reserved_env_includes_controller_and_pod_discovery() {
    let helpers = read("templates/_helpers.tpl");
    let reserved = helpers
        .split("{{- define \"ferrum-gateway.reservedEnv\" -}}")
        .nth(1)
        .and_then(|rest| rest.split("{{- end -}}").next())
        .expect("ferrum-gateway.reservedEnv define");
    for name in [
        "FERRUM_K8S_CONTROLLER_ENABLED",
        "FERRUM_K8S_POD_DISCOVERY_ENABLED",
    ] {
        assert!(
            reserved.contains(name),
            "reservedEnv must include {name} so env/extraEnv cannot re-enable watches"
        );
    }
}

#[test]
fn mode_cp_renders_controller_and_pod_discovery_false() {
    let helpers = read("templates/_helpers.tpl");
    let mode_env = helpers
        .split("{{- define \"ferrum-gateway.modeEnv\" -}}")
        .nth(1)
        .and_then(|rest| rest.split("{{- define ").next())
        .expect("ferrum-gateway.modeEnv define");
    assert!(
        mode_env.contains("eq $mode \"cp\""),
        "controller env must be gated to mode=cp"
    );
    assert!(
        mode_env.contains("- name: FERRUM_K8S_CONTROLLER_ENABLED")
            && mode_env.contains("value: \"false\"")
            && mode_env.contains("- name: FERRUM_K8S_POD_DISCOVERY_ENABLED"),
        "mode=cp must emit FERRUM_K8S_CONTROLLER_ENABLED=false and \
         FERRUM_K8S_POD_DISCOVERY_ENABLED=false"
    );
}

#[test]
fn opt_in_fails_render_and_points_at_ferrum_mesh() {
    let helpers = read("templates/_helpers.tpl");
    assert!(
        helpers.contains("k8sController.enabled=true is not supported")
            && helpers.contains("ferrum-mesh")
            && helpers.contains("controlPlane.rbac")
            && helpers.contains("403-retry"),
        "enabled=true must fail render with a pointer to ferrum-mesh, not ship RBAC"
    );
}

#[test]
fn chart_does_not_render_controller_rbac() {
    let templates = chart_root().join("templates");
    let entries = std::fs::read_dir(&templates).unwrap_or_else(|e| {
        panic!("failed to list {}: {e}", templates.display());
    });
    for entry in entries {
        let entry = entry.expect("read templates dirent");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.to_lowercase().contains("rbac"),
            "ferrum-gateway must not ship an RBAC template ({name}); \
             ferrum-mesh is the designated controller"
        );
        if name.ends_with(".yaml") || name.ends_with(".tpl") {
            let body = std::fs::read_to_string(entry.path()).unwrap_or_else(|e| {
                panic!("failed to read {}: {e}", entry.path().display());
            });
            for kind in [
                "kind: ClusterRole",
                "kind: ClusterRoleBinding",
                "kind: Role",
                "kind: RoleBinding",
            ] {
                assert!(
                    !body.contains(kind),
                    "{} must not render {kind}",
                    entry.path().display()
                );
            }
        }
    }
}

#[test]
fn cp_example_does_not_opt_in() {
    let example = read("examples/cp-values.yaml");
    assert!(
        !example.contains("k8sController:")
            && example.contains("ferrum-mesh")
            && example.contains("FERRUM_K8S_CONTROLLER_ENABLED=false"),
        "cp-values.yaml must inherit k8sController.enabled=false and document ferrum-mesh"
    );
}

#[test]
fn docs_and_notes_describe_default_off() {
    let readme = read("README.md");
    assert!(
        readme.contains("k8sController.enabled")
            && readme.contains("FERRUM_K8S_CONTROLLER_ENABLED=false")
            && readme.contains("ferrum-mesh"),
        "chart README must document the default-off controller"
    );
    let notes = read("templates/NOTES.txt");
    assert!(
        notes.contains("FERRUM_K8S_CONTROLLER_ENABLED=false") && notes.contains("ferrum-mesh"),
        "NOTES.txt must tell CP operators the controller is off"
    );
    let docs = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/kubernetes_deployment.md"),
    )
    .expect("read docs/kubernetes_deployment.md");
    assert!(
        docs.contains("k8sController.enabled")
            && docs.contains("FERRUM_K8S_CONTROLLER_ENABLED=false")
            && docs.contains("examples/cp-values.yaml"),
        "kubernetes_deployment.md quickstart must no longer start 403 loops"
    );
}

#[test]
fn hosted_ci_asserts_cp_controller_default_off_and_opt_in_fail() {
    let ci = read_ci();
    for needle in [
        "FERRUM_K8S_CONTROLLER_ENABLED",
        "FERRUM_K8S_POD_DISCOVERY_ENABLED",
        "k8sController.enabled=true is not supported",
        "env.FERRUM_K8S_CONTROLLER_ENABLED is managed by first-class chart values",
        "Gateway CP must not render controller RBAC",
    ] {
        assert!(
            ci.contains(needle),
            "hosted helm-chart job must assert issue #4384 contract: missing {needle}"
        );
    }
}
