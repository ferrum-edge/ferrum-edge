//! `ferrum-edge validate` namespace-filter mismatch (issues #5450 / #5451).

use ferrum_edge::cli::{
    ValidateArgs, ValidateNamespaceFilter, apply_validate_overrides, execute_validate,
};
use tempfile::TempDir;

use crate::unit::env_lock::EnvGuard;

const FILE_KEYS: &[&str] = &[
    "FERRUM_MODE",
    "FERRUM_NAMESPACE",
    "FERRUM_FILE_CONFIG_PATH",
    "FERRUM_CONF_PATH",
    "FERRUM_MESH_CONFIG_PROTOCOL",
    "FERRUM_MESH_FILE_CONFIG_PATH",
    "FERRUM_DP_CP_GRPC_URLS",
    "FERRUM_CP_DP_GRPC_JWT_SECRET",
    "FERRUM_MESH_CA_BACKEND",
    "FERRUM_MESH_CA_BOOTSTRAP_DEV",
    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
    "FERRUM_MESH_PRODUCTION_MODE",
    "FERRUM_MESH_ALLOW_NO_CA",
    "FERRUM_GATEWAY_SVID_CERT_PATH",
    "FERRUM_GATEWAY_SVID_KEY_PATH",
    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
];

const FERRUM_PROXY: &str = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
upstreams: []
plugin_configs: []
"#;

const EMPTY_FILE_SPEC: &str = r#"
version: "1"
proxies: []
consumers: []
upstreams: []
plugin_configs: []
"#;

const FERRUM_MESH_SLICE: &str = r#"
version: "1"
mesh:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      selector:
        labels:
          app: api
      service_name: api
      addresses: ["10.0.0.5"]
      ports:
        - port: 8080
          protocol: http
      trust_domain: cluster.local
      namespace: ferrum
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
      workloads:
        - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
"#;

const EMPTY_MESH_SLICE: &str = r#"
version: "1"
mesh: {}
"#;

fn write_yaml(dir: &TempDir, name: &str, contents: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).unwrap();
    path.to_str().unwrap().to_string()
}

fn file_args(spec: &str, allow_empty_namespace: bool) -> ValidateArgs {
    ValidateArgs {
        settings: None,
        spec: Some(spec.into()),
        mode: Some("file".into()),
        verbose: 0,
        fips_mode: None,
        allow_empty_namespace,
    }
}

fn mesh_args(spec: &str, allow_empty_namespace: bool) -> ValidateArgs {
    ValidateArgs {
        settings: None,
        spec: Some(spec.into()),
        mode: Some("mesh".into()),
        verbose: 0,
        fips_mode: None,
        allow_empty_namespace,
    }
}

fn install_internal_ca(guard: &EnvGuard) {
    guard.set("FERRUM_MESH_CA_BACKEND", "internal");
    guard.set("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    guard.set(
        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
        "spiffe://cluster.local/ns/ferrum/sa/api",
    );
}

fn file_env(guard: &EnvGuard) {
    guard.set("FERRUM_MODE", "file");
    guard.unset("FERRUM_NAMESPACE");
    guard.unset("FERRUM_FILE_CONFIG_PATH");
    guard.unset("FERRUM_CONF_PATH");
    guard.unset("FERRUM_MESH_CONFIG_PROTOCOL");
    guard.unset("FERRUM_MESH_FILE_CONFIG_PATH");
}

fn mesh_env(guard: &EnvGuard) {
    guard.set("FERRUM_MODE", "mesh");
    guard.unset("FERRUM_NAMESPACE");
    guard.unset("FERRUM_MESH_CONFIG_PROTOCOL");
    guard.unset("FERRUM_MESH_FILE_CONFIG_PATH");
    guard.unset("FERRUM_FILE_CONFIG_PATH");
    guard.unset("FERRUM_DP_CP_GRPC_URLS");
    guard.unset("FERRUM_CP_DP_GRPC_JWT_SECRET");
    guard.unset("FERRUM_MESH_PRODUCTION_MODE");
    guard.unset("FERRUM_MESH_ALLOW_NO_CA");
    guard.unset("FERRUM_GATEWAY_SVID_CERT_PATH");
    guard.unset("FERRUM_GATEWAY_SVID_KEY_PATH");
    guard.unset("FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH");
}

#[test]
fn file_zero_survivors_fails_closed() {
    let dir = TempDir::new().unwrap();
    let spec = write_yaml(&dir, "resources.yaml", FERRUM_PROXY);
    let guard = EnvGuard::new(FILE_KEYS);
    file_env(&guard);
    guard.set("FERRUM_NAMESPACE", "other-ns");

    let args = file_args(&spec, false);
    apply_validate_overrides(&args);
    let error = execute_validate(&args).expect_err("mismatched namespace must fail");
    assert!(
        error.contains("namespace filter mismatch"),
        "must name the mismatch, got: {error}"
    );
    assert!(
        error.contains("other-ns"),
        "must name the active namespace, got: {error}"
    );
    assert!(
        error.contains("ferrum"),
        "must name the document namespace, got: {error}"
    );
    assert!(
        error.contains("proxies=0"),
        "must include post-filter counts, got: {error}"
    );
    assert!(
        error.contains("--allow-empty-namespace"),
        "must name the opt-out flag, got: {error}"
    );
}

#[test]
fn file_allow_empty_namespace_warns_and_succeeds() {
    let dir = TempDir::new().unwrap();
    let spec = write_yaml(&dir, "resources.yaml", FERRUM_PROXY);
    let guard = EnvGuard::new(FILE_KEYS);
    file_env(&guard);
    guard.set("FERRUM_NAMESPACE", "other-ns");

    let args = file_args(&spec, true);
    apply_validate_overrides(&args);
    execute_validate(&args).expect("opt-out must succeed");
}

#[test]
fn file_matching_namespace_still_succeeds() {
    let dir = TempDir::new().unwrap();
    let spec = write_yaml(&dir, "resources.yaml", FERRUM_PROXY);
    let guard = EnvGuard::new(FILE_KEYS);
    file_env(&guard);
    guard.set("FERRUM_NAMESPACE", "ferrum");

    let args = file_args(&spec, false);
    apply_validate_overrides(&args);
    execute_validate(&args).expect("matching namespace must stay successful");
}

#[test]
fn file_empty_document_is_not_a_mismatch() {
    let dir = TempDir::new().unwrap();
    let spec = write_yaml(&dir, "empty.yaml", EMPTY_FILE_SPEC);
    let guard = EnvGuard::new(FILE_KEYS);
    file_env(&guard);
    guard.set("FERRUM_NAMESPACE", "other-ns");

    let args = file_args(&spec, false);
    apply_validate_overrides(&args);
    execute_validate(&args).expect("an empty document is not a namespace mismatch");
}

#[test]
fn mesh_zero_survivors_fails_closed() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", FERRUM_MESH_SLICE);
    let guard = EnvGuard::new(FILE_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_NAMESPACE", "other-ns");
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    let args = mesh_args(&slice, false);
    apply_validate_overrides(&args);
    ferrum_edge::modes::mesh::validate::prepare_validate_file_source()
        .expect("explicit file protocol accepts --spec");
    let error = execute_validate(&args).expect_err("mismatched mesh namespace must fail");
    assert!(
        error.contains("namespace filter mismatch"),
        "must name the mismatch, got: {error}"
    );
    assert!(
        error.contains("other-ns"),
        "must name the active namespace, got: {error}"
    );
    assert!(
        error.contains("ferrum"),
        "must name the document namespace, got: {error}"
    );
    assert!(
        error.contains("workloads=0")
            && error.contains("services=0")
            && error.contains("policies=0"),
        "must include post-filter mesh counts, got: {error}"
    );
}

#[test]
fn mesh_allow_empty_namespace_warns_and_succeeds() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", FERRUM_MESH_SLICE);
    let guard = EnvGuard::new(FILE_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_NAMESPACE", "other-ns");
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    let args = mesh_args(&slice, true);
    apply_validate_overrides(&args);
    ferrum_edge::modes::mesh::validate::prepare_validate_file_source()
        .expect("explicit file protocol accepts --spec");
    execute_validate(&args).expect("mesh opt-out must succeed");
}

#[test]
fn mesh_matching_namespace_still_succeeds() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", FERRUM_MESH_SLICE);
    let guard = EnvGuard::new(FILE_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_NAMESPACE", "ferrum");
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    let args = mesh_args(&slice, false);
    apply_validate_overrides(&args);
    ferrum_edge::modes::mesh::validate::prepare_validate_file_source()
        .expect("explicit file protocol accepts --spec");
    execute_validate(&args).expect("matching mesh namespace must stay successful");
}

#[test]
fn mesh_empty_document_is_not_a_mismatch() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "empty.yaml", EMPTY_MESH_SLICE);
    let guard = EnvGuard::new(FILE_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_NAMESPACE", "other-ns");
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    let args = mesh_args(&slice, false);
    apply_validate_overrides(&args);
    ferrum_edge::modes::mesh::validate::prepare_validate_file_source()
        .expect("explicit file protocol accepts --spec");
    execute_validate(&args).expect("an empty mesh document is not a namespace mismatch");
}

#[test]
fn empty_mismatch_helper_distinguishes_empty_documents() {
    let empty = ValidateNamespaceFilter {
        active_namespace: "other-ns".into(),
        document_namespaces: Vec::new(),
        document_had_namespaced_resources: false,
        count_fields: vec![("proxies", 0), ("consumers", 0)],
    };
    assert!(!empty.is_empty_mismatch());

    let mismatch = ValidateNamespaceFilter {
        active_namespace: "other-ns".into(),
        document_namespaces: vec!["ferrum".into()],
        document_had_namespaced_resources: true,
        count_fields: vec![("proxies", 0), ("consumers", 0)],
    };
    assert!(mismatch.is_empty_mismatch());
    let diagnostic = mismatch.diagnostic();
    assert!(diagnostic.contains("other-ns"));
    assert!(diagnostic.contains("ferrum"));
    assert!(diagnostic.contains("proxies=0"));
}

#[test]
fn validate_prints_warning_when_empty_namespace_is_allowed() {
    let source = include_str!("../../../src/cli.rs");
    assert!(
        source.contains("WARNING: {diagnostic}"),
        "allow-empty-namespace must print a loud warning"
    );
    assert!(
        source.contains("Continuing because --allow-empty-namespace was set."),
        "warning must name the opt-out flag"
    );
}
