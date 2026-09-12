//! `ferrum-edge validate -m mesh` file-protocol selection (issue #3925).

use ferrum_edge::cli::{
    RunArgs, ValidateArgs, apply_run_overrides, apply_validate_overrides, execute_validate,
};
use ferrum_edge::modes::mesh::validate::{
    CONFLICTING_MESH_FILE_SOURCES, prepare_validate_file_source,
};
use tempfile::TempDir;

use crate::unit::env_lock::EnvGuard;

const MESH_IDENTITY_KEYS: &[&str] = &[
    "FERRUM_MODE",
    "FERRUM_MESH_CONFIG_PROTOCOL",
    "FERRUM_MESH_FILE_CONFIG_PATH",
    "FERRUM_FILE_CONFIG_PATH",
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
    "FERRUM_CONF_PATH",
    "FERRUM_NAMESPACE",
];

const VALID_SLICE: &str = r#"
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

const GATEWAY_SPEC: &str = r#"
version: "1"
proxies: []
consumers: []
upstreams: []
plugin_configs: []
"#;

fn write_yaml(dir: &TempDir, name: &str, contents: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).unwrap();
    path.to_str().unwrap().to_string()
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

fn install_internal_ca(guard: &EnvGuard) {
    guard.set("FERRUM_MESH_CA_BACKEND", "internal");
    guard.set("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    guard.set(
        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
        "spiffe://cluster.local/ns/ferrum/sa/api",
    );
}

fn clear_identity(guard: &EnvGuard) {
    guard.unset("FERRUM_MESH_CA_BACKEND");
    guard.unset("FERRUM_MESH_CA_BOOTSTRAP_DEV");
    guard.unset("FERRUM_MESH_WORKLOAD_SPIFFE_ID");
    guard.unset("FERRUM_MESH_ALLOW_NO_CA");
}

fn validate_args(spec: Option<&str>) -> ValidateArgs {
    validate_args_with_empty_namespace(spec, false)
}

fn validate_args_with_empty_namespace(
    spec: Option<&str>,
    allow_empty_namespace: bool,
) -> ValidateArgs {
    ValidateArgs {
        settings: None,
        spec: spec.map(Into::into),
        mode: Some("mesh".into()),
        verbose: 0,
        fips_mode: None,
        allow_empty_namespace,
    }
}

#[test]
fn explicit_file_protocol_uses_spec_without_mesh_file_path() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    apply_validate_overrides(&validate_args(Some(&slice)));
    prepare_validate_file_source().expect("explicit file protocol accepts --spec");
    assert_eq!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").unwrap(),
        "file"
    );
    assert_eq!(
        std::env::var("FERRUM_MESH_FILE_CONFIG_PATH").unwrap(),
        slice
    );
    execute_validate(&validate_args(None)).expect("validate file protocol slice");
}

#[test]
fn infers_file_protocol_from_localized_spec() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);

    apply_validate_overrides(&validate_args(Some(&slice)));
    prepare_validate_file_source().expect("localized document infers file");
    assert_eq!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").unwrap(),
        "file"
    );
    assert_eq!(
        std::env::var("FERRUM_MESH_FILE_CONFIG_PATH").unwrap(),
        slice
    );
    execute_validate(&validate_args(None)).expect("inferred file protocol validates the slice");
}

#[test]
fn native_protocol_still_requires_cp_urls() {
    let dir = TempDir::new().unwrap();
    let gateway = write_yaml(&dir, "resources.yaml", GATEWAY_SPEC);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "native");

    apply_validate_overrides(&validate_args(Some(&gateway)));
    prepare_validate_file_source().expect("gateway spec is not a mesh slice");
    let error =
        execute_validate(&validate_args(None)).expect_err("native protocol still needs CP URLs");
    assert!(
        error.contains("FERRUM_DP_CP_GRPC_URLS"),
        "native mesh validate must keep CP requirements, got: {error}"
    );
}

#[test]
fn xds_protocol_still_requires_cp_urls() {
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "xds");

    let error =
        execute_validate(&validate_args(None)).expect_err("xds protocol still needs CP URLs");
    assert!(
        error.contains("FERRUM_DP_CP_GRPC_URLS"),
        "xds mesh validate must keep CP requirements, got: {error}"
    );
}

#[test]
fn explicit_native_rejects_localized_spec() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "native");

    apply_validate_overrides(&validate_args(Some(&slice)));
    let error = prepare_validate_file_source().expect_err("native + mesh slice is a conflict");
    assert!(
        error.contains("FERRUM_MESH_CONFIG_PROTOCOL=native"),
        "conflict must name the explicit protocol, got: {error}"
    );
    assert!(
        error.contains("{version?, mesh}"),
        "conflict must name the localized document shape, got: {error}"
    );
}

#[test]
fn conflicting_spec_and_mesh_file_paths_fail_closed() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let other = write_yaml(&dir, "other.yaml", "mesh: {}\n");
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");
    guard.set("FERRUM_MESH_FILE_CONFIG_PATH", &other);

    apply_validate_overrides(&validate_args(Some(&slice)));
    let error = prepare_validate_file_source().expect_err("distinct paths conflict");
    assert_eq!(error, CONFLICTING_MESH_FILE_SOURCES);
}

#[test]
fn identical_spec_and_mesh_file_paths_are_not_a_conflict() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");
    guard.set("FERRUM_MESH_FILE_CONFIG_PATH", &slice);

    apply_validate_overrides(&validate_args(Some(&slice)));
    prepare_validate_file_source().expect("same path is not a conflict");
    execute_validate(&validate_args(None)).expect("identical paths validate");
}

#[test]
fn gateway_spec_does_not_infer_file_protocol() {
    let dir = TempDir::new().unwrap();
    let gateway = write_yaml(&dir, "resources.yaml", GATEWAY_SPEC);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);

    apply_validate_overrides(&validate_args(Some(&gateway)));
    prepare_validate_file_source().expect("gateway document must not infer file");
    assert!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").is_err(),
        "inference must not set file protocol for a gateway document"
    );
    let error =
        execute_validate(&validate_args(None)).expect_err("default native still needs CP URLs");
    assert!(
        error.contains("FERRUM_DP_CP_GRPC_URLS"),
        "non-mesh document must not skip CP requirements, got: {error}"
    );
}

#[test]
fn malformed_slice_fails_under_explicit_file_protocol() {
    let dir = TempDir::new().unwrap();
    let bad = write_yaml(&dir, "bad.yaml", "mesh: [\n");
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    apply_validate_overrides(&validate_args(Some(&bad)));
    prepare_validate_file_source().expect("path mapping does not require a successful parse");
    let error =
        execute_validate(&validate_args(None)).expect_err("malformed mesh document must fail");
    assert!(
        error.contains("Mesh spec validation failed") || error.contains("invalid mesh"),
        "malformed document must surface the file parser diagnostic, got: {error}"
    );
}

#[test]
fn unknown_field_slice_fails_under_explicit_file_protocol() {
    let dir = TempDir::new().unwrap();
    let bad = write_yaml(
        &dir,
        "unknown.yaml",
        r#"
mesh:
  services: []
proxies: []
"#,
    );
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    apply_validate_overrides(&validate_args(Some(&bad)));
    prepare_validate_file_source().expect("explicit file protocol maps --spec");
    let error =
        execute_validate(&validate_args(None)).expect_err("unknown fields must fail closed");
    assert!(
        error.contains("proxies") && error.contains("Mesh spec validation failed"),
        "unknown fields must keep the file-source diagnostic, got: {error}"
    );
}

#[test]
fn file_protocol_still_requires_workload_identity() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    clear_identity(&guard);
    guard.set("FERRUM_MESH_CONFIG_PROTOCOL", "file");

    apply_validate_overrides(&validate_args(Some(&slice)));
    prepare_validate_file_source().expect("path mapping succeeds before identity");
    let error = execute_validate(&validate_args(None)).expect_err("missing identity must fail");
    assert!(
        error.contains("workload identity")
            || error.contains("FERRUM_MESH_CA_BACKEND")
            || error.contains("FERRUM_GATEWAY_SVID"),
        "file-protocol validate must keep identity/CA guardrails, got: {error}"
    );
    assert!(
        !error.contains("FERRUM_DP_CP_GRPC_URLS"),
        "identity failure must not be masked by a CP URL requirement, got: {error}"
    );
}

#[test]
fn run_overrides_do_not_select_mesh_file_protocol() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.yaml", VALID_SLICE);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);

    apply_run_overrides(&RunArgs {
        settings: None,
        spec: Some(slice.clone().into()),
        mode: Some("mesh".into()),
        verbose: 0,
        fips_mode: None,
    });
    assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "mesh");
    assert_eq!(std::env::var("FERRUM_FILE_CONFIG_PATH").unwrap(), slice);
    assert!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").is_err(),
        "run must not infer mesh file protocol from --spec"
    );
    assert!(
        std::env::var("FERRUM_MESH_FILE_CONFIG_PATH").is_err(),
        "run must not map --spec onto FERRUM_MESH_FILE_CONFIG_PATH"
    );
}

#[test]
fn missing_spec_for_inferred_file_keeps_native_cp_requirement() {
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);

    prepare_validate_file_source().expect("no document means no inference");
    let error =
        execute_validate(&validate_args(None)).expect_err("default native still needs CP URLs");
    assert!(
        error.contains("FERRUM_DP_CP_GRPC_URLS"),
        "inference must not fire without a localized document, got: {error}"
    );
}

#[test]
fn invalid_inner_mesh_fields_still_select_file_then_fail_validation() {
    let dir = TempDir::new().unwrap();
    let bad = write_yaml(
        &dir,
        "invalid-fields.yaml",
        r#"
mesh:
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 0
          protocol: http
"#,
    );
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);

    apply_validate_overrides(&validate_args(Some(&bad)));
    prepare_validate_file_source().expect("localized shape infers file even with invalid fields");
    assert_eq!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").unwrap(),
        "file"
    );
    let error = execute_validate(&validate_args(None)).expect_err("invalid mesh fields must fail");
    assert!(
        error.contains("Mesh spec validation failed") && error.contains("validation failed"),
        "inner field errors must come from the real file parser, got: {error}"
    );
}

#[test]
fn malformed_spec_does_not_infer_file_protocol() {
    let dir = TempDir::new().unwrap();
    let bad = write_yaml(&dir, "bad.yaml", "mesh: [\n");
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);

    apply_validate_overrides(&validate_args(Some(&bad)));
    prepare_validate_file_source().expect("malformed YAML is not the localized shape");
    assert!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").is_err(),
        "inference must not select file protocol for malformed YAML"
    );
    let error =
        execute_validate(&validate_args(None)).expect_err("default native still needs CP URLs");
    assert!(
        error.contains("FERRUM_DP_CP_GRPC_URLS"),
        "only the localized shape may skip CP requirements, got: {error}"
    );
}

#[test]
fn json_spec_infers_file_protocol_from_extension() {
    let dir = TempDir::new().unwrap();
    let slice = write_yaml(&dir, "slice.json", r#"{"mesh":{}}"#);
    let guard = EnvGuard::new(MESH_IDENTITY_KEYS);
    mesh_env(&guard);
    install_internal_ca(&guard);

    apply_validate_overrides(&validate_args(Some(&slice)));
    prepare_validate_file_source().expect("json localized document infers file");
    assert_eq!(
        std::env::var("FERRUM_MESH_CONFIG_PROTOCOL").unwrap(),
        "file"
    );
    execute_validate(&validate_args(None)).expect("empty mesh mapping is a valid file document");
}

#[test]
fn validate_wires_stock_xds_to_the_policy_only_loader() {
    let source = include_str!("../../../src/cli.rs");
    let validate = source
        .split("pub fn execute_validate(")
        .nth(1)
        .expect("execute_validate")
        .split("pub fn execute_health(")
        .next()
        .unwrap_or(source);
    assert!(
        validate.contains("MeshConfigProtocol::StockXds")
            && validate.contains("load_stock_policy_baseline"),
        "stock_xds validate must parse the local document with its policy-only admission"
    );
}
