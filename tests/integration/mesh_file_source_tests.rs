//! Localized file mesh config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`).
//!
//! Exercises `config_consumer::file_source::load_mesh_slice_from_file`: the
//! document contract (mesh section only, optional `version` stamp), fail-closed
//! validation, and slice-building parity with the CP-side materialization
//! (namespace scoping, version stamping from `loaded_at`).

use std::io::Write;

use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file;
use ferrum_edge::modes::mesh::slice::MeshSliceRequest;

fn request_for_namespace(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "file-source-node".to_string(),
        namespace: namespace.to_string(),
        ..MeshSliceRequest::default()
    }
}

fn write_temp(ext: &str, content: &str) -> tempfile::TempPath {
    let mut file = tempfile::Builder::new()
        .suffix(&format!(".{ext}"))
        .tempfile()
        .expect("create temp mesh config");
    file.write_all(content.as_bytes())
        .expect("write temp mesh config");
    file.into_temp_path()
}

const VALID_MESH_YAML: &str = r#"
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

#[test]
fn loads_yaml_mesh_document_and_builds_slice() {
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("valid mesh document loads");

    assert_eq!(slice.node_id, "file-source-node");
    assert_eq!(slice.namespace, "ferrum");
    assert_eq!(slice.workloads.len(), 1);
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "api");
    assert!(
        !slice.version.is_empty(),
        "slice version must carry the load timestamp"
    );
    chrono::DateTime::parse_from_rfc3339(&slice.version)
        .expect("file-built slice version is the RFC3339 load timestamp");
}

#[test]
fn loads_json_mesh_document() {
    let json = serde_json::json!({
        "mesh": {
            "services": [{
                "name": "api",
                "namespace": "ferrum",
                "ports": [{"port": 80, "protocol": "http"}],
            }],
        }
    });
    let path = write_temp("json", &json.to_string());
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("valid JSON mesh document loads");
    assert_eq!(slice.services.len(), 1);
}

#[test]
fn slice_building_scopes_by_request_namespace() {
    // Namespace scoping happens DP-side for the file source — the same
    // `MeshSlice::from_gateway_config` narrowing the CP applies.
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("other"))
        .expect("document loads under a different namespace");
    assert!(
        slice.services.is_empty() && slice.workloads.is_empty(),
        "resources in 'ferrum' must not leak into the 'other' namespace slice"
    );
}

#[test]
fn rejects_gateway_resources_in_mesh_document() {
    let doc = r#"
version: "1"
proxies: []
mesh:
  services: []
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("gateway resources must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("proxies") && msg.contains("FERRUM_MODE=file"),
        "error must name the offending field and steer to file mode: {msg}"
    );
}

#[test]
fn rejects_document_without_mesh_section() {
    let path = write_temp("yaml", "version: \"1\"\n");
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("a document without a mesh section must be rejected");
    assert!(err.to_string().contains("mesh"), "{err}");
}

#[test]
fn rejects_unknown_version_stamp() {
    let doc = r#"
version: "999"
mesh:
  services: []
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("an unknown version stamp must be rejected");
    assert!(err.to_string().contains("version"), "{err}");
}

#[test]
fn rejects_invalid_mesh_fields() {
    // Port 0 fails `validate_mesh_fields` — the same validation the
    // slice-apply task would run; the file source fails it eagerly so startup
    // is fail-closed.
    let doc = r#"
mesh:
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 0
          protocol: http
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("invalid mesh fields must be rejected");
    assert!(
        err.to_string().contains("validation failed"),
        "expected a mesh validation error, got: {err}"
    );
}

#[test]
fn missing_file_is_an_error() {
    let err = load_mesh_slice_from_file(
        std::path::Path::new("/nonexistent/ferrum-mesh-config.yaml"),
        request_for_namespace("ferrum"),
    )
    .expect_err("missing file must be an error");
    assert!(err.to_string().contains("not found"), "{err}");
}

#[test]
fn reload_then_load_produces_advancing_versions() {
    // The slice version is the load timestamp: two loads of the same document
    // produce slices that are `content_eq` (so the apply task no-ops) while
    // the version stamp itself advances.
    let path = write_temp("yaml", VALID_MESH_YAML);
    let first = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("first load succeeds");
    // Two `Utc::now()` stamps in the same instant would compare equal and
    // mask the assertion; force distinct timestamps.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let second = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("second load succeeds");
    assert!(
        first.content_eq(&second),
        "identical documents must build content-equal slices"
    );
    assert_ne!(
        first.version, second.version,
        "each load stamps its own version"
    );
}
