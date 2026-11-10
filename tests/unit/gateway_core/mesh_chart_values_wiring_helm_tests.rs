//! Static ferrum-mesh chart contracts for values that must reach the rendered
//! workload exactly once (issues #7297 and #7299), without requiring a local
//! `helm` binary.

use std::path::PathBuf;

fn read_chart(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("charts/ferrum-mesh")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read charts/ferrum-mesh/{rel}: {e}"))
}

/// `controlPlane.grpcPort` must move the listener, not only the declared
/// container and Service ports, or the Service targets a port nothing serves.
#[test]
fn control_plane_grpc_port_renders_the_listen_address() {
    let template = read_chart("templates/control-plane-deployment.yaml");
    assert!(
        template.contains("containerPort: {{ .Values.controlPlane.grpcPort }}")
            && template.contains("port: {{ .Values.controlPlane.grpcPort }}"),
        "the container port and the Service port must come from controlPlane.grpcPort"
    );
    assert!(
        template.contains(
            "{{- if not (hasKey .Values.controlPlane.env \"FERRUM_CP_GRPC_LISTEN_ADDR\") }}"
        ) && template.contains("- name: FERRUM_CP_GRPC_LISTEN_ADDR")
            && template.contains(
                "value: {{ printf \"0.0.0.0:%v\" .Values.controlPlane.grpcPort | quote }}"
            ),
        "the chart must render FERRUM_CP_GRPC_LISTEN_ADDR from controlPlane.grpcPort \
         unless controlPlane.env sets it"
    );
}

/// `-ebpf-tools` is a strict superset of `-ebpf`; appending `-ebpf` to it names
/// a tag the release pipeline never publishes. Every capture consumer must use
/// the one shared selector.
#[test]
fn ebpf_image_tag_selection_never_double_suffixes() {
    let helpers = read_chart("templates/_helpers.tpl");
    let start = helpers
        .find("{{- define \"ferrum-mesh.ebpfImageTag\" -}}")
        .expect("ferrum-mesh.ebpfImageTag helper must exist");
    let helper = &helpers[start..];
    let helper = &helper[..helper
        .find("{{- end -}}\n{{- end -}}")
        .expect("ebpfImageTag helper must be closed")];
    assert!(
        helper.contains("(hasSuffix \"-ebpf\" .) (hasSuffix \"-ebpf-tools\" .)"),
        "the helper must leave both -ebpf and -ebpf-tools tags unchanged"
    );

    for (rel, var) in [
        ("templates/node-agent-daemonset.yaml", "$nodeAgentImageTag"),
        ("templates/cni-uninstall-hook.yaml", "$imageTag"),
        ("templates/ambient-daemonset.yaml", "$ambientImageTag"),
    ] {
        let template = read_chart(rel);
        assert!(
            template.contains(&format!("include \"ferrum-mesh.ebpfImageTag\" {var}")),
            "{rel} must select the eBPF tag through ferrum-mesh.ebpfImageTag"
        );
        assert!(
            !template.contains(&format!("printf \"%s-ebpf\" {var}")),
            "{rel} must not append -ebpf itself"
        );
    }
}

/// Env names the chart renders from first-class values must be rejected in the
/// matching workload env map, or the container gets the name twice.
#[test]
fn chart_rendered_env_names_are_reserved() {
    let validation = read_chart("templates/validation.yaml");
    let injector = validation
        .lines()
        .find(|line| line.contains("\"label\" \"injector.env\""))
        .expect("validation.yaml must reserve injector.env names");
    for name in [
        "FERRUM_INJECTOR_LISTEN_ADDR",
        "FERRUM_INJECTOR_REQUIRE_ANNOTATION",
        "FERRUM_INJECTOR_TLS_CERT_PATH",
        "FERRUM_INJECTOR_TLS_KEY_PATH",
    ] {
        assert!(
            injector.contains(&format!("\"{name}\"")),
            "injector.env.{name} must be reserved: the injector Deployment renders it"
        );
    }
    let ambient = validation
        .lines()
        .find(|line| line.contains("\"label\" \"ambient.env\""))
        .expect("validation.yaml must reserve ambient.env names");
    assert!(
        ambient.contains("\"FERRUM_MESH_CAPTURE_MODE\""),
        "ambient.env.FERRUM_MESH_CAPTURE_MODE must be reserved: it renders from ambient.captureMode"
    );

    let helpers = read_chart("templates/_helpers.tpl");
    assert!(
        helpers.contains(
            "{{- if and $tlsClientCaKey (hasKey $env \"FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH\") -}}"
        ),
        "admin.tls.clientCaKey and an env client CA path must not both render"
    );
    assert!(
        helpers.contains("{{- if and $tlsCrlKey (hasKey $env \"FERRUM_TLS_CRL_FILE_PATH\") -}}"),
        "admin.tls.crlKey and an env CRL path must not both render"
    );
}

/// Templates render into the release namespace; a top-level `namespace` value
/// would be a no-op that `--set namespace=...` silently accepts.
#[test]
fn chart_has_no_unused_namespace_value() {
    let values = read_chart("values.yaml");
    assert!(
        !values.lines().any(|line| line.starts_with("namespace:")),
        "values.yaml must not declare a top-level namespace value no template reads"
    );
    let schema = read_chart("values.schema.json");
    assert!(
        !schema.contains("release namespace hint"),
        "values.schema.json must not admit a top-level namespace value"
    );
}
