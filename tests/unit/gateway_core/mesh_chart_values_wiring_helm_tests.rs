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

/// The ambient container ports must follow the listen addresses the proxy
/// binds (issue #7297). The listeners are configured only through
/// `ambient.env`, so separate port values would be decorative and could
/// disagree with the real listeners (NodeWaypoint discovery reads
/// `FERRUM_MESH_HBONE_LISTEN_ADDR`, then the named `hbone` port).
#[test]
fn ambient_container_ports_follow_the_listen_addresses() {
    let values = read_chart("values.yaml");
    let schema = read_chart("values.schema.json");
    for key in ["inboundPort", "outboundPort", "hbonePort"] {
        assert!(
            !values.contains(&format!("  {key}:")),
            "values.yaml must not declare ambient.{key}; the port comes from ambient.env"
        );
        assert!(
            !schema.contains(&format!("\"{key}\"")),
            "values.schema.json must not admit ambient.{key}"
        );
    }

    let template = read_chart("templates/ambient-daemonset.yaml");
    assert!(
        !template.contains(".Values.ambient.outboundPort")
            && !template.contains(".Values.ambient.inboundPort")
            && !template.contains(".Values.ambient.hbonePort"),
        "the ambient DaemonSet must not read the removed port values"
    );
    // Defaults must match the binary's DEFAULT_*_LISTEN_ADDR constants.
    for listener in [
        "(list \"outbound\" \"FERRUM_MESH_OUTBOUND_LISTEN_ADDR\" \"127.0.0.1:15001\")",
        "(list \"inbound\" \"FERRUM_MESH_INBOUND_LISTEN_ADDR\" \"0.0.0.0:15006\")",
        "(list \"hbone\" \"FERRUM_MESH_HBONE_LISTEN_ADDR\" \"0.0.0.0:15008\")",
    ] {
        assert!(
            template.contains(listener),
            "the ambient DaemonSet must derive a container port from {listener}"
        );
    }
    assert!(
        template.contains("include \"ferrum-mesh.ambientListenPort\""),
        "container ports must come from the shared ambientListenPort helper"
    );

    let mesh_mode = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/modes/mesh/mod.rs"),
    )
    .expect("read src/modes/mesh/mod.rs");
    for constant in [
        "const DEFAULT_INBOUND_LISTEN_ADDR: &str = \"0.0.0.0:15006\";",
        "const DEFAULT_OUTBOUND_LISTEN_ADDR: &str = \"127.0.0.1:15001\";",
        "const DEFAULT_HBONE_LISTEN_ADDR: &str = \"0.0.0.0:15008\";",
    ] {
        assert!(
            mesh_mode.contains(constant),
            "chart ambient listener defaults drifted from the binary: {constant}"
        );
    }

    let helpers = read_chart("templates/_helpers.tpl");
    let start = helpers
        .find("{{- define \"ferrum-mesh.ambientListenPort\" -}}")
        .expect("ferrum-mesh.ambientListenPort helper must exist");
    let helper = &helpers[start..];
    assert!(
        helper.contains("index .env .name | default .default")
            && helper.contains("{{- if ne ($port | int) 0 -}}"),
        "an ambient.env address must win over the default, and port 0 must omit the port"
    );
}

/// The CA Deployment runs `FERRUM_MODE=cp` from `ca.env`, which
/// `EnvConfig::validate_cp_dp_grpc_transport_security` refuses at boot on a
/// non-loopback plaintext CP gRPC bind (issue #7298). The chart must fail the
/// render instead, accepting the same three escapes the runtime accepts.
#[test]
fn ca_plaintext_cp_grpc_bind_fails_the_render() {
    let validation = read_chart("templates/validation.yaml");
    let ca_block = &validation[validation
        .find("{{- if .Values.ca.enabled -}}")
        .expect("validation.yaml must validate the CA component")..];
    let ca_block = &ca_block[..ca_block.find("{{- end -}}").expect("closed CA block")];
    assert!(
        ca_block.contains(
            "{{- include \"ferrum-mesh.validateCpGrpcTransport\" (dict \"label\" \"ca.env\" \"env\" .Values.ca.env) -}}"
        ),
        "the CA component must run the CP gRPC transport guard over ca.env"
    );

    let helpers = read_chart("templates/_helpers.tpl");
    let start = helpers
        .find("{{- define \"ferrum-mesh.validateCpGrpcTransport\" -}}")
        .expect("ferrum-mesh.validateCpGrpcTransport helper must exist");
    let helper = &helpers[start..];
    let helper = &helper[..helper
        .find("{{- end -}}\n{{- end -}}")
        .expect("closed helper")];
    for needle in [
        "\"FERRUM_CP_GRPC_LISTEN_ADDR\" | default \"0.0.0.0:50051\"",
        "\"FERRUM_CP_GRPC_TLS_CERT_PATH\"",
        "\"FERRUM_CP_GRPC_TLS_KEY_PATH\"",
        "\"FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT\"",
        "(list \"true\" \"1\" \"yes\")",
        "include \"ferrum-mesh.isLoopbackBind\" $host",
        "(ne ($port | int) 0)",
    ] {
        assert!(
            helper.contains(needle),
            "validateCpGrpcTransport must mirror the runtime check: missing {needle}"
        );
    }

    let runtime = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/config/env_config.rs"),
    )
    .expect("read src/config/env_config.rs");
    assert!(
        runtime.contains("fn validate_cp_dp_grpc_transport_security"),
        "the chart guard mirrors EnvConfig::validate_cp_dp_grpc_transport_security"
    );

    let dev = read_chart("examples/development-values.yaml");
    let ca = &dev[dev
        .find("\nca:\n")
        .expect("development example has a ca block")..];
    assert!(
        ca.contains("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT: \"true\""),
        "the development example must opt the CA into plaintext CP gRPC so \
         `-f development-values.yaml --set ca.enabled=true` still renders"
    );
}
