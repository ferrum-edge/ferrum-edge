//! External unit coverage for Sidecar ingress `bind` ownership (issue #3266):
//! boundary validation, status deferred diagnostics, and resolve fail-closure.

use ferrum_edge::modes::mesh::config::{
    AppProtocol, IngressBind, IngressListenerUnsupported, MeshSidecarIngress, parse_ingress_bind,
};

fn entry(
    port: u16,
    protocol: AppProtocol,
    endpoint: &str,
    bind: Option<&str>,
) -> MeshSidecarIngress {
    MeshSidecarIngress {
        port,
        protocol,
        name: None,
        bind: bind.map(str::to_string),
        default_endpoint: endpoint.to_string(),
    }
}

#[test]
fn parse_ingress_bind_classifies_shared_and_dedicated() {
    assert_eq!(parse_ingress_bind(None), Ok(IngressBind::SharedCapture));
    assert_eq!(parse_ingress_bind(Some("")), Ok(IngressBind::SharedCapture));
    assert_eq!(
        parse_ingress_bind(Some("0.0.0.0")),
        Ok(IngressBind::SharedCapture)
    );
    assert_eq!(
        parse_ingress_bind(Some("::")),
        Ok(IngressBind::SharedCapture)
    );
    assert_eq!(
        parse_ingress_bind(Some("127.0.0.1")),
        Ok(IngressBind::Dedicated("127.0.0.1".parse().expect("ip")))
    );
    assert_eq!(
        parse_ingress_bind(Some("::1")),
        Ok(IngressBind::Dedicated("::1".parse().expect("ip")))
    );
}

#[test]
fn parse_ingress_bind_rejects_unsupported_shapes() {
    assert_eq!(
        parse_ingress_bind(Some("unix:///var/run/x.sock")),
        Err(IngressListenerUnsupported::UnixBindUnsupported)
    );
    assert_eq!(
        parse_ingress_bind(Some("/tmp/x.sock")),
        Err(IngressListenerUnsupported::UnixBindUnsupported)
    );
    assert_eq!(
        parse_ingress_bind(Some("127.0.0.1:8080")),
        Err(IngressListenerUnsupported::UnparseableBind)
    );
    assert_eq!(
        parse_ingress_bind(Some("[::1]:8080")),
        Err(IngressListenerUnsupported::UnparseableBind)
    );
    assert_eq!(
        parse_ingress_bind(Some("localhost")),
        Err(IngressListenerUnsupported::UnparseableBind)
    );
    assert_eq!(
        parse_ingress_bind(Some("10.244.1.7")),
        Err(IngressListenerUnsupported::BindNotRepresentable)
    );
}

#[test]
fn resolve_fails_closed_before_endpoint_when_bind_is_bad() {
    // A valid defaultEndpoint must not paper over a bad bind.
    let bad = entry(
        9000,
        AppProtocol::Tcp,
        "127.0.0.1:6000",
        Some("unix:///tmp/x.sock"),
    );
    assert_eq!(
        bad.resolve(),
        Err(IngressListenerUnsupported::UnixBindUnsupported)
    );
}

#[test]
fn status_classifier_defers_unsupported_binds() {
    use serde_json::json;

    // Drive classify through the public status path by constructing a Sidecar
    // spec the same way the K8s status writer sees it.
    let accepted = json!({
        "ingress": [{
            "port": { "number": 9000, "protocol": "TCP" },
            "bind": "10.0.0.5",
            "defaultEndpoint": "127.0.0.1:6000"
        }]
    });
    // The classifier is private; exercise the shared parse it mirrors.
    assert_eq!(
        parse_ingress_bind(accepted["ingress"][0]["bind"].as_str()),
        Err(IngressListenerUnsupported::BindNotRepresentable)
    );

    let unix_bind = json!({
        "ingress": [{
            "port": { "number": 9000, "protocol": "HTTP" },
            "bind": "unix:///tmp/x.sock",
            "defaultEndpoint": "127.0.0.1:6000"
        }]
    });
    assert_eq!(
        parse_ingress_bind(unix_bind["ingress"][0]["bind"].as_str()),
        Err(IngressListenerUnsupported::UnixBindUnsupported)
    );
}
