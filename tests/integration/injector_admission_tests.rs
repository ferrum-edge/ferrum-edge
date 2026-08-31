//! Integration coverage for the Kubernetes sidecar-injector admission webhook
//! (`FERRUM_MODE=injector`).
//!
//! These tests exercise the public `admission_response` surface from outside
//! the crate to confirm the hostile-input boundary behavior:
//!   - a mis-scoped webhook delivering a non-Pod object is admitted without a
//!     patch (never inject into unknown kinds);
//!   - a `dryRun` request returns the identical patch (no implied side effects);
//!   - a real core `v1` Pod is still injected (happy path).

use base64::Engine as _;
use ferrum_edge::capture::{
    CaptureMode, DEFAULT_TPROXY_MARK, DEFAULT_UDP_OUTBOUND_PORT, Ip6TablesMode,
};
use ferrum_edge::modes::injector::{
    ContainerResourceConfig, InjectorConfig, SecretKeyRef, admission_response,
};
use serde_json::{Value, json};

fn injector_config(capture_mode: CaptureMode) -> InjectorConfig {
    InjectorConfig {
        listen_addr: "127.0.0.1:9443".parse().expect("listen addr"),
        namespace: "default".to_string(),
        sidecar_image: "ferrum-edge:test".to_string(),
        sidecar_env: vec![(
            "FERRUM_DP_CP_GRPC_URLS".to_string(),
            "http://cp:50051".to_string(),
        )],
        jwt_secret_ref: Some(SecretKeyRef {
            name: "ferrum-edge-secrets".to_string(),
            key: "cp-dp-grpc-jwt-secret".to_string(),
        }),
        sidecar_resources: ContainerResourceConfig {
            cpu_request: "25m".to_string(),
            memory_request: "64Mi".to_string(),
            cpu_limit: "250m".to_string(),
            memory_limit: "256Mi".to_string(),
        },
        init_resources: ContainerResourceConfig {
            cpu_request: "10m".to_string(),
            memory_request: "32Mi".to_string(),
            cpu_limit: "100m".to_string(),
            memory_limit: "128Mi".to_string(),
        },
        require_annotation: true,
        capture_mode,
        proxy_uid: Some(1337),
        exclude_outbound_ports: Vec::new(),
        exclude_inbound_ports: Vec::new(),
        include_outbound_cidrs: Vec::new(),
        exclude_outbound_cidrs: Vec::new(),
        ip6tables_mode: Ip6TablesMode::Auto,
        udp_capture_enabled: false,
        udp_outbound_port: DEFAULT_UDP_OUTBOUND_PORT,
        tproxy_mark: DEFAULT_TPROXY_MARK,
        trust_domain: "cluster.local".to_string(),
        tls_cert_path: None,
        tls_key_path: None,
        allow_plaintext: true,
        tls_handshake_timeout_seconds: 10,
        http_header_read_timeout_seconds: 10,
        admission_review_max_body_bytes: 4 * 1024 * 1024,
    }
}

fn pod_object() -> Value {
    json!({
        "metadata": {
            "labels": {"ferrum.io/mesh": "enabled"}
        },
        "spec": {
            "serviceAccountName": "api",
            "containers": [{"name": "app", "image": "app:test"}]
        }
    })
}

#[test]
fn admission_webhook_injects_core_v1_pod() {
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "pod-1",
            "namespace": "payments",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": pod_object()
        }
    });
    let response = admission_response(
        review.to_string().as_bytes(),
        &injector_config(CaptureMode::Iptables),
    )
    .expect("admission response");

    assert_eq!(
        response.pointer("/response/allowed"),
        Some(&Value::Bool(true))
    );
    assert_eq!(response.pointer("/response/uid"), Some(&json!("pod-1")));
    assert_eq!(
        response.pointer("/response/patchType"),
        Some(&Value::String("JSONPatch".to_string()))
    );
    let patch = response
        .pointer("/response/patch")
        .and_then(Value::as_str)
        .expect("encoded patch");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(patch)
        .expect("base64 patch");
    let ops: Vec<Value> = serde_json::from_slice(&decoded).expect("json patch");
    assert!(
        ops.iter().any(|op| {
            op.get("path").and_then(Value::as_str) == Some("/spec/initContainers/0")
                && op
                    .get("value")
                    .and_then(|value| value.get("name"))
                    .and_then(Value::as_str)
                    == Some("ferrum-edge")
        }),
        "native sidecar must be inserted at initContainers[0]"
    );
    let sidecar = ops.iter().find_map(|op| {
        op.get("value")
            .filter(|value| value.get("name").and_then(Value::as_str) == Some("ferrum-edge"))
    });
    let sidecar = sidecar.expect("sidecar container");
    assert_eq!(
        sidecar.get("restartPolicy"),
        Some(&Value::String("Always".to_string())),
        "injected Ferrum must be a Kubernetes native sidecar so Jobs can complete"
    );
}

#[test]
fn admission_webhook_admits_non_pod_without_injection() {
    // A mis-scoped MutatingWebhookConfiguration routes a Deployment here.
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "deploy-1",
            "namespace": "payments",
            "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
            "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
            "object": {
                "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                "spec": {"template": {"spec": {"containers": []}}}
            }
        }
    });
    let response = admission_response(
        review.to_string().as_bytes(),
        &injector_config(CaptureMode::Iptables),
    )
    .expect("admission response");

    assert_eq!(
        response.pointer("/response/allowed"),
        Some(&Value::Bool(true)),
        "non-Pod objects must be admitted, never blocked"
    );
    assert_eq!(
        response.pointer("/response/patch"),
        None,
        "non-Pod objects must never be patched"
    );
    assert_eq!(response.pointer("/response/patchType"), None);
}

#[test]
fn admission_webhook_dry_run_returns_identical_patch() {
    let make_review = |dry_run: bool| {
        json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "pod-1",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "dryRun": dry_run,
                "object": pod_object()
            }
        })
    };
    let config = injector_config(CaptureMode::Iptables);

    let live = admission_response(make_review(false).to_string().as_bytes(), &config)
        .expect("live response");
    let dry = admission_response(make_review(true).to_string().as_bytes(), &config)
        .expect("dry response");

    assert_eq!(live.pointer("/response/allowed"), Some(&Value::Bool(true)));
    assert_eq!(dry.pointer("/response/allowed"), Some(&Value::Bool(true)));
    assert_eq!(
        live.pointer("/response/patch"),
        dry.pointer("/response/patch"),
        "dryRun must not alter the computed patch"
    );
    assert!(dry.pointer("/response/patch").is_some());
}

/// Decode the JSON patch a `CaptureMode::Iptables` injection produces for
/// `pod`, with `mutate` applied to the injector config first.
fn injected_patch_ops(pod: Value, mutate: impl FnOnce(&mut InjectorConfig)) -> Vec<Value> {
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "pod-capture",
            "namespace": "payments",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": pod
        }
    });
    let mut config = injector_config(CaptureMode::Iptables);
    mutate(&mut config);
    let response =
        admission_response(review.to_string().as_bytes(), &config).expect("admission response");
    let patch = response
        .pointer("/response/patch")
        .and_then(Value::as_str)
        .expect("encoded patch");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(patch)
        .expect("base64 patch");
    serde_json::from_slice(&decoded).expect("json patch")
}

fn init_container_script(ops: &[Value]) -> String {
    ops.iter()
        .filter_map(|op| op.get("value"))
        .find(|value| value.pointer("/name").and_then(Value::as_str) == Some("ferrum-edge-init"))
        .and_then(|value| value.pointer("/args/0"))
        .and_then(Value::as_str)
        .expect("the iptables init container renders a capture script")
        .to_string()
}

fn sidecar_env_value<'a>(ops: &'a [Value], name: &str) -> Option<&'a str> {
    ops.iter()
        .filter_map(|op| op.get("value"))
        .find(|value| value.pointer("/name").and_then(Value::as_str) == Some("ferrum-edge"))
        .and_then(|value| value.pointer("/env"))
        .and_then(Value::as_array)
        .and_then(|env| {
            env.iter()
                .find(|entry| entry.pointer("/name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|entry| entry.pointer("/value"))
        .and_then(Value::as_str)
}

/// Issue #4276: the rendered init script must RETURN locally destined traffic
/// before any outbound REDIRECT, or every intra-pod `127.0.0.1` connection in a
/// multi-container pod is hairpinned into the mesh outbound proxy.
#[test]
fn injected_init_script_returns_local_traffic_before_the_outbound_redirect() {
    let ops = injected_patch_ops(pod_object(), |_| {});
    let script = init_container_script(&ops);

    let local_return = script
        .find("-I FERRUM_MESH_OUTBOUND 1 -m addrtype --dst-type LOCAL -j RETURN")
        .expect("default injection must carry the loopback/self RETURN");
    let redirect = script
        .find("-A FERRUM_MESH_OUTBOUND -p tcp -d 0.0.0.0/0 -j REDIRECT")
        .or_else(|| script.find("-A FERRUM_MESH_OUTBOUND -p tcp -j REDIRECT"))
        .expect("default injection must carry the outbound catch-all REDIRECT");
    assert!(
        local_return < redirect,
        "the RETURN must precede the REDIRECT — once REDIRECT fires the chain returns:\n{script}"
    );
}

/// Issue #4271: the sidecar must learn that `ip6tables` REDIRECT rules exist, or
/// it plans an IPv4-only capture listener and every captured IPv6 connection is
/// refused while the pod reports ready.
#[test]
fn injected_sidecar_learns_when_ipv6_capture_rules_are_installed() {
    let ipv4_only = injected_patch_ops(pod_object(), |_| {});
    assert_eq!(
        sidecar_env_value(&ipv4_only, "FERRUM_MESH_CAPTURE_IPV6_ENABLED"),
        None,
        "an IPv4-only capture scope must not claim IPv6 capture"
    );

    let dual_stack = injected_patch_ops(pod_object(), |config| {
        config.include_outbound_cidrs = vec!["0.0.0.0/0".to_string(), "fd00::/8".to_string()];
    });
    let script = init_container_script(&dual_stack);
    assert!(
        script.contains("ip6tables"),
        "an IPv6 include CIDR must render ip6tables rules:\n{script}"
    );
    assert_eq!(
        sidecar_env_value(&dual_stack, "FERRUM_MESH_CAPTURE_IPV6_ENABLED"),
        Some("true"),
        "the sidecar must be told to plan IPv6-capable capture listeners"
    );
    // The ip6tables fan-out carries the same loopback/self RETURN, and it still
    // precedes that family's REDIRECT.
    let v6_return = script
        .find(
            "ip6tables -t nat -w 5 -I FERRUM_MESH_OUTBOUND 1 -m addrtype --dst-type LOCAL -j RETURN",
        )
        .expect("the ip6tables chain must carry the loopback/self RETURN too");
    let v6_redirect = script
        .find("ip6tables -t nat -w 5 -A FERRUM_MESH_OUTBOUND -p tcp -d fd00::/8 -j REDIRECT")
        .expect("the ip6tables chain must carry the IPv6 include REDIRECT");
    assert!(
        v6_return < v6_redirect,
        "the ip6tables RETURN must precede the ip6tables REDIRECT:\n{script}"
    );
}

fn admission_denied_message(pod: Value) -> String {
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "pod-denied",
            "namespace": "payments",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": pod
        }
    });
    let response = admission_response(
        review.to_string().as_bytes(),
        &injector_config(CaptureMode::Iptables),
    )
    .expect("admission response");
    assert_eq!(
        response.pointer("/response/allowed"),
        Some(&Value::Bool(false)),
        "admission must fail closed rather than emit a captured-probe patch"
    );
    response
        .pointer("/response/status/message")
        .and_then(Value::as_str)
        .expect("denial message")
        .to_string()
}

/// Issue #4431: kubelet HTTP probe ports are inbound-excluded so a liveness
/// probe to the Pod IP is not redirected onto Ferrum's service-host routes.
#[test]
fn admission_excludes_named_and_numeric_http_probe_ports() {
    let pod = json!({
        "metadata": {
            "labels": {"ferrum.io/mesh": "enabled"}
        },
        "spec": {
            "serviceAccountName": "api",
            "containers": [{
                "name": "app",
                "image": "app:test",
                "ports": [{"containerPort": 8080, "name": "http"}],
                "livenessProbe": {
                    "httpGet": {"path": "/livez", "port": "http"}
                },
                "readinessProbe": {
                    "httpGet": {"path": "/readyz", "port": 9090}
                },
                "startupProbe": {
                    "exec": {"command": ["true"]}
                }
            }]
        }
    });
    let script = init_container_script(&injected_patch_ops(pod, |_| {}));
    assert!(
        script.contains("--dport 8080 -j RETURN"),
        "named http probe port must resolve and be excluded:\n{script}"
    );
    assert!(
        script.contains("--dport 9090 -j RETURN"),
        "numeric HTTP probe port must be excluded:\n{script}"
    );
}

#[test]
fn admission_rejects_unresolved_named_probe_port() {
    let pod = json!({
        "metadata": {
            "labels": {"ferrum.io/mesh": "enabled"}
        },
        "spec": {
            "serviceAccountName": "api",
            "containers": [{
                "name": "app",
                "image": "app:test",
                "livenessProbe": {
                    "httpGet": {"path": "/livez", "port": "metrics"}
                }
            }]
        }
    });
    let message = admission_denied_message(pod);
    assert!(
        message.contains("names port 'metrics'"),
        "denial must name the unresolved probe port: {message}"
    );
}
