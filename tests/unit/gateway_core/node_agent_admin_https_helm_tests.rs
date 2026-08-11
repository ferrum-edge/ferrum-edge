//! Static Helm/chart contract coverage for node-agent admin HTTPS (issue #3704).
//!
//! These tests prove values/templates propagate the shared `FERRUM_ADMIN_*`
//! contract (ports, Secret mounts, TLS-aware probes/scrape) without requiring
//! a local `helm` binary. Hosted CI still runs `helm template` end-to-end.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

#[test]
fn values_default_https_port_zero_preserves_http_only_installs() {
    let values = read("values.yaml");
    assert!(
        values.contains("httpsPort: 0"),
        "nodeAgent.admin.httpsPort must default to 0 so unset TLS keeps HTTP-only"
    );
    assert!(
        values.contains("tls:") && values.contains("secretName: \"\""),
        "admin TLS values must exist without inlining secret material"
    );
    assert!(
        values.contains("metricsScrape:"),
        "optional scrape annotation knobs must be first-class values"
    );
}

#[test]
fn schema_accepts_admin_tls_and_https_port() {
    let schema = read("values.schema.json");
    assert!(schema.contains("\"httpsPort\""));
    assert!(schema.contains("\"clientCaKey\""));
    assert!(schema.contains("\"crlKey\""));
    assert!(schema.contains("\"metricsScrape\""));
}

#[test]
fn daemonset_renders_managed_admin_https_and_tls_env() {
    let ds = read("templates/node-agent-daemonset.yaml");
    for needle in [
        "FERRUM_ADMIN_HTTPS_PORT",
        "FERRUM_ADMIN_TLS_CERT_PATH",
        "FERRUM_ADMIN_TLS_KEY_PATH",
        "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH",
        "FERRUM_TLS_CRL_FILE_PATH",
        "node-agent-admin-tls",
        "prometheus.io/scheme",
        "$nodeAgentProbeUsesTls",
        "$nodeAgentDefaultStartupProbe",
        "$nodeAgentDefaultLivenessProbe",
        "$nodeAgentDefaultReadyProbe",
        "$nodeAgentStartupHandler",
        "not $nodeAgentAdminClientCaKey",
        "external scrape config/sidecar",
    ] {
        assert!(
            ds.contains(needle),
            "node-agent DaemonSet template missing {needle}"
        );
    }
    assert!(
        ds.contains("toString .Values.nodeAgent.admin.port")
            && ds.contains("toString .Values.nodeAgent.admin.httpsPort")
            && !ds.contains("| default \"19090\"")
            && !ds.contains("httpsPort | default \"0\""),
        "admin port reads must preserve integer zero (no Sprig default on port/httpsPort)"
    );
    assert!(
        ds.contains("nodeAgent.admin.port and nodeAgent.admin.httpsPort both use"),
        "chart must reject node-agent HTTP/HTTPS same-port when both would bind"
    );
    assert!(
        ds.contains("nodeAgent.admin.httpsPort is nonzero but admin TLS is incomplete"),
        "chart must fail closed on HTTPS without TLS Secret config"
    );
    assert!(
        ds.contains("override/disable every enabled probe"),
        "mTLS HTTPS-only rejection must mention independent probe overrides"
    );
    assert!(
        !ds.contains("BEGIN CERTIFICATE"),
        "chart must not embed certificate material"
    );
}

#[test]
fn helpers_support_tls_admin_health_handlers() {
    let helpers = read("templates/_helpers.tpl");
    assert!(helpers.contains("ferrum-mesh.nodeAgentAdminTlsConfigured"));
    assert!(helpers.contains("--tls-no-verify"));
    assert!(
        helpers.contains("$tls := .tls | default false"),
        "adminHealthHandlers must accept an independent TLS flag"
    );
    assert!(
        helpers.contains("startupHandler"),
        "renderProbes must accept an optional independent startupHandler"
    );
}

#[test]
fn schema_and_values_expose_startup_override() {
    let schema = read("values.schema.json");
    assert!(
        schema.contains("\"startup\"") && schema.contains("Custom startup handler"),
        "workloadProbes.startup.override must be first-class in the schema"
    );
    let values = read("values.yaml");
    assert!(
        values.contains("startup:") && values.matches("override: {}").count() >= 6,
        "every first-class workload probes.startup must expose override: {{}}"
    );
    assert!(
        values.contains("simple Prometheus pod annotations")
            || values.contains("cannot present a client certificate"),
        "values must document mTLS scrape annotation limits"
    );
}

#[test]
fn ambient_rejects_only_active_https_port_collision_with_node_agent() {
    let ambient = read("templates/ambient-daemonset.yaml");
    assert!(
        ambient.contains("FERRUM_ADMIN_HTTPS_PORT=%s"),
        "ambient chart must reject shared hostNetwork HTTPS admin ports"
    );
    assert!(
        ambient.contains("$ambientAdminHttpsActive"),
        "collision guard must require ambient HTTPS to be actually active"
    );
    assert!(
        ambient.contains("$nodeAgentAdminHttpsActive"),
        "collision guard must require node-agent HTTPS to be actually active"
    );
    assert!(
        ambient.contains("FERRUM_ADMIN_TLS_CERT_PATH")
            && ambient.contains("FERRUM_ADMIN_TLS_KEY_PATH"),
        "ambient HTTPS activity must require complete admin TLS env"
    );
    assert!(
        ambient.contains("toString .Values.nodeAgent.admin.httpsPort")
            && !ambient.contains("httpsPort | default \"0\""),
        "ambient collision reads must preserve integer node-agent httpsPort=0"
    );
    assert!(
        ambient.contains(
            "ambient FERRUM_ADMIN_HTTP_PORT and nodeAgent.admin.httpsPort both use hostNetwork port"
        ) && ambient.contains(
            "ambient FERRUM_ADMIN_HTTPS_PORT and nodeAgent.admin.port both use hostNetwork port"
        ),
        "ambient chart must reject cross-protocol hostNetwork admin port collisions"
    );
}
