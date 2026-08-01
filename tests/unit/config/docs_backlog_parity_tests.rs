//! Static parity guards for the docs backlog reconciliation (#3336).
//!
//! Pins a few high-churn canonical-index / status phrases so closed issues and
//! superseded "roadmap / not yet implemented" claims cannot quietly return in
//! the ledgers this reconciliation owns. `include_str!` only — no runtime.

const PRODUCTION_READINESS: &str = include_str!("../../../PRODUCTION_READINESS.md");
const RESPONSE_BODY_STREAMING: &str = include_str!("../../../docs/response_body_streaming.md");
const MESH_SUPPORTED_MATRIX: &str = include_str!("../../../docs/mesh_supported_matrix.md");
const SPIRE_DEPLOYMENT: &str = include_str!("../../../docs/spire_deployment.md");
const PROTOCOL_PERF_REGRESSION: &str = include_str!("../../../docs/protocol_perf_regression.md");
const ISSUE_2110_REGISTER: &str = include_str!("../../../docs/backlog/issue_2110_register.md");
const MULTICLUSTER_RUNBOOK: &str =
    include_str!("../../../docs/mesh_multicluster_federation_runbook.md");
const SCRIPTED_BACKEND_PLAN: &str =
    include_str!("../../../docs/plans/test_framework_scripted_backends.md");

#[test]
fn production_readiness_does_not_track_completed_epic_rows_as_open() {
    assert!(
        !PRODUCTION_READINESS.contains("No Helm chart for core gateway modes | Low | TRACKED"),
        "PR-013 Helm chart is shipped (charts/ferrum-gateway); disposition must not stay TRACKED"
    );
    assert!(
        !PRODUCTION_READINESS
            .contains("Log schema not applied to WsDisconnectLogEntry | Low | TRACKED"),
        "PR-007 WsDisconnect schema support is implemented; disposition must not stay TRACKED"
    );
    assert!(
        !PRODUCTION_READINESS.contains("Stress tests excluded from CI | Low | TRACKED"),
        "PR-014 scheduled scaling-regression.yml covers the excluded stress suites"
    );
    assert!(
        PRODUCTION_READINESS.contains("#2475"),
        "remote-discovery JWT audience binding (#2475) must remain recorded as implemented"
    );
    assert!(
        PRODUCTION_READINESS.contains("intentional mixed strategy"),
        "k8s status ownership must document the intentional RMW+SSA mixed strategy"
    );
}

#[test]
fn response_streaming_decision_flow_matches_retry_header_contract() {
    assert!(
        !RESPONSE_BODY_STREAMING.contains("buffer (all attempts except final)"),
        "stale retry buffering claim must not reappear in the decision flow"
    );
    assert!(
        RESPONSE_BODY_STREAMING.contains("stream on every attempt when the proxy streams"),
        "decision flow must state the header-time streaming retry contract"
    );
}

#[test]
fn mesh_supported_matrix_product_deferral_index_is_current() {
    assert!(
        !MESH_SUPPORTED_MATRIX.contains("TLS-SNI L4 routing is on the roadmap"),
        "tls[] SNI passthrough is supported; roadmap claim is stale"
    );
    assert!(
        !MESH_SUPPORTED_MATRIX.contains("issues/2013"),
        "closed #2013 must not remain in the canonical open product deferral index"
    );
    for issue in ["#3263", "#3228", "#3331", "#3334"] {
        assert!(
            MESH_SUPPORTED_MATRIX.contains(issue),
            "product deferral index must cite live tracker {issue}"
        );
    }
    assert!(
        MESH_SUPPORTED_MATRIX.contains("sniHosts"),
        "matrix must name the supported tls[] SNI surface"
    );
}

#[test]
fn spire_dashboard_checklist_references_shipped_assets() {
    assert!(
        !SPIRE_DEPLOYMENT.contains("once the Grafana dashboards land under"),
        "dashboards already ship under charts/ferrum-mesh/dashboards/"
    );
    assert!(
        SPIRE_DEPLOYMENT.contains("certificate-posture.json"),
        "checklist must name the shipped certificate-posture dashboard"
    );
}

#[test]
fn protocol_perf_regression_documents_mesh_e2e_status() {
    assert!(
        PROTOCOL_PERF_REGRESSION.contains("Mesh in-process vs E2E suites"),
        "protocol perf runbook must reconcile mesh criterion vs E2E harness scope"
    );
    assert!(
        PROTOCOL_PERF_REGRESSION.contains("mesh-hbone-e2e")
            && PROTOCOL_PERF_REGRESSION.contains("mesh-dns-e2e"),
        "runbook must name both live mesh perf harnesses"
    );
    assert!(
        PROTOCOL_PERF_REGRESSION.contains("#3332"),
        "runbook must cite the baseline-publication tracker"
    );
    assert!(
        PROTOCOL_PERF_REGRESSION.contains("frozen Trusted Cross automation")
            && PROTOCOL_PERF_REGRESSION.contains("Benches deferred (not yet implemented)"),
        "runbook must state the protected mesh README is frozen historical prose"
    );
}

#[test]
fn issue_2110_register_maps_completed_work_and_live_trackers() {
    assert!(
        ISSUE_2110_REGISTER.contains("Historical snapshot only"),
        "register must be labeled historical, not live backlog"
    );
    assert!(
        ISSUE_2110_REGISTER.contains("#2475"),
        "remote-discovery JWT audience binding must remain recorded as implemented"
    );
    assert!(
        ISSUE_2110_REGISTER.contains("#3299")
            && ISSUE_2110_REGISTER.contains("`ai_stream_router` `google_gemini` adapter")
            && ISSUE_2110_REGISTER.contains("Implemented —"),
        "google_gemini stream-router adapter must remain recorded as implemented"
    );
    assert!(
        ISSUE_2110_REGISTER.contains("intentional mixed strategy"),
        "k8s status ownership must document the intentional RMW+SSA mixed strategy"
    );
    for issue in [
        "#3228", "#3263", "#3302", "#3304", "#3331", "#3332",
    ] {
        assert!(
            ISSUE_2110_REGISTER.contains(issue),
            "register must cite live tracker {issue}"
        );
    }
    assert!(
        ISSUE_2110_REGISTER.contains("EnvoyFilter / WasmPlugin"),
        "explicit non-goals must remain documented"
    );
    assert!(
        !ISSUE_2110_REGISTER.contains("TLS-SNI L4 routing “on roadmap”"),
        "completed TLS-SNI support must not remain a roadmap deferral"
    );
    assert!(
        ISSUE_2110_REGISTER.contains("frozen")
            && ISSUE_2110_REGISTER.contains("tests/performance/mesh/README.md")
            && ISSUE_2110_REGISTER.contains("mesh-hbone-e2e")
            && ISSUE_2110_REGISTER.contains("mesh-dns-e2e"),
        "register must explain the protected mesh README stays historical while naming live suites"
    );
}

#[test]
fn multicluster_runbook_opening_is_not_the_june_local_failure_report() {
    assert!(
        !MULTICLUSTER_RUNBOOK.contains("Date: 2026-06-21"),
        "obsolete local Docker/kind failure report must not open the runbook"
    );
    assert!(
        MULTICLUSTER_RUNBOOK.contains("multicluster-federation-live.yml"),
        "validation status must cite the live two-kind workflow"
    );
    assert!(
        MULTICLUSTER_RUNBOOK.contains("#3331"),
        "poller partition residual must cite #3331"
    );
}

#[test]
fn scripted_backend_plan_is_implemented_residual_record() {
    assert!(
        SCRIPTED_BACKEND_PLAN.contains("Implemented / Residual Record"),
        "plan must be labeled as an implemented/residual record"
    );
    assert!(
        !SCRIPTED_BACKEND_PLAN.contains("What's missing: **programmable backends**"),
        "opening must not claim programmable backends are still missing"
    );
    assert!(
        SCRIPTED_BACKEND_PLAN.contains("#2032"),
        "Phase-8 continuation closer #2032 must be recorded"
    );
}
