//! Static parity guards for the docs backlog reconciliation (#3336).
//!
//! Pins a few high-churn canonical-index / status phrases so closed issues and
//! superseded "roadmap / not yet implemented" claims cannot quietly return in
//! the ledgers this reconciliation owns. `include_str!` only — no runtime.

const RESPONSE_BODY_STREAMING: &str = include_str!("../../../docs/response_body_streaming.md");
const MESH_SUPPORTED_MATRIX: &str = include_str!("../../../docs/mesh_supported_matrix.md");
const NODE_AGENT: &str = include_str!("../../../docs/node_agent.md");
const SPIRE_DEPLOYMENT: &str = include_str!("../../../docs/spire_deployment.md");
const PROTOCOL_PERF_REGRESSION: &str = include_str!("../../../docs/protocol_perf_regression.md");
const MULTICLUSTER_RUNBOOK: &str =
    include_str!("../../../docs/mesh_multicluster_federation_runbook.md");
const SCRIPTED_BACKEND_PLAN: &str =
    include_str!("../../../docs/plans/test_framework_scripted_backends.md");
const PLUGINS_DOC: &str = include_str!("../../../docs/plugins.md");
const FEATURES: &str = include_str!("../../../FEATURES.md");
const RATE_LIMITING_SRC: &str = include_str!("../../../src/plugins/rate_limiting.rs");

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
    assert!(
        !MESH_SUPPORTED_MATRIX.contains("issues/2038"),
        "closed #2038 must not remain in the canonical open product deferral index"
    );
    assert!(
        !MESH_SUPPORTED_MATRIX.contains("remains part of #2038"),
        "closed #2038 must not be cited as pending enrolled-destination work"
    );
    for issue in ["#3228", "#3331", "#3334"] {
        assert!(
            MESH_SUPPORTED_MATRIX.contains(issue),
            "product deferral index must cite live tracker {issue}"
        );
    }
    assert!(
        !MESH_SUPPORTED_MATRIX.contains("issues/3621"),
        "closed #3621 must not remain in the canonical open product deferral index"
    );
    assert!(
        MESH_SUPPORTED_MATRIX.contains(
            "Ambient UDP capture producer + privileged live source-capture **and enrolled-destination** e2e (#2013 / #2038 / #3621"
        ),
        "completed #3621 must stay recorded in the completed historical rows"
    );
    assert!(
        MESH_SUPPORTED_MATRIX
            .contains("functional_mesh_live_source_capture_udp_manager_hbone_round_trip"),
        "completed enrolled-destination coverage must name the live source-capture gate"
    );
    assert!(
        MESH_SUPPORTED_MATRIX.contains("node-waypoint-ebpf-live")
            && MESH_SUPPORTED_MATRIX.contains("enrolled-pod `tc_inbound` guard"),
        "completed #3621 coverage must map the complementary live eBPF admit proof"
    );
    // #3263 shipped: external UDP ServiceEntry ports now materialize a
    // datagram-over-mesh destination allowlist on the EgressGateway. It must be
    // recorded as completed, never re-listed as an open deferral row.
    assert!(
        !MESH_SUPPORTED_MATRIX.contains("issues/3263"),
        "closed #3263 must not remain in the canonical open product deferral index"
    );
    assert!(
        MESH_SUPPORTED_MATRIX.contains("EgressGateway UDP `ServiceEntry` materialization (#3263"),
        "completed #3263 must stay recorded in the completed historical rows"
    );
    assert!(
        MESH_SUPPORTED_MATRIX.contains("sniHosts"),
        "matrix must name the supported tls[] SNI surface"
    );
}

#[test]
fn node_agent_udp_live_coverage_cites_closed_trackers_and_enrolled_destination_gate() {
    assert!(
        !NODE_AGENT.contains("remains part of #2038"),
        "closed #2038 must not be cited as pending live UDP verification"
    );
    assert!(
        !NODE_AGENT.contains("not yet live-gated"),
        "enrolled-destination UDP round trip must not remain a live residual"
    );
    assert!(
        NODE_AGENT.contains("functional_mesh_live_source_capture_udp_manager_hbone_round_trip"),
        "node_agent must name the live source-capture gate that closed #2013/#2038/#3621"
    );
    assert!(
        NODE_AGENT.contains("node-waypoint-ebpf-live")
            && NODE_AGENT.contains("enrolled-pod `tc_inbound` classifier"),
        "node_agent must distinguish the complementary eBPF admit gate from the netns fixture"
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

#[test]
fn plugins_doc_documents_credential_storage_at_rest() {
    assert!(
        PLUGINS_DOC.contains("Credential storage at rest"),
        "plugins doc must keep the credential-storage-at-rest section (#4545)"
    );
    assert!(
        PLUGINS_DOC.contains("stored recoverable"),
        "plugins doc must state that keyauth/jwt/hmac_auth secrets are stored recoverable"
    );
}

#[test]
fn features_plugin_cache_bullet_does_not_claim_configurable_rate_limit_entries() {
    assert!(
        !FEATURES.contains("and rate limiting plugins all have configurable"),
        "FEATURES.md must not claim the rate-limiting plugins take a configurable max_entries; \
         RATE_LIMITING_CONFIG_KEYS is a closed key set and rejects it as unknown"
    );
    assert!(
        FEATURES.contains("hardcoded entry ceilings"),
        "FEATURES.md must state that the rate-limiting family uses hardcoded entry ceilings, \
         matching docs/cache_management.md"
    );
}

#[test]
fn features_secret_timeout_envelope_covers_file_backends() {
    assert!(
        !FEATURES.contains("File-based secrets have no timeout"),
        "FEATURES.md must not claim _FILE secrets are untimed; SecretBackend::resolve_many wraps \
         every backend, including FileBackend, in the same timeout"
    );
    assert!(
        FEATURES.contains("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS"),
        "FEATURES.md must name the per-fetch secret timeout knob"
    );
}

#[test]
fn features_ai_federation_records_the_opt_in_streaming_block() {
    assert!(
        !FEATURES.contains("provider response streaming are not supported"),
        "FEATURES.md must not claim AI Federation cannot stream provider responses; the plugin \
         has an opt-in `streaming` root config block"
    );
    assert!(
        FEATURES.contains("The opt-in `streaming` block (disabled by default)"),
        "FEATURES.md must describe the AI Federation opt-in streaming block and its default"
    );
}

#[test]
fn features_cli_section_counts_every_shipped_subcommand() {
    assert!(
        !FEATURES.contains("Five subcommands"),
        "FEATURES.md must not undercount the CLI; src/cli.rs Command has six variants"
    );
    assert!(
        FEATURES.contains("Six subcommands"),
        "FEATURES.md CLI section must say six subcommands"
    );
    assert!(
        FEATURES.contains("ambient-udp-preflight"),
        "FEATURES.md CLI section must list the ambient-udp-preflight subcommand"
    );
}

#[test]
fn rate_limiting_plugin_cap_is_configurable_only_as_max_state_entries() {
    assert!(
        !RATE_LIMITING_SRC.contains("\"max_entries\""),
        "if rate_limiting ever gains a real `max_entries` config key, FEATURES.md's plugin-cache \
         bullet and docs/cache_management.md's rate-limiting paragraph must be updated together"
    );
    assert!(
        RATE_LIMITING_SRC.contains("\"max_state_entries\""),
        "rate_limiting's local key cap is the `max_state_entries` config key"
    );
    assert!(
        FEATURES.contains("`rate_limiting` exposes its 100,000-key ceiling as `max_state_entries`"),
        "FEATURES.md's plugin-cache bullet must name the one configurable rate-limit cap"
    );
}
