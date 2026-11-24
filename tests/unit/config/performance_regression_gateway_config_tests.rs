//! The daily `performance-regression.yml` overhead gate starts a file-mode
//! gateway from `tests/fixtures/performance_regression_gateway.yaml` and drives
//! `/health` and `/api/users` through it against `backend_server` on
//! 127.0.0.1:3001.
//!
//! That workflow runs only on its schedule and on manual dispatch, never on a
//! pull request. #7300 deleted the file, and every scheduled run failed at
//! "Start gateway" while every pull request stayed green (#7397). These tests
//! load the file on every pull request through the same production file
//! loader `FERRUM_MODE=file` uses, with the environment defaults the workflow
//! leaves unset. A schema change that stops the file from loading therefore
//! fails here, not one day later on `main`.
//!
//! `verify_required_ci.py` checks the other direction: the workflow's
//! `FERRUM_FILE_CONFIG_PATH` must name the fixture these tests load.

use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};

const PERFORMANCE_REGRESSION_GATEWAY_CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/performance_regression_gateway.yaml"
);

/// Mirrors the workflow's environment. It leaves these unset, so file mode
/// applies the `EnvConfig` defaults:
/// - `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS=30`;
/// - `FERRUM_BACKEND_ALLOW_IPS=both`, with the dangerous-range baseline
///   (`FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=true`);
/// - `FERRUM_NAMESPACE=ferrum`.
fn load_as_the_workflow_does() -> GatewayConfig {
    load_config_from_file(
        PERFORMANCE_REGRESSION_GATEWAY_CONFIG,
        30,
        &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
        "ferrum",
    )
    .expect("the performance-regression gateway config must load in file mode")
}

#[test]
fn performance_regression_gateway_config_loads_through_the_file_loader() {
    let config = load_as_the_workflow_does();
    assert!(
        !config.proxies.is_empty(),
        "the performance-regression gateway config must define proxies"
    );
}

/// `ci_overhead_bench.py` is pointed at `/api/users` and checks gateway
/// readiness at `/health`, both proxied to the benchmark backend.
#[test]
fn performance_regression_gateway_config_routes_the_benchmarked_paths_to_the_backend() {
    let config = load_as_the_workflow_does();
    for listen_path in ["/health", "/api/users"] {
        let proxy = config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some(listen_path))
            .unwrap_or_else(|| panic!("no proxy listens on `{listen_path}`"));
        assert_eq!(
            (proxy.backend_host.as_str(), proxy.backend_port),
            ("127.0.0.1", 3001),
            "`{listen_path}` must proxy to backend_server on 127.0.0.1:3001"
        );
    }
}
