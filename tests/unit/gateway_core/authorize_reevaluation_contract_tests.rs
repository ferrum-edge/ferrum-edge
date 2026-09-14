//! Which authorize plugins the HBONE admission fence may re-run for a LIVE
//! tunnel (issue #5042 step 1).
//!
//! A sweep is not a new request. Re-running an authorize hook that consumes a
//! budget, takes a permit, mutates admission state, dispatches a mirror,
//! accumulates a score, or makes an external call would — on a routine config
//! apply — spend a real client's quota and then revoke healthy,
//! policy-compliant tunnels: a worse outcome than the stale admission the fence
//! exists to close. `Plugin::reevaluates_live_admission` is therefore an
//! explicit, default-`false` opt-in, and this table forces every NEW authorize
//! plugin to be classified deliberately rather than inheriting whichever
//! default happens to be convenient.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Trait-impl marker. The trait's own default body lives in
/// `src/plugins/mod.rs`, which is excluded from the scan below.
const AUTHORIZE_IMPL: &str =
    "    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {";

/// The opt-in, exactly as an implementation must spell it.
const OPT_IN: &str = "    fn reevaluates_live_admission(&self) -> bool {\n        true\n    }";

/// Every built-in `authorize` implementation, keyed by its path under
/// `src/plugins/`, and whether it is declared safe for the fence to re-run.
///
/// `true` requires the hook to be a pure function of the request context and
/// the plugin's own immutable configuration:
///
/// * `access_control` — reads client IP, mapped Consumer, and authenticated
///   identity against immutable allow/deny sets.
/// * `mesh/authz` — local ALLOW/DENY/AUDIT evaluation against the published
///   slice; its one side-effecting arm (`action: CUSTOM` external delegation)
///   is skipped on a re-evaluation.
///
/// `false` is the fence-safe default and is REQUIRED for every hook below:
///
/// * `opa` — issues a `POST` to the decision endpoint per invocation.
/// * `rate_limiting` — consumes a token from the caller's budget.
/// * `request_mirror` — takes an in-flight permit and a body-budget lease and
///   bumps drop metrics.
/// * `waf` — initializes scan metadata, spends the cheap-scan budget, and
///   accumulates a score.
const EXPECTED_CLASSIFICATION: &[(&str, bool)] = &[
    ("access_control.rs", true),
    ("mesh/authz.rs", true),
    ("opa.rs", false),
    ("rate_limiting.rs", false),
    ("request_mirror.rs", false),
    ("waf/mod.rs", false),
];

fn read_source(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Built-in plugin sources that implement the `authorize` hook, as paths
/// relative to `src/plugins/`, paired with their contents.
fn authorize_plugin_sources() -> Vec<(String, String)> {
    let plugins_dir = repo_root().join("src/plugins");
    let mut files = Vec::new();
    collect_rust_sources(&plugins_dir, &mut files);
    files.sort();
    let mut sources = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&plugins_dir)
            .expect("path under src/plugins")
            .to_string_lossy()
            .replace('\\', "/");
        // The trait definition and its default body live here.
        if relative == "mod.rs" {
            continue;
        }
        let source = read_source(&path);
        if source.contains(AUTHORIZE_IMPL) {
            sources.push((relative, source));
        }
    }
    sources
}

#[test]
fn every_builtin_authorize_plugin_is_classified_for_live_readmission() {
    let sources = authorize_plugin_sources();
    let found: Vec<&str> = sources.iter().map(|(path, _)| path.as_str()).collect();
    let expected: Vec<&str> = EXPECTED_CLASSIFICATION.iter().map(|(p, _)| *p).collect();
    if found != expected {
        panic!(
            "built-in authorize plugins changed: found {found:?}, expected {expected:?}. \
             Classify every new authorize plugin in EXPECTED_CLASSIFICATION — the default is \
             `false` unless the hook is provably free of side effects and external I/O, \
             because the HBONE admission fence re-runs opted-in hooks against live tunnels"
        );
    }

    for ((path, source), (_, expected_opt_in)) in sources.iter().zip(EXPECTED_CLASSIFICATION) {
        let declares_opt_in = source.contains(OPT_IN);
        if declares_opt_in != *expected_opt_in {
            panic!(
                "src/plugins/{path}: `reevaluates_live_admission` must be \
                 {expected_opt_in}; a sweep re-runs only opted-in authorize hooks \
                 against already-admitted, still-live tunnels"
            );
        }
    }
}

#[test]
fn the_fence_sweep_filters_the_authorize_chain_by_the_opt_in() {
    let src = include_str!("../../../src/proxy/hbone_admission_fence.rs");
    assert!(
        src.contains(".filter(|plugin| plugin.reevaluates_live_admission())"),
        "the sweep must re-run only the authorize plugins that opted in"
    );
}

/// The authorize chain is protocol-scoped and the protocol is peer-selectable:
/// an HBONE CONNECT carrying `content-type: application/grpc` classifies as
/// gRPC, and a gRPC-Web request resolves an entirely separate view. A sweep that
/// hardcoded `ProxyProtocol::Http` would judge a chain the CONNECT was never
/// admitted against — in either direction.
#[test]
fn the_fence_sweep_resolves_the_admitting_plugin_view() {
    let src = include_str!("../../../src/proxy/hbone_admission_fence.rs");
    assert!(
        src.contains("snapshot.request_protocol"),
        "the sweep must resolve the protocol the admission recorded"
    );
    assert!(
        src.contains("grpc_web_request_view(&proxy.namespace, &proxy.id)"),
        "the sweep must honor the gRPC-Web view selector"
    );
    assert!(
        !src.contains("request_view(&proxy.namespace, &proxy.id, ProxyProtocol::Http)"),
        "the sweep must not hardcode the plain-HTTP plugin view"
    );
}
