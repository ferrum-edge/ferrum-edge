//! GA-scope conformance contract — the prescriptive core of the matrix.
//!
//! The conformance suite is otherwise *observational*: a feature may be
//! `Deferred` and CI stays green. That is correct for the in-progress Beta /
//! Experimental mesh surface, but it means a feature we have *promised* could
//! be silently downgraded without anyone noticing. This module closes that
//! hole.
//!
//! Two layers, defense in depth:
//!
//! 1. **Per-call assertion** (in [`super::registry::register`]): registering a
//!    `Maturity::Ga` feature as anything other than `Status::Supported` panics
//!    the declaring test. This is ordering-independent and catches the common
//!    case — a regression that forces a GA feature's test down to `Deferred`.
//!
//! 2. **Contract presence gate** ([`zz_ga_scope_contract_gate`]): asserts every
//!    entry in `ga_contract.yaml` is present in the registry, `Supported`, and
//!    tagged `Ga`, and that no feature is tagged `Ga` without being declared
//!    here. This catches a *deleted* or renamed GA test (its row vanishes) and
//!    tag/contract drift.
//!
//! The presence half depends on the whole suite having run, so it is enabled
//! only when `FERRUM_CONFORMANCE_STRICT_GATE` is set (CI sets it and runs the
//! suite with `--test-threads=1`). Ordering matters: libtest sorts by *full
//! test path*, so this gate is invoked from a top-level `zz_`-named test in
//! `mod.rs` (path `conformance::zz_…`, which sorts after every submodule test
//! and after `conformance::z_emit_coverage_artifacts`) rather than from a
//! `#[test]` in this module — a `conformance::ga_scope::*` test would sort
//! *before* `conformance::istio_*` and run before those features register.
//! Locally — where the suite runs multi-threaded and this gate can finish
//! before a slower peer registers its feature — the presence half is skipped to
//! avoid false failures; the always-on per-call assertion still guards every
//! run.
//!
//! Adding a GA semantic assertion to `ga_contract.yaml` is a product promise.
//! Removing one is a deliberate scope change. A feature earns its place here once its
//! translation/semantics are stable and pinned by a conformance test; the
//! *runtime* GA bar (live mTLS/authz/routing on real pods) is gated separately
//! by the `mesh-e2e-sidecar` and `multicluster-federation` live-datapath suites.

use super::contract::load_contract;
use super::registry::{Maturity, Status, snapshot};

/// Whether the (suite-completion-dependent) presence gate is enforced.
fn strict_gate_enabled() -> bool {
    std::env::var_os("FERRUM_CONFORMANCE_STRICT_GATE").is_some()
}

/// Enforce the GA contract. Invoked from the top-level `zz_`-named test in
/// `mod.rs` so it runs after every feature has registered (see module docs).
pub(crate) fn enforce_contract_gate() {
    let contract = load_contract().expect("ga_contract.yaml must be valid");
    let contract_ga_assertions = contract.ga_semantic_assertions();
    let snap = snapshot();

    // Always safe: a feature tagged GA but not declared in ga_contract.yaml is
    // drift (someone promoted a feature without recording the promise). A GA
    // feature that has not yet run simply is not in `snap`, so this never
    // false-fails.
    for f in &snap {
        if f.maturity == Maturity::Ga {
            let declared = contract_ga_assertions.iter().any(|assertion| {
                assertion.category == f.category && assertion.feature == f.feature
            });
            assert!(
                declared,
                "feature `{}/{}` is tagged `Maturity::Ga` but is missing from \
                 tests/conformance/ga_contract.yaml — add it to the declared product contract",
                f.category, f.feature,
            );
        }
    }

    if !strict_gate_enabled() {
        // Multi-threaded local run: skip the presence half to avoid a race with
        // peers that have not registered yet. The per-call assertion in
        // `register()` still enforces GA == Supported on every run.
        return;
    }

    // Strict (CI, single-threaded, runs last): every promised feature must be
    // present, Supported, and GA-tagged. A missing row means its test was
    // deleted/renamed/filtered.
    for assertion in contract_ga_assertions {
        let cat = assertion.category.as_str();
        let feat = assertion.feature.as_str();
        let found = snap
            .iter()
            .find(|f| f.category == cat && f.feature == feat)
            .unwrap_or_else(|| {
                panic!(
                    "GA-contract feature `{cat}/{feat}` is absent from the conformance registry — \
                     its test was deleted, renamed, or filtered out. Restore the test, or amend \
                     tests/conformance/ga_contract.yaml if the removal is intentional."
                )
            });
        assert_eq!(
            found.status,
            Status::Supported,
            "GA-contract feature `{cat}/{feat}` must be Supported",
        );
        assert_eq!(
            found.maturity,
            Maturity::Ga,
            "GA-contract feature `{cat}/{feat}` must be tagged `maturity = Maturity::Ga`",
        );
    }
}
