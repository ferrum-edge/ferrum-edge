# Reproducible Hyper patch stack

Ferrum vendors Hyper **1.10.0** from the published
[`hyper-1.10.0.crate`](https://static.crates.io/crates/hyper/hyper-1.10.0.crate)
archive, not from a moving upstream branch. The crates.io index pins its SHA-256
as `eb92f162bf56536459fc83c79b974bb12837acfed43d6bc370a7916d0ae15ecc`.
The archive's `.cargo_vcs_info.json` identifies upstream revision
`79dbab620bf14b96cd5d53a60ca35d7fe2ddbaf1` and includes `dirty: true`.
The pinned archive, rather than a clean checkout of that revision, is the
source baseline; the verifier records and checks this published marker.

Apply the complete diffs in [`series`](series) order, from the extracted crate
root. Each patch is based on the output of all preceding patches:

| Patch | Baseline | Purpose |
|---|---|---|
| [001](001-upgraded-h2-connect-error-reset/README.md) | Published Hyper 1.10.0 | Reset failed upgraded HTTP/2 CONNECT streams |
| [002](002-min-data-frame-capacity/README.md) | Hyper 1.10.0 + 001 | Pending body chunk foundation, positive-capacity progress and regressions |
| [003](003-greedy-h1-read/README.md) | Hyper 1.10.0 + 001 + 002 | HTTP/1 read-ahead and upgrade error handoff |
| [004](004-h2-body-write-timeout/README.md) | Hyper 1.10.0 + 001 + 002 + 003 | HTTP/2 request-body write-stall bound |
| [005](005-h2-small-window-coalescing/README.md) | Hyper 1.10.0 + 001 + 002 + 003 + 004 | Coalesce DATA frames cut from small HTTP/2 window increments |

Patch 002 supplies `pending_data`; patches 004 and 005 build on it. Patch 002
is a complete diff from its stated baseline, replacing the former incremental
correction that required the old fixed-minimum patch and patch 004 first.
No stage reinstates the unsafe 1 KiB send-capacity threshold; patch 005's
coalescing wait is bounded, so every positive window still makes progress.

## Hosted reconstruction gate

The **Dependency Audit (cargo-deny)** job in
[CI](../../.github/workflows/ci.yml) downloads and checks the pinned archive,
then runs [the reconstruction verifier](../../.github/scripts/verify_hyper_patch_stack.py)
before Cargo touches the vendor tree. It applies all five patches with
`git apply` to a fresh extracted crate. It neither formats the result nor
copies source from `vendor/` over it.

The verifier requires the complete file sets to match for all shipped Hyper
files: `src/**`, `Cargo.toml`, `LICENSE` and `README.md`. Those are the 68 files
currently retained in `vendor/hyper-1.10.0-ferrum-patched/`. Upstream packaging
files, examples and upstream integration tests outside that retained set are
not shipped by this vendor copy. Every retained file, including untouched
source, must match both the vendor bytes exactly and the LF-normalized SHA-256
in [`VENDOR_INTEGRITY.sha256`](../../vendor/VENDOR_INTEGRITY.sha256). Missing,
extra or drifted source fails the gate. The verifier's hosted self-tests cover
order/completeness, an incremental patch with a missing foundation, archive
path/link rejection, untouched-file drift, byte differences and manifest drift.

CI retains the pinned archive, application log, patch hashes, upstream revision
and reconstructed source hashes as `hyper-patch-stack-<SHA>-<attempt>` evidence.
Artifact-only changes and verifier changes select this job through the CI
planner without depending on skipped Rust build artifacts, so syntax-only patch
parsing cannot stand in for reconstruction.
The #5912 refresh ports the complete stack to the published 1.10.0 source.
The existing CI archive/test bindings still need the automation owner's update;
the optional security lockfile producer uses the new pins. See
[the security upgrade record](../dependency-security-upgrade-5912.md).

## Lifecycle

The current progress implementation is a deliberate fork paired with patches
004 and 005. [Hyper #4212](https://github.com/hyperium/hyper/pull/4212) closed unmerged
on 2026-10-04; it is historical evidence, not a release-adoption prerequisite.
See [patch 002's retirement plan](002-min-data-frame-capacity/README.md#retirement-plan)
and [the lifecycle inventory](../vendored-patch-lifecycle.json). The receiver's
adaptive DATA-frame budget fix is separate
[h2 patch 002](../upstream-h2-patches/002-runtime-data-frame-budget/README.md),
whose [h2 #965](https://github.com/hyperium/h2/pull/965) is open as of 2026-10-04.
