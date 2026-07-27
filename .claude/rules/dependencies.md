# Dependency & Vendored-Crate Rules

Full policy: `docs/dependency-policy.md`. These are the load-bearing rules.

## Vendored, Patched Crates

- Ferrum carries vendored upstream crates under `vendor/**`, wired via
  `[patch.crates-io]` in `Cargo.toml`: `reqwest 0.13.3`, `h3 0.0.8` (three
  patches), `tungstenite 0.29.0`, `tokio-tungstenite 0.29.0`.
- Each patch has a retirement plan under `docs/upstream-*-patches/` and a row in
  the inventory table in `docs/dependency-policy.md`. Keep them, the
  `[patch.crates-io]` block, and `scripts/check_vendored_patch_status.sh` in sync.
- Vendoring is a last resort: prefer a dependency bump, feature flag, or
  gateway-side workaround. A new vendored patch requires a written retirement
  plan and a behavioral regression test.
- **Never edit a file under `vendor/` without regenerating the drift manifest**
  (`scripts/update_vendor_integrity.sh`) and updating the matching
  `docs/upstream-*-patches/` notes. The diff to `vendor/VENDOR_INTEGRITY.sha256`
  is the audit trail.

## CI Actions and Kubernetes Tools

- External GitHub Actions must be pinned to a full commit SHA (see
  `docs/dependency-policy.md` → "CI Actions and Kubernetes tooling").
- `docker://` action refs and local-action Dockerfile bases must use full
  SHA-256 image digests; `scratch` is the only unpinned Dockerfile base.
- kind / kubectl / Helm install only via
  `.github/actions/setup-kubernetes-tools` with repository-pinned checksums.
- The trusted-base `pr_ci_plan.py --self-test` rejects mutable or dynamic
  action refs, pipe-to-shell installers, and unverified tool downloads. The
  pull request's proposed policy is tested separately but never controls gates.

## Drift Guard

- `tests/integration/vendor_integrity_tests.rs` hashes every governed `vendor/`
  file against `vendor/VENDOR_INTEGRITY.sha256` (LF-normalized SHA-256 for
  allowlisted text paths; byte-exact for binary/unrecognized paths) and runs in
  the `protocols-data-plane` integration shard. Incidental vendor `Cargo.lock`
  files are ignored unless listed in `GOVERNED_VENDOR_LOCKFILES` (currently the
  committed dimpl standalone-regression lockfile). Drift beyond the manifest
  fails CI.
- Regenerate only via `scripts/update_vendor_integrity.sh` (or
  `UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity`),
  which shares the guard's hashing so the two cannot diverge.
- A new `tests/integration/*.rs` module must also be added to a shard in
  `.github/workflows/ci.yml`, or the shard-coverage gate fails.

## Advisory Gate

- `cargo deny check advisories bans sources` is BLOCKING on every PR
  (`dependency-audit` job in `.github/workflows/ci.yml`) and re-runs weekly in
  `.github/workflows/dependency-audit.yml`.
- Every `[advisories.ignore]` in `deny.toml` needs a rationale and an
  `[expires:YYYY-MM-DD]` token; `scripts/check_advisory_expiry.sh` fails the
  weekly run once a date passes. Do not silence an advisory without both.
- Licenses are intentionally not part of the gate yet (see `deny.toml` header).
- A CVE in a vendored crate's lineage follows the emergency procedure in
  `docs/dependency-policy.md` (re-vendor on the fixed version or retire); a plain
  `cargo update` cannot reach a `[patch.crates-io]`-pinned crate.

## Behavioral Regression Coverage (must survive retirement)

- Per-request connect timeout across shared pool keys:
  `tests/integration/connection_pool_tests.rs`.
- HTTP/3 graceful close with a buffered response is not a false 502:
  `tests/integration/http3_integration_tests.rs` +
  `tests/functional/scripted_backend_h3_tests.rs`.
- Tungstenite `auto_pong` opt-out (issue #2963): vendored `--lib auto_pong`,
  `tests/unit/gateway_core/websocket_auto_pong_tests.rs`, and functional
  H1/H2/H3 Ping transparency tests in `functional_websocket_test.rs`.
