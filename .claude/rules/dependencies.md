# Dependency & Vendored-Crate Rules

Full policy: `docs/dependency-policy.md`. These are the load-bearing rules.

## Vendored, Patched Crates

- Ferrum carries vendored upstream crates under `vendor/**`, wired via
  `[patch.crates-io]` in `Cargo.toml`: `reqwest 0.13.3`, `h3 0.0.8` (three
  patches), `h3-quinn 0.0.10`, `tungstenite 0.29.0`, `tokio-tungstenite 0.29.0`,
  and `dimpl 0.6.1`.
- Each patch has a retirement plan under `docs/upstream-*-patches/` and a row in
  the inventory table in `docs/dependency-policy.md` plus a matching entry in
  `docs/vendored-patch-lifecycle.json`. Keep them, the
  `[patch.crates-io]` block, and `scripts/check_vendored_patch_lifecycle.py` in sync.
  The parity gate lives in the `dependency-audit` job, which must stay behind
  `mode == 'full'`, so `pr_ci_plan.py` keeps `docs/dependency-policy.md`,
  `docs/vendored-patch-lifecycle.json`, and `docs/upstream-*-patches/` off the
  lightweight docs path. A dated deliberate-fork reaffirmation belongs to an
  unfiled fork only; CI rejects one on a `filed` patch.
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
- A required live gate must decide its own relevance from a pinned trusted-base
  copy of `live_suite_path_filter.py`, never from the pull request's checkout.
  `verify_cross_build_policy.py` freezes that block byte-for-byte
  (`LIVE_SUITE_RELEVANCE_JOB_TEMPLATE`) for `mesh-e2e-sidecar-live.yml` and
  `multicluster-federation-live.yml`, together with the live job's
  `needs`/`if` binding. See `docs/ci_cd.md` → "Trusted-base relevance for
  required live gates".
- The fuzz/property lane is admitted only as two byte-frozen shapes:
  `CI_FUZZ_SMOKE_JOB` (the whole `fuzz-smoke` job in `ci.yml`) and
  `FUZZ_WORKFLOW` (the whole of `.github/workflows/fuzz.yml`). Either may be
  absent before initial adoption; once present on the trusted base, pull
  requests may neither remove nor alter it. Adoption additionally admits exactly
  three byte-exact, anchored lines wiring `fuzz-smoke` into the required `test`
  aggregate (`CI_FUZZ_SMOKE_AGGREGATE_INSERTIONS`: the `needs` entry, the
  `add_row "Fuzz Smoke"` row, and the `require_success "Fuzz Smoke"` assertion,
  each immediately after its `lint` counterpart); the rest of the aggregate is
  still compared byte for byte, and the wiring cannot be removed once adopted. A
  committed `.cargo/config[.toml]` below the repository root is rejected
  outright.
- `release.yml` is admitted in exactly two shapes
  (`RELEASE_IMAGE_FAMILY_GENERATIONS`): the current two image families, or those
  plus the complete frozen `-ebpf-tools` contract (`docker-ebpf-tools-manifest`
  job, tools build/export/upload steps in `docker-ebpf`, sole ownership of the
  `docker-ebpf-tools-digest-` wildcard, extended `create-release`
  `needs`/rationale-comment/notes,
  and three-family resolve/compare/SBOM/provenance/sign/verify coverage in
  `attest-release-images`). The credentialed eBPF producer and tools manifest
  have closed job-field sets and complete `steps:` contracts, so extra execution
  controls or context-rewrite steps are rejected. A revision is held to the
  complete contract of the shape it claims; the trusted base decides the
  transition. While the base is
  two-family a PR may leave the workflow byte-identical or adopt the whole
  three-family shape, and once the base is three-family a revert is refused. See
  `docs/ci_cd.md` → "Admitted release image-family adoption".
- `fips-build.yml` carries ONE temporary admitted generation transition for
  issue #3888 / PR #3889: the exact retired file text moving to the exact
  adopted one, each pinned by whole-file SHA-256
  (`FIPS_BUILD_RETIRED_GENERATION_SHA256`,
  `FIPS_BUILD_ADOPTED_GENERATION_SHA256`). It is exact on both ends, bound to
  the path, one-way, and withholds exactly one surface-equality verdict. Delete
  it once #3889 is on `main`. See `docs/ci_cd.md` and
  `docs/dependency-policy.md` → "Admitted `fips-build.yml` generation
  transition".

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
- Tungstenite/tokio-tungstenite fragment accounting + incomplete-message bounds
  (GHSA-qq94-2gv2-phh6): vendored `--lib fragment` / `--lib incomplete_message`
  and `tests/unit/gateway_core/websocket_fragment_metering_tests.rs`.
- h3-quinn `stop_sending` during an in-flight read (issue #3283): the vendored
  shape contract in `tests/unit/gateway_core/http3_server_dispatch_tests.rs`
  (`h3_quinn_vendored_recv_stream_can_stop_sending_during_an_in_flight_read`)
  plus the two upload-pump graceful-halt contracts in the same file. Both H3
  request-upload pumps rely on it to emit `STOP_SENDING(H3_NO_ERROR)` after
  cancelling a frontend receive mid-poll; without the patch that call is a
  process abort and skipping it downgrades the wire signal to `STOP_SENDING(0)`.
- h3 / h3-quinn per-stream `STOP_SENDING` watch (issue #3775): the vendored
  shape contract in `tests/unit/gateway_core/http3_server_dispatch_tests.rs`
  (`h3_quinn_vendored_send_stream_stopped_is_shared_and_static` and
  `h3_plain_header_wait_races_per_stream_stop_sending_not_only_connection_close`)
  plus the live same-connection cancellation tests in
  `tests/functional/functional_destination_active_requests_h3_test.rs`. Without
  the watch, destination `http2MaxRequests` stays held until a slow backend
  answers after a client cancels one multiplexed stream.
