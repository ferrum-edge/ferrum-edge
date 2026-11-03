---
paths:
  - "Cargo.toml"
  - "Cargo.lock"
  - "deny.toml"
  - "vendor/**"
  - "ebpf/Cargo.*"
  - "fuzz/**"
  - ".github/**"
  - "scripts/**"
  - "docs/dependency-policy.md"
  - "docs/vendored-patch-lifecycle.json"
  - "docs/upstream-*-patches/**"
  - "docs/ci_cd.md"
  - "tests/integration/vendor_integrity_tests.rs"
  - "tests/performance/multi_protocol/Cargo.*"
---

# Dependency & Vendored-Crate Rules

Full policy: `docs/dependency-policy.md`. These are the load-bearing rules.

## Vendored, Patched Crates

- Ferrum carries vendored upstream crates under `vendor/**`, wired via
  `[patch.crates-io]` in `Cargo.toml`: `sqlx-core 0.8.6`, `reqwest 0.13.4`,
  `h3 0.0.8`, `h3-quinn 0.0.10`, `tungstenite 0.29.0`,
  `tokio-tungstenite 0.29.0`, `dimpl 0.6.1`, `hyper-util 0.1.21`
  (patches 001–002), `hyper 1.10.0` (patches 001–008), and `h2 0.4.20` (coalescing,
  assigned-send-capacity, and reset-origin patches).
- Each patch has a retirement plan under `docs/upstream-*-patches/` and a row in
  the inventory table in `docs/dependency-policy.md` plus a matching entry in
  `docs/vendored-patch-lifecycle.json`. Keep them, the
  `[patch.crates-io]` block, and `scripts/check_vendored_patch_lifecycle.py` in sync.
  The isolated `fuzz/` workspace does not inherit that block: `fuzz/Cargo.toml`
  must carry the same entries (with `../vendor/` paths) and `fuzz/Cargo.lock`
  must resolve them as path crates, or the fuzz lane exercises stock registry
  code (issue #6583). `fuzz_target_schedule_parity_tests.rs` fails on drift.
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
- Action pins rotate without a policy edit or override
  (`docs/dependency-policy.md` → "Automated action pin rotation"). Every frozen
  surface in `verify_cross_build_policy.py` compares pin-normalized text
  (`normalize_action_pins`: `owner/repo@<sha> # comment` →
  `owner/repo@<placeholder>`). `action_pin_rotation_errors` in `Trusted Cross
  Build Policy` judges the pins on YAML lines the PR adds (its three-dot diff,
  `--proposed-changes`). It admits a new commit only when it is an upstream
  release-tag commit (from `git ls-remote` of `github.com/<owner>/<repo>`) that
  descends from every trusted pin of that repository. Never re-freeze a literal action
  commit in a template, digest, PR-tier verifier, or test. Match the action
  path plus `[0-9a-f]{40}`, or normalize first; the trusted rotation check is
  the only place a commit is judged. A new template must be written in
  normalized form, and a job digest is taken over normalized text.
  `cross-build-policy.yml` and the `CI Plan` early guard admit a pin-only change
  of `cross-build-policy.yml` through `--pin-normalized-equal`;
  `verify_cross_build_policy.py` stays byte-protected.
- Dependabot covers every action (`/` and `/.github/actions/*`) except
  `dtolnay/rust-toolchain`, which has no release tags.
  `dependabot-auto-merge.yml` queues merge-commit auto-merge on Dependabot's
  own non-major PRs with only `GITHUB_TOKEN`. Its merges start no push
  workflows, so a Dependabot merge commit is never itself a release candidate.
- `docker://` action refs and local-action Dockerfile bases must use full
  SHA-256 image digests; `scratch` is the only unpinned Dockerfile base.
- kind / kubectl / Helm install only via
  `.github/actions/setup-kubernetes-tools` with repository-pinned checksums.
- The trusted-base `pr_ci_plan.py --self-test` rejects mutable or dynamic
  action refs, pipe-to-shell installers, and unverified tool downloads. The
  pull request's proposed policy is tested separately but never controls gates.
- `Helm Chart` proves `.github/actions/setup-kubernetes-tools` against the
  trusted revision before `uses:`; the admitted checker generation is bound
  inside `verify_trusted_local_action.py`, never supplied by the candidate.
- A committed `.cargo/config[.toml]` below the repository root is rejected
  outright.

The trusted Cross policy (`verify_cross_build_policy.py`) also freezes these CI
shapes. Changes must satisfy its trusted-base contracts, including explicitly
admitted pin rotations and one-way generations; changing the verifier or adding
an unadmitted shape is reviewed direct-to-`main` policy work, since no pull
request may edit the verifier. Mechanics live in the named `docs/ci_cd.md`
sections:

- Publication boundary: `verify_publication_gate.py`,
  `.github/required-publication-checks.json`, and the release dispatcher and
  input validator are frozen; changing them needs a reviewed policy update (`verify_required_ci.py` is only a
  PR-mutable parity check). → "Publish-blocking required checks".
- Live-suite relevance (`LIVE_SUITE_RELEVANCE_JOB_TEMPLATE`,
  `LIVE_SUITE_RELEVANCE_CONTRACTS`): required live gates decide relevance from a
  pinned trusted-base `live_suite_path_filter.py`, and governed live workflows
  carry no workflow-level `paths:` filter. Extending the contract set is
  direct-to-`main`. `NodeWaypoint eBPF Live`, `Istio Status CAS Live`, and
  `CNI Lifecycle Live` are not branch-protection-required; never add them to
  `REQUIRED_MERGE_GROUP_WORKFLOWS` or `DEDICATED_REQUIRED_CHECKS`. →
  "Trusted-base relevance for required live gates".
- NodeWaypoint (`NODE_WAYPOINT_RELEVANCE_CONTRACT`, `NODE_WAYPOINT_FROZEN_JOBS`):
  the planner, smoke, and gate jobs are frozen (direct-to-`main` only); the PR
  path list is `ci_runtime_plan.py` `SUITE_PATTERNS`, changed by ordinary PR and
  scoped to NodeWaypoint-owned paths. Do not widen it without a replay
  (`ci_runtime_plan.decide_relevance` over merged PRs). → "NodeWaypoint
  relevance contract".
- Fuzz lane (`CI_FUZZ_SMOKE_JOB_GENERATIONS`, `FUZZ_WORKFLOW`,
  `CI_FUZZ_SMOKE_AGGREGATE_INSERTIONS`): both shapes are byte-frozen once
  adopted; a `fuzz-smoke` change appends a one-way successor generation that
  carries each `CI_FUZZ_SMOKE_*_BUDGET` text exactly once. → "Admitted
  `fuzz-smoke` generations".
- Release image families (`RELEASE_IMAGE_FAMILY_GENERATIONS`): `release.yml` is
  either the two-family shape or the complete three-family `-ebpf-tools`
  contract; the trusted base decides, and a three-family base refuses a revert.
  → "Admitted release image-family adoption".
- GNU producer (`LINUX_GNU_X86_PRODUCERS`, `linux_gnu_producer_contract_errors`):
  the published x86_64 GNU binaries are built only by `release.yml`'s
  `build-release-binaries` in the digest-pinned AlmaLinux 8.10 sysroot and are
  ABI-scanned before upload, so the scanned bytes are the published bytes. →
  "Published x86_64 GNU producer contract (standing)".
- GNU identity pins (`linux_gnu_contract_pin_errors`): the sysroot image,
  protoc digest, and smoke images are pinned in the producer's job `env:` and
  hardcoded in the verifier. An image or protoc bump moves the verifier
  constants, that `env:` block, and `.github/linux-gnu-abi.toml` together in one
  direct-to-`main` commit. → "GNU sysroot identity pins".
- Job generation pairs (`CI_JOB_GENERATION_TRANSITIONS`,
  `WORKFLOW_DIRECTORY_JOB_GENERATION_TRANSITIONS`): exact, path-bound, one-way
  SHA-256 pairs; read the live pairs from the verifier on `main`, never from
  this file. → "Admitted CI job SHA-256 generation transitions".

## Cargo Dependabot And The Rustc Wrapper

- The committed `.cargo/config.toml` must not set `[build] rustc-wrapper`. Every
  cargo process under the root reads it, including Dependabot's cargo updater,
  which runs `rustc -vV` through the wrapper and has no sccache. From #821 until
  the wrapper was removed, every cargo version and security update failed with
  `dependency_file_not_resolvable`. `verify_cross_build_policy.py`
  (`EXPECTED_CARGO_BUILD`) allowlists exactly `incremental = false` and rejects
  a committed wrapper; changing it is a direct-to-`main` / admin-merge change.
- sccache is selected by environment: `setup-sccache` exports `RUSTC_WRAPPER` /
  `CARGO_BUILD_RUSTC_WRAPPER` as the verified binary (or clears them), Cross and
  the GNU sysroot build pass them empty, and `scripts/install-build-deps.sh`
  writes the user-level `$CARGO_HOME/config.toml` wrapper locally.
- Dependabot `cargo` version updates cover `/` and `/tests/performance/mesh`,
  with minor/patch grouped. Every `[patch.crates-io]` crate plus `sqlx*` is in
  `ignore`: a bump past the vendored version silently drops the patch (Cargo
  only warns "patch was not used"). Keep those entries equal to the patch table;
  do not add compatibility caps there (`mongodb` tracks the latest driver).
  See `docs/dependency-policy.md` → "Cargo dependency updates".

## Drift Guard

- `tests/integration/vendor_integrity_tests.rs` hashes every governed `vendor/`
  file against `vendor/VENDOR_INTEGRITY.sha256` (LF-normalized SHA-256 for
  allowlisted text paths; byte-exact for binary/unrecognized paths) and runs in
  the `mesh-protocols` Integration Tests shard in `ci.yml`. Incidental vendor `Cargo.lock`
  files are ignored unless listed in `GOVERNED_VENDOR_LOCKFILES` (currently the
  committed dimpl standalone-regression lockfile). Drift beyond the manifest
  fails CI.
- Regenerate only via `scripts/update_vendor_integrity.sh` (or
  `UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity`),
  which shares the guard's hashing so the two cannot diverge.
- A new `tests/integration/*.rs` module must also be added to a shard in
  `.github/workflows/ci.yml`, or the shard-coverage gate fails.

## Advisory Gate

- `cargo deny check advisories bans sources licenses` is BLOCKING when the
  full dependency-audit lane is selected for an eligible event (pull request,
  merge group, push to `main`, or manual dispatch)
  (`dependency-audit` job in `.github/workflows/ci.yml`, gated on full mode
  plus `run_dependency_audit`) and re-runs weekly in
  `.github/workflows/dependency-audit.yml`.
- The gate covers BOTH workspaces: the root graph, and `ebpf/Cargo.toml` via
  `cargo deny --manifest-path ebpf/Cargo.toml check --config deny.toml ...`, in the per-PR
  job and the weekly workflow alike. `ferrum-ebpf` is not in the root graph but
  its object ships in the published `-ebpf` / `-ebpf-tools` images and runs
  privileged on the host network. One shared `deny.toml` — never add
  `ebpf/deny.toml`.
- Every `[advisories.ignore]` in `deny.toml` needs a rationale and an
  `[expires:YYYY-MM-DD]` token; `scripts/check_advisory_expiry.sh` fails the
  weekly run once a date passes. Do not silence an advisory without both.
- `[licenses.exceptions]` entries are time-boxed the same way, enforced by the
  same script on both workflows. cargo-deny accepts no `reason` field there, so
  the `# owner: <name> — <rationale> [expires:YYYY-MM-DD]` token goes in a
  comment immediately preceding (or trailing) the entry, one per entry. Both
  workflows run `scripts/check_advisory_expiry.sh --self-test` first, and also
  publish the locked-graph `third-party-licenses` inventory artifact.
- Licenses ARE part of the blocking gate (since #4468): the `[licenses]`
  allowlist and `confidence-threshold` in `deny.toml` fail CI.
- A CVE in a vendored crate's lineage follows the emergency procedure in
  `docs/dependency-policy.md` (re-vendor on the fixed version or retire); a plain
  `cargo update` cannot reach a `[patch.crates-io]`-pinned crate.

## Behavioral Regression Coverage (must survive retirement)

- SQL `verify-ca` exclusive root CA (issue #5534 review): the vendored
  `--lib tls_rustls::tests` pair in
  `vendor/sqlx-core-0.8.6-ferrum-patched/src/net/tls/tls_rustls.rs`
  (`root_store_with_configured_ca_replaces_the_default_trust_store`,
  `verify_ca_refuses_a_certificate_from_an_unconfigured_ca`), run by the
  `test-vendor-patches` job, plus `tests/service_integration/db_tls.rs`.
  Upstream UNIONS the configured CA with the bundled public roots; combined
  with the `verify-ca` name waiver that trusts any public certificate for any
  name, so the store must start from `RootCertStore::empty()` whenever a CA is
  configured. `EnvConfig::validate` additionally refuses
  `FERRUM_DB_TLS_MODE=verify-ca` with no configured CA.
- hyper-util HTTP/1 sender release (issue #5714): the vendored
  `--lib ferrum_release_on_close_tests` in
  `vendor/hyper-util-0.1.21-ferrum-patched/src/client/legacy/client.rs` plus
  the vendored `--test legacy_client` suite, run by the `test-vendor-patches`
  job. A request enqueued while its pooled HTTP/1 connection closes can miss
  the dispatcher's drain; releasing the only sender lets tokio drop the stranded
  envelope, so the request fails as unsent instead of hanging until
  `backend_read_timeout_ms`.
- hyper upgraded-stream reset (issue #5781): the vendored
  `--lib ferrum_connect_error_reset` tests in
  `vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/upgrade.rs`, run by the
  `test-vendor-patches` job, plus the HBONE relay
  tests in `tests/integration/mesh_hbone_tests.rs`
  (`*_sends_rst_stream_connect_error`, `*_still_ends_stream_cleanly`). A relay
  that ends on a socket error resets its CONNECT stream with
  `RST_STREAM(CONNECT_ERROR)`; stock hyper can only send `END_STREAM`.
- hyper HTTP/2 response flow-control stall (hyper patch 008 + hyper-util
  patch 002, #6998 follow-up): the vendored `--lib ferrum_response_write_timeout`
  tests in `vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/server.rs` (run on
  the vendored h2 by the `test-vendor-patches` `--lib ferrum_` pass) plus
  `tests/unit/gateway_core/frontend_h2_response_write_stall_tests.rs`. A
  client that never sends `WINDOW_UPDATE` parks the response pipe with an idle
  socket; `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` resets that stream with
  `CANCEL` so its body and backend are released. A full send buffer with
  window in hand is not counted.
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
