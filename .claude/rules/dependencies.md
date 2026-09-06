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
- The trusted publication boundary freezes
  `.github/scripts/verify_publication_gate.py` and
  `.github/required-publication-checks.json` by whole-file digest, plus the
  manual release dispatcher and input validator, plus the complete `main-publication-required-checks` job body in
  `gateway-api-conformance.yml`. The trusted verifier compares those proposal
  surfaces before inspecting candidate automation, and never executes the
  candidate publication verifier. Changing these protected
  surfaces requires a reviewed policy update; `verify_required_ci.py` remains a
  PR-mutable parity check, not the admission authority. See `docs/ci_cd.md` →
  "Publish-blocking required checks".
- A required live gate must decide its own relevance from a pinned trusted-base
  copy of `live_suite_path_filter.py`, never from the pull request's checkout.
  `verify_cross_build_policy.py` freezes that block byte-for-byte
  (`LIVE_SUITE_RELEVANCE_JOB_TEMPLATE`) for every
  `LIVE_SUITE_RELEVANCE_CONTRACTS` workflow — `ambient-host-udp-live.yml`,
  `mesh-e2e-sidecar-live.yml`, `multicluster-federation-live.yml`, and
  `multicluster-poller-partition-live.yml` — together with each live job's
  `needs`/`if` binding. That block is protected: no pull request may edit
  `verify_cross_build_policy.py`, so extending the contract set is a
  direct-to-`main` change.
- Governed live workflows carry NO workflow-level `paths:` trigger filter
  (issue #3908): a filter in the pull request's own checkout can exclude the
  change that broke the surface. `node-waypoint-ebpf-live.yml`,
  `istio-status-cas-live.yml`, and `cni-lifecycle-live.yml` now trigger on
  `pull_request`, `merge_group (checks_requested)`, `push: main`, and
  `workflow_dispatch`, decide relevance from a trusted-base classifier
  (`ci_runtime_plan.py` for NodeWaypoint, `live_suite_path_filter.py` for the
  other two), and report through an `if: always()` aggregate. Their aggregates
  (`NodeWaypoint eBPF Live`, `Istio Status CAS Live`, `CNI Lifecycle Live`) are
  NOT branch-protection-required and must not be added to
  `REQUIRED_MERGE_GROUP_WORKFLOWS` or `DEDICATED_REQUIRED_CHECKS` — freezing an
  optional gate's shape is not the same as making it required. Issue #3908 is
  now durably complete on all three: `cni-lifecycle-live.yml` and
  `istio-status-cas-live.yml` are entries in `LIVE_SUITE_RELEVANCE_CONTRACTS`,
  and NodeWaypoint has its own additive contract
  (`NODE_WAYPOINT_RELEVANCE_CONTRACT` + `NODE_WAYPOINT_FROZEN_JOBS`, enforced by
  `node_waypoint_relevance_errors` from both `validate_workflow_collection` and
  `compare_pr_workflow_collection`) because its planner job is
  `production-dockerfile-plan`, runs `ci_runtime_plan.py`, emits two verdicts,
  and binds fail-closed as `always() && … != 'false'` — none of which the shared
  template can express. That contract freezes `production-dockerfile-plan`,
  `production-dockerfile-smoke`, and `node-waypoint-ebpf-live-gate` whole, and
  freezes `needs`/`if` only on `production-dockerfile-smoke-default`,
  `production-dockerfile-smoke-ebpf`, and `node-waypoint-ebpf-live`; deleting
  the workflow is rejected. Editing any of this is a direct-to-`main` change:
  no pull request may modify `verify_cross_build_policy.py`. The temporary
  `--list-suites` bootstrap handshake is deleted from
  `live_suite_path_filter.py`. The classifier refuses to classify
  any change-set record that is not a normal repository-relative pathname and
  forces the suite to run instead. See `docs/ci_cd.md` → "Trusted-base
  relevance for required live gates" and "NodeWaypoint relevance contract".
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
- The `fuzz-smoke` job carries TWO admitted generations, now for issue #4442
  (`CI_FUZZ_SMOKE_JOB_GENERATIONS`, oldest first): `CI_FUZZ_SMOKE_RETIRED_JOB`
  is #4238's shape — the deterministic property smoke as the required
  `pull_request`/`merge_group` gate, the six-target libFuzzer budget on push to
  `main` / `workflow_dispatch` only, and `./.github/actions/setup-sccache` plus
  a `main`-push-only `save-if` cache (`pull_request`, fork, `merge_group`, and
  `workflow_dispatch` restore but never publish a `fuzz-smoke` cache);
  `CI_FUZZ_SMOKE_JOB` adds a seventh bounded invocation for
  `datagram_client_address` at `-max_len=65536`, that target's documented 64 KiB
  budget, so one hostile-UDP parser's length boundaries are reachable in BOTH
  required lanes rather than only the scheduled one. The
  transition is exact on both ends and
  one-way — withholding is symmetric, so `admitted_fuzz_smoke_removal_errors` is
  what refuses a revert. `CI_FUZZ_SMOKE_BOUNDED_BUDGET` must appear exactly once
  in every generation and `CI_FUZZ_SMOKE_DATAGRAM_BUDGET` exactly once in the
  adopted one, so a generation can never move or extend the lane and relax its
  bounds at the same time. `FUZZ_WORKFLOW` carries the same target in the
  scheduled matrix and the literal shell allowlist. Delete the retired
  generation once the adopted one is
  on `main`. See `docs/ci_cd.md` → "Admitted `fuzz-smoke` lane-split
  generation".
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
- The temporary `fips-build.yml` whole-file generation admission (first used
  for #3889, retired by #3943; re-armed for #3950 and spent when #3950 landed)
  is **re-armed for exactly one transition**: the issue #4018 FIPS
  test-binary memory mitigation, pair
  `17bfb40f…e5e9e1` → `7d995d79…2ca401` (`CARGO_BUILD_JOBS=3`,
  `line-tables-only` on the `dev` AND `test` profiles, and a best-effort
  additive Ferrum-owned swapfile on `fips-test-build`; recompute if the
  workflow bytes change).
  One-way, retire again once the mitigation lands. Every other
  `fips-build.yml` edit is compared by the normal fail-closed Cross surface
  scan. See `docs/ci_cd.md` → "Admitted `fips-build.yml` generation
  transition".
- `Helm Chart` proves `.github/actions/setup-kubernetes-tools` against the
  trusted revision before `uses:`. Issue #3904 admits exactly one extracted
  checker generation: current `action.yml`
  `6ecb4bde09a0d3d456d6019c03ef1678c3903cbc0275bba31fde3e56f6e6ef08` moving to
  PR #3910 `41dd4b9ae1b0ad74e021e2974afbcdac1a1bc0d856a166a57e94046e803d6cd9`.
  Source and destination are bound inside `verify_trusted_local_action.py`; the
  candidate cannot supply a digest. Retire the pair after #3910 is the trusted
  base.
- The published x86_64 GNU producers — `ci.yml`'s `build-binaries` and
  `release.yml`'s `build-release-binaries` — build their ONE x86_64 GNU matrix
  cell in the digest-pinned AlmaLinux 8.10 sysroot rather than natively on a
  moving `ubuntu-latest`, and gate the staged, checksummed `release-assets/`
  files on an ABI/oldest-baseline scan before uploading them (issue #4301).
  One producer, one artifact identity: the scanned bytes ARE the published
  bytes, so `create-release`, the `.sha256` sidecars, the `latest` prerelease,
  and the container image inputs cannot describe a binary that was never
  verified. Their #4301 `CI_JOB_GENERATION_TRANSITIONS` pairs are RETIRED
  (both destinations are on `main`, and issue #4423 moved both jobs again
  direct-to-`main`); the standing control is the absolute check
  `linux_gnu_producer_contract_errors`, which binds as soon as the repository
  references `.github/scripts/build_linux_gnu_sysroot.sh` and rejects a
  producer that native-compiles x86_64 GNU, scans a
  `target/x86_64-unknown-linux-gnu/...` rebuild, gates after the upload,
  shares the canonical artifact name with a second uploader, omits the
  job-level identity pins, or checks out with `persist-credentials` left on.
  The ARM64 Cross producer, its command/environment/image freeze, and every
  publication `needs` graph are untouched; ARM64 is scanned as published by
  `verify-linux-gnu-abi-aarch64` / `verify-latest-linux-gnu-abi-aarch64` and
  joined by the existing retraction gates, which is the only shape available
  while both its producer and its consumers are frozen. See `docs/ci_cd.md` →
  "Published x86_64 GNU producer contract (standing)".
- The GNU sysroot BUILD IMAGE and the protoc archive are pinned by IDENTITY,
  not just by form (issue #4423). `.github/linux-gnu-abi.toml` is
  PR-editable and `verify_linux_gnu_abi.py` runs from the pull request's own
  checkout, so the TOML cannot be the control. Both producer jobs pin
  `LINUX_GNU_SYSROOT_IMAGE`, `LINUX_GNU_PROTOC_SHA256`,
  `LINUX_GNU_SMOKE_FLOOR_IMAGE`, and `LINUX_GNU_SMOKE_UBUNTU2204_IMAGE` in
  their job-level `env:` — the shell scripts refuse to run when those
  disagree with the TOML — and `verify_cross_build_policy.py` hardcodes the
  expected image references, the protoc digest, and the required
  `https://github.com/protocolbuffers/protobuf/releases/download/` URL
  prefix. `linux_gnu_producer_contract_errors` holds the `env:` literals to
  those constants absolutely, and `linux_gnu_contract_pin_errors` re-validates
  the TOML from the trusted base checkout (`--linux-gnu-contract`, whose
  default is deliberately not supplied by `cross-build-policy.yml`). A
  deliberate image or protoc bump therefore moves the constants, both `env:`
  blocks, and the TOML in one direct-to-`main` commit. See `docs/ci_cd.md` →
  "GNU sysroot identity pins".
- Cross-sensitive `ci.yml` jobs `ci-plan`, `test`, and `performance-regression`
  carry temporary SHA-256 generation pairs (`CI_JOB_GENERATION_TRANSITIONS`)
  for PRs #3913 and #3911, the three per-suite live gates (`ebpf-live`,
  `netns-capture-live`, `two-cluster-mesh-live`) carry pairs for PR #3915's
  planner-gate split (adopted digests pinned against #3915's latest-main merge
  `d95ea4796`). The `build-binaries` / `build-release-binaries` pairs (PRs
  #3916 and #4355) are all retired; those two jobs carry no transition pair.
  `setup-rust-ci/action.yml` carries a two-step
  trusted-base chain (`LOCAL_ACTION_GENERATION_TRANSITIONS`): #3889's landed
  `fc4e41818dffdea880c057c8dfa0881a629cd01c917b43f69a9f2e5e9bd90dda` moving to
  the cache-budget generation
  `b6ca6315ff9f2a206c1011b6b0166de3a340370fd75bf3e9cffe41e872008924`
  (rust-cache `save-if` gated to trusted `refs/heads/main`), which may then
  move to the rebased combined #3911 destination
  `219187bdb0366d929577e67f48947b8c1096998dd7e04eafdffdb53dc3faa925`
  (adds the optional `workspaces` input/pass-through on top). The former
  direct #3889→#3911 pair is superseded; #3911 must rebase to the combined
  text. Each step is exact, path-bound, one-way, no candidate allowlist. See
  `docs/ci_cd.md` → "Admitted CI job SHA-256 generation transitions".
- Non-protected workflows get the same mechanism through
  `WORKFLOW_DIRECTORY_JOB_GENERATION_TRANSITIONS`, keyed by workflow filename
  AND job name: `coverage.yml`'s `coverage-merge` carries a pair for PR
  #3917's shard-scoped coverage-merge reshape (issue #3907; adopted digest
  pinned against #3917's latest-main merge). On the exact admitted pair only
  that job's `job:<name>:*` surfaces are withheld; everything else in the file
  is scanned as before, and the reverse pair is refused. Retire each tuple
  once its destination is on `main`. See `docs/ci_cd.md` → "Admitted
  workflow-directory job SHA-256 generation transitions".

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

- `cargo deny check advisories bans sources licenses` is BLOCKING on every PR
  (`dependency-audit` job in `.github/workflows/ci.yml`) and re-runs weekly in
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
