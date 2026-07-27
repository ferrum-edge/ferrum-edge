# Dependency & Vendored-Crate Governance

This document is the single policy for how Ferrum Edge manages third-party
dependencies and, in particular, the **vendored, patched copies** of upstream
crates it carries in `vendor/**`. It is the human half of the governance; the
machine half is `deny.toml`, the scheduled `.github/workflows/dependency-audit.yml`
workflow, and the drift guard in `tests/integration/vendor_integrity_tests.rs`.

> TL;DR — vendored patches must be **auditable** (pinned + drift-tested),
> **tracked** (an upstream PR — or a governed [deliberate-fork record](#deliberate-fork-policy-and-sla)
> — plus a retirement trigger, recorded and polled weekly), and
> **covered** (behavioral regression tests). Security advisories in the
> dependency tree are gated on every PR and re-checked weekly, so a fix landing
> in the reqwest/h3 lineage cannot be missed silently.

## Why we vendor

The HTTP/3, QUIC, and WebSocket stacks are young enough that we occasionally hit
upstream bugs (or need a not-yet-merged API) faster than upstream releases.
Vendoring a patched crate via `[patch.crates-io]` is an accepted, **last-resort**
tool when:

- the fix/feature is required for correctness or a documented Ferrum capability,
  and
- the change has been (or will be) proposed upstream, and
- a written retirement plan exists so the vendor copy does not become orphaned.

Vendoring without a retirement plan is not allowed. Prefer a dependency bump, a
feature flag, or a gateway-side workaround first.

## Vendored crate inventory

Each row is the authoritative tracking record. Keep this table, the
`[patch.crates-io]` block in `Cargo.toml`, the per-patch docs, and the
`PATCHES` array in `scripts/check_vendored_patch_status.sh` in sync.

| Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |
|---|---|---|---|---|---|---|---|
| `reqwest` | 0.13.3 | Per-request `RequestBuilder::connect_timeout` | [seanmonstar/reqwest#3017](https://github.com/seanmonstar/reqwest/pull/3017) (OPEN) | Ferrum Edge maintainers | Pool keys exclude request-only connect/read timeouts, so sibling proxies can share one client; without per-request connect timeout the first proxy's timeout leaks to all | PR #3017 merges and ships in a release we consume | [docs/upstream-reqwest-patches/001-…](upstream-reqwest-patches/001-per-request-connect-timeout/README.md) |
| `h3` | 0.0.8 | Drain buffered frames before propagating QUIC `CONNECTION_CLOSE` | issue [hyperium/h3#338](https://github.com/hyperium/h3/issues/338), PR [hyperium/h3#339](https://github.com/hyperium/h3/pull/339) | Ferrum Edge maintainers | io_uring batching of `STREAM(FIN)` + `CONNECTION_CLOSE(H3_NO_ERROR)` dropped a buffered HEADERS frame → false 502 on graceful close | Fix ships in an `h3` release **and** patches 002/003 are also retired | [docs/upstream-h3-patches/001-…](upstream-h3-patches/001-recv-frame-drain-on-quic-close/README.md) |
| `h3` | 0.0.8 | Add `Protocol::WEB_SOCKET` (RFC 9220 Extended CONNECT) | **Deliberate fork** — unfiled upstream; branch `feat/extended-connect-websocket-protocol` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock `h3` 0.0.8 rejects `:protocol=websocket` at the HEADERS layer, making WebSocket-over-HTTP/3 unreachable | Upstream files + merges the variant **and** patches 001/003 are also retired | [docs/upstream-h3-patches/002-…](upstream-h3-patches/002-extended-connect-websocket-protocol/README.md) |
| `h3` | 0.0.8 | Add `RequestStream::peek_recv_trailers()` for already-buffered trailers before FIN | **Deliberate fork** — unfiled upstream; branch `feat/peek-buffered-trailers-before-fin` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `poll_recv_trailers` buffers trailer HEADERS but waits for terminal FIN; gateway trailer-timeout collapse dropped trailers delivered before delayed FIN | Upstream files + merges the API **and** patches 001/002 are also retired | [docs/upstream-h3-patches/003-…](upstream-h3-patches/003-peek-buffered-trailers-before-fin/README.md) |
| `tungstenite` | 0.29.0 | `WebSocket::into_inner_with_read_buffer()` (lossless raw takeover) | [snapview/tungstenite-rs#556](https://github.com/snapview/tungstenite-rs/pull/556) | Ferrum Edge maintainers | Tunnel mode lost backend bytes coalesced with the `101` response when dropping to raw relay | **Both** this and tokio-tungstenite#380 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite` | 0.29.0 | Distinct `FrameTooLong` origin for pre-reservation frame policy | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Equal frame/message ceilings otherwise lose which parser boundary rejected input and can emit the wrong configured close reason | Upstream ships equivalent frame-vs-message capacity attribution, or the gateway no longer needs distinct policy reasons | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite` | 0.29.0 | `WebSocketConfig::auto_pong` opt-out for transparent Ping relay | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Stock framer auto-answers Ping while the gateway also forwards it, so one Ping yields two Pongs and a hung backend still looks healthy | Upstream ships equivalent default-true auto-Pong opt-out, or the gateway no longer needs transparent Ping/Pong | [docs/upstream-tungstenite-patches/003-…](upstream-tungstenite-patches/003-optional-auto-pong/README.md) |
| `tokio-tungstenite` | 0.29.0 | `WebSocketStream::into_inner_with_read_buffer()` | [snapview/tokio-tungstenite#380](https://github.com/snapview/tokio-tungstenite/pull/380) | Ferrum Edge maintainers | Same lossless-takeover gap on the async wrapper | **Both** this and tungstenite#556 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `dimpl` | 0.6.1 | Full leaf-first certificate-chain transport and zeroizing private-key ownership | **Deliberate fork** — unfiled upstream; base commit `37bb0fa83f4167420729de5ea71c61852f82e9ed` ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Published releases expose only one local certificate and retain endpoint/fallback credential bytes in ordinary `Vec<u8>` owners | Upstream ships compatible full-chain DTLS 1.2/1.3 transport, peer-chain output, and drop-time key zeroization on all ownership paths | [docs/upstream-dimpl-patches/001-…](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/README.md) |

> Ownership note: `vendor/`, `deny.toml`, this doc, `docs/upstream-*-patches/`,
> and the vendored-patch scripts are owned via
> [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`). Upstream `h3`
> work is staged from the `jeremyjpj0916/h3` fork referenced in the h3 patch
> docs. Patches carried without an upstream PR, including the tungstenite frame
> error-origin extension, the tungstenite `auto_pong` opt-out, and the dimpl
> credential-security patch, are governed by the
> [Deliberate fork policy and SLA](#deliberate-fork-policy-and-sla) below.

### Deliberate fork policy and SLA

Most vendored patches ride an **open upstream PR** (reqwest #3017, h3 #339,
tungstenite #556 / tokio-tungstenite #380); the weekly
`scripts/check_vendored_patch_status.sh` polls those and goes red when one
merges. Fork-only patches currently include **h3 002** (Extended CONNECT
`:protocol=websocket`), **h3 003** (`peek_recv_trailers`), the tungstenite
frame-limit origin extension, **tungstenite `auto_pong`** (transparent Ping
relay), and **dimpl 001** (DTLS certificate chains and private-key
zeroization). They are not untracked TODOs; they are carried as
**deliberate, time-boxed forks** and are governed as follows:

- **Owner.** The dependency-governance owner in
  [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`) — the same
  owner for `vendor/`, `deny.toml`, this doc, `docs/upstream-*-patches/`, and
  the vendored-patch scripts.
- **Review cadence (SLA).** Every weekly `dependency-audit` run lists each
  fork-only patch as `NOT YET FILED`. At each run the owner either (a) files the
  upstream issue/PR and records the numbers in the inventory table, the per-patch
  `README.md` Status block, **and** the `PATCHES` array in
  `scripts/check_vendored_patch_status.sh`, or (b) leaves it as a conscious
  re-affirmation that the fork is still the right call.
- **Hard checkpoint — no unfiled fork ships in a stable release.** A fork-only
  patch (no upstream PR link) may **not** survive the first tagged stable release
  (the schema-freeze milestone in
  [migrations.md → Stability & Upgrade Contract](migrations.md#when-v002-migrations-start-the-schema-freeze))
  without either a filed upstream issue/PR link recorded in the inventory table,
  or an explicit dated re-affirmation
  (`Deliberate fork — re-affirmed YYYY-MM-DD by <owner>: <reason>`) in the
  patch's `README.md`. This keeps "not yet filed" from silently becoming
  permanent in a released product.
- **Retirement is unchanged.** Whether upstreamed via PR or carried as a fork,
  each patch retires per its `README.md` retirement plan and the co-vendoring
  rule (all three h3 patches retire together — see the inventory `Removal
  trigger` column).

## Enforcement controls

### 1. Blocking advisory gate (`deny.toml` + CI)

`cargo deny check advisories bans sources` runs on **every PR**
(`dependency-audit` job in `.github/workflows/ci.yml`) and is **blocking**: any
RUSTSEC advisory in the resolved tree that is not explicitly time-boxed in
`deny.toml` fails CI. `unmaintained`/`unsound` are set to `all` (not the 0.19
default of `workspace`) so transitive advisories are blocking too, and
`unused-ignored-advisory = "deny"` forces a stale exception to be deleted once
its advisory is fixed/removed. `bans` (duplicate-version visibility) and
`sources` (crates.io-only) run alongside. License checking is intentionally
**not** in the gate yet — see the `deny.toml` header.

Run locally:

```bash
cargo install --locked cargo-deny
cargo deny check advisories bans sources   # the gate
```

### 2. Advisory exceptions are time-boxed

Every `[advisories.ignore]` entry in `deny.toml` carries a rationale and an
`[expires:YYYY-MM-DD]` token **inside its table `reason` string**.
`scripts/check_advisory_expiry.sh` (run by the per-PR gate **and** the weekly
workflow) fails once any date passes — or if an entry uses the string form or a
comment-only token, both of which would dodge the time-box — so an exception
cannot silently become permanent. A maintainer must re-fix the advisory or
consciously extend the window.

Current exceptions are all transitive and either no-fix-available or semver-pinned
by a transitive parent (e.g. `mongodb` pins `hickory ^0.25`; the old AWS SDK
chain pins `rustls-webpki ^0.101.7`, only present under the optional `secrets-aws`
feature). Each entry documents the confinement and the upstream we are waiting on.

### 3. Vendor drift guard

`tests/integration/vendor_integrity_tests.rs` hashes every governed file under
`vendor/` and compares it to `vendor/VENDOR_INTEGRITY.sha256`. Known text paths
(allowlisted source/docs/config extensions and basenames) use LF-normalized
SHA-256 (`\r` stripped) so CRLF checkouts stay stable; binary artifacts and any
unrecognized path are hashed byte-for-byte so CR bytes in `.der` / `.bin` (and
similar) cannot change unnoticed. Incidental crate-local `Cargo.lock` files
created by documented standalone vendor tests are ignored by default; intentionally
committed lockfiles that pin a standalone regression graph (currently
`vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock`) are allowlisted in
`GOVERNED_VENDOR_LOCKFILES` and must appear in the manifest. The guard runs in
the normal integration suite (the `protocols-data-plane` shard), so a PR that
changes any governed vendored byte without regenerating the manifest **fails CI**.
This keeps the vendored diff reviewable: an unexpected edit to upstream code
cannot slip in unnoticed.

Regenerate only as part of an intentional, documented patch change:

```bash
scripts/update_vendor_integrity.sh
# i.e. UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity
```

### 4. Scheduled `dependency-audit` workflow

`.github/workflows/dependency-audit.yml` runs weekly (Mon 05:30 UTC) and on
demand:

- **advisories** — re-runs the `cargo deny` gate against the freshly-fetched
  advisory DB (catches new advisories with no PR), runs the expiry check, and
  runs `cargo audit` as an independent second opinion.
- **upstream-patch-status** — `scripts/check_vendored_patch_status.sh` queries
  each tracked upstream PR. The run goes **red when an upstream PR has merged**
  (a retirement signal) and reports each crate's latest crates.io release.

### 5. Behavioral regression tests for the patched behaviors

The patches fix runtime behavior; these tests guard that behavior independently
of the vendor copy and must keep passing after retirement:

- Per-request connect timeout across shared pool keys —
  `tests/integration/connection_pool_tests.rs`
  (`test_connect_timeout_does_not_fragment_pool`,
  `test_pooled_client_exposes_per_request_connect_timeout`).
- HTTP/3 graceful close with a buffered response is not a false 502 —
  `tests/integration/http3_integration_tests.rs`
  (`h3_buffered_response_survives_graceful_close_race`,
  `h3_goaway_after_complete_body_is_treated_as_graceful`,
  `h3_stream_reset_after_partial_body_is_not_treated_as_graceful`), plus
  `tests/functional/scripted_backend_h3_tests.rs`.
- The h3 frame-drain unit tests live in the vendored crate
  (`vendor/h3-0.0.8-ferrum-patched/src/frame.rs::tests`) and on upstream PR #339;
  run them with
  `cargo test --manifest-path vendor/h3-0.0.8-ferrum-patched/Cargo.toml --lib frame`.
- The tungstenite pre-reservation frame-origin regression lives in the vendored
  crate (`protocol::frame::tests::size_limit_hit`) and runs alongside the
  raw-takeover regression in the vendored-patch job.
- The tungstenite `auto_pong` opt-out regressions live in the vendored crate
  (`protocol::tests::auto_pong_*`) and in
  `tests/unit/gateway_core/websocket_auto_pong_tests.rs`, with end-to-end
  coverage in `tests/functional/functional_websocket_test.rs`
  (`test_*websocket_ping_*`).
- The dimpl credential regressions live in
  `vendor/dimpl-0.6.1-ferrum-patched/tests/auto/credential_security.rs`. They
  cover DTLS 1.2 and 1.3 chain transmission plus deterministic clone,
  failed-construction, fallback, and shutdown zeroization observations. The
  Ferrum integration suite separately verifies a root-only client completes a
  handshake because the configured intermediate is transmitted.

CI gates these vendored-patch contracts in the `Vendored Patch Regressions`
job in `.github/workflows/ci.yml`. Keep that job in sync with this list when
adding, retiring, or changing a vendored patch.

## Procedures

### Adding a vendored patch

1. Confirm a dependency bump / feature flag / gateway workaround can't do it.
2. Copy the locked crates.io source into `vendor/<crate>-<ver>-ferrum-patched/`,
   apply the minimal upstream-proposed diff, and keep the diff reviewable (no
   private Ferrum-only API beyond the proposed surface).
3. Wire it through `[patch.crates-io]` in `Cargo.toml` with a comment block.
4. Add `docs/upstream-<crate>-patches/NNN-…/` with `README.md` (status, upstream
   links, retirement plan), the unified `.patch`, and issue/PR drafts.
5. Add a behavioral regression test for the fixed behavior and wire it into the
   `Vendored Patch Regressions` CI job when it lives outside the normal root
   test matrix.
6. Add a row to the inventory table above and to the `PATCHES` array in
   `scripts/check_vendored_patch_status.sh`.
7. Regenerate the drift manifest: `scripts/update_vendor_integrity.sh`.
8. File the upstream issue/PR and record the numbers.

### Refreshing a vendored patch (upstream review changes)

1. Re-fetch the upstream diff, re-apply over the pinned base version, copy the
   sources back into the vendor directory.
2. Update the per-patch `.patch` and README notes.
3. **Regenerate the drift manifest** (`scripts/update_vendor_integrity.sh`) and
   review the diff — the manifest change is the audit trail.
4. Run the behavioral regression tests.

### Retiring a vendored patch

Trigger: the upstream PR merges **and** ships in a release we consume (for `h3`
and tungstenite, *both* co-vendored patches must be ready — see the table).

1. Bump the registry version in `Cargo.toml` `[dependencies]` to the release
   containing the fix; update `Cargo.lock`.
2. Remove the crate's line from the `[patch.crates-io]` block.
3. `git rm -r vendor/<crate>-<ver>-ferrum-patched/` (and `vendor/` if empty).
4. Move `docs/upstream-<crate>-patches/NNN-…/` to `…/_retired/NNN-…/` with a
   `STATUS.md` (merge commit + registry version), or delete per that crate's
   README.
5. Remove the inventory row + the `scripts/check_vendored_patch_status.sh` entry.
6. Regenerate the drift manifest (now smaller) and keep the gateway call sites —
   they use the upstream API by design.
7. Run the behavioral regression tests; they must still pass.

### Emergency security update for a vendored crate

A vendored crate masks its upstream from a normal `cargo update`, so a CVE in the
reqwest/h3/tungstenite lineage needs an explicit path:

1. **Triage** which version fixes it and whether our patch applies cleanly to
   the fixed source.
2. **If a fixed release exists and we can retire:** follow "Retiring a vendored
   patch" immediately (bump + drop the vendor copy).
3. **If we must keep the patch:** re-vendor on top of the *fixed* upstream
   version — copy the patched-fixed source into a new
   `vendor/<crate>-<fixedver>-ferrum-patched/`, re-apply our minimal diff,
   update `[patch.crates-io]`, the per-patch docs, the inventory row, and
   **regenerate the drift manifest**.
4. **If neither is possible yet (no fix upstream):** add a time-boxed
   `[advisories.ignore]` in `deny.toml` with a rationale documenting the
   confinement and a near-term `[expires:]` date, and open a tracking issue.
5. Land the change on an expedited review per `SECURITY.md` severity timelines.
6. Never silence an advisory without an expiry and a rationale — the expiry
   check will fail the weekly run otherwise (by design).

## CI Actions and Kubernetes tooling

GitHub Actions and the kind / kubectl / Helm binaries used by live Kubernetes
jobs are a separate supply-chain surface from Rust crates. Policy:

1. **Pin every external action** to a full 40-character commit SHA, with an
   accurate version comment (for example
   `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`).
   Mutable tags (`@v7`, `@v7.0.1`), branches (`@main`), and short SHAs are
   forbidden. `docker://` action references require an explicit
   `@sha256:<64-hex>` image digest. Local composite actions under
   `./.github/actions/...` and reusable workflows directly under
   `./.github/workflows/` are allowed without a SHA pin; local Docker actions
   must also digest-pin every non-`scratch` `FROM` image.
2. **Install kind, kubectl, and Helm only through**
   [`.github/actions/setup-kubernetes-tools`](../.github/actions/setup-kubernetes-tools/action.yml).
   That composite action downloads from official versioned release URLs, verifies
   each artifact against repository-pinned SHA-256 digests **and** the matching
   official published checksum file for that exact version, then installs into
   the runner PATH. It never pipes remote content to a shell and fails closed on
   download or verification errors.
3. **Do not** use `azure/setup-helm`, `curl … | bash` installers, or
   `raw.githubusercontent.com/helm/helm/main` (or any other mutable-branch
   install script).
4. **Static enforcement.** The `ci-plan` job runs the trusted base branch's
   `.github/scripts/pr_ci_plan.py --self-test` on every CI run (including
   lightweight documentation PRs). Its checker rejects mutable action refs,
   pipe-to-shell installers, mutable-branch install scripts, and direct
   kind/kubectl/Helm downloads outside the composite action. Repository-local
   actions are allowed, but dynamic or matrix-generated `uses` references are
   rejected because the checker cannot prove that every generated value is a
   full immutable SHA. The head-executed required-CI verifier also runs a pull
   request's proposed planner self-tests without consuming planner outputs, so
   new policy code is exercised before merge while the base branch remains the
   sole authority for job gates.

   This is deliberately static enforcement, not a shell interpreter. It catches
   known direct URLs and folded/continued installer commands, but cannot prove
   the destination of a URL assembled indirectly from shell variables or other
   obfuscation. Reviewers must treat such construction as unverified and require
   a literal, versioned URL plus repository-pinned checksum (or the centralized
   installer) before approving it.

### Refreshing GitHub Actions (Dependabot)

`.github/dependabot.yml` already schedules weekly `github-actions` updates.
When reviewing an actions Dependabot PR:

1. Confirm the PR pins a full commit SHA (Dependabot for GitHub Actions should
   produce SHA pins when the repo already uses them).
2. Keep the trailing version comment accurate for the tag the SHA corresponds
   to.
3. Do not accept a PR that reintroduces a mutable tag ref.

The ARM64 Cross build and publication contracts are deliberately frozen by the
trusted `pull_request_target` verifier. Existing checkout uses on the guarded
workflow surfaces still carry the historical `# v6` annotation, although their
pinned `3d3c42e5...` SHA resolves to v7.0.1. The verifier treats an adjacent
annotation change as a change to that executable surface, so an ordinary pull
request cannot normalize those comments. Correct them only as part of an
authorized, coordinated rotation of the trusted policy; do not copy the legacy
annotation onto new uses.

### Refreshing kind / kubectl / Helm versions and checksums

Versions and digests live as defaults on the
`setup-kubernetes-tools` composite action inputs. To bump a tool:

1. Choose the new official release tag (kind GitHub release, Kubernetes
   `dl.k8s.io` release, or Helm release on `get.helm.sh`).
2. Fetch the **official** published checksum for that exact version and
   architecture (`linux/amd64`):
   - kind:
     `https://github.com/kubernetes-sigs/kind/releases/download/<tag>/kind-linux-amd64.sha256sum`
   - kubectl:
     `https://dl.k8s.io/release/<tag>/bin/linux/amd64/kubectl.sha256`
   - Helm:
     `https://get.helm.sh/helm-<tag>-linux-amd64.tar.gz.sha256sum`
     (optionally cross-check the detached signature assets on the Helm GitHub
     release before trusting a new digest).
3. Update the matching `*-version` and `*-sha256` defaults in
   `.github/actions/setup-kubernetes-tools/action.yml`.
4. Leave workflow jobs calling `uses: ./.github/actions/setup-kubernetes-tools`
   unchanged unless a job must pin an override input for a temporary skew.
5. Land the change via PR; the trusted CI planner policy and the live suites that
   path-filter on the composite action will exercise the new pins.

Never refresh a checksum by copying a digest from an unpinned adjacent path
without official release provenance, and never pipe a remote install script to
a shell as a shortcut.

## See also

- `deny.toml` — the gate configuration and current exceptions.
- `SECURITY.md` — vulnerability reporting and severity timelines.
- `docs/upstream-reqwest-patches/`, `docs/upstream-h3-patches/`,
  `docs/upstream-tungstenite-patches/`, `docs/upstream-dimpl-patches/` —
  per-patch detail and retirement plans.
- `Cargo.toml` `[patch.crates-io]` — the active vendored patches.
