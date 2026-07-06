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
| `reqwest` | 0.13.3 | Per-request `RequestBuilder::connect_timeout` | [seanmonstar/reqwest#3017](https://github.com/seanmonstar/reqwest/pull/3017) (OPEN) | Ferrum Edge maintainers | Pool keys exclude policy fields, so sibling proxies share one client; without per-request connect timeout the first proxy's timeout leaks to all | PR #3017 merges and ships in a release we consume | [docs/upstream-reqwest-patches/001-…](upstream-reqwest-patches/001-per-request-connect-timeout/README.md) |
| `h3` | 0.0.8 | Drain buffered frames before propagating QUIC `CONNECTION_CLOSE` | issue [hyperium/h3#338](https://github.com/hyperium/h3/issues/338), PR [hyperium/h3#339](https://github.com/hyperium/h3/pull/339) | Ferrum Edge maintainers | io_uring batching of `STREAM(FIN)` + `CONNECTION_CLOSE(H3_NO_ERROR)` dropped a buffered HEADERS frame → false 502 on graceful close | Fix ships in an `h3` release **and** patches 002/003 are also retired | [docs/upstream-h3-patches/001-…](upstream-h3-patches/001-recv-frame-drain-on-quic-close/README.md) |
| `h3` | 0.0.8 | Add `Protocol::WEB_SOCKET` (RFC 9220 Extended CONNECT) | **Deliberate fork** — unfiled upstream; branch `feat/extended-connect-websocket-protocol` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock `h3` 0.0.8 rejects `:protocol=websocket` at the HEADERS layer, making WebSocket-over-HTTP/3 unreachable | Upstream files + merges the variant **and** patches 001/003 are also retired | [docs/upstream-h3-patches/002-…](upstream-h3-patches/002-extended-connect-websocket-protocol/README.md) |
| `h3` | 0.0.8 | Add `RequestStream::peek_recv_trailers()` for already-buffered trailers before FIN | **Deliberate fork** — unfiled upstream; branch `feat/peek-buffered-trailers-before-fin` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `poll_recv_trailers` buffers trailer HEADERS but waits for terminal FIN; gateway trailer-timeout collapse dropped trailers delivered before delayed FIN | Upstream files + merges the API **and** patches 001/002 are also retired | [docs/upstream-h3-patches/003-…](upstream-h3-patches/003-peek-buffered-trailers-before-fin/README.md) |
| `tungstenite` | 0.29.0 | `WebSocket::into_inner_with_read_buffer()` (lossless raw takeover) | [snapview/tungstenite-rs#556](https://github.com/snapview/tungstenite-rs/pull/556) | Ferrum Edge maintainers | Tunnel mode lost backend bytes coalesced with the `101` response when dropping to raw relay | **Both** this and tokio-tungstenite#380 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tokio-tungstenite` | 0.29.0 | `WebSocketStream::into_inner_with_read_buffer()` | [snapview/tokio-tungstenite#380](https://github.com/snapview/tokio-tungstenite/pull/380) | Ferrum Edge maintainers | Same lossless-takeover gap on the async wrapper | **Both** this and tungstenite#556 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |

> Ownership note: `vendor/`, `deny.toml`, this doc, `docs/upstream-*-patches/`,
> and the vendored-patch scripts are owned via
> [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`). Upstream `h3`
> work is staged from the `jeremyjpj0916/h3` fork referenced in the h3 patch
> docs. Patches carried without an upstream PR are governed by the
> [Deliberate fork policy and SLA](#deliberate-fork-policy-and-sla) below.

### Deliberate fork policy and SLA

Most vendored patches ride an **open upstream PR** (reqwest #3017, h3 #339,
tungstenite #556 / tokio-tungstenite #380); the weekly
`scripts/check_vendored_patch_status.sh` polls those and goes red when one
merges. Two patches — **h3 002** (Extended CONNECT `:protocol=websocket`) and
**h3 003** (`peek_recv_trailers`) — have **no upstream issue or PR filed yet**.
They are not an untracked TODO; they are carried as a **deliberate, time-boxed
fork** of `h3` on `jeremyjpj0916/h3` and are governed as follows:

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

`tests/integration/vendor_integrity_tests.rs` hashes every file under `vendor/`
(LF-normalized SHA-256) and compares it to `vendor/VENDOR_INTEGRITY.sha256`. It
runs in the normal integration suite (the `protocols-data-plane` shard), so a
PR that changes any vendored byte without regenerating the manifest **fails CI**.
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

## See also

- `deny.toml` — the gate configuration and current exceptions.
- `SECURITY.md` — vulnerability reporting and severity timelines.
- `docs/upstream-reqwest-patches/`, `docs/upstream-h3-patches/`,
  `docs/upstream-tungstenite-patches/` — per-patch detail and retirement plans.
- `Cargo.toml` `[patch.crates-io]` — the active vendored patches.
