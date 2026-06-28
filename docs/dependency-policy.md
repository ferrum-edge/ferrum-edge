# Dependency & Vendored-Crate Governance

This document is the single policy for how Ferrum Edge manages third-party
dependencies and, in particular, the **vendored, patched copies** of upstream
crates it carries in `vendor/**`. It is the human half of the governance; the
machine half is `deny.toml`, the scheduled `.github/workflows/dependency-audit.yml`
workflow, and the drift guard in `tests/integration/vendor_integrity_tests.rs`.

> TL;DR — vendored patches must be **auditable** (pinned + drift-tested),
> **tracked** (upstream PR + retirement trigger recorded and polled weekly), and
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
| `h3` | 0.0.8 | Drain buffered frames before propagating QUIC `CONNECTION_CLOSE` | issue [hyperium/h3#338](https://github.com/hyperium/h3/issues/338), PR [hyperium/h3#339](https://github.com/hyperium/h3/pull/339) | Ferrum Edge maintainers | io_uring batching of `STREAM(FIN)` + `CONNECTION_CLOSE(H3_NO_ERROR)` dropped a buffered HEADERS frame → false 502 on graceful close | Fix ships in an `h3` release **and** patch 002 is also retired | [docs/upstream-h3-patches/001-…](upstream-h3-patches/001-recv-frame-drain-on-quic-close/README.md) |
| `h3` | 0.0.8 | Add `Protocol::WEB_SOCKET` (RFC 9220 Extended CONNECT) | **not yet filed** (drafts in docs) | Ferrum Edge maintainers | Stock `h3` 0.0.8 rejects `:protocol=websocket` at the HEADERS layer, making WebSocket-over-HTTP/3 unreachable | Upstream files + merges the variant **and** patch 001 is also retired | [docs/upstream-h3-patches/002-…](upstream-h3-patches/002-extended-connect-websocket-protocol/README.md) |
| `tungstenite` | 0.29.0 | `WebSocket::into_inner_with_read_buffer()` (lossless raw takeover) | [snapview/tungstenite-rs#556](https://github.com/snapview/tungstenite-rs/pull/556) | Ferrum Edge maintainers | Tunnel mode lost backend bytes coalesced with the `101` response when dropping to raw relay | **Both** this and tokio-tungstenite#380 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tokio-tungstenite` | 0.29.0 | `WebSocketStream::into_inner_with_read_buffer()` | [snapview/tokio-tungstenite#380](https://github.com/snapview/tokio-tungstenite/pull/380) | Ferrum Edge maintainers | Same lossless-takeover gap on the async wrapper | **Both** this and tungstenite#556 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |

> Ownership note: there is no `CODEOWNERS` file yet. Until one exists, the
> "Ferrum Edge maintainers" own these patches collectively; the upstream `h3`
> work is staged from the `jeremyjpj0916/h3` fork referenced in the h3 patch
> docs. Adding `vendor/`, `deny.toml`, and `docs/upstream-*-patches/` to a
> `CODEOWNERS` entry is recommended.

## Enforcement controls

### 1. Blocking advisory gate (`deny.toml` + CI)

`cargo deny check advisories bans sources` runs on **every PR**
(`dependency-audit` job in `.github/workflows/ci.yml`) and is **blocking**: any
RUSTSEC advisory in the resolved tree that is not explicitly time-boxed in
`deny.toml` fails CI. `bans` (duplicate-version visibility) and `sources`
(crates.io-only) run alongside. License checking is intentionally **not** in the
gate yet — see the `deny.toml` header.

Run locally:

```bash
cargo install --locked cargo-deny
cargo deny check advisories bans sources   # the gate
```

### 2. Advisory exceptions are time-boxed

Every `[advisories.ignore]` entry in `deny.toml` carries a rationale and an
`[expires:YYYY-MM-DD]` token. `scripts/check_advisory_expiry.sh` (run weekly)
fails once any date passes, so an exception cannot silently become permanent —
a maintainer must re-fix the advisory or consciously extend the window.

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

## Procedures

### Adding a vendored patch

1. Confirm a dependency bump / feature flag / gateway workaround can't do it.
2. Copy the locked crates.io source into `vendor/<crate>-<ver>-ferrum-patched/`,
   apply the minimal upstream-proposed diff, and keep the diff reviewable (no
   private Ferrum-only API beyond the proposed surface).
3. Wire it through `[patch.crates-io]` in `Cargo.toml` with a comment block.
4. Add `docs/upstream-<crate>-patches/NNN-…/` with `README.md` (status, upstream
   links, retirement plan), the unified `.patch`, and issue/PR drafts.
5. Add a behavioral regression test for the fixed behavior.
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
