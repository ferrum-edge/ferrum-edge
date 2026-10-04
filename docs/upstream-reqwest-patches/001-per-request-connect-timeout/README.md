# Vendored reqwest patch: per-request `connect_timeout`

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/reqwest-0.13.4-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## What this patches

Adds `RequestBuilder::connect_timeout(Duration)` to reqwest, letting each
outgoing request override the client-level connect timeout. Without this,
the connect timeout is a fixed property of the `reqwest::Client` set at
build time.

## Why ferrum-edge needs it

Ferrum's connection-pool keys exclude **request-only** policy fields like
`backend_connect_timeout_ms` (see `.claude/rules/proxy-protocols.md` pool-key
rules and the reqwest `rcfg` client-behavior suffix for settings that *are*
baked into the shared client). Two proxies that target the same backend and
share the same client-baked `rcfg` share one `reqwest::Client`. Before this
patch, the first proxy to populate a pool entry baked its connect timeout into
the shared client and dictated the timeout for every other proxy reusing it —
cross-proxy policy leakage.

The shipped fix moves both `backend_connect_timeout_ms` and
`backend_read_timeout_ms` to the dispatch-site `RequestBuilder`, where
they're applied per-request and override the (now absent) client default.
`backend_read_timeout_ms` was already there via the existing
`RequestBuilder::timeout()` API; this patch closes the gap for connect.

## Upstream tracking

- PR: <https://github.com/seanmonstar/reqwest/pull/3017>
- Title: *feat: request-scoped connect timeouts*
- Branch: `feat/request-connect-timeout` (head SHA pinned in
  [`reqwest-3017.patch`](reqwest-3017.patch) at fetch time)
- Status as of vendoring: `OPEN`, `mergeStateStatus: BLOCKED`

## Vendored crate

- Path: `vendor/reqwest-0.13.4-ferrum-patched/`
- Base release: reqwest **v0.13.4** (matches the version in `Cargo.lock`
  before vendoring)
- Wired in via `[patch.crates-io]` in the workspace `Cargo.toml`

## Patch fidelity

The historical upstream PR diff (`reqwest-3017.patch`) is preserved verbatim
for filing evidence. The current 0.13.4 vendor source includes that behavior,
patches 002–004 and later local corrections. Apply the complete
[`reqwest-ferrum.patch`](../reqwest-ferrum.patch) to the published archive;
see [the baseline record](../README.md). The historical PR artifact alone
is not sufficient to reconstruct the shipped crate.

## Files copied into `vendor/reqwest-0.13.4-ferrum-patched/`

- `src/` — the entire crate source (with the patch applied)
- `Cargo.toml` — patched to set `autotests = false` and `autoexamples = false`
  and to remove the `[[example]]` / `[[test]]` blocks that pointed at
  files we did not copy. The `dev-dependencies` block is left intact but
  unused.
- `LICENSE-APACHE`, `LICENSE-MIT`, `README.md` — verbatim upstream

`examples/` and `tests/` are intentionally NOT vendored — we depend on
reqwest as a library, not as a test target. Skipping them avoids pulling
in `wasm-bindgen-test` and other transitive dev-deps that are not in our
`Cargo.lock`.

## Retirement plan

When upstream PR #3017 lands and ships in a reqwest release that we want
to consume. The vendored crate also carries patches 002–004, so steps 2–3
wait until those are retired too; until then, drop only this patch's hunks
from the vendored source.

1. **Bump the registry version of reqwest** (`Cargo.toml` `[dependencies]`)
   to whatever release contains the merged PR.
2. **Remove the `reqwest` line** from the `[patch.crates-io]` block in the
   workspace `Cargo.toml` and its mirror in `tests/performance/mesh/Cargo.toml`.
3. **Delete the vendor directory**: `git rm -r vendor/reqwest-0.13.4-ferrum-patched/`,
   then regenerate the drift manifest (`scripts/update_vendor_integrity.sh`).
4. **Retire the governance records**: remove the inventory row in
   `docs/dependency-policy.md` and the entry in
   `docs/vendored-patch-lifecycle.json`, and delete or retire this docs directory
   per the [retirement procedure](../../dependency-policy.md#retiring-a-vendored-patch).
5. **Leave the call-site changes alone.** The proxy-dispatch code in
   `src/proxy/mod.rs`, `src/http3/cross_protocol.rs`, and the absence of
   client-level `.connect_timeout()` in `src/connection_pool.rs` all use
   the upstream API as proposed — once the registry version contains it,
   the call sites need no further changes.
6. **Update any docs** that still reference the vendored patch with a note
   that per-request `connect_timeout` landed upstream in reqwest vX.Y.Z.
7. **Run the regression tests**: `cargo test --test integration_tests
   test_connect_timeout_does_not_fragment_pool
   test_pooled_client_exposes_per_request_connect_timeout`
   (`tests/integration/connection_pool_tests.rs`) — these stay valid and
   continue to guard the contract.

If upstream rejects the PR or the API ships under a different name, port
the call sites to the new API and update step 5 accordingly.

## How to refresh the patch (if needed)

If the upstream PR receives review changes, refresh the diff:

```bash
curl -sL https://patch-diff.githubusercontent.com/raw/seanmonstar/reqwest/pull/3017.diff \
  -o docs/upstream-reqwest-patches/001-per-request-connect-timeout/reqwest-3017.patch
```

Then in a scratch clone of `seanmonstar/reqwest` at tag `v0.13.4`, re-apply
the diff together with patches 002–004, copy `src/` over the vendored
directory, regenerate the drift manifest, and re-run `cargo build --lib && cargo test --test unit_tests
&& cargo test --test integration_tests`.
