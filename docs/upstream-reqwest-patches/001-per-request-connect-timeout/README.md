# Vendored reqwest patch: per-request `connect_timeout`

## What this patches

Adds `RequestBuilder::connect_timeout(Duration)` to reqwest, letting each
outgoing request override the client-level connect timeout. Without this,
the connect timeout is a fixed property of the `reqwest::Client` set at
build time.

## Why ferrum-edge needs it

Ferrum's connection-pool keys intentionally exclude policy fields like
`backend_connect_timeout_ms` (see CLAUDE.md > "Connection Pool Keys"
> "Pool-key contract"). Two proxies that target the same backend share
one `reqwest::Client`. Before this patch, the first proxy to populate a
pool entry baked its connect timeout into the shared client and dictated
the timeout for every other proxy reusing it — cross-proxy policy leakage.

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

- Path: `vendor/reqwest-0.13.2-ferrum-patched/`
- Base release: reqwest **v0.13.2** (matches the version in `Cargo.lock`
  before vendoring)
- Wired in via `[patch.crates-io]` in the workspace `Cargo.toml`

## Patch fidelity

The upstream PR diff (`reqwest-3017.patch`) was authored against
reqwest's `master` branch. v0.13.2 was tagged earlier, so two log-line
context strings differ from `master`:

| File              | Upstream context (master)                                    | v0.13.2 context                                          |
| ----------------- | ------------------------------------------------------------ | -------------------------------------------------------- |
| `src/connect.rs`  | `log::debug!("proxy({proxy:?}) intercepts '{:?}'", dst.host());` | `log::debug!("proxy({proxy:?}) intercepts '{dst:?}'");` |
| `src/connect.rs`  | `log::debug!("starting new connection '{:?}'", dst.host());` | `log::debug!("starting new connection: {dst:?}");`      |

Both are unrelated cleanups; the patch itself is identical apart from
those two context lines. The applied patch in the vendor directory uses
the v0.13.2 context. The original PR diff is preserved verbatim in
`reqwest-3017.patch` for audit purposes.

No other deviations.

## Files copied into `vendor/reqwest-0.13.2-ferrum-patched/`

- `src/` — the entire crate source (with the patch applied)
- `Cargo.toml` — patched to set `autotests = false` and `autoexamples = false`
  and to remove the `[[example]]` / `[[test]]` blocks that pointed at
  files we did not copy. The `dev-dependencies` block is left intact but
  unused.
- `LICENSE-APACHE`, `LICENSE-MIT`, `README.md`, `CHANGELOG.md` — verbatim
  upstream

`examples/` and `tests/` are intentionally NOT vendored — we depend on
reqwest as a library, not as a test target. Skipping them avoids pulling
in `wasm-bindgen-test` and other transitive dev-deps that are not in our
`Cargo.lock`.

## Retirement plan

When upstream PR #3017 lands and ships in a reqwest release that we want
to consume:

1. **Bump the registry version of reqwest** (`Cargo.toml` `[dependencies]`)
   to whatever release contains the merged PR.
2. **Drop the `[patch.crates-io]` block** from the workspace `Cargo.toml`
   (the block is at the bottom of the file, separated by a comment header).
3. **Delete the vendor directory**: `rm -rf vendor/reqwest-0.13.2-ferrum-patched/`.
   If `vendor/` becomes empty, delete it too.
4. **Delete this docs directory**: `rm -rf docs/upstream-reqwest-patches/001-per-request-connect-timeout/`.
   If `docs/upstream-reqwest-patches/` becomes empty, delete it too.
5. **Leave the call-site changes alone.** The proxy-dispatch code in
   `src/proxy/mod.rs`, `src/http3/cross_protocol.rs`, and the absence of
   client-level `.connect_timeout()` in `src/connection_pool.rs` all use
   the upstream API as proposed — once the registry version contains it,
   the call sites need no further changes.
6. **Update CLAUDE.md** if the "Connection Pool Keys > Policy cross-proxy
   sharing" paragraph still references the vendored patch. Replace the
   `vendor/...` reference with a note that per-request `connect_timeout`
   landed upstream in reqwest vX.Y.Z.
7. **Run the regression test**: `cargo test --test integration_tests
   connection_pool::test_connect_timeout_does_not_fragment_pool
   connection_pool::test_pooled_client_exposes_per_request_connect_timeout`
   — these stay valid and continue to guard the contract.

If upstream rejects the PR or the API ships under a different name, port
the call sites to the new API and update step 5 accordingly.

## How to refresh the patch (if needed)

If the upstream PR receives review changes, refresh the diff:

```bash
curl -sL https://patch-diff.githubusercontent.com/raw/seanmonstar/reqwest/pull/3017.diff \
  -o docs/upstream-reqwest-patches/001-per-request-connect-timeout/reqwest-3017.patch
```

Then in a scratch clone of `seanmonstar/reqwest` at tag `v0.13.2`,
re-apply with the v0.13.2 context fixes, copy `src/` over the vendored
directory, and re-run `cargo build --lib && cargo test --test unit_tests
&& cargo test --test integration_tests`.
