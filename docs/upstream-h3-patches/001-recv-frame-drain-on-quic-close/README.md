# Patch 001 — h3 frame drain on QUIC close

## Status

| Field | Value |
|---|---|
| Patch ID | 001-recv-frame-drain-on-quic-close |
| Target crate | `h3` |
| Target version | 0.0.8 (forward-ports cleanly to master at the time of writing) |
| State | **Applied via vendored crate at `vendor/h3-0.0.8-ferrum-patched`** |
| Upstream issue | [hyperium/h3#338](https://github.com/hyperium/h3/issues/338) |
| Upstream PR | [hyperium/h3#339](https://github.com/hyperium/h3/pull/339) |
| Local fork | https://github.com/jeremyjpj0916/h3 (branch: `fix/recv-frame-drain-on-quic-close`) |
| Tracks | [ferrum-edge#506](https://github.com/ferrum-edge/ferrum-edge/pull/506) — gateway-side suppression (correct independently of this patch; see "Relationship to PR #506" below) |

## Why this directory exists

PR #506 ships a gateway-side suppression for the recv_response graceful-close race (don't penalize the backend's H3 capability, don't bypass `retryable_methods`, opt-in retry via `retryable_status_codes: [502]`). That suppression is correct on its own merits, but the 502 itself is a symptom of an upstream library limitation — fixed by the patch in this directory and currently shipped via a vendored crate. This directory captures the upstream artifacts so we can:

1. File the issue + PR upstream (artifacts ready in `issue.md` / `pr-description.md` / `h3-frame-rs.patch`)
2. Track when it merges
3. Cleanly retire the vendored copy once a registry release contains the fix
4. Audit-trail the change while it lives in `vendor/h3-0.0.8-ferrum-patched/`

## Files

| File | Purpose |
|---|---|
| `issue.md` | Bug report for hyperium/h3. Paste into a new GitHub issue verbatim. |
| `pr-description.md` | PR description for the fix. Submit alongside the patch. |
| `h3-frame-rs.patch` | Unified diff against `h3 0.0.8` (`h3/src/frame.rs`). Should forward-port to master with minimal effort. |

## Hand-off — how to file the upstream issue + PR

The patch is currently shipped via the vendored crate at `vendor/h3-0.0.8-ferrum-patched/` and wired in via `[patch.crates-io]` in the workspace `Cargo.toml`. The artifacts in this directory exist so we can submit the same fix upstream and ultimately retire the vendor copy. To file the upstream work:

1. **Open the issue.** GitHub → hyperium/h3 → New issue → paste `issue.md`. Capture the issue number.
2. **Update `pr-description.md`** — replace the `Fixes #NNN` placeholder with the real number.
3. **Push the fork branch.**
   ```bash
   # The fork exists at https://github.com/jeremyjpj0916/h3 (already created).
   # Clone (or use the existing local checkout at /Volumes/JustusStorage/Claude/ferrum-edge/h3-fork):
   git clone https://github.com/jeremyjpj0916/h3.git
   cd h3
   git checkout -b fix/recv-frame-drain-on-quic-close

   # Apply the patch. NOTE: the diff is against h3 0.0.8. If master has
   # diverged in frame.rs, the patch tool will reject; in that case
   # forward-port by hand (the change is ~30 lines and structural).
   git apply <ferrum-edge>/docs/upstream-h3-patches/001-recv-frame-drain-on-quic-close/h3-frame-rs.patch

   cargo test -p h3   # confirm both new tests pass and existing tests still pass

   git add -A
   git commit -F <ferrum-edge>/docs/upstream-h3-patches/001-recv-frame-drain-on-quic-close/pr-description.md
   git push origin fix/recv-frame-drain-on-quic-close
   ```
4. **Open the PR** at https://github.com/hyperium/h3/compare/master...jeremyjpj0916:fix/recv-frame-drain-on-quic-close — paste `pr-description.md` as the body. Link the issue.
5. **Update this README** with the issue + PR numbers under "Status" so future readers can find them.

## How we vendored — historical record

We vendored the patched h3 crate into the build because the upstream merge timeline was unknown and we wanted to eliminate the 502 itself in addition to PR #506's gateway-side suppression (which on its own already shipped safe behavior — no spurious capability downgrades; well-defined retry semantics for the 502). The reproduction steps that produced the current vendored copy:

```bash
# In a fresh worktree off ferrum-edge main:
git checkout -b vendor/h3-frame-drain-patch

mkdir -p vendor
cp -R ~/.cargo/registry/src/index.crates.io-*/h3-0.0.8 vendor/h3-0.0.8-ferrum-patched
cd vendor/h3-0.0.8-ferrum-patched
git apply <ferrum-edge>/docs/upstream-h3-patches/001-recv-frame-drain-on-quic-close/h3-frame-rs.patch
cd -

# Wire Cargo.toml (project root):
# Add at the bottom:
#
# [patch.crates-io]
# h3 = { path = "vendor/h3-0.0.8-ferrum-patched" }

cargo build --lib
cargo test --test unit_tests
cargo test --test integration_tests
cargo build --bin ferrum-edge && cargo test --test functional_tests h3 -- --ignored

git add Cargo.toml vendor/
git commit -m "Vendor h3 with frame-drain-on-quic-close patch (tracks hyperium/h3#NNN)"
```

With the vendored crate in place, the gateway-side suppression in PR #506 still applies (it's the right behavior independently — graceful closes shouldn't downgrade backend capability), and the 502 itself goes away because `recv_response` now drains buffered HEADERS instead of erroring. Inline regression tests in `vendor/h3-0.0.8-ferrum-patched/src/frame.rs` (`poll_next_drains_buffered_headers_before_quic_close`, `poll_data_drains_buffered_body_before_quic_close`) cover the fix at the library layer, and `poll_data_surfaces_stream_reset_over_a_truncated_buffered_body` / `poll_next_surfaces_stream_reset_over_a_buffered_frame` pin the stream-reset exemption described under "Changing the patch design before submission".

## Retirement — when upstream merges

Once `hyperium/h3` releases a version with the fix:

1. **Update the registry floor.** Bump `h3 = "X.Y.Z"` in `Cargo.toml` `[dependencies]` to the version that includes the fix.
2. **Drop the vendored crate** (mandatory — currently in use):
   - Remove the `h3 = { path = "vendor/h3-0.0.8-ferrum-patched" }` line from the `[patch.crates-io]` block at the bottom of `Cargo.toml`. If `reqwest` (the other `[patch.crates-io]` entry) is also retired by then and the block becomes empty, drop the block + its comment header too.
   - `git rm -r vendor/h3-0.0.8-ferrum-patched`. If `vendor/` becomes empty (i.e., the reqwest vendor was already retired), delete it too.
   - `cargo build` — confirm we're now pulling h3 from crates.io and the registry version is being resolved.
   - `cargo test --test unit_tests && cargo test --test integration_tests && cargo build --bin ferrum-edge && cargo test --test functional_tests -- --ignored` — confirm the registry version still passes regression tests for the graceful-close race (the inline regression tests we added live in the vendored frame.rs and disappear with it; the upstream version is expected to carry equivalents).
3. **Leave PR #506's gateway-side suppression in place.** It's correct behavior independently of the upstream fix:
   - `mark_h3_unsupported` should not fire for graceful closes regardless of whether we can recover the response.
   - `connection_error=false` for `GracefulRemoteClose` is the right contract — the request reached the wire.
   - The retry semantics, CB semantics, and passive-health semantics that PR #506 nailed down are correct on their own merits.
   The upstream fix removes the SYMPTOM (the 502 at recv_response when HEADERS are buffered); the gateway-side change ensures we behave correctly in the failure modes that DO remain (e.g., the recv_response close happens BEFORE any HEADERS bytes are buffered, which the upstream fix can't recover either).
4. **Update CLAUDE.md** — the "Backend Capability Registry" / "Upstream h3 fix tracked separately" paragraph references the vendored crate (`vendor/h3-0.0.8-ferrum-patched`); replace that with a note that the fix landed upstream in h3 vX.Y.Z.
5. **Update `docs/http3.md`** — remove any "this still 502s" caveat once normal responses survive the race.
6. **Move this directory to `docs/upstream-h3-patches/_retired/001-recv-frame-drain-on-quic-close/`** with a `STATUS.md` noting the merge commit and version. Keeps the audit trail without cluttering the active patches list. If `docs/upstream-h3-patches/` becomes empty (no other active patches and no `_retired/` content you want to surface), tidy as appropriate.

## Changing the patch design before submission

If a reviewer (us, or upstream) wants to change the approach, edit `h3-frame-rs.patch` and re-test. The structural choices in the current draft:

- **Hoist the error to a local variable** rather than mutate state on `FrameStream`: the cached error lives one stack frame, doesn't outlive the iteration, and doesn't introduce a new persistent state machine.
- **Drain ONCE per iteration** rather than loop-until-empty: terminates without proof obligations.
- **Apply to BOTH `poll_next` and `poll_data`**: same shape, same fix; addressing only one would leave the body path leaky.
- **`FakeRecv::chunk_then_error` helper instead of a separate fake**: keeps existing tests untouched and minimizes the test surface for review.
- **Never hoist a peer `RESET_STREAM`** (`FrameStreamError::is_stream_reset`, ferrum-edge#5741): the hoist assumes the held-back error is reported again on the next read, which holds for a connection error but not for a stream reset. Quinn reports `ReadError::Reset` exactly once and frees the receive stream as it does, so every later read is `ClosedStream`. The first draft held a reset back like any other error, which lost the reset code whenever buffered bytes were drained first. Worse, when the reset truncated a DATA frame whose tail was still buffered, `poll_data` returned `UnexpectedEnd`, which the request stream escalates to a connection-level `H3_FRAME_ERROR` ("received incomplete frame") that tears down every other stream on the connection. RFC 9114 §7.1 makes a truncated frame a connection error only for a stream that "terminates cleanly". A stream reset now surfaces on the poll that observed it, ahead of buffered bytes: that is stock h3 behaviour, and Quinn itself discards unread data on a reset (RFC 9000 §3.2). The gateway hit this as an HTTP/3 client reading a response cut by the route deadline while the reader was stalled in flow control (`tests/functional/functional_h3_local_policy_test.rs::functional_h3_route_request_timeout_cuts_a_client_that_stops_reading`). The same defect hit the gateway as a server (a client resetting a request body mid-frame) and as an H3 backend client (a backend resetting a response mid-frame).

Alternative designs considered and rejected:

- *Fix in quinn-proto* — quinn already does the right thing; the bug is at h3's frame layer.
- *Fix in h3-quinn's `RecvStream::poll_data`* — would re-shape the API contract between quinn and h3-quinn, larger surface area.
- *Stash the error on `FrameStream` itself as a new `pending_close_error: Option<StreamErrorIncoming>` field* — works but reintroduces a question of "when do we forget the error?" Local-variable hoist is simpler.

## Relationship to PR #506

The gateway-side suppression in PR #506 is correct independently of this patch — it ensures `mark_h3_unsupported` doesn't fire on graceful closes, that `connection_error=false` for `GracefulRemoteClose` matches the "request reached the wire" contract, and that retry/CB/passive-health semantics behave correctly when the close happens before any HEADERS are buffered (which the vendored fix can't recover from anyway). Vendoring the patched h3 in addition eliminates the 502 itself for the buffered-HEADERS-then-graceful-close shape; the two changes compose rather than replace one another.
