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
| Tracks | [ferrum-edge#506](https://github.com/ferrum-edge/ferrum-edge/pull/506) — gateway-side suppression that compensates while this is unfixed |

## Why this directory exists

PR #506 ships a gateway-side workaround for the recv_response graceful-close race (don't penalize the backend's H3 capability, don't bypass `retryable_methods`, opt-in retry via `retryable_status_codes: [502]`). The 502 to the client at recv_response is unavoidable at the gateway level — it's a symptom of an upstream library limitation. This directory captures the upstream fix as deliverable artifacts so we can:

1. File the issue + PR upstream
2. Track when it merges
3. Optionally vendor in the meantime
4. Cleanly retire the workaround once the fix is widely available

## Files

| File | Purpose |
|---|---|
| `issue.md` | Bug report for hyperium/h3. Paste into a new GitHub issue verbatim. |
| `pr-description.md` | PR description for the fix. Submit alongside the patch. |
| `h3-frame-rs.patch` | Unified diff against `h3 0.0.8` (`h3/src/frame.rs`). Should forward-port to master with minimal effort. |

## Hand-off — how to file the upstream issue + PR

This PR (#506) does NOT contain a working active patch — the parallel session that produced these artifacts hit permission boundaries on (a) pushing to a fork branch and (b) vendoring external code into the trusted build. To complete the upstream work:

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

## Optional — vendor the patched h3 into ferrum-edge while we wait

This is opt-in. The upstream merge timeline is unknown, and PR #506's gateway-side suppression is sufficient to ship correctness in the meantime (no spurious capability downgrades; well-defined retry semantics for the 502). If we want to additionally eliminate the 502 itself, we can vendor the patched h3:

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

After vendoring, the gateway-side suppression in PR #506 still applies (it's the right behavior independently — graceful closes shouldn't downgrade backend capability), but the 502 itself goes away because `recv_response` now drains buffered HEADERS instead of erroring. Inline tests in `tests/integration/http3_integration_tests.rs` that simulate the race (e.g., the `h3_buffered_response_survives_graceful_close_race` style) should switch from "expect 502 + Supported capability" to "expect 200 + Supported capability." Update assertions accordingly.

## Retirement — when upstream merges

Once `hyperium/h3` releases a version with the fix:

1. **Update the floor.** Bump `h3 = "X.Y.Z"` in `Cargo.toml` to the version that includes the fix.
2. **If we vendored:**
   - Remove the `[patch.crates-io] h3 = ...` line from `Cargo.toml`.
   - `git rm -r vendor/h3-0.0.8-ferrum-patched`.
   - `cargo build` — confirm we're now pulling from crates.io.
3. **Decide whether to remove PR #506's gateway-side suppression.** Don't. It's correct behavior independently of the upstream fix:
   - `mark_h3_unsupported` should not fire for graceful closes regardless of whether we can recover the response.
   - `connection_error=false` for `GracefulRemoteClose` is the right contract — the request reached the wire.
   - The retry semantics, CB semantics, and passive-health semantics that PR #506 nailed down are correct on their own merits.
   The upstream fix removes the SYMPTOM (the 502 at recv_response); the gateway-side change ensures we behave correctly in the failure modes that DO remain (e.g., the recv_response close happens BEFORE any HEADERS bytes are buffered, which the upstream fix can't recover either).
4. **Update `docs/http3.md`'s "Graceful close handling at recv_response" section** to remove the "this still 502s" caveat — once vendored / upstreamed, normal responses survive the race.
5. **Move this directory to `docs/upstream-h3-patches/_retired/001-recv-frame-drain-on-quic-close/`** with a `STATUS.md` noting the merge commit and version. Keeps the audit trail without cluttering the active patches list.

## Changing the patch design before submission

If a reviewer (us, or upstream) wants to change the approach, edit `h3-frame-rs.patch` and re-test. The structural choices in the current draft:

- **Hoist the error to a local variable** rather than mutate state on `FrameStream`: the cached error lives one stack frame, doesn't outlive the iteration, and doesn't introduce a new persistent state machine.
- **Drain ONCE per iteration** rather than loop-until-empty: terminates without proof obligations.
- **Apply to BOTH `poll_next` and `poll_data`**: same shape, same fix; addressing only one would leave the body path leaky.
- **`FakeRecv::chunk_then_error` helper instead of a separate fake**: keeps existing tests untouched and minimizes the test surface for review.

Alternative designs considered and rejected:

- *Fix in quinn-proto* — quinn already does the right thing; the bug is at h3's frame layer.
- *Fix in h3-quinn's `RecvStream::poll_data`* — would re-shape the API contract between quinn and h3-quinn, larger surface area.
- *Stash the error on `FrameStream` itself as a new `pending_close_error: Option<StreamErrorIncoming>` field* — works but reintroduces a question of "when do we forget the error?" Local-variable hoist is simpler.

## Why this isn't applied to our build

Per the discussion that produced this artifact set, the permission system in our worktree treats vendoring external crates and pushing to fork branches as actions requiring explicit per-action confirmation, even when the prior conversation authorized them. The maintainer can complete steps 3+ above with their own credentials and a freshly-permissioned session.

The gateway-side fix in PR #506 already ships safe behavior — the upstream patch is a strict improvement, not a correctness prerequisite.
