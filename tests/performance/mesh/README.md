# In-Process Performance Suite

In-process micro-benches for Ferrum Edge mesh and core policy hot paths. This
standalone crate (not a workspace member of the root `ferrum-edge` crate)
depends on the root crate by path so benches exercise the production public API.

Driven by [criterion](https://bheisler.github.io/criterion.rs/book/) — each bench parameterises over input size and emits an HTML report under `target/criterion/`.

## Quick start

```bash
cd tests/performance/mesh

# Run every bench
cargo bench

# Run a single bench
cargo bench --bench authz_match
cargo bench --bench ip_restriction

# Filter inside a bench
cargo bench --bench slice_apply -- "workloads/1000"

# Convenience wrapper
./run.sh             # all benches
./run.sh authz_match # one bench
./run.sh ip_restriction # large IP-policy lookup bench
./run.sh --skip-build authz_match  # reuse prior build artefacts
```

## Benches included

| Bench | Hot path measured | Why it matters |
|---|---|---|
| `authz_match` | `policy::evaluate_mesh_authorization_policies` over N policies | Mesh authz runs on every request through `mesh_authz`. Scaling characteristics of the linear policy scan matter when fleets ship thousands of `AuthorizationPolicy` resources. |
| `ip_restriction` | One or four `ip_restriction` instances evaluating a 10,000-rule miss or final-interval match | Guards the allocation-free indexed lookup promised by issue #2322 across supported multiple-instance composition. |
| `slice_apply` | `MeshSlice::from_gateway_config(&GatewayConfig, MeshSliceRequest)` over N workloads | Slice build cost dominates the latency budget when an xDS / native CP pushes a fresh slice; this is the cold-path that runs under the ArcSwap apply. |
| `xds_translation` | `xds::translator::translate_mesh_slice_to_snapshot(&MeshSlice)` over N workloads | Control-plane translation cost shared by every connected DP; the snapshot cache dedupes by content fingerprint downstream of this call. |

Most benches parameterise over input size: typically `[10, 100, 1_000, 10_000]`
for in-process traversals and `[100, 1_000, 5_000]` for slice / translation
paths. `ip_restriction` fixes the representative rule count at 10,000 and
parameterises over worst-case decision shape and attached instance count.

## Benches deferred (not yet implemented)

- **HBONE tunnel throughput** — requires a full mesh-mode gateway + mTLS peer. Belongs in a follow-up E2E suite that mirrors `tests/performance/multi_protocol/` (load gen → ferrum-edge → echo backend) rather than a criterion micro-bench.
- **DNS proxy resolution latency** — `dns_proxy.rs` evaluates resolution inside a UDP/TCP server task. A meaningful bench needs the server spun up and queried over the wire; in-process micro-benching the lookup table alone would understate the real cost.

Open follow-ups in `.context/mesh-audit/SP.md` track both deferrals.

## Reading results

Criterion writes:
- Console summary per bench (mean ± stddev, change vs baseline).
- HTML report at `target/criterion/<bench>/<id>/report/index.html`.
- Baseline snapshots stored under `target/criterion/<bench>/<id>/base/`.

`run.sh` does NOT clean `target/` so results accumulate across runs — `cargo criterion baseline` semantics work as documented in the criterion book.

A coarse one-shot baseline taken on the author's machine is checked in at [`baseline.md`](./baseline.md). It is **directional**, not authoritative — operator-specific hardware will see different numbers.

## Architecture decisions recorded

- **Standalone crate, not workspace member.** Same call as `tests/performance/multi_protocol/`. Keeps bench-only deps (criterion) out of the root manifest; isolates the target dir.
- **Root dependency patches mirrored locally.** Standalone manifests do not inherit the root `[patch.crates-io]` table, so this crate mirrors its vendored overrides and keeps the corresponding lockfile entries synchronized. This ensures benchmarks compile and measure the same patched production dependencies as the root crate.
- **Criterion, not `cargo bench` built-in.** Statistical sampling + change detection is non-negotiable for performance regression work; the unstable `test::Bencher` does not provide it.
- **Public API only, no `#[doc(hidden)]` perf hatches.** Every bench calls a function that already has a `pub` visibility for the audit / mesh runtime path. If a future hot path is only reachable through private code, the right answer is an inline `#[cfg(test)]` bench in the source file (per CLAUDE.md "do NOT promote fns to `pub` to enable external tests"), not a hatch here.

## Extending

Add a new bench:
1. Create `benches/<name>.rs` exporting `criterion_main!(benches)`.
2. Add `[[bench]] name = "<name>" harness = false` to `Cargo.toml`.
3. Document it in this README's table.
4. Capture a baseline number into `baseline.md` (hosted CI may leave a new row
   as `_TBD_` until a provenance-complete reference run is selected).
