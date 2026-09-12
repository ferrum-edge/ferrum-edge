# Moving BuildKit cache to GHCR

The Actions cache allowance remains 10 GB and the organization keeps its $0 budgets. GHCR container storage and bandwidth are currently free under GitHub's published policy; this is not a permanent capacity guarantee. Moving Docker build layers frees Actions cache space for compiler and fuzz data, but those remaining caches still need retention measurements.

## Original Ambient policy transition

The first change adds an exact second generation to the trusted Cross policy and leaves the active workflows unchanged. Its hosted candidate-policy self-test validates both generations and rejects partial adoption. Once that policy is reviewed and merged, a workflow change can adopt the registry generation through the ordinary PR gates.

The registry generation splits the Ambient image recipe into two mutually exclusive jobs:

- `ambient-host-udp-image-read` runs for relevant PRs, merge groups, and non-main dispatches. It has only `contents: read`, no registry login, and imports cache anonymously.
- `ambient-host-udp-image-write` runs only for relevant `push` or `workflow_dispatch` events on `ferrum-edge/ferrum-edge` main. It uses job-scoped `packages: write` and the existing pinned GHCR login action.
- The existing `ambient-host-udp-image` job becomes an aggregate. It requires successful planning, the selected recipe to pass, and the other recipe to be skipped. The outer required `Ambient Host UDP Live` gate and the kernel job remain unchanged.

Both recipes keep all three image builds, the `pr-build` profile, the tools runtime checks, and the distroless checks. Checkout does not persist credentials. The recipes use distinct references in `ghcr.io/ferrum-edge/ferrum-edge-buildcache` for `capture-tools-base`, `runtime-ebpf-tools`, and `runtime-ebpf`, with `ambient-v1-linux-amd64-` tag prefixes. They do not publish shipping images or alter release tags. A missing import performs a cold build; an export failure fails the writer.

## Activation and verification

Before considering migration complete, publish the dedicated cache package from trusted main and verify its repository connection and **public** visibility. New GHCR packages default to private; a public source repository alone does not establish anonymous package access. Verify an anonymous manifest fetch and an ordinary fork-compatible reader import without saved registry credentials. Do not change shipping package visibility as a substitute.

Update the runtime-cache verifier and CI documentation with the workflow activation. Measure hosted cold build, export, subsequent import, total job time, and cache size. Preserve all existing required checks. Check image targets separately so one cache reference cannot replace another target's graph. Record concurrent-writer behavior and retain current references when adding a scoped cache-version retention rule; do not delete shipping packages.

After the supported generation is active and verified, retire the old Actions-cache generation in a follow-up policy change. The NodeWaypoint eBPF smoke now shares Ambient’s registry cache. Its ordinary runtime uses the separate reader/writer contract below. The manual protocol benchmark remains a separate follow-up.

Keep issue #4643 open until Unit, Lint, and test-artifact lanes restore retained caches after a subsequent main push. Fuzz cache retention and the monolithic unit compilation footprint remain separate measurements.

Sources: [GitHub Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages), [Container registry permissions and visibility](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry), [Docker registry cache](https://docs.docker.com/build/cache/backends/registry/).

## NodeWaypoint ordinary runtime

The default image uses `default-v1-linux-amd64-runtime` in the existing public
`ferrum-edge-buildcache` package. It removes the roughly 2.37 GB Actions archive
previously written for each main commit. No existing cache is deleted by this
change; old Actions entries expire under LRU.

The ordinary reader and writer retain the same `Dockerfile`, `runtime` target,
`pr-build` profile, version invocation and complete distroless inventory.
Trusted main pushes and main manual dispatches alone select the writer with
`packages: write`. PRs, merge groups and other dispatches select the anonymous
reader. The aggregate rejects a failed selected recipe or an unexpectedly
executed unused recipe. The complete two recipes and aggregate are frozen in
the Cross policy, with runtime-cache mutation coverage for their boundaries.

`force_cold_cache` omits login, import and export on both recipes. Warm writer
export failure fails CI. A missing import can build cold, and each reader
still builds and checks its own source. Concurrent trusted push/manual writers
may replace the same tag; BuildKit validates input keys and never reuses a test
verdict. Last-writer cache coverage may vary, so record actual reuse in logs.

After adoption, verify one trusted-main writer and a subsequent anonymous PR
reader before claiming the migration active. Also run the explicit cold path.
Record elapsed build/import/export time and layer reuse, then recheck Actions
cache retention across later main writes. This does not complete native Rust
compiler-store integration or issues #4643/#4694 by itself. Package visibility,
Actions capacity and spending controls remain unchanged.
