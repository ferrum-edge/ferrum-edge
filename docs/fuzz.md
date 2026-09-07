# Adversarial fuzz and property-testing lane

Ferrum Edge carries a **separate** `fuzz/` cargo-fuzz workspace for hostile-input
testing of pure parsers and validators. libFuzzer, nightly, and `proptest` live
only under `fuzz/` — the production `ferrum-edge` binary does not depend on them.

## Targets and invariants

| Target | Surface | Budgets | Invariants |
|--------|---------|---------|------------|
| `traceparent` | W3C `traceparent` parse | 64 KiB input | Fail closed (`None`); accepted values round-trip |
| `config_decode` | YAML/JSON config decode + validation | 64 MiB doc (loader cap), 64 KiB fuzz input | No panic; validation errors only |
| `proxy_protocol` | PROXY v1/v2 header parse | 528-byte header cap | Fail closed; bounded address block |
| `datagram_client_address` | Datagram PROXY v2 DGRAM header + auth/freshness TLV walk + freshness record decode | 512-byte address-block cap, 64 KiB fuzz input (both hosted lanes) | Fail closed; bounded TLV walk; exactly-one auth and freshness TLV; fixed-length freshness value; no secret/tag/sequence/address output |
| `mesh_udp_frame` | HBONE datagram framing | 64 KiB input, 256 frames/invocation | Length prefix bounded; encode/decode round-trip |
| `k8s_crd` | Istio/Gateway API JSON → translation | 32 objects, depth 64 | Fail-closed translation errors |
| `plugin_config` | Representative plugin JSON validation (one selector byte followed by JSON) | depth 64 | `validate_plugin_config` never panics |

The `datagram_client_address` target parses attacker-controlled UDP bytes
entirely **before** the MAC decision, so it is scheduled in **both** required
lanes (issue #4442): the `.github/workflows/fuzz.yml` sanitizer matrix and its
shell allowlist, and the byte-frozen `fuzz-smoke` bounded budget in
`.github/workflows/ci.yml`. Its entry point walks the header, both
application-reserved TLVs (`0xE0` authentication tag, `0xE1` freshness record),
and — when a freshness TLV is present — the fixed-length freshness value.

Both lanes run it at `-max_len=65536`, the target's documented 64 KiB budget
(`fuzz_support::MAX_FUZZ_INPUT_BYTES`), rather than the smoke loop's generic
4 KiB ceiling: a parser whose length boundaries are reachable in one required
lane and unreachable in the other is not actually scheduled. In the smoke job
it is therefore its own invocation rather than a seventh entry in the
six-target loop; every other bound (`-runs=512`, `-max_total_time=8`,
`-timeout=2`, `-rss_limit_mb=1024`) matches the loop's.

The synthetic corpus covers valid IPv4/IPv6 DGRAM envelopes, `LOCAL` and
`AF_UNSPEC`, an unsupported (`AF_UNIX`) and an undefined address family, a
truncated header, a TLV whose declared length runs past the address block,
duplicate authentication and duplicate freshness TLVs, a wrong-length freshness
value, and an authenticated-shape envelope (freshness + tag TLVs).

Because the whole `fuzz-smoke` job is byte-frozen, scheduling the target
required a new admitted generation of that job rather than an edit, and the
`fuzz.yml` whole-file freeze had to move with it. That is a direct-to-`main`
trusted-policy change; no pull request can carry it.

Shared budgets and helpers live in `src/fuzz_support.rs`.

## Corpora

Seed only **synthetic boundary cases** under `fuzz/corpus/`. Never commit
production configs, JWTs, TLS material, or packet captures. The hosted workflow
rejects crash artifacts larger than 64 KiB before upload.

## Hosted CI

- **PR gate** (`ci.yml` → `Fuzz Smoke`): the locked `proptest` smoke tests
  (`cargo test --locked` in `fuzz/`). This is the required full-mode
  pull-request gate and runs on every full-mode pull request.
- **Bounded libFuzzer budget** (same `Fuzz Smoke` job, `if: github.event_name ==
  'push' || github.event_name == 'workflow_dispatch'`): six targets at ~8 s each
  (`-runs=512`, `-max_total_time=8`, `-max_len=4096`, `-timeout=2`,
  `-rss_limit_mb=1024`), then `datagram_client_address` at the same bounds with
  `-max_len=65536` (issue #4442). It runs on the push to `main` and on manual
  `workflow_dispatch` of `ci.yml` only. The bounds are byte-identical to what
  pull requests used to run; only *where* the budget executes changed (#3902
  took it off `pull_request` for cost, #4238 off `merge_group` for blast
  radius). Every merged change still reaches the budget seconds later through
  the push to `main`, which is also the only event permitted to populate this
  lane's cache.
- **Scheduled sanitizer lane** (`.github/workflows/fuzz.yml`): AddressSanitizer
  builds of all seven targets, 300 s per target at `-max_len=65536`, bounded
  crash artifacts uploaded after size/count checks, a 2048 MiB RSS cap, 7-day
  retention, and concurrency capped at two targets. Unchanged by #3902/#4238.

`cargo fuzz run` defaults to AddressSanitizer, so the bounded budget is a
sanitizer build in both lanes. That build, not the fuzzing, was the cost: the
`Fuzz Smoke` job averaged ~47 minutes on pull requests, of which ~39 minutes was
compiling the instrumented targets for ~48 seconds of fuzzing. The `Fuzz Smoke`
job now uses the repository's checksum-pinned `setup-sccache` action and
persists its bounded local cache directory through `Swatinem/rust-cache`.
`save-if` is strictly `${{ github.event_name == 'push' && github.ref ==
'refs/heads/main' }}`: pull requests (including same-repository PR refs and
forks), `merge_group`, and `workflow_dispatch` never publish a `fuzz-smoke`
cache. The generation that predates #3902 had no `save-if` at all, which is how
a full-mode predecessor PR could still mint a PR-ref Fuzz cache; neither
admitted generation can create another.
The credential-bearing sccache GHA backend is never enabled. Every run logs
`Fuzz property smoke seconds`, the lane shape it took, a closing
`sccache --show-stats`, and the on-disk cache size; runs that execute the
sanitizer budget add a second `--show-stats` just before it plus `Fuzz
sanitizer lane seconds`, so the log shows directly whether the sanitizer build
reused compilation. When sccache is unavailable the job emits a warning
annotation rather than letting caching fail silently.

Both hosted shapes are byte-frozen by the trusted Cross build policy. The
`fuzz-smoke` job is admitted as two generations with a one-way transition
(`CI_FUZZ_SMOKE_JOB_GENERATIONS`); see
[ci_cd.md](ci_cd.md#admitted-fuzz-smoke-lane-split-generation).

The fuzz crate links the main Ferrum Edge crate, whose Kafka dependency builds
`librdkafka` from source with OAuthBearer OIDC disabled. librdkafka 2.12.1
nevertheless includes `curl/curl.h` because one preprocessor guard tests whether
the disabled macro is defined instead of whether it is enabled. The isolated
fuzz dependency graph therefore activates `rdkafka`'s `curl-static` feature and
uses its real vendored curl headers. Production builds retain their existing
feature set, while the byte-frozen hosted workflows avoid relying on ambient
curl development headers or a nested Cargo configuration. They still install
the pinned workflow's required `protobuf-compiler` build dependency.

## Local workflow (optional)

Local builds are not required; GitHub Actions is the gate. When investigating a
crash locally:

```bash
cd fuzz
rustup toolchain install nightly-2025-07-01
cargo install cargo-fuzz --locked --version 0.13.1
cargo fuzz run traceparent corpus/traceparent/ -- -runs=0   # replay seeds
cargo fuzz run traceparent -- -max_total_time=60
```

Use only synthetic inputs. Scrub artifacts before sharing; never copy production
traffic into `corpus/`.

## Crash promotion

1. Reproduce from the uploaded artifact with `cargo fuzz run <target> <artifact>`.
2. Minimize: `cargo fuzz tmin <target> <artifact>`.
3. Add the minimized input to `fuzz/corpus/<target>/` with a descriptive name.
4. Add a permanent regression test under `tests/unit/` or `fuzz/tests/` when the
   crash encodes a real bug fix.
5. Do not merge corpora that contain secrets or customer data.

## Toolchain pins

| Component | Pin |
|-----------|-----|
| Rust (fuzz) | `nightly-2025-07-01` (`fuzz/rust-toolchain.toml`) |
| `cargo-fuzz` | `0.13.1` (pinned in admitted CI workflows) |
| `libfuzzer-sys` | `0.4.9` (`fuzz/Cargo.toml`) |
| `proptest` (smoke only) | `1.6.0` (`fuzz/Cargo.toml` dev-dep) |

Production `rust-toolchain.toml` remains `stable`; fuzz dependencies stay isolated
in the `fuzz/` crate per `docs/dependency-policy.md`.

## Compile-time resource observations (#4694)

The existing main/manual sanitizer smoke step emits `Fuzz build resources:`
JSON records during compilation and its unchanged seven-target run. Samples
are spaced 30 seconds apart, capped at 240 records and two hours, and written
directly to the hosted log so runner loss does not depend on artifact cleanup.
The observer stops with the owning shell and preserves its original exit code.

Records contain host available memory/swap, swap page counters, root cgroup
memory limits/events when exposed, and an RSS summary of at most 1,024 visible
processes. No process arguments, environment, request bytes or corpus data are
read or logged. Missing kernel counters are reported as null. RSS sums double
count shared pages, sampled maxima are not exact peaks, and root cgroup counters
may include other runner processes; none alone proves that rustc exhausted
memory. Compare the final samples and cgroup OOM counters with the runner's
termination annotation before attributing a shutdown to resource pressure.

This is diagnostic only: compiler/profile/cache settings, AddressSanitizer,
all seven targets and every libFuzzer bound remain unchanged. The scheduled
longer discovery workflow is unchanged.
