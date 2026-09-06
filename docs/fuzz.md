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
required a coordinated trusted-policy migration of that job and the
`fuzz.yml` whole-file freeze. Ordinary PR admission cannot authorize its own
policy changes; the controller owns any override for an authorized migration.

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
  'push' || github.event_name == 'workflow_dispatch'`): six targets at up to
  512 executions or roughly 8 s each
  (`-runs=512`, `-max_total_time=8`, `-max_len=4096`, `-timeout=2`,
  `-rss_limit_mb=1024`), then `datagram_client_address` at the same bounds with
  `-max_len=65536` (issue #4442). It runs on the push to `main` and on manual
  `workflow_dispatch` of `ci.yml` only. The bounds are byte-identical to what
  pull requests used to run; only *where* the budget executes changed (#3902
  took it off `pull_request` for cost, #4238 off `merge_group` for blast
  radius). Every merged change still reaches the budget seconds later through
  the push to `main`, which is also the only event permitted to populate this
  lane's cache. The smoke uses `--dev -s address` with optimization level 1
  and 16 codegen units;
  this changes compilation and achieved throughput, not the execution bounds.
- **Scheduled sanitizer lane** (`.github/workflows/fuzz.yml`): AddressSanitizer
  builds of all seven targets, 300 s per target at `-max_len=65536`, bounded
  crash artifacts uploaded after size/count checks, a 2048 MiB RSS cap, 7-day
  retention, and concurrency capped at two targets. Unchanged by #3902/#4238.

Issue #4694 records a successful main baseline of **53m02s** for Fuzz Smoke,
including **37m22s** compiling the first sanitizer target and **41m35s** in the
sanitizer step ([run 34018271780](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34018271780/job/101447338009)).
The smoke-specific profile experiment uses the documented `--dev` interface in
[cargo-fuzz 0.13.1's BuildOptions](https://github.com/rust-fuzz/cargo-fuzz/blob/1b34938413a104856042376b285c8d1c1e11b098/src/options.rs),
shared by `build` and `run`. In that exact version,
[the Cargo command builder](https://github.com/rust-fuzz/cargo-fuzz/blob/1b34938413a104856042376b285c8d1c1e11b098/src/project.rs#L135-L152)
omits `--release` when `dev` is set; sanitizer instrumentation is independent
and remains explicitly selected with `-s address`. The sanitizer step sets
optimization level 1. Debug assertions remain
active (cargo-fuzz also enables them in the predecessor unless `-O` is passed).

Only the bounded sanitizer **step** sets
`CARGO_PROFILE_DEV_OPT_LEVEL=1`, `CARGO_PROFILE_DEV_DEBUG=line-tables-only` and
`CARGO_PROFILE_DEV_INCREMENTAL=false`. Line tables retain file/line backtrace
information and match cargo-fuzz 0.13.1's release-mode debug override; incremental
output is disabled to avoid adding that payload to the shared cache. See
[Cargo profile settings](https://doc.rust-lang.org/cargo/reference/profiles.html).
No manifest, production profile, deterministic property command, scheduled
workflow, compiler/tool pin, or dependency changes accompany this experiment.
The scheduled discovery lane keeps cargo-fuzz's optimized default.

The first level-0 experiment in manual run
[34026677585](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34026677585)
reduced cold sanitizer time to 19m46s and first compilation to 12m46s. Six
targets completed 512 iterations, but `config_decode` completed only 45 within
the unchanged time cap, versus 512 in the optimized baseline. That revision
was not adopted. Level 1 is being measured to recover throughput while keeping
compilation cheaper than the production profile; equal time limits alone do
not establish equivalent smoke coverage.

The job retains the checksum-pinned `setup-sccache` action and
`Swatinem/rust-cache` payload/ownership policy. `save-if` remains strictly
`${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}`:
pull requests (including forks), `merge_group`, and `workflow_dispatch` restore
but never publish a `fuzz-smoke-dev-opt1` cache. The new stable cache key separates
this profile generation from the previous optimized payload: the step-only
profile overrides are applied after cache restoration, so the old key could
otherwise hit an immutable entry that cannot be refreshed with dev outputs.
It also avoids carrying unused optimized artifacts into the new payload.
Cache splitting, quota survival across
subsequent main runs, and elimination of redundant cache data are separate
#4694/#4643 work and are **not established by this profile change**.
The credential-bearing sccache GHA backend is never enabled. Every run logs
`Fuzz property smoke seconds`, lane shape, closing `sccache --show-stats`, and
on-disk compiler-cache size. Sanitizer runs also log pre-build sccache statistics,
the selected profile, a separate `cargo fuzz build` duration for each target,
and a completion marker after each successful bounded `cargo fuzz run`.
The run timer includes Cargo's freshness check, so it is not pure libFuzzer
time. Unfiltered libFuzzer output includes `Done ... runs` and, with
`-print_final_stats=1`, `stat::number_of_executed_units`, execution rate and peak
RSS. Read those actual per-target counts; 512 is a ceiling, not a claimed
completion count. An EXIT trap records sanitizer lane time and exit status even
on ordinary command failure; runner termination may prevent the trap. Build or
fuzz failures still fail the step, and no completion marker precedes success.

Hosted validation is pending until the controller runs **manual `ci.yml` on the
exact pushed branch SHA**; PR CI exercises only the deterministic property gate
when admitted. The existing trusted-base policy may reject this migration until
the controller arranges its authorized admission; candidate self-tests never
override that decision.
Compare first-target compilation, subsequent target links, total lane/job time,
actual executions, peak RSS, cache bytes and diagnostic source locations with
the optimized baseline, controlling source/toolchain and cache state for a fair
comparison. Dev code may complete fewer iterations or hit existing timeout/RSS
limits; equal seconds do not demonstrate equal fuzzing throughput or coverage.
No sanitizer crash is deliberately introduced to validate diagnostics.

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
