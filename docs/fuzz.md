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
| `datagram_client_address` | Datagram PROXY v2 DGRAM header + auth/freshness TLV walk + freshness record decode | 512-byte address-block cap, 64 KiB fuzz input | Fail closed; bounded TLV walk; exactly-one auth and freshness TLV; fixed-length freshness value; no secret/tag/sequence/address output |
| `mesh_udp_frame` | HBONE datagram framing | 64 KiB input, 256 frames/invocation | Length prefix bounded; encode/decode round-trip |
| `k8s_crd` | Istio/Gateway API JSON → translation | 32 objects, depth 64 | Fail-closed translation errors |
| `plugin_config` | Representative plugin JSON validation (one selector byte followed by JSON) | depth 64 | `validate_plugin_config` never panics |

The `datagram_client_address` target is locally complete (`fuzz/Cargo.toml`
`[[bin]]`, `fuzz_targets/datagram_client_address.rs`, synthetic corpus,
`fuzz_support::fuzz_parse_datagram_header`, and the `cargo test` property
smoke). Its entry point walks the header, both application-reserved TLVs
(`0xE0` authentication tag, `0xE1` freshness record), and — when a freshness
TLV is present — the fixed-length freshness value, so every parser a hostile
datagram can reach before the MAC decision is covered. The corpus carries an
authenticated-shape envelope (freshness + tag TLVs) and a wrong-length
freshness TLV alongside the earlier address/command/TLV cases. It is **not**
yet in the byte-frozen `CI_FUZZ_SMOKE_JOB` libFuzzer loop
(`.github/workflows/ci.yml`) or the `.github/workflows/fuzz.yml` matrix; those
trusted-base lists can only change on `main` after merge. Adding it means a new
admitted generation of the whole `fuzz-smoke` job, not an edit to the existing
one.

Shared budgets and helpers live in `src/fuzz_support.rs`.

## Corpora

Seed only **synthetic boundary cases** under `fuzz/corpus/`. Never commit
production configs, JWTs, TLS material, or packet captures. The hosted workflow
rejects crash artifacts larger than 64 KiB before upload.

## Hosted CI

- **PR gate** (`ci.yml` → `Fuzz Smoke`): the locked `proptest` smoke tests
  (`cargo test --locked` in `fuzz/`). This is the required full-mode
  pull-request gate and runs on every full-mode pull request.
- **Bounded libFuzzer budget** (same `Fuzz Smoke` job, `if: github.event_name !=
  'pull_request'`): all six targets at ~8 s each (`-runs=512`,
  `-max_total_time=8`, `-max_len=4096`, `-timeout=2`, `-rss_limit_mb=1024`), on
  `merge_group`, on the push to `main`, and on manual `workflow_dispatch` of
  `ci.yml`. The bounds are byte-identical to what pull requests used to run;
  only *where* the budget executes changed (issue #3902). The merge queue still
  runs the whole budget before a change merges, so nothing reaches `main`
  without it.
- **Scheduled sanitizer lane** (`.github/workflows/fuzz.yml`): AddressSanitizer
  builds, 300 s per target, bounded crash artifacts uploaded after size/count
  checks, a 2048 MiB RSS cap, 7-day retention, and concurrency capped at two
  targets. Unchanged by #3902.

`cargo fuzz run` defaults to AddressSanitizer, so the six-target budget is a
sanitizer build in both lanes. That build, not the fuzzing, was the cost: the
`Fuzz Smoke` job averaged ~47 minutes on pull requests, of which ~39 minutes was
compiling the instrumented targets for ~48 seconds of fuzzing. The `Fuzz Smoke`
job now uses the repository's checksum-pinned `setup-sccache` action and
persists its bounded local cache directory through `Swatinem/rust-cache`. That
cache is written only by pushes to `main` (`save-if`), so no untrusted ref can
populate what the sanitizer build later restores, and the credential-bearing
sccache GHA backend is never enabled. Every run logs `Fuzz property smoke
seconds`, the lane shape it took, a closing `sccache --show-stats`, and the
on-disk cache size; runs that execute the sanitizer budget add a second
`--show-stats` just before it plus `Fuzz sanitizer lane seconds`, so the log
shows directly whether the sanitizer build reused compilation. When sccache is
unavailable the job emits a warning annotation rather than letting caching fail
silently.

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
