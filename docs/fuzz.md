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
| `datagram_client_address` | Datagram PROXY v2 DGRAM header + auth/freshness TLV walk + freshness record decode | 512-byte address-block cap, 64 KiB fuzz input (both hosted lanes) | Fail closed; bounded TLV walk; at most one auth and freshness TLV (either may be absent; duplicates refused); valid lengths and freshness encoding when present; no secret/tag/sequence/address output |
| `mesh_udp_frame` | HBONE datagram framing | 64 KiB input, 256 frames/invocation | Length prefix bounded; encode/decode round-trip |
| `k8s_crd` | Istio/Gateway API JSON → translation | 32 objects, depth 64 | Fail-closed translation errors |
| `plugin_config` | Representative plugin JSON validation (one selector byte followed by JSON) | depth 64 | `validate_plugin_config` never panics |
| `ocsp_response` | Hand-rolled stapled-OCSP DER grammar (`tls::ocsp::validate_structure_with_policy`), under both the interoperable and the FIPS-enforced profile | 64 KiB (`MAX_OCSP_RESPONSE_BYTES`, equal to the fuzz input budget) | No panic; an accepted response reports the input length and 1–64 `SingleResponse` entries; FIPS acceptance implies interoperable acceptance with the same structure |
| `jwt_svid` | JWT-SVID strict duplicate-key-refusing JSON parser, compact-token validator, authority PEM admission, and external JWKS bundle admission (one selector byte, then mode-specific bytes; see `fuzz_support::FUZZ_JWT_SVID_MODES`) | 8 KiB token, 4 KiB segment, 64 KiB fuzz input | No panic; no token validates against the fixed fuzz bundle without the authority's signature; an accepted JWKS republishes and re-admits to the same keys |
| `tls_material` | PEM certificate-bundle and private-key admission (`parse_pem_certificate_bundle`, `parse_pem_private_key`) and CRL window classification (`classify_crl_window`) for PEM bundles and single DER records (selector byte; see `fuzz_support::FUZZ_TLS_MATERIAL_MODES`) | 64 KiB fuzz input, 64 CRL records per input | No panic; an accepted bundle holds 1–4096 records; a CRL admitted at the fixed instant reports a later `nextUpdate` |

The `datagram_client_address` target parses attacker-controlled UDP bytes
entirely **before** the MAC decision, so it is scheduled in **both** required
lanes (issue #4442): the `.github/workflows/fuzz.yml` sanitizer matrix and its
shell allowlist, and the byte-frozen `fuzz-smoke` bounded budget in
`.github/workflows/ci.yml`. Its entry point walks the header, both
application-reserved TLVs (`0xE0` authentication tag, `0xE1` freshness record),
and — when a freshness TLV is present — the fixed-length freshness value.
The structural parser the target exercises permits either TLV to be absent
and refuses a duplicate or wrong-length occurrence of each; it does not
require presence. Presence and authentication are enforced separately by the
configured runtime gate (the authentication-required branch verifies the tag
and requires freshness), so structural acceptance of an unauthenticated
envelope here is deliberate and is not an authentication decision.

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

`ocsp_response`, `jwt_svid`, and `tls_material` (issue #6584) cover the
hand-rolled parsers and admission rules for hostile ASN.1, PEM, and JSON input.
Stapled OCSP responses and TLS material arrive from files, provider URIs,
Kubernetes Secrets, and the admin API. JWT-SVIDs and federated JWKS bundles
arrive through the Workload API. All three run in both lanes at the 64 KiB
fuzz input budget, as their own smoke loop, because their size bounds (64 KiB
OCSP, 8 KiB token, larger PEM) sit above the six-target loop's 4 KiB ceiling.
`jwt_svid` validates against a fixed bundle holding the public half of the
repository's synthetic `tests/fixtures/test_rsa_*.pem` test key. The deterministic
smoke proves that bundle is admitted and verifies a correctly signed token, so
fuzz inputs reach signature verification instead of stopping at authority
admission. Seeds are synthetic DER, PEM, and JSON under
`fuzz/corpus/{ocsp_response,jwt_svid,tls_material}/`. Every `valid_*` OCSP seed
must be accepted, every `jwks_valid_*` seed must be an accepted JWKS, and every
`valid_crl*` seed must be inside its window at the fixed instant
(`FUZZ_CRL_NOW_UNIX`).

Shared budgets and helpers live in `src/fuzz_support.rs`.

## Corpora

Seed only **synthetic boundary cases** under `fuzz/corpus/`. Never commit
production configs, JWTs, TLS material, or packet captures. The hosted workflow
rejects crash artifacts larger than 64 KiB before upload.

## Hosted CI

- **PR gate** (`ci.yml` → `Fuzz Smoke`): the locked `proptest` smoke tests
  (`cargo test --locked` in `fuzz/`). This is a required gate for full-mode
  pull requests and merge-queue runs whose changes match the `run_fuzz_smoke`
  path gate (see [ci_cd.md](ci_cd.md)); every other event runs it
  unconditionally.
- **Bounded libFuzzer budget** (same `Fuzz Smoke` job, `if: github.event_name ==
  'push' || github.event_name == 'workflow_dispatch'`): six targets at ~8 s each
  (`-runs=512`, `-max_total_time=8`, `-max_len=4096`, `-timeout=2`,
  `-rss_limit_mb=1024`), then `ocsp_response`, `jwt_svid`, and `tls_material`
  (issue #6584) and
  `datagram_client_address` (issue #4442) at the same bounds with
  `-max_len=65536`. It runs on the push to `main` and on manual
  `workflow_dispatch` of `ci.yml` only (#3902 moved it off `pull_request` for
  cost, #4238 off `merge_group` for blast radius; the bounds did not change).
  Every merged change still reaches the budget seconds later through
  the push to `main`, which is also the only event permitted to populate this
  lane's cache.
- **Scheduled sanitizer lane** (`.github/workflows/fuzz.yml`): AddressSanitizer
  builds of all ten targets, 300 s per target at `-max_len=65536`, bounded
  crash artifacts uploaded after size/count checks, a 2048 MiB RSS cap, 7-day
  retention, and concurrency capped at two targets. Unchanged by #3902/#4238.

`cargo fuzz run` defaults to AddressSanitizer, so the bounded budget is a
sanitizer build in both lanes. That build, not the fuzzing, was the cost: the
`Fuzz Smoke` job averaged ~47 minutes on pull requests, of which ~39 minutes was
compiling the instrumented targets for ~48 seconds of fuzzing. The `Fuzz Smoke`
job now uses the repository's checksum-pinned `setup-sccache` action and
`Swatinem/rust-cache` (fuzz workspace, `fuzz-smoke` shared key); it holds only
`contents: read` and uses no remote compiler-cache backend. `save-if` is
strictly `${{ github.event_name == 'push' && github.ref ==
'refs/heads/main' }}`: pull requests (including same-repository PR refs and
forks), `merge_group`, and `workflow_dispatch` never publish a `fuzz-smoke`
cache. The generation that predates #3902 had no `save-if` at all, which is how
a full-mode predecessor PR could still mint a PR-ref Fuzz cache; no
admitted generation can create another.
The credential-bearing sccache GHA backend is never enabled. After a
successful property-smoke command the run logs `Fuzz property smoke seconds`,
and after a successful sanitizer budget `Fuzz sanitizer lane seconds`; both
echoes sit after their commands under `set -e`, so a failed or skipped
command emits no duration line. Runs that execute the sanitizer budget print
`sccache --show-stats` just before it, so the log shows directly whether the
sanitizer build reused compilation. The closing report step runs on every
outcome: it prints the lane shape the run took, a closing `--show-stats`, and
the on-disk cache size. When sccache is unavailable both steps say so, and the
closing step emits a warning annotation rather than letting caching fail
silently.

Both hosted shapes are byte-frozen by the trusted Cross build policy. The
`fuzz-smoke` job is admitted as an ordered list of generations with one-way
transitions (`CI_FUZZ_SMOKE_JOB_GENERATIONS`); see
[ci_cd.md](ci_cd.md#admitted-fuzz-smoke-generations).

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
rustup toolchain install nightly-2026-09-30
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
| Rust (fuzz) | `nightly-2026-09-30` (`fuzz/rust-toolchain.toml`) |
| `cargo-fuzz` | `0.13.1` (pinned in admitted CI workflows) |
| `libfuzzer-sys` | `0.4.9` (`fuzz/Cargo.toml`) |
| `proptest` (smoke only) | `1.6.0` (`fuzz/Cargo.toml` dev-dep) |

Production `rust-toolchain.toml` remains `stable`; fuzz dependencies stay isolated
in the `fuzz/` crate per `docs/dependency-policy.md`.

## Compile-time resource observations (#4694)

The existing main/manual sanitizer smoke step emits `Fuzz build resources:`
JSON records during compilation and its sanitizer target run. Samples
are spaced 30 seconds apart, capped at 240 records and two hours, and written
directly to the hosted log. Hard runner loss can prevent that log from being
published: the first observer trial lost communication and left no retrievable
Fuzz log or resource samples. Outer job status can also lag the actual failed
step; compare step timestamps before inferring ongoing compilation.
The observer stops with the owning shell and preserves its original exit code.

A second, best-effort channel emits at most nine notice annotations: the initial
sample, first available-memory crossings of 75/50/25/10/5 percent, first free-swap
crossings of 25/5 percent when swap exists, and the first increase in exposed root
cgroup OOM counters. Simultaneous reasons share one annotation. Notices carry
only selected numeric counters, are queued as runner timeline issues,
and do not grant API credentials to the observer or compiler. Results-only live
step updates can omit annotations; queuing does not establish that the Checks
API exposes them before step/job completion. They can also be
lost if the runner stops before forwarding them; missing records do not prove
absence of memory pressure. Validate retrieval on a hosted run before relying
on this channel. Thresholds select diagnostic samples and do not stop the build.
The [notice command](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#setting-a-notice-message)
and [runner issue handling](https://github.com/actions/runner/blob/0b0ac2fdabf53d69add6175026945b8afc8549a5/src/Runner.Worker/ExecutionContext.cs#L795)
describe the annotation path and the ten-notice limit; these are not a delivery
guarantee after runner loss.

Records contain host available memory/swap, swap page counters, root cgroup
memory limits/events when exposed, and an RSS summary of at most 1,024 visible
processes. No process arguments, environment, request bytes or corpus data are
read or logged. Missing kernel counters are reported as null. RSS sums double
count shared pages, sampled maxima are not exact peaks, and root cgroup counters
may include other runner processes; none alone proves that rustc exhausted
memory. Compare the final samples and cgroup OOM counters with the runner's
termination annotation before attributing a shutdown to resource pressure.

The second trial recovered 44 samples and six notices after a runner shutdown
(exit 143). The largest visible process reached about 14.3 GiB RSS, available
host memory fell below 250 MiB and the 3 GiB swap area had less than 45 MiB free.
Root cgroup OOM counters were unavailable, so this establishes severe sampled
pressure without proving a kernel OOM kill or the exact shutdown cause. Notices
were not observed through the Checks API during the run; both channels became
available afterward, so this is not proof of recovery after hard runner loss.

Main/manual jobs now add a bounded 12 GiB swap file under `/mnt`, following the
existing unit/PKCS11 provisioning. Existing swap remains enabled; provisioning
fails visibly if allocation or activation fails. The observer records whether
this adds useful headroom, and a fresh full run must validate it. Paging may
increase wall time; this is not a measured latency improvement. Compiler/profile/
cache settings, AddressSanitizer, every target and every libFuzzer bound
remain unchanged.

The scheduled sanitizer lane (`fuzz.yml`) builds the same AddressSanitizer
release library with the same profile and `--codegen-units 16`, but had only
the runner's 3 GiB swap. On 2026-10-01 the `fuzz-smoke` observer recorded a
14.6 GiB rustc RSS peak and about 22-23 GiB of RAM plus swap in use (up to
7.9 GiB of swap) during that compile, which a 16 GiB RAM + 3 GiB swap runner
cannot hold. As `ferrum-edge` grew (the `src/` tree is about 10% larger than on
2026-09-07, the last all-green week), scheduled lanes started dying inside that
compile with the runner shutdown signal: 1/7 on 2026-09-14, 7/7 on 09-21, 3/7
on 09-28, and 7/7 on the first `nightly-2026-09-30` dispatch. The lane now adds
the same bounded 12 GiB `/mnt` swap file before building; the toolchain,
profile, sanitizer, targets, matrix concurrency and every libFuzzer bound are
unchanged.
