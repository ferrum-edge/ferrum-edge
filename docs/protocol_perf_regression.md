# Protocol Performance Regression

Scheduled and manually runnable multi-protocol performance regression for
Ferrum Edge. This lane tracks throughput, error rate, and latency percentiles
across the supported protocol matrix, plus connection churn, long-lived soak /
resource plateaus, and reload-under-load coverage.

Neither this lane nor its static contracts run in `ci.yml` or on pull
requests, and noisy shared-runner microbenchmarks stay out of branch
protection. The lightweight static contracts for this lane (workflow verifier
self-test + repository contract, evaluator self-test, and a
`python3 -m py_compile` check of the scenario harness) run first in the
`Performance Regression Check` job of `.github/workflows/performance-regression.yml`,
which runs daily against the tip of `main` and on manual dispatch. That job
also runs the measured HTTP/1 overhead check
(`tests/performance/ci_overhead_bench.py`). It has read-only contents
permission, does not persist checkout credentials, and caches both the root
workspace (`. -> target`) and the standalone `tests/performance/mesh`
Criterion workspace through `setup-rust-ci`'s optional rust-cache `workspaces`
pass-through (`shared-key: ci-perf`). Other `setup-rust-ci` callers omit
`workspaces` and keep rust-cache's root-only default.

## Documented runner and build profile

| Setting | Value | Notes |
|---|---|---|
| Runner class | `ubuntu-26.04` | GitHub-hosted; expect noisy-neighbor variance |
| Gateway build profile | `ci-release` | Stable CI-oriented release profile from root `Cargo.toml` |
| Harness build profile | `release` | `tests/performance/multi_protocol` is not a workspace member and uses its local `release` profile |
| Workflow | `.github/workflows/protocol-perf-regression.yml` | `schedule` (Sundays 05:00 UTC) + `workflow_dispatch` |

Do not treat numbers from this lane as production SLOs until absolute floors are
filled in after measured runner variance.

## What it records

Per supported protocol (gateway path):

- Throughput (RPS)
- Error rate
- Latency p50 / p95 / p99

Additional scenarios from
`tests/performance/multi_protocol/run_protocol_regression_scenarios.py`:

- **Connection churn** — HTTP/1 with keep-alive / idle pool disabled
- **Long-lived soak** — `proto_bench saturate` hold window
- **Resource plateau** — RSS, FD count, and task/thread samples from `/proc`
  after the connection ramp, comparing early/late three-sample medians
- **Reload under load** — file-mode `SIGHUP` while traffic is flowing

## Budgets and trends

Versioned budgets live in
`tests/performance/multi_protocol/protocol_perf_budgets.json`.

- `enforcement` starts as `alert` (warnings only for **measured** budget
  breaches; soft product regressions stay green) so shared-runner variance
  does not block the schedule.
- **Harness / data-completeness failures are always hard failures**, even
  while `enforcement` is `alert`: missing expected protocol samples,
  missing per-iteration RPS/error/p50/p95/p99 fields, zero-total/invalid
  metrics, non-finite or malformed numeric fields (NaN, Infinity, non-numeric
  counts/rates/plateau arrays), missing or malformed runner-health/history
  evidence, nonzero scenario benchmark exits, an undelivered reload `SIGHUP`,
  missing required scenario output, and insufficient RSS/FD/task sampling all
  fail the job.
  Finite measured product regressions such as zero RPS or large latency stay
  alert-only under `enforcement=alert`.
- Absolute `min_gateway_rps` / `max_p*_us` floors are intentionally `null`
  until operators measure variance on `ubuntu-26.04` + `ci-release` and fill
  them in. Do not invent floors from unexecuted local runs.
- When prior trend artifacts exist, the evaluator also applies a rolling
  median ± MAD comparison (`rolling` block in the budgets file). History is
  accepted only from the newest successful `main` run, validated against schema
  version 1, filtered to the same runner/build profile, and bounded to the
  configured rolling window.
- Each run publishes machine-readable artifacts:
  - `combined_results.json`
  - `budget_report.json`
  - `protocol_perf_trends.json`
  - `runner_health.json` / `runner_health.log`

Evaluator:
`tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py`.

## Distinguishing product regressions from noisy neighbors

Retain and inspect:

- `runner_health.json` — CPU steal sample, scheduler jitter, `nproc`
- Multi-iteration matrix outputs (`matrix_run*.json`)
- Budget alerts vs hard failures (`enforcement`)
- Scenario resource series under `scenarios/resource_plateau`

If steal/jitter is elevated or CV across iterations is high, treat throughput
and latency alerts as provisional.

## Manual dispatch

Actions → **Protocol Performance Regression** → Run workflow.

Optional inputs: duration, concurrency, iterations, and one protocol selection
(or `all` for the complete matrix).

## Local static checks (no benchmarks)

```bash
python3 .github/scripts/verify_protocol_perf_regression_workflow.py --self-test
python3 .github/scripts/verify_protocol_perf_regression_workflow.py
python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py --self-test
python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py
```

The daily `Performance Regression Check` job runs the same static set
immediately after checkout.

## Historical-baseline H1 TLS POST check

`.github/workflows/h1-tls-post-regression.yml` (daily, plus manual dispatch)
answers the question the scheduled lanes above cannot: *is today's `main`
slower than a known historical revision on the HTTP/1.1 TLS POST/echo
workload?* Issue [#5505](https://github.com/ferrum-edge/ferrum-edge/issues/5505)
found a June-to-September throughput loss on that workload that only surfaced
by eye in `gateways-protocol-benchmark.yml` output; absolute RPS from
different runs cannot guard it because hosted runners change CPU class between
runs.

The check therefore measures **two revisions on one runner**:

1. Build the reference revision pinned in
   `tests/performance/multi_protocol/h1_tls_post_reference.json` and the
   candidate (`main` tip) with the same toolchain and the `ci-release`
   profile; build `proto_backend` / `proto_bench` once from the candidate tree.
2. Start one `proto_backend`; for each round start the reference and candidate
   gateways in alternating order (reference first on odd rounds) with an
   identical environment and `configs/http1_tls_e2e_perf.yaml` (TLS on both
   hops, `backend_read_timeout_ms` / `backend_write_timeout_ms` at their
   production values), warm up, then measure every payload size for
   `duration_secs` at `concurrency` connections.
3. Gate the **paired ratio** `candidate_rps / reference_rps` per round and
   payload size. The median paired ratio must stay at or above
   `thresholds.<size>.min_ratio`.

Runner-variance handling:

- Every measured sample must verify every echo (`total_errors == 0`); errors,
  missing rounds, duplicate samples, or missing provenance fail the job in any
  enforcement mode.
- If either side's three-round throughput spread exceeds
  `runner_variance.max_round_spread`, the runner was noisy and a below-floor
  ratio is downgraded to a **provisional alert** instead of a failure.
- With at least `rolling.min_samples` prior scheduled runs of the same
  reference and workload, a ratio below `median − mad_multiplier × MAD` raises
  a non-blocking alert even when it clears the floor, catching gradual slides.
- The pre-benchmark step records CPU steal and scheduler jitter alongside the
  evidence; treat verdicts as provisional when steal exceeds 5%.

The artifact `h1-tls-post-comparison-<sha>` retains every individual sample
(`samples/*.json`), gateway/backend logs, `rows.json`, `provenance.json`
(revision SHAs, binary and harness digests, toolchain, host), `report.json`,
and the extended `h1_tls_post_trends.json` ratio history.

Contract rules: `reference.sha` is an immutable commit; raise `min_ratio`
toward `1.0` as the gap closes and never lower it or change the workload to
make a production regression disappear. A manual dispatch may pass
`reference_sha` to compare the dispatched ref against any other revision on the
same runner — the matched-host bisect tool for future attribution work. Manual
runs do not extend the rolling history.

Local static checks:

```bash
python3 .github/scripts/h1_tls_post_comparison.py self-test
bash -n .github/scripts/run_h1_tls_post_comparison.sh
```

## Request-upload hand-off on the H1 TLS POST path

Issue [#5537](https://github.com/ferrum-edge/ferrum-edge/issues/5537) item 4
asks what the gateway-owned request-upload relay costs on this workload, and
whether a fully buffered upload can be handed to the backend transport without
it. This section records the answer, derived by static inspection of
`src/proxy/mod.rs`, `src/proxy/body.rs`, `src/proxy/upload_pump.rs` and the
harness, so a later attribution round does not have to re-derive it.

### Which classification the benchmark exercises

The workload's POST body is **streamed**, not buffered. Four facts decide it:

- `configs/http1_tls_e2e_perf.yaml` declares `plugins: []` and no `retry`, so
  `requires_request_body_buffering` and `has_effective_http_retries` are both
  false and `stream_request_body` is true.
- `proto_backend`'s HTTPS listener on port 3447 advertises only `http/1.1` in
  ALPN, so the backend capability registry can never mark it direct-H2 or H3;
  the dispatch runs through the reqwest pool.
- `.github/scripts/h1_tls_post_comparison.py` sets
  `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0`, so that dispatch takes the
  `CountingIncoming` arm rather than `SizeLimitedIncoming`.
- `backend_write_timeout_ms: 30000` is live, so
  `install_counting_upload_authorization` installs a gateway-owned pump.

The relay this benchmark pays is therefore the **bridged** one
(`UploadFrames::Bridged`, `run_upload_pump`). The direct hand-off built for
fully buffered uploads in
[#5510](https://github.com/ferrum-edge/ferrum-edge/pull/5510) is not on this
path at all — a point worth keeping in mind when reading that PR's neutral
paired result.

### The buffered classification already has the direct hand-off

Every classification whose bytes the gateway already owns reaches
`spawn_direct_upload_watch`, which relays nothing: the transport takes
refcounted `Bytes::split_to` slices of the collected buffer synchronously and
records each take, and a watcher future judges the watermark from that record.

| Dispatch | Entry point |
|---|---|
| Buffered reqwest (and its protocol-NACK replay) | `install_buffered_upload_write_watermark` → `spawn_buffered_upload_pump` |
| H3 → plain cross-protocol bridge | `install_buffered_upload_write_watermark` |
| HBONE / Unix / sidecar-mTLS replayable bodies | `ReplayableRequestBody::with_gateway_upload_pump` → `spawn_replayable_upload_pump` |
| Buffered native gRPC | `spawn_replayable_upload_pump_with_deferred_write` |

`only_streaming_uploads_pay_the_bridged_relay` in
`tests/unit/gateway_core/stream_auth_lifetime_tests.rs` pins that table from
both ends: the bridge channel is built in exactly one installer, the direct
source in exactly one other, and no buffered dispatch site reaches the relay.

Per request, with a non-empty body and a live `backend_write_timeout_ms`, that
hand-off costs six heap allocations — two control `oneshot`s, the terminal
`AtomicU8`, the backend-socket slot, the shared `DirectUploadProgress`, and one
boxed watcher future — plus one timer arm for the whole request. There is no
channel, no relay, no copy, and no task spawn on the ordinary path: the watcher
is driven inline by `await_upload_write_watermark_first` and is handed a task
only if that race ends while it is still live. Per frame it costs one clock
read, one atomic store, one refcount bump and one counter add; frames are
`min(64 KiB, remaining)`, so 10 KiB is one frame and 70 KiB is two.
`backend_write_timeout_ms == 0`, and an upload with nothing to write, keep the
allocation-, task- and timer-free path.

What remains is exactly the watermark, and it cannot be shed. The specialized
H1/H2 transports park **outside** a body poll precisely when a backend accepts
and stops reading, so a bound delivered through the body alone can never fire
there; removing the watcher reopens
[#4055](https://github.com/ferrum-edge/ferrum-edge/issues/4055). There is no
further direct hand-off to take on this classification.

### What the streaming relay costs

Relative to handing `UploadSource::Direct(incoming)` straight to the transport,
which is the shape the pinned June reference had, the bridged relay adds per
request:

- **At install: seven heap allocations.** Tokio's bounded channel (its shared
  state plus the first block of its intrusive list, a fixed number of
  `Frame<Bytes>` slots), the two control `oneshot`s, the terminal `AtomicU8`,
  the backend-socket slot, and the boxed relay future — which owns the client
  `Incoming`, both optional `Sleep`s and the `select!` state.
- **Per DATA frame: one task hand-off the direct body does not have.** The
  relay is polled by the frontend connection task (inline, through the
  dispatcher's header race) while the body is polled by reqwest's connection
  task, so every frame crosses a semaphore acquire/release pair, an
  intrusive-list push and pop, and both wakers.
- **Per relay-loop iteration while the watermark is armed:** one clock read and
  one `Sleep::reset()` — a timer-wheel deregistration and reinsertion — plus one
  `Sleep` poll, because the `biased` `select!` polls the idle arm before
  `sender.reserve()`.
- **Per frame: one extra `http_body::Body` layer**, `UploadPumpSource::poll_frame`
  between `CountingIncoming` and `Incoming`.
- **Once, on the way out of the race:** a `settle_inline()` poll through a no-op
  waker, or a `tokio::spawn` if the relay is still live.

Frame count for this workload: the frontend HTTP/1 parser buffer is
`max(FERRUM_MAX_HEADER_SIZE_BYTES, 8 KiB)` — 32 KiB with the shipped default —
and a TLS record carries at most 16 KiB of plaintext, so a 10 KiB upload arrives
as one DATA frame and a 70 KiB upload as at least three. That puts the relay at
roughly seven allocations plus three task hand-offs at 10 KiB, and seven plus
seven or more at 70 KiB, which is the right order of magnitude for the +3.8
June-normalised CPU units the issue attributes to it.

### Why the streaming relay is not convertible

The relay's one-frame lookahead is the **only** evidence the gateway has that a
transport has stopped consuming *while bytes were available*. Four alternatives
were considered and all of them weaken a standing invariant:

1. **Poll the client body in place from the transport.** The gateway then learns
   nothing between polls. A transport whose peer stopped reading simply stops
   polling, and "stopped polling" is indistinguishable from "the client sent
   nothing to hand over" — which must *not* trip the watermark
   (`an_inline_pump_waiting_on_the_client_keeps_the_write_watermark_dormant`).
2. **Record the last poll's outcome in the body and judge from that.** It does
   not close the gap. When the transport's last body poll reported "nothing
   available" and the client then delivers, the transport is woken but a
   connection whose write buffer is already full flushes rather than polling the
   body again; the body never observes the arrival, the watermark stays dormant,
   and the request runs on to `backend_read_timeout_ms` — exactly the #4055
   regression. Closing it requires waking the *gateway* when the client delivers
   while the transport is not polling, which means the gateway must own a
   lookahead, which means either a channel (what the relay is) or a lock shared
   between the two tasks on the request path. Hot-path invariants forbid the
   lock.
3. **Collect the upload opportunistically so it becomes the buffered case.**
   Refused by the standing rule: buffer only when a plugin requires request or
   response body buffering, or retry needs replay.
4. **Substitute the post-EOS socket send-queue judgment
   ([#4411](https://github.com/ferrum-edge/ferrum-edge/issues/4411)) for the
   relay.** That judgment is disarmed whenever no backend socket was published,
   which is the ordinary case for a request served on an already-pooled reqwest
   connection — the steady state of this benchmark's 200 keep-alive
   connections. It would leave the watermark unenforced for nearly every
   request.

Independently of the watermark, the #3815 ownership boundary ("after expiry the
gateway owns and polls no part of the inbound client body") is only satisfiable
while the gateway holds the `Incoming`. A direct streaming source hands that
ownership to the transport, so an authenticated streaming upload could not be
given one at all.

`the_backend_write_watermark_ends_a_streaming_upload_the_transport_stopped_taking`
is the positive proof that the relay is load-bearing here: a client that keeps
producing while the transport stops taking ends on `backend_write_timeout_ms`,
with the frame the relay had already read discarded rather than forwarded.

### Candidate left on the table

`run_upload_pump` re-arms its idle `Sleep` at the top of every loop iteration and
the `biased` `select!` polls it before `sender.reserve()`, so a healthy backend
pays a timer-wheel deregistration and reinsertion per DATA frame for a timer that
never fires. Trying `sender.try_reserve()` first and arming the timer only when
capacity is genuinely unavailable would remove it; `run_direct_upload_watch`
already uses the equivalent recompute-on-fire shape.

It is deliberately not taken here. It also changes which arm wins when the idle
deadline and a freed capacity slot are ready in the same poll — today the timer
wins and reports `WriteTimeout` even though the transport did consume — and that
is a behaviour change that deserves its own attributable measurement rather than
being folded in. Its ceiling is two timer-wheel operations and one clock read per
DATA frame: about one frame's worth at 10 KiB and three or more at 70 KiB.

## Native harness cert paths

The scheduled workflow runs `run_protocol_test.sh` **natively** (not in Docker).
Backend TLS configs use a `CA_PATH` placeholder in committed YAML; the harness
substitutes `tests/performance/multi_protocol/certs/ca.pem` at gateway start.
Docker comparison benches (`run_gateway_protocol_bench.sh`,
`run_connection_saturation_bench.sh`) rewrite the same placeholder to
`/etc/ferrum/tls/ca.pem` before mounting configs into containers. Committed
native perf YAML must not hardcode `/etc/ferrum/tls` paths — the workflow
verifier enforces this contract.

## Mesh in-process vs E2E suites

`tests/performance/mesh/` is the **in-process** Criterion crate (`authz_match`,
`ip_restriction`, `slice_apply`, `xds_translation`). HBONE tunnel throughput and
mesh DNS proxy resolution latency are **not** criterion micro-benches; they ship
as live E2E harnesses that spin up `ferrum-edge` plus stub peers:

| Suite | Path | Measures | Residual |
|---|---|---|---|
| In-process mesh Criterion | `tests/performance/mesh/` | `authz_match`, `ip_restriction`, `slice_apply`, `xds_translation` | Hosted collection workflow landed; `baseline.md` result cells stay `_TBD_` until a successful artifact is published — [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) |
| HBONE gateway overhead | `tests/performance/mesh-hbone-e2e/` | Gateway-to-mesh HBONE outbound throughput over H2 CONNECT/mTLS | Same two-stage publication residual — [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) |
| Mesh DNS proxy | `tests/performance/mesh-dns-e2e/` | Transparent mesh DNS proxy latency/QPS over UDP and TCP | Same two-stage publication residual — [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) |

Hosted collection (stage 1) lives in
`.github/workflows/mesh-performance-baselines.yml` and is dispatched after the
trusted workflow lands on `main`. Collection is pinned to GitHub-hosted
`ubuntu-26.04` (no arbitrary/self-hosted runner
input). It records provenance, Criterion trees, HBONE/DNS JSON (≥3 repetitions),
`runner_health.json` + per-E2E and per-mesh Criterion workload-interval steal probes, `summary.json`, and draft markdown
under the `mesh-performance-baselines-<sha>` artifact. Selected-suite acceptance
fails the job when required gates are false (undersampling, missing DNS rows,
nonzero errors, nonzero DNS NXDOMAIN counts, missing mesh Criterion / E2E
interval steal evidence, or CPU steal > 5.0%); artifacts still upload. Stage 2 copies
only zero-error hosted aggregates into the three `baseline.md` tables.
Manual and reusable workflow callers are limited to 3–5 E2E repetitions so a
misconfigured reusable caller cannot consume an unbounded hosted-runner budget.

`tests/performance/mesh/README.md` is a **frozen Trusted Cross automation
surface**: every path under `tests/performance/` is treated as protected
executable/configuration prose, including Markdown. Its historical
"Benches deferred (not yet implemented)" section is **not** the current
backlog source of truth and must remain unchanged. Live suite status,
`mesh-hbone-e2e` / `mesh-dns-e2e` pointers, and the [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332)
baseline-publication residual are documented here (and in
[`docs/backlog/issue_2110_register.md`](backlog/issue_2110_register.md))
instead of rewriting that protected README.

## Related surfaces

- Mesh/HBONE/DNS baseline collection: `.github/workflows/mesh-performance-baselines.yml`,
  with its non-literal computation in `.github/scripts/mesh_baseline_ledger.py`,
  `.github/scripts/mesh_baseline_runner_health.py`, and
  `.github/scripts/mesh_baseline_step_summary.py` (the workflow itself keeps a
  literal command surface; see `verify_mesh_performance_baselines_workflow.py`)
- Manual exploratory matrix: `.github/workflows/perf-benchmark.yml`
- Daily overhead check: `tests/performance/ci_overhead_bench.py` via
  `performance-regression.yml`
- Connection saturation headlines: `docs/connection_saturation_benchmark.md`
- Request-upload hand-off contracts (the section above):
  `tests/unit/gateway_core/stream_auth_lifetime_tests.rs`
- Suite index: `tests/performance/README.md`
- Scheduled lane details: this document (performance suite READMEs stay
  unchanged so trusted Cross automation digests are not rewritten)
