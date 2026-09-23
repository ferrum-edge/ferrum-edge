# Gateway benchmark audit — 17 September 2026

Ferrum's strongest repeatable losses are HTTPS/1.1 at medium and large payloads,
1 MiB WebSocket messages, and UDP. Small HTTP/2 and gRPC requests merit attention,
but correctness problems make several apparent wins and losses provisional.
The September 18 HTTP/3 experiment corrects an earlier admission claim: Envoy's
historical HCM stream setting did not configure the downstream QUIC transport
limit. Request-correctness checks passed, but transport fairness also requires
independent socket diagnostics and effective listener configuration. Section 2
records those measurements and the pinned Envoy packet-drop counter bug.
There is no evidence yet that one change will make Ferrum faster than every competitor.

The [September 18 H2/gRPC campaign](benchmark_h2_grpc_2026_09_18.md) reproduces
adaptive-window failures with typed transport evidence. Fixed-window request
observations do not establish a production repair or a throughput gain.

The [September 19 WSS/TCP-TLS audit](benchmark_wss_tcp_2026_09_19.md) retains
all 72 additional 500 KiB / 1 MiB observations and their paired uncertainty.
Client useful-work validation passed throughout; transport diagnostics,
shared-host effects and historical causality remain qualified.

**Evidence and scope.** [Run 35071334026](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35071334026)
tested `ff96f30468517706695538ffc74bc6770014ab07`, 15 seconds, base concurrency
200, three iterations. I downloaded and inspected all 359 JSON samples and
their stderr files. There are 141 distinct gateway/protocol/payload groups;
direct baselines run only in iteration 1. Concurrency scales to 100 at 1 MiB
and 50 at 5 MiB. The 512000-byte payload is **500 KiB**, despite some older
comments calling it 512 KiB. [Extracted measurements](benchmark_audit_2026_09_17_results.json)
retain per-iteration rates, error counts, byte totals, and p99 latency.

[Run 35195212169](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35195212169)
tests `d8a37c6911aba89112fd2571e9364118964e7955` and has completed successfully.
The current-main comparison below audits all 359 samples. Its benchmark files are identical to
the earlier run; changes between the two commits affect Ferrum. The source
audit used local checkout `29b751eef` and checked differences against the run's
commit. The body, TCP relay, UDP relay, and direct-H2 pool findings below apply
to the run's revision too.

**Original-run clean losses worth pursuing.** Values below are means across all three
iterations; both named gateways completed work with zero reported errors and
correct byte totals in all three. Other competitors in the same scenario may
have failed, so these are pairwise observations, not a complete scoreboard.
Percentages mean competitor RPS / Ferrum RPS minus one. Small differences need
interleaved replication before they justify architectural changes.

| Protocol | Payload | Ferrum RPS | Competitor RPS | Competitor lead |
|---|---:|---:|---:|---:|
| HTTPS/1.1 | 10 KiB | 24,802 | Envoy 26,512 | 6.9% |
| HTTPS/1.1 | 500 KiB | 1,053 | Envoy 1,286 | 22.2% |
| HTTPS/1.1 | 1 MiB | 546 | Tyk 636 | 16.5% |
| HTTPS/1.1 | 1 MiB | 546 | Envoy 616 | 12.8% |
| HTTPS/1.1 | 5 MiB | 125 | Tyk 140 | 12.0% |
| HTTPS/1.1 | 5 MiB | 125 | Envoy 131 | 4.4% |
| HTTP/2 TLS | 10 KiB | 13,300 | Envoy 13,878 | 4.4% |
| WSS | 500 KiB | 976 | Tyk 990 | 1.4% |
| WSS | 1 MiB | 466 | Tyk 523 | 12.3% |
| UDP | 1 KiB | 77,681 | Kong 81,643 | 5.1% |

KrakenD's HTTPS/1.1 means are 1,459 / 778 / 178 RPS at 500 KiB / 1 MiB /
5 MiB, roughly 39–43% above Ferrum. Every one of those groups contains errors;
only the third 5 MiB sample is clean. This is an optimization lead, not an
error-free victory. Envoy's 10 KiB gRPC mean is 13,855 versus Ferrum's 11,494
(20.5% higher), but Ferrum's second iteration recorded 159 errors. Both clean
Ferrum iterations also trail Envoy; first diagnose the failing iteration.

Ferrum already leads Envoy on larger HTTP/2 and gRPC payloads, larger TCP/TLS
payloads, and smaller WSS messages. Protect those paths during optimization.
The reported HTTP/3 lead is approximately 3.2–4.7 times, but the old run lacks
observed admission, phase timing, and socket diagnostics needed for a fair comparison.

**Correctness and measurement problems.** Forty-seven of 359 samples are
invalid under the common requirements of positive successful work, zero
errors, and `total_bytes == total_requests * payload_size`.

| Ferrum case | Errors in iterations 1 / 2 / 3 | Evidence |
|---|---:|---|
| HTTP/2, 70 KiB | 177 / 168 / 0 | stderr includes HTTP 502 responses |
| gRPC TLS, 10 KiB | 0 / 159 / 0 | JSON error counters |
| gRPC TLS, 70 KiB | 195 / 0 / 0 | JSON error counters |
| WSS, 5 MiB | 20 / 15 / 11 | 30-second echo timeouts in every iteration |

Kong TCP/TLS iterations 2 and 3 report zero requests **and zero errors** at
every payload. The shared `collect_results` discarded failed task outcomes
after logging them. Kong also has gRPC wall-clock timeout placeholders.
The old summary averaged these observations and displayed only the last
iteration's error count; its scoreboard did not exclude positive-RPS rows
with errors. Re-rendering the artifacts with the revised validity rules
excludes 16 of 31 opposed scenarios. The remaining 15 still include old H3
measurements: passing validity checks does not prove configuration parity.

The following limitations applied after the initial reporting repair (the
section-1 harness follow-up below addresses timing, observations and pairing):

- Client, backend, and gateway share a runner. Throughput includes their CPU,
  memory, scheduling, and TLS costs. Direct/gateway RPS differences are useful
  diagnostic ratios, not measurements of proxy CPU overhead.
- Gateway order is fixed and direct baselines are not repeated. Runners differ
  between protocols: the original logs show EPYC 9V45, 9V74, 7763, and Xeon
  Platinum 8370C machines. Compare
  competitors within a job; use paired/interleaved runs for revision comparisons.
- The H3 deadline starts before sequential connection establishment. Successful
  requests admitted before the deadline can finish afterward, yet RPS divides
  by the nominal duration. Short, slow runs are particularly sensitive to this.
  Establish connections, warm up, synchronize workers, then measure a common
  interval and report drain time separately.
- Failed workers retire, so concurrency can fall during a sample. The JSON's
  `effective_concurrency` is a requested worker count, not observed active
  streams. Record worker loss and actual concurrency/queueing in a future
  harness revision; invalidate any failed sample rather than retrying it away.

**Section 1 harness follow-up (#5588).** The new client establishes transports,
warms each worker with one validated echo, waits at a common measurement barrier,
and drains admitted exchanges separately. Only completions before the exclusive
deadline enter throughput and latency; warmup and drain counts/times are retained.
H3 endpoints explicitly close after drain. Sampled worker, physical client
connection, locally admitted stream/exchange and client admission-queue gauges
replace inference from requested `effective_concurrency`. Queue totals, barrier
participation and worker retirement are recorded in every raw sample. Server
stream admission and kernel/QUIC queue depths remain separate transport questions.

The runner now defaults to two counterbalanced same-host pairs per
invocation, repeats direct in every pair, and supports a separately provisioned
`ferrum-baseline` image for revision comparisons. Per-PID gateway/client/backend
CPU and RSS series include explicit measurement brackets and sampling slack.
The shell retains the static `timeout`/`gtimeout` client invocation; a passive
500 ms `/proc` sampler observes it and is signalled/reaped after the load.
Client CPU now comes from its own `getrusage` snapshots at the measurement
boundaries, with lifetime peak RSS recorded at the end; every required process
role must have a complete bracket. Never-observed transient gateway PIDs are
diagnostic. At least one gateway PID must be observed, and every observed gateway
PID must span the measurement window; even a PID observed once that exits
mid-window invalidates the sample. Only even pair counts are accepted, and the
combined summary exposes position balance.
Adaptive extension is opt-in and gated on measured per-pair cost and remaining
wall-clock budget; the frozen job defaults to two pairs without extension.
Use at least four predeclared pairs for a performance claim. Invalid pairs remain invalid; unresolved
uncertainty requires a longer predeclared experiment. This exploratory adaptation
does not by itself establish a statistically confirmed gain. Existing report
fields remain available, with raw constituent samples retained in aggregate
artifacts. The Cross-frozen benchmark job is unchanged.

See the [harness phases and paired procedure](../tests/performance/multi_protocol/README.md#phases-and-observed-concurrency-tracker-5588-section-1)
for definitions and caveats. TCP/TLS now uses bounded full-duplex echoes instead
of its former unbounded writer pipeline, identically for all gateways; its older
rates are therefore not a workload-matched reference. The explicit rolling-budget
`workload_revision` is now `2026-09-18.phased-bounded-echo.v1`: the evaluator
excludes old/unmarked points and restarts its window, preventing a deliberate
workload/accounting change from alerting as a regression. Absolute budgets and
the shared-harness historical H1 ratio reference remain unchanged. The historical runs in this
audit are not retroactively repaired by the harness change. A short hosted smoke
run verifies artifact plumbing, not a revision performance improvement; production
optimization experiments and the rest of #5588 remain open.

**Completed current-main comparison.** Run 35195212169 has the same 141 groups,
359 samples, three iterations, 15-second duration, and scaled concurrency as
the original. All 359 samples completed positive work with exact byte totals,
but **38 contain reported errors**, across 21 groups: Ferrum 12 samples,
KrakenD 12, Envoy 11, and Kong 3. Applying the validity rules excludes 15 of
31 opposed scenarios; five of the remaining scenarios are H3 with unverified
transport fairness. This is not a clean overall run.

The repeatable priorities persist. Selected pairwise comparisons below require
all three iterations of both named gateways to pass the reported validity
checks. Small differences still need paired replication.

| Protocol | Payload | Ferrum RPS | Competitor RPS | Competitor lead |
|---|---:|---:|---:|---:|
| HTTPS/1.1 | 10 KiB | 10,674 | Envoy 11,836 | 10.9% |
| HTTPS/1.1 | 500 KiB | 574 | Tyk 748 | 30.4% |
| HTTPS/1.1 | 1 MiB | 307 | Tyk 397 | 29.4% |
| HTTPS/1.1 | 1 MiB | 307 | Envoy 375 | 22.2% |
| HTTPS/1.1 | 5 MiB | 66 | Tyk 90 | 35.6% |
| HTTPS/1.1 | 5 MiB | 66 | Envoy 80 | 21.0% |
| HTTP/2 TLS | 10 KiB | 23,731 | Envoy 27,746 | 16.9% |
| WSS | 1 MiB | 459 | Tyk 523 | 14.0% |
| UDP | 1 KiB | 101,093 | Kong 106,880 | 5.7% |

Tyk's WSS leads at 70 KiB and 500 KiB are only 1.8% and 1.2%. Envoy's
500 KiB HTTPS mean is higher than Ferrum's but includes an error, so it is
excluded here. Every KrakenD HTTPS group again contains at least one failing
iteration. Ferrum still leads clean larger H2 and 1/5 MiB gRPC comparisons.
Its H3 means are 3.9–5.5 times Envoy's; those runs do not establish transport fairness.

| Ferrum case | Current errors, iterations 1 / 2 / 3 | Evidence |
|---|---:|---|
| HTTP/2, 70 KiB | 0 / 169 / 0 | stderr includes HTTP 502, 31-byte body |
| gRPC TLS, 10 KiB | 0 / 0 / 141 | JSON counters; stderr empty |
| gRPC TLS, 70 KiB | 143 / 168 / 0 | JSON counters; stderr empty |
| gRPC TLS, 500 KiB | 194 / 0 / 0 | JSON counters; stderr empty |
| WSS, 5 MiB | 23 / 33 / 5 | 30-second echo timeouts |
| TCP/TLS, 10 KiB | 0 / 1 / 0 | 15-second read timeout |
| TCP/TLS, 70 KiB | 0 / 0 / 1 | 15-second read timeout |
| TCP/TLS, 500 KiB | 0 / 0 / 1 | 15-second read timeout |
| TCP/TLS, 1 MiB | 0 / 0 / 1 | 15-second read timeout |

Kong's earlier zero-work TCP/TLS samples did not recur; its 5 MiB samples
instead report 16/13/9 errors with missing TLS close-notify in stderr. Envoy
also has TCP/TLS read timeouts. All 359 stderr files and 24 harness run logs
were inspected. This old harness retained no per-sample gateway/backend logs,
so these symptoms cannot yet be assigned a server-side root cause. The new
diagnostic capture in #5587 is needed for that investigation. The error count
decreasing from 47 invalid samples to 38 is not proof of a correctness fix.

Hardware makes revision-to-revision RPS especially misleading here:

| Protocol | Original runner CPU | Current-main runner CPU |
|---|---|---|
| HTTPS/1.1 | EPYC 9V45 | EPYC 7763 |
| HTTP/2 | EPYC 9V74 | Xeon 6973P-C |
| HTTP/3 | EPYC 9V45 | EPYC 7763 |
| gRPC TLS | Xeon Platinum 8370C | EPYC 9V74 |
| WSS | EPYC 7763 | EPYC 7763 |
| TCP/TLS | EPYC 9V74 | EPYC 7763 |
| UDP | EPYC 7763 | EPYC 9V74 |
| UDP/DTLS | EPYC 9V74 | EPYC 7763 |

At 10 KiB, Ferrum HTTPS falls 57.0% while direct falls 55.0%; Ferrum H2 rises
78.4% while direct rises 83.3%; Ferrum H3 falls 50.1% while direct falls 49.1%.
Those parallel movements are evidence of substantial environment effects,
not isolated regressions or improvements. Even a matching CPU model does not
make two hosted VMs a controlled pair. WSS direct rates move only 1.8–6.0%
down and Ferrum's 1 MiB gap to Tyk persists (12.3% then 14.0%), strengthening
that investigation priority. UDP's gap also persists (5.1% then 5.7%). The
evidence JSON retains current per-iteration p50/p99, rates, errors, byte totals,
stderr summaries, and both runs' CPU models. Use same-host interleaved A/B
measurements before attributing any cross-run change to code.

Follow-up correctness and profiling work is tracked in
[issue #5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

**Section 2 — same-host HTTP/3 transport experiment (18 September).**
The follow-up uses a committed
[`h3_experiment.json`](../tests/performance/multi_protocol/h3_experiment.json),
leaving the frozen benchmark job unchanged. Its four arms are direct, Ferrum,
Envoy 1.33.5 with limit 100, and the same Envoy image with limit 4. Both legs'
stream limits change together; all other Envoy configuration, SNI `localhost`,
CA verification, offered work, and strict HTTP 200/exact-body validation remain
the same. Two reversed-order pairs use 10-second measured intervals, one
iteration, and payloads 10,240 / 1,048,576 / 5,242,880 bytes. No adaptive
extension or error retry is enabled. These two-pair Student-t 95% intervals are
exploratory; they cannot establish a small performance improvement.

| Payload | Offered workers | Client connections | Limit 4 ceiling | Limit 100 ceiling |
|---|---:|---:|---:|---:|
| 10 KiB | 200 | 21 | 84 | 200 |
| 1 MiB | 100 | 11 | 44 | 100 |
| 5 MiB | 50 | 6 | 24 | 50 |

The ceilings follow the client's unchanged round-robin assignment, at most ten
workers per connection. Observed client stream admission is recorded separately.
Linux defaults and explicit Envoy options target **4,194,304 effective bytes for
each socket's receive and send buffer**. Linux doubles explicit `SO_*BUF`
requests, so Envoy requests 2,097,152 bytes on both downstream and upstream
sockets; Ferrum/Quinn inherit the kernel defaults. Socket counts and total
gateway memory are not equated. Independent `NETLINK_SOCK_DIAG` readbacks and
`/proc/net/udp{,6}` drops accompany host-namespace `/proc/net/snmp` deltas.
The latter include client and backend activity and must not be attributed solely
to a gateway. Socket cookies distinguish lifetimes; absent/reset counters remain
unknown. Unverified buffer parity or incomplete transport brackets reject the
paired comparison.

Per-thread CPU and backend per-connection accepted/completed echo counters now
provide distribution evidence with explicit sampling slack. Info-level startup
logs expose BPF/GRO/GSO warnings, and Docker timestamps plus sampled raw Envoy
stats retain watchdog, idle-close and `TOO_MANY_RTOS` observations. No warning
alone proves that an optimized path ran. Envoy 1.33.5's cumulative `SO_RXQ_OVFL`
counting bug remains in the pin; only independent kernel/socket deltas quantify
drops. Testing a verified corrected Envoy build remains a separate experiment.

Client drivers retain timestamped close reasons and final Quinn transport stats.
Endpoints close after worker drain under a shared five-second bound; drivers are
joined or aborted and reaped. `PhaseReport.transport_events` separates measured
work, drain, and explicit retirement. Follow-up commit `01991acfa` also timestamps
individual request failures and validates buffer readbacks at both boundaries.
The corrected experiment also holds transports for 750 ms at the ready barrier
and after drain so the passive 500 ms sampler brackets short-lived sockets.
Both holds are outside measurement and apply to every arm.

Hosted harness tests passed on each implementation commit. The measurement
commit `e5d1ee403` passed 17 Rust and 38 Python tests in
[run 35349584431](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35349584431),
including a live Linux check that passive socket-buffer readings equal
`getsockopt`. Follow-up `3840ea84d` retains sockets first seen inside the measured
interval and rejects their incomplete buffer brackets, omits process RSS from
thread records, and advances the regression workload revision to
`2026-09-18.h3-transport-observation.v2`. Its
[hosted test run 35352460596](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35352460596)
passed 17 Rust and 39 Python tests. No project code, build, test, formatter, or
script was executed locally.

**Initial diagnostic run and corrections.**
[Run 35345234851](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35345234851)
tested `c8e95b86502f22f6b5d43bb8807514fdba83e5e7` on a four-vCPU AMD EPYC 7763
runner. All 24 samples had positive work, zero errors, exact echo bytes, no
transport-close timeout, and no client-driver closure during measurement.
Nevertheless, its Envoy comparisons are **rejected**: the passive stats parser
mistook Envoy's histogram wrapper for a named scalar counter. Fast 10 KiB
upstream sockets and direct client teardown also escaped a complete sampling
bracket. The raw data remain in the combined artifact's `run_1/` directory.
The top-level flattened files were empty because download-artifact flattens a
single protocol artifact despite `merge-multiple: false`; the aggregate now
handles both layouts and fails explicitly if it cannot discover runs.

Crucially, **both apparent stream-limit arms admitted 200/100/50 client exchanges**.
The historical four-stream setting in downstream HCM `http3_protocol_options`
did not set the listener's QUIC transport limit. The intended 84/44/24 ceilings
require `udp_listener_config.quic_options.quic_protocol_options` instead.
The corrected generator pins that listener field as well as upstream capacity.
The [pinned listener API](https://github.com/envoyproxy/envoy/blob/v1.33.5/api/envoy/config/listener/v3/quic_config.proto)
and [listener implementation](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/common/quic/active_quic_listener.cc)
identify the relevant configuration. Thus the older claims in this audit and
tracker that the historical cap necessarily restricted downstream admission
were wrong; changing only the HCM field was not a downstream cap experiment.
The corrected run tests a real two-leg limit ablation. Local active-exchange
gauges include validation after transport closure and are not exact server
stream counters; queues and the pinned transport limits must be read together.

**Corrected measured outcome.**
[Run 35349581624](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35349581624)
completed the scoped experiment and aggregate successfully in about 36 minutes,
on `e5d1ee40301f54acf917011689f1eb56548df1f0`. The runner exposed four vCPUs,
AMD EPYC 9V74, 15 GiB RAM, and 0.0% steal in the startup probe; its boot ID was
`520d831f-46da-48e4-83ef-d4583ab8c660`. This is a different CPU model from the
initial diagnostic run, so their raw rates are not revision comparisons.
The Ferrum image ID was
`sha256:a5b7d5a0fad885f1400b1458e16b206bae0e37b23b704e0d787f65bdecf87b3b`;
both Envoy arms used
`envoyproxy/envoy@sha256:7684e69b9cf0af4008d851ec85bfd2874145ed61a1890dd3ff13d359306f923e`.
The combined artifact is
`gateways-protocol-bench-combined-e5d1ee40301f54acf917011689f1eb56548df1f0`.
It contains all 24 `observed-samples.json` records, the aggregate's
`paired-comparisons.json`, and raw logs/configs/sampler timelines under
`run_1/pairs/pair_001/diagnostics/` and `pair_002/diagnostics/`.
Orders were direct/Ferrum/Envoy-100/Envoy-4 and their exact reverse, giving
every arm mean position 2.5. Inputs were duration 10, concurrency 200,
iterations 1, skipped protocols `http1-tls http2 grpcs wss tcp-tls udp udp-dtls`,
skipped gateways `kong tyk krakend`, and skipped sizes `71680 512000`.

All **24/24** samples completed positive measured work with zero request errors,
exact expected body bytes, all offered workers at the barrier, and no early
worker retirement. All client stderr files were empty. **23/24** samples pass
the full comparison requirements: Envoy-100/10 KiB/pair 1 had one 200 ms
admin-stats query timeout at Unix time `1789739427.2701783`. Its transport
observation is incomplete even though its kernel counters and buffer readbacks
are present. The aggregate rejects every comparison involving that pair; no
retry, dropped observation, or one-pair estimate replaces it. A future 10 KiB
comparison needs a predeclared observation timeout/cadence that survives this
load, applied uniformly, followed by a complete new paired experiment.

Useful RPS below is **pair 1 / pair 2**. The starred cell is diagnostic only.

| Payload | Direct | Ferrum | Envoy-100 | Envoy-4 |
|---|---:|---:|---:|---:|
| 10 KiB | 39,449.7 / 41,010.6 | 15,090.8 / 15,353.4 | 2,818.0 / 2,941.4 * | 2,763.3 / 2,749.4 |
| 1 MiB | 531.3 / 535.9 | 225.7 / 225.5 | 51.2 / 47.4 | 51.8 / 49.3 |
| 5 MiB | 109.3 / 110.7 | 45.5 / 44.4 | 6.9 / 7.2 | 7.0 / 9.0 |

These are the aggregate artifact's matched-pair geometric ratios and Student-t
95% intervals, rounded here. Both cap intervals include 1; **neither establishes
a throughput benefit from changing 4 to 100**. The missing 10 KiB cap interval
is a rejected observation, not a claim of equivalence.

| Payload | Envoy-4 / Envoy-100 [95% interval] | Ferrum / Envoy-100 [95% interval] |
|---|---:|---:|
| 10 KiB | rejected: incomplete pair | rejected: incomplete pair |
| 1 MiB | 1.026 [0.861, 1.223] | 4.579 [2.822, 7.433] |
| 5 MiB | 1.126 [0.299, 4.242] | 6.377 [4.165, 9.762] |

The cap did change admission. Connections remained exactly 21/11/6 in every
arm. With limit 4, mean queued client requests were 116.53–116.66,
56.56–56.59, and 27.36–27.90 across ascending payloads; with limit 100 they
were 0.008–0.009, 0.007–0.013, and 0.308–0.316. The client-local
active-exchange maxima were 85/86, 45/45, and 24/24 for limit 4, versus
200/200, 100/100, and 50/50 for limit 100. A locally validated exchange can
outlive transport stream closure, so the small excess over the 84/44 transport
ceilings is not a server stream-limit violation. Sampled Envoy active-request
maxima were 81/81, 41/43, and 23/18 for limit 4, versus 197/194, 100/100,
and 50/50 for limit 100. These sampled gauges corroborate the admission
restriction but are not exact maxima or counts of open QUIC streams.

Envoy-100 p99 was 108–120 ms, 4.27–4.43 s, and 9.07–9.93 s; Envoy-4
p99 was 302–351 ms, 6.43–6.99 s, and 9.22–9.88 s. Ferrum p99 was
25.3–25.9 ms, 0.914–0.933 s, and 1.85–1.96 s. Every sample separately
drained 200/100/50 outstanding requests. At 5 MiB, drain took 0.53–0.70 s
for Ferrum, 2.00–2.33 s for Envoy-100, and 4.72–5.40 s for Envoy-4;
those completions are excluded from useful RPS.

**Buffers and real drop observations.** Every identified socket read back
4,194,304 bytes for both `SO_RCVBUF` and `SO_SNDBUF` at both boundaries in
all 24 samples. Static inspection of every raw timeline found no newly observed
relevant socket inside its measurement bracket, including sockets absent again
at the ending snapshot; the later socket-churn guard does not change this finding.
Ferrum's four upstream connections shared one UDP socket, alongside one
downstream socket. Envoy-100 used four upstream and four downstream sockets.
Envoy-4 retained 21/14 upstream sockets in pairs 1/2 at 10 KiB and 1 MiB,
then four in each pair at 5 MiB; its downstream count stayed four. Thus this
verifies equal **per-socket** budgets, not equal aggregate buffer ceilings or
memory consumption. Envoy's larger number of sockets must remain visible.

The following receive-drop counts are **pair 1 / pair 2**, from matched socket
lifetimes. Netlink `socket_drops` and `/proc/net/udp` drops agree exactly.
`RcvbufErrors` is the shared-host UDP counter; send-buffer error deltas were
zero in all 24 samples. All these counts were zero for the gateway arms at
10 KiB. They are bracketed counters, not packet-loss percentages.

| Arm / payload | Gateway downstream drops | Gateway upstream drops | Backend drops | Host `RcvbufErrors` |
|---|---:|---:|---:|---:|
| Ferrum / 1 MiB | 709 / 563 | 1,526 / 1,445 | 0 / 107 | 2,235 / 2,115 |
| Ferrum / 5 MiB | 532 / 622 | 1,217 / 1,349 | 373 / 36 | 2,122 / 2,007 |
| Envoy-100 / 1 MiB | 537 / 239 | 0 / 65 | 0 / 0 | 537 / 304 |
| Envoy-100 / 5 MiB | 104 / 125 | 64 / 21 | 0 / 0 | 168 / 146 |
| Envoy-4 / 1 MiB | 360 / 601 | 26 / 0 | 0 / 0 | 386 / 601 |
| Envoy-4 / 5 MiB | 924 / 915 | 24 / 175 | 0 / 0 | 948 / 1,090 |

Direct host receive errors were 0/0, 4,155/4,421, and 4,558/3,571 across
ascending payloads. Successful echo completion therefore did **not** mean
drop-free transport for either gateway or the direct baseline. Differing
throughput and socket counts prevent interpreting raw drop-count differences
as isolated implementation efficiency. Meanwhile Envoy's invalid cumulative
downstream drop statistic ended at 200,011,926 / 234,557,347 for limit 100
and 217,538,091 / 175,782,146 for limit 4. Those values are retained as
evidence of the known accounting defect, never used as loss totals.

**Retirement and startup evidence.** Every client connection reported
`H3_NO_ERROR`, `Connection closed by client`, and Quinn `LocallyClosed` during
the timestamped `transport_close` phase. There were no driver closures or
request-failure events during measurement or drain, and no close deadline
expired. Endpoint retirement took 0.089–2.186 s. No `TOO_MANY_RTOS` or
downstream idle-close event was recorded in the sampled/final Envoy stats.
Envoy-4 did record **17 / 10 upstream `QUIC_NETWORK_IDLE_TIMEOUT` closures**:
they first appeared at Unix times `1789739503.771731` / `1789739564.7888892`,
before the 5 MiB measurement starts `1789739512.1152377` / `1789739572.8624496`.
They match the surplus idle upstream pools shrinking from 21/14 to four,
rather than failed measured requests. The rejected Envoy-100/10 KiB/pair 1
also recorded one worker-3 watchdog miss during its measurement bracket;
the stats-query timeout and slow 2.186 s retirement are retained, without
claiming a causal link. No other measured watchdog counter increased.
Post-sample snapshots retained zero upstream H1/H2 connections, request retries,
and request timeouts.

Info-level startup logs from **both pairs and both gateways** are present.
Envoy lists its compiled GSO packet-writer extension but reports no BPF/GRO/GSO
fallback warning. It warns about an unset global downstream connection limit.
Ferrum reports a successful generic UDP GSO probe and a reserved/inactive generic
UDP GRO setting; neither message proves the Quinn HTTP/3 path used that feature.
Its HTTP/2/reqwest warmup warnings target the UDP-only backend port and do not
correspond to failed H3 work. **Optimized path use remains unverified.** Positive
verification needs runtime instrumentation or kernel tracing of reuseport BPF
steering and actual UDP segmentation/GRO ancillary data for Envoy and Quinn;
absence of warnings or a compiled extension list is insufficient. A separately
pinned image verified to contain Envoy's counter correction is also still needed.

**Upstream distribution and worker CPU.** At 10 KiB and 1 MiB, four upstream
connections carried work for each gateway; Envoy-4's additional pooled
connections had zero measured completions. Ferrum's per-connection completion
counts were nearly equal (at 1 MiB, 590/589/589/589 and 589/589/589/588).
Envoy-100 had 153/162/127/151 and 143/143/141/147; Envoy-4's four active
connections had 134/127/158/129 and 127/127/137/141. These backend observations
have explicit boundary slack and can include completions in the bracketing
margin; they are distribution evidence, not substitute RPS counts.

At 5 MiB, the profiles show a material connection/worker imbalance:

| Arm / pair | Backend completions on four pooled connections | CPU seconds on gateway workers |
|---|---|---|
| Ferrum / 1 | 117, 116, 114, 118 | 4.59, 4.62, 4.75, 4.58 |
| Ferrum / 2 | 116, 118, 117, 117 | 4.57, 4.63, 4.69, 4.59 |
| Envoy-100 / 1 | 25, 34, 34, 0 | 8.58, 0, 8.64, 8.16 |
| Envoy-100 / 2 | 31, 0, 34, 34 | 8.33, 8.73, 8.55, 0 |
| Envoy-4 / 1 | 0, 0, 44, 35 | 10.00, 0, 0, 10.05 |
| Envoy-4 / 2 | 25, 26, 31, 24 | 6.92, 5.98, 5.79, 6.85 |

Connection order is its recorded backend order, not a proven connection-to-TID
mapping. Envoy CPU columns are workers 0–3; Ferrum lists its four busy runtime
workers (two additional runtime threads had zero CPU). Process/thread brackets
span about 10.13–10.85 s, with the slack recorded per sample. At 5 MiB,
Ferrum gateway/backend/client CPU was approximately 18.5/10.1/9.0 s; Envoy-100
was 25.4–25.6/8.1/3.8–3.9 s. Gateway sampled peak RSS was 281–297 MB for
Ferrum, 1,308–1,398 MB for Envoy-100, and 677–734 MB for Envoy-4 (decimal MB).

Six downstream connections can leave Envoy workers idle in this topology;
in Envoy-4/pair 1, only two workers consumed substantial CPU, while pair 2 used
all four. This is consistent with worker routing contributing to the 5 MiB
variance, but does not isolate its cost from QUIC processing or flow control.
Client, backend, sampler and gateway share the four vCPUs; the Envoy admin
polling adds observer overhead too. These results do **not** establish that the
remaining gap is pure forwarding inefficiency. A longer predeclared experiment
with more pairs, positive transport-path instrumentation and per-worker stack
profiles is needed before production tuning. Preserve the same offered topology
across arms; any topology ablation must be a separately named experiment.

**Historical Envoy HTTP/3 repair (pre-phase harness).** The configuration history is unusually
helpful: [PR #533](https://github.com/ferrum-edge/ferrum-edge/pull/533),
[PR #552](https://github.com/ferrum-edge/ferrum-edge/pull/552), and
[PR #554](https://github.com/ferrum-edge/ferrum-edge/pull/554).
The first changes adjusted windows and buffers after resets. The last combined
four-stream limits, disabled route timeout, strict status/body validation, and
an actual TLS fix: explicit `sni: localhost`. Its investigation observed local
503 replies because the upstream hostname was empty. Older higher numbers
therefore cannot automatically be interpreted as useful successful throughput.

At concurrency 200 the client's 21 QUIC connections can offer about ten streams
each. An effective downstream four-stream limit would admit at most 84
simultaneously, or 44/24 at concurrency 100/50. The initial audit incorrectly
assumed the HCM setting imposed that limit; the September 18 experiment above
disproved it. The fixed client pool cannot create extra downstream connections.
Envoy's
[v1.33.5 upstream pool](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/common/http/http3/conn_pool.cc)
also uses the configured stream limit for upstream client capacity.

The old rationale, `4 * 6 MiB = 24 MiB`, is not a QUIC safety requirement.
Connection and stream flow-control credit advances as data is consumed; a
connection need not have credit for every whole body simultaneously.
Backpressure must operate when credit is exhausted.
[RFC 9000 §4](https://www.rfc-editor.org/rfc/rfc9000.html#section-4)
and [Envoy's QUIC integration](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/docs/quiche_integration.md)
describe these mechanisms. The [v1.33.5 protocol options](https://github.com/envoyproxy/envoy/blob/v1.33.5/api/envoy/config/core/v3/protocol.proto)
do cap the connection window at 24 MiB; that fact alone does not justify four streams.

The historical candidate sets **100 streams** in the HCM and upstream options,
retaining configured 6 MiB upstream stream windows, 24 MiB upstream connection
windows, 128 MiB connection buffers, disabled route timeout, trusted CA, explicit
SNI, and byte-for-byte HTTP 200 echo validation. It introduces no retries,
buffering filter, or protocol fallback.

Local validation used the unchanged benchmark client/backend:

- Native macOS Envoy 1.37.1: limits 4, 16, and 100; all five payloads; 200/100/50
  workers as in the workflow; five seconds per sample. All 15 samples completed
  with zero errors and exact byte totals.
- Pinned Linux Envoy 1.33.5: limits 4 and 100; all five payloads; the same scaled
  worker counts; ten seconds per sample. All ten samples completed with zero
  errors and exact byte totals. Config validation passed for both settings.
  Envoy ran natively as ARM64 in Colima; the x86 client/backend ran under
  emulation in a container sharing its network namespace. Initial attempts to
  emulate Envoy itself failed at socket-option setup and were discarded as
  environment failures. Neither architecture is the hosted x86 runner.

The local rate changes were mixed, without a consistent improvement from
changing the HCM/upstream limits. The completed hosted check below validates
successful requests with those settings. It did not test a downstream transport
cap, as established by the September 18 correction above.

**Completed hosted HTTP/3 candidate.**
[Run 35198436672](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35198436672)
tested `f2961bf1a9d4c72236e2b06f5473bf945d5f45af` on an x86 EPYC 7763 runner,
using pinned Envoy 1.33.5 with HCM/upstream limits of 100. All **35 expected
samples** passed: 15 Envoy, 15 Ferrum, and five direct baselines. Every sample
had positive completed work, zero client errors, and exact expected byte totals;
all three manifests matched the observed matrix. Every client stderr file was
empty. All 35 backend logs contained only the startup banner; all 30 gateway
logs were empty at the configured error log level.

All 15 Envoy stats snapshots were retrieved successfully. At each snapshot,
cumulative upstream HTTP 200/completed and downstream 2xx/completed counters
exactly matched cumulative client completions: final totals 34,339 / 34,816 /
35,273 across iterations. Upstream H1/H2 connection counts, request retries,
request timeouts, and upstream H3 RX/TX resets were zero throughout. Four
upstream H3 connections remained pooled, with no requests active or pending
at the post-sample snapshots. This verifies successful H3 forwarding without
protocol fallback or retries hiding failed requests.

| Payload | Ferrum mean RPS | Envoy mean RPS | Ferrum / Envoy | Envoy per-iteration p99 range |
|---|---:|---:|---:|---:|
| 10 KiB | 9,903 | 1,818 | 5.45× | 160–245 ms |
| 70 KiB | 1,994 | 379 | 5.26× | 811–1,305 ms |
| 500 KiB | 309 | 77 | 4.02× | 5.10–5.38 s |
| 1 MiB | 177 | 38 | 4.62× | 5.74–7.48 s |
| 5 MiB | 39 | 8 | 4.90× | 14.59–19.84 s |

The current-main H3 runner had the same CPU model, though it was a different
VM and revision. Relative to that old-cap run, Envoy mean RPS changed by
+1.5%, −8.5%, −0.1%, +1.9%, and +15.5% across ascending payloads. Direct
rates moved +0.8–2.6% and Ferrum +1.1–2.7%. These are observations, not a
controlled cap-only A/B. Changing those settings did not produce a broad
throughput recovery or establish equal downstream admission. At 5 MiB, one p99
exceeds the nominal 15-second duration, underlining the measurement/drain limitation described
above. Report these as nominal-duration rates until that timing is repaired.

Request success does **not** mean the transport diagnostics were uneventful:

- Cumulative downstream QUIC `TOO_MANY_RTOS` counts finish at 13/8/11;
  `SILENT_IDLE_TIMEOUT` at 34/51/39. These snapshots span successive payloads
  in one Envoy process and include earlier client connections. That revision's H3
  client did not explicitly close/drain its connection pool before process exit.
  Post-request teardown is therefore a plausible contributor, not an
  established explanation. Time-resolved connection events are needed before
  counting these closures as failed measured requests or dismissing them.
- The downstream UDP drop counter finishes at 191,187,978 / 176,100,361 /
  161,008,805. **Those are not credible actual loss totals.** The pinned
  [v1.33.5 socket implementation](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/common/network/io_socket_handle_impl.cc#L403)
  adds the kernel's cumulative `SO_RXQ_OVFL` value on every read in both
  receive paths (also line 528). Upstream
  [issue #38431](https://github.com/envoyproxy/envoy/issues/38431) and
  [fix #38652](https://github.com/envoyproxy/envoy/pull/38652) identify and
  correct this repeated counting. The inspected pin still has the old code.
  Real receive pressure remains possible; the counter's magnitude cannot
  quantify it. Obtain kernel/socket drop deltas independently.
- One worker watchdog miss appears in iteration 1. Empty error-level logs
  cannot establish that optimized UDP worker routing was available: Envoy's
  [pinned H3 documentation](https://github.com/envoyproxy/envoy/blob/v1.33.5/docs/root/intro/arch_overview/http/http3.rst)
  recommends BPF for multiple workers and documents startup warnings if it
  cannot be used. That harness revision suppressed warnings.

Those findings motivated the September 18 experiment above: independent buffer
and drop observations, visible startup warnings, explicit transport retirement,
and upstream/worker distribution profiles. A verified Envoy build containing the
counter correction and positive evidence of BPF/GRO/GSO path use remain needed
before claiming complete transport fairness. Request success alone establishes
neither condition.

Both requested runs and the candidate are now analyzed. The report and JSON
retain the findings; #5588 remains open for the correctness fixes, measurement
repairs, transport verification, and production optimization experiments.

### Section 4 — same-image HTTP/1.1 framing experiment

The first section-4 A/B is
[hosted run 35345033478](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35345033478),
revision `86724a319273e08277b82a83fc35d4bc22182561`, based on
`d44ca81545e9f96bd76c46db543d307a0422bf60`. The branch-committed
[`experiment.json`](../tests/performance/multi_protocol/experiment.json) selected
`ferrum` with `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` and
`ferrum-exp-cutoff-one` with `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1`. Both use
one image, one configuration, and identical useful-work validation. Direct is
repeated. The frozen benchmark matrix job is unchanged.

The runner was a 4-vCPU AMD EPYC 7763 VM under the Microsoft hypervisor,
with 15 GiB RAM, 3 GiB swap and 0.0% steal in the startup check. Host boot ID:
`1d9861a4-9ea3-4816-8319-a3bb5c028236`. Both Ferrum arms used image ID
`sha256:32d582ff627463224a83d55ab1850a17fb49141bf1d07ef0d4e14a5cc8c23b9b`
and `configs/http1_tls_e2e_perf.yaml` (no plugins, backend TLS on port 3447).
The image's revision label was absent; provenance is the workflow checkout
and recorded image ID, not an asserted OCI revision label.

Predeclared scope: HTTP/1.1 TLS on both legs, 30 seconds per sample, one
iteration, two counterbalanced pairs, all five payloads (10240/71680/512000/
1048576/5242880), offered workers 200/200/200/100/50. There are 30 expected
samples. Orders are direct/0/1 and 1/0/direct; all arms have mean position 2.
Adaptive extension is off. The conservative benchmark-step projection is
27.5 minutes; hosted build time is additional. This is an exploratory two-pair
experiment, not a confirmatory claim or a comparison against an older VM.
The actual benchmark step took 24m08s, image build 31m05s, and the entire
workflow finished in 56m32s. There was no second benchmark run or error retry.

The command used below ran the branch at the measured SHA above (the runner's
fixed default supplies `--pairs 2`). The final branch disables the manifest
after recording the result. To repeat, commit `enabled: true` on the intended
experiment branch before dispatching; record its new image and revision.

```bash
gh workflow run gateways-protocol-benchmark.yml \
  --ref worker/20260918-edge-5588-h1-framing-ab \
  -f duration=30 -f concurrency=200 -f iterations=1 \
  -f skip_protocols='http2 http3 grpcs wss tcp-tls udp udp-dtls' \
  -f skip_gateways='envoy kong tyk krakend' -f skip_payload_sizes=''
```

The passive `/proc` series now includes read/write accounting bytes and syscall
counters with the same CPU/RSS boundary brackets. The privileged reader observes
container PIDs without launching the client. H1 client observations add received
TLS wire records/bytes, Hyper data frames/bytes, and chunked/Content-Length
response counts. TLS framing is parsed below rustls without buffering payloads,
changing flushes or decrypting records. Each worker has separate counters.
See the [measurement definitions](../tests/performance/multi_protocol/README.md#same-image-environment-experiments-5588-section-4)
for boundary attribution and observer cost. Linux `syscr`/`syscw` are not all
socket calls; storage `read_bytes`/`write_bytes` are not network traffic. Client
Hyper frames are not the gateway's upstream frame count.

**Hosted results and retained evidence.** The
[combined artifact](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35345033478/artifacts/10549857170)
has SHA-256 `5ffe9dd128b69ae004d2bc2be91cab5cbec3a700c699c5ceff98074754928ead`.
All 30 raw observations, including failures, and all 15 hosted paired comparison
objects are retained in
[`5588-h1-cutoff-35345033478.json`](../tests/performance/multi_protocol/evidence/5588-h1-cutoff-35345033478.json).
The artifact expires October 18; its full passive time series remain useful
for follow-up. The download action extracted this single protocol directly into
`run_1/`. Consequently the old aggregate glob missed it: top-level
`observed-samples.json` and `paired-comparisons.json` are empty. The intervals
below are the **existing hosted output** in `run_1/paired_comparisons.json`,
which the combined artifact retained intact. This PR repairs the non-frozen
aggregate's single-artifact layout handling and includes named experiment arms
in all combined tables and rankings. It does not reinterpret missing output as
a clean run.

All 30 samples have positive completed work, exact echo byte totals, complete
process measurement brackets, and observed workers/connections fixed at the
offered 200/200/200/100/50. Every warmup/barrier completed; no worker retired
before the measurement deadline. **27/30 are valid**: three 5 MiB Ferrum samples
hit the shared drain deadline and reported one error each. Therefore both
5 MiB Ferrum groups and their paired comparison are invalid. Passing workflow
status does not override these sample failures.

| Payload | Cutoff 0 useful RPS | Cutoff 1 useful RPS | Cutoff 1 / 0, paired 95% interval |
|---------|--------------------|--------------------|---------------------------------|
| 10 KiB | 10,351.2 | 10,555.3 | 1.0202 (0.6573–1.5835) |
| 70 KiB | 3,139.1 | 3,102.8 | 0.9884 (0.9350–1.0448) |
| 500 KiB | 546.9 | 534.9 | 0.9780 (0.9461–1.0110) |
| 1 MiB | 290.5 | 283.5 | 0.9756 (0.9042–1.0527) |
| 5 MiB | Invalid group | Invalid group | No interval: invalid pair |

RPS is the equal-duration mean; ratios/intervals use matched log ratios with
Student-t, two pairs and one degree of freedom. All four accepted intervals
include 1. This rejects promoting cutoff `1` on the evidence available; it
does **not** prove equivalence or establish a slowdown. The particularly wide
10 KiB interval needs more predeclared pairs if revisited.

Per-sample latency ranges across the two pairs, in milliseconds (ranges of
quantiles, not pooled quantiles):

| Payload | Cutoff 0 p50 / p99 | Cutoff 1 p50 / p99 |
|---------|-------------------|-------------------|
| 10 KiB | 18.271–19.199 / 36.191–41.599 | 18.383–18.511 / 36.703–37.087 |
| 70 KiB | 61.439–61.727 / 126.783–128.063 | 62.111–62.527 / 129.151–133.247 |
| 500 KiB | 359.935–361.727 / 617.983–694.783 | 365.567–371.711 / 635.391–669.183 |
| 1 MiB | 343.807–345.343 / 542.719–552.447 | 352.255–353.279 / 536.575–572.415 |

The 5 MiB failures were cutoff 0/pair 1 and cutoff 1/pairs 1 and 2. Their
warmups lasted 66.856–66.917s and drains 30.002–30.004s; stderr records cancelled
tasks 8, 67 and 44 respectively. Cutoff 0/pair 2 finished cleanly (0.567s warmup,
0.467s drain), but it cannot rescue the group. At 1 MiB, cutoff 0/pair 1 and
both cutoff 1 samples also had 9.867–10.076s drains despite zero errors.
All gateway logs were empty, and backend logs contained only startup banners.
These observations do not locate the stall. Follow-up needs hosted connection
progress/timeout traces through warmup and drain, with the same offered work;
do not widen deadlines, lower one arm's concurrency or retry samples to obtain
a performance number.

Approximate measured cost/cadence below uses summed counters divided by summed
completed requests; RSS is the maximum sampled gateway RSS. Each cell is
**cutoff 0 / cutoff 1**. The 5 MiB row is retained diagnostic data from invalid
groups and must not be used to claim a performance or memory improvement.

| Payload | Gateway CPU ms/request | Gateway RSS MiB | Client TLS records/request | Client data frames/request | Gateway syscw/request |
|---------|------------------------|-----------------|----------------------------|----------------------------|-----------------------|
| 10 KiB | 0.210 / 0.211 | 138.6 / 137.7 | 1.00 / 1.00 | 1.00 / 1.00 | 2.01 / 2.01 |
| 70 KiB | 0.624 / 0.633 | 167.2 / 168.3 | 9.00 / 9.00 | 9.00 / 9.00 | 10.05 / 10.05 |
| 500 KiB | 3.504 / 3.597 | 158.8 / 164.9 | 63.16 / 63.13 | 63.16 / 63.13 | 65.60 / 65.64 |
| 1 MiB | 6.407 / 6.607 | 152.5 / 149.1 | 129.25 / 129.26 | 129.25 / 129.26 | 133.02 / 133.10 |
| 5 MiB (invalid) | 28.130 / 29.026 | 145.8 / 117.6 | 642.47 / 642.13 | 642.49 / 642.13 | 653.83 / 655.83 |

Both arms retain chunked responses with zero observed Content-Length responses;
all TLS parsers report zero errors. Mean received wire-record sizes remain
about 8.0–8.2 kB at 70 KiB and above in both arms. Direct has approximately
1/5/32/65/321 records per response across the five sizes and Content-Length
framing; this is a framing observation, not causal attribution to a particular
gateway adapter. The cutoff change produces no material change in observed
record/frame/write cadence. No individual-call timing or all-socket syscall
trace was captured.

All gateway I/O counters were readable. `read_bytes` and `write_bytes` were zero;
gateway `rchar` was only about 41.5–43.7 kB with 247–262 `syscr` calls per sample,
illustrating why these Linux accounting fields cannot represent socket receives.
The JSON retains every `wchar`, `syscw`, other I/O delta, client/backend/gateway
CPU/RSS record, observed queue/stream gauge and phase duration. Gateway CPU/I/O
brackets include about 0.59–0.62s slack around 30s (0.106s for clean 5 MiB/pair 2),
plus in-flight boundary work; normalized values are diagnostics rather than
precise per-response costs. No paired confidence interval for CPU or memory is
claimed. Client profiling adds overhead equally across arms, so these RPS values
should not be compared directly to older unprofiled runs.
The final harness marks future rolling data as
`2026-09-18.phased-h1-profile.v2` to start a fresh history window; this same-host
A/B remains pinned to its recorded experiment SHA.

**Pinned source comparison (read only).**
[Tyk v5.3.0](https://github.com/TykTechnologies/tyk/blob/v5.3.0/gateway/reverse_proxy.go#L332)
initializes a `sync.Pool` of 32 KiB buffers; `copyBuffer` acquires one, repeatedly
reads into it and writes the received slice, then returns it. `flushInterval`
selects immediate flushing for event streams and unknown-length responses;
`CopyResponse` otherwise uses the configured latency writer when enabled. This
is buffer reuse, not evidence of zero copied bytes.
[KrakenD v2.13.2 pins Lura v2.14.1](https://github.com/krakend/krakend-ce/blob/v2.13.2/go.mod#L38).
Lura's [no-op parser](https://github.com/luraproject/lura/blob/v2.14.1/proxy/http_response.go#L72)
retains a wrapped body reader plus status and headers. Its
[no-op renderer](https://github.com/luraproject/lura/blob/v2.14.1/router/gin/render.go#L149)
forwards metadata and calls `io.Copy`. Neither source inspection nor a no-op
name measures allocation/copy cost or makes the earlier error-affected KrakenD
results a clean victory. No competitor was executed in this experiment.

Ferrum already has the proposed single-frame mechanism: `CoalesceBuffer::Single`
retains a `Bytes` value and flushes it without copying; a second frame promotes
it to `BytesMut`, and a large frame bypasses aggregation. H1's existing
`COALESCE_TARGET` is 128 KiB. Its default coalescer flushes held data on upstream
Pending, EOF, trailers or error. Cutoff `1` selects this implementation for these
payloads without whole-response buffering. Both arms retain the existing unknown
streaming length. This A/B does not test restoring Content-Length or removing
truncation, trailer, deadline or late-policy handling.
Existing [allocation probes](../tests/unit/gateway_core/response_coalescing_allocation_tests.rs)
and [lazy-coalescer tests](../tests/unit/gateway_core/response_coalescing_lazy_tests.rs)
cover the single-frame/bypass and merge behavior; source inspection of those
tests is not a live allocation profile of the hosted proxy.

Allocations, internal copied bytes, gateway input frame counts and adapter/header
CPU attribution are **not observable** from these passive counters. Measuring
them needs a separately budgeted hosted profiling build with allocator/copy/frame
counters or permitted symbolized `perf`/eBPF probes, matching observer overhead
across arms. The current Docker release strips symbols and uses fat LTO; retain
matching symbols/frame pointers without changing optimization settings for CPU
attribution, and instrument copy sites to include inlined copies that a `memcpy`
probe misses. A dedicated streaming fixture must also exercise delayed tiny
frames, truncation, trailers, and late policy failure before changing aggregation
or adapters. The echo-only benchmark cannot certify their latency or semantics.

**Disposition by hypothesis.**

- **Enable existing bounded aggregation via cutoff `1`: reject promotion; keep
  cutoff `0` for this workload.** The four valid paired throughput intervals are
  above; none establishes a gain, and 5 MiB has no valid interval. This completes
  the first A/B tracker item with an explicit invalid-size result.
- **Add bounded aggregation/prompt flush/zero-copy single-frame variants: reject
  a new production change on this evidence.** These mechanisms already exist in
  the tested cutoff-1 implementation and the measured cadence barely changes.
  No additional prototype or independent interval is claimed. A different
  coalescing policy needs internal frame/copy profiles and the streaming fixture
  described above before another budgeted paired run.
- **Reduce H1 body/header adapter work: reject an unprofiled production edit;
  keep the hypothesis open.** Passive CPU totals do not attribute adapter cost.
  No independent A/B interval exists. Symbolized CPU and allocation/copy/frame
  observations are the missing prerequisite, so the full profiling and
  conditional optimization tracker items remain open. Content-Length restoration
  and removal of truncation/trailer/late-policy handling were never candidates.

Harness validation on the experiment SHA:
[run 35345035672](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35345035672)
passed 19 Rust tests and 34 Python tests, including record fragmentation,
transport forwarding/half-close, manifest rejection, missing-arm pairing,
I/O counter monotonicity and privileged-reader termination. No project code,
build, test or script was executed locally; local validation was source/diff
inspection and `git diff --check`.
The later aggregate layout/table regression tests and final report changes
require GitHub-hosted CI on the final pushed head; the experiment-SHA test run
does not validate those later edits.

### Ranked experiments (source hypotheses)

These are source-supported mechanisms and testable hypotheses. Section 4 above
records the first measured H1 experiment and its limits.

1. **Fix buffered-writer progress before tuning WSS.**
   `src/proxy/tcp_proxy.rs::poll_copy_direction` switches back to reading after
   `poll_write` accepts bytes and returns `Pending` on an idle reader without
   flushing the writer. A buffered writer may have accepted plaintext while
   retaining ciphertext. `tokio-rustls` 0.26.4 explicitly allows that outcome.
   Tokio's own `CopyBuffer::poll_copy` flushes when reads are pending to prevent
   the corresponding deadlock. I reproduced the omission using the exact
   extracted Ferrum polling function, replacing only its buffer allocator and
   inactive timing/error helpers: five bytes accepted into a `BufWriter`, zero
   bytes delivered while the client stayed open, immediate exact delivery after
   explicit flush. This proves the generic relay defect, not its responsibility
   for each CI timeout. Reproduce through actual rustls backpressure next.
   The shared helper serves WSS tunnel mode and userspace TCP/TLS; H2 byte
   tunnels also need parity checks. Preserve idle/write deadlines, half-close
   behavior, cancellation and error attribution when adding flush progress.

   **Outcome (2026-09-18): confirmed and fixed.** The defect reproduces through
   actual rustls backpressure against the production loop, not an extracted
   copy: with a TLS transport window smaller than one encrypted record,
   `tokio-rustls` accepts the whole plaintext, retains the ciphertext it could
   not push, and the far peer holds a partial record it cannot decrypt while the
   relay parks on a still-open client. `poll_copy_direction` now tracks whether
   the writer is holding accepted bytes (`CopyDirectionState::needs_flush`) and
   flushes before parking on a pending reader, mirroring tokio's `CopyBuffer`.
   The flush is owed once per accepted batch and an unbuffered writer's
   `poll_flush` is a no-op, so the plain-TCP hot path gains no syscall.
   `backend_write_timeout` stays armed across an in-flight flush *and* across
   the half-close that follows it, going inert only when `poll_shutdown`
   resolves, so a writer that cannot let go of accepted bytes trips the write
   deadline in either phase — including with `tcp_idle_timeout_seconds: 0` and
   `tcp_half_close_max_wait_seconds: 0`, where it is the only bound left. A
   `poll_shutdown` that fails while the writer still owes a flush ends the
   direction as a write-side failure rather than a clean completion; a
   half-close with nothing outstanding, and the benign peer-already-gone errnos,
   stay graceful. Half-close byte delivery, cancellation, the
   authorization-lifetime and admission-revocation bounds, and per-direction
   byte/error attribution are asserted unchanged. Coverage:
   `tests/unit/gateway_core/relay_flush_progress_tests.rs` (behavioral, through
   `bidirectional_copy_for_relay`, the fenced entry point
   `bidirectional_copy_for_fenced_relay`, and the authorization-bounded entry
   point) and
   `shared_invariant_parity_tests.rs::every_tunnelled_relay_path_shares_one_flushing_byte_pump`
   (set equality over every `src/**/*.rs` file that calls either entry point, so
   a fifth call site fails the build until it is listed).

   **What the fenced-relay test does and does not cover.** An earlier revision
   of this amendment called it "`bidirectional_copy_for_fenced_relay` — the
   HBONE H2 CONNECT byte tunnel", which overstates it. The test proves that the
   fenced entry point runs the same flushing pump; its buffering writer is a
   `BufWriter`, and it does not reproduce an H2 byte tunnel.
   `H2ConnectTunnel::poll_flush` is a compile-time `Poll::Ready(Ok(()))` —
   the h2 driver flushes on its own — so the H2 CONNECT leg can never be the
   writer that holds bytes. The direction a buffering writer can stall on HBONE
   is the opposite one: backend→client on the inbound fenced relay, where the
   bytes reach the peer through the inbound mTLS `TlsStream`. That writer's
   behaviour is what the rustls-backpressure test covers.

   **Sibling sweep (2026-09-23).** Every userspace byte relay was re-read for
   the same "accepted, never flushed" state. The pump itself holds: a reader
   `Pending` with `needs_flush` set always reaches `poll_flush`; a `Pending`
   flush returns with the writer's waker registered; EOF flushes through
   `poll_shutdown`; and tokio's `copy_bidirectional` fast path flushes on its
   own. No writer outside the pump buffers: `H2ConnectTunnel` and hyper's
   `H2Upgraded` hand DATA frames to the h2 driver, the H3 WebSocket bridge
   writes a `DuplexStream` and `send_data`, frame-mode WebSocket sends through
   `SinkExt::send` (which flushes), and the mesh UDP datagram tunnels write
   `H2ConnectTunnel`. Two writes that run **before** the relay did have the
   defect: the TCP+TLS first-bytes prefix forward and WebSocket tunnel mode's
   forward of backend bytes that arrived with the `101`. Both wrote into a
   possibly-`tokio-rustls` writer without flushing, and the relay starts with
   `needs_flush` clear, so a retained tail stayed put until the next relay
   write in that direction. Both now flush inside their existing bounds.
   Neither is expected to explain the benchmark timeouts: the WSS echo workload
   is client-first, so its backend sends nothing with the `101`, and the stall
   needs a transport that refuses ciphertext at connection setup.
   Tracker-requested coverage also added: a pending flush parks on the
   writer's waker instead of re-polling (no busy loop), the backend→client
   direction through a rustls *server* writer (the WSS reply path), and a
   rustls half-close that delivers retained ciphertext ahead of `close_notify`.

   **Hosted corroboration (2026-09-18).** Two scoped
   `gateways-protocol-benchmark` runs with identical inputs — ferrum only,
   http2 + grpcs + wss, 70 KiB and 5 MiB, `iterations=2` — on
   [`main` at `606b898a4`](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35327641299)
   and on
   [the fix at `c9a0c3d5c`](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35327635467):

   | Ferrum sample | main, errors (it. 1 / 2) | fix, errors (it. 1 / 2) |
   |---|---:|---:|
   | WSS / 5 MiB | **24 / 24** | **0 / 0** |
   | WSS / 70 KiB | 0 / 0 | 0 / 0 |
   | HTTP/2 / 70 KiB | 0 / 0 | 0 / 0 |
   | HTTP/2 / 5 MiB | 0 / 0 | 0 / 0 |
   | gRPC / 70 KiB, 5 MiB | 0 / 0 | 0 / 0 |

   Every WSS/5 MiB error on `main` is the tracker's signature,
   `ws echo error: timed out waiting 30s for echo`, and the gateway-free
   `direct` WSS/5 MiB baseline completed error-free in both arms (171.0 and
   179.5 RPS), so the failure is on the gateway path rather than in the harness
   or the backend. Twenty-four of twenty-five workers losing their in-flight
   echo is the end-of-run shape a relay that parks holding unflushed ciphertext
   produces.

   **What this does not establish.** The two runs started four seconds apart on
   **separate** hosted runners, not sequentially on one host, so nothing here
   controls for machine-to-machine variation. Two iterations per arm is
   corroboration, not a causal proof, and it does not rule out a second
   contributing mechanism at that payload. RPS across these runs is **not**
   usable: the two arms move in opposite directions by payload (WSS/70 KiB
   favours `main` by ~60%, HTTP/2 by ~70% the other way) with zero errors on
   both sides, which is the cross-run CPU variance this report warns about
   throughout. The regression tests — which cannot pass on the unfixed loop —
   remain the proof of the defect and of its repair.

2. **Measure HTTP/1.1 framing and TLS write cadence.**
   Ferrum's benchmark already disables response buffering and body-size limits,
   selecting `direct_streaming_body`; recommending “turn on streaming” or
   removing its coalescer would miss the actual tested path. Streaming response
   framing removes Content-Length and advertises an unknown body length, so
   HTTP/1.1 uses chunked transfer. The typed body is adapted through reqwest,
   error/deadline wrappers, and the final proxy body. In comparison,
   KrakenD/Lura's no-op path retains a response reader and forwards headers
   into `io.Copy`; Tyk uses a reusable body-copy buffer. The section-4 hosted A/B
   of `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` versus `1` found no demonstrated
   gain in the four valid sizes; 5 MiB failed drain validation. The existing
   coalescer already has bounded aggregation, prompt flushes and a zero-copy
   single-frame path. Internal copied bytes, allocations and adapter CPU remain
   unmeasured prerequisites for further independent changes. Do not restore an
   unverified or plugin-authored Content-Length: truncation, trailers, streaming
   latency and late policy rejection must remain observable.

3. **Reduce shared pool work for small HTTP/2 and gRPC requests.**
   Envoy owns connection pools per worker, keeping pool operations local to
   its event loop. Ferrum's direct-H2 and gRPC acquisition already reuse a
   thread-local key buffer, but still resolve a shared round-robin counter,
   increment it, probe shared pool shards, clone senders, and test readiness.
   Measure this cost before changing architecture. Test a generation-bound,
   route-owned pool handle or a carefully invalidated worker-local hot cache.
   Preserve every transport-affecting key dimension, TLS/SVID generation,
   reload atomicity, and sender readiness. Tokio tasks can migrate; a naive
   thread-local async connection pool is not equivalent to Envoy's model.
   Diagnose the 70 KiB 502/gRPC failures before accepting an RPS improvement.

4. **Reduce repeated UDP session bookkeeping; measure occupied batch size.**
   Ferrum already uses recvmmsg, sendmmsg/GSO machinery, a last-client cache,
   and nonblocking upstream `try_send`. It is not missing basic batching.
   The datagram path nevertheless checks the pending-session map before the
   established-session cache/map and updates shared counters/budgets. With
   200 interleaved clients, a one-entry last-client cache has limited locality.
   NGINX's stream proxy keeps per-session buffers and upstream state in its
   worker event loop. Profile lookup/cache misses and wakeups, then test a
   small cache keyed by the complete destination/owner/generation identity,
   or established-session-first lookup with explicit setup-race coverage.
   Retain authorization expiry, destination revocation, amplification budgets,
   pktinfo/source address semantics, and per-session ordering. A 5% observed
   gap does not justify weakening any of these boundaries.

Relevant primary source implementations:
[Envoy buffer slice move/coalescing](https://github.com/envoyproxy/envoy/blob/v1.33.5/source/common/buffer/buffer_impl.cc),
[Envoy connection-pool model](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/connection_pooling),
[Tyk v5.3.0 HTTP copy and upgrade relay](https://github.com/TykTechnologies/tyk/blob/v5.3.0/gateway/reverse_proxy.go),
[Lura v2.14.1 no-op response parser](https://github.com/luraproject/lura/blob/v2.14.1/proxy/http_response.go),
[Lura no-op renderer](https://github.com/luraproject/lura/blob/v2.14.1/router/gin/render.go),
[KrakenD v2.13.2 dependency pins](https://github.com/krakend/krakend-ce/blob/v2.13.2/go.mod),
and [upstream NGINX stream relay](https://github.com/nginx/nginx/blob/release-1.27.1/src/stream/ngx_stream_proxy_module.c).
The NGINX source illustrates the underlying design; its precise correspondence
to every Kong vendor patch has not been established.

**Changes prepared from this audit.** The benchmark now counts failed/panicked
workers, checks H3 request-finish errors, reports validity across every iteration,
withholds scenario wins when a measured competitor is invalid or incomplete,
and excludes exact ties. A manifest records the requested matrix before startup
so a gateway that never starts cannot disappear from the comparison. Raw
observations remain available. Backend logs,
gateway logs and Envoy counters are captured after each timed sample, outside
the JSON summary glob, so future failures can be diagnosed. The Envoy H3
configuration experiment is described above. These are harness changes; the proxy performance
experiments and the production relay fix remain follow-up work.

The validity reporting lands in the combined-summary job only. `Trusted Cross
Build Policy` compares each Cross-sensitive job in a workflow by its whole-job
digest, so a pull request cannot change the per-protocol matrix job at all —
neither to render the validity table there nor to run the new harness checks as
a pre-flight step. Both remain available from `benchmark_validity.py` and the
commands in `tests/performance/multi_protocol/README.md`; wiring them into the
matrix job needs a direct-to-`main` change.

Acceptance for performance work: reproduce the failure first, preserve strict
status/body/trailer validation, run at least three interleaved baseline/candidate
measurements on the same runner, retain all errors, and record proxy/client/
backend CPU separately. Require zero errors in every accepted iteration and
check p99 alongside useful throughput. Include realistic smaller HTTP payloads
and long-lived streams as well as this large echo workload.
