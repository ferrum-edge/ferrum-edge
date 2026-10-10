# H2 and gRPC CPU diagnostics, 2026-10-09

The hosted lane now retains process user/system CPU and all-thread scheduler
counters, plus bounded user-space CPU samples. Four EPYC campaigns identify
concrete Ferrum functions, but they do not resolve the Xeon-specific issue
#6148 or establish the cause of #6147's direct-H2 utilization gap. Keep pool,
affinity and crypto defaults unchanged on this evidence.

## Source, workload and repair provenance

Every campaign built source `7ab8d58c4c609a80feae7673da9e102b68c8822f`,
with Rust 1.99.0, shipping release optimization, fat LTO, one codegen unit,
default production features, debug info retained and no forced frame pointers.
This predates the bounded box-removal change #6157 and is not a final-release
performance qualification. Each four-logical-CPU runner used 200 connections,
15-second measurements, two alternating-order pairs, repeated direct controls,
and four passes: control-before, counters, CPU, control-after.

| Protocol | KiB | Actual CPU | Original run |
| --- | ---: | --- | --- |
| HTTP/2 | 10 | EPYC 7763 | [37918129651](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37918129651) |
| gRPC | 10 | EPYC 9V45 | [37918132309](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37918132309) |
| HTTP/2 | 70 | EPYC 7763 | [37918124571](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37918124571) |
| gRPC | 70 | EPYC 7763 | [37918126986](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37918126986) |

All four original report jobs failed on incomplete Ferrum decoding. The
matching 689,819,544-byte executable was retained after #6158 raised the shared
package limit to 1 GiB. Default `perf script` inline expansion then repeatedly
entered `addr2line` and hit the unchanged 30-second decoder limit after only
3–7 samples. Those failed reports remain retained, not relabeled as successes.

[Hosted replay 37923816395](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37923816395)
at experiment `f8cad81c261b3792d8eb505bb84608f49907ee86` applies #6159's
`--no-inline` decoder to the same raw captures. It verifies every raw perf hash
and retained mapped ELF hash before decoding. All 16 captures reconcile all
26,707 raw samples, with zero lost, throttled or foreign samples, in 1.55–5.13
seconds per decode. The production decoder source is
`9f94f4b3377976965c28dcf79bff445e34da1b23`; the experiment adds only its
branch-only replay workflow. It never reruns the gateway or traffic.

A separate task-owned parser rechecked raw-file hashes, decoded sample counts,
PID ownership and CLOCK_MONOTONIC measurement bounds, then counted symbols
only inside the conservative measurement interval. Symbol names come from
the hosted distribution's Rust demangler. Process CPU and scheduler deltas
were also recomputed from raw timeline endpoints, checking every intervening
process/thread generation and counter monotonicity; client-owned boundary
receipts remain the authoritative client counters. No repository code or binary ran
locally. Original capture failures and replay evidence remain distinguishable.

## Validity and attribution limits

After the decoding repair, 95 of 96 traffic observations are usable as
diagnostics. Envoy's first 70 KiB gRPC counters observation had four errors
and an incomplete setup/warmup barrier; it is excluded. All 16 CPU-pass traffic
observations are valid. No Ferrum or Envoy campaign has **both** control pairs
within the predeclared 5% drift limit. No comparative throughput, instrumentation
overhead, CPU-per-request advantage or new default is established.

Ferrum has known leaf symbols for 81.0–87.3% of measurement samples across
these workloads. Envoy has known leaves for only about 1.9–3.8%; its retained
package cannot support a comparable function-level breakdown. Most samples
contain at least one unresolved frame, which does not mean every frame is
unknown. Inline expansion is disabled; async, optimized-away, tail and
unmapped virtual-library frames remain incomplete. Full unwinding is never
claimed. Inclusive stack counts overlap and cannot be added.

## Ferrum user-space samples

These are leaf counts divided by all in-window samples, including unknown
leaves. The two AES-GCM update functions are grouped; the request-handler row
names its outer compiled function and includes whatever work was inlined into
it. Neither is an isolated request-cost or causal bottleneck measurement.

| Workload | Samples | Known leaves | AES-GCM update leaves | Request-handler leaves |
| --- | ---: | ---: | ---: | ---: |
| HTTP/2 10 KiB | 3,655 | 87.3% | 7.66% | 6.51% |
| gRPC 10 KiB | 3,542 | 84.2% | 8.89% | 8.44% |
| HTTP/2 70 KiB | 2,624 | 81.0% | 22.94% | 3.39% |
| gRPC 70 KiB | 2,956 | 81.8% | 23.41% | 3.62% |

Other known leaves include H2 connection/frame/HPACK work, HTTP header hashing,
allocation and Tokio scheduling. The larger TLS-copying workload spends a
larger sampled fraction in AES-GCM; this does not reverse the earlier 10 KiB
finding or establish that cipher selection explains the Xeon gap. Direct-H2
upload/coalescing scheduling remains a hypothesis requiring a controlled
counterfactual, not a conclusion from inclusive async frames.

## Process scheduler and kernel counters

The counters pass samples every process thread. The system fraction is system
CPU divided by user plus system CPU. Switch rates use each process's actual
recorded bracket, not the nominal 15 seconds. Boundary slack is retained in
the CSV; the sampler can bracket some work outside the client's exact interval.
Invalid traffic rows are excluded from this table.

| Workload | Gateway | Valid pairs | System CPU fraction | Voluntary switches/s | Involuntary switches/s |
| --- | --- | ---: | ---: | ---: | ---: |
| HTTP/2 10 KiB | ferrum | 2 | 26.7–27.7% | 2573.0–2633.0 | 2973.1–3036.0 |
| HTTP/2 10 KiB | envoy | 2 | 22.2–22.4% | 198.8–280.6 | 7989.8–8196.8 |
| gRPC 10 KiB | ferrum | 2 | 27.3–28.5% | 2716.5–2954.7 | 3373.2–3810.8 |
| gRPC 10 KiB | envoy | 2 | 31.6–32.6% | 2180.5–2293.7 | 3526.8–3825.3 |
| HTTP/2 70 KiB | ferrum | 2 | 37.5–37.9% | 2166.0–2175.2 | 2180.1–2383.6 |
| HTTP/2 70 KiB | envoy | 2 | 43.7–44.1% | 37.3–43.3 | 15264.2–15366.8 |
| gRPC 70 KiB | ferrum | 2 | 38.0–38.4% | 594.0–734.2 | 3405.6–3643.3 |
| gRPC 70 KiB | envoy | 1 | 42.8% | 106.7 | 10092.7 |

The relative system fractions change direction across workloads: Envoy's
fraction is higher in the 70 KiB and 10 KiB gRPC observations, while Ferrum's
is higher in 10 KiB HTTP/2. With the control drift, these values do not support
a general kernel-cost or Xeon conclusion. Kernel stacks were not selected, and context switches
alone do not identify a lock, queue or await site.

## Evidence and next step

- [All process observations](cpu-process-observations-2026-10-09.csv) retain
  every role and pass, invalid rows, original request counts, diagnostic RPS,
  user/system CPU, complete brackets/slack and available scheduler deltas.
- [All capture coverage](cpu-profile-coverage-2026-10-09.csv) retains every
  pair's raw/measurement/unknown-leaf counts, control drift and replay time.
- Original hosted artifacts retain binaries, mapped libraries, configs,
  process timelines, raw perf samples, CPU identity and original failed reports.
  Replay artifacts retain complete decoded stacks and the readable symbol map.

The follow-up needs a quiet, explicitly selected Xeon host for #6148 and
repeatable controls for #6147, with a matching symbolized Envoy build before
comparing its functions. The repository runner inventory returned zero
self-hosted runners on 2026-10-09. The generic Ubuntu hosted label does not
select a CPU model. Repeated random-host dispatches are not Xeon qualification.

Process CSV SHA-256: `f08cb35450b83c76ff8eb3f615da81253429f5205abb90005e848e3ec34f6d12`.
Coverage CSV SHA-256: `81fd1e12bbcf2c6611e185ac42548cb0288b5cc4d06689c70d0fa6e5e70206e7`.
