# Frontend affinity measurements, 2026-10-09

Keep frontend connection affinity enabled. In this isolated comparison,
turning it off reduced pooled 10 KiB gRPC throughput by 6.5% and increased
p99 latency by 10.8%. The other tested buckets had throughput ratios close
to one. These results support keeping the existing policy; they do not
establish a universal improvement across machines or workloads.

## Comparison and validity

The affinity-on baseline was `56218c91f9124a49ae640e7a25648294fc35b03b`,
using its signed production image
`ferrumedge/ferrum-edge:main-56218c91f9124a49ae640e7a25648294fc35b03b@sha256:eaff22723ecd01c9e756142fd18b4e20beee64beccc2ec7557ec15d87abf5b2f`.
The affinity-off candidate was `70e189a0128915326835ccd16e9381384e0c88b6`.
Its only production-source difference removes frontend affinity-slot
selection in `src/proxy/mod.rs`; response-body lifetime ownership remains.
Both gateway images use the shipping `release` profile and `cloud-secrets`.
These are the measured revisions, not the eventual 0.9.16 release identity.

[Pooled H2/gRPC run 37905846413](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37905846413)
and [per-RPC gRPC run 37905879153](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37905879153)
each retained direct, candidate, and baseline arms. Each bucket contains
three iterations of two alternating pairs, with 15-second measurements,
10 KiB at concurrency 100 and 5 MiB at concurrency 25. The default H2 stream
window was 8 MiB. Warmup preceded measurement. Each protocol campaign ran
on one shared hosted runner; the CPU types are listed below.

All 108 samples passed identity, byte/request accounting, phase completion,
concurrency, transport-error, and process-usage bracket checks. There were
zero client or transport errors and no discarded observations. The 36
candidate/baseline pairs are retained in the accompanying CSV. Cross-CPU
pooled versus per-RPC differences are not a causal comparison of those modes.

## Results

Ratios are **affinity off / affinity on**, geometric means of paired ratios.
Ranges are the observed six-pair ranges, not confidence intervals. Backend
accepts are medians during measurement, after warmup, so zero does not mean
that no connection was established for the workload.

| Campaign | Protocol | KiB | CPU | Pairs | RPS ratio (range) | p99 ratio | backend accepts affinity off / on |
|---|---|---:|---|---:|---|---:|---:|
| affinity-off-pooled | grpcs | 10 | AMD EPYC 7763 64-Core Processor | 6/6 | 0.935 (0.880–0.948) | 1.108 | 4.0 / 4.0 |
| affinity-off-pooled | grpcs | 5120 | AMD EPYC 7763 64-Core Processor | 6/6 | 1.005 (0.984–1.025) | 0.934 | 0.0 / 0.0 |
| affinity-off-pooled | http2 | 10 | AMD EPYC 7763 64-Core Processor | 6/6 | 1.000 (0.931–1.025) | 1.010 | 76.5 / 94.0 |
| affinity-off-pooled | http2 | 5120 | AMD EPYC 7763 64-Core Processor | 6/6 | 1.007 (1.003–1.011) | 1.032 | 0.0 / 0.0 |
| affinity-off-per-rpc | grpcs | 10 | INTEL(R) XEON(R) PLATINUM 8573C | 6/6 | 0.992 (0.937–1.015) | 1.019 | 4.0 / 4.0 |
| affinity-off-per-rpc | grpcs | 5120 | INTEL(R) XEON(R) PLATINUM 8573C | 6/6 | 0.999 (0.984–1.014) | 1.051 | 0.0 / 0.0 |

## Evidence and limitations

[Per-pair data](affinity-measurements-2026-10-09.csv) includes throughput,
p99, sampled gateway CPU per request, and backend accepts for both arms.
Hosted artifacts retain all direct-arm samples, raw process and backend
counters, position manifests, runner/compiler details, and resolved image
IDs. CPU/request uses sampled process brackets and is diagnostic.

The small pooled gRPC effect is consistent across all six pairs. Shared-host
scheduling and the finite workload set limit generalization; no significance
test or quiet-host confidence interval is claimed. The earlier historical
pre-affinity comparison was confounded by later code changes and is not used
for this decision. Later cancellation/accounting fixes and any subsequent
box-removal change require their own exact-revision validation.
