# Bounded request-future box measurements, 2026-10-09

The bounded box-removal candidate reduces allocator calls on H1, reqwest,
direct H2 and gRPC. The native streaming-H3 workload has no measurable change.
Keep the large routing and transport/connection-setup boundaries; the removed
children pass the existing concrete-state ceilings and hosted protocol suites.
This is an allocation and correctness result, not a throughput claim.

## Source and workload

[Hosted allocation run 37913287037](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37913287037)
compares baseline `48597a5d368860a60d78e3a0ead4e0dedfcbf7ab` with candidate
`5944175dc3cc76a55554b695178ac8381e1dbf5a`. PR #6157's reviewed head
`94af540dc5650687195e2979922aa8c1062e203b` has identical production source;
its only later changes correct three source-region delimiters in two tests.

Both native binaries use the shipping `release` profile plus the default-off
allocator observer, Rust 1.99.0, on one four-logical-CPU AMD EPYC 7763 hosted
runner. Each path has three alternating-order rounds per revision, 20-second
measurements, concurrency 32 and 1 KiB payloads. A separate warmup run precedes
the metric bracket. The measured client's own warmup and drain fall inside
that bracket and contribute to both allocator counts and backend echoes.
The binaries' SHA-256 values are:

- Baseline: `421668785cf4a6953db0e74d25b6c765c93f135f4c04b5e92786e2e1e402c831`.
- Candidate: `9f234e6feccc6a7f5b37ae24e7e6d7ae4091be2e538e1933f0f11d2796d3628e`.

All 30 observations are complete, with 9,204,005 backend echoes, zero client
or transport errors, no missing counter slots, no lost events and no allocator
failures. An independent task-owned data analysis recomputed each observation
from raw before/after process counters, backend echoes, client phase receipts
and the subsequent idle interval. It agrees with every reported per-run and
summary value. No repository code or binary ran locally.

## Results

Values are medians of three observations. Allocations combine allocate and
zeroed-allocate calls. Requested bytes are allocator traffic, not retained or
peak memory. The last column combines the maximum unpublished-event bound and
estimated background calls per echo; it is a diagnostic, not a confidence interval.

| Path | Baseline allocations/echo | Candidate allocations/echo | Delta | Baseline requested bytes/echo | Candidate requested bytes/echo | Diagnostic calls/echo |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `h1` | 107.013 | 104.011 | -3.001 | 119,562.0 | 92,417.8 | 0.033 |
| `h1-reqwest` | 147.020 | 145.020 | -2.000 | 123,822.5 | 103,631.6 | 0.037 |
| `h2` | 120.290 | 117.363 | -2.928 | 115,118.1 | 97,697.7 | 0.064 |
| `grpc` | 104.689 | 103.690 | -0.999 | 102,600.5 | 106,502.7 | 0.063 |
| `h3` | 207.967 | 207.964 | -0.003 | 93,718.3 | 93,718.3 | 0.075 |

H1 saves about three calls, reqwest two, direct H2 three and gRPC one per
echo. gRPC requested bytes increase by about 3,902 bytes/echo (3.8%) despite
the lower call count. Inlining a child changes the sizes/layouts of futures
retained by other allocations, so fewer boxes do not imply fewer bytes. This
run does not establish retained-memory or throughput effects.

The H3 change is below its 0.075-call diagnostic scale. This ordinary native
H3 workload streams request and response bodies through the unchanged
streaming-body pool path. The changed H3 factories construct exchanges with
already-buffered request bodies; this workload does not measure their isolated
allocation benefit. No H3 allocation improvement is claimed.

## Stack and correctness evidence

[Corrected isolated run 37911582415](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37911582415)
tested control, frontend, routing dispatch, direct H1, direct H2 and H3 exchange
variants. Every arm passed 6,039 library tests, 6,739 gateway tests and both H3
state/cold-dispatch tests.
[Combined run 37912309168](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37912309168)
passed the same suites for both control and combined candidate. The combined
frontend state is 2,000 bytes under the existing 8 KiB ceiling, routing 64,336
under 128 KiB, and backend 18,408 under 64 KiB. All eight H3 state guards pass.
These are coroutine-state sizes, not measurements of compiled poll-frame size.
The full PR's listener, cancellation, integration and protocol checks also pass.

The first isolated experiment replaced the production CI file and failed seven
CI-policy tests even in its control; restoring that file before tests produced
the corrected results above. The first full PR run found four source-guard
failures from renamed H3 factories; correcting their three delimiters changed
no production source. Neither failed run is counted as successful validation.

## Retained evidence and limits

[All observations](hot-box-measurements-2026-10-09.csv) retain per-run counters,
requested bytes, reallocations, background/tail diagnostics and diagnostic RPS.
The hosted artifact retains raw metrics, client/backend receipts, settings,
compiler/host information, exact source revisions and binary hashes.

Summary SHA-256: `2ecd16d58dc79864f15ce179dc22132817cf23f4cff8dacde74c1e6bf2d0b6fc`.
Recomputed CSV SHA-256: `8ac7bf10046093678fbccd549b5869dd43813ace56308b6ff3cfd096e68c45a2`.

This is an isolated source comparison, unlike the earlier cumulative
[allocation history](allocation-measurements-2026-10-09.md). It counts the
process-wide Rust allocator, including amortized connection setup, warmup,
drain and background work. Native allocations outside that allocator and
retained-memory peaks are outside its scope. Shared-runner RPS is diagnostic;
final-source affinity/performance validation remains a separate measurement.
