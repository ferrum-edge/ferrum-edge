# Allocation measurements, 2026-10-09

[Hosted run 37899482956](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37899482956)
compared candidate `0b0fed9ee735b690faec186372773d727cbddcdf` with the pre-#5993
baseline `67a57af8ea31e9e126c22381cdd7d01b6ea5f837`. Both used the shipping
`release` profile with the default-off `bench-h1-profile` allocator observer.
The harness came from the candidate. This is a cumulative before/after comparison:
the candidate also contains changes after #5993, so these deltas do not isolate
that PR or its dispatch boxes.

The hosted runner exposed four logical CPUs (AMD EPYC 7763) and Rust 1.99.0
(`b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`, LLVM 23.1.1). Each path used
1 KiB echoes, concurrency 32, three 20-second rounds and alternating candidate /
baseline order on that same runner. Pool warmup preceded each measurement.
All 30 observations completed with zero client errors, zero missing counter slots,
and no increase in lost events. Their backend counters covered 9,299,286 echoes.

## Results

Medians are allocator calls per served backend echo. `alloc` includes
`alloc_zeroed`; reallocations are reported separately. The final column is the
larger candidate/baseline sum of the reported unpublished-event bound and idle
background estimate; it is a measurement diagnostic, not a confidence interval.

| Path | Baseline alloc | Candidate alloc | Delta | Baseline realloc | Candidate realloc | Diagnostic calls/echo |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `h1` | 100.012 | 107.013 | +7.001 | 4.002 | 4.002 | 0.029 |
| `h1-reqwest` | 139.019 | 147.020 | +8.000 | 9.021 | 10.020 | 0.036 |
| `h2` | 112.312 | 120.307 | +7.995 | 3.798 | 4.801 | 0.052 |
| `grpc` | 102.700 | 104.687 | +1.987 | 3.437 | 3.434 | 0.076 |
| `h3` | 192.964 | 207.960 | +14.996 | 21.022 | 22.022 | 0.082 |

The increase is larger than the counter-tail/background diagnostic on every
path. This measures an allocation cost; it does not establish a throughput,
latency or live-memory regression. Requested-byte totals include the new size
of reallocations and are not retained heap size or bytes copied. Connection
setup is amortized by this keep-alive workload. Native-library allocations that
bypass Rust's allocator, kernel memory and jemalloc internals are outside coverage.
Shared-runner wall-clock rates are not used as performance claims.

## Evidence and disposition

[Per-observation data](allocation-measurements-2026-10-09.csv) retains every
round, request denominator, allocation/reallocation rate, requested-byte rate,
counter-tail bound, idle estimate and diagnostic client rate. The hosted artifact
`alloc-per-request-0b0fed9ee735b690faec186372773d727cbddcdf-1` additionally contains
all raw before/after/idle scrapes, backend counters, client outputs, configurations,
compiler/CPU identity and binary hashes. The CSV and summary medians were
independently recomputed from the raw counters without running repository code.
The original `summary.json` SHA-256 is
`2be2f2c57e348bd3d0b493f6a8798628d529e1f1ebbb2450835fb002c90e4ad5`.

The measurement portion of #6022 item 1 is complete. The allocation attribution
and box-removal decision remain separate: the compiled coroutine-state guards
and ordinary-stack listener tests must stay green before removing a dispatch
box. An aggregate historical delta alone is not evidence that a particular box
can safely be removed.
