# Published Benchmark Results

Each directory here is the complete, unedited output of one benchmark run
whose numbers are quoted publicly (for example on
[ferrumedge.com/performance](https://ferrumedge.com/performance)). Keep older
bundles: they are the record behind numbers that were published at the time.

| Bundle | Date (UTC) | Commit | Host |
|---|---|---|---|
| [`2026-10-06-apple-m4/`](2026-10-06-apple-m4/) | 2026-10-06 | `e5c7616` (v0.9.13+) | Apple M4, 10 cores, 16 GB, macOS 26.6.1 |

## Bundle contents

| File | Produced by | Contents |
|---|---|---|
| `manifest.json` | `multi_protocol/run_published_benchmark.sh` | Commit, version, toolchain, OS, CPU, memory, load average, arguments |
| `summary.md` / `summary.json` | `multi_protocol/summarize_published_benchmark.py` | Medians, min/max, CV, added latency, gateway CPU per request, flags |
| `samples.json.sha256` | `shasum -a 256 samples.json` | Checksum of the run's `samples.json` (every raw `proto_bench` report and gateway CPU sample). The raw file stays out of git: at about 1 MB it exhausts the trusted Cross build-policy verifier, which scans everything under `tests/performance`. `summary.json` keeps every per-run value |
| `scale-sqlite.json` | `functional/functional_scale_perf_test.rs` with `FERRUM_SCALE_RESULTS_JSON` | Every 3k-proxy wave of the 30k scale test |

## Reproducing a bundle

```bash
git checkout --detach <commit from manifest.json>
cd tests/performance/multi_protocol
./run_published_benchmark.sh            # writes results/<timestamp>/

cd ../../..
cargo build --release --bin ferrum-edge
FERRUM_SCALE_RESULTS_JSON=scale-sqlite.json \
cargo test --profile ci-release --test functional_tests -- --ignored --nocapture \
  --exact functional::functional_scale_perf_test::test_scale_perf_30k_proxies
```

To publish a new run, copy the result directory here as
`<date>-<host>/`, add `scale-sqlite.json`, add a row above, and only quote
rows whose `Flags` column is empty. See
[`multi_protocol/README.md#publishing-numbers`](../multi_protocol/README.md#publishing-numbers)
for how to read each column.
