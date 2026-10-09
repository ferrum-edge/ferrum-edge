# Mesh DNS Proxy E2E Baseline

**Directional reference numbers only.** Hardware-specific absolute QPS/latency
are not universal product targets. Use same-run direct-stub comparisons and
self-relative trends; do not promote opportunistic laptop numbers into CI floors.

> **Publication status (issue #3332):** Published 2026-08-20 from a **DNS-only**
> hosted collection at Ferrum SHA `a7921ea2176360c7812da6d2c2dff356ad99f5d8`
> ([Actions run 31917782760](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31917782760),
> artifact
> `mesh-performance-baselines-a7921ea2176360c7812da6d2c2dff356ad99f5d8`).
> Selected suite: **DNS E2E only** (`dns_complete=true`, `dns_errors_ok=true`,
> 3 clean repetitions, all `total_errors=0` and `total_nxdomain=0`,
> `runner_health_ok=true`, max CPU steal 0.0%). This run intentionally selected
> `suites=dns`, so `mesh_complete` / `hbone_complete` and aggregate
> `ready_to_publish_baselines` are false by selection — they do **not**
> invalidate the accepted DNS suite. Mesh Criterion and HBONE baselines come
> from an earlier all-suite collection (see combined provenance in
> `tests/performance/mesh/baseline.md`); that run's failed DNS portion must not
> be used as DNS evidence.

New hosted collections use `ubuntu-26.04`. The published measurements below
retain their original Ubuntu 24.04 provenance and must not be compared as
absolute regression gates across runner images.

## Reference environment (DNS-only collection)

| Field | Value |
|---|---|
| Ferrum commit SHA | `a7921ea2176360c7812da6d2c2dff356ad99f5d8` |
| Collected at (UTC) | 2026-08-16T00:41:30Z |
| Runner class | `ubuntu-24.04` (GitHub-hosted Linux; pinned) |
| CPU / RAM / OS / kernel / arch | AMD EPYC 9V74 80-Core Processor; 4 vCPU (2×2×1); 15.61 GiB; Linux 6.17.0-1022-azure / x86_64 |
| Rust / harness versions | rustc 1.97.1; cargo 1.97.1; `mesh-dns-e2e-perf`; hdrhistogram 7.5.4 |
| Build profile / features | `--release`, default features |
| Non-default settings | `run.sh` mesh-mode DNS env (`FERRUM_MESH_DNS_*`, stub CP/upstream); benchmark-only `FERRUM_MESH_ALLOW_NO_CA=true` in `start_gateway()` (no gateway SVID/CA — production mesh must provide identity) |
| Warmup / repetitions | listener ready then loadgen; **3 clean repetitions** |
| Command | `./run.sh --skip-build --json --duration 60 --concurrency 100 --protocol both` |
| Runner health | max CPU steal 0.0% (pre-collection + per-run workload-interval deltas) |
| Raw artifacts | [run 31917782760](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31917782760) → `dns/run_*.txt`, `summary.json`, `provenance.json` |

## Aggregation semantics

Published QPS and latency quantiles are **arithmetic means across the three
clean repetitions**. Run-to-run QPS ranges appear in table Notes where useful.
All retained repetitions had `total_errors=0` and `total_nxdomain=0`.

## Overhead formula

For the upstream-forward class only:

```text
overhead_percent = ((direct_stub_qps - gateway_upstream_forward_qps) / direct_stub_qps) * 100
```

Mesh-internal and mesh-wildcard names exist only inside the gateway resolution
table, so those rows are absolute gateway measurements (no direct baseline).

Latency p50/p90/p99 are means across clean repetitions and are not folded into
the overhead percent.

### Upstream-forward overhead (published)

| Transport | Gateway QPS (mean) | Direct stub QPS (mean) | Overhead |
|---|---:|---:|---:|
| UDP | 35,098 | 101,244 | 65.3 % |
| TCP | 4,609 | 14,007 | 67.1 % |

## Commands

```bash
# Hosted (required for publication):
# Actions → "Mesh Performance Baselines" → suites=dns|all, iterations=3

cd tests/performance/mesh-dns-e2e
./run.sh --skip-build --json --duration 60 --concurrency 100 --protocol both

# Optional EDNS(0) bottleneck / rerun (not the publication default):
./run.sh --skip-build --json --duration 60 --concurrency 100 --protocol both --edns 1232
```

## Via gateway (127.0.0.1:15053)

UDP transport:

| Name class | qps | p50 | p90 | p99 | Notes |
|---|---|---|---|---|---|
| mesh-internal | 35,097 | 584 µs | 1.01 ms | 1.45 ms | exact `DnsResolutionTable.exact` hit; QPS range 34,535–35,945 |
| mesh-wildcard | 35,098 | 549 µs | 971 µs | 1.40 ms | one-label wildcard suffix match; QPS range 34,535–35,946 |
| upstream-forward | 35,098 | 1.59 ms | 2.43 ms | 3.38 ms | UDP forward to `dns_upstream_stub`; QPS range 34,536–35,947 |

TCP transport (RFC 1035 §4.2.2 length-framed):

| Name class | qps | p50 | p90 | p99 | Notes |
|---|---|---|---|---|---|
| mesh-internal | 4,609 | 4.64 ms | 9.98 ms | 28.94 ms | QPS range 4,589–4,625 |
| mesh-wildcard | 4,610 | 4.66 ms | 10.00 ms | 29.34 ms | QPS range 4,589–4,625 |
| upstream-forward | 4,609 | 8.55 ms | 13.78 ms | 29.43 ms | TCP forward to `dns_upstream_stub`; QPS range 4,589–4,625 |

## Direct baseline (dns_upstream_stub)

Only the upstream-forward class is meaningful here (mesh-internal / mesh-wildcard names exist only inside the gateway).

| Class | Transport | qps | p50 | p90 | p99 |
|---|---|---|---|---|---|
| upstream-forward | UDP | 101,244 | 1.02 ms | 1.34 ms | 1.79 ms |
| upstream-forward | TCP | 14,007 | 4.63 ms | 11.49 ms | 57.76 ms |

Direct stub QPS ranges: UDP 100,933–101,497; TCP 13,947–14,050.

## Rerun procedure

1. Trigger **Mesh Performance Baselines** (`suites=dns` or `all`, `iterations=3–5`).
2. Download `mesh-performance-baselines-<sha>`.
3. Require `summary.json` → `acceptance_gate.dns_complete` and
   `acceptance_gate.dns_errors_ok` with every documented gateway row
   (mesh-internal, mesh-wildcard, upstream-forward × UDP/TCP) and both direct
   upstream-forward UDP/TCP rows at 3–5 repetitions.
4. Require `acceptance_gate.runner_health_ok` (CPU steal ≤ 5.0% across the
   pre-collection sample and each per-run workload-interval `/proc/stat` steal
   delta in `runner_health.json` / `runner_health_probes.jsonl`).
5. Discard any repetition with unexplained non-zero `total_errors` or non-zero
   `total_nxdomain`. NXDOMAIN is a distinct counter and is never folded into
   `total_errors`; partial NXDOMAIN across a class/repetition and all-NXDOMAIN
   collections both fail `dns_errors_ok`.
6. Publish mean qps/latency into the tables and record upstream-forward overhead
   with the formula above (UDP and TCP separately).
7. Link the artifact paths for raw JSON blobs.
8. To isolate EDNS(0) OPT-echo / UDP payload-size bottlenecks, rerun the harness
   with `--edns 1232` (or another 512..=4096 size). That option is available on
   `run.sh` but is not the hosted publication default (`--edns 0`).

The upstream stub must serve DNS-over-TCP on the same listen address as UDP.
A UDP-only stub makes `--protocol both` TCP rows connection-refused and fails
`dns_errors_ok`. Prefer a DNS-only hosted run after stub repairs rather than
publishing partial rows from a failed all-suite collection.

## Bottleneck review

- **Mesh-internal hit latency** measures `DnsResolutionTable::resolve` exact-path
  plus response template construction. Should be dominated by the `DashMap`
  cache hit on the second-and-later identical queries (`cached_mesh_response`).
- **Mesh-wildcard latency** adds a one-label suffix scan (sorted by suffix
  length) — expect a small p99 bump versus exact matches.
- **Upstream-forward latency** = round-trip to `dns_upstream_stub` (UDP or
  TCP, matching the client transport) + gateway txid rewriting cost. Subtract
  the direct-stub baseline to attribute gateway overhead. The stub must listen
  on both transports; a UDP-only stub makes TCP rows connection-refused.
- Localhost-only topology; kernel UDP behavior differs by OS (the DNS proxy
  reads one datagram per `recv_from` everywhere) — publish per runner OS/class.
- CP stub publishes one slice; slice-churn cost belongs to `mesh/slice_apply`,
  not these rows.
- Shared-runner CPU steal can inflate p99; publication fails closed above **5.0%**
  steal — re-run rather than publishing impaired baselines.
- **EDNS(0):** `./run.sh --edns <512..=4096>` still exists for OPT-echo and UDP
  payload-size bottleneck reruns. Hosted publication keeps `--edns 0`.

## Refresh cadence

Refresh after DNS proxy, resolution-table, or mesh CP subscribe changes; after
harness SYNC dependency bumps; after runner-class changes; and at least once per
minor release train. Collect only via
`.github/workflows/mesh-performance-baselines.yml` on GitHub-hosted Linux.
