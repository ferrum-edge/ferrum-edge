# Mesh Performance Baseline

**Directional reference numbers only.** Hardware-specific — collect your own baseline on the production-equivalent host before treating any of these as targets.

To regenerate on your machine:
```bash
cd tests/performance/mesh
./run.sh
```

Each row below records the criterion-reported mean (and an estimate of the variance class) for the parameterised bench. Times are listed in the smallest unit criterion reported on the reference machine. **Empty entries are expected on first commit** — fill them in as you run the suite.

## authz_match

`policy::evaluate_mesh_authorization_policies` over N synthetic ALLOW policies, request that misses every rule (worst case — every policy is fully traversed before the implicit-deny return).

| Policies (N) | Mean per call | Notes |
|---|---|---|
| 10 | _TBD_ | |
| 100 | _TBD_ | |
| 1 000 | _TBD_ | |
| 10 000 | _TBD_ | Worth tracking — fleets ship 1k–10k AuthorizationPolicy resources in larger Istio installations. |

## ip_restriction

`IpRestriction::on_request_received` over 10,000 sparse exact IPv4 intervals.
The authoritative client IP cache is initialized before timing so the result
isolates the async plugin hook and compiled interval lookup. The hosted
`Performance Regression Check` runs all four cases, pairs each with a 100-rule
same-run reference, enforces the guardrails below, and retains Criterion output.

| Decision shape | Instances | Mean per iteration | Notes |
|---|---:|---|---|
| Deny miss above every interval | 1 | _TBD_ | Worst-case ordered miss. |
| Deny miss above every interval | 4 | _TBD_ | Supported multiple scoped-instance composition. |
| Allow match in final interval | 1 | _TBD_ | High-address match. |
| Allow match in final interval | 4 | _TBD_ | High-address match across multiple instances. |

Hosted guardrails are intentionally generous and separate from the directional
reference numbers in this file. For each decision shape and instance count, the
10,000-rule Criterion mean must be at most 8x its 100-rule same-run mean and at
most 10 microseconds per plugin instance. The self-relative limit detects a
return to rule-count-proportional scans; the absolute ceiling also catches a
catastrophic regression in the cached client-IP or constant-time hook overhead.

## slice_apply

`MeshSlice::from_gateway_config(&GatewayConfig, MeshSliceRequest)` over N synthetic workloads + matching MeshService rows.

| Workloads (N) | Mean per call | Notes |
|---|---|---|
| 100 | _TBD_ | |
| 1 000 | _TBD_ | |
| 5 000 | _TBD_ | |

## xds_translation

`xds::translator::translate_mesh_slice_to_snapshot(&MeshSlice)` over a slice with N workloads + 1 service each.

| Workloads (N) | Mean per call | Notes |
|---|---|---|
| 100 | _TBD_ | |
| 1 000 | _TBD_ | |
| 5 000 | _TBD_ | |

## Interpretation notes

- These are **single-threaded** micro-benches. Production paths can amortise across cores; the numbers below are a per-CPU upper bound, not aggregate throughput.
- `authz_match` measures the worst-case linear scan. The plugin layer caches PolicyScope filter results per-request; that cache is _not_ exercised here.
- `ip_restriction` measures the compiled O(log n) lookup after canonical client-IP caching; policy construction and rule parsing are outside the timed loop.
- `slice_apply` measures the cold rebuild. The ArcSwap swap itself is ~constant time and is not included in the bench window.
- `xds_translation` runs on the CP side; the DP fingerprint-dedup downstream means most translations get reused, so production hit rate is high.
