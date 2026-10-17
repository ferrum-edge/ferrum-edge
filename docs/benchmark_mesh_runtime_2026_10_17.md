# Mesh Runtime Benchmark — First Results (2026-10-17)

First head-to-head measurement of Ferrum Edge as a service-mesh data
plane against another mesh data plane in the same environment, using the
new harness in `tests/performance/mesh_runtime/` and workflow
`.github/workflows/mesh-runtime-benchmark.yml`. Methodology, arm
definitions, and caveats: [`docs/mesh_runtime_benchmark.md`](mesh_runtime_benchmark.md).
Machine-readable results: [`benchmark_mesh_runtime_2026_10_17_results.json`](benchmark_mesh_runtime_2026_10_17_results.json).

## Top finding

At small payloads Ferrum's sidecar pair spends **≈1.9× the CPU per
request** of the Envoy pair (135µs vs 70µs CPU/request at 1KB, both
pairs saturated at ≈4.1–4.3 cores) and reaches 55% of Envoy's RPS
(31.5k vs 57.7k). At 500KB and above the arms are within **4–7%** of
each other in both RPS and CPU/request. The gap is a fixed per-request
cost, not a bulk-transfer cost — confirmed at concurrency 1, where the
pair adds 189µs (Ferrum) vs 130µs (Envoy) over the 35µs direct path.
Optimization target #1 is per-request CPU on the mesh sidecar path
(plugin-chain/identity work and H2 stream handling), not the body path.

## Environment (local first run — CI collection is the publishable one)

| Field | Value |
|---|---|
| Host | Apple M4 (arm64), macOS; Docker via Colima Linux/arm64 VM, 6 vCPU / 10GiB |
| Placement | all arms sequential on the **same** host (paired `direct`) |
| Ferrum | published image `ferrumedge/ferrum-edge:main-ee8c0e590155e3b6fd6ab5381d5d42e35fcbbd74` (`sha256:c5339667…`), exact benchmark-branch base SHA |
| Envoy | `envoyproxy/envoy:v1.39.1`, static H2/mTLS pair (not full Istio) |
| Linkerd | `ghcr.io/linkerd/proxy:edge-25.11.1` — `unsupported-standalone` (needs Destination service; see below) |
| Workload | HTTP/1.1 POST echo, H1 → H2/mTLS → H1, 10s × conc 100 (50 @1MB, 25 @5MB), 1 iteration |
| Collected | 2026-10-17 |

Local absolute values are directional (shared laptop-class VM, all
processes on 6 vCPUs). The workflow's hosted run on `ubuntu-26.04` is
the artifact to quote; this report will be updated with its run link.

## Results

### Throughput (RPS) and overhead vs same-host direct

| Payload | direct | ferrum | envoy | ferrum overhead | envoy overhead |
|---:|---:|---:|---:|---:|---:|
| 1KB | 435,921 | 31,531 | 57,736 | 92.8% | 86.8% |
| 10KB | 349,385 | 27,044 | 46,750 | 92.3% | 86.6% |
| 70KB | 99,526 | 13,132 | 16,261 | 86.8% | 83.7% |
| 500KB | 11,939 | 2,744 | 2,851 | 77.0% | 76.1% |
| 1MB | 5,263 | 1,410 | 1,507 | 73.2% | 71.4% |
| 5MB | 849 | 290 | 305 | 65.8% | 64.1% |

### Latency p50 (concurrency 100; 50 @1MB, 25 @5MB)

| Payload | direct | ferrum | envoy |
|---:|---:|---:|---:|
| 1KB | 208µs | 3.08ms | 1.57ms |
| 10KB | 257µs | 3.59ms | 1.98ms |
| 70KB | 928µs | 7.53ms | 5.90ms |
| 500KB | 8.04ms | 36.0ms | 34.1ms |
| 1MB | 9.21ms | 35.1ms | 32.0ms |
| 5MB | 28.9ms | 86.0ms | 85.2ms |

Closed-loop latency at saturation; the concurrency-1 fixed costs are
direct 35µs, envoy pair 165µs, ferrum pair 224µs (avg, 1KB).

### Proxy-pair CPU / memory (docker-stats cgroup usage, measured window)

Both pairs saturate ≈4.1–4.5 cores at every size on this 6-vCPU VM
(load generator and backend share the remainder), so read CPU through
CPU/request: **1KB — ferrum 135µs/req, envoy 70µs/req; 5MB — 14.2ms vs
13.4ms/req**. Pair memory is comparable (ferrum 118–311MiB, envoy
49–248MiB across sizes; Ferrum higher at small sizes, similar at bulk).

## What the benchmark caught during bring-up (harness fairness fixes)

1. **Access logging dominated Ferrum's first numbers.** With mesh
   Telemetry defaults, Ferrum injected `stdout_logging` per request
   (≈1.5GB of logs per sweep) and scored 15.0k RPS @1KB. Disabling
   access logging in *every* arm (Ferrum Telemetry switch; Envoy
   already `access_log: []`) doubled Ferrum to 31.5k. `FERRUM_LOG_LEVEL`
   alone does not control that plugin.
2. **Protocol shape matters.** Ferrum's sidecar east-west transport is
   pooled HTTP/2 over mTLS. The Envoy pair was reconfigured from H1 to
   explicit H2 east-west to match (Envoy @1KB moved 69.1k → 57.7k);
   comparing across different wire protocols would have been a
   methodology error.
3. **Authentication is probed.** Each arm must refuse a plaintext echo
   dialed at its mTLS inbound (:15006) before any cell is measured;
   both arms pass. Certificates are shared EC P-256 across arms;
   the CA private key is mounted into no proxy.

## Linkerd outcome

`ghcr.io/linkerd/proxy:edge-25.11.1` exits standalone with
`Invalid configuration: no destination service configured` (static file
identity accepted, then the Destination control-plane address is
required). The arm records `unsupported-standalone` with logs — no
numbers are fabricated. Measuring Linkerd (and full Istio, Cilium)
requires the Tier-2 kind environment in
[`docs/mesh_runtime_benchmark.md`](mesh_runtime_benchmark.md); Consul
Connect is the recommended next Tier-1 arm (real control plane, no
Kubernetes needed).

## Optimization follow-ups (hypotheses with confirming instrumentation)

1. **Per-request plugin/identity cost (small payloads).** Ferrum runs
   its full managed plugin chain per request where the Envoy control
   runs a minimal HCM+router. Confirm with effective plugin lists,
   per-request CPU profiling (existing profile workflows), and request
   duration metrics; do not remove security checks to chase the number.
2. **H2 pool width / stream concentration.** `MeshMtlsConnectionPool`
   grows at 8 pending response heads (`src/proxy/mesh_mtls_pool.rs`);
   record `ferrum_connection_pool_entries{pool="mesh_mtls"}` and pool
   handshake/eviction counters, and sweep pool width in a labeled
   diagnostic run.
3. **Flow-control asymmetry (large payloads).** Mesh pool windows vs
   frontend defaults differ (`src/proxy/mesh_mtls_pool.rs`,
   `src/proxy/mod.rs`); retain both peers' H2 SETTINGS and run a
   declared common-window diagnostic before tuning.
4. **Backend/client headroom.** Both pairs saturate the shared VM;
   hosted runs must show loadgen/backend CPU headroom before treating
   RPS ceilings as proxy ceilings.

## Review

Design and implementation were reviewed by a GPT-6.1 Sol (xhigh)
reviewer in two rounds (design before implementation; diff + results
after). Round-1 blockers (client Host/dial gap, H1-vs-H2 protocol
declaration, telemetry/access-log parity) are fixed in the shipped
harness; remaining reviewer items (same-runner paired direct in CI,
`/proc`-grade resource sampling, workload-interval steal gating,
Consul/kind arms) are recorded as limitations/follow-ups in
[`docs/mesh_runtime_benchmark.md`](mesh_runtime_benchmark.md).
