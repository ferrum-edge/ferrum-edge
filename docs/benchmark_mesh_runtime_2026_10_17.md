# Mesh Runtime Benchmark — First Local Results (2026-10-17, exploratory)

First head-to-head measurement of Ferrum Edge as a service-mesh data
plane against a static Envoy control pair and a Consul Connect pair
(real control plane) in the same environment,
using the harness in `tests/performance/mesh_runtime/` and workflow
`.github/workflows/mesh-runtime-benchmark.yml`. Methodology and caveats:
[`docs/mesh_runtime_benchmark.md`](mesh_runtime_benchmark.md). Results:
[`benchmark_mesh_runtime_2026_10_17_results.json`](benchmark_mesh_runtime_2026_10_17_results.json)
(concurrency-100 sweep) and
[`benchmark_mesh_runtime_2026_10_17_conc1.json`](benchmark_mesh_runtime_2026_10_17_conc1.json)
(concurrency-1 diagnostic).

**Evidence status:** one exploratory 10-second observation per cell on
a shared six-vCPU Colima arm64 VM (all arms sequential on that host).
Quote as: “the configured Ferrum run had lower small-payload throughput
than the static Envoy control and the Consul-generated pair, and bulk
RPS was closer.” These are not
validated mesh-product rankings; the hosted `ubuntu-26.04` collection
(first dispatch after the workflow lands on `main`, 30s × 3 iterations
recommended) is the publishable artifact and will supersede this page.

## Exploratory observation

At 1KiB the Ferrum pair reached 37,089 RPS on this VM, vs 74,254 for
the static Envoy pair and 132,324 for the Consul-generated pair;
estimated sampled CPU per request (docker-stats pair CPU ÷ RPS, an
unbracketed sampled estimate, not measured service demand) was ≈113µs
(Ferrum) vs ≈54µs (Envoy) vs ≈29µs (Consul). At 500KiB Ferrum was
within 4% of Envoy and 25% below Consul; at 5MiB all three were within
13%. At concurrency 1 the pairs added ≈207µs (Ferrum), ≈132µs
(Envoy), and ≈84µs (Consul) over the 36µs direct path at 1KiB. Wire
shapes differ as each product generates them: Ferrum and the static
Envoy control run H1 → HTTP/2-over-mTLS → H1, while Consul's generated
config for a `protocol: http` service runs H1 → HTTP/1.1-over-mTLS →
H1 — the comparison is each mesh's default generated data path, not a
normalized-transport study. The
pattern is *consistent with* a larger fixed per-request cost on the
Ferrum path; it does not by itself identify which component (plugin
chain, H2 stream handling, pool behavior, scheduling) accounts for it.
Hypotheses and confirming instrumentation are listed below — none is
established by this run.

## Environment

| Field | Value |
|---|---|
| Host | Apple M4 (arm64), macOS; Docker via Colima Linux/arm64 VM, 6 vCPU / 10GiB |
| Placement | arms sequential on the same host; load generator + backend share the VM (headroom not isolated) |
| Ferrum | published image `ferrumedge/ferrum-edge:main-ee8c0e590155e3b6fd6ab5381d5d42e35fcbbd74`, digest `sha256:c53396671a71d6bddf1156bcd913ec523d6ff8b41c1c8dbe910a27b5eb85319a` (benchmark-branch base SHA) |
| Envoy | `envoyproxy/envoy:v1.39.1`, static TLS-1.3 H2/mTLS pair (not full Istio) |
| Consul | `hashicorp/consul:1.21.4` dev agent + `envoyproxy/envoy:v1.39.1` sidecars bootstrapped by `consul connect envoy` (Consul Connect CA; bootstrap adapted only for admin ports + loopback xDS channel, see harness) |
| Linkerd | `ghcr.io/linkerd/proxy:edge-25.11.1` — `unsupported-standalone` (Destination service required; log evidence in the run artifact) |
| Workload | HTTP/1.1 POST echo; ferrum/envoy H1 → H2-over-mTLS (TLS 1.3) → H1, consul H1 → H1.1-over-mTLS → H1 (as generated); 10s/cell, conc 100 (50 @1MiB, 25 @5MiB), 1 iteration, byte-exact echo verification |
| Auth probes | plaintext refused; valid client cert accepted; no-cert and rogue-CA handshakes refused (ferrum/envoy); plaintext refused + deny intention breaks/restores echo (consul) |
| Collected | 2026-10-17 |

## Results (single observation per cell)

### Throughput (RPS) and loss vs same-host direct

| Payload | direct | ferrum | envoy | consul | ferrum loss | envoy loss | consul loss |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1KiB | 418,179 | 37,089 | 74,254 | 132,324 | 91.1% | 82.2% | 68.4% |
| 10KiB | 328,822 | 30,478 | 49,737 | 94,821 | 90.7% | 84.9% | 71.2% |
| 70KiB | 92,694 | 13,170 | 16,060 | 23,932 | 85.8% | 82.7% | 74.2% |
| 500KiB | 12,314 | 2,739 | 2,921 | 3,672 | 77.8% | 76.3% | 70.2% |
| 1MiB | 5,844 | 1,424 | 1,492 | 1,777 | 75.6% | 74.5% | 69.6% |
| 5MiB | 865 | 286 | 294 | 328 | 66.9% | 66.0% | 62.1% |

### Latency p50 at offered load (closed-loop)

| Payload | direct | ferrum | envoy | consul |
|---:|---:|---:|---:|---:|
| 1KiB | 213µs | 2.63ms | 1.22ms | 685µs |
| 10KiB | 270µs | 3.21ms | 1.87ms | 962µs |
| 70KiB | 993µs | 7.50ms | 5.88ms | 3.89ms |
| 500KiB | 7.79ms | 35.9ms | 25.5ms | 26.1ms |
| 1MiB | 8.27ms | 34.8ms | 27.3ms | 27.3ms |
| 5MiB | 28.4ms | 87.3ms | 82.7ms | 70.9ms |

Concurrency-1 average latency at 1KiB (diagnostic file above):
direct 36µs, consul 120µs, envoy 168µs, ferrum 243µs.

### Proxy-pair CPU / memory (docker-stats cgroup usage, sampled)

Pair CPU was ≈380–450% for every mesh arm at all sizes on this VM
(the load generator and backend compete for the same 6 vCPUs, so these
are shared-host capacity samples, not isolated proxy cost). Sampled
CPU/request at 1KiB: ferrum ≈113µs, envoy ≈54µs, consul ≈29µs; at
5MiB: ≈14.1ms vs ≈13.6ms vs ≈11.8ms. Pair memory mean ranges: ferrum
120–295MiB, envoy 49–226MiB, consul 45–202MiB (sidecars only; the
Consul agent itself is excluded, like other control planes).

## Fairness fixes found during bring-up (diagnostics, not archived cells)

1. **Access logging dominated Ferrum's first (unarchived) diagnostic**
   — with mesh Telemetry defaults the injected `stdout_logging` plugin
   more than halved Ferrum's small-payload RPS. All shipped arms now
   disable access logging explicitly (Ferrum Telemetry switch; Envoy
   `access_log: []`); `FERRUM_LOG_LEVEL` alone does not control it.
2. **Wire shape parity matters** — the Envoy pair was moved from H1 to
   explicit HTTP/2 east-west (and TLS 1.2→1.3 with resumption fully
   off) to match Ferrum's sidecar transport; cross-protocol rows are
   not quoted.
3. **TLS 1.3 probe subtlety** — client-auth rejection surfaces only
   after the client Finished; the auth probe therefore requires the
   server's H2 SETTINGS frame, not just a completed handshake.

## Linkerd outcome

`ghcr.io/linkerd/proxy:edge-25.11.1` with static file identity exits
with `Invalid configuration: no destination service configured`; the
arm records `unsupported-standalone` only on that evidence (image or
startup failures record `failed` instead). Measuring Linkerd — and
full Istio/Cilium — requires the Tier-2 kind environment; Consul
Connect is the recommended next Tier-1 arm. See
[`docs/mesh_runtime_benchmark.md`](mesh_runtime_benchmark.md).

## Optimization hypotheses (unproven; confirming instrumentation)

1. **Per-request plugin/identity CPU.** Ferrum executes its managed
   mesh plugin chain per request vs the control's minimal HCM+router.
   Confirm: effective plugin lists, CPU profiles
   (existing profile workflows), per-request metrics. Never remove
   security checks to chase the number.
2. **Mesh-mTLS H2 pool width / stream concentration.**
   `MeshMtlsConnectionPool` growth thresholds
   (`src/proxy/mesh_mtls_pool.rs`); record
   `ferrum_connection_pool_entries{pool="mesh_mtls"}` and handshake
   counters; sweep width in a labeled diagnostic.
3. **H2 window/frame asymmetry at bulk sizes** (pool 8MiB/32MiB vs
   frontend 256KiB/2MiB defaults; Envoy ships its own defaults —
   this run used untuned defaults on both sides). Retain both peers'
   SETTINGS; run a declared common-window diagnostic.
4. **Shared-host saturation.** Loadgen/backend CPU headroom must be
   shown before RPS ceilings are read as proxy ceilings.

## Review record

Two GPT-6.1 Sol (xhigh) review rounds: design (pre-implementation) and
implementation (diff + results). Round-2 blockers — relative
bind-mount sources on CI, opaque `$DOCKER` dispatch rejected by the
Cross build policy (confirmed by the PR's CI Policy failure), Envoy
TLS/runtime mismatch, and success-on-failure acceptance — are fixed in
the current head; remaining items (paired hosted repetitions beyond
the single-runner sequential layout, `/proc`-grade resource counters
on hosted Linux, Consul/kind arms) are tracked as limitations in
[`docs/mesh_runtime_benchmark.md`](mesh_runtime_benchmark.md).
