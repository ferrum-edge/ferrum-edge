# Mesh Runtime Head-to-Head Benchmark

Compares Ferrum Edge running as a **service-mesh data plane** against other
mesh data planes in the same environment: throughput, latency, and
proxy-pair CPU/memory across payload sizes. The mesh counterpart of
`tests/performance/multi_protocol/run_gateway_protocol_bench.sh` (which
compares API gateways, not meshes). Existing Ferrum-only mesh baselines
(Criterion microbenches, HBONE E2E, DNS) live in `tests/performance/mesh*`
and are collected by `mesh-performance-baselines.yml`; this suite is the
cross-product comparison those baselines deliberately are not.

Full methodology, honesty labels, and the Tier-2 (full Kubernetes mesh)
design: [`docs/mesh_runtime_benchmark.md`](../../../docs/mesh_runtime_benchmark.md).

## Topology (identical for every arm)

```
mesh_loadgen ──► client proxy (outbound) ──mTLS──► server proxy (inbound) ──► mesh_backend (echo)
mesh_loadgen ───────────────────────────────────────────────────────────────► mesh_backend      (direct)
```

## Arms

| Arm | Data plane under test | Identity / policy posture |
|---|---|---|
| `direct` | none | same-runner overhead baseline |
| `ferrum` | 2× `ferrum-edge`, `FERRUM_MODE=mesh`, Sidecar topology, `FERRUM_MESH_CONFIG_PROTOCOL=file` | file SVIDs, STRICT `PeerAuthentication`, destination SPIFFE ID pinned |
| `envoy` | 2× `envoyproxy/envoy:v1.39.1` hand-configured H2/mTLS pair | client cert required, SPIFFE URI SAN pinned both directions |
| `consul` | Consul 1.21.4 dev agent + 2× Envoy sidecars from `consul connect envoy`, default TCP protocol | L4 control: Consul Connect CA mTLS; deny-intention auth probe |
| `consulhttp` | Same Consul/Envoy pair with explicit HTTP service-defaults | L7: active measured listeners must contain HTTP connection managers; same intention probe |
| `linkerd` | 2× `ghcr.io/linkerd/proxy` standalone probe | records `unsupported-standalone` with logs unless the echo probe passes (the proxy requires the Destination control-plane service) |

`envoy` is the Istio sidecar **data-plane proxy**, hand-configured: it is
labeled Envoy everywhere, never full Istio (no istiod, telemetry, or Wasm
in the measurement). `consul` is a real (single-agent) Consul control
plane. Cilium's eBPF dataplane needs Kubernetes and belongs to the
Tier-2 design in the doc above.

## Quickstart

```bash
# One arm, two payloads (Linux Docker host; on macOS use a container VM
# context and put --output-dir under a path the VM mounts, e.g. $HOME):
./run_mesh_runtime_bench.sh ferrum \
  --payload-sizes "1024 1048576" --duration 5 --concurrency 50 \
  --output-dir /tmp/mesh-results/ferrum

# Summarize a results tree (results/<mesh>/run_*):
python3 ../../../.github/scripts/summarize_mesh_runtime_results.py \
  --results-root /tmp/mesh-results \
  --output /tmp/mesh-results/summary.json \
  --summary-md /tmp/mesh-results/summary.md
```

In CI: Actions → “Mesh Runtime Benchmark” → Run workflow (defaults:
10s × concurrency 100 × payloads 1KB–5MB, 1 iteration; use 3 iterations
for publishable numbers).

## Builds and images

The harness builds its own tools image (`mesh-bench-tools:local`) and, for
the `ferrum` arm, the repository image (`ferrum-edge:bench`) with literal
`docker build` commands (no Buildx action). The workflow builds both once in
a dedicated step before the arm loop:

```bash
./run_mesh_runtime_bench.sh --build-only --output-dir results/images
```

Every arm then runs with `--skip-build`, so an arm consumes the prepared
images and fails fast if one is missing instead of rebuilding mid-campaign.
Locally, omit `--skip-build` on a first single-arm run to let that arm build
what it needs; use `--build-only` to prebuild both images.

## Output contract

Per cell `<mesh>_http1_<payload>.json` carries the gateway-bench fields
(`gateway`, `protocol`, `payload_size`, `rps`, `latency_avg_us`, `p50_us`,
`p95_us`, `p99_us`, `total_requests`, `total_errors`, `total_bytes`) plus
`mesh`; the sibling `.stats.jsonl` holds `docker stats` samples of the two
proxy containers taken during the measured window. `<mesh>_arm_status.json`
records `ready` / `unsupported-standalone` / `failed`. A response only
counts toward RPS when status is 200 **and** the echoed body length equals
the payload length. The summarizer reports medians across iterations and
refuses to present error cells as results.

## Fairness controls

- One EC P-256 CA; the same svc/client certificates are presented by every
  arm's proxies (Ferrum consumes them as SVIDs).
- Same client (`mesh_loadgen`, one keep-alive connection per worker) and
  same echo backend in every arm, `direct` included.
- All containers (backend, proxies, load generator) run `--network host`,
  the `run_gateway_protocol_bench.sh` convention.
- Warmup load (discarded) precedes each measured cell; readiness is an
  end-to-end echo probe, not a port check.
