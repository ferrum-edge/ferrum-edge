# Mesh Runtime Benchmark (same-host proxy-pair study)

A head-to-head CI benchmark for Ferrum Edge running **as a service-mesh
data plane**, modeled on the gateways × protocols benchmark
(`.github/workflows/gateways-protocol-benchmark.yml`) but measuring the
mesh east-west path — client proxy → mTLS → server proxy — instead of the
north-south gateway path. It complements the Ferrum-only baselines in
`mesh-performance-baselines.yml` (Criterion microbenches, HBONE gateway
overhead, mesh DNS), which contain no competitor comparison.

- Workflow: `.github/workflows/mesh-runtime-benchmark.yml`
- Harness: `tests/performance/mesh_runtime/` (see its README)
- Summarizer: `.github/scripts/summarize_mesh_runtime_results.py`

## Qualification update (2026-10-21)

The historical `consul` arm has no HTTP service-defaults entry. It is an
L4 TCP/mTLS control, not an equivalent HTTP mesh: its echo and intention
probes do not establish L7 processing. `consulhttp` is the separate L7 arm,
with explicit HTTP service-defaults for both services and a live listener
filter check requiring an HTTP connection manager on each proxy. The L4
arm requires TCP proxy filters and no HTTP connection manager. Artifacts
include listener-only config dumps; SDS secrets are never collected.
Earlier tables and protocol descriptions below predate this correction.

The campaign now reverses arm and payload blocks every other repetition.
An optional exact `baseline_sha` builds a second Ferrum image with the same
Dockerfile, features and build profile, then runs adjacent same-payload
baseline/candidate pairs in AB/BA order. Both use the dispatched harness.
`provenance.json` records exact SHAs, image IDs, configuration hashes and
build profile; `campaign.json` retains the full schedule and required cells.
`ci-release` is a diagnostic profile and cannot establish shipping-profile
performance. Use `release`, 30 seconds and at least three repetitions for
production-profile comparisons.

The load generator warms each measured frontend connection, publishes one
common accounting window, and includes only byte-exact successful responses
completed inside it in RPS and latency. Successful post-deadline drains and
warmup are separate counters; warmup/exchange errors invalidate the cell.
Host `/proc` CPU and steal deltas are bracketed by receipt of the loadgen's
start/end stderr markers, excluding warmup/drains with pipe/scheduler jitter.
RSS is sampled every 100 ms; raw counters and container image IDs are kept.
Resource intervals missing markers, changing PIDs, or above 5% CPU steal fail
acceptance. These are process RSS and CPU deltas, not the older docker-stats
sample estimates. Closed-loop latency still has coordinated-omission limits.

The workflow builds the harness tools image and the Ferrum bench image once,
in a dedicated step before the arm loop (`run_mesh_runtime_bench.sh
--build-only`), then runs every arm with `--skip-build`. Image builds
therefore stay out of the per-cell measurement window and out of the arm
loop's failure surface; a missing image fails that arm immediately.

## What is measured

For each arm and each payload size (1KB, 10KB, 70KB, 500KB, 1MB, 5MB —
the gateway benchmark sweep plus a 1KB small-message size where
per-request mesh cost dominates):

- throughput (median RPS across iterations, derived MB/s),
- latency (avg / p50 / p95 / p99 from the median-RPS run),
- proxy-pair CPU% and RSS (mean/peak, `docker stats` during the
  measured window),
- overhead vs the same-runner's `direct` arm.

Workload: closed-loop HTTP/1.1 POST echo, one keep-alive connection per
worker (default 100 workers × 10s per cell; a common bulk schedule
reduces workers to 50 at 1MB and 25 at 5MB in every arm, mirroring the
gateway harness). Every mesh arm's wire shape is declared identically:
**H1 → HTTP/2-over-mTLS → H1** (Ferrum's sidecar transport is pooled H2;
the Envoy pair is explicitly configured for H2 east-west to match).
Latency is therefore closed-loop full-response latency under offered
load (coordinated-omission caveats apply), and MB/s means successful
response-payload bytes/s. A response counts only when status is 200 and
the echoed length equals the payload length. These are payload sizes,
not file-transfer timings (no disk is involved).

Access logging is off in every arm (Ferrum Telemetry
`access_logging.enabled: false`, Envoy `access_log: []`): at defaults
Ferrum's injected `stdout_logging` plugin otherwise dominates the
small-payload result. Authentication posture is probed, not assumed:
the harness fails an arm if plaintext dialed at the mTLS inbound
produces a successful echo.

## Arms and honesty labels

| Arm | What it is | What it is not |
|---|---|---|
| `direct` | loadgen → echo backend | — |
| `ferrum` | the real Ferrum mesh runtime: two `FERRUM_MODE=mesh` Sidecar processes, localized file config (`FERRUM_MESH_CONFIG_PROTOCOL=file`), file SVIDs, STRICT PeerAuthentication, SPIFFE-ID pinning, full proxy/plugin chain | not a stripped proxy fixture |
| `envoy` | two hand-configured `envoyproxy/envoy:v1.39.1` proxies as a static HTTP/2-over-mTLS sidecar pair (client-cert required, SAN pinning both directions, session resumption off) | **not full Istio** — no istiod-generated config, telemetry filters, Wasm, or capture iptables. An Envoy proxy control, labeled “Envoy” in every output |
| `consul` | a real Consul control plane (`hashicorp/consul:1.21.4` dev agent) generating two Envoy sidecars via `consul connect envoy` + xDS, Consul Connect CA mTLS, `protocol: http` service (generated east-west is HTTP/1.1-over-mTLS). Bootstrap adapted only for admin ports and the loopback agent xDS channel (`prepare_consul_bootstrap.py`) | a single dev agent on loopback, not a Consul cluster; intentions default-allow except during the deny probe; agent excluded from pair CPU/memory like other control planes |
| `linkerd` | standalone probe of `ghcr.io/linkerd/proxy` | cannot run without the Linkerd Destination/Identity control plane (`Invalid configuration: no destination service configured` with static identity); the arm records `unsupported-standalone` with logs instead of numbers |

Cilium service mesh also uses Envoy as the L7 data plane. Consul
Connect (above) is included as the second real mesh; Cilium's eBPF
datapath does require a Kubernetes/linux-node environment and is Tier-2
scope, below. Neither is silently represented by the `envoy` arm.

## Methodology and caveats (read before quoting numbers)

1. **Data-plane pair, not in-pod capture.** Proxies run as host-network
   containers and the client dials the outbound listener directly. There
   is no iptables/eBPF capture, no CNI hop, and no cross-node network.
   This isolates per-request data-plane cost (the thing optimization work
   can change) and excludes capture/placement costs (which are real in
   production and topology-specific).
2. **Control planes are out of the data path** in every arm, including
   Ferrum (localized file slices). Config-push latency and control-plane
   resource use are not measured.
3. **Same certificates where the product allows it.** One EC P-256 CA;
   the ferrum/envoy proxies present the same two workload certificates.
   Consul issues its own Connect CA leaves (same EC P-256 issuance
   profile, different files) — that is the product's real identity
   path, not a harness shortcut.
4. **Ferrum runs its full mesh stack** (slice materialization, routing,
   plugin chain, SPIFFE verification). Envoy runs a minimal static
   config: no telemetry/authz filter chain equivalent to a stock Istio
   sidecar. Different filter chains, settings, and placement can change
   the ranking either way; do not extrapolate an Envoy-control lead or
   deficit to a fully-featured Istio deployment.
5. **Closed-loop client.** RPS at high concurrency is
   concurrency/latency; compare arms at the same concurrency, and prefer
   latency + overhead-vs-direct over raw RPS across different runners.
6. **All CI arms run sequentially on one runner** in fixed order
   (direct → ferrum → envoy → linkerd), so overhead uses a same-runner
   `direct` denominator. Sequential same-host execution still carries
   drift/steal variance across the campaign; publishable comparisons
should use the 30s × 4-iteration profile for equal AB/BA order counts.
   New campaigns reverse arm/payload blocks; historical campaigns used fixed order.
7. **CPU/memory are container-level samples** (`docker stats`, 1s
   cadence, cgroup usage — not process RSS) summed across the proxy
   pair, with independent per-container peaks. They include idle/runtime
   overhead and sample quantisation; use them for arm-to-arm shape, not
   as precise per-request accounting. (The gateway harness's `/proc`
   sampler in `tests/performance/multi_protocol/process_usage.py` is
   the upgrade path; it needs host-visible PIDs, which a local
   container VM does not expose.)
8. **One service, static identity, warmed persistent connections.**
   No capture (iptables/eBPF), original-destination recovery, pod
   networking, rotation, policy churn, or connection-churn behavior is
   measured; loopback understates deployment latency and all four
   processes share one host's scheduler and memory bandwidth.

## Tier-2 follow-up: full meshes in Kubernetes (design, not yet built)

Consul has joined Tier-1 (above). Next candidates, in order:
**ztunnel** has a dedicated local-XDS/fake-CA development mode, so
“Istio ambient requires Kubernetes” is too strong — but ztunnel is an
L4/HBONE data plane (it does not terminate user HTTP), so it belongs in
a separate L4 row against an equivalent Ferrum Ambient pair, not in
this L7 table.

Goal: Ferrum (sidecar + ambient) vs Istio (sidecar + ambient/ztunnel)
vs Linkerd vs Cilium in four kind clusters with identical workloads
(fortio-style echo, same payload sweep), measuring the same metrics plus
capture overhead and control-plane cost. Reuse the deployment machinery
of `tests/k8s/mesh_e2e_sidecar/` (`mesh-e2e-sidecar-live.yml`) for the
Ferrum leg and vendor-pinned installers (istioctl, linkerd CLI, cilium
CLI/Helm) for the others. This is where the `linkerd` arm becomes
measurable. Expected CI cost is several × Tier-1, so it should stay
`workflow_dispatch`-only and payloads/iterations should default smaller.

## Interpreting results for optimization work

- A small-payload (1KB) gap with comparable large-payload throughput
  points at per-request costs: connection/TLS reuse on the mesh-mTLS
  pool (`src/proxy/hbone_pool.rs`, mesh mTLS pooling), per-request
  authz/policy evaluation, header/route work — not bulk copying.
- A large-payload-only gap points at the body path: buffering cutoffs,
  copy/frame sizes, TLS record sizing, flow-control windows.
- CPU% at equal RPS separates “slower because busier” (optimization
  target: hot path) from “slower at equal CPU” (target: waiting —
  handshakes, connection churn, window stalls).
- Error cells are never results: the summarizer excludes and flags them.
