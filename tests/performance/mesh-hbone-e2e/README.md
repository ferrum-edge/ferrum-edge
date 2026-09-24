# Mesh HBONE E2E Throughput Harness

End-to-end throughput harness for Ferrum Edge's **gateway-to-mesh HBONE outbound** path. Measures the steady-state overhead the gateway adds when fronting an Istio-style ambient sidecar via HTTP/2 CONNECT over mTLS on port 15008.

## Topology

```
hbone_loadgen (plain HTTP/1.1)
        │
        ▼
  hbone_perf_fixture (trusted projection → file::serve / ProxyState)
        │  opens HBONE tunnel (H2 CONNECT over mTLS)
        ▼
  hbone_sidecar (stub ambient sidecar — H2 CONNECT terminator)
        │  inner request relayed to backend over plain TCP
        ▼
  hbone_backend (HTTP/1.1 echo)
```

The harness also runs a **direct baseline**:
```
hbone_loadgen ──► hbone_backend  (no gateway, no sidecar, no tunnel)
```

## Why this shape

Mesh mode (`FERRUM_MODE=mesh`) requires a live native `MeshSubscribe` gRPC consumer and currently produces a `GatewayConfig` with empty `proxies`, so the inbound HBONE listener has nothing to route to without a production-code hatch. The **gateway-to-mesh HBONE outbound pool** (`src/proxy/hbone_pool.rs`) is the same H2-CONNECT-over-mTLS + tunnel-relay code path, driven by an `UpstreamTarget` whose reserved `mesh.hbone` / `mesh.hbone_port` tags are projected internally. Operator file/admin admission rejects those tags (`GatewayConfig::validate_operator_provided_fields`), so this harness launches the performance-only `hbone_perf_fixture` example: it constructs the fixture config in-process, normalizes it, and calls `file::serve` / `ProxyState` the same way mesh materialization does. That is the path edge-gateway users hit when their backend services are deployed behind an ambient mesh, without forging operator YAML.

## Quickstart

```bash
# From the repo root:
cargo build --release --example hbone_perf_fixture

# From this directory:
./run.sh --duration 30 --concurrency 50 --payload-size 1024
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--duration N` | 30 | Seconds to run each phase |
| `--concurrency N` | 50 | Concurrent in-flight requests |
| `--payload-size N` | 1024 | Request body bytes |
| `--skip-build` | off | Reuse existing binaries (use after first run) |
| `--json` | off | Machine-readable per-phase reports |
| `--sidecar-port N` | 15008 | HBONE listener port on the stub sidecar |

## Output

```
=======================================================
  HBONE Gateway Overhead — Side-by-side
=======================================================
| Path             | RPS     | p50      | p95      | p99      |
| Gateway+HBONE    | xxx,xxx |  xxx us  |  xxx us  |  xxx us  |
| Direct baseline  | xxx,xxx |  xxx us  |  xxx us  |  xxx us  |
| Overhead         |   xx %  |          |          |          |
```

## Caveats

- **Port conflicts fail closed.** `run.sh` refuses to start if 18000, 19999, or
  15008 is already bound, and cleanup stops only the gateway/sidecar/backend
  PIDs this run started (graceful `SIGTERM`, bounded wait, then `SIGKILL`) and
  removes `$RUNTIME_DIR` only after it was created by this run. It never kills
  an unrelated listener on those ports.
- **Steady-state only.** The mTLS handshake and HBONE CONNECT setup are amortised across many requests; the per-request cost dominates after the first.
- **Operator-specific numbers.** Baseline RPS depends entirely on hardware. The shipped `baseline.md` records provenance-tagged GitHub-hosted reference numbers; operators should run `./run.sh` on production-equivalent hardware before setting local expectations.
- **Cross-platform.** macOS works end-to-end via the userspace HBONE relay. Linux uses the same userspace relay (the gateway's `splice(2)` fast path is bypassed for HBONE because the tunnel terminates in userspace TLS state).
- **Standalone crate.** Not a workspace member; has its own `Cargo.lock`. Mirrors the layout of `tests/performance/multi_protocol/`.

## What the harness does not measure

- **HBONE inbound** (gateway acting as ambient sidecar receiving HBONE). The mesh mode dependency on a live CP and synthetic-slice → proxies pipeline is left to a follow-up that introduces a thin production hatch or a full stub CP path.
- **Trust-bundle rotation and SVID rotation drain windows.** These are correctness surfaces, not throughput surfaces.

## SYNC notes

The harness is an isolated standalone crate, so most dependency versions are free to drift from the root. **But** `rustls` and `h2` cross the wire between gateway and sidecar — a major-version mismatch on either can break the mTLS handshake or H2 flow-control framing. If you bump those in the root `Cargo.toml`, update the matching line here (look for `# SYNC:` comments) and re-run `cargo update -p <crate>` in this directory. Non-protocol deps (`rcgen`, `clap`, `hdrhistogram`, etc.) are intentionally allowed to drift.
