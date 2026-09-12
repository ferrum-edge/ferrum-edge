# Graceful Shutdown & Connection Draining

When the gateway receives SIGTERM or SIGINT, it performs a graceful shutdown that allows in-flight requests to complete before the process exits.

## Shutdown Sequence

Serving modes (database, file, cp, dp, mesh) run these phases **sequentially**, each with its own bounded budget. The worst-case total is the sum of every phase below, not just `FERRUM_SHUTDOWN_DRAIN_SECONDS`.

1. **Signal received** — the process publishes its draining verdict *before* anything else: `/health` and `/status` immediately report `{"status": "draining", "ready": false}` with HTTP 503, while `/live` deliberately keeps returning 200 so a Kubernetes livenessProbe cannot SIGKILL the pod mid-drain
2. **Pre-drain window (optional)** — for `FERRUM_SHUTDOWN_PREDRAIN_SECONDS` (default `0`) every listener keeps accepting normally while readiness already reports not-ready. In `database`/`file`/`dp`/`mesh` that is the proxy **and** admin listeners; in `cp` (the mesh chart's `controlPlane` and `ca` workloads) it is the admin HTTP/HTTPS plus CP gRPC / xDS listeners, all of which close on the same broadcast this window delays. This is the window in which a load balancer or orchestrator can withdraw the replica from its endpoint set before a single new connection is refused. At the default `0` the shutdown broadcast fires immediately, exactly as before
3. **Shutdown broadcast** — SIGTERM/SIGINT is broadcast to all components
4. **Accept loops exit** — no new connections are accepted on any listener (HTTP, HTTPS, H3, TCP, UDP)
5. **Drain phase begins** — the per-instance `draining` flag is set, causing:
   - All HTTP/1.1 responses include `Connection: close` (clients disconnect after their current request)
   - New requests/streams on existing connections are rejected (503 / gRPC `UNAVAILABLE`)
   - The gateway waits up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` for all in-flight connections to complete
6. **Connection tracking** — every accepted connection creates a `ConnectionGuard` (RAII) that increments an atomic counter on accept and decrements on drop. The drain waiter monitors this counter
7. **Drain timeout** — if connections remain after the drain period, they are force-closed and the gateway proceeds with shutdown
8. **Transport pool drain** — sidecar-ingress Unix backend pools release held file descriptors under a bounded tail (5s driver drain + 1s reap; see `unix_backend_pool.rs`)
9. **Background task cleanup** — DNS refresh, config polling, overload monitor, health checks, and other background tasks get 5 seconds to clean up
10. **Audit flush** (database and cp modes) — accepted audit events drain for `clamp(FERRUM_SHUTDOWN_DRAIN_SECONDS, 5, 60)` seconds while the database handle is still alive
11. **Observability delivery** — deferred logging/notification workers drain for `FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS` (default 2s)
12. **Plugin finalizers** — chargeback snapshot and Kafka logging generations finalize (best-effort; allow headroom in the pod grace period)
13. **Process exit**

`FERRUM_SHUTDOWN_DRAIN_SECONDS=0` still disables the drain **wait**; the close hint and the request-admission rejection in step 5 are unconditional, and the pre-drain window in step 2 is independent of it.

## Repeated signals

A second `SIGTERM`/`SIGINT` is an escalation, not a duplicate. The gateway keeps listening for signals for its whole lifetime, so:

- **First signal** — the ordinary sequence above.
- **Second signal** — logged at `warn`, and the process **skips whatever remains of the pre-drain window and the drain wait** (steps 2 and 5-7). Everything after that runs unchanged: the transport pool tail, background-task cleanup, audit flush, observability delivery, and plugin finalizers. The escalation means "stop waiting for peers", not "abandon cleanup".
- **Third and later** — logged at `warn` with a reminder that `SIGKILL` is the only stronger step, and that it skips the cleanup phases entirely.

This is the behavior operators expect from pressing Ctrl-C twice, and it gives an orchestrator an escalation path short of `SIGKILL`. In-flight requests are force-closed at the point of escalation exactly as they are on a drain timeout.

## Bounds on the drain knobs

Both knobs are refused at the configuration boundary — at startup and by the non-serving `ferrum-edge validate` command — rather than clamped, so a typo surfaces before an incident rather than during one:

| Variable | Minimum | Maximum |
|---|---|---|
| `FERRUM_SHUTDOWN_DRAIN_SECONDS` | `0` (skip the wait) | `86400` (24h) |
| `FERRUM_SHUTDOWN_PREDRAIN_SECONDS` | `0` (no window) | `3600` (1h) |

The pre-drain ceiling is the tighter of the two because that window keeps every listener **accepting new connections** while readiness already reports not-ready; it exists to bridge a load balancer's endpoint-withdrawal latency, which is at most a few health-check intervals.

## Configuration

```bash
# Seconds to wait for in-flight connections to drain (default: 30)
# Set to 0 to skip draining (immediate shutdown)
FERRUM_SHUTDOWN_DRAIN_SECONDS=30

# Seconds every listener (proxy AND admin) keeps accepting after the signal,
# while readiness already reports ready:false / 503 (default: 0 = disabled).
# Listener-serving modes only (database, file, cp, dp, mesh); injector,
# node_agent, and migrate ignore it.
FERRUM_SHUTDOWN_PREDRAIN_SECONDS=0

# Shared observability shutdown budget in milliseconds (default: 2000)
FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS=2000
```

### Worst-case budget (defaults)

With `FERRUM_SHUTDOWN_DRAIN_SECONDS=30` and the binary defaults above:

| Phase | Budget |
|---|---|
| In-flight drain | 30s |
| Transport pool tail | 6s |
| Background tasks | 5s |
| Audit flush (database/cp) | 30s (`clamp(30, 5, 60)`) |
| Observability delivery | 2s |
| Recommended finalizer slack | 5s |
| **Total** | **78s** |

## Deployment Recommendations

### Kubernetes

Kubernetes removes a terminating pod from its Service endpoints *concurrently with* stopping it. The deletion has to reach the EndpointSlice controller and then every node's kube-proxy, so for a short period kube-proxy is still steering **new** connections at a pod that has already been told to stop. `terminationGracePeriodSeconds` does not delay the accept-loop close by a single millisecond — it only bounds how long the pod may take once SIGTERM has been sent.

The mitigation is a `preStop` hook, which Kubernetes runs **before** SIGTERM. Kubernetes 1.29+ ships a native `SleepAction` (GA in 1.30) that needs no shell and therefore works on the distroless image.

The grace period must cover the WHOLE sequence — `preStop` included, because Kubernetes starts that clock at pod deletion:

```
terminationGracePeriodSeconds >= preStop + preDrain + drain
  + 6   # transport pool tail
  + 5   # background tasks
  + clamp(drain, 5, 60)   # audit flush (database/cp)
  + 2   # observability delivery (default)
  + 5   # finalizer slack
```

With the default 30s drain the post-SIGTERM budget is **78s**, and the chart's default 30s `preStop` brings the minimum to **108s**. The Ferrum gateway and mesh Helm charts default to **110s** and validate this at render time:

```yaml
spec:
  # preStop sleep + the full post-SIGTERM budget must fit inside the grace
  # period: Kubernetes starts this clock at pod deletion, preStop included.
  terminationGracePeriodSeconds: 110
  containers:
    - name: ferrum-edge
      lifecycle:
        preStop:
          sleep:
            seconds: 30
      env:
        - name: FERRUM_SHUTDOWN_DRAIN_SECONDS
          value: "30"
      readinessProbe:
        exec:
          command: ["/app/ferrum-edge", "health"]
        periodSeconds: 10
        failureThreshold: 3
      livenessProbe:
        exec:
          command: ["/app/ferrum-edge", "health", "--live"]
```

The readiness probe is drain-aware: `ferrum-edge health` exits non-zero as soon as termination begins, because `/health` reports `{"status": "draining", "ready": false}` with HTTP 503. Point liveness at `/live` (`--live`), which stays 200 throughout — a liveness probe wired to `/health` would have kubelet SIGKILL the pod mid-drain.

On clusters older than 1.29 there is no `SleepAction`. Use `FERRUM_SHUTDOWN_PREDRAIN_SECONDS` instead: it holds the accept loops (proxy and admin) open *after* SIGTERM while readiness already reports not-ready, so kubelet's `failureThreshold x periodSeconds` removal path completes before any connection is refused. Set it to at least `failureThreshold x periodSeconds` and add it to the grace period.

The Ferrum gateway and mesh Helm charts wire all of this from per-workload `shutdownPreStopSeconds`, `shutdownPreDrainSeconds`, `shutdownDrainSeconds`, and `probes.readiness.failureThreshold`, and fail `helm template` when the grace period cannot cover the sum. On Kubernetes older than 1.29, `ferrum-mesh` refuses a non-zero SleepAction `preStop` (except the unversioned `helm template` 1.20.0 sentinel) and tells operators to set `shutdownPreStopSeconds=0` and raise `shutdownPreDrainSeconds`.

### Load Balancer Integration

Preferred sequence, when the orchestrator can drive it:

1. Remove the gateway from the load balancer's target group
2. Wait for the LB to stop sending traffic (typically 1-2 health check intervals)
3. Send SIGTERM to the gateway
4. The gateway drains existing connections for up to `FERRUM_SHUTDOWN_DRAIN_SECONDS`

When the LB is health-check driven and cannot be told to withdraw the target first — which is the normal case, and always the case under Kubernetes — set `FERRUM_SHUTDOWN_PREDRAIN_SECONDS` to at least two health-check intervals. During that window the listeners keep accepting while `/health` already returns 503, so the LB observes the failure and withdraws the target before anything is refused. Without it, `/health` stops answering the moment the listeners close and the LB withdraws the target on a *connection refusal* it has already been serving traffic into.

### Rolling Deploys

The drain period protects **in-flight** requests. It says nothing about **new**
connection admission, which is what a rolling deploy actually races: between the
moment an instance is told to stop and the moment the load balancer stops
steering at it, every new connection lands on a closing accept loop.

For rolling deploys that do not refuse connections:
- Run multiple gateway instances behind a load balancer
- Deploy one instance at a time, and keep the old instance accepting until the
  balancer has withdrawn it — a `preStop` sleep on Kubernetes, or
  `FERRUM_SHUTDOWN_PREDRAIN_SECONDS` elsewhere
- Size that window against the balancer's endpoint-removal latency, not against
  the drain period
- The drain period then ensures no in-flight request is dropped during the
  switchover

With neither window configured, a rolling upgrade refuses new connections for as
long as the balancer's removal takes — on Kubernetes that is up to
`failureThreshold x periodSeconds` of readiness probing.

## Interaction with Overload Manager

During the drain phase, the overload manager's `draining` flag is set, which causes `Connection: close` on all responses. This is independent of the overload manager's `disable_keepalive` action (which is pressure-triggered). Both flags produce the same `Connection: close` behavior — they are OR'd together.

During the drain phase, authenticated `GET /overload` detail reports `draining: true`. Unauthenticated callers still receive only `{"level": ...}` and must not be used for drain-state alerting.
