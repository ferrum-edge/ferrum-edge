# Graceful Shutdown & Connection Draining

When the gateway receives SIGTERM or SIGINT, it performs a graceful shutdown that allows in-flight requests to complete before the process exits.

## Shutdown Sequence

1. **Signal received** — SIGTERM/SIGINT broadcasts shutdown to all components
2. **Accept loops exit** — no new connections are accepted on any listener (HTTP, HTTPS, H3, TCP, UDP)
3. **Drain phase begins** — the `draining` flag is set, causing:
   - All HTTP/1.1 responses include `Connection: close` (clients disconnect after their current request)
   - The gateway waits up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` for all in-flight connections to complete
4. **Connection tracking** — every accepted connection creates a `ConnectionGuard` (RAII) that increments an atomic counter on accept and decrements on drop. The drain waiter monitors this counter
5. **Drain timeout** — if connections remain after the drain period, they are force-closed and the gateway proceeds with shutdown
6. **Background task cleanup** — DNS refresh, config polling, overload monitor, and other background tasks get 5 seconds to clean up
7. **Process exit**

## Configuration

```bash
# Seconds to wait for in-flight connections to drain (default: 30)
# Set to 0 to skip draining (immediate shutdown)
FERRUM_SHUTDOWN_DRAIN_SECONDS=30
```

## Deployment Recommendations

### Kubernetes

Set the pod's `terminationGracePeriodSeconds` to at least `FERRUM_SHUTDOWN_DRAIN_SECONDS + 10`:

```yaml
spec:
  terminationGracePeriodSeconds: 45
  containers:
    - name: ferrum-edge
      env:
        - name: FERRUM_SHUTDOWN_DRAIN_SECONDS
          value: "30"
```

### Load Balancer Integration

1. Remove the gateway from the load balancer's target group (health check fails during drain since `/health` becomes unavailable after listeners close)
2. Wait for the LB to stop sending traffic (typically 1-2 health check intervals)
3. Send SIGTERM to the gateway
4. The gateway drains existing connections for up to `FERRUM_SHUTDOWN_DRAIN_SECONDS`

### Rolling Deploys

For zero-downtime rolling deploys:
- Run multiple gateway instances behind a load balancer
- Deploy one instance at a time
- The drain period ensures no in-flight requests are dropped during the switchover

## Interaction with Overload Manager

During the drain phase, the overload manager's `draining` flag is set, which causes `Connection: close` on all responses. This is independent of the overload manager's `disable_keepalive` action (which is pressure-triggered). Both flags produce the same `Connection: close` behavior — they are OR'd together.

The `GET /overload` endpoint reports `draining: true` during the drain phase.
