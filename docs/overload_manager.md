# Overload Manager

The overload manager monitors system resource pressure and progressively sheds load to prevent catastrophic failure. It runs as a background task and sets atomic flags that the proxy hot path reads with near-zero overhead.

## How It Works

A single background task polls four resource signals at a configurable interval (default: 1 second):

| Signal | Source | Why It Matters |
|--------|--------|----------------|
| **File descriptors** | OS `getrlimit(RLIMIT_NOFILE)` | Hitting the FD limit makes `accept()` fail with EMFILE — the gateway becomes completely unresponsive |
| **Active connections** | `ConnectionGuard` counter | Tracks all proxy connections (HTTP/1.1, H2, H3, gRPC, TCP, UDP) |
| **Active requests** | `RequestGuard` counter | Tracks in-flight requests — the real concurrency driver (one H2/gRPC connection can carry many). Only evaluated when a request cap is set (`FERRUM_MAX_REQUESTS` > 0) |
| **Event loop latency** | `yield_now()` scheduling delay | Detects thread starvation from blocking operations accidentally run on the async runtime |

Each signal produces a 0.0-1.0 pressure ratio. When a ratio exceeds a threshold, the monitor sets an atomic action flag.

## Progressive Actions

Actions escalate with pressure. Each action is additive — higher pressure activates additional actions on top of lower ones.

| Pressure Level | Action | Effect | Hot Path Cost |
|----------------|--------|--------|---------------|
| **0.80** (pressure) | Disable keepalive | Responses include `Connection: close`, causing HTTP/1.1 clients to disconnect after each request. This naturally frees connection slots | 1 `AtomicBool::load` per response (~1ns) |
| **0.95** (critical) | Reject new connections | TCP connections are accepted and immediately dropped (HTTP/H2). H3 connections are refused via QUIC. Existing connections continue serving | 1 `AtomicBool::load` per accept loop iteration (~1ns) |
| **0.95** (critical) | Reject new requests | New requests are rejected with `503` (gRPC `UNAVAILABLE`) once active requests reach `FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD` of `FERRUM_MAX_REQUESTS`. Only active when a request cap is configured (`FERRUM_MAX_REQUESTS` > 0) | 1 `AtomicBool::load` per request (~1ns) |

State transitions are logged at `warn` (entering overload) and `info` (recovering).

## Configuration

All settings are in `ferrum.conf` or environment variables:

```bash
# Monitor interval (minimum 100ms)
FERRUM_OVERLOAD_CHECK_INTERVAL_MS=1000

# FD thresholds
FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD=0.80    # disable keepalive
FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD=0.95    # reject connections

# Connection thresholds (ratio of active connections to FERRUM_MAX_CONNECTIONS)
FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD=0.85  # disable keepalive
FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD=0.95  # reject connections

# Request thresholds (ratio of active requests to FERRUM_MAX_REQUESTS; only active when max > 0)
FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD=0.85   # disable keepalive
FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD=0.95   # reject new requests (503 / gRPC UNAVAILABLE)

# Event loop latency thresholds (microseconds)
FERRUM_OVERLOAD_LOOP_WARN_US=10000            # log warning (10ms)
FERRUM_OVERLOAD_LOOP_CRITICAL_US=500000       # reject connections (500ms)
```

## Admin Endpoint

`GET /overload` returns the current state (unauthenticated, suitable for monitoring probes):

```json
{
  "level": "normal",
  "draining": false,
  "active_connections": 1247,
  "active_requests": 3891,
  "red_drop_probability_pct": 0.0,
  "port_exhaustion_events": 0,
  "stream_listeners": {
    "dtls_demux_sessions_total": 0,
    "dtls_demux_sessions": [],
    "bind_failures_total": 0,
    "bind_failures": []
  },
  "pressure": {
    "file_descriptors": {
      "current": 1247,
      "max": 65536,
      "ratio": 0.019
    },
    "connections": {
      "current": 1247,
      "max": 100000,
      "ratio": 0.012
    },
    "requests": {
      "current": 3891,
      "max": 0,
      "ratio": 0.0
    },
    "event_loop_latency_us": 42
  },
  "actions": {
    "disable_keepalive": false,
    "reject_new_connections": false,
    "reject_new_requests": false
  }
}
```

Returns HTTP 503 when `level` is `critical`.

## Port Exhaustion Monitoring

The `port_exhaustion_events` counter in the `/overload` response is a monotonic count of EADDRNOTAVAIL errors (OS error 99 on Linux, 49 on macOS) encountered across all outbound connection paths. This counter never resets and indicates that the gateway ran out of ephemeral ports for outbound connections.

**When this counter increases:**
- Widen the kernel ephemeral port range: `sysctl net.ipv4.ip_local_port_range="1024 65535"`
- Enable TIME_WAIT reuse: `sysctl net.ipv4.tcp_tw_reuse=1`
- Reduce pool idle timeout: `FERRUM_POOL_IDLE_TIMEOUT_SECONDS=30`
- Reduce max idle connections per host: `FERRUM_POOL_MAX_IDLE_PER_HOST=16`

All port exhaustion events are also logged at `error` level with the message prefix `PORT EXHAUSTION` and include remediation guidance.

## DTLS Pre-Handshake Monitoring

The `/overload.stream_listeners.dtls_demux_sessions_total` field reports the
number of frontend DTLS peers currently tracked by stream listeners, including
peers that have not finished the DTLS handshake yet. A non-zero or rising value
with dropped UDP+DTLS traffic usually means clients are slow to complete
handshakes or a spoofed/high-cardinality ClientHello spray is filling the
pre-handshake cap. The value is a diagnostic mirror of the DTLS demux counter
and can lag the exact in-server counter by a single increment/decrement window,
so treat it as operational telemetry rather than an admission-control source.

Mitigation knobs:
- `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` bounds how long a peer can hold DTLS demux state before completing the handshake.
- `FERRUM_UDP_MAX_SESSIONS` caps total UDP/DTLS sessions per proxy, including DTLS peers still in handshake.

## Stream-Listener Bind Failures

The `/overload.stream_listeners.bind_failures` array and its
`bind_failures_total` count report stream-listener (TCP/UDP/DTLS) resources that
are **not serving** after the most recent config reconcile — hard bind failures
**plus** listeners deferred or degraded for a config reason. A listener-task
failure that occurs asynchronously after reconcile is appended immediately. Each
entry carries a `kind` that classifies why; shared SNI listeners emit one entry
for every affected proxy. Entries are identified by
`(namespace, proxy_id, listen_port)` because proxy IDs are unique only within a
namespace:

```json
"stream_listeners": {
  "dtls_demux_sessions_total": 0,
  "dtls_demux_sessions": [],
  "bind_failures_total": 2,
  "bind_failures": [
    { "namespace": "ferrum", "proxy_id": "tcp-echo", "listen_port": 9100, "error": "Port 9100 is already in use on 0.0.0.0: Address already in use (os error 98)", "kind": "bind_failed" },
    { "namespace": "tenant-b", "proxy_id": "udp-dtls", "listen_port": 8853, "error": "Deferred: frontend_tls UDP listener requires DTLS cert/key material (not yet loaded)", "kind": "frontend_dtls_deferred" }
  ]
}
```

`kind` values:

| `kind` | Serving impact | Meaning |
| --- | --- | --- |
| `bind_failed` | Hard failure | The socket bind/probe failed (e.g. the port is already in use). |
| `backend_tls_invalid` | Hard failure | Backend TLS config validation failed while starting a new TCP+TLS listener; the listener was not installed. |
| `backend_tls_rotation_invalid` | Hard failure | In-place backend TLS material rotated to invalid content; the **previous** listener was kept running rather than closing the port. |
| `frontend_tls_deferred` | Deferral | A `frontend_tls` TCP listener is waiting for its rustls `ServerConfig` to be loaded. Clears once TLS material arrives. |
| `frontend_dtls_deferred` | Deferral | A `frontend_tls` UDP/DTLS listener is waiting for DTLS cert/key material. Clears once material arrives. |
| `frontend_dtls_build_failed` | Degradation | A `frontend_tls` UDP/DTLS listener could not build its DTLS config from the configured material; retried on the next reconcile. |

Hard failures (`bind_failed`, `backend_tls_invalid`, `backend_tls_rotation_invalid`)
are fatal at startup in `database`/`file` mode. A `frontend_*_deferred` entry is
not itself returned as a hard bind failure by reconciliation: in DP/runtime
reconciliation the listener can wait non-fatally for material, and loading the
material re-triggers reconciliation. During initial serving-mode startup,
however, the deferred listener remains in the desired set and the startup wait
does not complete until it binds; missing material can therefore still make
`database`, `file`, or `mesh` startup time out. An actual frontend TLS/DTLS
socket bind failure remains a hard `bind_failed` failure (and is fatal during
`database`/`file` startup).

In **data-plane (DP) mode** these binds are intentionally **non-fatal**: the DP
does not own its config (it comes from the control plane), so a single
unbindable CP-pushed stream proxy must not prevent the DP from starting or brick
the other listeners. Only the affected listener is skipped; it is retried on the
next reconcile. Before, a skip was only warn-logged; this structured surface lets
operators alert on `bind_failures_total > 0` and see exactly which proxy/port is
not serving (and why, via `kind`) without scraping logs. The list reflects the
latest reconcile plus any subsequent asynchronous listener-task failure, so a
resource that starts serving on a later reconcile clears its entry.
- Overload critical mode rejects new DTLS demux state before per-peer channels/tasks are allocated.

## Platform Support

| Platform | FD Monitoring | FD Limit |
|----------|--------------|----------|
| Linux | `/proc/self/fd` count | `getrlimit(RLIMIT_NOFILE)` |
| macOS | `proc_pidinfo(PROC_PIDLISTFDS)` | `getrlimit(RLIMIT_NOFILE)` |
| Windows | Not available (ratios are 0.0) | Not available |

Event loop latency and connection monitoring work on all platforms.
