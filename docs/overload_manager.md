# Overload Manager

The overload manager monitors system resource pressure and progressively sheds load to prevent catastrophic failure. It runs as a background task and sets atomic flags that the proxy hot path reads with near-zero overhead.

## How It Works

A single background task polls three resource signals at a configurable interval (default: 1 second):

| Signal | Source | Why It Matters |
|--------|--------|----------------|
| **File descriptors** | OS `getrlimit(RLIMIT_NOFILE)` | Hitting the FD limit makes `accept()` fail with EMFILE — the gateway becomes completely unresponsive |
| **Active connections** | `ConnectionGuard` counter | Tracks all proxy connections (HTTP/1.1, H2, H3, gRPC, TCP, UDP) |
| **Event loop latency** | `yield_now()` scheduling delay | Detects thread starvation from blocking operations accidentally run on the async runtime |

Each signal produces a 0.0-1.0 pressure ratio. When a ratio exceeds a threshold, the monitor sets an atomic action flag.

## Progressive Actions

Actions escalate with pressure. Each action is additive — higher pressure activates additional actions on top of lower ones.

| Pressure Level | Action | Effect | Hot Path Cost |
|----------------|--------|--------|---------------|
| **0.80** (pressure) | Disable keepalive | Responses include `Connection: close`, causing HTTP/1.1 clients to disconnect after each request. This naturally frees connection slots | 1 `AtomicBool::load` per response (~1ns) |
| **0.95** (critical) | Reject new connections | TCP connections are accepted and immediately dropped (HTTP/H2). H3 connections are refused via QUIC. Existing connections continue serving | 1 `AtomicBool::load` per accept loop iteration (~1ns) |

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
    "event_loop_latency_us": 42
  },
  "actions": {
    "disable_keepalive": false,
    "reject_new_connections": false
  }
}
```

Returns HTTP 503 when `level` is `critical`.

## Platform Support

| Platform | FD Monitoring | FD Limit |
|----------|--------------|----------|
| Linux | `/proc/self/fd` count | `getrlimit(RLIMIT_NOFILE)` |
| macOS | `proc_pidinfo(PROC_PIDLISTFDS)` | `getrlimit(RLIMIT_NOFILE)` |
| Windows | Not available (ratios are 0.0) | Not available |

Event loop latency and connection monitoring work on all platforms.
