# Overload Manager

The overload manager monitors system resource pressure and progressively sheds load to prevent catastrophic failure. It runs as a background task and sets atomic flags that the proxy hot path reads with near-zero overhead.

## How It Works

A single background task polls four resource signals at a configurable interval (default: 1 second). File-descriptor probing runs on Tokio's blocking pool so a large fdtable cannot stall a worker thread:

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
| **0.80** (pressure) | Disable keepalive | HTTP/1.1 and HTTP/2 responses include `Connection: close`, causing clients to disconnect after each request. HTTP/3 expresses the same tier as a one-shot GOAWAY per connection (see below). This naturally frees connection slots | 1 `AtomicBool::load` per response (~1ns); HTTP/3 pays nothing per request |
| **0.95** (critical) | Reject new connections | TCP connections are accepted and immediately dropped (HTTP/H2). H3 connections are refused via QUIC. Existing connections continue serving | 1 `AtomicBool::load` per accept loop iteration (~1ns) |
| **0.95** (critical) | Reject new requests | New requests are rejected with `503` (gRPC `UNAVAILABLE`) once active requests reach `FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD` of `FERRUM_MAX_REQUESTS`. Only active when a request cap is configured (`FERRUM_MAX_REQUESTS` > 0) | 1 `AtomicBool::load` per request (~1ns) |

State transitions are logged at `warn` (entering overload) and `info` (recovering).

### The keepalive tier on HTTP/3

HTTP/1.1 and HTTP/2 shrink the connection population one response at a time: every
response emitted while `disable_keepalive` is set (or while RED sampling fires)
carries `Connection: close`. HTTP/3 has no equivalent per-response lever — a QUIC
connection multiplexes request streams and is not torn down by a response header —
so the gateway expresses this tier as a **one-shot HTTP/3 GOAWAY** on each open
connection: the peer stops opening new request streams while already-accepted
streams run to completion.

Each HTTP/3 connection subscribes to an edge-triggered watch of the binary
`disable_keepalive` flag, so the GOAWAY costs no per-connection timer and nothing
at all on the request path. The GOAWAY is latched: it fires at most once per
connection, and the same latch is shared with the SIGTERM/SIGINT drain, so a
connection never receives two.

Three consequences are deliberate and worth stating plainly:

- **The GOAWAY is terminal for that connection.** Unlike HTTP/1.1 and HTTP/2
  `Connection: close`, it cannot be withdrawn if pressure recovers. The peer
  reconnects, and that new connection is still admitted — only the critical tier
  (`reject_new_connections`, FD ≥ 0.95 / Conn ≥ 0.95) refuses new connections.
- **Only the binary `disable_keepalive` flag drives it — never RED sampling.**
  `should_disable_keepalive_red()` is a per-response probabilistic sampler; a
  GOAWAY is per-connection and terminal. Sampling it would kill a random subset of
  connections outright instead of shrinking the population gracefully, so the RED
  probability is deliberately not consulted on the HTTP/3 path.
- **A peer that goes idle after receiving GOAWAY is bounded by the QUIC idle
  timeout, not closed immediately.** The vendored h3 accept loop returns
  `Ok(None)` only once in-flight streams have completed *and* the peer has either
  sent its own GOAWAY or tried to open a stream past `max_id`; outside graceful
  shutdown there is no drain deadline to force the issue. Such a connection is
  therefore reclaimed by `FERRUM_HTTP3_IDLE_TIMEOUT` (default 30 s). No additional
  timer is armed for it.

Because the watch is edge-triggered, a connection that is established while
pressure is *already* raised is not sent a GOAWAY until the next rising edge. That
is the intended split of responsibility: admitting new connections during the
pressure tier is exactly what the tier permits, and refusing them is the critical
tier's job.

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

`GET /overload` is tiered like `/health` and `/status`:

- **Unauthenticated** callers (load balancers and orchestrator probes) receive only a coarse, LB-safe `{"level": ...}` with the correct HTTP status code. This is enough to drive shedding decisions without exposing resource internals.
- **Authenticated** callers receive the full snapshot. Authentication uses the same observability policy as `/metrics`: a valid admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`, or a source IP in `FERRUM_METRICS_ALLOWED_CIDRS`.

Unauthenticated example:

```json
{
  "level": "normal"
}
```

Authenticated example (full snapshot):

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
  "listener_failures": {
    "failures_total": 0,
    "failures": []
  },
  "pressure": {
    "file_descriptors": {
      "current": 1247,
      "max": 65536,
      "ratio": 0.019,
      "enforced": true
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

Returns HTTP 503 when `level` is `critical` (both tiers).

## Port Exhaustion Monitoring

The `port_exhaustion_events` counter in the authenticated `/overload` detail tier is a monotonic count of EADDRNOTAVAIL errors (OS error 99 on Linux, 49 on macOS) encountered across all outbound connection paths. This counter never resets and indicates that the gateway ran out of ephemeral ports for outbound connections.

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
- `FERRUM_UDP_MAX_SESSIONS_PER_IP` caps how much of that table any one effective source IP may hold. The bound is taken on the ClientHello admission path, before any per-peer allocation, so a single spoofed-source or many-source-port client cannot fill the pre-handshake table and deny DTLS service to everyone else. It is the same gateway-wide counter the plain-UDP and TCP listeners use, and the demuxer releases its slot at accept handoff, so an established DTLS session is charged once rather than twice.

Refused ClientHellos and abandoned handshakes are both reported through rate-limited, fixed-cardinality warnings that carry the count they withheld, so a spray shows up as a bounded number of records rather than one line per peer.

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
| Linux | Kernel open-FD aggregate from `stat(/proc/self/fd).st_size` (Linux 6.2+); directory walk of `/proc/self/fd` on older kernels | `getrlimit(RLIMIT_NOFILE)`, falling back to `/proc/sys/fs/nr_open` when the hard cap is unlimited |
| macOS | `proc_pidinfo(PROC_PIDLISTFDS)` | `getrlimit(RLIMIT_NOFILE)`; an unlimited hard cap disables the FD tier |
| Windows | Not available (ratios are 0.0) | Not available |

Event loop latency and connection monitoring work on all platforms.

### When FD pressure is not enforceable

`pressure.file_descriptors.enforced` reports whether the FD tier is actually
shedding. It is `false` — with `max` reported as `0` and `ratio` as `0.0` —
whenever no enforceable per-process ceiling can be determined:

- the platform has no `RLIMIT_NOFILE` (Windows), or `getrlimit` failed;
- the hard cap is `RLIM_INFINITY` and the platform publishes no ceiling of its
  own. On Linux the gateway reads `/proc/sys/fs/nr_open` — the bound
  `setrlimit(RLIMIT_NOFILE)` is itself checked against — and measures pressure
  against that, so the tier keeps working; macOS publishes no equivalent, so
  the tier is disabled there.

`raise_fd_limit()` raises the soft cap to the hard cap at startup, so an
unlimited hard cap previously produced `max: 9223372036854775807` and a ratio
that could never reach the 0.80 pressure or 0.95 critical threshold — a tier
that looked healthy while doing nothing. It is now explicitly disabled instead,
with a one-shot startup `warn!` naming the reason. Connection-based and
request-based shedding are unaffected either way; set a finite `LimitNOFILE=`
(systemd), `--ulimit nofile=` (Docker), or `/etc/security/limits.conf` value to
re-enable the FD tier.

### Monitor liveness under a saturated blocking pool

The monitor counts open FDs on the tokio blocking pool, because the count may
`stat` or walk `/proc` and must not stall a worker thread. That call is bounded
by one `FERRUM_OVERLOAD_CHECK_INTERVAL_MS` budget: if the blocking pool is
saturated — io_uring splice relays hold two blocking threads each for a
connection's whole lifetime — the monitor keeps the previous FD count, logs a
rate-limited `warn!`, and continues the loop. It deliberately does **not** fail
closed to a maximal count, which would latch the gateway into permanent
rejection with nothing to clear it. A genuine panic of the counting task still
fails closed, because that is a bug signal rather than a load signal.

The concurrent io_uring splice relay cap is derived from
`FERRUM_BLOCKING_THREADS`: at most a quarter of the pool in relays, so at most
half of it in blocking threads, leaving the other half for the monitor, config
reload, and every other `spawn_blocking` user. At the default 512-thread pool
that is 128 concurrent relays; relays beyond the cap fall back to the async
splice path rather than queueing.
