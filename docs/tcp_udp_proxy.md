# TCP/UDP Stream Proxy

Ferrum Edge supports raw TCP and UDP stream proxying alongside its HTTP-based proxying. Each stream proxy binds to a dedicated port and forwards traffic bidirectionally between clients and backends.

## Use Cases

- **Databases**: Proxy PostgreSQL (TCP:5432), MySQL (TCP:3306), Redis (TCP:6379) with load balancing and health checks
- **DNS**: Proxy DNS traffic (UDP:53) with session tracking
- **Game Servers**: UDP-based game protocols with per-client session isolation
- **IoT/MQTT**: TCP-based MQTT brokers with TLS termination
- **Custom Protocols**: Any TCP or UDP protocol that doesn't require HTTP-level inspection

## Backend Protocols

| Protocol | Description |
|----------|-------------|
| `tcp` | Plain TCP stream forwarding |
| `tcps` | TCP with TLS origination to backend (gateway connects to backend over TLS) |
| `udp` | Plain UDP datagram forwarding with session tracking |
| `dtls` | UDP with DTLS 1.2/1.3 encryption to backend (auto-negotiated via `dimpl`) |

## Configuration

### YAML (File Mode)

Stream proxies route on `listen_port` — they MUST NOT set `listen_path`. The
field is forbidden on stream proxies and rejected at validation.

```yaml
proxies:
  - id: "postgres-proxy"
    name: "PostgreSQL Proxy"
    listen_port: 5432
    backend_scheme: tcp
    backend_host: "db.internal"
    backend_port: 5432
    enabled: true

  - id: "secure-redis"
    name: "Redis TLS Proxy"
    listen_port: 6380
    backend_scheme: tcps
    backend_host: "redis.internal"
    backend_port: 6379
    frontend_tls: true        # Terminate TLS on incoming connections
    tcp_idle_timeout_seconds: 600  # 10 min (override global default for long-lived DB connections)
    enabled: true

  - id: "dns-proxy"
    name: "DNS Proxy"
    listen_port: 5353
    backend_scheme: udp
    backend_host: "dns.internal"
    backend_port: 53
    udp_idle_timeout_seconds: 30
    enabled: true

  - id: "secure-iot"
    name: "IoT DTLS Proxy"
    listen_port: 5684
    backend_scheme: dtls
    backend_host: "iot-backend.internal"
    backend_port: 5684
    backend_tls_verify_server_cert: false   # Skip cert verification (testing)
    udp_idle_timeout_seconds: 120
    enabled: true
```

### Key Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_port` | `u16` | (required) | Dedicated port for this stream proxy (1024-65535) |
| `backend_scheme` | `string` | (required) | One of: `tcp`, `tcps`, `udp`, `dtls` |
| `frontend_tls` | `bool` | `false` | Terminate TLS (TCP) or DTLS (UDP) on incoming connections |
| `tcp_idle_timeout_seconds` | `u64` | (global) | TCP idle timeout override. When omitted, uses `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` (default 300s). 0 = disabled |
| `stream_proxy_protocol` | `bool` | `false` | Enable inbound PROXY protocol (v1 or v2) on this `tcp`/`tcp_tls` listener. See [Inbound PROXY Protocol](#inbound-proxy-protocol) below. |
| `udp_idle_timeout_seconds` | `u64` | `60` | UDP session idle timeout before cleanup |
| `udp_max_response_amplification_factor` | `f32` | unset | Drop backend response datagrams larger than `request_payload_size × factor`. A zero-length request receives only a one-byte response allowance; nonempty requests retain the exact configured payload ratio. |

### Synthetic `listen_path`

Stream proxies use synthetic `listen_path` values (`__tcp:PORT` or `__udp:PORT`) to maintain the UNIQUE constraint on `listen_path` without conflicting with HTTP path-based routing. These are auto-generated during config normalization if `listen_path` is empty.

## Encryption Support

All combinations of frontend and backend encryption are supported:

### TCP Encryption Matrix

| Configuration | Client → Gateway | Gateway → Backend |
|---------------|------------------|-------------------|
| `tcp` | Plain TCP | Plain TCP |
| `tcp` + `frontend_tls: true` | TLS | Plain TCP |
| `tcps` | Plain TCP | TLS |
| `tcps` + `frontend_tls: true` | TLS | TLS (full e2e) |

### UDP Encryption Matrix

| Configuration | Client → Gateway | Gateway → Backend |
|---------------|------------------|-------------------|
| `udp` | Plain UDP | Plain UDP |
| `udp` + `frontend_tls: true` | DTLS | Plain UDP |
| `dtls` | Plain UDP | DTLS |
| `dtls` + `frontend_tls: true` | DTLS | DTLS (full e2e) |

### TLS/DTLS Passthrough Mode

Set `passthrough: true` to forward encrypted client bytes directly to the backend without terminating TLS or DTLS. The gateway peeks at the TLS/DTLS ClientHello to extract the SNI hostname for logging and metrics, but never decrypts application data.

| Configuration | Client → Gateway | Gateway → Backend |
|---------------|------------------|-------------------|
| `tcp` + `passthrough: true` | TLS (untouched) | TLS (forwarded as-is) |
| `udp` + `passthrough: true` | DTLS (untouched) | DTLS (forwarded as-is) |

**Use cases:**
- End-to-end encryption where the proxy must not see plaintext (zero-trust, compliance)
- Performance — skip two TLS handshakes (termination + re-origination)
- Protocol-agnostic proxying of any TLS-wrapped protocol

```yaml
proxies:
  - id: "tls-passthrough"
    listen_port: 8444
    backend_scheme: tcp
    passthrough: true              # Forward raw encrypted bytes
    backend_host: "backend.internal"
    backend_port: 443
```

**SNI-based routing:** Multiple passthrough proxies can share the same `listen_port` to route to different backends based on the SNI hostname. Each proxy's `hosts` field defines which hostnames it handles (exact match and DNS suffix wildcards like `*.example.com`, which matches any DNS name below `example.com` but not `example.com` itself). One proxy per port may have empty `hosts` as a catch-all/default.

```yaml
proxies:
  # Route TLS traffic for api.example.com to the API backend
  - id: "tls-api"
    listen_port: 8444
    backend_scheme: tcp
    passthrough: true
    hosts: ["api.example.com"]
    backend_host: "api-backend.internal"
    backend_port: 443

  # Route TLS traffic for *.db.example.com to the database backend
  - id: "tls-db"
    listen_port: 8444
    backend_scheme: tcp
    passthrough: true
    hosts: ["*.db.example.com"]
    backend_host: "db-backend.internal"
    backend_port: 5432

  # Catch-all: any other SNI goes to the default backend
  - id: "tls-default"
    listen_port: 8444
    backend_scheme: tcp
    passthrough: true
    hosts: []
    backend_host: "default-backend.internal"
    backend_port: 443
```

**Constraints:**
- `passthrough` and `frontend_tls` are mutually exclusive
- Only valid on stream proxies (`tcp`, `tcps`, `udp`, `dtls`)
- Backend TLS fields (`backend_tls_client_cert_path`, etc.) cannot be set — the proxy does not originate its own TLS
- Plugins that require decrypted content cannot run; connection-level plugins (IP restriction, rate limiting, logging, throttle) still operate normally
- SNI hostname is available in `StreamConnectionContext.sni_hostname` and `StreamTransactionSummary.sni_hostname` for logging plugins (TLS/DTLS passthrough ClientHello peek, TCP TLS termination, and DTLS termination)
- When sharing a port, all proxies must have `passthrough: true`, hosts must not overlap, and at most one catch-all (empty `hosts`) is allowed

**What's available in passthrough logs:**
- Client IP/port, backend IP/port
- SNI hostname (from ClientHello)
- Bytes transferred (both directions)
- Connection duration, timestamps
- Connection success/failure

### Frontend TLS Termination (TCP)

Set `frontend_tls: true` to accept TLS connections from clients. The gateway uses its configured TLS certificates (same as HTTPS) to terminate the connection, then forwards plaintext to the backend.

For TLS-terminating TCP proxies, Ferrum completes the client-to-gateway TLS handshake before opening the backend connection. Stream lifecycle plugins then run with frontend TLS context, including client certificate material when mTLS is enabled, before any backend socket is consumed. Clients that fail the frontend TLS handshake, or are rejected by `on_stream_connect` plugins, are closed on the frontend side without dialing the backend. Frontend TLS failures remain frontend setup failures and are not recorded as backend circuit-breaker failures. Negotiated ClientHello/handshake SNI is available on `StreamConnectionContext.sni_hostname` and preserved on `StreamTransactionSummary.sni_hostname` for disconnect logging.

Latency trade-off: backend connect now starts after frontend TLS instead of overlapping with it, so legitimate TCP+TLS sessions may add roughly one backend RTT to first-byte latency compared with backend-first setup. The benefit is that failed frontend handshakes, plugin rejects, and already-open backend circuit breakers do not spend backend sockets or handshakes on unadmitted clients. If a backend circuit breaker is already open, Ferrum still completes frontend TLS before refusing the stream, so the cost shifts to bounded frontend TLS CPU instead of backend capacity.

`passthrough: true` is different: Ferrum does not terminate TLS, so it peeks at ClientHello SNI and forwards the encrypted stream to the backend.

### Backend TLS Origination (TCP)

Use `backend_scheme: tcps` to connect to the backend over TLS. The gateway establishes a TLS connection to the backend, forwarding the client's plaintext traffic encrypted.

Backend TLS settings are controlled by the proxy's `backend_tls_*` fields:
- `backend_tls_verify_server_cert` (default `true`) — verify backend certificate
- `backend_tls_server_ca_cert_path` — custom CA certificate for verification
- `backend_tls_client_cert_path` + `backend_tls_client_key_path` — client certificate for mutual TLS

### Frontend DTLS Termination (UDP)

Set `frontend_tls: true` on a UDP proxy to accept DTLS-encrypted connections from clients. The gateway uses ECDSA P-256 or P-384 certificates (configured via env vars) to terminate DTLS, then forwards decrypted datagrams to the backend.

Like TCP+TLS, frontend DTLS handshakes complete before backend session creation. `on_stream_connect` plugins run after DTLS accept with client certificate context available when DTLS mTLS is enabled; handshake failures and plugin rejections do not create backend UDP or DTLS sessions. Negotiated ClientHello SNI is exposed on `StreamConnectionContext.sni_hostname` at connect and preserved on `StreamTransactionSummary.sni_hostname` at disconnect for logging sinks.

Frontend DTLS preserves the peer's complete leaf-first certificate chain. Stream plugins receive the leaf in `StreamConnectionContext.tls_client_cert_der` (so certificate fingerprint behavior remains leaf-only) and the presented intermediates in `tls_client_cert_chain_der`, matching TCP/TLS context semantics. Ferrum validates the leaf plus transmitted intermediates against `FERRUM_DTLS_CLIENT_CA_CERT_PATH`.

```yaml
proxies:
  - id: "secure-iot-frontend"
    listen_port: 5684
    backend_scheme: udp          # Plain UDP to backend
    backend_host: "iot.internal"
    backend_port: 5684
    frontend_tls: true             # Accept DTLS from clients
```

Set the DTLS certificate via environment variables:
```bash
FERRUM_DTLS_CERT_PATH=/path/to/dtls-cert.pem
FERRUM_DTLS_KEY_PATH=/path/to/dtls-key.pem
```

The certificate source may contain a leaf-first PEM bundle. Ferrum parses every
certificate, validates that the first certificate matches the private key, and
transmits the complete configured chain in order for both DTLS 1.2 and 1.3.
Peers may therefore trust only the root while the gateway supplies the
intermediates. The root normally stays in the trust store rather than the
transmitted bundle.

With `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`, file/provider/Kubernetes/managed-backed DTLS cert, key, client-CA, and CRL sources are watched and swapped for new DTLS sessions without rebinding the UDP listener.

**Important:** DTLS requires ECDSA P-256 or P-384 certificates. RSA and Ed25519 keys are not supported by the underlying `dimpl` library.

### Backend DTLS Origination (UDP)

Use `backend_scheme: dtls` to encrypt UDP datagrams to the backend using DTLS 1.2/1.3 (auto-negotiated). The gateway accepts plain UDP from clients and establishes a DTLS session per client to the backend.

DTLS uses the same `backend_tls_*` proxy fields as TCP TLS:

When DTLS client authentication is configured, `backend_tls_client_cert_path`
may likewise be a leaf-first PEM bundle; Ferrum sends the full chain. Backend
server verification consumes the complete chain presented by the peer, so a
custom `backend_tls_server_ca_cert_path` can contain only the trust root.

```yaml
proxies:
  - id: "secure-udp-backend"
    listen_port: 5685
    backend_scheme: dtls
    backend_host: "backend.internal"
    backend_port: 5684
    backend_tls_verify_server_cert: false     # Skip verification (testing)
    # backend_tls_server_ca_cert_path: "/path/to/ca.pem"  # Custom CA
    # backend_tls_client_cert_path: "/path/to/client.pem" # Mutual TLS
    # backend_tls_client_key_path: "/path/to/client-key.pem"
```

### Full DTLS (Frontend + Backend)

Combine `frontend_tls: true` with `backend_scheme: dtls` for end-to-end DTLS encryption:

```yaml
proxies:
  - id: "full-dtls-proxy"
    listen_port: 5686
    backend_scheme: dtls           # DTLS to backend
    backend_host: "secure-backend.internal"
    backend_port: 5684
    frontend_tls: true               # DTLS from clients
    backend_tls_verify_server_cert: false
```

This provides full encryption: DTLS client → gateway (DTLS termination) → gateway (DTLS origination) → backend.

### DTLS Key Differences from TCP TLS

- DTLS uses ECDSA P-256 or P-384 certificates only (RSA and Ed25519 are not supported by the underlying DTLS library)
- Each UDP client session gets its own DTLS connection to the backend
- Frontend DTLS allocates demux state when the first datagram arrives from a new client, before the session is accepted by the UDP proxy
- Pre-handshake DTLS demux state is capped by `FERRUM_UDP_MAX_SESSIONS` and released on `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`
- The `udp_idle_timeout_seconds` setting applies to DTLS sessions the same as plain UDP
- Frontend DTLS uses separate certificates from TLS (set via `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH`)
- Frontend DTLS mTLS uses a separate trust store from TCP TLS mTLS (`FERRUM_DTLS_CLIENT_CA_CERT_PATH` vs `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`)
- DTLS identity private-key byte owners, including reload-cache clones and
  auto-negotiation fallback state, are cleared before release. Parsed signing
  keys remain inside the selected cryptographic provider and follow that
  provider's secret-memory lifecycle.

### Trust Store Model

The gateway uses separate trust stores for TCP and UDP encryption:

| Trust Store | Env Variable | Scope | Purpose |
|-------------|-------------|-------|---------|
| Backend server CA (TCP + UDP) | `backend_tls_server_ca_cert_path` | Per-proxy | Verify backend's certificate. Falls back to system roots for TCP if unset. |
| Backend client cert (TCP + UDP) | `backend_tls_client_cert_path` + `backend_tls_client_key_path` | Per-proxy | Gateway presents this cert to the backend (mTLS). |
| Frontend TLS client CA (TCP) | `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | Gateway-wide | Verify TCP client certificates (frontend mTLS). |
| Frontend DTLS client CA (UDP) | `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | Gateway-wide | Verify DTLS client certificates (frontend mTLS). |
| Frontend TLS server cert (TCP) | `FERRUM_TLS_CERT_PATH` + `FERRUM_TLS_KEY_PATH` | Gateway-wide | Gateway's TLS certificate for TCP frontend termination. |
| Frontend DTLS server cert (UDP) | `FERRUM_DTLS_CERT_PATH` + `FERRUM_DTLS_KEY_PATH` | Gateway-wide | Gateway's DTLS certificate for UDP frontend termination. |

The separation of TCP and UDP trust stores allows independent certificate rotation and different CA hierarchies for each protocol.

## Load Balancing

### Multi-address DNS backends

For a hostname target, TCP, TCP+TLS, DTLS, passthrough, and mesh stream
connectors consume the shared DNS cache's complete rotated answer set. They try
alternate IPv4 or IPv6 candidates deterministically through their relevant
connect or handshake boundary within the proxy's single overall connect budget;
a stalled candidate receives only its share of the remaining budget. Denied
addresses are filtered independently and the dial fails closed if no approved
address remains. TLS and DTLS continue to use `backend_host` (or the configured
TLS name override) for SNI and certificate verification—the selected IP is only
the socket peer.

Plain UDP is different: it has no network handshake, and `UdpSocket::connect`
does not prove that a peer is reachable. Each session deterministically selects
the first address in its rotated set and advances only on an immediate local
bind/connect setup error. Ferrum does not replay a datagram after a send error,
because it cannot know whether the original reached the application and a retry
could duplicate one-way traffic. Response-observable failover is available to
DTLS and UDP health probes; generic plain-UDP blackholes require an
application-level acknowledgement contract to detect. See
[DNS address selection and failover](dns_resolver.md#address-selection-and-failover).

Stream proxies support load balancing via upstreams, the same as HTTP proxies:

```yaml
upstreams:
  - id: "postgres-cluster"
    algorithm: round_robin
    targets:
      - host: "db1.internal"
        port: 5432
        weight: 1
      - host: "db2.internal"
        port: 5432
        weight: 1
    health_checks:
      active:
        interval_seconds: 10
        timeout_ms: 3000
        probe_type: tcp            # TCP SYN probe
        healthy_threshold: 2
        unhealthy_threshold: 3

proxies:
  - id: "postgres-proxy"
    listen_port: 5432
    backend_scheme: tcp
    upstream_id: "postgres-cluster"
```

## Health Checks

### TCP Probe (`probe_type: tcp`)

Attempts a TCP connection (SYN-ACK handshake) within the configured timeout. Connection accepted = healthy, refused/timeout = unhealthy.

### UDP Probe (`probe_type: udp`)

Sends a probe payload to the target and waits for any response within the timeout. Configure the payload as a hex-encoded string:

```yaml
health_checks:
  active:
    probe_type: udp
    udp_probe_payload: "0000"   # Hex-encoded bytes to send
    timeout_ms: 2000
```

### HTTP Probe (`probe_type: http`)

The default probe type. Sends an HTTP GET request and checks the response status code. Works for backends that expose HTTP health endpoints alongside their primary protocol.

## TCP Idle Timeout

TCP connections are monitored for idle activity. When no data is transferred in either direction for the configured timeout, the connection is closed. This prevents zombie connections from consuming resources when backends or clients silently disappear.

**Configuration hierarchy:**
1. Per-proxy `tcp_idle_timeout_seconds` — highest priority, set per proxy
2. Global `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` — applies to all TCP proxies that don't specify a per-proxy override
3. Default: 300 seconds (5 minutes)

**Special values:**
- `0` — disables idle timeout enforcement (relies on OS-level TCP keepalive only)
- Maximum: 86,400 seconds (24 hours)

**How it works:**
- The relay refreshes a shared activity watermark whenever either direction makes read or write progress
- A watchdog compares the last activity timestamp against the timeout. It ticks every 1 second for sub-30s timeouts and every 5 seconds for 30s+ timeouts, reducing timer churn for production-length connections
- When the timeout fires, the connection is closed gracefully and logged as a TCP idle timeout
- Connections with active data flow in either direction are never affected
- On Linux, plaintext TCP connections (no TLS on either side) always use `splice(2)` zero-copy relay, eliminating userspace memory copies entirely. The splice loops enforce `tcp_idle_timeout_seconds`, `tcp_half_close_max_wait_seconds`, `backend_read_timeout_ms`, and `backend_write_timeout_ms` directly via per-direction watermarks, so configuring any of those does not demote the connection to a userspace copy. Frontend-TLS TCP connections currently **retain the userspace rustls relay** even when `FERRUM_KTLS_ENABLED=auto`/`true` and the kernel `tls` module is loaded: the buffered tokio-rustls `TlsStream` cannot prove inbound TLS record alignment before secret extraction (issue #2955 — silent plaintext loss or deframer desync). Kernel kTLS splice will only be re-enabled from an unbuffered rustls handshake that reaches `WriteTraffic` before `dangerous_into_kernel_connection`. Plaintext-to-plaintext splice is unaffected. Stream transaction summaries report `splice=false` for frontend-TLS relays while this gate is in effect.
- TLS userspace relays additionally collapse to `tokio::io::copy_bidirectional_with_sizes` (no per-direction tracking) when the TCP idle timeout, TCP half-close cap, `backend_read_timeout_ms`, and `backend_write_timeout_ms` are all disabled (`0`); any non-zero bound opts into the direction-tracking copy path

```yaml
proxies:
  - id: "db-proxy"
    listen_port: 5432
    backend_scheme: tcp
    backend_host: "db.internal"
    backend_port: 5432
    tcp_idle_timeout_seconds: 600   # 10 min for long-lived DB connections

  - id: "cache-proxy"
    listen_port: 6379
    backend_scheme: tcp
    backend_host: "redis.internal"
    backend_port: 6379
    tcp_idle_timeout_seconds: 30    # 30 sec for short-lived cache connections
```

## TCP Backend Timeouts

`backend_read_timeout_ms` and `backend_write_timeout_ms` apply to TCP proxies as **per-direction inactivity timeouts**. They are enforced by a watchdog that polls per-direction watermarks:

- **`backend_read_timeout_ms`**: fires when the backend stops producing bytes (b2c direction goes stale). The watermark is refreshed on every successful read from the backend.
- **`backend_write_timeout_ms`**: fires when progress stalls writing to the backend (c2b direction goes stale). The watermark is refreshed on every partial `write()` that accepts bytes, so a slow-but-progressing backend keeps the watermark fresh.

Both default to 30,000 ms. Set to **`0` to disable** per-direction enforcement for long-lived TCP workloads (database keep-alives, message-broker streams, SSH/IMAP passthrough). When disabled, the TCP relay relies solely on `tcp_idle_timeout_seconds` (bidirectional) and the OS TCP keep-alive.

**Watchdog granularity**: The watchdog ticks every 1 second when the shortest active timeout is below 30 seconds, and every 5 seconds when all active timeouts are 30 seconds or longer. A configured 5,000 ms timeout therefore fires within ~6 s; the default 30,000 ms backend timeouts fire within ~35 s. This keeps short test/dev timeouts responsive while reducing per-connection timer churn for production-length TCP sessions.

**Splice/kTLS paths**: The per-direction inactivity timeouts apply to the Linux `splice(2)`, io_uring splice, and kTLS-accelerated splice paths too. Each direction carries a watermark refreshed on every successful splice syscall (read or write), and the same watchdog cadence (1 s under 30 s timeouts, 5 s otherwise) checks them. For the io_uring path the watermark is polled inline inside the blocking worker; on timeout the worker returns a sentinel error and the parent issues a `shutdown(SHUT_RDWR)` to unblock the other worker if needed. Successfully delivered bytes are preserved on EOF, idle timeout, per-direction read/write timeout, cancellation, and I/O/setup errors — the io_uring and libc-fallback workers return `bytes_so_far` with the error so metrics and `StreamTransactionSummary` still reflect volume transferred before the ending (issue #2957).

## UDP Session Management

UDP is connectionless, so the gateway tracks sessions by client source address (`SocketAddr`). Each unique client gets a dedicated backend socket for reply routing.

- **Session creation**: First datagram from a new client creates a session
- **Session cleanup**: Background task runs every `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` (default 10s), removing sessions idle longer than `udp_idle_timeout_seconds`. Idle activity and session `duration_ms` use a coarse process-monotonic clock (~100 ms resolution), not UTC/`SystemTime`, so NTP or administrator wall-clock corrections neither freeze nor prematurely expire sessions. Human-readable connect/disconnect timestamps remain civil-clock values and may diverge from `duration_ms` after a clock step.
- **Max sessions**: Limit of `FERRUM_UDP_MAX_SESSIONS` (default 10,000) concurrent sessions per proxy to prevent resource exhaustion
- **Adaptive batching**: When `FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED=true` (default), the per-proxy recv drain limit moves across fixed internal tiers (64 / 256 / 2000 / 6000 datagrams) by observed per-proxy traffic via an EWMA — independent of `FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT`, which only sets the limit used when adaptation is disabled or before a proxy's first sample. TCP/WebSocket tunnel copy buffers similarly adapt between `FERRUM_ADAPTIVE_BUFFER_MIN_SIZE` (8 KiB) and `FERRUM_ADAPTIVE_BUFFER_MAX_SIZE` (256 KiB) when `FERRUM_ADAPTIVE_BUFFER_ENABLED=true`. See [configuration.md](configuration.md) for the full `FERRUM_ADAPTIVE_*` set.
- **Reply routing**: Each session spawns a receiver task that forwards backend replies back to the correct client
- **Datagram hook concurrency / backpressure**: When any plugin opts into `on_udp_datagram`, each established session gets one bounded client→backend ingress worker (not one task per datagram). The shared listener recv/drain loop only enqueues onto that per-session FIFO and never awaits potentially I/O-bound hooks (for example Redis-backed `udp_rate_limiting`). Per-session ordering is preserved. Queue depth is capped at 256 datagrams and 256 KiB retained bytes per session; overload **fails closed** by dropping the datagram (it is never forwarded without running required hooks). Drops increment the listener's `hook_ingress_drops` counter and emit a rate-limited warning (first drop, then every 100th) without per-client label cardinality. Session stop/expiry wakes an idle worker by dropping the ingress sender (and drains any residual queue without running hooks or forwarding); the worker does not share the reply task's `Notify` stop wake. It also re-checks stop/expired after each receive and after the hook await so a late plugin return cannot forward into an expired session. Sessions without datagram hooks keep the inline forward path. Backend→client hooks remain on the existing per-session reply task.
- **Reply send buffers (Linux)**: Each plain-UDP session keeps a `sendmmsg` fallback batch and an optional GSO accumulator. `sendmmsg` slot buffers are allocated lazily at a 2 KiB preferred size (`SEND_MMSG_SLOT_SIZE`) instead of eagerly reserving `64 × 65535` (~4.2 MiB) per session. Datagrams larger than the slot size — including the full valid UDP maximum — use the existing pktinfo-aware direct-send path; GSO same-size batching and sendmmsg fallback remain unchanged for ordinary traffic.
- **Response amplification guard**: When `udp_max_response_amplification_factor` is set, each backend datagram is limited to the latest client request payload size multiplied by the factor. A legal zero-length request gets an explicit one-byte reply allowance instead of an unusable zero budget; positive-length requests receive no floor or extra allowance.
- **Reply-source selection (`FERRUM_UDP_PKTINFO_ENABLED=auto`, Linux)**: On wildcard / multi-homed binds, `IP_PKTINFO` / `IPV6_PKTINFO` captures the per-datagram local destination address (and interface index) on recv and reuses it as the reply source on send. This saves one kernel routing lookup per `sendmsg` flush (combined with `UDP_SEGMENT`/GSO in a single cmsg buffer) and ensures replies exit the same interface the client targeted — important for NAT-sensitive middleboxes, anycast, and scoped IPv6 (link-local `fe80::/10`, where the ifindex is required to disambiguate the source zone). The captured address is stored per-session via `OnceLock` on the first datagram that exposes pktinfo; subsequent datagrams reuse it lock-free. When pktinfo is active, the recv loop uses `readable() + recvmmsg` instead of `recv_from`, so the first datagram of each wakeup also surfaces cmsg — one-shot UDP flows (e.g. DNS) get the correct reply source even when the drain loop never fires.

## Compatible Plugins

Each plugin declares which protocols it supports via `supported_protocols()`. Only plugins that declare `Tcp` or `Udp` support are invoked for stream connections — the gateway automatically skips HTTP-specific plugins (auth, CORS, body transformer, request/response transformer, etc.).

| Plugin | Hook | Description |
|--------|------|-------------|
| `ip_restriction` | `on_stream_connect` | Block connections from denied IPs |
| `mtls_auth` | `on_stream_connect` | Map TCP+TLS or UDP+DTLS client certificates to Consumers |
| `access_control` | `on_stream_connect` | Consumer allow/deny after a stream auth plugin identifies the caller |
| `tcp_connection_throttle` | `on_stream_connect` + connection permit | Cap process-local active TCP/TCP+TLS connections per Consumer, else canonical client IP. UDP/DTLS attachment is rejected; each replica enforces an independent limit |
| `rate_limiting` | `on_stream_connect` | Connection/session rate limiting; consumer-aware when a stream identity exists |
| `correlation_id` | `on_stream_connect` | Assign request ID to private connection state and terminal metadata |
| `stdout_logging` | `on_stream_disconnect` | Log connection summary as JSON |
| `http_logging` | `on_stream_disconnect` | Send connection summary to HTTP endpoint |
| `tcp_logging` | `on_stream_disconnect` | Send connection summary to TCP/TLS endpoint |
| `transaction_debugger` | `on_stream_disconnect` | Log detailed connection debug info |
| `prometheus_metrics` | `on_stream_disconnect` | Record connection metrics |
| `otel_tracing` | `on_stream_disconnect` | Emit trace span for connection |

See [docs/plugin_execution_order.md](plugin_execution_order.md) for the full per-plugin protocol matrix.

Notes:
- `tcp_connection_throttle` is TCP/TCP+TLS-only. Explicit proxy/proxy-group attachment to any other protocol fails configuration admission and plugin-cache validation instead of silently claiming protection. A global policy with a nonempty effective target set must cover at least one TCP/TCP+TLS proxy; mixed global scope is applied only to its TCP-family listeners. In particular, it does not protect UDP/DTLS; use `udp_rate_limiting` for datagram/session admission. Its counters are process-local, so a replicated deployment's aggregate allowance can reach the configured limit per replica.
- `udp_rate_limiting` runs on every UDP/DTLS datagram (`on_udp_datagram`) in both directions. Steady-path capacity admission uses an atomic resident-entry count coordinated with insert/remove — it does not call `DashMap::len()` or lock every state shard per packet (local and Redis-fallback). On the plain-UDP frontend path, client→backend hooks for established sessions run on the per-session ingress worker described under [UDP Session Management](#udp-session-management) so a slow Redis round-trip for one client cannot stall the shared recv loop for every other session. See [docs/plugins.md](plugins.md#udp_rate_limiting).
- `access_control` applies to both TCP and UDP stream proxies. For TCP+TLS and UDP+DTLS, pair with `mtls_auth` for certificate-based consumer identification → ACL group/username authorization.
- `mtls_auth` applies to both TCP+TLS and UDP+DTLS stream proxies. It only activates when the listener is configured with `frontend_tls: true` and a client certificate is presented during the TLS/DTLS handshake.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_STREAM_PROXY_BIND_ADDRESS` | `0.0.0.0` | Bind address for all TCP/UDP listeners |
| `FERRUM_DTLS_CERT_PATH` | (none) | Leaf-first PEM certificate bundle for frontend DTLS termination (ECDSA P-256 or P-384 leaf) |
| `FERRUM_DTLS_KEY_PATH` | (none) | PEM private key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | (none) | PEM CA certificate for verifying DTLS client certs (frontend mTLS). Separate from `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` used for TCP. |
| `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` | `false` | Enables live reload for frontend TCP TLS, admin TLS, and frontend DTLS source changes |
| `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | `10` | Seconds allowed for frontend TCP+TLS and UDP+DTLS handshakes. `0` disables; use only when an upstream load balancer enforces an equivalent pre-handshake deadline |
| `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` | `300` | Default TCP idle timeout (5 min). Per-proxy `tcp_idle_timeout_seconds` overrides. 0 = disabled |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | Interval between UDP session cleanup sweeps |
| `FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT` | `6000` | Datagrams drained per UDP recv wakeup when adaptive batching is **disabled** (`FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED=false`), and the initial value before a proxy's first traffic sample. When adaptation is enabled (default) the per-proxy limit then moves across fixed internal tiers (64 / 256 / 2000 / 6000) by observed traffic and is **not** capped by this value. Raising it increases the disabled/initial limit |

### Linux Performance Tuning

These Linux-specific options auto-detect kernel support at startup when set to `auto` (default). Set to `true` to force enable or `false` to disable.

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_KTLS_ENABLED` | `auto` | kTLS kernel probe and cipher gating for TCP frontend-TLS paths (AES-128-GCM / AES-256-GCM on Linux 4.13/4.17+, ChaCha20-Poly1305 on 5.11+; **TLS 1.2 only** — TLS 1.3 KeyUpdate is not handled). Probes a real TCP loopback pair with full `TCP_ULP` + dummy key install at startup. **Handoff from the buffered tokio-rustls accept path is currently disabled** (issue #2955): rustls's public buffered API cannot prove the inbound deframer is empty, so every frontend-TLS connection keeps the userspace relay. Re-enable only with an unbuffered `UnbufferedServerConnection` → `WriteTraffic` → `dangerous_into_kernel_connection` handshake. |
| `FERRUM_IO_URING_SPLICE_ENABLED` | `auto` | io_uring-based splice via `IORING_OP_SPLICE` on dedicated blocking threads (Linux 5.6+). Each direction gets its own ring. Probes ring creation at startup. Uses `tokio::spawn_blocking` twice per TCP stream (one per direction), but concurrent io_uring relays are capped at 128 — beyond the cap, additional streams transparently fall back to the async libc splice path, so worst-case io_uring blocking-thread usage is 256. Keep `FERRUM_BLOCKING_THREADS` at the 512 default or higher so other `spawn_blocking` work retains headroom. Each blocking thread consumes ~2-4 MB of stack |
| `FERRUM_UDP_GRO_ENABLED` | `auto` | Reserved — UDP GRO cannot be enabled (primary recv uses `recv_from` which lacks cmsg). Infrastructure ready; requires recv loop rewrite |
| `FERRUM_UDP_GSO_ENABLED` | `auto` | UDP Generic Segmentation Offload — batches same-size datagrams into single `sendmsg()` with `UDP_SEGMENT` cmsg (Linux 4.18+). Probes on temp socket. Falls back to `sendmmsg` on failure |
| `FERRUM_UDP_PKTINFO_ENABLED` | `auto` | IP_PKTINFO / IPV6_PKTINFO on frontend UDP sockets (Linux). Captures the per-datagram local destination address (and interface index) on recv, reuses it as the reply source on send — skips one kernel routing-table lookup per flush. Combined with `UDP_SEGMENT` in one `sendmsg` cmsg. On multi-homed/wildcard binds, also ensures replies egress the same interface the client targeted. Probes both v4 and v6 on temp sockets (IPv6 ifindex preserved for link-local zones). When pktinfo is active, the UDP recv loop switches to `readable() + recvmmsg` so the first datagram of each wakeup also carries cmsg (one-shot DNS flows get the correct reply source). |
| `FERRUM_SO_BUSY_POLL_US` | `0` | Kernel busy-poll duration (µs) on UDP sockets. Reduces latency at cost of CPU. `0` = disabled |
| `FERRUM_TCP_FASTOPEN_ENABLED` | `auto` | TCP Fast Open on listener and outbound sockets. Saves 1 RTT for repeat connections. Checks `/proc/sys/net/ipv4/tcp_fastopen` sysctl |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | `64` | Datagrams per `recvmmsg` syscall (1-1024). Each slot allocates 65535 bytes |

## Inbound PROXY Protocol

Ferrum supports inbound [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) (v1 text and v2 binary, auto-detected by prefix) on TCP and TCP+TLS stream listeners. This lets a front-end load balancer (AWS NLB, HAProxy, etc.) prepend the real client address to each accepted connection so the gateway sees the originating source IP instead of the LB's own IP.

### Enabling PROXY Protocol

Add `stream_proxy_protocol: true` to any `tcp` or `tcp_tls` proxy:

```yaml
proxies:
  - id: db-proxy
    name: Postgres
    backend_scheme: tcp
    listen_port: 5432
    targets:
      - host: db.internal
        port: 5432
    stream_proxy_protocol: true   # expect PROXY header on every accepted connection
```

### Trust Gating

The forwarded address from the PROXY header is honored **only when** the socket peer (the load balancer's own IP) belongs to `FERRUM_TRUSTED_PROXIES`. This prevents a direct-connect client from spoofing their source IP by sending a hand-crafted PROXY header.

- Set `FERRUM_TRUSTED_PROXIES` to the CIDR(s) of your load balancer's egress IPs:
  ```
  FERRUM_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
  ```
- Connections from a peer **not** in `FERRUM_TRUSTED_PROXIES` are **closed immediately** with a structured warning log. An untrusted peer on a PROXY-protocol-enabled listener indicates a misconfiguration or an attack; silently ignoring the header would mislead downstream authz plugins.

### Fail-Closed Behavior

When `stream_proxy_protocol: true` is set:

| Scenario | Result |
|----------|--------|
| Trusted peer + valid PROXY header | `client_ip` = forwarded address; `direct_client_ip` = LB socket peer |
| Trusted peer + missing/invalid header | Connection **closed** immediately (structured warn) |
| Untrusted peer | Connection **closed** immediately (structured warn) |
| Trusted peer + PROXY v2 LOCAL command | `client_ip` = `direct_client_ip` = LB socket peer (LB health check) |
| v1 `UNKNOWN` or v2 `AF_UNSPEC` | `client_ip` = `direct_client_ip` = LB socket peer |

If the client does not send a PROXY header within 5 seconds, the connection is also closed.

### Client IP Resolution

After a trusted PROXY header parse, the resolved client IP flows through the full stream plugin chain:

- **`client_ip`** in `StreamConnectionContext` = forwarded source address (real originating client)
- **`direct_client_ip`** in `StreamConnectionContext` = raw socket peer (load balancer's IP)
- Stream logs and rate-limit plugins see `client_ip` (the forwarded address)
- Mesh authz `remote.ip` / `remoteIpBlocks` uses `client_ip`; `source.ip` / `ipBlocks` uses `direct_client_ip`

This mirrors the HTTP-path semantics of `X-Forwarded-For` + `FERRUM_TRUSTED_PROXIES`.

### Limitations

- **TCP and TCP+TLS only.** PROXY protocol is a TCP-borne framing; it cannot be used on `udp` or `dtls` proxies. Setting `stream_proxy_protocol: true` on a non-TCP proxy produces a validation error.
- **Shared (SNI-passthrough) ports must agree.** The PROXY header is read from the raw stream before the TLS ClientHello, so SNI-based proxy resolution has not happened yet — the accept loop applies one per-listener decision. Every passthrough proxy sharing a `listen_port` must set the same `stream_proxy_protocol` value; mixing is a validation error.
- **Not supported on mesh inbound relay paths.** Mesh tunnel peers (Sidecar mTLS, Ambient HBONE) carry cryptographic peer identity rather than PROXY headers; mesh inbound TCP relay never reads PROXY protocol headers.
- **No outbound PROXY protocol.** Ferrum currently does not prepend PROXY headers to backend connections (outbound PROXY protocol support is a future enhancement).

## Validation Rules

- `listen_port` is required for stream proxies (1024-65535)
- `listen_port` must be unique across all stream proxies (checked via database in DB/CP mode, in-memory in file mode)
- `listen_port` must not conflict with gateway reserved ports — the proxy HTTP/HTTPS ports (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`), admin HTTP/HTTPS ports (`FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`), or CP gRPC port (`FERRUM_CP_GRPC_LISTEN_ADDR`)
- HTTP proxies must not set `listen_port`
- `stream_proxy_protocol` may only be set on `tcp` / `tcp_tls` proxies; setting it on `udp`, `dtls`, or HTTP proxies is a validation error
- Stream proxies are excluded from the HTTP router (routed by port, not path)

### Port Availability Enforcement

Port conflicts are detected at multiple levels depending on the operating mode:

| Check | Database Mode | File Mode | CP Mode | DP Mode |
|-------|---------------|-----------|---------|---------|
| Port uniqueness across proxies | Admin API (DB query) | Config load | Admin API (DB query) | N/A (read-only) |
| Gateway reserved port conflict | Admin API (reject) | Startup (fatal) | Skipped¹ | Startup (warn) |
| OS-level port availability | Admin API (probe) | Startup (fatal) | Skipped¹ | Startup (warn) |
| Bind failure at listener start | Startup: fatal | Startup: fatal | N/A (no proxy) | Startup: warn, runtime: warn |

¹ In CP mode, stream proxies run on remote Data Plane nodes, not the CP host. The CP cannot probe DP ports, so local port checks are skipped. Port conflicts are caught when the DP attempts to bind.

**Database mode** provides the strongest pre-flight validation: the Admin API rejects a stream proxy configuration if the port conflicts with a gateway reserved port or is already bound by another process on the host.

**File mode** validates at startup — the gateway exits with a clear error if any stream proxy port conflicts with a gateway port or cannot be bound.

**DP mode** is intentionally lenient: the DP does not control its own configuration (it receives config from the CP), so port bind failures are logged as errors but do not prevent the DP from starting. This avoids a situation where a bad port pushed by the CP permanently prevents the DP from restarting. The DP continues serving HTTP traffic and any working stream proxies. When the CP pushes corrected config, the DP retries the failed listeners.

## Metrics

Stream proxy connections track:
- Active/total TCP connections (gauge/counter)
- Active/total UDP sessions (gauge/counter)
- Bytes sent/received per connection
- Connection duration
- Connection errors
- UDP `hook_ingress_drops` (listener counter): client→backend datagrams dropped when a session's bounded `on_udp_datagram` ingress queue is full or closed (fail closed; see [UDP Session Management](#udp-session-management))

## TCP SO_REUSEPORT Accept-Loop Supervision

When `FERRUM_ACCEPT_THREADS > 1`, a TCP stream listener binds multiple sockets on the same address via `SO_REUSEPORT` and runs one accept loop per socket. Those loops are peer components of a single listener:

- Unexpected exit of any loop (ordinary error, panic, or unexpected cancellation) is observed immediately while the listener is live.
- Failure policy is atomic: sibling loops are cancelled (and aborted if they ignore cancel), `started` is cleared, and the listener task returns a failure to `StreamListenerManager` so reconcile/readiness owners see the outage via the existing async bind-failure path rather than silently reduced accept capacity.
- Operator or per-listener shutdown completion remains a clean success and is not reported as an operational failure.

## Limitations

- **No protocol inspection**: Stream proxies forward raw bytes — no HTTP header manipulation, path routing, or content transformation
- **No WebSocket upgrade**: WebSocket connections should use HTTP proxies with `ws`/`wss` protocol, not TCP proxies
- **Circuit breaker (connection-phase only)**: TCP/UDP proxies participate in circuit breaker tracking for connection-phase failures (connect refused, timeout, TLS handshake error, DNS failure). Connection errors are controlled by `trip_on_connection_errors` (default: `true`); clean connection completion records success. Once bidirectional data transfer starts, the circuit breaker does not track per-byte errors since raw byte forwarding has no semantic failure signal (like HTTP status codes).
- **Connection-phase retries only**: TCP/UDP connections support retries during the connection phase (before data transfer starts). On connect failure, the gateway selects a different load-balanced target and retries with backoff. Once bytes have been forwarded, retries are not possible — the stream cannot be replayed.
- **UDP max datagram**: Limited to 65,535 bytes per datagram (UDP protocol limit)
- **Session isolation**: UDP sessions are keyed by source address — NAT'd clients sharing an IP:port will share a session
- **DTLS key types**: DTLS supports ECDSA P-256 and P-384 certificates — RSA and Ed25519 keys are not supported by the underlying `dimpl` library
- **DTLS protocol version**: Both DTLS 1.2 and DTLS 1.3 (RFC 9147) are supported. Version is auto-negotiated — the highest mutually supported version is used.
- **DTLS cert separation**: Frontend DTLS uses separate cert/key from TLS (`FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` env vars, not the gateway's TLS cert)
