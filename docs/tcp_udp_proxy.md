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

**SNI-based routing:** Multiple passthrough proxies can share the same `listen_port` to route to different backends based on the SNI hostname. Each proxy's `hosts` field defines which hostnames it handles (exact match and DNS suffix wildcards like `*.example.com`, which matches any DNS name below `example.com` but not `example.com` itself). One proxy per port may have empty `hosts` as a catch-all/default. The same routing plane is available on ordinary opaque `tcp` listeners — see [Opaque TLS SNI routing](#opaque-tls-sni-routing).

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
- When sharing a port, every proxy must agree on `passthrough`, no two proxies may tie inside one routing tier, and at most one catch-all (empty `hosts`) is allowed — see [Conflict rejection](#opaque-tls-sni-routing)

**What's available in passthrough logs:**
- Client IP/port, backend IP/port
- SNI hostname (from ClientHello)
- Bytes transferred (both directions)
- Connection duration, timestamps
- Connection success/failure

### Opaque TLS SNI routing

SNI routing is not limited to `passthrough: true`. Any **opaque** stream listener — one that terminates nothing — can select its backend from the client's TLS `server_name`. A listener is opaque when it is either `passthrough: true` (any stream scheme) or an ordinary `tcp` listener with `frontend_tls: false`; such a listener already relays client bytes verbatim, so the ClientHello reaches the backend untouched.

Declaring `hosts` on an opaque listener turns it into an SNI route. Two ordinary `tcp` proxies may therefore share one port when they are distinguished only by SNI:

```yaml
proxies:
  - id: "tenant-a"
    listen_port: 8443
    backend_scheme: tcp            # opaque relay; frontend_tls stays false
    hosts: ["tenant-a.example.com"]
    backend_host: "a.internal"
    backend_port: 443

  - id: "tenant-b"
    listen_port: 8443
    backend_scheme: tcp
    hosts: ["*.tenant-b.example.com"]
    backend_host: "b.internal"
    backend_port: 443

  # Optional: exactly one default route for hostnames no tier claims.
  - id: "default-route"
    listen_port: 8443
    backend_scheme: tcp
    hosts: []
    backend_host: "default.internal"
    backend_port: 443
```

**Route precedence** (absolute, not declaration order):

1. **Exact** host match.
2. **Wildcard** match (`*.example.com` matches any DNS name below `example.com`, but not `example.com` itself).
3. **Catch-all / default** — the one proxy on the port with empty `hosts`.
4. No tier matched and no default declared → the connection is closed. No backend is resolved, dialed, health-scored, or circuit-breaker-charged.

Candidates that also carry Istio `stream_match` L4 predicates are evaluated in declaration order (VirtualService first-match-wins) with SNI ANDed onto each rule, instead of the tier ladder.

**Normalization.** Configured `hosts` are validated as lowercase ASCII DNS names with no trailing dot, no port, and no scheme; the wire `server_name` is ASCII-lowercased before comparison. IDNA is an **A-label contract on both sides**: put punycode (`xn--…`) in `hosts`, because a non-ASCII `server_name` is not a representable SNI and a U-label in `hosts` is a config error.

**ClientHello peek bounds.** The peek is non-consuming (`TcpStream::peek`), so every inspected byte still reaches the selected backend — TLS is never terminated, and no byte is rewritten or dropped. A ClientHello fragmented across TCP segments or across TLS records is reassembled. The peek is bounded two ways:

- **Time** — `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` (the same deadline that bounds terminating handshakes). `0` disables the clock; the peek then takes a small bounded number of attempts instead.
- **Bytes** — a hard 16 KiB cap (one maximum TLS record). A hello that has not completed within the cap is refused rather than parsed from a prefix.

**Fail-closed admission.** What the peek concludes decides admission:

| ClientHello peek result | Behavior |
|---|---|
| `server_name` present and representable | Route through the precedence ladder above |
| Complete, well-formed hello with no `server_name` | Route to the default route only; closed if none is declared |
| Provably **not** TLS (first byte is not a handshake record, or the first handshake message is not a ClientHello) | **Closed**, unless `FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK=true` — then routed to the default route |
| Timed out, exceeded the 16 KiB cap, ended early, malformed, or a `server_name` this gateway cannot represent | **Closed, always** |

The last row is the security boundary: such a connection may have declared *any* tenant's hostname, so quietly sending it to the default route would be a cross-tenant downgrade. `FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK` deliberately does **not** rescue it — it authorizes only the determinate non-TLS case, for ports intentionally shared with direct plaintext TCP clients.

A port whose candidates declare no `hosts` at all is not SNI-routed and none of this applies: it is a plain relay that accepts every connection. A lone `passthrough: true` listener there still peeks the ClientHello to populate `sni_hostname` for stream lifecycle plugins and logs, but that peek never gates admission; a lone ordinary `tcp` listener does not peek at all.

**Conflict rejection.** Config admission rejects only what the ladder cannot resolve, so a tie inside one tier is an error while a cross-tier pair is not:

| Pair on one port | Verdict |
|---|---|
| same exact host twice | rejected — one hostname, two owners |
| two wildcards that can both match some name (equal, or one nested below the other) | rejected |
| an exact host and a wildcard that covers it (`api.example.com` + `*.example.com`) | **allowed** — exact wins |
| a named host and the catch-all | **allowed** — the catch-all is the last tier |
| two catch-alls | rejected — one default route per port |
| mixed `passthrough` on one port | rejected — the shared socket is built from one representative before any route is selected |

Candidates that all carry `stream_match` are exempt from the tie rules: their declaration order makes first-match deterministic.

`hosts` on a stream listener that *cannot* read a ClientHello — `frontend_tls: true`, `tcps` (backend TLS origination), or non-passthrough `udp`/`dtls` — is a validation error with a field-specific diagnostic, rather than silently inert config that looks like an admission restriction but is not.

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
- The `udp_idle_timeout_seconds` setting applies to DTLS sessions the same as plain UDP. Frontend-DTLS idle cleanup uses a shared activity watermark refreshed only after policy-admitted successful forward/delivery (not on rate-rejected decrypted application datagrams)
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
- On Linux, plaintext TCP connections (no TLS on either side) always use `splice(2)` zero-copy relay, eliminating userspace memory copies entirely. The splice loops enforce `tcp_idle_timeout_seconds`, `tcp_half_close_max_wait_seconds`, `backend_read_timeout_ms`, and `backend_write_timeout_ms` directly via per-direction watermarks, so configuring any of those does not demote the connection to a userspace copy. Frontend-TLS TCP connections use `splice(2)` too when — and only when — the TLS session can be handed to the kernel TLS ULP; see "Frontend-TLS kTLS splice" below. Every connection that cannot be handed off keeps the userspace rustls relay and reports `splice=false` in its stream transaction summary.
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

## Frontend-TLS kTLS Splice

`FERRUM_KTLS_ENABLED=auto|true` lets a TLS-terminating TCP proxy hand its
session keys to the Linux kernel TLS ULP so the relay can use `splice(2)`
instead of decrypting in userspace. This is a pure optimization: **every**
connection that cannot be handed off safely keeps the userspace rustls relay
and is never dropped for it.

### What is supported

| Axis | Supported | Everything else |
| --- | --- | --- |
| Platform | Linux with the `tls` kernel module (`modprobe tls`) | userspace relay |
| TLS version | **TLS 1.2 only** | userspace relay |
| Cipher | `ECDHE_{RSA,ECDSA}_WITH_CHACHA20_POLY1305_SHA256` (Linux 5.11+), gated on its own startup probe. TLS 1.2 AES-GCM suites stay on the userspace rustls relay — Linux cannot establish a race-free receive-record bound after accept (`FIONREAD` omits out-of-order skbs) | userspace relay |
| Backend | plain `tcp` backend | userspace relay |
| Plugins | no plugin requesting decrypted first bytes | userspace relay |
| Frontend mode | terminating `tcp_tls` (not `passthrough`) | unchanged |

TLS 1.3 is **refused, not approximated**. The kernel holds a static copy of the
application traffic secret and this gateway does not implement KeyUpdate
(RFC 8446 §4.6.3) rekeying, so a TLS 1.3 client is declined before any
handshake work — detected from the `supported_versions` extension in the
peeked ClientHello — and served by the userspace relay instead.

### Why the handoff is safe (issues #2955, #3619)

`ServerConnection::dangerous_extract_secrets` silently discards
decrypted-but-unread plaintext and any residual bytes in rustls's private
inbound deframer. Because kTLS resumes decryption straight off the socket at
the extracted `rx` sequence number, either would corrupt the stream — and
neither is observable through the buffered tokio-rustls API, which is why
issue #2955 pinned that path closed.

The handshake therefore runs on `rustls::server::UnbufferedServerConnection`
(`src/proxy/ktls_accept.rs`), whose input buffer is owned by the gateway, and
the gateway reads **one whole TLS record at a time, only while rustls reports
`BlockedHandshake`**. Reaching `ConnectionState::WriteTraffic` then proves all
three preconditions at once:

1. no decrypted plaintext is staged (`ReadTraffic`/`ReadEarlyData` would have
   been emitted first),
2. no outbound record is pending (`EncodeTlsData`/`TransmitTlsData` would have
   been emitted first, and `dangerous_into_kernel_connection` re-checks), and
3. the gateway-owned inbound buffer is empty and the socket is positioned on a
   record boundary.

A client that coalesces application data behind its handshake tail simply
leaves that record in the kernel receive queue, where the kTLS record layer
picks it up — the exact case that motivated #2955.

### Fallback contract

Eligibility is decided from a **peeked** (never consumed) ClientHello, so all
of the following decline with the socket byte-for-byte intact and the ordinary
buffered tokio-rustls accept takes over: secret extraction not enabled on the
listener, no kernel cipher probe passed, no complete ClientHello observable
before `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`, a TLS 1.3 offer, any
selectable AES-GCM suite in the offer set (finite confidentiality limit), an
offer set containing any suite this kernel cannot install for the remaining
unlimited ChaCha20-Poly1305 path, a `server_name` extension whose hostname this
path cannot reproduce as faithfully as `ServerConnection::server_name()` would
(see "Observability and semantics"), or a `TCP_ULP` install failure.
`TCP_ULP` is installed *before* the handshake precisely so its
failure is still recoverable; with no keys installed the ULP is the kernel's
transparent `TLS_BASE` variant, so the userspace relay on the decline path is
unaffected.

`FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` is **one budget for the whole
frontend admission**, not one allowance per stage. The deadline is opened once
in `accept_frontend_tls` and shared by the ClientHello peek, the unbuffered
kTLS handshake, and the buffered fallback, so a peer that dribbles a partial
hello cannot spend the budget on the kTLS attempt and then be granted a fresh
full timer on the fallback. A refusal made before the point of no return
records no handshake metric and leaves the socket pristine; the timeout/failure
metric is recorded exactly once, by whichever path actually terminates the
connection.

Handshake failures, peer I/O errors, and handshake timeouts terminate the
connection exactly as they would on the buffered path, with the same
`StreamSetupKind::FrontendTlsHandshake` attribution and the same mesh mTLS
handshake metrics. The one residual unrecoverable window is a failing
`setsockopt(SOL_TLS, TLS_TX/TLS_RX)` *after* the handshake completed and
rustls's session was consumed — guarded by the startup per-cipher probe (an
identical install on a real loopback socket) plus the pre-handshake `TCP_ULP`
install on this socket, leaving ENOMEM-class kernel failure.

### Observability and semantics

A handed-off connection reports `splice=true` in its stream transaction
summary; a fallback reports `splice=false`. Peer certificate identity (mTLS),
SNI, `on_stream_connect` plugin ordering, `tcp_idle_timeout_seconds`,
`tcp_half_close_max_wait_seconds`, `backend_read_timeout_ms`,
`backend_write_timeout_ms`, byte accounting, and first-failure direction
attribution are identical on both paths — the kTLS socket carries plaintext to
userspace, so it feeds the same splice loops as a plain-to-plain relay.

SNI is the one value with no shared source: the buffered path reads
`ServerConnection::server_name()`, while `UnbufferedServerConnection` exposes no
equivalent accessor, so the kTLS path re-parses the peeked ClientHello. Ferrum's
SNI validator is deliberately stricter than the `DnsName` rules rustls applies
to a received SNI — it refuses underscore labels and a trailing root dot, both
of which rustls accepts — so a ClientHello whose `server_name` extension is
present but not representable here would report no SNI where the buffered path
reports a hostname. Rather than let the two paths disagree, those connections
**decline the handoff** (before the socket is touched) and take the buffered
accept, which reports rustls's own value. Every handed-off connection therefore
observes the same SNI the userspace relay would have.

### TLS close handshake on a spliced connection

Both halves of the TLS shutdown are handled explicitly, because a kernel-owned
record layer changes how each one surfaces.

**Receive.** A kTLS receive side returns `EINVAL` from `splice(2)` for *any*
non-application record and **leaves that record queued** — `EINVAL` is not a
synonym for `close_notify`. It also covers fatal alerts, other warning alerts,
renegotiation handshake records, and ChangeCipherSpec, and `splice(2)` can
return `EINVAL` for reasons unrelated to TLS. The client-leg splice loop
therefore reads the pending record back with the `SOL_TLS` /
`TLS_GET_RECORD_TYPE` `recvmsg(2)` ancillary contract and classifies it
(`src/proxy/ktls_record.rs`). Only an **authenticated TLS 1.2 warning-level
`close_notify`** — the kernel delivers a record only after its AEAD tag
verifies, so it cannot be spoofed into an established session — is treated as a
clean EOF, and only then is the close not reported as a relay failure or
charged to the backend circuit breaker. A fatal alert, any other alert, an
unexpected control record, a malformed (non-two-byte) alert body, and an
unrelated `EINVAL` all remain attributed relay errors.

**A bare FIN is a truncation, not an EOF.** Because the kernel record layer
delivers `close_notify` as a queued alert record, a kTLS receive side that
reaches a plain zero-byte `splice(2)` — or a zero-byte `recvmsg(2)` while
resolving an `EINVAL` — has seen the peer stop writing with *nothing
authenticated* saying the stream ended. That is RFC 5246 §7.2.1 truncation, so
both paths return an attributed `ClientToBackend` / read failure instead of a
clean relay close. Only the classified warning-level `close_notify` produces
the clean outcome.

**Transmit.** A graceful backend EOF is propagated to the client as exactly one
TLS 1.2 warning `close_notify`, emitted through kTLS TX with the matching
`TLS_SET_RECORD_TYPE` `sendmsg(2)` ancillary message **after** the last
application byte and **before** the raw `shutdown(SHUT_WR)`. Without it a
conformant TLS client sees a truncated session rather than a clean close. Only
a `sendmsg(2)` that reports **exactly** the two alert bytes counts as an
emitted `close_notify`; a zero-length, short, or oversized result is an
explicit error and becomes an attributed backend-to-client write failure rather
than being accepted as a completed shutdown. The send is non-blocking and
bounded (250 ms): a peer that stopped reading cannot wedge teardown. The raw
half-close still follows even when the alert could not be delivered, while the
transaction remains observably failed instead of reporting a clean TLS close.
Because this write targets the client socket, the failure is neutral for the
backend circuit breaker; a client that resets or stops accepting the final
alert cannot make a healthy backend accumulate connection failures.
Half-close semantics are
preserved in both directions — receiving the client's `close_notify` half-closes
only the client→backend direction, so the backend's remaining response bytes
still reach the client and the reciprocal `close_notify` is sent after they
drain.

The io_uring splice path is not used for kTLS connections.

Secret material never leaves `Zeroizing` buffers, is never logged, and the
`KernelConnection` handle rustls returns alongside the secrets is dropped
immediately (it exists only for TLS 1.3 KeyUpdate and client-side session
tickets, neither of which applies here).

### Traffic-key confidentiality budget

rustls normally counts the messages each traffic key protects and refuses to
continue past the negotiated suite's `CipherSuiteCommon::confidentiality_limit`.
`dangerous_into_kernel_connection` ends that accounting: rustls's own `kernel`
module states that a `KernelConnection` cannot track it and that aborting before
the limit becomes the caller's responsibility. In the pinned providers
(`rustls 0.23.40`, aws-lc-rs and ring alike) the TLS 1.2 AES-GCM suites carry
`confidentiality_limit: 1 << 24` and ChaCha20-Poly1305 carries `u64::MAX`.

Ferrum does not hand finite-limit suites to kTLS. Linux does not expose a
race-free bound for TLS records admitted before a post-accept `SO_RCVBUF` pin:
`FIONREAD` reports only the contiguous readable prefix and can omit
out-of-order skbs already charged to the old, autotuned receive window. An
attacker could reveal those bytes after the pin and exceed the record count
precharged for one nonblocking receive.

Both TLS 1.2 AES-GCM families are therefore removed from kTLS ClientHello
eligibility before the handshake reads the socket. Those connections continue
through the ordinary buffered rustls relay, which retains rustls's own traffic
key accounting and preserves TLS functionality. This deliberately trades
AES-GCM splice acceleration for a sound confidentiality bound.

ChaCha20-Poly1305 has rustls's unlimited (`u64::MAX`) confidentiality posture,
so it remains eligible for kTLS, builds no confidentiality guard, and retains
normal receive autotuning. The defensive budget machinery in
`src/proxy/ktls_confidentiality.rs` remains fail-closed if a future caller ever
presents a finite-limit suite, but it is not a basis for making AES-GCM eligible.

`bidirectional_copy` is not a legal relay for a kTLS client leg (it enforces
neither the close handshake nor this budget), so the unreachable
kTLS-client-to-TLS-backend combination now fails closed rather than relaying.

### Ancillary-message safety

Every `msg_control` buffer in `src/proxy/ktls_record.rs` is an
`AlignedCmsgBuf`, whose storage is overlaid with a real `libc::cmsghdr` so it
carries that type's alignment. `CMSG_FIRSTHDR` / `CMSG_NXTHDR` hand back
`*mut cmsghdr` pointers into that storage and both the writer and the reader
dereference them, so a bare `[u8; N]` (alignment 1) would be undefined
behaviour irrespective of how a given stack frame happens to be laid out. Each
`CMSG_DATA` read is additionally gated on the header having declared at least
`CMSG_LEN(1)`, the control-buffer walk is clamped to the gateway's own
capacity, `MSG_CTRUNC` is an error rather than a guess, and a platform whose
`CMSG_SPACE(1)` does not fit the inline capacity fails closed instead of
truncating.

### Hosted live-kernel coverage

Because the whole point of issue #3619 is that the handoff had been *inert*,
classifier unit tests are not accepted as evidence on their own. The required
`Unit Tests` job runs `proxy::ktls_live_kernel_tests` on the GitHub-hosted
Linux runner's real kernel with `FERRUM_KTLS_LIVE_REQUIRED=1`, which proves, on
every pull request:

1. a real rustls TLS 1.2 ChaCha20-Poly1305 client reaches
   `KtlsAcceptOutcome::Installed` — the kernel actually took the keys — and an
   AES-GCM-only offer is refused with the socket still pristine (folded into
   the same test so the required pass count stays three);
2. application bytes relay both ways through `splice(2)`, i.e. the kernel is
   really decrypting on read and encrypting on write;
3. an authenticated `close_notify` is a clean EOF that half-closes the backend
   leg;
4. the clean backend EOF that follows produces the **reciprocal**
   `close_notify`, so the client's own rustls session closes cleanly instead of
   reporting a truncation;
5. a bare TCP FIN with no alert behind it is an attributed client→backend read
   failure; and
6. a record the kernel cannot authenticate ends the relay with an attributed
   failure and never with an EOF; and
7. the handed-off ChaCha20-Poly1305 session carries rustls's unlimited
   confidentiality posture (`u64::MAX`): no per-direction guard is built and no
   receive window is pinned.

Case 7 (and the AES refusal in case 1) is asserted inside case 1's test rather
than as a fourth test, so the required live gate's expected pass count stays at
three.

The tests are `#[ignore]`d by default and pin their throwaway TLS 1.2 install
client and server to ChaCha20-Poly1305 — the only cipher family production still
hands off — so the hosted kernel gate needs that kTLS family (Linux 5.11+). The
AES refusal coverage uses a separate AES-128-GCM-only offer set and never
requires AES kTLS support. `FERRUM_KTLS_LIVE_REQUIRED=1` turns an unavailable
ChaCha20-Poly1305 capability into a failure rather than a skip, and the CI step
also fails on any `SKIP:` line or on a pass count other than three — so a green
required check cannot mean "the live path did not run".

Because that gate stands entirely on the per-cipher capability probe, the probe
has to be asking the kernel the right question. `setsockopt(SOL_TLS, TLS_TX)`
is accepted only when `optlen` is **exactly** the cipher's
`tls12_crypto_info_*` size, and ChaCha20-Poly1305's `salt` member is
zero-length (`TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE == 0`), making that struct
56 bytes rather than the 60 an AES-shaped 4-byte salt would produce. A struct
of the wrong length is refused with `EINVAL` on every kernel and reads back
indistinguishably from "this kernel has no ChaCha20-Poly1305 kTLS". Two things
keep that from recurring silently: `socket_opts::ktls` pins all three struct
sizes and `rec_seq` offsets to `libc`'s UAPI definitions with compile-time
assertions, so a layout regression fails the build; and the availability probe
records each cipher's install `errno`, which
`ktls::ktls_availability_diagnostic()` reports in the live gate's failure
message instead of a bare `chacha20=false`.

Residual, covered only by the deterministic unit suite: peer-originated fatal
alerts and non-`close_notify` warning alerts are classified by
`classify_ktls_control_record`, because rustls exposes no API for emitting an
arbitrary alert mid-session. The live half of that contract is case 6 above.

## UDP Session Management

UDP is connectionless, so the gateway tracks sessions by client source address (`SocketAddr`). Each unique client gets a dedicated backend socket for reply routing.

- **Session creation**: First datagram from a new client creates a session
- **Session cleanup**: Background task runs every `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` (default 10s), removing sessions idle longer than `udp_idle_timeout_seconds`. Idle activity and session `duration_ms` use a coarse process-monotonic clock (~100 ms resolution), not UTC/`SystemTime`, so NTP or administrator wall-clock corrections neither freeze nor prematurely expire sessions. Human-readable connect/disconnect timestamps remain civil-clock values and may diverge from `duration_ms` after a clock step. The idle watermark advances only for **policy-admitted** application datagrams that are successfully forwarded client→backend or delivered backend→client (plain UDP and frontend-DTLS, including both plain and DTLS backends). Decrypted receives that `on_udp_datagram` plugins drop (for example `udp_rate_limiting`) do **not** refresh the watermark, so rejected traffic cannot retain sessions, relay tasks, sockets, or `FERRUM_UDP_MAX_SESSIONS` slots indefinitely. DTLS handshake/control remains on the crypto stack before the application relay and is unaffected.
- **Max sessions**: Limit of `FERRUM_UDP_MAX_SESSIONS` (default 10,000) concurrent sessions per proxy to prevent resource exhaustion
- **Adaptive batching**: When `FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED=true` (default), the per-proxy recv drain limit moves across fixed internal tiers (64 / 256 / 2000 / 6000 datagrams) by observed per-proxy traffic via an EWMA — independent of `FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT`, which only sets the limit used when adaptation is disabled or before a proxy's first sample. TCP/WebSocket tunnel copy buffers similarly adapt between `FERRUM_ADAPTIVE_BUFFER_MIN_SIZE` (8 KiB) and `FERRUM_ADAPTIVE_BUFFER_MAX_SIZE` (256 KiB) when `FERRUM_ADAPTIVE_BUFFER_ENABLED=true`. See [configuration.md](configuration.md) for the full `FERRUM_ADAPTIVE_*` set.
- **Reply routing**: Each session spawns a receiver task that forwards backend replies back to the correct client
- **Datagram hook concurrency / backpressure**: When any plugin opts into `on_udp_datagram`, each established session gets one bounded client→backend ingress worker (not one task per datagram). The shared listener recv/drain loop only enqueues onto that per-session FIFO and never awaits potentially I/O-bound hooks (for example Redis-backed `udp_rate_limiting` or `fault_injection` delays). Per-session ordering is preserved. Queue depth is capped at 256 datagrams and retained payload is capped at 256 KiB per session, with an additional 16 MiB retained-payload cap across the listener; both byte budgets remain charged while a dequeued payload is held by an in-flight hook/forward future, so one slow hook per session cannot escape the aggregate limit. Overload **fails closed** by dropping the datagram (it is never forwarded without running required hooks). Drops increment the listener's `hook_ingress_drops` counter and emit a rate-limited warning (first drop, then every 100th) without per-client label cardinality. Session stop/expiry wakes an idle worker by dropping the ingress sender, cancels an in-flight hook through a dedicated notification, and drains any residual queue without running hooks or forwarding. It also re-checks stop/expired after each receive and after the hook await so a late plugin return cannot forward into an expired session. Sessions without datagram hooks keep the inline forward path. Backend→client hooks remain on the existing per-session reply task.
- **Reply send buffers (Linux)**: Each plain-UDP session keeps a `sendmmsg` fallback batch and an optional GSO accumulator. `sendmmsg` slot buffers are allocated lazily at a 2 KiB preferred size (`SEND_MMSG_SLOT_SIZE`) instead of eagerly reserving `64 × 65535` (~4.2 MiB) per session. Datagrams larger than the slot size — including the full valid UDP maximum — use the existing pktinfo-aware direct-send path; GSO same-size batching and sendmmsg fallback remain unchanged for ordinary traffic.
- **Response amplification guard**: When `udp_max_response_amplification_factor` is set, each backend datagram is limited to the latest client request payload size multiplied by the factor. A legal zero-length request gets an explicit one-byte reply allowance instead of an unusable zero budget; positive-length requests receive no floor or extra allowance.
- **Reply-source selection (`FERRUM_UDP_PKTINFO_ENABLED=auto`, Linux)**: On wildcard / multi-homed binds, `IP_PKTINFO` / `IPV6_PKTINFO` captures the per-datagram local destination address (and interface index) on recv and reuses it as the reply source on send. This saves one kernel routing lookup per `sendmsg` flush (combined with `UDP_SEGMENT`/GSO in a single cmsg buffer) and ensures replies exit the same interface the client targeted — important for NAT-sensitive middleboxes, anycast, and scoped IPv6 (link-local `fe80::/10`, where the ifindex is required to disambiguate the source zone). The captured address is stored per-session via `OnceLock` on the first datagram that exposes pktinfo; subsequent datagrams reuse it lock-free. When pktinfo is active, the recv loop uses `readable() + recvmmsg` instead of `recv_from`, so the first datagram of each wakeup also surfaces cmsg — one-shot UDP flows (e.g. DNS) get the correct reply source even when the drain loop never fires.

### Mesh UDP capture is a separate datapath

Everything above describes a **configured** UDP proxy: an operator-declared
`listen_port`, an explicit backend, and sessions keyed by client source address.
Service-mesh UDP capture is a different entry point into the same session,
relay, overload, and idle-expiry machinery — there is no `listen_port` because
datagrams arrive transparently, and the destination is recovered per datagram
from the `IP_RECVORIGDSTADDR` cmsg (netfilter `TPROXY` delivers without rewriting
it, which is why capture cannot use the TCP `REDIRECT` model).

Captured sessions are keyed by `(client, original destination)` rather than by
client alone, and Ambient offers two capture **placements** with identical
downstream behaviour:

- **Per-pod-netns producer** (default) — rules and socket inside each enrolled
  pod's network namespace.
- **Host-network capture** (`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true`,
  issue #3288) — one transparent socket in the mesh proxy's own namespace, with
  `mangle PREROUTING` rules scoped per enrolled pod's host-side interface and each
  datagram attributed to a pod by that interface plus its registered source
  address.

See [mesh.md](mesh.md) → "UDP TPROXY capture" and "Host-network UDP capture" for
the capture rules, identity model, fail-closed contract, and the mandatory
generation-bound cleanup/finalize workflow for changing placement or enabled
state. A direct placement flip is rejected.

## Kubernetes Gateway API (`TCPRoute` / `UDPRoute`)

Stream proxies can also be produced by the Kubernetes controller instead of
being written by hand. A Gateway API `TCPRoute` attached to a `protocol: TCP`
listener and a `UDPRoute` attached to a `protocol: UDP` listener each
materialize one stream proxy per rule on the Gateway listener port. Everything
on this page — session management, idle timeout, stream plugins, metrics —
applies unchanged to those generated proxies; the route only decides the listen
port and the backend.

The one exception is the response amplification guard. It is opt-in through the
per-proxy `udp_max_response_amplification_factor` above, Gateway API defines no
field that maps onto it, and the translator leaves it unset — so a generated
`UDPRoute` proxy runs without a response-size ceiling, and a hand-applied
override cannot survive, because the proxy is regenerated from the route on
every reconcile.

For a `UDPRoute` the rule's `backendRefs` is a weighted **set**. A single
serviceable leg becomes a direct backend
(`<service>.<namespace>.svc.<cluster-domain>:<port>`); two or more
non-zero-weight legs become a generated Ferrum upstream whose target weights are
the declared Gateway API weights, so ordinary weighted round-robin selection
applies. Selection happens **once per UDP session** (the client 5-tuple keyed
above), not per datagram, so distribution converges over sessions. A leg whose
`Service` is missing keeps its weight but points at an unresolvable target, so
its share of sessions is dropped rather than handed to the healthy legs.

Route admission is strict and fail closed (required `spec.rules` and
`rules[].backendRefs` arrays with at least one entry each, required numeric
`backendRefs[].port` on every entry, core `Service` backends only,
`ReferenceGrant` for cross-namespace backends, no cross-namespace `parentRefs`,
at most one *supported* rule per `UDPRoute`, same-listener UDPRoute ownership
by oldest `creationTimestamp` then `{namespace}/{name}`, and no listener at all
for a declared Gateway parent that matches nothing or lost every claimed
listener). Every `UDPRoute` requires a concrete attached Gateway UDP listener:
a route with no `parentRefs`, or whose `parentRefs` name only non-Gateway
parents (a GAMMA `Service` parent or a mistyped `kind`), opens nothing. Present
but malformed or explicitly empty `parentRefs` fail closed too. Ferrum
implements no non-Gateway `UDPRoute` parent, and treating the backend port as a
listener would create an unannounced north-south bind. The historical
backend-port fallback remains only for genuinely parentless
`TCPRoute`/`TLSRoute` inputs. A TCPRoute or TLSRoute carrying only a
non-Gateway parent (including a GAMMA `Service` parent) also opens nothing:
Ferrum implements no such L4 parent, and treating the declaration as absent
would create the same unannounced listener.
Same-listener ownership suppresses **effective traffic** only: both
otherwise-valid `UDPRoute`s stay `Accepted=True` (attached), the oldest alone
is `Programmed`/effective, the shadowed newer route reports
`Programmed=False` with conflict evidence, and listener `attachedRoutes`
counts every accepted attached route — including a non-effective newer one. A
multi-rule `UDPRoute` is valid under the upstream CRD but has no
representable aggregate here, so it is refused as `Accepted=False` /
`UnsupportedValue` on `spec.rules` rather than resolved by listener bind order.
Missing/empty/non-array `rules` or `backendRefs` reject as `Invalid`.
See [gateway_api_conformance.md](gateway_api_conformance.md) for the full field
table, the exact support boundary, and the evidence that gates `UDPRoute` — CI
Unit Tests for translation/status plus a live UDP data-path integration suite
that serves a translated route through this page's UDP runtime (`TCPRoute` and
`TLSRoute` retain Ferrum live black-box coverage).

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
| `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | `10` | Seconds allowed for frontend TCP+TLS and UDP+DTLS handshakes, and for the opaque-TLS SNI ClientHello peek. `0` disables; use only when an upstream load balancer enforces an equivalent pre-handshake deadline |
| `FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK` | `false` | Whether an [opaque-TLS SNI listener](#opaque-tls-sni-routing) may send provably non-TLS opening bytes to its declared catch-all route instead of closing the connection. Enable only for a port deliberately shared with direct plaintext TCP clients. Never applies to a ClientHello that timed out, exceeded the 16 KiB peek bound, ended early, was malformed, or named an unrepresentable host — those always fail closed |
| `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` | `300` | Default TCP idle timeout (5 min). Per-proxy `tcp_idle_timeout_seconds` overrides. 0 = disabled |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | Interval between UDP session cleanup sweeps |
| `FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT` | `6000` | Datagrams drained per UDP recv wakeup when adaptive batching is **disabled** (`FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED=false`), and the initial value before a proxy's first traffic sample. When adaptation is enabled (default) the per-proxy limit then moves across fixed internal tiers (64 / 256 / 2000 / 6000) by observed traffic and is **not** capped by this value. Raising it increases the disabled/initial limit |

### Linux Performance Tuning

These Linux-specific options auto-detect kernel support at startup when set to `auto` (default). Set to `true` to force enable or `false` to disable.

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_KTLS_ENABLED` | `auto` | kTLS kernel probe, cipher gating, and frontend-TLS kernel handoff for TCP (**ChaCha20-Poly1305 on Linux 5.11+** is the only handoff-eligible family; AES-128-GCM / AES-256-GCM stay on the userspace rustls relay because Linux cannot report all out-of-order data admitted before a receive-buffer pin; **TLS 1.2 only** — TLS 1.3 is refused because KeyUpdate is not handled). Probes a real TCP loopback pair with full `TCP_ULP` + dummy key install at startup. Handoff runs from an unbuffered rustls handshake (`UnbufferedServerConnection` → `WriteTraffic` → `dangerous_into_kernel_connection`, issues #2955/#3619); anything unprovable falls back to the userspace relay. |
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

## Outbound PROXY Protocol

Ferrum can prepend a [PROXY protocol v2](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) binary header on backend TCP connects so L4 backends (PostgreSQL, MySQL, Redis, MQTT, custom TCP) see the originating client identity instead of the gateway egress IP. HTTP paths already have `X-Forwarded-For` / `Forwarded`; this is the L4 equivalent.

### Enabling outbound PROXY

Set `backend_proxy_protocol: v2` on any `tcp` or `tcps` proxy:

```yaml
proxies:
  - id: db-proxy
    name: Postgres
    backend_scheme: tcp
    listen_port: 5432
    targets:
      - host: db.internal
        port: 5432
    backend_proxy_protocol: v2   # prepend PROXY v2 on every backend connect
```

The header is written **immediately after** the backend TCP connect and **before** any relayed application bytes — including before backend TLS handshake when originating TLS, and before splice/kTLS engagement on the Linux fast paths. Passthrough proxies are supported: the PROXY header precedes the client's encrypted ClientHello on the wire.

### Address selection

| Field | Value |
|-------|-------|
| Source IP / port | Trusted stream `client_ip` + port (after inbound PROXY trust gating when enabled; otherwise the accept-time socket peer) |
| Destination IP / port | Trusted inbound-PROXY destination when present; otherwise the complete original destination (`SO_ORIGINAL_DST` / capture metadata), falling back to the accepted socket's local address. The original port is preserved and is never replaced by a transparent capture listener port. |

IPv4 pairs encode as `AF_INET`; mixed or IPv6 pairs encode as `AF_INET6` (IPv4 addresses are promoted to IPv4-mapped form). There are no TLVs.

Outbound PROXY can be combined with inbound `stream_proxy_protocol: true`: Ferrum consumes the LB's header, then re-advertises the forwarded client identity to the backend.

### Limitations (outbound)

- **TCP and TCP+TLS only.** Setting `backend_proxy_protocol` on `udp`, `dtls`, or HTTP proxies is a validation error. UDP outbound PROXY is intentionally out of scope (session semantics differ).
- **Opt-in per proxy.** There is no global `FERRUM_*` default; backends that do not expect PROXY framing must leave the field unset.
- **Fail closed.** If outbound PROXY is enabled but the client or destination address cannot be resolved, the connection is rejected rather than dialing without a header or inventing addresses.

## Validation Rules

- `listen_port` is required for stream proxies (1024-65535)
- `listen_port` must be unique across stream proxies unless every sharer forms one opaque-TLS SNI listener (homogeneous passthrough or ordinary opaque TCP) or one L4 `stream_match` group
- `listen_port` must not conflict with gateway reserved ports — the proxy HTTP/HTTPS ports (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`), admin HTTP/HTTPS ports (`FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`), or CP gRPC port (`FERRUM_CP_GRPC_LISTEN_ADDR`)
- `listen_port` is optional for HTTP-family proxies; when present it scopes the route to that frontend port and does not join stream-port sharing
- `stream_proxy_protocol` may only be set on `tcp` / `tcp_tls` proxies; setting it on `udp`, `dtls`, or HTTP proxies is a validation error
- `backend_proxy_protocol` may only be set on `tcp` / `tcps` proxies; setting it on `udp`, `dtls`, or HTTP proxies is a validation error
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

## DTLS Recv-Loop Supervision

A DTLS frontend listener runs `DtlsServer::run` (UDP demux / handshake) in a background task while the owning future selects on `accept()`, per-listener shutdown, and global SIGTERM:

- Unexpected recv-loop exit (ordinary `recv_from` failure, panic/`JoinError`, or unexpected cancellation) is observed immediately beside `accept()` — it must not leave the listener blocked in `accept()` with `started` still true while no task reads UDP.
- Failure policy clears `started`, closes the DTLS server, and returns a contextual error to `StreamListenerManager` so reconcile/async bind-failure/readiness see the outage and can restart the listener.
- Operator or per-listener shutdown still closes the server, awaits the recv task, and returns `Ok` — it is not reported as an operational failure.

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
