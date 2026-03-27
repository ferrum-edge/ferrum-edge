# TCP/UDP Stream Proxy

Ferrum Gateway supports raw TCP and UDP stream proxying alongside its HTTP-based proxying. Each stream proxy binds to a dedicated port and forwards traffic bidirectionally between clients and backends.

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
| `tcp_tls` | TCP with TLS origination to backend (gateway connects to backend over TLS) |
| `udp` | Plain UDP datagram forwarding with session tracking |
| `dtls` | UDP with DTLS encryption to backend (DTLS 1.2 via `webrtc-dtls`) |

## Configuration

### YAML (File Mode)

```yaml
proxies:
  - id: "postgres-proxy"
    name: "PostgreSQL Proxy"
    listen_path: ""           # Auto-generated as __tcp:5432
    listen_port: 5432
    backend_protocol: tcp
    backend_host: "db.internal"
    backend_port: 5432
    enabled: true

  - id: "secure-redis"
    name: "Redis TLS Proxy"
    listen_path: ""
    listen_port: 6380
    backend_protocol: tcp_tls
    backend_host: "redis.internal"
    backend_port: 6379
    frontend_tls: true        # Terminate TLS on incoming connections
    enabled: true

  - id: "dns-proxy"
    name: "DNS Proxy"
    listen_path: ""
    listen_port: 5353
    backend_protocol: udp
    backend_host: "dns.internal"
    backend_port: 53
    udp_idle_timeout_seconds: 30
    enabled: true

  - id: "secure-iot"
    name: "IoT DTLS Proxy"
    listen_path: ""
    listen_port: 5684
    backend_protocol: dtls
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
| `backend_protocol` | `string` | (required) | One of: `tcp`, `tcp_tls`, `udp`, `dtls` |
| `frontend_tls` | `bool` | `false` | Terminate TLS (TCP) or DTLS (UDP) on incoming connections |
| `udp_idle_timeout_seconds` | `u64` | `60` | UDP session idle timeout before cleanup |

### Synthetic `listen_path`

Stream proxies use synthetic `listen_path` values (`__tcp:PORT` or `__udp:PORT`) to maintain the UNIQUE constraint on `listen_path` without conflicting with HTTP path-based routing. These are auto-generated during config normalization if `listen_path` is empty.

## Encryption Support

All combinations of frontend and backend encryption are supported:

### TCP Encryption Matrix

| Configuration | Client → Gateway | Gateway → Backend |
|---------------|------------------|-------------------|
| `tcp` | Plain TCP | Plain TCP |
| `tcp` + `frontend_tls: true` | TLS | Plain TCP |
| `tcp_tls` | Plain TCP | TLS |
| `tcp_tls` + `frontend_tls: true` | TLS | TLS (full e2e) |

### UDP Encryption Matrix

| Configuration | Client → Gateway | Gateway → Backend |
|---------------|------------------|-------------------|
| `udp` | Plain UDP | Plain UDP |
| `udp` + `frontend_tls: true` | DTLS | Plain UDP |
| `dtls` | Plain UDP | DTLS |
| `dtls` + `frontend_tls: true` | DTLS | DTLS (full e2e) |

### Frontend TLS Termination (TCP)

Set `frontend_tls: true` to accept TLS connections from clients. The gateway uses its configured TLS certificates (same as HTTPS) to terminate the connection, then forwards plaintext to the backend.

### Backend TLS Origination (TCP)

Use `backend_protocol: tcp_tls` to connect to the backend over TLS. The gateway establishes a TLS connection to the backend, forwarding the client's plaintext traffic encrypted.

Backend TLS settings are controlled by the proxy's `backend_tls_*` fields:
- `backend_tls_verify_server_cert` (default `true`) — verify backend certificate
- `backend_tls_server_ca_cert_path` — custom CA certificate for verification
- `backend_tls_client_cert_path` + `backend_tls_client_key_path` — client certificate for mutual TLS

### Frontend DTLS Termination (UDP)

Set `frontend_tls: true` on a UDP proxy to accept DTLS-encrypted connections from clients. The gateway uses ECDSA P-256 or Ed25519 certificates (configured via env vars) to terminate DTLS, then forwards decrypted datagrams to the backend.

```yaml
proxies:
  - id: "secure-iot-frontend"
    listen_port: 5684
    backend_protocol: udp          # Plain UDP to backend
    backend_host: "iot.internal"
    backend_port: 5684
    frontend_tls: true             # Accept DTLS from clients
```

Set the DTLS certificate via environment variables:
```bash
FERRUM_DTLS_CERT_PATH=/path/to/dtls-cert.pem
FERRUM_DTLS_KEY_PATH=/path/to/dtls-key.pem
```

**Important:** DTLS requires ECDSA P-256 or Ed25519 certificates. RSA keys are not supported.

### Backend DTLS Origination (UDP)

Use `backend_protocol: dtls` to encrypt UDP datagrams to the backend using DTLS 1.2. The gateway accepts plain UDP from clients and establishes a DTLS session per client to the backend.

DTLS uses the same `backend_tls_*` proxy fields as TCP TLS:

```yaml
proxies:
  - id: "secure-udp-backend"
    listen_port: 5685
    backend_protocol: dtls
    backend_host: "backend.internal"
    backend_port: 5684
    backend_tls_verify_server_cert: false     # Skip verification (testing)
    # backend_tls_server_ca_cert_path: "/path/to/ca.pem"  # Custom CA
    # backend_tls_client_cert_path: "/path/to/client.pem" # Mutual TLS
    # backend_tls_client_key_path: "/path/to/client-key.pem"
```

### Full DTLS (Frontend + Backend)

Combine `frontend_tls: true` with `backend_protocol: dtls` for end-to-end DTLS encryption:

```yaml
proxies:
  - id: "full-dtls-proxy"
    listen_port: 5686
    backend_protocol: dtls           # DTLS to backend
    backend_host: "secure-backend.internal"
    backend_port: 5684
    frontend_tls: true               # DTLS from clients
    backend_tls_verify_server_cert: false
```

This provides full encryption: DTLS client → gateway (DTLS termination) → gateway (DTLS origination) → backend.

### DTLS Key Differences from TCP TLS

- DTLS uses ECDSA P-256 or Ed25519 certificates only (RSA is not supported by the underlying DTLS library)
- Each UDP client session gets its own DTLS connection to the backend
- DTLS handshake occurs when the first datagram arrives from a new client
- The `udp_idle_timeout_seconds` setting applies to DTLS sessions the same as plain UDP
- Frontend DTLS uses separate certificates from TLS (set via `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH`)
- Frontend DTLS mTLS uses a separate trust store from TCP TLS mTLS (`FERRUM_DTLS_CLIENT_CA_CERT_PATH` vs `FERRUM_TLS_CLIENT_CA_CERT_PATH`)

### Trust Store Model

The gateway uses separate trust stores for TCP and UDP encryption:

| Trust Store | Env Variable | Scope | Purpose |
|-------------|-------------|-------|---------|
| Backend server CA (TCP + UDP) | `backend_tls_server_ca_cert_path` | Per-proxy | Verify backend's certificate. Falls back to system roots for TCP if unset. |
| Backend client cert (TCP + UDP) | `backend_tls_client_cert_path` + `backend_tls_client_key_path` | Per-proxy | Gateway presents this cert to the backend (mTLS). |
| Frontend TLS client CA (TCP) | `FERRUM_TLS_CLIENT_CA_CERT_PATH` | Gateway-wide | Verify TCP client certificates (frontend mTLS). |
| Frontend DTLS client CA (UDP) | `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | Gateway-wide | Verify DTLS client certificates (frontend mTLS). |
| Frontend TLS server cert (TCP) | `FERRUM_TLS_CERT_PATH` + `FERRUM_TLS_KEY_PATH` | Gateway-wide | Gateway's TLS certificate for TCP frontend termination. |
| Frontend DTLS server cert (UDP) | `FERRUM_DTLS_CERT_PATH` + `FERRUM_DTLS_KEY_PATH` | Gateway-wide | Gateway's DTLS certificate for UDP frontend termination. |

The separation of TCP and UDP trust stores allows independent certificate rotation and different CA hierarchies for each protocol.

## Load Balancing

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
    backend_protocol: tcp
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

## UDP Session Management

UDP is connectionless, so the gateway tracks sessions by client source address (`SocketAddr`). Each unique client gets a dedicated backend socket for reply routing.

- **Session creation**: First datagram from a new client creates a session
- **Session cleanup**: Background task runs every `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` (default 10s), removing sessions idle longer than `udp_idle_timeout_seconds`
- **Max sessions**: Limit of `FERRUM_UDP_MAX_SESSIONS` (default 10,000) concurrent sessions per proxy to prevent resource exhaustion
- **Reply routing**: Each session spawns a receiver task that forwards backend replies back to the correct client

## Compatible Plugins

Each plugin declares which protocols it supports via `supported_protocols()`. Only plugins that declare `Tcp` or `Udp` support are invoked for stream connections — the gateway automatically skips HTTP-specific plugins (auth, CORS, body transformer, request/response transformer, etc.).

| Plugin | Hook | Description |
|--------|------|-------------|
| `ip_restriction` | `on_stream_connect` | Block connections from denied IPs |
| `rate_limiting` | `on_stream_connect` | Connection-level rate limiting |
| `correlation_id` | `on_stream_connect` | Assign request ID to connection metadata |
| `stdout_logging` | `on_stream_disconnect` | Log connection summary as JSON |
| `http_logging` | `on_stream_disconnect` | Send connection summary to HTTP endpoint |
| `transaction_debugger` | `on_stream_disconnect` | Log detailed connection debug info |
| `prometheus_metrics` | `on_stream_disconnect` | Record connection metrics |
| `otel_tracing` | `on_stream_disconnect` | Emit trace span for connection |

See [docs/plugin_execution_order.md](plugin_execution_order.md) for the full per-plugin protocol matrix.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_STREAM_PROXY_BIND_ADDRESS` | `0.0.0.0` | Bind address for all TCP/UDP listeners |
| `FERRUM_DTLS_CERT_PATH` | (none) | PEM certificate for frontend DTLS termination (ECDSA P-256 or Ed25519) |
| `FERRUM_DTLS_KEY_PATH` | (none) | PEM private key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | (none) | PEM CA certificate for verifying DTLS client certs (frontend mTLS). Separate from `FERRUM_TLS_CLIENT_CA_CERT_PATH` used for TCP. |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | Interval between UDP session cleanup sweeps |

## Validation Rules

- `listen_port` is required for stream proxies (1024-65535)
- `listen_port` must be unique across all stream proxies
- `listen_port` must not conflict with HTTP proxy ports, admin ports, or gRPC port
- HTTP proxies must not set `listen_port`
- Stream proxies are excluded from the HTTP router (routed by port, not path)

## Metrics

Stream proxy connections track:
- Active/total TCP connections (gauge/counter)
- Active/total UDP sessions (gauge/counter)
- Bytes sent/received per connection
- Connection duration
- Connection errors

## Limitations

- **No protocol inspection**: Stream proxies forward raw bytes — no HTTP header manipulation, path routing, or content transformation
- **No WebSocket upgrade**: WebSocket connections should use HTTP proxies with `ws`/`wss` protocol, not TCP proxies
- **UDP max datagram**: Limited to 65,535 bytes per datagram (UDP protocol limit)
- **Session isolation**: UDP sessions are keyed by source address — NAT'd clients sharing an IP:port will share a session
- **DTLS key types**: DTLS only supports ECDSA P-256 and Ed25519 certificates — RSA keys are not supported by the underlying `webrtc-dtls` library
- **DTLS protocol version**: Only DTLS 1.2 is supported (no DTLS 1.3)
- **DTLS cert separation**: Frontend DTLS uses separate cert/key from TLS (`FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` env vars, not the gateway's TLS cert)
