# Error Classification

Ferrum Gateway classifies gateway-level communication failures into human-friendly error categories via the `error_class` field on `TransactionSummary`. This helps operators quickly identify the root cause of failed transactions without parsing raw error messages.

## How It Works

When a backend request fails (connection error, timeout, TLS failure, etc.), the gateway inspects the error chain and assigns an `ErrorClass` variant. This classification:

1. **Runs only on the error path** — successful requests never execute the classification logic, so there is zero hot-path overhead.
2. **Is set in `BackendResponse`** — the proxy core classifies the error immediately when the backend call fails.
3. **Flows to `TransactionSummary`** — all logging plugins (stdout, HTTP, Prometheus, OTel, transaction debugger) receive the `error_class` field automatically.
4. **Is omitted when `None`** — successful transactions produce no extra JSON field (`#[serde(skip_serializing_if = "Option::is_none")]`).

## Error Classes

| Error Class | Serialized Value | When It Occurs | Likely Cause |
|---|---|---|---|
| `ConnectionTimeout` | `"ConnectionTimeout"` | TCP connect timed out before a connection was established | Backend is unreachable, firewall dropping SYN packets, network latency |
| `ConnectionRefused` | `"ConnectionRefused"` | TCP connect was refused by the backend (RST received during handshake) | Backend port not listening, firewall actively rejecting, service down |
| `ConnectionReset` | `"ConnectionReset"` | TCP connection was reset by the backend (RST received mid-stream) | Backend crashed, kernel killed the connection, intermediary proxy reset |
| `ConnectionClosed` | `"ConnectionClosed"` | TCP connection was closed cleanly by the backend before a response was sent | Backend closed idle connection, connection pool stale entry, keep-alive timeout |
| `DnsLookupError` | `"DnsLookupError"` | DNS resolution failed for the backend hostname | Hostname typo, DNS server unreachable, NXDOMAIN, missing DNS record |
| `TlsError` | `"TlsError"` | TLS handshake failed | Certificate expired/untrusted, protocol version mismatch, SNI mismatch, self-signed cert without `tls_no_verify` |
| `ReadWriteTimeout` | `"ReadWriteTimeout"` | Connection was established but the response was not received within the configured timeout | Backend is slow, query/computation takes too long, deadlock in backend |
| `ClientDisconnect` | `"ClientDisconnect"` | Client disconnected before the gateway could forward the full request/response | Client cancelled request, mobile network drop, browser navigation |
| `ProtocolError` | `"ProtocolError"` | HTTP/2 or HTTP/3 protocol-level error (stream reset, GOAWAY, etc.) | Backend sent invalid HTTP frames, HTTP/2 stream limit exceeded, QUIC protocol error |
| `ResponseBodyTooLarge` | `"ResponseBodyTooLarge"` | Backend response body exceeded the configured maximum size | Backend returned unexpectedly large payload, misconfigured size limit |
| `RequestBodyTooLarge` | `"RequestBodyTooLarge"` | Request body exceeded the configured maximum size | Client sent oversized upload, misconfigured size limit |
| `ConnectionPoolError` | `"ConnectionPoolError"` | Could not acquire or create an HTTP client from the connection pool | Pool exhaustion (all connections in use), pool configuration too restrictive |
| `RequestError` | `"RequestError"` | Catch-all for unclassified request errors | Unexpected error not matching any specific category — check gateway logs for details |

## Debugging Guide

### Network-Level Issues (Gateway Node)

These error classes typically indicate problems with the gateway node itself or the network between the gateway and backends:

- **`ConnectionTimeout`** — Check network connectivity to the backend. Verify firewall rules allow outbound connections. Consider increasing the proxy's `connect_timeout` if the backend is on a high-latency network.
- **`ConnectionRefused`** — Verify the backend is running and listening on the expected host:port. Check `backend_host` and `backend_port` in the proxy config.
- **`DnsLookupError`** — Check DNS resolver configuration. Verify the `backend_host` hostname is correct and resolvable. Check `/etc/resolv.conf` or the gateway's DNS settings.
- **`ConnectionPoolError`** — The gateway may be under heavy load with all pooled connections in use. Consider increasing the global `FERRUM_POOL_MAX_IDLE_PER_HOST` env var or the per-proxy `pool_idle_timeout` setting.

### TLS Issues

- **`TlsError`** — Check that the backend's TLS certificate is valid and trusted by the gateway. For self-signed certs in development, set `FERRUM_TLS_NO_VERIFY=true`. For mTLS backends, verify the client certificate and CA chain.

### Backend Performance Issues

- **`ReadWriteTimeout`** — The backend accepted the connection but didn't respond in time. Check backend application performance, database query times, or resource contention. Consider increasing the proxy's `request_timeout`.
- **`ConnectionReset`** / **`ConnectionClosed`** — The backend dropped the connection mid-transaction. Check backend logs for crashes, OOM kills, or connection limit violations.

### Client-Side Issues

- **`ClientDisconnect`** — The client (not the backend) dropped the connection. This is often benign (user navigated away, mobile network change). High rates may indicate client-side timeouts are too aggressive.

### Protocol Issues

- **`ProtocolError`** — Check for HTTP/2 or HTTP/3 compatibility issues between the gateway and backend. Verify the backend supports the negotiated protocol version.

### Size Limit Issues

- **`RequestBodyTooLarge`** / **`ResponseBodyTooLarge`** — Review the `body_validator` plugin config and proxy-level size limits. Adjust if the limits are too restrictive for legitimate traffic.

## Example Log Output

When a backend connection times out, the `TransactionSummary` JSON includes:

```json
{
  "timestamp_received": "2026-03-26T12:00:00.000Z",
  "client_ip": "10.0.0.1",
  "http_method": "GET",
  "request_path": "/api/v1/users",
  "backend_status": 502,
  "error_class": "ConnectionTimeout",
  "latency_ms": 30000,
  "proxy_id": "abc123"
}
```

For a successful request, `error_class` is omitted entirely:

```json
{
  "timestamp_received": "2026-03-26T12:00:00.000Z",
  "client_ip": "10.0.0.1",
  "http_method": "GET",
  "request_path": "/api/v1/users",
  "backend_status": 200,
  "latency_ms": 15,
  "proxy_id": "abc123"
}
```

## Protocol Coverage

Error classification is wired into all proxy protocols:

| Protocol | Summary Type | Error Classification | Classifier |
|---|---|---|---|
| HTTP/1.1 | `TransactionSummary` | Full (13 error classes) | `classify_reqwest_error()` |
| HTTP/2 | `TransactionSummary` | Full (13 error classes) | `classify_reqwest_error()` |
| HTTP/3 (QUIC) | `TransactionSummary` | Full (13 error classes) | `classify_reqwest_error()` |
| gRPC / gRPCs | `TransactionSummary` | Full (via gRPC error mapping) | `classify_grpc_proxy_error()` |
| WebSocket / WSS | `TransactionSummary` | Full (connection-phase errors) | `classify_boxed_error()` |
| TCP / TCP+TLS | `StreamTransactionSummary` | Field available (`error_class`) | Classified from `anyhow::Error` context |
| UDP / DTLS | `StreamTransactionSummary` | Field available (`error_class`) | Classified from `anyhow::Error` context |

### Per-Error-Class Protocol Applicability

Not all error classes apply to all protocols equally:

| Error Class | HTTP | gRPC | HTTP/3 | WebSocket | TCP/UDP |
|---|:---:|:---:|:---:|:---:|:---:|
| `ConnectionTimeout` | Yes | Yes | Yes | Yes | Yes |
| `ConnectionRefused` | Yes | Yes | Yes | Yes | Yes |
| `ConnectionReset` | Yes | — | Yes | Yes | Yes |
| `ConnectionClosed` | Yes | — | Yes | Yes | Yes |
| `DnsLookupError` | Yes | Yes | Yes | Yes | Yes |
| `TlsError` | Yes | Yes | Yes | Yes | Yes |
| `ReadWriteTimeout` | Yes | Yes | Yes | — | — |
| `ClientDisconnect` | Yes | — | — | — | — |
| `ProtocolError` | Yes | Yes | Yes | — | — |
| `ResponseBodyTooLarge` | Yes | — | Yes | — | — |
| `RequestBodyTooLarge` | Yes | — | — | — | — |
| `ConnectionPoolError` | Yes | — | — | — | — |
| `RequestError` | Yes | Yes | Yes | Yes | — |

**Notes:**
- gRPC uses hyper's HTTP/2 client (not reqwest), so its error classification maps from `GrpcProxyError` variants which carry enough context to distinguish timeout, TLS, refused, and protocol errors.
- WebSocket errors are classified during the backend connection phase (before the 101 upgrade). Once the connection is upgraded, errors occur at the frame level and are not classified (the connection is already established). `ReadWriteTimeout` does not apply because WebSocket connections are long-lived and use connect-phase timeouts only.
- TCP/UDP streams don't have request/response semantics, so body size limits and client disconnect don't apply. Their primary error classes are connection-level: timeout, refused, reset, DNS, and TLS.

## Implementation Details

Error classification is implemented in `src/retry.rs`:

- `ErrorClass` enum — 13 variants covering the full spectrum of gateway-level failures.
- `classify_reqwest_error()` — inspects the `reqwest::Error` chain (connect errors, timeout, TLS, DNS, reset, etc.) and returns the appropriate `ErrorClass`. Used by HTTP/1.1, HTTP/2, and HTTP/3 paths.
- `classify_grpc_proxy_error()` — maps `GrpcProxyError` variants (timeout, unavailable, internal) into `ErrorClass`. Inspects the error message to further distinguish TLS, connection refused, protocol, and DNS errors.
- `classify_boxed_error()` — inspects generic `Box<dyn Error>` by its Display/Debug representation. Used by the WebSocket path where errors come from `tokio-tungstenite` rather than reqwest.
- All classification functions are only called when the backend request fails, keeping the hot path allocation-free.
