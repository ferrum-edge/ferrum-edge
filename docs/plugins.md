# Plugin Reference

Ferrum Edge includes 37 built-in plugins organized into lifecycle phases. Each plugin executes at a specific priority (lower number = runs first).

For execution order, protocol support matrix, and design rationale, see [plugin_execution_order.md](plugin_execution_order.md).

## Lifecycle Phases

1. **`on_request_received`** — Called immediately when a request arrives (CORS preflight, rate limiting)
2. **`authenticate`** — Identifies the consumer (mTLS, JWKS, JWT, API Key, Basic Auth)
3. **`authorize`** — Checks consumer permissions (Access Control)
4. **`before_proxy`** — Modifies the request before forwarding (Request Transformer)
5. **`after_proxy`** — Modifies response headers or can replace the backend response before downstream commit
6. **`on_response_body`** — Processes the raw buffered backend body before transforms (AI token metrics, AI rate limiter)
7. **`transform_response_body`** — Rewrites the buffered response body (Response Transformer body rules)
8. **`on_final_response_body`** — Validates or stores the final client-visible buffered body (Body Validator, Response Size Limiting, Response Caching)
9. **`log`** — Logs the transaction summary (Stdout/HTTP Logging)
10. **`on_ws_frame`** — Per-frame WebSocket hooks (Size Limiting, Rate Limiting, Frame Logging)

## Scope

- **Global** plugins apply to all proxies
- **Proxy-scoped** plugins apply only to a specific proxy and override globals of the same plugin type

## Multi-Authentication Mode

When a proxy has `auth_mode: multi`, all attached authentication plugins execute sequentially. The first plugin that successfully identifies a consumer attaches that consumer's context. Subsequent auth plugins cannot overwrite it. After all auth plugins run, the Access Control plugin verifies that at least one consumer was identified.

## Consumer Identity Headers

When a request is successfully authenticated, the gateway automatically injects identity headers:

| Header | Value | Present |
|--------|-------|---------|
| `X-Consumer-Username` | Mapped Consumer `username`, otherwise external auth header/display identity, otherwise external `authenticated_identity` | Always (when authenticated) |
| `X-Consumer-Custom-Id` | The Consumer's `custom_id` field | Only when a gateway Consumer is mapped and `custom_id` is set |

These headers are injected on all proxy paths (HTTP, gRPC, and WebSocket).

---

## Logging Plugins

### `stdout_logging`

Logs a JSON transaction summary to stdout for each request via `tracing::info!` on the `access_log` target. Output flows through the non-blocking writer, so logging never blocks request-processing threads.

**Priority:** 9000
**Config**: None required.

```yaml
plugin_name: stdout_logging
config: {}
```

### `http_logging`

Sends transaction summaries as JSON to an external HTTP endpoint. Entries are buffered and sent in batches (as a JSON array) to reduce per-request HTTP overhead.

**Priority:** 9100

| Parameter | Type | Default | Description |
|---|---|---|---|
| `endpoint_url` | String | `""` | URL to POST transaction logs to |
| `authorization_header` | String | *(none)* | Authorization header value for the logging endpoint |
| `batch_size` | Integer | `50` | Number of entries to buffer before sending a batch |
| `flush_interval_ms` | Integer | `1000` | Max milliseconds before flushing a partial batch (min: 100) |
| `max_retries` | Integer | `3` | Retry attempts on failed batch delivery |
| `retry_delay_ms` | Integer | `1000` | Delay in milliseconds between retry attempts |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full |

Batches are flushed when `batch_size` is reached **or** `flush_interval_ms` elapses, whichever comes first.

`endpoint_url` must be a valid `http://` or `https://` URL with a hostname. Malformed or non-HTTP URLs reject plugin creation at config load time instead of failing later in the background flush task.

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://logging-service.example.com/ingest"
  authorization_header: "Bearer log-token-123"
  batch_size: 50
  flush_interval_ms: 1000
```

#### Splunk HEC Integration

The `http_logging` plugin works with [Splunk HTTP Event Collector (HEC)](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector) using the **raw endpoint** (`/services/collector/raw`). The raw endpoint accepts arbitrary JSON — including the JSON arrays that `http_logging` sends — without requiring the HEC envelope format (`{"event": ...}`).

**Setup steps:**

1. **Enable HEC in Splunk** — Settings → Data Inputs → HTTP Event Collector → New Token. Note the token value.

2. **Create a sourcetype** (optional but recommended) — create a custom sourcetype that extracts JSON fields. Under Settings → Source Types, create `ferrum_edge_logs` with:
   - Event Breaking: `[\r\n]+` (one JSON object per line after array expansion)
   - KV_MODE: `json`

3. **Configure the HEC token** — edit the token's settings:
   - **Source type**: set to `_json` (built-in) or your custom `ferrum_edge_logs`
   - **Index**: choose your target index
   - **Enable indexer acknowledgement**: optional, for guaranteed delivery

4. **Configure the plugin** — point `endpoint_url` at the raw HEC endpoint and set the `authorization_header` to `Splunk <your-token>`:

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://splunk.example.com:8088/services/collector/raw"
  authorization_header: "Splunk cf2fa345-1b2c-3d4e-5f6a-7b8c9d0e1f2a"
  batch_size: 100
  flush_interval_ms: 2000
```

Splunk will parse each object in the JSON array as a separate event. All `TransactionSummary` fields (`client_ip`, `latency_total_ms`, `response_status_code`, etc.) become searchable fields in Splunk.

**Example Splunk search:**
```
sourcetype="ferrum_edge_logs" response_status_code>=500
| stats count by matched_proxy_name, error_class
```

> **Note:** If you use the standard HEC endpoint (`/services/collector/event`) instead of `/services/collector/raw`, Splunk expects each event wrapped in `{"event": ...}` — which `http_logging` does not produce. Always use the `/raw` endpoint.

> **TLS verification:** If your Splunk instance uses an internal CA, set `FERRUM_TLS_CA_BUNDLE_PATH` to your CA bundle so the plugin's HTTP client can verify the HEC endpoint's certificate.

### Transaction Summary Reference

Both `stdout_logging` and `http_logging` emit the same JSON structures. HTTP-family protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket) use `TransactionSummary`. Stream protocols (TCP, UDP, DTLS) use `StreamTransactionSummary`.

#### TransactionSummary Fields (HTTP / gRPC / WebSocket)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp_received` | String (RFC 3339) | Request arrival time (UTC) |
| `client_ip` | String | Client IP after trusted-proxy resolution |
| `consumer_username` | String or null | Authenticated identity used for policy/logging: mapped Consumer username when present, otherwise external `authenticated_identity`; null if unauthenticated |
| `http_method` | String | HTTP method (e.g., `GET`, `POST`) |
| `request_path` | String | Request path (query string stripped) |
| `matched_proxy_id` | String or null | Proxy ID that matched the route (null for unmatched) |
| `matched_proxy_name` | String or null | Proxy name (null if unnamed or unmatched) |
| `backend_target_url` | String or null | Backend URL (`host:port/path`); null for rejected requests |
| `backend_resolved_ip` | String or null | DNS-resolved backend IP; omitted from JSON when null |
| `response_status_code` | u16 | HTTP status code |
| `latency_total_ms` | f64 | Total request-to-response time |
| `latency_gateway_processing_ms` | f64 | Total time excluding backend communication |
| `latency_backend_ttfb_ms` | f64 | Time to first byte from backend; -1.0 if no backend call |
| `latency_backend_total_ms` | f64 | Full backend response time; -1.0 for streaming responses |
| `latency_plugin_execution_ms` | f64 | Wall-clock time in all plugin hooks |
| `latency_plugin_external_io_ms` | f64 | Subset of plugin time spent on external HTTP calls |
| `latency_gateway_overhead_ms` | f64 | Pure gateway overhead (routing, framing, pool checkout) |
| `request_user_agent` | String or null | User-Agent header value |
| `response_streamed` | bool | Present and `true` when body was streamed (not buffered) |
| `client_disconnected` | bool | Present and `true` when client disconnected early |
| `error_class` | String or null | Error classification; omitted from JSON when null |
| `metadata` | Object | Plugin-injected key-value pairs (correlation ID, trace ID, etc.) |

**Notes on conditional fields:** `response_streamed`, `client_disconnected`, `backend_resolved_ip`, and `error_class` are omitted from the JSON output when false/null to keep log entries compact.

**`error_class` values:** `ConnectionFailed`, `Timeout`, `BadGateway`, `ServiceUnavailable`. Only set when the gateway itself could not communicate with the backend. Normal HTTP error responses from the backend (e.g., 404, 500) do not set `error_class`.

#### StreamTransactionSummary Fields (TCP / UDP / DTLS)

| Field | Type | Description |
|-------|------|-------------|
| `proxy_id` | String | Proxy ID |
| `proxy_name` | String or null | Proxy name |
| `client_ip` | String | Client IP |
| `backend_target` | String | Backend target (`host:port`); empty if target resolution failed before LB/config lookup |
| `backend_resolved_ip` | String or null | DNS-resolved backend IP; omitted from JSON when null |
| `protocol` | String | Protocol string: `tcp`, `tcp_tls`, `udp`, or `dtls` |
| `listen_port` | u16 | Proxy listen port |
| `duration_ms` | f64 | Connection/session lifetime in milliseconds |
| `bytes_sent` | u64 | Bytes sent to backend |
| `bytes_received` | u64 | Bytes received from backend |
| `connection_error` | String or null | Error message if the connection failed |
| `error_class` | String or null | Error classification; omitted from JSON when null |
| `timestamp_connected` | String (RFC 3339) | Connection start time |
| `timestamp_disconnected` | String (RFC 3339) | Connection end time |
| `metadata` | Object | Plugin-injected key-value pairs; omitted from JSON when empty |

#### Example: HTTP/1.1 or HTTP/2 (Buffered Response)

```json
{
  "timestamp_received": "2026-03-31T14:22:01.123Z",
  "client_ip": "10.0.1.50",
  "consumer_username": "api-service-a",
  "http_method": "POST",
  "request_path": "/api/v1/users",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440001",
  "matched_proxy_name": "users-api",
  "backend_target_url": "10.0.2.10:8080/api/v1/users",
  "backend_resolved_ip": "10.0.2.10",
  "response_status_code": 201,
  "latency_total_ms": 12.45,
  "latency_gateway_processing_ms": 2.10,
  "latency_backend_ttfb_ms": 9.80,
  "latency_backend_total_ms": 10.35,
  "latency_plugin_execution_ms": 1.22,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 0.88,
  "request_user_agent": "python-requests/2.31.0",
  "metadata": {"x-correlation-id": "abc-123-def"}
}
```

#### Example: HTTP/1.1 or HTTP/2 (Streaming Response)

```json
{
  "timestamp_received": "2026-03-31T14:22:03.456Z",
  "client_ip": "10.0.1.51",
  "consumer_username": null,
  "http_method": "GET",
  "request_path": "/api/v1/events",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440002",
  "matched_proxy_name": "sse-events",
  "backend_target_url": "10.0.2.15:8080/api/v1/events",
  "backend_resolved_ip": "10.0.2.15",
  "response_status_code": 200,
  "latency_total_ms": 4.80,
  "latency_gateway_processing_ms": 1.70,
  "latency_backend_ttfb_ms": 2.90,
  "latency_backend_total_ms": -1.0,
  "latency_plugin_execution_ms": 0.55,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 1.15,
  "request_user_agent": "curl/8.5.0",
  "response_streamed": true,
  "metadata": {}
}
```

`latency_backend_total_ms` is `-1.0` because the body is still streaming when the log is emitted. Use `latency_backend_ttfb_ms` for alerting on streaming responses.

#### Example: HTTP/3 (QUIC)

```json
{
  "timestamp_received": "2026-03-31T14:22:05.789Z",
  "client_ip": "10.0.1.55",
  "consumer_username": "mobile-app",
  "http_method": "GET",
  "request_path": "/api/v2/feed",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440003",
  "matched_proxy_name": "feed-api",
  "backend_target_url": "10.0.2.20:8080/api/v2/feed",
  "backend_resolved_ip": "10.0.2.20",
  "response_status_code": 200,
  "latency_total_ms": 5.30,
  "latency_gateway_processing_ms": 1.80,
  "latency_backend_ttfb_ms": 3.10,
  "latency_backend_total_ms": 3.50,
  "latency_plugin_execution_ms": 0.95,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 0.85,
  "request_user_agent": "CFNetwork/1568.200.51",
  "metadata": {"x-correlation-id": "h3-789-xyz"}
}
```

HTTP/3 uses the same `TransactionSummary` as HTTP/1.1 and HTTP/2. The frontend accepts QUIC; the backend is reached via reqwest (HTTP/2 over TCP).

#### Example: gRPC

```json
{
  "timestamp_received": "2026-03-31T14:22:10.456Z",
  "client_ip": "10.0.1.60",
  "consumer_username": "grpc-client",
  "http_method": "POST",
  "request_path": "/myapp.UserService/GetUser",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440004",
  "matched_proxy_name": "grpc-users",
  "backend_target_url": "10.0.2.30:50051/myapp.UserService/GetUser",
  "backend_resolved_ip": "10.0.2.30",
  "response_status_code": 200,
  "latency_total_ms": 8.12,
  "latency_gateway_processing_ms": 1.50,
  "latency_backend_ttfb_ms": 6.20,
  "latency_backend_total_ms": 6.62,
  "latency_plugin_execution_ms": 0.80,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 0.70,
  "request_user_agent": "grpc-go/1.62.0",
  "metadata": {
    "x-correlation-id": "grpc-456",
    "grpc_service": "myapp.UserService",
    "grpc_method": "GetUser"
  }
}
```

gRPC errors return HTTP 200 with the error in `grpc-status`/`grpc-message` trailers. This includes gateway-generated plugin rejections, which are translated into trailers-only gRPC errors unless the plugin already returned explicit gRPC error metadata. The `response_status_code` in the log reflects the HTTP status (200), not the gRPC status code. When the gateway cannot reach the gRPC backend, `error_class` is populated while the downstream HTTP status remains 200.

#### Example: WebSocket (Upgrade Handshake)

```json
{
  "timestamp_received": "2026-03-31T14:22:15.100Z",
  "client_ip": "10.0.1.70",
  "consumer_username": "ws-user",
  "http_method": "GET",
  "request_path": "/ws/chat",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440005",
  "matched_proxy_name": "ws-chat",
  "backend_target_url": "10.0.2.40:8080/ws/chat",
  "backend_resolved_ip": "10.0.2.40",
  "response_status_code": 101,
  "latency_total_ms": 3.20,
  "latency_gateway_processing_ms": 1.00,
  "latency_backend_ttfb_ms": 0.0,
  "latency_backend_total_ms": 0.0,
  "latency_plugin_execution_ms": 0.60,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 0.40,
  "request_user_agent": "Mozilla/5.0",
  "metadata": {"x-correlation-id": "ws-101-abc"}
}
```

WebSocket transaction logging captures the HTTP upgrade handshake only. After the 101 response, the connection is upgraded and no further `TransactionSummary` is emitted. For frame-level observability, use the `ws_frame_logging` plugin.

#### Example: WebSocket (Upgrade Failed)

```json
{
  "timestamp_received": "2026-03-31T14:22:16.200Z",
  "client_ip": "10.0.1.71",
  "consumer_username": null,
  "http_method": "GET",
  "request_path": "/ws/chat",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440005",
  "matched_proxy_name": "ws-chat",
  "backend_target_url": "10.0.2.40:8080/ws/chat",
  "response_status_code": 502,
  "latency_total_ms": 5012.30,
  "latency_gateway_processing_ms": 5012.30,
  "latency_backend_ttfb_ms": -1.0,
  "latency_backend_total_ms": -1.0,
  "latency_plugin_execution_ms": 0.45,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 5011.85,
  "request_user_agent": "Mozilla/5.0",
  "error_class": "ConnectionFailed",
  "metadata": {"rejection_phase": "websocket_backend_error"}
}
```

#### Example: Rejected Request (Auth Failure)

```json
{
  "timestamp_received": "2026-03-31T14:22:20.000Z",
  "client_ip": "10.0.1.99",
  "consumer_username": null,
  "http_method": "GET",
  "request_path": "/api/v1/secrets",
  "matched_proxy_id": "550e8400-e29b-41d4-a716-446655440001",
  "matched_proxy_name": "users-api",
  "backend_target_url": null,
  "response_status_code": 401,
  "latency_total_ms": 0.15,
  "latency_gateway_processing_ms": 0.15,
  "latency_backend_ttfb_ms": -1.0,
  "latency_backend_total_ms": -1.0,
  "latency_plugin_execution_ms": 0.12,
  "latency_plugin_external_io_ms": 0.0,
  "latency_gateway_overhead_ms": 0.03,
  "request_user_agent": "curl/8.5.0",
  "metadata": {"rejection_phase": "authenticate"}
}
```

Rejected requests have `backend_target_url: null` (no backend was contacted), latency fields at -1.0, and `metadata.rejection_phase` indicating which plugin phase rejected the request. Possible `rejection_phase` values: `authenticate`, `authorize`, `before_proxy`, `grpc_backend_error`, `websocket_backend_error`. Gateway-generated gRPC errors also populate `metadata.grpc_status` and `metadata.grpc_message` so log sinks can distinguish gRPC failures even though the downstream HTTP status is `200`.

#### Example: TCP Stream

```json
{
  "proxy_id": "550e8400-e29b-41d4-a716-446655440006",
  "proxy_name": "tcp-database",
  "client_ip": "10.0.1.80",
  "backend_target": "db-primary.internal:5432",
  "backend_resolved_ip": "10.0.2.50",
  "protocol": "tcp",
  "listen_port": 5432,
  "duration_ms": 45230.5,
  "bytes_sent": 102400,
  "bytes_received": 2048576,
  "connection_error": null,
  "timestamp_connected": "2026-03-31T14:22:25.000+00:00",
  "timestamp_disconnected": "2026-03-31T14:23:10.230+00:00"
}
```

#### Example: TCP Stream (TLS, Connection Failed)

```json
{
  "proxy_id": "550e8400-e29b-41d4-a716-446655440006",
  "proxy_name": "tcp-database",
  "client_ip": "10.0.1.80",
  "backend_target": "db-primary.internal:5432",
  "protocol": "tcp_tls",
  "listen_port": 5432,
  "duration_ms": 5002.0,
  "bytes_sent": 0,
  "bytes_received": 0,
  "connection_error": "DNS resolution failed for db-primary.internal: NXDOMAIN",
  "error_class": "ConnectionTimeout",
  "timestamp_connected": "2026-03-31T14:24:00.000+00:00",
  "timestamp_disconnected": "2026-03-31T14:24:05.002+00:00"
}
```

On connection failure, `backend_target` still shows the attempted target. `backend_resolved_ip` is absent when DNS failed. The `connection_error` message describes the failure.

#### Example: UDP Session

```json
{
  "proxy_id": "550e8400-e29b-41d4-a716-446655440007",
  "proxy_name": "udp-dns",
  "client_ip": "10.0.1.90",
  "backend_target": "dns-backend.internal:5353",
  "backend_resolved_ip": "10.0.2.60",
  "protocol": "udp",
  "listen_port": 5353,
  "duration_ms": 30000.0,
  "bytes_sent": 512,
  "bytes_received": 4096,
  "connection_error": null,
  "timestamp_connected": "2026-03-31T14:22:30.000+00:00",
  "timestamp_disconnected": "2026-03-31T14:23:00.000+00:00"
}
```

UDP sessions are logged when the session is cleaned up after idle timeout.

#### Example: DTLS Session

```json
{
  "proxy_id": "550e8400-e29b-41d4-a716-446655440008",
  "proxy_name": "dtls-iot",
  "client_ip": "10.0.1.100",
  "backend_target": "iot-backend.internal:5684",
  "backend_resolved_ip": "10.0.2.70",
  "protocol": "dtls",
  "listen_port": 5684,
  "duration_ms": 120500.0,
  "bytes_sent": 8192,
  "bytes_received": 16384,
  "connection_error": null,
  "timestamp_connected": "2026-03-31T14:20:00.000+00:00",
  "timestamp_disconnected": "2026-03-31T14:22:00.500+00:00"
}
```

### `transaction_debugger`

Emits verbose request/response diagnostics via `tracing::debug!` on the `transaction_debug` target. All output flows through the non-blocking writer, avoiding synchronous stdout mutex contention. Sensitive headers are automatically redacted. Enable per-proxy only for debugging — not recommended for production due to information disclosure risk. Requires `FERRUM_LOG_LEVEL=debug` (or `RUST_LOG=transaction_debug=debug`) to see output.

**Priority:** 9200

| Parameter | Type | Default | Description |
|---|---|---|---|
| `log_request_body` | bool | `false` | Log incoming request body |
| `log_response_body` | bool | `false` | Log backend response body |
| `redacted_headers` | String[] | `[]` | Additional header names to redact beyond the built-in sensitive list |

**Built-in redacted headers**: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-xsrf-token`, `www-authenticate`, `x-forwarded-authorization`

### `correlation_id`

Generates and propagates correlation IDs for request tracing across services.

**Priority:** 50

| Parameter | Type | Default | Description |
|---|---|---|---|
| `header_name` | String | `x-request-id` | Header name used for inbound, outbound, and echoed IDs |
| `echo_downstream` | bool | `true` | Include correlation ID in response headers |

### `prometheus_metrics`

Records gateway metrics in Prometheus exposition format. The admin API serves
the `/metrics` endpoint; this plugin only records request and stream metrics.

**Priority:** 9300

This plugin has no plugin-specific configuration.

### `otel_tracing`

W3C Trace Context propagation and OTLP span export. Runs at priority 25 (earliest plugin) to capture accurate request timing.

**Priority:** 25

Supports two modes:
- **Propagation + Export** (default): Generates/propagates `traceparent`/`tracestate` headers and exports spans to an OTLP collector via HTTP/JSON.
- **Propagation-only**: When no `endpoint` is configured, generates/propagates trace context without exporting spans.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `endpoint` | String | _(none)_ | OTLP/HTTP collector endpoint (e.g. `http://collector:4318/v1/traces`). Omit for propagation-only mode |
| `service_name` | String | `ferrum-edge` | Service name in spans and resource attributes |
| `deployment_environment` | String | _(none)_ | `deployment.environment` resource attribute |
| `generate_trace_id` | Boolean | `true` | Generate trace IDs for requests without incoming `traceparent` |
| `headers` | Object | `{}` | Custom HTTP headers sent with OTLP exports |
| `authorization` | String | _(none)_ | Authorization header value for OTLP exports |
| `batch_size` | Integer | `50` | Spans per export batch |
| `flush_interval_ms` | Integer | `5000` | Max delay before flushing a partial batch |
| `buffer_capacity` | Integer | `10000` | Max pending spans; new spans are dropped when the buffer is full |
| `max_retries` | Integer | `2` | Retry attempts on export failure |
| `retry_delay_ms` | Integer | `1000` | Delay between retries |

Exported spans include OTel semantic convention attributes, gateway-specific attributes (`gateway.proxy.id`, `gateway.latency.*`), error classification events, and resource attributes.

---

## Authentication Plugins

### `mtls_auth`

Authenticates requests using the client's TLS/DTLS certificate, matching a configurable certificate field against consumer credentials. On TCP stream proxies, it runs in `on_stream_connect` after the frontend TLS handshake. On UDP stream proxies, it runs after the frontend DTLS handshake completes. In both cases, the client certificate is mapped to a Consumer before later stream plugins run.

**Priority:** 950

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cert_field` | String | `subject_cn` | Certificate field to use as identity |
| `allowed_issuers` | Object[] | *(none)* | Per-proxy issuer DN filters |
| `allowed_ca_fingerprints_sha256` | String[] | *(none)* | SHA-256 fingerprints of allowed CA/intermediate certs |

**Supported `cert_field` values:** `subject_cn`, `subject_ou`, `subject_o`, `san_dns`, `san_email`, `fingerprint_sha256`, `serial`

**Consumer credential** (`mtls_auth`):
```yaml
credentials:
  mtls_auth:
    identity: "client.example.com"
```

**Issuer Filtering:**
When `allowed_issuers` is configured, each filter object can specify `cn`, `o`, and/or `ou` fields. Within a single filter, all specified fields must match (AND logic). Across filter entries, any match is sufficient (OR logic).

```yaml
plugin_name: mtls_auth
config:
  cert_field: subject_cn
  allowed_issuers:
    - cn: "Internal Services CA"
    - cn: "Partner Portal CA"
      o: "Partner Corp"
```

**CA Fingerprint Filtering:**
When `allowed_ca_fingerprints_sha256` is configured, at least one certificate in the client's TLS chain must match a configured SHA-256 fingerprint. When both `allowed_issuers` and `allowed_ca_fingerprints_sha256` are configured, both constraints must pass (AND logic).

Issuer-constraint rejection bodies are always emitted as valid JSON even when certificate subject fields contain quotes, newlines, or other control characters.

Works with `auth_mode: multi` — if the mTLS check fails, the gateway continues to the next auth plugin.

### `jwks_auth`

Authenticates using Bearer JWTs validated against one or more Identity Provider JWKS endpoints. Supports multi-provider configurations with per-provider claim-based authorization.

**Priority:** 1000

| Parameter | Type | Description |
|---|---|---|
| `providers` | Array | Array of identity provider configurations (required) |
| `providers[].jwks_uri` | String | Direct URL to the IdP's JWKS endpoint |
| `providers[].discovery_url` | String | OIDC discovery URL (auto-discovers `jwks_uri`) |
| `providers[].issuer` | String (optional) | Expected JWT `iss` claim — routes tokens to this provider |
| `providers[].audience` | String (optional) | Expected JWT `aud` claim |
| `providers[].required_scopes` | String[] (optional) | Scopes that must all be present in the token |
| `providers[].required_roles` | String[] (optional) | Roles where any one must be present in the token |
| `providers[].scope_claim` | String (optional) | Per-provider override for scope claim path |
| `providers[].role_claim` | String (optional) | Per-provider override for role claim path |
| `scope_claim` | String | Global scope claim path (default: `"scope"`) |
| `role_claim` | String | Global role claim path (default: `"roles"`) |
| `consumer_identity_claim` | String | JWT claim for consumer lookup (default: `"sub"`) |
| `consumer_header_claim` | String | JWT claim for `X-Consumer-Username` header (default: same as `consumer_identity_claim`) |
| `jwks_refresh_interval_secs` | u64 | JWKS key refresh interval in seconds (default: `300`) |

Claim values are auto-detected as space-delimited strings (OAuth2 standard), JSON arrays, or nested objects via dot-notation paths.

### `jwt_auth`

Authenticates requests using HS256 JWT Bearer tokens matched against consumer credentials.

**Priority:** 1100

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token_lookup` | String | `header:Authorization` | Where to find the token (`header:<name>` or `query:<name>`) |
| `consumer_claim_field` | String | `sub` | JWT claim identifying the consumer |

**Consumer credential** (`jwt`):
```yaml
credentials:
  jwt:
    secret: "consumer-specific-hs256-secret"
```

### `key_auth`

Authenticates requests using an API key matched against consumer credentials.

**Priority:** 1200

| Parameter | Type | Default | Description |
|---|---|---|---|
| `key_location` | String | `header:X-API-Key` | Where to find the key (`header:<name>` or `query:<name>`) |

**Consumer credential** (`keyauth`):
```yaml
credentials:
  keyauth:
    key: "the-api-key-value"
```

### `basic_auth`

Authenticates using HTTP Basic credentials. Supports two hash formats:
- **HMAC-SHA256** (~1μs) — default when `FERRUM_BASIC_AUTH_HMAC_SECRET` is set (recommended). A default secret is provided but **must be changed in production**.
- **bcrypt** (~100ms) — backward-compatible fallback for `$2b$`/`$2a$` hashes.

**Priority:** 1300

**Config**: None required.

**Consumer credential** (`basicauth`):
```yaml
credentials:
  basicauth:
    password_hash: "hmac_sha256:ab3f..." # HMAC-SHA256 (preferred)
    # or: "$2b$12$..."                   # bcrypt (legacy)
```

### `hmac_auth`

Authenticates requests using HMAC signatures.

**Priority:** 1400

| Parameter | Type | Default | Description |
|---|---|---|---|
| `clock_skew_seconds` | u64 | `300` | Maximum allowed skew for the `Date` header replay window |

Expected `Authorization` header format:

```text
hmac username="<username>", algorithm="hmac-sha256", signature="<base64>"
```

- `algorithm` is optional and defaults to `hmac-sha256`
- Supported algorithms: `hmac-sha256`, `hmac-sha512`
- Unknown algorithms are rejected
- Requests must include a valid `Date` header (RFC 2822 or RFC 3339) within the configured skew window

**Consumer credential** (`hmac_auth`):
```yaml
credentials:
  hmac_auth:
    secret: "shared-secret"
```

---

## Authorization Plugins

### `access_control`

Authorizes requests based on the authenticated caller. By default it checks the
identified consumer's username. Optionally it can also allow externally
authenticated identities (for example `jwks_auth` users without a mapped
gateway Consumer). On TCP stream proxies, it uses the consumer already placed
in the stream context by an earlier auth plugin such as [`mtls_auth`](#mtls_auth).

**Priority:** 2000

| Parameter | Type | Description |
|---|---|---|
| `allowed_consumers` | String[] | Usernames allowed access (empty = allow all) |
| `disallowed_consumers` | String[] | Usernames explicitly denied |
| `allow_authenticated_identity` | bool | Allows requests with `ctx.authenticated_identity` set even when no Consumer was mapped |

Use [`ip_restriction`](#ip_restriction) for IP address or CIDR-based enforcement.

### `tcp_connection_throttle`

Limits concurrent TCP connections per observed client identity on a per-proxy basis.

**Priority:** 2050

| Parameter | Type | Description |
|---|---|---|
| `max_connections_per_key` | u64 | Maximum active TCP connections for one key |

**Key selection:**
- If a prior stream auth plugin identified a Consumer, the key is `consumer:<username>`
- Otherwise the key is `ip:<client_ip>`

This makes plaintext TCP listeners IP-scoped, while TCP+TLS and UDP+DTLS listeners can be scoped by the Consumer identified by [`mtls_auth`](#mtls_auth). Pair it with [`ip_restriction`](#ip_restriction) for IP authorization on plaintext TCP/UDP and [`access_control`](#access_control) for consumer allow/deny on TCP+TLS.

### `ip_restriction`

Restricts access based on client IP address or CIDR range.

**Priority:** 150

| Parameter | Type | Description |
|---|---|---|
| `allow` | String[] | Allowed IP addresses or CIDR ranges |
| `deny` | String[] | Denied IP addresses or CIDR ranges |
| `mode` | String | `allow_first` (default) or `deny_first` |

Rules are validated at config load time. Invalid IP/CIDR entries reject plugin creation instead of being silently ignored. When both `allow` and `deny` are configured, `deny` always overrides a matching `allow`; `mode` only controls which list is checked first for non-overlapping entries.

### `rate_limiting`

Enforces request rate limits per time window. Supports limiting by client IP or authenticated consumer identity.

**Priority:** 2900

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit_by` | String | `ip` | Rate limit key: `ip` or `consumer` |
| `expose_headers` | bool | `false` | Inject `x-ratelimit-*` headers |
| `requests_per_second` | u64 (optional) | — | Max requests per second |
| `requests_per_minute` | u64 (optional) | — | Max requests per minute |
| `requests_per_hour` | u64 (optional) | — | Max requests per hour |
| `sync_mode` | String | `local` | `local` (in-memory per instance) or `redis` (centralized) |
| `redis_url` | String (optional) | — | Redis connection URL (required when `sync_mode: "redis"`) |
| `redis_tls` | bool | `false` | Enable TLS for Redis connection |
| `redis_key_prefix` | String | `ferrum:rate_limiting` | Redis key namespace prefix |
| `redis_pool_size` | u64 | `4` | Number of multiplexed Redis connections |
| `redis_connect_timeout_seconds` | u64 | `5` | Redis connection timeout in seconds |
| `redis_health_check_interval_seconds` | u64 | `5` | Interval for background health check pings when Redis is unavailable |
| `redis_username` | String (optional) | — | Redis ACL username (Redis 6+) |
| `redis_password` | String (optional) | — | Redis password |

> **Note:** When `redis_tls` is enabled, CA certificate verification and skip-verify behavior are controlled by the gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` environment variables, not per-plugin settings.

**Behavior by mode:**
- `limit_by: "ip"` — Enforces in `on_request_received` phase (before auth), keyed by client IP.
- `limit_by: "consumer"` — Enforces in `authorize` phase (after auth), keyed by the authenticated identity: mapped consumer username when present, otherwise external `authenticated_identity`. Falls back to client IP if neither exists.
- Stream (`on_stream_connect`) — When `limit_by: "consumer"` and a stream auth plugin has already identified a Consumer, the stream rate-limit key is that consumer username; otherwise it falls back to client IP.

**Rate limit headers** (when `expose_headers: true`): `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-window`, `x-ratelimit-identity`

Returns HTTP `429 Too Many Requests` when exceeded.

**Centralized mode** (`sync_mode: "redis"`): Rate limit counters are stored in Redis so multiple gateway instances (e.g., multiple data planes) share a single global rate limit. Uses a two-window weighted approximation algorithm with native Redis commands (`INCR`, `GET`, `EXPIRE` pipelined) for smooth sliding window semantics. If Redis becomes unreachable, the plugin automatically falls back to local in-memory rate limiting and switches back when connectivity is restored. Compatible with any RESP-protocol server: Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

```yaml
plugin_name: rate_limiting
config:
  limit_by: consumer
  requests_per_minute: 100
  expose_headers: true
  sync_mode: redis
  redis_url: "redis://redis-host:6379/0"
  redis_tls: true
  redis_key_prefix: "myapp:rate_limiting"
```

---

## Traffic Control Plugins

### `cors`

Handles Cross-Origin Resource Sharing at the gateway level.

**Priority:** 100

| Parameter | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | String[] | `["*"]` | Permitted origins |
| `allowed_methods` | String[] | `["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]` | Allowed methods |
| `allowed_headers` | String[] | `["Accept","Authorization","Content-Type","Origin","X-Requested-With"]` | Allowed headers |
| `exposed_headers` | String[] | `[]` | Response headers exposed to browser JavaScript |
| `allow_credentials` | bool | `false` | Send `Access-Control-Allow-Credentials: true` |
| `max_age` | u64 | `86400` | Preflight cache duration in seconds |
| `preflight_continue` | bool | `false` | Pass preflight requests to backend |

See [cors_plugin.md](cors_plugin.md) for detailed configuration and troubleshooting.

### `bot_detection`

Detects and blocks bot traffic based on User-Agent patterns.

**Priority:** 200

| Parameter | Type | Default | Description |
|---|---|---|---|
| `blocked_patterns` | String[] | `["curl","wget","python-requests",...]` | User-Agent substrings to block |
| `allow_list` | String[] | `[]` | User-Agent substrings to always allow |
| `allow_missing_user_agent` | bool | `true` | Allow requests with no User-Agent header |
| `custom_response_code` | u16 | `403` | HTTP status code for blocked requests |

### `request_termination`

Returns a predefined response without proxying to the backend. Useful for maintenance mode, mocking, or header/path-based short-circuiting. It runs immediately after CORS so browser preflight requests still receive valid CORS responses, and opted-in header plugins such as CORS can still decorate the rejected response.

**Priority:** 125

| Parameter | Type | Default | Description |
|---|---|---|---|
| `status_code` | u16 | `503` | HTTP status code to return |
| `body` | String | `""` | Explicit response body. When set, `message` is ignored |
| `content_type` | String | `application/json` | Response `Content-Type` header |
| `message` | String | `"Service unavailable"` | Message used to build the default JSON/XML/plain-text body |
| `trigger.path_prefix` | String | _(none)_ | Only terminate when the request path starts with this prefix |
| `trigger.header` | String | _(none)_ | Only terminate when this request header is present |
| `trigger.header_value` | String | `""` | Optional exact value for `trigger.header`; empty means any value |

---

## Serverless Function Plugin

### `serverless_function`

Invokes AWS Lambda, Azure Functions, or Google Cloud Functions as middleware in the proxy pipeline. Two modes are supported:

- **`pre_proxy`** (default) — calls the function with request context, injects response headers/metadata into the proxied request, then continues to the backend.
- **`terminate`** — calls the function and returns its response directly to the client, bypassing backend proxying.

**Priority:** 3025
**Protocols:** HTTP, gRPC

#### Provider Configuration

**AWS Lambda** — uses the Lambda Invoke API with SigV4 request signing:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | (required) | `"aws_lambda"` |
| `aws_region` | String | — | AWS region. Falls back to `AWS_DEFAULT_REGION` / `AWS_REGION` env var |
| `aws_access_key_id` | String | — | IAM access key. Falls back to `AWS_ACCESS_KEY_ID` env var |
| `aws_secret_access_key` | String | — | IAM secret key. Falls back to `AWS_SECRET_ACCESS_KEY` env var |
| `aws_function_name` | String | — | Lambda function name or ARN. Falls back to `AWS_LAMBDA_FUNCTION_NAME` env var |
| `aws_session_token` | String | — | STS session token. Falls back to `AWS_SESSION_TOKEN` env var |
| `aws_qualifier` | String | — | Optional version/alias qualifier (e.g., `$LATEST`, `prod`) |

**Azure Functions** — calls the HTTP trigger URL:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | (required) | `"azure_functions"` |
| `function_url` | String | (required) | HTTPS trigger URL |
| `azure_function_key` | String | — | Function key for auth. Falls back to `AZURE_FUNCTIONS_KEY` env var |

**GCP Cloud Functions** — calls the HTTPS trigger URL:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | (required) | `"gcp_cloud_functions"` |
| `function_url` | String | (required) | HTTPS trigger URL |
| `gcp_bearer_token` | String | — | Bearer token for auth. Falls back to `GCP_CLOUD_FUNCTIONS_BEARER_TOKEN` env var |

#### Common Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `mode` | String | `"pre_proxy"` | `"pre_proxy"` or `"terminate"` |
| `forward_body` | bool | `false` | Include request body in function payload |
| `forward_headers` | String[] | `[]` | Header names to forward to the function |
| `forward_query_params` | bool | `false` | Include query parameters in function payload |
| `timeout_ms` | u64 | `5000` | Function invocation timeout in milliseconds |
| `max_response_body_bytes` | u64 | `10485760` | Max function response body size (10 MiB) |
| `on_error` | String | `"reject"` | `"reject"` returns error to client; `"continue"` skips and proxies normally |
| `error_status_code` | u16 | `502` | HTTP status when rejecting on error |

#### Function Request Payload

The plugin sends a JSON payload to the function:

```json
{
  "method": "POST",
  "path": "/api/v1/users",
  "client_ip": "10.0.0.1",
  "consumer_username": "alice",
  "authenticated_identity": "user@example.com",
  "headers": { "x-request-id": "abc-123" },
  "query_params": { "page": "1" },
  "body": { "name": "Alice" }
}
```

#### Function Response Format (pre_proxy mode)

The function should return JSON with optional `headers` and `metadata` fields:

```json
{
  "headers": {
    "x-custom-header": "computed-value",
    "x-user-tier": "premium"
  },
  "metadata": {
    "decision": "allowed",
    "reason": "user is premium"
  }
}
```

Headers are injected into the proxied request. Metadata is stored in `ctx.metadata` with a `serverless_` prefix and flows into transaction logs.

#### Environment Variable Fallback

Cloud credential fields fall back to well-known environment variables when not set in plugin config. Config values always take precedence. These env vars may themselves be resolved by the gateway's secret resolution system (Vault, AWS Secrets Manager, etc.).

#### Example: AWS Lambda pre-proxy enrichment

```yaml
plugin_name: serverless_function
config:
  provider: aws_lambda
  aws_region: us-east-1
  aws_function_name: enrich-request
  mode: pre_proxy
  forward_headers: ["authorization", "x-request-id"]
  forward_body: true
  timeout_ms: 3000
  on_error: continue
```

#### Example: Azure Functions terminate mode

```yaml
plugin_name: serverless_function
config:
  provider: azure_functions
  function_url: https://my-app.azurewebsites.net/api/compute
  mode: terminate
  forward_body: true
  timeout_ms: 10000
```

---

## Transform Plugins

### `request_transformer`

Modifies request headers, query parameters, and JSON body fields before proxying.

**Priority:** 3000

```yaml
config:
  rules:
    - operation: add       # add, remove, update, rename
      target: header       # header, query, body
      key: "X-Custom"
      value: "my-value"
    - operation: rename
      target: body
      key: "user.old_field"       # dot-notation for nested JSON
      new_key: "user.new_field"
    - operation: remove
      target: body
      key: "internal.debug_info"
```

Body rules use dot-notation paths for nested JSON. Values are auto-parsed as JSON when possible. Body transformation only applies to `application/json` content types.
When body rules modify the payload, the gateway recomputes the forwarded `Content-Length` automatically.
On HTTPS backends, body-transforming requests also bypass the direct backend H2 pool so the buffered plugin output is what reaches the upstream. HTTP/3 backends apply the same transformed buffered body before forwarding.

### `response_transformer`

Modifies response headers and JSON body fields before sending to the client. When body rules are configured, response body buffering is automatically enabled.

**Priority:** 4000

```yaml
config:
  rules:
    - operation: add
      key: "X-Powered-By"
      value: "Ferrum-Gateway"
    - operation: rename
      target: body
      key: "resp_data"
      new_key: "data"
```

Header rules default to `target: header` (no `target` field required). Body rules require explicit `target: body`.

---

## Validation Plugins

### `body_validator`

Validates JSON, XML, and gRPC protobuf request and response bodies against schemas. Supports comprehensive JSON Schema validation.

Request-side validation only buffers matching request bodies: methods that can carry a body and whose `content-type` matches `content_types`. Response-only configs do not force request buffering.

**Priority:** 2950

**Request validation:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `json_schema` | Object | — | JSON Schema for request body validation |
| `required_fields` | String[] | `[]` | Simple required field names |
| `validate_xml` | bool | `false` | Enable XML well-formedness validation |
| `required_xml_elements` | String[] | `[]` | Required XML element names |
| `content_types` | String[] | `["application/json","application/xml","text/xml"]` | MIME types to validate |

**Response validation:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `response_json_schema` | Object | — | JSON Schema for response body validation |
| `response_required_fields` | String[] | `[]` | Required field names in response |
| `response_validate_xml` | bool | `false` | XML validation for responses |
| `response_required_xml_elements` | String[] | `[]` | Required XML elements in responses |
| `response_content_types` | String[] | `["application/json","application/xml","text/xml"]` | Response MIME types to validate |

**Protobuf validation (gRPC):**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `protobuf_descriptor_path` | String | — | Path to compiled `FileDescriptorSet` binary (`protoc --descriptor_set_out --include_imports`) |
| `protobuf_request_type` | String | — | Default fully-qualified protobuf message type for request validation |
| `protobuf_response_type` | String | — | Default fully-qualified protobuf message type for response validation |
| `protobuf_method_messages` | Object | `{}` | Per-method message type overrides keyed by gRPC path (e.g., `/pkg.Svc/Method`). Each value has `request` and/or `response` string fields |
| `protobuf_reject_unknown_fields` | bool | `false` | Reject messages containing field numbers not in the descriptor |

**gRPC compression**: Compressed gRPC frames (compression flag = 1) are automatically decompressed using gzip before validation. Non-gzip compression algorithms will produce a validation error. Uncompressed frames are validated directly.

**Scope**: Protobuf validation supports unary RPCs only (single frame per message). Streaming RPCs with multiple concatenated frames are not validated — the length mismatch check will reject multi-frame bodies.

**Supported JSON Schema `format` values**: `email`, `ipv4`, `ipv6`, `uri`, `date-time`, `date`, `uuid`

### `request_size_limiting`

Enforces per-proxy request body size limits. Rejects with HTTP 413.

**Priority:** 2800

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_bytes` | u64 | `0` (disabled) | Maximum allowed request body size in bytes |

Enforcement happens in three places:
- `on_request_received` rejects oversized `Content-Length` headers without reading the body.
- `before_proxy` checks the buffered raw body when another plugin already needed early body access.
- `on_final_request_body` re-checks the final buffered body after request transforms, so body-rewriting plugins cannot expand the request past the configured limit before it reaches the backend.

### `response_size_limiting`

Enforces per-proxy response body size limits. Rejects with HTTP 502.

**Priority:** 3490

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_bytes` | u64 | `0` (disabled) | Maximum allowed response body size in bytes |
| `require_buffered_check` | bool | `false` | Force response body buffering to verify actual final size when `Content-Length` is absent |

### `response_caching`

Caches final client-visible HTTP responses in gateway memory. The cache key includes the matched proxy, request method, path, optional query string, optional authenticated identity, and any request headers selected by plugin config or backend `Vary`.

**Priority:** 3500
**Protocol:** HTTP only

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ttl_seconds` | u64 | `300` | Default TTL when the backend response does not provide cache freshness headers |
| `max_entries` | u64 | `10000` | Maximum number of in-memory cache entries before eviction |
| `max_entry_size_bytes` | u64 | `1048576` | Maximum size of a single cached response body |
| `max_total_size_bytes` | u64 | `104857600` | Maximum total in-memory cache size across all entries |
| `cacheable_methods` | String[] | `["GET","HEAD"]` | Methods eligible for caching |
| `cacheable_status_codes` | u16[] | `[200,301,404]` | Response status codes eligible for caching |
| `respect_cache_control` | bool | `true` | Honor backend `Cache-Control` directives such as `no-store`, `private`, `max-age`, and `s-maxage` |
| `respect_no_cache` | bool | `true` | Bypass cache lookup when the client sends `Cache-Control: no-cache` or `no-store` |
| `vary_by_headers` | String[] | `[]` | Additional request headers to include in the cache key even when the backend does not send `Vary` |
| `cache_key_include_query` | bool | `true` | Include query parameters in the cache key |
| `cache_key_include_consumer` | bool | `false` | Partition the cache by authenticated identity / consumer |
| `add_cache_status_header` | bool | `true` | Add `X-Cache-Status` (`MISS`, `HIT`, `BYPASS`, `REVALIDATED`) to downstream responses |
| `invalidate_on_unsafe_methods` | bool | `true` | Invalidate cached entries for the same path prefix on non-cacheable methods such as `POST`, `PUT`, `PATCH`, and `DELETE` |

Behavior:
- The plugin caches the final post-transform response body and headers, so cached hits include `response_transformer` output rather than the raw backend payload.
- Backend `Vary` is honored automatically. If the origin returns `Vary: Accept-Encoding`, compressed and uncompressed representations are cached separately.
- Conditional requests are served from cache. Matching `If-None-Match` or `If-Modified-Since` requests return `304 Not Modified` directly from the edge cache when a fresh cached validator exists.
- Responses with `Authorization` on the request are not shared-cached unless the backend explicitly allows it via `Cache-Control: public`, `must-revalidate`, or `s-maxage`, or you partition the key with `cache_key_include_consumer: true`.
- The plugin stores arbitrary response bytes, so binary responses and backend-compressed payloads can be cached safely.

Compression note:
- Ferrum does **not** generate gzip or brotli on its own — compression remains backend-driven pass-through.
- It forwards backend `Content-Encoding` as-is and caches compressed variants correctly when the origin sends the matching `Vary` header.
- The `body_validator` plugin decompresses gzip-compressed gRPC frames for protobuf validation, but this is internal to the validation path and does not affect the cached or forwarded body.

### `graphql`

GraphQL-aware proxying with query analysis, depth/complexity limiting, and per-operation rate limiting.

Request buffering is only enabled when at least one GraphQL policy is configured and the incoming request is a JSON `POST`.

**Priority:** 2850

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_depth` | u32 (optional) | — | Maximum allowed query nesting depth |
| `max_complexity` | u32 (optional) | — | Maximum allowed field count |
| `max_aliases` | u32 (optional) | — | Maximum allowed alias count |
| `introspection_allowed` | bool | `true` | Whether introspection queries are permitted |
| `limit_by` | String | `ip` | Rate limit key: `ip` or authenticated identity (`consumer`) |
| `type_rate_limits` | Object | `{}` | Rate limits by operation type (`query`, `mutation`, `subscription`) |
| `operation_rate_limits` | Object | `{}` | Rate limits by named operation |

Each rate limit entry: `{max_requests: u64, window_seconds: u64}`.

Populates `ctx.metadata` with `graphql_operation_type`, `graphql_operation_name`, `graphql_depth`, and `graphql_complexity`.

```yaml
plugin_name: graphql
config:
  max_depth: 10
  max_complexity: 100
  introspection_allowed: false
  type_rate_limits:
    mutation:
      max_requests: 20
      window_seconds: 60
```

---

## gRPC Plugins

### `grpc_method_router`

Parses the gRPC path (`/package.Service/Method`) and enables per-method access control and rate limiting. Populates `grpc_service`, `grpc_method`, and `grpc_full_method` metadata for downstream plugins.

**Priority:** 275
**Protocol:** gRPC only

| Parameter | Type | Default | Description |
|---|---|---|---|
| `allow_methods` | String[] | *(none)* | Only these gRPC methods are permitted (allowlist) |
| `deny_methods` | String[] | `[]` | These gRPC methods are explicitly blocked (checked before allow) |
| `method_rate_limits` | Object | `{}` | Per-method rate limits keyed by full method path |
| `limit_by` | String | `ip` | Rate limit key: `ip` or authenticated identity (`consumer`) |

Each rate limit entry: `{max_requests: u64, window_seconds: u64}`.

Deny takes precedence over allow. When `allow_methods` is set, only listed methods are permitted.

Populates `ctx.metadata` with `grpc_service`, `grpc_method`, and `grpc_full_method` in the `on_request_received` phase.

```yaml
plugin_name: grpc_method_router
config:
  deny_methods:
    - /admin.AdminService/DeleteAll
  method_rate_limits:
    /myapp.UserService/CreateUser:
      max_requests: 10
      window_seconds: 60
    /myapp.UserService/ListUsers:
      max_requests: 100
      window_seconds: 60
  limit_by: consumer
```

### `grpc_deadline`

Manages the `grpc-timeout` metadata header at the gateway. Can enforce maximum deadlines, inject defaults when clients omit `grpc-timeout`, and subtract gateway processing time before forwarding.

**Priority:** 3050
**Protocol:** gRPC only

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_deadline_ms` | u64 (optional) | *(none)* | Cap incoming deadlines to this value (milliseconds) |
| `default_deadline_ms` | u64 (optional) | *(none)* | Inject `grpc-timeout` when client omits it |
| `subtract_gateway_processing` | bool | `false` | Subtract elapsed gateway time before forwarding |
| `reject_no_deadline` | bool | `false` | Reject requests missing `grpc-timeout` (gRPC clients receive normalized `grpc-status`) |

Parses all gRPC timeout units: `H` (hours), `M` (minutes), `S` (seconds), `m` (milliseconds), `u` (microseconds), `n` (nanoseconds).

Forwarded deadlines are re-encoded to stay within the gRPC wire-format limit of 8 digits, preserving millisecond precision whenever it fits.

When `subtract_gateway_processing` is true and the remaining deadline is zero or negative, returns gRPC status `DEADLINE_EXCEEDED` (status code 4) using the trailers-only response pattern.

Populates `ctx.metadata` with `grpc_original_deadline_ms` and `grpc_adjusted_deadline_ms`.

```yaml
plugin_name: grpc_deadline
config:
  max_deadline_ms: 30000
  default_deadline_ms: 5000
  subtract_gateway_processing: true
```

---

## AI / LLM Plugins

Four plugins purpose-built for AI/LLM API gateway use cases. They auto-detect the LLM provider from the response JSON structure, supporting **OpenAI** (and compatible), **Anthropic**, **Google Gemini**, **Cohere**, **Mistral**, and **AWS Bedrock**.

### `ai_token_metrics`

Extracts token usage from LLM response bodies and writes it to request metadata for downstream logging and observability plugins.

**Priority:** 4100

| Parameter | Type | Default | Description |
|---|---|---|---|
| `provider` | String | `"auto"` | LLM provider format |
| `include_model` | Boolean | `true` | Extract model name into metadata |
| `include_token_details` | Boolean | `true` | Extract prompt/completion tokens separately |
| `metadata_prefix` | String | `"ai"` | Prefix for metadata keys |
| `cost_per_prompt_token` | Float | *(none)* | Calculate estimated cost per request |
| `cost_per_completion_token` | Float | *(none)* | Calculate estimated cost per request |

**Note**: Requires response body buffering. Set `response_body_mode: buffer` on the proxy.

`provider` is parsed case-insensitively and ignores surrounding whitespace.

```yaml
plugin_name: ai_token_metrics
config:
  provider: auto
  cost_per_prompt_token: 0.000003
  cost_per_completion_token: 0.000012
```

### `ai_request_guard`

Validates and constrains AI/LLM API requests before they reach the backend.

Request buffering is only enabled for matching JSON `POST` requests when at least one guard or transform rule is configured.

**Priority:** 2975

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_tokens_limit` | Integer | *(none)* | Maximum allowed `max_tokens` value |
| `enforce_max_tokens` | String | `"reject"` | `reject` (400 error) or `clamp` (silently cap) |
| `default_max_tokens` | Integer | *(none)* | Inject `max_tokens` if not present |
| `allowed_models` | String[] | `[]` | Whitelist of allowed model names (empty = allow all) |
| `blocked_models` | String[] | `[]` | Blacklist of model names (takes precedence) |
| `require_user_field` | Boolean | `false` | Require `user` field in request body |
| `max_messages` | Integer | *(none)* | Maximum messages in the messages array |
| `max_prompt_characters` | Integer | *(none)* | Maximum total characters across messages |
| `temperature_range` | Float[2] | *(none)* | Allowed [min, max] range for temperature |
| `block_system_prompts` | Boolean | `false` | Reject requests with `role: "system"` messages |
| `required_metadata_fields` | String[] | `[]` | Required fields in request body |

```yaml
plugin_name: ai_request_guard
config:
  allowed_models: [gpt-4o-mini, gpt-4o, claude-sonnet-4-20250514]
  blocked_models: [o3]
  max_tokens_limit: 4096
  enforce_max_tokens: clamp
  default_max_tokens: 1024
```

### `ai_rate_limiter`

Rate-limits consumers by LLM token consumption instead of request count.

**Priority:** 4200

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token_limit` | Integer | `100000` | Maximum tokens allowed per window |
| `window_seconds` | Integer | `60` | Sliding window duration in seconds |
| `count_mode` | String | `"total_tokens"` | What to count: `total_tokens`, `prompt_tokens`, or `completion_tokens` |
| `limit_by` | String | `"consumer"` | Rate limit key: authenticated identity (`consumer`) or `ip` |
| `expose_headers` | Boolean | `false` | Inject `x-ai-ratelimit-*` headers |
| `provider` | String | `"auto"` | LLM provider format for token extraction |
| `sync_mode` | String | `local` | `local` (in-memory per instance) or `redis` (centralized) |
| `redis_url` | String (optional) | — | Redis connection URL (required when `sync_mode: "redis"`) |
| `redis_tls` | bool | `false` | Enable TLS for Redis connection |
| `redis_key_prefix` | String | `ferrum:ai_rate_limiter` | Redis key namespace prefix |
| `redis_pool_size` | u64 | `4` | Number of multiplexed Redis connections |
| `redis_connect_timeout_seconds` | u64 | `5` | Redis connection timeout in seconds |
| `redis_health_check_interval_seconds` | u64 | `5` | Interval for background health check pings when Redis is unavailable |
| `redis_username` | String (optional) | — | Redis ACL username (Redis 6+) |
| `redis_password` | String (optional) | — | Redis password |

> **Note:** When `redis_tls` is enabled, CA certificate verification and skip-verify behavior are controlled by the gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` environment variables, not per-plugin settings.

`provider` is parsed case-insensitively and ignores surrounding whitespace.

**Centralized mode** (`sync_mode: "redis"`): Token budgets are shared across all gateway instances so consumers cannot exceed limits by spreading requests across data planes. Uses the same two-window weighted approximation and automatic fallback as `rate_limiting`. Compatible with any RESP-protocol server: Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

```yaml
plugin_name: ai_rate_limiter
config:
  token_limit: 500000
  window_seconds: 3600
  limit_by: consumer
  expose_headers: true
  sync_mode: redis
  redis_url: "redis://redis-host:6379/1"
```

### `ai_prompt_shield`

Scans AI/LLM request bodies for PII and either rejects, redacts, or warns.

Request buffering is only enabled for matching JSON `POST` requests when the plugin has at least one valid pattern to scan.

**Priority:** 2925

| Parameter | Type | Default | Description |
|---|---|---|---|
| `action` | String | `"reject"` | `reject`, `redact`, or `warn` |
| `patterns` | String[] | `["ssn", "credit_card", "api_key", "aws_key"]` | Built-in patterns to enable |
| `custom_patterns` | Object[] | `[]` | Custom `{name, regex}` patterns |
| `scan_fields` | String | `"content"` | `content` or `all` |
| `exclude_roles` | String[] | `[]` | Message roles to skip scanning |
| `redaction_placeholder` | String | `"[REDACTED:{type}]"` | Template for redacted text |
| `max_scan_bytes` | Integer | `1048576` | Skip scanning if body exceeds this size |

**Built-in patterns**: `ssn`, `credit_card`, `email`, `phone_us`, `api_key`, `aws_key`, `ip_address`, `iban`

```yaml
plugin_name: ai_prompt_shield
config:
  action: redact
  patterns: [ssn, credit_card, email, api_key, aws_key]
  custom_patterns:
    - name: internal_account
      regex: "ACCT-\\d{8}"
  exclude_roles: [system]
```

### AI Plugin Composition Example

A typical AI gateway proxy combining all four plugins:

```yaml
# Proxy config for OpenAI API
listen_path: /v1/chat/completions
backend_protocol: https
backend_host: api.openai.com
backend_port: 443
backend_path: /v1/chat/completions
response_body_mode: buffer

# Plugin configs (applied in priority order automatically)
plugins:
  - plugin_name: key_auth
    config: {}
  - plugin_name: ai_prompt_shield
    config:
      action: redact
      patterns: [ssn, credit_card, email, api_key]
  - plugin_name: ai_request_guard
    config:
      allowed_models: [gpt-4o-mini, gpt-4o]
      max_tokens_limit: 4096
      enforce_max_tokens: clamp
      default_max_tokens: 1024
  - plugin_name: ai_token_metrics
    config:
      cost_per_prompt_token: 0.00000015
      cost_per_completion_token: 0.0000006
  - plugin_name: ai_rate_limiter
    config:
      token_limit: 1000000
      window_seconds: 86400
      limit_by: consumer
      expose_headers: true
  - plugin_name: stdout_logging
    config: {}
```

---

## WebSocket Plugins

WebSocket plugins operate at the frame level via the `on_ws_frame` lifecycle hook. They fire on every WebSocket frame (both client-to-backend and backend-to-client directions) and can inspect, modify, or reject individual frames.

### `ws_message_size_limiting`

Enforces maximum frame size for WebSocket connections. Closes the connection with code 1009 (Message Too Big) when a Text, Binary, or Ping frame exceeds the configured limit. Operates in both directions (client-to-backend and backend-to-client).

**Priority:** 2810

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_frame_bytes` | u64 | `0` | Maximum allowed frame size in bytes (0 = no effect) |
| `close_reason` | String | `"Message too large"` | Close frame reason text |

`close_reason` is truncated to the WebSocket protocol limit for close-frame reason strings (123 UTF-8 bytes).

```yaml
plugin_name: ws_message_size_limiting
config:
  max_frame_bytes: 65536
```

### `ws_rate_limiting`

Rate limits WebSocket frames per-connection using a token bucket algorithm. Closes the connection with code 1008 (Policy Violation) when the configured frame rate is exceeded.

**Priority:** 2910

| Parameter | Type | Default | Description |
|---|---|---|---|
| `frames_per_second` | u64 | `100` | Maximum frames per second per connection |
| `burst_size` | u64 | (= `frames_per_second`) | Token bucket capacity (burst allowance) |
| `close_reason` | String | `"Frame rate exceeded"` | Close frame reason text |
| `sync_mode` | String | `local` | `local` (in-memory per instance) or `redis` (centralized) |
| `redis_url` | String (optional) | — | Redis connection URL (required when `sync_mode: "redis"`) |
| `redis_tls` | bool | `false` | Enable TLS for Redis connection |
| `redis_key_prefix` | String | `ferrum:ws_rate_limiting` | Redis key namespace prefix |
| `redis_pool_size` | u64 | `4` | Number of multiplexed Redis connections |
| `redis_connect_timeout_seconds` | u64 | `5` | Redis connection timeout in seconds |
| `redis_health_check_interval_seconds` | u64 | `5` | Interval for background health check pings when Redis is unavailable |
| `redis_username` | String (optional) | — | Redis ACL username (Redis 6+) |
| `redis_password` | String (optional) | — | Redis password |

> **Note:** When `redis_tls` is enabled, CA certificate verification and skip-verify behavior are controlled by the gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` environment variables, not per-plugin settings.

**Redis mode** (`sync_mode: "redis"`): Frame counters are stored in Redis instead of in-memory state. Because WebSocket `connection_id` values are process-local, Redis keys are namespaced per gateway instance to avoid cross-instance collisions; this mode externalizes the counter backend but does not make per-connection limits portable across reconnects to a different instance. Uses 1-second fixed windows with native Redis `INCR`/`EXPIRE` commands. If Redis becomes unreachable, falls back to local in-memory rate limiting automatically. Compatible with any RESP-protocol server: Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

```yaml
plugin_name: ws_rate_limiting
config:
  frames_per_second: 50
  burst_size: 75
  close_reason: "Rate limit exceeded"
  sync_mode: redis
  redis_url: "redis://redis-host:6379/2"
```

### `ws_frame_logging`

Logs metadata for every WebSocket frame passing through the proxy. Provides frame-level observability without requiring packet captures. This plugin never transforms or drops frames — it is purely observational.

**Priority:** 9050

| Parameter | Type | Default | Description |
|---|---|---|---|
| `log_level` | String | `"info"` | Log level for frame entries: `trace`, `debug`, or `info` |
| `include_payload_preview` | bool | `false` | Include a payload preview in log entries |
| `payload_preview_bytes` | u64 | `128` | Maximum payload bytes to preview (clamped to 64 KiB) |
| `log_ping_pong` | bool | `false` | Log Ping and Pong control frames |

```yaml
plugin_name: ws_frame_logging
config:
  log_level: debug
  include_payload_preview: true
  payload_preview_bytes: 256
  log_ping_pong: false
```

---

## Custom Plugins

Ferrum supports drop-in custom plugins. Create a `.rs` file in the `custom_plugins/` directory, export a `create_plugin()` factory function, and rebuild — the build script auto-discovers and registers it.

Optionally set `FERRUM_CUSTOM_PLUGINS=plugin_a,plugin_b` at **build time** to include only specific custom plugins.

See [CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md) for the full developer guide, trait reference, and working examples.
