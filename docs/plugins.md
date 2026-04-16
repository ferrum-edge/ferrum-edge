# Plugin Reference

Ferrum Edge includes 58 built-in plugins organized into lifecycle phases. Each plugin executes at a specific priority (lower number = runs first).

For execution order, protocol support matrix, and design rationale, see [plugin_execution_order.md](plugin_execution_order.md).

## Lifecycle Phases

1. **`on_request_received`** — Called immediately when a request arrives (CORS preflight, IP restriction, rate limiting)
2. **`authenticate`** — Identifies the consumer (mTLS, JWKS, JWT, API Key, LDAP, Basic Auth, HMAC)
3. **`authorize`** — Checks consumer permissions (Access Control, consumer-mode rate limiting)
4. **`before_proxy`** — Modifies the request before forwarding (Request Transformer)
5. **`after_proxy`** — Modifies response headers or can replace the backend response before downstream commit
6. **`on_response_body`** — Processes the raw buffered backend body before transforms (AI token metrics, AI rate limiter)
7. **`transform_response_body`** — Rewrites the buffered response body (Response Transformer body rules)
8. **`on_final_response_body`** — Validates or stores the final client-visible buffered body (Body Validator, Response Size Limiting, Response Caching)
9. **`log`** — Logs the transaction summary (Stdout/HTTP/Kafka Logging)
10. **`on_ws_frame`** — Per-frame WebSocket hooks (Size Limiting, Rate Limiting, Frame Logging)

## Custom Plugins

Custom plugins are auto-discovered from the `custom_plugins/` directory at build time. They can also declare database migrations via `plugin_migrations()` for creating private tables. See [CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md) for the full development guide and [migrations.md](migrations.md#custom-plugin-migrations) for migration details.

## Scope

- **Global** plugins (`scope: "global"`) apply to all proxies automatically. `proxy_id` must be null.
- **Proxy-scoped** plugins (`scope: "proxy"`) apply only to a specific proxy. `proxy_id` is required.
- **Proxy-group-scoped** plugins (`scope: "proxy_group"`) apply to a subset of proxies that reference the plugin in their `plugins` association list. `proxy_id` must be null. A **single shared plugin instance** is reused across all associated proxies, so stateful plugins (e.g., `rate_limiting`) share counters across the group. When a proxy is deleted, only the association is removed — the proxy-group plugin config survives.
- A proxy may have **multiple instances** of the same plugin type (e.g., two `http_logging` configs shipping to different destinations). Each instance has its own `id`, `config`, and optional `priority_override` to control execution order

**Example** (file mode YAML):

```yaml
plugin_configs:
  # Global — applies to ALL proxies automatically
  - id: global-logging
    plugin_name: stdout_logging
    scope: global
    config: {}

  # Proxy — applies to exactly ONE proxy
  - id: frontend-cors
    plugin_name: cors
    scope: proxy
    proxy_id: public-frontend
    config:
      origins: ["https://app.example.com"]

  # ProxyGroup — shared across a SUBSET of proxies
  # One instance, shared rate limit counters across the group
  - id: internal-rate-limit
    plugin_name: rate_limiting
    scope: proxy_group
    config:
      window_seconds: 60
      max_requests: 500
      limit_by: consumer

  - id: internal-key-auth
    plugin_name: key_auth
    scope: proxy_group
    config:
      key_names: ["x-api-key"]

proxies:
  # Both internal proxies share the same auth + rate limit group plugins
  - id: users-api
    listen_path: /api/users
    backend_protocol: http
    backend_host: users-svc
    backend_port: 3000
    plugins:
      - plugin_config_id: internal-key-auth
      - plugin_config_id: internal-rate-limit

  - id: orders-api
    listen_path: /api/orders
    backend_protocol: http
    backend_host: orders-svc
    backend_port: 3001
    plugins:
      - plugin_config_id: internal-key-auth
      - plugin_config_id: internal-rate-limit

  # Public proxy — no group plugins, has its own proxy-scoped CORS
  - id: public-frontend
    listen_path: /public
    backend_protocol: http
    backend_host: frontend-svc
    backend_port: 8080
    plugins:
      - plugin_config_id: frontend-cors
```

### Plugin Scope Merging

Each proxy's effective plugin list is built by merging global, proxy-scoped, and proxy-group-scoped plugins:

1. Start with all enabled **global** plugins
2. For each **proxy-scoped** or **proxy-group-scoped** plugin attached to the proxy, remove any global plugin with the same `plugin_name` (the scoped instance replaces it)
3. Multiple scoped instances of the same `plugin_name` all coexist — only the global is replaced
4. Sort by effective priority (built-in priority or `priority_override`)

**Examples:**

| Global plugins | Scoped plugins | Effective list for proxy |
|---|---|---|
| `http_logging` (g1) | *(none)* | g1 |
| `http_logging` (g1) | `http_logging` (ps1, proxy) | ps1 (replaces g1) |
| `http_logging` (g1) | `http_logging` (pg1, proxy_group) | pg1 (replaces g1, shared instance) |
| `http_logging` (g1) | `http_logging` (ps1), `http_logging` (ps2) | ps1, ps2 (g1 replaced, both scoped kept) |
| *(none)* | `http_logging` (ps1), `http_logging` (ps2) | ps1, ps2 |
| `http_logging` (g1), `cors` (g2) | `http_logging` (ps1) | ps1, g2 (only same-name global replaced) |

Use `priority_override` to control the relative execution order of instances that share the same built-in priority. Without it, instances at the same priority execute in a stable but implicit order based on config iteration

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
| `custom_headers` | Object | *(none)* | Key-value pairs of custom HTTP headers to include on every batch request |
| `batch_size` | Integer | `50` | Number of entries to buffer before sending a batch |
| `flush_interval_ms` | Integer | `1000` | Max milliseconds before flushing a partial batch (min: 100) |
| `max_retries` | Integer | `3` | Retry attempts on failed batch delivery |
| `retry_delay_ms` | Integer | `1000` | Delay in milliseconds between retry attempts |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full |

Batches are flushed when `batch_size` is reached **or** `flush_interval_ms` elapses, whichever comes first.

Retries fire on transport errors and 5xx responses. A **4xx response aborts the batch immediately** (retrying a malformed or unauthorized payload just delays the drop) — fix the endpoint URL, authorization header, or field schema rather than waiting through `max_retries × retry_delay_ms`.

`endpoint_url` must be a valid `http://` or `https://` URL with a hostname. Malformed or non-HTTP URLs reject plugin creation at config load time instead of failing later in the background flush task.

`custom_headers` accepts a JSON object of header name → value pairs. All headers are sent with every batch POST request. This supports services that require non-standard authentication headers (e.g., `DD-API-KEY` for Datadog, `Api-Key` for New Relic, `X-Sumo-Category` for Sumo Logic). Use `Authorization` as a key for services that authenticate via the standard Authorization header (e.g., Splunk HEC, Logtail).

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://logging-service.example.com/ingest"
  custom_headers:
    Authorization: "Bearer log-token-123"
  batch_size: 50
  flush_interval_ms: 1000
```

#### Service Integration Quick Reference

The table below summarizes how to configure `http_logging` for popular log ingestion services. All services receive the same JSON array of `TransactionSummary` / `StreamTransactionSummary` objects.

| Service | Endpoint URL | Required `custom_headers` | Auth Mechanism | Accepts JSON Arrays | Batch Limits | Notes |
|---------|-------------|--------------------------|----------------|--------------------|--------------|----|
| **Splunk HEC** | `https://<host>:8088/services/collector/raw` | `Authorization: "Splunk <token>"` | Token in Authorization header | Yes (raw endpoint) | 1MB default | Must use `/raw` endpoint, not `/event` |
| **Datadog** | `https://http-intake.logs.datadoghq.com/api/v2/logs` | `DD-API-KEY: "<key>"` | Dedicated API key header | Yes | 1000 entries / 5MB | Regional endpoints: `.datadoghq.eu` (EU), `.us3.datadoghq.com` (US3), `.us5.datadoghq.com` (US5), `.ap1.datadoghq.com` (AP1) |
| **New Relic** | `https://log-api.newrelic.com/log/v1` | `Api-Key: "<license-key>"` | Dedicated API key header | Yes | 1MB compressed | EU: `log-api.eu.newrelic.com` |
| **Sumo Logic** | `https://<endpoint>.sumologic.com/receiver/v1/http/<token>` | `X-Sumo-Category`, `X-Sumo-Name`, `X-Sumo-Host` (optional metadata) | Token embedded in URL | Yes | 1MB default | No auth header needed — token is in the URL path |
| **Elastic / OpenSearch** | `https://<host>:9200/<index>/_bulk` | `Authorization: "Basic <b64>"` or `Authorization: "Bearer <token>"` | Standard Authorization header | Yes (bulk API) | 100MB default | Consider using `_bulk` with NDJSON adapter or direct index API |
| **Azure Monitor** | `https://<dce>.ingest.monitor.azure.com/dataCollectionRules/<dcr-id>/streams/<stream>?api-version=2023-01-01` | `Authorization: "Bearer <aad-token>"` | Azure AD OAuth2 bearer token | Yes (custom tables) | 1MB per call | Requires Data Collection Endpoint + Rule; fields map to custom table columns |
| **AWS CloudWatch** | Requires intermediary (Fluent Bit/Firehose HTTP endpoint) | `Authorization: "Bearer <token>"` or custom | Varies by intermediary | **No** — needs `PutLogEvents` API format | N/A | Cannot POST directly; use a Firehose HTTP endpoint or Fluent Bit as intermediary |
| **Google Cloud Logging** | Requires intermediary (Fluent Bit/custom) | `Authorization: "Bearer <token>"` | OAuth2 bearer token | **No** — needs `entries.write` format | N/A | Cannot POST directly; use Fluent Bit or a custom HTTP bridge |
| **Logtail / Better Stack** | `https://in.logs.betterstack.com` | `Authorization: "Bearer <source-token>"` | Standard Authorization header | Yes | 10MB | Fields auto-parsed from JSON |
| **Axiom** | `https://api.axiom.co/v1/datasets/<dataset>/ingest` | `Authorization: "Bearer <api-token>"` | Standard Authorization header | Yes | 10MB | Fields auto-parsed; supports `Content-Type: application/json` |
| **Mezmo (LogDNA)** | `https://logs.mezmo.com/logs/ingest?hostname=<host>&apikey=<key>` | *(none — key in query string)* | API key in URL query parameter | Yes (lines API) | 10MB | Hostname is a required query parameter |

> **TLS verification:** If any service uses an internal CA, set `FERRUM_TLS_CA_BUNDLE_PATH` to your CA bundle so the plugin's HTTP client can verify the endpoint's certificate.

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

4. **Configure the plugin** — point `endpoint_url` at the raw HEC endpoint and set the Splunk auth token via `custom_headers`:

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://splunk.example.com:8088/services/collector/raw"
  custom_headers:
    Authorization: "Splunk cf2fa345-1b2c-3d4e-5f6a-7b8c9d0e1f2a"
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

#### Datadog Integration

[Datadog's HTTP log intake API](https://docs.datadoghq.com/api/latest/logs/) accepts JSON arrays directly. Authenticate with the `DD-API-KEY` header.

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://http-intake.logs.datadoghq.com/api/v2/logs"
  custom_headers:
    DD-API-KEY: "your-datadog-api-key"
  batch_size: 100
  flush_interval_ms: 2000
```

Datadog will ingest all `TransactionSummary` fields as log attributes. Set up a [log pipeline](https://docs.datadoghq.com/logs/log_configuration/pipelines/) to remap fields (e.g., `response_status_code` → `http.status_code`) for Datadog's standard attributes.

#### New Relic Integration

[New Relic's Log API](https://docs.newrelic.com/docs/logs/log-api/introduction-log-api/) accepts JSON arrays. Authenticate with the `Api-Key` header.

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://log-api.newrelic.com/log/v1"
  custom_headers:
    Api-Key: "your-new-relic-license-key"
  batch_size: 100
  flush_interval_ms: 2000
```

Use `log-api.eu.newrelic.com` for EU accounts. New Relic will parse the JSON fields automatically.

#### Sumo Logic Integration

[Sumo Logic's HTTP Source](https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/logs-metrics/) uses URL-based authentication (the collector URL contains the token). Use `custom_headers` for source metadata.

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://endpoint1.collection.us1.sumologic.com/receiver/v1/http/YOUR_TOKEN"
  custom_headers:
    X-Sumo-Category: "ferrum-edge/proxy"
    X-Sumo-Name: "ferrum-edge-gateway"
    X-Sumo-Host: "gateway-prod-01"
  batch_size: 100
  flush_interval_ms: 2000
```

#### Logtail / Better Stack Integration

[Logtail (Better Stack)](https://betterstack.com/docs/logs/logging-start/) accepts JSON arrays with Bearer token authentication.

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://in.logs.betterstack.com"
  custom_headers:
    Authorization: "Bearer your-source-token"
  batch_size: 100
  flush_interval_ms: 2000
```

#### Axiom Integration

[Axiom's ingest API](https://axiom.co/docs/send-data/ingest) accepts JSON arrays with Bearer token authentication.

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://api.axiom.co/v1/datasets/your-dataset/ingest"
  custom_headers:
    Authorization: "Bearer your-api-token"
  batch_size: 100
  flush_interval_ms: 2000
```

#### Elastic / OpenSearch Integration

For direct index ingestion, use the `_doc` endpoint with Basic or Bearer auth:

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://elasticsearch.example.com:9200/ferrum-logs/_doc"
  custom_headers:
    Authorization: "Basic dXNlcjpwYXNzd29yZA=="
  batch_size: 100
  flush_interval_ms: 2000
```

> **Note:** The `_doc` endpoint accepts single documents. For bulk ingestion, use a log shipper (Logstash, Fluent Bit) as an intermediary that transforms the JSON array into Elasticsearch's NDJSON bulk format.

#### Azure Monitor Integration

[Azure Monitor's log ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) accepts JSON arrays via a Data Collection Endpoint (DCE) and Data Collection Rule (DCR).

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://your-dce.eastus-1.ingest.monitor.azure.com/dataCollectionRules/dcr-abc123/streams/Custom-FerrumLogs_CL?api-version=2023-01-01"
  custom_headers:
    Authorization: "Bearer your-aad-oauth2-token"
  batch_size: 100
  flush_interval_ms: 2000
```

> **Note:** The Bearer token is a short-lived Azure AD OAuth2 token. For production use, consider placing an auth proxy (e.g., Azure API Management) in front that handles token refresh, or use Fluent Bit with the Azure Monitor output plugin.

#### AWS CloudWatch Logs Integration

CloudWatch Logs does not have an HTTP JSON intake API. Use [Fluent Bit](https://docs.fluentbit.io/manual/pipeline/outputs/cloudwatch) or an [Amazon Kinesis Data Firehose HTTP endpoint](https://docs.aws.amazon.com/firehose/latest/dev/create-destination.html#create-destination-http) as an intermediary:

```yaml
plugin_name: http_logging
config:
  endpoint_url: "http://fluent-bit.internal:8888/ferrum"
  batch_size: 100
  flush_interval_ms: 2000
```

#### Google Cloud Logging Integration

Cloud Logging does not have a direct HTTP JSON intake API. Use [Fluent Bit with the stackdriver output](https://docs.fluentbit.io/manual/pipeline/outputs/stackdriver) or a custom Cloud Function/Cloud Run bridge:

```yaml
plugin_name: http_logging
config:
  endpoint_url: "http://fluent-bit.internal:8888/ferrum"
  batch_size: 100
  flush_interval_ms: 2000
```

### `statsd_logging`

Sends transaction metrics to a StatsD-compatible server (StatsD, Datadog DogStatsD, Telegraf, etc.) over UDP. Extracts counters, timers, and gauges from each transaction summary and ships them in batched, newline-delimited StatsD line protocol.

**Priority:** 9075

| Parameter | Type | Default | Description |
|---|---|---|---|
| `host` | String | *(required)* | StatsD server hostname or IP address |
| `port` | Integer | `8125` | StatsD server UDP port (1–65535) |
| `prefix` | String | `FERRUM_NAMESPACE` | Metric name prefix (e.g., `ferrum.request.count`). Defaults to the gateway's `FERRUM_NAMESPACE` value (default: `"ferrum"`) |
| `global_tags` | Object | *(none)* | Key-value pairs appended as DogStatsD tags to every metric |
| `flush_interval_ms` | Integer | `500` | Max milliseconds before flushing buffered metrics (min: 50) |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full |
| `max_batch_lines` | Integer | `50` | Max metric entries to batch before flushing |

Metrics are flushed when `max_batch_lines` is reached **or** `flush_interval_ms` elapses, whichever comes first. Large payloads are automatically split across multiple UDP packets at 1472-byte MTU boundaries.

**DNS handling.** The StatsD endpoint is resolved through the gateway's shared `DnsCache` at startup (pre-warmed via `warmup_hostnames()`) and re-resolved every 60 seconds by the background flush task. If the resolved address changes (DNS flip, service discovery update), the UDP socket is rebound to the new address without a gateway restart.

**Tag sanitization.** Operator-controlled tag values (proxy name/id, HTTP method, protocol) are sanitized before being written to the line protocol: `,` `|` `#` `:` and whitespace are replaced with `_`. Empty values become the literal `none`. This keeps a proxy name containing delimiters from corrupting downstream parsing in StatsD / DogStatsD / Telegraf.

**Metrics emitted per HTTP/gRPC/WebSocket request:**

| Metric | Type | Description |
|--------|------|-------------|
| `{prefix}.request.count` | Counter | Request count |
| `{prefix}.request.latency_total_ms` | Timer | Total request latency |
| `{prefix}.request.latency_backend_ttfb_ms` | Timer | Backend time-to-first-byte |
| `{prefix}.request.latency_gateway_overhead_ms` | Timer | Pure gateway overhead |
| `{prefix}.request.latency_plugin_execution_ms` | Timer | Plugin execution time |
| `{prefix}.request.status.{N}xx` | Counter | Status code bucket (2xx, 4xx, 5xx, etc.) |

Tags: `method`, `status`, `status_class`, `proxy` (plus any `global_tags`). When `FERRUM_NAMESPACE` is non-default, a `namespace` tag is automatically injected into all metrics.

**Metrics emitted per stream (TCP/UDP) disconnect:**

| Metric | Type | Description |
|--------|------|-------------|
| `{prefix}.stream.count` | Counter | Stream connection count |
| `{prefix}.stream.duration_ms` | Timer | Connection duration |
| `{prefix}.stream.bytes_sent` | Gauge | Bytes sent to client |
| `{prefix}.stream.bytes_received` | Gauge | Bytes received from client |

Tags: `protocol`, `proxy`, `error` (plus any `global_tags`).

```yaml
plugin_name: statsd_logging
config:
  host: "statsd.internal.example.com"
  port: 8125
  prefix: "ferrum"
  global_tags:
    env: "production"
    region: "us-east-1"
  flush_interval_ms: 500
  max_batch_lines: 50
```

#### DogStatsD / Datadog Integration

The `global_tags` config maps directly to DogStatsD tag format (`|#key:value,key:value`). Per-request tags (method, status, proxy) are always included. To route metrics to Datadog:

1. Point `host` at your Datadog Agent or DogStatsD server
2. Set `global_tags` with environment and service metadata
3. Metrics appear in Datadog with full tag filtering

### `ws_logging`

Sends transaction summaries as JSON to an external WebSocket endpoint. Like `http_logging`, entries are buffered and sent in batches (as a JSON array text messages) to reduce per-message overhead. The WebSocket connection is maintained persistently with automatic reconnection on failure.

**Priority:** 9175

| Parameter | Type | Default | Description |
|---|---|---|---|
| `endpoint_url` | String | `""` | WebSocket URL to send transaction logs to |
| `batch_size` | Integer | `50` | Number of entries to buffer before sending a batch |
| `flush_interval_ms` | Integer | `1000` | Max milliseconds before flushing a partial batch (min: 100) |
| `max_retries` | Integer | `3` | Retry attempts on failed batch delivery |
| `retry_delay_ms` | Integer | `1000` | Delay in milliseconds between retry attempts |
| `reconnect_delay_ms` | Integer | `5000` | Delay in milliseconds before reconnecting after connection failure |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full |

Batches are flushed when `batch_size` is reached **or** `flush_interval_ms` elapses, whichever comes first. Each batch is sent as a single JSON array text message over the WebSocket connection.

`endpoint_url` must be a valid `ws://` or `wss://` URL with a hostname. Malformed or non-WebSocket URLs reject plugin creation at config load time.

```yaml
plugin_name: ws_logging
config:
  endpoint_url: "wss://logging-service.example.com/ws/ingest"
  batch_size: 50
  flush_interval_ms: 1000
```

**Connection lifecycle:** The plugin establishes a persistent WebSocket connection on the first batch flush. If the connection drops, the plugin automatically reconnects on the next send attempt. Failed batches are retried up to `max_retries` times with `retry_delay_ms` between attempts. After exhausting retries, the batch is discarded and a warning is logged.

### `tcp_logging`

Sends transaction summaries as newline-delimited JSON (NDJSON) over a persistent TCP or TCP+TLS connection. Entries are buffered and flushed in batches, with automatic reconnection on failure. Ideal for shipping logs to Logstash, Fluentd, Vector, rsyslog, or any TCP-based log collector.

**Priority:** 9125

| Parameter | Type | Default | Description |
|---|---|---|---|
| `host` | String | *(required)* | Hostname or IP of the TCP log receiver |
| `port` | Integer | *(required)* | Port of the TCP log receiver (1–65535) |
| `tls` | Boolean | `false` | Enable TLS encryption for the connection |
| `tls_server_name` | String | *(none)* | SNI server name override for TLS (defaults to `host`) |
| `batch_size` | Integer | `50` | Number of entries to buffer before sending a batch |
| `flush_interval_ms` | Integer | `1000` | Max milliseconds before flushing a partial batch (min: 100) |
| `max_retries` | Integer | `3` | Retry attempts on failed batch delivery |
| `retry_delay_ms` | Integer | `1000` | Delay in milliseconds between retry attempts |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full |
| `connect_timeout_ms` | Integer | `5000` | TCP connection timeout in milliseconds (min: 100) |

Batches are flushed when `batch_size` is reached **or** `flush_interval_ms` elapses, whichever comes first. Each entry is serialized as a single JSON line followed by a newline (`\n`), making the output compatible with NDJSON/JSON Lines consumers.

The TCP connection is persistent — it is reused across batches and automatically re-established on write failure or disconnect. TLS uses the gateway's global CA bundle (`FERRUM_TLS_CA_BUNDLE_PATH`) and skip-verify setting (`FERRUM_TLS_NO_VERIFY`).

```yaml
plugin_name: tcp_logging
config:
  host: "logstash.example.com"
  port: 5140
  tls: true
  tls_server_name: "logstash.internal"
  batch_size: 100
  flush_interval_ms: 2000
```

#### Logstash Integration

Configure a Logstash TCP input with JSON codec:

```
input {
  tcp {
    port => 5140
    codec => json_lines
  }
}
```

For TLS, add `ssl_enable => true` with your certificate configuration to the Logstash TCP input.

### `udp_logging`

Sends transaction summaries as JSON to an external UDP endpoint. Entries are buffered and sent in batches (as a JSON array) in a single UDP datagram. Supports both plain UDP and DTLS-encrypted transport.

**Priority:** 9160

| Parameter | Type | Default | Description |
|---|---|---|---|
| `host` | String | *(required)* | UDP endpoint hostname or IP address |
| `port` | Integer | *(required)* | UDP endpoint port (1–65535) |
| `dtls` | Boolean | `false` | Enable DTLS encryption for log datagrams |
| `dtls_cert_path` | String | *(none)* | PEM client certificate for DTLS mutual TLS |
| `dtls_key_path` | String | *(none)* | PEM private key for DTLS mutual TLS (must be paired with `dtls_cert_path`) |
| `dtls_ca_cert_path` | String | *(none)* | PEM CA certificate for verifying the DTLS server |
| `dtls_no_verify` | Boolean | `false` | Skip DTLS server certificate verification (testing only) |
| `batch_size` | Integer | `10` | Number of entries to buffer before sending a batch |
| `flush_interval_ms` | Integer | `1000` | Max milliseconds before flushing a partial batch (min: 100) |
| `max_retries` | Integer | `1` | Retry attempts on failed batch delivery |
| `retry_delay_ms` | Integer | `500` | Delay in milliseconds between retry attempts |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full |

Batches are flushed when `batch_size` is reached **or** `flush_interval_ms` elapses, whichever comes first. Each batch is serialized as a JSON array and sent as a single UDP datagram.

**Datagram size:** Operators should size `batch_size` to keep serialized payloads under the network MTU (typically ~1400 bytes for DTLS, ~1472 bytes for plain UDP over Ethernet). Oversized datagrams may be fragmented or dropped by the network.

**DNS handling:** The UDP endpoint is resolved through the gateway's shared `DnsCache` (TTL-aware, stale-while-revalidate, background refresh). For plain UDP, the background flush task re-resolves every 60 seconds and rebinds the socket if the address changes — DNS flips propagate without a restart. DTLS sessions are not re-handshaken mid-session.

```yaml
plugin_name: udp_logging
config:
  host: "syslog.example.com"
  port: 9514
  batch_size: 5
  flush_interval_ms: 1000
```

#### DTLS Configuration

For encrypted log shipping, enable DTLS. An ephemeral self-signed certificate is used by default when no client certificate is provided:

```yaml
plugin_name: udp_logging
config:
  host: "secure-log-collector.example.com"
  port: 9515
  dtls: true
  dtls_cert_path: "/etc/ferrum/certs/log-client.pem"
  dtls_key_path: "/etc/ferrum/certs/log-client-key.pem"
  dtls_ca_cert_path: "/etc/ferrum/certs/log-server-ca.pem"
```

### `kafka_logging`

Produces transaction summaries as JSON messages to an Apache Kafka topic. Uses an async mpsc channel to decouple the proxy hot path from Kafka I/O, with librdkafka's `ThreadedProducer` handling batching, compression, delivery retries, and partition assignment.

**Priority:** 9150

**Requires:** The `kafka` cargo feature (`--features kafka` or `--all-features`). Without it, plugin creation returns an error at runtime.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `broker_list` | String | *(required)* | Comma-separated Kafka broker addresses (e.g., `broker1:9092,broker2:9092`) |
| `topic` | String | *(required)* | Kafka topic to produce messages to |
| `key_field` | String | `"client_ip"` | Partition key field: `client_ip`, `proxy_id`, or `none` (round-robin). Any other value is rejected at plugin construction time so operator typos surface immediately instead of silently falling back to `client_ip` |
| `buffer_capacity` | Integer | `10000` | Channel capacity — new entries are dropped when full. Each entry is a serialized JSON `TransactionSummary` (~1-2 KB), so the default 10,000 entries may use ~10-20 MB of memory |
| `compression` | String | `"lz4"` | Compression: `none`, `gzip`, `snappy`, `lz4`, `zstd` |
| `flush_timeout_seconds` | Integer | `5` | Seconds to wait for librdkafka to flush pending messages during graceful shutdown |
| `acks` | String | *(librdkafka default)* | Delivery acknowledgment: `0`, `1`, `all` (or `-1`) |
| `message_timeout_ms` | Integer | *(librdkafka default)* | Timeout for message delivery in milliseconds |
| `security_protocol` | String | *(none)* | Protocol: `plaintext`, `ssl`, `sasl_plaintext`, `sasl_ssl` |
| `sasl_mechanism` | String | *(none)* | SASL mechanism (e.g., `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`) |
| `sasl_username` | String | *(none)* | SASL username |
| `sasl_password` | String | *(none)* | SASL password |
| `ssl_ca_location` | String | *(gateway default)* | Path to CA certificate for broker TLS verification. Falls back to `FERRUM_TLS_CA_BUNDLE_PATH` |
| `ssl_no_verify` | Boolean | *(gateway default)* | Skip broker TLS certificate verification. Falls back to `FERRUM_TLS_NO_VERIFY` |
| `ssl_certificate_location` | String | *(none)* | Path to client certificate for mTLS |
| `ssl_key_location` | String | *(none)* | Path to client private key for mTLS |
| `producer_config` | Object | *(none)* | Escape hatch: arbitrary librdkafka producer properties as key-value pairs |

#### Gateway TLS Integration

Kafka uses its own binary protocol over TCP/TLS (not HTTP), so TLS is handled by librdkafka (OpenSSL) rather than the gateway's rustls stack. However, the plugin integrates with the gateway's TLS settings as defaults:

- **`FERRUM_TLS_CA_BUNDLE_PATH`** is applied as `ssl.ca.location` when `ssl_ca_location` is not set in the plugin config
- **`FERRUM_TLS_NO_VERIFY`** is applied as `enable.ssl.certificate.verification=false` when `ssl_no_verify` is not set in the plugin config
- Plugin-level fields always override the gateway defaults

This means operators who have already configured `FERRUM_TLS_CA_BUNDLE_PATH` for internal CAs do not need to duplicate the CA path in the kafka_logging plugin config.

**Note:** `FERRUM_TLS_CRL_FILE_PATH` is **not** applied to Kafka connections — librdkafka manages CRL checking independently via its own `ssl.crl.location` property (configurable via `producer_config`).

```yaml
plugin_name: kafka_logging
config:
  broker_list: "broker1:9092,broker2:9092,broker3:9092"
  topic: "access-logs"
  compression: "lz4"
  acks: "1"
  key_field: "client_ip"
```

#### Kafka with SASL/SSL Authentication

```yaml
plugin_name: kafka_logging
config:
  broker_list: "kafka.example.com:9093"
  topic: "access-logs"
  security_protocol: "sasl_ssl"
  sasl_mechanism: "SCRAM-SHA-256"
  sasl_username: "ferrum-edge"
  sasl_password: "secret"
  ssl_ca_location: "/etc/ferrum/certs/kafka-ca.pem"
```

#### Advanced librdkafka Tuning

```yaml
plugin_name: kafka_logging
config:
  broker_list: "broker1:9092"
  topic: "access-logs"
  producer_config:
    linger.ms: "50"
    batch.num.messages: "1000"
    queue.buffering.max.kbytes: "1048576"
```

### Transaction Summary Reference

All logging plugins (`stdout_logging`, `http_logging`, `tcp_logging`, `udp_logging`, `kafka_logging`, `statsd_logging`, `loki_logging`) emit metrics from the same transaction structures. HTTP-family protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket) use `TransactionSummary`. Stream protocols (TCP, UDP, DTLS) use `StreamTransactionSummary`.

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
| `consumer_username` | String or null | Identified consumer username (gateway Consumer) or external authenticated identity resolved during `on_stream_connect`. Omitted from JSON when null |
| `backend_target` | String | Backend target (`host:port`); empty if target resolution failed before LB/config lookup |
| `backend_resolved_ip` | String or null | DNS-resolved backend IP; omitted from JSON when null |
| `protocol` | String | Protocol string: `tcp`, `tcp_tls`, `udp`, or `dtls` |
| `listen_port` | u16 | Proxy listen port |
| `duration_ms` | f64 | Connection/session lifetime in milliseconds |
| `bytes_sent` | u64 | Bytes the gateway **relayed from the client to the backend** (client→backend direction) |
| `bytes_received` | u64 | Bytes the gateway **relayed from the backend to the client** (backend→client direction) |
| `connection_error` | String or null | Error message if the connection failed |
| `error_class` | String or null | Error classification; omitted from JSON when null |
| `timestamp_connected` | String (RFC 3339) | Connection start time |
| `timestamp_disconnected` | String (RFC 3339) | Connection end time |
| `sni_hostname` | String or null | SNI from TLS/DTLS ClientHello when passthrough mode is enabled; omitted from JSON when null |
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

WebSocket transaction logging captures the HTTP upgrade handshake only. After the upgrade response (101 Switching Protocols for HTTP/1.1, or 200 OK for HTTP/2 Extended CONNECT per RFC 8441), the connection is upgraded and no further `TransactionSummary` is emitted. For HTTP/2 WebSocket, `http_method` is `"CONNECT"` and `response_status_code` is `200`. For frame-level observability, use the `ws_frame_logging` plugin.

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

### `loki_logging`

**Priority**: 9155
**Phases**: `log`, `on_stream_disconnect`
**Protocols**: All (HTTP, gRPC, WebSocket, TCP, UDP)

Ships transaction logs to Grafana Loki via the push API (`POST /loki/api/v1/push`). Entries are batched asynchronously and grouped by label set for efficient ingestion. Supports gzip compression (enabled by default), static and dynamic labels, custom headers for multi-tenant Loki (`X-Scope-OrgID`), and authentication via `Authorization` header.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint_url` | string | (required) | Loki push API URL |
| `authorization_header` | string | (none) | `Authorization` header value (Bearer/Basic) |
| `custom_headers` | object | `{}` | Extra HTTP headers (e.g., `X-Scope-OrgID`) |
| `labels` | object | `{"service":"ferrum-edge"}` | Static labels applied to every log stream |
| `include_proxy_id_label` | bool | `true` | Add `proxy_id` as a label. The legacy key `include_listen_path_label` is still accepted for backward compatibility (the label name has always been `proxy_id`); if both are set, `include_proxy_id_label` wins |
| `include_status_class_label` | bool | `true` | Add `status_class` (2xx/3xx/4xx/5xx) as a label |
| `gzip` | bool | `true` | Gzip-compress request bodies |
| `batch_size` | integer | `100` | Max entries per batch |
| `flush_interval_ms` | integer | `1000` | Flush timer interval (minimum 100) |
| `buffer_capacity` | integer | `10000` | Channel buffer capacity |
| `max_retries` | integer | `3` | Retry attempts on failure |
| `retry_delay_ms` | integer | `1000` | Delay between retries |

Retries fire on transport errors and 5xx responses. A **4xx response aborts the batch immediately** (retrying a malformed or unauthorized payload just delays the drop) — fix the endpoint URL, `authorization_header`, or tenant header rather than waiting through `max_retries × retry_delay_ms`.

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

| Parameter | Type | Default | Description |
|---|---|---|---|
| `render_cache_ttl_seconds` | Integer | `5` | How long the cached `/metrics` response is served before rebuilding |
| `stale_entry_ttl_seconds` | Integer | `3600` | How long idle metric entries live before eviction (prevents unbounded memory growth from deleted/recreated proxies) |
| `cache_invalidation_min_age_ms` | Integer | `500` | Minimum age (ms) of the render cache before `record()` will invalidate it. Under extreme load this prevents an allocation per request — the render TTL is the real freshness guarantee |

> **Namespace isolation:** When `FERRUM_NAMESPACE` is set to a non-default value (anything other than `"ferrum"`), all Prometheus metrics include an additional `namespace` label (e.g., `namespace="staging"`). This prevents metric collisions when multiple gateway instances with different namespaces are scraped by the same Prometheus server. When namespace is the default, no label is added and output is identical to pre-namespace behavior.

### `api_chargeback`

Tracks per-consumer API usage charges based on configurable pricing tiers keyed
by HTTP status code. Charges accumulate in-memory and are exposed via the admin
`/charges` endpoint in both Prometheus text and JSON formats for external billing
system integration.

Only requests with an identified consumer (gateway Consumer or external
authenticated identity) are charged — anonymous traffic is not tracked. Status
codes not listed in any pricing tier are free (not tracked).

**Priority:** 9350

| Parameter | Type | Default | Description |
|---|---|---|---|
| `currency` | String | `"USD"` | Currency label included in Prometheus metrics and JSON output. Informational only — the plugin does not perform currency conversion |
| `pricing_tiers` | Array | _(required)_ | One or more pricing tiers. Each tier maps a set of status codes to a per-call price |
| `pricing_tiers[].status_codes` | Array\<Integer\> | _(required)_ | HTTP status codes that trigger this tier's charge. A status code must appear in exactly one tier |
| `pricing_tiers[].price_per_call` | Number | _(required)_ | Charge per API call (e.g. `0.00001`). Must be non-negative |
| `render_cache_ttl_seconds` | Integer | `5` | How long the cached `/charges` response is served before rebuilding |
| `stale_entry_ttl_seconds` | Integer | `3600` | How long idle chargeback entries live before eviction |
| `cache_invalidation_min_age_ms` | Integer | `500` | Minimum age (ms) of the render cache before `record()` will invalidate it |

**Admin endpoint:** `GET /charges` (unauthenticated, like `/metrics`).

| Query Parameter | Description |
|---|---|
| _(none)_ | Prometheus text exposition format — two counter families: `ferrum_api_chargeable_calls_total` (call counts) and `ferrum_api_charges_total` (monetary charges) with labels `consumer`, `proxy_id`, `proxy_name`, `status_code`, and `currency`. When `FERRUM_NAMESPACE` is non-default, all metrics include an additional `namespace` label |
| `?format=json` | JSON format with nested consumer → proxy → status breakdowns and pre-computed totals |

**Multi-node deployments (CP/DP):** Each gateway node (DP) accumulates charges
independently in memory. In CP/DP topologies, the CP does not proxy traffic and
therefore has no chargeback data. You must scrape `/charges` from **every DP
node** and aggregate externally (e.g., via Prometheus federation, Thanos, or a
custom collector that sums counters across instances). The same applies to
multi-instance database or file mode deployments behind a load balancer. Charges
are monotonically increasing counters, so Prometheus `increase()` or `rate()`
functions work correctly across scrapes. Counters reset to zero on gateway
restart — Prometheus handles resets natively via `increase()`.

**Example configuration:**

```yaml
plugins:
  - name: api_chargeback
    config:
      currency: "USD"
      pricing_tiers:
        - status_codes: [200, 201, 202, 204]
          price_per_call: 0.00001
        - status_codes: [301, 302]
          price_per_call: 0.000005
```

**Example Prometheus scrape config** (multi-DP):

```yaml
scrape_configs:
  - job_name: ferrum-chargeback
    static_configs:
      - targets:
          - dp-1:9000
          - dp-2:9000
          - dp-3:9000
    metrics_path: /charges
```

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

**Consumer credential** (`mtls_auth`) — single or array for rotation:
```yaml
credentials:
  mtls_auth:
    identity: "client.example.com"
  # Array format for zero-downtime rotation:
  # mtls_auth:
  #   - identity: "old-cert-cn.example.com"
  #   - identity: "new-cert-cn.example.com"
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
| `providers[].consumer_identity_claim` | String (optional) | Per-provider override for consumer identity claim |
| `providers[].consumer_header_claim` | String (optional) | Per-provider override for consumer header claim |
| `scope_claim` | String | Global scope claim path (default: `"scope"`) |
| `role_claim` | String | Global role claim path (default: `"roles"`) |
| `consumer_identity_claim` | String | Global JWT claim for consumer lookup (default: `"sub"`) |
| `consumer_header_claim` | String | Global JWT claim for `X-Consumer-Username` header (default: same as `consumer_identity_claim`) |
| `jwks_refresh_interval_secs` | u64 | JWKS key refresh interval in seconds (default: `900`) |

Claim values are auto-detected as space-delimited strings (OAuth2 standard), JSON arrays, or nested objects via dot-notation paths.

### `jwt_auth`

Authenticates requests using HS256 JWT Bearer tokens matched against consumer credentials.

**Priority:** 1100

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token_lookup` | String | `header:Authorization` | Where to find the token (`header:<name>` or `query:<name>`) |
| `consumer_claim_field` | String | `sub` | JWT claim identifying the consumer |

**Consumer credential** (`jwt`) — single or array for rotation. Secrets must be at least 32 characters:
```yaml
credentials:
  jwt:
    secret: "consumer-specific-hs256-secret-key-here"
  # Array format for zero-downtime rotation:
  # jwt:
  #   - secret: "old-secret-at-least-32-chars-long"
  #   - secret: "new-secret-at-least-32-chars-long"
```

### `key_auth`

Authenticates requests using an API key matched against consumer credentials.

**Priority:** 1200

| Parameter | Type | Default | Description |
|---|---|---|---|
| `key_location` | String | `header:X-API-Key` | Where to find the key (`header:<name>` or `query:<name>`) |

**Consumer credential** (`keyauth`) — single or array for rotation:
```yaml
credentials:
  keyauth:
    key: "the-api-key-value"
  # Array format for zero-downtime rotation:
  # keyauth:
  #   - key: "old-api-key"
  #   - key: "new-api-key"
```

### `basic_auth`

Authenticates using HTTP Basic credentials. Supports two hash formats:
- **HMAC-SHA256** (~1μs) — default when `FERRUM_BASIC_AUTH_HMAC_SECRET` is set (recommended). A default secret is provided but **must be changed in production**.
- **bcrypt** (~100ms) — backward-compatible fallback for `$2b$`/`$2a$` hashes.

**Priority:** 1300

**Config**: None required.

**Consumer credential** (`basicauth`) — single or array for rotation:
```yaml
credentials:
  basicauth:
    password_hash: "hmac_sha256:ab3f..." # HMAC-SHA256 (preferred)
    # or: "$2b$12$..."                   # bcrypt (legacy)
  # Array format for zero-downtime rotation:
  # basicauth:
  #   - password_hash: "hmac_sha256:old..."
  #   - password_hash: "hmac_sha256:new..."
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

**Consumer credential** (`hmac_auth`) — single or array for rotation:
```yaml
credentials:
  hmac_auth:
    secret: "shared-secret"
  # Array format for zero-downtime rotation:
  # hmac_auth:
  #   - secret: "old-secret"
  #   - secret: "new-secret"
```

### ldap_auth

Authenticates requests by extracting HTTP Basic credentials and validating them against an LDAP directory. Supports direct bind (faster, no service account) or search-then-bind (more flexible), with optional Active Directory / LDAP group filtering.

**Priority:** 1250

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ldap_url` | string | (required) | LDAP server URL (`ldap://` or `ldaps://`) |
| `bind_dn_template` | string | (none) | Direct bind DN template with `{username}` placeholder (e.g., `uid={username},ou=users,dc=example,dc=com`) |
| `search_base_dn` | string | (none) | Base DN for search-then-bind user search |
| `search_filter` | string | (none) | LDAP search filter with `{username}` placeholder (e.g., `(&(objectClass=user)(sAMAccountName={username}))`) |
| `service_account_dn` | string | (none) | DN for the service account used in search-then-bind |
| `service_account_password` | string | (none) | Password for the service account |
| `group_base_dn` | string | (none) | Base DN for group membership search (required when `required_groups` is set) |
| `group_filter` | string | auto | Group search filter with `{user_dn}` and `{username}` placeholders. Default checks `member`, `uniqueMember`, and `memberUid` attributes |
| `required_groups` | string[] | `[]` | List of LDAP/AD group names the user must belong to (OR logic — at least one must match) |
| `group_attribute` | string | `cn` | Attribute containing the group name for matching against `required_groups` |
| `starttls` | bool | `false` | Use STARTTLS to upgrade `ldap://` connections to TLS (cannot be used with `ldaps://`) |
| `connect_timeout_seconds` | u64 | `5` | LDAP connection and operation timeout |
| `cache_ttl_seconds` | u64 | `0` | How long to cache successful auth results (0 = disabled). Cache is keyed by username + password hash |
| `consumer_mapping` | bool | `true` | Whether to look up a matching gateway Consumer via `consumer_index.find_by_identity()` |

**Authentication modes** (must configure one):

1. **Direct bind** — set `bind_dn_template` with `{username}` placeholder. Fastest option, no service account needed.
2. **Search-then-bind** — set `search_base_dn`, `search_filter`, `service_account_dn`, and `service_account_password`. The service account searches for the user's DN, then the plugin binds as the user.

**Example — Direct bind:**
```yaml
plugins:
  - name: ldap_auth
    config:
      ldap_url: "ldap://ldap.example.com:389"
      bind_dn_template: "uid={username},ou=users,dc=example,dc=com"
```

**Example — AD search-then-bind with group filtering:**
```yaml
plugins:
  - name: ldap_auth
    config:
      ldap_url: "ldaps://dc.contoso.com:636"
      search_base_dn: "OU=Users,DC=contoso,DC=com"
      search_filter: "(&(objectClass=user)(sAMAccountName={username}))"
      service_account_dn: "CN=svc-proxy,OU=ServiceAccounts,DC=contoso,DC=com"
      service_account_password: "S3cret!"
      group_base_dn: "OU=Groups,DC=contoso,DC=com"
      group_filter: "(&(objectClass=group)(member={user_dn}))"
      required_groups:
        - "Proxy Users"
        - "Domain Admins"
      cache_ttl_seconds: 300
```

The plugin sets `ctx.authenticated_identity` to the LDAP username. When `consumer_mapping` is enabled (default), it also attempts to find a matching gateway Consumer for ACL and rate-limiting integration.

**Input escaping:** Usernames are automatically escaped before interpolation into LDAP queries — DN values are escaped per RFC 4514 and filter values per RFC 4515. This prevents LDAP injection attacks from usernames containing special characters like `*`, `(`, `)`, `\`, `,`, or `=`.

### `soap_ws_security`

Validates WS-Security headers in SOAP XML envelopes. Supports UsernameToken authentication (PasswordText and PasswordDigest), X.509 certificate signature verification, optional SAML assertion validation, timestamp freshness checks, and nonce replay protection.

The plugin buffers request bodies with SOAP content types (`text/xml`, `application/soap+xml`, `application/xml`) and parses the `wsse:Security` header from the SOAP envelope. Non-SOAP requests pass through untouched.

**Priority:** 1500

| Parameter | Type | Default | Description |
|---|---|---|---|
| `reject_missing_security_header` | bool | `true` | Reject SOAP requests that lack a WS-Security header |
| `timestamp.require` | bool | `true` | Require a `wsu:Timestamp` element in the Security header |
| `timestamp.max_age_seconds` | u64 | `300` | Maximum age of the `Created` timestamp before rejection |
| `timestamp.require_expires` | bool | `false` | Require an `Expires` element in the Timestamp |
| `timestamp.clock_skew_seconds` | u64 | `300` | Clock skew tolerance for timestamp validation |
| `username_token.enabled` | bool | `false` | Enable UsernameToken authentication |
| `username_token.password_type` | String | `PasswordDigest` | `PasswordText` or `PasswordDigest` |
| `username_token.credentials` | Object[] | `[]` | Array of `{username, password}` credential pairs |
| `x509_signature.enabled` | bool | `false` | Enable X.509 signature verification |
| `x509_signature.trusted_certs` | String[] | `[]` | PEM file paths of trusted signing certificates |
| `x509_signature.allowed_algorithms` | String[] | `["rsa-sha256"]` | Allowed signature algorithms (`rsa-sha256`, `rsa-sha1`) |
| `x509_signature.require_signed_timestamp` | bool | `true` | Require the Timestamp to be included in the signature |
| `saml.enabled` | bool | `false` | Enable SAML assertion validation |
| `saml.trusted_issuers` | String[] | `[]` | Trusted SAML Issuer values |
| `saml.audience` | String | *(none)* | Expected SAML Audience value |
| `saml.clock_skew_seconds` | u64 | `300` | Clock skew tolerance for SAML condition timestamps |
| `nonce.cache_ttl_seconds` | u64 | `300` | How long to remember nonces for replay detection |
| `nonce.max_cache_size` | u64 | `10000` | Maximum nonce cache entries before eviction sweep |

At least one security feature must be enabled (`timestamp.require`, `username_token`, `x509_signature`, or `saml`).

#### UsernameToken — PasswordDigest

The PasswordDigest mode computes `Base64(SHA-1(nonce + created + password))` per the WS-Security UsernameToken Profile 1.0 specification. The SOAP request must include `wsse:Nonce` and `wsu:Created` elements alongside the password. Each nonce is tracked for replay protection.

```yaml
plugin_name: soap_ws_security
config:
  username_token:
    enabled: true
    password_type: PasswordDigest
    credentials:
      - username: "service-account"
        password: "shared-secret"
  timestamp:
    require: true
    max_age_seconds: 300
```

#### UsernameToken — PasswordText

PasswordText mode compares the password directly (no hashing). Only use over TLS.

```yaml
plugin_name: soap_ws_security
config:
  username_token:
    enabled: true
    password_type: PasswordText
    credentials:
      - username: "admin"
        password: "admin-password"
  timestamp:
    require: false
```

#### X.509 Signature Verification

Verifies XMLDSig signatures using trusted X.509 certificates. The signing certificate must be present as a `wsse:BinarySecurityToken` or inline `ds:X509Certificate` in the Signature's `KeyInfo`. The certificate is matched against the configured trusted certs by SHA-256 fingerprint.

```yaml
plugin_name: soap_ws_security
config:
  x509_signature:
    enabled: true
    trusted_certs:
      - /etc/ferrum/certs/partner-signing.pem
    allowed_algorithms:
      - rsa-sha256
    require_signed_timestamp: true
  timestamp:
    require: true
```

#### SAML Assertion Validation

Validates SAML 2.0 assertions embedded in the WS-Security header. Checks issuer trust, `NotBefore`/`NotOnOrAfter` conditions, and optional audience restriction.

```yaml
plugin_name: soap_ws_security
config:
  saml:
    enabled: true
    trusted_issuers:
      - "https://idp.example.com"
    audience: "https://api.example.com"
    clock_skew_seconds: 300
  timestamp:
    require: true
```

#### Combined Configuration

Multiple security features can be enabled together. All enabled checks must pass.

```yaml
plugin_name: soap_ws_security
config:
  timestamp:
    require: true
    max_age_seconds: 300
    require_expires: true
  username_token:
    enabled: true
    password_type: PasswordDigest
    credentials:
      - username: "service-a"
        password: "secret-a"
  x509_signature:
    enabled: true
    trusted_certs:
      - /etc/ferrum/certs/signing-ca.pem
    require_signed_timestamp: true
  nonce:
    cache_ttl_seconds: 600
    max_cache_size: 50000
  reject_missing_security_header: true
```

**Metadata:** On successful UsernameToken authentication, the plugin sets `ctx.metadata["soap_ws_username"]` to the authenticated username, available to downstream plugins and logging.

**Namespace prefix agnostic:** The plugin matches XML elements by local name, so it works regardless of namespace prefix conventions (`wsse:`, `WSSE:`, `sec:`, `soap:`, `s:`, etc.).

---

## Authorization Plugins

### `access_control`

Authorizes requests based on the authenticated caller. Checks the identified
consumer's username and/or their `acl_groups` membership. Groups let you map a
single consumer into access across multiple proxies — assign the consumer to an
ACL group once and reference the group in each proxy's plugin config instead of
listing every username individually. Optionally it can also allow externally
authenticated identities (for example `jwks_auth` users without a mapped
gateway Consumer). On TCP stream proxies, it uses the consumer already placed
in the stream context by an earlier auth plugin such as [`mtls_auth`](#mtls_auth).

**Priority:** 2000

| Parameter | Type | Description |
|---|---|---|
| `allowed_consumers` | String[] | Usernames allowed access (empty = no username-level allow rule) |
| `disallowed_consumers` | String[] | Usernames explicitly denied |
| `allowed_groups` | String[] | ACL group names allowed access — matches against the consumer's `acl_groups` list (empty = no group-level allow rule) |
| `disallowed_groups` | String[] | ACL group names explicitly denied — matches against the consumer's `acl_groups` list |
| `allow_authenticated_identity` | bool | Allows requests with `ctx.authenticated_identity` set even when no Consumer was mapped |

At least one of the above must be configured (non-empty list or `allow_authenticated_identity: true`).

**Evaluation order:** deny (consumer username → group) → allow (consumer username → group).
If both `allowed_consumers` and `allowed_groups` are set, matching _either_ grants access.
Deny always takes precedence — a consumer whose username is in `allowed_consumers` is still
rejected if any of their groups appear in `disallowed_groups`.

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

### `geo_restriction`

Restricts access based on the geographic location of the client IP address using MaxMind GeoIP2/GeoLite2 `.mmdb` database files.

**Priority:** 175

**Supported protocols:** All (HTTP, gRPC, WebSocket, TCP, UDP)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db_path` | String | (required) | Path to MaxMind `.mmdb` file |
| `allow_countries` | String[] | `[]` | ISO 3166-1 alpha-2 country codes to allow (whitelist mode) |
| `deny_countries` | String[] | `[]` | ISO 3166-1 alpha-2 country codes to deny (blacklist mode) |
| `inject_headers` | bool | `false` | Inject `X-Geo-Country` header into upstream requests |
| `on_lookup_failure` | String | `"allow"` | Action when GeoIP lookup fails: `allow` or `deny` |

`allow_countries` and `deny_countries` are mutually exclusive. At least one must be non-empty.

The `.mmdb` file is memory-mapped at plugin startup for zero-copy lookups on the hot path. A gateway restart (or config reload) is required to pick up a new database file.

**CP/DP deployment note:** In control plane / data plane deployments, the `.mmdb` file only needs to exist on the **data plane** nodes where proxy traffic is handled. The control plane accepts `geo_restriction` plugin configs via the admin API without requiring the file locally. If the `.mmdb` file is missing on a data plane node at startup, the plugin degrades gracefully — all GeoIP lookups fall back to the `on_lookup_failure` policy (default: `allow`) until the file is deployed and the config is reloaded. Other proxies and plugins are unaffected.

**Behavior by mode:**

| Mode | Missing `.mmdb` file at startup |
|------|-------------------------------|
| **File** | Fatal — gateway refuses to start |
| **Database** | Warning logged, plugin degrades to `on_lookup_failure` policy |
| **Control Plane** | Admin API accepts config normally (CP does not proxy traffic) |
| **Data Plane** | Warning logged, plugin degrades to `on_lookup_failure` policy; all other proxies/plugins work normally |

> **Note:** Ferrum Edge does not ship or bundle any GeoIP database. Operators are responsible for obtaining a MaxMind GeoIP2 or GeoLite2 `.mmdb` file, accepting MaxMind's license terms, and managing updates. GeoLite2 (free) requires a [MaxMind account](https://www.maxmind.com/en/geolite2/signup) and is subject to the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula). MaxMind publishes weekly database updates.

```yaml
plugin_name: geo_restriction
config:
  db_path: /etc/ferrum/GeoLite2-Country.mmdb
  allow_countries: [US, CA, GB, DE, FR]
  inject_headers: true
```

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
| `redis_key_prefix` | String | `{FERRUM_NAMESPACE}:rate_limiting` | Redis key namespace prefix. Defaults to `ferrum:rate_limiting` when namespace is `"ferrum"` |
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

> **Namespace isolation:** When `FERRUM_NAMESPACE` is set to a non-default value, the default `redis_key_prefix` automatically includes the namespace (e.g., `staging:rate_limiting` instead of `ferrum:rate_limiting`). This prevents key collisions when multiple gateway instances with different namespaces share the same Redis cluster. An explicit `redis_key_prefix` in the plugin config overrides this behavior entirely.

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

### `request_deduplication`

Prevents duplicate API calls by tracking idempotency keys. When a request arrives with an idempotency key header and the same key was seen within the configured TTL, the plugin returns the cached response instead of forwarding to the backend.

**Priority:** 2750

| Parameter | Type | Default | Description |
|---|---|---|---|
| `header_name` | String | `"Idempotency-Key"` | Header name to read the idempotency key from (case-insensitive) |
| `ttl_seconds` | u64 | `300` | Time-to-live for cached responses (must be > 0) |
| `max_entries` | u64 | `10000` | Maximum number of cached entries (local mode) |
| `applicable_methods` | String[] | `["POST", "PUT", "PATCH"]` | HTTP methods to apply deduplication to |
| `scope_by_consumer` | bool | `true` | Scope keys by authenticated consumer identity |
| `enforce_required` | bool | `false` | Reject requests missing the idempotency header with 400 |
| `sync_mode` | String | `"local"` | `local` (in-memory) or `redis` (centralized) |
| `redis_url` | String (optional) | — | Redis connection URL (required when `sync_mode: "redis"`) |
| `redis_tls` | bool | `false` | Enable TLS for Redis connection |
| `redis_key_prefix` | String | `"{FERRUM_NAMESPACE}:dedup"` | Redis key namespace prefix. Defaults to `ferrum:dedup` when namespace is `"ferrum"` |
| `redis_pool_size` | u64 | `4` | Number of multiplexed Redis connections |
| `redis_connect_timeout_seconds` | u64 | `5` | Redis connection timeout |
| `redis_health_check_interval_seconds` | u64 | `5` | Health check interval when Redis is unavailable |
| `redis_username` | String (optional) | — | Redis ACL username |
| `redis_password` | String (optional) | — | Redis password |

**Behavior:**
- On cache hit: returns the cached response with `X-Idempotent-Replayed: true` header
- Concurrent duplicates: returns `409 Conflict` when a request with the same key is already in-flight
- GET/HEAD/OPTIONS/DELETE requests are ignored unless explicitly added to `applicable_methods`
- `scope_by_consumer: true` isolates keys per authenticated identity so different consumers can use the same idempotency key independently

**Centralized mode** (`sync_mode: "redis"`): Uses the shared `RedisRateLimitClient` infrastructure for centralized deduplication across multiple gateway instances. Automatic local fallback when Redis is unreachable. Compatible with Redis, Valkey, DragonflyDB, KeyDB, or Garnet. Namespace-aware key prefix prevents collisions when gateways with different `FERRUM_NAMESPACE` values share the same Redis cluster.

```yaml
plugin_name: request_deduplication
config:
  header_name: Idempotency-Key
  ttl_seconds: 300
  enforce_required: true
  sync_mode: redis
  redis_url: "redis://redis-host:6379/0"
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

## Response Mock Plugin

### `response_mock`

Returns configurable mock responses without proxying to the backend. Supports matching by HTTP method and path pattern (exact or regex), with configurable status codes, headers, body, and optional latency simulation. Useful for early API testing before backends are ready, contract testing, and local development.

**Priority:** 3030 | **Phase:** `before_proxy` | **Protocols:** HTTP family

**Path matching is relative to the proxy's `listen_path`.** The plugin strips the proxy's prefix listen_path before matching rules. For example, if the proxy has `listen_path: /api/v1` and a request arrives at `/api/v1/users`, the mock rule path should be `/users`. For proxies with regex listen_paths (`~` prefix) or root listen_path (`/`), the full request path is used.

```yaml
# Proxy with listen_path: /api/v1
config:
  rules:
    - method: GET                        # optional — omit to match all methods
      path: /users                       # matches /api/v1/users
      status_code: 200
      headers:
        content-type: application/json
      body: '{"users": []}'
      delay_ms: 50                       # optional simulated latency (ms)
    - path: "~/users/[0-9]+"             # regex path (~ prefix, auto-anchored)
      status_code: 200                   # matches /api/v1/users/42
      body: '{"id": 1, "name": "Mock User"}'
    - method: POST
      path: /users                       # matches POST /api/v1/users
      status_code: 201
      body: '{"id": 2, "name": "Created"}'
  passthrough_on_no_match: true          # false (default) returns 404 for unmatched requests
```

Rules are evaluated in order — first match wins. Regex paths use the same `~` prefix and auto-anchoring as `listen_path` patterns. A request to exactly the listen_path (e.g., `/api/v1` with no trailing path) is matched as `/`. When `passthrough_on_no_match` is `false` (default), requests that don't match any rule receive a `404` with `{"error":"no mock rule matched"}`. When `true`, unmatched requests continue to the real backend — useful for mocking only some endpoints while the rest hit the backend.

### `spec_expose`

Exposes API specification documents (OpenAPI, Swagger, WSDL, WADL) on a `/specz` sub-path of each proxy's listen path. When a `GET` request arrives at `{listen_path}/specz`, the plugin fetches the specification from the configured upstream URL and returns it to the caller. The `/specz` endpoint is **unauthenticated** — the plugin short-circuits in the `on_request_received` phase before authentication runs, so consumers can discover API contracts without credentials.

Useful for providing a common, discoverable pattern for API specifications across enterprise-wide APIs.

**Priority:** 210 | **Phase:** `on_request_received` | **Protocols:** HTTP only

**Only works with prefix-based `listen_path` proxies.** Regex listen paths (`~` prefix) are skipped — the plugin continues without intercepting. Host-only or port-only routing is not supported.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `spec_url` | String | _(required)_ | Full URL to fetch the API specification document (e.g., `https://internal-service/docs/openapi.yaml`) |
| `content_type` | String | _(upstream)_ | Override the response `Content-Type`. When omitted, the upstream response's `Content-Type` is passed through (so YAML specs return as YAML, JSON as JSON, etc.) |
| `tls_no_verify` | bool | `FERRUM_TLS_NO_VERIFY` | Skip TLS certificate verification when fetching the spec. Defaults to the gateway's global `FERRUM_TLS_NO_VERIFY` setting. Useful for internal endpoints with self-signed certificates |

```yaml
# Example: Expose an OpenAPI spec for an API behind /my/api/v1
# GET https://gateway.com/my/api/v1/specz → fetches and returns the spec
config:
  spec_url: "https://internal-service.corp.net/docs/openapi.yaml"
```

```yaml
# Example: Override content-type and skip TLS verification
config:
  spec_url: "https://10.0.1.50:8443/api/swagger.json"
  content_type: "application/json"
  tls_no_verify: true
```

**Error handling:** If the upstream spec URL is unreachable or returns a non-2xx status, the plugin returns a `502` JSON error response with details. The `spec_url` hostname is pre-warmed via DNS at startup alongside other backend hostnames.

**Interaction with other plugins:** The plugin runs at priority 210 — after CORS (100), IP restriction (150), and bot detection (200), but before all authentication plugins (950+). This means blocked IPs and bots cannot access `/specz`, CORS preflight responses work correctly for browser-based spec consumers, and all authentication and authorization plugins are skipped for `/specz` requests.

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

### `compression`

On-the-fly response compression and request decompression. Negotiates the best algorithm via the client's `Accept-Encoding` header (RFC 9110 §12.5.3). Supports gzip and brotli.

**Priority:** 4050

**Response compression** (enabled by default):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithms` | String[] | `["gzip", "br"]` | Enabled algorithms in server preference order (used to break q-value ties) |
| `min_content_length` | u64 | `256` | Skip compression for bodies smaller than this (bytes) |
| `content_types` | String[] | 10 defaults | Content-type whitelist (see below) |
| `disable_on_etag` | bool | `false` | Skip compression when the response has an ETag header |
| `remove_accept_encoding` | bool | `true` | Strip `Accept-Encoding` from the backend request so the backend sends uncompressed |
| `gzip_level` | u64 | `6` | Gzip compression level (1=fastest, 9=best) |
| `brotli_quality` | u64 | `4` | Brotli quality (0=fastest, 11=best) |

**Request decompression** (opt-in):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `decompress_request` | bool | `false` | Enable decompression of gzip/brotli request bodies |
| `max_decompressed_request_size` | u64 | `10485760` | Zip bomb protection: max decompressed size in bytes (10 MB) |

**Default content types:** `application/json`, `application/javascript`, `application/xml`, `application/xhtml+xml`, `text/html`, `text/plain`, `text/css`, `text/xml`, `text/javascript`, `image/svg+xml`

**Skip conditions** (checked in order):
1. Response status is 204 or 304
2. Response already has `Content-Encoding` (no double-compression)
3. `disable_on_etag` is true and response has an `ETag` header
4. Response `Content-Type` is not in the whitelist
5. Response `Content-Length` is below `min_content_length`
6. Client did not send `Accept-Encoding` with a supported algorithm

**Behavior:**
- Strips `Accept-Encoding` from backend requests (configurable) so the backend sends uncompressed responses for the gateway to compress
- Adds `Vary: Accept-Encoding` to compressed responses for cache correctness
- Removes `Content-Length` after compression (the gateway recalculates it from the compressed body)
- Forces response body buffering on proxies where this plugin is enabled
- Request decompression removes `Content-Encoding` and `Content-Length` from the forwarded request headers

```yaml
config:
  algorithms: ["gzip", "br"]
  min_content_length: 256
  gzip_level: 6
  brotli_quality: 4
  remove_accept_encoding: true
  decompress_request: false
```

**Note:** This plugin handles HTTP-level `Content-Encoding` compression/decompression. gRPC message-level compression (the compressed flag in gRPC wire frames) is handled separately by `body_validator` for protobuf validation — these are different protocol layers and should not be confused.

---

### `sse`

Server-Sent Events stream handler. Validates inbound SSE client criteria, shapes requests for backends, and ensures proper streaming response headers for SSE delivery.

**Priority:** 250

**Lifecycle:**

1. **`on_request_received`** — Validates SSE client conformance: rejects non-GET with 405 + `Allow: GET`, rejects missing/wrong `Accept` with 406, stashes `Last-Event-ID` in metadata for reconnection.
2. **`before_proxy`** — Strips `Accept-Encoding` to prevent compressed responses from breaking SSE line-delimited framing. Forwards `Last-Event-ID` header to the backend.
3. **`after_proxy`** — Sets `Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no`. Strips `Content-Length`. Optionally forces `Content-Type: text/event-stream`.
4. **`transform_response_body`** — Optionally wraps non-SSE response bodies in `data: ...\n\n` SSE event framing (buffered responses only).

**Request validation:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `require_get_method` | bool | `true` | Reject non-GET requests with 405 |
| `require_accept_header` | bool | `true` | Require `Accept: text/event-stream` header (406 if missing) |

**Request shaping:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `strip_accept_encoding` | bool | `true` | Strip `Accept-Encoding` to prevent compressed chunked responses breaking SSE framing |

**Response shaping:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `add_no_buffering_header` | bool | `true` | Add `X-Accel-Buffering: no` to disable nginx/ALB buffering |
| `strip_content_length` | bool | `true` | Remove `Content-Length` (SSE streams are indefinite) |
| `retry_ms` | u64 | _(none)_ | EventSource reconnection hint (ms), prepended as `retry:` when wrapping |
| `force_sse_content_type` | bool | `false` | Force `Content-Type: text/event-stream` even if backend returns something else |
| `wrap_non_sse_responses` | bool | `false` | Wrap non-SSE response bodies in `data: ...\n\n` SSE event framing |

**Note:** When `wrap_non_sse_responses` is enabled, the plugin requires response body buffering. When disabled (default), the response streams through with zero overhead — ideal for backends that already emit `text/event-stream`.

```yaml
config:
  require_get_method: true
  require_accept_header: true
  strip_accept_encoding: true
  add_no_buffering_header: true
  retry_ms: 3000
  force_sse_content_type: false
  wrap_non_sse_responses: false
```

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
- **Responses containing `Set-Cookie` headers are never cached.** Set-Cookie headers are per-client and replaying them from a shared cache would leak session cookies to other users (RFC 7234 §8).
- The plugin stores arbitrary response bytes, so binary responses and backend-compressed payloads can be cached safely.

Compression note:
- The `compression` plugin (priority 4050) can generate gzip or brotli responses at the gateway. When both `response_caching` and `compression` are enabled on the same proxy, the cache stores the uncompressed backend response (since `response_caching` at 3500 runs before `compression` at 4050). Compression is applied after cache retrieval, so cached responses are compressed on each cache hit.
- Without the `compression` plugin, the gateway forwards backend `Content-Encoding` as-is and caches compressed variants correctly when the origin sends the matching `Vary` header.
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

### `grpc_web`

Translates between gRPC-Web (browser-compatible) and native gRPC (HTTP/2) wire formats. Enables browser clients to call gRPC backends through the gateway without a dedicated gRPC-Web proxy.

Supports both encoding modes:
- **Binary** (`application/grpc-web`, `application/grpc-web+proto`): same length-prefixed framing as native gRPC — request body passes through unchanged.
- **Text** (`application/grpc-web-text`, `application/grpc-web-text+proto`): base64-encoded binary frames — decoded on request and re-encoded on response.

On the request path, the plugin rewrites `content-type` to `application/grpc` so downstream plugins (`grpc_method_router`, `grpc_deadline`, etc.) treat the request as native gRPC. On the response path, it embeds HTTP/2 trailers (`grpc-status`, `grpc-message`, and custom trailing metadata) as a length-prefixed trailer frame (flag byte `0x80`) in the response body, then rewrites `content-type` back to the original gRPC-Web variant.

**Priority:** 260 (runs before `grpc_method_router` at 275)
**Protocols:** HTTP, gRPC

| Parameter | Type | Default | Description |
|---|---|---|---|
| `expose_headers` | String[] | `[]` | Additional response headers to include in `Access-Control-Expose-Headers` for browser CORS compatibility. `grpc-status` and `grpc-message` are always exposed. |

```yaml
plugin_name: grpc_web
config:
  expose_headers:
    - custom-header-bin
    - x-request-id
```

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

### `request_mirror`

Duplicates live proxy traffic to a secondary destination for shadow testing, validation, or migration checks without affecting client responses. The mirror request is fire-and-forget — the gateway spawns an async task and proceeds with the real backend call immediately.

**Priority:** 3075
**Protocols:** HTTP, gRPC

Mirror response metadata (status code, response size, latency) is logged as a separate `TransactionSummary` entry with `mirror: true`, flowing through all logging plugins (stdout, http_logging, ws_logging, prometheus, transaction_debugger). The mirror request uses the proxy's `backend_read_timeout_ms` and the gateway's shared DNS cache and connection pool.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `mirror_host` | String | **(required)** | Hostname or IP of the mirror target |
| `mirror_port` | Integer | 80/443 | Port of the mirror target (default based on protocol) |
| `mirror_protocol` | String | `"http"` | `"http"` or `"https"` |
| `mirror_path` | String | _(none)_ | Override the request path for the mirror. When unset, uses the original request path |
| `percentage` | Float | `100.0` | Percentage of requests to mirror (0.0–100.0) |
| `mirror_request_body` | Boolean | `true` | Whether to include the request body in the mirror request |

When `mirror_request_body` is enabled, the plugin preserves binary payloads (including gRPC protobuf) using a binary-safe body store. Non-UTF-8 request bodies are mirrored correctly.

```yaml
plugin_name: request_mirror
config:
  mirror_host: shadow.internal
  mirror_port: 8443
  mirror_protocol: https
  percentage: 50.0
  mirror_request_body: true
```

---

### `load_testing`

Enables on-demand load testing of a proxy's backend by sending concurrent requests through the gateway's own proxy listener. Triggered when a request includes an `X-Loadtesting-Key` header matching the configured secret key. The triggering request proceeds normally; the load test runs in the background.

**Priority:** 3080
**Protocols:** HTTP

Synthetic requests are sent to `127.0.0.1:{gateway_port}` without the `X-Loadtesting-Key` header, so they flow through the full proxy pipeline (routing, auth, rate limiting, backend dispatch, logging) without re-triggering the load test. The gateway's native transaction logging captures every synthetic request automatically. An `AtomicBool` guard prevents concurrent load tests on the same proxy.

For multi-node deployments, `gateway_addresses` fans out the trigger (WITH the key) to remote gateway nodes, so each starts its own independent local load test.

For HTTPS-only deployments that disable the HTTP listener, set `gateway_tls: true`. Since the gateway's frontend cert typically won't match `127.0.0.1`, `gateway_tls_no_verify` defaults to `true` when TLS is enabled. This only affects the loopback connection — backend TLS uses the normal CA trust chain.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `key` | String | **(required)** | Value that `X-Loadtesting-Key` must match to trigger |
| `concurrent_clients` | Integer | **(required)** | Number of concurrent virtual clients (1–10,000) |
| `duration_seconds` | Integer | **(required)** | How long the test runs in seconds (1–3,600) |
| `ramp` | Boolean | `false` | Gradually start clients over the duration instead of all at once (see ramp example below) |
| `request_timeout_ms` | Integer | `30000` | Per-request timeout in milliseconds. Prevents workers from hanging on streaming/long-lived responses (SSE, long-poll) |
| `gateway_port` | Integer | env or 8000/8443 | Local gateway port for synthetic requests. Reads `FERRUM_PROXY_HTTP_PORT` (or `FERRUM_PROXY_HTTPS_PORT` when `gateway_tls` is enabled) |
| `gateway_tls` | Boolean | `false` | Use HTTPS for local loopback synthetic requests |
| `gateway_tls_no_verify` | Boolean | `true` when `gateway_tls` on | Skip TLS cert verification for loopback only |
| `gateway_addresses` | Array | _(none)_ | Remote gateway URLs to fan out the trigger to. Each receives the original request WITH the key header |

**Ramp behavior:** When `ramp: true`, all client tasks are spawned immediately but each sleeps a stagger delay before sending requests. The delay for client _i_ is `duration * i / concurrent_clients`. All clients share the same deadline, so later clients get less sending time.

Example with `concurrent_clients: 10, duration_seconds: 30, ramp: true`:

| Client | Delay | Starts at | Sends until | Active time |
|--------|-------|-----------|-------------|-------------|
| 0 | 0s | 0s | 30s | 30s |
| 1 | 3s | 3s | 30s | 27s |
| 2 | 6s | 6s | 30s | 24s |
| 3 | 9s | 9s | 30s | 21s |
| 4 | 12s | 12s | 30s | 18s |
| 5 | 15s | 15s | 30s | 15s |
| 6 | 18s | 18s | 30s | 12s |
| 7 | 21s | 21s | 30s | 9s |
| 8 | 24s | 24s | 30s | 6s |
| 9 | 27s | 27s | 30s | 3s |

With `ramp: false` (default), all clients start sending at t=0 simultaneously.

**Caveats:**
- **HTTP and GraphQL only**: Synthetic requests are plain HTTP via reqwest. gRPC proxies require HTTP/2 with protobuf length-prefixed framing, and WebSocket proxies require an upgrade handshake — neither is supported. GraphQL works because it is standard HTTP POST. TCP/UDP stream proxies are excluded.
- **Auth forwarding**: Synthetic requests forward the triggering request's headers. For auth schemes with short-lived tokens (HMAC timestamps), tokens may expire during long tests.
- **Rate limiting**: Synthetic requests pass through rate limiting plugins, which is realistic but may throttle throughput if limits are tight.

```yaml
plugin_name: load_testing
config:
  key: my-secret-load-test-key
  concurrent_clients: 50
  duration_seconds: 30
  ramp: true
  gateway_tls: true
  gateway_port: 8443
  gateway_addresses:
    - https://node2:8443
    - https://node3:8443
```

---

## AI / LLM Plugins

Seven plugins purpose-built for AI/LLM API gateway use cases. They auto-detect the LLM provider from the response JSON structure, supporting **OpenAI** (and compatible), **Anthropic**, **Google Gemini**, **Cohere**, **Mistral**, and **AWS Bedrock**.

### `ai_federation`

Universal AI gateway that routes requests in OpenAI Chat Completions format to any of 11 supported AI providers, translating requests to native provider format and normalizing responses back to OpenAI format. Uses the "terminate and respond" pattern — makes its own HTTP call to the matched provider and returns the response directly, bypassing the normal proxy dispatch.

**Priority:** 2985

**Supported providers:**
- **OpenAI-compatible** (send OpenAI format directly): OpenAI, Mistral, xAI (Grok), DeepSeek, Meta Llama, Hugging Face, Azure OpenAI
- **Requires translation**: Anthropic (Messages API), Google Gemini, Google Vertex AI (OAuth2), AWS Bedrock (Converse API, SigV4), Cohere v2

| Parameter | Type | Default | Description |
|---|---|---|---|
| `providers` | Array | _(required)_ | Array of provider configurations (see below) |
| `fallback_enabled` | Boolean | `true` | Try next provider on failure |
| `fallback_on_status_codes` | Array | `[429, 500, 502, 503]` | HTTP status codes that trigger fallback |
| `fallback_on_network_errors` | Boolean | `true` | TCP/TLS failures trigger fallback |

**Provider configuration fields:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | String | _(required)_ | Unique provider name for logging |
| `provider_type` | String | _(required)_ | One of: `openai`, `anthropic`, `google_gemini`, `google_vertex`, `azure_openai`, `aws_bedrock`, `mistral`, `cohere`, `xai`, `deepseek`, `meta_llama`, `hugging_face` |
| `api_key` | String | _(required for most)_ | API key for authentication |
| `priority` | Integer | _(index + 1)_ | Lower = tried first |
| `model_patterns` | Array | `[]` (catch-all) | Glob patterns to match model names (e.g., `["claude-*"]`) |
| `model_mapping` | Object | `{}` | Map client model names to provider-native names |
| `default_model` | String | _(none)_ | Default model when no mapping matches |
| `connect_timeout_seconds` | Integer | `5` | TCP + TLS handshake timeout |
| `read_timeout_seconds` | Integer | `60` | Full response read timeout |
| `base_url` | String | _(provider default)_ | Custom endpoint URL (for self-hosted or proxy endpoints) |

**Azure OpenAI additional fields:** `azure_resource`, `azure_deployment`, `azure_api_version` (default `"2024-06-01"`).

**Google Vertex additional fields:** `google_project_id`, `google_region`, `google_service_account_json`.

**AWS Bedrock additional fields:** `aws_region`, `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`. Credentials fall back to standard AWS environment variables (`AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).

**Example configuration:**

```yaml
plugins:
  - name: ai_federation
    enabled: true
    config:
      providers:
        - name: anthropic-primary
          provider_type: anthropic
          api_key: "sk-ant-..."
          priority: 1
          model_patterns: ["claude-*"]
          model_mapping:
            claude-4-sonnet: "claude-sonnet-4-20250514"
          default_model: "claude-sonnet-4-20250514"
          read_timeout_seconds: 90
        - name: openai-fallback
          provider_type: openai
          api_key: "sk-..."
          priority: 2
          model_patterns: ["gpt-*", "o1-*", "o3-*"]
          default_model: "gpt-4o"
        - name: bedrock
          provider_type: aws_bedrock
          aws_region: "us-east-1"
          priority: 3
          model_patterns: ["bedrock-*"]
          model_mapping:
            bedrock-claude: "anthropic.claude-3-sonnet-20240229-v1:0"
      fallback_enabled: true
      fallback_on_status_codes: [429, 500, 502, 503]
```

**Cross-plugin synergy:** Works with all other AI plugins on the same proxy:
- `ai_prompt_shield` (2925) scans/redacts PII before federation
- `ai_request_guard` (2975) validates model, tokens, temperature before federation
- `ai_federation` (2985) routes to provider, writes token metadata to `ctx.metadata`
- `ai_rate_limiter` (4200) records token usage from federation metadata via `applies_after_proxy_on_reject`

**Metadata keys written:** `ai_total_tokens`, `ai_prompt_tokens`, `ai_completion_tokens`, `ai_model`, `ai_provider`, `ai_federation_provider` — same keys as `ai_token_metrics` for downstream compatibility.

**TLS trust chain:** Because this plugin bypasses the normal proxy dispatch and makes outbound HTTP calls via the shared `PluginHttpClient`, it uses **global TLS settings only** — `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY`. Per-proxy backend TLS overrides (`backend_tls_server_ca_cert_path`, `backend_tls_client_cert_path`, `backend_tls_verify_server_cert`) and CRL checking do not apply. For providers behind private endpoints (e.g., Azure Private Link, VPC endpoints), add the internal CA to the global CA bundle PEM file. Note that when `FERRUM_TLS_CA_BUNDLE_PATH` is set, webpki/system roots are excluded (CA exclusivity) — include public root CAs in the bundle if some providers are public and others use internal CAs.

### `ai_semantic_cache`

Caches LLM responses keyed by normalized prompts to reduce redundant API calls and latency. v1 uses exact-match with normalization: prompts are lowercased, whitespace is collapsed, and the result is SHA-256 hashed to produce the cache key. Supports local in-memory (DashMap) and centralized Redis storage backends.

**Priority:** 2700

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ttl_seconds` | u64 | `300` | Time-to-live for cached entries in seconds |
| `max_entries` | u64 | `10000` | Maximum number of cached entries (local mode) |
| `max_entry_size_bytes` | u64 | `1048576` | Maximum size of a single cached response body in bytes (1 MiB) |
| `max_total_size_bytes` | u64 | `104857600` | Maximum total cache size in bytes (100 MiB, local mode) |
| `include_model_in_key` | bool | `true` | Include the model name in the cache key (different models get separate cache entries) |
| `include_params_in_key` | bool | `false` | Include request parameters (temperature, max_tokens, etc.) in the cache key |
| `scope_by_consumer` | bool | `false` | Scope cache entries per consumer (authenticated consumer ID is included in the cache key) |
| `sync_mode` | String | `"local"` | `"local"` (in-memory DashMap) or `"redis"` (centralized Redis) |
| `redis_url` | String (optional) | -- | Redis connection URL (required when `sync_mode: "redis"`) |
| `redis_tls` | bool | `false` | Enable TLS for Redis connection |
| `redis_key_prefix` | String | `"{FERRUM_NAMESPACE}:ai_cache"` | Redis key namespace prefix. Defaults to `ferrum:ai_cache` when namespace is `"ferrum"` |
| `redis_pool_size` | u64 | `4` | Number of multiplexed Redis connections |
| `redis_connect_timeout_seconds` | u64 | `5` | Redis connection timeout in seconds |
| `redis_health_check_interval_seconds` | u64 | `5` | Interval for background health check pings when Redis is unavailable |
| `redis_username` | String (optional) | -- | Redis ACL username (Redis 6+) |
| `redis_password` | String (optional) | -- | Redis password |

**Behavior:**

- **Cache key normalization**: The prompt text is lowercased and whitespace is collapsed (multiple spaces, tabs, newlines reduced to a single space), then SHA-256 hashed. This ensures semantically identical prompts with minor formatting differences produce the same cache key.
- **Cache status header**: Responses include an `X-Ai-Cache-Status` header: `HIT` when the response is served from cache, `MISS` when the response is fetched from the backend and stored.
- **SSE responses**: Server-Sent Events (streaming) responses are not cached because they arrive incrementally and cannot be reliably replayed from a stored buffer.
- **Redis mode**: When `sync_mode: "redis"`, cache entries are stored in Redis with TTL-based expiration. If Redis becomes unreachable, the plugin falls back to local in-memory storage automatically. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). Namespace-aware key prefix prevents cache collisions when gateways with different `FERRUM_NAMESPACE` values share the same Redis cluster.

```yaml
plugin_name: ai_semantic_cache
config:
  ttl_seconds: 600
  max_entries: 5000
  max_entry_size_bytes: 2097152
  include_model_in_key: true
  scope_by_consumer: true
```

**Redis mode example:**

```yaml
plugin_name: ai_semantic_cache
config:
  ttl_seconds: 3600
  sync_mode: redis
  redis_url: "redis://redis-host:6379/3"
  redis_key_prefix: "myapp:ai_cache"
```

#### v2 Roadmap

A future v2 will add semantic similarity matching using embedding vectors. Instead of requiring exact normalized prompt matches, v2 will compute embeddings for prompts and use cosine similarity to find cached responses for semantically similar (but not identical) prompts. This will support configurable similarity thresholds and pluggable embedding providers.

### `ai_token_metrics`

Extracts token usage from LLM response bodies and writes it to request metadata for downstream logging and observability plugins. Supports both regular JSON responses and SSE (Server-Sent Events) streaming responses.

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

**SSE streaming support:** When the response content-type is `text/event-stream`, the plugin parses `data:` lines from the SSE stream to extract token usage. For OpenAI-compatible providers, usage data is found in the final SSE event (when `stream_options.include_usage: true` is set on the request). For Anthropic streaming, usage is extracted from `message_start` (input tokens) and `message_delta` (output tokens) events. Model name is extracted from the first parseable chunk. Sets `{prefix}_streaming: true` metadata when processing a streaming response.

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

Rate-limits consumers by LLM token consumption instead of request count. Supports both regular JSON and SSE streaming responses — when `ai_token_metrics` is active, reads tokens from metadata; when used standalone, parses response bodies directly including SSE `data:` lines.

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
| `redis_key_prefix` | String | `{FERRUM_NAMESPACE}:ai_rate_limiter` | Redis key namespace prefix. Defaults to `ferrum:ai_rate_limiter` when namespace is `"ferrum"` |
| `redis_pool_size` | u64 | `4` | Number of multiplexed Redis connections |
| `redis_connect_timeout_seconds` | u64 | `5` | Redis connection timeout in seconds |
| `redis_health_check_interval_seconds` | u64 | `5` | Interval for background health check pings when Redis is unavailable |
| `redis_username` | String (optional) | — | Redis ACL username (Redis 6+) |
| `redis_password` | String (optional) | — | Redis password |

> **Note:** When `redis_tls` is enabled, CA certificate verification and skip-verify behavior are controlled by the gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` environment variables, not per-plugin settings.

`provider` is parsed case-insensitively and ignores surrounding whitespace.

**Centralized mode** (`sync_mode: "redis"`): Token budgets are shared across all gateway instances so consumers cannot exceed limits by spreading requests across data planes. Uses the same two-window weighted approximation and automatic fallback as `rate_limiting`. Compatible with any RESP-protocol server: Redis, Valkey, DragonflyDB, KeyDB, or Garnet. Namespace-aware key prefix prevents collisions when gateways with different `FERRUM_NAMESPACE` values share the same Redis cluster.

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

### `ai_response_guard`

Validates and filters LLM response content before it reaches the client. Complements `ai_prompt_shield` (which guards inputs) by providing output-side guardrails including PII detection in responses, keyword/phrase blocklists, and response format validation.

**Priority:** 4075

| Parameter | Type | Default | Description |
|---|---|---|---|
| `action` | String | `"reject"` | `reject` (502), `redact`, or `warn` |
| `pii_patterns` | String[] | `[]` | Built-in PII patterns to scan for in responses |
| `custom_pii_patterns` | Object[] | `[]` | Custom `{name, regex}` PII patterns |
| `blocked_phrases` | String[] | `[]` | Case-insensitive literal phrases to block |
| `blocked_patterns` | Object[] | `[]` | Custom `{name, regex}` content patterns to block |
| `scan_fields` | String | `"content"` | `content` (LLM completion fields only) or `all` (entire body) |
| `redaction_placeholder` | String | `"[REDACTED:{type}]"` | Template for redacted text |
| `max_scan_bytes` | Integer | `1048576` | Skip scanning if body exceeds this size |
| `require_json` | bool | `false` | Reject responses that are not valid JSON |
| `required_fields` | String[] | `[]` | Required top-level JSON fields (rejects with 502 if missing) |
| `max_completion_length` | Integer | `0` | Maximum completion text length in characters (0 = unlimited) |

At least one of `pii_patterns`, `blocked_phrases`, `blocked_patterns`, `require_json`, `required_fields`, or `max_completion_length` must be configured.

**Built-in PII patterns** (same as `ai_prompt_shield`): `ssn`, `credit_card`, `email`, `phone_us`, `api_key`, `aws_key`, `ip_address`, `iban`

**Multi-provider support:** Extracts completion text from OpenAI (`choices[].message.content`), Anthropic (`content[].text`), and Google Gemini (`candidates[].content.parts[].text`) response formats.

**Metadata keys** (for observability):
- `ai_response_guard_detected` — comma-separated list of detected pattern types (warn mode)
- `ai_response_guard_redacted` — comma-separated list of redacted pattern types (redact mode)
- `ai_response_guard_warning` — completion length violation message

```yaml
plugin_name: ai_response_guard
config:
  action: redact
  pii_patterns: [ssn, credit_card, email, api_key]
  blocked_phrases: ["ignore all previous instructions"]
  blocked_patterns:
    - name: profanity
      regex: "\\b(?:badword1|badword2)\\b"
  max_completion_length: 10000
```

### AI Plugin Composition Example

A typical AI gateway proxy combining all seven AI plugins with `ai_federation` for multi-provider routing:

```yaml
# Proxy config — ai_federation handles provider routing, so backend_host is unused
listen_path: /v1/chat/completions
backend_protocol: https
backend_host: placeholder.local
backend_port: 443

# Plugin configs (applied in priority order automatically)
plugins:
  - plugin_name: key_auth
    config: {}
  - plugin_name: ai_semantic_cache
    config:
      ttl_seconds: 600
      include_model_in_key: true
      scope_by_consumer: true
  - plugin_name: ai_prompt_shield
    config:
      action: redact
      patterns: [ssn, credit_card, email, api_key]
  - plugin_name: ai_request_guard
    config:
      allowed_models: [claude-*, gpt-*, gemini-*]
      max_tokens_limit: 4096
      enforce_max_tokens: clamp
      default_max_tokens: 1024
  - plugin_name: ai_federation
    config:
      providers:
        - name: anthropic
          provider_type: anthropic
          api_key: "sk-ant-..."
          priority: 1
          model_patterns: ["claude-*"]
        - name: openai
          provider_type: openai
          api_key: "sk-..."
          priority: 2
          model_patterns: ["gpt-*"]
        - name: gemini
          provider_type: google_gemini
          api_key: "AIza..."
          priority: 3
          model_patterns: ["gemini-*"]
      fallback_enabled: true
  - plugin_name: ai_response_guard
    config:
      action: redact
      pii_patterns: [ssn, credit_card, email]
      blocked_phrases: ["ignore all previous instructions"]
  - plugin_name: ai_rate_limiter
    config:
      token_limit: 1000000
      window_seconds: 86400
      limit_by: consumer
      expose_headers: true
  - plugin_name: stdout_logging
    config: {}
```

> **Note:** When `ai_federation` is active, it short-circuits the proxy via `RejectBinary`, so `ai_token_metrics`, `ai_response_guard`, and `ai_semantic_cache` do not fire on the response path. The federation plugin writes the same metadata keys directly. The `ai_rate_limiter` records token usage via `applies_after_proxy_on_reject` on the rejection path.

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
| `redis_key_prefix` | String | `{FERRUM_NAMESPACE}:ws_rate_limiting` | Redis key namespace prefix. Defaults to `ferrum:ws_rate_limiting` when namespace is `"ferrum"` |
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
