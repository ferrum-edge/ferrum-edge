# Plugin Reference

Ferrum Edge includes 31 built-in plugins organized into lifecycle phases. Each plugin executes at a specific priority (lower number = runs first).

For execution order, protocol support matrix, and design rationale, see [plugin_execution_order.md](plugin_execution_order.md).

## Lifecycle Phases

1. **`on_request_received`** — Called immediately when a request arrives (CORS preflight, rate limiting)
2. **`authenticate`** — Identifies the consumer (mTLS, JWKS, JWT, API Key, Basic Auth)
3. **`authorize`** — Checks consumer permissions (Access Control)
4. **`before_proxy`** — Modifies the request before forwarding (Request Transformer)
5. **`after_proxy`** — Modifies the response from the backend (Response Transformer, CORS headers)
6. **`on_response_body`** — Processes response body (AI token metrics, AI rate limiter)
7. **`log`** — Logs the transaction summary (Stdout/HTTP Logging)
8. **`on_ws_frame`** — Per-frame WebSocket hooks (Size Limiting, Rate Limiting, Frame Logging)

## Scope

- **Global** plugins apply to all proxies
- **Proxy-scoped** plugins apply only to a specific proxy and override globals of the same plugin type

## Multi-Authentication Mode

When a proxy has `auth_mode: multi`, all attached authentication plugins execute sequentially. The first plugin that successfully identifies a consumer attaches that consumer's context. Subsequent auth plugins cannot overwrite it. After all auth plugins run, the Access Control plugin verifies that at least one consumer was identified.

## Consumer Identity Headers

When a request is successfully authenticated, the gateway automatically injects identity headers:

| Header | Value | Present |
|--------|-------|---------|
| `X-Consumer-Username` | The consumer's `username` field | Always (when authenticated) |
| `X-Consumer-Custom-Id` | The consumer's `custom_id` field | Only when `custom_id` is set |

These headers are injected on all proxy paths (HTTP, gRPC, and WebSocket).

---

## Logging Plugins

### `stdout_logging`

Logs a JSON transaction summary to stdout for each request.

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

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://logging-service.example.com/ingest"
  authorization_header: "Bearer log-token-123"
  batch_size: 50
  flush_interval_ms: 1000
```

### `transaction_debugger`

Logs verbose request/response details to stdout. Sensitive headers are automatically redacted. Enable per-proxy only for debugging.

**Priority:** 9200

| Parameter | Type | Default | Description |
|---|---|---|---|
| `log_request_body` | bool | `false` | Log incoming request body |
| `log_response_body` | bool | `false` | Log backend response body |
| `redacted_headers` | String[] | `[]` | Additional header names to redact beyond the built-in sensitive list |

**Built-in redacted headers**: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-xsrf-token`, `www-authenticate`, `x-forwarded-authorization`

### `correlation_id`

Generates and propagates correlation IDs for request tracing across services.

**Priority:** 9000

| Parameter | Type | Default | Description |
|---|---|---|---|
| `header_name` | String | `X-Correlation-ID` | Header name for correlation ID |
| `generator` | String | `uuid` | ID generation strategy |
| `echo_downstream` | bool | `true` | Include correlation ID in response headers |

### `prometheus_metrics`

Exports gateway metrics in Prometheus exposition format.

**Priority:** 9300

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | String | `/metrics` | Metrics endpoint path |

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
| `buffer_capacity` | Integer | `10000` | Max pending spans; drops oldest when full |
| `max_retries` | Integer | `2` | Retry attempts on export failure |
| `retry_delay_ms` | Integer | `1000` | Delay between retries |

Exported spans include OTel semantic convention attributes, gateway-specific attributes (`gateway.proxy.id`, `gateway.latency.*`), error classification events, and resource attributes.

---

## Authentication Plugins

### `mtls_auth`

Authenticates requests using the client's TLS certificate, matching a configurable certificate field against consumer credentials.

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

| Parameter | Type | Description |
|---|---|---|
| `secret` | String | Shared secret for HMAC computation |
| `algorithm` | String | Hash algorithm (e.g., `sha256`) |
| `header` | String | Header containing the HMAC signature |

---

## Authorization Plugins

### `access_control`

Authorizes requests based on IP address, CIDR range, and/or the identified consumer's username. Blocked IPs take precedence over allowed IPs.

**Priority:** 2000

| Parameter | Type | Description |
|---|---|---|
| `allowed_ips` | String[] | IP addresses or CIDR ranges allowed |
| `blocked_ips` | String[] | IP addresses or CIDR ranges explicitly denied |
| `allowed_consumers` | String[] | Usernames allowed access (empty = allow all) |
| `disallowed_consumers` | String[] | Usernames explicitly denied |

### `ip_restriction`

Restricts access based on client IP address or CIDR range.

**Priority:** 100

| Parameter | Type | Description |
|---|---|---|
| `allow` | String[] | Allowed IP addresses or CIDR ranges |
| `deny` | String[] | Denied IP addresses or CIDR ranges |

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

**Behavior by mode:**
- `limit_by: "ip"` — Enforces in `on_request_received` phase (before auth), keyed by client IP.
- `limit_by: "consumer"` — Enforces in `authorize` phase (after auth), keyed by consumer username. Falls back to client IP if no consumer.

**Rate limit headers** (when `expose_headers: true`): `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-window`, `x-ratelimit-identity`

Returns HTTP `429 Too Many Requests` when exceeded.

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

**Priority:** 100

| Parameter | Type | Default | Description |
|---|---|---|---|
| `blocked_patterns` | String[] | `["curl","wget","python-requests",...]` | User-Agent substrings to block |
| `allow_list` | String[] | `[]` | User-Agent substrings to always allow |
| `allow_missing_user_agent` | bool | `true` | Allow requests with no User-Agent header |
| `custom_response_code` | u16 | `403` | HTTP status code for blocked requests |

### `request_termination`

Returns a predefined response without proxying to the backend. Useful for maintenance mode.

**Priority:** 3000

| Parameter | Type | Description |
|---|---|---|
| `status_code` | u16 | HTTP status code to return |
| `body` | String | Response body |
| `content_type` | String | Response Content-Type header |
| `message` | String | Error message |

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

Validates JSON and XML request and response bodies against schemas. Supports comprehensive JSON Schema validation.

**Priority:** 3000

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

**Supported JSON Schema `format` values**: `email`, `ipv4`, `ipv6`, `uri`, `date-time`, `date`, `uuid`

### `request_size_limiting`

Enforces per-proxy request body size limits. Rejects with HTTP 413.

**Priority:** 3000

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_bytes` | u64 | `0` (disabled) | Maximum allowed request body size in bytes |

### `response_size_limiting`

Enforces per-proxy response body size limits. Rejects with HTTP 502.

**Priority:** 4000

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_bytes` | u64 | `0` (disabled) | Maximum allowed response body size in bytes |
| `require_buffered_check` | bool | `false` | Force response body buffering to verify actual size |

### `graphql`

GraphQL-aware proxying with query analysis, depth/complexity limiting, and per-operation rate limiting.

**Priority:** 2850

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_depth` | u32 (optional) | — | Maximum allowed query nesting depth |
| `max_complexity` | u32 (optional) | — | Maximum allowed field count |
| `max_aliases` | u32 (optional) | — | Maximum allowed alias count |
| `introspection_allowed` | bool | `true` | Whether introspection queries are permitted |
| `limit_by` | String | `ip` | Rate limit key: `ip` or `consumer` |
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

```yaml
plugin_name: ai_token_metrics
config:
  provider: auto
  cost_per_prompt_token: 0.000003
  cost_per_completion_token: 0.000012
```

### `ai_request_guard`

Validates and constrains AI/LLM API requests before they reach the backend.

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
| `limit_by` | String | `"consumer"` | Rate limit key: `consumer` or `ip` |
| `expose_headers` | Boolean | `false` | Inject `x-ai-ratelimit-*` headers |
| `provider` | String | `"auto"` | LLM provider format for token extraction |

```yaml
plugin_name: ai_rate_limiter
config:
  token_limit: 500000
  window_seconds: 3600
  limit_by: consumer
  expose_headers: true
```

### `ai_prompt_shield`

Scans AI/LLM request bodies for PII and either rejects, redacts, or warns.

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

## Custom Plugins

Ferrum supports drop-in custom plugins. Create a `.rs` file in the `custom_plugins/` directory, export a `create_plugin()` factory function, and rebuild — the build script auto-discovers and registers it.

Optionally set `FERRUM_CUSTOM_PLUGINS=plugin_a,plugin_b` at **build time** to include only specific custom plugins.

See [CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md) for the full developer guide, trait reference, and working examples.
