# Plugin Execution Order

Ferrum Gateway executes plugins in a deterministic order based on two dimensions: **lifecycle phases** and **priority within each phase**.

## Lifecycle Phases

Every request passes through six phases in strict order. Each phase has a specific purpose, and plugins only run in the phases they implement:

```
Request In
    │
    ▼
┌─────────────────────────┐
│ 1. on_request_received  │  Pre-processing: CORS preflight
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 2. authenticate         │  Identity verification: mTLS, JWT, OAuth2, API key, Basic
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 3. authorize            │  Access control, consumer rate limiting
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 4. before_proxy         │  Request transformation before backend call
└────────────┬────────────┘
             │
             ▼
       ┌───────────┐
       │  Backend   │  Actual HTTP call to upstream
       └─────┬─────┘
             │
             ▼
┌─────────────────────────┐
│ 5. after_proxy          │  Response transformation, CORS headers
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 6. log                  │  Logging & observability (fire-and-forget)
└─────────────────────────┘
```

Any plugin can short-circuit the pipeline by returning a `Reject` result. For example, CORS returns a `204` preflight response in phase 1 without ever reaching authentication. Rate limiting returns `429` in the authorize phase (phase 3) after the consumer is identified.

## Priority Bands

Within each lifecycle phase, plugins are sorted by **priority** (lower number runs first). Priority is intrinsic to each plugin — it is not user-configurable. Plugins at the same priority have no guaranteed relative order.

Priority bands are spaced with gaps so future plugins can slot in without renumbering:

| Band | Priority Range | Purpose | Plugins |
|------|---------------|---------|---------|
| **Early** | 0–999 | Pre-processing that must run before auth | `cors` (100), `ip_restriction` (150), `bot_detection` (200) |
| **AuthN** | 950–1999 | Authentication / identity verification | `mtls_auth` (950), `oauth2_auth` (1000), `jwt_auth` (1100), `key_auth` (1200), `basic_auth` (1300), `hmac_auth` (1400) |
| **AuthZ** | 2000–2999 | Authorization & post-auth enforcement | `access_control` (2000), `graphql` (2850), `rate_limiting` (2900) |
| **Transform** | 3000–3999 | Request modification before backend call | `request_transformer` (3000), `body_validator` (3100), `request_termination` (3200) |
| **Response** | 4000–4999 | Response modification after backend call | `response_transformer` (4000) |
| **Custom** | 5000 | Default for unrecognized/custom plugins | _(future plugins)_ |
| **Logging** | 9000–9999 | Observability, runs outside the hot path | `stdout_logging` (9000), `correlation_id` (9050), `http_logging` (9100), `transaction_debugger` (9200), `prometheus_metrics` (9300), `otel_tracing` (9400) |

## Complete Execution Order

Given all built-in plugins enabled, the execution order is:

| # | Plugin | Priority | Active Phases |
|---|--------|----------|---------------|
| 1 | `cors` | 100 | on_request_received, after_proxy |
| 2 | `ip_restriction` | 150 | on_request_received |
| 3 | `bot_detection` | 200 | on_request_received |
| 4 | `mtls_auth` | 950 | authenticate |
| 5 | `oauth2_auth` | 1000 | authenticate |
| 6 | `jwt_auth` | 1100 | authenticate |
| 7 | `key_auth` | 1200 | authenticate |
| 8 | `basic_auth` | 1300 | authenticate |
| 9 | `hmac_auth` | 1400 | authenticate |
| 10 | `access_control` | 2000 | authorize |
| 11 | `graphql` | 2850 | before_proxy |
| 12 | `rate_limiting` | 2900 | on_request_received (IP mode), authorize (consumer mode) |
| 13 | `request_transformer` | 3000 | before_proxy |
| 14 | `body_validator` | 3100 | before_proxy, on_response_body |
| 15 | `request_termination` | 3200 | before_proxy |
| 16 | `response_transformer` | 4000 | after_proxy |
| 17 | `stdout_logging` | 9000 | log |
| 18 | `correlation_id` | 9050 | on_request_received, log |
| 19 | `http_logging` | 9100 | log |
| 20 | `transaction_debugger` | 9200 | on_request_received, after_proxy, log |
| 21 | `prometheus_metrics` | 9300 | after_proxy, log |
| 22 | `otel_tracing` | 9400 | on_request_received, after_proxy |

## Why This Order Matters

### CORS runs first (priority 100)

Browser preflight (`OPTIONS`) requests must be answered before authentication. If an auth plugin ran first, it would reject the preflight with `401` and the browser would never complete the CORS handshake. CORS at priority 100 ensures preflight responses are returned immediately.

### Authentication before authorization (1000s before 2000s)

Authentication plugins identify *who* the caller is (setting `ctx.identified_consumer`). Authorization plugins like `access_control` then decide *whether* that consumer is allowed. Running auth first is required — ACL checks are meaningless without a verified identity.

After all plugin phases complete, the gateway automatically injects `X-Consumer-Username` (and `X-Consumer-Custom-Id` when set) headers into the request forwarded to the backend, so upstream services can identify the authenticated caller.

### Rate limiting runs after auth (priority 2900)

Rate limiting sits at the end of the AuthZ band (priority 2900) so it can enforce limits by **authenticated consumer identity**, not just by IP address. When `limit_by: "consumer"`, the plugin needs `ctx.identified_consumer` which is only available after the authenticate phase.

**Dual-phase behavior:**
- `limit_by: "ip"` — enforces IP-based limits in `on_request_received` (phase 1, before auth). This protects auth endpoints from brute-force attacks.
- `limit_by: "consumer"` — enforces consumer-based limits in `authorize` (phase 3, after auth). If no consumer is identified (unauthenticated request), falls back to IP-based keying.

**Header exposure** (`expose_headers: true`): When enabled, the plugin injects `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-window`, and `x-ratelimit-identity` headers on both upstream requests (`before_proxy`) and downstream responses (`after_proxy`). This lets backends and clients see current rate-limit state without additional lookups. Disabled by default so gateway admins control whether limit details are exposed.

### Transforms after auth (3000+)

Request transformers run after authentication and authorization, so they only modify requests that are already permitted. This prevents wasted transformation work on requests that will be rejected.

### Logging runs last (9000+)

Logging plugins run in phase 6 (`log`) which is fire-and-forget after the response is sent to the client. They are outside the hot path and do not affect request latency. Their relative ordering within the logging band (9000–9200) does not impact behavior.

All logging plugins receive the `TransactionSummary` struct which includes an `error_class` field for failed transactions. This field classifies gateway-level errors (e.g., `ConnectionTimeout`, `TlsError`, `DnsLookupError`) to help operators quickly identify root causes. See [docs/error_classification.md](error_classification.md) for the full list of error classes and debugging guidance.

## Adding a New Plugin

When implementing a new plugin, choose a priority that places it in the correct band:

```rust
impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }

    fn priority(&self) -> u16 {
        // Pick a value in the appropriate band:
        // 0-999: pre-processing (before auth)
        // 1000-1999: authentication
        // 2000-2999: authorization / post-auth enforcement
        // 3000-3999: request transformation
        // 4000-4999: response transformation
        // 9000-9999: logging
        500  // Example: runs after CORS (100), before auth (1000+)
    }

    // Declare which protocols this plugin supports.
    // Default is HTTP_ONLY_PROTOCOLS. Use one of the predefined constants:
    //   ALL_PROTOCOLS           — HTTP, gRPC, WebSocket, TCP, UDP
    //   HTTP_FAMILY_PROTOCOLS   — HTTP, gRPC, WebSocket
    //   HTTP_GRPC_PROTOCOLS     — HTTP, gRPC
    //   HTTP_ONLY_PROTOCOLS     — HTTP only (default)
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS  // Example: this plugin works with all protocols
    }

    // If your plugin makes outbound HTTP calls to a configured endpoint,
    // override warmup_hostnames() so the endpoint is pre-resolved at startup
    // via the gateway's shared DNS cache:
    fn warmup_hostnames(&self) -> Vec<String> {
        vec!["my-endpoint.example.com".to_string()]
    }
}
```

### Response Body Buffering

If your plugin needs access to the full response body (e.g., for body-level transformation or inspection), override `requires_response_body_buffering()` to return `true`. This forces the gateway to buffer the entire backend response before forwarding it to the client, even when the proxy's `response_body_mode` is set to `stream`.

```rust
impl Plugin for MyBodyPlugin {
    fn name(&self) -> &str { "my_body_plugin" }

    fn requires_response_body_buffering(&self) -> bool {
        true  // Forces response buffering for this proxy
    }
}
```

By default, this method returns `false`. When `response_transformer` has body transformation rules configured (`target: "body"`), it automatically returns `true` from this method, forcing buffering so the JSON body can be parsed and rewritten. When only header rules are configured, it returns `false` and works with streaming mode. See [docs/response_body_streaming.md](response_body_streaming.md) for the full streaming architecture.

Add the constant to `src/plugins/mod.rs` in the `priority` module for discoverability:

```rust
pub mod priority {
    pub const MY_PLUGIN: u16 = 500;
    // ...
}
```

The default priority is `5000` (the Custom band), which runs after all transforms but before logging. This is a safe default for plugins that don't have strong ordering requirements.

## Protocol Support

Each plugin declares which proxy protocols it supports via `supported_protocols()`. The gateway skips plugins that don't support the current proxy's protocol — for example, CORS is never invoked for a TCP stream proxy.

TLS/DTLS are transport-layer concerns, not separate protocols. A plugin that supports `Tcp` also supports TCP+TLS, and a plugin that supports `Udp` also supports UDP+DTLS.

| Protocol | Description |
|----------|-------------|
| `Http` | HTTP/1.1, HTTP/2, HTTP/3 (includes HTTPS) |
| `Grpc` | gRPC / gRPCs (HTTP/2-based RPC) |
| `WebSocket` | WS / WSS |
| `Tcp` | Raw TCP stream proxy (includes TLS termination/origination) |
| `Udp` | Raw UDP datagram proxy (includes DTLS termination/origination) |

### Per-Plugin Protocol Matrix

| Plugin | Http | Grpc | WebSocket | Tcp | Udp | Rationale |
|--------|:----:|:----:|:---------:|:---:|:---:|-----------|
| `cors` | ✓ | | | | | HTTP-only concept (Origin/ACAO headers) |
| `ip_restriction` | ✓ | ✓ | ✓ | ✓ | ✓ | IP filtering is protocol-agnostic |
| `bot_detection` | ✓ | ✓ | ✓ | | | Needs User-Agent header |
| `mtls_auth` | ✓ | ✓ | ✓ | | | Requires TLS client certificate |
| `oauth2_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `jwt_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `key_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `basic_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `hmac_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `access_control` | ✓ | ✓ | ✓ | | | Needs consumer identity (auth not available on TCP/UDP) |
| `graphql` | ✓ | | | | | GraphQL is HTTP-only (JSON body parsing) |
| `rate_limiting` | ✓ | ✓ | ✓ | ✓ | ✓ | Connection/session rate applies everywhere |
| `request_transformer` | ✓ | ✓ | | | | Modifies HTTP headers/query/body |
| `body_validator` | ✓ | ✓ | | | | Validates request and response bodies |
| `request_termination` | ✓ | ✓ | ✓ | | | Returns HTTP error response |
| `response_transformer` | ✓ | ✓ | | | | Modifies HTTP response headers/body |
| `stdout_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `correlation_id` | ✓ | ✓ | ✓ | ✓ | ✓ | ID assignment is protocol-agnostic |
| `http_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `transaction_debugger` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `prometheus_metrics` | ✓ | ✓ | ✓ | ✓ | ✓ | Metrics for all protocols |
| `otel_tracing` | ✓ | ✓ | ✓ | ✓ | ✓ | Tracing for all protocols |

Protocol-filtered plugin lists are pre-computed in `PluginCache` at config reload time, so there is zero filtering cost on the hot path.

## Body Transformation

Both `request_transformer` and `response_transformer` support JSON body field manipulation using dot-notation paths. Use `"target": "body"` in the rules array alongside existing header and query rules.

### Configuration

```json
{
  "rules": [
    {"operation": "rename", "target": "body", "key": "user.old_field", "new_key": "user.new_field"},
    {"operation": "remove", "target": "body", "key": "internal.debug_info"},
    {"operation": "add", "target": "body", "key": "metadata.version", "value": "v2"},
    {"operation": "update", "target": "body", "key": "user.role", "value": "admin"}
  ]
}
```

### Dot-Notation Paths

Fields are referenced using dot-delimited paths that navigate nested JSON objects:

| Path | Targets |
|------|---------|
| `name` | `{"name": "..."}` |
| `user.email` | `{"user": {"email": "..."}}` |
| `a.b.c.d` | `{"a": {"b": {"c": {"d": "..."}}}}` |

### Operations

| Operation | Behavior |
|-----------|----------|
| `add` | Insert field only if it doesn't already exist. Creates intermediate objects as needed. |
| `update` | Always set the field value (overwrites if exists, creates if not). |
| `remove` | Delete the field at the given path. |
| `rename` | Move the value from `key` path to `new_key` path (both use dot notation). |

### Value Parsing

String values in the `"value"` field are parsed as JSON when possible:
- `"42"` → number `42`
- `"true"` → boolean `true`
- `"{\"a\":1}"` → object `{"a": 1}`
- `"hello"` → string `"hello"` (not valid JSON, kept as string)

Non-string JSON values (numbers, booleans, objects, arrays) in the config are used directly.

### Content-Type Awareness

Body transformation only applies to JSON bodies (detected by `Content-Type` containing `application/json` or `+json`). Non-JSON bodies are passed through unchanged.

### Performance Notes

- Body rules are parsed once at config load time, not per-request.
- When `response_transformer` has body rules, it automatically enables response body buffering for the proxy. Without body rules, responses stream through with zero overhead.
- `request_transformer` body transformation runs after the request body is collected and before it is sent to the backend (HTTP/1.1 and HTTPS paths).
- Header, query, and body rules can be mixed in a single plugin configuration.

## gRPC Compatibility

All plugins in the execution pipeline work transparently with gRPC requests. gRPC metadata maps directly to HTTP/2 headers, so:

- **Authentication plugins** (JWT, OAuth2, API key, Basic) inspect the `authorization` header, which gRPC clients send as metadata.
- **Rate limiting** works identically for gRPC — keyed by IP or consumer identity.
- **Request/Response transformers** can add, modify, or remove gRPC metadata (HTTP/2 headers).
- **Logging plugins** receive the same `TransactionSummary` with the gRPC path (e.g., `/my.Service/MyMethod`) and HTTP status.

gRPC requests are detected by their `content-type: application/grpc` header and routed to the dedicated gRPC proxy path, which uses hyper's HTTP/2 client for trailer forwarding. The plugin pipeline runs before and after the gRPC backend call, just like HTTP requests.
