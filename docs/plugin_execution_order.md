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
│ 2. authenticate         │  Identity verification: JWT, OAuth2, API key, Basic
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
| **Early** | 0–999 | Pre-processing that must run before auth | `cors` (100) |
| **AuthN** | 1000–1999 | Authentication / identity verification | `oauth2_auth` (1000), `jwt_auth` (1100), `key_auth` (1200), `basic_auth` (1300) |
| **AuthZ** | 2000–2999 | Authorization & post-auth enforcement | `access_control` (2000), `rate_limiting` (2900) |
| **Transform** | 3000–3999 | Request modification before backend call | `request_transformer` (3000) |
| **Response** | 4000–4999 | Response modification after backend call | `response_transformer` (4000) |
| **Custom** | 5000 | Default for unrecognized/custom plugins | _(future plugins)_ |
| **Logging** | 9000–9999 | Observability, runs outside the hot path | `stdout_logging` (9000), `http_logging` (9100), `transaction_debugger` (9200) |

## Complete Execution Order

Given all built-in plugins enabled, the execution order is:

| # | Plugin | Priority | Active Phases |
|---|--------|----------|---------------|
| 1 | `cors` | 100 | on_request_received, after_proxy |
| 2 | `oauth2_auth` | 1000 | authenticate |
| 3 | `jwt_auth` | 1100 | authenticate |
| 4 | `key_auth` | 1200 | authenticate |
| 5 | `basic_auth` | 1300 | authenticate |
| 6 | `access_control` | 2000 | authorize |
| 7 | `rate_limiting` | 2900 | on_request_received (IP mode), authorize (consumer mode) |
| 8 | `request_transformer` | 3000 | before_proxy |
| 9 | `response_transformer` | 4000 | after_proxy |
| 10 | `stdout_logging` | 9000 | log |
| 11 | `http_logging` | 9100 | log |
| 12 | `transaction_debugger` | 9200 | on_request_received, after_proxy, log |

## Why This Order Matters

### CORS runs first (priority 100)

Browser preflight (`OPTIONS`) requests must be answered before authentication. If an auth plugin ran first, it would reject the preflight with `401` and the browser would never complete the CORS handshake. CORS at priority 100 ensures preflight responses are returned immediately.

### Authentication before authorization (1000s before 2000s)

Authentication plugins identify *who* the caller is (setting `ctx.identified_consumer`). Authorization plugins like `access_control` then decide *whether* that consumer is allowed. Running auth first is required — ACL checks are meaningless without a verified identity.

### Rate limiting runs after auth (priority 2900)

Rate limiting sits at the end of the AuthZ band (priority 2900) so it can enforce limits by **authenticated consumer identity**, not just by IP address. When `limit_by: "consumer"`, the plugin needs `ctx.identified_consumer` which is only available after the authenticate phase.

**Dual-phase behavior:**
- `limit_by: "ip"` — enforces IP-based limits in `on_request_received` (phase 1, before auth). This protects auth endpoints from brute-force attacks.
- `limit_by: "consumer"` — enforces consumer-based limits in `authorize` (phase 3, after auth). If no consumer is identified (unauthenticated request), falls back to IP-based keying.

### Transforms after auth (3000+)

Request transformers run after authentication and authorization, so they only modify requests that are already permitted. This prevents wasted transformation work on requests that will be rejected.

### Logging runs last (9000+)

Logging plugins run in phase 6 (`log`) which is fire-and-forget after the response is sent to the client. They are outside the hot path and do not affect request latency. Their relative ordering within the logging band (9000–9200) does not impact behavior.

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

By default, this method returns `false`. Existing plugins like `response_transformer` only modify headers (not the body), so they work with both streaming and buffered modes without overriding this method. See [docs/response_body_streaming.md](response_body_streaming.md) for the full streaming architecture.

Add the constant to `src/plugins/mod.rs` in the `priority` module for discoverability:

```rust
pub mod priority {
    pub const MY_PLUGIN: u16 = 500;
    // ...
}
```

The default priority is `5000` (the Custom band), which runs after all transforms but before logging. This is a safe default for plugins that don't have strong ordering requirements.

## gRPC Compatibility

All plugins in the execution pipeline work transparently with gRPC requests. gRPC metadata maps directly to HTTP/2 headers, so:

- **Authentication plugins** (JWT, OAuth2, API key, Basic) inspect the `authorization` header, which gRPC clients send as metadata.
- **Rate limiting** works identically for gRPC — keyed by IP or consumer identity.
- **Request/Response transformers** can add, modify, or remove gRPC metadata (HTTP/2 headers).
- **Logging plugins** receive the same `TransactionSummary` with the gRPC path (e.g., `/my.Service/MyMethod`) and HTTP status.

gRPC requests are detected by their `content-type: application/grpc` header and routed to the dedicated gRPC proxy path, which uses hyper's HTTP/2 client for trailer forwarding. The plugin pipeline runs before and after the gRPC backend call, just like HTTP requests.
