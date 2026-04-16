# Custom Plugin Development Guide

This guide explains how to create, register, and build custom plugins for Ferrum Edge without modifying any core source files.

## Architecture Overview

Ferrum Edge uses a trait-based plugin system. All plugins implement the `Plugin` trait, which defines lifecycle hooks that the gateway calls during request processing.

### HTTP/gRPC/WebSocket Lifecycle

```
Request received
  │
  ▼
on_request_received()           ── can reject
  │
  ▼
Route matching
  │
  ▼
authenticate()                  ── can reject (auth plugins only)
  │
  ▼
authorize()                     ── can reject
  │
  ▼
before_proxy()                  ── can reject, can modify headers
  │
  ▼
transform_request_body()        ── can transform request body (buffered only)
  │
  ▼
on_final_request_body()         ── can reject (post-transform validation)
  │
  ▼
Proxy to backend
  │
  ▼
after_proxy()                   ── can reject, can modify response headers
  │
  ▼
on_response_body()              ── can reject (buffered responses only)
  │
  ▼
transform_response_body()       ── can transform response body (buffered only)
  │
  ▼
on_final_response_body()        ── can reject (post-transform validation)
  │
  ▼
log()                           ── fire-and-forget
  │
  ▼
Response sent to client
```

### WebSocket Frame Lifecycle (per-frame, after upgrade)

```
on_ws_frame()  ── inspect/transform/close per WebSocket frame
```

### TCP/UDP Stream Lifecycle

```
Stream connection established (TLS handshake complete for TCP+TLS)
  │
  ▼
on_stream_connect()             ── can reject (auth, authz, throttle)
  │
  ▼
Bidirectional data forwarding
  │
  ▼
on_stream_disconnect()          ── fire-and-forget (logging, metrics)
```

## Quick Start

### 1. Create your plugin file

Create a new `.rs` file in the `custom_plugins/` directory at the project root. The file name becomes the plugin name (e.g., `my_header_injector.rs` → plugin name `my_header_injector`).

Each plugin file must export a `create_plugin` factory function that returns `Result`:

```rust
// custom_plugins/my_header_injector.rs

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};

pub struct MyHeaderInjector {
    header_name: String,
    header_value: String,
}

impl MyHeaderInjector {
    // Constructor MUST return Result<Self, String>.
    // Return Err for invalid or missing required config values.
    pub fn new(config: &Value) -> Result<Self, String> {
        Ok(Self {
            header_name: config["header_name"]
                .as_str()
                .unwrap_or("X-My-Header")
                .to_string(),
            header_value: config["header_value"]
                .as_str()
                .unwrap_or("hello")
                .to_string(),
        })
    }
}

#[async_trait]
impl Plugin for MyHeaderInjector {
    fn name(&self) -> &str {
        "my_header_injector"  // Must match the file name
    }

    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        headers.insert(self.header_name.clone(), self.header_value.clone());
        PluginResult::Continue
    }
}

/// Required factory function — the build script calls this automatically.
/// Must return Result so invalid configs are rejected at admission time
/// (admin API returns 400, file mode fails startup, DB mode logs warnings).
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(MyHeaderInjector::new(config)?)))
}
```

### Config Validation Rules

Your `new()` constructor must validate the plugin config and return `Err(String)` when:

- **Required fields are missing** — if the plugin cannot function without a field, return an error (don't silently default to a no-op).
- **Values are invalid** — reject malformed regexes, unknown enum variants, out-of-range numbers, unparseable URLs.
- **The plugin would have no effect** — e.g., a rate limiter with no rate windows, a size limiter with `max_bytes=0`, a transformer with no rules.

Sensible defaults for optional fields (e.g., `limit_by` defaulting to `"ip"`) are fine — only return `Err` for fields where there is no safe default.

This validation is enforced at three levels:
1. **Admin API** — `create_plugin()` is called at create/update time; errors return HTTP 400.
2. **File mode** — each enabled plugin is instantiated at startup; errors are fatal.
3. **Database mode** — each enabled plugin is instantiated at load time; errors are warned.

### 2. Build

```bash
cargo build --release
```

That's it. The build script automatically discovers your file, declares the module, and registers it in the plugin factory. No registry file to edit, no core files modified.

### Filtering plugins (optional)

To include only specific custom plugins, set `FERRUM_CUSTOM_PLUGINS` at **build time**:

```bash
FERRUM_CUSTOM_PLUGINS=my_header_injector,my_auth cargo build --release
```

If unset, all `.rs` files in `custom_plugins/` are included.

### 4. Configure

Add your plugin to the gateway config (YAML or database):

```yaml
plugin_configs:
  - id: "my-header-plugin-1"
    plugin_name: "my_header_injector"
    enabled: true
    scope: "global"
    config:
      header_name: "X-Powered-By"
      header_value: "my-company"
```

## Plugin Trait Reference

Every plugin implements the `Plugin` trait from `src/plugins/mod.rs`. All methods have default implementations, so you only need to override the ones relevant to your plugin.

### Required Methods

| Method | Description |
|--------|-------------|
| `fn name(&self) -> &str` | Unique identifier for your plugin. Must match the config `plugin_name` and the file name. |

### Lifecycle Hooks — HTTP/gRPC/WebSocket

| Method | Phase | Can Reject? | Typical Use |
|--------|-------|-------------|-------------|
| `on_request_received(&mut ctx)` | Pre-routing | Yes | IP filtering, request validation, early termination |
| `authenticate(&mut ctx, &consumer_index)` | Authentication | Yes | Verify identity (JWT, API key, custom tokens) |
| `authorize(&mut ctx)` | Authorization | Yes | Check permissions, enforce rate limits |
| `before_proxy(&mut ctx, &mut headers)` | Pre-backend | Yes | Transform request headers, add tracing IDs. **Read request headers from `headers`, not `ctx.headers`** (see note below) |
| `transform_request_body(&body, content_type)` | Pre-backend (buffered) | No | Rewrite request body before sending to backend |
| `on_final_request_body(&headers, &body)` | Pre-backend (post-transform) | Yes | Validate the final request body after all transforms |
| `after_proxy(&mut ctx, status, &mut headers)` | Post-backend | Yes | Transform response headers, reject responses |
| `on_response_body(&mut ctx, status, &headers, &body)` | Post-backend (buffered) | Yes | Inspect buffered response body, extract metrics |
| `transform_response_body(&body, content_type)` | Post-backend (buffered) | No | Rewrite response body before sending to client |
| `on_final_response_body(&mut ctx, status, &headers, &body)` | Post-backend (post-transform) | Yes | Validate the final response body after all transforms |
| `log(&summary)` | Logging | No | Send transaction data to external systems |
| `on_ws_frame(proxy_id, connection_id, direction, &message)` | WebSocket frame | Close* | Inspect/transform per-frame WebSocket traffic |

\*`on_ws_frame` cannot return `PluginResult::Reject`. Instead, return `Some(Message::Close(...))` to close the connection in both directions. Return `None` for passthrough, or `Some(transformed_message)` to replace the frame.

**`before_proxy` header parameter**: In `before_proxy`, always read request headers from the `headers` parameter, **not** from `ctx.headers`. The proxy handler avoids cloning the headers HashMap when no plugin modifies them — it moves headers out of `ctx.headers` into the `headers` parameter via `std::mem::take()`, leaving `ctx.headers` empty during the call. After `before_proxy` completes, headers are moved back. This means `ctx.headers.get("content-type")` returns `None` inside `before_proxy`, while `headers.get("content-type")` returns the actual value. If your plugin calls helper methods that need request headers, pass the `headers` parameter through rather than reading `ctx.headers` in the helper. This only affects `before_proxy` — other phases like `authenticate` and `on_request_received` can safely read `ctx.headers`.

### Lifecycle Hooks — TCP/UDP Streams

| Method | Phase | Can Reject? | Typical Use |
|--------|-------|-------------|-------------|
| `on_stream_connect(&mut stream_ctx)` | Connection established | Yes | Auth, authz, throttling, rate limiting for stream proxies |
| `on_stream_disconnect(&stream_summary)` | Connection closed | No | Logging, metrics for stream proxies |

For TCP+TLS proxies, `on_stream_connect` runs **after** the frontend TLS handshake, so client cert data is available in `StreamConnectionContext`.

### Capability Methods

| Method | Default | Description |
|--------|---------|-------------|
| `fn priority(&self) -> u16` | `5000` | Execution order (lower = earlier). See priority bands below. |
| `fn supported_protocols(&self) -> &'static [ProxyProtocol]` | `HTTP_ONLY_PROTOCOLS` | Which proxy protocols this plugin supports. See protocol constants below. |
| `fn is_auth_plugin(&self) -> bool` | `false` | Set to `true` if your plugin participates in the authentication phase. |
| `fn modifies_request_headers(&self) -> bool` | `false` | Set to `true` if your plugin modifies outgoing request headers in `before_proxy`. |
| `fn modifies_request_body(&self) -> bool` | `false` | Set to `true` if your plugin transforms the request body via `transform_request_body`. |
| `fn requires_request_body_before_before_proxy(&self) -> bool` | `false` | Set to `true` if your plugin needs the raw request body available during `before_proxy`. |
| `fn requires_request_body_buffering(&self) -> bool` | Derived | By default returns `true` if `modifies_request_body()` or `requires_request_body_before_before_proxy()`. Override for custom logic. |
| `fn should_buffer_request_body(&self, &ctx) -> bool` | Delegates | Per-request decision on whether to buffer. Defaults to `requires_request_body_buffering()`. Override for conditional buffering (e.g., only for certain content types). |
| `fn requires_response_body_buffering(&self) -> bool` | `false` | Set to `true` if your plugin needs the entire response body buffered. Disables streaming for the proxy. |
| `fn applies_after_proxy_on_reject(&self) -> bool` | `false` | Set to `true` if your plugin's `after_proxy` should also run on gateway-generated rejection responses (e.g., CORS headers on error responses). |
| `fn requires_ws_frame_hooks(&self) -> bool` | `false` | Set to `true` if your plugin implements `on_ws_frame()`. Pre-computed per proxy for zero overhead when unused. |
| `fn warmup_hostnames(&self) -> Vec<String>` | `[]` | Hostnames your plugin connects to (for DNS pre-warming at startup). |
| `fn tracked_keys_count(&self) -> Option<usize>` | `None` | Number of tracked rate-limit keys (for admin API diagnostics). |

### Request Body Buffering — Two-Tier System

Request body buffering uses a two-tier system to avoid unnecessary buffering:

1. **Config-time**: `requires_request_body_buffering()` determines if a proxy *may* need buffering (pre-computed in `PluginCache`).
2. **Request-time**: `should_buffer_request_body(&ctx)` decides per-request whether to actually buffer.

Only plugins that read the body (GraphQL validation, body validation, AI request guard, AI prompt shield) trigger buffering. Transform-only plugins do not force early prebuffering.

## Protocol Constants

Use these constants in `supported_protocols()` to declare which proxy protocols your plugin supports:

| Constant | Protocols | Use Case |
|----------|-----------|----------|
| `ALL_PROTOCOLS` | Http, Grpc, WebSocket, Tcp, Udp | Protocol-agnostic plugins (logging, metrics, tracing) |
| `HTTP_FAMILY_PROTOCOLS` | Http, Grpc, WebSocket | Plugins for all HTTP-based protocols |
| `HTTP_FAMILY_AND_TCP_PROTOCOLS` | Http, Grpc, WebSocket, Tcp | HTTP family plus raw TCP streams |
| `HTTP_GRPC_PROTOCOLS` | Http, Grpc | Plugins for HTTP and gRPC only |
| `HTTP_ONLY_PROTOCOLS` | Http | HTTP-only plugins (default) |
| `GRPC_ONLY_PROTOCOLS` | Grpc | gRPC-specific plugins |
| `WS_ONLY_PROTOCOLS` | WebSocket | WebSocket frame-level plugins |
| `TCP_ONLY_PROTOCOLS` | Tcp | TCP stream-only plugins |

## Priority Bands

Plugins execute in priority order (lowest number first) within each lifecycle phase. Choose a priority that places your plugin in the correct band:

| Band | Range | Purpose | Built-in Examples |
|------|-------|---------|-------------------|
| Observability | 0–99 | Tracing, correlation | otel_tracing (25), correlation_id (50) |
| Preflight | 100–999 | CORS, IP filtering, termination, bot detection | cors (100), request_termination (125), ip_restriction (150), bot_detection (200), grpc_method_router (275) |
| Authentication | 950–1499 | Identity verification | mtls_auth (950), jwks_auth (1000), jwt_auth (1100), key_auth (1200), basic_auth (1300), hmac_auth (1400) |
| Authorization | 2000–2099 | Access control, throttling | access_control (2000), tcp_connection_throttle (2050) |
| Request Validation | 2800–2999 | Size limits, rate limits, body validation | request_size_limiting (2800), ws_message_size_limiting (2810), graphql (2850), rate_limiting (2900), ws_rate_limiting (2910), ai_prompt_shield (2925), body_validator (2950), ai_request_guard (2975) |
| Request Transform | 3000–3099 | Modify request before backend | request_transformer (3000), grpc_deadline (3050) |
| Response Validation | 3400–3599 | Response size limits, caching | response_size_limiting (3490), response_caching (3500) |
| Response Transform | 4000–4299 | Modify response, metrics | response_transformer (4000), ai_token_metrics (4100), ai_rate_limiter (4200) |
| **Custom Default** | **5000** | **Default for custom plugins** | — |
| Logging | 9000–9999 | Observability, metrics | stdout_logging (9000), ws_frame_logging (9050), statsd_logging (9075), http_logging (9100), tcp_logging (9125), kafka_logging (9150), loki_logging (9155), udp_logging (9160), ws_logging (9175), transaction_debugger (9200), prometheus (9300) |

To set a priority, override the `priority()` method:

```rust
fn priority(&self) -> u16 {
    3500  // Runs after request_transformer but before response_transformer
}
```

## Writing an Authentication Plugin

Authentication plugins participate in the gateway's auth mode logic (Single vs Multi). To create one:

1. Override `is_auth_plugin()` to return `true`
2. Implement the `authenticate()` method
3. Set priority in the 950–1499 range

```rust
use crate::consumer_index::ConsumerIndex;

#[async_trait]
impl Plugin for MyCustomAuth {
    fn name(&self) -> &str { "my_custom_auth" }

    fn is_auth_plugin(&self) -> bool { true }

    fn priority(&self) -> u16 { 1500 }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        // Extract credentials from the request
        let token = match ctx.headers.get("x-custom-token") {
            Some(t) => t.clone(),
            None => return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Missing X-Custom-Token header"}"#.to_string(),
                headers: HashMap::new(),
            },
        };

        // Look up the consumer by credential
        // ConsumerIndex provides O(1) lookups by credential type
        for consumer in consumer_index.consumers().iter() {
            if let Some(cred) = consumer.credentials.get("custom_token") {
                if cred.as_str() == Some(token.as_str()) {
                    ctx.identified_consumer = Some(consumer.clone());
                    return PluginResult::Continue;
                }
            }
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid token"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}
```

### Auth Modes

The gateway supports two authentication modes per proxy:

- **Single** (default): Auth plugins run sequentially. First failure rejects the request.
- **Multi**: All auth plugins run. First success wins (sets the consumer). If all fail, the request is rejected. Multi-auth recognizes both `ctx.identified_consumer` (consumer-backed auth) and `ctx.authenticated_identity` (external JWKS/OIDC identity) as successful authentication.

Your auth plugin works with both modes automatically — just implement `authenticate()` and return `Continue` on success or `Reject` on failure.

### External Identity Support

For auth plugins that verify external identities (e.g., OIDC/JWKS tokens) without mapping to a gateway Consumer, set `ctx.authenticated_identity` instead of `ctx.identified_consumer`:

```rust
// When the token is valid but no Consumer mapping exists:
ctx.authenticated_identity = Some("user@example.com".to_string());
// Optionally set a display name for the X-Consumer-Username backend header:
ctx.authenticated_identity_header = Some("Jane Doe".to_string());
```

The `authenticated_identity` is treated as a first-class principal across rate-limit keys, cache keys, log summaries, and backend identity-header injection on all protocol paths.

## Writing a Request Body Plugin

If your plugin needs to inspect or transform the request body, use the body buffering and transform hooks:

### Inspecting the Request Body

```rust
#[async_trait]
impl Plugin for MyBodyValidator {
    fn name(&self) -> &str { "my_body_validator" }

    fn requires_request_body_buffering(&self) -> bool {
        true  // Tells the gateway to buffer the request body
    }

    async fn on_final_request_body(
        &self,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Validate the final request body (after all transforms)
        if body.len() > 1_000_000 {
            return PluginResult::Reject {
                status_code: 413,
                body: r#"{"error":"Request body too large"}"#.to_string(),
                headers: HashMap::new(),
            };
        }
        PluginResult::Continue
    }
}
```

### Transforming the Request Body

```rust
#[async_trait]
impl Plugin for MyBodyTransformer {
    fn name(&self) -> &str { "my_body_transformer" }

    fn modifies_request_body(&self) -> bool {
        true  // Implies requires_request_body_buffering() = true
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Option<Vec<u8>> {
        // Return Some(new_body) to replace, None to leave unchanged
        if content_type == Some("application/json") {
            // Transform the JSON body...
            Some(transformed_bytes)
        } else {
            None  // Passthrough for non-JSON
        }
    }
}
```

## Writing a Response Body Plugin

### Inspecting the Response Body

```rust
#[async_trait]
impl Plugin for MyResponseInspector {
    fn name(&self) -> &str { "my_response_inspector" }

    fn requires_response_body_buffering(&self) -> bool {
        true  // Forces response buffering (disables streaming)
    }

    async fn on_response_body(
        &self,
        _ctx: &mut RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Inspect the raw backend response body (before transforms)
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Validate the final response body (after all transforms)
        PluginResult::Continue
    }
}
```

### Transforming the Response Body

```rust
async fn transform_response_body(
    &self,
    body: &[u8],
    content_type: Option<&str>,
) -> Option<Vec<u8>> {
    // Return Some(new_body) to replace, None to leave unchanged
    None
}
```

**Important**: Response body buffering disables streaming, increasing memory usage and latency. Use it sparingly.

## Writing a Stream Plugin (TCP/UDP)

Stream plugins handle raw TCP and UDP proxy connections. They use `StreamConnectionContext` (for connect) and `StreamTransactionSummary` (for disconnect):

```rust
use crate::plugins::{
    Plugin, PluginResult, StreamConnectionContext, StreamTransactionSummary,
    ProxyProtocol, ALL_PROTOCOLS,
};

#[async_trait]
impl Plugin for MyStreamPlugin {
    fn name(&self) -> &str { "my_stream_plugin" }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS  // Must include Tcp and/or Udp
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut StreamConnectionContext,
    ) -> PluginResult {
        // ctx.client_ip, ctx.proxy_id, ctx.listen_port, ctx.backend_protocol
        // ctx.tls_client_cert_der (available for TCP+TLS after handshake)
        // ctx.metadata — shared between connect and disconnect
        ctx.metadata.insert("connected_at".to_string(), "...".to_string());
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        // summary.duration_ms, summary.bytes_sent, summary.bytes_received
        // summary.metadata — carries forward from on_stream_connect
    }
}
```

## Writing a Stateful Plugin

Plugins are instantiated once and cached for the lifetime of the config. This means you can hold state across requests:

```rust
use dashmap::DashMap;
use std::sync::Arc;

pub struct MyRateLimiter {
    counts: Arc<DashMap<String, u64>>,
    max_requests: u64,
}

impl MyRateLimiter {
    pub fn new(config: &Value) -> Self {
        Self {
            counts: Arc::new(DashMap::new()),
            max_requests: config["max_requests"].as_u64().unwrap_or(100),
        }
    }
}
```

The `DashMap` state persists across requests because the `PluginCache` holds an `Arc<dyn Plugin>` for each plugin instance.

## Using the Shared HTTP Client

If your plugin needs to make outbound HTTP calls (webhooks, token introspection, external APIs), use the shared `PluginHttpClient` passed to the factory:

```rust
use crate::plugins::PluginHttpClient;

pub struct MyWebhookPlugin {
    http_client: PluginHttpClient,
    webhook_url: String,
}

impl MyWebhookPlugin {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Self {
        Self {
            http_client,
            webhook_url: config["webhook_url"]
                .as_str()
                .unwrap_or("http://localhost:8080/webhook")
                .to_string(),
        }
    }
}
```

Then in the factory function at the bottom of your plugin file:

```rust
pub fn create_plugin(
    config: &Value,
    http_client: PluginHttpClient,
) -> Option<Arc<dyn Plugin>> {
    Some(Arc::new(MyWebhookPlugin::new(config, http_client)))
}
```

The shared HTTP client provides:
- **Connection pooling and keepalive** from the gateway's core infrastructure
- **DNS caching** via the gateway's shared `DnsCache` (pre-warmed, TTL-based, stale-while-revalidate)
- **Slow-call logging** via `execute()` — logs a warning when calls exceed `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS`
- **Tracked timing** via `execute_tracked()` — accumulates external I/O time into `ctx.plugin_http_call_ns` for latency breakdown in transaction logs
- **TLS settings** — `tls_no_verify()` and `tls_ca_bundle_path()` expose the gateway's global TLS config for plugins that make non-HTTP connections (e.g., Redis)

If your plugin connects to external hostnames, also implement `warmup_hostnames()` so the gateway pre-resolves DNS at startup:

```rust
fn warmup_hostnames(&self) -> Vec<String> {
    if let Ok(url) = url::Url::parse(&self.webhook_url) {
        if let Some(host) = url.host_str() {
            return vec![host.to_string()];
        }
    }
    vec![]
}
```

## Plugin Configuration

Plugins receive their configuration as a `serde_json::Value` in the constructor. This is the `config` field from the `PluginConfig` resource:

```yaml
plugin_configs:
  - id: "my-plugin-1"
    plugin_name: "my_plugin"
    enabled: true
    scope: "global"              # or "proxy"
    proxy_id: "proxy-1"          # only if scope is "proxy"
    config:                      # <-- this is what your plugin receives
      setting_a: "value"
      setting_b: 42
      nested:
        key: "value"
```

### Scopes

- **Global**: Plugin runs for all proxies
- **Proxy**: Plugin runs only for the specified proxy. If a proxy-scoped plugin has the same name as a global one, the proxy-scoped version overrides the global one for that proxy.

## Request Context

The `RequestContext` is a mutable struct passed through all HTTP/gRPC/WebSocket lifecycle phases. Plugins can read and write to it:

```rust
pub struct RequestContext {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub matched_proxy: Option<Arc<Proxy>>,
    pub identified_consumer: Option<Consumer>,
    /// External identity set by JWKS/OIDC auth plugins when no Consumer mapping exists.
    /// Used as rate-limit key, cache key, and in transaction logs.
    pub authenticated_identity: Option<String>,
    /// Display name for the X-Consumer-Username backend header.
    /// Falls back to authenticated_identity when not set.
    pub authenticated_identity_header: Option<String>,
    pub timestamp_received: DateTime<Utc>,
    /// Extra metadata plugins can attach (inter-plugin communication)
    pub metadata: HashMap<String, String>,
    /// DER-encoded client certificate from mTLS handshake (first cert in chain).
    /// Shared via Arc to avoid cloning cert bytes on HTTP/2 connections.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded CA/intermediate certs from the client's TLS cert chain.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// Cumulative nanoseconds spent by plugins making external HTTP calls.
    pub plugin_http_call_ns: Arc<AtomicU64>,
}
```

**Helper methods:**
- `effective_identity()` — returns the stable identity (Consumer username preferred over external identity)
- `backend_consumer_username()` — returns the identity for the `X-Consumer-Username` backend header
- `backend_consumer_custom_id()` — returns the Consumer custom ID, if a gateway Consumer was resolved

### Inter-Plugin Communication

Use the `metadata` field to pass data between plugins. For example, a correlation ID plugin sets `metadata["request_id"]`, and a logging plugin reads it:

```rust
// In your plugin:
ctx.metadata.insert("my_custom_field".to_string(), "some_value".to_string());

// In a downstream plugin or logging:
if let Some(val) = ctx.metadata.get("my_custom_field") {
    // use val
}
```

## Stream Connection Context

The `StreamConnectionContext` is passed to `on_stream_connect` for TCP/UDP stream proxies:

```rust
pub struct StreamConnectionContext {
    pub client_ip: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub listen_port: u16,
    pub backend_protocol: BackendProtocol,
    pub consumer_index: Arc<ConsumerIndex>,
    pub identified_consumer: Option<Consumer>,
    pub authenticated_identity: Option<String>,
    pub metadata: HashMap<String, String>,
    /// DER-encoded client cert from frontend TLS handshake (TCP+TLS only).
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
}
```

Metadata set during `on_stream_connect` is carried through to `on_stream_disconnect` via `StreamTransactionSummary.metadata`.

## Transaction Summary

The `TransactionSummary` struct is passed to the `log()` hook:

```rust
pub struct TransactionSummary {
    pub timestamp_received: String,
    pub client_ip: String,
    pub consumer_username: Option<String>,
    pub http_method: String,
    pub request_path: String,
    pub matched_proxy_id: Option<String>,
    pub matched_proxy_name: Option<String>,
    pub backend_target_url: Option<String>,
    pub backend_resolved_ip: Option<String>,
    pub response_status_code: u16,
    pub latency_total_ms: f64,
    pub latency_gateway_processing_ms: f64,
    pub latency_backend_ttfb_ms: f64,
    pub latency_backend_total_ms: f64,        // -1.0 for streaming responses
    pub latency_plugin_execution_ms: f64,
    pub latency_plugin_external_io_ms: f64,
    pub latency_gateway_overhead_ms: f64,
    pub request_user_agent: Option<String>,
    pub response_streamed: bool,
    pub client_disconnected: bool,
    pub error_class: Option<ErrorClass>,
    // Response body streaming attribution (populated for streaming responses).
    // `error_class` covers pre-body failures (connect, TLS, headers);
    // `body_error_class` covers failures observed while streaming the body.
    pub body_error_class: Option<ErrorClass>,
    pub body_completed: bool,
    pub bytes_streamed_to_client: u64,
    pub metadata: HashMap<String, String>,
}
```

## Stream Transaction Summary

The `StreamTransactionSummary` struct is passed to `on_stream_disconnect`:

```rust
pub struct StreamTransactionSummary {
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    pub backend_target: String,
    pub backend_resolved_ip: Option<String>,
    pub protocol: String,
    pub listen_port: u16,
    pub duration_ms: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_error: Option<String>,
    pub error_class: Option<ErrorClass>,
    // Disconnect attribution. `disconnect_cause` disambiguates idle timeouts
    // from recv errors (before these fields, both presented as `error_class: None`).
    pub disconnect_direction: Option<Direction>,
    pub disconnect_cause: Option<DisconnectCause>,
    pub timestamp_connected: String,
    pub timestamp_disconnected: String,
    pub metadata: HashMap<String, String>,     // Carried from on_stream_connect
}
```

`Direction` and `DisconnectCause` live in `src/plugins/mod.rs` and serialize as snake_case:

```rust
pub enum Direction {
    ClientToBackend,   // serialized as "client_to_backend"
    BackendToClient,   // serialized as "backend_to_client"
    Unknown,           // serialized as "unknown"
}

pub enum DisconnectCause {
    IdleTimeout,       // serialized as "idle_timeout"
    RecvError,         // serialized as "recv_error"     (frontend recv failed)
    BackendError,      // serialized as "backend_error"  (backend recv failed)
    GracefulShutdown,  // serialized as "graceful_shutdown"
}
```

## PluginResult

All lifecycle hooks that can reject return `PluginResult`:

```rust
pub enum PluginResult {
    /// Continue to the next plugin/phase.
    Continue,
    /// Short-circuit: immediately return this response to the client.
    Reject {
        status_code: u16,
        body: String,
        headers: HashMap<String, String>,
    },
}
```

For `application/grpc` requests, plugin rejects are automatically converted to trailers-only gRPC errors (`HTTP 200` + `grpc-status` / `grpc-message`) rather than raw HTTP error responses.

## Directory Structure

```
ferrum-edge/
├── src/                       # Core gateway source (do not edit for custom plugins)
│   ├── plugins/
│   │   ├── mod.rs             # Plugin trait, factory (auto-delegates to custom_plugins)
│   │   ├── jwt_auth.rs        # Built-in plugins...
│   │   └── ...
│   ├── config/
│   │   └── migrations/
│   │       └── mod.rs         # MigrationRunner + CustomPluginMigration type
│   ├── main.rs
│   └── lib.rs
├── build.rs                   # Auto-discovers plugins + migrations at compile time
├── custom_plugins/            # YOUR PLUGINS GO HERE — just drop .rs files
│   ├── mod.rs                 # Thin shim (includes build-script-generated code)
│   ├── example_plugin.rs      # Working example — header injection (can be removed)
│   ├── example_audit_plugin.rs # Working example — database migrations (can be removed)
│   ├── my_header_injector.rs  # Your plugin
│   └── my_custom_auth.rs      # Your plugin
├── CUSTOM_PLUGINS.md          # This guide
└── Cargo.toml
```

## Database Migrations

Custom plugins that need their own database tables can declare migrations that run alongside the gateway's core schema migrations. This uses the same `FERRUM_MODE=migrate` infrastructure, with a separate tracking table (`_ferrum_plugin_migrations`) so plugin version numbers are scoped per-plugin and never conflict with core migrations.

> **MongoDB note:** The `CustomPluginMigration` system is SQL-only. When `FERRUM_DB_TYPE=mongodb`, custom plugin SQL migrations are skipped. Custom plugins that need MongoDB-specific collections or indexes should create them in their `create_plugin()` initialization function using the MongoDB driver's idempotent `createIndex` API. Prefix collection names with the plugin name to avoid collisions (e.g., `my_plugin_audit_log`).

### How It Works

1. Export a `plugin_migrations()` function from your plugin file
2. The build script detects it automatically (no registration needed)
3. Run `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` to apply pending migrations
4. Plugin migrations run after core migrations in the same database transaction

### Declaring Migrations

Add a `plugin_migrations()` function to your plugin file that returns a `Vec<CustomPluginMigration>`:

```rust
use crate::config::migrations::CustomPluginMigration;

pub fn plugin_migrations() -> Vec<CustomPluginMigration> {
    vec![
        CustomPluginMigration {
            version: 1,
            name: "create_my_table",
            checksum: "v1_create_my_table_a1b2c3",
            sql: r#"
                CREATE TABLE IF NOT EXISTS my_plugin_data (
                    id TEXT PRIMARY KEY,
                    proxy_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_my_plugin_data_proxy
                    ON my_plugin_data (proxy_id)
            "#,
            sql_postgres: None,  // Use default SQL
            sql_mysql: None,     // Use default SQL
        },
        CustomPluginMigration {
            version: 2,
            name: "add_ttl_column",
            checksum: "v2_add_ttl_col_d4e5f6",
            sql: "ALTER TABLE my_plugin_data ADD COLUMN ttl_seconds INTEGER",
            sql_postgres: None,
            sql_mysql: None,
        },
    ]
}
```

### CustomPluginMigration Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | `i64` | Migration version number, scoped per plugin. Must be positive and monotonically increasing. |
| `name` | `&'static str` | Human-readable name (e.g., `"create_audit_log"`). |
| `checksum` | `&'static str` | Unique checksum for tamper detection. Convention: `v{N}_{name}_{short_hash}`. |
| `sql` | `&'static str` | Default SQL for all databases. Must be SQLite/PostgreSQL/MySQL compatible when no overrides are set. |
| `sql_postgres` | `Option<&'static str>` | PostgreSQL-specific override. Use when you need `JSONB`, `TIMESTAMPTZ`, `SERIAL`, etc. |
| `sql_mysql` | `Option<&'static str>` | MySQL-specific override. Use when you need `AUTO_INCREMENT`, `JSON`, `DATETIME(3)`, etc. |

### Database-Specific SQL

Most simple table definitions work across all three databases. Use overrides when you need vendor-specific features:

```rust
CustomPluginMigration {
    version: 1,
    name: "create_events",
    checksum: "v1_create_events_c3d4e5",
    // Default: works for SQLite
    sql: r#"
        CREATE TABLE IF NOT EXISTS my_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            payload TEXT
        )
    "#,
    // PostgreSQL: use TIMESTAMPTZ and JSONB for richer querying
    sql_postgres: Some(r#"
        CREATE TABLE IF NOT EXISTS my_events (
            id TEXT PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            payload JSONB
        )
    "#),
    // MySQL: use VARCHAR for primary key, DATETIME(3) for millisecond precision
    sql_mysql: Some(r#"
        CREATE TABLE IF NOT EXISTS my_events (
            id VARCHAR(255) PRIMARY KEY,
            timestamp DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
            payload JSON
        )
    "#),
}
```

### Multi-Statement Migrations

Separate multiple SQL statements with semicolons. Each statement is executed independently:

```rust
CustomPluginMigration {
    version: 1,
    name: "create_table_and_indexes",
    checksum: "v1_create_tbl_idx_a1b2",
    sql: r#"
        CREATE TABLE IF NOT EXISTS my_cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_my_cache_expires ON my_cache (expires_at)
    "#,
    sql_postgres: None,
    sql_mysql: None,
}
```

### Running Migrations

```bash
# Apply all pending migrations (core + plugin)
FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=sqlite FERRUM_DB_URL=sqlite://ferrum.db \
  cargo run

# Dry run — show what would be applied without making changes
FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=sqlite FERRUM_DB_URL=sqlite://ferrum.db \
  cargo run

# Check migration status (core + plugin)
FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=sqlite FERRUM_DB_URL=sqlite://ferrum.db \
  cargo run
```

Example output:

```
=== Ferrum Edge Migration Status ===

Applied migrations:
  V1: initial_schema (applied: 2026-04-01T..., checksum: v001_initial_schema)

Pending migrations: (none — schema is up to date)

=== Custom Plugin Migration Status ===

Applied plugin migrations:
  [example_audit_plugin] V1: create_audit_log (applied: 2026-04-01T..., checksum: v1_create_audit_log_f8a3e1)

Pending plugin migrations:
  [example_audit_plugin] V2: add_status_timestamp_index
```

### Migration Tracking

Plugin migrations are tracked in the `_ferrum_plugin_migrations` table with a composite primary key of `(plugin_name, version)`:

| Column | Description |
|--------|-------------|
| `plugin_name` | The plugin's name (matches the `.rs` file name) |
| `version` | Migration version within the plugin |
| `name` | Human-readable migration name |
| `applied_at` | RFC 3339 timestamp of when the migration was applied |
| `checksum` | Checksum at the time of application (warns if source changes later) |
| `execution_time_ms` | How long the migration took to execute |

This is separate from the core `_ferrum_migrations` table, so plugin versions never conflict with gateway versions.

### Table Naming Convention

Prefix your tables with a short identifier related to your plugin name to avoid collisions with the gateway's core tables (`proxies`, `consumers`, `upstreams`, `plugin_configs`, `proxy_plugins`) and other custom plugins:

```
audit_log           ← example_audit_plugin
my_cache_entries    ← my_cache_plugin
acme_rate_counters  ← acme_rate_limiter
```

### Complete Example

See `custom_plugins/example_audit_plugin.rs` for a full working example that demonstrates:
- Multi-version migrations (V1: create table + indexes, V2: add composite index)
- PostgreSQL overrides (`TIMESTAMPTZ`, `JSONB`)
- MySQL overrides (`DATETIME(3)`, `JSON`, `VARCHAR`)
- Multi-statement SQL (CREATE TABLE + CREATE INDEX in one migration)

## Adding Dependencies

If your custom plugin needs additional crates, add them to `Cargo.toml` under `[dependencies]`. The `custom_plugins/` directory is compiled as part of the main crate, so all dependencies are available.

```toml
[dependencies]
# ... existing deps ...
my-custom-crate = "1.0"
```

## Building and Distributing

### Development Build

```bash
cargo build
```

### Release Build

```bash
cargo build --release
```

The output binary at `target/release/ferrum-edge` includes your custom plugins compiled in.

### Docker Build

The included `Dockerfile` works with custom plugins out of the box since `custom_plugins/` is part of the project tree:

```bash
docker build -t my-ferrum-edge .
```

## Testing Custom Plugins

### Unit Tests

Add tests directly in your plugin file or in a separate test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_my_plugin_adds_header() {
        let config = json!({ "header_name": "X-Test", "header_value": "hello" });
        let plugin = MyHeaderInjector::new(&config);

        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/test".to_string(),
        );
        let mut headers = HashMap::new();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(headers.get("X-Test"), Some(&"hello".to_string()));
    }
}
```

Run tests:

```bash
cargo test
```

### Integration Tests

Use the gateway's test infrastructure in `tests/` to create end-to-end tests with your plugin enabled.

## Checklist

- [ ] Plugin `.rs` file created in `custom_plugins/`
- [ ] `create_plugin()` factory function exported with signature `(config: &Value, http_client: PluginHttpClient) -> Option<Arc<dyn Plugin>>`
- [ ] `fn name()` returns the file name (without `.rs`)
- [ ] Priority set appropriately for the execution phase
- [ ] `supported_protocols()` returns the correct protocol set
- [ ] `is_auth_plugin()` returns `true` if it's an auth plugin
- [ ] `modifies_request_body()` returns `true` if it transforms the request body
- [ ] `requires_request_body_buffering()` returns `true` if it reads the request body
- [ ] `requires_response_body_buffering()` returns `true` if it reads the response body
- [ ] `requires_ws_frame_hooks()` returns `true` if it implements `on_ws_frame()`
- [ ] `warmup_hostnames()` returns external hosts if applicable
- [ ] If using database tables: `plugin_migrations()` exported with versioned migrations
- [ ] If using database tables: table names prefixed to avoid collisions
- [ ] If using database tables: `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` tested
- [ ] Unit tests written and passing
- [ ] `cargo build` succeeds with no warnings
