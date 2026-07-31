# Custom Plugin Development Guide

This guide explains how to create, register, and build custom plugins for Ferrum Edge without modifying any core source files.

## Architecture Overview

Ferrum Edge uses a trait-based plugin system. All plugins implement the `Plugin` trait, which defines lifecycle hooks that the gateway calls during request processing.

### HTTP/gRPC/WebSocket Lifecycle

```
Request received
  │
  ▼
Route matching                  ── unmatched requests return 404 here
  │
  ▼
Allowed-method admission       ── matched disallowed methods return 405 here
  │
  ▼
Native gRPC POST admission     ── non-POST native gRPC is rejected here
  │
  ▼
on_request_received()           ── can reject; matched/allowed requests only
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
on_response_committed()         ── observe-only final buffered status/body
  │
  ▼
log()                           ── awaited sequentially on buffered responses
  │
  ▼
Buffered response returned to the embedded HTTP server, then sent to the client
```

Streamed responses have a different terminal path. For hyper-owned H1/H2 and
gRPC bodies, the handler returns the response first; body completion then
spawns `on_response_stream_terminated()` and sequential `log()` hooks. Native
H3 drives the body to completion inside its handler and then awaits the
terminal and log hooks before that handler returns. See
[Transaction log hook timing](#transaction-log-hook-timing) for lifecycle and
shutdown guidance.

### WebSocket Frame Lifecycle (per-frame, after upgrade)

```
on_ws_frame()  ── inspect/transform/close per WebSocket frame
on_ws_reassembly_frames() ── charge physical fragments of a reassembled message
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

Each plugin file must export a `create_plugin` factory function that returns
`Result` and a `failure_policy` metadata function:

```rust
// custom_plugins/my_header_injector.rs

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::plugins::{
    Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult, RequestContext,
};

pub struct MyHeaderInjector {
    header_name: String,
    header_value: String,
}

const MAX_CUSTOM_HEADER_NAME_BYTES: usize = 256;
const MAX_CUSTOM_HEADER_VALUE_BYTES: usize = 8 * 1024;

impl MyHeaderInjector {
    // Constructor MUST return Result<Self, String>.
    // Return Err for invalid or missing required config values.
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config
            .as_object()
            .ok_or_else(|| "my_header_injector config must be a JSON object".to_string())?;
        for key in config.keys() {
            if !matches!(key.as_str(), "header_name" | "header_value") {
                return Err(format!(
                    "my_header_injector config contains unknown key '{key}'; expected only 'header_name' and 'header_value'"
                ));
            }
        }

        let header_name = match config.get("header_name") {
            None => "X-My-Header".to_string(),
            Some(Value::String(value)) => value.clone(),
            Some(_) => return Err("header_name must be a string when present".to_string()),
        };
        if header_name.len() > MAX_CUSTOM_HEADER_NAME_BYTES {
            return Err(format!(
                "header_name must be at most {MAX_CUSTOM_HEADER_NAME_BYTES} bytes"
            ));
        }
        HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|error| format!("header_name must be a valid HTTP header name: {error}"))?;

        let header_value = match config.get("header_value") {
            None => "hello".to_string(),
            Some(Value::String(value)) => value.clone(),
            Some(_) => return Err("header_value must be a string when present".to_string()),
        };
        if header_value.len() > MAX_CUSTOM_HEADER_VALUE_BYTES {
            return Err(format!(
                "header_value must be at most {MAX_CUSTOM_HEADER_VALUE_BYTES} bytes"
            ));
        }
        HeaderValue::from_str(&header_value)
            .map_err(|error| format!("header_value must be a valid HTTP header value: {error}"))?;

        Ok(Self {
            header_name,
            header_value,
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
/// Must return Result so invalid configs follow this plugin's failure policy.
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(MyHeaderInjector::new(config)?)))
}

/// Required metadata function — the build script records this policy.
pub fn failure_policy() -> PluginFailurePolicy {
    PluginFailurePolicy::KeepLastKnownGood
}
```

### Config Validation Rules

Your `new()` constructor must validate the plugin config and return `Err(String)` when:

- **Required fields are missing** — if the plugin cannot function without a field, return an error (don't silently default to a no-op).
- **Values are invalid** — reject malformed regexes, unknown enum variants, out-of-range numbers, unparseable URLs.
- **The config shape is unexpected** — reject non-object roots, unknown keys, and present values of the wrong JSON type. Apply an optional field's default only when that field is omitted.
- **A value crosses a typed protocol boundary** — parse header names/values, URLs, CIDRs, and similar values in the constructor and apply an explicit size bound before retaining them.
- **The plugin would have no effect** — e.g., a rate limiter with no rate windows, a size limiter with `max_bytes=0`, a transformer with no rules.

Sensible defaults for optional fields (e.g., `limit_by` defaulting to `"ip"`) are fine — only return `Err` for fields where there is no safe default.

The `failure_policy()` return value controls cache publication when construction
or validation fails:

- `FailClosed` rejects startup or reload rather than serving without the plugin.
- `KeepLastKnownGood` rejects reload publication so the previous plugin cache
  keeps serving. Startup also rejects because there is no prior cache.
- `OptionalFailOpen` logs the failure and omits the plugin from the published
  cache. Use this only for non-enforcing plugins such as best-effort telemetry.

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

If unset, all `.rs` files directly in `custom_plugins/` are included.
Pedagogical examples under `custom_plugins/examples/` are **never** part of
the default discovery set; list them explicitly to compile them:

```bash
FERRUM_CUSTOM_PLUGINS=example_plugin,example_audit_plugin cargo build
```

Default source, release, and Docker builds leave `FERRUM_CUSTOM_PLUGINS` unset
so example plugins (and their migrations) do not alter the production registry
or schema.

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
| `on_request_received(&mut ctx)` | Post-route, post-allowed-method admission | Yes | IP filtering, request validation, early termination for matched/allowed requests |
| `authenticate(&mut ctx, &consumer_index)` | Authentication | Yes | Verify identity (JWT, API key, custom tokens) |
| `authorize(&mut ctx)` | Authorization | Yes | Check permissions, enforce rate limits |
| `before_proxy(&mut ctx, &mut headers)` | Pre-backend | Yes | Transform request headers, add tracing IDs. **Read request headers from `headers`, not `ctx.headers`** (see note below) |
| `transform_request_body(&body, content_type)` | Pre-backend (buffered) | No | Rewrite request body before sending to backend |
| `on_final_request_body(&headers, &body)` | Pre-backend (post-transform) | Yes | Validate the final request body after all transforms |
| `after_proxy(&mut ctx, status, &mut headers)` | Post-backend | Yes | Transform response headers, reject responses |
| `apply_websocket_handshake_response_headers(&ctx, status, &mut headers)` | Successful WebSocket handshake (H1 `101`; H2/H3 `200`) | No | Synchronously decorate successful handshake response headers in configured order. After this non-rejecting hook returns, proxy core scrubs transport-owned handshake/framing fields and reconstructs them authoritatively. |
| `on_response_body(&mut ctx, status, &headers, &body)` | Post-backend (buffered) | Yes | Inspect buffered response body, extract metrics |
| `transform_response_body(&body, content_type, &headers)` | Post-backend (buffered) | No | Rewrite response body before sending to client |
| `on_final_response_body(&mut ctx, status, &headers, &body)` | Post-backend (post-transform) | Yes | Validate the final response body after all transforms |
| `on_response_committed(&mut ctx, status, &headers, &body)` | Post-backend (buffered commit) | No | Export the final client-visible buffered response after validators and rejection replacement; opt in with `requires_response_committed_hook()` |
| `response_stream_inspector(&ctx, status, content_type)` | Post-backend (streaming) | No (can truncate) | Create one stateful, per-response body inspector |
| `on_response_stream_terminated(&mut ctx, status, outcome)` | Post-backend (streaming terminal) | No | Clean up/account for streaming state and write aggregate transaction metadata before logging; does not receive body bytes |
| `log(&summary)` | Logging | No | Hand transaction data to a bounded sink; timing depends on response ownership |
| `on_ws_frame(proxy_id, connection_id, direction, &message)` | WebSocket frame | Close* | Inspect/transform per-frame WebSocket traffic |
| `on_ws_reassembly_frames(proxy_id, connection_id, direction, fragment_frames)` | WebSocket physical fragments | Close** | Charge/observe the wire frames a fragmented message consumed before it reassembled |
| `prepare_ws_frame_delivery(&message)` / `emit_ws_frame_delivery(...)` | After successful WS sink accept | — | Delivery-accurate observation (final post-guard message); default no-op |

\*`on_ws_frame` cannot return `PluginResult::Reject`. Instead, return `Some(Message::Close(...))` to close the connection in both directions. Return `None` for passthrough, or `Some(transformed_message)` to replace the frame. The first terminal Close from a priority-ordered admission/mutating hook is preserved: later mutating plugins are skipped for that frame (so they cannot charge budget or overwrite the Close), while observational hooks that return `true` from `observes_ws_frame_decisions()` still see the final Close. Delivery-accurate loggers should emit from `prepare_ws_frame_delivery` / `emit_ws_frame_delivery` (after the control-frame guard and successful sink accept), not from `on_ws_frame`, so cancelled/failed writes are not presented as delivered frames.

\*\*`on_ws_reassembly_frames` sees the frames `on_ws_frame` cannot: tungstenite reassembles Text/Binary continuations, so the initial non-final frame and every intermediate continuation — including zero-length ones, which trip no size ceiling — never surface as a message. The relay meters them and calls this hook (with `fragment_frames >= 1`) before the `on_ws_frame` chain for the read that surfaced them, and for an interleaved Ping/Pong; a peer `Close` is exempt, matching the existing rule that peer Closes bypass mutating admission. There is no message to mutate: only `Some(Message::Close(...))` is honored, everything else is ignored, and observe-only plugins are skipped. The completing frame is charged once through `on_ws_frame`, so a plugin implementing both hooks counts each wire frame exactly once. Set `requires_ws_frame_hooks()` to `true` to receive it.

**Streaming inspectors:** A `ResponseStreamInspector` runs after response headers have been committed. It can forward, hold, or terminate the remaining body, but it cannot change the response status or retract bytes already sent.

**`on_request_received` routing boundary:** This hook runs only after a route
matches and that proxy's `allowed_methods` check succeeds. At that point
`ctx.matched_proxy` is populated and the hook runs over the resolved view of
applicable global and proxy/proxy-group-scoped plugins. An unmatched request
returns 404 without running any global or scoped `on_request_received` hook. A
matched request with a disallowed method returns 405 without running either
kind of ordinary request hook, but still emits one terminal transaction summary
(`metadata.rejection_phase = "allowed_methods"`) from the protocol-filtered
plugin-cache view. Native gRPC requests must also use `POST` before this hook runs.
A matched non-POST native gRPC request is rejected before global or scoped
hooks even when `allowed_methods` permits it. H1, H2, and H3 share the
ordinary-hook blind spots for unmatched 404 and gRPC non-POST admission.
Terminal transaction logging is separate; do not use this ordinary
request hook as a count of every connection or response the gateway handled.

**`before_proxy` header parameter**: In `before_proxy`, always read request headers from the `headers` parameter, **not** from `ctx.headers`. The proxy handler avoids cloning the headers HashMap when no plugin modifies them — it moves headers out of `ctx.headers` into the `headers` parameter via `std::mem::take()`, leaving `ctx.headers` empty during the call. After `before_proxy` completes, headers are moved back. This means `ctx.headers.get("content-type")` returns `None` inside `before_proxy`, while `headers.get("content-type")` returns the actual value. If your plugin calls helper methods that need request headers, pass the `headers` parameter through rather than reading `ctx.headers` in the helper. This only affects `before_proxy` — other phases like `authenticate` and `on_request_received` can safely read `ctx.headers`.

### Transaction log hook timing

`log()` is sequential within one transaction: Ferrum awaits each configured
plugin in priority/config order. Where that wait occurs depends on who owns the
response body:

- Buffered responses, buffered rejections/errors, and other synchronous
  terminal paths normally await every `log()` hook before the handler returns
  the response. Direct endpoint or filesystem I/O in the hook therefore adds
  latency, and multiple slow hooks add that latency serially. Buffered H1/H2
  requests with an active absolute gRPC deadline are the exception: Ferrum
  moves their owned terminal log state to a five-second detached cleanup task
  so a blocked sink cannot delay the terminal RPC response.
- Hyper-owned streamed H1/H2 and gRPC bodies return from the handler before the
  body is complete. At terminal body completion, Ferrum spawns one task that
  awaits `on_response_stream_terminated()` and then all `log()` hooks in
  sequence. The work can be lost if no Tokio runtime remains or the runtime
  shuts down before the task finishes.
- Native H3 owns and drives its QUIC body inside the request handler. After the
  body terminates, it synchronously awaits terminal hooks and sequential
  `log()` hooks before the handler completes. It does not use the detached
  hyper-body logger.

For potentially slow I/O, use an explicitly bounded channel whose sender,
worker, cancellation state, and retry budget are owned by the plugin instance.
Stage the worker in `start_background_tasks()` during cache construction (workers
must stay dormant / gated), release it from `commit_background_tasks()` only
after the cache generation is atomically installed, define an explicit
queue-full policy, and close/signal the worker when the instance is dropped. Do
not spawn one unbounded task per transaction.
Because `Drop` cannot await and runtime shutdown can still cancel a worker,
durability-sensitive sinks should persist records before acknowledging them or
hand off to an external collector with its own drain protocol; a custom plugin
must not claim lossless shutdown merely because it uses a background task.

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
| `fn egresses_request_body_before_finalization(&self) -> bool` | `false` | Set to `true` if `before_proxy` sends the buffered request body to an external service before request transforms/final hooks. Candidate admission and runtime cache construction then reject same-protocol body-transform compositions and same HTTP/gRPC-protocol final request-body policy plugins (`enforces_finalized_request_policy()`). |
| `fn requires_prior_request_deduplication(&self) -> bool` | `false` | Set to `true` if `before_proxy` can execute an external side effect and return a terminal response. Any attached same-protocol `request_deduplication` instance must then have a strictly lower effective priority. |
| `fn requires_request_body_before_before_proxy(&self) -> bool` | `false` | Set to `true` if your plugin needs the raw request body available during `before_proxy`. |
| `fn requires_request_body_buffering(&self) -> bool` | Derived | By default returns `true` if `modifies_request_body()` or `requires_request_body_before_before_proxy()`. Override for custom logic. |
| `fn should_buffer_request_body(&self, &ctx) -> bool` | Delegates | Per-request decision on whether to buffer. Defaults to `requires_request_body_buffering()`. Override for conditional buffering (e.g., only for certain content types). |
| `fn requires_response_body_buffering(&self) -> bool` | `false` | Config-time upper bound. Set to `true` if the plugin may need the complete response body. |
| `fn should_buffer_response_body(&self, &ctx) -> bool` | Delegates | Per-request refinement. Defaults to `requires_response_body_buffering()` and may skip buffering for irrelevant requests. |
| `fn should_buffer_response_body_for_content_type(&self, &ctx, content_type, status, &headers) -> bool` | Delegates | Post-header refinement on supported dispatch paths. Inspect status and the full header map (including `Content-Encoding`) when representation metadata affects safety. This is narrowing-only: it may release a response selected for buffering, but cannot force a streaming response to buffer. |
| `fn may_modify_response_content_type(&self, &ctx, backend_content_type) -> bool` | `false` | Set when `after_proxy` may relabel the backend `Content-Type`; this prevents an unsafe buffer-to-stream downgrade. The answer must match the current request and backend type exactly. |
| `fn requires_response_stream_hooks(&self) -> bool` | `false` | Config-time opt-in for streaming response inspection. |
| `fn response_stream_inspector(&self, &ctx, status, content_type) -> Option<Box<dyn ResponseStreamInspector>>` | `None` | Create state owned by one eligible streaming response, or return `None` for passthrough. |
| `fn forces_reqwest_dispatch(&self, &ctx) -> bool` | `false` | Optional per-request native-H3 dispatch override when reqwest is operationally preferable; inspectors do not require it for transport coverage. |
| `fn correlation_id_header_name(&self) -> Option<&str>` | `None` | Return the non-empty correlation header owned by this instance, or `None` when it owns no correlation header. Empty or whitespace-only claims fail admission with a capability-specific error. Core candidate admission and runtime cache construction defensively trim and compare valid claims ASCII-case-insensitively, rejecting the effective deployment-specific `FERRUM_REAL_IP_HEADER` and duplicate effective headers or priorities on one plugin chain, including custom-only chains. CP/DP deployments require every DP to advertise the same effective real-IP header as the CP before config distribution. Custom plugins must still trim, validate, and normalize the header names used by their own runtime writes. |
| `fn applies_after_proxy_on_reject(&self) -> bool` | `false` | Set to `true` if your plugin's `after_proxy` should also run on gateway-generated rejection responses (e.g., CORS headers on error responses). |
| `fn requires_ws_frame_hooks(&self) -> bool` | `false` | Set to `true` if your plugin implements `on_ws_frame()` or `on_ws_reassembly_frames()`. Pre-computed per proxy for zero overhead when unused. |
| `fn observes_ws_frame_decisions(&self) -> bool` | `false` | Set to `true` for observe-only frame hooks. After an earlier admission plugin returns a terminal Close, the shared relay still invokes observational hooks with that Close while skipping later mutating plugins. The relay always ignores an observational hook's return value. |
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
| Preflight | 100–999 | Matched-request CORS, IP filtering, termination, bot detection | cors (100), request_termination (125), ip_restriction (150), bot_detection (200), grpc_method_router (275) |
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

## Streaming-safe response plugins

Response plugins have two different body-access models:

- **Buffer the complete body** with `requires_response_body_buffering()` and the `should_buffer_response_body*()` refinements. Use the buffered lifecycle hooks when the decision needs the complete payload or must replace the status/body before headers are sent.
- **Inspect while streaming** with `requires_response_stream_hooks()` and `response_stream_inspector()`. Use this for bounded, incremental inspection of latency-sensitive or unbounded responses such as SSE.

**Which do I pick?** If correctness requires the complete body, or you must transform it or reject it with a new HTTP status, buffer it. If you can decide from bounded windows and forwarding must remain incremental, use a stream inspector. Do not set `requires_response_body_buffering()` merely to observe an SSE stream: doing so removes its streaming behavior and can collect an unbounded body until the response-size limit produces a 502.

A stream inspector runs only when the response remains on a streaming path. Non-SSE responses with a known `Content-Length` at or below `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (64 KiB by default) may be eagerly buffered before an inspector is created. If a plugin must cover those responses too, implement the corresponding buffered hook as a fallback or configure the cutoff to `0`. SSE is always exempt from this adaptive small-response buffering.

See the [response-body streaming guide](docs/response_body_streaming.md) for the gateway's buffering decision flow and protocol-specific behavior.

### Buffer the complete response

`requires_response_body_buffering()` is the config-time upper bound. `should_buffer_response_body()` may narrow it using request context. On dispatch paths that support the post-header downgrade, `should_buffer_response_body_for_content_type()` gets one final opportunity to narrow the decision after the backend status and headers arrive. Despite its historical name, this hook must consider any response header that determines whether the buffered hook can inspect the representation. In particular, do not release non-identity `Content-Encoding` bytes when correctness depends on a bounded final decode or fail-closed rejection. The content-type hook cannot turn a streaming decision into buffering; returning `true` where `should_buffer_response_body()` returned `false` has no effect. See the response-body streaming guide for the current protocol coverage.

```rust
#[async_trait]
impl Plugin for MyJsonResponseInspector {
    fn name(&self) -> &str { "my_json_response_inspector" }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && (200..300).contains(&response_status)
            && content_type.is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
            })
    }

    async fn on_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Inspect the normalized body before ordinary response transforms.
        let _inspected_bytes = body.len();
        PluginResult::Continue
    }
}
```

Use `on_final_response_body()` instead when you need the final client-visible body after all `transform_response_body*()` hooks. To replace a buffered body, use the current three-argument signature:

```rust
async fn transform_response_body(
    &self,
    body: &[u8],
    content_type: Option<&str>,
    response_headers: &HashMap<String, String>,
) -> Option<Vec<u8>> {
    let _ = (body, content_type, response_headers);
    None // Some(new_body) replaces it
}
```

Exporters that must observe the response after all rejecting validators should
also return `true` from `requires_response_committed_hook()` and emit from
`on_response_committed()`. That hook receives the final buffered status,
headers, and body, but returns `()` and therefore cannot mutate or reject the
response. Keep any fail-closed sink-health admission in an earlier rejecting
hook; keep sampling, redaction, and record shaping inside the exporter.

### Inspect while streaming

`requires_response_stream_hooks()` opts the plugin into the streaming pipeline. For each streaming response, `response_stream_inspector()` receives immutable request context plus the final response status and content type. Return a fresh inspector for responses you handle, or `None` for passthrough.

The inspector must own all per-response state. The proxy may move it into a detached H1/H2 task or drive it inside an H3 loop; it cannot borrow `RequestContext`. Keep accumulators bounded because SSE and similar streams may never end.

For transaction-metadata write-back, use `ctx.response_stream_id()` in the factory as the key for a bounded plugin-owned shared slot (for example an `Arc<DashMap<u64, Arc<Mutex<...>>>>`). Give the inspector the slot handle, update it only at decision/window boundaries (never lock on every chunk), then remove the entry in `on_response_stream_terminated(&mut ctx, ..., outcome)` and fold the aggregate into `ctx.metadata`. The terminal hook runs for clean EOF, backend errors, policy cuts, and client disconnects, before `TransactionSummary.metadata` is finalized. Gate slot creation on both returning an inspector and the plugin's own observability setting; the no-inspector path must allocate nothing. Configuration such as metadata emission and argument hashing remains the plugin's responsibility—the core does not interpret or filter plugin fields.

```rust
use bytes::Bytes;
use crate::plugins::{ResponseStreamAction, ResponseStreamInspector};

const BLOCKED: &[u8] = b"forbidden";

struct SseInspector {
    // Retain only enough bytes to detect a match split across two chunks.
    tail: Vec<u8>,
}

#[async_trait]
impl ResponseStreamInspector for SseInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        let mut scan = Vec::with_capacity(self.tail.len() + chunk.len());
        scan.extend_from_slice(&self.tail);
        scan.extend_from_slice(chunk);
        if scan.windows(BLOCKED.len()).any(|window| window == BLOCKED) {
            return ResponseStreamAction::Terminate(Some(Bytes::from_static(
                b"event: error\ndata: blocked\n\n",
            )));
        }

        let keep = BLOCKED.len().saturating_sub(1).min(scan.len());
        let held_tail = scan.split_off(scan.len() - keep);
        self.tail = held_tail;
        // Release only bytes that cannot begin a future cross-chunk match.
        ResponseStreamAction::Forward(Bytes::from(scan))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        ResponseStreamAction::Forward(Bytes::from(std::mem::take(&mut self.tail)))
    }
}

#[async_trait]
impl Plugin for MySseInspector {
    fn name(&self) -> &str { "my_sse_inspector" }

    fn requires_response_stream_hooks(&self) -> bool {
        true
    }

    fn response_stream_inspector(
        &self,
        _ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        let is_sse = content_type.is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        });
        ((200..300).contains(&response_status) && is_sse)
            .then(|| {
                Box::new(SseInspector { tail: Vec::new() })
                    as Box<dyn ResponseStreamInspector>
            })
    }

    fn forces_reqwest_dispatch(&self, _ctx: &RequestContext) -> bool {
        true // Optional transport preference; inspection does not depend on it.
    }
}
```

The proxy drives inspectors on reqwest, direct HTTP/2, and native HTTP/3 response arms. Use `forces_reqwest_dispatch()` only as a scoped transport preference when reqwest is operationally desirable for a request; it is not required for inspector coverage.

The `ResponseStreamInspector` action contract is:

- `on_chunk(&mut self, chunk)` receives each decoded body chunk. `Forward(bytes)` releases those bytes now; `Forward(Bytes::new())` emits nothing and means the inspector is holding data in its own accumulator. `Terminate(None)` ends the body, while `Terminate(Some(bytes))` emits the final bytes and then ends it.
- `on_end(&mut self)` is the clean end-of-stream flush for a trailing partial window. Its default returns an empty `Forward`.
- Response headers are already committed before either hook runs. `Terminate` can only truncate the in-flight response; it cannot change the HTTP status, replace headers, or retract previously forwarded bytes.

Inspectors must remain portable across the detached H1/H2 driver and the native H3 event loop. They cannot borrow request context, must keep accumulators bounded, and must treat `on_downstream_terminated()` as the signal that a later inspector cut bytes they had already observed.

### `Content-Type` relabeling trap

The gateway may downgrade a pre-flight buffer decision to streaming after it sees the backend `Content-Type`. If your `after_proxy()` hook may relabel that type, you must also implement `may_modify_response_content_type()` so a body-inspection plugin is not incorrectly bypassed before the relabel occurs.

The capability answer must mirror `after_proxy()` for the current request and backend type. In particular, return `false` when the backend already sent the target type: reporting a possible relabel for an already-SSE response can pin an unbounded event stream to the buffered path.

```rust
fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
    })
}

fn may_modify_response_content_type(
    &self,
    _ctx: &RequestContext,
    backend_content_type: Option<&str>,
) -> bool {
    !is_event_stream(backend_content_type)
}

async fn after_proxy(
    &self,
    _ctx: &mut RequestContext,
    _response_status: u16,
    response_headers: &mut HashMap<String, String>,
) -> PluginResult {
    if !is_event_stream(response_headers.get("content-type").map(String::as_str)) {
        response_headers.insert("content-type".into(), "text/event-stream".into());
    }
    PluginResult::Continue
}
```

This declaration is a safety gate; it is not a request to buffer by itself. Likewise, `should_buffer_response_body_for_content_type()` is narrowing-only and cannot opt a plugin into buffering after headers arrive.

### SSE and gRPC implications

- SSE (`text/event-stream`) is exempt from adaptive small-response buffering whenever streaming has been selected, regardless of `Content-Length`. Buffered hooks such as `on_response_body()` never see a response that remains streamed. Use a stream inspector for incremental SSE inspection; forcing full-body buffering destroys SSE latency and can run until the response-size limit.
- A response-body-buffering plugin takes gRPC off its streaming response/trailer path. The gateway collects the full body and trailers before constructing the response, so do not opt into buffering for gRPC unless the plugin genuinely requires complete-message access and can accept the loss of live server streaming.

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
        // ctx.client_ip, ctx.proxy_id, ctx.listen_port, ctx.backend_scheme
        // ctx.tls_client_cert_der (available for TCP+TLS after handshake)
        // Metadata is shared between connect and disconnect.
        ctx.insert_metadata("connected_at".to_string(), "...".to_string());
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
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config
            .as_object()
            .ok_or_else(|| "my_rate_limiter config must be a JSON object".to_string())?;
        for key in config.keys() {
            if key != "max_requests" {
                return Err(format!("unknown my_rate_limiter config key: {key}"));
            }
        }
        let max_requests = match config.get("max_requests") {
            None => 100,
            Some(Value::Number(value)) => value
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or_else(|| "max_requests must be a positive integer".to_string())?,
            Some(_) => return Err("max_requests must be an integer when present".to_string()),
        };
        Ok(Self {
            counts: Arc::new(DashMap::new()),
            max_requests,
        })
    }
}
```

The `DashMap` state persists across requests because the `PluginCache` holds an `Arc<dyn Plugin>` for each plugin instance.

## Opting Into Transaction-Log Schema Customization

Logging-style custom plugins can opt into the same `schema:` /
`schema_ref:` controls as the built-in loggers by importing the
public helpers and wrapping every `serde_json::to_string(summary)` call
site behind a schema branch:

```rust
use std::sync::Arc;
use crate::plugins::utils::log_schema::{
    SchemaCapabilities, SchemaView, SummarySchema, resolve_schema,
};

pub struct MyLogger {
    schema: Option<Arc<SummarySchema>>,
    // ... other fields
}

impl MyLogger {
    pub fn new(config: &Value) -> Result<Self, String> {
        // Pass `SchemaCapabilities::BASE` for HTTP / stream logging. Only the
        // built-in `ws_logging` plugin passes `SchemaCapabilities::WS_LOGGING`
        // to opt into the WebSocket-disconnect native fields. The capability is
        // honored for both inline `schema:` and `schema_ref:`.
        let schema = resolve_schema(config, "my_logger", SchemaCapabilities::BASE)?;
        Ok(Self { schema /*, ... */ })
    }
}

#[async_trait]
impl Plugin for MyLogger {
    async fn log(&self, summary: &TransactionSummary) {
        let json = match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        // ... ship json
    }
}
```

`SummaryLogEntryView` and `SummaryLogEntryBatchView` are available for
the batched / multi-variant case (mirroring `http_logging`, `tcp_logging`
etc.). Metadata redaction is preserved on every code path. See
[docs/log_schema.md](docs/log_schema.md) for the operator-facing
schema reference.

## Using the Shared HTTP Client

If your plugin needs to make outbound HTTP calls (webhooks, token introspection, external APIs), use the shared `PluginHttpClient` passed to the factory:

```rust
use crate::plugins::{Plugin, PluginFailurePolicy, PluginHttpClient};

pub struct MyWebhookPlugin {
    http_client: PluginHttpClient,
    webhook_url: String,
}

impl MyWebhookPlugin {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config = config
            .as_object()
            .ok_or_else(|| "my_webhook config must be a JSON object".to_string())?;
        for key in config.keys() {
            if key != "webhook_url" {
                return Err(format!("unknown my_webhook config key: {key}"));
            }
        }
        let webhook_url = match config.get("webhook_url") {
            None => "http://localhost:8080/webhook".to_string(),
            Some(Value::String(value)) if value.len() <= 2048 => value.clone(),
            Some(Value::String(_)) => {
                return Err("webhook_url must be at most 2048 bytes".to_string());
            }
            Some(_) => return Err("webhook_url must be a string when present".to_string()),
        };
        let parsed = url::Url::parse(&webhook_url)
            .map_err(|error| format!("webhook_url must be a valid URL: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("webhook_url scheme must be http or https".to_string());
        }
        Ok(Self {
            http_client,
            webhook_url,
        })
    }
}
```

Then in the factory function at the bottom of your plugin file:

```rust
pub fn create_plugin(
    config: &Value,
    http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(MyWebhookPlugin::new(config, http_client)?)))
}

pub fn failure_policy() -> PluginFailurePolicy {
    PluginFailurePolicy::OptionalFailOpen
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
    /// Authentication mechanism that succeeded (e.g., "jwt_auth", "key_auth").
    /// None when no auth plugin identified the client.
    pub auth_method: Option<&'static str>,
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
    /// Optional routing overrides consumed after `before_proxy`.
    pub route_override_upstream_id: Option<String>,
    pub route_override_backend_host: Option<String>,
    pub route_override_backend_port: Option<u16>,
    pub route_override_resolved_tls: Option<BackendTlsConfig>,
}
```

**Helper methods:**
- `effective_identity()` — returns the stable identity (Consumer username preferred over external identity)
- `backend_consumer_username()` — returns the identity for the `X-Consumer-Username` backend header
- `backend_consumer_custom_id()` — returns the Consumer custom ID, if a gateway Consumer was resolved
- `apply_route_overrides(proxy)` — returns an `Arc<Proxy>` with direct route overrides applied. This helper cannot re-resolve upstream TLS for `route_override_upstream_id`.
- `apply_route_overrides_with_upstreams(proxy, upstreams)` — use this in custom dispatch paths that honor `route_override_upstream_id`; it re-resolves `resolved_tls` from the effective upstream snapshot.

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
let mut ctx = StreamConnectionContext::new(
    client_ip,
    direct_client_ip,
    proxy_id,
    proxy_name,
    listen_port,
    backend_scheme,
    consumer_index,
);

ctx.authenticated_identity = Some("external-principal".to_string());
ctx.insert_metadata("custom.key".to_string(), "value".to_string());
```

Runtime code creates the context, so custom plugins normally only read or update its public fields.
External test harnesses must use `StreamConnectionContext::new`; struct literals are intentionally
unsupported because authoritative stream correlation ownership is private lifecycle state. A plugin
that changes the public `client_ip` may reset `canonical_client_ip` to `Default::default()` so typed
client-IP policy reparses the new value. That reset does not erase correlation ownership. Metadata
set during `on_stream_connect` is carried through to `on_stream_disconnect` via
`StreamTransactionSummary.metadata`; built-in correlation values are authoritatively re-projected
over plugin-writable compatibility metadata when the terminal summary is constructed.

## Transaction Summary

The `TransactionSummary` struct is passed to the `log()` hook:

```rust
pub struct TransactionSummary {
    pub timestamp_received: String,
    pub client_ip: String,
    pub consumer_username: Option<String>,
    pub auth_method: Option<&'static str>,
    pub http_method: String,
    pub request_path: String,
    pub proxy_id: Option<String>,
    pub proxy_name: Option<String>,
    pub backend_target: Option<String>,
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
    // Same JSON keys as StreamTransactionSummary so logs unify across
    // HTTP and TCP/UDP transactions. Omitted from output when zero.
    pub bytes_sent: u64,     // client -> backend (request body size)
    pub bytes_received: u64, // backend -> client (response body size)
    pub mirror: bool,
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
    pub consumer_username: Option<String>,
    pub auth_method: Option<&'static str>,
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
│   ├── examples/              # Opt-in pedagogical examples (not compiled by default)
│   │   ├── README.md
│   │   ├── example_plugin.rs  # Protocol-scoped header/body/correlation example
│   │   └── example_audit_plugin.rs # DB-backed audit + migration example
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
4. Plugin migrations run after core migrations under the same cross-process
   migration lock, using the dialect-specific transaction contract documented
   in [Database Migrations](docs/migrations.md#multi-statement-migrations)

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

Separate multiple SQL statements with semicolons. Each statement is executed
independently. Ferrum uses a quote/comment/dollar-quote-aware splitter (shared
by classification and execution) so semicolons inside string literals,
comments (including PostgreSQL nested block comments), PostgreSQL dollar-quoted
bodies, and `BEGIN … END` compound blocks do not create false boundaries.
MySQL compound routines may use `DELIMITER //` … `//` `DELIMITER ;` (client
meta-commands are stripped and never sent to the server). Malformed SQL fails
during apply validation before statement one runs — see
[Multi-Statement Migrations](docs/migrations.md#multi-statement-migrations).

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
example_audit_log   ← example_audit_plugin (plugin-prefixed)
my_cache_entries    ← my_cache_plugin
acme_rate_counters  ← acme_rate_limiter
```

Custom plugin migrations have no automatic down/uninstall path. Removing a
plugin from a later binary leaves its tables and `_ferrum_plugin_migrations`
rows until an operator drops them deliberately.

### Complete Example

See `custom_plugins/examples/example_audit_plugin.rs` (build with
`FERRUM_CUSTOM_PLUGINS=example_audit_plugin`) for a full working example that
demonstrates:
- Multi-version migrations (V3: create table + indexes, V4: add composite index)
- PostgreSQL overrides (including `DOUBLE PRECISION`)
- MySQL overrides (`VARCHAR` sizing) with exact drop/recreate index reconciliation
- Multi-statement SQL (CREATE TABLE + CREATE INDEX in one migration)
- Atomic batch persistence via a bounded queue into the gateway configuration database (effective SQL URL through `EnvConfig::resolve_effective_sql_backend`, including canonical `FERRUM_DB_TLS_*` parameters; SQL-only)
- Separate HTTP transport and terminal gRPC status fields; WebSocket upgrade transactions without frame capture
- Lifecycle-owned hourly retention and documented best-effort storage-failure recovery

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

<!-- custom-plugin-guide-test: fallible-constructor-result -->

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_my_plugin_adds_header() -> Result<(), String> {
        let config = json!({ "header_name": "X-Test", "header_value": "hello" });
        let plugin = MyHeaderInjector::new(&config)?;

        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/test".to_string(),
        );
        let mut headers = HashMap::new();

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(headers.get("X-Test").map(String::as_str), Some("hello"));
        Ok(())
    }
}
```

The repository's external unit suite compiles this fallible-constructor pattern
and checks the marked Markdown snippet so a later signature edit cannot silently
restore a method call on `Result<MyHeaderInjector, String>`.

Run tests:

```bash
cargo test
```

### Integration Tests

Use the gateway's test infrastructure in `tests/` to create end-to-end tests with your plugin enabled.

## Checklist

- [ ] Plugin `.rs` file created in `custom_plugins/`
- [ ] `create_plugin()` factory function exported with signature `(config: &Value, http_client: PluginHttpClient) -> Result<Option<Arc<dyn Plugin>>, String>`
- [ ] `failure_policy()` metadata function exported with the desired `PluginFailurePolicy`
- [ ] `fn name()` returns the file name (without `.rs`)
- [ ] Constructor rejects non-object roots, unknown keys, present wrong types, and invalid/oversized protocol values
- [ ] `on_request_received()` logic does not assume it will observe unmatched 404 or matched 405 responses
- [ ] Priority set appropriately for the execution phase
- [ ] `supported_protocols()` returns the correct protocol set
- [ ] `is_auth_plugin()` returns `true` if it's an auth plugin
- [ ] `modifies_request_body()` returns `true` if it transforms the request body
- [ ] `egresses_request_body_before_finalization()` returns `true` if `before_proxy` sends body bytes to an external service before finalization (candidate admission then refuses same-protocol body transformers and same HTTP/gRPC-protocol final request-body policy plugins)
- [ ] `requires_prior_request_deduplication()` returns `true` if a terminal external side effect must run after attached deduplication instances
- [ ] `requires_request_body_buffering()` returns `true` if it reads the request body
- [ ] Complete-body response plugins declare `requires_response_body_buffering()` and only narrow it in `should_buffer_response_body*()`
- [ ] Streaming response plugins declare `requires_response_stream_hooks()` and return a bounded, state-owning `ResponseStreamInspector`
- [ ] A plugin that relabels response `Content-Type` declares `may_modify_response_content_type()` with the same conditions as `after_proxy()`
- [ ] `requires_ws_frame_hooks()` returns `true` if it implements `on_ws_frame()` or `on_ws_reassembly_frames()`
- [ ] Per-frame budget plugins implement `on_ws_reassembly_frames()` too, or a peer can fragment-flood past them
- [ ] Mutating `on_ws_frame` hooks treat an inbound `Message::Close` as already-final (no budget charge / no replacement) unless they intentionally observe-only via `observes_ws_frame_decisions()`
- [ ] `warmup_hostnames()` returns external hosts if applicable
- [ ] Slow `log()` I/O uses a bounded, lifecycle-owned handoff with explicit overflow and shutdown behavior
- [ ] If using database tables: `plugin_migrations()` exported with versioned migrations
- [ ] If using database tables: table names prefixed to avoid collisions
- [ ] If using database tables: `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` tested
- [ ] Unit tests written and passing
- [ ] `cargo build` succeeds with no warnings
