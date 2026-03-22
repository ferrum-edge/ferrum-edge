# Custom Plugin Development Guide

This guide explains how to create, register, and build custom plugins for Ferrum Gateway without modifying any core source files.

## Architecture Overview

Ferrum Gateway uses a trait-based plugin system. All plugins implement the `Plugin` trait, which defines lifecycle hooks that the gateway calls during request processing:

```
Request received
  │
  ▼
on_request_received()  ── can reject
  │
  ▼
Route matching
  │
  ▼
authenticate()         ── can reject (auth plugins only)
  │
  ▼
authorize()            ── can reject
  │
  ▼
before_proxy()         ── can reject, can modify headers
  │
  ▼
Proxy to backend
  │
  ▼
after_proxy()          ── can modify response headers
  │
  ▼
log()                  ── fire-and-forget
  │
  ▼
Response sent to client
```

## Quick Start

### 1. Create your plugin file

Create a new `.rs` file in the `custom_plugins/` directory at the project root:

```rust
// custom_plugins/my_header_injector.rs

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::plugins::{Plugin, PluginResult, RequestContext};

pub struct MyHeaderInjector {
    header_name: String,
    header_value: String,
}

impl MyHeaderInjector {
    pub fn new(config: &Value) -> Self {
        Self {
            header_name: config["header_name"]
                .as_str()
                .unwrap_or("X-My-Header")
                .to_string(),
            header_value: config["header_value"]
                .as_str()
                .unwrap_or("hello")
                .to_string(),
        }
    }
}

#[async_trait]
impl Plugin for MyHeaderInjector {
    fn name(&self) -> &str {
        "my_header_injector"
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
```

### 2. Register it in `custom_plugins/mod.rs`

Open `custom_plugins/mod.rs` and make three additions:

```rust
// Step 1: Declare the module
pub mod my_header_injector;

// Step 2: Add to the factory match (inside create_custom_plugin)
"my_header_injector" => Some(Arc::new(
    my_header_injector::MyHeaderInjector::new(config)
)),

// Step 3: Add to the names list (inside custom_plugin_names)
"my_header_injector",
```

### 3. Build

```bash
cargo build --release
```

That's it. No core files edited. Your plugin is now available to use in gateway configuration.

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
| `fn name(&self) -> &str` | Unique identifier for your plugin. Must match the config `plugin_name` and the factory match arm. |

### Optional Lifecycle Hooks

| Method | Phase | Can Reject? | Typical Use |
|--------|-------|-------------|-------------|
| `on_request_received(&mut ctx)` | Pre-routing | Yes | IP filtering, request validation, early termination |
| `authenticate(&mut ctx, &consumer_index)` | Authentication | Yes | Verify identity (JWT, API key, custom tokens) |
| `authorize(&mut ctx)` | Authorization | Yes | Check permissions, enforce rate limits |
| `before_proxy(&mut ctx, &mut headers)` | Pre-backend | Yes | Transform request headers, add tracing IDs |
| `after_proxy(&mut ctx, status, &mut headers)` | Post-backend | No* | Transform response headers |
| `log(&summary)` | Logging | No | Send transaction data to external systems |

*`after_proxy` return values are ignored — it cannot reject the response.

### Optional Capability Methods

| Method | Default | Description |
|--------|---------|-------------|
| `fn priority(&self) -> u16` | `5000` | Execution order (lower = earlier). See priority bands below. |
| `fn is_auth_plugin(&self) -> bool` | `false` | Set to `true` if your plugin participates in the authentication phase. |
| `fn requires_response_body_buffering(&self) -> bool` | `false` | Set to `true` if your plugin needs to inspect the response body. Disables streaming. |
| `fn warmup_hostnames(&self) -> Vec<String>` | `[]` | Hostnames your plugin connects to (for DNS pre-warming). |

## Priority Bands

Plugins execute in priority order (lowest number first) within each lifecycle phase. Choose a priority that places your plugin in the correct band:

| Band | Range | Purpose | Built-in Examples |
|------|-------|---------|-------------------|
| Preflight | 0–999 | Pre-processing, CORS, IP filtering | cors (100), ip_restriction (150) |
| Authentication | 1000–1999 | Identity verification | jwt_auth (1100), key_auth (1200) |
| Authorization | 2000–2999 | Access control, rate limiting | access_control (2000), rate_limiting (2900) |
| Request Transform | 3000–3999 | Modify request before backend | request_transformer (3000) |
| Response Transform | 4000–4999 | Modify response after backend | response_transformer (4000) |
| **Custom Default** | **5000** | **Default for custom plugins** | — |
| Logging | 9000–9999 | Observability, metrics | stdout_logging (9000), prometheus (9300) |

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
3. Set priority in the 1000–1999 range

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
- **Multi**: All auth plugins run. First success wins (sets the consumer). If all fail, the request is rejected.

Your auth plugin works with both modes automatically — just implement `authenticate()` and return `Continue` on success or `Reject` on failure.

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

Then in the factory registration:

```rust
// In custom_plugins/mod.rs, inside create_custom_plugin():
"my_webhook" => Some(Arc::new(
    my_webhook::MyWebhookPlugin::new(config, _http_client)
)),
```

The shared HTTP client provides connection pooling, keepalive, and DNS caching from the gateway's core infrastructure.

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

The `RequestContext` is a mutable struct passed through all lifecycle phases. Plugins can read and write to it:

```rust
pub struct RequestContext {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub matched_proxy: Option<Arc<Proxy>>,
    pub identified_consumer: Option<Consumer>,
    pub timestamp_received: DateTime<Utc>,
    pub metadata: HashMap<String, String>,  // inter-plugin communication
}
```

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

## Response Body Buffering

By default, the gateway streams responses from backend to client. If your plugin needs to inspect or transform the response body, override:

```rust
fn requires_response_body_buffering(&self) -> bool {
    true
}
```

This forces the gateway to buffer the entire response before forwarding it. Use this sparingly — it increases memory usage and latency.

## Directory Structure

```
ferrum-gateway/
├── src/                       # Core gateway source (do not edit for custom plugins)
│   ├── plugins/
│   │   ├── mod.rs             # Plugin trait, factory (auto-delegates to custom_plugins)
│   │   ├── jwt_auth.rs        # Built-in plugins...
│   │   └── ...
│   ├── main.rs
│   └── lib.rs
├── custom_plugins/            # YOUR PLUGINS GO HERE
│   ├── mod.rs                 # Registry: declare modules, register in factory
│   ├── example_plugin.rs      # Working example (can be removed)
│   ├── my_header_injector.rs  # Your plugin
│   └── my_custom_auth.rs      # Your plugin
├── CUSTOM_PLUGINS.md          # This guide
└── Cargo.toml
```

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

The output binary at `target/release/ferrum-gateway` includes your custom plugins compiled in.

### Docker Build

The included `Dockerfile` works with custom plugins out of the box since `custom_plugins/` is part of the project tree:

```bash
docker build -t my-ferrum-gateway .
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

- [ ] Plugin file created in `custom_plugins/`
- [ ] Module declared in `custom_plugins/mod.rs`
- [ ] Plugin registered in `create_custom_plugin()` match arm
- [ ] Plugin name added to `custom_plugin_names()`
- [ ] Priority set appropriately for the execution phase
- [ ] `is_auth_plugin()` returns `true` if it's an auth plugin
- [ ] `requires_response_body_buffering()` returns `true` if needed
- [ ] `warmup_hostnames()` returns external hosts if applicable
- [ ] Unit tests written and passing
- [ ] `cargo build` succeeds with no warnings
