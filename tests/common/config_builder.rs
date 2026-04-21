//! Fluent builders for `GatewayConfig`, `Proxy`, `Consumer`, `Upstream`,
//! and `PluginConfig`.
//!
//! All builders produce `serde_json::Value`, which serialises identically
//! for:
//! - admin API request bodies (`POST /proxies`, etc.),
//! - file-mode YAML config (serde_yaml from a Value),
//! - test assertions (shape comparison via serde_json).
//!
//! Why not use `ferrum_edge::config::types::Proxy` directly? Those structs
//! require many fields and aren't ergonomic for partial-field fixtures. The
//! builders match the shape admin API handlers accept, which lets tests
//! stay terse without sacrificing type safety on the fields they care about.
//!
//! Matches the conventions in `tests/functional/namespace_helpers.rs` which
//! has been in use for namespace tests.

use serde_json::{Map, Value, json};
use std::path::Path;

// ────── Proxy ─────────────────────────────────────────────────────────────

/// Fluent builder for a proxy JSON value.
///
/// ```ignore
/// let p = ProxyBuilder::new("echo")
///     .listen_path("/echo")
///     .backend("127.0.0.1", 8080)
///     .strip_listen_path(true)
///     .build();
/// ```
pub struct ProxyBuilder {
    inner: Map<String, Value>,
}

impl ProxyBuilder {
    /// Start a new HTTP proxy with `id`. Defaults: `backend_scheme=http`,
    /// `strip_listen_path=true`. Callers must still set `listen_path` or at
    /// least one host (HTTP-family proxies need at least one) before
    /// `build()` — the builder does not enforce that.
    pub fn new(id: impl Into<String>) -> Self {
        let mut inner = Map::new();
        inner.insert("id".into(), Value::String(id.into()));
        inner.insert("backend_scheme".into(), Value::String("http".into()));
        inner.insert("strip_listen_path".into(), Value::Bool(true));
        Self { inner }
    }

    /// Start a stream proxy. Caller must still set `backend_scheme`
    /// (`tcp`, `tcps`, `udp`, or `dtls`) via [`Self::backend_scheme`]
    /// and `listen_port` via [`Self::listen_port`].
    pub fn new_stream(id: impl Into<String>) -> Self {
        let mut inner = Map::new();
        inner.insert("id".into(), Value::String(id.into()));
        Self { inner }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.inner.insert("name".into(), Value::String(name.into()));
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.inner
            .insert("namespace".into(), Value::String(namespace.into()));
        self
    }

    pub fn listen_path(mut self, path: impl Into<String>) -> Self {
        self.inner
            .insert("listen_path".into(), Value::String(path.into()));
        self
    }

    pub fn listen_port(mut self, port: u16) -> Self {
        self.inner.insert("listen_port".into(), json!(port));
        self
    }

    /// Set `hosts` to a single host. Use [`Self::hosts`] for multiple.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.inner.insert(
            "hosts".into(),
            Value::Array(vec![Value::String(host.into())]),
        );
        self
    }

    pub fn hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let arr: Vec<Value> = hosts.into_iter().map(|s| Value::String(s.into())).collect();
        self.inner.insert("hosts".into(), Value::Array(arr));
        self
    }

    pub fn backend(mut self, host: impl Into<String>, port: u16) -> Self {
        self.inner
            .insert("backend_host".into(), Value::String(host.into()));
        self.inner.insert("backend_port".into(), json!(port));
        self
    }

    /// Set the proxy's backend scheme (wire + TLS). Accepts a string literal
    /// matching one of `http`, `https`, `tcp`, `tcps`, `udp`, `dtls`. The
    /// builder omits the field when this method is not called — the gateway
    /// then defaults HTTP-family proxies to `https` during normalization.
    pub fn backend_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.inner
            .insert("backend_scheme".into(), Value::String(scheme.into()));
        self
    }

    /// Opt the proxy into preferring HTTP/3 to the backend. Only meaningful
    /// when `backend_scheme == "https"`; validation rejects `true` with
    /// other schemes.
    pub fn backend_prefer_h3(mut self, prefer: bool) -> Self {
        self.inner
            .insert("backend_prefer_h3".into(), Value::Bool(prefer));
        self
    }

    pub fn backend_path(mut self, path: impl Into<String>) -> Self {
        self.inner
            .insert("backend_path".into(), Value::String(path.into()));
        self
    }

    pub fn strip_listen_path(mut self, strip: bool) -> Self {
        self.inner
            .insert("strip_listen_path".into(), Value::Bool(strip));
        self
    }

    pub fn preserve_host_header(mut self, preserve: bool) -> Self {
        self.inner
            .insert("preserve_host_header".into(), Value::Bool(preserve));
        self
    }

    pub fn upstream_id(mut self, upstream_id: impl Into<String>) -> Self {
        self.inner
            .insert("upstream_id".into(), Value::String(upstream_id.into()));
        // Clear backend_host/port if we're switching to an upstream — some
        // tests round-trip both, but callers can re-add them if they want.
        self.inner.remove("backend_host");
        self.inner.remove("backend_port");
        self
    }

    pub fn frontend_tls(mut self, tls: bool) -> Self {
        self.inner.insert("frontend_tls".into(), Value::Bool(tls));
        self
    }

    pub fn passthrough(mut self, passthrough: bool) -> Self {
        self.inner
            .insert("passthrough".into(), Value::Bool(passthrough));
        self
    }

    pub fn plugins<I, S>(mut self, plugin_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let arr: Vec<Value> = plugin_ids
            .into_iter()
            .map(|s| Value::String(s.into()))
            .collect();
        self.inner.insert("plugins".into(), Value::Array(arr));
        self
    }

    /// Escape hatch for arbitrary field assignment. Value is not validated.
    pub fn field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.inner.insert(key.into(), value);
        self
    }

    pub fn build(self) -> Value {
        Value::Object(self.inner)
    }
}

// ────── Consumer ──────────────────────────────────────────────────────────

/// Fluent builder for a consumer JSON value.
pub struct ConsumerBuilder {
    inner: Map<String, Value>,
}

impl ConsumerBuilder {
    pub fn new(id: impl Into<String>, username: impl Into<String>) -> Self {
        let mut inner = Map::new();
        inner.insert("id".into(), Value::String(id.into()));
        inner.insert("username".into(), Value::String(username.into()));
        Self { inner }
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.inner
            .insert("namespace".into(), Value::String(namespace.into()));
        self
    }

    pub fn custom_id(mut self, custom_id: impl Into<String>) -> Self {
        self.inner
            .insert("custom_id".into(), Value::String(custom_id.into()));
        self
    }

    pub fn acl_groups<I, S>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let arr: Vec<Value> = groups
            .into_iter()
            .map(|s| Value::String(s.into()))
            .collect();
        self.inner.insert("acl_groups".into(), Value::Array(arr));
        self
    }

    /// Set a single credential entry for `cred_type`. The admin API accepts
    /// either a single object or an array — this writes a single object.
    /// For multi-credential rotation, use [`Self::credentials_multi`].
    pub fn credential(mut self, cred_type: impl Into<String>, value: Value) -> Self {
        let credentials = self
            .inner
            .entry("credentials".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = credentials {
            map.insert(cred_type.into(), value);
        }
        self
    }

    /// Set multiple credential entries for `cred_type` (array form, for
    /// rotation per `FERRUM_MAX_CREDENTIALS_PER_TYPE`).
    pub fn credentials_multi(mut self, cred_type: impl Into<String>, values: Vec<Value>) -> Self {
        let credentials = self
            .inner
            .entry("credentials".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = credentials {
            map.insert(cred_type.into(), Value::Array(values));
        }
        self
    }

    pub fn tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let arr: Vec<Value> = tags.into_iter().map(|s| Value::String(s.into())).collect();
        self.inner.insert("tags".into(), Value::Array(arr));
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.inner.insert(key.into(), value);
        self
    }

    pub fn build(self) -> Value {
        Value::Object(self.inner)
    }
}

// ────── Upstream ──────────────────────────────────────────────────────────

/// Fluent builder for an upstream JSON value.
pub struct UpstreamBuilder {
    inner: Map<String, Value>,
    targets: Vec<Value>,
}

impl UpstreamBuilder {
    /// Start a new upstream. Defaults: `algorithm=round_robin`.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut inner = Map::new();
        inner.insert("id".into(), Value::String(id.into()));
        inner.insert("name".into(), Value::String(name.into()));
        inner.insert("algorithm".into(), Value::String("round_robin".into()));
        Self {
            inner,
            targets: Vec::new(),
        }
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.inner
            .insert("namespace".into(), Value::String(namespace.into()));
        self
    }

    pub fn algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.inner
            .insert("algorithm".into(), Value::String(algorithm.into()));
        self
    }

    pub fn target(mut self, host: impl Into<String>, port: u16, weight: u32) -> Self {
        self.targets.push(json!({
            "host": host.into(),
            "port": port,
            "weight": weight,
        }));
        self
    }

    pub fn target_with_path(
        mut self,
        host: impl Into<String>,
        port: u16,
        weight: u32,
        path: impl Into<String>,
    ) -> Self {
        self.targets.push(json!({
            "host": host.into(),
            "port": port,
            "weight": weight,
            "path": path.into(),
        }));
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.inner.insert(key.into(), value);
        self
    }

    pub fn build(mut self) -> Value {
        self.inner
            .insert("targets".into(), Value::Array(self.targets));
        Value::Object(self.inner)
    }
}

// ────── PluginConfig ──────────────────────────────────────────────────────

/// Fluent builder for a plugin config JSON value.
pub struct PluginConfigBuilder {
    inner: Map<String, Value>,
}

impl PluginConfigBuilder {
    /// Start a new plugin config with the given `id` and `plugin_name`.
    /// Defaults: `enabled=true`, `scope="global"`, empty `config={}`.
    ///
    /// The wire field is `plugin_name` (see [`PluginConfig`] in
    /// `src/config/types.rs`), not `name` — the admin API will reject the
    /// `name` key with HTTP 400.
    ///
    /// [`PluginConfig`]: ferrum_edge::config::types::PluginConfig
    pub fn new(id: impl Into<String>, plugin_name: impl Into<String>) -> Self {
        let mut inner = Map::new();
        inner.insert("id".into(), Value::String(id.into()));
        inner.insert("plugin_name".into(), Value::String(plugin_name.into()));
        inner.insert("enabled".into(), Value::Bool(true));
        inner.insert("scope".into(), Value::String("global".into()));
        inner.insert("config".into(), Value::Object(Map::new()));
        Self { inner }
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.inner
            .insert("namespace".into(), Value::String(namespace.into()));
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.inner.insert("enabled".into(), Value::Bool(enabled));
        self
    }

    /// Set the scope: `"global"`, `"proxy"`, or `"proxy_group"`.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.inner
            .insert("scope".into(), Value::String(scope.into()));
        self
    }

    pub fn proxy_id(mut self, proxy_id: impl Into<String>) -> Self {
        self.inner
            .insert("proxy_id".into(), Value::String(proxy_id.into()));
        self
    }

    pub fn priority_override(mut self, priority: u16) -> Self {
        self.inner
            .insert("priority_override".into(), json!(priority));
        self
    }

    /// Replace the entire `config` object.
    pub fn config(mut self, config: Value) -> Self {
        self.inner.insert("config".into(), config);
        self
    }

    /// Merge a key into the existing `config` object.
    pub fn config_field(mut self, key: impl Into<String>, value: Value) -> Self {
        let config = self
            .inner
            .entry("config".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = config {
            map.insert(key.into(), value);
        }
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.inner.insert(key.into(), value);
        self
    }

    pub fn build(self) -> Value {
        Value::Object(self.inner)
    }
}

// ────── GatewayConfig ─────────────────────────────────────────────────────

/// Builder for a file-mode YAML config shape: `{proxies, consumers, upstreams, plugin_configs}`.
pub struct GatewayConfigBuilder {
    proxies: Vec<Value>,
    consumers: Vec<Value>,
    upstreams: Vec<Value>,
    plugin_configs: Vec<Value>,
}

impl Default for GatewayConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayConfigBuilder {
    pub fn new() -> Self {
        Self {
            proxies: Vec::new(),
            consumers: Vec::new(),
            upstreams: Vec::new(),
            plugin_configs: Vec::new(),
        }
    }

    pub fn proxy(mut self, proxy: Value) -> Self {
        self.proxies.push(proxy);
        self
    }

    pub fn consumer(mut self, consumer: Value) -> Self {
        self.consumers.push(consumer);
        self
    }

    pub fn upstream(mut self, upstream: Value) -> Self {
        self.upstreams.push(upstream);
        self
    }

    pub fn plugin_config(mut self, plugin: Value) -> Self {
        self.plugin_configs.push(plugin);
        self
    }

    /// Produce the `{proxies: [...], consumers: [...], upstreams: [...],
    /// plugin_configs: [...]}` JSON value suitable for file-mode YAML.
    pub fn build(self) -> Value {
        json!({
            "proxies": self.proxies,
            "consumers": self.consumers,
            "upstreams": self.upstreams,
            "plugin_configs": self.plugin_configs,
        })
    }

    /// Write the built config as YAML to `path`. Equivalent to
    /// `write_yaml_value(path, &self.build())`.
    pub fn write_yaml(self, path: &Path) -> Result<(), std::io::Error> {
        write_yaml_value(path, &self.build())
    }
}

/// Serialise a `serde_json::Value` as YAML and write it to `path`.
pub fn write_yaml_value(path: &Path, value: &Value) -> Result<(), std::io::Error> {
    let yaml = serde_yaml::to_string(value)
        .map_err(|e| std::io::Error::other(format!("yaml serialise: {e}")))?;
    std::fs::write(path, yaml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_builder_minimal() {
        let p = ProxyBuilder::new("echo")
            .listen_path("/echo")
            .backend("127.0.0.1", 8080)
            .build();
        assert_eq!(p["id"], "echo");
        assert_eq!(p["listen_path"], "/echo");
        assert_eq!(p["backend_host"], "127.0.0.1");
        assert_eq!(p["backend_port"], 8080);
        assert_eq!(p["backend_scheme"], "http");
        assert_eq!(p["strip_listen_path"], true);
    }

    #[test]
    fn proxy_builder_host_only() {
        let p = ProxyBuilder::new("h")
            .host("example.com")
            .backend("127.0.0.1", 9999)
            .build();
        assert_eq!(p["hosts"][0], "example.com");
        assert!(p.get("listen_path").is_none());
    }

    #[test]
    fn proxy_builder_upstream_clears_backend() {
        let p = ProxyBuilder::new("u")
            .listen_path("/u")
            .backend("127.0.0.1", 8080)
            .upstream_id("up-1")
            .build();
        assert_eq!(p["upstream_id"], "up-1");
        assert!(p.get("backend_host").is_none());
        assert!(p.get("backend_port").is_none());
    }

    #[test]
    fn stream_proxy_builder_no_listen_path() {
        let p = ProxyBuilder::new_stream("tcp-proxy")
            .backend_scheme("tcp")
            .listen_port(7000)
            .backend("127.0.0.1", 7100)
            .build();
        assert_eq!(p["listen_port"], 7000);
        assert_eq!(p["backend_scheme"], "tcp");
        assert!(p.get("listen_path").is_none());
    }

    #[test]
    fn consumer_builder_credentials() {
        let c = ConsumerBuilder::new("c1", "alice")
            .credential("keyauth", json!({"key": "secret"}))
            .credential("basicauth", json!({"username": "alice", "password": "pw"}))
            .build();
        assert_eq!(c["credentials"]["keyauth"]["key"], "secret");
        assert_eq!(c["credentials"]["basicauth"]["username"], "alice");
    }

    #[test]
    fn consumer_builder_multi_credentials() {
        let c = ConsumerBuilder::new("c1", "alice")
            .credentials_multi("keyauth", vec![json!({"key": "k1"}), json!({"key": "k2"})])
            .build();
        let arr = c["credentials"]["keyauth"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["key"], "k1");
        assert_eq!(arr[1]["key"], "k2");
    }

    #[test]
    fn upstream_builder_targets() {
        let u = UpstreamBuilder::new("u1", "my-upstream")
            .algorithm("least_connections")
            .target("127.0.0.1", 8001, 1)
            .target("127.0.0.1", 8002, 2)
            .build();
        assert_eq!(u["algorithm"], "least_connections");
        let targets = u["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0]["port"], 8001);
        assert_eq!(targets[1]["weight"], 2);
    }

    #[test]
    fn plugin_config_builder_config_fields() {
        let pc = PluginConfigBuilder::new("pc1", "rate_limiting")
            .scope("proxy")
            .proxy_id("p1")
            .config_field("minute", json!(60))
            .config_field("limit_by", json!("ip"))
            .build();
        assert_eq!(pc["scope"], "proxy");
        assert_eq!(pc["proxy_id"], "p1");
        assert_eq!(pc["config"]["minute"], 60);
        assert_eq!(pc["config"]["limit_by"], "ip");
    }

    #[test]
    fn gateway_config_builder() {
        let cfg = GatewayConfigBuilder::new()
            .proxy(
                ProxyBuilder::new("p1")
                    .listen_path("/a")
                    .backend("127.0.0.1", 8080)
                    .build(),
            )
            .consumer(ConsumerBuilder::new("c1", "alice").build())
            .upstream(
                UpstreamBuilder::new("u1", "my-up")
                    .target("127.0.0.1", 9000, 1)
                    .build(),
            )
            .plugin_config(PluginConfigBuilder::new("pc1", "cors").build())
            .build();
        assert_eq!(cfg["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["consumers"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["upstreams"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["plugin_configs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn write_yaml_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        let cfg = GatewayConfigBuilder::new()
            .proxy(
                ProxyBuilder::new("p1")
                    .listen_path("/a")
                    .backend("127.0.0.1", 8080)
                    .build(),
            )
            .build();
        write_yaml_value(&path, &cfg).unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert!(read.contains("listen_path: /a"));
        assert!(read.contains("backend_host: 127.0.0.1"));
    }
}
