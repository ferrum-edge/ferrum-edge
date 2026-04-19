//! Shared helpers for multi-namespace functional tests.
//!
//! These helpers centralize the X-Ferrum-Namespace header handling, JWT auth,
//! and JSON factories that several namespace tests need. Placed in a single
//! module so that any change to e.g. the admin header name or JWT claim shape
//! is applied uniformly across SQLite/Postgres/MySQL/MongoDB test runs.
//!
//! This module is `#[allow(dead_code)]` — individual tests consume only the
//! subset of helpers relevant to them.
#![allow(dead_code)]

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use uuid::Uuid;

pub const JWT_SECRET: &str = "namespace-test-secret-key-1234567890";
pub const JWT_ISSUER: &str = "ferrum-edge-namespace-test";

/// Mint a short-lived admin JWT using `JWT_SECRET` / `JWT_ISSUER`.
pub fn admin_jwt() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "namespace-test-admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(JWT_SECRET.as_bytes());
    encode(&header, &claims, &key).expect("encode admin JWT")
}

/// Locate the `ferrum-edge` binary built by `cargo build`.
pub fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

/// Send an authenticated admin API request with an optional `X-Ferrum-Namespace`
/// header. When `namespace` is `None` the header is omitted so server-side
/// defaulting behavior can be exercised.
pub async fn admin_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    namespace: Option<&str>,
    body: Option<&Value>,
) -> reqwest::Response {
    let mut req = client
        .request(method, url)
        .header("Authorization", format!("Bearer {}", admin_jwt()));
    if let Some(ns) = namespace {
        req = req.header("X-Ferrum-Namespace", ns);
    }
    if let Some(body) = body {
        req = req.json(body);
    }
    req.send().await.expect("admin request send")
}

/// Assert a JSON array of resources all carry the expected `namespace` field.
///
/// The admin list endpoints either return a raw array or `{"data": [...], ...}`
/// when paginated. This helper handles both shapes.
pub fn assert_only_namespace(body: &Value, expected_ns: &str) {
    let arr = if body.is_array() {
        body.as_array().unwrap()
    } else if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        arr
    } else {
        panic!("unexpected list response shape: {body}");
    };
    for item in arr {
        let actual = item
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        assert_eq!(
            actual, expected_ns,
            "resource leaked from another namespace: {item}"
        );
    }
}

/// Count items in either a bare-array or a `{data: [...]}` paginated response.
pub fn list_len(body: &Value) -> usize {
    if let Some(arr) = body.as_array() {
        arr.len()
    } else if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        arr.len()
    } else {
        panic!("unexpected list response shape: {body}");
    }
}

/// Minimal HTTP proxy JSON suitable for POST /proxies.
pub fn sample_proxy(id: &str, listen_path: &str, backend_port: u16) -> Value {
    json!({
        "id": id,
        "listen_path": listen_path,
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
    })
}

/// Proxy with an explicit `name` set (for name-uniqueness tests).
pub fn sample_proxy_with_name(id: &str, name: &str, listen_path: &str, backend_port: u16) -> Value {
    json!({
        "id": id,
        "name": name,
        "listen_path": listen_path,
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
    })
}

/// Minimal TCP stream proxy JSON with a `listen_port` (for port-uniqueness tests).
///
/// Stream proxies route on `listen_port` and must NOT set `listen_path`.
/// Sending `"listen_path": ""` — or any value — would be rejected by validation.
pub fn sample_stream_proxy(id: &str, listen_port: u16, backend_port: u16) -> Value {
    json!({
        "id": id,
        "backend_protocol": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "listen_port": listen_port,
    })
}

/// Minimal host-only HTTP proxy JSON — routes all traffic on the given host.
/// Produces a body with a `hosts` list and no `listen_path` key. HTTP-family
/// proxies MUST set at least one of `hosts` or `listen_path`; a host-only
/// proxy uses `hosts` alone.
pub fn sample_host_only_proxy(id: &str, host: &str, backend_port: u16) -> Value {
    json!({
        "id": id,
        "hosts": [host],
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
    })
}

/// Minimal consumer JSON.
pub fn sample_consumer(id: &str, username: &str, custom_id: Option<&str>) -> Value {
    let mut v = json!({
        "id": id,
        "username": username,
    });
    if let Some(cid) = custom_id {
        v["custom_id"] = json!(cid);
    }
    v
}

/// Minimal upstream JSON.
pub fn sample_upstream(id: &str, name: &str, backend_port: u16) -> Value {
    json!({
        "id": id,
        "name": name,
        "algorithm": "round_robin",
        "targets": [{
            "host": "127.0.0.1",
            "port": backend_port,
            "weight": 1,
        }],
    })
}

/// Bind an ephemeral port, return the assigned port, and drop the listener.
/// Not race-free — use the retry-with-rebind pattern for listeners the gateway
/// itself will bind.
pub async fn ephemeral_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}
