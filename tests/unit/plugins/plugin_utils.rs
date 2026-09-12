//! Common test utilities for plugin tests

use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, PluginAssociation, PluginConfig, PluginScope,
    Proxy, default_namespace,
};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use hmac::{KeyInit, Mac};
use http::HeaderMap;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Read one HTTP/1.1 request and discard its body through `Content-Length`.
///
/// Keep-alive fixtures must drain the request body before responding; leaving
/// unread body bytes on the socket breaks reuse for later POSTs on the connection
/// (transaction-summary batches are often larger than a single 1 KiB read).
pub async fn read_http11_request_headers(socket: &mut TcpStream) -> bool {
    read_http11_request_body(socket).await.is_some()
}

/// Read one HTTP/1.1 request and return its body bytes (after draining
/// `Content-Length`). Returns `None` on EOF or malformed framing.
pub async fn read_http11_request_body(socket: &mut TcpStream) -> Option<Vec<u8>> {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    let header_end = loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) => return None,
            Ok(n) => n,
            Err(_) => return None,
        };
        request.extend_from_slice(&buf[..n]);
        if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
        if request.len() > 64 * 1024 {
            return None;
        }
    };

    let content_length = std::str::from_utf8(&request[..header_end])
        .ok()
        .and_then(|headers| {
            headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);

    let mut body = request[header_end..].to_vec();
    while body.len() < content_length {
        let want = (content_length - body.len()).min(buf.len());
        match socket.read(&mut buf[..want]).await {
            Ok(0) => return None,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(_) => return None,
        }
    }
    body.truncate(content_length);
    Some(body)
}

/// Test-only HMAC secret matching the value set in test env vars.
const TEST_HMAC_SECRET: &str = "test-hmac-secret-for-basic-auth-unit-tests";

fn hmac_sha256_password_hash(password: &str) -> String {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(TEST_HMAC_SECRET.as_bytes()).unwrap();
    mac.update(password.as_bytes());
    format!("hmac_sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

/// Create a test consumer with all credential types
pub fn create_test_consumer() -> Consumer {
    let mut credentials = HashMap::new();
    let mut keyauth_creds = Map::new();
    keyauth_creds.insert("key".to_string(), Value::String("test-api-key".to_string()));
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(keyauth_creds)]),
    );

    let mut basicauth_creds = Map::new();
    basicauth_creds.insert(
        "password_hash".to_string(),
        Value::String(hmac_sha256_password_hash("password")),
    );
    credentials.insert(
        "basicauth".to_string(),
        Value::Array(vec![Value::Object(basicauth_creds)]),
    );

    let mut jwt_creds = Map::new();
    jwt_creds.insert(
        "secret".to_string(),
        Value::String("test-jwt-secret".to_string()),
    );
    credentials.insert(
        "jwt".to_string(),
        Value::Array(vec![Value::Object(jwt_creds)]),
    );

    Consumer {
        id: "test-consumer".to_string(),
        namespace: default_namespace(),
        username: "testuser".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a test request context with common headers
pub fn create_test_context() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.headers
        .insert("Authorization".to_string(), "Bearer test-token".to_string());
    ctx.headers
        .insert("X-API-Key".to_string(), "test-api-key".to_string());
    ctx.headers
        .insert("User-Agent".to_string(), "test-agent".to_string());

    // Set a test consumer so access control plugin doesn't reject
    ctx.identified_consumer = Some(std::sync::Arc::new(create_test_consumer()));
    ctx
}

/// Build a request context whose raw header map contains `value`, then run
/// `materialize_headers()`.
///
/// `value` is always valid UTF-8, so materialization keeps it byte-exact (issue
/// #5010). The divergence these repros exercise is the RFC-bound visible-ASCII
/// credential policy in `header_extract`, which reads the retained RAW map and
/// still reports a non-ASCII field line as present-but-malformed.
pub fn context_with_materialized_raw_header(name: &str, value: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.headers.clear();
    ctx.identified_consumer = None;

    let mut raw = HeaderMap::new();
    let header_name = http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
    raw.insert(
        header_name,
        http::HeaderValue::from_bytes(value.as_bytes()).expect("valid header bytes"),
    );
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    assert_eq!(
        ctx.headers
            .get(name.to_ascii_lowercase().as_str())
            .map(String::as_str),
        Some(value),
        "valid UTF-8 header values must be materialized byte-exact in this repro"
    );
    ctx
}

/// Build a request context from raw header bytes, then materialize the map.
///
/// Bytes that are not valid UTF-8 cannot be represented in the materialized map
/// and stay out of it; valid UTF-8 is materialized byte-exact.
pub fn context_with_materialized_raw_header_bytes(name: &str, value: &[u8]) -> RequestContext {
    let ctx = context_with_materialized_raw_header_lines(name, &[value]);
    if std::str::from_utf8(value).is_err() {
        assert!(
            !ctx.headers.contains_key(name.to_ascii_lowercase().as_str())
                && !ctx.headers.contains_key(name),
            "non-UTF-8 header values must stay out of the materialized map in this repro"
        );
    }
    ctx
}

/// Build a request context from repeated raw header field lines, including
/// field lines that the materialized map cannot represent.
pub fn context_with_materialized_raw_header_lines(name: &str, values: &[&[u8]]) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.headers.clear();
    ctx.identified_consumer = None;

    let mut raw = HeaderMap::new();
    let header_name = http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
    for value in values {
        raw.append(
            header_name.clone(),
            http::HeaderValue::from_bytes(value).expect("valid header bytes"),
        );
    }
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx
}

/// Assert that a plugin result is Reject with the expected JSON body.
#[allow(dead_code)]
pub fn assert_reject_body(result: PluginResult, expected_body: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 401);
            assert_eq!(body, expected_body);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

/// Create a test proxy with default configuration
#[allow(dead_code)]
pub fn create_test_proxy() -> Proxy {
    Proxy {
        id: "test-proxy".to_string(),
        namespace: default_namespace(),
        name: Some("Test Proxy".to_string()),
        hosts: vec![],
        listen_path: Some("/test".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

/// Create a test transaction summary for logging plugins
#[allow(dead_code)]
pub fn create_test_transaction_summary() -> ferrum_edge::plugins::TransactionSummary {
    ferrum_edge::plugins::TransactionSummary {
        // Terminal-log trigger carrier: stamped centrally by
        // `log_with_mirror` from the authoritative RequestContext.
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: Utc::now().to_rfc3339(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some("testuser".to_string()),
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some("test-proxy".to_string()),
        proxy_name: Some("Test Proxy".to_string()),
        backend_target: Some("http://localhost:3000/test".to_string()),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        response_status_code: 200,
        latency_total_ms: 100.0,
        latency_gateway_processing_ms: 10.0,
        latency_backend_ttfb_ms: 80.0,
        latency_backend_total_ms: 90.0,
        latency_plugin_execution_ms: 5.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 5.0,
        request_user_agent: Some("test-agent".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

/// Create a test stream transaction summary for stream-aware logging plugins
#[allow(dead_code)]
pub fn create_test_stream_transaction_summary() -> ferrum_edge::plugins::StreamTransactionSummary {
    ferrum_edge::plugins::StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        proxy_id: "test-stream-proxy".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("Test Stream Proxy".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some("testuser".to_string()),
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 9000,
        duration_ms: 25.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: Utc::now().to_rfc3339(),
        timestamp_disconnected: Utc::now().to_rfc3339(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

/// Apply the production pre-`before_proxy` request-normalization phase to a
/// gzip- or Brotli-encoded body and return the plaintext request views.
///
/// This is shared by composition tests for body-aware plugins that run before
/// the configured `compression` plugin in ordinary hook priority order.
pub async fn normalize_compressed_request_for_plugin_test(
    content_type: &str,
    path: &str,
    encoding: &str,
    plaintext: &[u8],
) -> (RequestContext, HashMap<String, String>, Vec<u8>) {
    use ferrum_edge::_test_support::apply_buffered_request_body_normalization_before_before_proxy_for_test;
    use ferrum_edge::plugins::compression::CompressionPlugin;

    let mut body = match encoding {
        "gzip" => {
            use flate2::write::GzEncoder;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(plaintext).unwrap();
            encoder.finish().unwrap()
        }
        "br" => {
            let params = brotli::enc::BrotliEncoderParams::default();
            let mut compressed = Vec::new();
            brotli::BrotliCompress(&mut &plaintext[..], &mut compressed, &params).unwrap();
            compressed
        }
        other => panic!("unsupported test encoding {other}"),
    };

    let compression =
        Arc::new(CompressionPlugin::new(&serde_json::json!({"decompress_request": true})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        path.to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    ctx.headers
        .insert("content-encoding".to_string(), encoding.to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(&body));
    let mut headers = ctx.headers.clone();
    headers.insert("content-length".to_string(), body.len().to_string());
    let plugins: Vec<Arc<dyn Plugin>> = vec![compression];

    let result = apply_buffered_request_body_normalization_before_before_proxy_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
    )
    .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body, plaintext);
    assert_eq!(ctx.request_body_bytes.as_deref(), Some(plaintext));
    assert_eq!(
        ctx.metadata.get("request_body").map(String::as_bytes),
        Some(plaintext)
    );
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    ctx.headers = headers.clone();
    (ctx, headers, body)
}

/// Assert that a plugin result is Continue
#[allow(dead_code)]
pub fn assert_continue(result: PluginResult) {
    match result {
        PluginResult::Continue => {}
        _ => panic!("Expected Continue, got {:?}", result),
    }
}

/// Assert that a validated far-future credential expiry was admitted without an
/// *effective* deadline (issue #5420).
///
/// Which of the two admissible answers a platform gives is decided by its
/// monotonic clock rather than by the plugin: a `timespec`-backed
/// `tokio::time::Instant` carries `i64` seconds and can express
/// `now + (i64::MAX - now_unix)`, so it publishes that astronomically distant
/// bound, while a narrower representation saturates and publishes no bound at
/// all. Both admit the credential. What must never happen — the regression
/// issue #5420 fixed — is a bound that has ALREADY elapsed, which is how the
/// old collapse onto `now` presented a token the JWT layer had just validated
/// as live.
///
/// The conversion's `Unbounded` branch itself is proven deterministically, on
/// every platform, by the injected-clock tests in
/// `auth_flow_credential_deadline_tests`.
#[allow(dead_code)]
pub fn assert_no_effective_credential_deadline(ctx: &RequestContext) {
    // Longer than any authenticated stream this gateway holds open, so a
    // deadline still beyond it is indistinguishable from an absent one.
    const A_YEAR: std::time::Duration = std::time::Duration::from_secs(365 * 24 * 60 * 60);

    if let Some(deadline) = ferrum_edge::_test_support::request_credential_deadline_at(ctx) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            remaining > A_YEAR,
            "a validated far-future expiry must publish either no monotonic bound or one \
             far beyond any real session, never one that already elapsed: {remaining:?} left"
        );
    }
}

/// Assert that a plugin result is Reject with optional status code check
#[allow(dead_code)]
pub fn assert_reject(result: PluginResult, expected_status: Option<u16>) {
    match result {
        PluginResult::Reject { status_code, .. } => {
            if let Some(expected) = expected_status {
                assert_eq!(
                    status_code, expected,
                    "Expected status {}, got {}",
                    expected, status_code
                );
            }
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tracing capture (advisory GHSA-8594-2xhc-8g38 sink-URL redaction tests)
// ---------------------------------------------------------------------------

/// In-memory `tracing` sink for asserting that a diagnostic never renders a
/// credential.
///
/// Log-capture assertions for the observability sinks are negative ("this
/// sentinel must not appear anywhere"), so they need the complete emitted text
/// rather than a structured record.
#[derive(Clone, Default)]
pub struct CapturedLogs {
    buffer: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl CapturedLogs {
    #[allow(dead_code)]
    pub fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

pub struct CapturedLogsGuard {
    buffer: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturedLogsGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogsGuard;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogsGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

/// A global `tracing` dispatcher whose only job is to keep callsite interest
/// from collapsing to `never`. `tracing::subscriber::set_default` installs a
/// thread-local dispatcher and does NOT rebuild the global interest cache, so a
/// callsite that some other test hit first (before any dispatcher existed) can
/// stay cached as disabled and a later thread-local capture sees nothing. With
/// this floor registered, `rebuild_interest_cache()` yields `sometimes` for
/// every callsite and captures work regardless of test ordering. The unit suite
/// is split across several test binaries, so no test may rely on another
/// module having installed a global subscriber earlier in the process.
struct InterestFloorSubscriber;

impl tracing::Subscriber for InterestFloorSubscriber {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install [`InterestFloorSubscriber`] as the global default exactly once for
/// this test binary. Idempotent and tolerant of an already-set global default.
/// Call it before installing a thread-local capturing subscriber, then run
/// `tracing::callsite::rebuild_interest_cache()` after `set_default`.
#[allow(dead_code)]
pub fn install_interest_floor() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(InterestFloorSubscriber);
    });
}

/// Guarantee `FERRUM_BASIC_AUTH_HMAC_SECRET` is set for tests that construct
/// every registered plugin (`basic_auth` refuses to start without it). The
/// monolithic unit binary used to inherit the value from `basic_auth_tests`
/// running earlier in the same process; each split binary must set it itself.
/// Sets only when absent, under the shared env lock, so env-scoped tests that
/// deliberately clear the variable are not raced.
#[allow(dead_code)]
pub fn ensure_basic_auth_test_secret() {
    const KEY: &str = "FERRUM_BASIC_AUTH_HMAC_SECRET";
    let _guard = crate::unit::env_lock::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if std::env::var_os(KEY).is_none() {
        // SAFETY: serialized by ENV_LOCK with every env-mutating unit test, and
        // the value is a fixed test constant set once for the process.
        unsafe {
            std::env::set_var(KEY, "unit-test-basic-auth-hmac-secret-0123456789abcdef");
        }
    }
}

/// Install a thread-local capturing subscriber for the duration of the returned
/// guard. Use `flavor = "current_thread"` so plugin flush workers stay on the
/// thread the subscriber is installed for.
#[allow(dead_code)]
pub fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    capture_logs_at_level(tracing::Level::INFO)
}

/// Capture every event when a diagnostic's warning is shared and sampled.
#[allow(dead_code)]
pub fn capture_debug_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    capture_logs_at_level(tracing::Level::DEBUG)
}

fn capture_logs_at_level(
    level: tracing::Level,
) -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    install_interest_floor();
    let writer = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    (writer, guard)
}

/// Assert that no sentinel — and no raw credential-bearing URL — survived into
/// captured diagnostics.
#[allow(dead_code)]
pub fn assert_no_secrets(logs: &str, context: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !logs.contains(secret),
            "{context} leaked {secret:?} into diagnostics: {logs}"
        );
    }
}

// ---- Shared plugin fixtures (formerly in plugin_cache_tests) ----

/// Returns the minimal valid config for a given plugin name so that `create_plugin` succeeds.
#[allow(dead_code)]
pub(crate) fn minimal_plugin_config(plugin_name: &str) -> serde_json::Value {
    match plugin_name {
        "access_control" => json!({"allowed_consumers": ["testuser"]}),
        "tcp_connection_throttle" => json!({"max_connections_per_key": 10}),
        "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
        "geo_restriction" => json!({
            "db_path": "/nonexistent/GeoIP2-Country.mmdb",
            "allow_countries": ["US"]
        }),
        "rate_limiting" => json!({
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]
        }),
        "request_transformer" => {
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
        }
        "response_transformer" => {
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
        }
        "request_size_limiting" => json!({"max_bytes": 1048576}),
        "waf" => json!({ "mode": "monitor" }),
        "response_size_limiting" => json!({"max_bytes": 1048576}),
        "ws_message_size_limiting" => json!({"max_frame_bytes": 65536}),
        "ws_rate_limiting" => json!({"frames_per_second": 100}),
        "body_validator" => json!({"required_fields": ["name"]}),
        "graphql" => json!({"max_depth": 100}),
        "grpc_method_router" => json!({"allow_methods": ["test.Svc/Method"]}),
        "grpc_deadline" => json!({"max_deadline_ms": 30000}),
        "ai_rate_limiter" => json!({"token_limit": 100000}),
        "cors" => json!({"allowed_origins": ["*"]}),
        "response_caching" => json!({"ttl_seconds": 60}),
        "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
        "tcp_logging" => json!({"host": "localhost", "port": 5140}),
        "ws_logging" => json!({"endpoint_url": "ws://localhost:9300/logs"}),
        "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
        // `hmac_auth` defaults to the single-use `ferrum-hmac-v2` profile, which
        // requires an explicit replay-scope declaration.
        "hmac_auth" => json!({"replay_scope": "process"}),
        "jwks_auth" => {
            json!({"providers": [{"jwks_uri": "http://127.0.0.1:9/.well-known/jwks.json"}]})
        }
        "oauth2_introspection" => json!({
            "providers": [{
                "introspection_endpoint": "http://127.0.0.1:9/introspect",
                "client_auth": {"method": "none"}
            }]
        }),
        "oidc_relying_party" => json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
                "client_id": "ferrum-gateway",
                "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
                "scopes": ["openid", "profile"],
                "redirect_uri": "https://app.example.com/oauth/callback",
                "callback_path": "/oauth/callback",
                "logout_path": "/oauth/logout"
            }],
            "session": {
                "store": "cookie",
                "encryption_secret": "01234567890123456789012345678901"
            },
            "behavior": {"trusted_redirect_hosts": ["app.example.com"]}
        }),
        "udp_rate_limiting" => json!({"datagrams_per_second": 1000}),
        "serverless_function" => {
            json!({"provider": "azure_functions", "function_url": "https://example.com/func"})
        }
        "request_mirror" => json!({"mirror_host": "mirror.local"}),
        "load_testing" => json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 8000
        }),
        "fault_injection" => json!({
            "abort": {"status_code": 503, "percentage": 100.0},
            "runtime_overlay_scope": "checkout"
        }),
        "udp_logging" => json!({"host": "127.0.0.1", "port": 9514}),
        "statsd_logging" => json!({"host": "127.0.0.1", "port": 8125}),
        "loki_logging" => json!({"endpoint_url": "http://localhost:3100/loki/api/v1/push"}),
        "kafka_logging" => json!({"broker_list": "localhost:9092", "topic": "test-logs"}),
        "request_deduplication" => json!({}),
        "response_mock" => json!({"rules": [{"path": "/test", "body": "mock"}]}),
        "openapi_validator" => json!({
            "operations": [{
                "method": "GET",
                "path_template": "/health",
                "path_regex": "^/health$",
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "type": "object"
                            }
                        }
                    }
                }
            }]
        }),
        "ai_federation" => {
            json!({"providers": [{"name": "test", "provider_type": "openai", "api_key": "sk-test"}]})
        }
        "ai_stream_router" => json!({
            "providers": [{
                "name": "test",
                "provider_type": "openai",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "api_key": "sk-test",
                "model_patterns": ["gpt-*"]
            }]
        }),
        "mcp_gateway" => json!({
            "mode": "transparent_proxy",
            "endpoint": {"path": "/mcp"},
            "servers": {
                "tools": {
                    "upstream_url": "http://mcp-gateway.example/mcp",
                    "namespace": "tools"
                }
            }
        }),
        "a2a_gateway" => json!({
            "discovery": {"rewrite_agent_card_urls": false},
            "mode": "transparent_proxy",
            "endpoint": {
                "path": "/a2a",
                "agent_card_path": "/.well-known/agent-card.json",
                "grpc_services": ["a2a.v1.A2AService"]
            }
        }),
        "ai_semantic_firewall" => json!({
            "provider": {
                "type": "openai_compatible_embeddings",
                "endpoint": "http://127.0.0.1:9/v1/embeddings",
                "request_timeout_ms": 100
            }
        }),
        "ai_tool_governor" => json!({
            "tools": { "github.create_pr": { "action": "allow" } }
        }),
        "ai_transcript_audit" => json!({
            "sink": {"endpoint_url": "https://localhost:9200/audit"}
        }),
        "ldap_auth" => json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com",
            "canonical_identity_attribute": "uid"
        }),
        "spec_expose" => json!({"spec_url": "https://example.com/openapi.yaml"}),
        "api_chargeback" => {
            json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}]})
        }
        "api_chargeback_sink" => json!({
            "clickhouse": {
                "url": "http://127.0.0.1:8123",
                "database": "default",
                "table": "ferrum_charge_events"
            },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}],
            "spool": {"enabled": false}
        }),
        "ai_response_guard" => json!({"pii_patterns": ["ssn"], "action": "reject"}),
        "ai_request_guard" => json!({"max_messages": 100}),
        "transaction_log_schema" => {
            json!({"schemas": {"default": {"summary_type": "both"}}})
        }
        "mesh_route_dispatch" => json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }),
        "mesh_outbound_registry" => {
            json!({"registry": ["reviews.default.svc.cluster.local"]})
        }
        "opa" => json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": "ferrum/authz/allow"
        }),
        "proxy_alerts" => json!({
            "channels": {
                "ops": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
            },
            "rules": [{
                "name": "r", "type": "error_rate",
                "status_codes": [500], "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        _ => json!({}),
    }
}

#[allow(dead_code)]
pub(crate) fn make_proxy(id: &str, listen_path: &str, plugin_ids: Vec<&str>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: Some(format!("Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: plugin_ids
            .into_iter()
            .map(|id| PluginAssociation {
                plugin_config_id: id.to_string(),
            })
            .collect(),

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

#[allow(dead_code)]
pub(crate) fn make_plugin_config(
    id: &str,
    plugin_name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    enabled: bool,
) -> PluginConfig {
    // Some plugins now require non-empty config to be created successfully.
    let config = minimal_plugin_config(plugin_name);
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[allow(dead_code)]
pub(crate) fn make_plugin_config_with_json(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
    scope: PluginScope,
    proxy_id: Option<&str>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}
