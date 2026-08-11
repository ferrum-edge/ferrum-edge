//! Common test utilities for plugin tests

use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, Proxy, default_namespace,
};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use hmac::{KeyInit, Mac};
use serde_json::{Map, Value};
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

/// Install a thread-local capturing subscriber for the duration of the returned
/// guard. Use `flavor = "current_thread"` so plugin flush workers stay on the
/// thread the subscriber is installed for.
#[allow(dead_code)]
pub fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    let writer = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
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
