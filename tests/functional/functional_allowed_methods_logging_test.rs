//! Functional coverage for transaction logging of matched-proxy
//! `allowed_methods` 405 rejections (issue #2614).
//!
//! Ordinary request hooks must stay skipped, but stdout and remote/batched
//! sinks must still receive one terminal summary attributed to the matched
//! proxy with `rejection_phase = "allowed_methods"`.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use http::{HeaderMap, Method};
use serde_json::Value;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

async fn start_counting_http1_backend(
    listener: TcpListener,
    target_path: &'static str,
    target_hits: Arc<AtomicUsize>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&target_hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let target_prefix = format!("GET {target_path} ");
            if !request.starts_with(&target_prefix) {
                let _ = stream.shutdown().await;
                return;
            }

            hits.fetch_add(1, Ordering::SeqCst);
            let response = "HTTP/1.1 200 OK\r\n\
                            Content-Length: 2\r\n\
                            Content-Type: text/plain\r\n\
                            Connection: close\r\n\
                            \r\n\
                            ok";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Minimal HTTP/1.1 POST sink that records JSON transaction bodies.
async fn start_http_logging_sink() -> (u16, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind http_logging sink");
    let port = listener.local_addr().expect("sink addr").port();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&bodies);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let captured = Arc::clone(&captured);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut collected = Vec::new();
                loop {
                    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => collected.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                    if collected.windows(4).any(|w| w == b"\r\n\r\n") {
                        // Keep reading briefly so short bodies arrive after headers.
                        for _ in 0..4 {
                            match tokio::time::timeout(
                                Duration::from_millis(50),
                                stream.read(&mut buf),
                            )
                            .await
                            {
                                Ok(Ok(0)) => break,
                                Ok(Ok(n)) => collected.extend_from_slice(&buf[..n]),
                                _ => break,
                            }
                        }
                        break;
                    }
                }
                let raw = String::from_utf8_lossy(&collected);
                if let Some(idx) = raw.find("\r\n\r\n") {
                    let body = raw[idx + 4..].trim();
                    // http_logging may POST a JSON array (batch) or object.
                    if let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(body) {
                        if let Ok(mut guard) = captured.lock() {
                            guard.extend(entries);
                        }
                    } else if let Ok(entry) = serde_json::from_str::<Value>(body)
                        && let Ok(mut guard) = captured.lock()
                    {
                        guard.push(entry);
                    }
                }
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, bodies)
}

fn build_logging_config(
    backend_port: u16,
    allowed_methods: &[&str],
    http_log_port_a: u16,
    http_log_port_b: u16,
) -> String {
    let allowed_methods_yaml = allowed_methods
        .iter()
        .map(|method| format!("      - \"{method}\"\n"))
        .collect::<String>();
    format!(
        r#"version: "1"
proxies:
  - id: "allowed-methods-logging"
    listen_path: "/allowed"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods:
{allowed_methods_yaml}
    plugins:
      - plugin_config_id: "proxy-http-log-a"
      - plugin_config_id: "proxy-http-log-b"

consumers: []
plugin_configs:
  - id: "global-stdout-log"
    plugin_name: stdout_logging
    scope: global
    enabled: true
    config: {{}}
  - id: "proxy-http-log-a"
    plugin_name: http_logging
    scope: proxy
    proxy_id: "allowed-methods-logging"
    enabled: true
    config:
      endpoint_url: "http://127.0.0.1:{http_log_port_a}/logs"
      batch_size: 1
      flush_interval_ms: 100
  - id: "proxy-http-log-b"
    plugin_name: http_logging
    scope: proxy
    proxy_id: "allowed-methods-logging"
    enabled: true
    config:
      endpoint_url: "http://127.0.0.1:{http_log_port_b}/logs"
      batch_size: 1
      flush_interval_ms: 100
"#
    )
}

fn extract_access_logs(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.is_object() && entry.get("proxy_id").is_some())
        .collect()
}

fn assert_allowed_methods_summary(entry: &Value, expected_method: &str) {
    assert_eq!(
        entry.get("proxy_id").and_then(Value::as_str),
        Some("allowed-methods-logging")
    );
    assert_eq!(
        entry.get("http_method").and_then(Value::as_str),
        Some(expected_method)
    );
    assert_eq!(
        entry.get("request_path").and_then(Value::as_str),
        Some("/allowed")
    );
    assert_eq!(
        entry.get("response_status_code").and_then(Value::as_u64),
        Some(405)
    );
    assert_eq!(
        entry
            .pointer("/metadata/rejection_phase")
            .and_then(Value::as_str),
        Some("allowed_methods")
    );
    assert!(
        entry.get("backend_target").is_none()
            || entry.get("backend_target").is_some_and(Value::is_null),
        "405 method admission must not contact a backend: {entry}"
    );
}

fn assert_allow_header(headers: &HeaderMap, expected: &[&str]) {
    let actual = headers
        .get(http::header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .expect("Allow header");
    let actual_methods = actual
        .split(',')
        .map(|method| method.trim().to_ascii_uppercase())
        .collect::<Vec<_>>();
    let expected_methods = expected
        .iter()
        .map(|method| method.to_ascii_uppercase())
        .collect::<Vec<_>>();
    assert_eq!(actual_methods, expected_methods, "Allow header: {actual}");
}

async fn wait_for_sink_entries(
    sink: &Arc<Mutex<Vec<Value>>>,
    min_count: usize,
    timeout: Duration,
) -> Vec<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = sink.lock().map(|g| g.clone()).unwrap_or_default();
        if snapshot.len() >= min_count || Instant::now() >= deadline {
            return snapshot;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

#[ignore]
#[tokio::test]
async fn functional_allowed_methods_405_logs_stdout_and_http_sinks_h1_h2_and_grpc() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn(start_counting_http1_backend(
        backend_listener,
        "/allowed",
        Arc::clone(&hits),
    ));

    let (sink_a_port, sink_a) = start_http_logging_sink().await;
    let (sink_b_port, sink_b) = start_http_logging_sink().await;

    let mut gateway = TestGateway::builder()
        .mode_file(build_logging_config(
            backend_port,
            &["GET", "HEAD"],
            sink_a_port,
            sink_b_port,
        ))
        .log_level("warn")
        .capture_output()
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let url = gateway.proxy_url("/allowed");
    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");
    let h1_blocked = h1.post(&url).send().await.expect("h1 blocked POST");
    assert_eq!(h1_blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(h1_blocked.headers(), &["GET", "HEAD"]);

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let h2_blocked = h2.delete(&url).send().await.expect("h2 blocked DELETE");
    assert_eq!(h2_blocked.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);

    // gRPC-flavored invalid method: Content-Type selects gRPC policy/view, but
    // route-level allowed_methods still rejects before request hooks (POST is
    // absent from the allowlist). The client may observe trailers-only gRPC
    // shaping; transaction logs still record 405 + rejection_phase.
    let grpc_blocked = h1
        .post(&url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .send()
        .await
        .expect("grpc-flavored blocked POST");
    assert!(
        grpc_blocked.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
            || grpc_blocked.status() == reqwest::StatusCode::OK,
        "gRPC-flavored method admission must reject; got {}",
        grpc_blocked.status()
    );

    let stdout = gateway
        .wait_for_captured_output(
            |raw| {
                extract_access_logs(raw)
                    .iter()
                    .filter(|e| {
                        e.pointer("/metadata/rejection_phase").and_then(Value::as_str)
                            == Some("allowed_methods")
                    })
                    .count()
                    >= 3
            },
            Duration::from_secs(5),
        )
        .await
        .expect("read stdout capture");
    let access_logs = extract_access_logs(&stdout)
        .into_iter()
        .filter(|e| {
            e.pointer("/metadata/rejection_phase").and_then(Value::as_str) == Some("allowed_methods")
        })
        .collect::<Vec<_>>();
    assert!(
        access_logs.len() >= 3,
        "expected >=3 stdout 405 summaries, got {}: {access_logs:?}",
        access_logs.len()
    );
    for entry in &access_logs {
        assert_eq!(
            entry.get("proxy_id").and_then(Value::as_str),
            Some("allowed-methods-logging")
        );
        assert_eq!(
            entry.get("response_status_code").and_then(Value::as_u64),
            Some(405)
        );
    }

    let sink_a_entries = wait_for_sink_entries(&sink_a, 3, Duration::from_secs(5)).await;
    let sink_b_entries = wait_for_sink_entries(&sink_b, 3, Duration::from_secs(5)).await;
    assert!(
        sink_a_entries.len() >= 3,
        "proxy-scoped http_logging instance A missing records: {sink_a_entries:?}"
    );
    assert!(
        sink_b_entries.len() >= 3,
        "proxy-scoped http_logging instance B missing records: {sink_b_entries:?}"
    );
    for entry in sink_a_entries
        .iter()
        .chain(sink_b_entries.iter())
        .filter(|e| {
            e.pointer("/metadata/rejection_phase").and_then(Value::as_str) == Some("allowed_methods")
        })
    {
        assert_eq!(
            entry.get("response_status_code").and_then(Value::as_u64),
            Some(405)
        );
        assert_eq!(
            entry.get("proxy_id").and_then(Value::as_str),
            Some("allowed-methods-logging")
        );
    }

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "blocked methods must not reach the backend"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_allowed_methods_405_logs_stdout_on_http3() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn(start_counting_http1_backend(
        backend_listener,
        "/allowed",
        Arc::clone(&hits),
    ));

    let (sink_a_port, sink_a) = start_http_logging_sink().await;
    let (sink_b_port, _sink_b) = start_http_logging_sink().await;

    let https_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve https port");
    let https_port = https_listener.local_addr().expect("https addr").port();
    drop(https_listener);

    let mut gateway = TestGateway::builder()
        .mode_file(build_logging_config(
            backend_port,
            &["GET", "HEAD"],
            sink_a_port,
            sink_b_port,
        ))
        .log_level("warn")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/allowed");
    let options = GetOptions::default().method(Method::POST);
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        match client.get_with_options(&url, options.clone()).await {
            Ok(response) => break response,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 POST did not complete: {err}"),
        }
    };
    assert_eq!(response.status, http::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(&response.headers, &["GET", "HEAD"]);

    let stdout = gateway
        .wait_for_captured_output(
            |raw| {
                extract_access_logs(raw).iter().any(|e| {
                    e.pointer("/metadata/rejection_phase").and_then(Value::as_str)
                        == Some("allowed_methods")
                })
            },
            Duration::from_secs(5),
        )
        .await
        .expect("read stdout capture");
    let entry = extract_access_logs(&stdout)
        .into_iter()
        .find(|e| {
            e.pointer("/metadata/rejection_phase").and_then(Value::as_str) == Some("allowed_methods")
        })
        .expect("missing H3 allowed_methods access log");
    assert_allowed_methods_summary(&entry, "POST");

    let sink_entries = wait_for_sink_entries(&sink_a, 1, Duration::from_secs(5)).await;
    let remote = sink_entries
        .iter()
        .find(|e| {
            e.pointer("/metadata/rejection_phase").and_then(Value::as_str) == Some("allowed_methods")
        })
        .expect("missing H3 http_logging record");
    assert_allowed_methods_summary(remote, "POST");

    assert_eq!(hits.load(Ordering::SeqCst), 0);
    gateway.shutdown();
    backend_task.abort();
}
