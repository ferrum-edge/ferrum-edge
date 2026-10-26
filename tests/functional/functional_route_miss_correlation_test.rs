//! Global correlation policies must cover unrouted traffic on every HTTP frontend.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::Duration;

async fn start_gateway(plugin_configs: Value) -> TestGateway {
    let config = serde_yaml::to_string(&json!({
        "version": "1",
        "proxies": [],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": plugin_configs,
    }))
    .unwrap();
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start route-miss gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .unwrap();
    let client = Http3Client::insecure().unwrap();
    let url = format!(
        "https://localhost:{}/ready",
        gateway.env_port("FERRUM_PROXY_HTTPS_PORT").unwrap()
    );
    client.get(&url).await.expect("QUIC listener ready");
    gateway
}

fn request_options(content_type: Option<&str>, inbound: Option<&str>) -> GetOptions {
    let mut options = GetOptions::default();
    if let Some(content_type) = content_type {
        options = options
            .method(Method::POST)
            .header("content-type", content_type);
    }
    if let Some(inbound) = inbound {
        options = options.header("x-client-id", inbound);
    }
    options
        .header("x-request-id", "caller-cannot-pick-this")
        .header("x-private-id", "private-client-id")
}

async fn request(
    gateway: &TestGateway,
    protocol: &str,
    path: &str,
    options: GetOptions,
) -> (StatusCode, HeaderMap) {
    if protocol == "h3" {
        let client = Http3Client::insecure().unwrap();
        let url = format!(
            "https://localhost:{}{path}",
            gateway.env_port("FERRUM_PROXY_HTTPS_PORT").unwrap()
        );
        let response = client.get_with_options(&url, options).await.unwrap();
        assert!(
            response.body_error.is_none(),
            "clean H3 response termination"
        );
        (response.status, response.headers)
    } else {
        let builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        let client = if protocol == "h2" {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        }
        .build()
        .unwrap();
        let mut request = client.request(options.method, gateway.proxy_url(path));
        for (name, value) in options.headers {
            request = request.header(name, value);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.version(),
            if protocol == "h2" {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            }
        );
        (response.status(), response.headers().clone())
    }
}

fn access_logs(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| {
            entry
                .pointer("/metadata/rejection_phase")
                .and_then(Value::as_str)
                == Some("route_not_found")
        })
        .collect()
}

#[ignore]
#[tokio::test]
async fn functional_route_miss_correlation_echoes_and_logs_on_h1_h2_h3() {
    // Deliberately reversed configuration order: effective priority owns the
    // canonical ID, independently of a later preserved client trust domain.
    let mut gateway = start_gateway(json!([
        {
            "id": "quiet-id", "plugin_name": "correlation_id", "scope": "global",
            "enabled": true, "priority_override": 70,
            "config": {"header_name": "x-private-id", "echo_downstream": false}
        },
        {
            "id": "client-id", "plugin_name": "correlation_id", "scope": "global",
            "enabled": true, "priority_override": 60,
            "config": {"header_name": "x-client-id"}
        },
        {
            "id": "gateway-id", "plugin_name": "correlation_id", "scope": "global",
            "enabled": true, "priority_override": 40,
            "config": {"inbound_policy": "generate"}
        },
        {
            "id": "access-log", "plugin_name": "stdout_logging", "scope": "global",
            "enabled": true, "config": {}
        }
    ]))
    .await;
    let oversized = "a".repeat(257);
    let mut expected = Vec::new();
    let mut generated = HashSet::new();
    for protocol in ["h1", "h2", "h3"] {
        for (case, inbound, content_type) in [
            ("missing", None, None),
            ("preserve", Some("client-123"), None),
            ("invalid", Some("bad value"), None),
            ("oversized", Some(oversized.as_str()), None),
            ("grpc", Some("client-123"), Some("application/grpc")),
            (
                "grpc-web",
                Some("client-123"),
                Some("application/grpc-web+proto"),
            ),
        ] {
            let path = format!("/missing-{protocol}-{case}");
            let (status, headers) = request(
                &gateway,
                protocol,
                &path,
                request_options(content_type, inbound),
            )
            .await;
            assert_eq!(
                status,
                if content_type.is_some() {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            );
            if content_type == Some("application/grpc") {
                let grpc_status = headers.get("grpc-status").unwrap().to_str().unwrap();
                assert_ne!(grpc_status, "0", "unmatched RPC must fail");
                if protocol == "h3" {
                    assert_eq!(grpc_status, "5", "preserve native H3 NOT_FOUND signalling");
                }
            }
            let id = headers
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 4);
            assert!(
                generated.insert(id.clone()),
                "fresh canonical ID per request"
            );
            let client_id = headers.get("x-client-id").unwrap().to_str().unwrap();
            if inbound == Some("client-123") {
                assert_eq!(client_id, "client-123");
            } else {
                assert!(uuid::Uuid::parse_str(client_id).is_ok());
            }
            assert!(!headers.contains_key("x-private-id"), "echo disabled");
            expected.push((path, id));
        }
    }
    let stdout = gateway
        .wait_for_captured_output(
            |raw| {
                let entries = access_logs(raw);
                expected
                    .iter()
                    .all(|(path, _)| entries.iter().any(|entry| entry["request_path"] == *path))
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let entries = access_logs(&stdout);
    for (path, id) in expected {
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| entry["request_path"] == path)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "one unrouted record for {path}: {entries:?}"
        );
        let entry = matching[0];
        assert_eq!(entry["metadata"]["request_id"], id);
        assert_eq!(entry["response_status_code"], 404);
        assert!(entry["proxy_id"].is_null());
        assert!(entry["backend_target"].is_null());
    }
    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_route_miss_without_global_correlation_does_not_echo_inbound_ids() {
    let mut gateway = start_gateway(json!([])).await;
    for protocol in ["h1", "h2", "h3"] {
        let (status, headers) = request(
            &gateway,
            protocol,
            "/without-policy",
            request_options(None, Some("client-123")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        for name in ["x-request-id", "x-client-id", "x-private-id"] {
            assert!(!headers.contains_key(name));
        }
    }
    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_route_miss_global_correlation_echoes_without_a_logger() {
    let mut gateway = start_gateway(json!([{
        "id": "global-id", "plugin_name": "correlation_id", "scope": "global",
        "enabled": true, "config": {}
    }]))
    .await;
    for protocol in ["h1", "h2", "h3"] {
        let (status, headers) = request(
            &gateway,
            protocol,
            "/without-logger",
            request_options(None, None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            headers.get("x-request-id").unwrap(),
            "caller-cannot-pick-this"
        );
    }
    gateway.shutdown();
}
