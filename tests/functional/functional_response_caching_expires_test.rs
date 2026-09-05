//! Origin-count regression for explicit Expires freshness (#4645).

use crate::common::TestGateway;
use crate::scaffolding::backends::http1::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::clients::{Http1Client, Http2Client, Http3Client};
use crate::scaffolding::ports::reserve_port;

use chrono::Utc;
use serde_json::json;

fn origin_response(path: &'static str, count: usize, expires: Option<&str>) -> Vec<HttpStep> {
    let body = json!({"path": path, "origin_count": count}).to_string();
    let mut steps = vec![
        HttpStep::ExpectRequest(RequestMatcher::method_path("GET", path)),
        HttpStep::RespondStatus {
            status: 200,
            reason: "OK".to_string(),
        },
        HttpStep::RespondHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        },
        HttpStep::RespondHeader {
            name: "Date".to_string(),
            value: Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        },
        HttpStep::RespondHeader {
            name: "Content-Length".to_string(),
            value: body.len().to_string(),
        },
        HttpStep::RespondHeader {
            name: "Connection".to_string(),
            value: "close".to_string(),
        },
    ];
    if let Some(expires) = expires {
        steps.push(HttpStep::RespondHeader {
            name: "Expires".to_string(),
            value: expires.to_string(),
        });
    }
    steps.push(HttpStep::RespondBodyChunk(body.into_bytes()));
    steps.push(HttpStep::RespondBodyEnd);
    steps
}

async fn assert_expires_origin_counts(protocol: u8) {
    let reservation = reserve_port().await.expect("reserve origin listener");
    let past = (Utc::now() - chrono::Duration::seconds(60))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .connection_scripts([
            origin_response("/expires", 1, Some(&past)),
            origin_response("/expires", 2, Some(&past)),
            origin_response("/invalid", 3, Some("0")),
            origin_response("/invalid", 4, Some("0")),
            origin_response("/control", 5, None),
        ])
        .spawn()
        .expect("start scripted origin");
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "expires",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend.port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "expires-cache"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "expires-cache",
            "proxy_id": "expires",
            "plugin_name": "response_caching",
            "scope": "proxy",
            "enabled": true,
            "config": {}
        }]
    });
    let mut builder = TestGateway::builder()
        .mode_file(serde_yaml::to_string(&config).expect("serialize config"))
        .env("FERRUM_POOL_WARMUP_ENABLED", "false");
    if protocol == 3 {
        builder = builder
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key");
    }
    let gateway = builder.spawn().await.expect("start cache gateway");
    let h1 = Http1Client::insecure().expect("H1 client");
    let h2 = Http2Client::h2c_prior_knowledge().expect("H2 client");
    let h3 = Http3Client::insecure().expect("H3 client");

    for (path, expected_count, hit) in [
        ("/expires", 1, false),
        ("/expires", 2, false),
        ("/invalid", 3, false),
        ("/invalid", 4, false),
        ("/control", 5, false),
        ("/control", 5, true),
    ] {
        let (status, headers, body) = match protocol {
            1 => {
                let response = h1.get(&gateway.proxy_url(path)).await.expect("H1 GET");
                (response.status, response.headers, response.body_bytes)
            }
            2 => {
                let response = h2.get(&gateway.proxy_url(path)).await.expect("H2 GET");
                (response.status, response.headers, response.body_bytes)
            }
            3 => {
                let port = gateway
                    .env_port("FERRUM_PROXY_HTTPS_PORT")
                    .expect("HTTPS port");
                let response = h3
                    .get(&format!("https://127.0.0.1:{port}{path}"))
                    .await
                    .expect("H3 GET");
                assert_eq!(response.body_error, None);
                (response.status, response.headers, response.body_bytes)
            }
            _ => panic!("unsupported test protocol"),
        };
        assert_eq!(status.as_u16(), 200);
        let cache_status = headers
            .get("x-cache-status")
            .expect("cache status")
            .to_str()
            .expect("ASCII cache status");
        if hit {
            assert_eq!(cache_status, "HIT", "H{protocol} {path}");
        } else {
            assert!(
                matches!(cache_status, "MISS" | "PREDICTED-BYPASS"),
                "H{protocol} {path}: unexpected {cache_status}"
            );
        }
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("origin JSON");
        assert_eq!(payload["path"], path);
        assert_eq!(payload["origin_count"], expected_count);
        assert_eq!(backend.received_requests().await.len(), expected_count);
    }
    backend.assert_no_matcher_mismatches().await;
}

#[tokio::test]
#[ignore]
async fn response_caching_expires_origin_count_http1() {
    assert_expires_origin_counts(1).await;
}

#[tokio::test]
#[ignore]
async fn response_caching_expires_origin_count_http2() {
    assert_expires_origin_counts(2).await;
}

#[tokio::test]
#[ignore]
async fn response_caching_expires_origin_count_http3() {
    assert_expires_origin_counts(3).await;
}
