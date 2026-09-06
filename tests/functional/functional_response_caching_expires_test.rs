//! Origin-count regression for explicit Expires freshness (#4645).

use crate::common::TestGateway;
use crate::scaffolding::clients::{Http1Client, Http2Client, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use chrono::Utc;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

fn http_date(offset_seconds: i64) -> String {
    (Utc::now() + chrono::Duration::seconds(offset_seconds))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Request-driven origin: every request the gateway forwards is counted and
/// the count travels in the body, so a cache HIT shows as a repeated number.
/// Connection order is irrelevant, which keeps the gateway's startup h2c
/// capability probe — an HTTP/2 preface hyper rejects before the service
/// runs — from consuming a scripted answer meant for the first request.
async fn serve_origin(listener: TcpListener, hits: Arc<AtomicUsize>) {
    let mut connections = JoinSet::new();
    while let Ok((stream, _)) = listener.accept().await {
        let hits = Arc::clone(&hits);
        connections.spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let count = hits.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    let path = request.uri().path().to_string();
                    let body = json!({"path": path, "origin_count": count}).to_string();
                    let mut response = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .header("date", http_date(0))
                        .header("content-length", body.len());
                    match path.as_str() {
                        "/expires" => response = response.header("expires", http_date(-60)),
                        "/invalid" => response = response.header("expires", "0"),
                        _ => {}
                    }
                    Ok::<_, Infallible>(
                        response
                            .body(Full::new(Bytes::from(body)))
                            .expect("origin response"),
                    )
                }
            });
            // The probe connection fails to parse as HTTP/1.1; that is not a hit.
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn assert_expires_origin_counts(protocol: u8) {
    let reservation = reserve_port().await.expect("reserve origin listener");
    let backend_port = reservation.port;
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = tokio::spawn(serve_origin(reservation.into_listener(), Arc::clone(&hits)));
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "expires",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
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
        assert_eq!(hits.load(Ordering::SeqCst), expected_count);
    }
    origin.abort();
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
