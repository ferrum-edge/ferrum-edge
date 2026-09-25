//! Admission/503 regression for `adaptive_concurrency` baseline relearning
//! (#5737).
//!
//! The limiter's latency baseline used to be an all-time minimum, so one
//! unusually fast success pinned a healthy target at `min_limit` forever and
//! overlapping requests kept receiving `503`. The baseline is now a windowed
//! minimum: once two `baseline_window_samples` windows close after the
//! outlier, ordinary latency is within target again and saturated healthy
//! traffic regains capacity.

use crate::common::TestGateway;
use crate::scaffolding::clients::{ClientResponse, Http1Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

/// Ordinary backend latency. The very first request is answered immediately
/// and becomes the fast outlier.
const ORDINARY_LATENCY: Duration = Duration::from_millis(100);

/// Request-driven backend: the hit counter advances when a request reaches the
/// backend, before its response is delayed, so a test can tell that the
/// gateway is holding an admission permit for it. The gateway's startup h2c
/// capability probe fails to parse as HTTP/1.1 and is never counted.
async fn serve_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    let mut connections = JoinSet::new();
    while let Ok((stream, _)) = listener.accept().await {
        let hits = Arc::clone(&hits);
        connections.spawn(async move {
            let service = service_fn(move |_request: Request<Incoming>| {
                let hit = hits.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if hit > 1 {
                        tokio::time::sleep(ORDINARY_LATENCY).await;
                    }
                    let body = json!({"hit": hit}).to_string();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .header("content-length", body.len())
                            .body(Full::new(Bytes::from(body)))
                            .expect("backend response"),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn wait_for_backend_hits(hits: &AtomicUsize, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) < expected {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the backend never received request {expected}"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn sequential_healthy_requests(client: &Http1Client, url: &str, count: usize) {
    for request in 0..count {
        let response = client.get(url).await.expect("sequential GET");
        assert_eq!(
            response.status,
            StatusCode::OK,
            "sequential request {request} must be admitted"
        );
    }
}

/// Send a request, wait until the backend is serving it (so its admission
/// permit is held), then send a second request that overlaps it.
async fn overlapping_pair(
    client: &Http1Client,
    url: &str,
    hits: &AtomicUsize,
) -> (StatusCode, ClientResponse) {
    let expected_hits = hits.load(Ordering::SeqCst) + 1;
    let first_client = client.as_reqwest().clone();
    let first_url = url.to_string();
    let first = tokio::spawn(async move { first_client.get(first_url).send().await });
    wait_for_backend_hits(hits, expected_hits).await;
    let second = client.get(url).await.expect("overlapping GET");
    let first = first
        .await
        .expect("first request task joins")
        .expect("first GET");
    (first.status(), second)
}

#[tokio::test]
#[ignore]
async fn adaptive_concurrency_relearns_fast_outlier_baseline_over_http1() {
    let reservation = reserve_port().await.expect("reserve backend listener");
    let backend_port = reservation.port;
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = reservation.into_listener();
    let backend = tokio::spawn(serve_backend(listener, Arc::clone(&hits)));
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "adaptive-baseline",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "adaptive-baseline-limit"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "adaptive-baseline-limit",
            "proxy_id": "adaptive-baseline",
            "plugin_name": "adaptive_concurrency",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "min_limit": 1,
                "initial_limit": 4,
                "max_limit": 4,
                "min_samples": 5,
                "baseline_window_samples": 10,
                "target_latency_multiplier": 1.5,
                "decrease_ratio": 0.5,
                "increase_step": 1
            }
        }]
    });
    let gateway = TestGateway::builder()
        .mode_file(serde_yaml::to_string(&config).expect("serialize config"))
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start adaptive concurrency gateway");
    let client = Http1Client::insecure().expect("H1 client");
    let url = gateway.proxy_url("/work");

    // Sample 1 is the fast outlier; samples 2..=10 are ordinary. Past
    // `min_samples` each ordinary sample is far above the outlier-derived
    // target, so the limit falls to `min_limit`. Sample 10 closes the
    // outlier's baseline window.
    sequential_healthy_requests(&client, &url, 10).await;
    assert_eq!(hits.load(Ordering::SeqCst), 10);

    let (held, shed) = overlapping_pair(&client, &url, &hits).await;
    assert_eq!(held, StatusCode::OK, "the single slot admits one request");
    assert_eq!(
        shed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the outlier-pinned target sheds an overlapping request"
    );
    let shed_error = shed.headers.get("x-gateway-error");
    assert_eq!(
        shed_error.and_then(|value| value.to_str().ok()),
        Some("concurrency_limit"),
    );

    // Samples 12..=21 close the next window (sample 20), which holds only
    // ordinary latency. The saturated completion at sample 20 grows the
    // relearned target; on the old all-time minimum it stayed pinned.
    sequential_healthy_requests(&client, &url, 10).await;

    let (first, second) = overlapping_pair(&client, &url, &hits).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(
        second.status,
        StatusCode::OK,
        "the relearned target admits overlapping traffic again"
    );

    backend.abort();
}
