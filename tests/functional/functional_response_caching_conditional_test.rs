//! Issues #4639/#4646: cache-generated 304 eligibility across H1/H2/H3.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, Version};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

const LAST_MODIFIED: &str = "Wed, 01 Jan 2020 00:00:00 GMT";
const LATER: &str = "Wed, 01 Jan 2025 00:00:00 GMT";
const EARLIER: &str = "Tue, 01 Jan 2019 00:00:00 GMT";

async fn serve_origin(listener: TcpListener, hits: Arc<AtomicUsize>) {
    let mut connections = JoinSet::new();
    while let Ok((stream, _)) = listener.accept().await {
        let hits = Arc::clone(&hits);
        connections.spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let count = hits.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    let path = request.uri().path();
                    let status = if path.ends_with("/negative") {
                        404
                    } else if path.ends_with("/gone") {
                        410
                    } else if path.ends_with("/redirect") {
                        301
                    } else {
                        200
                    };
                    // A cache miss must visibly reach origin evaluation. On a
                    // hit this branch cannot supply the gateway's synthetic 304.
                    let origin_conditional = status == 200
                        && request
                            .headers()
                            .get("if-none-match")
                            .is_some_and(|v| v == "*");
                    let body = format!("origin {path}, request {count}");
                    let mut response = Response::builder()
                        .status(if origin_conditional { 304 } else { status })
                        .header("cache-control", "public, max-age=3600")
                        .header("last-modified", LAST_MODIFIED)
                        .header("content-type", "text/plain");
                    if !path.ends_with("/no-etag") {
                        response = response.header("etag", "\"v1\"");
                    }
                    if status == 301 {
                        response = response.header("location", "/destination");
                    }
                    if origin_conditional {
                        response = response.header("x-origin-conditional", "true");
                    } else {
                        response = response.header("content-length", body.len());
                    }
                    let body = if origin_conditional || request.method() == Method::HEAD {
                        Bytes::new()
                    } else {
                        Bytes::from(body)
                    };
                    Ok::<_, Infallible>(response.body(Full::new(body)).expect("origin response"))
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .expect("origin connection");
        });
    }
}

async fn spawn_gateway(backend_port: u16) -> (TestGateway, u16) {
    let config = format!(
        r#"version: "1"
proxies:
  - id: conditional-cache
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: conditional-cache-plugin
consumers: []
plugin_configs:
  - id: conditional-cache-plugin
    plugin_name: response_caching
    scope: proxy
    proxy_id: conditional-cache
    enabled: true
    config:
      cacheable_status_codes: [200, 301, 404, 410]
"#
    );
    let mut last_error = String::new();
    for _ in 0..5 {
        let (tcp, udp) = reserve_colocated_tcp_udp()
            .await
            .expect("reserve TLS/QUIC port");
        let https_port = tcp.drop_and_take_port();
        udp.drop_and_take_port();
        // The shared harness proves child ownership and readiness. Pinning
        // TLS requires a fresh port and a fresh harness on each spawn attempt.
        match TestGateway::builder()
            .mode_file(config.clone())
            .max_attempts(1)
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => last_error = error.to_string(),
        }
    }
    panic!("conditional cache gateway failed to start: {last_error}");
}

enum Frontend {
    Tcp(reqwest::Client, Version),
    H3(Http3Client),
}

struct WireResponse {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
}

impl Frontend {
    async fn request(
        &self,
        url: &str,
        method: &Method,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
    ) -> WireResponse {
        match self {
            Self::Tcp(client, version) => {
                let mut request = client.request(method.clone(), url);
                if let Some(value) = if_none_match {
                    request = request.header("if-none-match", value);
                }
                if let Some(value) = if_modified_since {
                    request = request.header("if-modified-since", value);
                }
                let response = request.send().await.expect("TCP request");
                assert_eq!(response.version(), *version, "{url}");
                WireResponse {
                    status: response.status().as_u16(),
                    headers: response.headers().clone(),
                    body: response.bytes().await.expect("TCP body"),
                }
            }
            Self::H3(client) => {
                let mut options = GetOptions::default().method(method.clone());
                if let Some(value) = if_none_match {
                    options = options.header("if-none-match", value);
                }
                if let Some(value) = if_modified_since {
                    options = options.header("if-modified-since", value);
                }
                let response = client
                    .get_with_options(url, options)
                    .await
                    .expect("H3 request");
                assert!(
                    response.body_error.is_none(),
                    "{url}: {:?}",
                    response.body_error
                );
                WireResponse {
                    status: response.status.as_u16(),
                    headers: response.headers,
                    body: response.body_bytes,
                }
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn functional_response_caching_conditional_eligibility_h1_h2_h3() {
    let reservation = reserve_port().await.expect("reserve origin port");
    let backend_port = reservation.port;
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = tokio::spawn(serve_origin(
        reservation.into_listener(),
        Arc::clone(&hits),
    ));
    let (mut gateway, https_port) = spawn_gateway(backend_port).await;
    let h1 = reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H1 client");
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H2 client");
    let frontends = [
        ("h1", Frontend::Tcp(h1, Version::HTTP_11)),
        ("h2", Frontend::Tcp(h2, Version::HTTP_2)),
        ("h3", Frontend::H3(Http3Client::insecure().expect("H3 client"))),
    ];

    for (protocol, frontend) in frontends {
        let base = if protocol == "h3" {
            format!("https://localhost:{https_port}")
        } else {
            gateway.proxy_base_url.clone()
        };
        for method in [Method::GET, Method::HEAD] {
            for (route, stored_status) in [
                ("no-etag", 200),
                ("etag", 200),
                ("negative", 404),
                ("gone", 410),
                ("redirect", 301),
            ] {
                let url = format!("{base}/{protocol}/{method}/{route}");
                let before = hits.load(Ordering::SeqCst);
                let stored = frontend.request(&url, &method, None, None).await;
                assert_eq!(stored.status, stored_status, "{url}");
                assert_eq!(stored.headers["x-cache-status"], "MISS", "{url}");
                assert_eq!(hits.load(Ordering::SeqCst), before + 1, "{url}: seed");
                assert_eq!(stored.headers.contains_key("etag"), route != "no-etag");
                if method == Method::GET {
                    assert!(!stored.body.is_empty(), "{url}: origin body");
                } else {
                    assert!(stored.body.is_empty(), "{url}: HEAD body");
                }
                let cases = [
                    (None, None, false),
                    (Some("*"), None, true),
                    (Some("*"), Some(EARLIER), true),
                    (Some(r#"W/"v1""#), None, route != "no-etag"),
                    (Some(r#"W/"v1""#), Some(EARLIER), route != "no-etag"),
                    (Some(r#""other", W/"v1""#), None, route != "no-etag"),
                    (Some(r#""other""#), Some(LATER), false),
                    (Some(r#"*, "v1""#), Some(LATER), false),
                    (Some(r#""v1", *"#), Some(LATER), false),
                    (None, Some(LATER), true),
                    (None, Some(EARLIER), false),
                ];
                for (if_none_match, if_modified_since, matches) in cases {
                    let response = frontend
                        .request(&url, &method, if_none_match, if_modified_since)
                        .await;
                    let not_modified = stored_status == 200 && matches;
                    assert_eq!(
                        response.status,
                        if not_modified { 304 } else { stored_status },
                        "{url}: INM={if_none_match:?}, IMS={if_modified_since:?}"
                    );
                    assert_eq!(
                        hits.load(Ordering::SeqCst),
                        before + 1,
                        "{url}: a cache response must not reach origin"
                    );
                    let cache_status = if not_modified { "REVALIDATED" } else { "HIT" };
                    assert_eq!(response.headers["x-cache-status"], cache_status);
                    assert_eq!(response.headers.get("etag"), stored.headers.get("etag"));
                    assert_eq!(response.headers["last-modified"], LAST_MODIFIED);
                    assert_eq!(response.headers["cache-control"], "public, max-age=3600");
                    assert!(
                        response.headers["age"]
                            .to_str()
                            .unwrap()
                            .parse::<u64>()
                            .is_ok()
                    );
                    if not_modified {
                        assert!(response.body.is_empty(), "{url}: 304 body");
                        assert!(!response.headers.contains_key("content-length"));
                    } else {
                        assert_eq!(response.body, stored.body, "{url}: replay body");
                        assert_eq!(response.headers["content-type"], "text/plain");
                        if stored_status == 301 {
                            assert_eq!(response.headers["location"], "/destination");
                        }
                    }
                }
            }

            let url = format!("{base}/{protocol}/{method}/miss/no-etag");
            let before = hits.load(Ordering::SeqCst);
            let response = frontend.request(&url, &method, Some("*"), None).await;
            assert_eq!(response.status, 304, "{url}: origin conditional response");
            assert!(response.body.is_empty());
            assert_eq!(response.headers["x-cache-status"], "MISS");
            assert_eq!(response.headers["x-origin-conditional"], "true");
            assert_eq!(hits.load(Ordering::SeqCst), before + 1, "{url}: miss");
        }
    }

    gateway.shutdown();
    origin.abort();
    let _ = origin.await;
}
