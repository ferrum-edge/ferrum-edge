//! CORS request/response parity across H1, H2, and H3 frontends.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ORIGIN: &str = "https://app.example";
const CANONICAL_ORIGIN: &str = "https://xn--bcher-kva.example";
/// Istio `StringMatch.exact` value that LOOKS like the plugin's native
/// wildcard-subdomain syntax. On the literal matcher it must authorize only
/// itself (issue #3254).
const LITERAL_WILDCARD_ORIGIN: &str = "*.example.com";
const BACKEND_ACCESS_CONTROL_HEADERS: [&str; 7] = [
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-allow-private-network",
];
const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct CapturedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

struct PermissiveCorsBackend {
    port: u16,
    handle: Option<JoinHandle<()>>,
}

impl PermissiveCorsBackend {
    async fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let mut request = Vec::with_capacity(4096);
                            let mut chunk = [0u8; 4096];
                            let mut request_head_complete = false;
                            while request.len() < MAX_REQUEST_HEAD_BYTES {
                                let remaining = MAX_REQUEST_HEAD_BYTES - request.len();
                                let read_len = remaining.min(chunk.len());
                                let size = match stream.read(&mut chunk[..read_len]).await {
                                    Ok(0) => {
                                        request_head_complete = true;
                                        break;
                                    }
                                    Ok(size) => size,
                                    Err(_) => return,
                                };
                                request.extend_from_slice(&chunk[..size]);
                                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                    request_head_complete = true;
                                    break;
                                }
                            }
                            if !request_head_complete {
                                return;
                            }

                            let request = String::from_utf8_lossy(&request);
                            let path = request
                                .lines()
                                .next()
                                .and_then(|line| line.split_whitespace().nth(1))
                                .unwrap_or("/")
                                .replace('"', "\\\"");
                            let body = format!(r#"{{"echo":"{path}"}}"#);
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE\r\nAccess-Control-Allow-Headers: Authorization, X-Admin\r\nAccess-Control-Expose-Headers: X-Secret\r\nAccess-Control-Max-Age: 99999\r\nAccess-Control-Allow-Private-Network: true\r\nX-Backend: permissive\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for PermissiveCorsBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

#[ignore]
#[tokio::test]
async fn functional_cors_forwarded_preflight_and_composition_match_h1_h2_h3() {
    let mut harness = CorsProtocolHarness::spawn().await;

    let allowed_h1 = send_h1(&harness, Method::OPTIONS, Some("PUT"), Some("X-Custom")).await;
    let allowed_h2 = send_h2(&harness, Method::OPTIONS, Some("PUT"), Some("X-Custom")).await;
    let allowed_h3 = send_h3(&harness, Method::OPTIONS, Some("PUT"), Some("X-Custom")).await;
    for response in [&allowed_h1, &allowed_h2, &allowed_h3] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            String::from_utf8_lossy(&response.body).contains("cors-protocol"),
            "forwarded preflight must retain the backend body: {response:?}"
        );
        assert_eq!(header(response, "access-control-allow-origin"), ORIGIN);
        assert_eq!(header(response, "access-control-allow-methods"), "PUT");
        assert_eq!(header(response, "access-control-allow-headers"), "X-Custom");
        assert_eq!(header(response, "access-control-max-age"), "600");
        assert_eq!(header(response, "access-control-allow-credentials"), "true");
        assert_eq!(
            header(response, "access-control-expose-headers"),
            "X-Response"
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-private-network")
        );
        assert_vary(response, "Origin");
        assert_vary(response, "Access-Control-Request-Method");
        assert_vary(response, "Access-Control-Request-Headers");
    }

    for response in [&allowed_h2, &allowed_h3] {
        assert_eq!(response.body, allowed_h1.body);
    }

    for response in [
        send_h1(&harness, Method::OPTIONS, Some("DELETE"), None).await,
        send_h2(&harness, Method::OPTIONS, Some("DELETE"), None).await,
        send_h3(&harness, Method::OPTIONS, Some("DELETE"), None).await,
    ] {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(
            String::from_utf8_lossy(&response.body).contains("CORS method not allowed: DELETE"),
            "later CORS policy must reject the conflicting preflight method: {response:?}"
        );
    }

    for response in [
        send_h1(&harness, Method::DELETE, None, None).await,
        send_h2(&harness, Method::DELETE, None, None).await,
        send_h3(&harness, Method::DELETE, None, None).await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            String::from_utf8_lossy(&response.body).contains("cors-protocol"),
            "preflight-only method policy must not reject the actual request: {response:?}"
        );
        assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN);
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-methods")
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-headers")
        );
    }

    for response in [
        send_h1(
            &harness,
            Method::OPTIONS,
            Some("PUT"),
            Some("Authorization"),
        )
        .await,
        send_h2(
            &harness,
            Method::OPTIONS,
            Some("PUT"),
            Some("Authorization"),
        )
        .await,
        send_h3(
            &harness,
            Method::OPTIONS,
            Some("PUT"),
            Some("Authorization"),
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(
            String::from_utf8_lossy(&response.body)
                .contains("CORS header not allowed: Authorization"),
            "later CORS policy must reject the conflicting header: {response:?}"
        );
    }

    for response in [
        send_h1_path(&harness, "/mixed-cors", Method::GET, None, None, ORIGIN).await,
        send_h2_path(&harness, "/mixed-cors", Method::GET, None, None, ORIGIN).await,
        send_h3_path(&harness, "/mixed-cors", Method::GET, None, None, ORIGIN).await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("mixed-cors"));
        assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN);
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-methods")
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-headers")
        );
    }

    for response in [
        send_h1_path(
            &harness,
            "/mixed-cors",
            Method::OPTIONS,
            Some("GET"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            "/mixed-cors",
            Method::OPTIONS,
            Some("GET"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            "/mixed-cors",
            Method::OPTIONS,
            Some("GET"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(
            String::from_utf8_lossy(&response.body).contains("CORS method not allowed: GET"),
            "the empty Istio preflight list must narrow the native approval: {response:?}"
        );
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("istio-forward"));
        assert_no_access_control_headers(&response);
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-forward",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-forward",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-forward",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("istio-forward"));
        assert_no_access_control_headers(&response);
    }

    for response in [
        send_h1_path(
            &harness,
            "/no-cors",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/no-cors",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/no-cors",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("no-cors"));
        assert_backend_access_control_headers_preserved(&response);
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-ignore",
            Method::OPTIONS,
            Some("DELETE"),
            None,
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-ignore",
            Method::OPTIONS,
            Some("DELETE"),
            None,
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-ignore",
            Method::OPTIONS,
            Some("DELETE"),
            None,
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_no_access_control_headers(&response);
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN);
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-methods")
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-headers")
        );
        assert!(!response.headers.contains_key("access-control-max-age"));
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-star",
            Method::GET,
            None,
            None,
            "https://anything.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-star",
            Method::GET,
            None,
            None,
            "https://anything.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-star",
            Method::GET,
            None,
            None,
            "https://anything.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(header(&response, "access-control-allow-origin"), "*");
    }

    for response in [
        send_h1_path(
            &harness,
            "/canonical",
            Method::GET,
            None,
            None,
            CANONICAL_ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            "/canonical",
            Method::GET,
            None,
            None,
            CANONICAL_ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            "/canonical",
            Method::GET,
            None,
            None,
            CANONICAL_ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header(&response, "access-control-allow-origin"),
            CANONICAL_ORIGIN,
            "configured Unicode host and default HTTPS port must match the browser-serialized origin"
        );
    }

    harness.shutdown();
}

/// Live data path for the Istio-shaped literal `exact` and bounded `regex`
/// origin matchers (issues #3254 / #3253).
///
/// The plugin config carries `{"exact": "*.example.com"}`. On the native
/// plain-string form that value is wildcard-subdomain syntax; as a LITERAL
/// matcher it must authorize only the byte-identical `Origin` and must NOT
/// authorize any subdomain — that difference is the security property, so it is
/// asserted from outside the process, over real H1/H2/H3 frontends.
#[ignore]
#[tokio::test]
async fn functional_cors_literal_exact_and_regex_origins_are_not_widened() {
    let mut harness = CorsProtocolHarness::spawn().await;
    const PATH: &str = "/literal-matchers";

    // 1. The literal `*.example.com` matcher authorizes exactly its own string
    //    and reflects it (credentialed, so never `*`).
    for response in [
        send_h1_path(
            &harness,
            PATH,
            Method::GET,
            None,
            None,
            LITERAL_WILDCARD_ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            PATH,
            Method::GET,
            None,
            None,
            LITERAL_WILDCARD_ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            PATH,
            Method::GET,
            None,
            None,
            LITERAL_WILDCARD_ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header(&response, "access-control-allow-origin"),
            LITERAL_WILDCARD_ORIGIN,
            "a literal exact matcher reflects the request origin verbatim"
        );
        assert_eq!(
            header(&response, "access-control-allow-credentials"),
            "true",
            "a concrete literal origin keeps credentialed CORS usable"
        );
        assert_vary(&response, "Origin");
    }

    // 2. The security property: a real subdomain is NOT authorized. If the
    //    literal were reinterpreted as native wildcard syntax, this would be a
    //    200 with the subdomain reflected.
    for origin in [
        "https://app.example.com",
        "https://deep.sub.example.com",
        "https://example.com",
    ] {
        for response in [
            send_h1_path(&harness, PATH, Method::GET, None, None, origin).await,
            send_h2_path(&harness, PATH, Method::GET, None, None, origin).await,
            send_h3_path(&harness, PATH, Method::GET, None, None, origin).await,
        ] {
            assert_eq!(
                response.status,
                StatusCode::FORBIDDEN,
                "`{origin}` must not be widened into the literal `*.example.com` matcher"
            );
            assert_no_access_control_headers(&response);
        }
    }

    // 3. The bounded regex matcher full-matches, with no implicit `.*`.
    let allowed = send_h1_path(
        &harness,
        PATH,
        Method::GET,
        None,
        None,
        "https://v2.api.example.com",
    )
    .await;
    assert_eq!(allowed.status, StatusCode::OK);
    assert_eq!(
        header(&allowed, "access-control-allow-origin"),
        "https://v2.api.example.com"
    );

    let suffixed = send_h1_path(
        &harness,
        PATH,
        Method::GET,
        None,
        None,
        "https://v2.api.example.com.evil.com",
    )
    .await;
    assert_eq!(
        suffixed.status,
        StatusCode::FORBIDDEN,
        "the regex is a FULL match, so a suffixed origin must not be authorized"
    );

    // 4. A credentialed preflight from the literal origin is answered locally
    //    with the exact origin reflected and the configured method/header lists.
    let preflight = send_h1_path(
        &harness,
        PATH,
        Method::OPTIONS,
        Some("PUT"),
        Some("X-Custom"),
        LITERAL_WILDCARD_ORIGIN,
    )
    .await;
    assert_eq!(preflight.status, StatusCode::NO_CONTENT);
    assert_eq!(
        header(&preflight, "access-control-allow-origin"),
        LITERAL_WILDCARD_ORIGIN
    );
    assert_eq!(
        header(&preflight, "access-control-allow-credentials"),
        "true"
    );

    // An uncredentialed, unmatched preflight stays fail-closed on the native
    // (non-Istio) policy shape.
    let denied_preflight = send_h1_path(
        &harness,
        PATH,
        Method::OPTIONS,
        Some("PUT"),
        None,
        "https://app.example.com",
    )
    .await;
    assert_eq!(denied_preflight.status, StatusCode::FORBIDDEN);
    assert_no_access_control_headers(&denied_preflight);

    harness.shutdown();
}

struct CorsProtocolHarness {
    gateway: TestGateway,
    echo: PermissiveCorsBackend,
    https_port: u16,
}

impl CorsProtocolHarness {
    async fn spawn() -> Self {
        let mut echo = PermissiveCorsBackend::spawn()
            .await
            .expect("spawn CORS backend");
        let config = cors_config(echo.port);
        let mut last_error = String::new();
        for _ in 0..5 {
            let reservation = reserve_port().await.expect("reserve HTTPS port");
            let https_port = reservation.drop_and_take_port();
            let spawn = TestGateway::builder()
                .mode_file(config.clone())
                .log_level("warn")
                // The pinned HTTPS/QUIC port must change between attempts, so
                // this outer loop owns startup retries.
                .max_attempts(1)
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                .spawn()
                .await;
            match spawn {
                Ok(mut gateway) => {
                    match gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        Ok(()) => {
                            return Self {
                                gateway,
                                echo,
                                https_port,
                            };
                        }
                        Err(error) => {
                            last_error = error.to_string();
                            gateway.shutdown();
                        }
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
        }
        echo.abort();
        panic!("start CORS protocol gateway after retries: {last_error}");
    }

    fn h1_h2_url(&self, path: &str) -> String {
        self.gateway.proxy_url(path)
    }

    fn h3_url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.echo.abort();
    }
}

fn cors_config(backend_port: u16) -> String {
    let proxies = vec![
        cors_proxy(
            "cors-protocol",
            "/cors-protocol",
            backend_port,
            &["cors-wide", "cors-narrow"],
        ),
        cors_proxy(
            "istio-forward",
            "/istio-forward",
            backend_port,
            &["istio-forward"],
        ),
        cors_proxy(
            "istio-ignore",
            "/istio-ignore",
            backend_port,
            &["istio-ignore"],
        ),
        cors_proxy(
            "mixed-cors",
            "/mixed-cors",
            backend_port,
            &["mixed-native", "mixed-istio"],
        ),
        cors_proxy("istio-star", "/istio-star", backend_port, &["istio-star"]),
        cors_proxy("canonical", "/canonical", backend_port, &["canonical"]),
        cors_proxy(
            "literal-matchers",
            "/literal-matchers",
            backend_port,
            &["literal-matchers"],
        ),
        cors_proxy("no-cors", "/no-cors", backend_port, &[]),
    ];
    let config = serde_json::json!({
        "version": "1",
        "proxies": proxies,
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "cors-wide",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "cors-protocol",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["PUT", "DELETE"],
                    "allowed_headers": ["X-Custom", "Authorization"],
                    "exposed_headers": ["X-Response", "X-Wide"],
                    "allow_credentials": true,
                    "max_age": 900,
                    "preflight_continue": true
                }
            },
            {
                "id": "cors-narrow",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "cors-protocol",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["PUT"],
                    "allowed_headers": ["X-Custom"],
                    "exposed_headers": ["X-Response"],
                    "allow_credentials": true,
                    "max_age": 600,
                    "preflight_continue": true
                }
            },
            {
                "id": "mixed-native",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "mixed-cors",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["GET"],
                    "allowed_headers": ["Authorization"]
                }
            },
            {
                "id": "mixed-istio",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "mixed-cors",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                }
            },
            {
                "id": "istio-forward",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "istio-forward",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                }
            },
            {
                "id": "istio-ignore",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "istio-ignore",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "ignore"
                }
            },
            {
                "id": "istio-star",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "istio-star",
                "enabled": true,
                "config": {
                    "allowed_origins": [{"exact": "*"}],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                }
            },
            {
                "id": "canonical",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "canonical",
                "enabled": true,
                "config": {
                    "allowed_origins": ["HTTPS://BÜCHER.EXAMPLE:443"]
                }
            },
            {
                // Istio-shaped literal exact + bounded regex origin matchers
                // (issues #3254 / #3253) on the live data path.
                "id": "literal-matchers",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "literal-matchers",
                "enabled": true,
                "config": {
                    "allowed_origins": [
                        {"exact": LITERAL_WILDCARD_ORIGIN},
                        {"regex": "https://[a-z0-9-]+\\.api\\.example\\.com"}
                    ],
                    "allowed_methods": ["GET", "PUT"],
                    "allowed_headers": ["X-Custom"],
                    "allow_credentials": true
                }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize CORS config")
}

fn cors_proxy(
    id: &str,
    listen_path: &str,
    backend_port: u16,
    plugin_ids: &[&str],
) -> serde_json::Value {
    let plugins = plugin_ids
        .iter()
        .map(|plugin_config_id| {
            serde_json::json!({
                "plugin_config_id": plugin_config_id
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": plugins
    })
}

fn apply_cors_headers(
    mut request: reqwest::RequestBuilder,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> reqwest::RequestBuilder {
    request = request.header("origin", origin);
    if let Some(method) = requested_method {
        request = request.header("access-control-request-method", method);
    }
    if let Some(headers) = requested_headers {
        request = request.header("access-control-request-headers", headers);
    }
    request
}

async fn send_h1(
    harness: &CorsProtocolHarness,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
) -> CapturedResponse {
    send_h1_path(
        harness,
        "/cors-protocol",
        method,
        requested_method,
        requested_headers,
        ORIGIN,
    )
    .await
}

async fn send_h1_path(
    harness: &CorsProtocolHarness,
    path: &str,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> CapturedResponse {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("H1 client");
    let response = apply_cors_headers(
        client.request(method, harness.h1_h2_url(path)),
        requested_method,
        requested_headers,
        origin,
    )
    .send()
    .await
    .expect("H1 CORS request");
    capture_reqwest(response).await
}

async fn send_h2(
    harness: &CorsProtocolHarness,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
) -> CapturedResponse {
    send_h2_path(
        harness,
        "/cors-protocol",
        method,
        requested_method,
        requested_headers,
        ORIGIN,
    )
    .await
}

async fn send_h2_path(
    harness: &CorsProtocolHarness,
    path: &str,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> CapturedResponse {
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("H2 client");
    let response = apply_cors_headers(
        client.request(method, harness.h1_h2_url(path)),
        requested_method,
        requested_headers,
        origin,
    )
    .send()
    .await
    .expect("H2 CORS request");
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    capture_reqwest(response).await
}

async fn capture_reqwest(response: reqwest::Response) -> CapturedResponse {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.expect("response body");
    CapturedResponse {
        status,
        headers,
        body,
    }
}

async fn send_h3(
    harness: &CorsProtocolHarness,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
) -> CapturedResponse {
    send_h3_path(
        harness,
        "/cors-protocol",
        method,
        requested_method,
        requested_headers,
        ORIGIN,
    )
    .await
}

async fn send_h3_path(
    harness: &CorsProtocolHarness,
    path: &str,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> CapturedResponse {
    let client = Http3Client::insecure().expect("H3 client");
    let mut options = GetOptions::default().method(method);
    options = options.header("origin", origin);
    if let Some(method) = requested_method {
        options = options.header("access-control-request-method", method);
    }
    if let Some(headers) = requested_headers {
        options = options.header("access-control-request-headers", headers);
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .get_with_options(&harness.h3_url(path), options.clone())
            .await
        {
            Ok(response) => {
                return CapturedResponse {
                    status: response.status,
                    headers: response.headers,
                    body: response.body_bytes,
                };
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 CORS request did not complete: {error}"),
        }
    }
}

fn header<'a>(response: &'a CapturedResponse, name: &str) -> &'a str {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("missing {name}: {response:?}"))
}

fn assert_vary(response: &CapturedResponse, expected: &str) {
    assert!(
        header(response, "vary")
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case(expected)),
        "missing Vary token {expected}: {response:?}"
    );
}

fn assert_no_access_control_headers(response: &CapturedResponse) {
    assert!(
        response
            .headers
            .keys()
            .all(|name| !name.as_str().starts_with("access-control-")),
        "backend Access-Control-* headers must be removed: {response:?}"
    );
}

fn assert_backend_access_control_headers_preserved(response: &CapturedResponse) {
    for name in BACKEND_ACCESS_CONTROL_HEADERS {
        assert!(
            response.headers.contains_key(name),
            "ordinary upstream header {name} must be preserved: {response:?}"
        );
    }
}
