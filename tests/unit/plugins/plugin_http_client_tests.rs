use ferrum_edge::plugins::PluginHttpClient;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct ProxyEnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl ProxyEnvGuard {
    fn point_all_at(proxy_url: &str) -> Self {
        const PROXY_KEYS: &[&str] = &[
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ];
        let saved = PROXY_KEYS
            .iter()
            .map(|&key| (key, std::env::var_os(key)))
            .collect();
        for &key in &PROXY_KEYS[..6] {
            // SAFETY: this test holds the repository-wide ENV_LOCK until the
            // guard restores every proxy variable.
            unsafe { std::env::set_var(key, proxy_url) };
        }
        for &key in &PROXY_KEYS[6..] {
            // SAFETY: serialized by the same repository-wide ENV_LOCK.
            unsafe { std::env::remove_var(key) };
        }
        Self { saved }
    }
}

impl Drop for ProxyEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            // SAFETY: the caller still holds ENV_LOCK while this guard drops.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(*key, value),
                    None => std::env::remove_var(*key),
                }
            }
        }
    }
}

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn live(client: &PluginHttpClient) -> &reqwest::Client {
    client.get().expect("test plugin HTTP client")
}

#[tokio::test(flavor = "current_thread")]
async fn plugin_http_client_ignores_ambient_proxy_environment() {
    let proxy = MockServer::start().await;
    let client = {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());

        // Reqwest snapshots the system proxy configuration while building the
        // client. Restore the process environment before any async operation;
        // the constructed client retains the proxy posture under test.
        default_client()
    };

    let _ = client
        .get()
        .expect("test plugin HTTP client")
        .get("http://198.51.100.1:9/no-proxy-canary")
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    assert_eq!(
        proxy.received_requests().await.unwrap_or_default().len(),
        0,
        "ambient proxy variables must not receive plugin traffic"
    );
}

async fn start_connection_drop_server(
    expected_connections: usize,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = attempts.clone();

    let task = tokio::spawn(async move {
        for _ in 0..expected_connections {
            let (stream, _) = listener.accept().await.unwrap();
            attempts_clone.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }

        let extra_attempt =
            tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(extra_attempt.is_err(), "unexpected extra retry attempt");
    });

    (format!("http://{}", addr), attempts, task)
}

#[tokio::test]
async fn test_execute_returns_successful_response() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    let client = default_client();
    let req = live(&client).post(format!("{}/logs", mock_server.uri()));
    let resp = client.execute(req, "test_plugin").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_execute_returns_error_response() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fail"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = default_client();
    let req = live(&client).get(format!("{}/fail", mock_server.uri()));
    let resp = client.execute(req, "test_plugin").await.unwrap();
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn test_execute_screens_denied_literal_ip_endpoint() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};

    // A shared client carrying the production default egress policy (blocks
    // cloud-metadata / link-local). reqwest skips the DnsCacheResolver for an IP
    // literal, so `execute` is the runtime chokepoint: a request to a denied
    // literal must be surfaced to the plugin as a 502 WITHOUT dialing (so this is
    // hermetic — no server needed).
    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).unwrap();
    let client = PluginHttpClient::default_with_backend_allow_ips(policy);

    let req = live(&client).get("http://169.254.169.254/latest/meta-data/");
    let resp = client.execute(req, "test_plugin").await.unwrap();
    assert_eq!(
        resp.status(),
        502,
        "denied literal-IP endpoint must be screened to 502, not dialed"
    );
}

#[tokio::test]
async fn classified_execute_marks_dns_egress_denial_pre_wire() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    use ferrum_edge::retry::ErrorClass;

    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Public, "", "", true).unwrap();
    let client = PluginHttpClient::default_with_backend_allow_ips(policy);
    let external_latency = AtomicU64::new(0);
    let request = client
        .get()
        .expect("test plugin HTTP client")
        .post("http://localhost/provider")
        .body("non-idempotent");

    let failure = client
        .execute_redacted_tracked_classified(
            request,
            "classified_egress_test",
            "http://localhost/provider",
            &external_latency,
        )
        .await
        .unwrap_err();

    assert_eq!(failure.error_class, ErrorClass::DispatchPolicyRejected);
    assert!(
        !failure.request_reached_wire,
        "DNS egress denial happens before any provider dial"
    );
}

#[tokio::test]
async fn classified_execute_marks_literal_ip_egress_denial_pre_wire() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    use ferrum_edge::retry::ErrorClass;

    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).unwrap();
    let client = PluginHttpClient::default_with_backend_allow_ips(policy);
    let external_latency = AtomicU64::new(0);
    let request = client
        .get()
        .expect("test plugin HTTP client")
        .post("http://169.254.169.254/provider")
        .body("non-idempotent");

    let failure = client
        .execute_redacted_tracked_classified(
            request,
            "classified_literal_egress_test",
            "http://169.254.169.254/[REDACTED_PATH]",
            &external_latency,
        )
        .await
        .unwrap_err();

    assert_eq!(failure.error_class, ErrorClass::DispatchPolicyRejected);
    assert!(!failure.request_reached_wire);
    assert_eq!(external_latency.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn classified_execute_preserves_remote_502_as_a_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/provider"))
        .respond_with(ResponseTemplate::new(502).set_body_string("remote application response"))
        .mount(&server)
        .await;
    let client = default_client();
    let external_latency = AtomicU64::new(0);
    let request = client
        .get()
        .expect("test plugin HTTP client")
        .post(format!("{}/provider", server.uri()))
        .body("non-idempotent");

    let response = client
        .execute_redacted_tracked_classified(
            request,
            "classified_remote_502_test",
            &format!("{}/provider", server.uri()),
            &external_latency,
        )
        .await
        .expect("a remote 502 is an application response, not a pre-wire failure");

    assert_eq!(response.status(), 502);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_execute_returns_redirect_response_without_following() {
    let redirect_server = MockServer::start().await;
    let target_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("followed"))
        .mount(&target_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/target", target_server.uri())),
        )
        .mount(&redirect_server)
        .await;

    let client = default_client();
    let req = client
        .get()
        .expect("test plugin HTTP client")
        .get(format!("{}/redirect", redirect_server.uri()));
    let resp = client.execute(req, "test_plugin").await.unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(
        target_server
            .received_requests()
            .await
            .map(|requests| requests.len())
            .unwrap_or(0),
        0,
        "no-redirect execution must not request the Location target"
    );
}

#[tokio::test]
async fn test_execute_propagates_connection_error() {
    let client = default_client();
    // Port 1 should be unreachable on any test machine
    let req = live(&client).get("http://127.0.0.1:1/unreachable");
    let result = client.execute(req, "test_plugin").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_execute_logs_slow_call() {
    let mock_server = MockServer::start().await;
    // Respond after a 200ms delay
    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(200)))
        .mount(&mock_server)
        .await;

    // Build a client with a very low threshold (50ms) so the 200ms delay triggers it
    let client = PluginHttpClient::from_pool_config_with_threshold(
        &ferrum_edge::config::PoolConfig::default(),
        50,
    );
    let req = live(&client).get(format!("{}/slow", mock_server.uri()));
    // The call should succeed - the warning is logged but doesn't affect the result
    let resp = client.execute(req, "slow_test").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_execute_no_warning_for_fast_call() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fast"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Threshold of 60 seconds - fast local call should never trigger
    let client = PluginHttpClient::from_pool_config_with_threshold(
        &ferrum_edge::config::PoolConfig::default(),
        60_000,
    );
    let req = live(&client).get(format!("{}/fast", mock_server.uri()));
    let resp = client.execute(req, "fast_test").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_execute_retries_safe_method_transport_failures() {
    let (base_url, attempts, server_task) = start_connection_drop_server(3).await;
    let client = PluginHttpClient::from_pool_config_with_settings(
        &ferrum_edge::config::PoolConfig::default(),
        60_000,
        2,
        25,
    );

    let started = Instant::now();
    let req = live(&client).get(format!("{}/unstable", base_url));
    let result = client.execute(req, "retry_test").await;

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert!(started.elapsed() >= Duration::from_millis(40));
    server_task.await.unwrap();
}

#[test]
fn test_plugin_http_retries_connection_pool_error() {
    // Issue #4406: hyper is_canceled is ConnectionPoolError (pre-wire).
    // Moving that case off ConnectionReset would drop plugin HTTP retries
    // unless this predicate includes the new class. The live drop-server
    // test keeps the expected attempt count at 3; this locks the arm.
    let production = production_plugin_http_client_source();
    let retry_pred = function_region(
        production,
        "fn is_retryable_transport_error(",
        "impl Default for PluginHttpClient {",
    );
    let uncommented = uncommented_lines(retry_pred).join("\n");
    assert!(
        uncommented.contains("ErrorClass::ConnectionPoolError"),
        "plugin HTTP must retry ConnectionPoolError (hyper is_canceled)"
    );
    assert!(
        !ferrum_edge::retry::request_reached_wire(
            ferrum_edge::retry::ErrorClass::ConnectionPoolError
        ),
        "ConnectionPoolError must stay pre-wire so retry_on_connect_failure \
         and the plugin predicate agree on this class"
    );
}

#[tokio::test]
async fn test_execute_does_not_retry_http_status_failures() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status-fail"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = PluginHttpClient::from_pool_config_with_settings(
        &ferrum_edge::config::PoolConfig::default(),
        60_000,
        2,
        25,
    );
    let req = client
        .get()
        .expect("test plugin HTTP client")
        .get(format!("{}/status-fail", mock_server.uri()));
    let response = client.execute(req, "status_fail_test").await.unwrap();
    assert_eq!(response.status(), 500);
}

#[tokio::test]
async fn test_execute_does_not_retry_non_idempotent_methods() {
    let (base_url, attempts, server_task) = start_connection_drop_server(1).await;
    let client = PluginHttpClient::from_pool_config_with_settings(
        &ferrum_edge::config::PoolConfig::default(),
        60_000,
        2,
        25,
    );

    let req = client
        .get()
        .expect("test plugin HTTP client")
        .post(format!("{}/write", base_url))
        .body("payload");
    let result = client.execute(req, "post_retry_test").await;

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_shared_client_does_not_follow_redirects() {
    // finding #80: the shared outbound client must not auto-follow redirects,
    // so a 30x from a permitted host can't transparently redirect a plugin call
    // (jwks/oidc discovery, webhooks, request_mirror, …) to an internal service
    // or cloud-metadata endpoint. With redirect::Policy::none() the caller
    // receives the 3xx response itself rather than the followed target.
    let mock_server = MockServer::start().await;
    let target = format!("{}/target", mock_server.uri());
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", target.as_str()))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("followed-the-redirect"))
        .mount(&mock_server)
        .await;

    let client = default_client();
    // Deliberately build with an unrelated reqwest client, whose default
    // policy follows redirects. PluginHttpClient::execute must discard that
    // client choice and retain the gateway-owned execution posture.
    let req = reqwest::Client::new().get(format!("{}/redirect", mock_server.uri()));
    let resp = client.execute(req, "redirect_test").await.unwrap();

    assert_eq!(
        resp.status(),
        302,
        "shared client must surface the 3xx, not follow it"
    );
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        body, "followed-the-redirect",
        "the redirect target must not have been fetched"
    );
}

#[tokio::test]
async fn get_http2_companion_speaks_h2c_prior_knowledge() {
    use bytes::Bytes;
    use h2::server as h2_server;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<http::Version>();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut h2) = h2_server::handshake(tcp).await else {
            return;
        };
        let mut tx = Some(tx);
        while let Some(result) = h2.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let Some(tx) = tx.take() else {
                continue;
            };
            tokio::spawn(async move {
                let version = request.version();
                let mut body = request.into_body();
                while let Some(chunk) = body.data().await {
                    if let Ok(bytes) = chunk {
                        let _ = body.flow_control().release_capacity(bytes.len());
                    }
                }
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("empty response");
                let _ = respond.send_response(response, true);
                let _ = tx.send(version);
            });
        }
    });

    let client = default_client();
    let url = format!("http://{addr}/grpc");
    let req = client
        .get_http2()
        .expect("test plugin HTTP/2 client")
        .post(&url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Bytes::from_static(b"\x00\x00\x00\x00\x00"));
    let resp = client
        .execute_http2_redacted(req, "http2_companion", &url)
        .await
        .expect("h2c prior-knowledge request");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        rx.await.expect("h2c sink"),
        http::Version::HTTP_2,
        "get_http2 must force h2c prior knowledge"
    );
}

#[tokio::test]
async fn default_get_client_still_speaks_http1_to_plain_sinks() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tx.send(head);
        }
    });

    let client = default_client();
    let url = format!("http://{addr}/plain");
    let req = live(&client).get(&url);
    let resp = client.execute(req, "http1_default").await.unwrap();
    assert_eq!(resp.status(), 200);
    let head = rx.await.expect("http1 sink");
    assert!(
        head.starts_with("GET /plain HTTP/1.1"),
        "default client must remain HTTP/1.1 capable: {head}"
    );
}

// ---------------------------------------------------------------------------
// Ambient proxy isolation for every policy-governed plugin client family
// (GHSA-c4pj-vq6x-53rw). reqwest enables system-proxy discovery by default; a
// selected proxy dials the destination itself, so the ultimate address never
// reaches Ferrum's `DnsCacheResolver` egress screen.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn plugin_http2_companion_client_ignores_ambient_proxy_environment() {
    let proxy = MockServer::start().await;
    let client = {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());
        default_client()
    };

    let _ = client
        .get_http2()
        .expect("test plugin HTTP/2 client")
        .get("http://198.51.100.1:9/no-proxy-canary")
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    assert_eq!(
        proxy.received_requests().await.unwrap_or_default().len(),
        0,
        "the HTTP/2 companion must share the shared client's no-proxy posture"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn plugin_http_client_ignores_ambient_proxy_even_with_non_matching_no_proxy() {
    // `NO_PROXY` only ever *narrows* reqwest's proxy selection. A `NO_PROXY`
    // that does not cover the destination is the worst case: without
    // `.no_proxy()` the request would be relayed.
    let proxy = MockServer::start().await;
    let client = {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());
        // SAFETY: the repository-wide ENV_LOCK is held, and ProxyEnvGuard
        // restores NO_PROXY when it drops at the end of this block.
        unsafe { std::env::set_var("NO_PROXY", "unrelated.invalid") };
        default_client()
    };

    let _ = client
        .get()
        .expect("test plugin HTTP client")
        .get("http://198.51.100.1:9/no-proxy-canary")
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    assert_eq!(
        proxy.received_requests().await.unwrap_or_default().len(),
        0,
        "a non-matching NO_PROXY must not re-enable ambient proxying"
    );
}

/// Every policy-governed `reqwest` client family, as source text.
///
/// A behavioural test can only reach the client families that are reachable
/// from a plugin constructor; the fallback builders inside
/// `build_dns_cached_fallback_client` only run when a configured build fails,
/// and `api_chargeback_sink`'s dedicated client needs TLS material on disk.
/// This guard therefore asserts the invariant at the construction site so a new
/// builder — or a dropped `.no_proxy()` — fails CI instead of silently
/// reopening the bypass.
const POLICY_GOVERNED_CLIENT_SOURCES: &[(&str, &str)] = &[
    (
        "src/tls/backend.rs",
        include_str!("../../../src/tls/backend.rs"),
    ),
    (
        "src/health_check.rs",
        include_str!("../../../src/health_check.rs"),
    ),
    (
        "src/plugins/utils/http_client.rs",
        include_str!("../../../src/plugins/utils/http_client.rs"),
    ),
    (
        "src/plugins/api_chargeback_sink.rs",
        include_str!("../../../src/plugins/api_chargeback_sink.rs"),
    ),
    (
        "src/plugins/spec_expose.rs",
        include_str!("../../../src/plugins/spec_expose.rs"),
    ),
    (
        "src/plugins/load_testing.rs",
        include_str!("../../../src/plugins/load_testing.rs"),
    ),
];

#[test]
fn every_policy_governed_reqwest_builder_disables_ambient_proxies() {
    const NEEDLE: &str = "reqwest::Client::builder()";
    let mut checked = 0usize;
    for (path, source) in POLICY_GOVERNED_CLIENT_SOURCES {
        let mut offset = 0usize;
        while let Some(found) = source[offset..].find(NEEDLE) {
            let start = offset + found;
            offset = start + NEEDLE.len();
            // Skip prose: doc comments and `//` comments mention the builder by
            // name without constructing one.
            let line_start = source[..start].rfind('\n').map_or(0, |idx| idx + 1);
            if source[line_start..start].trim_start().starts_with("//") {
                continue;
            }
            // The builder chain runs to the statement terminator.
            let chain_end = source[start..]
                .find(';')
                .map(|end| start + end)
                .unwrap_or(source.len());
            let chain = &source[start..chain_end];
            assert!(
                chain.contains(".no_proxy()"),
                "{path}: a policy-governed reqwest client builder does not call .no_proxy(); \
                 ambient HTTP_PROXY/HTTPS_PROXY/ALL_PROXY would bypass backend egress policy.\n\
                 offending chain:\n{chain}"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 11,
        "expected to find every policy-governed client builder family, only found {checked}"
    );
}

#[test]
fn health_check_fallback_propagates_construction_failure_without_panic() {
    let source = POLICY_GOVERNED_CLIENT_SOURCES
        .iter()
        .find(|(path, _)| *path == "src/health_check.rs")
        .map(|(_, source)| *source)
        .expect("health_check.rs is a policy-governed client source");
    let start = source
        .find("fn build_dns_cached_fallback_client(")
        .expect("health-check fallback helper present");
    let rest = &source[start..];
    let end = rest
        .find("\nfn accept_health_check_client(")
        .expect("health-check accept helper present");
    let helper = &rest[..end];
    assert!(
        helper.contains("Result<reqwest::Client, reqwest::Error>"),
        "health-check fallback must propagate construction failure as Result"
    );
    assert!(
        !helper.contains("panic!"),
        "health-check fallback must not panic on construction failure"
    );
    let code_mentions_default_ctor = helper.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//")
            && !trimmed.starts_with("///")
            && !trimmed.starts_with('*')
            && trimmed.contains("Client::new()")
    });
    assert!(
        !code_mentions_default_ctor,
        "health-check fallback must not re-enable ambient proxies via Client::new()"
    );
}

fn production_plugin_http_client_source() -> &'static str {
    include_str!("../../../src/plugins/utils/http_client.rs")
        .split("\n#[cfg(test)]")
        .next()
        .expect("production plugin HTTP client source precedes test modules")
}

fn uncommented_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("///") && !trimmed.starts_with('*')
        })
        .collect()
}

fn function_region<'a>(source: &'a str, start_needle: &str, end_needle: &str) -> &'a str {
    let start = source
        .find(start_needle)
        .unwrap_or_else(|| panic!("{start_needle} present in plugin HTTP client source"));
    let rest = &source[start..];
    let end = rest
        .find(end_needle)
        .unwrap_or_else(|| panic!("{end_needle} follows {start_needle}"));
    &rest[..end]
}

#[test]
fn plugin_http_client_production_builder_has_no_panic_or_expect() {
    let production = production_plugin_http_client_source();
    let uncommented = uncommented_lines(production).join("\n");
    assert!(
        !uncommented.contains("panic!("),
        "plugin HTTP client production builder must not panic when host CA roots cannot load"
    );
    assert!(
        !uncommented.contains(".expect("),
        "plugin HTTP client production builder must not expect() on client construction"
    );
    assert!(
        !uncommented.contains("Client::new()"),
        "plugin HTTP client production builder must not re-enable ambient proxies via Client::new()"
    );
    assert!(
        !uncommented.contains("reconstruct_fail_closed_plugin_client"),
        "plugin HTTP client production builder must not spin reconstructing a reqwest client"
    );
    assert!(
        !uncommented.contains("process::abort") && !uncommented.contains("process::exit"),
        "plugin HTTP client production builder must not abort the process"
    );
    assert!(
        uncommented.contains("client: Option<Arc<reqwest::Client>>"),
        "terminal construction failure must be represented as Option, not an assumed-live client"
    );
    assert!(
        uncommented.contains("Result<&reqwest::Client, PluginHttpClientUnavailable>"),
        "get()/get_http2() must expose terminal construction failure without panicking"
    );
}

#[test]
fn plugin_http_client_callers_do_not_treat_get_result_as_reqwest_client() {
    // Compile-blocker regression: after get()/get_http2() started returning
    // Result, any `.get().post(...)` chain (including across newlines) treats
    // the Result as a reqwest client. Production callers must bind the Result
    // first and fail closed.
    const FORBIDDEN: &[&str] = &[
        ".get().get(",
        ".get().post(",
        ".get().put(",
        ".get().patch(",
        ".get().delete(",
        ".get().head(",
        ".get().request(",
        ".get_http2().get(",
        ".get_http2().post(",
        ".get_http2().put(",
        ".get_http2().patch(",
        ".get_http2().delete(",
        ".get_http2().head(",
        ".get_http2().request(",
        "build_request(client.get()",
        "http.get().post(",
        "http.get().put(",
        "http.get().patch(",
        "http.get().delete(",
        "http.get().get(",
        "http.get().request(",
    ];
    for (name, source) in plugin_http_client_caller_sources() {
        let collapsed = uncommented_lines(production_portion(source))
            .join("\n")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        for needle in FORBIDDEN {
            assert!(
                !collapsed.contains(needle),
                "{name} still treats get()/get_http2() Result as a reqwest client: {needle}"
            );
        }
    }
}

fn production_portion(source: &str) -> &str {
    source.split("\n#[cfg(test)]").next().unwrap_or(source)
}

fn plugin_http_client_caller_sources() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "src/plugins/utils/http_client.rs",
            include_str!("../../../src/plugins/utils/http_client.rs"),
        ),
        (
            "src/plugins/request_mirror.rs",
            include_str!("../../../src/plugins/request_mirror.rs"),
        ),
        (
            "src/service_discovery/mod.rs",
            include_str!("../../../src/service_discovery/mod.rs"),
        ),
        (
            "src/plugins/api_chargeback_sink.rs",
            include_str!("../../../src/plugins/api_chargeback_sink.rs"),
        ),
        (
            "src/plugins/otel_tracing.rs",
            include_str!("../../../src/plugins/otel_tracing.rs"),
        ),
        (
            "src/plugins/utils/jwks_store.rs",
            include_str!("../../../src/plugins/utils/jwks_store.rs"),
        ),
        (
            "src/plugins/jwks_auth.rs",
            include_str!("../../../src/plugins/jwks_auth.rs"),
        ),
        (
            "src/plugins/oauth2_introspection.rs",
            include_str!("../../../src/plugins/oauth2_introspection.rs"),
        ),
        (
            "src/plugins/oidc_relying_party.rs",
            include_str!("../../../src/plugins/oidc_relying_party.rs"),
        ),
        (
            "src/plugins/serverless_function.rs",
            include_str!("../../../src/plugins/serverless_function.rs"),
        ),
        (
            "src/plugins/opa.rs",
            include_str!("../../../src/plugins/opa.rs"),
        ),
        (
            "src/plugins/mesh/ext_authz.rs",
            include_str!("../../../src/plugins/mesh/ext_authz.rs"),
        ),
        (
            "src/plugins/mcp_gateway.rs",
            include_str!("../../../src/plugins/mcp_gateway.rs"),
        ),
        (
            "src/plugins/loki_logging.rs",
            include_str!("../../../src/plugins/loki_logging.rs"),
        ),
        (
            "src/plugins/http_logging.rs",
            include_str!("../../../src/plugins/http_logging.rs"),
        ),
        (
            "src/plugins/ai_transcript_audit.rs",
            include_str!("../../../src/plugins/ai_transcript_audit.rs"),
        ),
        (
            "src/plugins/ai_tool_governor.rs",
            include_str!("../../../src/plugins/ai_tool_governor.rs"),
        ),
        (
            "src/plugins/ai_semantic_firewall.rs",
            include_str!("../../../src/plugins/ai_semantic_firewall.rs"),
        ),
        (
            "src/plugins/ai_semantic_cache.rs",
            include_str!("../../../src/plugins/ai_semantic_cache.rs"),
        ),
        (
            "src/plugins/ai_federation.rs",
            include_str!("../../../src/plugins/ai_federation.rs"),
        ),
        (
            "src/modes/mesh/federation.rs",
            include_str!("../../../src/modes/mesh/federation.rs"),
        ),
        (
            "src/notifications/channels/mod.rs",
            include_str!("../../../src/notifications/channels/mod.rs"),
        ),
        (
            "src/notifications/channels/webhook.rs",
            include_str!("../../../src/notifications/channels/webhook.rs"),
        ),
        (
            "src/plugins/load_testing.rs",
            include_str!("../../../src/plugins/load_testing.rs"),
        ),
    ]
}

#[test]
fn plugin_http_client_terminal_fallback_is_fail_closed_no_proxy_no_redirect() {
    let production = production_plugin_http_client_source();
    let fail_closed = function_region(
        production,
        "fn apply_fail_closed_empty_trust(",
        "fn apply_or_inert(",
    );
    let uncommented_tls = uncommented_lines(fail_closed).join("\n");
    assert!(
        uncommented_tls.contains("tls_danger_accept_invalid_certs(false)"),
        "fail-closed TLS must keep certificate verification enabled"
    );
    assert!(
        uncommented_tls.contains("tls_certs_only"),
        "fail-closed TLS must disable ambient native/built-in roots via tls_certs_only"
    );
    assert!(
        !uncommented_tls.contains("danger_accept_invalid_certs(true)"),
        "fail-closed TLS must not disable certificate verification"
    );

    let inert = function_region(
        production,
        "fn apply_inert_crypto_posture(",
        "fn apply_terminal_fail_closed_tls(",
    );
    let uncommented_inert = uncommented_lines(inert).join("\n");
    assert!(
        uncommented_inert.contains("apply_fail_closed_empty_trust"),
        "FIPS inert posture must reuse the empty-trust fail-closed TLS helper"
    );
    assert!(
        uncommented_inert.contains("https_only(true)"),
        "FIPS inert posture must keep HTTPS-only so plaintext is not a fallback"
    );

    let terminal = function_region(
        production,
        "struct PluginHttpClientBuildError",
        "impl PluginHttpClient {",
    );
    let uncommented_terminal = uncommented_lines(terminal).join("\n");
    assert!(
        uncommented_terminal.contains(".no_proxy()"),
        "terminal fallback must keep .no_proxy()"
    );
    assert!(
        uncommented_terminal.contains("reqwest::redirect::Policy::none()"),
        "terminal fallback must keep redirects disabled"
    );
    let preconfigured = function_region(
        production,
        "fn try_build_preconfigured_fail_closed_plugin_client(",
        "/// Bounded fail-closed construction:",
    );
    let uncommented_preconfigured = uncommented_lines(preconfigured).join("\n");
    assert!(
        uncommented_preconfigured.contains("attach_plugin_client_dns"),
        "preconfigured terminal fallback must retain the supplied gateway DNS resolver"
    );
    assert!(
        uncommented_preconfigured.contains("attach_plugin_client_http2"),
        "preconfigured terminal fallback must retain HTTP/2 prior knowledge"
    );
    assert!(
        uncommented_terminal.contains("apply_terminal_fail_closed_tls"),
        "terminal fallback must apply fail-closed empty-trust TLS"
    );
    assert!(
        uncommented_terminal.contains("use_preconfigured_tls"),
        "terminal reconstruction must use an explicit empty rustls root store"
    );
    assert!(
        uncommented_terminal.contains("RootCertStore::empty()"),
        "preconfigured reconstruction must install an empty trust store"
    );
    assert!(
        uncommented_terminal.contains("builder_with_provider"),
        "preconfigured reconstruction must not panic via rustls ClientConfig::builder()"
    );
    assert!(
        !uncommented_terminal.contains("ClientConfig::builder()"),
        "preconfigured reconstruction must not use rustls ClientConfig::builder(), \
         which panics without a process default provider"
    );
    assert!(
        uncommented_terminal.contains("Result<reqwest::Client, PluginHttpClientBuildError>"),
        "terminal construction must return Result so failure is representable"
    );
    assert!(
        uncommented_terminal.contains("fn accept_plugin_http_client("),
        "terminal construction failure must convert to an inert Option wrapper"
    );
    assert!(
        !uncommented_terminal.contains("loop {"),
        "terminal construction must not retry without a bound"
    );
    assert!(
        !uncommented_terminal.contains("unwrap_or_else"),
        "terminal construction must not unwrap a fallible builder into a \
         spinning or panicking fallback"
    );
    assert!(
        !uncommented_terminal.contains(".unwrap()"),
        "terminal construction must not unwrap a fallible builder"
    );
    assert!(
        !uncommented_terminal.contains("panic!("),
        "terminal fallback must not panic"
    );
    assert!(
        !uncommented_terminal.contains(".expect("),
        "terminal fallback must not expect() on construction"
    );
    assert!(
        !uncommented_terminal.contains("Client::new()"),
        "terminal fallback must not call Client::new()"
    );
    assert!(
        !uncommented_terminal.contains("danger_accept_invalid_certs(true)"),
        "terminal fallback must not disable certificate verification"
    );

    let execute = function_region(
        production,
        "fn unavailable_plugin_http_failure(",
        "fn classify_plugin_http_failure(",
    );
    let uncommented_execute = uncommented_lines(execute).join("\n");
    assert!(
        uncommented_execute.contains("ErrorClass::ConnectionPoolError"),
        "classified execute must report unavailable construction as a pre-wire pool error"
    );
    assert!(
        uncommented_execute.contains("request_reached_wire: false"),
        "unavailable construction must not be treated as a post-wire failure"
    );
    assert!(
        !uncommented_execute.contains(".build()"),
        "unavailable execute must not construct another fallible reqwest client per call"
    );
    assert!(
        !uncommented_execute.contains("tracing::"),
        "terminal construction is logged once; unavailable execute must not warn per call"
    );

    let fail_closed_builder = function_region(
        production,
        "fn build_fail_closed_plugin_client(",
        "fn build_dns_cached_fallback_client(",
    );
    let uncommented_fail_closed_builder = uncommented_lines(fail_closed_builder)
        .join("\n")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    assert!(
        uncommented_fail_closed_builder
            .contains("try_build_plugin_client(dns_cache,http2_prior_knowledge"),
        "terminal empty-trust construction must keep the caller's DNS resolver"
    );
    assert!(
        !uncommented_fail_closed_builder
            .contains("try_build_plugin_client(None,http2_prior_knowledge"),
        "terminal fallback must not drop a supplied DNS resolver"
    );
    assert!(
        uncommented_fail_closed_builder.contains(
            "try_build_preconfigured_fail_closed_plugin_client(dns_cache,http2_prior_knowledge"
        ),
        "preconfigured reconstruction must inherit DNS and HTTP/2 posture"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fail_closed_empty_trust_client_ignores_proxy_and_does_not_follow_redirects() {
    use ferrum_edge::config::{BackendEgressPolicy, PoolConfig};
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tempdir = tempfile::tempdir().expect("create tempdir");
    let ca_path = tempdir.path().join("invalid-ca.pem");
    std::fs::write(&ca_path, "not a pem certificate").expect("write invalid CA");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect listener");
    let addr = listener.local_addr().expect("listener address");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            hits_task.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let body = "redirected";
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{addr}/chased\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let proxy = MockServer::start().await;
    let client = {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());
        PluginHttpClient::new(
            &PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            1000,
            0,
            100,
            false,
            ca_path.to_str(),
            Arc::new(Vec::new()),
            ferrum_edge::config::types::DEFAULT_NAMESPACE,
            BackendEgressPolicy::unrestricted(),
            Arc::new(Vec::new()),
            0,
        )
    };

    let _ = client
        .get()
        .expect("test plugin HTTP client")
        .get("http://198.51.100.1:9/no-proxy-canary")
        .timeout(Duration::from_millis(200))
        .send()
        .await;
    assert_eq!(
        proxy.received_requests().await.unwrap_or_default().len(),
        0,
        "fail-closed empty-trust client must ignore ambient proxy variables"
    );

    let resp = client
        .get()
        .expect("test plugin HTTP client")
        .get(format!("http://{addr}/"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("HTTP to the local listener must succeed on the fail-closed client");
    assert_eq!(resp.status().as_u16(), 302, "must surface the 302");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "fail-closed empty-trust client must not follow redirects"
    );
}

// ---------------------------------------------------------------------------
// Redacted execution APIs — advisory GHSA-8594-2xhc-8g38
//
// Every HTTP-backed observability sink whose endpoint may embed a credential
// funnels through one of these two helpers. The literal-IP egress denial, the
// retry warning, and the slow-call warning are all emitted inside this client,
// so proving redaction here proves it for every such caller at once.
// ---------------------------------------------------------------------------

/// The credential-bearing components a sink endpoint may legitimately hold.
const URL_PATH_SENTINEL: &str = "shared-client-path-token-canary";
const URL_QUERY_SENTINEL: &str = "shared-client-query-key-canary";

fn sentinel_url(base: &str) -> String {
    format!("{base}/receiver/{URL_PATH_SENTINEL}?apikey={URL_QUERY_SENTINEL}")
}

fn assert_url_sentinels_absent(logs: &str, context: &str) {
    for sentinel in [URL_PATH_SENTINEL, URL_QUERY_SENTINEL] {
        assert!(
            !logs.contains(sentinel),
            "{context} leaked {sentinel:?}: {logs}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn execute_redacted_hides_literal_ip_egress_denial_url() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};

    let (logs, guard) = super::plugin_utils::capture_logs();
    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).unwrap();
    let client = PluginHttpClient::default_with_backend_allow_ips(policy);

    let url = sentinel_url("http://169.254.169.254");
    let req = live(&client).post(&url).body("batch");
    let response = client
        .execute_redacted(req, "sink_test", "http://169.254.169.254/redacted")
        .await
        .expect("a denied literal IP is surfaced as a 502, not an error");
    assert_eq!(response.status(), 502);

    drop(guard);
    let captured = logs.contents();
    assert!(
        captured.contains("denied literal-IP endpoint"),
        "the denial diagnostic must have been emitted: {captured}"
    );
    assert!(captured.contains("http://169.254.169.254/redacted"));
    assert_url_sentinels_absent(&captured, "egress denial diagnostic");
}

#[tokio::test(flavor = "current_thread")]
async fn execute_with_redacted_url_hides_literal_ip_egress_denial_url() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};

    // `api_chargeback_sink` uses this variant so it can classify the typed
    // `reqwest::Error` itself; it must redact exactly like `execute_redacted`.
    let (logs, guard) = super::plugin_utils::capture_logs();
    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).unwrap();
    let client = PluginHttpClient::default_with_backend_allow_ips(policy);

    let url = sentinel_url("http://169.254.169.254");
    let req = live(&client).post(&url).body("rows");
    let response = client
        .execute_with_redacted_url(req, "chargeback_test", "http://169.254.169.254/redacted")
        .await
        .expect("a denied literal IP is surfaced as a 502, not an error");
    assert_eq!(response.status(), 502);

    drop(guard);
    let captured = logs.contents();
    assert!(
        captured.contains("denied literal-IP endpoint"),
        "the denial diagnostic must have been emitted: {captured}"
    );
    assert_url_sentinels_absent(&captured, "egress denial diagnostic");
}

/// Slow-call and retry warnings are emitted from the same code path for both
/// redacted helpers; a dead port with `slow_threshold_ms = 0` triggers both.
#[tokio::test(flavor = "current_thread")]
async fn redacted_transport_failure_slow_and_retry_warnings_hide_the_url() {
    let (logs, guard) = super::plugin_utils::capture_logs();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client = PluginHttpClient::from_pool_config_with_settings(
        &ferrum_edge::config::PoolConfig::default(),
        0, // every call is "slow"
        2, // retries enabled for GET
        1,
    );
    let url = sentinel_url(&format!("http://{addr}"));
    let redacted = format!("http://{addr}/redacted");

    // GET so the retry path is eligible.
    let req = live(&client).get(&url);
    let error = client
        .execute_redacted(req, "sink_test", &redacted)
        .await
        .expect_err("a dead port must fail");
    assert!(
        !error.contains(URL_PATH_SENTINEL) && !error.contains(URL_QUERY_SENTINEL),
        "the returned error must be sanitized: {error}"
    );

    drop(guard);
    let captured = logs.contents();
    assert!(
        captured.contains("Retrying plugin HTTP call")
            || captured.contains("Slow plugin HTTP call"),
        "retry and/or slow-call diagnostics must have been emitted: {captured}"
    );
    assert_url_sentinels_absent(&captured, "transport failure diagnostics");
}
