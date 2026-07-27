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
    let req = client.get().post(format!("{}/logs", mock_server.uri()));
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
    let req = client.get().get(format!("{}/fail", mock_server.uri()));
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

    let req = client.get().get("http://169.254.169.254/latest/meta-data/");
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
    let req = client.get().get("http://127.0.0.1:1/unreachable");
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
    let req = client.get().get(format!("{}/slow", mock_server.uri()));
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
    let req = client.get().get(format!("{}/fast", mock_server.uri()));
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
    let req = client.get().get(format!("{}/unstable", base_url));
    let result = client.execute(req, "retry_test").await;

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert!(started.elapsed() >= Duration::from_millis(40));
    server_task.await.unwrap();
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
    let req = client.get().get(&url);
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
