use ferrum_edge::plugins::PluginHttpClient;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    let req = client.get().get(format!("{}/redirect", mock_server.uri()));
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
