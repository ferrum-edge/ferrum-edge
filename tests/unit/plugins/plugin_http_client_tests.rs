use ferrum_edge::plugins::PluginHttpClient;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
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
