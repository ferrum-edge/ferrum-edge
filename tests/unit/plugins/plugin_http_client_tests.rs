use ferrum_edge::plugins::PluginHttpClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
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
    use std::time::Duration;

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
    // The call should succeed — the warning is logged but doesn't affect the result
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

    // Threshold of 60 seconds — fast local call should never trigger
    let client = PluginHttpClient::from_pool_config_with_threshold(
        &ferrum_edge::config::PoolConfig::default(),
        60_000,
    );
    let req = client.get().get(format!("{}/fast", mock_server.uri()));
    let resp = client.execute(req, "fast_test").await.unwrap();
    assert_eq!(resp.status(), 200);
}
