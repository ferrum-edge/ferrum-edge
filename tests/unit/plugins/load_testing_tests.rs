use bytes::Bytes;
use ferrum_edge::plugins::load_testing::{
    LOAD_TESTING_CONFIG_KEYS, LoadTesting, MAX_GATEWAY_ADDRESSES, MAX_REPLAY_REQUEST_BODY_BYTES,
    MIN_TRIGGER_KEY_LEN, RunOutcome,
};
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    RequestContext, plugin_failure_policy, priority, validate_plugin_config,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

const VALID_KEY: &str = "test-load-key-0123456789abcdef!!"; // exactly 32 chars

type StalledRequestObserver = (u16, oneshot::Receiver<()>, oneshot::Receiver<()>);

fn make_valid_config() -> serde_json::Value {
    json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 8000
    })
}

fn make_plugin() -> LoadTesting {
    LoadTesting::new(&make_valid_config(), PluginHttpClient::default()).unwrap()
}

async fn run_before_proxy(
    plugin: &LoadTesting,
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> PluginResult {
    // Production keeps `ctx.headers` as the immutable ingress view and passes a
    // clone through header-transforming hooks. Mirror that contract in direct
    // plugin tests so trigger authentication exercises both views.
    ctx.headers = headers.clone();
    plugin.before_proxy(ctx, headers).await
}

fn matched_proxy() -> Arc<ferrum_edge::config::types::Proxy> {
    Arc::new(
        serde_json::from_value(json!({
            "id": "proxy-1",
            "name": "test-proxy",
            "listen_path": "/api",
            "backend_host": "backend.local",
            "backend_port": 8080,
            "backend_scheme": "http"
        }))
        .unwrap(),
    )
}

async fn wait_until_idle(plugin: &LoadTesting) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while plugin.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !plugin.is_running(),
        "timed out waiting for load_testing cohort to stop"
    );
}

async fn wait_for_result(plugin: &LoadTesting) -> ferrum_edge::plugins::load_testing::RunResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(result) = plugin.last_run_result() {
            return result;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for load_testing run result");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Capture one complete HTTP/1.1 request from a local listener, then reply 200.
async fn capture_one_http_request(listener: tokio::net::TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = socket.read(&mut tmp).await.expect("read");
        assert!(n > 0, "connection closed before complete request");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            while buf.len() < header_end + content_length {
                let n = socket.read(&mut tmp).await.expect("read body");
                assert!(n > 0, "connection closed before body completed");
                buf.extend_from_slice(&tmp[..n]);
            }
            let body = b"ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
            return buf;
        }
        assert!(buf.len() < 64 * 1024, "request grew too large");
    }
}

async fn spawn_stalled_request_observer() -> StalledRequestObserver {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled listener");
    let port = listener.local_addr().expect("listener address").port();
    let (request_started_tx, request_started_rx) = oneshot::channel();
    let (client_closed_tx, client_closed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept stalled request");
        let mut request = [0u8; 4096];
        let read = socket
            .read(&mut request)
            .await
            .expect("read stalled request");
        assert!(read > 0, "stalled request must send bytes");
        let _ = request_started_tx.send(());

        // Never send a response. Cancellation must drop the in-flight reqwest
        // future and close its HTTP/1.1 connection before the run deadline.
        let mut byte = [0u8; 1];
        loop {
            match socket.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = client_closed_tx.send(());
    });

    (port, request_started_rx, client_closed_rx)
}

fn parse_captured_request(raw: &[u8]) -> (String, HashMap<String, String>, Vec<u8>) {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let header_text = std::str::from_utf8(&raw[..header_end]).expect("headers utf8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    (request_line, headers, raw[header_end..].to_vec())
}

#[test]
fn validate_plugin_config_with_policy_screens_denied_gateway_address() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    use ferrum_edge::plugins::validate_plugin_config_with_policy;

    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");

    let denied = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 8000,
        "gateway_addresses": ["http://169.254.169.254:8000"]
    });
    assert!(
        validate_plugin_config_with_policy("load_testing", &denied, &default_policy).is_err(),
        "metadata gateway address must be rejected under the default policy"
    );

    let loopback = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 8000,
        "gateway_addresses": ["http://10.0.0.2:8000"]
    });
    assert!(
        validate_plugin_config_with_policy("load_testing", &loopback, &default_policy).is_ok(),
        "private gateway address must remain valid by default"
    );
}

#[test]
fn test_plugin_name() {
    assert_eq!(make_plugin().name(), "load_testing");
}

#[test]
fn test_plugin_priority_before_request_mirror() {
    let plugin = make_plugin();
    assert_eq!(plugin.priority(), priority::LOAD_TESTING);
    const {
        assert!(
            priority::LOAD_TESTING < priority::REQUEST_MIRROR,
            "load_testing must strip the trigger key before request_mirror can observe it"
        );
        assert!(
            priority::GRPC_DEADLINE < priority::LOAD_TESTING,
            "load_testing remains after grpc_deadline in the deferred transform band"
        );
    }
}

#[test]
fn test_supported_protocols() {
    assert_eq!(make_plugin().supported_protocols(), HTTP_ONLY_PROTOCOLS);
}

#[test]
fn test_declares_header_mutation_and_trigger_redaction() {
    let plugin = make_plugin();
    assert!(plugin.modifies_request_headers());
    assert_eq!(plugin.request_headers_to_redact(), &["x-loadtesting-key"]);
    assert_eq!(
        plugin.request_body_buffer_limit(),
        Some(MAX_REPLAY_REQUEST_BODY_BYTES),
        "load-testing replay bodies must remain bounded when the global limit is unlimited"
    );
}

#[test]
fn test_valid_minimal_config() {
    assert!(LoadTesting::new(&make_valid_config(), PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_ramp() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "ramp": true,
        "gateway_port": 8000
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_port() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_port": 9090
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_tls() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_tls": true,
        "gateway_port": 8443
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_addresses() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_port": 8000,
        "gateway_addresses": ["https://node1:8443", "https://node2:8443"]
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_boundary_values() {
    let config = json!({
        "key": "test-load-key-0123456789abcdef!!",
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());

    let config = json!({
        "key": "test-load-key-0123456789abcdef!!",
        "concurrent_clients": 10000,
        "duration_seconds": 3600,
        "gateway_port": 8000
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_every_supported_field() {
    let config = json!({
        "key": "full-surface-load-key-0123456789!",
        "concurrent_clients": 25,
        "duration_seconds": 45,
        "ramp": true,
        "request_timeout_ms": 5000,
        "max_response_body_bytes": 2048,
        "gateway_port": 8443,
        "gateway_tls": true,
        "gateway_tls_no_verify": true,
        "gateway_addresses": ["https://10.0.0.2:8443", "https://10.0.0.3:8443"]
    });
    assert_eq!(
        config.as_object().unwrap().len(),
        LOAD_TESTING_CONFIG_KEYS.len(),
        "fixture must exercise every accepted top-level key"
    );
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
    assert!(validate_plugin_config("load_testing", &config).is_ok());
}

#[test]
fn test_optional_null_fields_still_select_defaults() {
    let env = crate::unit::env_lock::EnvGuard::new(&["FERRUM_PROXY_HTTP_PORT"]);
    env.unset("FERRUM_PROXY_HTTP_PORT");
    let config = json!({
        "key": "null-defaults-key-0123456789abcdef!",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "ramp": null,
        "request_timeout_ms": null,
        "max_response_body_bytes": null,
        "gateway_port": null,
        "gateway_tls": null,
        "gateway_tls_no_verify": null,
        "gateway_addresses": null
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_rejects_short_trigger_key() {
    let short = "x".repeat(MIN_TRIGGER_KEY_LEN - 1);
    let config = json!({
        "key": short,
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("at least 32 characters"), "got: {err}");
}

#[test]
fn test_trigger_key_must_be_a_stable_printable_ascii_header_value() {
    let invalid = [
        "😀".repeat(MIN_TRIGGER_KEY_LEN),
        format!(" {VALID_KEY}"),
        format!("{VALID_KEY} "),
        format!("{VALID_KEY}\r\ninjected"),
        format!("{VALID_KEY}\tmore"),
    ];

    for key in invalid {
        let err = LoadTesting::new(
            &json!({
                "key": key.clone(),
                "concurrent_clients": 1,
                "duration_seconds": 1,
                "gateway_port": 8000
            }),
            PluginHttpClient::default(),
        )
        .err()
        .expect("non-header-safe trigger key must fail");
        assert!(err.contains("printable ASCII"), "got: {err}");
        assert!(
            !err.contains(key.as_str()),
            "trigger key leaked in error: {err}"
        );
    }

    let internal_space = json!({
        "key": "test load key 0123456789abcdef!!",
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000
    });
    assert!(LoadTesting::new(&internal_space, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_rejects_one_typo_with_path_qualified_suggestion() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 50,
        "duration_seconds": 30,
        "request_timeot_ms": 5000
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("typo must be rejected");
    assert!(err.contains("'config.request_timeot_ms'"), "got: {err}");
    assert!(
        err.contains("did you mean 'request_timeout_ms'"),
        "got: {err}"
    );
}

#[test]
fn shared_file_admin_database_cp_dp_admission_rejects_unknown_keys() {
    assert_eq!(
        plugin_failure_policy("load_testing"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );

    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "request_timeot_ms": 5000
    });
    let err = validate_plugin_config("load_testing", &config).expect_err("must reject typo");
    assert!(err.contains("'config.request_timeot_ms'"), "got: {err}");
}

#[test]
fn test_non_object_config_is_error() {
    let err = LoadTesting::new(&json!("bad"), PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_missing_key_is_error() {
    let config = json!({
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("'key' is required"), "got: {err}");
}

#[test]
fn test_empty_key_is_error() {
    let config = json!({
        "key": "",
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("'key' is required"), "got: {err}");
}

#[test]
fn test_zero_gateway_port_is_error() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 0
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–65535"), "got: {err}");
}

#[test]
fn test_request_timeout_above_max_is_error() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "request_timeout_ms": 60_001
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("60000"), "got: {err}");
}

#[test]
fn test_gateway_address_validation_never_echoes_raw_secrets() {
    let cases = [
        (
            "https://user:s3cret-token@node2:8443",
            "userinfo",
            &["s3cret-token", "user:s3cret", "@node2"][..],
        ),
        (
            "https://node2:8443?access_token=leak-me-now&api_key=abc",
            "query or fragment",
            &["access_token", "leak-me-now", "api_key=abc"][..],
        ),
        (
            "https://node2:8443#frag-secret-value",
            "query or fragment",
            &["frag-secret-value", "#frag"][..],
        ),
        (
            "https://node2:8443?X=%2Fsecret%2Fpath",
            "query or fragment",
            &["%2Fsecret", "X=%2F"][..],
        ),
        (
            "HtTpS://USER:TokEn@Node2:8443/path?q=1#f",
            "userinfo",
            &["TokEn", "USER:TokEn", "/path", "q=1"][..],
        ),
        (
            "not a url at all :::token=raw",
            "invalid gateway address",
            &["token=raw", ":::"][..],
        ),
    ];

    for (address, expected_fragment, forbidden) in cases {
        let config = json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 8000,
            "gateway_addresses": [address]
        });
        let err = LoadTesting::new(&config, PluginHttpClient::default())
            .err()
            .unwrap_or_else(|| panic!("address {address} should fail"));
        assert!(
            err.contains(expected_fragment),
            "address {address}: expected '{expected_fragment}' in {err}"
        );
        for needle in forbidden {
            assert!(
                !err.contains(needle),
                "address {address}: error leaked '{needle}': {err}"
            );
        }
        assert!(
            !err.contains(address),
            "address {address}: error echoed raw URL: {err}"
        );
    }
}

#[test]
fn test_gateway_addresses_shape_validation() {
    let empty = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": []
    });
    let err = LoadTesting::new(&empty, PluginHttpClient::default())
        .err()
        .expect("empty gateway_addresses must fail");
    assert!(
        err.contains("must not be empty when provided"),
        "got: {err}"
    );

    let non_string = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": [123]
    });
    let err = LoadTesting::new(&non_string, PluginHttpClient::default())
        .err()
        .expect("non-string gateway address must fail");
    assert!(
        err.contains("each 'gateway_addresses' entry must be a string"),
        "got: {err}"
    );

    let empty_entry = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": [""]
    });
    let err = LoadTesting::new(&empty_entry, PluginHttpClient::default())
        .err()
        .expect("empty gateway address entry must fail");
    assert!(err.contains("entries must not be empty"), "got: {err}");

    let not_array = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": "https://node2:8443"
    });
    let err = LoadTesting::new(&not_array, PluginHttpClient::default())
        .err()
        .expect("non-array gateway_addresses must fail");
    assert!(
        err.contains("'gateway_addresses' must be an array"),
        "got: {err}"
    );
}

#[test]
fn test_gateway_addresses_max_items_enforced() {
    let too_many: Vec<String> = (0..=MAX_GATEWAY_ADDRESSES)
        .map(|i| format!("https://10.0.0.{}:8443", i + 2))
        .collect();
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": too_many
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("over-max gateway_addresses must fail");
    assert!(
        err.contains(&format!("at most {MAX_GATEWAY_ADDRESSES}")),
        "got: {err}"
    );

    let exact: Vec<String> = (0..MAX_GATEWAY_ADDRESSES)
        .map(|i| format!("https://10.0.0.{}:8443", i + 2))
        .collect();
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": exact
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_duplicate_gateway_addresses_are_rejected() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": ["https://node2:8443/", "https://node2:8443"]
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("duplicate"), "got: {err}");
}

#[test]
fn test_self_loopback_gateway_aliases_are_rejected() {
    for address in [
        "http://127.0.0.1:8000",
        "http://127.0.0.9:8000",
        "http://localhost:8000",
        "http://LOCALHOST:8000",
        "http://localhost.:8000",
        "http://node.localhost:8000",
        "http://NODE.LOCALHOST.:8000",
        "http://[::1]:8000",
        "http://[::ffff:127.0.0.1]:8000",
    ] {
        let config = json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 8000,
            "gateway_addresses": [address]
        });
        let err = LoadTesting::new(&config, PluginHttpClient::default())
            .err()
            .unwrap_or_else(|| panic!("{address} must be rejected as local loopback"));
        assert!(
            err.contains("local loopback"),
            "address {address}: got {err}"
        );
    }

    // Different effective port is not the local target.
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": ["http://127.0.0.1:8001"]
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_env_derived_disabled_http_port_is_rejected() {
    let env = crate::unit::env_lock::EnvGuard::new(&["FERRUM_PROXY_HTTP_PORT"]);
    env.set("FERRUM_PROXY_HTTP_PORT", "0");
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("disabled HTTP listener must fail closed");
    assert!(err.contains("resolved gateway port is 0"), "got: {err}");
    assert!(err.contains("HTTP (FERRUM_PROXY_HTTP_PORT)"), "got: {err}");
}

#[test]
fn test_env_derived_disabled_https_port_is_rejected() {
    let env = crate::unit::env_lock::EnvGuard::new(&["FERRUM_PROXY_HTTPS_PORT"]);
    env.set("FERRUM_PROXY_HTTPS_PORT", "0");
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_tls": true
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("disabled HTTPS listener must fail closed");
    assert!(err.contains("resolved gateway port is 0"), "got: {err}");
    assert!(
        err.contains("HTTPS (FERRUM_PROXY_HTTPS_PORT)"),
        "got: {err}"
    );
}

#[test]
fn test_explicit_port_overrides_disabled_env_default() {
    let env = crate::unit::env_lock::EnvGuard::new(&["FERRUM_PROXY_HTTP_PORT"]);
    env.set("FERRUM_PROXY_HTTP_PORT", "0");
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 18080
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_env_derived_enabled_http_port_is_accepted() {
    let env = crate::unit::env_lock::EnvGuard::new(&["FERRUM_PROXY_HTTP_PORT"]);
    env.set("FERRUM_PROXY_HTTP_PORT", "18081");
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_should_buffer_only_when_trigger_key_matches() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    assert!(!plugin.should_buffer_request_body(&ctx));
    ctx.headers.insert(
        "x-loadtesting-key".to_string(),
        "wrong-key-value!!".to_string(),
    );
    assert!(
        !plugin.should_buffer_request_body(&ctx),
        "a wrong key must not let unauthenticated callers force body buffering"
    );
    ctx.headers
        .insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    assert!(plugin.should_buffer_request_body(&ctx));
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_request_body_bytes());
    assert!(!plugin.needs_request_body_text());
}

#[tokio::test]
async fn test_skips_when_no_key_header() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_skips_when_key_does_not_match() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "x-loadtesting-key".to_string(),
        "wrong-load-key-0123456789abcdef!".to_string(),
    );
    headers.insert(
        "X-Loadtesting-Key".to_string(),
        "operator-injected-load-key-variant".to_string(),
    );
    headers.insert("x-loadtesting-fanout".to_string(), "1".to_string());
    headers.insert("X-Loadtesting-Fanout".to_string(), "1".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-loadtesting-key")),
        "every case variant of the reserved trigger header must be stripped: {headers:?}"
    );
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("x-loadtesting-fanout")),
        "every case variant of the fan-out marker must be stripped: {headers:?}"
    );
}

#[tokio::test]
async fn test_header_transformers_cannot_manufacture_or_change_trigger_authentication() {
    let plugin = make_plugin();

    // A matching value introduced only into the mutable hook map was not
    // present when body admission ran and must not start a cohort.
    let mut injected_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut injected_headers =
        HashMap::from([("x-loadtesting-key".to_string(), VALID_KEY.to_string())]);
    let injected_result = plugin
        .before_proxy(&mut injected_ctx, &mut injected_headers)
        .await;
    assert!(matches!(injected_result, PluginResult::Continue));
    assert!(!plugin.is_running());
    assert!(!injected_headers.contains_key("x-loadtesting-key"));

    // Likewise, a client key that an earlier hook changed no longer has the
    // same authenticated value and must fail closed.
    let mut changed_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    changed_ctx
        .headers
        .insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let mut changed_headers = HashMap::from([(
        "x-loadtesting-key".to_string(),
        "changed-load-key-0123456789abcdef!".to_string(),
    )]);
    let changed_result = plugin
        .before_proxy(&mut changed_ctx, &mut changed_headers)
        .await;
    assert!(matches!(changed_result, PluginResult::Continue));
    assert!(!plugin.is_running());
    assert!(!changed_headers.contains_key("x-loadtesting-key"));
}

#[tokio::test]
async fn test_matching_paths_strip_trigger_before_continue_or_ack() {
    // Already-running path: first trigger starts a cohort; second matching
    // trigger must still strip the secret before Continue.
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": 9,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(!headers.contains_key("x-loadtesting-key"));
    assert!(plugin.is_running());

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx2.matched_proxy = Some(matched_proxy());
    let mut headers2 = HashMap::new();
    headers2.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let result2 = run_before_proxy(&plugin, &mut ctx2, &mut headers2).await;
    assert!(matches!(result2, PluginResult::Continue));
    assert!(
        !headers2.contains_key("x-loadtesting-key"),
        "already-running matching path must still redact the trigger secret"
    );
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_strips_trigger_key_from_original_request() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("x-forwarded-for".to_string(), "203.0.113.9".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("x-loadtesting-key"));
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_fanout_control_request_terminates_before_backend() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("x-loadtesting-fanout".to_string(), "1".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 204),
        other => panic!("expected fanout ack reject, got {other:?}"),
    }
    assert!(!headers.contains_key("x-loadtesting-key"));
    assert!(!headers.contains_key("x-loadtesting-fanout"));
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_ingress_fanout_marker_cannot_be_removed_to_reenable_fanout() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    ctx.headers
        .insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    ctx.headers
        .insert("x-loadtesting-fanout".to_string(), "1".to_string());

    // Model an earlier transformer removing only the one-hop marker from the
    // effective map. Ingress provenance must still force the terminal 204 ack.
    let mut headers = HashMap::from([("x-loadtesting-key".to_string(), VALID_KEY.to_string())]);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 204),
        other => panic!("expected fanout ack reject, got {other:?}"),
    }
    assert!(!headers.contains_key("x-loadtesting-key"));
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_connection_refusal_is_not_reported_as_completed_throughput() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 2,
            "duration_seconds": 1,
            "gateway_port": 9,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let result = wait_for_result(&plugin).await;
    assert!(result.attempted_requests > 0);
    assert_eq!(result.responses_completed, 0);
    assert!(result.transport_errors > 0);
    assert_eq!(result.completed_requests_per_second(), 0.0);
    assert!(matches!(
        result.outcome,
        RunOutcome::Failed | RunOutcome::Degraded | RunOutcome::Cancelled
    ));
}

#[tokio::test]
async fn test_request_timeouts_are_distinct_from_transport_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept stalled request");
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": port,
            "request_timeout_ms": 100
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/timeout".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let result = wait_for_result(&plugin).await;
    assert!(result.request_timeouts > 0, "got: {result:?}");
    assert_eq!(result.responses_completed, 0);
    assert_eq!(result.completed_requests_per_second(), 0.0);
    assert_eq!(result.outcome, RunOutcome::Failed);
}

#[tokio::test]
async fn test_non_success_status_is_counted_and_degrades_a_completed_run() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept error response");
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        let _ = socket
            .write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
    });

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": port,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/unavailable".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let result = wait_for_result(&plugin).await;
    assert!(result.status_5xx >= 1, "got: {result:?}");
    assert!(result.responses_completed >= 1, "got: {result:?}");
    assert_eq!(result.outcome, RunOutcome::Degraded);
}

#[tokio::test]
async fn test_truncated_chunk_stream_is_a_body_error_not_a_completed_response() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept broken response");
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        let _ = socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nabc",
            )
            .await;
    });

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": port,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/broken-body".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let result = wait_for_result(&plugin).await;
    assert!(result.responses_received >= 1, "got: {result:?}");
    assert!(result.response_body_errors >= 1, "got: {result:?}");
    assert_eq!(result.responses_completed, 0);
    assert_eq!(result.outcome, RunOutcome::Failed);
}

#[tokio::test]
async fn test_generated_request_fidelity_and_header_sanitization() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let capture = tokio::spawn(capture_one_http_request(listener));

    let body = Bytes::from_static(&[0x7b, 0xff, 0x7d]); // non-UTF-8 JSON-ish bytes
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": port,
            "request_timeout_ms": 1000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/orders".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    ctx.set_raw_query_string("tag=red&tag=blue&q=a+b&path=%2Froot&flag&empty=".to_string());
    ctx.request_body_bytes = Some(body.clone());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );
    headers.insert("content-length".to_string(), "999".to_string()); // stale framing
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert("x-forwarded-for".to_string(), "198.51.100.7".to_string());
    headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    headers.insert("x-forwarded-host".to_string(), "evil.example".to_string());
    headers.insert(
        "connection".to_string(),
        "x-sensitive, keep-alive".to_string(),
    );
    headers.insert("x-sensitive".to_string(), "should-not-forward".to_string());
    headers.insert("x-custom".to_string(), "keep-me".to_string());
    headers.insert("host".to_string(), "gateway.example".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("x-loadtesting-key"));

    let raw = capture.await.expect("capture task");
    let (request_line, req_headers, req_body) = parse_captured_request(&raw);

    assert_eq!(
        request_line,
        "DELETE /orders?tag=red&tag=blue&q=a+b&path=%2Froot&flag&empty= HTTP/1.1"
    );
    assert_eq!(req_body, body.as_ref());
    assert_eq!(
        req_headers.get("content-length").map(String::as_str),
        Some("3"),
        "reqwest must derive Content-Length from the exact body bytes"
    );
    assert!(!req_headers.contains_key("x-loadtesting-key"));
    assert!(!req_headers.contains_key("x-loadtesting-fanout"));
    assert!(!req_headers.contains_key("x-forwarded-for"));
    assert!(!req_headers.contains_key("x-forwarded-proto"));
    assert!(!req_headers.contains_key("x-forwarded-host"));
    assert!(!req_headers.contains_key("connection"));
    assert!(!req_headers.contains_key("x-sensitive"));
    assert!(!req_headers.contains_key("transfer-encoding"));
    assert_eq!(
        req_headers.get("x-custom").map(String::as_str),
        Some("keep-me")
    );
    assert_eq!(
        req_headers.get("host").map(String::as_str),
        Some("gateway.example"),
        "synthetic requests must preserve the original Host for routing"
    );

    let run = wait_for_result(&plugin).await;
    assert!(run.responses_completed > 0);
    assert!(run.status_2xx > 0);
    assert!(matches!(
        run.outcome,
        RunOutcome::Success | RunOutcome::Degraded
    ));
}

#[tokio::test]
async fn test_empty_request_body_replays_with_consistent_framing() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let capture = tokio::spawn(capture_one_http_request(listener));
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": port,
            "request_timeout_ms": 500
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/empty".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    ctx.request_body_bytes = Some(Bytes::new());
    let mut headers = HashMap::from([
        ("x-loadtesting-key".to_string(), VALID_KEY.to_string()),
        ("content-length".to_string(), "0".to_string()),
    ]);

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let raw = capture.await.expect("capture task");
    let (request_line, request_headers, request_body) = parse_captured_request(&raw);
    assert_eq!(request_line, "POST /empty HTTP/1.1");
    assert!(request_body.is_empty());
    assert!(
        request_headers
            .get("content-length")
            .is_none_or(|value| value == "0"),
        "empty replay advertised nonzero framing: {request_headers:?}"
    );
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_fanout_request_replays_body_query_and_sanitized_headers_on_wire() {
    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = local_listener.local_addr().unwrap().port();
    let remote_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_port = remote_listener.local_addr().unwrap().port();
    let local_capture = tokio::spawn(capture_one_http_request(local_listener));
    let remote_capture = tokio::spawn(capture_one_http_request(remote_listener));

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": local_port,
            "gateway_addresses": [format!("http://127.0.0.1:{remote_port}")],
            "request_timeout_ms": 1000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let body = Bytes::from_static(&[0x00, 0xff, 0x41, 0x42]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/fanout".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    ctx.set_raw_query_string("raw=a+b&encoded=%2Froot&flag".to_string());
    ctx.request_body_bytes = Some(body.clone());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("content-length".to_string(), "999".to_string());
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert("x-forwarded-for".to_string(), "198.51.100.7".to_string());
    headers.insert("connection".to_string(), "x-private".to_string());
    headers.insert("x-private".to_string(), "must-strip".to_string());
    headers.insert("x-keep".to_string(), "present".to_string());
    headers.insert("host".to_string(), "gateway.example".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("x-loadtesting-key"));

    let remote_raw = tokio::time::timeout(Duration::from_secs(3), remote_capture)
        .await
        .expect("fan-out request timeout")
        .expect("fan-out capture task");
    let (request_line, fanout_headers, fanout_body) = parse_captured_request(&remote_raw);
    assert_eq!(
        request_line,
        "DELETE /fanout?raw=a+b&encoded=%2Froot&flag HTTP/1.1"
    );
    assert_eq!(fanout_body, body.as_ref());
    assert_eq!(
        fanout_headers.get("x-loadtesting-key").map(String::as_str),
        Some(VALID_KEY)
    );
    assert_eq!(
        fanout_headers
            .get("x-loadtesting-fanout")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        fanout_headers.get("content-length").map(String::as_str),
        Some("4")
    );
    assert_eq!(
        fanout_headers.get("host").map(String::as_str),
        Some("gateway.example")
    );
    assert_eq!(
        fanout_headers.get("x-keep").map(String::as_str),
        Some("present")
    );
    for stripped in [
        "connection",
        "x-private",
        "transfer-encoding",
        "x-forwarded-for",
    ] {
        assert!(
            !fanout_headers.contains_key(stripped),
            "fan-out leaked stripped header {stripped}: {fanout_headers:?}"
        );
    }

    let _ = tokio::time::timeout(Duration::from_secs(3), local_capture)
        .await
        .expect("local synthetic request timeout")
        .expect("local capture task");
    let run = wait_for_result(&plugin).await;
    assert!(run.attempted_requests > 0);
}

#[tokio::test]
async fn test_extension_method_body_replay_and_invalid_method_accounting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let capture = tokio::spawn(capture_one_http_request(listener));

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": port,
            "request_timeout_ms": 1000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let body = Bytes::from_static(b"{\"sku\":\"A-123\"}");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "PURGE".to_string(),
        "/cache".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    ctx.request_body_bytes = Some(body.clone());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let raw = capture.await.expect("capture task");
    let (request_line, _, req_body) = parse_captured_request(&raw);
    assert!(
        request_line.starts_with("PURGE /cache HTTP/1.1"),
        "extension method must not be rewritten to GET: {request_line}"
    );
    assert_eq!(req_body, body.as_ref());
    wait_until_idle(&plugin).await;

    // Invalid method bytes must not panic; they account as transport errors.
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "BAD METHOD".to_string(),
        "/x".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let run = wait_for_result(&plugin).await;
    assert!(run.attempted_requests > 0);
    assert_eq!(run.responses_completed, 0);
    assert!(run.transport_errors > 0);
}

#[tokio::test]
async fn test_exactly_at_cap_response_is_completed_not_truncated() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = vec![b'x'; 16];
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.write_all(&body).await;
    });

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": port,
            "request_timeout_ms": 1000,
            "max_response_body_bytes": 16
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/exact".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let run = wait_for_result(&plugin).await;
    assert!(
        run.responses_completed >= 1,
        "exact-at-cap plus EOF must complete: {run:?}"
    );
    assert_eq!(run.responses_truncated, 0, "exact-at-cap must not truncate");
}

#[tokio::test]
async fn test_beyond_cap_response_is_truncated() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = vec![b'y'; 32];
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.write_all(&body).await;
    });

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": port,
            "request_timeout_ms": 1000,
            "max_response_body_bytes": 16
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/over".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    let run = wait_for_result(&plugin).await;
    assert!(
        run.responses_truncated >= 1,
        "bytes beyond the cap must truncate: {run:?}"
    );
    assert_eq!(run.responses_completed, 0);
}

#[tokio::test]
async fn test_last_owner_removal_cancels_active_cohort() {
    let (port, request_started, client_closed) = spawn_stalled_request_observer().await;

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 30,
            "gateway_port": port,
            "request_timeout_ms": 5000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/slow".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(plugin.is_running());

    tokio::time::timeout(Duration::from_secs(2), request_started)
        .await
        .expect("worker must start before owner drop")
        .expect("stalled observer must report request start");

    drop(plugin);

    tokio::time::timeout(Duration::from_secs(3), client_closed)
        .await
        .expect("last-owner cancellation must close the stalled client before the 30s deadline")
        .expect("stalled observer must report client closure");
}

#[tokio::test]
async fn test_triggers_when_key_matches_and_blocks_concurrent_trigger() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": 9,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.is_running());

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx2.matched_proxy = Some(matched_proxy());
    let mut headers2 = HashMap::new();
    headers2.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let result2 = run_before_proxy(&plugin, &mut ctx2, &mut headers2).await;
    assert!(matches!(result2, PluginResult::Continue));
    wait_until_idle(&plugin).await;
}

#[test]
fn test_gateway_address_query_fragment_still_rejected() {
    for address in [
        "https://node2:8443?x=1",
        "https://node2:8443#frag",
        "ftp://node2:8443",
    ] {
        let config = json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 8000,
            "gateway_addresses": [address]
        });
        assert!(
            LoadTesting::new(&config, PluginHttpClient::default()).is_err(),
            "address {address} should fail"
        );
    }
}

#[tokio::test]
async fn test_synthetic_request_strips_trailer_internal_markers_and_hostile_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let capture = tokio::spawn(capture_one_http_request(listener));

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": port,
            "request_timeout_ms": 1000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/sanitize".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert(
        "Connection".to_string(),
        "X-Hop , , bad:token, Keep-Alive".to_string(),
    );
    headers.insert("X-Hop".to_string(), "per-connection".to_string());
    headers.insert("Trailer".to_string(), "X-Foo".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("proxy-authorization".to_string(), "Basic leak".to_string());
    headers.insert("te".to_string(), "trailers".to_string());
    headers.insert("x-custom".to_string(), "keep-me".to_string());
    headers.insert("host".to_string(), "gateway.example".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let raw = capture.await.expect("capture task");
    let (_, req_headers, _) = parse_captured_request(&raw);
    for stripped in [
        "connection",
        "x-hop",
        "trailer",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
        "proxy-authorization",
        "te",
        "x-loadtesting-key",
    ] {
        assert!(
            !req_headers.contains_key(stripped),
            "synthetic request leaked `{stripped}`: {req_headers:?}"
        );
    }
    assert_eq!(
        req_headers.get("x-custom").map(String::as_str),
        Some("keep-me")
    );
    assert_eq!(
        req_headers.get("host").map(String::as_str),
        Some("gateway.example")
    );
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_synthetic_and_fanout_h2_h3_parity_strips_protocol_invalid_fields() {
    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = local_listener.local_addr().unwrap().port();
    let remote_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_port = remote_listener.local_addr().unwrap().port();
    let local_capture = tokio::spawn(capture_one_http_request(local_listener));
    let remote_capture = tokio::spawn(capture_one_http_request(remote_listener));

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": local_port,
            "gateway_addresses": [format!("http://127.0.0.1:{remote_port}")],
            "request_timeout_ms": 1000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/h2h3".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    // H2/H3 inbound: no Connection, but Trailer + internal markers present.
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("trailer".to_string(), "grpc-status".to_string());
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert("content-length".to_string(), "999".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "br".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("x-forwarded-host".to_string(), "evil.example".to_string());
    headers.insert("x-keep".to_string(), "present".to_string());
    headers.insert("host".to_string(), "gateway.example".to_string());

    let result = run_before_proxy(&plugin, &mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let remote_raw = tokio::time::timeout(Duration::from_secs(3), remote_capture)
        .await
        .expect("fan-out request timeout")
        .expect("fan-out capture task");
    let (_, fanout_headers, _) = parse_captured_request(&remote_raw);
    for stripped in [
        "trailer",
        "transfer-encoding",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
        "x-forwarded-host",
    ] {
        assert!(
            !fanout_headers.contains_key(stripped),
            "fan-out H2/H3 parity leaked `{stripped}`: {fanout_headers:?}"
        );
    }
    assert_eq!(
        fanout_headers.get("x-keep").map(String::as_str),
        Some("present")
    );

    let local_raw = tokio::time::timeout(Duration::from_secs(3), local_capture)
        .await
        .expect("local synthetic request timeout")
        .expect("local capture task");
    let (_, local_headers, _) = parse_captured_request(&local_raw);
    for stripped in [
        "trailer",
        "transfer-encoding",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
        "x-forwarded-host",
        "x-loadtesting-key",
    ] {
        assert!(
            !local_headers.contains_key(stripped),
            "synthetic H2/H3 parity leaked `{stripped}`: {local_headers:?}"
        );
    }
    wait_until_idle(&plugin).await;
}
