use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_edge::config::PoolConfig;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, opa::Opa,
    priority, validate_plugin_config,
};
use serde_json::{Value, json};
use tracing_subscriber::fmt::MakeWriter;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_consumer, create_test_proxy,
};

const POLICY_PATH: &str = "ferrum/authz/allow";
const DECISION_PATH: &str = "/v1/data/ferrum/authz/allow";

#[derive(Clone, Default)]
struct SharedWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct SharedGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

fn default_client() -> PluginHttpClient {
    PluginHttpClient::from_pool_config(&PoolConfig::default())
}

fn base_config(opa_host: &str) -> Value {
    json!({
        "opa_host": opa_host,
        "policy_path": POLICY_PATH,
    })
}

fn plugin(server: &MockServer, extra: Value) -> Opa {
    let mut config = base_config(&server.uri());
    if let Some(config_obj) = config.as_object_mut()
        && let Some(extra_obj) = extra.as_object()
    {
        for (key, value) in extra_obj {
            config_obj.insert(key.clone(), value.clone());
        }
    }
    Opa::new(&config, default_client()).expect("valid opa config")
}

fn make_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.set_raw_query_string("a=1&b=two".to_string());
    ctx.headers
        .insert("x-request-id".to_string(), "req-123".to_string());
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.identified_consumer = Some(Arc::new(create_test_consumer()));
    ctx
}

async fn mount_opa(server: &MockServer, status: u16, body: Value) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_opa_raw(server: &MockServer, status: u16, body: &'static str) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

async fn mount_opa_with_delay(server: &MockServer, delay: Duration) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"result": true}))
                .set_delay(delay),
        )
        .mount(server)
        .await;
}

async fn received_opa_payload(server: &MockServer) -> Value {
    for _ in 0..20 {
        if let Some(requests) = server.received_requests().await
            && let Some(request) = requests.first()
        {
            return request.body_json().expect("OPA request should be JSON");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("OPA mock did not receive a request");
}

#[test]
fn opa_validates_config() {
    let invalid_configs = [
        json!({"policy_path": POLICY_PATH}),
        json!({"opa_host": "file:///tmp/opa", "policy_path": POLICY_PATH}),
        json!({"opa_host": "http://user:pass@localhost:8181", "policy_path": POLICY_PATH}),
        json!({"opa_host": "http://localhost:8181", "policy_path": ""}),
        json!({"opa_host": "http://localhost:8181", "policy_path": "/ferrum/authz"}),
        json!({"opa_host": "http://localhost:8181", "policy_path": "ferrum/../authz"}),
        json!({"opa_host": "http://localhost:8181", "policy_path": "ferrum%2F..%2Fauthz"}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "deny_status": 200}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "fail_closed_status": 200}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "headers": {"Invalid Header": "value"}}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "headers": {"Content-Type": "text/plain"}}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "fail_open": true, "fail_closed": false}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "max_response_bytes": 0}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "max_body_bytes": 0}),
        json!({"opa_host": "http://localhost:8181", "policy_path": POLICY_PATH, "redact_query_keys": [""]}),
    ];

    for config in invalid_configs {
        assert!(
            Opa::new(&config, default_client()).is_err(),
            "config should be rejected: {config}"
        );
    }

    assert!(
        Opa::new(
            &json!({
                "opa_host": "http://localhost:8181",
                "policy_path": POLICY_PATH,
                "fail_closed": false
            }),
            default_client(),
        )
        .is_ok()
    );

    let error = match Opa::new(&json!("opa secret"), default_client()) {
        Ok(_) => panic!("non-object OPA config should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error, "opa: config must be a JSON object");
    assert!(!error.contains("opa secret"));
}

#[test]
fn opa_plugin_contract() {
    let plugin = Opa::new(
        &json!({
            "opa_host": "http://localhost:8181",
            "policy_path": POLICY_PATH,
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.name(), "opa");
    assert_eq!(plugin.priority(), priority::OPA);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());

    let body_plugin = Opa::new(
        &json!({
            "opa_host": "http://localhost:8181",
            "policy_path": POLICY_PATH,
            "include_body": true,
        }),
        default_client(),
    )
    .unwrap();
    assert!(body_plugin.requires_request_body_buffering());
    assert!(!body_plugin.requires_request_body_before_authenticate());
    assert!(body_plugin.requires_request_body_before_authorize());
    assert!(body_plugin.needs_request_body_bytes());
    assert!(!body_plugin.needs_request_body_text());
    assert_eq!(body_plugin.request_body_buffer_limit(), Some(1024 * 1024));

    let bounded_body_plugin = Opa::new(
        &json!({
            "opa_host": "http://localhost:8181",
            "policy_path": POLICY_PATH,
            "include_body": true,
            "max_body_bytes": 4096,
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(bounded_body_plugin.request_body_buffer_limit(), Some(4096));
}

#[test]
fn opa_accepts_and_clamps_timeout_above_runtime_cap() {
    let config = json!({
        "opa_host": "http://localhost:8181",
        "policy_path": POLICY_PATH,
        "timeout_ms": 45000,
    });

    assert!(Opa::new(&config, default_client()).is_ok());
    assert!(validate_plugin_config("opa", &config).is_ok());
}

#[test]
fn opa_rejects_unknown_security_sensitive_config_keys() {
    for typo in [
        "decision_pointr",
        "fail_opne",
        "include_heders",
        "include_bdy",
        "redact_heders",
        "redact_query_key",
        "query_ambiguity_polcy",
    ] {
        let mut config = base_config("http://localhost:8181");
        config
            .as_object_mut()
            .expect("base config is an object")
            .insert(typo.to_string(), json!(true));
        let error = match Opa::new(&config, default_client()) {
            Ok(_) => panic!("unknown OPA key {typo} must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("unknown config key"), "got: {error}");
        assert!(error.contains(typo), "got: {error}");
    }
}

#[tokio::test]
async fn opa_allows_boolean_true_result() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_rejects_duplicate_query_parameter_keys() {
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=delete&action=view".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
    let requests = server
        .received_requests()
        .await
        .expect("wiremock request history should be available");
    assert!(
        requests.is_empty(),
        "OPA should not be called when duplicate query keys are present"
    );
}

#[tokio::test]
async fn opa_rejects_identical_value_duplicate_query_keys() {
    // A repeated name is ambiguous even when the values agree: an
    // all-values backend receives `["1","1"]` and a strict backend rejects
    // outright, so `"1"` is not provably the value the backend executes.
    // Matches the `serverless_function` duplicate contract exactly.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("a=1&a=1".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
}

#[tokio::test]
async fn opa_rejects_literal_plus_query_value() {
    // GHSA-gr4p-3qw3-87r5 reproduction: OPA would see `delete+record` while a
    // form-decoding backend executes `delete record`.
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=delete+record".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
    let requests = server
        .received_requests()
        .await
        .expect("wiremock request history should be available");
    assert!(
        requests.is_empty(),
        "OPA must not be called with a literal-plus query"
    );
}

#[tokio::test]
async fn opa_rejects_literal_plus_query_name() {
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("a+b=1".to_string());

    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
}

#[tokio::test]
async fn opa_rejects_malformed_percent_encoding() {
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=%zz".to_string());

    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
}

#[tokio::test]
async fn opa_accepts_percent_encoded_space_and_plus() {
    // `%20` and `%2B` are unambiguous: every decoder agrees they are a space
    // and a `+`. Only a literal `+` byte is ambiguous, so the inverse policy
    // the advisory describes must still be expressible.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=delete%20record&sign=a%2Bb".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["query"]["action"], json!("delete record"));
    assert_eq!(payload["input"]["query"]["sign"], json!("a+b"));
    assert_eq!(payload["input"]["query_ambiguity"], json!([]));
}

#[tokio::test]
async fn opa_query_pairs_preserve_order_bare_and_empty_values() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    // `flag` (bare) and `empty=` (explicit empty) both decode to an empty
    // value; only the `bare` bit keeps them distinguishable.
    ctx.set_raw_query_string("z=last&flag&empty=".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(
        payload["input"]["query_pairs"],
        json!([
            {"name": "z", "value": "last", "bare": false},
            {"name": "flag", "value": "", "bare": true},
            {"name": "empty", "value": "", "bare": false},
        ]),
        "wire order and the bare/empty distinction must survive to policy"
    );
}

#[tokio::test]
async fn opa_delegate_mode_omits_flat_query_and_reports_ambiguity() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"query_ambiguity_policy": "delegate"}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("scope=denied&scope=allowed".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert!(
        payload["input"].get("query").is_none(),
        "the flat map must be withheld for an ambiguous query so a rule \
         written against it cannot authorize a value the backend skips"
    );
    assert_eq!(
        payload["input"]["query_ambiguity"],
        json!(["duplicate_name"])
    );
    assert_eq!(
        payload["input"]["query_pairs"],
        json!([
            {"name": "scope", "value": "denied", "bare": false},
            {"name": "scope", "value": "allowed", "bare": false},
        ]),
        "delegate mode must expose every occurrence, not just the last"
    );
}

#[tokio::test]
async fn opa_delegate_mode_still_redacts_query_credentials() {
    // Opting into `delegate` must never widen what OPA is told. The ordered
    // occurrence view is redacted exactly like the flat map, so a duplicated
    // credential reaches the policy only as a classification token.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"query_ambiguity_policy": "delegate"}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("api_key=first-secret&api_key=second-secret&scope=read".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert!(payload["input"].get("query").is_none());
    assert_eq!(
        payload["input"]["query_ambiguity"],
        json!(["duplicate_name"])
    );
    assert_eq!(
        payload["input"]["query_pairs"],
        json!([{"name": "scope", "value": "read", "bare": false}]),
        "credential occurrences must be redacted from the ordered view too"
    );
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(!serialized.contains("first-secret"));
    assert!(!serialized.contains("second-secret"));
}

#[test]
fn opa_rejects_unknown_query_ambiguity_policy() {
    let mut config = base_config("http://localhost:8181");
    config
        .as_object_mut()
        .expect("base config is an object")
        .insert("query_ambiguity_policy".to_string(), json!("allow"));

    let error = match Opa::new(&config, default_client()) {
        Ok(_) => panic!("unknown policy must be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("query_ambiguity_policy"), "got: {error}");
    assert!(validate_plugin_config("opa", &config).is_err());
}

#[tokio::test]
async fn opa_rejects_percent_encoded_key_collision() {
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("a%20b=1&a%20b=2".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
}

#[tokio::test]
async fn opa_rejects_conflicting_keys_without_equals() {
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("flag&flag=1".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
}

#[tokio::test]
async fn opa_rejects_conflicting_duplicate_with_empty_pairs() {
    let server = MockServer::start().await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("a=1&&a=2".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
}

#[tokio::test]
async fn opa_allows_duplicate_query_keys_when_rejection_disabled() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"query_ambiguity_policy": "delegate"}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=delete&action=view".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_allows_duplicate_query_keys_when_include_query_disabled() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"include_query": false}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=delete&action=view".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_allows_nested_pointer_result() {
    let server = MockServer::start().await;
    mount_opa(
        &server,
        200,
        json!({"result": {"allow": true, "obligations": []}}),
    )
    .await;
    let plugin = plugin(
        &server,
        json!({
            "decision_pointer": ["result", "allow"]
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_allows_empty_decision_pointer_result() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!(true)).await;
    let plugin = plugin(
        &server,
        json!({
            "decision_pointer": []
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_allows_object_with_allow_true() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": {"allow": true}})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_nested_false_decision_cannot_fall_back_to_enclosing_allow_true() {
    let server = MockServer::start().await;
    mount_opa(
        &server,
        200,
        json!({"result": {"allow": true, "decision": false}}),
    )
    .await;
    let plugin = plugin(&server, json!({"decision_pointer": ["result", "decision"]}));

    let mut ctx = make_ctx();
    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
}

#[tokio::test]
async fn opa_denies_false_result() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": false})).await;
    let plugin = plugin(
        &server,
        json!({
            "deny_body": "{\"error\":\"denied\"}"
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "{\"error\":\"denied\"}");
        }
        other => panic!("expected reject, got {other:?}"),
    }
}

#[tokio::test]
async fn opa_denies_when_decision_pointer_is_missing() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"other": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(403));
}

#[tokio::test]
async fn opa_honors_custom_deny_response() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": false})).await;
    let plugin = plugin(
        &server,
        json!({
            "deny_status": 451,
            "deny_body": "blocked by policy",
            "deny_headers": {
                "x-policy": "opa"
            }
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 451);
            assert_eq!(body, "blocked by policy");
            assert_eq!(headers.get("x-policy").map(String::as_str), Some("opa"));
        }
        other => panic!("expected reject, got {other:?}"),
    }
}

#[tokio::test]
async fn opa_timeout_fails_closed_by_default() {
    let server = MockServer::start().await;
    mount_opa_with_delay(&server, Duration::from_millis(200)).await;
    let plugin = plugin(
        &server,
        json!({
            "timeout_ms": 20
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(503));
}

#[tokio::test]
async fn opa_honors_custom_fail_closed_response() {
    let server = MockServer::start().await;
    mount_opa(&server, 500, json!({"error": "unavailable"})).await;
    let plugin = plugin(
        &server,
        json!({
            "deny_status": 451,
            "deny_body": "blocked by policy",
            "fail_closed_status": 503,
            "fail_closed_body": "authorization service unavailable",
            "fail_closed_headers": {
                "Retry-After": "2"
            }
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(body, "authorization service unavailable");
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("2"));
        }
        other => panic!("expected reject, got {other:?}"),
    }
}

#[tokio::test]
async fn opa_timeout_can_fail_open() {
    let server = MockServer::start().await;
    mount_opa_with_delay(&server, Duration::from_millis(200)).await;
    let plugin = plugin(
        &server,
        json!({
            "timeout_ms": 20,
            "fail_open": true
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_timeout_can_fail_open_with_fail_closed_false() {
    let server = MockServer::start().await;
    mount_opa_with_delay(&server, Duration::from_millis(200)).await;
    let plugin = plugin(
        &server,
        json!({
            "timeout_ms": 20,
            "fail_closed": false
        }),
    );

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_continue(result);
}

#[tokio::test]
async fn opa_non_success_fails_closed() {
    let server = MockServer::start().await;
    mount_opa(&server, 500, json!({"error": "unavailable"})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(503));
}

#[tokio::test]
async fn opa_malformed_json_fails_closed() {
    let server = MockServer::start().await;
    mount_opa_raw(&server, 200, "{not-json").await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    let result = plugin.authorize(&mut ctx).await;

    assert_reject(result, Some(503));
}

#[tokio::test]
async fn opa_accepts_response_exactly_at_byte_limit() {
    let body = r#"{"result":true}"#;
    let server = MockServer::start().await;
    mount_opa_raw(&server, 200, body).await;
    let plugin = plugin(&server, json!({"max_response_bytes": body.len()}));

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);
}

#[tokio::test]
async fn opa_oversized_declared_response_fails_closed() {
    let server = MockServer::start().await;
    mount_opa_raw(
        &server,
        200,
        r#"{"result":true,"padding":"policy-service-controlled"}"#,
    )
    .await;
    let plugin = plugin(&server, json!({"max_response_bytes": 16}));

    let mut ctx = make_ctx();
    assert_reject(plugin.authorize(&mut ctx).await, Some(503));
}

#[tokio::test]
async fn opa_oversized_streamed_response_honors_fail_open() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let read = socket.read(&mut buffer).await.unwrap();
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for chunk in [
            b"{\"result\":false,".as_slice(),
            b"\"padding\":\"policy-service-controlled\"}".as_slice(),
        ] {
            let header = format!("{:x}\r\n", chunk.len());
            if socket.write_all(header.as_bytes()).await.is_err()
                || socket.write_all(chunk).await.is_err()
                || socket.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });

    let mut config = base_config(&format!("http://{addr}"));
    config
        .as_object_mut()
        .expect("base config is an object")
        .extend([
            ("max_response_bytes".to_string(), json!(16)),
            ("fail_open".to_string(), json!(true)),
        ]);
    let plugin = Opa::new(&config, default_client()).unwrap();

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);
    server.await.unwrap();
}

#[tokio::test]
async fn opa_forwards_configured_headers_to_opa() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({
            "headers": {
                "Authorization": "Bearer opa-token"
            }
        }),
    );

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);

    let requests = server.received_requests().await.unwrap();
    let auth = requests[0]
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    assert_eq!(auth, Some("Bearer opa-token"));
}

#[tokio::test]
async fn opa_redacts_sensitive_request_headers_by_default() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    ctx.headers.clear();
    ctx.headers.insert(
        "Authorization".to_string(),
        "Bearer client-token".to_string(),
    );
    ctx.headers
        .insert("Cookie".to_string(), "session=secret".to_string());
    ctx.headers.insert(
        "X-Loadtesting-Key".to_string(),
        "load-test-secret-0123456789abcdef".to_string(),
    );
    ctx.headers
        .insert("X-Loadtesting-Fanout".to_string(), "1".to_string());
    ctx.headers
        .insert("X-Request-ID".to_string(), "req-456".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let headers = &payload["input"]["headers"];
    assert!(headers.get("authorization").is_none());
    assert!(headers.get("cookie").is_none());
    assert!(headers.get("x-loadtesting-key").is_none());
    assert!(headers.get("x-loadtesting-fanout").is_none());
    assert_eq!(headers["x-request-id"], "req-456");
}

#[tokio::test]
async fn opa_custom_redact_headers_are_additive() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({
            "redact_headers": ["x-tenant"]
        }),
    );

    let mut ctx = make_ctx();
    ctx.headers.clear();
    ctx.headers.insert(
        "Authorization".to_string(),
        "Bearer client-token".to_string(),
    );
    ctx.headers
        .insert("X-Tenant".to_string(), "tenant-secret".to_string());
    ctx.headers
        .insert("X-Request-ID".to_string(), "req-456".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let headers = &payload["input"]["headers"];
    assert!(headers.get("authorization").is_none());
    assert!(headers.get("x-tenant").is_none());
    assert_eq!(headers["x-request-id"], "req-456");
}

#[tokio::test]
async fn opa_redacts_default_and_authenticated_query_credentials() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    ctx.set_raw_query_string(
        "action=read&api_key=default-secret&custom_credential=verified-secret&oauth_custom=oauth-secret"
            .to_string(),
    );
    ctx.metadata.insert(
        "auth.query_credential_param.custom_credential".to_string(),
        "true".to_string(),
    );
    ctx.metadata.insert(
        "auth.strip_query_param.oauth_custom".to_string(),
        "true".to_string(),
    );

    assert_continue(plugin.authorize(&mut ctx).await);
    let payload = received_opa_payload(&server).await;
    let query = &payload["input"]["query"];
    assert_eq!(query["action"], "read");
    assert!(query.get("api_key").is_none());
    assert!(query.get("custom_credential").is_none());
    assert!(query.get("oauth_custom").is_none());
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(!serialized.contains("default-secret"));
    assert!(!serialized.contains("verified-secret"));
    assert!(!serialized.contains("oauth-secret"));
}

#[tokio::test]
async fn opa_query_credential_opt_in_preserves_explicit_redactions() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({
            "include_query_credentials": true,
            "redact_query_keys": ["Session_ID"],
        }),
    );

    let mut ctx = make_ctx();
    ctx.set_raw_query_string(
        "api_key=explicitly-forwarded&custom_credential=also-forwarded&session_id=redacted"
            .to_string(),
    );
    ctx.metadata.insert(
        "auth.query_credential_param.custom_credential".to_string(),
        "true".to_string(),
    );

    assert_continue(plugin.authorize(&mut ctx).await);
    let payload = received_opa_payload(&server).await;
    let query = &payload["input"]["query"];
    assert_eq!(query["api_key"], "explicitly-forwarded");
    assert_eq!(query["custom_credential"], "also-forwarded");
    assert!(query.get("session_id").is_none());
}

#[tokio::test]
async fn opa_body_is_forwarded_only_when_configured() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin_without_body = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        "stale duplicate that must not be forwarded".to_string(),
    );
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(br#"{"hello":"world"}"#));
    assert_continue(plugin_without_body.authorize(&mut ctx).await);

    let first_payload = received_opa_payload(&server).await;
    assert!(first_payload["input"].get("body").is_none());
    assert!(first_payload["input"].get("body_base64").is_none());

    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin_with_body = plugin(&server, json!({"include_body": true}));

    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        "stale duplicate that must not be forwarded".to_string(),
    );
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(br#"{"hello":"world"}"#));
    assert_continue(plugin_with_body.authorize(&mut ctx).await);

    let second_payload = received_opa_payload(&server).await;
    assert_eq!(second_payload["input"]["body"], "{\"hello\":\"world\"}");
    assert!(second_payload["input"].get("body_base64").is_none());

    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin_with_raw_body = plugin(&server, json!({"include_body": true}));

    let mut ctx = make_ctx();
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(&[0xff, 0x00]));
    assert_continue(plugin_with_raw_body.authorize(&mut ctx).await);

    let third_payload = received_opa_payload(&server).await;
    assert!(third_payload["input"].get("body").is_none());
    assert_eq!(third_payload["input"]["body_base64"], "/wA=");
}

#[tokio::test(flavor = "current_thread")]
async fn opa_error_logs_do_not_include_request_fields() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();

    let guard = tracing::subscriber::set_default(subscriber);
    {
        let server = MockServer::start().await;
        mount_opa_raw(
            &server,
            200,
            r#"{"result":false,"policy_response_secret":"never-log-this"}"#,
        )
        .await;
        let plugin = plugin(
            &server,
            json!({"include_body": true, "max_response_bytes": 16}),
        );

        let mut ctx = make_ctx();
        ctx.path = "/private/bearer".to_string();
        ctx.set_raw_query_string("token=Bearer%20client-token".to_string());
        ctx.headers.insert(
            "Authorization".to_string(),
            "Bearer client-token".to_string(),
        );
        ctx.metadata
            .insert("request_body".to_string(), "client body secret".to_string());
        ctx.request_body_bytes = Some(bytes::Bytes::from_static(b"client body secret"));

        assert_reject(plugin.authorize(&mut ctx).await, Some(503));
    }
    drop(guard);

    let logs = writer.contents();
    // The mock returns an oversized body, so the OPA plugin normally logs
    // `opa_response_too_large`. Under heavy parallel test load the request to
    // the local mock can instead fail transiently before reaching it, which the
    // plugin logs as `opa_call_failed` (and still rejects 503). Either way an
    // OPA error was logged and the property under test — no request fields in
    // the error log — must hold, so accept either reason rather than coupling
    // to the exact (environment-dependent) error path.
    assert!(
        logs.contains("opa_response_too_large") || logs.contains("opa_call_failed"),
        "an OPA error must be logged on a failed decision; logs={logs}"
    );
    for secret in [
        "Authorization",
        "Bearer client-token",
        "/private/bearer",
        "client body secret",
        "never-log-this",
    ] {
        assert!(
            !logs.contains(secret),
            "OPA error logs must not contain request field {secret:?}; logs={logs}"
        );
    }
}

/// `deny_headers` and `fail_closed_headers` are installed verbatim onto a client
/// `Reject`, so their names are arbitrary response-header destinations. The
/// gateway's final wire boundary owns framing and connection control, so those
/// destinations are refused at construction with the same shared
/// case-insensitive predicate `response_transformer` / `response_mock` /
/// `security_headers` use.
#[test]
fn reject_header_maps_refuse_protocol_managed_destinations() {
    for field in ["deny_headers", "fail_closed_headers"] {
        for name in [
            "connection",
            "content-length",
            "keep-alive",
            "proxy-authenticate",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            for spelling in [name.to_string(), name.to_ascii_uppercase()] {
                let mut headers = serde_json::Map::new();
                headers.insert(spelling.clone(), Value::String("x".to_string()));
                let mut config = base_config("http://127.0.0.1:8181");
                config
                    .as_object_mut()
                    .expect("object config")
                    .insert(field.to_string(), Value::Object(headers));
                // `Opa` has no `Debug`, so take the error rather than
                // `expect_err`.
                let error = Opa::new(&config, default_client())
                    .err()
                    .unwrap_or_else(|| panic!("{field}['{spelling}'] must be rejected"));
                assert!(
                    error.contains("protocol-managed") && error.contains(name),
                    "diagnostic must name the offending {field} entry: {error}"
                );
            }
        }

        // Ordinary destinations stay accepted.
        let mut headers = serde_json::Map::new();
        headers.insert("x-policy".to_string(), Value::String("opa".to_string()));
        headers.insert("Retry-After".to_string(), Value::String("30".to_string()));
        let mut config = base_config("http://127.0.0.1:8181");
        config
            .as_object_mut()
            .expect("object config")
            .insert(field.to_string(), Value::Object(headers));
        Opa::new(&config, default_client())
            .unwrap_or_else(|error| panic!("ordinary {field} names must stay allowed: {error}"));
    }
}
