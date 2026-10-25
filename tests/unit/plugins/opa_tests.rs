use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ferrum_edge::config::PoolConfig;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
    opa::Opa, priority, validate_plugin_config,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_consumer, create_test_proxy,
    read_http11_request_body,
};

const POLICY_PATH: &str = "ferrum/authz/allow";
const DECISION_PATH: &str = "/v1/data/ferrum/authz/allow";

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
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": ""}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": "/ferrum/authz"}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": "ferrum/../authz"}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": "ferrum%2F..%2Fauthz"}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "deny_status": 200}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "fail_closed_status": 200}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "headers": {"Invalid Header": "value"}}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "headers": {"Content-Type": "text/plain"}}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "fail_open": true, "fail_closed": false}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "max_response_bytes": 0}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "max_body_bytes": 0}),
        json!({"opa_host": "http://127.0.0.1:8181", "policy_path": POLICY_PATH, "redact_query_keys": [""]}),
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
                "opa_host": "http://127.0.0.1:8181",
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
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": POLICY_PATH,
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.name(), "opa");
    assert_eq!(plugin.priority(), priority::OPA);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Grpc));
    assert!(
        plugin
            .supported_protocols()
            .contains(&ProxyProtocol::WebSocket)
    );
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());

    let body_plugin = Opa::new(
        &json!({
            "opa_host": "http://127.0.0.1:8181",
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
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": POLICY_PATH,
            "include_body": true,
            "max_body_bytes": 4096,
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(bounded_body_plugin.request_body_buffer_limit(), Some(4096));
}

fn websocket_upgrade_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.headers
        .insert("connection".to_string(), "upgrade".to_string());
    ctx.headers
        .insert("upgrade".to_string(), "websocket".to_string());
    ctx.headers.insert(
        "sec-websocket-key".to_string(),
        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
    );
    ctx.headers
        .insert("sec-websocket-version".to_string(), "13".to_string());
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx
}

fn grpc_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx
}

#[tokio::test]
async fn opa_denies_websocket_upgrade_request_shape() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": false})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = websocket_upgrade_ctx("POST", "/x");
    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
}

#[tokio::test]
async fn opa_denies_native_grpc_request_shape() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": false})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = grpc_ctx("POST", "/my.Service/Method");
    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
}

#[tokio::test]
async fn opa_allows_websocket_upgrade_request_shape_when_policy_allows() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = websocket_upgrade_ctx("POST", "/x");
    assert_continue(plugin.authorize(&mut ctx).await);
}

#[tokio::test]
async fn opa_allows_native_grpc_request_shape_when_policy_allows() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = grpc_ctx("POST", "/my.Service/Method");
    assert_continue(plugin.authorize(&mut ctx).await);
}

#[test]
fn opa_accepts_and_clamps_timeout_above_runtime_cap() {
    let config = json!({
        "opa_host": "http://127.0.0.1:8181",
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
        let mut config = base_config("http://127.0.0.1:8181");
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
async fn opa_rejects_unencoded_semicolon_without_calling_opa() {
    // Issue #6579: OPA would read one `a` while a `;`-splitting backend also
    // executes `tenant=admin`.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("a=1;tenant=admin".to_string());

    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
    let requests = server
        .received_requests()
        .await
        .expect("wiremock request history should be available");
    assert!(
        requests.is_empty(),
        "OPA must not be called with an unencoded ';' in the query"
    );
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
async fn opa_delegate_mode_redacts_credentials_behind_a_semicolon() {
    // Issue #6579: `carrier=;api_key=secret` is a `carrier` pair to Ferrum but
    // an `api_key` credential to a backend that also splits on `;`. Delegate
    // mode must not hand its value to the policy service.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({"query_ambiguity_policy": "delegate", "redact_query_keys": ["tenant_secret"]}),
    );
    let mut ctx = make_ctx();
    ctx.set_raw_query_string(
        "carrier=;api_key=builtin-secret&x=;api%5Fkey=encoded-secret&y=;tenant_secret=explicit-secret&page=1"
            .to_string(),
    );

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let input = &payload["input"];
    let rendered = serde_json::to_string(&payload).unwrap();
    for secret in ["builtin-secret", "encoded-secret", "explicit-secret"] {
        assert!(!rendered.contains(secret), "{secret} leaked: {rendered}");
    }
    assert_eq!(
        input["query_pairs"],
        json!([{"name": "page", "value": "1", "bare": false}])
    );
    assert_eq!(input["query_ambiguity"], json!(["semicolon_separator"]));
}

#[tokio::test]
async fn opa_delegate_mode_redacts_sub_pairs_by_their_encoded_names() {
    // Sub-pairs are split on the still-encoded bytes, so a configured name
    // containing `=` or `;` matches its encoded spelling behind a raw `;`.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({
            "query_ambiguity_policy": "delegate",
            "redact_query_keys": ["private=key", "a;b"]
        }),
    );
    let mut ctx = make_ctx();
    ctx.set_raw_query_string(
        "carrier=;private%3Dkey=first-secret&other=;a%3Bb=second-secret&page=1".to_string(),
    );

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let rendered = serde_json::to_string(&payload).unwrap();
    assert!(!rendered.contains("first-secret"), "{rendered}");
    assert!(!rendered.contains("second-secret"), "{rendered}");
    assert_eq!(
        payload["input"]["query_pairs"],
        json!([{"name": "page", "value": "1", "bare": false}])
    );
}

#[tokio::test]
async fn opa_delegate_mode_redacts_form_decoded_semicolon_names() {
    // `;private+key=` is `private key` to a form-decoding backend, so the
    // explicit redaction must hold for it too.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({"query_ambiguity_policy": "delegate", "redact_query_keys": ["private key"]}),
    );
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("carrier=;private+key=form-secret&page=1".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let rendered = serde_json::to_string(&payload).unwrap();
    assert!(!rendered.contains("form-secret"), "{rendered}");
    assert_eq!(
        payload["input"]["query_pairs"],
        json!([{"name": "page", "value": "1", "bare": false}])
    );
}

#[tokio::test]
async fn opa_delegate_mode_redacts_an_ordinary_form_decoded_alias() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(
        &server,
        json!({"query_ambiguity_policy": "delegate", "redact_query_keys": ["private key"]}),
    );
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("private+key=alias-secret&private%2Bkey=literal&page=1".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let rendered = serde_json::to_string(&payload).unwrap();
    assert!(!rendered.contains("alias-secret"), "{rendered}");
    // `%2B` decodes to a literal `+`; `private+key` is not the redacted name.
    assert!(rendered.contains("literal"), "{rendered}");
}

#[tokio::test]
async fn opa_keeps_a_value_with_an_encoded_semicolon() {
    // `%3B` is content, not a separator: the query is unambiguous, and the
    // whole `action` value must reach the policy so a denial on it holds.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("action=delete%3Btoken%3Dx".to_string());

    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(
        payload["input"]["query"],
        json!({"action": "delete;token=x"})
    );
    assert_eq!(
        payload["input"]["query_pairs"],
        json!([{"name": "action", "value": "delete;token=x", "bare": false}])
    );
    assert_eq!(payload["input"]["query_ambiguity"], json!([]));
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
    let mut config = base_config("http://127.0.0.1:8181");
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
    let (writer, guard) = super::plugin_utils::capture_logs();
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

// ---------------------------------------------------------------------------
// External-I/O accounting through the decision body — issue #5059
// ---------------------------------------------------------------------------

/// Serve one HTTP/1.1 decision whose HEADERS are written immediately and whose
/// BODY is written `body_delay` later.
///
/// A policy service that behaves this way used to contribute almost nothing to
/// `latency_plugin_external_io_ms` and never crossed the slow-call threshold,
/// even though the authorization decision waits for the whole document.
async fn spawn_delayed_body_opa(body_delay: Duration) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        const BODY: &[u8] = br#"{"result":true}"#;

        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        if read_http11_request_body(&mut socket).await.is_none() {
            return;
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            BODY.len()
        );
        if socket.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let _ = socket.flush().await;
        tokio::time::sleep(body_delay).await;
        let _ = socket.write_all(BODY).await;
        let _ = socket.flush().await;
    });
    addr
}

#[tokio::test(flavor = "current_thread")]
async fn opa_external_io_and_slow_call_telemetry_cover_the_decision_body_wait() {
    let (writer, guard) = super::plugin_utils::capture_logs();

    let body_delay = Duration::from_millis(200);
    let addr = spawn_delayed_body_opa(body_delay).await;
    let config = json!({
        "opa_host": format!("http://{addr}"),
        "policy_path": POLICY_PATH,
        "timeout_ms": 5000,
    });
    let client = PluginHttpClient::from_pool_config_with_threshold(&PoolConfig::default(), 50);
    let plugin = Opa::new(&config, client).expect("valid opa config");

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);

    let charged = Duration::from_nanos(ctx.plugin_http_call_ns.load(Ordering::Relaxed));
    drop(guard);

    // Headers arrive in well under a millisecond on loopback, so anything near
    // the body delay can only have come from the decision-body wait.
    assert!(
        charged >= body_delay.mul_f64(0.75),
        "the decision body wait must be charged to external I/O, got {charged:?}"
    );
    let logs = writer.contents();
    assert!(
        logs.contains("Slow plugin HTTP call"),
        "a body-delayed decision must cross the slow-call threshold: {logs}"
    );
}

/// Control for the case above: a header-delayed decision was always measured,
/// and must still be charged exactly once now that the body read is inside the
/// same span.
#[tokio::test(flavor = "current_thread")]
async fn opa_external_io_charges_a_header_delayed_decision_exactly_once() {
    let header_delay = Duration::from_millis(200);
    let server = MockServer::start().await;
    mount_opa_with_delay(&server, header_delay).await;
    let plugin = plugin(&server, json!({"timeout_ms": 5000}));

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);

    let charged = Duration::from_nanos(ctx.plugin_http_call_ns.load(Ordering::Relaxed));
    assert!(
        charged >= header_delay.mul_f64(0.75),
        "the header wait must be charged, got {charged:?}"
    );
    assert!(
        charged < header_delay.mul_f64(1.8),
        "the header wait must be charged exactly once, got {charged:?}"
    );
}

// ---------------------------------------------------------------------------
// Decision-endpoint redaction — advisory GHSA-4ghp-v85j-5hvq
// ---------------------------------------------------------------------------

/// `opa_host` rejects userinfo, query, and fragment but accepts a base PATH,
/// and a deployment may put a reusable credential there. The shared client's
/// diagnostics must record the origin only.
#[tokio::test(flavor = "current_thread")]
async fn opa_slow_call_diagnostics_never_print_the_configured_base_path() {
    const BASE_PATH_CANARY: &str = "opa-base-path-canary";

    let (writer, guard) = super::plugin_utils::capture_logs();

    let server = MockServer::start().await;
    let decision_path = format!("/{BASE_PATH_CANARY}{DECISION_PATH}");
    Mock::given(method("POST"))
        .and(path(decision_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": true})))
        .mount(&server)
        .await;

    let base = server.uri();
    let config = json!({
        "opa_host": format!("{base}/{BASE_PATH_CANARY}"),
        "policy_path": POLICY_PATH,
    });
    // Threshold 0 makes every call "slow", so the diagnostic always fires.
    let client = PluginHttpClient::from_pool_config_with_threshold(&PoolConfig::default(), 0);
    let plugin = Opa::new(&config, client).expect("valid opa config");

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);
    drop(guard);

    let logs = writer.contents();
    assert!(
        logs.contains("Slow plugin HTTP call"),
        "the slow-call diagnostic must have been emitted: {logs}"
    );
    assert!(
        !logs.contains(BASE_PATH_CANARY),
        "OPA diagnostics leaked the configured base path: {logs}"
    );
}

#[test]
fn opa_rejects_a_fail_posture_configured_twice_even_when_the_values_agree() {
    let config = json!({
        "opa_host": "http://127.0.0.1:8181",
        "policy_path": POLICY_PATH,
        "fail_open": false,
        "fail_closed": true,
    });
    let Err(error) = Opa::new(&config, default_client()) else {
        panic!("configuring both fail-posture flags must be rejected");
    };
    assert!(
        error.contains("configure only one of `fail_open` or `fail_closed`"),
        "unexpected error: {error}"
    );
}

#[test]
fn opa_accepts_null_byte_limits_as_the_documented_defaults() {
    for field in ["max_response_bytes", "max_body_bytes"] {
        let mut config = json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": POLICY_PATH,
        });
        config
            .as_object_mut()
            .expect("config object")
            .insert(field.to_string(), Value::Null);
        Opa::new(&config, default_client())
            .unwrap_or_else(|error| panic!("null {field} must select the default: {error}"));
    }
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let canary = "'SECURITY_DIAGNOSTIC_CANARY\"`\n\\payload";
    let header = "'security-diagnostic-canary";
    let cases: &[(serde_json::Value, &[&str])] = &[
        (
            json!({
                "opa_host": "https://opa.example.com",
                "policy_path": "allow",
                "headers": {(header): true}
            }),
            &["`headers`", "must be a string"],
        ),
        (
            json!({
                "opa_host": "https://opa.example.com",
                "policy_path": "allow",
                "redact_headers": [canary]
            }),
            &["`redact_headers[0]`", "invalid", "header name"],
        ),
        (
            json!({
                "opa_host": "https://opa.example.com",
                "policy_path": "allow",
                "timeout_ms": -8675309
            }),
            &["`timeout_ms`", "unsigned integer"],
        ),
    ];

    for (config, expected) in cases {
        let error = ferrum_edge::plugins::validate_plugin_config("opa", config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for &fragment in *expected {
            assert!(
                rendered.contains(fragment),
                "missing {fragment:?}: {rendered}"
            );
        }
        for supplied in [
            "SECURITY_DIAGNOSTIC_CANARY",
            "security-diagnostic-canary",
            "8675309",
            "54321",
            "16384",
            "true",
        ] {
            assert!(
                !rendered.contains(supplied),
                "leaked {supplied:?}: {rendered}"
            );
        }
    }
}

/// The decision call carries the request's gateway hop count (`received + 1`)
/// as exactly one `X-Ferrum-Hops` field line, so an OPA host that resolves back
/// to the gateway is refused at the proxy hop limit like a looping route
/// (issue #6128). With the limit disabled nothing is stamped.
#[tokio::test]
async fn opa_decision_call_carries_the_proxy_hop_count() {
    for (outbound_proxy_hops, expected) in [(Some(7), vec!["7"]), (None, Vec::new())] {
        let server = MockServer::start().await;
        mount_opa(&server, 200, json!({"result": true})).await;
        let plugin = plugin(&server, json!({}));

        let mut ctx = make_ctx();
        ctx.outbound_proxy_hops = outbound_proxy_hops;
        assert_continue(plugin.authorize(&mut ctx).await);

        let received = server.received_requests().await.unwrap_or_default();
        assert_eq!(received.len(), 1);
        let hops: Vec<&str> = received[0]
            .headers
            .get_all("x-ferrum-hops")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(hops, expected, "hops={outbound_proxy_hops:?}");
    }
}

/// `headers` cannot name the gateway-owned `X-Ferrum-Hops` field in any
/// spelling: the decision call stamps the request's hop count itself, so a
/// configured copy would sit beside it as a second field line (issue #6128).
#[test]
fn opa_headers_cannot_name_the_proxy_hop_count() {
    for name in ["X-Ferrum-Hops", "x_ferrum_hops", "X_FERRUM_HOPS"] {
        let config = json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": POLICY_PATH,
            "headers": {name: "0"},
        });
        let error = match Opa::new(&config, default_client()) {
            Ok(_) => panic!("`headers` naming {name:?} must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("X-Ferrum-Hops"), "{name:?}: {error}");
        assert!(validate_plugin_config("opa", &config).is_err(), "{name:?}");
    }
}

// ---------------------------------------------------------------------------
// Decision-URL normalization (issue #6368) and header value domain (#6369)
// ---------------------------------------------------------------------------

fn opa_schema_validator() -> jsonschema::Validator {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/OpaPluginConfig",
        "components": spec["components"].clone(),
    });
    jsonschema::draft202012::options()
        .build(&schema)
        .expect("OpaPluginConfig schema compiles")
}

/// The WHATWG URL parser treats `\` as a separator for http/https, strips
/// tab/CR/LF, trims trailing spaces and controls, and then removes dot
/// segments. Every policy path that parsing would rewrite out of (or within)
/// `/v1/data/` must be refused by BOTH the constructor and the schema.
#[test]
fn opa_policy_path_rejects_values_url_normalization_would_rewrite() {
    let validator = opa_schema_validator();
    let traversal_shaped = [
        "..\\..\\outside",
        "ferrum\\..\\..\\outside",
        "ferrum/authz\\allow",
        "ferrum/.. ",
        "ferrum/allow ",
        " ferrum/allow",
        "ferrum/.\t.",
        "ferrum/\n../outside",
        "ferrum/\r..",
        "ferrum/allow\u{0}",
        "ferrum/allow\u{7f}",
        "ferrum/al low",
    ];
    for policy_path in traversal_shaped {
        let config = json!({
            "opa_host": "https://opa.example",
            "policy_path": policy_path,
        });
        let error = match Opa::new(&config, default_client()) {
            Ok(_) => panic!("policy_path {policy_path:?} must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.contains("`policy_path`"),
            "{policy_path:?}: unexpected error {error}"
        );
        assert!(
            !error.contains("outside"),
            "{policy_path:?}: the diagnostic must not echo the supplied value: {error}"
        );
        assert!(
            validate_plugin_config("opa", &config).is_err(),
            "{policy_path:?}: validate_plugin_config must agree with the constructor"
        );
        assert!(
            !validator.is_valid(&config),
            "{policy_path:?}: OpaPluginConfig must reject what the constructor rejects"
        );
    }

    for policy_path in ["ferrum/authz/allow", "ferrum/authz/allów", "a..b/c./.d"] {
        let config = json!({
            "opa_host": "https://opa.example",
            "policy_path": policy_path,
        });
        assert!(
            Opa::new(&config, default_client()).is_ok(),
            "{policy_path:?}: constructor must admit an ordinary data path"
        );
        assert!(
            validator.is_valid(&config),
            "{policy_path:?}: OpaPluginConfig must admit what the constructor admits"
        );
    }
}

/// A base path with dot segments is normalized before the Data API prefix is
/// appended, and the decision call is sent to exactly the admitted URL: the
/// mock answers only `/v1/data/{policy_path}`, so any other target would fail
/// closed with a 503 instead of continuing.
#[tokio::test]
async fn opa_decision_call_targets_the_normalized_data_api_path() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let config = json!({
        "opa_host": format!("{}/base/..", server.uri()),
        "policy_path": POLICY_PATH,
    });
    let plugin = Opa::new(&config, default_client()).expect("valid opa config");

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);

    let received = server.received_requests().await.unwrap_or_default();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].url.path(), DECISION_PATH);
}

/// `headers`, `deny_headers`, and `fail_closed_headers` values share one
/// domain: whatever `HeaderValue::from_str` accepts (visible ASCII, space,
/// HTAB, and UTF-8 obs-text). NUL, CR, LF, DEL, and other C0 controls are
/// refused by both the constructor and the schema.
#[test]
fn opa_header_value_domain_matches_between_schema_and_constructor() {
    let validator = opa_schema_validator();
    let cases = [
        ("denied", true),
        ("café", true),
        ("tab\tseparated", true),
        ("", true),
        ("nul\u{0}byte", false),
        ("carriage\rreturn", false),
        ("line\nfeed", false),
        ("del\u{7f}byte", false),
        ("bell\u{7}byte", false),
    ];
    for field in ["headers", "deny_headers", "fail_closed_headers"] {
        for (value, expected_valid) in cases {
            let config = json!({
                "opa_host": "http://127.0.0.1:8181",
                "policy_path": POLICY_PATH,
                field: {"X-Policy": value},
            });
            assert_eq!(
                Opa::new(&config, default_client()).is_ok(),
                expected_valid,
                "{field} value {value:?}: constructor admission"
            );
            assert_eq!(
                validator.is_valid(&config),
                expected_valid,
                "{field} value {value:?}: OpaPluginConfig admission"
            );
        }
    }
}

/// A non-loopback cleartext `opa_host` carries the authorization input and the
/// decision in clear, so it needs the explicit opt-in.
#[test]
fn opa_cleartext_host_needs_opt_in_off_loopback() {
    let with = |host: &str, opt_in: Option<Value>| {
        let mut config = base_config(host);
        if let Some(flag) = opt_in {
            config["allow_plaintext"] = flag;
        }
        config
    };
    for config in [
        with("http://opa.internal:8181", None),
        with("http://opa.internal:8181", Some(json!(false))),
        with("http://localhost:8181", None),
        with("http://127.1:8181", None),
        with("http://[0:0:0:0:0:0:0:1]:8181", None),
    ] {
        let error = match Opa::new(&config, default_client()) {
            Ok(_) => panic!("{config} must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("allow_plaintext"), "{config}: {error}");
        assert!(validate_plugin_config("opa", &config).is_err(), "{config}");
    }
    for config in [
        with("http://opa.internal:8181", Some(json!(true))),
        with("http://127.0.0.1:8181", None),
        with("http://[::1]:8181", None),
        with("https://opa.internal:8181", None),
    ] {
        assert!(Opa::new(&config, default_client()).is_ok(), "{config}");
    }
    // The flag is typed whenever supplied, even where it has no effect.
    for flag in [json!("yes"), Value::Null] {
        let config = with("https://opa.internal:8181", Some(flag));
        let error = match Opa::new(&config, default_client()) {
            Ok(_) => panic!("{config} must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("allow_plaintext"), "{config}: {error}");
    }
}

// ---------------------------------------------------------------------------
// Production-launch review fixes: identity realm, header field lines, body
// representation, credential classification, obligations, bulkhead, and
// decision observability.
// ---------------------------------------------------------------------------

/// Commits `alice` as an external identity through the shared authentication
/// boundary, vouched for by the authority digest it was built with.
struct RealmProbe([u8; 32]);

#[async_trait::async_trait]
impl ferrum_edge::plugins::utils::auth_flow::AuthMechanism for RealmProbe {
    fn mechanism_name(&self) -> &'static str {
        "realm_probe"
    }

    fn authentication_challenge(&self) -> &'static str {
        "Bearer"
    }

    fn extract(
        &self,
        _ctx: &RequestContext,
    ) -> ferrum_edge::plugins::utils::auth_flow::ExtractedCredential {
        ferrum_edge::plugins::utils::auth_flow::ExtractedCredential::BearerToken(
            "probe-secret-token".to_string(),
        )
    }

    fn identity_realm_authority(&self) -> Option<[u8; 32]> {
        Some(self.0)
    }

    async fn verify(
        &self,
        _credential: ferrum_edge::plugins::utils::auth_flow::ExtractedCredential,
        _consumer_index: &ferrum_edge::consumer_index::ConsumerIndex,
    ) -> ferrum_edge::plugins::utils::auth_flow::VerifyOutcome {
        ferrum_edge::plugins::utils::auth_flow::VerifyOutcome::success(
            None,
            Some("alice".to_string()),
            None,
        )
    }
}

async fn external_alice_ctx(authority: [u8; 32]) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/admin".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.headers.insert(
        "authorization".to_string(),
        "Bearer probe-secret-token".to_string(),
    );
    // A client cannot claim a realm through a header.
    ctx.headers
        .insert("x-identity-realm".to_string(), "corporate".to_string());
    let result = ferrum_edge::plugins::utils::auth_flow::run_auth_external_identity(
        &RealmProbe(authority),
        &mut ctx,
        &ferrum_edge::consumer_index::ConsumerIndex::new(&[]),
    )
    .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("alice"));
    assert!(ctx.identified_consumer.is_none());
    ctx
}

/// opa-SOL-1: equal subjects verified by different authorities are different
/// principals, so the OPA input carries the verified realm and a
/// realm-specific policy allows one and denies the other.
#[tokio::test]
async fn opa_input_distinguishes_equal_subjects_from_different_realms() {
    let corporate = [0x11; 32];
    let partner = [0x22; 32];
    let corporate_hex = hex::encode(corporate);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .and(body_partial_json(json!({
            "input": {"consumer": {
                "identity": "alice",
                "realm": {"mechanism": "realm_probe", "authority": corporate_hex}
            }}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": true})))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": false})))
        .with_priority(2)
        .mount(&server)
        .await;
    let plugin = plugin(&server, json!({}));

    let mut corporate_ctx = external_alice_ctx(corporate).await;
    assert_continue(plugin.authorize(&mut corporate_ctx).await);
    let mut partner_ctx = external_alice_ctx(partner).await;
    assert_reject(plugin.authorize(&mut partner_ctx).await, Some(403));

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 2);
    let corporate_input: Value = requests[0].body_json().expect("JSON input");
    let partner_input: Value = requests[1].body_json().expect("JSON input");
    assert_eq!(corporate_input["input"]["consumer"]["identity"], "alice");
    assert_eq!(partner_input["input"]["consumer"]["identity"], "alice");
    assert_eq!(
        corporate_input["input"]["consumer"]["realm"],
        json!({"mechanism": "realm_probe", "authority": corporate_hex})
    );
    assert_eq!(
        partner_input["input"]["consumer"]["realm"]["authority"],
        json!(hex::encode(partner))
    );
    for input in [&corporate_input, &partner_input] {
        let serialized = serde_json::to_string(input).expect("serialize input");
        assert!(!serialized.contains("probe-secret-token"), "{serialized}");
    }
}

/// An identity a plugin wrote without the authentication boundary carries no
/// realm, so a policy can refuse to trust it.
#[tokio::test]
async fn opa_external_identity_without_a_committed_realm_has_null_realm() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("alice".to_string());
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["consumer"]["identity"], "alice");
    assert!(payload["input"]["consumer"]["realm"].is_null());
    assert!(
        payload["input"]["consumer"]
            .as_object()
            .expect("consumer object")
            .contains_key("realm")
    );
}

/// opa-SOL-2 / opa-claude-3: the policy body is never read from
/// plugin-writable metadata; with no byte view it is `null`.
#[tokio::test]
async fn opa_body_is_never_sourced_from_request_body_metadata() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"include_body": true}));

    let mut ctx = make_ctx();
    ctx.request_body_bytes = None;
    ctx.metadata.insert(
        "request_body".to_string(),
        "METADATA_BODY_CANARY".to_string(),
    );
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert!(payload["input"]["body"].is_null());
    assert!(
        payload["input"]
            .as_object()
            .expect("input object")
            .contains_key("body")
    );
    let serialized = serde_json::to_string(&payload).expect("serialize payload");
    assert!(!serialized.contains("METADATA_BODY_CANARY"), "{serialized}");
}

/// The empty byte view every frontend publishes for a proven-empty upload
/// serializes as `body: ""`, the same as a collected `Content-Length: 0`.
#[tokio::test]
async fn opa_empty_body_view_is_an_empty_string() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"include_body": true}));

    let mut ctx = make_ctx();
    ctx.request_body_bytes = Some(bytes::Bytes::new());
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["body"], json!(""));
    assert!(payload["input"].get("body_base64").is_none());
}

fn raw_header_ctx(lines: &[(&'static str, &'static str)]) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.headers.clear();
    let mut raw = http::HeaderMap::new();
    for &(name, value) in lines {
        raw.append(name, http::HeaderValue::from_static(value));
    }
    ctx.set_raw_headers(raw);
    ctx
}

/// opa-claude-1: a repeated non-list header is ambiguous — the folded value
/// matches none of the lines a backend may execute — so the default rejects
/// before OPA is called.
#[tokio::test]
async fn opa_rejects_a_repeated_singleton_header_before_calling_opa() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = raw_header_ctx(&[("x-role", "banned"), ("x-role", "user")]);
    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
    assert_eq!(
        ctx.metadata
            .get(ferrum_edge::plugins::opa::OPA_REASON_METADATA_KEY)
            .map(String::as_str),
        Some("ambiguous_header")
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .is_empty(),
        "an ambiguous header must be refused before the decision call"
    );
}

/// Under `delegate` OPA sees every line, the classification, and no flat
/// value for the ambiguous name.
#[tokio::test]
async fn opa_delegate_mode_reports_repeated_header_lines() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"header_ambiguity_policy": "delegate"}));

    let mut ctx = raw_header_ctx(&[
        ("x-role", "banned"),
        ("x-role", "user"),
        ("x-request-id", "req-1"),
    ]);
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let input = &payload["input"];
    assert_eq!(input["header_ambiguity"], json!(["duplicate_field_lines"]));
    assert!(input["headers"].get("x-role").is_none());
    assert_eq!(input["headers"]["x-request-id"], "req-1");
    assert_eq!(
        input["header_pairs"],
        json!([
            {"name": "x-request-id", "value": "req-1"},
            {"name": "x-role", "value": "banned"},
            {"name": "x-role", "value": "user"}
        ])
    );
}

/// List-valued fields mean the same thing repeated or folded, so they are
/// never ambiguous; a single line reports no ambiguity either.
#[tokio::test]
async fn opa_repeated_list_valued_headers_are_not_ambiguous() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = raw_header_ctx(&[
        ("accept", "text/html"),
        ("accept", "application/json"),
        ("x-role", "user"),
    ]);
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    let input = &payload["input"];
    assert_eq!(input["header_ambiguity"], json!([]));
    assert_eq!(input["headers"]["accept"], "text/html, application/json");
    assert_eq!(input["headers"]["x-role"], "user");
    assert_eq!(
        input["header_pairs"],
        json!([
            {"name": "accept", "value": "text/html"},
            {"name": "accept", "value": "application/json"},
            {"name": "x-role", "value": "user"}
        ])
    );
}

/// An earlier plugin's rewrite replaces every raw line with one value, so the
/// rewritten header is forwarded once and is not ambiguous.
#[tokio::test]
async fn opa_rewritten_repeated_header_is_reported_once() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = raw_header_ctx(&[("x-role", "banned"), ("x-role", "user")]);
    ctx.materialize_headers();
    ctx.headers.insert("x-role".to_string(), "user".to_string());
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["headers"]["x-role"], "user");
    assert_eq!(
        payload["input"]["header_pairs"],
        json!([{"name": "x-role", "value": "user"}])
    );
}

/// opa-claude-2: credential-shaped names outside the exact built-in lists are
/// withheld by the shared sensitive-name classifier.
#[tokio::test]
async fn opa_redacts_classifier_recognized_header_and_query_credentials() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    ctx.headers.clear();
    ctx.headers
        .insert("x-vault-token".to_string(), "VAULT_CANARY".to_string());
    ctx.headers.insert(
        "x-amz-security-token".to_string(),
        "AMZ_TOKEN_CANARY".to_string(),
    );
    ctx.headers
        .insert("x-request-id".to_string(), "req-9".to_string());
    ctx.set_raw_query_string(
        "action=read&refresh_token=REFRESH_CANARY&X-Amz-Signature=SIG_CANARY&password=PW_CANARY"
            .to_string(),
    );
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["headers"]["x-request-id"], "req-9");
    assert_eq!(payload["input"]["query"]["action"], "read");
    let serialized = serde_json::to_string(&payload).expect("serialize payload");
    for canary in [
        "VAULT_CANARY",
        "AMZ_TOKEN_CANARY",
        "REFRESH_CANARY",
        "SIG_CANARY",
        "PW_CANARY",
    ] {
        assert!(
            !serialized.contains(canary),
            "{canary} leaked: {serialized}"
        );
    }

    // The explicit query opt-in still forwards classifier-recognized names.
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let opted_in = self::plugin(&server, json!({"include_query_credentials": true}));
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("refresh_token=REFRESH_CANARY".to_string());
    assert_continue(opted_in.authorize(&mut ctx).await);
    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["query"]["refresh_token"], "REFRESH_CANARY");
}

/// opa-claude-5: authentication-marked query names are collected once per
/// request and still match case-insensitively.
#[tokio::test]
async fn opa_marked_query_credentials_match_case_insensitively() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({}));

    let mut ctx = make_ctx();
    ctx.set_raw_query_string("Carrier_Ref=MARKED_CANARY&page=2".to_string());
    ctx.metadata.insert(
        "auth.query_credential_param.carrier_ref".to_string(),
        "true".to_string(),
    );
    assert_continue(plugin.authorize(&mut ctx).await);

    let payload = received_opa_payload(&server).await;
    assert_eq!(payload["input"]["query"]["page"], "2");
    let serialized = serde_json::to_string(&payload).expect("serialize payload");
    assert!(!serialized.contains("MARKED_CANARY"), "{serialized}");
}

/// opa-claude-6: allow obligations set listed upstream headers, and every
/// client copy of a listed name (any case, `_` or `-`) is removed.
#[tokio::test]
async fn opa_allow_obligation_installs_listed_upstream_headers() {
    let server = MockServer::start().await;
    mount_opa(
        &server,
        200,
        json!({"result": {"allow": true, "headers": {"X-Tenant": "blue"}}}),
    )
    .await;
    let plugin = plugin(&server, json!({"decision_request_headers": ["x-tenant"]}));
    assert!(plugin.modifies_request_headers());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-tenant".to_string(), "spoofed".to_string());
    ctx.headers
        .insert("X_Tenant".to_string(), "spoofed-underscore".to_string());
    assert_continue(plugin.authorize(&mut ctx).await);

    assert_eq!(
        ctx.headers.get("x-tenant").map(String::as_str),
        Some("blue")
    );
    assert!(!ctx.headers.contains_key("X_Tenant"));
    assert_eq!(
        ctx.headers.get("x-request-id").map(String::as_str),
        Some("req-123")
    );
}

/// A bare `true` decision carries no obligation, but a listed destination is
/// still gateway-owned and the client copy is removed.
#[tokio::test]
async fn opa_listed_destinations_are_stripped_without_an_obligation() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let plugin = plugin(&server, json!({"decision_request_headers": ["x-tenant"]}));

    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-tenant".to_string(), "spoofed".to_string());
    assert_continue(plugin.authorize(&mut ctx).await);
    assert!(!ctx.headers.contains_key("x-tenant"));
}

/// An obligation the gateway cannot honor exactly is a denial, never an allow
/// with the obligation dropped.
#[tokio::test]
async fn opa_invalid_allow_obligations_deny() {
    for decision in [
        json!({"allow": true, "headers": {"x-unlisted": "v"}}),
        json!({"allow": true, "headers": {"x-tenant": 7}}),
        json!({"allow": true, "headers": ["x-tenant"]}),
        json!({"allow": true, "headers": {"x-tenant": "a", "X-Tenant": "b"}}),
        json!({"allow": true, "headers": {"x-tenant": "line\nbreak"}}),
    ] {
        let server = MockServer::start().await;
        mount_opa(&server, 200, json!({"result": decision.clone()})).await;
        let plugin = plugin(
            &server,
            json!({"decision_request_headers": ["x-tenant", "x-user"]}),
        );
        let mut ctx = make_ctx();
        assert_reject(plugin.authorize(&mut ctx).await, Some(403));
        assert_eq!(
            ctx.metadata
                .get(ferrum_edge::plugins::opa::OPA_REASON_METADATA_KEY)
                .map(String::as_str),
            Some("invalid_obligation"),
            "{decision}"
        );
        assert!(!ctx.headers.contains_key("x-tenant"), "{decision}");
    }
}

/// Without the opt-in, decision-document headers are ignored exactly as
/// before.
#[tokio::test]
async fn opa_allow_obligations_are_ignored_by_default() {
    let server = MockServer::start().await;
    mount_opa(
        &server,
        200,
        json!({"result": {"allow": true, "headers": {"x-tenant": "blue"}}}),
    )
    .await;
    let plugin = plugin(&server, json!({}));
    assert!(!plugin.modifies_request_headers());

    let mut ctx = make_ctx();
    assert_continue(plugin.authorize(&mut ctx).await);
    assert!(!ctx.headers.contains_key("x-tenant"));
}

#[test]
fn opa_decision_request_headers_refuse_owned_and_credential_names() {
    for name in [
        "authorization",
        "Proxy-Authorization",
        "cookie",
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "x-consumer-username",
        "X_Consumer_Role",
        "x-ferrum-hops",
        "x-forwarded-for",
        "x-geo-country",
        "x-api-key",
        "x-vault-token",
        "x-session-id",
        "Bad Header",
        "",
    ] {
        let config = json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": POLICY_PATH,
            "decision_request_headers": [name],
        });
        assert!(
            Opa::new(&config, default_client()).is_err(),
            "{name:?} must be refused"
        );
        assert!(validate_plugin_config("opa", &config).is_err(), "{name:?}");
    }

    let duplicate = json!({
        "opa_host": "http://127.0.0.1:8181",
        "policy_path": POLICY_PATH,
        "decision_request_headers": ["x-tenant", "X_Tenant"],
    });
    assert!(Opa::new(&duplicate, default_client()).is_err());

    let too_many: Vec<String> = (0..33)
        .map(|index| format!("x-obligation-{index}"))
        .collect();
    let config = json!({
        "opa_host": "http://127.0.0.1:8181",
        "policy_path": POLICY_PATH,
        "decision_request_headers": too_many,
    });
    assert!(Opa::new(&config, default_client()).is_err());

    let ordinary = json!({
        "opa_host": "http://127.0.0.1:8181",
        "policy_path": POLICY_PATH,
        "decision_request_headers": ["x-tenant", "X-User-Id"],
        "decision_deny_response": true,
    });
    assert!(Opa::new(&ordinary, default_client()).is_ok());
}

/// Deny obligations shape the rejection only when opted in; a malformed one
/// still denies with the static response.
#[tokio::test]
async fn opa_deny_obligation_shapes_the_rejection_when_enabled() {
    let decision = json!({
        "result": {
            "allow": false,
            "status": 429,
            "body": "{\"error\":\"slow down\"}",
            "headers": {"Retry-After": "5"}
        }
    });

    let server = MockServer::start().await;
    mount_opa(&server, 200, decision.clone()).await;
    let plugin = plugin(&server, json!({"decision_deny_response": true}));
    let mut ctx = make_ctx();
    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(body, "{\"error\":\"slow down\"}");
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("5"));
        }
        other => panic!("expected reject, got {other:?}"),
    }

    // Default: the static response, whatever the decision says.
    let server = MockServer::start().await;
    mount_opa(&server, 200, decision).await;
    let plugin = self::plugin(&server, json!({}));
    let mut ctx = make_ctx();
    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, r#"{"error":"forbidden by policy"}"#);
        }
        other => panic!("expected reject, got {other:?}"),
    }

    for malformed in [
        json!({"allow": false, "status": 200}),
        json!({"allow": false, "status": "429"}),
        json!({"allow": false, "body": 5}),
        json!({"allow": false, "headers": {"Content-Length": "3"}}),
        json!({"allow": false, "headers": {"Retry-After": 5}}),
    ] {
        let server = MockServer::start().await;
        mount_opa(&server, 200, json!({"result": malformed.clone()})).await;
        let plugin = self::plugin(&server, json!({"decision_deny_response": true}));
        let mut ctx = make_ctx();
        match plugin.authorize(&mut ctx).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 403, "{malformed}");
                assert_eq!(body, r#"{"error":"forbidden by policy"}"#, "{malformed}");
            }
            other => panic!("{malformed}: expected reject, got {other:?}"),
        }
        assert_eq!(
            ctx.metadata
                .get(ferrum_edge::plugins::opa::OPA_REASON_METADATA_KEY)
                .map(String::as_str),
            Some("invalid_obligation"),
            "{malformed}"
        );
    }
}

/// opa-claude-7: over the per-instance bound a request takes the failure
/// posture immediately instead of queueing behind a slow policy service.
#[tokio::test]
async fn opa_concurrency_bulkhead_applies_the_failure_posture() {
    for fail_open in [false, true] {
        let server = MockServer::start().await;
        mount_opa_with_delay(&server, Duration::from_millis(1500)).await;
        let plugin = Arc::new(plugin(
            &server,
            json!({
                "max_concurrent_decisions": 1,
                "timeout_ms": 5000,
                "fail_open": fail_open,
            }),
        ));

        let in_flight = {
            let plugin = Arc::clone(&plugin);
            tokio::spawn(async move {
                let mut ctx = make_ctx();
                plugin.authorize(&mut ctx).await
            })
        };
        for _ in 0..80 {
            if server
                .received_requests()
                .await
                .is_some_and(|requests| !requests.is_empty())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let mut ctx = make_ctx();
        let result = plugin.authorize(&mut ctx).await;
        if fail_open {
            assert_continue(result);
            assert_eq!(
                ctx.metadata
                    .get(ferrum_edge::plugins::opa::OPA_DECISION_METADATA_KEY)
                    .map(String::as_str),
                Some("error_fail_open")
            );
        } else {
            assert_reject(result, Some(503));
            assert_eq!(
                ctx.metadata
                    .get(ferrum_edge::plugins::opa::OPA_DECISION_METADATA_KEY)
                    .map(String::as_str),
                Some("error_fail_closed")
            );
        }
        assert_eq!(
            ctx.metadata
                .get(ferrum_edge::plugins::opa::OPA_REASON_METADATA_KEY)
                .map(String::as_str),
            Some("opa_concurrency_limit")
        );

        assert_continue(in_flight.await.expect("in-flight decision task"));
        // The permit is released once the decision completes.
        let mut ctx = make_ctx();
        assert_continue(plugin.authorize(&mut ctx).await);
    }
}

#[test]
fn opa_max_concurrent_decisions_is_bounded() {
    for (value, valid) in [
        (json!(0), false),
        (json!(1), true),
        (json!(1_000_000), true),
        (json!(1_000_001), false),
        (json!(-1), false),
        (json!("8"), false),
    ] {
        let config = json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": POLICY_PATH,
            "max_concurrent_decisions": value,
        });
        assert_eq!(
            Opa::new(&config, default_client()).is_ok(),
            valid,
            "{config}"
        );
    }
}

fn outcome(ctx: &RequestContext) -> (Option<&str>, Option<&str>) {
    (
        ctx.metadata
            .get(ferrum_edge::plugins::opa::OPA_DECISION_METADATA_KEY)
            .map(String::as_str),
        ctx.metadata
            .get(ferrum_edge::plugins::opa::OPA_REASON_METADATA_KEY)
            .map(String::as_str),
    )
}

/// opa-claude-8: every decision records a fixed-cardinality outcome that the
/// transaction-log metadata gate emits.
#[tokio::test]
async fn opa_records_decision_outcome_metadata() {
    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": true})).await;
    let mut ctx = make_ctx();
    assert_continue(plugin(&server, json!({})).authorize(&mut ctx).await);
    assert_eq!(outcome(&ctx), (Some("allow"), Some("policy_allowed")));

    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"result": false})).await;
    let mut ctx = make_ctx();
    assert_reject(
        plugin(&server, json!({})).authorize(&mut ctx).await,
        Some(403),
    );
    assert_eq!(outcome(&ctx), (Some("deny"), Some("policy_denied")));

    let server = MockServer::start().await;
    mount_opa(&server, 200, json!({"other": true})).await;
    let mut ctx = make_ctx();
    assert_reject(
        plugin(&server, json!({})).authorize(&mut ctx).await,
        Some(403),
    );
    assert_eq!(outcome(&ctx), (Some("deny"), Some("decision_undefined")));

    let server = MockServer::start().await;
    mount_opa(&server, 500, json!({})).await;
    let mut ctx = make_ctx();
    assert_reject(
        plugin(&server, json!({})).authorize(&mut ctx).await,
        Some(503),
    );
    assert_eq!(
        outcome(&ctx),
        (Some("error_fail_closed"), Some("opa_non_success_status"))
    );

    let server = MockServer::start().await;
    mount_opa(&server, 500, json!({})).await;
    let mut ctx = make_ctx();
    assert_continue(
        plugin(&server, json!({"fail_open": true}))
            .authorize(&mut ctx)
            .await,
    );
    assert_eq!(
        outcome(&ctx),
        (Some("error_fail_open"), Some("opa_non_success_status"))
    );

    let server = MockServer::start().await;
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("a=1&a=2".to_string());
    assert_reject(
        plugin(&server, json!({})).authorize(&mut ctx).await,
        Some(403),
    );
    assert_eq!(outcome(&ctx), (Some("deny"), Some("ambiguous_query")));

    for key in [
        ferrum_edge::plugins::opa::OPA_DECISION_METADATA_KEY,
        ferrum_edge::plugins::opa::OPA_REASON_METADATA_KEY,
    ] {
        assert!(
            !ferrum_edge::plugins::utils::metadata_redaction::metadata_value_is_redacted(key),
            "{key} must be emitted in transaction logs"
        );
    }
}

#[test]
fn opa_new_config_keys_are_typed_and_closed() {
    for (key, value) in [
        ("header_ambiguity_policy", json!("allow")),
        ("header_ambiguity_policy", json!(true)),
        ("decision_deny_response", json!("yes")),
        ("decision_request_headers", json!("x-tenant")),
        ("decision_request_headers", json!([7])),
    ] {
        let mut config = base_config("http://127.0.0.1:8181");
        config[key] = value.clone();
        assert!(
            Opa::new(&config, default_client()).is_err(),
            "{key}: {value} must be refused"
        );
    }
    for policy in ["reject", "delegate"] {
        let mut config = base_config("http://127.0.0.1:8181");
        config["header_ambiguity_policy"] = json!(policy);
        assert!(Opa::new(&config, default_client()).is_ok(), "{policy}");
    }
}
