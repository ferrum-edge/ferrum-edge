//! End-to-end OPA input redaction for key-auth and other API-key headers.

use crate::common::{TestGateway, spawn_http_echo};

use http::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DECISION_PATH: &str = "/v1/data/ferrum/authz/allow";

#[ignore]
#[tokio::test]
async fn opa_omits_dynamic_and_static_credential_headers_from_decision_input() {
    let opa = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": true})))
        .mount(&opa)
        .await;
    let mut backend = spawn_http_echo().await.expect("spawn echo backend");
    let config = key_auth_opa_config(backend.port, &opa.uri());
    let mut gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start key-auth OPA gateway");

    let response = reqwest::Client::new()
        .get(
            gateway.proxy_url("/resource?api_key=query-secret&ordinary_query=ordinary-query-value"),
        )
        .header("X-Tenant-Credential", "test-api-key-0123456789")
        .header("API-Key", "azure-secret")
        .header("X-Goog-Api-Key", "google-secret")
        .header("X-Policy-Secret", "configured-secret")
        .header("X-Ordinary", "ordinary-header-value")
        .send()
        .await
        .expect("key-auth request completes");
    assert_eq!(response.status(), StatusCode::OK);

    let requests = opa.received_requests().await.expect("read OPA requests");
    assert_eq!(requests.len(), 1, "expected one OPA decision request");
    let payload: Value = requests[0]
        .body_json()
        .expect("OPA decision request should be JSON");
    let headers = payload["input"]["headers"]
        .as_object()
        .expect("OPA input headers should be an object");
    for credential_header in [
        "x-tenant-credential",
        "api-key",
        "x-goog-api-key",
        "x-policy-secret",
    ] {
        assert!(
            !headers.contains_key(credential_header),
            "OPA input exposed credential header {credential_header}: {payload}"
        );
    }
    assert_eq!(
        headers.get("x-ordinary"),
        Some(&json!("ordinary-header-value"))
    );
    assert_eq!(
        payload["input"]["query"]["ordinary_query"],
        "ordinary-query-value"
    );
    assert!(
        payload["input"]["query"].get("api_key").is_none(),
        "existing query-credential omission regressed: {payload}"
    );

    let serialized = serde_json::to_string(&payload).expect("serialize OPA payload");
    for secret in [
        "test-api-key-0123456789",
        "azure-secret",
        "google-secret",
        "configured-secret",
        "query-secret",
    ] {
        assert!(
            !serialized.contains(secret),
            "OPA decision payload leaked {secret}: {serialized}"
        );
    }

    gateway.shutdown();
    backend.abort();
}

fn key_auth_opa_config(backend_port: u16, opa_host: &str) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "key-auth-opa",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "plugins": [
                {"plugin_config_id": "key-auth"},
                {"plugin_config_id": "opa-authz"}
            ]
        }],
        "consumers": [{
            "id": "opa-consumer",
            "username": "opa-user",
            "credentials": {"keyauth": [{"key": "test-api-key-0123456789"}]}
        }],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "key-auth",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "key-auth-opa",
                "enabled": true,
                "config": {"key_location": "header:X-Tenant-Credential"}
            },
            {
                "id": "opa-authz",
                "plugin_name": "opa",
                "scope": "proxy",
                "proxy_id": "key-auth-opa",
                "enabled": true,
                "config": {
                    "opa_host": opa_host,
                    "policy_path": "ferrum/authz/allow",
                    "redact_headers": ["X-Policy-Secret"]
                }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize key-auth OPA config")
}
