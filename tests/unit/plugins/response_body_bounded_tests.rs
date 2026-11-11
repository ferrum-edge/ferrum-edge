//! Tests for `plugins::utils::response_body` bounded readers.
//!
//! Verifies that `read_response_body_bounded` and
//! `measure_response_body_bounded` enforce their cap by streaming the body
//! and aborting as soon as the running total exceeds the limit, instead of
//! buffering the full payload before checking. Stops a misbehaving sink from
//! exhausting gateway memory.

use ferrum_edge::plugins::utils::response_body::{
    BoundedReadError, measure_response_body_bounded, parse_max_response_body_bytes,
    read_response_body_bounded,
};
use ferrum_edge::plugins::{
    PluginHttpClient, opa::Opa, request_mirror::RequestMirror,
    serverless_function::ServerlessFunction, spec_expose::SpecExpose,
};
use serde_json::json;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn test_parse_max_response_body_bytes_defaults_and_validates() {
    assert_eq!(
        parse_max_response_body_bytes(&json!({}), "test_plugin", "limit", 4096).unwrap(),
        4096
    );
    assert_eq!(
        parse_max_response_body_bytes(&json!({ "limit": null }), "test_plugin", "limit", 4096)
            .unwrap(),
        4096
    );
    assert_eq!(
        parse_max_response_body_bytes(&json!({ "limit": 8192 }), "test_plugin", "limit", 4096)
            .unwrap(),
        8192
    );
    assert!(
        parse_max_response_body_bytes(&json!({ "limit": 0 }), "test_plugin", "limit", 4096)
            .unwrap_err()
            .contains("greater than zero")
    );
    assert!(
        parse_max_response_body_bytes(&json!({ "limit": -1 }), "test_plugin", "limit", 4096)
            .unwrap_err()
            .contains("non-negative integer")
    );
    assert!(
        parse_max_response_body_bytes(&json!({ "limit": "8192" }), "test_plugin", "limit", 4096)
            .unwrap_err()
            .contains("non-negative integer")
    );

    let max_u64_result =
        parse_max_response_body_bytes(&json!({ "limit": u64::MAX }), "test_plugin", "limit", 4096);
    if let Ok(max_usize) = usize::try_from(u64::MAX) {
        assert_eq!(max_u64_result.unwrap(), max_usize);
    } else {
        // Regression for finding #92: the platform-overflow message must honor
        // the documented invariant that error messages never echo the
        // offending value, matching the sibling `ai_response_guard` wording.
        let err = max_u64_result.unwrap_err();
        assert!(err.contains("too large for this platform"));
        assert!(
            !err.chars().any(|c| c.is_ascii_digit()),
            "overflow message must not echo the offending value: {err}"
        );
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(err), &[]);
        assert_eq!(
            rendered,
            "test_plugin: `limit` is too large for this platform"
        );
    }
}

#[tokio::test]
async fn response_body_limit_rejections_retain_rendered_fields_for_every_caller() {
    for (plugin, field, base) in [
        (
            "spec_expose",
            "max_response_body_bytes",
            json!({"spec_url": "https://spec.example.test/openapi.json"}),
        ),
        (
            "serverless_function",
            "max_response_body_bytes",
            json!({
                "provider": "azure_functions",
                "function_url": "https://function.example.test/run"
            }),
        ),
        (
            "request_mirror",
            "max_response_body_bytes",
            json!({"allow_plaintext": true, "mirror_host": "mirror.example.test"}),
        ),
        (
            "opa",
            "max_response_bytes",
            json!({"opa_host": "https://policy.example.test", "policy_path": "authz/allow"}),
        ),
        (
            "opa",
            "max_body_bytes",
            json!({"opa_host": "https://policy.example.test", "policy_path": "authz/allow"}),
        ),
    ] {
        for (value, reason) in [
            (
                json!("'RESPONSE_LIMIT_SECRET\"`\\\n"),
                "must be a non-negative integer",
            ),
            (json!(-918273641), "must be a non-negative integer"),
            (json!(0), "must be greater than zero"),
        ] {
            let mut config = base.clone();
            config[field] = value;
            let client = PluginHttpClient::default();
            let result = match plugin {
                "spec_expose" => SpecExpose::new(&config, client).map(|_| ()),
                "serverless_function" => ServerlessFunction::new(&config, client).map(|_| ()),
                "request_mirror" => RequestMirror::new(&config, client).map(|_| ()),
                "opa" => Opa::new(&config, client).map(|_| ()),
                _ => unreachable!(),
            };
            let error = result.expect_err("invalid body limits must reject construction");
            let rendered =
                ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
            assert_eq!(rendered, format!("{plugin}: `{field}` {reason}"));
            for supplied in ["RESPONSE_LIMIT_SECRET", "918273641", ".example.test", "0"] {
                assert!(!rendered.contains(supplied), "{supplied}: {rendered}");
            }
        }
    }
}

/// 2 KiB body against a 1 KiB limit must error and must NOT allocate the full
/// 2 KiB.
#[tokio::test]
async fn test_read_response_body_bounded_exceeds_limit() {
    let server = MockServer::start().await;
    let body = vec![b'A'; 2048];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let result = read_response_body_bounded(resp, 1024).await;

    match result {
        Err(BoundedReadError::LimitExceeded {
            max_bytes,
            read_so_far,
        }) => {
            assert_eq!(max_bytes, 1024);
            assert!(
                read_so_far > 1024,
                "read_so_far should be > limit when triggering the error, got {}",
                read_so_far
            );
            assert!(
                read_so_far <= 2048,
                "should not exceed total body size, got {}",
                read_so_far
            );
        }
        other => panic!("Expected LimitExceeded, got {:?}", other),
    }
}

/// Body within the limit returns Ok with the expected bytes.
#[tokio::test]
async fn test_read_response_body_bounded_within_limit() {
    let server = MockServer::start().await;
    let body = vec![b'B'; 512];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let buf = read_response_body_bounded(resp, 1024)
        .await
        .expect("body within limit should succeed");
    assert_eq!(buf.len(), 512);
    assert_eq!(buf.as_ref(), body.as_slice());
}

/// Empty body (204) returns Ok with empty bytes.
#[tokio::test]
async fn test_read_response_body_bounded_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let buf = read_response_body_bounded(resp, 1024).await.unwrap();
    assert!(buf.is_empty());
}

/// Exactly-at-limit body succeeds (the check is `>`, not `>=`).
#[tokio::test]
async fn test_read_response_body_bounded_exactly_at_limit() {
    let server = MockServer::start().await;
    let body = vec![b'C'; 1024];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let buf = read_response_body_bounded(resp, 1024).await.unwrap();
    assert_eq!(buf.len(), 1024);
    assert_eq!(buf.as_ref(), body.as_slice());
}

/// `measure_response_body_bounded` returns the size for an in-limit body.
#[tokio::test]
async fn test_measure_response_body_bounded_within_limit() {
    let server = MockServer::start().await;
    let body = vec![b'D'; 512];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let n = measure_response_body_bounded(resp, 1024).await.unwrap();
    assert_eq!(n, 512);
}

/// `measure_response_body_bounded` aborts when the running total exceeds the
/// limit.
#[tokio::test]
async fn test_measure_response_body_bounded_exceeds_limit() {
    let server = MockServer::start().await;
    let body = vec![b'E'; 4096];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let result = measure_response_body_bounded(resp, 1024).await;
    match result {
        Err(BoundedReadError::LimitExceeded {
            max_bytes,
            read_so_far,
        }) => {
            assert_eq!(max_bytes, 1024);
            assert!(read_so_far > 1024);
        }
        other => panic!("Expected LimitExceeded, got {:?}", other),
    }
}
