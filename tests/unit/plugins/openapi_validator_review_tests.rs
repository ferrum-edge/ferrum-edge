//! Regression tests for the `openapi_validator` production-launch review:
//! request parameter validation, multipart collection `contentType`, XML array
//! item names and whitespace, `format` assertions, charged decoding, operation
//! specificity, scope-list and plugin-scope admission, and declared
//! event-stream responses.

use chrono::Utc;
use ferrum_edge::_test_support::{
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, RESPONSE_DECODE_BROTLI_SCRATCH_BYTES,
    ResponseBufferBudgetProbe, openapi_validator_decode_body_in,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, openapi_validator::OpenapiValidator,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write as _;

use super::plugin_utils::{assert_continue, assert_reject};

fn content_type_headers(content_type: &str) -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), content_type.to_string())])
}

fn ctx_for(method: &str, path: &str) -> RequestContext {
    RequestContext::new("127.0.0.1".into(), method.into(), path.into())
}

fn request_error(ctx: &RequestContext) -> Option<&str> {
    ctx.metadata
        .get("openapi_validator.request_error")
        .map(String::as_str)
}

fn reject_body(result: PluginResult) -> Value {
    match result {
        PluginResult::Reject { body, .. } => serde_json::from_str(&body).expect("problem body"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

// ───────────────────────── parameters (SOL-4 / M2) ─────────────────────────

fn orders_parameter_config(mode: &str) -> Value {
    json!({
        "enforcement_mode": mode,
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "GET",
            "path_template": "/orders/{id}",
            "path_regex": "^/orders/[^/]+$",
            "parameters": [
                {"name": "id", "in": "path", "required": true,
                 "schema": {"type": "integer", "minimum": 1}},
                {"name": "X-Tenant-Id", "in": "header", "required": true,
                 "schema": {"type": "string", "pattern": "^[a-z0-9-]+$"}},
                {"name": "limit", "in": "query",
                 "schema": {"type": "integer", "maximum": 100}},
                {"name": "session", "in": "cookie",
                 "schema": {"type": "string", "minLength": 3}}
            ],
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    })
}

fn orders_ctx(path: &str, query: Option<&str>, tenant: Option<&str>) -> RequestContext {
    let mut ctx = ctx_for("GET", path);
    if let Some(query) = query {
        ctx.set_raw_query_string(query.to_string());
    }
    if let Some(tenant) = tenant {
        ctx.headers
            .insert("x-tenant-id".to_string(), tenant.to_string());
    }
    ctx
}

async fn run_before_proxy(plugin: &OpenapiValidator, ctx: &mut RequestContext) -> PluginResult {
    let mut headers = ctx.headers.clone();
    plugin.before_proxy(ctx, &mut headers).await
}

#[tokio::test]
async fn declared_parameters_admit_a_conforming_request() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();
    let mut ctx = orders_ctx("/orders/5", Some("limit=10"), Some("acme"));
    ctx.headers.insert(
        "cookie".to_string(),
        "theme=dark; session=abcdef".to_string(),
    );
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    // Optional parameters may be absent.
    let mut ctx = orders_ctx("/orders/5", None, Some("acme"));
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
}

#[tokio::test]
async fn invalid_path_parameter_is_rejected_without_echoing_the_value() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();
    for path in ["/orders/not-an-integer", "/orders/0"] {
        let mut ctx = orders_ctx(path, None, Some("acme"));
        let result = run_before_proxy(&plugin, &mut ctx).await;
        let body = reject_body(result);
        assert_eq!(body["status"], 400, "{path}");
        assert_eq!(body["title"], "Request parameter validation failed");
        let detail = request_error(&ctx).unwrap_or_default().to_string();
        assert!(detail.contains("path parameter 'id'"), "{detail}");
        assert!(!detail.contains("not-an-integer"), "{detail}");
    }
}

#[tokio::test]
async fn missing_required_header_parameter_is_rejected() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();
    let mut ctx = orders_ctx("/orders/5", None, None);
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
    assert_eq!(
        request_error(&ctx),
        Some("Required header parameter 'X-Tenant-Id' is missing")
    );
    // Header names match case-insensitively.
    let mut ctx = orders_ctx("/orders/5", None, None);
    ctx.headers
        .insert("X-TENANT-ID".to_string(), "acme".to_string());
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
}

#[tokio::test]
async fn query_parameter_constraints_and_repeats_are_enforced() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();
    let mut ctx = orders_ctx("/orders/5", Some("limit=1000000"), Some("acme"));
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
    let detail = request_error(&ctx).unwrap_or_default();
    assert!(detail.contains("query parameter 'limit'"), "{detail}");
    assert!(detail.contains("maximum"), "{detail}");
    assert!(!detail.contains("1000000"), "{detail}");

    // A scalar parameter that repeats is ambiguous (first vs last wins).
    let mut ctx = orders_ctx("/orders/5", Some("limit=1&limit=2"), Some("acme"));
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));

    // Percent-encoded names and values are decoded before matching.
    let mut ctx = orders_ctx("/orders/5", Some("%6Cimit=%31%30"), Some("acme"));
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    let mut ctx = orders_ctx("/orders/5", Some("limit=abc"), Some("acme"));
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
}

#[tokio::test]
async fn cookie_parameter_is_validated() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();
    let mut ctx = orders_ctx("/orders/5", None, Some("acme"));
    ctx.headers
        .insert("cookie".to_string(), "session=ab".to_string());
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("cookie parameter 'session'")
    );
}

fn wire_headers(pairs: &[(&'static str, &'static str)]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for &(name, value) in pairs {
        map.append(name, http::HeaderValue::from_static(value));
    }
    map
}

#[tokio::test]
async fn header_parameters_are_read_from_the_pristine_wire_headers() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();

    // An earlier before_proxy hook (e.g. a request_transformer with a lower
    // priority_override) ADDED the required header to the mutable map: the
    // client never sent it, so the request is still refused.
    let mut ctx = ctx_for("GET", "/orders/5");
    ctx.set_raw_headers(wire_headers(&[]));
    let mut transformed = HashMap::from([("x-tenant-id".to_string(), "acme".to_string())]);
    assert_reject(
        plugin.before_proxy(&mut ctx, &mut transformed).await,
        Some(400),
    );
    assert_eq!(
        request_error(&ctx),
        Some("Required header parameter 'X-Tenant-Id' is missing")
    );

    // An earlier hook REMOVED or rewrote an invalid client value: the client's
    // own value is what is validated.
    let mut ctx = ctx_for("GET", "/orders/5");
    ctx.set_raw_headers(wire_headers(&[("x-tenant-id", "NOT VALID")]));
    let mut transformed = HashMap::from([("x-tenant-id".to_string(), "acme".to_string())]);
    assert_reject(
        plugin.before_proxy(&mut ctx, &mut transformed).await,
        Some(400),
    );

    // Same for cookies.
    let mut ctx = ctx_for("GET", "/orders/5");
    ctx.set_raw_headers(wire_headers(&[
        ("x-tenant-id", "acme"),
        ("cookie", "session=ab"),
    ]));
    let mut transformed = HashMap::from([
        ("x-tenant-id".to_string(), "acme".to_string()),
        ("cookie".to_string(), "session=abcdef".to_string()),
    ]);
    assert_reject(
        plugin.before_proxy(&mut ctx, &mut transformed).await,
        Some(400),
    );

    // A conforming client request passes whatever the mutable map says, and
    // repeated cookie field lines are folded like the gateway folds them.
    let mut ctx = ctx_for("GET", "/orders/5");
    ctx.set_raw_headers(wire_headers(&[
        ("x-tenant-id", "acme"),
        ("cookie", "theme=dark"),
        ("cookie", "session=abcdef"),
    ]));
    let mut transformed = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut transformed).await);
}

#[tokio::test]
async fn cookie_parameters_are_percent_decoded_per_form_serialization() {
    let plugin = OpenapiValidator::new(&json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "GET", "path_template": "/c", "path_regex": "^/c$",
            "parameters": [
                {"name": "tag", "in": "cookie",
                 "schema": {"type": "string", "enum": ["a,b", "a+b"], "maxLength": 3}},
                {"name": "ids", "in": "cookie", "explode": false,
                 "schema": {"type": "array", "items": {"type": "string", "maxLength": 3}}}
            ]
        }]
    }))
    .unwrap();
    let run = |cookie: &str| {
        let mut ctx = ctx_for("GET", "/c");
        ctx.headers.insert("cookie".to_string(), cookie.to_string());
        ctx
    };
    for (cookie, accepted) in [
        ("tag=a%2Cb", true),
        ("tag=a+b", true),
        ("tag=a%2Bb", true),
        ("tag=a%2", false),
        ("tag=%zz", false),
        ("tag=%FF", false),
        // Delimiters are found before decoding: `%2C` stays inside one item.
        ("ids=a%2Cb,c", true),
        ("ids=a%2Cbc", false),
    ] {
        let mut ctx = run(cookie);
        let result = run_before_proxy(&plugin, &mut ctx).await;
        if accepted {
            assert_continue(result);
        } else {
            assert_reject(result, Some(400));
        }
    }
}

#[tokio::test]
async fn parameter_violations_follow_mode_and_validate_request() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("log_only")).unwrap();
    let mut ctx = orders_ctx("/orders/abc", None, Some("acme"));
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("logged_request_mismatch")
    );

    let mut config = orders_parameter_config("block");
    config["validate_request"] = json!(false);
    let plugin = OpenapiValidator::new(&config).unwrap();
    let mut ctx = orders_ctx("/orders/abc", None, None);
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
}

#[tokio::test]
async fn array_and_object_parameters_use_default_serializations() {
    let plugin = OpenapiValidator::new(&json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "GET",
            "path_template": "/search",
            "path_regex": "^/search$",
            "parameters": [
                {"name": "id", "in": "query",
                 "schema": {"type": "array", "maxItems": 2, "items": {"type": "integer"}}},
                {"name": "tag", "in": "query", "explode": false,
                 "schema": {"type": "array", "items": {"type": "string", "maxLength": 3}}},
                {"name": "x-dims", "in": "header", "explode": true,
                 "schema": {"type": "object", "required": ["w"],
                            "properties": {"w": {"type": "integer"}, "h": {"type": "integer"}}}}
            ],
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    }))
    .unwrap();

    let run = |query: &str, dims: Option<&str>| {
        let mut ctx = ctx_for("GET", "/search");
        ctx.set_raw_query_string(query.to_string());
        if let Some(dims) = dims {
            ctx.headers.insert("x-dims".to_string(), dims.to_string());
        }
        ctx
    };

    // form + explode: one item per occurrence.
    let mut ctx = run("id=1&id=2", None);
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    let mut ctx = run("id=1&id=2&id=3", None);
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
    let mut ctx = run("id=1&id=x", None);
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));

    // form + explode=false: comma-delimited on the wire spelling, so an
    // encoded `%2C` stays inside one item.
    let mut ctx = run("tag=ab,cd", None);
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    let mut ctx = run("tag=a%2Cb,c", None);
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    let mut ctx = run("tag=a%2Cbc", None);
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));

    // simple + explode object header: `name=value` members.
    let mut ctx = run("", Some("w=3, h=4"));
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    let mut ctx = run("", Some("h=4"));
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
    let mut ctx = run("", Some("w=wide"));
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
}

#[tokio::test]
async fn query_pair_scan_is_bounded_and_fails_closed() {
    let plugin = OpenapiValidator::new(&orders_parameter_config("block")).unwrap();
    let query = ["x=1"; 1025].join("&");
    let mut ctx = orders_ctx("/orders/5", Some(&query), Some("acme"));
    assert_reject(run_before_proxy(&plugin, &mut ctx).await, Some(400));
    assert_eq!(
        request_error(&ctx),
        Some("Request query string exceeds the parameter validation pair limit")
    );
    let query = ["x=1"; 1000].join("&");
    let mut ctx = orders_ctx("/orders/5", Some(&query), Some("acme"));
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
}

#[test]
fn parameter_only_operations_are_a_validation_rule() {
    let plugin = OpenapiValidator::new(&json!({
        "fail_on_unknown_operation": false,
        "operations": [{
            "method": "GET", "path_template": "/q", "path_regex": "^/q$",
            "parameters": [{"name": "q", "in": "query", "required": true,
                            "schema": {"type": "string"}}]
        }]
    }));
    assert!(plugin.is_ok(), "{:?}", plugin.err());
}

#[test]
fn unsupported_or_malformed_parameter_descriptors_are_refused_at_construction() {
    let base = |parameter: Value, template: &str| {
        json!({
            "operations": [{
                "method": "GET", "path_template": template, "path_regex": "^/x/[^/]+$",
                "parameters": [parameter],
                "responses": {"200": {"application/json": {"type": "object"}}}
            }]
        })
    };
    for (parameter, template, needle) in [
        (
            json!({"name": "f", "in": "query", "style": "deepObject",
                   "schema": {"type": "object"}}),
            "/x/{id}",
            "not supported",
        ),
        (
            json!({"name": "ids", "in": "query", "style": "pipeDelimited",
                   "schema": {"type": "array"}}),
            "/x/{id}",
            "not supported",
        ),
        (
            json!({"name": "f", "in": "query", "schema": {"type": "object"}}),
            "/x/{id}",
            "explode=true",
        ),
        (
            json!({"name": "id", "in": "path", "style": "matrix", "schema": {"type": "string"}}),
            "/x/{id}",
            "not supported",
        ),
        (
            json!({"name": "other", "in": "path", "schema": {"type": "string"}}),
            "/x/{id}",
            "path_template",
        ),
        (
            json!({"name": "id", "in": "path", "required": false, "schema": {"type": "string"}}),
            "/x/{id}",
            "must be true",
        ),
        (
            json!({"name": "Authorization", "in": "header", "schema": {"type": "string"}}),
            "/x/{id}",
            "ignores",
        ),
        (
            json!({"name": "q", "in": "body", "schema": {"type": "string"}}),
            "/x/{id}",
            "must be one of",
        ),
        (json!({"name": "q", "in": "query"}), "/x/{id}", "schema"),
        (
            json!({"name": "q", "in": "query", "schema": {"type": "string"},
                   "allowEmptyValue": true}),
            "/x/{id}",
            "allowEmptyValue",
        ),
        (
            json!({"name": "ids", "in": "query",
                   "schema": {"type": "array", "items": {"type": "array"}}}),
            "/x/{id}",
            "not supported",
        ),
    ] {
        let config = base(parameter.clone(), template);
        let error = match OpenapiValidator::new(&config) {
            Ok(_) => panic!("{parameter} must be refused"),
            Err(error) => error,
        };
        assert!(error.contains(needle), "{parameter}: {error}");
    }

    let duplicate = json!({
        "operations": [{
            "method": "GET", "path_template": "/x", "path_regex": "^/x$",
            "parameters": [
                {"name": "X-A", "in": "header", "schema": {"type": "string"}},
                {"name": "x-a", "in": "header", "schema": {"type": "string"}}
            ]
        }]
    });
    let error = match OpenapiValidator::new(&duplicate) {
        Ok(_) => panic!("duplicate header parameters must be refused"),
        Err(error) => error,
    };
    assert!(error.contains("more than once"), "{error}");
}

// ───────────────────── multipart collection contentType (SOL-1) ─────────────

fn multipart_body(part_content_type: Option<&str>, name: &str, value: &str) -> Vec<u8> {
    let mut body = format!("--abc\r\nContent-Disposition: form-data; name=\"{name}\"\r\n");
    if let Some(content_type) = part_content_type {
        body.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    body.push_str(&format!("\r\n{value}\r\n--abc--\r\n"));
    body.into_bytes()
}

#[tokio::test]
async fn serialized_multipart_collections_enforce_encoding_content_type() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST", "path_template": "/contract", "path_regex": "^/contract$",
            "request_body": {"content": {"multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "numbers": {"type": "array", "items": {"type": "integer"}},
                        "dims": {"type": "object", "properties": {"w": {"type": "integer"}}}
                    }
                },
                "encoding": {
                    "numbers": {"style": "form", "explode": false, "contentType": "text/plain"},
                    "dims": {"style": "form", "explode": false, "contentType": "text/plain"}
                }
            }}}
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    for (name, value, part_type, accepted) in [
        ("numbers", "1,2", Some("text/plain"), true),
        ("numbers", "1,2", None, true),
        ("numbers", "1,2", Some("application/json"), false),
        ("dims", "w,3", Some("text/plain"), true),
        ("dims", "w,3", Some("text/csv"), false),
    ] {
        let body = multipart_body(part_type, name, value);
        let mut ctx = ctx_for("POST", "/contract");
        ctx.headers = headers.clone();
        let result = plugin
            .validate_client_request_body_contract(&mut ctx, &headers, &body)
            .await;
        if accepted {
            assert_continue(result);
        } else {
            assert_reject(result, Some(400));
            assert!(
                request_error(&ctx)
                    .unwrap_or_default()
                    .contains("does not match encoding contentType"),
                "{name} {part_type:?}: {:?}",
                request_error(&ctx)
            );
        }
    }
}

// ───────────────────────── XML (SOL-2, SOL-3) ─────────────────────────

async fn assert_xml_both_directions(schema: &Value, body: &str, accepted: bool) {
    let plugin = OpenapiValidator::new(&json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST", "path_template": "/xml", "path_regex": "^/xml$",
            "request_body": {"content": {"application/xml": schema}},
            "responses": {"200": {"application/xml": schema}}
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/xml");
    let mut ctx = ctx_for("POST", "/xml");
    ctx.headers = headers.clone();
    let result = plugin
        .validate_client_request_body_contract(&mut ctx, &headers, body.as_bytes())
        .await;
    if accepted {
        assert_continue(result);
    } else {
        assert_reject(result, Some(400));
    }
    let mut ctx = ctx_for("POST", "/xml");
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body.as_bytes())
        .await;
    if accepted {
        assert_continue(result);
    } else {
        assert_reject(result, Some(502));
    }
}

#[tokio::test]
async fn directly_converted_xml_arrays_enforce_item_names_and_namespaces() {
    let schema = json!({
        "type": "array",
        "minItems": 1,
        "xml": {"name": "values", "wrapped": true},
        "items": {
            "type": "integer",
            "maximum": 10,
            "xml": {"name": "value", "namespace": "urn:trusted"}
        }
    });
    for (body, accepted) in [
        (
            r#"<values xmlns:t="urn:trusted"><t:value>1</t:value></values>"#,
            true,
        ),
        (
            r#"<values xmlns="urn:trusted"><value>1</value><value>2</value></values>"#,
            true,
        ),
        (
            r#"<values xmlns:e="urn:evil"><e:value>1</e:value></values>"#,
            false,
        ),
        ("<values><value>1</value></values>", false),
        (
            r#"<values xmlns:t="urn:trusted"><t:other>1</t:other></values>"#,
            false,
        ),
        ("<values><unmodeled>1</unmodeled></values>", false),
    ] {
        assert_xml_both_directions(&schema, body, accepted).await;
    }
    // Without a declared item name, the historical any-child behavior holds.
    let unnamed = json!({"type": "array", "xml": {"name": "values"}, "items": {"type": "integer"}});
    assert_xml_both_directions(&unnamed, "<values><anything>1</anything></values>", true).await;
}

#[tokio::test]
async fn xml_strings_are_validated_untrimmed_while_numbers_ignore_xml_whitespace() {
    let schema = json!({
        "type": "object",
        "xml": {"name": "record"},
        "properties": {
            "role": {"type": "string", "enum": ["user"], "maxLength": 4},
            "count": {"type": "integer", "maximum": 5},
            "code": {"type": "string", "xml": {"attribute": true}, "pattern": "^[A-Z]+$"}
        }
    });
    for (body, accepted) in [
        ("<record><role>user</role></record>", true),
        ("<record><role> user </role></record>", false),
        ("<record><role>\n  user\n</role></record>", false),
        ("<record><role>&#xA0;user&#xA0;</role></record>", false),
        ("<record><count> 3 </count></record>", true),
        ("<record><count>\n3\n</count></record>", true),
        ("<record><count>&#xA0;3</count></record>", false),
        (r#"<record code="ABC"/>"#, true),
        (r#"<record code=" ABC"/>"#, false),
    ] {
        assert_xml_both_directions(&schema, body, accepted).await;
    }
    // The reverse direction: a contract that requires surrounding spaces now
    // accepts its own valid representation.
    let padded = json!({
        "type": "object", "xml": {"name": "record"},
        "properties": {"role": {"type": "string", "enum": [" user "]}}
    });
    assert_xml_both_directions(&padded, "<record><role> user </role></record>", true).await;
    // Generic (schema-less) leaves keep exact character data too.
    let generic = json!({
        "type": "object", "xml": {"name": "record"},
        "properties": {},
        "not": {"required": ["note"], "properties": {"note": {"const": "x"}}}
    });
    assert_xml_both_directions(&generic, "<record><note>x</note></record>", false).await;
    assert_xml_both_directions(&generic, "<record><note> x </note></record>", true).await;
}

// ───────────────────────── format assertions (M1) ─────────────────────────

#[tokio::test]
async fn format_is_asserted_under_every_schema_draft() {
    for draft in ["draft2020-12", "auto", "draft7"] {
        let plugin = OpenapiValidator::new(&json!({
            "schema_draft": draft,
            "operations": [{
                "method": "POST", "path_template": "/f", "path_regex": "^/f$",
                "request_body": {"content": {"application/json": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "email": {"type": "string", "format": "email"},
                        "at": {"type": "string", "format": "date-time"},
                        "n": {"type": "integer", "format": "int64"}
                    }
                }}}
            }]
        }))
        .unwrap();
        let headers = content_type_headers("application/json");
        for (body, accepted) in [
            (
                r#"{"id":"0f8fad5b-d9cb-469f-a165-70867728950e","email":"a@example.com","at":"2026-10-24T12:00:00Z","n":3}"#,
                true,
            ),
            // `uuid` is a Draft 2019-09+ format; Draft 7 treats it as unknown.
            (r#"{"id":"not-a-uuid"}"#, draft == "draft7"),
            (r#"{"email":"not an email"}"#, false),
            (r#"{"at":"yesterday"}"#, false),
        ] {
            let mut ctx = ctx_for("POST", "/f");
            ctx.headers = headers.clone();
            let result = plugin
                .validate_client_request_body_contract(&mut ctx, &headers, body.as_bytes())
                .await;
            if accepted {
                assert_continue(result);
            } else {
                assert_reject(result, Some(400));
                assert!(
                    request_error(&ctx).unwrap_or_default().contains("format"),
                    "{draft} {body}: {:?}",
                    request_error(&ctx)
                );
            }
        }
    }
}

// ───────────────────────── charged decoding (M3) ─────────────────────────

#[test]
fn body_decoding_is_charged_to_the_decode_budget_and_released() {
    let plaintext = br#"{"name":"book"}"#.to_vec();
    let encoded = gzip_bytes(&plaintext);

    // One reservation block cannot hold the gzip decoder's own heap, so the
    // decode is refused as CAPACITY (not as a representation error) before any
    // decoder is constructed.
    let tight = ResponseBufferBudgetProbe::new(UNIT, UNIT);
    assert_eq!(
        openapi_validator_decode_body_in(&tight, Some("gzip"), &encoded, 1024 * 1024),
        Err(None)
    );
    assert_eq!(
        tight.available_bytes(),
        UNIT,
        "a refused decode holds nothing"
    );

    // Identity bodies never touch the budget.
    assert_eq!(
        openapi_validator_decode_body_in(&tight, Some("identity"), &plaintext, 1024 * 1024),
        Ok((plaintext.clone(), UNIT))
    );

    let generous =
        ResponseBufferBudgetProbe::new(UNIT, RESPONSE_DECODE_BROTLI_SCRATCH_BYTES + 64 * UNIT);
    let total = generous.available_bytes();
    let (decoded, available_while_held) =
        openapi_validator_decode_body_in(&generous, Some("gzip"), &encoded, 1024 * 1024)
            .expect("gzip body decodes");
    assert_eq!(decoded, plaintext);
    // The surviving plaintext stays charged while it is inspected (one block
    // covers this small body); only the transient decoder working set is
    // returned before inspection.
    assert_eq!(
        available_while_held,
        total - UNIT,
        "decoded plaintext must stay charged during inspection"
    );
    assert_eq!(
        generous.available_bytes(),
        total,
        "the plaintext's charge is released when inspection ends"
    );

    // Representation faults keep the fixed, payload-free category.
    assert_eq!(
        openapi_validator_decode_body_in(&generous, Some("zstd"), b"x", 1024),
        Err(Some("Content-Encoding could not be decoded".to_string()))
    );
    assert_eq!(
        openapi_validator_decode_body_in(&generous, Some("gzip"), b"not-gzip", 1024),
        Err(Some("Content-Encoding could not be decoded".to_string()))
    );
}

// ───────────────────── operation specificity (M4) ─────────────────────

#[tokio::test]
async fn overlapping_templates_order_by_segment_specificity_not_labels() {
    let config = json!({
        "operations": [
            {
                "method": "GET",
                "path_template": "/{tenant}/admin/settings",
                "path_regex": "^/[^/]+/admin/settings$",
                "operation_label": "a-very-long-label-that-used-to-win-the-tie-break",
                "responses": {"200": {"application/json": {"type": "object"}}}
            },
            {
                "method": "GET",
                "path_template": "/users/{id}/settings",
                "path_regex": "^/users/[^/]+/settings$",
                "operation_label": "users",
                "responses": {"200": {"application/json": {"type": "object"}}}
            }
        ]
    });
    let mut reversed = config.clone();
    reversed["operations"].as_array_mut().unwrap().reverse();
    for config in [config, reversed] {
        let plugin = OpenapiValidator::new(&config).unwrap();
        let mut ctx = ctx_for("GET", "/users/admin/settings");
        assert_continue(run_before_proxy(&plugin, &mut ctx).await);
        assert_eq!(
            ctx.metadata
                .get("openapi_validator.matched_operation")
                .map(String::as_str),
            Some("users"),
            "the leftmost literal segment wins regardless of labels and document order"
        );
        // The other template still serves paths only it matches.
        let mut ctx = ctx_for("GET", "/acme/admin/settings");
        assert_continue(run_before_proxy(&plugin, &mut ctx).await);
        assert_eq!(
            ctx.metadata
                .get("openapi_validator.matched_operation")
                .map(String::as_str),
            Some("a-very-long-label-that-used-to-win-the-tie-break")
        );
    }
}

#[test]
fn duplicate_method_and_path_regex_operations_are_refused() {
    let operation = json!({
        "method": "GET", "path_template": "/a", "path_regex": "^/a$",
        "responses": {"200": {"application/json": {"type": "object"}}}
    });
    let mut lowercase = operation.clone();
    lowercase["method"] = json!("get");
    let error = match OpenapiValidator::new(&json!({"operations": [operation, lowercase]})) {
        Ok(_) => panic!("duplicate operations must be refused"),
        Err(error) => error,
    };
    assert!(error.contains("same path_regex"), "{error}");
}

#[tokio::test]
async fn pinned_operation_survives_a_later_path_rewrite() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET", "path_template": "/items", "path_regex": "^/items$",
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    }))
    .unwrap();
    let mut ctx = ctx_for("GET", "/items");
    assert_continue(run_before_proxy(&plugin, &mut ctx).await);
    // A before_proxy rewrite changes the path; every later predicate reads the
    // pinned operation instead of re-matching.
    ctx.path = "/rewritten".to_string();
    assert!(plugin.should_buffer_response_body(&ctx));
    let headers = content_type_headers("application/json");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"[]")
            .await,
        Some(502),
    );
}

// ───────────────────── scope lists and plugin scope (M5, M6) ─────────────────

#[test]
fn empty_content_type_scope_lists_are_refused() {
    for field in ["request_content_types", "response_content_types"] {
        let config = json!({
            field: [],
            "operations": [{
                "method": "POST", "path_template": "/a", "path_regex": "^/a$",
                "request_body": {"content": {"application/json": {"type": "object"}}}
            }]
        });
        let error = match OpenapiValidator::new(&config) {
            Ok(_) => panic!("empty {field} must be refused"),
            Err(error) => error,
        };
        assert!(
            error.contains(field) && error.contains("must not be empty"),
            "{error}"
        );
    }
}

fn validator_plugin_config(scope: PluginScope, proxy_id: Option<&str>) -> PluginConfig {
    PluginConfig {
        id: "ov1".to_string(),
        labels: Default::default(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "openapi_validator".to_string(),
        config: json!({"operations": []}),
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn non_proxy_scoped_validators_are_refused_by_shared_config_validation() {
    for scope in [PluginScope::Global, PluginScope::ProxyGroup] {
        let plugin = validator_plugin_config(scope, None);
        let field_errors = plugin
            .validate_fields()
            .expect_err("admin/field validation");
        assert!(
            field_errors
                .iter()
                .any(|error| error.contains("openapi_validator must have scope `proxy`")),
            "{field_errors:?}"
        );
        let config = GatewayConfig {
            version: "1".to_string(),
            plugin_configs: vec![plugin],
            loaded_at: Utc::now(),
            ..Default::default()
        };
        let load_errors = config
            .validate_plugin_references()
            .expect_err("full-config load validation");
        assert!(
            load_errors
                .iter()
                .any(|error| error.contains("(openapi_validator) must have scope `proxy`")),
            "{load_errors:?}"
        );
    }
    assert!(
        validator_plugin_config(PluginScope::Proxy, Some("p1"))
            .validate_fields()
            .is_ok()
    );
}

// ───────────────────── declared event streams (M8) ─────────────────────

#[tokio::test]
async fn declared_event_stream_responses_are_released_while_undeclared_ones_fail_closed() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST", "path_template": "/chat", "path_regex": "^/chat$",
            "request_body": {"content": {"application/json": {
                "type": "object", "required": ["prompt"]
            }}},
            "responses": {
                "200": {"text/event-stream": {}, "application/json": {"type": "object"}},
                "default": {"application/json": {"type": "object"}}
            }
        }]
    }))
    .unwrap();
    let mut ctx = ctx_for("POST", "/chat");
    let mut response_headers = content_type_headers("text/event-stream");
    assert!(plugin.should_buffer_response_body(&ctx));
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("event_stream_declared")
    );

    // The `default` response object declares no event stream.
    let mut ctx = ctx_for("POST", "/chat");
    let mut response_headers = content_type_headers("text/event-stream");
    assert_reject(
        plugin
            .after_proxy(&mut ctx, 500, &mut response_headers)
            .await,
        Some(502),
    );

    // The buffered / synthetic final-body path applies the same exemption,
    // even with a schema that raw SSE text could never satisfy.
    let strict = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET", "path_template": "/events", "path_regex": "^/events$",
            "responses": {
                "200": {"text/event-stream": {"type": "object"},
                        "application/json": {"type": "object"}},
                "default": {"application/json": {"type": "object"}}
            }
        }]
    }))
    .unwrap();
    let sse_body = b"data: {\"ok\":true}\n\n";
    let sse_headers = content_type_headers("text/event-stream");
    let mut ctx = ctx_for("GET", "/events");
    assert_continue(
        strict
            .on_final_response_body(&mut ctx, 200, &sse_headers, sse_body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("event_stream_declared")
    );
    // A relabeled (non-SSE) final representation is validated normally.
    let mut ctx = ctx_for("GET", "/events");
    assert_reject(
        strict
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/json"),
                b"[]",
            )
            .await,
        Some(502),
    );
    // A status whose response object does not declare SSE is not exempted.
    let mut ctx = ctx_for("GET", "/events");
    let _ = strict
        .on_final_response_body(&mut ctx, 500, &sse_headers, sse_body)
        .await;
    assert_ne!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("event_stream_declared")
    );

    // Request-side validation on the same operation still blocks.
    let headers = content_type_headers("application/json");
    let mut ctx = ctx_for("POST", "/chat");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .validate_client_request_body_contract(&mut ctx, &headers, b"{}")
            .await,
        Some(400),
    );
}

#[test]
fn declared_event_stream_release_never_survives_a_later_content_type_relabel() {
    use ferrum_edge::_test_support::{
        refine_stream_response_for_content_type_for_test, retry_response_decision_context_for_test,
        stamp_original_response_metadata_for_test,
    };
    use ferrum_edge::plugins::response_transformer::ResponseTransformer;
    use std::sync::Arc;

    let validator = |declared: bool| -> Arc<dyn Plugin> {
        let mut ok = json!({"application/json": {"type": "object"}});
        if declared {
            ok["text/event-stream"] = json!({});
        }
        Arc::new(
            OpenapiValidator::new(&json!({
                "operations": [{
                    "method": "GET", "path_template": "/events", "path_regex": "^/events$",
                    "responses": {"200": ok}
                }]
            }))
            .unwrap(),
        )
    };
    // A header-only transformer that relabels the stream as JSON. It casts no
    // buffering vote of its own.
    let relabel: Arc<dyn Plugin> = Arc::new(
        ResponseTransformer::new(&json!({"rules": [{
            "operation": "update", "target": "header",
            "key": "content-type", "value": "application/json"
        }]}))
        .unwrap(),
    );
    let proxy = super::plugin_utils::create_test_proxy();
    let sse = content_type_headers("text/event-stream");
    let ctx = ctx_for("GET", "/events");
    let retry_ctx = retry_response_decision_context_for_test(&ctx);

    for decision_ctx in [&ctx, &retry_ctx] {
        // Declared SSE with nothing that can relabel it: streams, unvalidated.
        assert!(refine_stream_response_for_content_type_for_test(
            &proxy,
            &[validator(true)],
            decision_ctx,
            200,
            &sse,
        ));
        // Declared SSE that a later hook relabels to JSON: the declared-SSE
        // admission must not release it, so it stays buffered and the final
        // body is validated against the JSON contract.
        assert!(
            !refine_stream_response_for_content_type_for_test(
                &proxy,
                &[validator(true), relabel.clone()],
                decision_ctx,
                200,
                &sse,
            ),
            "a relabeled declared event stream must stay buffered"
        );
    }

    // Undeclared SSE keeps its label-independent release: it is refused in
    // after_proxy whatever a later hook does to the label.
    assert!(refine_stream_response_for_content_type_for_test(
        &proxy,
        &[validator(false), relabel],
        &ctx,
        200,
        &sse,
    ));

    // The predicates themselves, over a backend response stamped as SSE.
    let declared = validator(true);
    let mut stamped = ctx_for("GET", "/events");
    stamp_original_response_metadata_for_test(&mut stamped, 200, &sse);
    assert!(
        !declared.should_release_response_body_before_content_type_rewrite(&stamped, 200, &sse)
    );
    assert!(declared.should_release_response_body_under_retries(&stamped, 200, &sse));
    // At a decision point where an earlier hook already relabeled the original
    // event stream as JSON, the declared-SSE release is withheld.
    let json_now = content_type_headers("application/json");
    assert!(!declared.should_release_response_body_under_retries(&stamped, 200, &json_now));
}
