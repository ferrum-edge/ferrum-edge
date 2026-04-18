//! Tests for body_validator plugin — XML CDATA, comments, processing instructions

use ferrum_edge::plugins::{Plugin, RequestContext, body_validator::BodyValidator};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject};

fn make_xml_ctx(body: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/xml".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/xml".to_string());
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    ctx
}

fn make_xml_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/xml".to_string());
    headers
}

fn make_json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

fn xml_plugin() -> BodyValidator {
    BodyValidator::new(&json!({
        "validate_xml": true
    }))
    .unwrap()
}

fn xml_plugin_with_required(elements: Vec<&str>) -> BodyValidator {
    BodyValidator::new(&json!({
        "validate_xml": true,
        "required_xml_elements": elements
    }))
    .unwrap()
}

#[test]
fn test_request_vs_response_buffering_flags_are_config_sensitive() {
    let request_plugin = BodyValidator::new(&json!({"validate_xml": true})).unwrap();
    assert!(request_plugin.requires_request_body_buffering());
    assert!(!request_plugin.requires_response_body_buffering());

    let response_only = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    assert!(!response_only.requires_request_body_buffering());
    assert!(response_only.requires_response_body_buffering());
}

#[test]
fn test_request_body_buffering_only_for_matching_request_methods_and_types() {
    let plugin = BodyValidator::new(&json!({"validate_xml": true})).unwrap();

    let xml_ctx = make_xml_ctx("<root/>");
    assert!(plugin.should_buffer_request_body(&xml_ctx));

    let mut get_ctx = make_xml_ctx("<root/>");
    get_ctx.method = "GET".to_string();
    assert!(!plugin.should_buffer_request_body(&get_ctx));

    let mut json_only_ctx = make_xml_ctx("<root/>");
    json_only_ctx.headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );
    assert!(!plugin.should_buffer_request_body(&json_only_ctx));
}

#[test]
fn test_trait_object_dispatches_request_body_buffering_hooks() {
    let plugin: std::sync::Arc<dyn Plugin> =
        std::sync::Arc::new(BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());

    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.should_buffer_request_body(&ctx));
}

// ─── Basic XML Validation ──────────────────────────────────────────────

#[tokio::test]
async fn test_xml_simple_valid() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item>text</item></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_tag() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// Regression: self-closing tags with whitespace before `/` (`<br />`,
// `<input attr="v" />`, `<foo\n/>`) were previously rejected as unbalanced
// because the `/` detection only looked at the byte immediately before `>`.
#[tokio::test]
async fn test_xml_self_closing_with_space_before_slash() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br /></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_with_attr_and_whitespace() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx(r#"<root><img src="x.png" alt="" /></root>"#);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_with_newline_before_slash() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br\n/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_with_tab_before_slash() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br\t/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_unbalanced_tags_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── CDATA Handling ────────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_cdata_with_fake_tags() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[This contains <fake> tags and </closing>]]></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_cdata_empty() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[]]></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_cdata_with_special_chars() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[<>&\"' special chars]]></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_multiple_cdata_sections() {
    let plugin = xml_plugin();
    let body =
        "<root><a><![CDATA[first <section>]]></a><b><![CDATA[second </section>]]></b></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Comment Handling ──────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_comment_with_fake_tags() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><!-- comment with <fake> tags --></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_comment_between_elements() {
    let plugin = xml_plugin();
    let body = "<root><a>text</a><!-- between --><b>more</b></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_comment_empty() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><!----></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Processing Instructions ───────────────────────────────────────────

#[tokio::test]
async fn test_xml_processing_instruction() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<?xml version=\"1.0\"?>\n<root>content</root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_processing_instruction_with_encoding() {
    let plugin = xml_plugin();
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><item>text</item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── DOCTYPE Declarations ──────────────────────────────────────────────

#[tokio::test]
async fn test_xml_doctype_declaration() {
    let plugin = xml_plugin();
    let body = "<!DOCTYPE root>\n<root>content</root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Combined / Mixed Content ──────────────────────────────────────────

#[tokio::test]
async fn test_xml_mixed_cdata_and_comments() {
    let plugin = xml_plugin();
    let body = r#"<?xml version="1.0"?>
<root>
  <!-- header comment -->
  <item><![CDATA[data with <tags>]]></item>
  <!-- footer comment -->
  <other>text</other>
</root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_all_constructs() {
    let plugin = xml_plugin();
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<root>
  <!-- A comment -->
  <item attr="value"><![CDATA[Some <data>]]></item>
  <empty/>
  <?custom-pi param="value"?>
  <nested>
    <deep><!-- inner comment --></deep>
  </nested>
</root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Required Elements with Special Constructs ─────────────────────────

#[tokio::test]
async fn test_xml_required_element_with_cdata() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = "<root><item><![CDATA[content <here>]]></item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_required_element_missing() {
    let plugin = xml_plugin_with_required(vec!["missing"]);
    let body = "<root><item>content</item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Edge Cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_empty_body_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("");
    let mut headers = make_xml_headers();
    // Empty body is skipped (returns Continue) because the body.is_empty() check
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_not_starting_with_angle_bracket() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("not xml at all");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_get_request_skipped() {
    let plugin = xml_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/xml".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/xml".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not valid xml".to_string());
    let mut headers = make_xml_headers();
    // GET requests are skipped
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ═══════════════════════════════════════════════════════════════════════
//  JSON Schema Validation Tests
// ═══════════════════════════════════════════════════════════════════════

fn make_json_ctx(body: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/json".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    ctx
}

fn json_schema_plugin(schema: serde_json::Value) -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "json_schema": schema
    }))
    .unwrap()
}

// ─── Type validation ──────────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_type_object_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_json_ctx(r#"{"key": "value"}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_object_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_json_ctx(r#"[1, 2, 3]"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_type_string_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string"}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_integer_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer"}));
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_integer_rejects_float() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer"}));
    let mut ctx = make_json_ctx("3.14");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── String constraints ──────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_min_length_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_min_length_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 10}));
    let mut ctx = make_json_ctx(r#""hi""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_max_length_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 5}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_max_length_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_min_max_length_counts_code_points_not_bytes() {
    // "日本語" is 3 code points but 9 UTF-8 bytes. Per JSON Schema §6.3,
    // minLength/maxLength count characters (code points), not bytes.
    let plugin =
        json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3, "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""日本語""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // 2 code points fails minLength:3
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3}));
    let mut ctx = make_json_ctx(r#""日本""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    // 4 code points fails maxLength:3
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""日本語x""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_pattern_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_pattern_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}));
    let mut ctx = make_json_ctx(r#""Hello123""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Numeric constraints ─────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_minimum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "minimum": 0}));
    let mut ctx = make_json_ctx("5");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_minimum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "minimum": 10}));
    let mut ctx = make_json_ctx("5");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_maximum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "maximum": 100}));
    let mut ctx = make_json_ctx("50");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_maximum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "maximum": 10}));
    let mut ctx = make_json_ctx("50");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_exclusive_minimum() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "exclusiveMinimum": 5}));
    let mut ctx = make_json_ctx("5");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_exclusive_maximum() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "exclusiveMaximum": 10}));
    let mut ctx = make_json_ctx("10");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Enum constraint ─────────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_enum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"enum": ["red", "green", "blue"]}));
    let mut ctx = make_json_ctx(r#""green""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_enum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"enum": ["red", "green", "blue"]}));
    let mut ctx = make_json_ctx(r#""yellow""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Array constraints ───────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_array_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "array",
        "items": {"type": "integer"}
    }));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_array_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "array",
        "items": {"type": "integer"}
    }));
    let mut ctx = make_json_ctx(r#"[1, "two", 3]"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_min_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "minItems": 2}));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_min_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "minItems": 5}));
    let mut ctx = make_json_ctx("[1, 2]");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_max_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "maxItems": 3}));
    let mut ctx = make_json_ctx("[1, 2]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_max_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "maxItems": 2}));
    let mut ctx = make_json_ctx("[1, 2, 3, 4]");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_unique_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_unique_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx("[1, 2, 2, 3]");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Object constraints ──────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_additional_properties_false() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "additionalProperties": false
    }));
    let mut ctx = make_json_ctx(r#"{"name": "test", "extra": 123}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_additional_properties_false_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "additionalProperties": false
    }));
    let mut ctx = make_json_ctx(r#"{"name": "test"}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_required_and_properties() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["name", "age"],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "age": {"type": "integer", "minimum": 0, "maximum": 150}
        }
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice", "age": 30}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_required_missing() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["name", "age"]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice"}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_nested_property_validation() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "address": {
                "type": "object",
                "required": ["city"],
                "properties": {
                    "city": {"type": "string", "minLength": 1},
                    "zip": {"type": "string", "pattern": "^[0-9]{5}$"}
                }
            }
        }
    }));
    let mut ctx = make_json_ctx(r#"{"address": {"city": "NYC", "zip": "10001"}}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_nested_property_invalid_zip() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "address": {
                "type": "object",
                "properties": {
                    "zip": {"type": "string", "pattern": "^[0-9]{5}$"}
                }
            }
        }
    }));
    let mut ctx = make_json_ctx(r#"{"address": {"zip": "abc"}}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Composition: allOf / anyOf / oneOf / not ─────────────────────────

#[tokio::test]
async fn test_json_schema_all_of_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "allOf": [
            {"type": "object", "required": ["name"]},
            {"type": "object", "required": ["age"]}
        ]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice", "age": 30}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_all_of_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "allOf": [
            {"type": "object", "required": ["name"]},
            {"type": "object", "required": ["age"]}
        ]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice"}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_any_of_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "anyOf": [
            {"type": "string"},
            {"type": "integer"}
        ]
    }));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_any_of_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "anyOf": [
            {"type": "string"},
            {"type": "integer"}
        ]
    }));
    let mut ctx = make_json_ctx("true");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_one_of_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "oneOf": [
            {"type": "string"},
            {"type": "integer"}
        ]
    }));
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_one_of_multiple_match_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "oneOf": [
            {"type": "number"},
            {"type": "integer"}
        ]
    }));
    // integer 42 matches both "number" and "integer" type schemas
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_not_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "not": {"type": "string"}
    }));
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_not_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "not": {"type": "string"}
    }));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Format validation ───────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_format_email_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "email"}));
    let mut ctx = make_json_ctx(r#""user@example.com""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_email_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "email"}));
    let mut ctx = make_json_ctx(r#""not-an-email""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_format_ipv4_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "ipv4"}));
    let mut ctx = make_json_ctx(r#""192.168.1.1""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_ipv4_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "ipv4"}));
    let mut ctx = make_json_ctx(r#""999.999.999.999""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_format_uuid_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "uuid"}));
    let mut ctx = make_json_ctx(r#""550e8400-e29b-41d4-a716-446655440000""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_datetime_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "date-time"}));
    let mut ctx = make_json_ctx(r#""2024-01-15T10:30:00Z""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Complex real-world schema ───────────────────────────────────────

#[tokio::test]
async fn test_json_schema_complex_api_payload() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["method", "params"],
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
            "params": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 1},
                    "timeout": {"type": "integer", "minimum": 0, "maximum": 30000},
                    "headers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "value"],
                            "properties": {
                                "name": {"type": "string"},
                                "value": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    }));
    let mut ctx = make_json_ctx(
        r#"{"method": "POST", "params": {"url": "/api/data", "timeout": 5000, "headers": [{"name": "X-Custom", "value": "test"}]}}"#,
    );
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Pre-compiled regex pattern reuse ─────────────────────────────────

#[tokio::test]
async fn test_json_schema_pattern_pre_compiled_reuse() {
    // Create a plugin with a pattern constraint — the regex is pre-compiled at config time
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "string",
        "pattern": "^[A-Z]{3}-[0-9]{4}$"
    }));

    // First request: matching pattern
    let mut ctx1 = make_json_ctx(r#""ABC-1234""#);
    let mut headers1 = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx1, &mut headers1).await);

    // Second request: non-matching pattern (implicitly exercises the same pre-compiled regex)
    let mut ctx2 = make_json_ctx(r#""invalid""#);
    let mut headers2 = make_json_headers();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(400),
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Response Body Validation Tests
// ═══════════════════════════════════════════════════════════════════════

fn make_response_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/data".to_string(),
    )
}

fn response_json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn response_xml_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/xml".to_string());
    h
}

fn response_schema_plugin(schema: serde_json::Value) -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "response_json_schema": schema
    }))
    .unwrap()
}

// ─── requires_response_body_buffering ─────────────────────────────────

#[test]
fn test_response_buffering_required_when_response_schema_configured() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_response_buffering_required_when_response_required_fields() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_response_buffering_not_required_when_only_request_validation() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "json_schema": {"type": "object"}
    }))
    .unwrap();
    assert!(!plugin.requires_response_body_buffering());
}

// ─── Response JSON Schema Validation ──────────────────────────────────

#[tokio::test]
async fn test_response_json_schema_valid() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"}
        }
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"id": 1, "name": "Alice"}"#;
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_json_schema_missing_required_field() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["id", "name"]
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"id": 1}"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_json_schema_wrong_type() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"[1, 2, 3]"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_json_invalid_json() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = b"not json at all";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_json_empty_body_skipped() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"")
            .await,
    );
}

#[tokio::test]
async fn test_response_json_non_matching_content_type_skipped() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let body = b"not json";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

// ─── Response Required Fields ─────────────────────────────────────────

#[tokio::test]
async fn test_response_required_fields_valid() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_required_fields": ["status", "data"]
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"status": "ok", "data": []}"#;
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_required_fields_missing() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_required_fields": ["status", "data"]
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"status": "ok"}"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

// ─── Response XML Validation ──────────────────────────────────────────

#[tokio::test]
async fn test_response_xml_valid() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_validate_xml": true
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><item>text</item></root>";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_xml_invalid() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_validate_xml": true
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><item></root>";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_xml_required_elements() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_validate_xml": true,
        "response_required_xml_elements": ["result"]
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><data>text</data></root>";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

// ─── Combined Request + Response Validation ───────────────────────────

#[tokio::test]
async fn test_both_request_and_response_validation() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "json_schema": {"type": "object", "required": ["action"]},
        "response_json_schema": {"type": "object", "required": ["result"]}
    }))
    .unwrap();

    // Request validation still works
    let mut req_ctx = make_json_ctx(r#"{"action": "create"}"#);
    let mut req_headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut req_ctx, &mut req_headers).await);

    // Request with missing field is rejected (400)
    let mut bad_req_ctx = make_json_ctx(r#"{"other": "value"}"#);
    let mut bad_req_headers = make_json_headers();
    assert_reject(
        plugin
            .before_proxy(&mut bad_req_ctx, &mut bad_req_headers)
            .await,
        Some(400),
    );

    // Response validation works
    let mut resp_ctx = make_response_ctx();
    let resp_headers = response_json_headers();
    assert_continue(
        plugin
            .on_final_response_body(&mut resp_ctx, 200, &resp_headers, br#"{"result": "ok"}"#)
            .await,
    );

    // Response with missing field is rejected (502)
    assert_reject(
        plugin
            .on_final_response_body(&mut resp_ctx, 200, &resp_headers, br#"{"other": "value"}"#)
            .await,
        Some(502),
    );

    // Buffering is required because response validation is configured
    assert!(plugin.requires_response_body_buffering());
}

// ─── Response schema with pattern (pre-compiled regex) ────────────────

#[tokio::test]
async fn test_response_json_schema_pattern_valid() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "code": {"type": "string", "pattern": "^[A-Z]{3}-[0-9]+$"}
        }
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"code": "ABC-123"}"#;
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_json_schema_pattern_invalid() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "code": {"type": "string", "pattern": "^[A-Z]{3}-[0-9]+$"}
        }
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"code": "invalid"}"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

// ─── Response with no validation configured skips ─────────────────────

#[tokio::test]
async fn test_response_no_validation_skips() {
    // Only request validation configured — response body should pass through
    let plugin = BodyValidator::new(&serde_json::json!({
        "json_schema": {"type": "object"}
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = b"totally invalid json!!!";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

// ════════════════════════════════════��══════════════════════════════════
//  Protobuf Validation Tests (gRPC)
// ══════════════════��═════════════════════════════��══════════════════════

/// Path to the test descriptor file compiled from test_validator.proto.
fn test_descriptor_path() -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/tests/fixtures/test_validator.bin", manifest_dir)
}

/// Build a gRPC length-prefixed frame: [0x00] [4-byte big-endian length] [payload].
fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0); // not compressed
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Encode a valid HelloRequest protobuf using prost-reflect.
fn encode_hello_request(name: &str, age: i32) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let descriptor_bytes = std::fs::read(test_descriptor_path()).unwrap();
    let pool = DescriptorPool::decode(descriptor_bytes.as_slice()).unwrap();
    let msg_desc = pool.get_message_by_name("test.HelloRequest").unwrap();
    let mut msg = DynamicMessage::new(msg_desc);
    msg.set_field_by_name("name", Value::String(name.to_string()));
    msg.set_field_by_name("age", Value::I32(age));
    msg.encode_to_vec()
}

/// Encode a valid HelloResponse protobuf using prost-reflect.
fn encode_hello_response(message: &str, success: bool) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let descriptor_bytes = std::fs::read(test_descriptor_path()).unwrap();
    let pool = DescriptorPool::decode(descriptor_bytes.as_slice()).unwrap();
    let msg_desc = pool.get_message_by_name("test.HelloResponse").unwrap();
    let mut msg = DynamicMessage::new(msg_desc);
    msg.set_field_by_name("message", Value::String(message.to_string()));
    msg.set_field_by_name("success", Value::Bool(success));
    msg.encode_to_vec()
}

fn protobuf_plugin() -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "protobuf_response_type": "test.HelloResponse"
    }))
    .unwrap()
}

fn protobuf_plugin_with_method_messages() -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_method_messages": {
            "/test.Greeter/SayHello": {
                "request": "test.HelloRequest",
                "response": "test.HelloResponse"
            }
        }
    }))
    .unwrap()
}

fn protobuf_plugin_reject_unknown() -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "protobuf_reject_unknown_fields": true
    }))
    .unwrap()
}

// ─── Config and Buffering Flags ─��───────────────────────────────────

#[test]
fn test_protobuf_config_sets_validation_flags() {
    let plugin = protobuf_plugin();
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_protobuf_request_only_config() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest"
    }))
    .unwrap();
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[test]
fn test_protobuf_response_only_config() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_response_type": "test.HelloResponse"
    }))
    .unwrap();
    assert!(!plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_protobuf_should_buffer_grpc_content_type() {
    let plugin = protobuf_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_protobuf_should_buffer_grpc_proto_content_type() {
    let plugin = protobuf_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    );
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_protobuf_does_not_buffer_non_matching_content_types() {
    // Protobuf-only config with content_types restricted to gRPC
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "content_types": ["application/grpc"]
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/json".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // JSON content-type doesn't match the explicit content_types list
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ─── gRPC Frame Parsing ───────��──────────────────────────────────────

#[tokio::test]
async fn test_protobuf_valid_request() {
    let plugin = protobuf_plugin();
    let payload = encode_hello_request("Alice", 30);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_invalid_request_body() {
    let plugin = protobuf_plugin();
    // Random bytes that are not valid protobuf for HelloRequest
    let invalid_payload = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
    let frame = grpc_frame(&invalid_payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_frame_too_short() {
    let plugin = protobuf_plugin();
    let frame = vec![0x00, 0x01]; // Only 2 bytes, need at least 5
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_frame_length_mismatch() {
    let plugin = protobuf_plugin();
    // Frame says 100 bytes but only has 3
    let mut frame = vec![0x00]; // not compressed
    frame.extend_from_slice(&100u32.to_be_bytes());
    frame.extend_from_slice(&[0x01, 0x02, 0x03]);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_frame_valid() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = protobuf_plugin();
    let payload = encode_hello_request("Bob", 25);
    // Compress with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();
    // Build frame with compressed flag = 1
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1); // compressed flag
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_compressed_invalid_gzip_data_rejected() {
    let plugin = protobuf_plugin();
    // Not valid gzip — just raw protobuf bytes with compressed flag set
    let payload = encode_hello_request("Bob", 25);
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(1); // compressed flag = 1
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_invalid_protobuf_rejected() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = protobuf_plugin();
    // Compress garbage bytes that aren't valid protobuf
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"\xff\xff\xff\xff").unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_response_valid() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = protobuf_plugin();
    let payload = encode_hello_response("Hi Bob!", true);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &frame)
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_empty_body_skipped() {
    let plugin = protobuf_plugin();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &[]).await);
}

#[tokio::test]
async fn test_protobuf_non_grpc_content_type_skipped() {
    let plugin = protobuf_plugin();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        plugin
            .on_final_request_body(&headers, b"not protobuf")
            .await,
    );
}

// ─── Method-based Message Type Routing ──────────────────────────────

#[tokio::test]
async fn test_protobuf_method_message_lookup() {
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_request("Charlie", 40);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_unknown_method_skipped_when_no_default() {
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_request("Charlie", 40);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(
        ":path".to_string(),
        "/test.Greeter/UnknownMethod".to_string(),
    );
    // No default type and method not in map — skip validation
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_unknown_method_uses_default_type() {
    let plugin = protobuf_plugin();
    let payload = encode_hello_request("Dave", 50);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/AnyMethod".to_string());
    // Default type is configured, so validation runs
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

// Regression: response-side per-method descriptor lookup must use the request
// path from `ctx.path` (or `grpc_full_method` metadata) — not the response
// headers, which never carry `:path`. Previously the lookup always failed and
// silently fell back to the global default, causing per-method
// `protobuf_method_messages` for response validation to be ignored entirely.
#[tokio::test]
async fn test_protobuf_response_per_method_descriptor_resolved_from_ctx_path() {
    // No global `protobuf_response_type` — only per-method config. With the bug,
    // this lookup would miss and the response would silently pass without
    // validation. With the fix, validation runs against the per-method type and
    // valid responses pass while invalid ones reject.
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_response("Hi", true);
    let frame = grpc_frame(&payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    // Note: no `:path` in response_headers — that's the bug being guarded against.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &frame)
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_response_per_method_invalid_body_rejected() {
    let plugin = protobuf_plugin_with_method_messages();
    // Random bytes that don't decode as HelloResponse
    let invalid = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let frame = grpc_frame(&invalid);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &frame)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_protobuf_response_uses_grpc_full_method_metadata_when_present() {
    // When `grpc_method_router` ran upstream, it stores `grpc_full_method`
    // (without the leading slash) in metadata. The response validator must
    // accept that form and prepend the slash to look up the descriptor.
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_response("Hi", true);
    let frame = grpc_frame(&payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/some/other/path".to_string(), // ctx.path is misleading
    );
    ctx.metadata.insert(
        "grpc_full_method".to_string(),
        "test.Greeter/SayHello".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &frame)
            .await,
    );
}

// ���── Unknown Fields ���────────────────────────────────────────────────

#[tokio::test]
async fn test_protobuf_unknown_fields_allowed_by_default() {
    let plugin = protobuf_plugin();
    // Encode a message with an extra field (field number 99)
    let mut payload = encode_hello_request("Eve", 25);
    // Append a varint field: tag = (99 << 3) | 0 = 792, value = 42
    // 792 = 0x318, varint encoding: 0x98 0x06
    payload.extend_from_slice(&[0x98, 0x06, 42]);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_unknown_fields_rejected_when_configured() {
    let plugin = protobuf_plugin_reject_unknown();
    let mut payload = encode_hello_request("Eve", 25);
    // Same unknown field as above
    payload.extend_from_slice(&[0x98, 0x06, 42]);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

// ─── Response Validation ���────────────────────────────────���──────────

#[tokio::test]
async fn test_protobuf_valid_response() {
    let plugin = protobuf_plugin();
    let payload = encode_hello_response("Hello, Alice!", true);
    let frame = grpc_frame(&payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &frame)
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_invalid_response() {
    let plugin = protobuf_plugin();
    let invalid_payload = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let frame = grpc_frame(&invalid_payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &frame)
            .await,
        Some(502),
    );
}

// ─── Invalid Config Graceful Handling ───────────���───────────────────

#[test]
fn test_protobuf_invalid_descriptor_path_degrades_gracefully() {
    let result = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": "/nonexistent/path/descriptor.bin",
        "protobuf_request_type": "test.HelloRequest"
    }));
    // Invalid descriptor path yields no valid rules, so plugin creation fails
    let err = result
        .err()
        .expect("expected error for invalid descriptor path");
    assert!(err.contains("no validation rules configured"), "got: {err}");
}

#[test]
fn test_protobuf_invalid_message_type_degrades_gracefully() {
    let result = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "nonexistent.MessageType"
    }));
    // Invalid message type yields no valid descriptor, so plugin creation fails
    let err = result
        .err()
        .expect("expected error for invalid message type");
    assert!(err.contains("no validation rules configured"), "got: {err}");
}

// ─── gRPC before_proxy is skipped (uses on_final_request_body instead) ──

#[tokio::test]
async fn test_protobuf_before_proxy_skips_grpc() {
    let plugin = protobuf_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    // before_proxy should return Continue for gRPC — validation happens in on_final_request_body
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Empty protobuf message (valid for proto3) ──────────────────────

#[tokio::test]
async fn test_protobuf_empty_message_valid() {
    let plugin = protobuf_plugin();
    // Empty protobuf payload is valid in proto3 (all fields have defaults)
    let frame = grpc_frame(&[]);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}
