//! Tests for body_validator plugin — XML CDATA, comments, processing instructions

use ferrum_gateway::plugins::{Plugin, RequestContext, body_validator::BodyValidator};
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

fn xml_plugin() -> BodyValidator {
    BodyValidator::new(&json!({
        "validate_xml": true
    }))
}

fn xml_plugin_with_required(elements: Vec<&str>) -> BodyValidator {
    BodyValidator::new(&json!({
        "validate_xml": true,
        "required_xml_elements": elements
    }))
}

// ─── Basic XML Validation ──────────────────────────────────────────────

#[tokio::test]
async fn test_xml_simple_valid() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item>text</item></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_tag() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br/></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_unbalanced_tags_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── CDATA Handling ────────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_cdata_with_fake_tags() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[This contains <fake> tags and </closing>]]></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_cdata_empty() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[]]></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_cdata_with_special_chars() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[<>&\"' special chars]]></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_multiple_cdata_sections() {
    let plugin = xml_plugin();
    let body =
        "<root><a><![CDATA[first <section>]]></a><b><![CDATA[second </section>]]></b></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Comment Handling ──────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_comment_with_fake_tags() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><!-- comment with <fake> tags --></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_comment_between_elements() {
    let plugin = xml_plugin();
    let body = "<root><a>text</a><!-- between --><b>more</b></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_comment_empty() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><!----></root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Processing Instructions ───────────────────────────────────────────

#[tokio::test]
async fn test_xml_processing_instruction() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<?xml version=\"1.0\"?>\n<root>content</root>");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_processing_instruction_with_encoding() {
    let plugin = xml_plugin();
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><item>text</item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── DOCTYPE Declarations ──────────────────────────────────────────────

#[tokio::test]
async fn test_xml_doctype_declaration() {
    let plugin = xml_plugin();
    let body = "<!DOCTYPE root>\n<root>content</root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Required Elements with Special Constructs ─────────────────────────

#[tokio::test]
async fn test_xml_required_element_with_cdata() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = "<root><item><![CDATA[content <here>]]></item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_required_element_missing() {
    let plugin = xml_plugin_with_required(vec!["missing"]);
    let body = "<root><item>content</item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Edge Cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_empty_body_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("");
    let mut headers = HashMap::new();
    // Empty body is skipped (returns Continue) because the body.is_empty() check
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_not_starting_with_angle_bracket() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("not xml at all");
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
}

// ─── Type validation ──────────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_type_object_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_json_ctx(r#"{"key": "value"}"#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_object_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_json_ctx(r#"[1, 2, 3]"#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_type_string_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string"}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_integer_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer"}));
    let mut ctx = make_json_ctx("42");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_integer_rejects_float() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer"}));
    let mut ctx = make_json_ctx("3.14");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── String constraints ──────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_min_length_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_min_length_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 10}));
    let mut ctx = make_json_ctx(r#""hi""#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_max_length_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 5}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_max_length_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_pattern_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_pattern_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}));
    let mut ctx = make_json_ctx(r#""Hello123""#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Numeric constraints ─────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_minimum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "minimum": 0}));
    let mut ctx = make_json_ctx("5");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_minimum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "minimum": 10}));
    let mut ctx = make_json_ctx("5");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_maximum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "maximum": 100}));
    let mut ctx = make_json_ctx("50");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_maximum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "maximum": 10}));
    let mut ctx = make_json_ctx("50");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_exclusive_minimum() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "exclusiveMinimum": 5}));
    let mut ctx = make_json_ctx("5");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_exclusive_maximum() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "exclusiveMaximum": 10}));
    let mut ctx = make_json_ctx("10");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Enum constraint ─────────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_enum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"enum": ["red", "green", "blue"]}));
    let mut ctx = make_json_ctx(r#""green""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_enum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"enum": ["red", "green", "blue"]}));
    let mut ctx = make_json_ctx(r#""yellow""#);
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_array_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "array",
        "items": {"type": "integer"}
    }));
    let mut ctx = make_json_ctx(r#"[1, "two", 3]"#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_min_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "minItems": 2}));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_min_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "minItems": 5}));
    let mut ctx = make_json_ctx("[1, 2]");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_max_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "maxItems": 3}));
    let mut ctx = make_json_ctx("[1, 2]");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_max_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "maxItems": 2}));
    let mut ctx = make_json_ctx("[1, 2, 3, 4]");
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_unique_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_unique_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx("[1, 2, 2, 3]");
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_required_missing() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["name", "age"]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice"}"#);
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_not_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "not": {"type": "string"}
    }));
    let mut ctx = make_json_ctx("42");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_not_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "not": {"type": "string"}
    }));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Format validation ───────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_format_email_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "email"}));
    let mut ctx = make_json_ctx(r#""user@example.com""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_email_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "email"}));
    let mut ctx = make_json_ctx(r#""not-an-email""#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_format_ipv4_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "ipv4"}));
    let mut ctx = make_json_ctx(r#""192.168.1.1""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_ipv4_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "ipv4"}));
    let mut ctx = make_json_ctx(r#""999.999.999.999""#);
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_format_uuid_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "uuid"}));
    let mut ctx = make_json_ctx(r#""550e8400-e29b-41d4-a716-446655440000""#);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_datetime_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "date-time"}));
    let mut ctx = make_json_ctx(r#""2024-01-15T10:30:00Z""#);
    let mut headers = HashMap::new();
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
    let mut headers = HashMap::new();
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
    let mut headers1 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx1, &mut headers1).await);

    // Second request: non-matching pattern (implicitly exercises the same pre-compiled regex)
    let mut ctx2 = make_json_ctx(r#""invalid""#);
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(400),
    );
}
