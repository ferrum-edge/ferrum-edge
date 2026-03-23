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
