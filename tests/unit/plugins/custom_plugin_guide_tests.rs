//! Compile and consistency guard for the copyable custom-plugin guide sample.

use async_trait::async_trait;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, ResponseBodyProduction};
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;

const GUIDE: &str = include_str!("../../../CUSTOM_PLUGINS.md");
const MAX_CUSTOM_HEADER_NAME_BYTES: usize = 256;
const MAX_CUSTOM_HEADER_VALUE_BYTES: usize = 8 * 1024;

struct MyHeaderInjector {
    header_name: String,
    header_value: String,
}

impl MyHeaderInjector {
    fn new(config: &Value) -> Result<Self, String> {
        let config = config
            .as_object()
            .ok_or_else(|| "my_header_injector config must be a JSON object".to_string())?;
        for key in config.keys() {
            if !matches!(key.as_str(), "header_name" | "header_value") {
                return Err(format!(
                    "my_header_injector config contains unknown key '{key}'; expected only 'header_name' and 'header_value'"
                ));
            }
        }

        let header_name = match config.get("header_name") {
            None => "X-My-Header".to_string(),
            Some(Value::String(value)) => value.clone(),
            Some(_) => return Err("header_name must be a string when present".to_string()),
        };
        if header_name.len() > MAX_CUSTOM_HEADER_NAME_BYTES {
            return Err(format!(
                "header_name must be at most {MAX_CUSTOM_HEADER_NAME_BYTES} bytes"
            ));
        }
        HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|error| format!("header_name must be a valid HTTP header name: {error}"))?;

        let header_value = match config.get("header_value") {
            None => "hello".to_string(),
            Some(Value::String(value)) => value.clone(),
            Some(_) => return Err("header_value must be a string when present".to_string()),
        };
        if header_value.len() > MAX_CUSTOM_HEADER_VALUE_BYTES {
            return Err(format!(
                "header_value must be at most {MAX_CUSTOM_HEADER_VALUE_BYTES} bytes"
            ));
        }
        HeaderValue::from_str(&header_value)
            .map_err(|error| format!("header_value must be a valid HTTP header value: {error}"))?;

        Ok(Self {
            header_name,
            header_value,
        })
    }
}

#[async_trait]
impl Plugin for MyHeaderInjector {
    fn name(&self) -> &str {
        "my_header_injector"
    }

    fn response_body_production(&self) -> ResponseBodyProduction {
        ResponseBodyProduction::Never
    }

    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        headers.insert(self.header_name.clone(), self.header_value.clone());
        PluginResult::Continue
    }
}

#[tokio::test]
async fn copied_test_pattern_compiles_and_handles_the_fallible_constructor() -> Result<(), String> {
    let config = serde_json::json!({ "header_name": "X-Test", "header_value": "hello" });
    let plugin = MyHeaderInjector::new(&config)?;

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(headers.get("X-Test").map(String::as_str), Some("hello"));
    Ok(())
}

#[test]
fn markdown_keeps_the_compiled_fallible_constructor_pattern() {
    assert!(GUIDE.contains("<!-- custom-plugin-guide-test: fallible-constructor-result -->"));
    assert!(GUIDE.contains("async fn test_my_plugin_adds_header() -> Result<(), String>"));
    assert!(GUIDE.contains("let plugin = MyHeaderInjector::new(&config)?;"));
    assert!(!GUIDE.contains("let plugin = MyHeaderInjector::new(&config);"));
    assert!(GUIDE.contains("HeaderName::from_bytes(header_name.as_bytes())"));
    assert!(GUIDE.contains("HeaderValue::from_str(&header_value)"));
}

#[test]
fn guide_teaches_fail_closed_response_body_production_contract() {
    assert!(
        GUIDE.contains("ResponseBodyProduction::Never"),
        "quick-start / capability guidance must teach non-producers to declare Never"
    );
    assert!(
        GUIDE.contains("BoundedByRetainedCeiling"),
        "guide must name the only permitted producer declaration"
    );
    assert!(
        GUIDE.contains("BoundedResponseBodySink") && GUIDE.contains("bounded_json_vec"),
        "guide must require construction-time ceiling-bounded materialization"
    );
    assert!(
        GUIDE.contains("post-allocation length check is not")
            || GUIDE.contains("post-allocation length check is not a substitute")
            || GUIDE.contains("A post-allocation length check is not sufficient"),
        "guide must not imply a post-allocation length check is enough"
    );
    assert!(
        GUIDE.contains("intentionally fail-closed")
            && GUIDE.contains("refuses the producer before invocation"),
        "guide must teach undeclared custom producers are refused before invocation"
    );
    assert!(
        GUIDE.contains("refused rather than installed"),
        "guide must teach Never+Some is refused rather than installed"
    );
    assert!(
        GUIDE.contains("fn response_body_production(&self) -> ResponseBodyProduction")
            && GUIDE.contains("ResponseBodyProduction::Never"),
        "quick-start header-only sample must declare Never so copies do not inherit Undeclared"
    );
}
