//! Request Termination / Mocking Plugin
//!
//! Returns a canned response without proxying to the backend.
//! Useful for maintenance mode, mocking APIs, or blocking specific paths.
//! Supports JSON, XML, and plain text response bodies with configurable
//! content type and HTTP status code.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone)]
enum Trigger {
    Always,
    PathPrefix(String),
    HeaderMatch { header: String, value: String },
}

pub struct RequestTermination {
    status_code: u16,
    content_type: String,
    body: String,
    trigger: Trigger,
    message: Option<String>,
}

impl RequestTermination {
    pub fn new(config: &Value) -> Result<Self, String> {
        let status_code = config["status_code"]
            .as_u64()
            .map(|c| c as u16)
            .filter(|&c| (100..=599).contains(&c))
            .unwrap_or(503);
        let content_type = config["content_type"]
            .as_str()
            .unwrap_or("application/json")
            .to_string();
        let body = config["body"].as_str().unwrap_or("").to_string();
        let message = config["message"].as_str().map(String::from);

        let trigger = if let Some(path) = config["trigger"]["path_prefix"].as_str() {
            Trigger::PathPrefix(path.to_string())
        } else if let Some(header) = config["trigger"]["header"].as_str() {
            let value = config["trigger"]["header_value"]
                .as_str()
                .unwrap_or("")
                .to_string();
            Trigger::HeaderMatch {
                header: header.to_lowercase(),
                value,
            }
        } else {
            Trigger::Always
        };

        Ok(Self {
            status_code,
            content_type,
            body,
            trigger,
            message,
        })
    }

    fn build_response_body(&self) -> String {
        if !self.body.is_empty() {
            return self.body.clone();
        }

        // Build a default response based on content type
        let msg = self.message.as_deref().unwrap_or("Service unavailable");

        if self.content_type.contains("json") {
            let escaped = msg.replace('\\', "\\\\").replace('"', "\\\"");
            format!(
                r#"{{"message":"{}","status_code":{}}}"#,
                escaped, self.status_code
            )
        } else if self.content_type.contains("xml") {
            let escaped = msg
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            format!(
                r#"<?xml version="1.0"?><response><message>{}</message><status_code>{}</status_code></response>"#,
                escaped, self.status_code
            )
        } else {
            msg.to_string()
        }
    }
}

#[async_trait]
impl Plugin for RequestTermination {
    fn name(&self) -> &str {
        "request_termination"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TERMINATION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let should_terminate = match &self.trigger {
            Trigger::Always => true,
            Trigger::PathPrefix(prefix) => ctx.path.starts_with(prefix.as_str()),
            Trigger::HeaderMatch { header, value } => ctx
                .headers
                .get(header.as_str())
                .is_some_and(|v| value.is_empty() || v == value),
        };

        if should_terminate {
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), self.content_type.clone());

            return PluginResult::Reject {
                status_code: self.status_code,
                body: self.build_response_body(),
                headers,
            };
        }

        PluginResult::Continue
    }
}
