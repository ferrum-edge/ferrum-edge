//! Bot Detection Plugin
//!
//! Blocks requests from known bot user agents by matching against
//! configurable patterns. Supports an allow-list for legitimate bots.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

pub struct BotDetection {
    blocked_patterns: Vec<String>,
    allow_list: Vec<String>,
    custom_response_code: u16,
}

impl BotDetection {
    pub fn new(config: &Value) -> Self {
        let blocked_patterns = config["blocked_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_else(default_blocked_patterns);

        let allow_list = config["allow_list"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        let custom_response_code = config["custom_response_code"].as_u64().unwrap_or(403) as u16;

        Self {
            blocked_patterns,
            allow_list,
            custom_response_code,
        }
    }
}

fn default_blocked_patterns() -> Vec<String> {
    vec![
        "curl".to_string(),
        "wget".to_string(),
        "python-requests".to_string(),
        "python-urllib".to_string(),
        "scrapy".to_string(),
        "httpclient".to_string(),
        "java/".to_string(),
        "libwww-perl".to_string(),
        "mechanize".to_string(),
        "php/".to_string(),
    ]
}

/// Plugin priority: runs early in pre-processing (before auth).
pub const BOT_DETECTION_PRIORITY: u16 = 200;

#[async_trait]
impl Plugin for BotDetection {
    fn name(&self) -> &str {
        "bot_detection"
    }

    fn priority(&self) -> u16 {
        BOT_DETECTION_PRIORITY
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let user_agent = match ctx.headers.get("user-agent") {
            Some(ua) => ua.to_lowercase(),
            None => {
                // No user-agent header — reject as suspicious
                return PluginResult::Reject {
                    status_code: self.custom_response_code,
                    body: r#"{"error":"Forbidden"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Check allow-list first
        for allowed in &self.allow_list {
            if user_agent.contains(allowed.as_str()) {
                return PluginResult::Continue;
            }
        }

        // Check blocked patterns
        for pattern in &self.blocked_patterns {
            if user_agent.contains(pattern.as_str()) {
                return PluginResult::Reject {
                    status_code: self.custom_response_code,
                    body: r#"{"error":"Forbidden"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        }

        PluginResult::Continue
    }
}
