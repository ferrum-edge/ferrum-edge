//! Bot Detection Plugin
//!
//! Blocks requests from known bot user agents by matching against
//! configurable patterns. Supports an allow-list for legitimate bots.

use async_trait::async_trait;
use regex::{RegexSet, RegexSetBuilder};
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

const FORBIDDEN_BODY: &str = r#"{"error":"Forbidden"}"#;

pub struct BotDetection {
    blocked_patterns: Option<RegexSet>,
    allow_list: Option<RegexSet>,
    custom_response_code: u16,
    /// Whether to allow requests with no User-Agent header.
    /// Defaults to false to prevent bypass via missing User-Agent.
    allow_missing_user_agent: bool,
}

impl BotDetection {
    pub fn new(config: &Value) -> Result<Self, String> {
        let blocked_patterns =
            parse_pattern_list(config, "blocked_patterns", Some(default_blocked_patterns()))?;
        let allow_list = parse_pattern_list(config, "allow_list", None)?;
        let custom_response_code = parse_response_code(config)?;
        let allow_missing_user_agent = parse_bool(config, "allow_missing_user_agent", false)?;

        Ok(Self {
            blocked_patterns: compile_literal_pattern_set("blocked_patterns", &blocked_patterns)?,
            allow_list: compile_literal_pattern_set("allow_list", &allow_list)?,
            custom_response_code,
            allow_missing_user_agent,
        })
    }
}

fn default_blocked_patterns() -> Vec<&'static str> {
    vec![
        "curl",
        "wget",
        "python-requests",
        "python-urllib",
        "scrapy",
        "httpclient",
        "java/",
        "libwww-perl",
        "mechanize",
        "php/",
    ]
}

fn parse_pattern_list(
    config: &Value,
    key: &str,
    default: Option<Vec<&'static str>>,
) -> Result<Vec<String>, String> {
    let Some(value) = config.get(key) else {
        return Ok(default
            .unwrap_or_default()
            .into_iter()
            .map(str::to_string)
            .collect());
    };
    if value.is_null() {
        return Ok(default
            .unwrap_or_default()
            .into_iter()
            .map(str::to_string)
            .collect());
    }
    let Value::Array(arr) = value else {
        return Err(format!(
            "bot_detection: '{key}' must be an array of User-Agent substrings"
        ));
    };

    let mut patterns = Vec::with_capacity(arr.len());
    for value in arr {
        let pattern = value
            .as_str()
            .ok_or_else(|| format!("bot_detection: '{key}' entries must be strings"))?
            .trim();
        if pattern.is_empty() {
            return Err(format!(
                "bot_detection: '{key}' entries must be non-empty strings"
            ));
        }
        patterns.push(pattern.to_string());
    }
    Ok(patterns)
}

fn compile_literal_pattern_set(key: &str, patterns: &[String]) -> Result<Option<RegexSet>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let escaped_patterns = patterns.iter().map(|pattern| regex::escape(pattern));
    let mut builder = RegexSetBuilder::new(escaped_patterns);
    builder.case_insensitive(true);
    builder
        .build()
        .map(Some)
        .map_err(|e| format!("bot_detection: failed to compile '{key}' patterns: {e}"))
}

fn parse_response_code(config: &Value) -> Result<u16, String> {
    match config.get("custom_response_code") {
        None | Some(Value::Null) => Ok(403),
        Some(Value::Number(value)) => {
            let Some(code) = value.as_u64() else {
                return Err(
                    "bot_detection: 'custom_response_code' must be an integer from 100 to 599"
                        .to_string(),
                );
            };
            if !(100..=599).contains(&code) {
                return Err(format!(
                    "bot_detection: 'custom_response_code' must be from 100 to 599, got {code}"
                ));
            }
            u16::try_from(code)
                .map_err(|_| "bot_detection: 'custom_response_code' is too large".to_string())
        }
        Some(other) => Err(format!(
            "bot_detection: 'custom_response_code' must be an integer from 100 to 599, got: {other}"
        )),
    }
}

fn parse_bool(config: &Value, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "bot_detection: '{key}' must be a boolean, got: {other}"
        )),
    }
}

/// Plugin priority: runs early in pre-processing (before auth).
pub const BOT_DETECTION_PRIORITY: u16 = super::priority::BOT_DETECTION;

#[async_trait]
impl Plugin for BotDetection {
    fn name(&self) -> &str {
        "bot_detection"
    }

    fn priority(&self) -> u16 {
        BOT_DETECTION_PRIORITY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let user_agent = match ctx.headers.get("user-agent").map(String::as_str) {
            Some(ua) => ua,
            None => {
                // No user-agent header — allow or reject based on configuration.
                // Health checks, load balancers, and internal services often omit
                // User-Agent. Default is to reject missing User-Agent.
                if self.allow_missing_user_agent {
                    return PluginResult::Continue;
                }
                return PluginResult::Reject {
                    status_code: self.custom_response_code,
                    body: FORBIDDEN_BODY.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Check allow-list first
        if self
            .allow_list
            .as_ref()
            .is_some_and(|allow_list| allow_list.is_match(user_agent))
        {
            return PluginResult::Continue;
        }

        // Check blocked patterns
        if self
            .blocked_patterns
            .as_ref()
            .is_some_and(|blocked_patterns| blocked_patterns.is_match(user_agent))
        {
            return PluginResult::Reject {
                status_code: self.custom_response_code,
                body: FORBIDDEN_BODY.to_string(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }
}
