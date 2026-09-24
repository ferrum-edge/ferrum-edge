//! Bot Detection Plugin
//!
//! Blocks requests from known bot user agents by matching against
//! configurable patterns. Supports an allow-list for legitimate bots.
//!
//! Matching semantics:
//! - `blocked_patterns` are case-insensitive **substring** matches against the
//!   `User-Agent` header.
//! - `allow_list` entries are case-insensitive **word-boundary** matches and
//!   are evaluated **before** `blocked_patterns` (an allow-list match wins).
//!   Word-boundary anchoring prevents an allowed token from being smuggled as
//!   a substring of an otherwise-blocked agent.
//! - The `User-Agent` is client-controlled and spoofable, so this plugin is a
//!   coarse first filter; for strong bot verification prefer forward-confirmed
//!   reverse DNS or published IP ranges.
//! - A no-op config (empty `blocked_patterns` while missing User-Agent headers
//!   are allowed) is rejected at construction.
//! - Configuration must be an object with only the four documented keys.
//!   Field-level `null` selects that field's documented default.
//! - Rejection statuses are restricted to body-capable 4xx and 5xx responses.

use async_trait::async_trait;
use regex::{RegexSet, RegexSetBuilder};
use serde_json::{Map, Value};
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

const FORBIDDEN_BODY: &str = r#"{"error":"Forbidden"}"#;

/// Every accepted top-level configuration property.
pub const BOT_DETECTION_CONFIG_KEYS: &[&str] = &[
    "blocked_patterns",
    "allow_list",
    "allow_missing_user_agent",
    "custom_response_code",
];

pub struct BotDetection {
    blocked_patterns: Option<RegexSet>,
    allow_list: Option<RegexSet>,
    custom_response_code: u16,
    /// Whether to allow requests with no User-Agent header.
    /// Defaults to true so health checks (which often omit User-Agent) pass.
    allow_missing_user_agent: bool,
}

impl BotDetection {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config.as_object().ok_or_else(|| {
            format!(
                "bot_detection: config must be a JSON object; allowed keys: `{}`",
                BOT_DETECTION_CONFIG_KEYS.join("`, `")
            )
        })?;
        reject_unknown_config_keys(config)?;

        let blocked_patterns =
            parse_pattern_list(config, "blocked_patterns", Some(default_blocked_patterns()))?;
        let allow_list = parse_pattern_list(config, "allow_list", None)?;
        let custom_response_code = parse_response_code(config)?;
        let allow_missing_user_agent = parse_bool(config, "allow_missing_user_agent", true)?;

        // Reject a no-op config: a security plugin with no blocked patterns
        // and no missing-User-Agent rejection would silently always Continue,
        // even if an allow-list is present. Fail loudly at construction per
        // the project rule that `new()` rejects no-op config.
        // (The default path is unaffected: `blocked_patterns` defaults to a
        // non-empty list when the key is absent.)
        if blocked_patterns.is_empty() && allow_missing_user_agent {
            return Err(
                "bot_detection: `blocked_patterns` is empty and missing User-Agent headers are allowed; \
                 plugin would have no effect"
                    .to_string(),
            );
        }

        Ok(Self {
            blocked_patterns: compile_literal_pattern_set("blocked_patterns", &blocked_patterns)?,
            allow_list: compile_word_boundary_pattern_set("allow_list", &allow_list)?,
            custom_response_code,
            allow_missing_user_agent,
        })
    }
}

fn reject_unknown_config_keys(config: &Map<String, Value>) -> Result<(), String> {
    if let Some(unknown) = config
        .keys()
        .find(|key| !BOT_DETECTION_CONFIG_KEYS.contains(&key.as_str()))
    {
        return Err(format!(
            "bot_detection: unknown config key {unknown:?}; allowed keys: `{}`",
            BOT_DETECTION_CONFIG_KEYS.join("`, `")
        ));
    }
    Ok(())
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
    config: &Map<String, Value>,
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
            "bot_detection: `{key}` must be an array of User-Agent substrings or null, got {}",
            json_type_name(value)
        ));
    };

    let mut patterns = Vec::with_capacity(arr.len());
    for (index, value) in arr.iter().enumerate() {
        let pattern = value
            .as_str()
            .ok_or_else(|| {
                format!(
                    "bot_detection: `{key}` entry at index {index} must be a string, got {}",
                    json_type_name(value)
                )
            })?
            .trim();
        if pattern.is_empty() {
            return Err(format!(
                "bot_detection: `{key}` entry at index {index} must contain a non-whitespace character"
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
    builder.build().map(Some).map_err(|_| {
        format!("bot_detection: failed to compile `{key}` patterns (complexity limit exceeded)")
    })
}

/// Compile allow-list patterns with word-boundary anchors (`\b…\b`).
///
/// The allow-list is evaluated BEFORE the blocked patterns and returns
/// `Continue` on any match, so unanchored substring matching against the
/// client-controlled, spoofable User-Agent let an attacker smuggle an allowed
/// token inside an otherwise-blocked agent (e.g. allow `Chrome` matching
/// `evilChromebot`). Anchoring to word boundaries closes the embedded-token
/// bypass class so an allow token only matches when it appears as a standalone
/// token, while legitimate whole-token allow-list entries (e.g. `Googlebot`,
/// `Slackbot`) keep matching real UAs. Note this does not make a self-asserted
/// User-Agent substring trustworthy — for strong bot verification prefer
/// forward-confirmed reverse DNS or published IP ranges.
fn compile_word_boundary_pattern_set(
    key: &str,
    patterns: &[String],
) -> Result<Option<RegexSet>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }

    // `\b` only matches between a word and a non-word character, so anchoring a
    // punctuation edge (e.g. `(compatible; UptimeRobot/2.0; ...)`) would require
    // a word character outside the entry and the entry could never match. A
    // non-word edge already delimits the token, so anchor word-character edges
    // only.
    let is_word = |ch: char| ch.is_alphanumeric() || ch == '_';
    let anchored_patterns = patterns.iter().map(|pattern| {
        let lead = if pattern.starts_with(is_word) {
            r"\b"
        } else {
            ""
        };
        let trail = if pattern.ends_with(is_word) {
            r"\b"
        } else {
            ""
        };
        format!("{lead}{}{trail}", regex::escape(pattern))
    });
    let mut builder = RegexSetBuilder::new(anchored_patterns);
    builder.case_insensitive(true);
    builder.build().map(Some).map_err(|_| {
        format!("bot_detection: failed to compile `{key}` patterns (complexity limit exceeded)")
    })
}

fn parse_response_code(config: &Map<String, Value>) -> Result<u16, String> {
    match config.get("custom_response_code") {
        None | Some(Value::Null) => Ok(403),
        Some(Value::Number(value)) => {
            let code = value.as_u64().or_else(|| {
                let code = value.as_f64()?;
                (code.is_finite() && code.fract() == 0.0 && (400.0..=599.0).contains(&code))
                    .then_some(code as u64)
            });
            let Some(code) = code else {
                return Err(format!(
                    "bot_detection: `custom_response_code` must be an integer from 400 to 599, got {value:?}",
                    value = value.to_string()
                ));
            };
            if !(400..=599).contains(&code) {
                return Err(format!(
                    "bot_detection: `custom_response_code` must be from 400 to 599, got \"{code}\""
                ));
            }
            u16::try_from(code)
                .map_err(|_| "bot_detection: `custom_response_code` is too large".to_string())
        }
        Some(other) => Err(format!(
            "bot_detection: `custom_response_code` must be an integer from 400 to 599 or null, got {}",
            json_type_name(other)
        )),
    }
}

fn parse_bool(config: &Map<String, Value>, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "bot_detection: `{key}` must be a boolean or null, got {}",
            json_type_name(other)
        )),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
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
                // User-Agent. Default is to allow missing User-Agent.
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

        // Allow-list takes precedence over blocked patterns: a User-Agent that
        // matches an allow-list entry is permitted even if it would otherwise
        // match a blocked pattern. Allow-list entries are word-boundary
        // anchored (see `compile_word_boundary_pattern_set`) so an allowed
        // token cannot be smuggled as a substring of a blocked agent. The
        // User-Agent is client-controlled and spoofable; allow-list entries
        // should be specific tokens and are not a substitute for reverse-DNS
        // bot verification.
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
