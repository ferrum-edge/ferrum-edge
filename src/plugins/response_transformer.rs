use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::body_transform::{self, BodyRule};
use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone)]
struct TransformRule {
    operation: String, // add, remove, update, rename
    /// Pre-lowercased header key (avoids per-request `.to_lowercase()`).
    key: String,
    value: Option<String>,
    /// New key for rename operations (pre-lowercased).
    new_key: Option<String>,
}

pub struct ResponseTransformer {
    rules: Vec<TransformRule>,
    /// Pre-parsed body transformation rules (target: "body").
    body_rules: Vec<BodyRule>,
}

impl ResponseTransformer {
    pub fn new(config: &Value) -> Self {
        let rules: Vec<TransformRule> = config["rules"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        let operation = r["operation"].as_str()?.to_string();
                        // Skip body rules — handled separately.
                        // Response transformer rules default to "header" target
                        // for backwards compatibility (no target field required).
                        let target = r["target"].as_str().unwrap_or("header");
                        if target == "body" {
                            return None;
                        }
                        let raw_key = r["key"].as_str()?.to_string();
                        let value = r["value"].as_str().map(String::from);
                        let raw_new_key = r["new_key"].as_str().map(String::from);

                        Some(TransformRule {
                            operation,
                            key: raw_key.to_lowercase(),
                            value,
                            new_key: raw_new_key.map(|k| k.to_lowercase()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let body_rules = body_transform::parse_body_rules(config);

        if rules.is_empty() && body_rules.is_empty() {
            tracing::warn!(
                "response_transformer: no 'rules' configured — plugin will have no effect"
            );
        }

        Self { rules, body_rules }
    }
}

#[async_trait]
impl Plugin for ResponseTransformer {
    fn name(&self) -> &str {
        "response_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_TRANSFORMER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        !self.body_rules.is_empty()
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        for rule in &self.rules {
            match rule.operation.as_str() {
                "add" => {
                    if let Some(ref val) = rule.value {
                        response_headers.entry(rule.key.clone()).or_insert_with(|| {
                            debug!("response_transformer: added header {}={}", rule.key, val);
                            val.clone()
                        });
                    }
                }
                "update" => {
                    if let Some(ref val) = rule.value {
                        response_headers.insert(rule.key.clone(), val.clone());
                        debug!("response_transformer: set header {}={}", rule.key, val);
                    }
                }
                "remove" => {
                    response_headers.remove(&rule.key);
                    debug!("response_transformer: removed header {}", rule.key);
                }
                "rename" => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = response_headers.remove(&rule.key)
                    {
                        debug!(
                            "response_transformer: renamed header {} -> {}",
                            rule.key, new_key
                        );
                        response_headers.insert(new_key.clone(), val);
                    }
                }
                _ => {}
            }
        }
        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Option<Vec<u8>> {
        // Only transform JSON bodies
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return None;
        }

        body_transform::apply_body_rules(body, &self.body_rules)
    }
}
