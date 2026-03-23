use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone)]
struct TransformRule {
    operation: String,
    key: String,
    value: Option<String>,
}

pub struct ResponseTransformer {
    rules: Vec<TransformRule>,
}

impl ResponseTransformer {
    pub fn new(config: &Value) -> Self {
        let rules = config["rules"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        Some(TransformRule {
                            operation: r["operation"].as_str()?.to_string(),
                            key: r["key"].as_str()?.to_string(),
                            value: r["value"].as_str().map(String::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self { rules }
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
                        response_headers.entry(rule.key.to_lowercase()).or_insert_with(|| {
                            debug!("response_transformer: added header {}={}", rule.key, val);
                            val.clone()
                        });
                    }
                }
                "update" => {
                    if let Some(ref val) = rule.value {
                        response_headers.insert(rule.key.to_lowercase(), val.clone());
                        debug!("response_transformer: set header {}={}", rule.key, val);
                    }
                }
                "remove" => {
                    response_headers.remove(&rule.key.to_lowercase());
                    debug!("response_transformer: removed header {}", rule.key);
                }
                _ => {}
            }
        }
        PluginResult::Continue
    }
}
