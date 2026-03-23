use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone)]
struct TransformRule {
    operation: String, // add, remove, update
    target: String,    // header, query
    key: String,
    value: Option<String>,
}

pub struct RequestTransformer {
    rules: Vec<TransformRule>,
}

impl RequestTransformer {
    pub fn new(config: &Value) -> Self {
        let rules = config["rules"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        Some(TransformRule {
                            operation: r["operation"].as_str()?.to_string(),
                            target: r["target"].as_str()?.to_string(),
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
impl Plugin for RequestTransformer {
    fn name(&self) -> &str {
        "request_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TRANSFORMER
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        for rule in &self.rules {
            match rule.target.as_str() {
                "header" => match rule.operation.as_str() {
                    "add" | "update" => {
                        if let Some(ref val) = rule.value {
                            headers.insert(rule.key.to_lowercase(), val.clone());
                            debug!("request_transformer: set header {}={}", rule.key, val);
                        }
                    }
                    "remove" => {
                        headers.remove(&rule.key.to_lowercase());
                        debug!("request_transformer: removed header {}", rule.key);
                    }
                    _ => {}
                },
                "query" => match rule.operation.as_str() {
                    "add" | "update" => {
                        if let Some(ref val) = rule.value {
                            ctx.query_params.insert(rule.key.clone(), val.clone());
                        }
                    }
                    "remove" => {
                        ctx.query_params.remove(&rule.key);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        PluginResult::Continue
    }
}
