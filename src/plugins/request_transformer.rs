use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone)]
struct TransformRule {
    operation: String, // add, remove, update, rename
    target: String,    // header, query
    /// Pre-lowercased for header rules (avoids per-request `.to_lowercase()`).
    key: String,
    value: Option<String>,
    /// New key for rename operations (pre-lowercased for header rules).
    new_key: Option<String>,
}

pub struct RequestTransformer {
    rules: Vec<TransformRule>,
}

impl RequestTransformer {
    pub fn new(config: &Value) -> Self {
        let rules: Vec<TransformRule> = config["rules"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        let operation = r["operation"].as_str()?.to_string();
                        let target = r["target"].as_str()?.to_string();
                        let raw_key = r["key"].as_str()?.to_string();
                        let value = r["value"].as_str().map(String::from);
                        let raw_new_key = r["new_key"].as_str().map(String::from);

                        // Pre-lowercase header keys at config time
                        let key = if target == "header" {
                            raw_key.to_lowercase()
                        } else {
                            raw_key
                        };
                        let new_key = if target == "header" {
                            raw_new_key.map(|k| k.to_lowercase())
                        } else {
                            raw_new_key
                        };

                        Some(TransformRule {
                            operation,
                            target,
                            key,
                            value,
                            new_key,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        if rules.is_empty() {
            tracing::warn!(
                "request_transformer: no 'rules' configured — plugin will have no effect"
            );
        }

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
                    "add" => {
                        if let Some(ref val) = rule.value {
                            headers.entry(rule.key.clone()).or_insert_with(|| {
                                debug!("request_transformer: added header {}={}", rule.key, val);
                                val.clone()
                            });
                        }
                    }
                    "update" => {
                        if let Some(ref val) = rule.value {
                            headers.insert(rule.key.clone(), val.clone());
                            debug!("request_transformer: set header {}={}", rule.key, val);
                        }
                    }
                    "remove" => {
                        headers.remove(&rule.key);
                        debug!("request_transformer: removed header {}", rule.key);
                    }
                    "rename" => {
                        if let Some(ref new_key) = rule.new_key
                            && let Some(val) = headers.remove(&rule.key)
                        {
                            debug!(
                                "request_transformer: renamed header {} -> {}",
                                rule.key, new_key
                            );
                            headers.insert(new_key.clone(), val);
                        }
                    }
                    _ => {}
                },
                "query" => match rule.operation.as_str() {
                    "add" => {
                        if let Some(ref val) = rule.value {
                            ctx.query_params
                                .entry(rule.key.clone())
                                .or_insert_with(|| val.clone());
                        }
                    }
                    "update" => {
                        if let Some(ref val) = rule.value {
                            ctx.query_params.insert(rule.key.clone(), val.clone());
                        }
                    }
                    "remove" => {
                        ctx.query_params.remove(&rule.key);
                    }
                    "rename" => {
                        if let Some(ref new_key) = rule.new_key
                            && let Some(val) = ctx.query_params.remove(&rule.key)
                        {
                            ctx.query_params.insert(new_key.clone(), val);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        PluginResult::Continue
    }
}
