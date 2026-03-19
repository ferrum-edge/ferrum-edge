use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext, TransactionSummary};

pub struct TransactionDebugger {
    log_request_body: bool,
    log_response_body: bool,
}

impl TransactionDebugger {
    pub fn new(config: &Value) -> Self {
        Self {
            log_request_body: config["log_request_body"].as_bool().unwrap_or(false),
            log_response_body: config["log_response_body"].as_bool().unwrap_or(false),
        }
    }
}

#[async_trait]
impl Plugin for TransactionDebugger {
    fn name(&self) -> &str {
        "transaction_debugger"
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        println!("[DEBUG] === Incoming Request ===");
        println!("[DEBUG] {} {} from {}", ctx.method, ctx.path, ctx.client_ip);
        println!("[DEBUG] Headers: {:?}", ctx.headers);
        if self.log_request_body {
            println!("[DEBUG] (Request body logging enabled)");
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        println!("[DEBUG] === Backend Response ===");
        println!(
            "[DEBUG] Status: {} for {} {}",
            response_status, ctx.method, ctx.path
        );
        println!("[DEBUG] Response Headers: {:?}", response_headers);
        if self.log_response_body {
            println!("[DEBUG] (Response body logging enabled)");
        }
        PluginResult::Continue
    }

    async fn log(&self, summary: &TransactionSummary) {
        println!(
            "[DEBUG] Transaction: {} {} -> {} ({}ms)",
            summary.http_method,
            summary.request_path,
            summary.response_status_code,
            summary.latency_total_ms
        );
    }
}
