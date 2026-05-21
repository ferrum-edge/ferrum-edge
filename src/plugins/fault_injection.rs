//! Fault Injection Plugin
//!
//! Injects controlled failures (delays and aborts) into request processing
//! for chaos engineering workflows. Both fault types are probabilistic —
//! each has a `percentage` field (0.0–100.0) checked per-request.
//!
//! Runs in the `before_proxy` phase for HTTP-family requests so it fires after
//! authentication, authorization, and consumer rate limiting but before backend
//! dispatch. Stream proxies run the same fault decision in `on_stream_connect`;
//! stream rejects close the connection/session and do not deliver HTTP status
//! bodies to clients.
//!
//! ## Config
//!
//! ```json
//! {
//!   "abort": {
//!     "status_code": 503,
//!     "percentage": 50.0,
//!     "grpc_status": 14,
//!     "body": "service unavailable"
//!   },
//!   "delay": {
//!     "duration_ms": 2000,
//!     "percentage": 25.0
//!   },
//!   "runtime_overlay_scope": "checkout"
//! }
//! ```
//!
//! At least one of `abort` or `delay` must be present. When both are
//! configured and both trigger on the same request, the delay executes
//! first, then the abort fires.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the plugin reads its
//! `abort.percentage` and `delay.percentage` from the RTDS-driven
//! [`MeshRuntimeOverlay`](crate::modes::mesh::config::MeshRuntimeOverlay)
//! at request time. Reserved keys:
//!
//! - `ferrum.fault_injection.<scope>.abort_percent`
//! - `ferrum.fault_injection.<scope>.delay_percent`
//!
//! Each accepts either a `Number(0..=100)` or a `FractionalPercent` value.
//! Missing / malformed entries fall back to the static config so a partial
//! overlay never silently disables the plugin.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::utils::fault_roll::FaultRoller;
use super::{Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext};
use runtime_overlay::FaultOverridesSnapshot;

pub mod runtime_overlay;

const MAX_DELAY_MS: u64 = 3_600_000;
const NON_UDP_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
];

struct AbortFault {
    status_code: u16,
    percentage: f64,
    grpc_status: Option<u32>,
    body: String,
}

struct DelayFault {
    duration_ms: u64,
    percentage: f64,
}

pub struct FaultInjectionPlugin {
    abort: Option<AbortFault>,
    delay: Option<DelayFault>,
    roller: FaultRoller,
    /// Optional RTDS overlay scope. When set, the plugin reads its
    /// `abort.percentage` and `delay.percentage` from
    /// `ferrum.fault_injection.<scope>.{abort,delay}_percent` on every
    /// request and falls back to the static config when the overlay does
    /// not carry the key. Empty string is rejected at construction.
    runtime_overlay_scope: Option<String>,
}

impl FaultInjectionPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or("fault_injection: config must be an object")?;
        reject_unknown_keys(
            obj.keys(),
            &["abort", "delay", "runtime_overlay_scope"],
            "config",
        )?;

        let abort = match obj.get("abort") {
            Some(Value::Object(abort_obj)) => {
                reject_unknown_keys(
                    abort_obj.keys(),
                    &["status_code", "percentage", "grpc_status", "body"],
                    "abort",
                )?;
                let status_code = abort_obj
                    .get("status_code")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: abort.status_code is required and must be an integer",
                    )?;

                if !(200..=599).contains(&status_code) {
                    return Err(format!(
                        "fault_injection: abort.status_code must be 200-599, got {status_code}"
                    ));
                }

                let percentage = parse_percentage(abort_obj.get("percentage"), "abort.percentage")?;

                let grpc_status = if let Some(grpc_val) = abort_obj.get("grpc_status") {
                    let code = grpc_val
                        .as_u64()
                        .ok_or("fault_injection: abort.grpc_status must be an integer")?;
                    if code > 16 {
                        return Err(format!(
                            "fault_injection: abort.grpc_status must be 0-16, got {code}"
                        ));
                    }
                    Some(code as u32)
                } else {
                    None
                };

                let body = match abort_obj.get("body") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(_) => {
                        return Err("fault_injection: abort.body must be a string".to_string());
                    }
                };

                Some(AbortFault {
                    status_code: status_code as u16,
                    percentage,
                    grpc_status,
                    body,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'abort' must be an object".to_string()),
        };

        let delay = match obj.get("delay") {
            Some(Value::Object(delay_obj)) => {
                reject_unknown_keys(delay_obj.keys(), &["duration_ms", "percentage"], "delay")?;
                let duration_ms = delay_obj
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: delay.duration_ms is required and must be a positive integer",
                    )?;

                if duration_ms == 0 {
                    return Err(
                        "fault_injection: delay.duration_ms must be greater than 0".to_string()
                    );
                }
                if duration_ms > MAX_DELAY_MS {
                    return Err(format!(
                        "fault_injection: delay.duration_ms must be <= {MAX_DELAY_MS}, got {duration_ms}"
                    ));
                }

                let percentage = parse_percentage(delay_obj.get("percentage"), "delay.percentage")?;

                Some(DelayFault {
                    duration_ms,
                    percentage,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'delay' must be an object".to_string()),
        };

        if abort.is_none() && delay.is_none() {
            return Err(
                "fault_injection: at least one of 'abort' or 'delay' must be configured"
                    .to_string(),
            );
        }

        let runtime_overlay_scope = match obj.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "fault_injection: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
                Some(trimmed.to_string())
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err("fault_injection: runtime_overlay_scope must be a string".to_string());
            }
        };

        Ok(Self {
            abort,
            delay,
            roller: FaultRoller::new(),
            runtime_overlay_scope,
        })
    }

    /// Resolve the abort percentage for this request, preferring the
    /// RTDS-driven overlay when the plugin has a configured scope and the
    /// overlay carries the matching key. Returns `None` when no abort
    /// fault is configured at all.
    fn effective_abort_percentage(&self, overrides: &FaultOverridesSnapshot) -> Option<f64> {
        self.abort.as_ref().map(|abort| {
            self.runtime_overlay_scope
                .as_deref()
                .and_then(|scope| overrides.abort_percent(scope))
                .unwrap_or(abort.percentage)
        })
    }

    /// Resolve the delay percentage for this request, preferring the
    /// RTDS-driven overlay when the plugin has a configured scope and the
    /// overlay carries the matching key. Returns `None` when no delay
    /// fault is configured at all.
    fn effective_delay_percentage(&self, overrides: &FaultOverridesSnapshot) -> Option<f64> {
        self.delay.as_ref().map(|delay| {
            self.runtime_overlay_scope
                .as_deref()
                .and_then(|scope| overrides.delay_percent(scope))
                .unwrap_or(delay.percentage)
        })
    }
}

fn reject_unknown_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), String> {
    for key in keys {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("fault_injection: unknown {scope} field '{key}'"));
        }
    }
    Ok(())
}

fn parse_percentage(val: Option<&Value>, field_name: &str) -> Result<f64, String> {
    let pct = match val {
        Some(Value::Number(n)) => n
            .as_f64()
            .ok_or_else(|| format!("fault_injection: {field_name} must be a number"))?,
        Some(_) => {
            return Err(format!("fault_injection: {field_name} must be a number"));
        }
        None => {
            return Err(format!("fault_injection: {field_name} is required"));
        }
    };

    if !(0.0..=100.0).contains(&pct) {
        return Err(format!(
            "fault_injection: {field_name} must be 0.0-100.0, got {pct}"
        ));
    }
    if pct == 0.0 {
        return Err(format!(
            "fault_injection: {field_name} must be greater than 0.0"
        ));
    }

    Ok(pct)
}

impl FaultInjectionPlugin {
    fn decide_faults(&self, overrides: &FaultOverridesSnapshot) -> (bool, bool) {
        let outcome = self.roller.roll_pair(
            self.effective_delay_percentage(overrides),
            self.effective_abort_percentage(overrides),
        );
        (outcome.delay_triggered, outcome.abort_triggered)
    }

    fn reject_for_abort(&self, abort: &AbortFault) -> PluginResult {
        let mut headers = HashMap::new();
        if let Some(grpc_status) = abort.grpc_status {
            headers.insert("grpc-status".to_string(), grpc_status.to_string());
        }
        PluginResult::Reject {
            status_code: abort.status_code,
            body: abort.body.clone(),
            headers,
        }
    }

    fn reject_for_stream_abort(&self, abort: &AbortFault) -> PluginResult {
        PluginResult::Reject {
            status_code: abort.status_code,
            body: String::new(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for FaultInjectionPlugin {
    fn name(&self) -> &str {
        "fault_injection"
    }

    fn priority(&self) -> u16 {
        super::priority::FAULT_INJECTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        NON_UDP_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.metadata.contains_key("fault_injected") {
            return PluginResult::Continue;
        }

        let overrides = runtime_overlay::current_overrides();
        let (delay_triggered, abort_triggered) = self.decide_faults(&overrides);

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.metadata
            .insert("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            tokio::time::sleep(std::time::Duration::from_millis(d.duration_ms)).await;
            ctx.metadata
                .insert("fault_delay_ms".to_string(), d.duration_ms.to_string());
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.metadata
                .insert("fault_type".to_string(), fault_type.to_string());
            ctx.metadata
                .insert("fault_abort_status".to_string(), a.status_code.to_string());

            return self.reject_for_abort(a);
        }

        ctx.metadata
            .insert("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        if ctx
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.contains_key("fault_injected"))
        {
            return PluginResult::Continue;
        }

        let overrides = runtime_overlay::current_overrides();
        let (delay_triggered, abort_triggered) = self.decide_faults(&overrides);

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.insert_metadata("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            tokio::time::sleep(std::time::Duration::from_millis(d.duration_ms)).await;
            ctx.insert_metadata("fault_delay_ms".to_string(), d.duration_ms.to_string());
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.insert_metadata("fault_type".to_string(), fault_type.to_string());
            ctx.insert_metadata("fault_abort_status".to_string(), a.status_code.to_string());

            return self.reject_for_stream_abort(a);
        }

        ctx.insert_metadata("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }
}
