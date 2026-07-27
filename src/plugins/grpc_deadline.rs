//! gRPC Deadline Propagation Plugin
//!
//! Manages the `grpc-timeout` metadata header at the gateway:
//! - Enforces maximum deadlines (caps incoming `grpc-timeout` values)
//! - Injects default deadlines when clients omit `grpc-timeout`
//! - Subtracts gateway processing time before forwarding to backends
//! - Optionally rejects requests that arrive without a deadline
//!
//! The `grpc-timeout` header format follows the gRPC spec:
//! `<value><unit>` where unit is one of: H (hours), M (minutes),
//! S (seconds), m (milliseconds), u (microseconds), n (nanoseconds).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

use super::{GRPC_ONLY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};
use crate::proxy::grpc_proxy::{
    GATEWAY_DEADLINE_EXCEEDED_MESSAGE, GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER,
};

const MAX_GRPC_TIMEOUT_VALUE: u64 = 99_999_999;
const ALLOWED_CONFIG_KEYS: [&str; 4] = [
    "max_deadline_ms",
    "default_deadline_ms",
    "subtract_gateway_processing",
    "reject_no_deadline",
];

pub struct GrpcDeadline {
    max_deadline_ms: Option<u64>,
    default_deadline_ms: Option<u64>,
    subtract_gateway_processing: bool,
    reject_no_deadline: bool,
}

impl GrpcDeadline {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("grpc_deadline: config must be an object".to_string());
        }
        if let Some(object) = config.as_object()
            && let Some(key) = object
                .keys()
                .find(|key| !ALLOWED_CONFIG_KEYS.contains(&key.as_str()))
        {
            return Err(format!(
                "grpc_deadline: unknown configuration property 'config.{key}'"
            ));
        }

        let max_deadline_ms = optional_u64(config, "max_deadline_ms")?;
        let default_deadline_ms = optional_u64(config, "default_deadline_ms")?;
        let subtract_gateway_processing =
            optional_bool(config, "subtract_gateway_processing")?.unwrap_or(false);
        let reject_no_deadline = optional_bool(config, "reject_no_deadline")?.unwrap_or(false);

        if let Some(0) = max_deadline_ms {
            return Err(
                "grpc_deadline: 'max_deadline_ms' must be greater than zero (configured value would reject every request)"
                    .to_string(),
            );
        }
        if let Some(0) = default_deadline_ms {
            return Err(
                "grpc_deadline: 'default_deadline_ms' must be greater than zero".to_string(),
            );
        }
        if let (Some(default_ms), Some(max_ms)) = (default_deadline_ms, max_deadline_ms)
            && default_ms > max_ms
        {
            return Err(format!(
                "grpc_deadline: 'default_deadline_ms' ({default_ms}) cannot exceed 'max_deadline_ms' ({max_ms})"
            ));
        }

        // Reject configurations where the plugin does no useful work — same policy as
        // other admission/observability plugins (see CLAUDE.md "Plugin Config Validation").
        //
        // Any of the four fields is a legitimate standalone rule:
        //   - `max_deadline_ms`: caps incoming deadlines
        //   - `default_deadline_ms`: injects a deadline when the client omits one
        //   - `reject_no_deadline`: rejects requests arriving without a deadline
        //   - `subtract_gateway_processing`: adjusts incoming deadlines by gateway
        //     processing time (useful on its own when clients already send
        //     `grpc-timeout`). It is a no-op when the client omits the header, but
        //     that matches the user's intent — the rule shouldn't fire when there's
        //     nothing to subtract from.
        let has_any_rule = max_deadline_ms.is_some()
            || default_deadline_ms.is_some()
            || subtract_gateway_processing
            || reject_no_deadline;
        if !has_any_rule {
            return Err(
                "grpc_deadline: no rules configured — set at least one of 'max_deadline_ms', \
                 'default_deadline_ms', 'subtract_gateway_processing', or 'reject_no_deadline'"
                    .to_string(),
            );
        }

        Ok(Self {
            max_deadline_ms,
            default_deadline_ms,
            subtract_gateway_processing,
            reject_no_deadline,
        })
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err(format!("grpc_deadline: '{key}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("grpc_deadline: '{key}' must be an unsigned integer")),
        None => Ok(None),
        Some(_) => Err(format!(
            "grpc_deadline: '{key}' must be an unsigned integer"
        )),
    }
}

/// Parse a `grpc-timeout` header value into a Duration.
///
/// Format: `<digits><unit>` where unit is:
/// - `H` = hours, `M` = minutes, `S` = seconds
/// - `m` = milliseconds, `u` = microseconds, `n` = nanoseconds
///
/// We use byte-wise parsing rather than `str::split_at(len-1)` so a malformed
/// non-ASCII value (e.g., a multi-byte UTF-8 sequence) cannot panic on a
/// char-boundary violation.
///
/// Per gRPC spec the digit portion is at most 8 ASCII digits.
fn parse_grpc_timeout(val: &str) -> Option<Duration> {
    let bytes = val.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let unit = bytes[bytes.len() - 1];
    // Reject multi-byte UTF-8 by requiring the unit byte to be a plain ASCII letter.
    if !unit.is_ascii_alphabetic() {
        return None;
    }
    let digits = match std::str::from_utf8(&bytes[..bytes.len() - 1]) {
        Ok(s) => s,
        Err(_) => return None,
    };
    if digits.is_empty() {
        return None;
    }
    if digits.len() > 8 {
        return None;
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    match unit {
        b'H' => Some(Duration::from_secs(value.saturating_mul(3600))),
        b'M' => Some(Duration::from_secs(value.saturating_mul(60))),
        b'S' => Some(Duration::from_secs(value)),
        b'm' => Some(Duration::from_millis(value)),
        b'u' => Some(Duration::from_micros(value)),
        b'n' => Some(Duration::from_nanos(value)),
        _ => None,
    }
}

fn ceil_div_u64(value: u64, divisor: u64) -> u64 {
    value / divisor + u64::from(!value.is_multiple_of(divisor))
}

/// Format a Duration as a valid `grpc-timeout` value.
///
/// The gRPC wire format allows at most 8 digits. We preserve exact
/// millisecond precision whenever it fits, and only coarsen the unit when the
/// 8-digit limit would otherwise be exceeded.
fn format_grpc_timeout(d: Duration) -> String {
    format_grpc_timeout_ms(d.as_millis().min(u128::from(u64::MAX)) as u64)
}

/// Format whole milliseconds as a valid `grpc-timeout` value.
///
/// Shared with the proxy's per-attempt remaining-budget rewrite
/// (`grpc_proxy::apply_remaining_grpc_timeout_header`) so the plugin and the
/// transport cannot drift on unit coarsening or the 8-digit wire limit.
/// Callers that must not emit the invalid wire value `0m` are responsible for
/// passing at least `1` — the deadline plugin deliberately keeps `0m` for an
/// exhausted budget it is about to reject.
pub(crate) fn format_grpc_timeout_ms(ms: u64) -> String {
    let candidates = [
        ('m', 1_u64),
        ('S', 1_000_u64),
        ('M', 60_000_u64),
        ('H', 3_600_000_u64),
    ];

    for (unit, divisor) in candidates {
        let value = ceil_div_u64(ms, divisor);
        if value <= MAX_GRPC_TIMEOUT_VALUE {
            let mut timeout = value.to_string();
            timeout.push(unit);
            return timeout;
        }
    }

    let mut timeout = MAX_GRPC_TIMEOUT_VALUE.to_string();
    timeout.push('H');
    timeout
}

pub(crate) fn duration_millis_ceil_saturating(duration: Duration) -> Option<u64> {
    if duration.is_zero() {
        return None;
    }
    let nanos = duration.as_nanos();
    let millis = nanos.div_ceil(1_000_000).min(u128::from(u64::MAX)) as u64;
    Some(millis.max(1))
}

fn timeout_header(headers: &HashMap<String, String>) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("grpc-timeout"))
        .map(|(_, value)| value.as_str())
}

fn initialize_deadline_from_headers(ctx: &mut RequestContext, headers: &HashMap<String, String>) {
    if ctx.grpc_deadline_initialized {
        return;
    }
    let deadline_ms = timeout_header(headers)
        .and_then(parse_grpc_timeout)
        .and_then(duration_millis_ceil_saturating);
    if let Some(original_ms) = deadline_ms {
        ctx.metadata.insert(
            "grpc_original_deadline_ms".to_string(),
            original_ms.to_string(),
        );
    }
    ctx.initialize_grpc_deadline_budget(deadline_ms);
}

/// Establish the request's single typed gRPC deadline before any plugin or
/// request-body await. Policies are applied in configured execution order, so
/// multiple scoped instances compose once without repeatedly deducting elapsed
/// gateway time from a rewritten relative header.
pub fn prepare_request_deadline(
    plugins: &[std::sync::Arc<dyn Plugin>],
    ctx: &mut RequestContext,
) -> PluginResult {
    // This API accepts the cache's pre-filtered deadline-policy list. Every
    // gRPC request still anchors a valid client grpc-timeout once for transport
    // correctness, but the transaction-log metadata belongs to the configured
    // grpc_deadline policy and is therefore omitted when this list is empty.
    if !ctx.grpc_deadline_initialized {
        let deadline_ms = timeout_header(&ctx.headers)
            .and_then(parse_grpc_timeout)
            .and_then(duration_millis_ceil_saturating);
        if !plugins.is_empty()
            && let Some(original_ms) = deadline_ms
        {
            ctx.metadata.insert(
                "grpc_original_deadline_ms".to_string(),
                original_ms.to_string(),
            );
        }
        ctx.initialize_grpc_deadline_budget(deadline_ms);
    }
    for plugin in plugins {
        match plugin.prepare_grpc_deadline(ctx) {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    ctx.grpc_deadline_preflight_complete = true;
    PluginResult::Continue
}

/// Returns a header map with `content-type: application/grpc`.
fn grpc_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/grpc".to_string());
    h
}

#[async_trait]
impl Plugin for GrpcDeadline {
    fn name(&self) -> &str {
        "grpc_deadline"
    }

    fn priority(&self) -> u16 {
        super::priority::GRPC_DEADLINE
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        GRPC_ONLY_PROTOCOLS
    }

    fn prepare_grpc_deadline(&self, ctx: &mut RequestContext) -> PluginResult {
        let mut deadline_ms = ctx.grpc_deadline_budget_ms;
        if !ctx.grpc_deadline_had_valid_client_timeout && self.reject_no_deadline {
            debug!(
                plugin = "grpc_deadline",
                "Request missing valid grpc-timeout"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: r#"{"error":"a positive grpc-timeout header is required"}"#.to_string(),
                headers: grpc_content_type_header(),
            };
        }
        if deadline_ms.is_none()
            && let Some(default_ms) = self.default_deadline_ms
        {
            deadline_ms = Some(default_ms);
        }
        if let (Some(current), Some(max)) = (deadline_ms, self.max_deadline_ms)
            && current > max
        {
            debug!(
                current_ms = current,
                max_ms = max,
                plugin = "grpc_deadline",
                "Capping grpc-timeout to max"
            );
            deadline_ms = Some(max);
        }

        ctx.set_grpc_deadline_budget(deadline_ms);
        ctx.grpc_deadline_header_is_remaining |= self.subtract_gateway_processing;
        PluginResult::Continue
    }

    fn requires_grpc_deadline_preflight(&self) -> bool {
        true
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        // grpc_method_router historically ran before this hook. Preserve that
        // terminal-policy ordering when method authorization moves to the
        // backend-effective path boundary; without such a policy, the gateway
        // still runs this hook in the ordinary initial pass.
        true
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Direct plugin tests and custom embedders may call `before_proxy`
        // without the gateway's receipt-time preparation pass. Preserve that
        // API by initializing and applying this policy once on the fallback
        // path; normal gateway requests arrive here already fully prepared.
        if !ctx.grpc_deadline_preflight_complete {
            if !ctx.grpc_deadline_initialized {
                initialize_deadline_from_headers(ctx, headers);
            }
            if let reject @ (PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }) =
                self.prepare_grpc_deadline(ctx)
            {
                return reject;
            }
        }

        let Some(effective_ms) = ctx.grpc_deadline_budget_ms else {
            if let Some(value) = timeout_header(headers) {
                debug!(
                    timeout_val = %value,
                    plugin = "grpc_deadline",
                    "Could not establish a positive grpc-timeout"
                );
            }
            return PluginResult::Continue;
        };

        let deadline_ms = if ctx.grpc_deadline_header_is_remaining {
            let remaining_ms = ctx.grpc_deadline_remaining_ms().unwrap_or_else(|| {
                let elapsed = chrono::Utc::now()
                    .signed_duration_since(ctx.timestamp_received)
                    .num_milliseconds()
                    .max(0) as u64;
                effective_ms.saturating_sub(elapsed)
            });
            if remaining_ms == 0 {
                debug!(
                    deadline_ms = effective_ms,
                    plugin = "grpc_deadline",
                    "Deadline already exceeded after gateway processing"
                );
                let mut resp_headers = grpc_content_type_header();
                resp_headers.insert(
                    "grpc-status".to_string(),
                    GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER.to_string(),
                );
                resp_headers.insert(
                    "grpc-message".to_string(),
                    GATEWAY_DEADLINE_EXCEEDED_MESSAGE.to_string(),
                );
                return PluginResult::Reject {
                    status_code: 200,
                    body: String::new(),
                    headers: resp_headers,
                };
            }
            remaining_ms
        } else {
            effective_ms
        };

        let timeout_val = format_grpc_timeout(Duration::from_millis(deadline_ms));
        headers.retain(|name, _| !name.eq_ignore_ascii_case("grpc-timeout"));
        headers.insert("grpc-timeout".to_string(), timeout_val);
        ctx.metadata.insert(
            "grpc_adjusted_deadline_ms".to_string(),
            deadline_ms.to_string(),
        );

        PluginResult::Continue
    }
}
