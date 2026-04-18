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

const MAX_GRPC_TIMEOUT_VALUE: u64 = 99_999_999;

pub struct GrpcDeadline {
    max_deadline_ms: Option<u64>,
    default_deadline_ms: Option<u64>,
    subtract_gateway_processing: bool,
    reject_no_deadline: bool,
}

impl GrpcDeadline {
    pub fn new(config: &Value) -> Result<Self, String> {
        let max_deadline_ms = config["max_deadline_ms"].as_u64();
        let default_deadline_ms = config["default_deadline_ms"].as_u64();
        let subtract_gateway_processing = config["subtract_gateway_processing"]
            .as_bool()
            .unwrap_or(false);
        let reject_no_deadline = config["reject_no_deadline"].as_bool().unwrap_or(false);

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
/// Per gRPC spec the digit portion is at most 8 ASCII digits, but we accept
/// longer digit strings (within u64 range) for backwards compatibility with
/// clients that violate the spec — the value is later capped by
/// `max_deadline_ms` if configured.
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
    let ms = d.as_millis().min(u128::from(u64::MAX)) as u64;
    let candidates = [
        ('m', 1_u64),
        ('S', 1_000_u64),
        ('M', 60_000_u64),
        ('H', 3_600_000_u64),
    ];

    for (unit, divisor) in candidates {
        let value = ceil_div_u64(ms, divisor);
        if value <= MAX_GRPC_TIMEOUT_VALUE {
            return format!("{value}{unit}");
        }
    }

    format!("{MAX_GRPC_TIMEOUT_VALUE}H")
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

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let existing_timeout = headers.get("grpc-timeout").cloned();

        let mut deadline_ms: Option<u64> = match &existing_timeout {
            Some(val) => match parse_grpc_timeout(val) {
                Some(d) => {
                    ctx.metadata.insert(
                        "grpc_original_deadline_ms".to_string(),
                        d.as_millis().to_string(),
                    );
                    Some(d.as_millis() as u64)
                }
                None => {
                    debug!(
                        timeout_val = %val,
                        plugin = "grpc_deadline",
                        "Could not parse grpc-timeout header"
                    );
                    None
                }
            },
            None => None,
        };

        // Handle missing deadline
        if deadline_ms.is_none() && self.reject_no_deadline {
            debug!(plugin = "grpc_deadline", "Request missing grpc-timeout");
            return PluginResult::Reject {
                status_code: 400,
                body: r#"{"error":"grpc-timeout header is required"}"#.to_string(),
                headers: grpc_content_type_header(),
            };
        }
        if deadline_ms.is_none()
            && let Some(default_ms) = self.default_deadline_ms
        {
            deadline_ms = Some(default_ms);
        }

        // Apply max deadline cap
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

        // Subtract gateway processing time
        if self.subtract_gateway_processing
            && let Some(current) = deadline_ms
        {
            let elapsed = chrono::Utc::now()
                .signed_duration_since(ctx.timestamp_received)
                .num_milliseconds()
                .max(0) as u64;
            if elapsed >= current {
                debug!(
                    elapsed_ms = elapsed,
                    deadline_ms = current,
                    plugin = "grpc_deadline",
                    "Deadline already exceeded after gateway processing"
                );
                let mut resp_headers = grpc_content_type_header();
                resp_headers.insert("grpc-status".to_string(), "4".to_string());
                resp_headers.insert(
                    "grpc-message".to_string(),
                    "Deadline exceeded at gateway".to_string(),
                );
                return PluginResult::Reject {
                    status_code: 200,
                    body: String::new(),
                    headers: resp_headers,
                };
            }
            deadline_ms = Some(current - elapsed);
        }

        // Set the adjusted grpc-timeout header
        if let Some(ms) = deadline_ms {
            let timeout_val = format_grpc_timeout(Duration::from_millis(ms));
            headers.insert("grpc-timeout".to_string(), timeout_val);
            ctx.metadata
                .insert("grpc_adjusted_deadline_ms".to_string(), ms.to_string());
        }

        PluginResult::Continue
    }
}
