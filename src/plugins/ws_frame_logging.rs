//! WebSocket Frame Logging Plugin
//!
//! Logs metadata for every WebSocket frame passing through the proxy.
//! Provides frame-level observability without requiring packet captures.
//!
//! Each frame log entry includes: proxy_id, connection_id, direction,
//! frame type, payload size in bytes, and an optional payload fingerprint.
//! Disconnect events on the same `ws_frame_log` target reuse that admission
//! `connection_id` so operators can join the terminal record to the frame
//! stream. The ID is process-local; multi-instance aggregation must include a
//! gateway instance identity alongside `proxy_id` and `connection_id`.
//!
//! This plugin never transforms or drops frames — it is purely observational.
//!
//! ## Payload privacy
//!
//! WebSocket application frames routinely carry credentials — bearer tokens,
//! session cookies, API keys (e.g. a GraphQL-over-WS `connection_init` payload
//! with `{"Authorization":"Bearer ..."}` or a custom auth handshake). To honor
//! the project invariant "do not log secrets", this plugin NEVER logs raw frame
//! contents. When `include_payload_preview` is enabled, the `preview` field
//! carries only a keyed, non-reversible fingerprint of the form
//! `hmac-sha256:<12 hex chars> len=<bytes>` (and `+` after the digest when only
//! a prefix of the payload was hashed). The per-plugin-instance key prevents
//! offline payload guessing from log access alone while still letting operators
//! correlate identical payloads observed by that plugin instance; the length is
//! always also available as the dedicated `size_bytes` field.
//!
//! Config:
//! ```json
//! {
//!   "log_level": "info",
//!   "include_payload_preview": false,
//!   "payload_preview_bytes": 128,
//!   "log_ping_pong": false
//! }
//! ```

use async_trait::async_trait;
use ring::rand::SecureRandom;
use serde_json::{Map, Value};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::callsite::{DefaultCallsite, Identifier};
use tracing::field::FieldSet;
use tracing::metadata::Kind;
use tracing::{Level, Metadata, warn};

use super::{
    Direction, Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection,
    WsDisconnectContext,
};

/// Allowed configuration keys for `ws_frame_logging`.
pub const WS_FRAME_LOGGING_CONFIG_KEYS: &[&str] = &[
    "log_level",
    "include_payload_preview",
    "payload_preview_bytes",
    "log_ping_pong",
];

/// Maximum leading payload bytes folded into a fingerprint digest.
pub const MAX_PAYLOAD_PREVIEW_BYTES: u64 = 65_536;

/// Default `log_level` when omitted. Healthy per-frame records remain
/// informational; construction emits an actionable warning when the active
/// filter (including the gateway default `warn`) suppresses them.
#[allow(dead_code)] // Used by external unit tests that verify OpenAPI/default parity.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Log level for frame logging output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
}

/// Build one distinct static probe callsite per macro expansion while keeping
/// the metadata shape identical across configured levels.
macro_rules! filter_probe_metadata {
    ($level:expr) => {{
        static CALLSITE: DefaultCallsite = DefaultCallsite::new(&META);
        static META: Metadata<'static> = Metadata::new(
            "ws_frame_logging.filter_probe",
            "ws_frame_log",
            $level,
            None,
            None,
            None,
            FieldSet::new(&[], Identifier(&CALLSITE)),
            Kind::HINT,
        );
        &META
    }};
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
        }
    }

    /// Construction-time admission probe for the *active* dispatcher only.
    ///
    /// `tracing::enabled!` is not suitable here: it consults the process-global
    /// callsite interest cache and `LevelFilter::current()`, which under
    /// parallel tests (and per-layer EnvFilters) can report a filtered `info`
    /// level as enabled. `Dispatch::register_callsite` asks only the current
    /// thread's subscriber — the same EnvFilter stack the gateway installs —
    /// without depending on other dispatchers' aggregated interest.
    fn is_admitted_by_active_dispatcher(self) -> bool {
        let meta = self.filter_probe_metadata();
        tracing::dispatcher::get_default(|dispatch| {
            let interest = dispatch.register_callsite(meta);
            if interest.is_never() {
                false
            } else if interest.is_always() {
                true
            } else {
                dispatch.enabled(meta)
            }
        })
    }

    /// Static `ws_frame_log` metadata used only for construction-time filter
    /// probes. Not registered in the global callsite cache; passed directly to
    /// the active dispatcher's `register_callsite`.
    fn filter_probe_metadata(self) -> &'static Metadata<'static> {
        match self {
            Self::Trace => filter_probe_metadata!(Level::TRACE),
            Self::Debug => filter_probe_metadata!(Level::DEBUG),
            Self::Info => filter_probe_metadata!(Level::INFO),
            Self::Warn => filter_probe_metadata!(Level::WARN),
        }
    }
}

pub struct WsFrameLogging {
    log_level: LogLevel,
    include_payload_preview: bool,
    payload_preview_bytes: usize,
    payload_fingerprint_key: Option<[u8; 32]>,
    log_ping_pong: bool,
}

impl WsFrameLogging {
    pub fn new(config: &Value) -> Result<Self, String> {
        let Some(object) = config.as_object() else {
            return Err("ws_frame_logging: config must be a JSON object".to_string());
        };
        reject_unknown_keys(object)?;

        // Validate log_level explicitly — unknown values are rejected per the
        // plugin-validation rules so misspellings (e.g. "info " or "INFO") are
        // caught at config-load time rather than silently downgraded.
        // Healthy per-frame records default to `info`. If the gateway's
        // default `FERRUM_LOG_LEVEL=warn` filter suppresses them, the
        // construction-time diagnostic below remains visible instead.
        let log_level = match object.get("log_level") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: 'log_level' must be a string ('trace', 'debug', 'info', or 'warn'); null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => match v.as_str() {
                Some("trace") => LogLevel::Trace,
                Some("debug") => LogLevel::Debug,
                Some("info") => LogLevel::Info,
                Some("warn") => LogLevel::Warn,
                Some(other) => {
                    return Err(format!(
                        "ws_frame_logging: invalid 'log_level' value '{other}' \
                         (expected 'trace', 'debug', 'info', or 'warn')"
                    ));
                }
                None => {
                    return Err(
                        "ws_frame_logging: 'log_level' must be a string ('trace', 'debug', 'info', or 'warn')"
                            .to_string(),
                    );
                }
            },
            None => LogLevel::Info,
        };

        let include_payload_preview = match object.get("include_payload_preview") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: 'include_payload_preview' must be a boolean; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => v.as_bool().ok_or_else(|| {
                "ws_frame_logging: 'include_payload_preview' must be a boolean".to_string()
            })?,
            None => false,
        };

        // Reject out-of-range preview budgets instead of silently clamping so
        // OpenAPI `maximum: 65536`, docs, and runtime admission stay identical.
        let payload_preview_bytes = match object.get("payload_preview_bytes") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: 'payload_preview_bytes' must be a non-negative integer; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => {
                let raw = v.as_u64().ok_or_else(|| {
                    "ws_frame_logging: 'payload_preview_bytes' must be a non-negative integer"
                        .to_string()
                })?;
                if raw > MAX_PAYLOAD_PREVIEW_BYTES {
                    return Err(format!(
                        "ws_frame_logging: 'payload_preview_bytes' must be <= {MAX_PAYLOAD_PREVIEW_BYTES} (got {raw})"
                    ));
                }
                raw as usize
            }
            None => 128,
        };
        if include_payload_preview && payload_preview_bytes == 0 {
            return Err(
                "ws_frame_logging: 'payload_preview_bytes' must be greater than zero when payload previews are enabled"
                    .to_string(),
            );
        }
        let payload_fingerprint_key = if include_payload_preview {
            let mut key = [0u8; 32];
            ring::rand::SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| {
                    "ws_frame_logging: failed to generate payload fingerprint key".to_string()
                })?;
            Some(key)
        } else {
            None
        };

        let log_ping_pong = match object.get("log_ping_pong") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: 'log_ping_pong' must be a boolean; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => v
                .as_bool()
                .ok_or_else(|| "ws_frame_logging: 'log_ping_pong' must be a boolean".to_string())?,
            None => false,
        };

        // Surface a construction-time warning when the active tracing
        // subscriber filters the configured level. Probe the active dispatcher
        // directly (not `tracing::enabled!`) so parallel interest/LevelFilter
        // aggregation cannot suppress the diagnostic. With no subscriber the
        // warning macro is a no-op, while scoped subscribers can observe it.
        if !log_level.is_admitted_by_active_dispatcher() {
            warn!(
                target: "ws_frame_log",
                configured_level = log_level.as_str(),
                "ws_frame_logging is enabled but its configured log_level is filtered by the active tracing EnvFilter \
                 (gateway default FERRUM_LOG_LEVEL=warn). Frame parsing, plugin selection, and on_ws_frame dispatch \
                 still occur; fingerprint/event construction is skipped. Raise FERRUM_LOG_LEVEL or set log_level to \
                 a level admitted by the filter (default plugin log_level is info)."
            );
        }

        Ok(Self {
            log_level,
            include_payload_preview,
            payload_preview_bytes,
            payload_fingerprint_key,
            log_ping_pong,
        })
    }

    /// Configured tracing level label (`trace`/`debug`/`info`/`warn`).
    #[allow(dead_code)] // Used by external unit tests; the binary uses the parsed enum directly.
    pub fn configured_log_level(&self) -> &'static str {
        self.log_level.as_str()
    }

    /// Leading payload bytes folded into fingerprints when previews are enabled.
    #[allow(dead_code)] // Used by external unit tests; runtime reads the field directly.
    pub fn payload_preview_bytes(&self) -> usize {
        self.payload_preview_bytes
    }

    fn frame_type_label(message: &Message) -> &'static str {
        match message {
            Message::Text(_) => "text",
            Message::Binary(_) => "binary",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::Close(_) => "close",
            Message::Frame(_) => "frame",
        }
    }

    fn frame_size(message: &Message) -> usize {
        match message {
            Message::Text(s) => s.len(),
            Message::Binary(b) => b.len(),
            Message::Ping(d) | Message::Pong(d) => d.len(),
            // Close frames carry a 2-byte status code (when present) plus an
            // optional UTF-8 reason. Report the reason length — which is the
            // operator-visible payload — rather than 0.
            Message::Close(Some(cf)) => cf.reason.len(),
            Message::Close(None) => 0,
            // `Frame` is raw-frame mode (unused by the gateway's WS path but
            // exposed for plugin flexibility). Use its payload length.
            Message::Frame(f) => f.payload().len(),
        }
    }

    /// Build a non-reversible payload fingerprint for the frame.
    ///
    /// Returns `None` when previews are disabled or the message type has no
    /// application payload (only Text and Binary carry one).
    ///
    /// SECURITY: WebSocket payloads routinely carry credentials (bearer tokens,
    /// cookies, API keys). We therefore NEVER emit the raw bytes. Instead we
    /// fold up to `payload_preview_bytes` leading bytes into a keyed HMAC-SHA256
    /// digest and emit a short, non-reversible fingerprint:
    ///   `hmac-sha256:<12 hex chars> len=<total payload bytes>`
    /// A trailing `+` is appended after the digest hex when only a prefix of the
    /// payload was hashed (payload longer than `payload_preview_bytes`), so the
    /// fingerprint is unambiguous about partial coverage. The key is generated
    /// during plugin construction, so log access alone is not enough to verify
    /// guessed credentials offline. See the module-level "Payload privacy" note.
    fn payload_preview(&self, message: &Message) -> Option<String> {
        if !self.include_payload_preview {
            return None;
        }
        let key = self.payload_fingerprint_key.as_ref()?;
        let (full_len, bytes): (usize, &[u8]) = match message {
            Message::Text(s) => (s.len(), s.as_bytes()),
            Message::Binary(b) => (b.len(), b.as_ref()),
            _ => return None,
        };
        let hashed_len = full_len.min(self.payload_preview_bytes);
        let truncated = hashed_len < full_len;
        Some(payload_fingerprint(
            key,
            &bytes[..hashed_len],
            full_len,
            truncated,
        ))
    }
}

fn reject_unknown_keys(object: &Map<String, Value>) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .filter(|key| !WS_FRAME_LOGGING_CONFIG_KEYS.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "ws_frame_logging: unknown configuration key(s): {}; allowed keys: {}",
        unknown.join(", "),
        WS_FRAME_LOGGING_CONFIG_KEYS.join(", ")
    ))
}

/// Render a keyed, non-reversible payload fingerprint string.
///
/// `key` is generated on the plugin construction path and intentionally never
/// logged or exposed.
/// `hashed` is the prefix of the payload that is folded into the digest,
/// `full_len` is the total payload length reported to operators, and
/// `truncated` indicates the digest only covers a prefix of the payload.
fn payload_fingerprint(key: &[u8; 32], hashed: &[u8], full_len: usize, truncated: bool) -> String {
    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let digest = ring::hmac::sign(&hmac_key, hashed);
    // 6 bytes -> 12 lowercase hex chars: enough entropy to correlate frames
    // within a plugin instance while staying compact in log lines.
    let prefix = hex::encode(&digest.as_ref()[..6]);
    let marker = if truncated { "+" } else { "" };
    format!("hmac-sha256:{prefix}{marker} len={full_len}")
}

/// Emit a structured log at the given tracing level.
///
/// tracing macros require the level as a compile-time token, so we use a macro
/// to deduplicate the field list across Trace/Debug/Info/Warn without copy-paste.
macro_rules! emit_ws_frame_log {
    ($level:ident, $proxy_id:expr, $conn_id:expr, $dir:expr, $ftype:expr, $size:expr, $preview:expr) => {
        if let Some(ref p) = $preview {
            tracing::$level!(
                target: "ws_frame_log",
                proxy_id = %$proxy_id,
                connection_id = $conn_id,
                direction = $dir,
                frame_type = $ftype,
                size_bytes = $size,
                preview = %p,
                "WebSocket frame"
            );
        } else {
            tracing::$level!(
                target: "ws_frame_log",
                proxy_id = %$proxy_id,
                connection_id = $conn_id,
                direction = $dir,
                frame_type = $ftype,
                size_bytes = $size,
                "WebSocket frame"
            );
        }
    };
}

#[async_trait]
impl Plugin for WsFrameLogging {
    fn name(&self) -> &str {
        "ws_frame_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_FRAME_LOGGING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        // Always true while enabled: selection/framing cost is paid even when
        // the active EnvFilter suppresses emission. Filtering skips only
        // fingerprint computation and tracing event construction.
        true
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        // Skip ping/pong logging unless explicitly enabled
        if !self.log_ping_pong && matches!(message, Message::Ping(_) | Message::Pong(_)) {
            return None;
        }

        let dir_label = match direction {
            WebSocketFrameDirection::ClientToBackend => "client->backend",
            WebSocketFrameDirection::BackendToClient => "backend->client",
        };
        let frame_type = Self::frame_type_label(message);
        let size = Self::frame_size(message);

        // Defer preview computation — only allocate if the tracing level is active.
        // tracing macros short-circuit when the level is filtered, so we compute
        // the preview inside the macro guard to avoid wasted work. Frame parsing
        // and this hook dispatch have already occurred by the time we get here.
        match self.log_level {
            LogLevel::Trace => {
                if tracing::enabled!(target: "ws_frame_log", tracing::Level::TRACE) {
                    let preview = self.payload_preview(message);
                    emit_ws_frame_log!(
                        trace,
                        proxy_id,
                        connection_id,
                        dir_label,
                        frame_type,
                        size,
                        preview
                    );
                }
            }
            LogLevel::Debug => {
                if tracing::enabled!(target: "ws_frame_log", tracing::Level::DEBUG) {
                    let preview = self.payload_preview(message);
                    emit_ws_frame_log!(
                        debug,
                        proxy_id,
                        connection_id,
                        dir_label,
                        frame_type,
                        size,
                        preview
                    );
                }
            }
            LogLevel::Info => {
                if tracing::enabled!(target: "ws_frame_log", tracing::Level::INFO) {
                    let preview = self.payload_preview(message);
                    emit_ws_frame_log!(
                        info,
                        proxy_id,
                        connection_id,
                        dir_label,
                        frame_type,
                        size,
                        preview
                    );
                }
            }
            LogLevel::Warn => {
                if tracing::enabled!(target: "ws_frame_log", tracing::Level::WARN) {
                    let preview = self.payload_preview(message);
                    emit_ws_frame_log!(
                        warn,
                        proxy_id,
                        connection_id,
                        dir_label,
                        frame_type,
                        size,
                        preview
                    );
                }
            }
        }

        // Never transform frames — purely observational
        None
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        // Match the frame-level log's structure so operators can correlate
        // the session end with the per-frame stream on the same `ws_frame_log`
        // target via shared `connection_id`. Direction/error_class/frames are
        // always emitted so even clean closes produce a final record suitable
        // for session accounting.
        let direction_label = match ctx.direction {
            Some(Direction::ClientToBackend) => "client_to_backend",
            Some(Direction::BackendToClient) => "backend_to_client",
            Some(Direction::Unknown) => "unknown",
            None => "none",
        };
        let error_class_label = ctx
            .error_class
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "none".to_string());
        let correlation_id = ctx
            .metadata
            .get(super::REQUEST_ID_METADATA_KEY)
            .or_else(|| ctx.metadata.get("correlation_id"))
            .map(String::as_str)
            .unwrap_or("-");

        // Pick a tracing macro at the plugin's configured level so that log
        // targets routed by `ws_frame_log` match the frame output volume.
        // `connection_id` is the same process-local admission ID carried on
        // every frame event for this session (see `WsDisconnectContext`).
        match self.log_level {
            LogLevel::Trace => tracing::trace!(
                target: "ws_frame_log",
                namespace = %ctx.namespace,
                proxy_id = %ctx.proxy_id,
                connection_id = ctx.connection_id,
                proxy_name = %ctx.proxy_name.as_deref().unwrap_or("-"),
                client_ip = %ctx.client_ip,
                backend_target = %ctx.backend_target,
                listen_port = ctx.listen_port,
                duration_ms = ctx.duration_ms,
                frames_c2b = ctx.frames_client_to_backend,
                frames_b2c = ctx.frames_backend_to_client,
                direction = direction_label,
                error_class = %error_class_label,
                consumer = ctx.consumer_username.as_deref().unwrap_or("-"),
                auth_method = ctx.auth_method.unwrap_or("-"),
                correlation_id = %correlation_id,
                event = "disconnect",
                "WebSocket session ended"
            ),
            LogLevel::Debug => tracing::debug!(
                target: "ws_frame_log",
                namespace = %ctx.namespace,
                proxy_id = %ctx.proxy_id,
                connection_id = ctx.connection_id,
                proxy_name = %ctx.proxy_name.as_deref().unwrap_or("-"),
                client_ip = %ctx.client_ip,
                backend_target = %ctx.backend_target,
                listen_port = ctx.listen_port,
                duration_ms = ctx.duration_ms,
                frames_c2b = ctx.frames_client_to_backend,
                frames_b2c = ctx.frames_backend_to_client,
                direction = direction_label,
                error_class = %error_class_label,
                consumer = ctx.consumer_username.as_deref().unwrap_or("-"),
                auth_method = ctx.auth_method.unwrap_or("-"),
                correlation_id = %correlation_id,
                event = "disconnect",
                "WebSocket session ended"
            ),
            LogLevel::Info => tracing::info!(
                target: "ws_frame_log",
                namespace = %ctx.namespace,
                proxy_id = %ctx.proxy_id,
                connection_id = ctx.connection_id,
                proxy_name = %ctx.proxy_name.as_deref().unwrap_or("-"),
                client_ip = %ctx.client_ip,
                backend_target = %ctx.backend_target,
                listen_port = ctx.listen_port,
                duration_ms = ctx.duration_ms,
                frames_c2b = ctx.frames_client_to_backend,
                frames_b2c = ctx.frames_backend_to_client,
                direction = direction_label,
                error_class = %error_class_label,
                consumer = ctx.consumer_username.as_deref().unwrap_or("-"),
                auth_method = ctx.auth_method.unwrap_or("-"),
                correlation_id = %correlation_id,
                event = "disconnect",
                "WebSocket session ended"
            ),
            LogLevel::Warn => tracing::warn!(
                target: "ws_frame_log",
                namespace = %ctx.namespace,
                proxy_id = %ctx.proxy_id,
                connection_id = ctx.connection_id,
                proxy_name = %ctx.proxy_name.as_deref().unwrap_or("-"),
                client_ip = %ctx.client_ip,
                backend_target = %ctx.backend_target,
                listen_port = ctx.listen_port,
                duration_ms = ctx.duration_ms,
                frames_c2b = ctx.frames_client_to_backend,
                frames_b2c = ctx.frames_backend_to_client,
                direction = direction_label,
                error_class = %error_class_label,
                consumer = ctx.consumer_username.as_deref().unwrap_or("-"),
                auth_method = ctx.auth_method.unwrap_or("-"),
                correlation_id = %correlation_id,
                event = "disconnect",
                "WebSocket session ended"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    #[test]
    fn frame_size_close_reports_reason_length() {
        let cf = CloseFrame {
            code: CloseCode::Normal,
            reason: "client went away".into(),
        };
        let msg = Message::Close(Some(cf));
        assert_eq!(WsFrameLogging::frame_size(&msg), "client went away".len());
    }

    #[test]
    fn frame_size_close_without_reason_is_zero() {
        let msg = Message::Close(None);
        assert_eq!(WsFrameLogging::frame_size(&msg), 0);
    }

    #[test]
    fn frame_size_text_and_binary() {
        let text = Message::Text("abc".into());
        assert_eq!(WsFrameLogging::frame_size(&text), 3);

        let bin = Message::Binary(vec![1u8, 2, 3, 4, 5].into());
        assert_eq!(WsFrameLogging::frame_size(&bin), 5);
    }
}
