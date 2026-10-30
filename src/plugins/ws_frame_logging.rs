//! WebSocket Frame Logging Plugin
//!
//! Logs metadata for every complete WebSocket message that the shared
//! H1/H2/H3 relay successfully delivers (post-plugin, post-control-frame
//! guard), plus every gateway-published policy Close decision. Provides
//! message-level observability without requiring packet captures.
//!
//! Granularity is one record per **reassembled message**, not per wire frame:
//! tungstenite reassembles a fragmented Text/Binary message (initial non-final
//! frame plus continuations) before the relay sees it, so a message sent as
//! many fragments produces one record whose `size_bytes` is the reassembled
//! payload length. Control frames (Ping/Pong/Close) are never fragmented and
//! map one-to-one. Under `websocket_permessage_deflate: terminate`, sizes are
//! the inflated (plaintext) lengths. The disconnect record's `frames_*`
//! counters use the same unit (delivered messages).
//!
//! Each delivered record includes: plugin_id, proxy_id, connection_id,
//! direction, frame type, payload size in bytes, optional close code / reason
//! length, and an optional payload fingerprint. Disconnect events on the same
//! `ws_frame_log` target reuse that admission `connection_id` so operators can
//! join the terminal record to the message stream. The ID is process-local;
//! multi-instance aggregation must include a gateway instance identity
//! alongside `proxy_id` and `connection_id`. `plugin_id` is the plugin-config
//! resource id, so two effective instances on one proxy stay distinguishable.
//!
//! Volume controls (`sample_rate`, `direction`, `max_records_per_connection`)
//! select which `delivered` records are emitted. `policy_close` decisions and
//! the per-session disconnect record are bounded per session and always
//! emitted at the configured level.
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
//! Application Close reasons are arbitrary payload and may contain secrets.
//! Close records expose only `close_code` and `close_reason_len` (never the
//! reason string).
//!
//! Config:
//! ```json
//! {
//!   "log_level": "info",
//!   "include_payload_preview": false,
//!   "payload_preview_bytes": 128,
//!   "log_ping_pong": false,
//!   "sample_rate": 1.0,
//!   "direction": "both",
//!   "max_records_per_connection": 0
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::fips::backend::rand::SecureRandom;
use async_trait::async_trait;
use serde_json::{Map, Value};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message};
use tracing::callsite::{DefaultCallsite, Identifier};
use tracing::field::FieldSet;
use tracing::metadata::Kind;
use tracing::{Level, Metadata, warn};

use super::{
    Direction, Plugin, ProxyProtocol, RequestContext, WS_ONLY_PROTOCOLS, WebSocketFrameDirection,
    WsDisconnectContext, WsFrameDeliveryObservation,
};

/// Allowed configuration keys for `ws_frame_logging`.
pub const WS_FRAME_LOGGING_CONFIG_KEYS: &[&str] = &[
    "log_level",
    "include_payload_preview",
    "payload_preview_bytes",
    "log_ping_pong",
    "sample_rate",
    "direction",
    "max_records_per_connection",
];

/// Maximum leading payload bytes folded into a fingerprint digest.
pub const MAX_PAYLOAD_PREVIEW_BYTES: u64 = 65_536;

/// Default `log_level` when omitted. Healthy per-frame records remain
/// informational; construction emits an actionable warning when the active
/// filter (including the gateway default `warn`) suppresses them.
#[allow(dead_code)] // Used by external unit tests that verify OpenAPI/default parity.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Accepted `direction` values, in documentation order.
pub const DIRECTION_FILTER_VALUES: &[&str] = &["both", "client_to_backend", "backend_to_client"];

/// `plugin_id` rendered when the instance was constructed without a
/// plugin-config resource id (validation or direct construction).
pub const UNATTRIBUTED_PLUGIN_ID: &str = "-";

/// Log level for frame logging output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
}

/// Which relay direction's `delivered` records are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionFilter {
    Both,
    ClientToBackend,
    BackendToClient,
}

impl DirectionFilter {
    #[inline]
    fn admits(self, direction: WebSocketFrameDirection) -> bool {
        match self {
            Self::Both => true,
            Self::ClientToBackend => direction == WebSocketFrameDirection::ClientToBackend,
            Self::BackendToClient => direction == WebSocketFrameDirection::BackendToClient,
        }
    }
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

    fn is_enabled(self) -> bool {
        match self {
            Self::Trace => tracing::enabled!(target: "ws_frame_log", tracing::Level::TRACE),
            Self::Debug => tracing::enabled!(target: "ws_frame_log", tracing::Level::DEBUG),
            Self::Info => tracing::enabled!(target: "ws_frame_log", tracing::Level::INFO),
            Self::Warn => tracing::enabled!(target: "ws_frame_log", tracing::Level::WARN),
        }
    }
}

/// Emit a structured frame log at the given tracing level.
///
/// Close code / reason length and preview are optional: the macro branches so
/// absent fields are omitted entirely rather than logged as empty sentinels.
macro_rules! emit_ws_frame_log {
    ($level:ident, $plugin_id:expr, $proxy_id:expr, $conn_id:expr, $dir:expr, $obs:expr, $outcome:expr) => {{
        let obs = $obs;
        let plugin_id: &str = $plugin_id;
        match (&obs.preview, obs.close_code, obs.close_reason_len) {
            (Some(preview), Some(code), Some(reason_len)) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %$proxy_id,
                    connection_id = $conn_id,
                    direction = $dir,
                    frame_type = obs.frame_type,
                    size_bytes = obs.size_bytes,
                    preview = %preview,
                    close_code = code,
                    close_reason_len = reason_len,
                    outcome = $outcome,
                    "WebSocket frame"
                );
            }
            (Some(preview), None, None) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %$proxy_id,
                    connection_id = $conn_id,
                    direction = $dir,
                    frame_type = obs.frame_type,
                    size_bytes = obs.size_bytes,
                    preview = %preview,
                    outcome = $outcome,
                    "WebSocket frame"
                );
            }
            (None, Some(code), Some(reason_len)) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %$proxy_id,
                    connection_id = $conn_id,
                    direction = $dir,
                    frame_type = obs.frame_type,
                    size_bytes = obs.size_bytes,
                    close_code = code,
                    close_reason_len = reason_len,
                    outcome = $outcome,
                    "WebSocket frame"
                );
            }
            (None, None, None) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %$proxy_id,
                    connection_id = $conn_id,
                    direction = $dir,
                    frame_type = obs.frame_type,
                    size_bytes = obs.size_bytes,
                    outcome = $outcome,
                    "WebSocket frame"
                );
            }
            // Close(None) or inconsistent close metadata: omit close fields.
            (Some(preview), _, _) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %$proxy_id,
                    connection_id = $conn_id,
                    direction = $dir,
                    frame_type = obs.frame_type,
                    size_bytes = obs.size_bytes,
                    preview = %preview,
                    outcome = $outcome,
                    "WebSocket frame"
                );
            }
            (None, _, _) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %$proxy_id,
                    connection_id = $conn_id,
                    direction = $dir,
                    frame_type = obs.frame_type,
                    size_bytes = obs.size_bytes,
                    outcome = $outcome,
                    "WebSocket frame"
                );
            }
        }
    }};
}

/// Immutable construction-time configuration shared by the plugin-cache
/// instance and every session-bound instance it hands the relay.
struct WsFrameLoggingConfig {
    log_level: LogLevel,
    include_payload_preview: bool,
    payload_preview_bytes: usize,
    /// Built once at construction; rebuilding the HMAC key per frame costs two
    /// extra SHA-256 compressions on the WebSocket hot path.
    payload_fingerprint_key: Option<crate::fips::backend::hmac::Key>,
    log_ping_pong: bool,
    /// `None` logs every connection (`sample_rate: 1`). Otherwise a connection
    /// is sampled when `splitmix64(connection_id) < threshold`.
    sample_threshold: Option<u64>,
    direction: DirectionFilter,
    /// `0` disables the per-connection cap.
    max_records_per_connection: u64,
    /// Plugin-config resource id, or [`UNATTRIBUTED_PLUGIN_ID`].
    plugin_id: Box<str>,
}

pub struct WsFrameLogging {
    config: Arc<WsFrameLoggingConfig>,
    /// `delivered` records emitted on one session. Present only on the
    /// session-bound instance `bind_ws_session` returns when
    /// `max_records_per_connection` is non-zero, so an uncapped configuration
    /// allocates nothing per session and touches no atomic per message.
    session_records: Option<AtomicU64>,
}

impl WsFrameLogging {
    /// Construct without a plugin-config resource id (validation and direct
    /// construction). Records carry `plugin_id = "-"`.
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_config_id(config, None)
    }

    /// Construct with the stable plugin-config resource id that production
    /// `PluginCache` builds pass, stamped on every record as `plugin_id`.
    /// A supplied id that is blank or carries control characters fails closed.
    pub fn new_with_config_id(
        config: &Value,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        let Some(object) = config.as_object() else {
            return Err("ws_frame_logging: config must be a JSON object".to_string());
        };
        reject_unknown_keys(object)?;

        let plugin_id: Box<str> = match plugin_config_id {
            None => UNATTRIBUTED_PLUGIN_ID.into(),
            Some(id) if id.trim().is_empty() || id.chars().any(char::is_control) => {
                return Err(
                    "ws_frame_logging: plugin config id must be non-blank and must not contain control characters"
                        .to_string(),
                );
            }
            Some(id) => id.into(),
        };

        // Validate log_level explicitly — unknown values are rejected per the
        // plugin-validation rules so misspellings (e.g. "info " or "INFO") are
        // caught at config-load time rather than silently downgraded.
        // Healthy per-frame records default to `info`. If the gateway's
        // default `FERRUM_LOG_LEVEL=warn` filter suppresses them, the
        // construction-time diagnostic below remains visible instead.
        let log_level = match object.get("log_level") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `log_level` must be a string (`trace`, `debug`, `info`, or `warn`); null is not allowed"
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
                        "ws_frame_logging: invalid `log_level` value {other:?} \
                         (expected `trace`, `debug`, `info`, or `warn`)"
                    ));
                }
                None => {
                    return Err(
                        "ws_frame_logging: `log_level` must be a string (`trace`, `debug`, `info`, or `warn`)"
                            .to_string(),
                    );
                }
            },
            None => LogLevel::Info,
        };

        let include_payload_preview = match object.get("include_payload_preview") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `include_payload_preview` must be a boolean; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => v.as_bool().ok_or_else(|| {
                "ws_frame_logging: `include_payload_preview` must be a boolean".to_string()
            })?,
            None => false,
        };

        // Reject out-of-range preview budgets instead of silently clamping so
        // OpenAPI `maximum: 65536`, docs, and runtime admission stay identical.
        let payload_preview_bytes = match object.get("payload_preview_bytes") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `payload_preview_bytes` must be a non-negative integer; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => {
                let raw = v.as_u64().ok_or_else(|| {
                    "ws_frame_logging: `payload_preview_bytes` must be a non-negative integer"
                        .to_string()
                })?;
                if raw > MAX_PAYLOAD_PREVIEW_BYTES {
                    return Err(format!(
                        "ws_frame_logging: `payload_preview_bytes` must be <= {MAX_PAYLOAD_PREVIEW_BYTES} (got \"{raw}\")"
                    ));
                }
                raw as usize
            }
            None => 128,
        };
        if include_payload_preview && payload_preview_bytes == 0 {
            return Err(
                "ws_frame_logging: `payload_preview_bytes` must be greater than zero when payload previews are enabled"
                    .to_string(),
            );
        }

        let log_ping_pong = match object.get("log_ping_pong") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `log_ping_pong` must be a boolean; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => v
                .as_bool()
                .ok_or_else(|| "ws_frame_logging: `log_ping_pong` must be a boolean".to_string())?,
            None => false,
        };

        let sample_threshold = match object.get("sample_rate") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `sample_rate` must be a number between 0 and 1; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => {
                let rate = v.as_f64().ok_or_else(|| {
                    "ws_frame_logging: `sample_rate` must be a number between 0 and 1".to_string()
                })?;
                if !(0.0..=1.0).contains(&rate) {
                    return Err(format!(
                        "ws_frame_logging: `sample_rate` must be between 0 and 1 inclusive (got {rate})"
                    ));
                }
                sample_threshold_for_rate(rate)
            }
            None => None,
        };

        let direction = match object.get("direction") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `direction` must be a string (`both`, `client_to_backend`, or `backend_to_client`); null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => match v.as_str() {
                Some("both") => DirectionFilter::Both,
                Some("client_to_backend") => DirectionFilter::ClientToBackend,
                Some("backend_to_client") => DirectionFilter::BackendToClient,
                Some(other) => {
                    return Err(format!(
                        "ws_frame_logging: invalid `direction` value {other:?} \
                         (expected `both`, `client_to_backend`, or `backend_to_client`)"
                    ));
                }
                None => {
                    return Err(
                        "ws_frame_logging: `direction` must be a string (`both`, `client_to_backend`, or `backend_to_client`)"
                            .to_string(),
                    );
                }
            },
            None => DirectionFilter::Both,
        };

        let max_records_per_connection = match object.get("max_records_per_connection") {
            Some(Value::Null) => {
                return Err(
                    "ws_frame_logging: `max_records_per_connection` must be a non-negative integer; null is not allowed"
                        .to_string(),
                );
            }
            Some(v) => v.as_u64().ok_or_else(|| {
                "ws_frame_logging: `max_records_per_connection` must be a non-negative integer"
                    .to_string()
            })?,
            None => 0,
        };

        let payload_fingerprint_key = if include_payload_preview {
            let mut key = [0u8; 32];
            crate::fips::backend::rand::SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| {
                    "ws_frame_logging: failed to generate payload fingerprint key".to_string()
                })?;
            Some(crate::fips::backend::hmac::Key::new(
                crate::fips::backend::hmac::HMAC_SHA256,
                &key,
            ))
        } else {
            None
        };

        // Surface a construction-time warning when the active tracing
        // subscriber filters the configured level. Probe the active dispatcher
        // directly (not `tracing::enabled!`) so parallel interest/LevelFilter
        // aggregation cannot suppress the diagnostic. With no subscriber the
        // warning macro is a no-op, while scoped subscribers can observe it.
        if !log_level.is_admitted_by_active_dispatcher() {
            warn!(
                target: "ws_frame_log",
                configured_level = %crate::startup::sanitize_startup_scalar(log_level.as_str()),
                "ws_frame_logging is enabled but its configured log_level is filtered by the active tracing EnvFilter \
                 (gateway default FERRUM_LOG_LEVEL=warn). Frame parsing, plugin selection, and on_ws_frame / \
                 delivery-observation dispatch still occur; fingerprint/event construction is skipped. Raise \
                 FERRUM_LOG_LEVEL or set log_level to a level admitted by the filter (default plugin log_level \
                 is info)."
            );
        }

        Ok(Self {
            config: Arc::new(WsFrameLoggingConfig {
                log_level,
                include_payload_preview,
                payload_preview_bytes,
                payload_fingerprint_key,
                log_ping_pong,
                sample_threshold,
                direction,
                max_records_per_connection,
                plugin_id,
            }),
            session_records: None,
        })
    }

    /// Configured tracing level label (`trace`/`debug`/`info`/`warn`).
    #[allow(dead_code)] // Used by external unit tests; the binary uses the parsed enum directly.
    pub fn configured_log_level(&self) -> &'static str {
        self.config.log_level.as_str()
    }

    /// Leading payload bytes folded into fingerprints when previews are enabled.
    #[allow(dead_code)] // Used by external unit tests; runtime reads the field directly.
    pub fn payload_preview_bytes(&self) -> usize {
        self.config.payload_preview_bytes
    }

    /// Plugin-config resource id stamped on every record as `plugin_id`.
    #[allow(dead_code)] // Used by external unit tests; runtime reads the field directly.
    pub fn plugin_id(&self) -> &str {
        &self.config.plugin_id
    }

    /// Whether `delivered` records for `connection_id` pass `sample_rate`.
    ///
    /// Deterministic per connection (the whole session is either recorded or
    /// not, so a sampled session stays coherent) and stateless: one mixing
    /// hash of the process-local admission id, no allocation or shared state.
    pub fn connection_sampled(&self, connection_id: u64) -> bool {
        match self.config.sample_threshold {
            None => true,
            Some(threshold) => splitmix64(connection_id) < threshold,
        }
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

    /// Operator-visible size for `size_bytes`.
    ///
    /// Close frames with a status code report `2 + reason.len()` — the two
    /// status-code bytes plus the UTF-8 reason length — never the reason text.
    /// Close without a code reports `0`.
    fn frame_size(message: &Message) -> usize {
        match message {
            Message::Text(s) => s.len(),
            Message::Binary(b) => b.len(),
            Message::Ping(d) | Message::Pong(d) => d.len(),
            Message::Close(close) => Self::close_size(close.as_ref()),
            // `Frame` is raw-frame mode (unused by the gateway's WS path but
            // exposed for plugin flexibility). Use its payload length.
            Message::Frame(f) => f.payload().len(),
        }
    }

    fn close_size(close: Option<&CloseFrame>) -> usize {
        close.map_or(0, |cf| 2usize.saturating_add(cf.reason.len()))
    }

    fn close_metadata(close: Option<&CloseFrame>) -> (Option<u16>, Option<usize>) {
        match close {
            Some(cf) => (Some(u16::from(cf.code)), Some(cf.reason.len())),
            None => (None, None),
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
        if !self.config.include_payload_preview {
            return None;
        }
        let key = self.config.payload_fingerprint_key.as_ref()?;
        let (full_len, bytes): (usize, &[u8]) = match message {
            Message::Text(s) => (s.len(), s.as_bytes()),
            Message::Binary(b) => (b.len(), b.as_ref()),
            _ => return None,
        };
        let hashed_len = full_len.min(self.config.payload_preview_bytes);
        let truncated = hashed_len < full_len;
        Some(payload_fingerprint(
            key,
            &bytes[..hashed_len],
            full_len,
            truncated,
        ))
    }

    fn observation_from_message(&self, message: &Message) -> Option<WsFrameDeliveryObservation> {
        if !self.config.log_ping_pong && matches!(message, Message::Ping(_) | Message::Pong(_)) {
            return None;
        }
        if !self.config.log_level.is_enabled() {
            return None;
        }
        let (close_code, close_reason_len) = match message {
            Message::Close(close) => Self::close_metadata(close.as_ref()),
            _ => (None, None),
        };
        Some(WsFrameDeliveryObservation {
            frame_type: Self::frame_type_label(message),
            size_bytes: Self::frame_size(message),
            preview: self.payload_preview(message),
            close_code,
            close_reason_len,
        })
    }

    fn emit_observation(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        observation: &WsFrameDeliveryObservation,
        outcome: &'static str,
    ) {
        let dir_label = match direction {
            WebSocketFrameDirection::ClientToBackend => "client->backend",
            WebSocketFrameDirection::BackendToClient => "backend->client",
        };
        let plugin_id: &str = &self.config.plugin_id;
        match self.config.log_level {
            LogLevel::Trace => emit_ws_frame_log!(
                trace,
                plugin_id,
                proxy_id,
                connection_id,
                dir_label,
                observation,
                outcome
            ),
            LogLevel::Debug => emit_ws_frame_log!(
                debug,
                plugin_id,
                proxy_id,
                connection_id,
                dir_label,
                observation,
                outcome
            ),
            LogLevel::Info => emit_ws_frame_log!(
                info,
                plugin_id,
                proxy_id,
                connection_id,
                dir_label,
                observation,
                outcome
            ),
            LogLevel::Warn => emit_ws_frame_log!(
                warn,
                plugin_id,
                proxy_id,
                connection_id,
                dir_label,
                observation,
                outcome
            ),
        }
    }

    /// One bounded marker per capped session, emitted on the first suppressed
    /// `delivered` record so operators can tell a quiet session from a capped
    /// one.
    fn emit_record_cap_reached(&self, proxy_id: &str, connection_id: u64) {
        let plugin_id: &str = &self.config.plugin_id;
        let max_records_per_connection = self.config.max_records_per_connection;
        macro_rules! emit_cap {
            ($level:ident) => {
                tracing::$level!(
                    target: "ws_frame_log",
                    plugin_id,
                    proxy_id = %proxy_id,
                    connection_id,
                    max_records_per_connection,
                    event = "record_cap_reached",
                    "WebSocket frame record cap reached; further delivered records for this connection are suppressed"
                )
            };
        }
        match self.config.log_level {
            LogLevel::Trace => emit_cap!(trace),
            LogLevel::Debug => emit_cap!(debug),
            LogLevel::Info => emit_cap!(info),
            LogLevel::Warn => emit_cap!(warn),
        }
    }
}

/// Map `sample_rate` (already validated to `0..=1`) to the per-connection hash
/// threshold. `1` samples every connection without hashing.
fn sample_threshold_for_rate(rate: f64) -> Option<u64> {
    if rate >= 1.0 {
        return None;
    }
    // `rate * 2^64` is below 2^64 for every rate < 1; `as` saturates anyway.
    Some((rate * 18_446_744_073_709_551_616.0_f64) as u64)
}

/// SplitMix64 finalizer: a fixed, well-distributed mix of the monotonic
/// admission id, so consecutive connections are not sampled in runs.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
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
        "ws_frame_logging: `config`: unknown configuration key(s): {unknown:?}; allowed keys: `{}`",
        WS_FRAME_LOGGING_CONFIG_KEYS.join("`, `")
    ))
}

/// Render a keyed, non-reversible payload fingerprint string.
///
/// `key` is generated on the plugin construction path and intentionally never
/// logged or exposed.
/// `hashed` is the prefix of the payload that is folded into the digest,
/// `full_len` is the total payload length reported to operators, and
/// `truncated` indicates the digest only covers a prefix of the payload.
fn payload_fingerprint(
    key: &crate::fips::backend::hmac::Key,
    hashed: &[u8],
    full_len: usize,
    truncated: bool,
) -> String {
    let digest = crate::fips::backend::hmac::sign(key, hashed);
    // 6 bytes -> 12 lowercase hex chars: enough entropy to correlate frames
    // within a plugin instance while staying compact in log lines.
    let prefix = hex::encode(&digest.as_ref()[..6]);
    let marker = if truncated { "+" } else { "" };
    format!("hmac-sha256:{prefix}{marker} len={full_len}")
}

macro_rules! emit_ws_disconnect_log {
    ($level:ident, $ctx:expr, $plugin_id:expr, $direction_label:expr, $error_class_label:expr, $io_side_label:expr, $termination_reason:expr, $correlation_id:expr) => {
        tracing::$level!(
            target: "ws_frame_log",
            plugin_id = $plugin_id,
            namespace = %$ctx.namespace,
            proxy_id = %$ctx.proxy_id,
            connection_id = $ctx.connection_id,
            proxy_name = %$ctx.proxy_name.as_deref().unwrap_or("-"),
            client_ip = %$ctx.client_ip,
            backend_target = %$ctx.backend_target,
            listen_port = $ctx.listen_port,
            duration_ms = $ctx.duration_ms,
            frames_c2b = $ctx.frames_client_to_backend,
            frames_b2c = $ctx.frames_backend_to_client,
            bytes_c2b = $ctx.bytes_client_to_backend,
            bytes_b2c = $ctx.bytes_backend_to_client,
            direction = $direction_label,
            io_side = $io_side_label,
            error_class = %$error_class_label,
            termination_reason = $termination_reason,
            consumer = $ctx.consumer_username.as_deref().unwrap_or("-"),
            auth_method = $ctx.auth_method.unwrap_or("-"),
            correlation_id = %$correlation_id,
            event = "disconnect",
            "WebSocket session ended"
        )
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

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::NONE
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

    fn observes_ws_frame_decisions(&self) -> bool {
        // Purely observational: the relay ignores any `on_ws_frame` return
        // value and reports every gateway-published policy Close through
        // `on_ws_policy_close`, independent of this plugin's priority.
        true
    }

    /// Hand the relay a session-bound instance carrying the per-connection
    /// `delivered` record budget. Only allocated when
    /// `max_records_per_connection` is configured; otherwise the shared
    /// instance stays in place and no per-session state exists.
    fn bind_ws_session(self: Arc<Self>, _ctx: &RequestContext) -> Option<Arc<dyn Plugin>> {
        if self.config.max_records_per_connection == 0 {
            return None;
        }
        Some(Arc::new(Self {
            config: Arc::clone(&self.config),
            session_records: Some(AtomicU64::new(0)),
        }))
    }

    fn on_ws_policy_close(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        close: Option<&CloseFrame>,
    ) {
        // Decision record: not sampled, direction-filtered, or capped (at most
        // one per relay half), so a policy-killed session is never invisible.
        if !self.config.log_level.is_enabled() {
            return;
        }
        let (close_code, close_reason_len) = Self::close_metadata(close);
        let observation = WsFrameDeliveryObservation {
            frame_type: "close",
            size_bytes: Self::close_size(close),
            preview: None,
            close_code,
            close_reason_len,
        };
        self.emit_observation(
            proxy_id,
            connection_id,
            direction,
            &observation,
            "policy_close",
        );
    }

    fn prepare_ws_frame_delivery(
        &self,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<WsFrameDeliveryObservation> {
        // Called only for frames the relay intends to forward after the final
        // control-frame guard (ordinary data/control and peer Close). Plugin
        // policy Close is recorded separately through `on_ws_policy_close` with
        // `outcome=policy_close` and never reaches this helper.
        //
        // Selection runs before any per-message work so filtered, unsampled,
        // or capped messages skip fingerprinting entirely.
        if !self.config.direction.admits(direction) || !self.connection_sampled(connection_id) {
            return None;
        }
        // `> max`, not `>= max`: the message that finds the budget exactly
        // spent still reaches `emit_ws_frame_delivery`, which reports the cap
        // once instead of emitting it.
        if let Some(emitted) = &self.session_records
            && emitted.load(Ordering::Relaxed) > self.config.max_records_per_connection
        {
            return None;
        }
        self.observation_from_message(message)
    }

    fn emit_ws_frame_delivery(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        observation: WsFrameDeliveryObservation,
    ) {
        if let Some(emitted) = &self.session_records {
            // Both relay halves share this budget; one RMW keeps the cap exact
            // under concurrent delivery and reports it exactly once.
            let previous = emitted.fetch_add(1, Ordering::Relaxed);
            let max = self.config.max_records_per_connection;
            if previous >= max {
                if previous == max {
                    self.emit_record_cap_reached(proxy_id, connection_id);
                }
                return;
            }
        }
        self.emit_observation(
            proxy_id,
            connection_id,
            direction,
            &observation,
            "delivered",
        );
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        // Match the frame-level log's structure so operators can correlate
        // the session end with the per-frame stream on the same `ws_frame_log`
        // target via shared `connection_id`. Direction/io_side/error_class/
        // frames/bytes are always emitted so even clean closes produce a final
        // record suitable for session accounting. Message and byte totals are
        // success-only (incremented only after the destination sink accepts a
        // forward). The disconnect record is not subject to sampling, the
        // direction filter, or the per-connection cap.
        let direction_label = match ctx.direction {
            Some(Direction::ClientToBackend) => "client_to_backend",
            Some(Direction::BackendToClient) => "backend_to_client",
            Some(Direction::Unknown) => "unknown",
            None => "none",
        };
        let io_side_label = match ctx.io_side {
            Some(crate::proxy::tcp_proxy::StreamIoSide::Read) => "read",
            Some(crate::proxy::tcp_proxy::StreamIoSide::Write) => "write",
            None => "none",
        };
        let error_class_label = ctx
            .error_class
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "none".to_string());
        // Bounded classification the relay always (over)writes, so plugin- or
        // peer-influenced metadata cannot forge it. Surfaces session-level
        // stops (idle timeout, drain, maximum lifetime, credential expiry,
        // trust withdrawal) that are not policy Close frame records.
        let termination_reason = ctx
            .metadata
            .get(crate::proxy::WS_TERMINATION_METADATA_KEY)
            .map(String::as_str)
            .unwrap_or("-");
        let correlation_id = ctx
            .metadata
            .get(super::REQUEST_ID_METADATA_KEY)
            .or_else(|| ctx.metadata.get("correlation_id"))
            .map(String::as_str)
            .unwrap_or("-");
        let plugin_id: &str = &self.config.plugin_id;

        // Pick a tracing macro at the plugin's configured level so that log
        // targets routed by `ws_frame_log` match the frame output volume.
        // `connection_id` is the same process-local admission ID carried on
        // every frame event for this session (see `WsDisconnectContext`).
        match self.config.log_level {
            LogLevel::Trace => emit_ws_disconnect_log!(
                trace,
                ctx,
                plugin_id,
                direction_label,
                error_class_label,
                io_side_label,
                termination_reason,
                correlation_id
            ),
            LogLevel::Debug => emit_ws_disconnect_log!(
                debug,
                ctx,
                plugin_id,
                direction_label,
                error_class_label,
                io_side_label,
                termination_reason,
                correlation_id
            ),
            LogLevel::Info => emit_ws_disconnect_log!(
                info,
                ctx,
                plugin_id,
                direction_label,
                error_class_label,
                io_side_label,
                termination_reason,
                correlation_id
            ),
            LogLevel::Warn => emit_ws_disconnect_log!(
                warn,
                ctx,
                plugin_id,
                direction_label,
                error_class_label,
                io_side_label,
                termination_reason,
                correlation_id
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    #[test]
    fn frame_size_close_includes_status_code_bytes() {
        let cf = CloseFrame {
            code: CloseCode::Normal,
            reason: "client went away".into(),
        };
        let msg = Message::Close(Some(cf));
        assert_eq!(
            WsFrameLogging::frame_size(&msg),
            2 + "client went away".len()
        );
    }

    #[test]
    fn frame_size_close_without_reason_is_status_code_only() {
        let cf = CloseFrame {
            code: CloseCode::Normal,
            reason: "".into(),
        };
        let msg = Message::Close(Some(cf));
        assert_eq!(WsFrameLogging::frame_size(&msg), 2);
    }

    #[test]
    fn frame_size_close_without_code_is_zero() {
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
