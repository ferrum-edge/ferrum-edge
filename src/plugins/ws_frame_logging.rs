//! WebSocket Frame Logging Plugin
//!
//! Logs metadata for every WebSocket frame passing through the proxy.
//! Provides frame-level observability without requiring packet captures.
//!
//! Each frame log entry includes: proxy_id, connection_id, direction,
//! frame type, payload size in bytes, and an optional payload preview.
//!
//! This plugin never transforms or drops frames — it is purely observational.
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
use serde_json::Value;
use tokio_tungstenite::tungstenite::protocol::Message;

use super::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};

/// Log level for frame logging output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Trace,
    Debug,
    Info,
}

pub struct WsFrameLogging {
    log_level: LogLevel,
    include_payload_preview: bool,
    payload_preview_bytes: usize,
    log_ping_pong: bool,
}

impl WsFrameLogging {
    pub fn new(config: &Value) -> Result<Self, String> {
        let log_level = match config["log_level"].as_str().unwrap_or("info") {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            _ => LogLevel::Info,
        };

        let include_payload_preview = config["include_payload_preview"].as_bool().unwrap_or(false);

        // Clamp to 64 KiB to prevent OOM from hex_encode on large binary frames
        const MAX_PREVIEW_BYTES: usize = 65_536;
        let payload_preview_bytes = (config["payload_preview_bytes"].as_u64().unwrap_or(128)
            as usize)
            .min(MAX_PREVIEW_BYTES);

        let log_ping_pong = config["log_ping_pong"].as_bool().unwrap_or(false);

        Ok(Self {
            log_level,
            include_payload_preview,
            payload_preview_bytes,
            log_ping_pong,
        })
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

    /// Build a payload preview string, borrowing from the message where possible.
    /// Returns None when previews are disabled or the message type has no payload.
    ///
    /// For text: truncates at a UTF-8 char boundary at or before `payload_preview_bytes`.
    /// For binary: hex-encodes the first `payload_preview_bytes` bytes.
    fn payload_preview<'a>(&self, message: &'a Message) -> Option<PreviewStr<'a>> {
        if !self.include_payload_preview {
            return None;
        }
        match message {
            Message::Text(s) => {
                if s.len() <= self.payload_preview_bytes {
                    // Borrow the original string — zero allocation
                    Some(PreviewStr::Borrowed(s.as_str()))
                } else {
                    // Truncate at a UTF-8 char boundary at or before the byte limit
                    let mut end = self.payload_preview_bytes;
                    while end > 0 && !s.is_char_boundary(end) {
                        end -= 1;
                    }
                    Some(PreviewStr::Borrowed(&s[..end]))
                }
            }
            Message::Binary(b) => {
                let len = b.len().min(self.payload_preview_bytes);
                Some(PreviewStr::Owned(hex_encode(&b[..len])))
            }
            _ => None,
        }
    }
}

/// A preview string that borrows from the message when possible (text),
/// or owns a new allocation when required (binary hex encoding).
enum PreviewStr<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl std::fmt::Display for PreviewStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreviewStr::Borrowed(s) => f.write_str(s),
            PreviewStr::Owned(s) => f.write_str(s),
        }
    }
}

/// Simple hex encoding for binary payload previews.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Emit a structured log at the given tracing level.
///
/// tracing macros require the level as a compile-time token, so we use a macro
/// to deduplicate the field list across Trace/Debug/Info without 6x copy-paste.
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
        // the preview inside the macro guard to avoid wasted work.
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
        }

        // Never transform frames — purely observational
        None
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
