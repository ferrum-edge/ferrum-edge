//! WebSocket Message Size Limiting Plugin
//!
//! Enforces per-proxy frame and reassembled-message limits on WebSocket
//! connections. The shared relay installs these limits in both tungstenite
//! parsers before reads, so declared oversized frames are rejected before
//! payload reservation and fragmented messages have an independent bound.
//!
//! This is the WebSocket equivalent of `request_size_limiting` for HTTP.
//! Its parser policy automatically keeps tunnel mode disabled; enforcement
//! does not use `on_ws_frame` because that hook receives reassembled messages.
//!
//! Config:
//! ```json
//! {
//!   "max_frame_bytes": 65536,
//!   "max_message_bytes": 262144,
//!   "close_reason": "Message too large",
//!   "backend_to_client": { "max_frame_bytes": 1048576, "max_message_bytes": 4194304 }
//! }
//! ```
//!
//! The top-level fields are the default for both directions. The optional
//! `client_to_backend` / `backend_to_client` objects override any of the same
//! three fields for frames read from that peer, so a tight client bound can
//! coexist with larger backend pushes. Both directions are resolved once at
//! construction; the relay only reads the precomputed values per session.

use serde_json::{Map, Value};
use std::sync::Arc;
use tracing::warn;

use super::utils::size_limit::required_positive_usize;
use super::{
    Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketDirectionSizeLimits, WebSocketSizeLimits,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// Authoritative closed set of top-level `ws_message_size_limiting` configuration keys.
const WS_MESSAGE_SIZE_LIMITING_CONFIG_KEYS: &[&str] = &[
    "backend_to_client",
    "client_to_backend",
    "close_reason",
    "max_frame_bytes",
    "max_message_bytes",
];

/// Authoritative closed set of keys inside a per-direction override object.
const WS_MESSAGE_SIZE_LIMITING_DIRECTION_KEYS: &[&str] =
    &["close_reason", "max_frame_bytes", "max_message_bytes"];

const DEFAULT_CLOSE_REASON: &str = "Message too large";

/// One per-direction override block and its diagnostic labels.
struct DirectionOverride {
    key: &'static str,
    /// Plugin label for the shared positive-size diagnostics.
    label: &'static str,
}

const CLIENT_TO_BACKEND: DirectionOverride = DirectionOverride {
    key: "client_to_backend",
    label: "ws_message_size_limiting: `client_to_backend`",
};

const BACKEND_TO_CLIENT: DirectionOverride = DirectionOverride {
    key: "backend_to_client",
    label: "ws_message_size_limiting: `backend_to_client`",
};

/// Explicitly configured values at one level (top level or one override).
struct ConfiguredLimits<'a> {
    max_frame_bytes: Option<usize>,
    max_message_bytes: Option<usize>,
    close_reason: Option<&'a str>,
}

pub struct WsMessageSizeLimiting {
    limits: WebSocketSizeLimits,
}

impl WsMessageSizeLimiting {
    const MAX_CLOSE_REASON_BYTES: usize = 123;

    pub fn new(config: &Value) -> Result<Self, String> {
        let Some(config_obj) = config.as_object() else {
            return Err("ws_message_size_limiting: config must be an object".to_string());
        };
        reject_unknown_keys(
            config_obj,
            "config",
            WS_MESSAGE_SIZE_LIMITING_CONFIG_KEYS,
            "ws_message_size_limiting: `config`: ",
        )?;

        let max_frame_bytes =
            required_positive_usize(config, "max_frame_bytes", "ws_message_size_limiting")?;
        let max_message_bytes = match config.get("max_message_bytes") {
            Some(_) => Some(required_positive_usize(
                config,
                "max_message_bytes",
                "ws_message_size_limiting",
            )?),
            None => None,
        };
        let top = ConfiguredLimits {
            max_frame_bytes: Some(max_frame_bytes),
            max_message_bytes,
            close_reason: optional_string(config, "close_reason", "ws_message_size_limiting")?,
        };
        // The top level is the default for both directions and must be valid
        // on its own, whatever the overrides change.
        let default_limits = Self::resolve(&top, None, "ws_message_size_limiting")?;

        let client_to_backend =
            Self::resolve_override(config_obj, &CLIENT_TO_BACKEND, &top, &default_limits)?;
        let backend_to_client =
            Self::resolve_override(config_obj, &BACKEND_TO_CLIENT, &top, &default_limits)?;

        Ok(Self {
            limits: WebSocketSizeLimits {
                client_to_backend,
                backend_to_client,
            },
        })
    }

    /// Resolve one direction: the override's values win, the top level fills
    /// the rest, and a message ceiling set at neither level defaults to four
    /// times that direction's frame ceiling.
    fn resolve_override(
        config_obj: &Map<String, Value>,
        direction: &DirectionOverride,
        top: &ConfiguredLimits<'_>,
        default_limits: &WebSocketDirectionSizeLimits,
    ) -> Result<WebSocketDirectionSizeLimits, String> {
        let Some(value) = config_obj.get(direction.key) else {
            return Ok(default_limits.clone());
        };
        let Some(override_obj) = value.as_object() else {
            return Err(format!("{}: must be an object", direction.label));
        };
        reject_unknown_keys(
            override_obj,
            &format!("config.{}", direction.key),
            WS_MESSAGE_SIZE_LIMITING_DIRECTION_KEYS,
            &format!("{}: ", direction.label),
        )?;
        let overridden = ConfiguredLimits {
            max_frame_bytes: match override_obj.get("max_frame_bytes") {
                Some(_) => Some(required_positive_usize(
                    value,
                    "max_frame_bytes",
                    direction.label,
                )?),
                None => None,
            },
            max_message_bytes: match override_obj.get("max_message_bytes") {
                Some(_) => Some(required_positive_usize(
                    value,
                    "max_message_bytes",
                    direction.label,
                )?),
                None => None,
            },
            close_reason: optional_string(value, "close_reason", direction.label)?,
        };
        Self::resolve(top, Some(&overridden), direction.label)
    }

    fn resolve(
        top: &ConfiguredLimits<'_>,
        overridden: Option<&ConfiguredLimits<'_>>,
        label: &str,
    ) -> Result<WebSocketDirectionSizeLimits, String> {
        // The top level always carries a validated frame ceiling; the zero
        // check keeps that invariant explicit instead of unwrapping it.
        let max_frame_bytes = overridden
            .and_then(|limits| limits.max_frame_bytes)
            .or(top.max_frame_bytes)
            .unwrap_or(0);
        if max_frame_bytes == 0 {
            return Err(format!(
                "{label}: `max_frame_bytes` is required and must be greater than zero"
            ));
        }
        let max_message_bytes = overridden
            .and_then(|limits| limits.max_message_bytes)
            .or(top.max_message_bytes)
            .unwrap_or_else(|| max_frame_bytes.saturating_mul(4));
        if max_message_bytes < max_frame_bytes {
            return Err(format!(
                "{label}: `max_message_bytes` must be greater than or equal to `max_frame_bytes`"
            ));
        }
        let close_reason = overridden
            .and_then(|limits| limits.close_reason)
            .or(top.close_reason)
            .unwrap_or(DEFAULT_CLOSE_REASON);
        Ok(WebSocketDirectionSizeLimits {
            max_frame_bytes,
            max_message_bytes,
            close_reason: Arc::from(Self::bounded_close_reason(close_reason)),
        })
    }

    fn bounded_close_reason(close_reason: &str) -> &str {
        if close_reason.len() <= Self::MAX_CLOSE_REASON_BYTES {
            return close_reason;
        }
        warn!(
            max_bytes = Self::MAX_CLOSE_REASON_BYTES,
            "ws_message_size_limiting: `close_reason` exceeds WebSocket limit — truncating"
        );
        &close_reason[..Self::truncate_utf8_boundary(close_reason, Self::MAX_CLOSE_REASON_BYTES)]
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }
}

fn optional_string<'a>(
    config: &'a Value,
    field: &'static str,
    label: &str,
) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("{label}: `{field}` must be a string"))
}

impl Plugin for WsMessageSizeLimiting {
    fn name(&self) -> &str {
        "ws_message_size_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_MESSAGE_SIZE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn websocket_size_limits(&self) -> Option<WebSocketSizeLimits> {
        Some(self.limits.clone())
    }
}
