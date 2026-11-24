//! RTDS overlay keys for the `request_transformer` plugin.
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.request_transformer.<scope>.enabled` → `Bool`
//!
//! Plugin behaviour: when `runtime_overlay_scope: "<scope>"` is set on a
//! `request_transformer` instance, the accepted overlay's gate for that scope
//! is folded into the instance's own configuration on the mesh cold path
//! ([`scope_gates`] + [`crate::plugins::utils::transformer_gate::materialize_resolved_gate`]).
//! A `false` value short-circuits header, query, and body rule application; a
//! `true` value applies the rules normally. A scope the accepted overlay does
//! not name falls back to `default_enabled` from plugin config (defaults to
//! `true` so adding RTDS support is fail-open).
//!
//! The gate is therefore published in the same `RequestEpoch` as the rules it
//! gates and resolved once, immutably, at plugin construction — the request
//! path performs no overlay lookup at all (GHSA-83rc-23c9-3g9x). Unlike the
//! response side, whose published gate map carries the policy identity
//! `response_caching` and `request_deduplication` bind retained
//! representations to, nothing reads a published request-side map, so there is
//! no process-global store here (issue #7152).

use std::collections::HashMap;

use crate::modes::mesh::config::MeshRuntimeOverlay;
use crate::plugins::utils::transformer_gate;

pub(crate) const KEY_PREFIX: &str = "ferrum.request_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

/// The request-transformer gate namespace of `overlay`, for cold-path binding
/// of candidate instance configs.
pub fn scope_gates(overlay: &MeshRuntimeOverlay) -> HashMap<String, bool> {
    transformer_gate::scope_gates(overlay, KEY_PREFIX, ENABLED_SUFFIX)
}
