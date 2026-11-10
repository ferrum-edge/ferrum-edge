//! RTDS overlay consumer for the `request_transformer` plugin.
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
//! path performs no overlay lookup at all (GHSA-83rc-23c9-3g9x). The
//! process-global store below is retained for provenance/observability only:
//! `response_caching` and `request_deduplication` bind representations they
//! retain to the response-side publication identity, and both stores keep
//! publishing post-accept so that provenance stays available. Nothing
//! behavioral reads them.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::modes::mesh::config::MeshRuntimeOverlay;
use crate::plugins::utils::runtime_bool_gate::{self, BoolGateStore};
use crate::plugins::utils::transformer_gate;

pub(crate) const KEY_PREFIX: &str = "ferrum.request_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

static GATES: LazyLock<BoolGateStore> = LazyLock::new(runtime_bool_gate::new_store);

pub type GateSnapshot = runtime_bool_gate::BoolGateSnapshot;

/// The live published gate map.
///
/// Provenance/observability only — no plugin phase consults it, since the gate
/// that governs rule application is bound into the instance config and resolved
/// at construction (GHSA-83rc-23c9-3g9x). Reachable from `tests/`.
pub fn current_gates() -> GateSnapshot {
    runtime_bool_gate::current_snapshot(&GATES)
}

pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    runtime_bool_gate::apply_overlay(&GATES, overlay, KEY_PREFIX, ENABLED_SUFFIX);
}

/// The request-transformer gate namespace of `overlay`, for cold-path binding
/// of candidate instance configs. Independent of the published store, so a
/// rejected slice's gates never reach an instance.
pub fn scope_gates(overlay: &MeshRuntimeOverlay) -> HashMap<String, bool> {
    transformer_gate::scope_gates(overlay, KEY_PREFIX, ENABLED_SUFFIX)
}

/// Reset state for tests in external crates. `pub` + `#[doc(hidden)]` so
/// the symbol is reachable from `tests/unit/plugins/*` and
/// `tests/integration/*` without ad-hoc visibility hacks. Not part of the
/// library's public surface.
#[doc(hidden)]
pub fn reset_for_test() {
    runtime_bool_gate::reset(&GATES);
}
