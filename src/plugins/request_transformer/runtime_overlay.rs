//! RTDS overlay consumer for the `request_transformer` plugin.
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.request_transformer.<scope>.enabled` → `Bool`
//!
//! Plugin behaviour: when `runtime_overlay_scope: "<scope>"` is set on a
//! `request_transformer` instance, the plugin reads its gate from the
//! global snapshot at request time. A `false` value short-circuits header,
//! query, and body rule application; a `true` value applies the rules
//! normally. A missing entry falls back to `default_enabled` from plugin
//! config (defaults to `true` so adding RTDS support is fail-open).
//!
//! Cold path rebuilds a `HashMap<String, bool>` and stores it on a
//! process-global `ArcSwap`. Hot path: one `Arc<HashMap>` clone per
//! request — no map allocation, no locking.

use std::sync::LazyLock;

use crate::modes::mesh::config::MeshRuntimeOverlay;
use crate::plugins::utils::runtime_bool_gate::{self, BoolGateStore};

pub(crate) const KEY_PREFIX: &str = "ferrum.request_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

static GATES: LazyLock<BoolGateStore> = LazyLock::new(runtime_bool_gate::new_store);

pub type GateSnapshot = runtime_bool_gate::BoolGateSnapshot;

pub fn current_gates() -> GateSnapshot {
    runtime_bool_gate::current_snapshot(&GATES)
}

pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    runtime_bool_gate::apply_overlay(&GATES, overlay, KEY_PREFIX, ENABLED_SUFFIX);
}

/// Reset state for tests in external crates. `pub` + `#[doc(hidden)]` so
/// the symbol is reachable from `tests/unit/plugins/*` and
/// `tests/integration/*` without ad-hoc visibility hacks. Not part of the
/// library's public surface; the binary build path does not consume it
/// — hence the `#[allow(dead_code)]`.
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_test() {
    runtime_bool_gate::reset(&GATES);
}
