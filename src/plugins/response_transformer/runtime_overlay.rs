//! RTDS overlay consumer for the `response_transformer` plugin.
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.response_transformer.<scope>.enabled` → `Bool`
//!
//! Mirrors the `request_transformer` overlay keys
//! ([`crate::plugins::request_transformer::runtime_overlay`]) — the two
//! plugins use independent gate namespaces so an operator can disable one
//! direction without affecting the other. As on the request side, the gate that
//! actually governs rule application is bound into the candidate instance
//! config on the cold path and published with its `RequestEpoch`
//! (GHSA-83rc-23c9-3g9x). The store below exists for its policy identity
//! ([`policy_stamp`]), which retained-representation caches bind to; the gate
//! values in it are provenance only.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::modes::mesh::config::MeshRuntimeOverlay;
use crate::plugins::utils::runtime_bool_gate::{self, BoolGateStore, GatePolicyStamp};
use crate::plugins::utils::transformer_gate;

pub(crate) const KEY_PREFIX: &str = "ferrum.response_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

static GATES: LazyLock<BoolGateStore> = LazyLock::new(runtime_bool_gate::new_store);

pub type GateSnapshot = runtime_bool_gate::BoolGateSnapshot;

/// The live published gate map. Provenance/observability only: no plugin
/// phase consults it, since the gate that governs rule application is bound
/// into the instance config and resolved at construction
/// (GHSA-83rc-23c9-3g9x). Reachable from `tests/`.
pub fn current_gates() -> GateSnapshot {
    runtime_bool_gate::current_snapshot(&GATES)
}

/// Opaque identity paired atomically with the live response-side gate map.
///
/// A cached representation is replayable only while this identity remains
/// current. The identity carries no gate, rule, header, or body content.
pub fn policy_stamp() -> GatePolicyStamp {
    runtime_bool_gate::current_policy_stamp(&GATES)
}

pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    runtime_bool_gate::apply_overlay(&GATES, overlay, KEY_PREFIX, ENABLED_SUFFIX);
}

/// The response-transformer gate namespace of `overlay`, for cold-path binding
/// of candidate instance configs. Independent of the published store, so a
/// rejected slice's gates never reach an instance.
pub fn scope_gates(overlay: &MeshRuntimeOverlay) -> HashMap<String, bool> {
    transformer_gate::scope_gates(overlay, KEY_PREFIX, ENABLED_SUFFIX)
}

/// Reset state for tests in external crates. `pub` + `#[doc(hidden)]` so the
/// symbol is reachable from `tests/` without ad-hoc visibility hacks.
#[doc(hidden)]
pub fn reset_for_test() {
    runtime_bool_gate::reset(&GATES);
}
