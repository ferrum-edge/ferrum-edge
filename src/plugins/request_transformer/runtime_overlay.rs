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

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;

use crate::modes::mesh::config::MeshRuntimeOverlay;
#[cfg(test)]
use crate::modes::mesh::config::RuntimeValue;

pub(crate) const KEY_PREFIX: &str = "ferrum.request_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

type GateMap = HashMap<String, bool>;

static GATES: LazyLock<ArcSwap<GateMap>> = LazyLock::new(|| ArcSwap::new(Arc::new(HashMap::new())));

/// Cheap process-wide snapshot of the current gate state.
#[derive(Clone)]
pub struct GateSnapshot {
    inner: Arc<GateMap>,
}

impl GateSnapshot {
    /// `Some(value)` when the overlay carried `ferrum.request_transformer.<scope>.enabled`;
    /// `None` otherwise so the plugin can fall back to its static default.
    pub fn gate(&self, scope: &str) -> Option<bool> {
        self.inner.get(scope).copied()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

pub fn current_gates() -> GateSnapshot {
    GateSnapshot {
        inner: GATES.load_full(),
    }
}

pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    let mut next: GateMap = HashMap::new();
    crate::plugins::utils::transformer_gate::collect_gates(
        overlay,
        KEY_PREFIX,
        ENABLED_SUFFIX,
        &mut next,
    );
    GATES.store(Arc::new(next));
}

/// Reset state for tests in external crates. `pub` + `#[doc(hidden)]` so
/// the symbol is reachable from `tests/unit/plugins/*` and
/// `tests/integration/*` without ad-hoc visibility hacks. Not part of the
/// library's public surface; the binary build path does not consume it
/// — hence the `#[allow(dead_code)]`.
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_test() {
    GATES.store(Arc::new(HashMap::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn overlay(entries: &[(&str, RuntimeValue)]) -> MeshRuntimeOverlay {
        let mut fields = HashMap::new();
        for (key, value) in entries {
            fields.insert((*key).to_string(), value.clone());
        }
        MeshRuntimeOverlay { fields }
    }

    #[test]
    fn applies_bool_gate_per_scope() {
        let _guard = test_guard();
        reset_for_test();
        apply_overlay(&overlay(&[
            (
                "ferrum.request_transformer.public.enabled",
                RuntimeValue::Bool(false),
            ),
            (
                "ferrum.request_transformer.internal.enabled",
                RuntimeValue::Bool(true),
            ),
        ]));
        let snap = current_gates();
        assert_eq!(snap.gate("public"), Some(false));
        assert_eq!(snap.gate("internal"), Some(true));
        assert_eq!(snap.gate("missing"), None);
    }

    #[test]
    fn ignores_non_bool_values() {
        let _guard = test_guard();
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.request_transformer.bad.enabled",
            RuntimeValue::Number(1.0),
        )]));
        let snap = current_gates();
        assert!(snap.is_empty());
    }

    #[test]
    fn empty_scope_is_ignored() {
        let _guard = test_guard();
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.request_transformer..enabled",
            RuntimeValue::Bool(true),
        )]));
        let snap = current_gates();
        assert!(snap.is_empty());
    }

    #[test]
    fn empty_overlay_clears_state() {
        let _guard = test_guard();
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.request_transformer.cart.enabled",
            RuntimeValue::Bool(false),
        )]));
        assert_eq!(current_gates().gate("cart"), Some(false));
        apply_overlay(&MeshRuntimeOverlay::default());
        assert_eq!(current_gates().gate("cart"), None);
    }
}
