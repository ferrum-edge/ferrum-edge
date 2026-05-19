//! RTDS overlay consumer for the `response_transformer` plugin.
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.response_transformer.<scope>.enabled` → `Bool`
//!
//! Mirrors the `request_transformer` overlay consumer
//! ([`crate::plugins::request_transformer::runtime_overlay`]) — the two
//! plugins maintain independent gate maps so an operator can disable one
//! direction without affecting the other.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;

use crate::modes::mesh::config::MeshRuntimeOverlay;
#[cfg(test)]
use crate::modes::mesh::config::RuntimeValue;

pub(crate) const KEY_PREFIX: &str = "ferrum.response_transformer.";
pub(crate) const ENABLED_SUFFIX: &str = ".enabled";

type GateMap = HashMap<String, bool>;

static GATES: LazyLock<ArcSwap<GateMap>> = LazyLock::new(|| ArcSwap::new(Arc::new(HashMap::new())));

#[derive(Clone)]
pub struct GateSnapshot {
    inner: Arc<GateMap>,
}

impl GateSnapshot {
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

/// Same contract as
/// [`crate::plugins::request_transformer::runtime_overlay::reset_for_test`].
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
                "ferrum.response_transformer.public.enabled",
                RuntimeValue::Bool(true),
            ),
            (
                "ferrum.response_transformer.internal.enabled",
                RuntimeValue::Bool(false),
            ),
        ]));
        let snap = current_gates();
        assert_eq!(snap.gate("public"), Some(true));
        assert_eq!(snap.gate("internal"), Some(false));
    }

    #[test]
    fn ignores_request_keys() {
        let _guard = test_guard();
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.request_transformer.public.enabled",
            RuntimeValue::Bool(false),
        )]));
        assert!(current_gates().is_empty());
    }
}
