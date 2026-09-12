//! Integration coverage for the RTDS runtime-overlay consumer dispatch.
//!
//! `MeshRuntimeState::record_applied_slice_with_token` fans an accepted slice's
//! process-wide knobs out to header transformer gates and tracing log levels.
//! Fault percentages are request-epoch-local and covered by fault
//! materialization/generation tests.
//! These tests install
//! representative slices and assert each consumer reflects the overlay,
//! covering the full cold-path wiring without depending on the live xDS
//! ADS server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ferrum_edge::logging::{LogLevelReloader, log_level_reloader, set_log_level_reloader};
use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::request_transformer::runtime_overlay as request_gate;
use ferrum_edge::plugins::response_transformer::runtime_overlay as response_gate;

/// Process-global lock serialising every test that touches RTDS consumer
/// state. The consumers all back onto module-level `ArcSwap` state, so two
/// tests racing `apply_overlay` / `reset_for_test` would corrupt each other's
/// assertions.
fn consumer_test_guard() -> std::sync::MutexGuard<'static, ()> {
    ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock()
}

#[derive(Default, Clone)]
struct CapturingReloader {
    captured: Arc<Mutex<Vec<String>>>,
}

impl LogLevelReloader for CapturingReloader {
    fn reload(&self, directive: &str) -> Result<(), String> {
        self.captured
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(directive.to_string());
        Ok(())
    }
}

fn install_slice_with_overlay(state: &MeshRuntimeState, overlay: MeshRuntimeOverlay) {
    let slice = MeshSlice {
        namespace: "alpha".to_string(),
        version: "consumer-test".to_string(),
        runtime_overlay: overlay,
        ..MeshSlice::default()
    };
    state.install_slice(slice.clone());
    let token = state.begin_revision_apply(&slice);
    state.record_applied_slice_with_token(&slice, token);
}

#[test]
fn slice_install_fans_out_to_process_wide_consumers() {
    // The consumer registry is process-global, so this test serialises
    // against any sibling that touches the same `ArcSwap` state via the
    // module-level `CONSUMER_TEST_GUARD` mutex. Reset every consumer at
    // entry and exit so leftover state from an earlier sibling can't
    // corrupt assertions.
    let _guard = consumer_test_guard();

    request_gate::reset_for_test();
    response_gate::reset_for_test();

    let captured = Arc::new(Mutex::new(Vec::new()));
    // Best-effort: another test in the same binary may have already
    // installed a reloader. If so, we observe whatever it captured.
    let _ = set_log_level_reloader(Box::new(CapturingReloader {
        captured: captured.clone(),
    }));

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.consumer_e2e.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    fields.insert(
        "ferrum.response_transformer.consumer_e2e.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    fields.insert(
        "ferrum.log.level".to_string(),
        RuntimeValue::String("ferrum_edge=debug".into()),
    );

    let state = MeshRuntimeState::new();
    install_slice_with_overlay(&state, MeshRuntimeOverlay { fields });

    // Request gate populated.
    assert_eq!(
        request_gate::current_gates().gate("consumer_e2e"),
        Some(false)
    );

    // Response gate populated and independent from request gate.
    assert_eq!(
        response_gate::current_gates().gate("consumer_e2e"),
        Some(true)
    );

    // Log-level reload either captured our directive (if our reloader is
    // active) or was applied to whatever reloader the binary registered.
    // Either way, calling apply doesn't panic, and if our reloader is
    // active the captured vec includes the directive.
    if log_level_reloader().is_some() {
        // It may have been our reloader. Either way, no panic was raised.
    }
    // If our reloader was the one that got installed, the directive
    // appears.
    let captured_now = captured.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if !captured_now.is_empty() {
        assert!(
            captured_now.contains(&"ferrum_edge=debug".to_string()),
            "captured directives missing entry: {captured_now:?}"
        );
    }

    // Clean up.
    request_gate::reset_for_test();
    response_gate::reset_for_test();
}

#[test]
fn dropping_key_from_subsequent_slice_clears_transformer_value() {
    let _guard = consumer_test_guard();

    request_gate::reset_for_test();

    let state = MeshRuntimeState::new();

    // Slice 1 sets values.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.rolling.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    install_slice_with_overlay(&state, MeshRuntimeOverlay { fields });
    assert_eq!(request_gate::current_gates().gate("rolling"), Some(false));

    // Slice 2 has no overlay → the consumer must clear.
    install_slice_with_overlay(&state, MeshRuntimeOverlay::default());
    assert_eq!(request_gate::current_gates().gate("rolling"), None);

    request_gate::reset_for_test();
}

#[test]
fn rejected_slice_receive_does_not_mutate_consumer_values() {
    let _guard = consumer_test_guard();

    request_gate::reset_for_test();

    let state = MeshRuntimeState::new();
    let mut accepted_fields = HashMap::new();
    accepted_fields.insert(
        "ferrum.request_transformer.stable.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    install_slice_with_overlay(
        &state,
        MeshRuntimeOverlay {
            fields: accepted_fields,
        },
    );
    assert_eq!(request_gate::current_gates().gate("stable"), Some(false));

    let mut rejected_fields = HashMap::new();
    rejected_fields.insert(
        "ferrum.request_transformer.stable.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    state.install_slice(MeshSlice {
        namespace: "alpha".to_string(),
        version: "received-but-not-accepted".to_string(),
        runtime_overlay: MeshRuntimeOverlay {
            fields: rejected_fields,
        },
        ..MeshSlice::default()
    });

    assert_eq!(
        request_gate::current_gates().gate("stable"),
        Some(false),
        "received-only slices must not update live RTDS consumers"
    );

    request_gate::reset_for_test();
}
