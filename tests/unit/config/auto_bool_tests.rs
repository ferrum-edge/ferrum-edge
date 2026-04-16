//! Tests for `AutoBool` — the tri-state (auto/true/false) toggle used by
//! Linux-specific optimization env vars.
//!
//! These tests only exercise the `AutoBool` enum methods (`resolve`,
//! `could_be_enabled`, `Display`). Parsing is handled by the private
//! `resolve_auto_bool` helper in `env_config.rs` which is exercised by
//! `env_config_tests.rs` when it reads the actual env vars (e.g.
//! `FERRUM_KTLS_ENABLED`, `FERRUM_IO_URING_SPLICE_ENABLED`).

use ferrum_edge::config::AutoBool;

#[test]
fn resolve_auto_calls_probe_and_returns_true() {
    let result = AutoBool::Auto.resolve(|| true);
    assert!(
        result,
        "Auto must return the probe's value when probe is true"
    );
}

#[test]
fn resolve_auto_calls_probe_and_returns_false() {
    let result = AutoBool::Auto.resolve(|| false);
    assert!(
        !result,
        "Auto must return the probe's value when probe is false"
    );
}

#[test]
fn resolve_true_does_not_call_probe_and_returns_true() {
    // Prove the probe is not invoked by having it panic if called.
    let result = AutoBool::True.resolve(|| panic!("probe must not be called for True"));
    assert!(result, "True must short-circuit to true without probing");
}

#[test]
fn resolve_false_does_not_call_probe_and_returns_false() {
    let result = AutoBool::False.resolve(|| panic!("probe must not be called for False"));
    assert!(!result, "False must short-circuit to false without probing");
}

#[test]
fn could_be_enabled_true_for_auto_and_true() {
    assert!(AutoBool::Auto.could_be_enabled());
    assert!(AutoBool::True.could_be_enabled());
}

#[test]
fn could_be_enabled_false_only_for_false() {
    assert!(!AutoBool::False.could_be_enabled());
}

#[test]
fn display_round_trip() {
    assert_eq!(format!("{}", AutoBool::Auto), "auto");
    assert_eq!(format!("{}", AutoBool::True), "true");
    assert_eq!(format!("{}", AutoBool::False), "false");
}

#[test]
fn auto_bool_copy_and_eq() {
    // Copy + Eq + PartialEq are needed because `EnvConfig` holds AutoBool by value
    // and the code reads the same value from multiple places.
    let a = AutoBool::Auto;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(a, AutoBool::False);
}
