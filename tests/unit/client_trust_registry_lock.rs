//! Process-wide lock shared by every unit test that touches the frontend
//! client-trust registry (`ferrum_edge::tls::client_trust`).
//!
//! The registry is process-global by design, and `reset_for_test` clears every
//! scope, so all tests in one binary that publish to or reset it must hold the
//! same lock: two modules with private locks would reset each other mid-test.
//! This test-free module is compiled by every unit target that needs the lock
//! (`unit_tests` for `tls::*`, `unit_gateway_core_tests` for the DTLS frontend
//! tests), so neither target has to compile the other's test modules.
#![allow(dead_code)] // used by sibling test modules

use std::sync::{Mutex, MutexGuard, OnceLock};

/// The one lock every test in this binary that touches the process-global trust
/// registry must hold.
pub(crate) fn registry_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Take the registry lock and reset every scope. Held for the test body.
pub(crate) fn isolated_registry() -> MutexGuard<'static, ()> {
    let guard = registry_lock();
    ferrum_edge::tls::client_trust::reset_for_test();
    guard
}
