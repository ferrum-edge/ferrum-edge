//! Cross-test serialization helper for env-var-touching identity tests.
//!
//! Several tests under `tests/unit/identity/` modify `FERRUM_MESH_*` env
//! vars to exercise dev / production gates. Cargo runs tests in parallel by
//! default, so without a shared lock concurrent tests would race each
//! other's env-var reads. This module exposes a single static `Mutex` plus
//! an RAII `EnvGuard` that:
//!   1. Locks `ENV_LOCK` for the lifetime of the guard.
//!   2. Snapshots a list of env vars on construction.
//!   3. Restores them on drop.
//!
//! Every env-touching test in `identity/` should hold one of these guards
//! until **after** every assertion that depends on the env state.

#![allow(dead_code)] // used by sibling test files
// Re-export the process-wide shared env lock so identity tests serialize
// against config tests that read the same env vars (see tests/unit/env_lock.rs).
pub use crate::unit::env_lock::ENV_LOCK;

pub struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    keys: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    pub fn new(keys: &[&'static str]) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let snapshot = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect::<Vec<_>>();
        Self {
            _lock: lock,
            keys: snapshot,
        }
    }

    pub fn set(&self, k: &str, v: &str) {
        // SAFETY: we hold ENV_LOCK for the lifetime of this guard, and every
        // identity test that touches env vars goes through here, so no other
        // thread can be concurrently reading.
        unsafe { std::env::set_var(k, v) }
    }

    pub fn unset(&self, k: &str) {
        // SAFETY: see set().
        unsafe { std::env::remove_var(k) }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.keys {
            // SAFETY: serialised by ENV_LOCK.
            unsafe {
                match v {
                    Some(s) => std::env::set_var(k, s),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}
