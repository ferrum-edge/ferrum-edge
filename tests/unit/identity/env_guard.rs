//! Cross-test serialization helper for env-var-touching identity tests.
//!
//! Several tests under `tests/unit/identity/` modify `FERRUM_MESH_*` env
//! vars to exercise dev / production gates. Cargo runs tests in parallel by
//! default, so without a shared lock concurrent tests would race each
//! other's env-var reads. Identity tests use the process-wide [`EnvGuard`]
//! in `tests/unit/env_lock.rs`, which:
//!   1. Locks `ENV_LOCK` for the lifetime of the guard.
//!   2. Clears every ambient `FERRUM_*` variable and snapshots extra named
//!      keys on construction.
//!   3. Restores them on drop.
//!
//! Every env-touching test in `identity/` should hold one of these guards
//! until **after** every assertion that depends on the env state.

#![allow(dead_code)] // used by sibling test files
pub use crate::unit::env_lock::EnvGuard;
