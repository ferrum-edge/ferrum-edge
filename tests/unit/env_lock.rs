//! Process-wide environment lock shared by every env-var-mutating unit test.
//!
//! `cargo test --test unit_tests` runs tests in parallel, so any two tests
//! that read or write the same `FERRUM_*` process env var must serialize
//! against a single mutex — otherwise one test's mutation races another's
//! read. The config env-var helper (`config::env_config_tests`), the identity
//! guardrail tests (`identity::env_guard`), the CLI tests (`cli::cli_tests`),
//! every secret-backend suite under `secrets::*`, and
//! `plugins::serverless_function_tests` all acquire THIS lock, so e.g. an
//! identity test toggling `FERRUM_MESH_PRODUCTION_MODE` can never interleave
//! with a config test that reads it through `EnvConfig::from_env()`.
//!
//! Guarded tests also isolate from ambient `FERRUM_*` variables left in the
//! process by a locally running gateway. [`EnvGuard`], [`with_env_vars`],
//! [`without_env_vars`], [`with_env_vars_async`], and
//! [`StreamAuthMaxLifetimeGuard`] snapshot every present `FERRUM_*` key,
//! remove them for the duration of the guard, and restore the exact original
//! `OsString` values on drop. Variables a test sets through the helper stay
//! visible until drop; they are not treated as ambient.
//!
//! A per-file mutex is NOT an acceptable substitute and must not be
//! reintroduced. It orders a file against itself only, which leaves `set_var`
//! in one module racing `getenv` in another — the exact undefined behavior
//! Rust 2024 made `set_var` unsafe to flag. It also produced a subtler bug:
//! `secrets::redaction_tests` builds a lazily cached, process-wide redaction
//! plan by reading fixture variables back out of the environment, so a
//! concurrently mutating test elsewhere could get that cache built from
//! transient state and poison every later assertion in the binary.
//!
//! Acquire it poison-tolerantly (`unwrap_or_else(|p| p.into_inner())`). It
//! guards no invariant of its own, only mutual exclusion, so one panicking
//! test must not cascade into unrelated failures across the whole binary.
#![allow(dead_code)] // used by sibling test modules

use std::ffi::{OsStr, OsString};
use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());

fn is_ferrum_key(key: impl AsRef<OsStr>) -> bool {
    key.as_ref()
        .to_str()
        .is_some_and(|key| key.starts_with("FERRUM_"))
}

fn present_ferrum_vars() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(key, _)| is_ferrum_key(key))
        .collect()
}

/// Snapshot every present `FERRUM_*` variable and remove it. Caller holds
/// [`ENV_LOCK`].
fn capture_and_clear_ferrum_vars() -> Vec<(OsString, OsString)> {
    let saved = present_ferrum_vars();
    for (key, _) in &saved {
        // SAFETY: caller holds ENV_LOCK.
        unsafe { std::env::remove_var(key) }
    }
    saved
}

/// Remove every current `FERRUM_*` variable, then restore `saved`. Caller
/// holds [`ENV_LOCK`]. Test-set keys that were not ambient stay unset.
fn restore_ferrum_vars(saved: &[(OsString, OsString)]) {
    for (key, _) in present_ferrum_vars() {
        // SAFETY: caller holds ENV_LOCK.
        unsafe { std::env::remove_var(key) }
    }
    for (key, value) in saved {
        // SAFETY: caller holds ENV_LOCK.
        unsafe { std::env::set_var(key, value) }
    }
}

/// Poison-tolerant RAII guard for tests that read or mutate process environment.
///
/// The guard owns [`ENV_LOCK`], clears every ambient `FERRUM_*` variable,
/// snapshots any extra named (including non-`FERRUM_*`) keys, and restores
/// the captured state on drop so failures cannot leak test state.
pub struct EnvGuard {
    saved_ferrum: Vec<(OsString, OsString)>,
    saved_extra: Vec<(String, Option<OsString>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn new(keys: &[&str]) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved_extra = keys
            .iter()
            .filter(|key| !is_ferrum_key(*key))
            .map(|key| (key.to_string(), std::env::var_os(key)))
            .collect();
        let saved_ferrum = capture_and_clear_ferrum_vars();
        Self {
            saved_ferrum,
            saved_extra,
            _lock: lock,
        }
    }

    pub fn set(&self, key: &str, value: &str) {
        // SAFETY: this guard owns the process-wide environment lock.
        unsafe { std::env::set_var(key, value) }
    }

    pub fn unset(&self, key: &str) {
        // SAFETY: this guard owns the process-wide environment lock.
        unsafe { std::env::remove_var(key) }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: `Drop::drop` runs while all fields, including `_lock`,
        // remain alive, so restoration is still serialized by ENV_LOCK.
        restore_ferrum_vars(&self.saved_ferrum);
        for (key, value) in &self.saved_extra {
            // SAFETY: `_lock` is still alive, so extra-key restoration is
            // serialized by ENV_LOCK.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// Set `vars`, run `f`, then restore ambient `FERRUM_*` (and the named keys).
///
/// Holds [`ENV_LOCK`] for the whole call so parallel tests cannot interleave.
pub fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let keys: Vec<&str> = vars.iter().map(|(key, _)| *key).collect();
    let guard = EnvGuard::new(&keys);
    for (key, value) in vars {
        guard.set(key, value);
    }
    f();
}

/// Unset `vars`, run `f`, then restore ambient `FERRUM_*` (and the named keys).
///
/// Holds [`ENV_LOCK`] for the whole call so parallel tests cannot interleave.
pub fn without_env_vars<F: FnOnce()>(vars: &[&str], f: F) {
    let guard = EnvGuard::new(vars);
    for key in vars {
        guard.unset(key);
    }
    f();
}

/// Async counterpart of [`with_env_vars`]. Drives `f` on a current-thread
/// runtime while [`ENV_LOCK`] is held.
pub fn with_env_vars_async<F, Fut>(vars: &[(&str, &str)], f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let keys: Vec<&str> = vars.iter().map(|(key, _)| *key).collect();
    let guard = EnvGuard::new(&keys);
    for (key, value) in vars {
        guard.set(key, value);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("env-isolation async test runtime");
    rt.block_on(f());
}

/// Poison-tolerant RAII guard for tests that write the process-wide validated
/// `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` scalar
/// (`proxy::auth_lifetime`).
///
/// It owns THE SAME [`ENV_LOCK`], deliberately — not a second mutex. The
/// scalar's only production writer is the accepted startup configuration, so
/// the tests that write it are exactly the tests that also drive `EnvConfig`,
/// and a second lock domain would either leave the two racing or introduce a
/// lock-ordering hazard between them. One domain, no ordering to get wrong.
///
/// Ambient `FERRUM_*` variables are isolated for the same reason
/// [`EnvGuard`] isolates them: those tests call `EnvConfig::from_env()`.
/// The previous scalar value is restored on drop, so a test that changes
/// the maximum cannot contaminate any later test in the binary — including
/// the ones that assert the documented `3600` default.
pub struct StreamAuthMaxLifetimeGuard {
    saved_ferrum: Vec<(OsString, OsString)>,
    saved: u64,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl StreamAuthMaxLifetimeGuard {
    pub fn new() -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved_ferrum = capture_and_clear_ferrum_vars();
        let saved =
            ferrum_edge::_test_support::authenticated_stream_max_lifetime_seconds_for_test();
        Self {
            saved_ferrum,
            saved,
            _lock: lock,
        }
    }

    /// Publish a value for the duration of this guard.
    pub fn publish(&self, seconds: u64) {
        ferrum_edge::_test_support::publish_authenticated_stream_max_lifetime_seconds_for_test(
            seconds,
        );
    }

    /// The currently published value.
    pub fn published(&self) -> u64 {
        ferrum_edge::_test_support::authenticated_stream_max_lifetime_seconds_for_test()
    }
}

impl Default for StreamAuthMaxLifetimeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StreamAuthMaxLifetimeGuard {
    fn drop(&mut self) {
        // Runs while `_lock` is still alive, so restoration stays serialized.
        restore_ferrum_vars(&self.saved_ferrum);
        ferrum_edge::_test_support::publish_authenticated_stream_max_lifetime_seconds_for_test(
            self.saved,
        );
    }
}
