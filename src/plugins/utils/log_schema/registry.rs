//! Process-global registry of named [`SummarySchema`] definitions.
//!
//! Populated by the `transaction_log_schema` plugin at construction time;
//! consumed by other logging plugins that reference a schema by name via
//! `schema_ref:`.
//!
//! The inner map is wholly replaced on config reload via [`begin_reload`] +
//! [`commit_reload`] so renamed/removed schemas don't leak.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

use serde_json::Value;

use super::SummarySchema;

/// A registered named schema. Carries the raw definition alongside the
/// BASE-compiled form so a capability-bearing caller (`ws_logging`) can
/// recompile it under its own capability at resolve time (see
/// [`super::resolve_schema`]), while BASE callers keep sharing `compiled`.
#[derive(Clone)]
struct NamedSchema {
    raw: Arc<Value>,
    compiled: Arc<SummarySchema>,
}

#[derive(Default)]
struct RegistryState {
    /// Live map consulted by `lookup_named`.
    schemas: HashMap<String, NamedSchema>,
    /// Staging area built by `register_named` during reload; promoted on
    /// `commit_reload`.
    staging: Option<HashMap<String, NamedSchema>>,
}

fn registry() -> &'static RwLock<RegistryState> {
    static REGISTRY: OnceLock<RwLock<RegistryState>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(RegistryState::default()))
}

// Lock helpers recover from poisoning by extracting the inner guard.
//
// SAFETY rationale: the critical sections under this lock perform only
// HashMap inserts/removes and Option swaps — no I/O, no fallible
// allocations, no `?` propagation. A panic while held is therefore
// unlikely, but if it ever occurs the registry data itself is still
// structurally valid (the poison flag is the only thing wrong). Treating
// poison as fatal would brick every future `schema_ref` lookup across
// the process; recovering keeps the gateway serving from cached state.
// If fallible work is ever added inside these locks, reconsider this
// recovery strategy.
fn read_lock() -> RwLockReadGuard<'static, RegistryState> {
    registry().read().unwrap_or_else(PoisonError::into_inner)
}

fn write_lock() -> RwLockWriteGuard<'static, RegistryState> {
    registry().write().unwrap_or_else(PoisonError::into_inner)
}

// Process-wide reload-bracket serializer.
//
// Concurrent reload brackets would interleave: thread A's `begin_reload`
// clobbers thread B's just-built staging map, B's `register_named` writes
// into A's empty staging, and whichever commits last drops the other's
// schemas. plugin_cache reloads always run on the same thread in
// production, but parallel integration tests routinely race: any test
// that starts a gateway drives its own reload bracket on its test
// thread, and absent a process-wide lock those brackets clobber each
// other (and any in-flight test that's mid-bracket on another thread).
//
// `begin_reload` enters the bracket; `commit_reload` leaves it. A
// thread-local depth counter lets tests use `lock_for_tests()` around a
// complete reload plus assertions. Reload brackets themselves are deliberately
// non-reentrant: a nested `begin_reload` is an error rather than permission to
// replace the outer staging map.
fn reload_serializer() -> &'static Mutex<()> {
    static RELOAD: OnceLock<Mutex<()>> = OnceLock::new();
    RELOAD.get_or_init(|| Mutex::new(()))
}

struct BracketKeeper {
    /// Outermost holder's mutex guard. `Some` iff this thread currently
    /// holds the serializer; the inner `MutexGuard` is dropped when the
    /// outermost bracket leaves (depth → 0), releasing the mutex.
    outer_guard: Option<MutexGuard<'static, ()>>,
    /// Nesting depth — incremented by every `enter_bracket()` on this
    /// thread, decremented by every `leave_bracket()`.
    depth: u32,
    /// True only while this thread owns an actual begin/commit-or-abort reload
    /// pass. `lock_for_tests()` increments `depth` without setting this flag.
    reload_open: bool,
}

thread_local! {
    static KEEPER: RefCell<BracketKeeper> = const { RefCell::new(BracketKeeper {
        outer_guard: None,
        depth: 0,
        reload_open: false,
    }) };
}

/// Increment the bracket depth on the current thread, acquiring the
/// process-wide serializer if this is the outermost entry.
fn enter_bracket() {
    let need_acquire = KEEPER.with(|k| k.borrow().depth == 0);
    let guard = if need_acquire {
        // Acquire WITHOUT holding the RefCell borrow — `lock()` may block.
        Some(
            reload_serializer()
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    } else {
        None
    };
    KEEPER.with(|k| {
        let mut k = k.borrow_mut();
        if let Some(g) = guard {
            k.outer_guard = Some(g);
        }
        k.depth += 1;
    });
}

/// Decrement the bracket depth on the current thread, releasing the
/// process-wide serializer if this is the outermost exit.
///
/// In debug builds, panics when called without a matching prior
/// `enter_bracket` on the same thread. That state means either:
///   1. `commit_reload` / `abort_reload` ran on a different thread than
///      its `begin_reload` — the originating thread's mutex guard would
///      leak forever, deadlocking every subsequent reload.
///   2. `commit_reload` / `abort_reload` ran without a prior
///      `begin_reload` — the staging area was never opened.
///
/// Both are programming errors; release builds tolerate them (the live
/// map remains consistent — only future reloads on the originating
/// thread would block, which surfaces as a visible deadlock rather
/// than silent corruption).
fn leave_bracket() {
    KEEPER.with(|k| {
        let mut k = k.borrow_mut();
        debug_assert!(
            k.depth > 0,
            "log_schema::registry: leave_bracket called without a matching enter_bracket on this thread \
             (likely begin_reload and commit_reload/abort_reload ran on different threads)"
        );
        if k.depth > 0 {
            k.depth -= 1;
            if k.depth == 0 {
                k.outer_guard = None;
            }
        }
    });
}

/// Begin building a fresh named-schema map. Called once per config-load
/// pass before any `transaction_log_schema` plugin's `new()` runs.
///
/// Acquires the process-wide reload-bracket lock so two concurrent
/// reloads serialize at the bracket boundary (without serializing reads
/// against `lookup_named`). The lock is released by [`commit_reload`].
/// A test can hold the serializer via [`lock_for_tests`] and still call one
/// begin/commit pair normally within it. A second `begin_reload` before the
/// first pass closes returns an error and preserves the existing staging map.
///
/// **Threading invariant:** `begin_reload` / `register_named` /
/// `commit_reload` for one reload pass must all run on the same thread.
/// The serializer guard is stored thread-local; cross-thread brackets
/// leak the guard. plugin_cache and tests both satisfy this naturally.
pub fn begin_reload() -> Result<(), String> {
    enter_bracket();
    let nested = KEEPER.with(|keeper| keeper.borrow().reload_open);
    if nested {
        leave_bracket();
        return Err(
            "log_schema::registry: nested begin_reload on the same thread would clobber the active staging map"
                .to_string(),
        );
    }

    let staging_already_open = {
        let mut state = write_lock();
        if state.staging.is_some() {
            true
        } else {
            state.staging = Some(HashMap::new());
            false
        }
    };
    if staging_already_open {
        leave_bracket();
        return Err(
            "log_schema::registry: begin_reload found an active staging map without a matching reload owner"
                .to_string(),
        );
    }

    KEEPER.with(|keeper| keeper.borrow_mut().reload_open = true);
    Ok(())
}

/// Register a named schema into the in-progress reload staging area.
///
/// When called between [`begin_reload`] and [`commit_reload`] (the normal
/// loader path), writes to the staging map and rejects duplicates.
///
/// When called outside a reload pass (for example, isolated constructor
/// validation via `validate_plugin_config`), this is a no-op. Prospective
/// graph validation opens an abort-only bracket explicitly, so it detects
/// duplicates and resolves referrers without changing the live registry.
pub fn register_named(
    name: &str,
    raw: Arc<Value>,
    compiled: Arc<SummarySchema>,
) -> Result<(), String> {
    let mut state = write_lock();
    let Some(staging) = state.staging.as_mut() else {
        return Ok(()); // validation-mode no-op
    };
    if staging.contains_key(name) {
        return Err(format!(
            "transaction_log_schema: named schema '{name}' registered more than once"
        ));
    }
    staging.insert(name.to_string(), NamedSchema { raw, compiled });
    Ok(())
}

/// Promote the staging area to be the live map. Called after all
/// `transaction_log_schema` plugins for this reload pass have constructed
/// AND the rest of the plugin-cache build has succeeded. Decrements the
/// bracket depth (releases the serializer on outermost exit).
pub fn commit_reload() -> Result<(), String> {
    if !KEEPER.with(|keeper| keeper.borrow().reload_open) {
        return Err(
            "log_schema::registry: commit_reload called without an open reload on this thread"
                .to_string(),
        );
    }

    let promoted = {
        let mut state = write_lock();
        if let Some(staging) = state.staging.take() {
            state.schemas = staging;
            true
        } else {
            false
        }
    };
    KEEPER.with(|keeper| keeper.borrow_mut().reload_open = false);
    leave_bracket();
    if promoted {
        Ok(())
    } else {
        Err("log_schema::registry: commit_reload found no active staging map".to_string())
    }
}

/// Discard the staging area without promoting it. Called when the rest
/// of the plugin-cache build fails after schemas have been staged, so
/// the process-global live `schemas` map keeps reflecting the last
/// successfully-applied config. Decrements the bracket depth (releases
/// the serializer on outermost exit).
///
/// Always pair `begin_reload` with exactly one of `commit_reload` or
/// `abort_reload` on the same thread.
pub fn abort_reload() -> Result<(), String> {
    if !KEEPER.with(|keeper| keeper.borrow().reload_open) {
        return Err(
            "log_schema::registry: abort_reload called without an open reload on this thread"
                .to_string(),
        );
    }

    let discarded = {
        let mut state = write_lock();
        state.staging.take().is_some()
    };
    KEEPER.with(|keeper| keeper.borrow_mut().reload_open = false);
    leave_bracket();
    if discarded {
        Ok(())
    } else {
        Err("log_schema::registry: abort_reload found no active staging map".to_string())
    }
}

/// Test-only: hold the reload-bracket serializer across an arbitrary
/// section of test code so the registry's `schemas` map doesn't get
/// stomped by a parallel test's gateway-startup reload between the
/// returned guard's creation and its drop. Inner `begin_reload` /
/// `commit_reload` calls on the same thread are reentrant.
///
/// The returned guard releases the serializer on `Drop`. Tests should
/// scope it to cover both their writes (begin/register/commit) and any
/// `lookup_named` assertions that follow the commit.
#[doc(hidden)]
#[allow(dead_code)]
#[must_use = "drop the guard to release the reload-bracket serializer"]
pub fn lock_for_tests() -> ReloadBracketTestGuard {
    enter_bracket();
    ReloadBracketTestGuard { _private: () }
}

/// RAII handle returned by [`lock_for_tests`].
#[doc(hidden)]
pub struct ReloadBracketTestGuard {
    _private: (),
}

impl Drop for ReloadBracketTestGuard {
    fn drop(&mut self) {
        leave_bracket();
    }
}

/// Look up a named schema. Returns `None` if no schema with this name
/// is registered (either never registered, or removed by a reload).
///
/// If the calling thread is itself in the middle of a reload bracket
/// (between [`begin_reload`] and [`commit_reload`] / [`abort_reload`]),
/// the staging area is the authoritative new state — it shadows the
/// live `schemas` map. This lets the second pass of a plugin-cache
/// build resolve `schema_ref` against the not-yet-committed schemas.
/// External threads (admin API, concurrent reads) continue to see the
/// live committed map, so the atomic-swap-at-commit semantic holds for
/// every reader outside the reload.
pub fn lookup_named(name: &str) -> Option<Arc<SummarySchema>> {
    lookup_entry(name).map(|e| e.compiled)
}

/// Look up the RAW definition of a named schema. Used by
/// [`super::resolve_schema`] so a capability-bearing caller can recompile the
/// named schema under its own capability. Same staging-shadow semantics as
/// [`lookup_named`].
pub fn lookup_named_raw(name: &str) -> Option<Arc<Value>> {
    lookup_entry(name).map(|e| e.raw)
}

fn lookup_entry(name: &str) -> Option<NamedSchema> {
    let on_reload_thread = KEEPER.with(|k| k.borrow().depth > 0);
    let state = read_lock();
    if on_reload_thread && let Some(staging) = &state.staging {
        return staging.get(name).cloned();
    }
    state.schemas.get(name).cloned()
}

/// Snapshot of the registered names (for diagnostics / admin endpoints).
#[allow(dead_code)]
pub fn registered_names() -> Vec<String> {
    let state = read_lock();
    let mut names: Vec<String> = state.schemas.keys().cloned().collect();
    names.sort();
    names
}

/// Test-only: forcefully clear both live and staging state.
///
/// Production callers must use `begin_reload` / `register_named` /
/// `commit_reload`. Exposed (not `#[cfg(test)]`) because integration
/// tests in `tests/integration/` are a separate crate and cannot see
/// items gated on the library's `cfg(test)`.
///
/// Does NOT touch the thread-local bracket keeper — tests holding
/// `lock_for_tests()` continue to own the serializer across this call.
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_tests() {
    let mut state = write_lock();
    state.schemas.clear();
    state.staging = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::utils::log_schema::{
        FieldSpec, MetadataPolicy, SummarySchema, SummaryType, TimestampFormat,
    };

    // The registry is process-global; serialize tests via the same
    // reentrant reload-bracket lock that production callers use, so the
    // bracket stays open across the test's writes AND its assertions.
    fn lock() -> ReloadBracketTestGuard {
        lock_for_tests()
    }

    fn empty_schema() -> Arc<SummarySchema> {
        Arc::new(SummarySchema {
            summary_type: SummaryType::Both,
            fields: Vec::<FieldSpec>::new(),
            metadata: MetadataPolicy::Nested,
            timestamp_format: TimestampFormat::Rfc3339,
            capability_scoped: false,
            flatten_reserved: Default::default(),
        })
    }

    fn raw_schema() -> Arc<Value> {
        Arc::new(serde_json::json!({}))
    }

    #[test]
    fn register_without_begin_is_validation_noop() {
        let _g = lock();
        reset_for_tests();
        // No begin_reload — should succeed silently without registering.
        assert!(register_named("x", raw_schema(), empty_schema()).is_ok());
        assert!(lookup_named("x").is_none());
    }

    #[test]
    fn commit_publishes_staging() {
        let _g = lock();
        reset_for_tests();
        begin_reload().expect("reload bracket opens");
        register_named("a", raw_schema(), empty_schema()).unwrap();
        // The reload thread sees its own staging so plugin construction
        // in the second pass can resolve `schema_ref` before commit.
        assert!(lookup_named("a").is_some());
        // External readers (other threads) still see the live map,
        // which is empty until commit.
        let on_other_thread = std::thread::spawn(lookup_named_a).join().unwrap();
        assert!(
            on_other_thread.is_none(),
            "external readers see only the committed map"
        );
        commit_reload().expect("reload bracket commits");
        assert!(lookup_named("a").is_some());
        // After commit, external readers see the promoted schemas too.
        let on_other_thread = std::thread::spawn(lookup_named_a).join().unwrap();
        assert!(on_other_thread.is_some());
    }

    fn lookup_named_a() -> Option<Arc<SummarySchema>> {
        lookup_named("a")
    }

    #[test]
    fn abort_discards_staging() {
        let _g = lock();
        reset_for_tests();
        // Seed a live schema so we can confirm it survives the aborted
        // reload.
        begin_reload().expect("reload bracket opens");
        register_named("keep", raw_schema(), empty_schema()).unwrap();
        commit_reload().expect("reload bracket commits");
        assert!(lookup_named("keep").is_some());

        // Start a reload that registers a new schema, then abort.
        begin_reload().expect("reload bracket opens");
        register_named("transient", raw_schema(), empty_schema()).unwrap();
        abort_reload().expect("reload bracket aborts");

        // The aborted reload's staged schema must NOT leak into the live map.
        assert!(
            lookup_named("transient").is_none(),
            "abort discards staging"
        );
        // The previously-committed schema must survive.
        assert!(
            lookup_named("keep").is_some(),
            "abort preserves last commit"
        );
    }

    #[test]
    fn duplicate_within_reload_rejected() {
        let _g = lock();
        reset_for_tests();
        begin_reload().expect("reload bracket opens");
        register_named("a", raw_schema(), empty_schema()).unwrap();
        let r = register_named("a", raw_schema(), empty_schema());
        assert!(r.is_err());
        abort_reload().expect("reload bracket aborts");
    }

    #[test]
    fn reload_replaces_previous_set() {
        let _g = lock();
        reset_for_tests();
        // First reload: register "a".
        begin_reload().expect("reload bracket opens");
        register_named("a", raw_schema(), empty_schema()).unwrap();
        commit_reload().expect("reload bracket commits");
        assert!(lookup_named("a").is_some());

        // Second reload: register only "b". "a" should vanish.
        begin_reload().expect("reload bracket opens");
        register_named("b", raw_schema(), empty_schema()).unwrap();
        commit_reload().expect("reload bracket commits");
        assert!(lookup_named("a").is_none());
        assert!(lookup_named("b").is_some());
    }

    #[test]
    fn registered_names_sorted() {
        let _g = lock();
        reset_for_tests();
        begin_reload().expect("reload bracket opens");
        register_named("zebra", raw_schema(), empty_schema()).unwrap();
        register_named("alpha", raw_schema(), empty_schema()).unwrap();
        register_named("mango", raw_schema(), empty_schema()).unwrap();
        commit_reload().expect("reload bracket commits");
        assert_eq!(registered_names(), vec!["alpha", "mango", "zebra"]);
    }
}
