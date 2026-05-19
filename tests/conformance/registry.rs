//! Process-global conformance feature registry.
//!
//! Each conformance test calls [`register`] (typically via the
//! [`register_feature!`] macro) before its assertions. The registry stores
//! `(category, feature, status, notes, test_name)` tuples behind a mutex; the
//! end-of-suite reporter ([`super::report`]) drains the registry to produce
//! the coverage matrix.
//!
//! Concurrency: `cargo test` runs test functions in parallel. The mutex
//! protects against races and duplicate registrations — duplicates are silently
//! deduplicated on `(category, feature)` so a test that runs twice (e.g. via
//! `cargo test -- --test-threads=2`) doesn't inflate the matrix.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Status {
    /// The feature works as documented. Most entries should land here.
    Supported,
    /// Known not-yet-implemented; the test records the assertion needed to
    /// flip the status to `Supported` once the gap closes. Operators see a
    /// clear note explaining why.
    Deferred,
    /// Explicit non-goals (e.g. Wasm, EnvoyFilter). Documented for completeness
    /// so operators don't keep asking.
    OutOfScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Feature {
    pub category: &'static str,
    pub feature: String,
    pub status: Status,
    pub notes: Option<String>,
    pub test_name: &'static str,
}

fn registry() -> &'static Mutex<BTreeMap<(String, String), Feature>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<(String, String), Feature>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn register(
    category: &'static str,
    feature: impl Into<String>,
    status: Status,
    notes: Option<String>,
    test_name: &'static str,
) {
    let feature = feature.into();
    let key = (category.to_string(), feature.clone());
    let entry = Feature {
        category,
        feature,
        status,
        notes,
        test_name,
    };
    if let Ok(mut guard) = registry().lock() {
        // Insert-or-replace: a test that runs more than once should record the
        // *latest* status. Tests that legitimately register the same feature
        // (e.g., the matcher matrix module covering one VS predicate in two
        // tests) should pick distinct feature names.
        guard.insert(key, entry);
    }
}

pub(crate) fn snapshot() -> Vec<Feature> {
    let guard = match registry().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard.values().cloned().collect()
}

/// Convenience macro that auto-populates `test_name` from the surrounding
/// `fn` via `function_name!()`-style stringification — or, simpler, from a
/// caller-supplied `module_path` plus literal.
///
/// Usage:
/// ```ignore
/// register_feature!(
///     category = "istio_virtual_service",
///     feature = "uri.exact",
///     status = Status::Supported,
/// );
/// ```
///
/// The macro stamps `module_path!()` as the test name so the matrix points
/// operators at the test that proved the behavior.
#[macro_export]
macro_rules! register_feature {
    (
        category = $category:expr,
        feature = $feature:expr,
        status = $status:expr $(,)?
    ) => {
        $crate::conformance::registry::register($category, $feature, $status, None, module_path!());
    };
    (
        category = $category:expr,
        feature = $feature:expr,
        status = $status:expr,
        notes = $notes:expr $(,)?
    ) => {
        $crate::conformance::registry::register(
            $category,
            $feature,
            $status,
            Some(($notes).to_string()),
            module_path!(),
        );
    };
}
