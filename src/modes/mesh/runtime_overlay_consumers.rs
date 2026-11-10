//! Consumers for the xDS RTDS-driven [`MeshRuntimeOverlay`].
//!
//! Operators ship runtime knobs through the mesh xDS client; every accepted
//! slice runs through [`apply_overlay`] so process-wide consumers can publish
//! their current value without walking the overlay on every request.
//!
//! ## What is NOT published here, and why
//!
//! A knob that shapes how a request is proxied must not live in a store that is
//! published separately from the `RequestEpoch` carrying the configuration it
//! modifies. This fanout runs AFTER `ProxyState::update_config`, so any
//! behavioral value published here would have two straddle windows: the
//! publication gap (a new plugin reading the old value) and the whole lifetime
//! of an already-admitted request (an old plugin reading the new value).
//!
//! Both `fault_injection` and the two transformers are therefore deliberately
//! absent from the behavioral path: their values are materialized into the
//! candidate plugin configs on the cold path
//! (`materialize_fault_runtime_overlay`,
//! `materialize_transformer_runtime_overlay`), validated, built into the
//! candidate plugin cache, and published atomically with the request epoch whose
//! config they modify (GHSA-83rc-23c9-3g9x for the transformers).
//!
//! Consumer dispatch is by reserved key namespace:
//!
//! - `ferrum.log.level` — rebuild the tracing `EnvFilter` via the global
//!   reload handle installed at startup (`crate::logging::reload_layer`). This
//!   one is genuinely process-global: it shapes diagnostics, not proxying.
//! - `ferrum.request_transformer.<scope>.enabled` /
//!   `ferrum.response_transformer.<scope>.enabled` — published for
//!   PROVENANCE ONLY. No plugin phase reads these stores; the gate that governs
//!   rule application is the one materialized into each instance's config. The
//!   response-side publication identity is still what `response_caching` and
//!   `request_deduplication` bind retained representations to, so do not delete
//!   these calls on the grounds that the transformers no longer read them.
//!
//! GAP-3E note: the registry is intentionally tiny — each consumer owns its
//! own state and reads what it cares about. Adding a new consumer is a
//! single `apply_*` call from [`apply_overlay`] plus its own module-global
//! `ArcSwap` (or equivalent reload handle).

#![allow(dead_code)]

use std::sync::{LazyLock, Mutex, MutexGuard};

use crate::modes::mesh::config::MeshRuntimeOverlay;

static RUNTIME_OVERLAY_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[doc(hidden)]
pub fn test_lock() -> MutexGuard<'static, ()> {
    RUNTIME_OVERLAY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Apply every RTDS-driven runtime knob exposed on `overlay`. Called from
/// `MeshRuntimeState::record_applied_slice_with_token` after the proxy runtime
/// accepts a slice so consumers never observe values from rejected updates.
///
/// The two transformer calls publish provenance state only — see the module
/// docs. Because they run post-accept, a rejected slice leaves the previous
/// generation's provenance in place, matching the last-known-good behavior the
/// epoch itself retains.
///
/// Cold path; allocations are bounded by the number of `ferrum.*` keys in
/// the overlay. No-op when none are present.
pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    crate::plugins::request_transformer::runtime_overlay::apply_overlay(overlay);
    crate::plugins::response_transformer::runtime_overlay::apply_overlay(overlay);
    crate::logging::runtime_overlay::apply_overlay(overlay);
}
