//! DOC-03 public `FERRUM_*` settings inventory (EnvConfig ↔ docs ↔ ferrum.conf).
//!
//! The coverage contract's machine-readable inventory is the union of:
//! 1. Every setting accepted by production `EnvConfig` parsing in
//!    [`super::env_config`] (`env_config!` keys, `FERRUM_MODE`, and the
//!    in-cluster default bool knobs resolved outside the macro).
//! 2. [`EXTRA_PUBLIC_FERRUM_ENV_SETTINGS`] — public operator controls resolved
//!    outside `EnvConfig` (for example dynamically constructed injector
//!    resource quantities) that still require documentation and template
//!    coverage.
//!
//! [`PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS`] is a small allowlist for accepted
//! compatibility aliases (and similar) that intentionally share the canonical
//! setting's docs/template row. Build-out policy does not add new legacy
//! shims; only existing permitted aliases belong here.
//!
//! External unit tests under `tests/unit/config/env_docs_parity_tests.rs`
//! assemble the inventory and fail closed when a public setting lacks a
//! `docs/configuration.md` table row or a `ferrum.conf` template assignment.

/// Public `FERRUM_*` settings resolved outside production `EnvConfig` parsing
/// that still require canonical docs table + `ferrum.conf` coverage.
///
/// Keep this list sorted. When adding a dynamically constructed or otherwise
/// out-of-`env_config!` operator setting, append it here and update
/// `docs/configuration.md` plus `ferrum.conf` in the same change.
pub const EXTRA_PUBLIC_FERRUM_ENV_SETTINGS: &[&str] = &[
    "FERRUM_INJECTOR_INIT_CPU_LIMIT",
    "FERRUM_INJECTOR_INIT_CPU_REQUEST",
    "FERRUM_INJECTOR_INIT_MEMORY_LIMIT",
    "FERRUM_INJECTOR_INIT_MEMORY_REQUEST",
    "FERRUM_INJECTOR_SIDECAR_CPU_LIMIT",
    "FERRUM_INJECTOR_SIDECAR_CPU_REQUEST",
    "FERRUM_INJECTOR_SIDECAR_MEMORY_LIMIT",
    "FERRUM_INJECTOR_SIDECAR_MEMORY_REQUEST",
    "FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES",
    "FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS",
];

/// Accepted settings that intentionally do not own a separate docs table row
/// and/or `ferrum.conf` assignment. Canonical replacements remain covered.
///
/// Keep this list sorted and minimal. Prefer documenting the canonical name
/// only; do not grow this allowlist for new aliases under build-out policy.
pub const PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS: &[&str] = &[
    // Compatibility alias of `FERRUM_TLS_KEY_EXCHANGE_GROUPS` (canonical).
    "FERRUM_TLS_CURVES",
];

/// Returns extra public settings that are part of the DOC-03 inventory but are
/// not discovered from `EnvConfig` production parse sites.
pub fn extra_public_ferrum_env_settings() -> &'static [&'static str] {
    EXTRA_PUBLIC_FERRUM_ENV_SETTINGS
}

/// Returns coverage exemptions for compatibility-only aliases.
pub fn public_ferrum_env_coverage_exemptions() -> &'static [&'static str] {
    PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS
}

/// True when `key` is an explicit coverage exemption.
pub fn is_public_ferrum_env_coverage_exempt(key: &str) -> bool {
    PUBLIC_FERRUM_ENV_COVERAGE_EXEMPTIONS
        .binary_search(&key)
        .is_ok()
}
