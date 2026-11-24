//! Unit Tests: gateway core
//!
//! Core data structures and runtime (consumers, DNS, proxy, router, websocket,
//! capture, overload, ...). Split out of the former monolithic `unit_tests`
//! binary so the Unit Tests matrix compiles it in parallel with the plugin
//! halves and the remaining `unit_tests` target. The test-free plugin
//! `plugin_utils` helpers and the shared lock modules are compiled here as
//! well because these tests use them; the `tls` tests run only in `unit_tests`.
//!
//! Run with: cargo test --test unit_gateway_core_tests [filter]

// Process-wide tracing interest floor shared by every thread-local log
// capture in this binary (see tests/support/diagnostic_interest.rs).
#[allow(dead_code, unused_imports, unused_macros)]
#[path = "support/diagnostic_interest.rs"]
pub(crate) mod diagnostic_test_interest;

mod unit {
    pub mod client_trust_registry_lock;
    pub mod env_lock;
    pub mod gateway_trust_observability_lock;

    pub mod plugins {
        #[allow(dead_code)]
        pub(crate) mod plugin_utils;
    }

    mod gateway_core;
}
