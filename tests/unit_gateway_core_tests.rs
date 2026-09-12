//! Unit Tests: gateway core
//!
//! Core data structures and runtime (consumers, DNS, proxy, router, websocket,
//! capture, overload, ...). Split out of the former monolithic `unit_tests`
//! binary so the Unit Tests matrix compiles it in parallel with the plugin
//! halves and the remaining `unit_tests` target. The `tls` module and the
//! plugin `plugin_utils` helpers are compiled here as well because these tests
//! use their fixtures; the `tls` tests therefore also run in this target.
//!
//! Run with: cargo test --test unit_gateway_core_tests [filter]

mod unit {
    pub mod env_lock;
    pub mod gateway_trust_observability_lock;
    #[allow(dead_code, unused_imports)]
    pub(crate) mod tls;

    pub mod plugins {
        #[allow(dead_code)]
        pub(crate) mod plugin_utils;
    }

    mod gateway_core;
}
