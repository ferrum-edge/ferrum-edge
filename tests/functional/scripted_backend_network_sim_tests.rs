//! Phase-5 acceptance tests — network-simulation wrappers.
//!
//! These tests wrap scripted HTTP/1.1 backends with network simulators
//! (latency, bandwidth limit, truncate) and assert the gateway's
//! per-direction timeout and metrics behaviour against them.
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_network_sim -- --ignored --nocapture

#![allow(clippy::bool_assert_comparison)]

// These tests are filled in once the Phase-4 UDP acceptance tests are
// stable. See `mod.rs` entries for the three Phase-5 tests:
//
// - slow_backend_within_read_timeout_completes
// - backend_bandwidth_below_budget_triggers_write_timeout
// - high_latency_preserves_first_byte_latency_metrics
