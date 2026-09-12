//! Unit Tests
//!
//! Tests for individual modules and components in isolation.
//! These tests do not require any external services or the gateway binary.
//!
//! The unit suite is four test targets so CI compiles them in parallel
//! instead of one 642k-line rustc frontend:
//!   - `unit_tests` (this file): config, admin, tls, identity, secrets, cli,
//!     notifications, util, build, logging, openapi
//!   - `unit_plugins_a_tests`: plugin tests whose file names start with a–j
//!   - `unit_plugins_b_tests`: plugin tests whose file names start with k–z
//!   - `unit_gateway_core_tests`: core data structures and runtime
//!
//! Run with: cargo test --test unit_tests [filter]
//! (or `cargo test unit::plugins::cors_tests` to search every target)

#[path = "common/isolated_audit_fallback.rs"]
mod isolated_audit_fallback;
pub use isolated_audit_fallback::isolated_audit_fallback_dir;

mod unit;
