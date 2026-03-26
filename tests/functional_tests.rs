//! Functional Tests
//!
//! End-to-end tests that spawn the actual ferrum-gateway binary and exercise
//! the full system. These tests are marked with #[ignore] and must be run
//! explicitly since they require the binary to be compiled first.
//!
//! Tests:
//!   - functional_cp_dp_test: CP/DP mode with gRPC, database TLS config
//!   - functional_database_test: Database mode with SQLite, Admin API, proxy routing
//!   - functional_db_tls_test: Database TLS (PostgreSQL/MySQL/SQLite) connectivity + CRUD
//!   - functional_file_mode_test: File mode with YAML config, SIGHUP reload
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture

mod functional;
