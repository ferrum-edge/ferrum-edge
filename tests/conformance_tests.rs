//! Ferrum Edge Conformance Test Suite.
//!
//! Tests in this crate exercise Ferrum Edge's Istio + xDS compatibility surface
//! end-to-end and emit an auto-generatable coverage matrix that operators can
//! use to decide "is this Istio config supported by Ferrum?".
//!
//! Layout:
//!   - `conformance::registry` — process-global feature registry; each test
//!     calls `register_feature!(category, name, status)` before its assertions
//!     so the matrix is built up as the suite runs.
//!   - `conformance::report` — emits `target/conformance/coverage.{json,md}`
//!     at end-of-suite. The reporter sleeps inside a `Drop` so it fires only
//!     after every test that registered a feature has finished.
//!   - Per-category modules (`istio_virtual_service`, `istio_authorization_policy`,
//!     ...) each cover a slice of the matcher/CRD surface.
//!
//! Run with: `cargo test --test conformance_tests`
//!
//! Artifacts land in `target/conformance/coverage.json` and
//! `target/conformance/coverage.md`. See `CONFORMANCE.md` at the repo root for
//! the operator-facing reference.

mod conformance;
