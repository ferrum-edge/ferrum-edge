//! Generated SPIFFE Workload API stubs.
//!
//! `tonic_prost_build` (invoked from `build.rs`) compiles `proto/workload_api.proto`
//! and emits a module under `OUT_DIR`. The SPIFFE Workload API proto has no
//! package, so `prost-build` writes it to `_.rs`. We re-include it here so the
//! rest of the crate uses a stable path:
//! `crate::identity::workload_api::proto::*`.

// `clippy::double_must_use`: tonic's generated server trait expands through
// async-trait, which adds a bare `#[must_use]` to methods already returning a
// must-use boxed future.
#![allow(
    missing_docs,
    clippy::double_must_use,
    clippy::large_enum_variant,
    clippy::derive_partial_eq_without_eq
)]

include!(concat!(env!("OUT_DIR"), "/_.rs"));
