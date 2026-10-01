//! Shared helpers for the mesh DNS proxy E2E perf harness.

pub mod dns_wire;
pub mod metrics;
pub mod slice;
pub mod upstream_stub;

pub mod proto {
    // tonic's generated server traits expand through async-trait, which adds a
    // bare `#[must_use]` to methods already returning a must-use boxed future.
    #![allow(clippy::double_must_use)]
    tonic::include_proto!("ferrum");
}

/// Synthetic mesh slice version stamp the stub publishes.
pub const STUB_SLICE_VERSION: &str = "perf-stub-v1";
