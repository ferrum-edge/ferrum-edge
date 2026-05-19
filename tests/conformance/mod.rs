//! Conformance test modules.
//!
//! Each sub-module covers a slice of the Istio/xDS compatibility surface and
//! registers its findings into the shared [`registry`] so the end-of-suite
//! reporter can emit a coverage matrix.

#[macro_use]
pub(crate) mod registry;

pub(crate) mod report;

mod istio_authorization_policy;
mod istio_destination_rule;
mod istio_peer_authentication;
mod istio_service_entry_egress;
mod istio_virtual_service;
mod mesh_topology_matrix;
mod xds_type_urls;

// `emit_coverage_artifacts` is the last test in the suite — it forces a flush
// of the registry to disk. Cargo's test runner does not guarantee ordering,
// but the reporter's `Drop`-on-`Lazy` strategy + this test's name being
// lexicographically after every other test keeps the artifact emit reliable
// without relying on `#[ctor]` or a `lib.rs` shim.
#[test]
fn z_emit_coverage_artifacts() {
    report::emit_artifacts().expect("coverage artifacts must serialize cleanly");
}
