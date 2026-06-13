//! SPIFFE Workload API — both gRPC client (talking to a SPIRE agent) and
//! gRPC server (Ferrum acting as the Workload API for local workloads).
//!
//! Sub-modules:
//! - [`proto`] — generated protobuf bindings (`proto/workload_api.proto`).
//! - [`client`] — gRPC client over Unix domain socket, decoding `X509SVID`
//!   responses into [`crate::identity::SvidBundle`].
//! - [`server`] — server-side service backed by a [`crate::identity::ca::CertificateAuthority`]
//!   and a chain of [`crate::identity::attestation::Attestor`]s.
//! - [`fetch_loop`] — long-lived background task that hot-swaps the latest
//!   SVID into a shared `ArcSwap` for the lock-free TLS-resolver path.

pub mod client;
pub mod fetch_loop;
pub mod proto;
pub mod server;

#[allow(unused_imports)]
pub use client::{DEFAULT_WORKLOAD_API_SOCKET, WorkloadApiClient, WorkloadApiClientError};
#[allow(unused_imports)]
pub use fetch_loop::{
    FetchLoopConfig, FetchLoopError, SvidFetchHandle, spawn_fetch_loop,
    spawn_fetch_loop_with_handle,
};
#[allow(unused_imports)]
pub use server::WorkloadApiService;
