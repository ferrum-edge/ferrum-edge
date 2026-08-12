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
//! - [`listener`] — Unix-socket bind / serve / shutdown lifecycle for the
//!   server, including the fail-closed socket path/ownership/mode contract.
//! - [`admission`] — the transport admission boundary: total / per-peer-UID
//!   connection ceilings taken before an accepted socket reaches tonic,
//!   permit-owning connection wrappers, initial/idle connection deadlines, the
//!   service-wide **and per-peer-UID** RPC ceilings (held for a streaming RPC's
//!   whole response stream), the bounded shutdown force-close, and the fatal
//!   accept signal that routes an unusable listener into that same bounded path.

pub mod admission;
pub mod client;
pub mod fetch_loop;
pub mod latest_wins;
pub mod listener;
pub mod proto;
pub mod server;

#[allow(unused_imports)]
pub use admission::{
    AcceptDecision, AcceptFailure, AcceptRetryPolicy, ActivitySnapshot, AdmittedStream,
    ConnectionActivity, ConnectionAdmission, ConnectionPermit, ConnectionWatchdog,
    FatalAcceptSignal, PermitStream, RpcAdmission, RpcPermit, WorkloadApiAdmissionConfig,
    close_reason, reject_reason, watchdog_tick,
};
#[cfg(unix)]
#[allow(unused_imports)]
pub use admission::{AdmittedUnixStream, classify_accept_error};
#[allow(unused_imports)]
pub use client::{DEFAULT_WORKLOAD_API_SOCKET, WorkloadApiClient, WorkloadApiClientError};
#[allow(unused_imports)]
pub use fetch_loop::{
    FetchLoopConfig, FetchLoopError, FetchLoopMetricsSource, SvidFetchHandle, spawn_fetch_loop,
    spawn_fetch_loop_with_handle,
};
#[allow(unused_imports)]
pub use listener::{
    DEFAULT_FERRUM_WORKLOAD_API_SOCKET, DEFAULT_WORKLOAD_API_SOCKET_MODE, DirectoryTrustVerdict,
    MAX_STAGING_SUFFIX_BYTES, SocketLiveness, WorkloadApiListener, WorkloadApiListenerError,
    WorkloadApiSocketConfig, classify_connect_result, classify_directory_component,
    matches_bound_socket_identity, serve_workload_api, serve_workload_api_with_admission,
};
#[allow(unused_imports)]
pub use server::WorkloadApiService;
