//! xDS and native mesh-config distribution (Layer 3).
//!
//! Phase B keeps this path strictly additive: the ADS service is only mounted
//! when `FERRUM_XDS_ENABLED=true`, and all xDS/native streams translate from
//! the canonical Layer 2 mesh model instead of reading any config source
//! directly.

// Phase B exposes xDS pieces before every runtime path consumes them. Keep the
// allowance scoped to dead code only; unused imports should still be caught.
#![allow(dead_code)]

pub mod admission;
pub mod carrier;
pub mod conformance;
pub mod nonce;
pub mod server;
pub mod snapshot;
/// Issue #3317: the stock Envoy / third-party Istio interoperability profile.
/// Kept strictly separate from [`carrier`] / [`translator`], which implement
/// the Ferrum-private xDS profile.
pub mod stock;
pub mod translator;

pub mod proto {
    // Not google.protobuf.Any/Status: these are the minimal wire-compatible
    // xDS shims Ferrum needs for Phase B.
    tonic::include_proto!("envoy.service.discovery.v3");
}

pub mod runtime_proto {
    // GAP-3E: vendored `envoy.service.runtime.v3.Runtime` plus a minimal
    // `google.protobuf.Struct`-shaped payload (field numbers match the
    // upstream well-known types, so layers emitted by real Envoy / Istio
    // CPs decode cleanly here).
    //
    // The `Value::Kind` oneof variants (`NullValue`, `NumberValue`, ...)
    // mirror the upstream `google.protobuf.Value` exactly. Renaming them
    // to satisfy `clippy::enum_variant_names` would break that one-to-one
    // mapping — suppress the lint at the module level so the prost
    // generated code stays drop-in compatible.
    #![allow(clippy::enum_variant_names)]
    tonic::include_proto!("envoy.service.runtime.v3");
}

pub mod stock_proto {
    //! Issue #3317: decode-only projections of the upstream Envoy v3 resource
    //! messages consumed by the stock interoperability profile. These are
    //! NEVER encoded — Ferrum's own CP keeps emitting the Ferrum-private
    //! resources declared in [`super::proto`]. See
    //! `proto/envoy/stock/v3/stock_xds.proto` for the field-number provenance
    //! and the "declared means consumed or refused" invariant.
    tonic::include_proto!("ferrum.stockxds.v3");
}

// Public re-exports are used by library consumers/tests even when the binary
// target only reaches xDS through narrower module paths.
#[allow(unused_imports)]
pub use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
#[allow(unused_imports)]
pub use admission::{
    DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS, DEFAULT_XDS_MAX_ACTIVE_NODES,
    DEFAULT_XDS_MAX_NODE_ID_BYTES, DEFAULT_XDS_MAX_STREAMS_PER_NAMESPACE,
    DEFAULT_XDS_MAX_STREAMS_PER_NODE, DEFAULT_XDS_MAX_STREAMS_PER_PRINCIPAL,
    DEFAULT_XDS_MAX_TOTAL_STREAMS, XdsAdmissionController, XdsAdmissionLimits,
    XdsAdmissionRejection, XdsStreamPermit, principal_key, redacted_identifier, validate_node_id,
    xds_state_key,
};
#[allow(unused_imports)]
pub use carrier::{
    FERRUM_ECDS_LABELS_TYPE_URL, FERRUM_ECDS_MESH_POLICIES_TYPE_URL,
    FERRUM_ECDS_MULTI_CLUSTER_TYPE_URL, FERRUM_ECDS_OUTBOUND_POLICY_TYPE_URL,
    FERRUM_ECDS_PEER_AUTH_TYPE_URL, FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL,
    FERRUM_ECDS_REQUEST_AUTH_TYPE_URL, FERRUM_ECDS_SERVICE_ENTRIES_TYPE_URL,
    FERRUM_ECDS_SERVICES_TYPE_URL, FERRUM_ECDS_SIDECAR_EGRESS_SCOPE_TYPE_URL,
    FERRUM_ECDS_TELEMETRY_TYPE_URL, FERRUM_ECDS_TRUST_BUNDLES_TYPE_URL,
    FERRUM_ECDS_VS_L4_PROXIES_TYPE_URL, FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL,
    FERRUM_ECDS_WORKLOADS_TYPE_URL, MAX_WAYPOINT_GATEWAY_CLASS_CARRIER_BYTES,
    MAX_WAYPOINT_GATEWAY_CLASS_LEN, MeshSliceCarrier, apply_carrier, build_slice_carriers,
};
#[allow(unused_imports)]
pub use nonce::{AckOutcome, XdsNonceTracker};
pub use server::XdsAdsServer;
#[allow(unused_imports)]
pub use snapshot::{XdsResource, XdsSnapshot, XdsSnapshotCache};
#[allow(unused_imports)]
pub use stock::{
    STOCK_REQUIRED_TYPE_URLS, STOCK_XDS_TYPE_URLS, StockDiscovery, StockRefusal,
    StockXdsAccumulator, StockXdsLimits, parse_istio_cluster_name, parse_kubernetes_service_host,
    refuse_stock_secret,
};
#[allow(unused_imports)]
pub use translator::{
    CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, FERRUM_ECDS_DESTINATION_RULE_TYPE_URL, LDS_TYPE_URL,
    RDS_TYPE_URL, RTDS_TYPE_URL, SDS_TYPE_URL, XDS_TYPE_URLS, translate_destination_rule_carriers,
    translate_mesh_slice_to_snapshot, translate_rtds_layer,
};
