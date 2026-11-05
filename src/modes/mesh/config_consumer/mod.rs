#![allow(dead_code)]

//! Mesh configuration consumers.

pub mod common;
pub mod file_source;
pub mod native_client;
pub mod native_tls;
/// Debounced pending-generation state machine shared by the ADS clients.
pub mod pending_generation;
/// Issue #3317: stock Envoy / third-party Istio ADS consumer. Separate from
/// [`xds_client`], which is the Ferrum-private xDS profile.
pub mod stock_xds_client;
/// Issue #3852: finite authorization lifetime for the stock xDS bearer
/// credential.
pub mod stock_xds_credential;
/// Issue #3853: fail-closed transport admission for stock xDS endpoints.
pub mod stock_xds_transport;
/// Issue #3854: shared attempt/liveness policy for every mesh configuration
/// stream.
pub mod stream_lifecycle;
pub mod update_validation;
pub mod xds_client;
