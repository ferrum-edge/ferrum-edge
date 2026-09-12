//! Shared helpers for the `service_integration` test suite.

pub mod containers;
pub mod host_ports;
pub mod hydra;

// Reuse the bounded subprocess/port-retry harness for Kafka artifact acceptance.
#[path = "../../common/echo_servers.rs"]
#[allow(dead_code)] // this target only needs the HTTP echo backend
pub mod echo_servers;
#[path = "../../common/gateway_harness.rs"]
#[allow(dead_code)] // shared harness exposes helpers used by other test targets
pub mod gateway_harness;
