//! Shared EndpointSlice endpoint lifecycle eligibility.
//!
//! Kubernetes EndpointSlice `conditions` are tri-state. Ferrum's controller
//! admission and standalone Kubernetes service discovery must apply the same
//! rules when deciding whether an endpoint is routable:
//!
//! - Missing `conditions` → eligible.
//! - `terminating == true` → ineligible (even when `ready == true`, including
//!   `publishNotReadyAddresses`-style state).
//! - Omitted `ready` defaults to `true` for non-terminating endpoints.
//! - Omitted `serving` inherits the effective `ready` value.
//! - Explicit `serving == false` → ineligible.

use serde_json::Value;

/// Why an EndpointSlice endpoint was accepted or skipped for routing.
///
/// Fixed-cardinality reasons only — suitable for structured diagnostics and
/// counters without unbounded labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSliceEndpointEligibility {
    /// Endpoint may be published as a routable target.
    Eligible,
    /// `conditions.terminating` is explicitly true.
    Terminating,
    /// Effective `ready` is false.
    NotReady,
    /// Effective `serving` is false while effective `ready` is true.
    NotServing,
}

impl EndpointSliceEndpointEligibility {
    /// Whether this verdict admits the endpoint into the routable set.
    #[inline]
    pub fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// Evaluate EndpointSlice endpoint lifecycle eligibility.
///
/// Semantics match the historical Kubernetes controller admission helper so
/// both ingestion paths agree on which endpoints are routable.
pub fn endpoint_slice_endpoint_eligibility(endpoint: &Value) -> EndpointSliceEndpointEligibility {
    let Some(conditions) = endpoint.get("conditions") else {
        return EndpointSliceEndpointEligibility::Eligible;
    };
    if conditions
        .get("terminating")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return EndpointSliceEndpointEligibility::Terminating;
    }
    // EndpointSlice readiness fields are tri-state; Kubernetes treats omitted
    // `ready`/`serving` as true for endpoints that are not terminating.
    let ready = conditions.get("ready").and_then(Value::as_bool);
    let serving = conditions
        .get("serving")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| ready.unwrap_or(true));
    if !ready.unwrap_or(true) {
        return EndpointSliceEndpointEligibility::NotReady;
    }
    if !serving {
        return EndpointSliceEndpointEligibility::NotServing;
    }
    EndpointSliceEndpointEligibility::Eligible
}

/// Whether an EndpointSlice endpoint is eligible for routing.
#[inline]
pub fn endpoint_slice_endpoint_is_ready(endpoint: &Value) -> bool {
    endpoint_slice_endpoint_eligibility(endpoint).is_eligible()
}
