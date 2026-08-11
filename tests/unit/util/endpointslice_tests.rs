//! External coverage for shared EndpointSlice lifecycle eligibility (#3716).

use ferrum_edge::util::endpointslice::{
    EndpointSliceEndpointEligibility, endpoint_slice_endpoint_eligibility,
    endpoint_slice_endpoint_is_ready,
};
use serde_json::json;

#[test]
fn endpoint_slice_lifecycle_eligibility_table() {
    let cases: &[(&str, serde_json::Value, EndpointSliceEndpointEligibility)] = &[
        (
            "no conditions object → eligible",
            json!({"addresses": ["10.0.0.1"]}),
            EndpointSliceEndpointEligibility::Eligible,
        ),
        (
            "ready=true, serving=true, terminating=false → eligible",
            json!({
                "addresses": ["10.0.0.1"],
                "conditions": {
                    "ready": true,
                    "serving": true,
                    "terminating": false
                }
            }),
            EndpointSliceEndpointEligibility::Eligible,
        ),
        (
            "ready=true, serving=false → rejected as non-serving",
            json!({
                "addresses": ["10.0.0.1"],
                "conditions": {"ready": true, "serving": false}
            }),
            EndpointSliceEndpointEligibility::NotServing,
        ),
        (
            "ready=true, terminating=true → rejected as terminating",
            json!({
                "addresses": ["10.0.0.1"],
                "conditions": {"ready": true, "terminating": true}
            }),
            EndpointSliceEndpointEligibility::Terminating,
        ),
        (
            "ready omitted, serving=false → rejected as non-serving",
            json!({
                "addresses": ["10.0.0.1"],
                "conditions": {"serving": false}
            }),
            EndpointSliceEndpointEligibility::NotServing,
        ),
        (
            "ready omitted, serving omitted, terminating=false → eligible",
            json!({
                "addresses": ["10.0.0.1"],
                "conditions": {"terminating": false}
            }),
            EndpointSliceEndpointEligibility::Eligible,
        ),
        (
            "publishNotReadyAddresses-style ready=true on terminating → rejected",
            json!({
                "addresses": ["10.0.0.1"],
                "conditions": {
                    "ready": true,
                    "serving": true,
                    "terminating": true
                }
            }),
            EndpointSliceEndpointEligibility::Terminating,
        ),
    ];

    for (label, endpoint, expected) in cases {
        let got = endpoint_slice_endpoint_eligibility(endpoint);
        assert_eq!(got, *expected, "{label}");
        assert_eq!(
            endpoint_slice_endpoint_is_ready(endpoint),
            expected.is_eligible(),
            "{label}: is_ready parity"
        );
    }
}

#[test]
fn endpoint_slice_ready_false_is_not_ready_not_non_serving() {
    let endpoint = json!({
        "addresses": ["10.0.0.1"],
        "conditions": {"ready": false}
    });
    assert_eq!(
        endpoint_slice_endpoint_eligibility(&endpoint),
        EndpointSliceEndpointEligibility::NotReady
    );
}
