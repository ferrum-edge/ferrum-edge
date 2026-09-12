//! The HTTP/3 cross-protocol bridge must apply the CANONICAL backend-request
//! strip inventory, not a hand-maintained copy of part of it.
//!
//! Issue #5110: the bridge kept its own list and therefore forwarded the
//! gateway-internal `x-ferrum-original-content-encoding` handoff marker to
//! origins after `compression` normalized an upload — a header the H1/H2 and
//! native-H3 backend builders both remove, so origin-visible request metadata
//! depended on the client's frontend protocol.

use ferrum_edge::_test_support::cross_protocol_backend_header_is_stripped_for_test as bridge_strips;
use ferrum_edge::proxy::headers::{
    BACKEND_REQUEST_STRIP_HEADER_NAMES, is_backend_request_strip_header,
};

/// The bridge's forwarding-identity names. Held here rather than imported so a
/// silent narrowing of the bridge's own inventory fails this test.
const BRIDGE_FORWARDING_IDENTITY_NAMES: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "via",
    "forwarded",
];

#[test]
fn bridge_strips_every_canonical_backend_request_name() {
    // Structural reuse rather than a second allowlist: enumerating the shared
    // inventory is what keeps a future strip arm from reaching the H1/H2 and
    // native-H3 builders while the bridge silently keeps forwarding it.
    for &name in BACKEND_REQUEST_STRIP_HEADER_NAMES {
        assert!(
            bridge_strips(name),
            "{name} is in the canonical backend strip inventory and must not reach an origin \
             through the H3 cross-protocol bridge"
        );
        assert!(
            bridge_strips(&name.to_ascii_uppercase()),
            "{name} must be stripped regardless of case"
        );
    }
}

#[test]
fn bridge_strips_the_internal_compression_handoff_marker() {
    // The exact #5110 regression: a marker the gateway itself writes after
    // successful request normalization, in both the wire-lowercase form and a
    // plugin-synthesised mixed-case form.
    for name in [
        "x-ferrum-original-content-encoding",
        "X-Ferrum-Original-Content-Encoding",
    ] {
        assert!(bridge_strips(name), "{name} must never reach the backend");
    }
    assert!(is_backend_request_strip_header(
        "x-ferrum-original-content-encoding"
    ));
}

#[test]
fn bridge_still_strips_its_own_forwarding_identity_names() {
    // Delegating to the canonical predicate must not drop the bridge's other
    // half: it regenerates these itself, and the plain builder APPENDS, so a
    // spoofed value that survived would precede the gateway-owned element.
    for &name in BRIDGE_FORWARDING_IDENTITY_NAMES {
        assert!(bridge_strips(name), "{name} must be stripped");
        assert!(
            bridge_strips(&name.to_ascii_uppercase()),
            "{name} must be stripped regardless of case"
        );
    }
}

#[test]
fn bridge_forwards_ordinary_application_and_grpc_headers() {
    for name in [
        "content-type",
        "grpc-timeout",
        "grpc-encoding",
        "user-agent",
        "accept-encoding",
        "x-forwarded",
        "Content-Type",
    ] {
        assert!(!bridge_strips(name), "{name} must reach the backend");
    }
}
