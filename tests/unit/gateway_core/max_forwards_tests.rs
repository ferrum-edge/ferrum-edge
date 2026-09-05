//! RFC 9110 §7.6.2 `Max-Forwards` hop-budget decision for proxied OPTIONS
//! requests (issue #4647).
//!
//! Live origin-count / header-echo coverage over real HTTP/1.1, HTTP/2, and
//! HTTP/3 frontends lives in `tests/functional/functional_max_forwards_test.rs`.
//! These tests pin the shared parser/decision helper and its documented
//! bounded behaviour for malformed, repeated, and oversized values.

use std::collections::HashMap;

use ferrum_edge::proxy::max_forwards::{
    MAX_FORWARDS_HEADER, MAX_FORWARDS_INVALID_BODY, MAX_FORWARDS_RECIPIENT_MAX,
};
use ferrum_edge::proxy::max_forwards::{
    MaxForwardsDecision, MaxForwardsTerminal, apply_options_max_forwards,
    decide_options_max_forwards, max_forwards_response_headers, parse_max_forwards,
};
use hyper::StatusCode;

fn options_headers(value: &str) -> HashMap<String, String> {
    HashMap::from([(MAX_FORWARDS_HEADER.to_string(), value.to_string())])
}

#[test]
fn parse_accepts_one_decimal_with_optional_whitespace() {
    assert_eq!(parse_max_forwards("0"), Some(0));
    assert_eq!(parse_max_forwards("1"), Some(1));
    assert_eq!(parse_max_forwards("10"), Some(10));
    assert_eq!(parse_max_forwards(" 7\t"), Some(7));
    assert_eq!(parse_max_forwards("007"), Some(7));
}

#[test]
fn parse_saturates_instead_of_overflowing() {
    assert_eq!(
        parse_max_forwards("4294967295"),
        Some(MAX_FORWARDS_RECIPIENT_MAX)
    );
    assert_eq!(
        parse_max_forwards("4294967296"),
        Some(MAX_FORWARDS_RECIPIENT_MAX)
    );
    let huge = "9".repeat(4096);
    assert_eq!(parse_max_forwards(&huge), Some(MAX_FORWARDS_RECIPIENT_MAX));
}

#[test]
fn parse_refuses_anything_but_one_decimal() {
    for value in [
        "", "   ", "abc", "-1", "+1", "1.0", "1 0", "1, 1", "0,0", "1e3", "0x10", "\u{0663}",
    ] {
        assert_eq!(parse_max_forwards(value), None, "{value:?}");
    }
}

#[test]
fn non_options_methods_never_touch_the_field() {
    for method in [
        "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "options",
    ] {
        let mut owned = None;
        let mut ctx = options_headers("0");
        assert_eq!(
            apply_options_max_forwards(method, &mut owned, &mut ctx),
            MaxForwardsDecision::Forward,
            "{method}"
        );
        assert_eq!(ctx[MAX_FORWARDS_HEADER], "0", "{method}");
        assert!(owned.is_none(), "{method}");
    }
}

#[test]
fn options_without_the_field_forwards_unchanged() {
    let mut owned = None;
    let mut ctx = HashMap::from([("host".to_string(), "example.test".to_string())]);
    assert_eq!(
        apply_options_max_forwards("OPTIONS", &mut owned, &mut ctx),
        MaxForwardsDecision::Forward
    );
    assert_eq!(ctx.len(), 1);
    assert!(owned.is_none());
}

#[test]
fn zero_makes_the_gateway_the_final_recipient_and_leaves_the_field_intact() {
    let mut owned = None;
    let mut ctx = options_headers("0");
    assert_eq!(
        apply_options_max_forwards("OPTIONS", &mut owned, &mut ctx),
        MaxForwardsDecision::Terminal(MaxForwardsTerminal::FinalRecipient)
    );
    assert_eq!(ctx[MAX_FORWARDS_HEADER], "0");
    assert!(owned.is_none());
}

#[test]
fn positive_budgets_are_decremented_exactly_once_in_place() {
    for (received, forwarded) in [("1", 0u32), ("2", 1), ("10", 9), (" 3 ", 2)] {
        let mut ctx = options_headers(received);
        assert_eq!(
            decide_options_max_forwards(&mut ctx),
            MaxForwardsDecision::Decremented,
            "{received:?}"
        );
        assert_eq!(
            ctx[MAX_FORWARDS_HEADER],
            forwarded.to_string(),
            "{received:?}"
        );
        assert_eq!(ctx.len(), 1, "{received:?}");
    }
}

#[test]
fn oversized_budget_forwards_the_recipient_maximum_minus_one() {
    let mut ctx = options_headers(&"9".repeat(40));
    assert_eq!(
        decide_options_max_forwards(&mut ctx),
        MaxForwardsDecision::Decremented
    );
    assert_eq!(ctx[MAX_FORWARDS_HEADER], "4294967294");
}

#[test]
fn decrement_lands_in_the_owned_map_when_a_plugin_transformed_headers() {
    let mut owned = Some(options_headers("10"));
    let mut ctx = options_headers("10");
    assert_eq!(
        apply_options_max_forwards("OPTIONS", &mut owned, &mut ctx),
        MaxForwardsDecision::Decremented
    );
    let owned = owned.expect("owned map retained");
    assert_eq!(owned[MAX_FORWARDS_HEADER], "9");
    // The plugin-transformed map is the wire map; the pristine context view
    // is not the source any transport reads once a clone exists.
    assert_eq!(ctx[MAX_FORWARDS_HEADER], "10");
}

#[test]
fn decrement_lands_in_the_context_map_when_it_is_the_wire_map() {
    let mut owned = None;
    let mut ctx = options_headers("1");
    assert_eq!(
        apply_options_max_forwards("OPTIONS", &mut owned, &mut ctx),
        MaxForwardsDecision::Decremented
    );
    assert!(owned.is_none());
    assert_eq!(ctx[MAX_FORWARDS_HEADER], "0");
}

#[test]
fn owned_map_is_authoritative_over_the_context_view() {
    // A plugin removed the field from the outbound map: there is no budget to
    // process even though the pristine context still carries a zero, and a
    // plugin-supplied budget wins over the client's.
    let mut owned = Some(HashMap::new());
    let mut ctx = options_headers("0");
    assert_eq!(
        apply_options_max_forwards("OPTIONS", &mut owned, &mut ctx),
        MaxForwardsDecision::Forward
    );
    assert_eq!(ctx[MAX_FORWARDS_HEADER], "0");

    let mut owned = Some(options_headers("5"));
    let mut ctx = options_headers("0");
    assert_eq!(
        apply_options_max_forwards("OPTIONS", &mut owned, &mut ctx),
        MaxForwardsDecision::Decremented
    );
    assert_eq!(owned.expect("owned map retained")[MAX_FORWARDS_HEADER], "4");
}

#[test]
fn malformed_and_repeated_fields_are_refused_without_forwarding_or_reset() {
    for value in ["abc", "1, 1", "0, 0", "", "-1", "1.0"] {
        let mut ctx = options_headers(value);
        assert_eq!(
            decide_options_max_forwards(&mut ctx),
            MaxForwardsDecision::Terminal(MaxForwardsTerminal::Malformed),
            "{value:?}"
        );
        assert_eq!(ctx[MAX_FORWARDS_HEADER], value, "value must not be reset");
    }
}

#[test]
fn terminal_outcomes_have_fixed_bounded_responses() {
    assert_eq!(
        MaxForwardsTerminal::FinalRecipient.status(),
        StatusCode::NO_CONTENT
    );
    assert!(MaxForwardsTerminal::FinalRecipient.body().is_empty());
    assert_eq!(
        MaxForwardsTerminal::Malformed.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        MaxForwardsTerminal::Malformed.body().as_ref(),
        MAX_FORWARDS_INVALID_BODY
    );
    assert_eq!(
        MAX_FORWARDS_INVALID_BODY,
        br#"{"error":"Invalid Max-Forwards header"}"#
    );
}

#[test]
fn final_recipient_allow_uses_route_methods_or_the_protocol_level_list() {
    let route = vec!["get".to_string(), " options ".to_string()];
    let headers = max_forwards_response_headers(MaxForwardsTerminal::FinalRecipient, Some(&route));
    assert_eq!(
        headers.get("allow").map(String::as_str),
        Some("GET, OPTIONS")
    );
    assert_eq!(headers.len(), 1);

    let headers = max_forwards_response_headers(MaxForwardsTerminal::FinalRecipient, None);
    assert_eq!(
        headers.get("allow").map(String::as_str),
        Some("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
    );

    let malformed = max_forwards_response_headers(MaxForwardsTerminal::Malformed, Some(&route));
    assert!(malformed.is_empty());
    assert!(max_forwards_response_headers(MaxForwardsTerminal::Malformed, None).is_empty());
}

/// Source contract: each frontend ladder takes the shared decision exactly
/// once per inbound request, so a retry helper cannot decrement again and a
/// second frontend cannot grow its own parser.
#[test]
fn every_frontend_ladder_takes_the_shared_decision_once() {
    let h1_h2 = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/server.rs");
    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let call = "max_forwards::apply_options_max_forwards(";
    assert_eq!(h1_h2.matches(call).count(), 1, "H1/H2 ladder");
    assert_eq!(h3.matches(call).count(), 1, "native H3 ladder");
    assert_eq!(
        cross_protocol.matches(call).count(),
        0,
        "the H3 bridge reuses the H3 ladder's decision"
    );
    assert!(
        !h1_h2.contains("\"max-forwards\"") && !h3.contains("\"max-forwards\""),
        "the field name is owned by the shared helper"
    );
}
