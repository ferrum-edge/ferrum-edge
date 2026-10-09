//! Request-time proxy hop limit (`X-Ferrum-Hops`, `FERRUM_MAX_PROXY_HOPS`,
//! issue #6109).
//!
//! These tests pin the shared parser/decision helper, the allocation-free
//! stamp, the outbound re-assertion, the `loop_detected` observability token,
//! plugin admission refusals, and the structural parity of the two frontends
//! that take the decision. The live loop (a route whose upstream is the gateway
//! itself) is exercised in `tests/functional/functional_proxy_hop_limit_test.rs`.

use std::collections::HashMap;

use ferrum_edge::plugins::validate_plugin_config;
use ferrum_edge::proxy::hop_limit::{self, ProxyHopDecision};
use ferrum_edge::retry::{
    HTTP_METRICS_GATEWAY_ERROR_CLASSES, HTTP_OBSERVABILITY_ERROR_CLASSES, OBS_LOOP_DETECTED,
    http_metrics_error_class, intern_http_observability_error_class, token_for_rejection_phase,
};
use serde_json::json;

const HOPS: &str = hop_limit::PROXY_HOPS_HEADER;
const PHASE: &str = hop_limit::PROXY_HOP_LIMIT_REJECTION_PHASE;

fn headers_with(values: &[&str]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for value in values {
        headers.append(HOPS, http::HeaderValue::from_str(value).unwrap());
    }
    headers
}

fn decide(values: &[&str], max_hops: u8) -> ProxyHopDecision {
    hop_limit::decide_proxy_hops(&headers_with(values), max_hops)
}

#[test]
fn default_limit_is_ten() {
    assert_eq!(hop_limit::DEFAULT_MAX_PROXY_HOPS, 10);
    assert_eq!(HOPS, "x-ferrum-hops");
}

#[test]
fn parse_accepts_one_decimal_with_optional_whitespace() {
    assert_eq!(hop_limit::parse_proxy_hops(b"0"), Some(0));
    assert_eq!(hop_limit::parse_proxy_hops(b"7"), Some(7));
    assert_eq!(hop_limit::parse_proxy_hops(b" 9\t"), Some(9));
    assert_eq!(hop_limit::parse_proxy_hops(b"007"), Some(7));
}

#[test]
fn parse_saturates_instead_of_overflowing() {
    assert_eq!(hop_limit::parse_proxy_hops(b"4294967295"), Some(u32::MAX));
    assert_eq!(hop_limit::parse_proxy_hops(b"99999999999"), Some(u32::MAX));
    // Saturation still validates every remaining byte.
    assert_eq!(hop_limit::parse_proxy_hops(b"99999999999x"), None);
}

#[test]
fn parse_refuses_anything_but_one_decimal() {
    let cases: [&[u8]; 6] = [b"", b"-1", b"1.0", b"1, 2", b"one", b"0x10"];
    for value in cases {
        assert_eq!(hop_limit::parse_proxy_hops(value), None, "{value:?}");
    }
}

#[test]
fn absent_field_is_hop_zero_and_forwards_one() {
    assert_eq!(
        decide(&[], hop_limit::DEFAULT_MAX_PROXY_HOPS),
        ProxyHopDecision::Forward(1)
    );
}

#[test]
fn received_count_below_the_limit_is_incremented() {
    assert_eq!(decide(&["0"], 10), ProxyHopDecision::Forward(1));
    assert_eq!(decide(&["9"], 10), ProxyHopDecision::Forward(10));
    assert_eq!(decide(&["254"], 255), ProxyHopDecision::Forward(255));
}

#[test]
fn received_count_at_or_above_the_limit_is_a_loop() {
    assert_eq!(decide(&["10"], 10), ProxyHopDecision::LoopDetected);
    assert_eq!(decide(&["11"], 10), ProxyHopDecision::LoopDetected);
    assert_eq!(decide(&["255"], 255), ProxyHopDecision::LoopDetected);
    assert_eq!(
        decide(&["99999999999999999999"], 255),
        ProxyHopDecision::LoopDetected
    );
    // A limit of one admits only a request no Ferrum gateway forwarded yet.
    assert_eq!(decide(&["1"], 1), ProxyHopDecision::LoopDetected);
    assert_eq!(decide(&[], 1), ProxyHopDecision::Forward(1));
}

#[test]
fn malformed_or_repeated_field_is_refused_not_reset() {
    for value in ["", "-1", "1.0", "abc", "1, 1"] {
        assert_eq!(
            decide(&[value], 10),
            ProxyHopDecision::Malformed,
            "{value:?}"
        );
    }
    // Two field lines are malformed even when they agree.
    assert_eq!(decide(&["1", "1"], 10), ProxyHopDecision::Malformed);
}

#[test]
fn zero_limit_disables_the_check_entirely() {
    assert_eq!(decide(&[], 0), ProxyHopDecision::Disabled);
    assert_eq!(decide(&["10"], 0), ProxyHopDecision::Disabled);
    assert_eq!(decide(&["abc"], 0), ProxyHopDecision::Disabled);
    assert_eq!(decide(&["1", "2"], 0), ProxyHopDecision::Disabled);
}

#[test]
fn stamp_replaces_every_client_field_line() {
    let mut headers = headers_with(&["0", "0"]);
    headers.insert("x-other", http::HeaderValue::from_static("kept"));
    hop_limit::stamp_proxy_hops(&mut headers, 3);
    assert_eq!(headers.get_all(HOPS).iter().count(), 1);
    assert_eq!(headers.get(HOPS).unwrap(), "3");
    assert_eq!(headers.get("x-other").unwrap(), "kept");

    for hops in [0u8, 1, 9, 10, 100, 254, 255] {
        hop_limit::stamp_proxy_hops(&mut headers, hops);
        assert_eq!(
            headers.get(HOPS).unwrap().to_str().unwrap(),
            hops.to_string()
        );
    }
}

#[test]
fn a_stamped_count_is_read_back_by_the_next_hop() {
    // Simulate a request looping through gateways with the default limit:
    // every hop forwards `received + 1` until the limit refuses it.
    let mut headers = http::HeaderMap::new();
    let mut forwarded: usize = 0;
    loop {
        match hop_limit::decide_proxy_hops(&headers, hop_limit::DEFAULT_MAX_PROXY_HOPS) {
            ProxyHopDecision::Forward(hops) => {
                hop_limit::stamp_proxy_hops(&mut headers, hops);
                forwarded += 1;
            }
            ProxyHopDecision::LoopDetected => break,
            other => panic!("unexpected decision {other:?}"),
        }
        assert!(forwarded <= 255, "the loop must terminate");
    }
    assert_eq!(forwarded, usize::from(hop_limit::DEFAULT_MAX_PROXY_HOPS));
}

#[test]
fn header_name_predicate_folds_case_and_underscore() {
    for name in [
        "x-ferrum-hops",
        "X-Ferrum-Hops",
        "X-FERRUM-HOPS",
        "x_ferrum_hops",
        "X_Ferrum-Hops",
    ] {
        assert!(hop_limit::is_proxy_hops_header(name), "{name}");
    }
    for name in ["x-ferrum-hop", "x-ferrum-hops2", "ferrum-hops"] {
        assert!(!hop_limit::is_proxy_hops_header(name), "{name}");
    }
}

#[test]
fn reassert_is_a_no_op_when_disabled() {
    let mut ctx_headers = HashMap::from([(HOPS.to_string(), "abc".to_string())]);
    let mut owned = None;
    hop_limit::reassert_outbound_proxy_hops(None, &mut owned, &mut ctx_headers);
    assert_eq!(ctx_headers.get(HOPS).unwrap(), "abc");
    assert!(owned.is_none());
}

#[test]
fn reassert_keeps_an_intact_value() {
    let mut ctx_headers = HashMap::from([
        (HOPS.to_string(), "4".to_string()),
        ("x-other".to_string(), "kept".to_string()),
    ]);
    let mut owned = None;
    hop_limit::reassert_outbound_proxy_hops(Some(4), &mut owned, &mut ctx_headers);
    assert_eq!(ctx_headers.get(HOPS).unwrap(), "4");
    assert_eq!(ctx_headers.len(), 2);
}

#[test]
fn reassert_restores_a_plugin_rewritten_or_removed_value() {
    let mut owned = None;
    let mut ctx_headers = HashMap::from([(HOPS.to_string(), "0".to_string())]);
    hop_limit::reassert_outbound_proxy_hops(Some(2), &mut owned, &mut ctx_headers);
    assert_eq!(ctx_headers.get(HOPS).unwrap(), "2");

    let mut ctx_headers = HashMap::new();
    hop_limit::reassert_outbound_proxy_hops(Some(5), &mut owned, &mut ctx_headers);
    assert_eq!(ctx_headers.get(HOPS).unwrap(), "5");
}

#[test]
fn reassert_writes_the_owned_outbound_map_when_one_exists() {
    let mut ctx_headers = HashMap::from([(HOPS.to_string(), "3".to_string())]);
    let mut owned = Some(HashMap::from([
        (HOPS.to_string(), "0".to_string()),
        ("X-Ferrum-Hops".to_string(), "0".to_string()),
        ("x_ferrum_hops".to_string(), "0".to_string()),
    ]));
    hop_limit::reassert_outbound_proxy_hops(Some(3), &mut owned, &mut ctx_headers);
    let owned = owned.unwrap();
    assert_eq!(owned.len(), 1, "case and underscore variants are dropped");
    assert_eq!(owned.get(HOPS).unwrap(), "3");
}

#[test]
fn loop_detected_is_a_closed_gateway_token() {
    assert_eq!(OBS_LOOP_DETECTED, "loop_detected");
    let header_tokens = HTTP_OBSERVABILITY_ERROR_CLASSES;
    let metric_tokens = HTTP_METRICS_GATEWAY_ERROR_CLASSES;
    assert!(header_tokens.contains(&OBS_LOOP_DETECTED));
    assert!(metric_tokens.contains(&OBS_LOOP_DETECTED));
    assert_eq!(
        intern_http_observability_error_class("loop_detected"),
        Some(OBS_LOOP_DETECTED)
    );
    assert_eq!(token_for_rejection_phase(PHASE), Some(OBS_LOOP_DETECTED));
    assert_eq!(
        http_metrics_error_class(None, 508, Some(PHASE)),
        Some(OBS_LOOP_DETECTED)
    );
    // The malformed-field `400` shares the phase but carries no 5xx label.
    assert_eq!(http_metrics_error_class(None, 400, Some(PHASE)), None);
}

#[test]
fn request_transformer_refuses_every_rule_touching_the_hop_count() {
    for name in ["x-ferrum-hops", "X-Ferrum-Hops", "x_ferrum_hops"] {
        let rules = [
            json!({"target": "header", "operation": "add", "key": name, "value": "0"}),
            json!({"target": "header", "operation": "update", "key": name, "value": "0"}),
            json!({"target": "header", "operation": "remove", "key": name}),
            json!({"target": "header", "operation": "rename",
                "key": name, "new_key": "x-copy"}),
            json!({"target": "header", "operation": "rename",
                "key": "x-source", "new_key": name}),
        ];
        for rule in rules {
            let config = json!({"rules": [rule]});
            let Err(error) = validate_plugin_config("request_transformer", &config) else {
                panic!("{name}: a rule naming x-ferrum-hops must fail admission");
            };
            assert!(error.contains("x-ferrum-hops"), "{name}: {error}");
        }
    }
}

#[test]
fn correlation_id_and_claim_mappings_cannot_target_the_hop_count() {
    use ferrum_edge::plugins::utils::claim_header_fanout::is_reserved_header;

    let config = json!({"header_name": "X-Ferrum-Hops"});
    let Err(error) = validate_plugin_config("correlation_id", &config) else {
        panic!("correlation_id must refuse x-ferrum-hops as its header_name");
    };
    assert!(error.contains("header_name"), "{error}");
    assert!(is_reserved_header("x-ferrum-hops"));
    assert!(is_reserved_header("X_Ferrum_Hops"));
}

/// Both frontends take the same decision before routing and re-assert the
/// forwarded count at the same point in their dispatch ladders. A frontend
/// that dropped either half would let a loop through on that protocol.
#[test]
fn both_http_frontends_take_the_decision_and_reassert_the_count() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for path in ["src/proxy/mod.rs", "src/http3/server.rs"] {
        let source = std::fs::read_to_string(root.join(path)).unwrap();
        for needle in [
            "hop_limit::decide_proxy_hops(",
            "hop_limit::stamp_proxy_hops(",
            "hop_limit::reassert_outbound_proxy_hops(",
        ] {
            assert_eq!(
                source.matches(needle).count(),
                1,
                "{path} must call `{needle}` exactly once"
            );
        }
        // The stamp lands before the raw block is confined and stored.
        let stamp_at = source.find("hop_limit::stamp_proxy_hops(").unwrap();
        assert!(
            source[stamp_at..].contains("confine_connection_nominated_request_headers("),
            "{path}: the stamp must precede the Connection confinement"
        );
    }
}
