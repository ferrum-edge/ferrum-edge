//! Request-time proxy hop limit (`X-Ferrum-Hops`, `FERRUM_MAX_PROXY_HOPS`,
//! issue #6109).
//!
//! These tests pin the shared parser/decision helper, the allocation-free
//! stamp, the outbound re-assertion (including the later gateway-assertion
//! refresh a finalized-egress header overlay runs), the mesh inbound
//! forwarded count, the `loop_detected` observability token, plugin admission
//! refusals, and the structural parity of the two frontends that take the
//! decision. The live loop (a route whose upstream is the gateway itself) and
//! the HTTP/2 native-gRPC backend count are exercised in
//! `tests/functional/functional_proxy_hop_limit_test.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::types::Proxy;
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::plugins::{RequestContext, validate_plugin_config};
use ferrum_edge::proxy::hop_limit::{self, ProxyHopDecision};
use ferrum_edge::retry::{
    HTTP_METRICS_GATEWAY_ERROR_CLASSES, HTTP_OBSERVABILITY_ERROR_CLASSES, OBS_LOOP_DETECTED,
    http_metrics_error_class, intern_http_observability_error_class, token_for_rejection_phase,
};
use serde_json::json;

const HOPS: &str = hop_limit::PROXY_HOPS_HEADER;
const PHASE: &str = hop_limit::PROXY_HOP_LIMIT_REJECTION_PHASE;
const INVALID_PHASE: &str = hop_limit::PROXY_HOPS_INVALID_REJECTION_PHASE;

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
}

#[test]
fn malformed_field_refusal_has_its_own_phase_and_no_token() {
    assert_eq!(INVALID_PHASE, "proxy_hops_invalid");
    assert_ne!(INVALID_PHASE, PHASE);
    assert_eq!(hop_limit::refusal_rejection_phase(true), PHASE);
    assert_eq!(hop_limit::refusal_rejection_phase(false), INVALID_PHASE);
    // The `400` is client-caused: its phase maps to no gateway token, so no
    // surface can ever label it `loop_detected`.
    assert_eq!(token_for_rejection_phase(INVALID_PHASE), None);
    assert_eq!(
        http_metrics_error_class(None, 400, Some(INVALID_PHASE)),
        None
    );
}

#[test]
fn stamped_values_are_the_decimal_count() {
    for hops in 0..=u8::MAX {
        let mut headers = http::HeaderMap::new();
        hop_limit::stamp_proxy_hops(&mut headers, hops);
        assert_eq!(
            headers.get(HOPS).unwrap().as_bytes(),
            hops.to_string().as_bytes(),
            "{hops}"
        );
    }
}

/// A finalized-egress header overlay (a `serverless_function` `pre_proxy`
/// header copy) or a deferred `before_proxy` pass writes headers after the
/// main re-assertion. Both re-run the gateway-assertion refresh, which must
/// restore the forwarded count.
#[test]
fn gateway_assertion_refresh_restores_the_count_over_an_overlay() {
    let mut ctx = context_with_hops(Some(3));
    let mut outbound = HashMap::from([
        ("x-other".to_string(), "kept".to_string()),
        (HOPS.to_string(), "3".to_string()),
    ]);
    // The overlay merge: a function response resets the count and adds case
    // and underscore variants.
    outbound.insert(HOPS.to_string(), "0".to_string());
    outbound.insert("X-Ferrum-Hops".to_string(), "0".to_string());
    outbound.insert("x_ferrum_hops".to_string(), "0".to_string());
    ferrum_edge::proxy::refresh_backend_gateway_assertion_headers(&ctx, &mut outbound);
    assert_eq!(outbound.get(HOPS).map(String::as_str), Some("3"));
    assert_eq!(outbound.get("x-other").map(String::as_str), Some("kept"));
    assert_eq!(
        outbound.len(),
        2,
        "case and underscore variants are dropped"
    );

    // A removed count is restored too.
    outbound.remove(HOPS);
    ferrum_edge::proxy::refresh_backend_gateway_assertion_headers(&ctx, &mut outbound);
    assert_eq!(outbound.get(HOPS).map(String::as_str), Some("3"));

    // With the limit disabled the refresh leaves the field alone.
    ctx.outbound_proxy_hops = None;
    outbound.insert(HOPS.to_string(), "0".to_string());
    ferrum_edge::proxy::refresh_backend_gateway_assertion_headers(&ctx, &mut outbound);
    assert_eq!(outbound.get(HOPS).map(String::as_str), Some("0"));
}

#[test]
fn reassert_in_map_rewrites_a_changed_value_in_place() {
    let mut headers = HashMap::from([(HOPS.to_string(), "10".to_string())]);
    hop_limit::reassert_outbound_proxy_hops_in_map(Some(9), &mut headers);
    assert_eq!(headers.get(HOPS).map(String::as_str), Some("9"));
    hop_limit::reassert_outbound_proxy_hops_in_map(Some(100), &mut headers);
    assert_eq!(headers.get(HOPS).map(String::as_str), Some("100"));
    hop_limit::reassert_outbound_proxy_hops_in_map(None, &mut headers);
    assert_eq!(headers.get(HOPS).map(String::as_str), Some("100"));
}

fn forwarded(ctx: &RequestContext) -> Option<u8> {
    hop_limit::effective_outbound_proxy_hops(ctx)
}

fn context_with_hops(hops: Option<u8>) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.outbound_proxy_hops = hops;
    ctx
}

fn route(id: &str, backend_port: u16) -> Arc<Proxy> {
    let proxy = serde_json::from_value::<Proxy>(json!({
        "id": id,
        "namespace": "default",
        "hosts": ["reviews.default.svc.cluster.local"],
        "listen_path": "/",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port
    }))
    .expect("hop-limit test route must deserialize");
    Arc::new(proxy)
}

/// A mesh inbound context: accepted on the Sidecar inbound listener (`15006`),
/// matched the materialized inbound route to the local app on `9080`, and the
/// frontend stamped `received + 1 = 3`.
fn mesh_inbound_context() -> RequestContext {
    let mut ctx = context_with_hops(Some(3));
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx.frontend_listen_port = Some(15006);
    ctx.matched_proxy = Some(route("__mesh-inbound-default-reviews-9080", 9080));
    ctx
}

#[test]
fn mesh_inbound_hop_to_the_local_workload_forwards_the_received_count() {
    let ctx = mesh_inbound_context();
    assert_eq!(forwarded(&ctx), Some(2));

    // Sidecar `ingress[]` routes are local-workload routes too.
    let mut ingress = mesh_inbound_context();
    ingress.matched_proxy = Some(route("__mesh-ingress-default-reviews-8443", 8443));
    assert_eq!(forwarded(&ingress), Some(2));

    // The outbound map carries the unchanged count after the re-assertion,
    // and the gateway-assertion refresh agrees with it.
    let mut outbound = HashMap::from([(HOPS.to_string(), "3".to_string())]);
    hop_limit::reassert_outbound_proxy_hops_in_map(forwarded(&ctx), &mut outbound);
    assert_eq!(outbound.get(HOPS).map(String::as_str), Some("2"));
    ferrum_edge::proxy::refresh_backend_gateway_assertion_headers(&ctx, &mut outbound);
    assert_eq!(outbound.get(HOPS).map(String::as_str), Some("2"));
}

#[test]
fn every_other_hop_increments_the_count() {
    // Ordinary gateway hop.
    let ctx = context_with_hops(Some(3));
    assert_eq!(forwarded(&ctx), Some(3));

    // Mesh outbound hop.
    let mut outbound = mesh_inbound_context();
    outbound.mesh_direction = Some(MeshTrafficDirection::Outbound);
    assert_eq!(forwarded(&outbound), Some(3));

    // An inbound listener serving a non-mesh route (EgressGateway external
    // routes, operator routes) still forwards somewhere other than the local
    // workload.
    let mut operator = mesh_inbound_context();
    operator.matched_proxy = Some(route("operator-route", 9080));
    assert_eq!(forwarded(&operator), Some(3));

    // An outbound mesh route matched on an inbound listener.
    let mut wrong_direction = mesh_inbound_context();
    wrong_direction.matched_proxy = Some(route("__mesh-outbound-default-ratings-9080", 9080));
    assert_eq!(forwarded(&wrong_direction), Some(3));

    // A plugin route override can send the request anywhere.
    let mut overridden = mesh_inbound_context();
    overridden.route_override_backend_port = Some(9090);
    assert_eq!(forwarded(&overridden), Some(3));

    // A loopback target on the accepting listener's own port would re-enter
    // the same inbound listener: it must still count.
    let mut self_target = mesh_inbound_context();
    self_target.matched_proxy = Some(route("__mesh-inbound-default-reviews-15006", 15006));
    assert_eq!(forwarded(&self_target), Some(3));

    // No matched route yet (frontend refusals, HBONE CONNECT relays).
    let mut unrouted = mesh_inbound_context();
    unrouted.matched_proxy = None;
    assert_eq!(forwarded(&unrouted), Some(3));

    // Disabled limit.
    let mut disabled = mesh_inbound_context();
    disabled.outbound_proxy_hops = None;
    assert_eq!(forwarded(&disabled), None);
}

/// A mesh inbound hop still CHECKS the received count: the frontend decision
/// is direction-blind, so a looped request reaching an inbound sidecar at the
/// limit is refused there.
#[test]
fn mesh_inbound_hop_still_refuses_at_the_limit() {
    assert_eq!(decide(&["10"], 10), ProxyHopDecision::LoopDetected);
    let mut ctx = mesh_inbound_context();
    ctx.outbound_proxy_hops = Some(10);
    assert_eq!(forwarded(&ctx), Some(9));
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
            "hop_limit::refusal_rejection_phase(",
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

/// The deferred `before_proxy` passes and both finalized-egress overlay
/// helpers restore gateway assertions through
/// `refresh_backend_gateway_assertion_headers`; that refresh must re-assert the
/// hop count with the same effective value as the main dispatch point.
#[test]
fn every_gateway_assertion_refresh_reasserts_the_count() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/proxy/mod.rs")).unwrap();
    let refresh = fn_body(&source, "pub fn refresh_backend_gateway_assertion_headers(");
    assert!(
        refresh.contains("hop_limit::reassert_outbound_proxy_hops_in_map(")
            && refresh.contains("hop_limit::effective_outbound_proxy_hops(ctx)"),
        "the gateway-assertion refresh must re-assert X-Ferrum-Hops"
    );
    for overlay in [
        "pub(crate) fn apply_finalized_request_egress_header_overlay(",
        "pub(crate) fn apply_finalized_request_egress_header_overlay_in_map(",
    ] {
        assert!(
            fn_body(&source, overlay).contains("refresh_"),
            "`{overlay}` must re-run the gateway-assertion refresh after its merge"
        );
    }
}

/// The text of the top-level function starting at `signature`, up to its
/// closing brace.
fn fn_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing `{signature}`"));
    let end = source[start..]
        .find("\n}\n")
        .unwrap_or_else(|| panic!("unterminated `{signature}`"));
    &source[start..start + end]
}
