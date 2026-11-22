//! Request-header passthrough (issue #6671).
//!
//! A routed request no plugin can observe dispatches from its wire header block
//! instead of the materialized `RequestContext::headers` map. These tests pin
//! the equivalence that makes that safe: for every eligible block the
//! passthrough view reads, rebuilds, rematerializes and forwards exactly what
//! the eager path would, and every block the eager path would reshape
//! (repeated names, non-UTF-8 values, reserved gateway assertions) stays on the
//! materialized path.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use ferrum_edge::_test_support::{
    RequestHeaderPassthroughProbe, basic_auth_with_secret_for_test,
    begin_request_header_passthrough_for_test, end_request_header_passthrough_for_test,
    plugin_capabilities_for_plugins_for_test, preserved_response_content_length_parity_for_test,
    request_header_passthrough_overlay_probe_for_test, request_header_passthrough_probe_for_test,
    response_header_passthrough_parity_for_test, run_after_proxy_hooks_reject_for_test,
};
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::{
    BackendAdmissionContext, BackendAdmissionDecision, Plugin, PluginHooks, PluginResult,
    ProxyProtocol, RequestContext, create_plugin,
};
use ferrum_edge::{PluginCache, PluginCapabilities};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::json;

use crate::unit::plugins::plugin_utils::{
    create_test_consumer, make_plugin_config_with_json, make_proxy,
};

const PROBE_NAMES: &[&str] = &[
    "host",
    "Host",
    "User-Agent",
    "x-ferrum-hops",
    "X-Ferrum-Hops",
    "absent-header",
    "not a header name",
    "",
];

fn block(fields: &[(&str, &[u8])]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_bytes(value).expect("test header value"),
        );
    }
    map
}

fn probe(
    raw: HeaderMap,
    authority: Option<&str>,
    proxy_hops: Option<u8>,
) -> Option<RequestHeaderPassthroughProbe> {
    request_header_passthrough_probe_for_test(raw, authority, proxy_hops, PROBE_NAMES)
}

fn assert_equivalent(probe: &RequestHeaderPassthroughProbe) {
    assert_eq!(probe.view_map, probe.eager, "view rebuilds the eager map");
    assert_eq!(
        probe.rematerialized, probe.eager,
        "leaving the lane yields the eager map"
    );
    assert!(
        probe.lookups_match,
        "every lookup agrees with the eager map"
    );
    assert!(probe.len_matches, "length and entry count agree");
    assert!(
        probe.connection_listed_matches,
        "Connection-listed names agree"
    );
    assert_eq!(
        probe.view_outbound, probe.eager_outbound,
        "outbound headers are byte-identical"
    );
}

#[test]
fn http1_block_is_equivalent_and_keeps_the_client_host() {
    let probe = probe(
        block(&[
            ("host", b"api.example.com"),
            ("user-agent", b"curl/8.9"),
            ("accept", b"application/json, text/plain;q=0.5"),
            ("cookie", b"a=1; b=2"),
            ("content-length", b"42"),
            ("x-request-id", b"req-1"),
            ("x-ferrum-hops", b"1"),
        ]),
        Some("ignored.example.com"),
        Some(1),
    )
    .expect("plain H1 block is eligible");
    assert_equivalent(&probe);
    assert_eq!(
        probe.eager.get("host").map(String::as_str),
        Some("api.example.com")
    );
}

#[test]
fn http2_block_backfills_host_from_authority() {
    let probe = probe(
        block(&[
            ("content-type", b"application/json"),
            ("x-ferrum-hops", b"1"),
        ]),
        Some("api.example.com:8443"),
        Some(1),
    )
    .expect("H2 block without Host is eligible");
    assert_equivalent(&probe);
    assert_eq!(
        probe.view_map.get("host").map(String::as_str),
        Some("api.example.com:8443")
    );
}

#[test]
fn reasserted_hop_count_replaces_or_appends_the_wire_value() {
    let replaced = probe(block(&[("x-ferrum-hops", b"7")]), None, Some(2))
        .expect("single hop field is eligible");
    assert_equivalent(&replaced);
    assert_eq!(
        replaced.view_map.get("x-ferrum-hops").map(String::as_str),
        Some("2")
    );

    let appended = probe(block(&[("accept", b"*/*")]), None, Some(3))
        .expect("block without a hop field is eligible");
    assert_equivalent(&appended);
    assert_eq!(
        appended.view_map.get("x-ferrum-hops").map(String::as_str),
        Some("3")
    );
}

#[test]
fn disabled_hop_limit_forwards_the_client_value_unchanged() {
    let probe = probe(block(&[("x-ferrum-hops", b"9")]), None, None)
        .expect("hop field with the limit disabled is eligible");
    assert_equivalent(&probe);
    assert_eq!(
        probe.view_map.get("x-ferrum-hops").map(String::as_str),
        Some("9")
    );
}

#[test]
fn utf8_obs_text_and_tab_values_forward_byte_exact() {
    let probe = probe(
        block(&[
            ("x-name", "caf\u{e9}".as_bytes()),
            ("x-tabbed", b"a\tb"),
            ("x-empty", b""),
        ]),
        None,
        None,
    )
    .expect("UTF-8 obs-text is eligible");
    assert_equivalent(&probe);
}

#[test]
fn empty_block_is_equivalent() {
    let probe = probe(HeaderMap::new(), None, None).expect("empty block is eligible");
    assert_equivalent(&probe);
    assert!(probe.eager.is_empty());
}

#[test]
fn blocks_the_eager_path_reshapes_stay_materialized() {
    let ineligible = [
        (
            "repeated name folds into one value",
            block(&[("accept", b"text/html"), ("accept", b"*/*")]),
        ),
        (
            "repeated cookie folds with a semicolon",
            block(&[("cookie", b"a=1"), ("cookie", b"b=2")]),
        ),
        (
            "non-UTF-8 value is dropped",
            block(&[("x-binary", &[0x66, 0xff, 0x6f])]),
        ),
        (
            "consumer assertion is scrubbed",
            block(&[("x-consumer-username", b"mallory")]),
        ),
        (
            "underscore consumer assertion is scrubbed",
            block(&[("x_consumer_id", b"1")]),
        ),
        (
            "path-parameter assertion is scrubbed",
            block(&[("x-path-param-id", b"7")]),
        ),
        (
            "GeoIP assertion is scrubbed",
            block(&[("x-geo-country", b"US")]),
        ),
        (
            "underscore GeoIP assertion is scrubbed",
            block(&[("x_geo_country", b"US")]),
        ),
        (
            "authenticated-identity assertion is scrubbed",
            block(&[("x-authenticated-identity", b"spiffe://evil")]),
        ),
        (
            "underscore authenticated-identity assertion is scrubbed",
            block(&[("x_authenticated_identity", b"spiffe://evil")]),
        ),
        (
            "backend-equivalent hop-count spelling is scrubbed",
            block(&[("x_ferrum_hops", b"0")]),
        ),
        (
            "case-folded hop-count spelling next to the canonical one",
            block(&[("x-ferrum-hops", b"1"), ("x_Ferrum_Hops", b"0")]),
        ),
    ];
    for (case, raw) in ineligible {
        assert!(
            probe(raw, Some("api.example.com"), Some(1)).is_none(),
            "{case}"
        );
    }
}

#[test]
fn connection_listed_names_match_the_eager_parse() {
    let probe = probe(
        block(&[
            ("connection", b"keep-alive, X-Debug, , bad header"),
            ("x-debug", b"1"),
            ("keep-alive", b"timeout=5"),
        ]),
        None,
        Some(1),
    )
    .expect("single Connection field is eligible");
    assert_equivalent(&probe);
}

/// Strip `//` comment lines and all whitespace so the check survives rustfmt.
fn compact(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// The handler admits a request to the lane only behind every exclusion the
/// view does not model, and only once the plugin view is known.
#[test]
fn handler_gate_keeps_every_lane_exclusion() {
    let source = compact(include_str!("../../../src/proxy/mod.rs"));
    let arm = source
        .find("ifrm.path_params.is_empty(){request_headers_deferred=true;}else{")
        .expect("route match defers only routes without path-parameter captures");
    let view = source
        .find("letplugin_cache_view=ifgrpc_web_request{")
        .expect("plugin view resolution");
    let gate_start = source[view..]
        .find("ifrequest_headers_deferred{")
        .map(|at| view + at)
        .expect("passthrough decision follows the plugin view");
    assert!(arm < view, "deferral is recorded at route match");
    let gate_end = source[gate_start..]
        .find("materialize_routed_request_headers(&mutctx,req.uri().authority());")
        .map(|at| gate_start + at)
        .expect("a declined request materializes at the decision point");
    let gate = &source[gate_start..gate_end];
    for needle in [
        "matches!(request_protocol,ProxyProtocol::Http)",
        "matches!(flavor,HttpFlavor::Plain)",
        "!grpc_web_request",
        "hyper::Version::HTTP_10|hyper::Version::HTTP_11|hyper::Version::HTTP_2",
        "ctx.mesh_direction.is_none()",
        "!is_hbone_connect_any",
        "method!=\"OPTIONS\"",
        "state.mesh_egress_strip_baggage_keys.is_empty()",
        "!plugin_cache_view.has_plugins()",
        "ctx.try_begin_request_header_passthrough(",
    ] {
        assert!(gate.contains(needle), "passthrough gate lost `{needle}`");
    }
    let first_reject = source[gate_start..]
        .find("ROUTE_PROTOCOL_NOT_PERMITTED_BODY")
        .map(|at| gate_start + at)
        .expect("route-level protocol reject");
    assert!(
        gate_end < first_reject,
        "the decision precedes every route-level reject that can log headers"
    );
}

#[test]
fn authority_that_cannot_be_a_header_value_stays_materialized() {
    assert!(
        probe(block(&[("accept", b"*/*")]), Some("bad\u{7f}host"), Some(1)).is_none(),
        "a Host backfill the outbound builders would drop must not enter the lane"
    );
}

#[test]
fn overlay_strips_credentials_and_injects_gateway_assertions_identically() {
    let probe = request_header_passthrough_overlay_probe_for_test(
        block(&[
            ("host", b"api.example.com"),
            ("x-api-key", b"super-secret-key"),
            ("content-type", b"application/json"),
            ("x-ferrum-hops", b"1"),
        ]),
        None,
        Some(2),
        &["x-api-key"],
        Some("alice"),
        Some("cust-42"),
        Some("alice@example.com"),
        Some("US"),
        PROBE_NAMES,
    )
    .expect("header-only key_auth overlay with valid assertions is eligible");
    assert_equivalent(&probe);
    assert!(!probe.view_map.contains_key("x-api-key"));
    assert_eq!(
        probe
            .view_map
            .get("x-consumer-username")
            .map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        probe
            .view_map
            .get("x-consumer-custom-id")
            .map(String::as_str),
        Some("cust-42")
    );
    assert_eq!(
        probe
            .view_map
            .get("x-authenticated-identity")
            .map(String::as_str),
        Some("alice@example.com")
    );
    assert_eq!(
        probe.view_map.get("x-geo-country").map(String::as_str),
        Some("US")
    );
}

#[test]
fn overlay_falls_back_on_unrepresentable_assertion_values() {
    assert!(
        request_header_passthrough_overlay_probe_for_test(
            block(&[("host", b"api.example.com"), ("x-api-key", b"k")]),
            None,
            Some(1),
            &["x-api-key"],
            Some("bad\u{7f}user"),
            None,
            None,
            None,
            PROBE_NAMES,
        )
        .is_none(),
        "control characters in gateway assertions must decline the overlay and materialize"
    );
}

#[test]
fn overlay_stripping_host_hides_authority_backfill() {
    let probe = request_header_passthrough_overlay_probe_for_test(
        block(&[("accept", b"*/*")]),
        Some("api.example.com"),
        Some(1),
        &["host"],
        Some("alice"),
        None,
        None,
        None,
        PROBE_NAMES,
    )
    .expect("stripping host keeps view and materialized maps consistent");
    assert_equivalent(&probe);
    assert!(!probe.view_map.contains_key("host"));
}

#[test]
fn key_auth_passthrough_eligibility_rules() {
    let header_key_auth = create_plugin("key_auth", &json!({ "key_location": "header:X-API-Key" }))
        .expect("header key_auth builds")
        .expect("key_auth is registered");
    assert!(header_key_auth.supports_request_header_passthrough());

    let query_key_auth = create_plugin("key_auth", &json!({ "key_location": "query:api_key" }))
        .expect("query key_auth builds")
        .expect("key_auth is registered");
    assert!(!query_key_auth.supports_request_header_passthrough());

    let host_key_auth = create_plugin("key_auth", &json!({ "key_location": "header:Host" }))
        .expect("host key_auth builds")
        .expect("key_auth is registered");
    assert!(
        !host_key_auth.supports_request_header_passthrough(),
        "header:Host needs materialized H2 Host backfill before lookup"
    );

    let visible_key_auth = create_plugin(
        "key_auth",
        &json!({
            "key_location": "header:X-API-Key",
            "hide_credentials": false
        }),
    )
    .expect("hide_credentials=false key_auth builds")
    .expect("key_auth is registered");
    assert!(visible_key_auth.supports_request_header_passthrough());

    let proxy = make_proxy("bench-key-auth", "/api", vec!["key-auth-1"]);
    let plugin_cfg = make_plugin_config_with_json(
        "key-auth-1",
        "key_auth",
        json!({ "key_location": "header:X-API-Key", "hide_credentials": true }),
        PluginScope::Proxy,
        Some("bench-key-auth"),
    );
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        plugin_configs: vec![plugin_cfg],
        ..Default::default()
    };
    let cache = PluginCache::new(&cfg).expect("plugin cache builds");
    let view = cache.request_view("ferrum", "bench-key-auth", ProxyProtocol::Http);
    assert!(
        view.capabilities()
            .has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "header-only key_auth chain must advertise SUPPORTS_REQUEST_HEADER_PASSTHROUGH"
    );

    // Adding a trigger disables passthrough so trigger evaluation sees materialized headers.
    cfg.plugin_configs[0].trigger = Some(
        serde_json::from_value(json!({
            "when": { "match": { "method": ["POST"] } }
        }))
        .expect("valid trigger"),
    );
    let triggered_cache = PluginCache::new(&cfg).expect("triggered plugin cache builds");
    let triggered_view =
        triggered_cache.request_view("ferrum", "bench-key-auth", ProxyProtocol::Http);
    assert!(
        !triggered_view
            .capabilities()
            .has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "a trigger on key_auth must disable request-header passthrough"
    );
}

#[test]
fn deferred_response_header_lane_matches_materialized_wire_headers() {
    let raw = block(&[
        ("content-type", b"application/json"),
        ("content-length", b"1024"),
        ("connection", b"keep-alive"),
        ("keep-alive", b"timeout=5"),
        ("via", b"1.1 envoy"),
        ("alt-svc", b"h3=\":8443\""),
        ("set-cookie", b"a=1; Path=/"),
        ("set-cookie", b"b=2; Path=/"),
        ("x-gateway-error", b"spoofed"),
        ("x-gateway-upstream-status", b"spoofed"),
        ("x-ferrum-diagnostic-ref", b"spoofed"),
        ("x-upstream-id", b"backend-1"),
    ]);
    let (materialized, deferred) = response_header_passthrough_parity_for_test(
        raw,
        200,
        Some("1.1 ferrum"),
        Some("h3=\":443\""),
    )
    .expect("standard H1 response with multi Set-Cookie and Connection: keep-alive is eligible");
    assert_eq!(
        deferred, materialized,
        "deferred HeaderMap lane must produce byte-identical wire headers (including Via/Alt-Svc append)"
    );
    let via_count = deferred.iter().filter(|(name, _)| name == "via").count();
    assert_eq!(
        via_count, 2,
        "upstream Via and gateway Via must both be present"
    );
    let alt_svc_count = deferred
        .iter()
        .filter(|(name, _)| name == "alt-svc")
        .count();
    assert_eq!(
        alt_svc_count, 2,
        "upstream Alt-Svc and gateway Alt-Svc must both be present"
    );

    // Connection nominating a non-standard header (such as content-length or x-custom)
    // must decline passthrough so collection strips it identically.
    assert!(
        response_header_passthrough_parity_for_test(
            block(&[
                ("connection", b"keep-alive, content-length"),
                ("content-length", b"42"),
            ]),
            200,
            None,
            None,
        )
        .is_none()
    );
    assert!(
        response_header_passthrough_parity_for_test(
            block(&[("x-dup", b"one"), ("x-dup", b"two")]),
            200,
            None,
            None,
        )
        .is_none()
    );

    // Comma-folded Content-Length ("42, 42"), signed "+42", and 204 responses
    // must produce identical declared-length decisions on both lanes.
    assert_eq!(
        preserved_response_content_length_parity_for_test(
            block(&[("content-length", b"42, 42")]),
            200,
        ),
        (None, None),
        "comma-folded Content-Length must be rejected on both materialized and deferred lanes"
    );
    assert_eq!(
        preserved_response_content_length_parity_for_test(
            block(&[("content-length", b"+42")]),
            200,
        ),
        (None, None),
    );
    assert_eq!(
        preserved_response_content_length_parity_for_test(block(&[("content-length", b"42")]), 200),
        (Some(42), Some(42)),
    );
    assert_eq!(
        preserved_response_content_length_parity_for_test(block(&[("content-length", b"42")]), 204),
        (None, None),
    );
}

struct CustomFinalHeaderPolicyPlugin {
    stream_terminated_called: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl Plugin for CustomFinalHeaderPolicyPlugin {
    fn name(&self) -> &str {
        "custom_final_header_policy"
    }

    fn lifecycle_hooks(&self) -> PluginHooks {
        PluginHooks::NONE
    }

    fn enforces_final_client_visible_response_headers(&self, _ctx: &RequestContext) -> bool {
        true
    }

    async fn finalize_client_visible_response_headers(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> PluginResult {
        if response_headers.contains_key("x-forbidden") {
            PluginResult::Reject {
                status_code: 451,
                body: r#"{"error":"forbidden header"}"#.to_string(),
                headers: HashMap::new(),
            }
        } else {
            PluginResult::Continue
        }
    }

    async fn on_response_stream_terminated(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _outcome: &ferrum_edge::proxy::deferred_log::BodyOutcome,
    ) {
        self.stream_terminated_called
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn custom_plugin_with_none_lifecycle_hooks_retains_after_proxy_phase() {
    let stream_terminated_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(CustomFinalHeaderPolicyPlugin {
        stream_terminated_called: Arc::clone(&stream_terminated_called),
    })];
    let caps = plugin_capabilities_for_plugins_for_test(&plugins);
    assert!(
        caps.has(PluginCapabilities::HAS_AFTER_PROXY_HOOK),
        "custom plugins must retain HAS_AFTER_PROXY_HOOK even when lifecycle_hooks() returns NONE"
    );
    assert!(
        caps.has(PluginCapabilities::HAS_TERMINAL_SUMMARY_CONSUMER),
        "custom plugins must retain HAS_TERMINAL_SUMMARY_CONSUMER even when lifecycle_hooks() returns NONE"
    );
    assert!(
        !caps.has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "custom plugins must never qualify for built-in key_auth request-header passthrough"
    );

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut response_headers = HashMap::from([("x-forbidden".to_string(), "1".to_string())]);
    let reject =
        run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut response_headers)
            .await
            .expect("custom final response-header policy must reject forbidden response header");
    assert_eq!(reject.0, 451);

    ferrum_edge::proxy::deferred_log::run_response_stream_termination_hooks(
        &plugins,
        &mut ctx,
        200,
        &ferrum_edge::proxy::deferred_log::BodyOutcome::success(128),
    )
    .await;
    assert!(
        stream_terminated_called.load(std::sync::atomic::Ordering::SeqCst),
        "custom plugin on_response_stream_terminated must still run when lifecycle_hooks() returns NONE"
    );
}

fn make_passthrough_pair(client_ip: &str, raw: HeaderMap) -> (RequestContext, RequestContext) {
    let mut materialized = RequestContext::new(
        client_ip.to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    materialized.set_raw_headers(raw.clone());
    materialized.materialize_headers();

    let mut passthrough = RequestContext::new(
        client_ip.to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    assert!(
        begin_request_header_passthrough_for_test(&mut passthrough, raw, None),
        "test header block must enter passthrough"
    );
    assert!(
        passthrough.headers.is_empty(),
        "passthrough must leave ctx.headers empty"
    );
    (materialized, passthrough)
}

#[tokio::test]
async fn generalized_passthrough_builtins_match_materialized_behavior() {
    // 1. jwt_auth: valid & invalid Bearer tokens behave identically on both lanes.
    let jwt_plugin = create_plugin("jwt_auth", &json!({ "hide_credentials": false }))
        .expect("jwt_auth builds")
        .expect("jwt_auth registered");
    assert!(jwt_plugin.supports_request_header_passthrough());
    let jwt_hidden = create_plugin("jwt_auth", &json!({ "hide_credentials": true }))
        .expect("jwt_auth hide_credentials builds")
        .expect("jwt_auth registered");
    assert!(!jwt_hidden.supports_request_header_passthrough());

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(std::slice::from_ref(&consumer));
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({
            "iss": "testuser",
            "sub": "testuser",
            "exp": 9_999_999_999u64,
            "nbf": 0u64,
        }),
        &jsonwebtoken::EncodingKey::from_secret(b"test-jwt-secret-0123456789abcdefghij"),
    )
    .expect("jwt encodes");
    let auth_header = format!("Bearer {token}");
    let (mut mat_ctx, mut pt_ctx) = make_passthrough_pair(
        "127.0.0.1",
        block(&[
            ("host", b"api.example.com"),
            ("authorization", auth_header.as_bytes()),
        ]),
    );
    let mat_res = jwt_plugin.authenticate(&mut mat_ctx, &consumer_index).await;
    let pt_res = jwt_plugin.authenticate(&mut pt_ctx, &consumer_index).await;
    assert!(matches!(mat_res, PluginResult::Continue));
    assert!(matches!(pt_res, PluginResult::Continue));
    assert!(pt_ctx.headers.is_empty());
    assert_eq!(
        pt_ctx
            .identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        mat_ctx
            .identified_consumer
            .as_ref()
            .map(|c| c.username.as_str())
    );
    assert_eq!(
        pt_ctx.authenticated_identity,
        mat_ctx.authenticated_identity
    );

    let (mut mat_bad, mut pt_bad) = make_passthrough_pair(
        "127.0.0.1",
        block(&[
            ("host", b"api.example.com"),
            ("authorization", b"Bearer invalid.token.here"),
        ]),
    );
    let mat_bad_res = jwt_plugin.authenticate(&mut mat_bad, &consumer_index).await;
    let pt_bad_res = jwt_plugin.authenticate(&mut pt_bad, &consumer_index).await;
    assert!(matches!(
        mat_bad_res,
        PluginResult::Reject {
            status_code: 401,
            ..
        }
    ));
    assert!(matches!(
        pt_bad_res,
        PluginResult::Reject {
            status_code: 401,
            ..
        }
    ));
    assert!(pt_bad.headers.is_empty());

    // 2. basic_auth: valid & invalid Basic credentials behave identically on both lanes.
    let basic_plugin = basic_auth_with_secret_for_test(
        &json!({ "hide_credentials": false }),
        "test-hmac-secret-for-basic-auth-unit-tests",
    )
    .expect("basic_auth builds");
    assert!(basic_plugin.supports_request_header_passthrough());
    let basic_hidden = basic_auth_with_secret_for_test(
        &json!({ "hide_credentials": true }),
        "test-hmac-secret-for-basic-auth-unit-tests",
    )
    .expect("basic_auth hide_credentials builds");
    assert!(!basic_hidden.supports_request_header_passthrough());

    let encoded_basic = base64::engine::general_purpose::STANDARD.encode(b"testuser:password");
    let basic_val = format!("Basic {encoded_basic}");
    let (mut mat_ctx, mut pt_ctx) = make_passthrough_pair(
        "127.0.0.1",
        block(&[
            ("host", b"api.example.com"),
            ("authorization", basic_val.as_bytes()),
        ]),
    );
    let mat_res = basic_plugin
        .authenticate(&mut mat_ctx, &consumer_index)
        .await;
    let pt_res = basic_plugin
        .authenticate(&mut pt_ctx, &consumer_index)
        .await;
    assert!(matches!(mat_res, PluginResult::Continue));
    assert!(matches!(pt_res, PluginResult::Continue));
    assert!(pt_ctx.headers.is_empty());
    assert_eq!(
        pt_ctx
            .identified_consumer
            .as_ref()
            .map(|c| c.username.as_str()),
        mat_ctx
            .identified_consumer
            .as_ref()
            .map(|c| c.username.as_str())
    );

    // 3. bot_detection: blocked and allowed User-Agent match on both lanes.
    let bot_plugin = create_plugin("bot_detection", &json!({ "blocked_patterns": ["BadBot"] }))
        .expect("bot_detection builds")
        .expect("bot_detection registered");
    assert!(bot_plugin.supports_request_header_passthrough());

    let (mut mat_bot, mut pt_bot) = make_passthrough_pair(
        "127.0.0.1",
        block(&[("host", b"api.example.com"), ("user-agent", b"BadBot/1.0")]),
    );
    assert!(matches!(
        bot_plugin.on_request_received(&mut mat_bot).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert!(matches!(
        bot_plugin.on_request_received(&mut pt_bot).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert!(pt_bot.headers.is_empty());

    let (mut mat_ok, mut pt_ok) = make_passthrough_pair(
        "127.0.0.1",
        block(&[("host", b"api.example.com"), ("user-agent", b"Mozilla/5.0")]),
    );
    assert!(matches!(
        bot_plugin.on_request_received(&mut mat_ok).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        bot_plugin.on_request_received(&mut pt_ok).await,
        PluginResult::Continue
    ));
    assert!(pt_ok.headers.is_empty());

    // 4. geo_restriction with inject_headers=true: keeps ctx.headers empty on
    //    passthrough while setting the private backend_geo_country assertion.
    let mmdb_b64 = include_str!("../../fixtures/maxmind/GeoIP2-Country-Test.mmdb.b64");
    let mmdb_encoded: String = mmdb_b64.lines().collect();
    let mmdb_bytes = base64::engine::general_purpose::STANDARD
        .decode(mmdb_encoded)
        .expect("MaxMind fixture decodes");
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let mmdb_path = temp_dir.path().join("country.mmdb");
    std::fs::write(&mmdb_path, &mmdb_bytes).expect("write fixture");
    let geo_plugin = create_plugin(
        "geo_restriction",
        &json!({
            "db_path": mmdb_path.to_str().expect("utf8 path"),
            "allow_countries": ["SE"],
            "inject_headers": true,
            "on_lookup_failure": "deny"
        }),
    )
    .expect("geo_restriction builds")
    .expect("geo_restriction registered");
    assert!(geo_plugin.supports_request_header_passthrough());

    let (mut mat_geo, mut pt_geo) =
        make_passthrough_pair("89.160.20.112", block(&[("host", b"api.example.com")]));
    assert!(matches!(
        geo_plugin.on_request_received(&mut mat_geo).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        geo_plugin.on_request_received(&mut pt_geo).await,
        PluginResult::Continue
    ));
    assert!(
        pt_geo.headers.is_empty(),
        "geo_restriction must never mutate ctx.headers while passthrough is active"
    );
    assert_eq!(pt_geo.backend_geo_country(), Some("SE"));
    assert_eq!(mat_geo.backend_geo_country(), Some("SE"));
    assert_eq!(pt_geo.metadata, mat_geo.metadata);
    end_request_header_passthrough_for_test(&mut pt_geo);
    assert_eq!(pt_geo.headers.get("host"), mat_geo.headers.get("host"));

    // 5. access_control: allowed vs denied consumer matches on both lanes.
    let acl_plugin = create_plugin(
        "access_control",
        &json!({ "allowed_consumers": ["testuser"] }),
    )
    .expect("access_control builds")
    .expect("access_control registered");
    assert!(acl_plugin.supports_request_header_passthrough());

    let (mut mat_acl, mut pt_acl) =
        make_passthrough_pair("127.0.0.1", block(&[("host", b"api.example.com")]));
    mat_acl.identified_consumer = Some(Arc::new(consumer.clone()));
    pt_acl.identified_consumer = Some(Arc::new(consumer));
    assert!(matches!(
        acl_plugin.authorize(&mut mat_acl).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        acl_plugin.authorize(&mut pt_acl).await,
        PluginResult::Continue
    ));
    assert!(pt_acl.headers.is_empty());

    let (mut mat_acl_deny, mut pt_acl_deny) =
        make_passthrough_pair("127.0.0.1", block(&[("host", b"api.example.com")]));
    assert!(matches!(
        acl_plugin.authorize(&mut mat_acl_deny).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert!(matches!(
        acl_plugin.authorize(&mut pt_acl_deny).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert!(pt_acl_deny.headers.is_empty());

    // 6. adaptive_concurrency: backend admission matches on both lanes.
    let ac_plugin = create_plugin("adaptive_concurrency", &json!({}))
        .expect("adaptive_concurrency builds")
        .expect("adaptive_concurrency registered");
    assert!(ac_plugin.supports_request_header_passthrough());

    let proxy = make_proxy("pt-chain", "/api", vec!["jwt-1", "bot-1", "acl-1", "ac-1"]);
    let admission_ctx = BackendAdmissionContext {
        proxy: &proxy,
        upstream_target: None,
        protocol: ProxyProtocol::Http,
    };
    let (mut mat_ac, mut pt_ac) =
        make_passthrough_pair("127.0.0.1", block(&[("host", b"api.example.com")]));
    assert!(matches!(
        ac_plugin
            .on_backend_admission(&mut mat_ac, &admission_ctx)
            .await,
        BackendAdmissionDecision::Admit(_)
    ));
    assert!(matches!(
        ac_plugin
            .on_backend_admission(&mut pt_ac, &admission_ctx)
            .await,
        BackendAdmissionDecision::Admit(_)
    ));
    assert!(pt_ac.headers.is_empty());

    // 7. PluginCache advertises SUPPORTS_REQUEST_HEADER_PASSTHROUGH for a
    //    composed chain of newly eligible built-ins, and disables it on trigger.
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        plugin_configs: vec![
            make_plugin_config_with_json(
                "jwt-1",
                "jwt_auth",
                json!({ "hide_credentials": false }),
                PluginScope::Proxy,
                Some("pt-chain"),
            ),
            make_plugin_config_with_json(
                "bot-1",
                "bot_detection",
                json!({ "blocked_patterns": ["BadBot"] }),
                PluginScope::Proxy,
                Some("pt-chain"),
            ),
            make_plugin_config_with_json(
                "acl-1",
                "access_control",
                json!({ "allowed_consumers": ["testuser"] }),
                PluginScope::Proxy,
                Some("pt-chain"),
            ),
            make_plugin_config_with_json(
                "ac-1",
                "adaptive_concurrency",
                json!({}),
                PluginScope::Proxy,
                Some("pt-chain"),
            ),
        ],
        ..Default::default()
    };
    let cache = PluginCache::new(&cfg).expect("plugin cache builds");
    let view = cache.request_view("ferrum", "pt-chain", ProxyProtocol::Http);
    assert!(
        view.capabilities()
            .has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "composed audited built-in chain must advertise SUPPORTS_REQUEST_HEADER_PASSTHROUGH"
    );

    cfg.plugin_configs[1].trigger = Some(
        serde_json::from_value(json!({
            "when": { "match": { "method": ["POST"] } }
        }))
        .expect("valid trigger"),
    );
    let triggered_cache = PluginCache::new(&cfg).expect("triggered cache builds");
    let triggered_view = triggered_cache.request_view("ferrum", "pt-chain", ProxyProtocol::Http);
    assert!(
        !triggered_view
            .capabilities()
            .has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "a trigger on any passthrough-eligible built-in must disable request-header passthrough"
    );
}
