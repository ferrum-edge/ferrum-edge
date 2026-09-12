//! Wide-charset body-decoding parity between the request and response scan
//! paths (issue #4792, GHSA-98fm-3pg9-3wjv / GHSA-3vw6-p639-cr6g).
//!
//! A UTF-16 / UTF-32 body is transcoded into UTF-8 inspection views before the
//! rule sets run, because a backend that honours the declared charset reads the
//! payload the raw-byte scan never sees. That decode was added to the request
//! path and, for a while, not to the response path — the #4792 shape.
//!
//! This is the sibling table for that invariant: one enforcing rule per
//! direction, one wide-charset encoding per row, and the assertion that the SAME
//! body is caught on BOTH paths. A direction that stops decoding wide charsets
//! fails every row.
//!
//! The cross-cutting parity file for the other shared invariants is
//! `tests/unit/gateway_core/shared_invariant_parity_tests.rs`.

use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

/// Payload both direction rules match. Deliberately not a default-rule
/// signature: this test is about the decode, not about rule content.
const MARKER: &str = "ferrum-parity-marker";
const BENIGN: &str = "ordinary body with no marker";

const REQUEST_RULE_ID: &str = "CUSTOM-PARITY-REQUEST-BODY";
const RESPONSE_RULE_ID: &str = "CUSTOM-PARITY-RESPONSE-BODY";

/// One enforcing rule per direction over the same pattern, so a row that fails
/// can only be a decode difference between the two paths.
fn parity_waf() -> Waf {
    Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [
            {
                "id": REQUEST_RULE_ID,
                "name": "request body parity marker",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": MARKER,
                "action": "enforce"
            },
            {
                "id": RESPONSE_RULE_ID,
                "name": "response body parity marker",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "contains",
                "pattern": MARKER,
                "action": "enforce"
            }
        ]
    }))
    .expect("parity WAF config must compile")
}

fn encode_utf16(text: &str, big_endian: bool) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(text.len().saturating_mul(2));
    for unit in text.encode_utf16() {
        let bytes = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        encoded.extend_from_slice(&bytes);
    }
    encoded
}

fn encode_utf32(text: &str, big_endian: bool) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(text.len().saturating_mul(4));
    for ch in text.chars() {
        let bytes = if big_endian {
            (ch as u32).to_be_bytes()
        } else {
            (ch as u32).to_le_bytes()
        };
        encoded.extend_from_slice(&bytes);
    }
    encoded
}

/// The wide-charset encodings both scan paths must decode before inspecting.
/// `encode` is applied to whichever payload the assertion needs.
struct WideCharset {
    label: &'static str,
    content_type: &'static str,
    encode: fn(&str) -> Vec<u8>,
}

fn utf16le(text: &str) -> Vec<u8> {
    encode_utf16(text, false)
}

fn utf16be(text: &str) -> Vec<u8> {
    encode_utf16(text, true)
}

fn utf32le(text: &str) -> Vec<u8> {
    encode_utf32(text, false)
}

fn utf32be(text: &str) -> Vec<u8> {
    encode_utf32(text, true)
}

const WIDE_CHARSETS: &[WideCharset] = &[
    WideCharset {
        label: "UTF-16LE (declared charset)",
        content_type: "text/plain; charset=utf-16le",
        encode: utf16le,
    },
    WideCharset {
        label: "UTF-16BE (declared charset)",
        content_type: "text/plain; charset=utf-16be",
        encode: utf16be,
    },
    WideCharset {
        label: "UTF-32LE (declared charset)",
        content_type: "text/plain; charset=utf-32le",
        encode: utf32le,
    },
    WideCharset {
        label: "UTF-32BE (declared charset)",
        content_type: "text/plain; charset=utf-32be",
        encode: utf32be,
    },
];

async fn scan_request_body(
    plugin: &Waf,
    content_type: &str,
    body: &[u8],
) -> (PluginResult, RequestContext) {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/parity".into());
    let headers = HashMap::from([("content-type".to_string(), content_type.to_string())]);
    ctx.headers = headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body)
        .await;
    (result, ctx)
}

async fn scan_response_body(
    plugin: &Waf,
    content_type: &str,
    body: &[u8],
) -> (PluginResult, RequestContext) {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "GET".into(), "/parity".into());
    let headers = HashMap::from([("content-type".to_string(), content_type.to_string())]);
    let result = plugin
        .finalize_client_visible_response_body(&mut ctx, 200, &headers, body)
        .await;
    (result, ctx)
}

fn hit(ctx: &RequestContext, rule_id: &str) -> bool {
    ctx.metadata
        .get("waf.rule_hits")
        .is_some_and(|hits| hits.contains(rule_id))
}

#[tokio::test]
async fn wide_charset_bodies_are_decoded_on_both_the_request_and_response_paths() {
    let plugin = parity_waf();

    // The UTF-8 control: both directions must already agree here, so a wide
    // charset failing below is a decode gap and not a rule-wiring difference.
    let (request_utf8, request_utf8_ctx) =
        scan_request_body(&plugin, "text/plain", MARKER.as_bytes()).await;
    assert!(matches!(request_utf8, PluginResult::Reject { .. }));
    assert!(hit(&request_utf8_ctx, REQUEST_RULE_ID));
    let (response_utf8, response_utf8_ctx) =
        scan_response_body(&plugin, "text/plain", MARKER.as_bytes()).await;
    assert!(matches!(response_utf8, PluginResult::Reject { .. }));
    assert!(hit(&response_utf8_ctx, RESPONSE_RULE_ID));

    for charset in WIDE_CHARSETS {
        let body = (charset.encode)(MARKER);

        let (request_result, request_ctx) =
            scan_request_body(&plugin, charset.content_type, &body).await;
        assert!(
            matches!(request_result, PluginResult::Reject { .. }),
            "{}: the request path must decode the declared charset before scanning",
            charset.label
        );
        assert!(
            hit(&request_ctx, REQUEST_RULE_ID),
            "{}: request scan must attribute the hit to the request body rule",
            charset.label
        );

        let (response_result, response_ctx) =
            scan_response_body(&plugin, charset.content_type, &body).await;
        assert!(
            matches!(response_result, PluginResult::Reject { .. }),
            "{}: the response path must decode the same declared charset — a decode added to one \
             direction only is the #4792 shape",
            charset.label
        );
        assert!(
            hit(&response_ctx, RESPONSE_RULE_ID),
            "{}: response scan must attribute the hit to the response body rule",
            charset.label
        );
    }
}

#[tokio::test]
async fn wide_charset_decoding_does_not_manufacture_hits_on_either_path() {
    // The other half of parity: neither direction may turn a benign wide-charset
    // body into a block. A row that only ever rejects proves nothing about the
    // decode.
    let plugin = parity_waf();

    for charset in WIDE_CHARSETS {
        let body = (charset.encode)(BENIGN);

        let (request_result, request_ctx) =
            scan_request_body(&plugin, charset.content_type, &body).await;
        assert!(
            matches!(request_result, PluginResult::Continue),
            "{}: a benign request body must not be blocked",
            charset.label
        );
        assert!(
            !hit(&request_ctx, REQUEST_RULE_ID),
            "{}: a benign request body must not record a rule hit",
            charset.label
        );

        let (response_result, response_ctx) =
            scan_response_body(&plugin, charset.content_type, &body).await;
        assert!(
            matches!(response_result, PluginResult::Continue),
            "{}: a benign response body must not be blocked",
            charset.label
        );
        assert!(
            !hit(&response_ctx, RESPONSE_RULE_ID),
            "{}: a benign response body must not record a rule hit",
            charset.label
        );
    }
}

#[tokio::test]
async fn the_shared_body_scan_engine_serves_both_directions() {
    // Structural half of the invariant: both directions enter the same
    // `scan_body_rules`, and the wide-charset decode sits above the direction
    // switch rather than inside one branch. A future direction-specific copy of
    // the decode is exactly what this asserts against.
    let scan = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/plugins/waf/scan.rs"),
    )
    .expect("src/plugins/waf/scan.rs must be readable");
    let decode_sites = scan
        .matches("normalize::decode_wide_charset_body_views(")
        .count();
    assert_eq!(
        decode_sites, 1,
        "the wide-charset decode must have exactly one call site, shared by both directions"
    );
    for entry in [
        "self.scan_body_rules(subject, body, content_type, BodyDirection::Request)",
        "self.scan_body_rules(subject, body, content_type, BodyDirection::Response)",
    ] {
        assert!(
            scan.contains(entry),
            "both directions must enter the shared body scan: missing `{entry}`"
        );
    }
}
