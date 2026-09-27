//! `Sec-WebSocket-Extensions` filtering for `websocket_permessage_deflate:
//! passthrough` proxies (issue #5769): only RFC 7692 `permessage-deflate`
//! elements survive, byte-for-byte, and malformed values fail closed.

use std::collections::HashMap;

use ferrum_edge::_test_support::{
    collect_forwardable_websocket_headers_for_test, forward_permessage_deflate_offer_for_test,
    permessage_deflate_answer_for_test, push_permessage_deflate_offer_for_test,
};
use ferrum_edge::config::types::WebSocketPermessageDeflate;
use ferrum_edge::proxy::retain_permessage_deflate_extensions;
use hyper::HeaderMap;
use hyper::header::{HeaderValue, SEC_WEBSOCKET_EXTENSIONS};

fn extensions_header(values: &[(String, String)]) -> Vec<&str> {
    values
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"))
        .map(|(_, value)| value.as_str())
        .collect()
}

#[test]
fn keeps_only_permessage_deflate_elements_verbatim() {
    let offer = "permessage-deflate; client_max_window_bits, x-webkit-deflate-frame";
    assert_eq!(
        retain_permessage_deflate_extensions(offer).as_deref(),
        Some("permessage-deflate; client_max_window_bits")
    );

    let two_offers = "permessage-deflate; server_no_context_takeover; \
                      client_max_window_bits=10, permessage-deflate";
    assert_eq!(
        retain_permessage_deflate_extensions(two_offers).as_deref(),
        Some(two_offers)
    );

    let mixed_case = " Permessage-Deflate ;server_max_window_bits=12 ";
    assert_eq!(
        retain_permessage_deflate_extensions(mixed_case).as_deref(),
        Some("Permessage-Deflate ;server_max_window_bits=12")
    );
}

#[test]
fn drops_every_other_extension_token() {
    for value in [
        "x-webkit-deflate-frame",
        "permessage-bzip2; level=9",
        "foo, bar; baz=1",
        "permessage-deflate-v2",
        "",
        " , ,",
    ] {
        assert_eq!(
            retain_permessage_deflate_extensions(value),
            None,
            "{value:?} must not survive"
        );
    }
}

#[test]
fn quoted_commas_do_not_split_elements() {
    let value = "foo; note=\"a, permessage-deflate\", permessage-deflate";
    assert_eq!(
        retain_permessage_deflate_extensions(value).as_deref(),
        Some("permessage-deflate")
    );

    let escaped = "foo; note=\"x\\\", y\", permessage-deflate; client_max_window_bits";
    assert_eq!(
        retain_permessage_deflate_extensions(escaped).as_deref(),
        Some("permessage-deflate; client_max_window_bits")
    );
}

#[test]
fn unterminated_quoted_string_fails_closed() {
    let value = "permessage-deflate, foo; note=\"unterminated";
    assert_eq!(retain_permessage_deflate_extensions(value), None);
}

#[test]
fn offer_is_stripped_by_default_forwarding() {
    let mut raw = HeaderMap::new();
    raw.insert(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
    );
    raw.insert("x-app", HeaderValue::from_static("kept"));
    let proxy_headers = HashMap::from([
        (
            "sec-websocket-extensions".to_string(),
            "permessage-deflate; client_max_window_bits".to_string(),
        ),
        ("x-app".to_string(), "kept".to_string()),
    ]);
    let forwarded = collect_forwardable_websocket_headers_for_test(&raw, &proxy_headers);
    assert!(
        extensions_header(&forwarded).is_empty(),
        "the default (strip) forwarding must never carry an offer: {forwarded:?}"
    );
}

#[test]
fn passthrough_offer_forwards_only_permessage_deflate() {
    let proxy_headers = HashMap::from([(
        "Sec-WebSocket-Extensions".to_string(),
        "x-webkit-deflate-frame, permessage-deflate; client_max_window_bits".to_string(),
    )]);
    let mut client_headers = vec![("x-app".to_string(), "kept".to_string())];
    assert!(push_permessage_deflate_offer_for_test(
        &mut client_headers,
        &proxy_headers
    ));
    assert_eq!(
        extensions_header(&client_headers),
        vec!["permessage-deflate; client_max_window_bits"]
    );
}

#[test]
fn runtime_gate_forwards_only_for_passthrough_without_framing() {
    let proxy_headers = HashMap::from([(
        "sec-websocket-extensions".to_string(),
        "permessage-deflate; client_max_window_bits".to_string(),
    )]);
    let cases = [
        (WebSocketPermessageDeflate::Strip, false, false),
        (WebSocketPermessageDeflate::Strip, true, false),
        (WebSocketPermessageDeflate::Passthrough, true, false),
        (WebSocketPermessageDeflate::Passthrough, false, true),
    ];
    for (mode, requires_framing, expected) in cases {
        let mut client_headers = vec![("x-app".to_string(), "kept".to_string())];
        let forwarded = forward_permessage_deflate_offer_for_test(
            mode,
            requires_framing,
            &mut client_headers,
            &proxy_headers,
        );
        assert_eq!(
            forwarded, expected,
            "mode {mode:?}, requires_framing {requires_framing}"
        );
        let expected_offer: Vec<&str> = if expected {
            vec!["permessage-deflate; client_max_window_bits"]
        } else {
            Vec::new()
        };
        assert_eq!(extensions_header(&client_headers), expected_offer);
    }
}

#[test]
fn passthrough_offer_requires_a_deflate_element() {
    let cases = [
        HashMap::new(),
        HashMap::from([(
            "sec-websocket-extensions".to_string(),
            "x-webkit-deflate-frame".to_string(),
        )]),
        // Nominated hop-by-hop by the client: never forwarded.
        HashMap::from([
            (
                "sec-websocket-extensions".to_string(),
                "permessage-deflate".to_string(),
            ),
            (
                "connection".to_string(),
                "Upgrade, Sec-WebSocket-Extensions".to_string(),
            ),
        ]),
    ];
    for proxy_headers in cases {
        let mut client_headers = Vec::new();
        assert!(
            !push_permessage_deflate_offer_for_test(&mut client_headers, &proxy_headers),
            "no offer may be forwarded for {proxy_headers:?}"
        );
        assert!(extensions_header(&client_headers).is_empty());
    }
}

#[test]
fn backend_answer_keeps_only_permessage_deflate() {
    let mut headers = HeaderMap::new();
    headers.append(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_static("x-unrequested"),
    );
    headers.append(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_static("permessage-deflate; server_no_context_takeover"),
    );
    let answer = permessage_deflate_answer_for_test(&headers);
    assert_eq!(
        answer.as_ref().and_then(|value| value.to_str().ok()),
        Some("permessage-deflate; server_no_context_takeover")
    );

    let mut other_only = HeaderMap::new();
    other_only.insert(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_static("x-unrequested"),
    );
    assert!(permessage_deflate_answer_for_test(&other_only).is_none());
    assert!(permessage_deflate_answer_for_test(&HeaderMap::new()).is_none());
}
