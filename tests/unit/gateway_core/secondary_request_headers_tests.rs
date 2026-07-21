//! Parity guards for the shared secondary-request header sanitizer used by
//! `request_mirror` and `load_testing`.

use ferrum_edge::proxy::headers::{
    BACKEND_REQUEST_STRIP_HEADER_NAMES, PROXY_GENERATED_FORWARDING_HEADER_NAMES,
    SecondaryRequestHostPolicy, filter_secondary_request_headers, is_backend_request_strip_header,
    is_proxy_generated_forwarding_header, synthesize_grpc_te_trailers_if_needed,
};
use std::collections::{HashMap, HashSet};

#[test]
fn secondary_filter_honors_every_canonical_backend_and_forwarding_name() {
    for &name in BACKEND_REQUEST_STRIP_HEADER_NAMES {
        assert!(
            is_backend_request_strip_header(name),
            "predicate drift for `{name}`"
        );
        let mut headers = HashMap::new();
        headers.insert(name.to_string(), "x".to_string());
        headers.insert("x-keep".to_string(), "ok".to_string());
        let out =
            filter_secondary_request_headers(&headers, SecondaryRequestHostPolicy::Preserve, &[]);
        assert!(
            !out.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)),
            "secondary filter must strip canonical name `{name}`: {out:?}"
        );
        assert!(out.iter().any(|(k, _)| k == "x-keep"));
    }

    for &name in PROXY_GENERATED_FORWARDING_HEADER_NAMES {
        assert!(is_proxy_generated_forwarding_header(name));
        let mut headers = HashMap::new();
        headers.insert(name.to_string(), "spoofed".to_string());
        headers.insert("x-keep".to_string(), "ok".to_string());
        let out =
            filter_secondary_request_headers(&headers, SecondaryRequestHostPolicy::Preserve, &[]);
        assert!(
            !out.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)),
            "secondary filter must strip proxy-owned `{name}`: {out:?}"
        );
    }
}

#[test]
fn secondary_filter_parses_mixed_case_ows_and_malformed_connection_tokens() {
    let mut headers = HashMap::new();
    // Repeated / mixed-case Connection with OWS and a garbage token.
    headers.insert(
        "CONNECTION".to_string(),
        " X-Hop , , bad:token, Keep-Alive ".to_string(),
    );
    headers.insert("x-hop".to_string(), "per-connection".to_string());
    headers.insert("keep-alive".to_string(), "timeout=5".to_string());
    headers.insert("Trailer".to_string(), "X-Foo".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "br".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("authorization".to_string(), "Bearer keep".to_string());
    headers.insert("x-keep".to_string(), "ok".to_string());

    let out = filter_secondary_request_headers(&headers, SecondaryRequestHostPolicy::Strip, &[]);
    let names: HashSet<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    for forbidden in [
        "connection",
        "x-hop",
        "keep-alive",
        "trailer",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
    ] {
        assert!(
            !names.contains(forbidden),
            "leaked `{forbidden}` from hostile H1 map: {out:?}"
        );
    }
    assert!(names.contains("authorization"));
    assert!(names.contains("x-keep"));
}

#[test]
fn secondary_filter_h2_h3_parity_strips_protocol_invalid_and_internal_markers() {
    // H2/H3 reject Connection at the frame layer, but Trailer + Ferrum markers
    // can still appear in the materialised plugin map (plugin synthesis).
    let mut headers = HashMap::new();
    headers.insert("trailer".to_string(), "grpc-status".to_string());
    headers.insert("te".to_string(), "trailers".to_string());
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert("content-length".to_string(), "12".to_string());
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );
    headers.insert("x-grpc-web-mode".to_string(), "1".to_string());
    headers.insert("x-forwarded-proto".to_string(), "https".to_string());
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("x-keep".to_string(), "ok".to_string());

    let mut out =
        filter_secondary_request_headers(&headers, SecondaryRequestHostPolicy::Strip, &[]);
    synthesize_grpc_te_trailers_if_needed(&mut out);

    let names: HashSet<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    for forbidden in [
        "trailer",
        "transfer-encoding",
        "content-length",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
        "x-forwarded-proto",
    ] {
        assert!(
            !names.contains(forbidden),
            "H2/H3 parity leaked `{forbidden}`: {out:?}"
        );
    }
    assert_eq!(
        out.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("te"))
            .map(|(_, v)| v.as_str()),
        Some("trailers"),
        "gRPC secondary requests must re-synthesise te: trailers: {out:?}"
    );
    assert!(names.contains("content-type"));
    assert!(names.contains("x-keep"));
}

#[test]
fn secondary_filter_host_policy_and_extra_excludes() {
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), "gateway.example".to_string());
    headers.insert("x-loadtesting-key".to_string(), "secret".to_string());
    headers.insert("x-custom".to_string(), "keep".to_string());

    let stripped =
        filter_secondary_request_headers(&headers, SecondaryRequestHostPolicy::Strip, &[]);
    assert!(!stripped.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")));

    let preserved = filter_secondary_request_headers(
        &headers,
        SecondaryRequestHostPolicy::Preserve,
        &["x-loadtesting-key"],
    );
    assert!(
        preserved
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("host") && v == "gateway.example")
    );
    assert!(!preserved
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-loadtesting-key")));
    assert!(preserved.iter().any(|(k, _)| k == "x-custom"));
}
