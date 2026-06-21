use ferrum_edge::proxy::{
    build_forwarded_value, check_host_authority_consistency, check_protocol_headers,
    is_h2_websocket_connect, is_hbone_connect_request, is_valid_websocket_key,
    normalize_request_host_for_routing, websocket_origin_allowed, ws_accept_from_key,
};
use hyper::header::HeaderValue;

// ============================================================================
// check_protocol_headers tests
// ============================================================================

// --- Content-Length + Transfer-Encoding conflict (HTTP/1.1 smuggling) ---

#[test]
fn http11_rejects_cl_and_te_together() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(
        result
            .unwrap()
            .contains("Content-Length and Transfer-Encoding")
    );
}

#[test]
fn http10_rejects_te_alone() {
    // HTTP/1.0 does not support Transfer-Encoding (RFC 9112 §6.2)
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_10);
    assert!(result.is_some());
    assert!(result.unwrap().contains("HTTP/1.0 does not support"));
}

#[test]
fn http10_rejects_cl_and_te_together() {
    // HTTP/1.0 + TE is rejected (TE check triggers before CL+TE check)
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_10);
    assert!(result.is_some());
    // The HTTP/1.0 TE rejection fires first
    assert!(result.unwrap().contains("HTTP/1.0 does not support"));
}

#[test]
fn http10_allows_cl_only() {
    // HTTP/1.0 with only Content-Length is fine
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_10).is_none());
}

#[test]
fn http2_rejects_transfer_encoding_even_without_cl() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("Transfer-Encoding"));
}

#[test]
fn http2_rejects_cl_and_transfer_encoding_together() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("Transfer-Encoding"));
}

#[test]
fn http3_rejects_transfer_encoding() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("Transfer-Encoding"));
}

#[test]
fn http11_allows_cl_only() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn http11_allows_te_only() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

// --- Multiple Content-Length with mismatched values ---

#[test]
fn rejects_conflicting_content_length_values() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("42"));
    headers.append("content-length", HeaderValue::from_static("99"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

#[test]
fn allows_duplicate_content_length_same_value() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("42"));
    headers.append("content-length", HeaderValue::from_static("42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn conflicting_content_length_checked_on_http2() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("10"));
    headers.append("content-length", HeaderValue::from_static("20"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

#[test]
fn conflicting_content_length_checked_on_http3() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("100"));
    headers.append("content-length", HeaderValue::from_static("200"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

// --- Comma-separated Content-Length (coalesced by intermediary) ---

#[test]
fn rejects_comma_separated_conflicting_content_length() {
    // An intermediary may coalesce "Content-Length: 42" + "Content-Length: 0"
    // into a single "Content-Length: 42, 0" field line.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42, 0"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

#[test]
fn allows_comma_separated_identical_content_length() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42, 42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn rejects_mixed_header_and_comma_content_length() {
    // One header entry with "100", another with "100, 200"
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("100"));
    headers.append("content-length", HeaderValue::from_static("100, 200"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

#[test]
fn allows_comma_separated_with_ows() {
    // Whitespace around comma-separated values should be trimmed
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42 , 42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn rejects_empty_content_length_token_trailing_comma() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42,"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid empty value"));
}

#[test]
fn rejects_empty_content_length_token_leading_comma_on_http2() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static(",42"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid empty value"));
}

#[test]
fn rejects_empty_content_length_token_middle_comma_on_http3() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42,,42"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid empty value"));
}

// --- Multiple Host headers (HTTP/1.1) ---

#[test]
fn http11_rejects_multiple_host_headers() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("host", HeaderValue::from_static("evil.com"));
    headers.append("host", HeaderValue::from_static("real.com"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("multiple Host"));
}

#[test]
fn http11_allows_single_host() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn http2_allows_multiple_host_headers() {
    // The framing-only validator does not inspect :authority. The separate
    // authority-consistency gate rejects this before routing.
    let mut headers = hyper::HeaderMap::new();
    headers.append("host", HeaderValue::from_static("a.com"));
    headers.append("host", HeaderValue::from_static("b.com"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

// --- TE header validation (HTTP/2) ---

#[test]
fn http2_allows_te_trailers() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("trailers"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_allows_te_trailers_case_insensitive() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("Trailers"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_rejects_te_chunked() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("TE header"));
}

#[test]
fn http2_rejects_te_gzip() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("gzip"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("TE header"));
}

#[test]
fn http2_rejects_empty_te_token_trailing_comma() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("trailers,"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid empty value"));
}

#[test]
fn http3_rejects_empty_te_token_leading_comma() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static(",trailers"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid empty value"));
}

#[test]
fn http2_allows_no_te() {
    let headers = hyper::HeaderMap::new();
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_rejects_te_trailers_plus_invalid_in_same_field() {
    // "te: trailers, gzip" has a valid token + invalid token — must reject
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("trailers, gzip"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("TE header"));
}

#[test]
fn http2_rejects_second_te_header_entry_with_invalid_value() {
    // First entry is valid, second is not — must catch via get_all iteration
    let mut headers = hyper::HeaderMap::new();
    headers.append("te", HeaderValue::from_static("trailers"));
    headers.append("te", HeaderValue::from_static("gzip"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("TE header"));
}

#[test]
fn http11_allows_any_te_value() {
    // TE header restrictions only apply to HTTP/2
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("gzip, chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

// --- Clean requests pass validation ---

#[test]
fn clean_http11_request_passes() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    headers.insert("content-length", HeaderValue::from_static("100"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn clean_http2_request_passes() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("100"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

// --- Host / :authority consistency (HTTP/2 and HTTP/3) ---

#[test]
fn http2_rejects_host_authority_mismatch() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("evil.example"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    let result = check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("authority disagree"));
}

#[test]
fn http3_rejects_host_authority_mismatch() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("evil.example"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    let result = check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("authority disagree"));
}

#[test]
fn http2_accepts_matching_host_authority_after_case_and_dot_normalization() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("API.EXAMPLE.:8443"));
    let uri: hyper::Uri = "https://api.example:8443/".parse().unwrap();
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_accepts_https_default_port_host_authority_equivalence() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("api.example:443"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http3_accepts_https_default_port_host_authority_equivalence() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("api.example"));
    let uri: hyper::Uri = "https://api.example:443/".parse().unwrap();
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_3).is_none());
}

#[test]
fn http2_accepts_http_default_port_host_authority_equivalence() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("api.example:80"));
    let uri: hyper::Uri = "http://api.example/".parse().unwrap();
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_rejects_non_default_port_host_authority_mismatch() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("api.example:8443"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    let result = check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("authority disagree"));
}

#[test]
fn http2_rejects_multiple_host_headers_before_routing() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("host", HeaderValue::from_static("api.example"));
    headers.append("host", HeaderValue::from_static("evil.example"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    let result = check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("multiple Host"));
}

#[test]
fn http2_rejects_invalid_host_authority_port() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("api.example:notaport"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    let result = check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid authority"));
}

#[test]
fn http2_rejects_unbracketed_ipv6_host_authority() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("2001:db8::1"));
    let uri: hyper::Uri = "https://[2001:db8::1]/".parse().unwrap();
    let result = check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid authority"));
}

#[test]
fn http2_no_host_no_authority_passes_consistency_check() {
    let headers = hyper::HeaderMap::new();
    let uri: hyper::Uri = "/path".parse().unwrap();
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_2).is_none());
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_3).is_none());
}

#[test]
fn http11_ignores_authority_consistency_helper() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("evil.example"));
    let uri: hyper::Uri = "https://api.example/".parse().unwrap();
    assert!(check_host_authority_consistency(&headers, &uri, hyper::Version::HTTP_11).is_none());
}

#[test]
fn empty_headers_pass() {
    let headers = hyper::HeaderMap::new();
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_3).is_none());
}

// --- Content-Length non-numeric value validation (RFC 9110 §8.6) ---

#[test]
fn rejects_content_length_negative() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("-1"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn rejects_content_length_alphabetic() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("abc"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn rejects_content_length_decimal() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("1.5"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn rejects_content_length_hex_prefix() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("0x10"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn rejects_content_length_plus_sign() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("+42"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn allows_content_length_zero() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("0"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn allows_content_length_large_valid() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("999999999999"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn rejects_content_length_overflowing_usize() {
    let mut headers = hyper::HeaderMap::new();
    let overflowing = format!("{}0", usize::MAX);
    headers.insert(
        "content-length",
        HeaderValue::from_str(&overflowing).unwrap(),
    );
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("exceeds supported integer range"));
}

#[test]
fn allows_content_length_with_ows_valid_digits() {
    // OWS is trimmed before digit validation
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static(" 42 "));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn rejects_content_length_non_numeric_on_http2() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("abc"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn rejects_content_length_non_numeric_on_http3() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("-5"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

#[test]
fn rejects_comma_separated_content_length_with_non_numeric() {
    // "42, abc" — the second token is not all-digits
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42, abc"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("invalid non-numeric"));
}

// ============================================================================
// websocket_origin_allowed tests
// ============================================================================

#[test]
fn websocket_origin_allows_default_port_variants() {
    let allowed = vec!["https://good.example".to_string()];

    assert!(websocket_origin_allowed(&allowed, "https://good.example"));
    assert!(websocket_origin_allowed(
        &allowed,
        "https://good.example:443"
    ));
    assert!(websocket_origin_allowed(
        &["http://good.example:80".to_string()],
        "http://good.example"
    ));
}

#[test]
fn websocket_origin_preserves_non_default_ports() {
    let allowed = vec!["https://good.example:8443".to_string()];

    assert!(websocket_origin_allowed(
        &allowed,
        "https://GOOD.example:8443"
    ));
    assert!(!websocket_origin_allowed(&allowed, "https://good.example"));
    assert!(!websocket_origin_allowed(
        &["https://good.example".to_string()],
        "https://good.example:8443"
    ));
}

#[test]
fn websocket_origin_falls_back_to_exact_match_for_unparseable_values() {
    let allowed = vec!["null".to_string()];

    assert!(websocket_origin_allowed(&allowed, "NULL"));
    assert!(!websocket_origin_allowed(&allowed, "https://null"));
}

#[test]
fn websocket_origin_does_not_normalize_path_query_or_fragment() {
    let allowed = vec!["https://good.example".to_string()];

    assert!(!websocket_origin_allowed(
        &allowed,
        "https://good.example/path"
    ));
    assert!(!websocket_origin_allowed(
        &allowed,
        "https://good.example?x=1"
    ));
    assert!(!websocket_origin_allowed(
        &allowed,
        "https://good.example#frag"
    ));
}

#[test]
fn websocket_origin_rejects_userinfo_smuggling() {
    let allowed = vec!["https://good.example".to_string()];

    // An Origin carrying userinfo must not be normalized down to the
    // allow-listed host and waved through admission. RFC 6454 serialized
    // origins never contain credentials, so these fail closed.
    assert!(!websocket_origin_allowed(
        &allowed,
        "https://attacker@good.example"
    ));
    assert!(!websocket_origin_allowed(
        &allowed,
        "https://attacker:secret@good.example"
    ));
    assert!(!websocket_origin_allowed(
        &allowed,
        "https://attacker@good.example:443"
    ));
    // A userinfo-bearing entry on the allow-list side must not match a
    // bare origin either.
    assert!(!websocket_origin_allowed(
        &["https://user@good.example".to_string()],
        "https://good.example"
    ));
}

// ============================================================================
// is_valid_websocket_key tests
// ============================================================================

#[test]
fn valid_websocket_key_16_bytes_base64() {
    // 16 random bytes base64-encoded = 24 characters
    assert!(is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ=="));
}

#[test]
fn valid_websocket_key_all_zeros() {
    // 16 zero bytes = "AAAAAAAAAAAAAAAAAAAAAA=="
    assert!(is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAA=="));
}

#[test]
fn invalid_websocket_key_too_short() {
    // Only 4 bytes worth of base64
    assert!(!is_valid_websocket_key("AAAA"));
}

#[test]
fn invalid_websocket_key_too_long() {
    // 32 bytes base64-encoded
    assert!(!is_valid_websocket_key(
        "dGhlIHNhbXBsZSBub25jZSB0aGUgc2FtcGxlIG5vbmNl"
    ));
}

#[test]
fn invalid_websocket_key_not_base64() {
    assert!(!is_valid_websocket_key("not-valid-base64!!!!"));
}

#[test]
fn invalid_websocket_key_empty() {
    assert!(!is_valid_websocket_key(""));
}

#[test]
fn invalid_websocket_key_15_bytes() {
    // 15 bytes base64 = "AAAAAAAAAAAAAAAAAAAA" (20 chars)
    assert!(!is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAA"));
}

#[test]
fn invalid_websocket_key_17_bytes() {
    // 17 bytes base64 = "AAAAAAAAAAAAAAAAAAAAAA==" wait that's 16.
    // Let me compute: 17 bytes = ceil(17*4/3) = 24 chars with padding
    // Actually base64 of 17 bytes = 24 chars. Let me use a real 17-byte value.
    // b"\x00" * 17 = "AAAAAAAAAAAAAAAAAAAAAAA=" (23 chars + padding)
    assert!(!is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAAA="));
}

#[test]
fn valid_websocket_key_with_trailing_whitespace_is_accepted() {
    // RFC 9110 §5.5 requires header parsers to strip OWS, but cross-hop
    // normalization is not guaranteed. The validator must trim defensively
    // so a legitimate whitespace-padded key is still accepted.
    assert!(is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ==  "));
    assert!(is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ==\t"));
}

#[test]
fn valid_websocket_key_with_leading_whitespace_is_accepted() {
    assert!(is_valid_websocket_key("  dGhlIHNhbXBsZSBub25jZQ=="));
}

#[test]
fn valid_websocket_key_with_surrounding_whitespace_is_accepted() {
    assert!(is_valid_websocket_key(" dGhlIHNhbXBsZSBub25jZQ== "));
}

// ============================================================================
// ws_accept_from_key tests (RFC 6455 §4.2.2)
// ============================================================================

/// RFC 6455 §4.2.2 example: SHA-1(key + GUID) base64-encoded.
/// `derive_accept_key(b"dGhlIHNhbXBsZSBub25jZQ==")` == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
const RFC6455_EXAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const RFC6455_EXAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

#[test]
fn ws_accept_from_key_rfc6455_example() {
    // Sanity-check the helper against the RFC 6455 §1.3 reference vector.
    assert_eq!(
        ws_accept_from_key(RFC6455_EXAMPLE_KEY),
        RFC6455_EXAMPLE_ACCEPT
    );
}

#[test]
fn ws_accept_from_key_trims_trailing_whitespace() {
    // RFC 6455 §4.2.2: Accept value is computed over the EXACT base64 key.
    // A non-trimmed input would silently emit an Accept hash the client rejects.
    // Trailing whitespace must produce the same Accept value as the untrimmed key.
    let key_with_ws = format!("{RFC6455_EXAMPLE_KEY}  ");
    assert_eq!(
        ws_accept_from_key(&key_with_ws),
        ws_accept_from_key(RFC6455_EXAMPLE_KEY),
    );
    assert_eq!(ws_accept_from_key(&key_with_ws), RFC6455_EXAMPLE_ACCEPT);
}

#[test]
fn ws_accept_from_key_trims_leading_whitespace() {
    let key_with_ws = format!("  {RFC6455_EXAMPLE_KEY}");
    assert_eq!(ws_accept_from_key(&key_with_ws), RFC6455_EXAMPLE_ACCEPT);
}

#[test]
fn ws_accept_from_key_trims_tabs_and_mixed_whitespace() {
    let key_with_ws = format!(" \t{RFC6455_EXAMPLE_KEY}\t ");
    assert_eq!(ws_accept_from_key(&key_with_ws), RFC6455_EXAMPLE_ACCEPT);
}

#[test]
fn ws_accept_from_key_empty_preserves_fallback_semantics() {
    // The accept-key derivation site falls back to "" when the
    // sec-websocket-key header is missing/unreadable (admission already
    // rejects malformed requests, so this branch is only reachable in
    // pathological / mock cases). The helper must keep that semantics.
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
    assert_eq!(ws_accept_from_key(""), derive_accept_key(b""));
}

#[test]
fn ws_accept_from_key_whitespace_only_matches_empty_fallback() {
    // A whitespace-only header should reduce to the empty-key fallback —
    // not produce a SHA-1 over literal whitespace bytes.
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
    assert_eq!(ws_accept_from_key("   "), derive_accept_key(b""));
    assert_eq!(ws_accept_from_key("   "), ws_accept_from_key(""));
}

// ============================================================================
// is_h2_websocket_connect tests (RFC 8441 Extended CONNECT)
// ============================================================================

/// Helper to build a test request with the given method, version, and optional Protocol extension.
fn build_test_request(
    method: &str,
    version: hyper::Version,
    protocol: Option<&'static str>,
) -> hyper::Request<()> {
    let mut req = hyper::Request::builder()
        .method(method)
        .version(version)
        .uri("https://example.com/ws")
        .body(())
        .unwrap();
    if let Some(proto) = protocol {
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static(proto));
    }
    req
}

#[test]
fn h2_connect_with_websocket_protocol_is_detected() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_2, Some("websocket"));
    assert!(is_h2_websocket_connect(&req));
}

#[test]
fn h2_connect_with_websocket_protocol_case_insensitive() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_2, Some("WebSocket"));
    assert!(is_h2_websocket_connect(&req));
}

#[test]
fn h2_connect_without_protocol_extension_is_not_websocket() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_2, None);
    assert!(!is_h2_websocket_connect(&req));
}

#[test]
fn h2_connect_with_wrong_protocol_is_not_websocket() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_2, Some("mqtt"));
    assert!(!is_h2_websocket_connect(&req));
}

#[test]
fn http11_connect_with_websocket_protocol_is_not_detected() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_11, Some("websocket"));
    assert!(!is_h2_websocket_connect(&req));
}

#[test]
fn h2_get_with_websocket_protocol_is_not_detected() {
    let req = build_test_request("GET", hyper::Version::HTTP_2, Some("websocket"));
    assert!(!is_h2_websocket_connect(&req));
}

#[test]
fn h2_post_with_websocket_protocol_is_not_detected() {
    let req = build_test_request("POST", hyper::Version::HTTP_2, Some("websocket"));
    assert!(!is_h2_websocket_connect(&req));
}

// ============================================================================
// build_forwarded_value tests (RFC 7239)
// ============================================================================

#[test]
fn forwarded_ipv4_with_host() {
    let val = build_forwarded_value("192.0.2.60", "https", Some("example.com"));
    assert_eq!(val, "for=192.0.2.60;proto=https;host=example.com");
}

#[test]
fn forwarded_quotes_host_with_port() {
    let val = build_forwarded_value("192.0.2.60", "https", Some("example.com:8443"));
    assert_eq!(val, "for=192.0.2.60;proto=https;host=\"example.com:8443\"");
}

#[test]
fn forwarded_quotes_host_with_parameter_separator() {
    let val = build_forwarded_value("192.0.2.60", "https", Some("example.com;for=198.51.100.99"));
    assert_eq!(
        val,
        "for=192.0.2.60;proto=https;host=\"example.com;for=198.51.100.99\""
    );
}

#[test]
fn forwarded_escapes_quoted_host_value() {
    let val = build_forwarded_value("192.0.2.60", "https", Some(r#"exa"mple\host"#));
    assert_eq!(val, r#"for=192.0.2.60;proto=https;host="exa\"mple\\host""#);
}

#[test]
fn forwarded_ipv4_without_host() {
    let val = build_forwarded_value("192.0.2.60", "http", None);
    assert_eq!(val, "for=192.0.2.60;proto=http");
}

#[test]
fn forwarded_ipv6_quoted() {
    // IPv6 must be quoted per RFC 7239 §6
    let val = build_forwarded_value("2001:db8::1", "https", Some("example.com"));
    assert_eq!(val, "for=\"[2001:db8::1]\";proto=https;host=example.com");
}

#[test]
fn forwarded_h3_proto() {
    let val = build_forwarded_value("10.0.0.1", "h3", Some("api.example.com"));
    assert_eq!(val, "for=10.0.0.1;proto=h3;host=api.example.com");
}

// ============================================================================
// H4: H2.CL downgrade smuggling verification
// Verify that Content-Length from HTTP/2 requests cannot poison HTTP/1.1 backends.
// The gateway strips CL as a hop-by-hop header; reqwest recalculates from body.
// ============================================================================

#[test]
fn h2_content_length_not_in_protocol_headers_check() {
    // HTTP/2 request with a Content-Length that doesn't match body intent.
    // check_protocol_headers does NOT strip CL (that's the proxy path's job),
    // but it validates CL values are consistent and numeric.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    // A valid single CL value should pass validation on HTTP/2
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn h2_conflicting_content_length_still_rejected() {
    // Even on HTTP/2, conflicting CL values are caught
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("42"));
    headers.append("content-length", HeaderValue::from_static("99"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

// ============================================================================
// H5: TE.TE obfuscation verification
// Verify that obfuscated Transfer-Encoding values are handled safely.
// For HTTP/1.x: TE is stripped as hop-by-hop before forwarding.
// For HTTP/2: TE must be "trailers" only (case-insensitive).
// ============================================================================

#[test]
fn te_obfuscation_capitalized_chunked_http11_passes_validation() {
    // HTTP/1.1 allows any TE value — it's stripped before forwarding
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static("Chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn te_obfuscation_leading_space_http11_passes_validation() {
    // Leading spaces in TE value — HTTP/1.1 allows any TE (stripped before forwarding)
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static(" chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn te_obfuscation_identity_http11_passes_validation() {
    // "identity" is a valid but unusual TE value — HTTP/1.1 allows it (stripped)
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "transfer-encoding",
        HeaderValue::from_static("chunked, identity"),
    );
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn http2_te_trailers_case_variants_all_accepted() {
    // HTTP/2 TE validation is case-insensitive for "trailers"
    for val in &["trailers", "Trailers", "TRAILERS", "tRaIlErS"] {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("te", HeaderValue::from_static(val));
        assert!(
            check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none(),
            "TE value '{}' should be accepted on HTTP/2",
            val
        );
    }
}

#[test]
fn http2_te_obfuscated_chunked_rejected() {
    // HTTP/2 must reject any TE value that isn't "trailers"
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_some());
}

#[test]
fn http2_te_with_leading_space_trailers_accepted() {
    // "trailers" with leading space — trim() handles this
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static(" trailers "));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http10_te_rejected_regardless_of_obfuscation() {
    // HTTP/1.0 rejects ALL TE headers — obfuscation doesn't help
    for val in &["chunked", "Chunked", " chunked", "identity"] {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("transfer-encoding", HeaderValue::from_static(val));
        let result = check_protocol_headers(&headers, hyper::Version::HTTP_10);
        assert!(
            result.is_some(),
            "HTTP/1.0 should reject TE value '{}'",
            val
        );
        assert!(result.unwrap().contains("HTTP/1.0 does not support"));
    }
}

// ============================================================================
// CONNECT method blocking tests
// ============================================================================

/// HTTP/1.1 CONNECT requests are not valid WebSocket upgrades and should be
/// blocked by the CONNECT check in handle_proxy_request.
#[test]
fn h2_connect_without_websocket_protocol_is_not_ws() {
    // An HTTP/2 CONNECT without :protocol = "websocket" is NOT a WS upgrade.
    // is_h2_websocket_connect checks for method=CONNECT + version=HTTP/2 + protocol extension.
    let req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_2)
        .uri("/")
        .body(())
        .unwrap();
    // No Protocol extension set — should NOT be detected as WebSocket
    assert!(!is_h2_websocket_connect(&req));
}

#[test]
fn h2_connect_without_protocol_is_hbone_only_in_mesh_mode() {
    let req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_2)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .unwrap();
    let mesh_env = ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        ..Default::default()
    };
    let non_mesh_env = ferrum_edge::config::EnvConfig::default();

    assert!(is_hbone_connect_request(&req, &mesh_env));
    assert!(!is_hbone_connect_request(&req, &non_mesh_env));
}

#[test]
fn hbone_detection_requires_http2_mesh_mode() {
    let h1_connect = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_11)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .unwrap();
    let mesh_env = ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        ..Default::default()
    };

    assert!(!is_hbone_connect_request(&h1_connect, &mesh_env));
}

#[test]
fn extended_connect_protocols_are_not_hbone() {
    let mut websocket = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_2)
        .uri("/")
        .body(())
        .unwrap();
    websocket
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let mut connect_udp = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_2)
        .uri("/")
        .body(())
        .unwrap();
    connect_udp
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("connect-udp"));
    let env = ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        ..Default::default()
    };

    assert!(!is_hbone_connect_request(&websocket, &env));
    assert!(!is_hbone_connect_request(&connect_udp, &env));
}

#[test]
fn h2_connect_with_websocket_protocol_is_ws() {
    let mut req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_2)
        .uri("/")
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    assert!(is_h2_websocket_connect(&req));
}

#[test]
fn h2_connect_with_non_websocket_protocol_is_not_ws() {
    // Extended CONNECT with a non-websocket :protocol value (e.g., "h2c", "connect-udp")
    // should NOT be detected as WebSocket — must be rejected by the proxy.
    let mut req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_2)
        .uri("/")
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("connect-udp"));
    assert!(!is_h2_websocket_connect(&req));
}

#[test]
fn h1_connect_is_not_ws() {
    // HTTP/1.1 CONNECT is never a WebSocket upgrade
    let req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .version(hyper::Version::HTTP_11)
        .uri("/")
        .body(())
        .unwrap();
    assert!(!is_h2_websocket_connect(&req));
}

// ============================================================================
// Host header trailing dot normalization tests
// ============================================================================

/// Verify that trailing dots in hostnames are equivalent in DNS and routing.
/// The proxy normalizes "example.com." to "example.com" before routing.
/// This test validates the normalization logic used in host extraction.
#[test]
fn host_trailing_dot_stripped_for_routing() {
    let host_with_dot = "example.com.";
    let normalized = normalize_request_host_for_routing(host_with_dot).unwrap();
    assert_eq!(normalized, "example.com");
}

#[test]
fn host_without_trailing_dot_unchanged() {
    let host = "example.com";
    let normalized = normalize_request_host_for_routing(host).unwrap();
    assert_eq!(normalized, "example.com");
}

#[test]
fn host_with_port_and_trailing_dot_normalized() {
    let host = "example.com.:8080";
    let normalized = normalize_request_host_for_routing(host).unwrap();
    assert_eq!(normalized, "example.com");
}

#[test]
fn host_ipv6_literal_with_port_preserved_for_routing() {
    let host = "[2001:db8::1]:8443";
    let normalized = normalize_request_host_for_routing(host).unwrap();
    assert_eq!(normalized, "[2001:db8::1]");
}

#[test]
fn host_ipv6_literal_without_port_preserved_for_routing() {
    let host = "[2001:db8::1]";
    let normalized = normalize_request_host_for_routing(host).unwrap();
    assert_eq!(normalized, "[2001:db8::1]");
}

#[test]
fn host_unbracketed_ipv6_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("2001:db8::1").is_none());
    assert!(normalize_request_host_for_routing("::1").is_none());
}

#[test]
fn host_single_dot_rejected_for_routing() {
    // A bare dot normalizes to empty, which is not a valid hostname.
    assert!(normalize_request_host_for_routing(".").is_none());
}

#[test]
fn host_trailing_colon_no_port_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("example.com:").is_none());
}

#[test]
fn host_non_numeric_port_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("example.com:notaport").is_none());
}

#[test]
fn host_port_above_u16_max_rejected_for_routing() {
    // Ports above 65535 are not a valid TCP port. Without the range check,
    // digit-only validation accepts them and lets a malformed authority reach
    // routing/backend dispatch.
    assert!(normalize_request_host_for_routing("example.com:65536").is_none());
    assert!(normalize_request_host_for_routing("example.com:9999999999").is_none());
    assert!(normalize_request_host_for_routing("[2001:db8::1]:65536").is_none());
}

#[test]
fn host_port_at_u16_max_accepted_for_routing() {
    // 65535 is the maximum valid TCP port.
    assert_eq!(
        normalize_request_host_for_routing("example.com:65535"),
        Some("example.com".to_string())
    );
    assert_eq!(
        normalize_request_host_for_routing("[2001:db8::1]:65535"),
        Some("[2001:db8::1]".to_string())
    );
}

#[test]
fn host_with_userinfo_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("user@example.com").is_none());
}

#[test]
fn host_with_path_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("api.example/foo").is_none());
}

#[test]
fn host_with_query_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("api.example?q=1").is_none());
}

#[test]
fn host_with_fragment_rejected_for_routing() {
    assert!(normalize_request_host_for_routing("api.example#top").is_none());
}

#[test]
fn host_with_comma_rejected_for_routing() {
    // Comma is the HTTP list separator. Accepting it in a hostname would let a
    // single Host header smuggle multiple authority-shaped values past anything
    // downstream that splits on commas (logs, plugin matchers, etc.).
    assert!(normalize_request_host_for_routing("api.example,evil.example").is_none());
}

#[test]
fn host_with_backslash_rejected_for_routing() {
    assert!(normalize_request_host_for_routing(r"api.example\foo").is_none());
}

#[test]
fn host_empty_brackets_rejected_for_routing() {
    // RFC 3986: bracketed authority must contain IPv6address or IPvFuture.
    // `[]` is malformed authority syntax — without validation it would
    // normalize to `[]` and bypass host-scoped routes via the catch-all tier.
    assert!(normalize_request_host_for_routing("[]").is_none());
    assert!(normalize_request_host_for_routing("[]:8443").is_none());
}

#[test]
fn host_brackets_around_non_ip_rejected_for_routing() {
    // `[not-an-ip]` and similar opaque bracket contents are not valid
    // IPv6address/IPvFuture and must not be routable.
    assert!(normalize_request_host_for_routing("[not-an-ip]").is_none());
    assert!(normalize_request_host_for_routing("[example.com]").is_none());
    assert!(normalize_request_host_for_routing("[evil.example]:443").is_none());
}

#[test]
fn host_brackets_around_ipv4_rejected_for_routing() {
    // RFC 3986 reserves brackets exclusively for IPv6address / IPvFuture,
    // not IPv4. `[127.0.0.1]` is malformed.
    assert!(normalize_request_host_for_routing("[127.0.0.1]").is_none());
}

#[test]
fn host_brackets_around_ipv6_accepted_for_routing() {
    // Valid IPv6 literals must still be accepted after the new validator.
    assert_eq!(
        normalize_request_host_for_routing("[::1]"),
        Some("[::1]".to_string())
    );
    assert_eq!(
        normalize_request_host_for_routing("[2001:db8::1]:8443"),
        Some("[2001:db8::1]".to_string())
    );
}

#[test]
fn host_brackets_around_ipvfuture_accepted_for_routing() {
    // RFC 3986 IPvFuture: "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ).
    assert!(normalize_request_host_for_routing("[v1.fe80::a:b]").is_some());
    assert!(normalize_request_host_for_routing("[v7.example-future]").is_some());
}

/// Verify that hyper's HeaderMap normalizes header names to lowercase,
/// preventing header name case obfuscation (e.g., "Transfer-Encoding" vs "transfer-encoding").
#[test]
fn hyper_headermap_normalizes_header_names() {
    let mut headers = hyper::HeaderMap::new();
    // Insert with mixed case — hyper normalizes to lowercase
    headers.insert(
        hyper::header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    // Lookup with lowercase string succeeds
    assert!(headers.contains_key("transfer-encoding"));
    // This means our check_protocol_headers checks (which use lowercase strings)
    // will always match regardless of how the client sent the header name.
}
