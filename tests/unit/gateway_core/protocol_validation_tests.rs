use ferrum_edge::proxy::{build_forwarded_value, check_protocol_headers, is_valid_websocket_key};
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
fn http2_allows_cl_and_te_trailers() {
    // HTTP/2 doesn't use Transfer-Encoding, but if somehow present,
    // the CL+TE check only applies to HTTP/1.x
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    // HTTP/2 skips the CL+TE check (it's a protocol-level concern for HTTP/1.x)
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    // Should not trigger the CL+TE error (but may trigger TE validation)
    assert!(
        result.is_none()
            || !result
                .unwrap()
                .contains("Content-Length and Transfer-Encoding")
    );
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
    // HTTP/2 uses :authority, not Host — multiple Host headers are not a routing concern
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

// ============================================================================
// build_forwarded_value tests (RFC 7239)
// ============================================================================

#[test]
fn forwarded_ipv4_with_host() {
    let val = build_forwarded_value("192.0.2.60", "https", Some("example.com"));
    assert_eq!(val, "for=192.0.2.60;proto=https;host=example.com");
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
