use ferrum_edge::plugins::RequestContext;
use http::HeaderMap;

// -- Lazy header materialization tests ----------------------------------------

#[test]
fn materialize_headers_converts_raw_to_hashmap() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("content-type", "application/json".parse().unwrap());
    raw.insert("x-custom", "value".parse().unwrap());
    ctx.set_raw_headers(raw);

    assert!(
        ctx.headers.is_empty(),
        "headers should be empty before materialization"
    );

    ctx.materialize_headers();

    assert_eq!(ctx.headers.len(), 2);
    assert_eq!(ctx.headers.get("content-type").unwrap(), "application/json");
    assert_eq!(ctx.headers.get("x-custom").unwrap(), "value");
}

#[test]
fn materialize_headers_is_idempotent() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("host", "example.com".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();
    assert_eq!(ctx.headers.len(), 1);

    // Insert an extra header into the materialized map
    ctx.headers.insert("extra".into(), "val".into());

    // Second materialize should be a no-op (raw_headers already consumed)
    ctx.materialize_headers();
    assert_eq!(
        ctx.headers.len(),
        2,
        "second materialize should not overwrite"
    );
    assert_eq!(ctx.headers.get("extra").unwrap(), "val");
}

#[test]
fn raw_header_get_reads_before_materialization() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
    ctx.set_raw_headers(raw);

    assert_eq!(ctx.raw_header_get("x-forwarded-for"), Some("10.0.0.1"));
    assert_eq!(ctx.raw_header_get("nonexistent"), None);
}

#[test]
fn raw_header_values_exposes_all_duplicate_field_lines() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("x-forwarded-for", "198.51.100.10".parse().unwrap());
    raw.append("x-forwarded-for", "203.0.113.77".parse().unwrap());
    ctx.set_raw_headers(raw);

    let values: Vec<&str> = ctx.raw_header_values("x-forwarded-for").collect();
    assert_eq!(values, vec!["198.51.100.10", "203.0.113.77"]);
}

#[test]
fn materialize_headers_reassembles_cookie_crumbs_with_semicolon_space() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("cookie", "session=abc".parse().unwrap());
    raw.append("cookie", "theme=dark".parse().unwrap());
    raw.append("cookie", "csrf=def".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert_eq!(
        ctx.headers.get("cookie").map(String::as_str),
        Some("session=abc; theme=dark; csrf=def")
    );
}

#[test]
fn materialize_headers_comma_folds_repeated_request_fields() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("x-forwarded-for", "198.51.100.10".parse().unwrap());
    raw.append("x-forwarded-for", "203.0.113.77".parse().unwrap());
    raw.append("accept", "application/json".parse().unwrap());
    raw.append("accept", "text/plain".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert_eq!(
        ctx.headers.get("x-forwarded-for").map(String::as_str),
        Some("198.51.100.10, 203.0.113.77")
    );
    assert_eq!(
        ctx.headers.get("accept").map(String::as_str),
        Some("application/json, text/plain")
    );
}

#[test]
fn materialize_headers_folds_duplicate_connection_lines() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("connection", "x-one".parse().unwrap());
    raw.append("connection", "x-two, x-three".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert_eq!(
        ctx.headers.get("connection").map(String::as_str),
        Some("x-one, x-two, x-three")
    );
}

#[test]
fn materialize_headers_skips_reserved_identity_headers_even_when_repeated() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("x-consumer-username", "spoofed".parse().unwrap());
    raw.append("x-consumer-username", "also-spoofed".parse().unwrap());
    raw.append("x-consumer-custom-id", "custom".parse().unwrap());
    raw.append("x-forwarded-for", "198.51.100.10".parse().unwrap());
    raw.append("x-forwarded-for", "203.0.113.77".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert!(!ctx.headers.contains_key("x-consumer-username"));
    assert!(!ctx.headers.contains_key("x-consumer-custom-id"));
    assert_eq!(
        ctx.headers.get("x-forwarded-for").map(String::as_str),
        Some("198.51.100.10, 203.0.113.77")
    );
}

#[test]
fn materialize_headers_skips_reserved_path_param_headers_even_when_repeated() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("x-path-param-user_id", "spoofed".parse().unwrap());
    raw.append("x-path-param-user_id", "also-spoofed".parse().unwrap());
    raw.append("X-Path-Param-Other", "spoofed-other".parse().unwrap());
    raw.append("x-path-param-", "empty-name".parse().unwrap());
    raw.append("x-path-paramish", "ordinary".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert!(!ctx.headers.contains_key("x-path-param-user_id"));
    assert!(!ctx.headers.contains_key("x-path-param-other"));
    assert!(!ctx.headers.contains_key("x-path-param-"));
    assert_eq!(
        ctx.headers.get("x-path-paramish").map(String::as_str),
        Some("ordinary")
    );
}

#[test]
fn raw_header_get_returns_none_after_materialization() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("host", "example.com".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    // raw_headers is consumed, so raw_header_get returns None
    assert_eq!(ctx.raw_header_get("host"), None);
    // but the materialized map has it
    assert_eq!(ctx.headers.get("host").unwrap(), "example.com");
}

#[test]
fn materialize_headers_skips_non_utf8_values() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("good", "value".parse().unwrap());
    // HeaderValue can contain non-UTF-8 bytes
    raw.insert(
        "binary",
        http::HeaderValue::from_bytes(&[0x80, 0x81]).unwrap(),
    );
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert_eq!(ctx.headers.len(), 1, "non-UTF-8 header should be skipped");
    assert_eq!(ctx.headers.get("good").unwrap(), "value");
}

#[test]
fn materialize_headers_empty_headermap() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_headers(HeaderMap::new());

    ctx.materialize_headers();
    assert!(ctx.headers.is_empty());
}

#[test]
fn materialize_headers_preserves_existing_entries() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    // Pre-populate a header (e.g., path param injection)
    ctx.headers.insert("x-existing".into(), "pre".into());

    let mut raw = HeaderMap::new();
    raw.insert("host", "example.com".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    // Both the pre-existing and raw headers should be present
    assert_eq!(ctx.headers.get("x-existing").unwrap(), "pre");
    assert_eq!(ctx.headers.get("host").unwrap(), "example.com");
}

// -- Lazy query param materialization tests -----------------------------------

#[test]
fn materialize_query_params_basic() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("foo=bar&baz=qux".into());

    assert!(
        ctx.query_params.is_empty(),
        "should be empty before materialization"
    );

    ctx.materialize_query_params();

    assert_eq!(ctx.query_params.len(), 2);
    assert_eq!(ctx.query_params.get("foo").unwrap(), "bar");
    assert_eq!(ctx.query_params.get("baz").unwrap(), "qux");
}

#[test]
fn materialize_query_params_percent_decoding() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("key%20name=val%26ue&a%3Db=c".into());

    ctx.materialize_query_params();

    assert_eq!(ctx.query_params.get("key name").unwrap(), "val&ue");
    assert_eq!(ctx.query_params.get("a=b").unwrap(), "c");
}

#[test]
fn materialize_query_params_flag_without_equals() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("flag&key=val".into());

    ctx.materialize_query_params();

    assert_eq!(ctx.query_params.get("flag").unwrap(), "");
    assert_eq!(ctx.query_params.get("key").unwrap(), "val");
}

#[test]
fn materialize_query_params_empty_segments() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("&&a=1&&b=2&&".into());

    ctx.materialize_query_params();

    assert_eq!(ctx.query_params.len(), 2);
    assert_eq!(ctx.query_params.get("a").unwrap(), "1");
    assert_eq!(ctx.query_params.get("b").unwrap(), "2");
}

#[test]
fn materialize_query_params_idempotent() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("x=1".into());

    ctx.materialize_query_params();
    assert_eq!(ctx.query_params.len(), 1);

    // Add extra entry, then materialize again — should be no-op
    ctx.query_params.insert("extra".into(), "val".into());
    ctx.materialize_query_params();
    assert_eq!(
        ctx.query_params.len(),
        2,
        "second materialize should be no-op"
    );
}

#[test]
fn materialize_query_params_empty_string_is_noop() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("".into());

    ctx.materialize_query_params();
    assert!(ctx.query_params.is_empty());
}

#[test]
fn set_raw_query_string_ignores_empty() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("".into());

    // Should not have stored anything, so materialize is a no-op
    ctx.materialize_query_params();
    assert!(ctx.query_params.is_empty());
}

#[test]
fn set_raw_query_string_replaces_materialized_params() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("a=1&old=value".into());
    ctx.materialize_query_params();
    assert_eq!(ctx.query_params.get("a").unwrap(), "1");

    ctx.set_raw_query_string("b=2".into());
    assert_eq!(ctx.raw_query_string(), Some("b=2"));
    assert!(ctx.query_params.is_empty());

    ctx.materialize_query_params();
    assert_eq!(ctx.query_params.len(), 1);
    assert_eq!(ctx.query_params.get("b").unwrap(), "2");
    assert!(!ctx.query_params.contains_key("a"));
    assert!(!ctx.query_params.contains_key("old"));
}

#[test]
fn set_raw_query_string_empty_clears_materialized_params() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("a=1".into());
    ctx.materialize_query_params();
    assert_eq!(ctx.query_params.get("a").unwrap(), "1");

    ctx.set_raw_query_string("".into());
    assert_eq!(ctx.raw_query_string(), None);
    assert!(ctx.query_params.is_empty());

    ctx.materialize_query_params();
    assert!(ctx.query_params.is_empty());
}

#[test]
fn materialize_query_params_raw_no_decoding() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("key%20name=val%26ue".into());

    ctx.materialize_query_params_raw();

    // Raw materialization should NOT percent-decode
    assert_eq!(ctx.query_params.get("key%20name").unwrap(), "val%26ue");
}

#[test]
fn materialize_query_params_raw_keeps_valueless_flag() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("flag&key=val".into());

    ctx.materialize_query_params_raw();

    // A valueless flag (no '=') is stored with an empty value, matching the
    // decoded path, so plugins that presence-test a query param see it on
    // HTTP/3 (raw) just as they would on HTTP/1.1 and HTTP/2 (decoded).
    assert_eq!(ctx.query_params.len(), 2);
    assert_eq!(ctx.query_params.get("flag").unwrap(), "");
    assert!(ctx.query_params.contains_key("flag"));
    assert_eq!(ctx.query_params.get("key").unwrap(), "val");
}

#[test]
fn materialize_query_params_raw_skips_empty_segments() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("&&a=1&&flag&&".into());

    ctx.materialize_query_params_raw();

    // Empty segments are skipped (so a trailing/leading `&` does not create a
    // bare empty-string key), matching the decoded variant.
    assert_eq!(ctx.query_params.len(), 2);
    assert_eq!(ctx.query_params.get("a").unwrap(), "1");
    assert_eq!(ctx.query_params.get("flag").unwrap(), "");
    assert!(!ctx.query_params.contains_key(""));
}

#[test]
fn materialize_query_params_raw_and_decoded_expose_same_keys_for_valueless_flag() {
    // Cross-protocol parity: the raw (HTTP/3 default) and decoded (HTTP/1.1 /
    // HTTP/2) paths must expose the same key set for a valueless flag so a
    // security/admission plugin presence-testing `ctx.query_params` sees the
    // same params regardless of protocol. The only intended difference is
    // percent-decoding, which a plain ASCII flag does not exercise.
    let raw_query = "admin&debug=&user=alice";

    let mut decoded = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    decoded.set_raw_query_string(raw_query.into());
    decoded.materialize_query_params();

    let mut raw = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    raw.set_raw_query_string(raw_query.into());
    raw.materialize_query_params_raw();

    let mut decoded_keys: Vec<&str> = decoded.query_params.keys().map(String::as_str).collect();
    let mut raw_keys: Vec<&str> = raw.query_params.keys().map(String::as_str).collect();
    decoded_keys.sort_unstable();
    raw_keys.sort_unstable();
    assert_eq!(
        decoded_keys, raw_keys,
        "raw and decoded query-param materialization must expose the same key set"
    );

    // The valueless flag and the empty-valued param are both present with empty
    // values on both paths.
    assert_eq!(decoded.query_params.get("admin").unwrap(), "");
    assert_eq!(raw.query_params.get("admin").unwrap(), "");
    assert_eq!(decoded.query_params.get("debug").unwrap(), "");
    assert_eq!(raw.query_params.get("debug").unwrap(), "");
}

// -- Direct mutation tests ----------------------------------------------------

#[test]
fn direct_query_params_set_works_without_materialization() {
    // Plugins in tests often set query_params directly — verify that still works
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.query_params.insert("key".into(), "val".into());
    assert_eq!(ctx.query_params.get("key").unwrap(), "val");
}

#[test]
fn direct_headers_set_works_without_materialization() {
    // Plugins in tests often set headers directly — verify that still works
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.headers.insert("x-test".into(), "value".into());
    assert_eq!(ctx.headers.get("x-test").unwrap(), "value");
}
