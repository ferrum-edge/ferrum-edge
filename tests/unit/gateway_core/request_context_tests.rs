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
fn raw_header_get_uses_last_value_wins_for_multi_valued() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("x-custom", "first".parse().unwrap());
    raw.append("x-custom", "second".parse().unwrap());
    raw.append("x-custom", "third".parse().unwrap());
    ctx.set_raw_headers(raw);

    // raw_header_get should return the last value, matching materialize_headers
    // behavior (HashMap::insert overwrites, so last value wins)
    assert_eq!(ctx.raw_header_get("x-custom"), Some("third"));

    // Verify materialize_headers produces the same result
    ctx.materialize_headers();
    assert_eq!(ctx.headers.get("x-custom").unwrap(), "third");
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
fn materialize_query_params_raw_no_decoding() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("key%20name=val%26ue".into());

    ctx.materialize_query_params_raw();

    // Raw materialization should NOT percent-decode
    assert_eq!(ctx.query_params.get("key%20name").unwrap(), "val%26ue");
}

#[test]
fn materialize_query_params_raw_skips_no_equals() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_query_string("flag&key=val".into());

    ctx.materialize_query_params_raw();

    // Raw variant only includes pairs with '='
    assert_eq!(ctx.query_params.len(), 1);
    assert_eq!(ctx.query_params.get("key").unwrap(), "val");
}

// -- Direct-set backwards compatibility tests --------------------------------

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
