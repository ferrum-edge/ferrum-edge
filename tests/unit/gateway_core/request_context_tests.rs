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

// ── Issue #5010: obs-text field values must survive materialization ─────────
//
// RFC 9110 §5.5 permits obs-text (0x80-0xFF) in a field value, and
// `HeaderValue::from_str` accepts those bytes — only `HeaderValue::to_str`
// refuses them. Decoding with `to_str` therefore deleted every obs-text field
// value from the backend request, because the materialized map is the
// authoritative removal set for the outbound merges.

#[test]
fn materialize_headers_keeps_non_ascii_utf8_values_byte_exact() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert(
        "x-api-key",
        http::HeaderValue::from_bytes("ユニコード-api-key-value-32chars-min".as_bytes())
            .expect("obs-text is a valid header value"),
    );
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert_eq!(
        ctx.headers.get("x-api-key").map(String::as_str),
        Some("ユニコード-api-key-value-32chars-min")
    );
    // Non-vacuity: the exact bytes round-trip back onto the wire.
    assert_eq!(
        http::HeaderValue::from_str(ctx.headers.get("x-api-key").unwrap())
            .expect("materialized value must be representable on the wire")
            .as_bytes(),
        "ユニコード-api-key-value-32chars-min".as_bytes()
    );
}

#[test]
fn materialize_headers_folds_repeated_non_ascii_utf8_field_lines() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append(
        "x-note",
        http::HeaderValue::from_bytes("café".as_bytes()).unwrap(),
    );
    raw.append(
        "x-note",
        http::HeaderValue::from_bytes("naïve".as_bytes()).unwrap(),
    );
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert_eq!(
        ctx.headers.get("x-note").map(String::as_str),
        Some("café, naïve")
    );
}

#[test]
fn materialize_headers_still_omits_values_that_are_not_valid_utf8() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert(
        "x-binary",
        http::HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap(),
    );
    raw.insert("x-plain", "ok".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert!(!ctx.headers.contains_key("x-binary"));
    assert_eq!(ctx.headers.get("x-plain").map(String::as_str), Some("ok"));
    // The raw map still carries the exact bytes for plugins that inspect them.
    assert_eq!(
        ctx.raw_header_value_bytes("x-binary").next(),
        Some(&[0xFF, 0xFE][..])
    );
}

#[test]
fn materialize_headers_still_drops_reserved_gateway_assertions_with_obs_text() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert(
        "x-consumer-username",
        http::HeaderValue::from_bytes("スプーフ".as_bytes()).unwrap(),
    );
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert!(
        !ctx.headers.contains_key("x-consumer-username"),
        "a client-supplied gateway assertion must never be materialized"
    );
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
fn materialize_headers_skips_reserved_gateway_assertions_even_when_repeated() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.append("x-consumer-username", "spoofed".parse().unwrap());
    raw.append("x-consumer-username", "also-spoofed".parse().unwrap());
    raw.append("x-consumer-custom-id", "custom".parse().unwrap());
    raw.append("x-geo-country", "attacker-first".parse().unwrap());
    raw.append("x-geo-country", "attacker-second".parse().unwrap());
    raw.append("x-forwarded-for", "198.51.100.10".parse().unwrap());
    raw.append("x-forwarded-for", "203.0.113.77".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert!(!ctx.headers.contains_key("x-consumer-username"));
    assert!(!ctx.headers.contains_key("x-consumer-custom-id"));
    assert!(!ctx.headers.contains_key("x-geo-country"));
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
fn raw_header_get_remains_available_after_materialization() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    let mut raw = HeaderMap::new();
    raw.insert("host", "example.com".parse().unwrap());
    raw.append("x-policy", http::HeaderValue::from_bytes(&[0x80]).unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    // Raw field lines stay available for fail-closed security decisions even
    // after the lossy materialized map is built.
    assert!(ctx.has_raw_headers());
    assert_eq!(ctx.raw_header_get("host"), Some("example.com"));
    assert_eq!(
        ctx.raw_header_value_bytes("x-policy").collect::<Vec<_>>(),
        vec![&[0x80u8][..]]
    );
    assert_eq!(ctx.headers.get("host").unwrap(), "example.com");
    assert!(
        !ctx.headers.contains_key("x-policy"),
        "non-UTF-8 values stay omitted from the materialized map"
    );
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

// ── Issue #5537: per-plugin request state is allocated lazily ────────────────
//
// `RequestContext` used to inline every plugin family's staging collection, so
// the plugin-free edge request built, moved, cloned, and dropped two dozen
// hashers per request for state nothing on the proxy could ever read. The
// collections now live in one `Option<Box<PluginRequestState>>`; these tests
// pin both halves of that contract — the plugin-free path never materializes
// the box, and a family that does stage something still projects identically
// into transaction-log metadata.

fn has_plugin_state(ctx: &RequestContext) -> bool {
    ferrum_edge::_test_support::request_context_has_plugin_state(ctx)
}

#[test]
fn plugin_free_request_context_never_materializes_plugin_state() {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/echo".into());
    assert!(
        !has_plugin_state(&ctx),
        "a freshly constructed context must not allocate per-plugin state"
    );

    // Everything a plugin-free H1 POST actually does to its context: headers
    // materialize, metadata is written, the terminal projects log metadata, and
    // the context is cloned for a deferred consumer.
    let mut raw = HeaderMap::new();
    raw.insert("content-type", "application/octet-stream".parse().unwrap());
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx.metadata
        .insert("request_protocol".into(), "http".into());

    let metadata = ferrum_edge::_test_support::clone_log_metadata(&ctx);
    assert_eq!(
        metadata.get("request_protocol").map(String::as_str),
        Some("http")
    );
    let cloned = ctx.clone();
    assert!(
        !has_plugin_state(&cloned),
        "cloning a plugin-free context must not allocate per-plugin state"
    );
    drop(cloned);
    assert!(
        !has_plugin_state(&ctx),
        "no plugin-free read may materialize per-plugin state"
    );
}

#[test]
fn staged_waf_metadata_materializes_plugin_state_and_reaches_log_metadata() {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/echo".into());
    ferrum_edge::_test_support::set_waf_metadata_for_test(&mut ctx, "waf.action", "monitored");
    assert!(
        has_plugin_state(&ctx),
        "a staging plugin family materializes the boxed state"
    );

    let metadata = ferrum_edge::_test_support::clone_log_metadata(&ctx);
    assert_eq!(
        metadata.get("waf.action").map(String::as_str),
        Some("monitored"),
        "WAF-owned metadata still projects into the transaction log"
    );

    let cloned = ctx.clone();
    assert_eq!(
        ferrum_edge::_test_support::clone_log_metadata(&cloned),
        metadata,
        "a cloned context projects byte-identical log metadata"
    );
}

#[test]
fn absent_plugin_state_still_strips_unowned_waf_log_metadata() {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/echo".into());
    // No `waf` instance ran, so nothing owns this field. The fail-closed strip
    // must still happen with no per-plugin state allocated.
    ctx.metadata.insert("waf.score".into(), "99".into());

    let metadata = ferrum_edge::_test_support::clone_log_metadata(&ctx);
    assert!(
        !metadata.contains_key("waf.score"),
        "an unowned waf.* field must never reach transaction logs"
    );
    assert!(
        !has_plugin_state(&ctx),
        "the strip must not materialize per-plugin state"
    );
}

// ── Issue #5537: nothing may reach `plugin_state_mut()` on the plugin-free
// ── request path ─────────────────────────────────────────────────────────────
//
// `plugin_free_request_context_never_materializes_plugin_state` above exercises
// `RequestContext` in isolation: construct, materialize headers, project log
// metadata, clone. That cannot catch a proxy-core or plugin-core caller that
// starts reaching `plugin_state_mut()` once per request, which is the failure
// this half of the contract actually has to survive. There is no in-process
// fixture that drives a real plugin-free request through
// `handle_proxy_request_inner` (it is a private future with no test entry
// point, and the functional suites drive a spawned gateway subprocess whose
// contexts are unreachable from the harness), so the guard is structural: every
// `plugin_state_mut()` call site in `src/plugins/mod.rs` is enumerated below
// with the gate that keeps it off the plugin-free path. Adding one fails this
// test until its gate is named, the same way the `assert_markers_in_order`
// source contracts pin control flow elsewhere in the suite.
//
// `plugin_state()` and `plugin_state_opt_mut()` never materialize, so they are
// deliberately unconstrained.

const PLUGINS_SOURCE: &str = include_str!("../../../src/plugins/mod.rs");

const PLUGIN_STATE_MUT: &str = "plugin_state_mut()";

/// `(enclosing method, in-method gate, why a plugin-free request never lands here)`.
///
/// A `None` gate means the method body is unconditional and the gate is at the
/// caller: it runs only because that plugin family is configured on the proxy.
const PLUGIN_STATE_MUT_CALL_SITES: &[(&str, Option<&str>, &str)] = &[
    (
        "adopt_final_request_body_hook_plugin_state",
        Some("if self.plugin_state.is_none()"),
        "the final-request-body hook adopt returns before materializing when \
         the live context has no state and all four adopted families are empty",
    ),
    (
        "stage_response_cache_request_header_delta",
        Some("if delta.is_empty() {"),
        "a configured `response_caching` instance stages a delta only when the \
         backend-visible header map actually differs from the inbound one",
    ),
    (
        "mark_query_credential_partition_digest",
        None,
        "reached only from `token_extract::mark_query_credential_metadata`, \
         which runs for a configured query credential location and only when \
         that parameter is actually present on the request",
    ),
    (
        "set_waf_metadata",
        None,
        "a configured `waf` instance is the only writer of WAF-owned metadata",
    ),
    (
        "accumulate_waf_instance_score",
        Some("if contribution == 0"),
        "a configured `waf` instance is the only scorer, and a never-seen zero \
         contribution returns before materializing",
    ),
    (
        "merge_waf_metadata",
        Some("if value.is_empty() {"),
        "a configured `waf` instance is the only writer, and an empty value \
         returns before materializing",
    ),
];

/// The name of the 4-space-indented `fn` this line declares, if it declares one.
fn declared_method_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("    ")?;
    if rest.starts_with(' ') {
        return None;
    }
    let rest = rest.strip_prefix("pub(crate) ").unwrap_or(rest);
    let rest = rest.strip_prefix("pub ").unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    Some(rest.split(['(', '<']).next().unwrap_or(rest))
}

/// The method containing `offset`, as `(name, byte offset of its signature)`.
fn enclosing_method(source: &str, offset: usize) -> (&str, usize) {
    let mut enclosing = None;
    let mut line_start = 0;
    for line in source.split_inclusive('\n') {
        if line_start >= offset {
            break;
        }
        if let Some(name) = declared_method_name(line) {
            enclosing = Some((name, line_start));
        }
        line_start += line.len();
    }
    enclosing.expect("every plugin_state_mut() call site sits inside a method")
}

#[test]
fn every_plugin_state_mut_call_site_is_behind_a_documented_gate() {
    let mut sites = Vec::new();
    let mut offset = 0;
    while let Some(relative) = PLUGINS_SOURCE[offset..].find(PLUGIN_STATE_MUT) {
        let at = offset + relative;
        offset = at + PLUGIN_STATE_MUT.len();
        sites.push(enclosing_method(PLUGINS_SOURCE, at));
    }

    let found: Vec<&str> = sites.iter().map(|(name, _)| *name).collect();
    let documented: Vec<&str> = PLUGIN_STATE_MUT_CALL_SITES
        .iter()
        .map(|(name, _, _)| *name)
        .collect();
    assert_eq!(
        found, documented,
        "every `plugin_state_mut()` call site in src/plugins/mod.rs must be \
         listed in PLUGIN_STATE_MUT_CALL_SITES with the gate that keeps it off \
         the plugin-free request path; a new one materializes the boxed state \
         on every request that reaches it"
    );

    for ((name, signature_at), (_, gate, rationale)) in
        sites.iter().zip(PLUGIN_STATE_MUT_CALL_SITES.iter())
    {
        let Some(gate) = gate else {
            continue;
        };
        let call_at = PLUGINS_SOURCE[*signature_at..]
            .find(PLUGIN_STATE_MUT)
            .expect("the call site follows its own signature");
        let body = &PLUGINS_SOURCE[*signature_at..*signature_at + call_at];
        assert!(
            body.contains(gate),
            "{name} must keep its documented gate `{gate}` before it \
             materializes per-plugin state ({rationale})"
        );
    }
}
