//! Normalization parity with the parsers WAF-protected backends actually run.
//!
//! Each case is a payload whose raw bytes do not match a signature but which
//! the backend's own decoder turns into exactly what the signature describes:
//!
//! * JSON / JavaScript single-character string escapes (`\t`, `\n`, `\"`,
//!   `\/`, `\\`), resolved by every JSON parser before the application sees
//!   the value;
//! * IIS / classic ASP and JavaScript `unescape()` `%uXXXX` escapes;
//! * percent-encoded cookie values, which PHP, Express `cookie-parser`, and
//!   Rails decode before binding them.
//!
//! Every assertion drives the real plugin hooks so it covers the complete
//! view pipeline (raw scan plus bounded decoded variants), and each attack has
//! a benign twin that must stay clean.

use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new("203.0.113.10".into(), method.into(), path.into())
}

fn monitor_waf() -> Waf {
    Waf::new(&json!({ "mode": "monitor", "scan_budget_ms": 0 })).unwrap()
}

fn hit(ctx: &RequestContext, rule_id: &str) -> bool {
    ctx.metadata
        .get("waf.rule_hits")
        .is_some_and(|hits| hits.split(',').any(|hit| hit == rule_id))
}

fn hits(ctx: &RequestContext) -> Option<&String> {
    ctx.metadata.get("waf.rule_hits")
}

async fn scan_body(plugin: &Waf, content_type: &str, body: &[u8]) -> RequestContext {
    let mut request = ctx("POST", "/submit");
    request
        .headers
        .insert("content-type".into(), content_type.into());
    let headers = request.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(&mut request, &headers, body)
        .await;
    request
}

async fn scan_query(plugin: &Waf, raw_query: &str) -> RequestContext {
    let mut request = ctx("GET", "/search");
    request.set_raw_query_string(raw_query.into());
    let _ = plugin.authorize(&mut request).await;
    request
}

async fn scan_cookie(plugin: &Waf, cookie: &str) -> (PluginResult, RequestContext) {
    let mut request = ctx("GET", "/");
    request.headers.insert("cookie".into(), cookie.into());
    let result = plugin.authorize(&mut request).await;
    (result, request)
}

#[tokio::test]
async fn json_whitespace_escapes_cannot_hide_sql_token_separators() {
    let plugin = monitor_waf();
    // Raw bytes carry `\t` / `\n` (a backslash and a letter) where the
    // signature needs whitespace; the backend's JSON parser yields a real TAB
    // or LF, which every SQL engine treats as token whitespace.
    for body in [
        br#"{"q":"1 union\tselect password from users"}"#.as_slice(),
        br#"{"q":"1 UNION\nSELECT password FROM users"}"#,
        br#"{"q":"1 union\r\nall\tselect 1"}"#,
    ] {
        let request = scan_body(&plugin, "application/json", body).await;
        assert!(
            hit(&request, "FE-SQLI-001-B"),
            "{:?} must be recognised after JSON unescaping; hits={:?}",
            String::from_utf8_lossy(body),
            hits(&request)
        );
    }
}

#[tokio::test]
async fn json_escaped_quotes_cannot_hide_a_double_quoted_tautology() {
    let plugin = monitor_waf();
    let request = scan_body(
        &plugin,
        "application/json",
        br#"{"user":"admin\" or \"1\"=\"1"}"#,
    )
    .await;
    assert!(hit(&request, "FE-SQLI-002-B"), "hits={:?}", hits(&request));

    // An escaped quote in ordinary prose is not a tautology.
    let benign = scan_body(
        &plugin,
        "application/json",
        br#"{"quote":"She said \"hello\" or \"goodbye\" twice"}"#,
    )
    .await;
    assert!(!hit(&benign, "FE-SQLI-002-B"), "hits={:?}", hits(&benign));
}

#[tokio::test]
async fn json_escaped_slashes_and_backslashes_cannot_hide_file_targets() {
    let plugin = monitor_waf();
    let request = scan_body(
        &plugin,
        "application/json",
        br#"{"url":"file:\/\/\/etc\/passwd"}"#,
    )
    .await;
    assert!(hit(&request, "FE-SSRF-002"), "hits={:?}", hits(&request));
    assert!(hit(&request, "FE-LFI-001-B"), "hits={:?}", hits(&request));

    // `\\` is ONE backslash to the backend, so `C:\\Windows\\win.ini` is the
    // Windows path the LFI signature names.
    let windows = scan_body(
        &plugin,
        "application/json",
        br#"{"path":"C:\\Windows\\win.ini"}"#,
    )
    .await;
    assert!(hit(&windows, "FE-LFI-001-B"), "hits={:?}", hits(&windows));

    let benign = scan_body(
        &plugin,
        "application/json",
        br#"{"url":"https:\/\/www.example.com\/docs\/","path":"D:\\builds\\app"}"#,
    )
    .await;
    assert!(
        !hit(&benign, "FE-SSRF-002") && !hit(&benign, "FE-LFI-001-B"),
        "hits={:?}",
        hits(&benign)
    );
}

#[tokio::test]
async fn escaped_backslash_before_a_unicode_escape_still_reduces_layer_by_layer() {
    let plugin = monitor_waf();
    // A JSON parser reads `\\u003c` as the literal text `\u003c`; a second
    // unescape (double-decoding application, template engine) yields `<`. The
    // layered decode reaches the payload either way.
    let request = scan_body(
        &plugin,
        "application/json",
        br#"{"c":"\\u003cscript\\u003ealert(1)"}"#,
    )
    .await;
    assert!(hit(&request, "FE-XSS-001-B"), "hits={:?}", hits(&request));
}

#[tokio::test]
async fn percent_u_escapes_are_decoded_in_query_and_form_bodies() {
    let plugin = monitor_waf();
    let query = scan_query(&plugin, "q=%u003cscript%u003ealert(1)").await;
    assert!(hit(&query, "FE-XSS-001"), "hits={:?}", hits(&query));

    let upper = scan_query(&plugin, "q=%U003Cscript%U003E").await;
    assert!(hit(&upper, "FE-XSS-001"), "hits={:?}", hits(&upper));

    let form = scan_body(
        &plugin,
        "application/x-www-form-urlencoded",
        b"comment=%u003cscript%u003ealert(1)%u003c/script%u003e",
    )
    .await;
    assert!(hit(&form, "FE-XSS-001-B"), "hits={:?}", hits(&form));

    // A `%u` that is not followed by four hex digits is ordinary text.
    let benign = scan_query(&plugin, "discount=15%25+off&unit=100%u").await;
    assert!(!hit(&benign, "FE-XSS-001"), "hits={:?}", hits(&benign));
}

#[tokio::test]
async fn percent_encoded_cookie_values_are_scanned_after_decoding() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "include_default_rules": false,
        "scan_budget_ms": 0,
        "custom_rules": [{
            "id": "CK-XSS",
            "category": "xss",
            "target": "cookies",
            "match_kind": "contains",
            "pattern": "<script"
        }]
    }))
    .unwrap();

    for cookie in [
        "theme=dark; pref=%3Cscript%3Ealert(1)%3C/script%3E",
        "pref=%253Cscript%253E",
        "pref=%u003cscript%u003e",
        // The raw crumb is still scanned for backends that do not decode.
        "pref=<script>alert(1)</script>",
    ] {
        let (_, request) = scan_cookie(&plugin, cookie).await;
        assert!(
            hit(&request, "CK-XSS"),
            "{cookie:?} must be recognised; hits={:?}",
            hits(&request)
        );
    }

    let (_, benign) = scan_cookie(
        &plugin,
        "_ga=GA1.2.1234567890.1700000000; blob=YWJj+ZGVm/Z2hp==; locale=en%2DUS",
    )
    .await;
    assert!(!hit(&benign, "CK-XSS"), "hits={:?}", hits(&benign));
}

#[tokio::test]
async fn encoded_cookie_control_characters_reach_the_built_in_cookie_rule() {
    let plugin = monitor_waf();
    // `%0d%0a` in a decoded cookie value is a header-splitting primitive for
    // any application that reflects the value into `Set-Cookie`.
    let (_, request) = scan_cookie(&plugin, "lang=en%0d%0aSet-Cookie:%20admin=1").await;
    assert!(hit(&request, "FE-COOKIE-001"), "hits={:?}", hits(&request));

    let (_, benign) = scan_cookie(&plugin, "lang=en-US; tz=Europe%2FBerlin").await;
    assert!(!hit(&benign, "FE-COOKIE-001"), "hits={:?}", hits(&benign));
}

#[tokio::test]
async fn an_encoded_semicolon_cannot_forge_an_extra_cookie_crumb() {
    // An anchored cookie rule sees each crumb on its own. Decoding happens
    // after the split, so `%3B` stays inside the crumb it was sent in rather
    // than starting a new one.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "scan_budget_ms": 0,
        "custom_rules": [{
            "id": "CK-ADMIN",
            "category": "custom",
            "target": "cookies",
            "pattern": "^role=admin$",
            "action": "enforce"
        }]
    }))
    .unwrap();

    let (forged, request) = scan_cookie(&plugin, "session=1%3Brole=admin").await;
    assert!(
        matches!(forged, PluginResult::Continue),
        "hits={:?}",
        hits(&request)
    );

    let (real, _) = scan_cookie(&plugin, "session=1; role=admin").await;
    assert!(matches!(real, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn backslash_runs_alone_do_not_raise_a_residual_encoding_signal() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "scan_budget_ms": 0,
        "rule_modes": { "FE-ENCODING-001": "enforce" }
    }))
    .unwrap();

    // A run of backslashes halves on every decode round, so ordinary
    // backslash-heavy text is still "changing" at the round cap. None of it
    // hides a percent, `\u` / `\x`, or entity layer.
    let quote_4x = format!(r#"{{"v":"{}"ok"}}"#, "\\".repeat(15));
    let unc_2x = format!(
        r#"{{"cfg":"{{\"share\":\"{}new-host{}share\"}}"}}"#,
        "\\".repeat(8),
        "\\".repeat(8)
    );
    let latex = format!(r#"{{"tex":"a{}newline b"}}"#, "\\".repeat(16));
    let regex = format!(r#"{{"re":"^{}d+$"}}"#, "\\".repeat(16));
    for body in [quote_4x, unc_2x, latex, regex] {
        let request = scan_body(&plugin, "application/json", body.as_bytes()).await;
        assert!(
            !hit(&request, "FE-ENCODING-001"),
            "{body:?} must not be flagged as residual encoding; hits={:?}",
            hits(&request)
        );
    }

    // A real code-point escape still pending behind the backslash layers at
    // the cap, and a deep percent or entity stack, remain residuals.
    let deep_unicode = format!(r#"{{"v":"{}u003cscript"}}"#, "\\".repeat(8));
    for body in [
        deep_unicode.as_bytes(),
        b"q=%2525253Cscript%2525253E".as_slice(),
        b"q=&amp;amp;amp;lt;script&amp;amp;amp;gt;".as_slice(),
    ] {
        let request = scan_body(&plugin, "text/plain", body).await;
        assert!(
            hit(&request, "FE-ENCODING-001"),
            "{:?} must be flagged; hits={:?}",
            String::from_utf8_lossy(body),
            hits(&request)
        );
    }
}

#[tokio::test]
async fn cookie_views_decode_percent_escapes_only() {
    let plugin = monitor_waf();
    // Express `j:` JSON cookie whose string holds `\n` (percent-encoded as
    // `%5Cn`): the application reads a backslash and an `n`, never a LF.
    let (_, json_cookie) = scan_cookie(&plugin, "prefs=j%3A%7B%22m%22%3A%22a%5Cnb%22%7D").await;
    assert!(
        !hit(&json_cookie, "FE-COOKIE-001"),
        "hits={:?}",
        hits(&json_cookie)
    );
    // An HTML numeric entity is not a cookie encoding either.
    let (_, entity_cookie) = scan_cookie(&plugin, "note=a&#10;b").await;
    assert!(
        !hit(&entity_cookie, "FE-COOKIE-001"),
        "hits={:?}",
        hits(&entity_cookie)
    );

    // Percent-encoded control characters, single or layered, still reach the
    // rule, as does a raw one.
    for cookie in ["lang=en%0Ab", "lang=en%250Ab", "lang=en%u000Ab"] {
        let (_, request) = scan_cookie(&plugin, cookie).await;
        assert!(
            hit(&request, "FE-COOKIE-001"),
            "{cookie:?} must be recognised; hits={:?}",
            hits(&request)
        );
    }
}

#[tokio::test]
async fn percent_encoded_plus_decodes_to_plus_not_space() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "include_default_rules": false,
        "scan_budget_ms": 0,
        "custom_rules": [{
            "id": "Q-SSTI",
            "category": "custom",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "{{7+7}}"
        }]
    }))
    .unwrap();

    // A form decoder turns `%2B` / `%u002B` into `+`; only a literal `+` is a
    // space.
    for query in ["q=%7B%7B7%2B7%7D%7D", "q=%7B%7B7%u002B7%7D%7D"] {
        let request = scan_query(&plugin, query).await;
        assert!(
            hit(&request, "Q-SSTI"),
            "{query:?} must decode to `{{{{7+7}}}}`; hits={:?}",
            hits(&request)
        );
    }

    let benign = scan_query(&plugin, "q=%7B%7B7+7%7D%7D").await;
    assert!(!hit(&benign, "Q-SSTI"), "hits={:?}", hits(&benign));
}

#[tokio::test]
async fn json_path_values_are_not_json_unescaped_twice() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "include_default_rules": false,
        "scan_budget_ms": 0,
        "custom_rules": [
            {
                "id": "JP-LF",
                "category": "custom",
                "target": { "type": "body_json_path", "path": "path" },
                "pattern": "[\\r\\n]"
            },
            {
                "id": "JP-XSS",
                "category": "custom",
                "target": { "type": "body_json_path", "path": "path" },
                "match_kind": "contains",
                "pattern": "<script"
            }
        ]
    }))
    .unwrap();

    // The parser yields `C:\new` — a backslash and an `n`, not a line feed.
    let benign = scan_body(&plugin, "application/json", br#"{"path":"C:\\new"}"#).await;
    assert!(!hit(&benign, "JP-LF"), "hits={:?}", hits(&benign));

    // A JSON `\n` IS a line feed in the parsed value.
    let lf = scan_body(&plugin, "application/json", br#"{"path":"a\nb"}"#).await;
    assert!(hit(&lf, "JP-LF"), "hits={:?}", hits(&lf));

    // A code-point escape left in the parsed value still gets the second,
    // application-level decode.
    let xss = scan_body(
        &plugin,
        "application/json",
        br#"{"path":"\\u003cscript\\u003e"}"#,
    )
    .await;
    assert!(hit(&xss, "JP-XSS"), "hits={:?}", hits(&xss));
}
