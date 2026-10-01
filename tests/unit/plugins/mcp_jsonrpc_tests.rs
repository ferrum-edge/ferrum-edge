//! Tests for the shared MCP JSON-RPC `tools/call` recognizer (issue #5908).

use ferrum_edge::plugins::utils::mcp_jsonrpc::{
    MAX_BATCH_BYTES, MAX_BATCH_ITEM_BYTES, MAX_BATCH_ITEMS, RequestScan,
    content_type_charset_is_utf8, content_type_is_json, for_each_tool_call_arguments_mut,
    has_tool_call, may_carry_tool_call, scan_request_bytes, tool_calls_in_value,
};
use serde_json::{Value, json};

fn tool_call(id: Value, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

fn to_body(document: &Value) -> Vec<u8> {
    serde_json::to_vec(document).expect("serialize")
}

/// One recognized member: its raw id token and, for a call, its tool name.
type Member = (Option<String>, Option<String>);

/// `(batch, members)` of a scan that found tool calls.
fn scanned(body: &[u8]) -> (bool, Vec<Member>) {
    let RequestScan::ToolCalls { batch, members } = scan_request_bytes(body) else {
        panic!("expected tool calls in {}", String::from_utf8_lossy(body));
    };
    let members = members
        .iter()
        .map(|member| {
            let id = member.id.map(|id| id.get().to_string());
            let name = member.tool_call.as_ref().and_then(|call| call.name.clone());
            (id, name)
        })
        .collect();
    (batch, members)
}

fn member(id: Option<&str>, name: Option<&str>) -> Member {
    (id.map(str::to_string), name.map(str::to_string))
}

#[test]
fn singleton_tools_call_is_recognized_with_its_id_name_and_arguments() {
    let body = to_body(&tool_call(json!(7), "pets.getPet", json!({"petId": "7"})));
    let scan = scan_request_bytes(&body);
    let calls: Vec<_> = scan.tool_calls().collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), Some("pets.getPet"));
    let arguments = calls[0].arguments.map(|arguments| arguments.get());
    assert_eq!(arguments, Some(r#"{"petId":"7"}"#));

    let (batch, members) = scanned(&body);
    assert!(!batch);
    assert_eq!(members, vec![member(Some("7"), Some("pets.getPet"))]);
}

#[test]
fn batch_lists_every_member_and_marks_only_tool_calls() {
    let document = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        tool_call(json!("a"), "pets.getPet", json!({})),
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "pets.deletePet"}},
        tool_call(json!(3), "pets.createPet", json!({"body": {}}))
    ]);
    let body = to_body(&document);
    let (batch, members) = scanned(&body);
    assert!(batch);
    let expected = vec![
        member(Some("1"), None),
        member(Some(r#""a""#), Some("pets.getPet")),
        // A notification-form call has no id but is still a call.
        member(None, Some("pets.deletePet")),
        member(Some("3"), Some("pets.createPet")),
    ];
    assert_eq!(members, expected);
    let scan = scan_request_bytes(&body);
    assert_eq!(scan.tool_calls().count(), 3);
}

#[test]
fn escaped_member_names_and_method_are_decoded() {
    let body = br#"{"id":1,"m\u0065thod":"tools\/call","params":{"n\u0061me":"x"}}"#;
    let (batch, members) = scanned(body);
    assert!(!batch);
    assert_eq!(members, vec![member(Some("1"), Some("x"))]);
}

#[test]
fn other_methods_and_non_json_rpc_bodies_carry_no_tool_call() {
    let bodies: [&[u8]; 9] = [
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"tools/call"}]}"#,
        br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
        b"not json at all",
        b"",
        br#"{"method":"tools/call""#,
        br#""tools/call""#,
    ];
    for body in bodies {
        let scan = scan_request_bytes(body);
        assert!(
            matches!(scan, RequestScan::NoToolCall),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn duplicate_member_names_are_uninspectable() {
    let bodies: [&[u8]; 3] = [
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}"#,
        br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping"}]"#,
    ];
    for body in bodies {
        let scan = scan_request_bytes(body);
        assert!(
            matches!(scan, RequestScan::Uninspectable("ambiguous_body")),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn batches_past_the_shared_bounds_are_uninspectable() {
    let members: Vec<Value> = (0..=MAX_BATCH_ITEMS)
        .map(|index| tool_call(json!(index), "pets.getPet", json!({})))
        .collect();
    let body = to_body(&Value::Array(members));
    let scan = scan_request_bytes(&body);
    assert!(matches!(
        scan,
        RequestScan::Uninspectable("batch_too_many_items")
    ));

    let large = "x".repeat(MAX_BATCH_ITEM_BYTES);
    let body = to_body(&json!([tool_call(json!(1), "a", json!({"blob": large}))]));
    let scan = scan_request_bytes(&body);
    assert!(matches!(
        scan,
        RequestScan::Uninspectable("batch_item_too_large")
    ));

    let mut body = to_body(&json!([tool_call(json!(1), "a", json!({}))]));
    body.extend(std::iter::repeat_n(b' ', MAX_BATCH_BYTES));
    let scan = scan_request_bytes(&body);
    assert!(matches!(
        scan,
        RequestScan::Uninspectable("batch_too_large")
    ));
}

#[test]
fn a_batch_at_the_item_bound_is_read_in_full() {
    let members: Vec<Value> = (0..MAX_BATCH_ITEMS)
        .map(|index| tool_call(json!(index), "pets.getPet", json!({})))
        .collect();
    let body = to_body(&Value::Array(members));
    let (batch, members) = scanned(&body);
    assert!(batch);
    assert_eq!(members.len(), MAX_BATCH_ITEMS);
}

#[test]
fn mcp_json_media_types_match_mcp_gateway_admission() {
    for accepted in [
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/json-rpc",
        "application/vnd.api+json",
        "application/vnd.audit+JSON",
    ] {
        assert!(content_type_is_json(accepted), "{accepted}");
    }
    for refused in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "application/jsonx",
    ] {
        assert!(!content_type_is_json(refused), "{refused}");
    }
}

#[test]
fn only_utf8_charsets_are_admitted() {
    for accepted in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON; Charset=UTF-8",
        "application/json;charset=\"utf-8\"",
        "application/json ; charset = utf8",
        "application/json; profile=x",
    ] {
        assert!(content_type_charset_is_utf8(accepted), "{accepted}");
    }
    for refused in [
        "application/json; charset=utf-7",
        "application/json; charset=UTF-16LE",
        "application/json; charset=iso-8859-1",
        "application/json; charset=\"utf-7\"",
        "application/json; charset=",
        "application/json; charset=\"utf-8",
        "application/json; charset=utf-8; charset=utf-7",
    ] {
        assert!(!content_type_charset_is_utf8(refused), "{refused}");
    }
}

fn utf16_be(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn utf32(text: &str, encode: fn(u32) -> [u8; 4]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for character in text.chars() {
        bytes.extend(encode(u32::from(character)));
    }
    bytes
}

#[test]
fn lenient_tool_call_prefilter_flags_encodings_comments_and_json5_whitespace() {
    let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
    let mut flagged: Vec<Vec<u8>> = vec![
        call.as_bytes().to_vec(),
        format!("\u{feff}{call}").into_bytes(),
        format!("/*x*/{call}").into_bytes(),
        format!("# x\n{call}").into_bytes(),
        format!("\x0B{call}").into_bytes(),
        format!("\x0C{call}").into_bytes(),
        format!("\u{a0}{call}").into_bytes(),
        format!("\u{2028}{call}").into_bytes(),
        format!(" \u{feff}{call}").into_bytes(),
        br#"{"m":"t\u006fols/call"}"#.to_vec(),
    ];
    flagged.push(call.encode_utf16().flat_map(u16::to_le_bytes).collect());
    let mut utf16_bom = vec![0xFE, 0xFF];
    utf16_bom.extend(call.encode_utf16().flat_map(u16::to_be_bytes));
    flagged.push(utf16_bom);
    // Without a BOM: UTF-16BE (`00 7B`) and UTF-32 in either byte order.
    flagged.push(utf16_be(r#"{"method":"tools/call"}"#));
    flagged.push(utf32(call, u32::to_le_bytes));
    flagged.push(utf32(call, u32::to_be_bytes));
    for body in &flagged {
        assert!(may_carry_tool_call(body), "{body:?}");
    }
    // The last two are binary uploads (JPEG and PNG magic): a high byte that
    // does not open a valid UTF-8 character is not JSON5 whitespace, and NUL
    // bytes count only ahead of a JSON-shaped lead character.
    let unflagged: [&[u8]; 6] = [
        b"",
        b"petId=7",
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"n":NaN"#,
        b"AAAAAAJ7fQ==",
        b"\xFF\xD8\xFF\xE0",
        b"\x89PNG\r\n\x1A\n\x00\x00\x00\x0DIHDR",
    ];
    for body in unflagged {
        assert!(!may_carry_tool_call(body), "{body:?}");
    }
}

#[test]
fn parsed_documents_expose_every_tool_call_and_its_arguments() {
    let mut document = json!([
        tool_call(json!(1), "a", json!({"secret": "one"})),
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"arguments": {"x": 1}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "b"}},
        tool_call(json!(4), "c", json!({"secret": "two"}))
    ]);
    assert!(has_tool_call(&document));
    let calls = tool_calls_in_value(&document);
    let names: Vec<Option<&str>> = calls.iter().map(|call| call.name).collect();
    assert_eq!(names, vec![Some("a"), Some("b"), Some("c")]);
    assert!(calls[1].arguments.is_none());
    assert_eq!(calls[2].id, Some(&json!(4)));

    let mut visited = 0;
    for_each_tool_call_arguments_mut(&mut document, |arguments| {
        visited += 1;
        arguments["secret"] = json!("[REDACTED]");
    });
    assert_eq!(visited, 2, "calls without arguments are skipped");
    assert_eq!(document[0]["params"]["arguments"]["secret"], "[REDACTED]");
    assert_eq!(document[3]["params"]["arguments"]["secret"], "[REDACTED]");
    // A non-call member is never touched, whatever it carries.
    assert_eq!(document[1]["params"]["arguments"], json!({"x": 1}));

    let mut singleton = tool_call(json!(9), "d", json!({"secret": "three"}));
    for_each_tool_call_arguments_mut(&mut singleton, |arguments| {
        arguments["secret"] = json!("[REDACTED]");
    });
    assert_eq!(singleton["params"]["arguments"]["secret"], "[REDACTED]");
    assert!(!has_tool_call(&json!({"method": "tools/list"})));
    assert!(!has_tool_call(&json!("tools/call")));
}
