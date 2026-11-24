use ferrum_edge::plugins::utils::body_transform::{
    RequestBodyRulesOutcome, apply_request_body_rules, is_event_stream_content_type,
    is_json_content_type, parse_body_rules,
};
use serde_json::{Value, json};

/// Run body `rules` against `document` through the production request path:
/// rule admission ([`parse_body_rules`]) then [`apply_request_body_rules`].
/// `Some(rewritten)` when a rule changed the document, `None` when it was left
/// unchanged.
fn apply(document: &Value, rules: Value) -> Option<Value> {
    let rules = parse_body_rules(&json!({ "rules": rules })).expect("valid body rules");
    let body = serde_json::to_vec(document).expect("serialize document");
    match apply_request_body_rules(&body, &rules) {
        RequestBodyRulesOutcome::Replaced(bytes) => {
            Some(serde_json::from_slice(&bytes).expect("rewritten document is JSON"))
        }
        RequestBodyRulesOutcome::Skipped(_) | RequestBodyRulesOutcome::Unchanged => None,
        RequestBodyRulesOutcome::Ambiguous(reason) => {
            panic!("a serialized `Value` is never ambiguous: {reason}")
        }
    }
}

fn update(document: &Value, key: &str, value: Value) -> Option<Value> {
    apply(
        document,
        json!([{"operation": "update", "target": "body", "key": key, "value": value}]),
    )
}

fn add(document: &Value, key: &str, value: Value) -> Option<Value> {
    apply(
        document,
        json!([{"operation": "add", "target": "body", "key": key, "value": value}]),
    )
}

fn remove(document: &Value, key: &str) -> Option<Value> {
    apply(
        document,
        json!([{"operation": "remove", "target": "body", "key": key}]),
    )
}

fn rename(document: &Value, key: &str, new_key: &str) -> Option<Value> {
    apply(
        document,
        json!([{"operation": "rename", "target": "body", "key": key, "new_key": new_key}]),
    )
}

// ── Path navigation ───────────────────────────────────────────────────────

#[test]
fn test_path_reaches_nested_field() {
    let root = json!({"user": {"name": "Alice"}});
    assert_eq!(remove(&root, "user.name"), Some(json!({"user": {}})));
}

#[test]
fn test_path_to_missing_field_changes_nothing() {
    let root = json!({"user": {"name": "Alice"}});
    assert_eq!(remove(&root, "user.age"), None);
    assert_eq!(update(&root, "user.name.first", json!("A")), None);
}

#[test]
fn test_path_reaches_top_level_field() {
    let root = json!({"name": "Alice"});
    assert_eq!(remove(&root, "name"), Some(json!({})));
}

#[test]
fn test_path_reaches_deep_field() {
    let root = json!({"user": {"address": {"city": "NYC"}}});
    assert_eq!(
        update(&root, "user.address.city", json!("LA")),
        Some(json!({"user": {"address": {"city": "LA"}}}))
    );
}

#[test]
fn test_update_creates_intermediate_objects() {
    assert_eq!(
        update(&json!({}), "a.b.c", json!("deep")),
        Some(json!({"a": {"b": {"c": "deep"}}}))
    );
}

#[test]
fn test_update_overwrites_existing() {
    let root = json!({"user": {"name": "Alice"}});
    assert_eq!(
        update(&root, "user.name", json!("Bob")),
        Some(json!({"user": {"name": "Bob"}}))
    );
}

#[test]
fn test_update_through_non_object_intermediate_changes_nothing() {
    let root = json!({"user": "not_an_object"});
    assert_eq!(update(&root, "user.name", json!("Alice")), None);
}

#[test]
fn test_update_top_level() {
    assert_eq!(
        update(&json!({}), "key", json!(42)),
        Some(json!({"key": 42}))
    );
}

#[test]
fn test_update_on_non_object_root_changes_nothing() {
    assert_eq!(update(&json!("string"), "key", json!(42)), None);
}

#[test]
fn test_add_only_when_absent() {
    let root = json!({"user": {"name": "Alice"}});
    assert_eq!(add(&root, "user.name", json!("Bob")), None);
    assert_eq!(
        add(&root, "user.age", json!(30)),
        Some(json!({"user": {"name": "Alice", "age": 30}}))
    );
}

/// Removing a member keeps the remaining members in their original order.
/// serde_json's `preserve_order` map (enabled in this build) swap-removes,
/// which moved the last member into the removed slot. The kept keys are
/// already sorted, so the expected bytes hold for a sorted map too.
#[test]
fn test_remove_preserves_member_order() {
    for (body, key, expected) in [
        (
            r#"{"debug":true,"id":1,"name":"a","price":2}"#,
            "debug",
            r#"{"id":1,"name":"a","price":2}"#,
        ),
        (
            r#"{"id":1,"internal":true,"name":"a","price":2}"#,
            "internal",
            r#"{"id":1,"name":"a","price":2}"#,
        ),
        (
            r#"{"outer":{"a":1,"drop":0,"b":2,"c":3},"z":0}"#,
            "outer.drop",
            r#"{"outer":{"a":1,"b":2,"c":3},"z":0}"#,
        ),
    ] {
        let rules = parse_body_rules(
            &json!({ "rules": [{"operation": "remove", "target": "body", "key": key}] }),
        )
        .expect("valid body rules");
        match apply_request_body_rules(body.as_bytes(), &rules) {
            RequestBodyRulesOutcome::Replaced(bytes) => assert_eq!(
                String::from_utf8(bytes).expect("UTF-8 body"),
                expected,
                "removing {key:?} must not reorder the remaining members"
            ),
            RequestBodyRulesOutcome::Skipped(_)
            | RequestBodyRulesOutcome::Unchanged
            | RequestBodyRulesOutcome::Ambiguous(_) => {
                panic!("removing {key:?} must rewrite the body")
            }
        }
    }
}

#[test]
fn test_remove_nested_field() {
    let root = json!({"user": {"name": "Alice", "age": 30}});
    assert_eq!(
        remove(&root, "user.age"),
        Some(json!({"user": {"name": "Alice"}}))
    );
}

#[test]
fn test_rename_nested_field() {
    let root = json!({"user": {"first_name": "Alice"}});
    assert_eq!(
        rename(&root, "user.first_name", "user.given_name"),
        Some(json!({"user": {"given_name": "Alice"}}))
    );
}

#[test]
fn test_rename_missing_source_changes_nothing() {
    assert_eq!(
        rename(&json!({"user": {}}), "user.missing", "user.new_key"),
        None
    );
}

#[test]
fn test_rename_across_levels() {
    let root = json!({"old": {"nested": {"key": "val"}}});
    assert_eq!(
        rename(&root, "old.nested.key", "flat_key"),
        Some(json!({"old": {"nested": {}}, "flat_key": "val"}))
    );
}

#[test]
fn test_is_json_content_type() {
    assert!(is_json_content_type("application/json"));
    assert!(is_json_content_type("application/json; charset=utf-8"));
    assert!(is_json_content_type("application/vnd.api+json"));
    assert!(is_json_content_type("application/graphql-response+json"));
    assert!(!is_json_content_type("text/html"));
    assert!(!is_json_content_type("application/xml"));
    assert!(!is_json_content_type("application/jsonp"));
    assert!(!is_json_content_type("application/notjson"));
    assert!(!is_json_content_type("text/application/json"));
    assert!(!is_json_content_type("application/json-seq"));
}

/// Finding #91: simplifying the SSE check to a single `event-stream` substring
/// match must not change behavior — `text/event-stream` (and its parameterized
/// / case-variant forms) still match, and the intentionally-conservative
/// substring match still treats vendor-prefixed SSE types as SSE.
#[test]
fn test_is_event_stream_content_type() {
    assert!(is_event_stream_content_type("text/event-stream"));
    assert!(is_event_stream_content_type(
        "text/event-stream; charset=utf-8"
    ));
    assert!(is_event_stream_content_type("TEXT/EVENT-STREAM"));
    // Substring match is intentional: vendor-prefixed SSE types count too.
    assert!(is_event_stream_content_type(
        "application/vnd.my-event-stream"
    ));
    // Non-SSE types do not match.
    assert!(!is_event_stream_content_type("application/json"));
    assert!(!is_event_stream_content_type("text/plain"));
    assert!(!is_event_stream_content_type(""));
}

#[test]
fn test_is_json_content_type_case_insensitive() {
    // ASCII-insensitive: no allocation needed for mixed-case matches.
    assert!(is_json_content_type("Application/JSON"));
    assert!(is_json_content_type("APPLICATION/VND.API+JSON"));
    assert!(is_json_content_type("Application/JSON; Charset=UTF-8"));
    assert!(!is_json_content_type("TEXT/HTML"));
}

// ── Array indexing ────────────────────────────────────────────────────────

#[test]
fn test_path_indexes_into_arrays() {
    let root = json!({"items": [{"name": "a"}, {"name": "b"}]});
    assert_eq!(
        remove(&root, "items.0.name"),
        Some(json!({"items": [{}, {"name": "b"}]}))
    );
    assert_eq!(
        remove(&root, "items.1.name"),
        Some(json!({"items": [{"name": "a"}, {}]}))
    );
}

#[test]
fn test_path_array_index_out_of_bounds_changes_nothing() {
    let root = json!({"items": [{"name": "a"}]});
    assert_eq!(remove(&root, "items.5.name"), None);
}

#[test]
fn test_update_replaces_array_element() {
    assert_eq!(
        update(&json!({"items": [1, 2, 3]}), "items.1", json!(99)),
        Some(json!({"items": [1, 99, 3]}))
    );
}

#[test]
fn test_update_array_index_out_of_bounds_changes_nothing() {
    // Cannot auto-grow arrays — out-of-bounds index fails.
    assert_eq!(update(&json!({"items": [1, 2]}), "items.5", json!(9)), None);
}

#[test]
fn test_remove_array_element() {
    assert_eq!(
        remove(&json!({"items": [1, 2, 3]}), "items.1"),
        Some(json!({"items": [1, 3]}))
    );
}

// ── Dot escape ────────────────────────────────────────────────────────────

#[test]
fn test_path_with_dot_escape() {
    let root = json!({"weird.key": "v", "a": {"b.c": "nested"}});
    assert_eq!(
        remove(&root, "weird\\.key"),
        Some(json!({"a": {"b.c": "nested"}}))
    );
    assert_eq!(
        remove(&root, "a.b\\.c"),
        Some(json!({"weird.key": "v", "a": {}}))
    );
}

#[test]
fn test_update_with_dot_escape() {
    assert_eq!(
        update(&json!({}), "weird\\.key", json!(42)),
        Some(json!({"weird.key": 42}))
    );
}

// ── Rename rollback ───────────────────────────────────────────────────────

#[test]
fn test_rename_rolls_back_when_destination_is_unreachable() {
    // new_key traverses through a non-object, so the insert fails. The old
    // value must be restored so data isn't lost, and the document is left
    // unchanged.
    let root = json!({"user": {"name": "Alice"}, "count": 7});
    assert_eq!(rename(&root, "user.name", "count.x"), None);
    assert_eq!(
        apply(
            &root,
            json!([
                {"operation": "rename", "target": "body", "key": "user.name", "new_key": "count.x"},
                {"operation": "add", "target": "body", "key": "marker", "value": true}
            ])
        ),
        Some(json!({"user": {"name": "Alice"}, "count": 7, "marker": true})),
        "a failed rename must restore the source before later rules run"
    );
}

#[test]
fn test_rename_new_key_is_prefix_of_old_key() {
    // After removing the deepest leaf, the higher-level value is set by
    // overwriting the parent object. This must not panic or corrupt the tree.
    assert_eq!(
        rename(&json!({"a": {"b": "val"}}), "a.b", "a"),
        Some(json!({"a": "val"}))
    );
}

#[test]
fn test_rename_escaped_dot_in_path() {
    assert_eq!(
        rename(&json!({"weird.key": "val"}), "weird\\.key", "renamed"),
        Some(json!({"renamed": "val"}))
    );
}

// ── Literal-backslash preservation ─────────────────────────────────────────

#[test]
fn test_path_preserves_literal_backslash_in_key() {
    // Only `\.` and `\\` are escapes. Any other `\X` sequence keeps the
    // backslash literally: keys like `device\serial` are valid JSON and
    // appear in real payloads.
    let root = json!({"device\\serial": "abc-123"});
    assert_eq!(remove(&root, "device\\serial"), Some(json!({})));

    let written =
        update(&json!({}), "device\\serial", json!("XYZ")).expect("update writes the literal key");
    assert_eq!(written, json!({"device\\serial": "XYZ"}));
    assert_eq!(
        update(&written, "device\\serial", json!("ABC")),
        Some(json!({"device\\serial": "ABC"}))
    );
}

#[test]
fn test_path_double_backslash_escapes_to_single_backslash() {
    // Path `a\\b` in the raw path string (written `a\\\\b` in Rust source)
    // produces the key `a\b` after escape collapse.
    let written = update(&json!({}), "a\\\\b", json!(42)).expect("update writes the key");
    assert_eq!(written, json!({"a\\b": 42}));
    assert_eq!(remove(&written, "a\\\\b"), Some(json!({})));
}

// ── parse_body_rules strict validation ────────────────────────────────────

#[test]
fn test_body_rules_null_target_rejected() {
    // `"target": null` is an explicit configuration error and must be
    // rejected, not silently skipped. Only absent `target` means "not a body
    // rule — let the caller handle it".
    let config = json!({
        "rules": [
            {"operation": "add", "target": null, "key": "x", "value": "v"}
        ]
    });
    let err = parse_body_rules(&config).expect_err("expected error for null target");
    assert!(err.contains("`target` must be a string"), "got: {err}");
}

#[test]
fn test_body_rules_reject_invalid_rules_container_shapes() {
    for config in [json!({"rules": "not-array"}), json!({"rules": [42]})] {
        let err = parse_body_rules(&config).expect_err("expected invalid rules shape");
        assert!(
            err.contains("`rules` must be an array") || err.contains("rule must be an object"),
            "unexpected error for {config:?}: {err}"
        );
    }
}

#[test]
fn test_body_rules_reject_operation_irrelevant_fields() {
    for (rule, field) in [
        (
            json!({"operation": "add", "target": "body", "key": "x", "value": "v", "new_key": "y"}),
            "`new_key` must not be set",
        ),
        (
            json!({"operation": "update", "target": "body", "key": "x", "value": "v", "new_key": "y"}),
            "`new_key` must not be set",
        ),
        (
            json!({"operation": "remove", "target": "body", "key": "x", "value": null}),
            "`value` must not be set",
        ),
        (
            json!({"operation": "remove", "target": "body", "key": "x", "new_key": "y"}),
            "`new_key` must not be set",
        ),
        (
            json!({"operation": "rename", "target": "body", "key": "x", "new_key": "y", "value": "ignored"}),
            "`value` must not be set",
        ),
    ] {
        let config = json!({ "rules": [rule] });
        let err = parse_body_rules(&config).expect_err("expected irrelevant field rejection");
        assert!(err.contains(field), "expected {field:?}, got: {err}");
    }
}

// ── rename array-index rejection ──────────────────────────────────────────
// `rename` on array indices is ambiguous (move? swap? overwrite?) and the
// forward path combined with `Vec::remove`'s leftward shift silently drops
// data. These rules are rejected at parse time so users fall back to the
// well-defined `remove` + `add` composition instead.

#[test]
fn test_rename_rejects_array_index_in_key() {
    let config = json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "items.0", "new_key": "items.first"}
        ]
    });
    let err = parse_body_rules(&config).expect_err("expected rejection for array index in key");
    assert!(err.contains("does not support array indices"), "got: {err}");
}

#[test]
fn test_rename_rejects_array_index_in_new_key() {
    let config = json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "items.first", "new_key": "items.0"}
        ]
    });
    let err = parse_body_rules(&config).expect_err("expected rejection for array index in new_key");
    assert!(err.contains("does not support array indices"), "got: {err}");
}

#[test]
fn test_rename_rejects_array_index_in_both() {
    let config = json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "items.0", "new_key": "items.1"}
        ]
    });
    let err = parse_body_rules(&config)
        .expect_err("expected rejection when both sides are array indices");
    assert!(err.contains("does not support array indices"), "got: {err}");
}

#[test]
fn test_rename_allows_escaped_numeric_segment() {
    // `counts\.0` is a single key literally named `counts.0` — NOT an array
    // index. The escaped-dot segment must be accepted since there is no
    // ambiguity: both sides are plain object keys.
    let config = json!({
        "rules": [
            {
                "operation": "rename",
                "target": "body",
                "key": "counts\\.0",
                "new_key": "counts\\.1"
            }
        ]
    });
    let rules =
        parse_body_rules(&config).expect("escaped numeric segments must be accepted for rename");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].key, "counts\\.0");
    assert_eq!(rules[0].new_key.as_deref(), Some("counts\\.1"));
}

#[test]
fn test_rename_rejects_deep_array_index() {
    // Numeric segments anywhere in the path must be rejected — not just the
    // terminal segment. Here the ambiguous segment is in the middle of the
    // path.
    let config = json!({
        "rules": [
            {
                "operation": "rename",
                "target": "body",
                "key": "data.items.0.name",
                "new_key": "data.items.0.label"
            }
        ]
    });
    let err = parse_body_rules(&config)
        .expect_err("expected rejection for numeric segment anywhere in the path");
    assert!(err.contains("does not support array indices"), "got: {err}");
}

#[test]
fn parse_body_rules_rejects_empty_path_segments() {
    // Shared by request_transformer and response_transformer: an empty
    // dot-segment would silently read or write a `""` member.
    for key in ["", "a.", ".a", "a..b"] {
        for rule in [
            json!({"operation": "remove", "target": "body", "key": key}),
            json!({"operation": "rename", "target": "body", "key": "a", "new_key": key}),
        ] {
            let error = parse_body_rules(&json!({"rules": [rule]}))
                .expect_err("an empty path segment must be rejected");
            assert!(error.contains("empty path segment"), "{key:?}: {error}");
        }
    }
    assert!(
        parse_body_rules(&json!({"rules": [
            {"operation": "remove", "target": "body", "key": "a\\.b"}
        ]}))
        .is_ok(),
        "an escaped dot is part of one non-empty segment"
    );
}

// ---------------------------------------------------------------------------
// GHSA-pq95-952r-2x32: BOM-prefixed and duplicate-member JSON bodies.
// ---------------------------------------------------------------------------

fn remove_and_rename_rules() -> Vec<ferrum_edge::plugins::utils::body_transform::BodyRule> {
    parse_body_rules(&json!({ "rules": [
        {"operation": "remove", "target": "body", "key": "user.role"},
        {"operation": "rename", "target": "body", "key": "user.token", "new_key": "user.redacted"}
    ]}))
    .expect("valid body rules")
}

/// One leading UTF-8 BOM is stripped before parsing, so `remove` and `rename`
/// apply to a BOM-prefixed document, and the rewrite carries no BOM.
#[test]
fn bom_prefixed_body_has_remove_and_rename_applied_without_the_bom() {
    let mut body = b"\xEF\xBB\xBF".to_vec();
    body.extend_from_slice(br#"{"user":{"role":"admin","token":"t0k","name":"a"}}"#);
    match apply_request_body_rules(&body, &remove_and_rename_rules()) {
        RequestBodyRulesOutcome::Replaced(bytes) => {
            assert!(
                !bytes.starts_with(b"\xEF\xBB\xBF"),
                "the rewrite must not carry the BOM"
            );
            let rewritten: Value = serde_json::from_slice(&bytes).expect("rewrite is JSON");
            assert_eq!(rewritten, json!({"user": {"name": "a", "redacted": "t0k"}}));
        }
        other => panic!("a BOM-prefixed document must be rewritten, got {other:?}"),
    }
}

/// Only ONE BOM is stripped; a second one is document content no JSON parser
/// accepts, so it keeps the ordinary parse-error handling.
#[test]
fn a_second_bom_keeps_parse_error_handling() {
    let mut body = b"\xEF\xBB\xBF\xEF\xBB\xBF".to_vec();
    body.extend_from_slice(br#"{"user":{"role":"admin"}}"#);
    assert!(matches!(
        apply_request_body_rules(&body, &remove_and_rename_rules()),
        RequestBodyRulesOutcome::Skipped(
            ferrum_edge::plugins::utils::body_transform::BodyRulesSkipReason::ParseError
        )
    ));
}

/// A duplicated ANCESTOR key whose earlier occurrence holds the targeted leaf
/// must never come back as "unchanged" (which forwards the original bytes) or
/// as a rewrite of the last-wins collapse: it is ambiguous, with or without a
/// BOM, at any depth.
#[test]
fn duplicate_ancestor_key_is_ambiguous_not_unchanged() {
    for body in [
        br#"{"user":{"role":"admin","token":"t0k"},"user":{"name":"a"}}"#.to_vec(),
        [
            b"\xEF\xBB\xBF".as_slice(),
            br#"{"user":{"role":"admin"},"user":{"name":"a"}}"#.as_slice(),
        ]
        .concat(),
        br#"{"items":[{"user":{"role":"admin"},"user":{}}]}"#.to_vec(),
        // A sibling duplicate elsewhere in the document is just as ambiguous.
        br#"{"user":{"role":"admin"},"a":1,"a":2}"#.to_vec(),
    ] {
        match apply_request_body_rules(&body, &remove_and_rename_rules()) {
            RequestBodyRulesOutcome::Ambiguous(reason) => assert_eq!(
                reason, "JSON body contains duplicate object member names",
                "the reason is the fixed scanner reason"
            ),
            other => panic!(
                "{:?} must be refused as ambiguous, got {other:?}",
                String::from_utf8_lossy(&body)
            ),
        }
    }
}

/// Member names are compared after escape decoding: a literal name and a
/// `\u`-escaped spelling of the same name collide.
#[test]
fn escaped_name_duplicates_collide() {
    for body in [
        br#"{"user":{"role":"admin"},"\u0075ser":{"name":"a"}}"#.as_slice(),
        br#"{"user":{"role":"admin","\u0072ole":"viewer"}}"#.as_slice(),
    ] {
        assert!(
            matches!(
                apply_request_body_rules(body, &remove_and_rename_rules()),
                RequestBodyRulesOutcome::Ambiguous(_)
            ),
            "{:?} must be ambiguous",
            String::from_utf8_lossy(body)
        );
    }
}

/// A lone surrogate escape is accepted by some downstream parsers while
/// `serde_json` rejects it, so it is refused rather than skipped as a parse
/// error that would forward the original bytes.
#[test]
fn invalid_surrogate_escape_is_ambiguous() {
    assert!(matches!(
        apply_request_body_rules(br#"{"user":{"role":"\ud800"}}"#, &remove_and_rename_rules()),
        RequestBodyRulesOutcome::Ambiguous(_)
    ));
}

/// Bytes that are not JSON at all keep their existing parse-error handling.
#[test]
fn non_json_bodies_keep_parse_error_handling() {
    for body in [
        b"role=admin&role=viewer".as_slice(),
        b"<user><role>admin</role></user>".as_slice(),
        br#"{"user":{"role":"admin"},"user":"#.as_slice(),
    ] {
        assert!(
            matches!(
                apply_request_body_rules(body, &remove_and_rename_rules()),
                RequestBodyRulesOutcome::Skipped(
                    ferrum_edge::plugins::utils::body_transform::BodyRulesSkipReason::ParseError
                )
            ),
            "{:?} must keep parse-error handling",
            String::from_utf8_lossy(body)
        );
    }
}

/// An unambiguous document is still rewritten exactly as before.
#[test]
fn unambiguous_document_is_still_rewritten() {
    match apply_request_body_rules(
        br#"{"user":{"role":"admin","token":"t0k"},"users":[{"role":1},{"role":2}]}"#,
        &remove_and_rename_rules(),
    ) {
        RequestBodyRulesOutcome::Replaced(bytes) => {
            let rewritten: Value = serde_json::from_slice(&bytes).expect("rewrite is JSON");
            assert_eq!(
                rewritten,
                json!({"user": {"redacted": "t0k"}, "users": [{"role": 1}, {"role": 2}]})
            );
        }
        other => panic!("an unambiguous document must be rewritten, got {other:?}"),
    }
}

/// A unique-member document nested between `serde_json`'s 128-level recursion
/// limit and the duplicate-key screen's 256-level budget is well-formed JSON a
/// downstream parser may accept, so it must be refused rather than skipped as a
/// parse error that forwards the original bytes — with or without a BOM.
#[test]
fn well_formed_document_serde_cannot_materialize_is_refused() {
    use ferrum_edge::plugins::utils::body_transform::UNMATERIALIZABLE_JSON_REASON;

    let deep = [
        br#"{"user":{"role":"admin"},"deep":"#.as_slice(),
        "[".repeat(200).as_bytes(),
        "]".repeat(200).as_bytes(),
        b"}".as_slice(),
    ]
    .concat();
    for body in [deep.clone(), [b"\xEF\xBB\xBF".as_slice(), &deep].concat()] {
        match apply_request_body_rules(&body, &remove_and_rename_rules()) {
            RequestBodyRulesOutcome::Ambiguous(reason) => {
                assert_eq!(reason, UNMATERIALIZABLE_JSON_REASON)
            }
            other => {
                panic!("a well-formed unmaterializable document must be refused, got {other:?}")
            }
        }
    }
}
