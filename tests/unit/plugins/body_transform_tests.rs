use ferrum_edge::plugins::utils::body_transform::{
    get_nested_value, is_json_content_type, remove_nested_value, rename_nested_field,
    set_nested_value,
};
use serde_json::json;

#[test]
fn test_get_nested_value_simple() {
    let root = json!({"user": {"name": "Alice"}});
    assert_eq!(get_nested_value(&root, "user.name"), Some(&json!("Alice")));
}

#[test]
fn test_get_nested_value_missing() {
    let root = json!({"user": {"name": "Alice"}});
    assert_eq!(get_nested_value(&root, "user.age"), None);
}

#[test]
fn test_get_nested_value_top_level() {
    let root = json!({"name": "Alice"});
    assert_eq!(get_nested_value(&root, "name"), Some(&json!("Alice")));
}

#[test]
fn test_set_nested_value_creates_intermediate_objects() {
    let mut root = json!({});
    assert!(set_nested_value(&mut root, "a.b.c", json!("deep")));
    assert_eq!(root, json!({"a": {"b": {"c": "deep"}}}));
}

#[test]
fn test_set_nested_value_overwrites_existing() {
    let mut root = json!({"user": {"name": "Alice"}});
    assert!(set_nested_value(&mut root, "user.name", json!("Bob")));
    assert_eq!(root, json!({"user": {"name": "Bob"}}));
}

#[test]
fn test_set_nested_value_returns_false_for_non_object_intermediate() {
    let mut root = json!({"user": "not_an_object"});
    assert!(!set_nested_value(&mut root, "user.name", json!("Alice")));
}

#[test]
fn test_set_nested_value_top_level() {
    let mut root = json!({});
    assert!(set_nested_value(&mut root, "key", json!(42)));
    assert_eq!(root, json!({"key": 42}));
}

#[test]
fn test_set_nested_value_returns_false_for_non_object_root() {
    let mut root = json!("string");
    assert!(!set_nested_value(&mut root, "key", json!(42)));
}

#[test]
fn test_remove_nested_value() {
    let mut root = json!({"user": {"name": "Alice", "age": 30}});
    let removed = remove_nested_value(&mut root, "user.age");
    assert_eq!(removed, Some(json!(30)));
    assert_eq!(root, json!({"user": {"name": "Alice"}}));
}

#[test]
fn test_remove_nested_value_missing() {
    let mut root = json!({"user": {"name": "Alice"}});
    assert_eq!(remove_nested_value(&mut root, "user.age"), None);
}

#[test]
fn test_rename_nested_field() {
    let mut root = json!({"user": {"first_name": "Alice"}});
    assert!(rename_nested_field(
        &mut root,
        "user.first_name",
        "user.given_name"
    ));
    assert_eq!(root, json!({"user": {"given_name": "Alice"}}));
}

#[test]
fn test_rename_nested_field_missing_source() {
    let mut root = json!({"user": {}});
    assert!(!rename_nested_field(
        &mut root,
        "user.missing",
        "user.new_key"
    ));
}

#[test]
fn test_get_nested_value_deep() {
    let root = json!({"user": {"address": {"city": "NYC"}}});
    assert_eq!(
        get_nested_value(&root, "user.address.city"),
        Some(&json!("NYC"))
    );
}

#[test]
fn test_rename_across_levels() {
    let mut root = json!({"old": {"nested": {"key": "val"}}});
    assert!(rename_nested_field(&mut root, "old.nested.key", "flat_key"));
    assert_eq!(root, json!({"old": {"nested": {}}, "flat_key": "val"}));
}

#[test]
fn test_is_json_content_type() {
    assert!(is_json_content_type("application/json"));
    assert!(is_json_content_type("application/json; charset=utf-8"));
    assert!(is_json_content_type("application/vnd.api+json"));
    assert!(!is_json_content_type("text/html"));
    assert!(!is_json_content_type("application/xml"));
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
fn test_get_nested_value_array_index() {
    let root = json!({"items": [{"name": "a"}, {"name": "b"}]});
    assert_eq!(get_nested_value(&root, "items.0.name"), Some(&json!("a")));
    assert_eq!(get_nested_value(&root, "items.1.name"), Some(&json!("b")));
}

#[test]
fn test_get_nested_value_array_index_out_of_bounds() {
    let root = json!({"items": [{"name": "a"}]});
    assert_eq!(get_nested_value(&root, "items.5.name"), None);
}

#[test]
fn test_set_nested_value_replaces_array_element() {
    let mut root = json!({"items": [1, 2, 3]});
    assert!(set_nested_value(&mut root, "items.1", json!(99)));
    assert_eq!(root, json!({"items": [1, 99, 3]}));
}

#[test]
fn test_set_nested_value_array_index_out_of_bounds_fails() {
    let mut root = json!({"items": [1, 2]});
    // Cannot auto-grow arrays — out-of-bounds index fails.
    assert!(!set_nested_value(&mut root, "items.5", json!(9)));
    assert_eq!(root, json!({"items": [1, 2]}));
}

#[test]
fn test_remove_nested_value_array_element() {
    let mut root = json!({"items": [1, 2, 3]});
    assert_eq!(remove_nested_value(&mut root, "items.1"), Some(json!(2)));
    assert_eq!(root, json!({"items": [1, 3]}));
}

// ── Dot escape ────────────────────────────────────────────────────────────

#[test]
fn test_get_nested_value_with_dot_escape() {
    let root = json!({"weird.key": "v", "a": {"b.c": "nested"}});
    assert_eq!(get_nested_value(&root, "weird\\.key"), Some(&json!("v")));
    assert_eq!(get_nested_value(&root, "a.b\\.c"), Some(&json!("nested")));
}

#[test]
fn test_set_nested_value_with_dot_escape() {
    let mut root = json!({});
    assert!(set_nested_value(&mut root, "weird\\.key", json!(42)));
    assert_eq!(root, json!({"weird.key": 42}));
}

// ── Rename rollback ───────────────────────────────────────────────────────

#[test]
fn test_rename_nested_field_rollback_on_set_failure() {
    // new_path traverses through a non-object ⇒ set_nested_value fails.
    // The old value must be restored so data isn't lost.
    let mut root = json!({"user": {"name": "Alice"}, "count": 7});
    // "count" is a number — navigating through "count.x" fails.
    assert!(!rename_nested_field(&mut root, "user.name", "count.x"));
    // Alice must still be at user.name after rollback.
    assert_eq!(get_nested_value(&root, "user.name"), Some(&json!("Alice")));
}

#[test]
fn test_rename_nested_field_array_rollback_preserves_ordering() {
    // Regression: `remove_nested_value` calls `Vec::remove(idx)` which shifts
    // elements leftward. The rollback must use `Vec::insert(idx, value)` to
    // reverse that shift — restoring via `set_nested_value` would OVERWRITE
    // the element that got shifted into the vacated slot, losing data.
    //
    // Setup: rename items.0 -> count.x. `count` is a number so the set fails,
    // triggering rollback. Before this fix, A would overwrite B (the
    // previously-shifted neighbor) and the array would become [A, C] instead
    // of the original [A, B, C].
    let mut root = json!({"items": ["A", "B", "C"], "count": 7});
    assert!(!rename_nested_field(&mut root, "items.0", "count.x"));
    // The array must be byte-for-byte identical to the pre-rename state.
    assert_eq!(root["items"], json!(["A", "B", "C"]));
    assert_eq!(root["count"], json!(7));
}

#[test]
fn test_rename_nested_field_array_rollback_middle_index() {
    // Same regression but removing from the middle of the array to catch
    // off-by-one bugs in the rollback insert index.
    let mut root = json!({"nums": [10, 20, 30, 40]});
    assert!(!rename_nested_field(&mut root, "nums.2", "nums.0.never"));
    assert_eq!(root["nums"], json!([10, 20, 30, 40]));
}

#[test]
fn test_rename_nested_field_object_rollback_preserves_value() {
    // Explicit coverage of the object-key rollback path (counterpart to the
    // array rollback above).
    let mut root = json!({"user": {"name": "Alice"}, "count": 7});
    assert!(!rename_nested_field(&mut root, "user.name", "count.x"));
    assert_eq!(root["user"]["name"], json!("Alice"));
}

#[test]
fn test_rename_nested_field_prefix_overlap_new_path_is_prefix_of_old() {
    // Case where new_path is a prefix of old_path. After removing the deepest
    // leaf, we set the higher-level value, which succeeds by overwriting the
    // parent object. This must not panic or corrupt the tree.
    let mut root = json!({"a": {"b": "val"}});
    // Rename "a.b" -> "a". After removing "a.b", root is {"a": {}}. Then set
    // "a" = "val" succeeds (overwrites the empty object).
    assert!(rename_nested_field(&mut root, "a.b", "a"));
    assert_eq!(root, json!({"a": "val"}));
}

#[test]
fn test_rename_nested_field_escaped_dot_in_path() {
    // Rename a key that contains a literal dot (escaped with backslash). The
    // rollback logic must correctly re-escape the segment when reconstructing
    // the parent path for potential array rollback.
    let mut root = json!({"weird.key": "val"});
    assert!(rename_nested_field(&mut root, "weird\\.key", "renamed"));
    assert_eq!(root, json!({"renamed": "val"}));
}
