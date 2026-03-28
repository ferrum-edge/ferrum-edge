use ferrum_gateway::plugins::body_transform::{
    get_nested_value, remove_nested_value, rename_nested_field, set_nested_value,
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
