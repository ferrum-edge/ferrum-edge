//! JSON body transformation utilities using dot-notation field paths.
//!
//! Provides helpers for navigating and mutating nested JSON structures
//! using dot-delimited paths (e.g., `"user.address.city"`).
//!
//! Used by `request_transformer` and `response_transformer` plugins to
//! support `target: "body"` rules.

use serde_json::Value;
use tracing::debug;

/// Navigate a dot-notation path and return a reference to the nested value.
///
/// Path segments are split on `.`. Each segment is treated as an object key.
/// Returns `None` if any segment along the path is missing or the parent is
/// not an object.
///
/// # Examples
/// ```ignore
/// // Given: {"user": {"address": {"city": "NYC"}}}
/// get_nested_value(&json, "user.address.city") // => Some(&Value::String("NYC"))
/// get_nested_value(&json, "user.missing")       // => None
/// ```
pub fn get_nested_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Set a value at a dot-notation path, creating intermediate objects as needed.
///
/// Returns `true` if the value was successfully set, `false` if a non-object
/// node was encountered along the path (e.g., trying to traverse into a string).
///
/// # Examples
/// ```ignore
/// // Given: {"user": {"name": "Alice"}}
/// set_nested_value(&mut json, "user.age", json!(30));
/// // Result: {"user": {"name": "Alice", "age": 30}}
///
/// // Creating intermediate objects:
/// set_nested_value(&mut json, "a.b.c", json!("deep"));
/// // Result: {"a": {"b": {"c": "deep"}}}
/// ```
pub fn set_nested_value(root: &mut Value, path: &str, value: Value) -> bool {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return false;
    }

    let mut current = root;
    // Navigate to parent, creating intermediate objects
    for &segment in &segments[..segments.len() - 1] {
        let Some(obj) = current.as_object_mut() else {
            return false;
        };
        current = obj
            .entry(segment.to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }

    // Set the final key
    if let Some(obj) = current.as_object_mut() {
        obj.insert(segments[segments.len() - 1].to_string(), value);
        true
    } else {
        false
    }
}

/// Remove a value at a dot-notation path.
///
/// Returns the removed value if it existed, `None` otherwise.
/// Does not remove empty parent objects after removal.
///
/// # Examples
/// ```ignore
/// // Given: {"user": {"name": "Alice", "age": 30}}
/// remove_nested_value(&mut json, "user.age");
/// // Result: {"user": {"name": "Alice"}}
/// ```
pub fn remove_nested_value(root: &mut Value, path: &str) -> Option<Value> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return None;
    }

    let mut current = root;
    // Navigate to parent
    for &segment in &segments[..segments.len() - 1] {
        current = current.as_object_mut()?.get_mut(segment)?;
    }

    // Remove the final key
    current
        .as_object_mut()?
        .remove(segments[segments.len() - 1])
}

/// Rename a field at a dot-notation path.
///
/// Both `old_path` and `new_path` use dot notation. The value is removed from
/// `old_path` and inserted at `new_path`, creating intermediate objects for the
/// new path as needed.
///
/// Returns `true` if the rename was performed, `false` if the old path didn't
/// exist or wasn't reachable.
///
/// # Examples
/// ```ignore
/// // Given: {"user": {"first_name": "Alice"}}
/// rename_nested_field(&mut json, "user.first_name", "user.given_name");
/// // Result: {"user": {"given_name": "Alice"}}
///
/// // Moving across nesting levels:
/// rename_nested_field(&mut json, "old.nested.key", "new_location");
/// ```
pub fn rename_nested_field(root: &mut Value, old_path: &str, new_path: &str) -> bool {
    if let Some(value) = remove_nested_value(root, old_path) {
        set_nested_value(root, new_path, value)
    } else {
        false
    }
}

/// Represents a parsed body transformation rule.
#[derive(Debug, Clone)]
pub struct BodyRule {
    pub operation: BodyOperation,
    /// Dot-notation path to the field (e.g., "user.address.city").
    pub key: String,
    /// Value for add/update operations (JSON string that will be parsed,
    /// or a raw string that becomes a JSON string value).
    pub value: Option<Value>,
    /// New dot-notation path for rename operations.
    pub new_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BodyOperation {
    Add,
    Update,
    Remove,
    Rename,
}

/// Parse body rules from the plugin config's rules array.
///
/// Only extracts rules with `"target": "body"`. Each rule must have:
/// - `operation`: "add", "update", "remove", or "rename"
/// - `key`: dot-notation field path
/// - `value` (for add/update): a JSON value or string
/// - `new_key` (for rename): new dot-notation field path
pub fn parse_body_rules(config: &Value) -> Vec<BodyRule> {
    config["rules"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let target = r["target"].as_str()?;
                    if target != "body" {
                        return None;
                    }

                    let operation = match r["operation"].as_str()? {
                        "add" => BodyOperation::Add,
                        "update" => BodyOperation::Update,
                        "remove" => BodyOperation::Remove,
                        "rename" => BodyOperation::Rename,
                        _ => return None,
                    };

                    let key = r["key"].as_str()?.to_string();

                    // Parse value: try as JSON first, fall back to string
                    let value = r.get("value").map(|v| {
                        if let Some(s) = v.as_str() {
                            // Try parsing the string as JSON (e.g., "42" → Number,
                            // "true" → Bool, "{\"a\":1}" → Object).
                            // If it doesn't parse, keep it as a JSON string value.
                            serde_json::from_str(s).unwrap_or_else(|_| v.clone())
                        } else {
                            v.clone()
                        }
                    });

                    let new_key = r["new_key"].as_str().map(String::from);

                    Some(BodyRule {
                        operation,
                        key,
                        value,
                        new_key,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Apply body transformation rules to a JSON body.
///
/// Parses `body` as JSON, applies rules in order, and returns the serialized
/// result. Returns `None` if:
/// - The body is not valid JSON
/// - No rules matched or changed anything
///
/// Content-type is checked by the caller — this function assumes JSON input.
pub fn apply_body_rules(body: &[u8], rules: &[BodyRule]) -> Option<Vec<u8>> {
    if rules.is_empty() || body.is_empty() {
        return None;
    }

    let mut json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            debug!("body_transform: failed to parse body as JSON: {}", e);
            return None;
        }
    };

    let mut modified = false;

    for rule in rules {
        match rule.operation {
            BodyOperation::Add => {
                // Only add if the field doesn't already exist
                if let Some(ref value) = rule.value
                    && get_nested_value(&json, &rule.key).is_none()
                    && set_nested_value(&mut json, &rule.key, value.clone())
                {
                    debug!("body_transform: added field {}", rule.key);
                    modified = true;
                }
            }
            BodyOperation::Update => {
                // Always set the value (overwrite if exists, create if not)
                if let Some(ref value) = rule.value
                    && set_nested_value(&mut json, &rule.key, value.clone())
                {
                    debug!("body_transform: updated field {}", rule.key);
                    modified = true;
                }
            }
            BodyOperation::Remove => {
                if remove_nested_value(&mut json, &rule.key).is_some() {
                    debug!("body_transform: removed field {}", rule.key);
                    modified = true;
                }
            }
            BodyOperation::Rename => {
                if let Some(ref new_key) = rule.new_key
                    && rename_nested_field(&mut json, &rule.key, new_key)
                {
                    debug!("body_transform: renamed field {} -> {}", rule.key, new_key);
                    modified = true;
                }
            }
        }
    }

    if modified {
        match serde_json::to_vec(&json) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                debug!(
                    "body_transform: failed to serialize transformed body: {}",
                    e
                );
                None
            }
        }
    } else {
        None
    }
}

/// Check if a content-type header value indicates JSON.
pub fn is_json_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.contains("application/json") || ct.contains("+json")
}
