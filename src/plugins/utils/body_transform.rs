//! JSON body transformation utilities using dot-notation field paths.
//!
//! Provides helpers for navigating and mutating nested JSON structures
//! using dot-delimited paths (e.g., `"user.address.city"`). Supports:
//! - Nested object traversal
//! - Array indexing via numeric segments (`"items.0.name"`)
//! - Dot escape via backslash for keys containing literal dots (`"weird\\.key"`)
//!
//! Used by `request_transformer` and `response_transformer` plugins to
//! support `target: "body"` rules.

use std::borrow::Cow;

use serde_json::{Map, Value};
use tracing::{debug, warn};

// ── Path parsing ──────────────────────────────────────────────────────────

/// Iterator over dot-notation path segments, honoring `\\.` as a literal dot.
///
/// Fast path (no backslashes): zero heap allocation. Segments are borrowed
/// slices of the input path, yielded lazily by [`std::str::Split`].
///
/// Slow path (contains `\\`): one upfront `Vec<String>` allocation for the
/// parsed segments, then iteration over it.
enum PathSegments<'a> {
    Simple(std::str::Split<'a, char>),
    Escaped(std::vec::IntoIter<String>),
}

impl<'a> Iterator for PathSegments<'a> {
    type Item = Cow<'a, str>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PathSegments::Simple(split) => split.next().map(Cow::Borrowed),
            PathSegments::Escaped(vec_iter) => vec_iter.next().map(Cow::Owned),
        }
    }
}

/// Build a path-segment iterator. Picks the zero-alloc fast path when the
/// path contains no `\`.
fn path_segments(path: &str) -> PathSegments<'_> {
    if !path.contains('\\') {
        return PathSegments::Simple(path.split('.'));
    }
    let mut segments: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut escape = false;
    for c in path.chars() {
        if escape {
            buf.push(c);
            escape = false;
        } else if c == '\\' {
            escape = true;
        } else if c == '.' {
            segments.push(std::mem::take(&mut buf));
        } else {
            buf.push(c);
        }
    }
    if escape {
        // Trailing backslash — treat as literal.
        buf.push('\\');
    }
    segments.push(buf);
    PathSegments::Escaped(segments.into_iter())
}

/// Immutable child lookup: works on both objects and arrays (numeric index).
fn child<'a>(parent: &'a Value, segment: &str) -> Option<&'a Value> {
    match parent {
        Value::Object(map) => map.get(segment),
        Value::Array(arr) => segment.parse::<usize>().ok().and_then(|i| arr.get(i)),
        _ => None,
    }
}

/// Mutable child lookup: works on both objects and arrays (numeric index).
fn child_mut<'a>(parent: &'a mut Value, segment: &str) -> Option<&'a mut Value> {
    match parent {
        Value::Object(map) => map.get_mut(segment),
        Value::Array(arr) => segment
            .parse::<usize>()
            .ok()
            .and_then(move |i| arr.get_mut(i)),
        _ => None,
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Navigate a dot-notation path and return a reference to the nested value.
///
/// Path segments are split on `.`. Numeric segments index into arrays; other
/// segments are object keys. `\\.` is treated as a literal `.` in a key.
/// Returns `None` if any segment along the path is missing or the parent node
/// is not an object/array (or index is out of bounds).
pub fn get_nested_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path_segments(path) {
        current = child(current, segment.as_ref())?;
    }
    Some(current)
}

/// Set a value at a dot-notation path, creating intermediate **objects** as
/// needed (arrays are never auto-created — their size is user-controlled).
///
/// Returns `true` if the value was successfully set, `false` if an
/// unreachable node was encountered (non-object intermediate, out-of-bounds
/// array index, or array index that can't be parsed).
pub fn set_nested_value(root: &mut Value, path: &str, value: Value) -> bool {
    set_nested_value_inner(root, path, value).is_ok()
}

/// Internal: set_nested_value that returns the value back on failure so the
/// caller can recover it without an upfront clone.
fn set_nested_value_inner(root: &mut Value, path: &str, value: Value) -> Result<(), Value> {
    let mut iter = path_segments(path).peekable();
    if iter.peek().is_none() {
        return Err(value);
    }
    let mut current = root;
    loop {
        // `peek` above confirmed at least one segment; subsequent iterations
        // only reach this line after `peek().is_some()` on the prior check.
        let segment = match iter.next() {
            Some(s) => s,
            None => return Err(value),
        };
        let seg = segment.as_ref();
        let is_last = iter.peek().is_none();
        if is_last {
            return match current {
                Value::Object(map) => {
                    map.insert(seg.to_string(), value);
                    Ok(())
                }
                Value::Array(arr) => match seg.parse::<usize>() {
                    Ok(idx) if idx < arr.len() => {
                        arr[idx] = value;
                        Ok(())
                    }
                    _ => Err(value),
                },
                _ => Err(value),
            };
        }
        // Intermediate navigation.
        current = match current {
            Value::Object(map) => map
                .entry(seg.to_string())
                .or_insert_with(|| Value::Object(Map::new())),
            Value::Array(arr) => match seg.parse::<usize>() {
                Ok(idx) => match arr.get_mut(idx) {
                    Some(c) => c,
                    None => return Err(value),
                },
                Err(_) => return Err(value),
            },
            _ => return Err(value),
        };
    }
}

/// Remove a value at a dot-notation path.
///
/// Returns the removed value if it existed, `None` otherwise. For arrays,
/// uses `Vec::remove` which shifts subsequent elements.
pub fn remove_nested_value(root: &mut Value, path: &str) -> Option<Value> {
    let mut iter = path_segments(path).peekable();
    iter.peek()?;
    let mut current = root;
    loop {
        let segment = iter.next()?;
        let seg = segment.as_ref();
        if iter.peek().is_none() {
            // Terminal: remove at current.
            return match current {
                Value::Object(map) => map.remove(seg),
                Value::Array(arr) => seg.parse::<usize>().ok().and_then(|i| {
                    if i < arr.len() {
                        Some(arr.remove(i))
                    } else {
                        None
                    }
                }),
                _ => None,
            };
        }
        current = child_mut(current, seg)?;
    }
}

/// Captures how a value was removed so a failed rename can faithfully undo it.
///
/// For object removals, restoration is a plain `map.insert(key, value)` at the
/// same parent — identical to `set_nested_value_inner(old_path, value)`.
///
/// For array removals, restoration MUST use `Vec::insert(idx, value)` to
/// reverse the leftward shift caused by `Vec::remove(idx)`. Using
/// `set_nested_value_inner` here would write into whatever element currently
/// occupies that index (the previously-shifted neighbor), overwriting it and
/// losing data — the exact bug this enum fixes.
enum RemovalContext {
    /// Removed from an object. `old_path` suffices for restoration via
    /// `set_nested_value_inner`, which performs `map.insert(last_segment, v)`.
    Object,
    /// Removed from an array at `parent_path` index `idx`. Restoration must
    /// call `Vec::insert(idx, v)` on the array at `parent_path` to restore the
    /// pre-removal ordering.
    Array { parent_path: String, idx: usize },
}

/// Remove a value at `path` and return both the removed value AND the parent
/// context needed to faithfully restore it.
///
/// This mirrors [`remove_nested_value`] but records whether the removal came
/// from an object key or an array index, along with enough information to
/// reverse the latter.
fn remove_nested_value_with_context(
    root: &mut Value,
    path: &str,
) -> Option<(Value, RemovalContext)> {
    // We need to know the parent path (everything up to the final segment) so
    // that Array rollback can navigate to the same Vec and call insert.
    // Re-walk using the segment iterator so we correctly handle escaped dots.
    let segments: Vec<Cow<'_, str>> = path_segments(path).collect();
    if segments.is_empty() {
        return None;
    }
    let (last_seg, parent_segs) = segments.split_last()?;

    // Navigate to the parent node.
    let mut current: &mut Value = root;
    for seg in parent_segs {
        current = child_mut(current, seg.as_ref())?;
    }

    // Remove at the terminal, recording the context.
    match current {
        Value::Object(map) => {
            let removed = map.remove(last_seg.as_ref())?;
            Some((removed, RemovalContext::Object))
        }
        Value::Array(arr) => {
            let idx = last_seg.as_ref().parse::<usize>().ok()?;
            if idx >= arr.len() {
                return None;
            }
            let removed = arr.remove(idx);
            // Reconstruct the parent path. For the simple (no-escape) case
            // this is the common path; escaped segments already have the
            // backslashes stripped so we rebuild with escape-safe joining.
            let parent_path = join_segments(parent_segs);
            Some((removed, RemovalContext::Array { parent_path, idx }))
        }
        _ => None,
    }
}

/// Re-escape and join segments back into a dot-notation path.
///
/// Any literal dots or backslashes inside a segment are escaped so that
/// subsequent `path_segments()` parses them as a single segment. This is
/// required for rollback fidelity when a segment contains unusual characters.
fn join_segments(segments: &[Cow<'_, str>]) -> String {
    let mut out = String::new();
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        for c in seg.chars() {
            if c == '\\' || c == '.' {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out
}

/// Insert a value at an array index inside the `Vec` located at `parent_path`.
///
/// Returns `Err(value)` if the parent cannot be reached or is not an array, so
/// the caller can still recover the value. Used only by the rollback path.
fn insert_into_array_at(
    root: &mut Value,
    parent_path: &str,
    idx: usize,
    value: Value,
) -> Result<(), Value> {
    // Navigate to parent. An empty parent_path means the array IS the root.
    let mut current: &mut Value = root;
    if !parent_path.is_empty() {
        for seg in path_segments(parent_path) {
            current = match child_mut(current, seg.as_ref()) {
                Some(c) => c,
                None => return Err(value),
            };
        }
    }
    match current {
        Value::Array(arr) => {
            // `idx` came from a successful prior `remove(idx)`, so it is at
            // most the original length; clamp defensively.
            let bounded = idx.min(arr.len());
            arr.insert(bounded, value);
            Ok(())
        }
        _ => Err(value),
    }
}

/// Rename a field at a dot-notation path.
///
/// Both `old_path` and `new_path` use dot notation. The value is removed from
/// `old_path` and inserted at `new_path`, creating intermediate objects as
/// needed.
///
/// If inserting at `new_path` fails (e.g., the destination traverses a
/// non-object node), the value is restored at `old_path` so no data is lost.
/// For array sources, restoration uses `Vec::insert(idx, value)` to reverse
/// the leftward shift caused by `Vec::remove(idx)` — restoring via
/// `set_nested_value_inner` would overwrite the element that was shifted into
/// the vacated slot.
///
/// If restoration itself fails, it means we could no longer reach the parent
/// container (only possible when `new_path` is a strict prefix of `old_path`
/// and the intermediate we depended on was replaced mid-operation — an
/// API-misuse edge case). We log a warning and return `false`.
pub fn rename_nested_field(root: &mut Value, old_path: &str, new_path: &str) -> bool {
    let Some((value, ctx)) = remove_nested_value_with_context(root, old_path) else {
        return false;
    };
    match set_nested_value_inner(root, new_path, value) {
        Ok(()) => true,
        Err(recovered) => {
            // Attempt to restore using the removal context so arrays are
            // restored with insert (preserving ordering) rather than overwrite.
            let restore_result = match &ctx {
                RemovalContext::Object => set_nested_value_inner(root, old_path, recovered),
                RemovalContext::Array { parent_path, idx } => {
                    insert_into_array_at(root, parent_path, *idx, recovered)
                }
            };
            // The rollback path reaches this branch only when the failing
            // `set_nested_value_inner(new_path)` was a no-op: it returns `Err`
            // at the terminal step (non-object/non-array terminal, out-of-bounds
            // array index, or empty path) without mutating the tree, or before
            // the terminal at an intermediate non-object/array-miss (also no
            // mutation). Since the tree between `remove_nested_value_with_context`
            // and here is unchanged apart from the original removal, restoration
            // should always succeed. The `warn!` below exists as a defensive
            // log for any future refactor that breaks this invariant — if it
            // ever fires, that is a bug, not a user error.
            if restore_result.is_err() {
                debug_assert!(
                    false,
                    "body_transform: rename rollback invariant violated for {old_path} -> {new_path}"
                );
                warn!(
                    "body_transform: rename rollback failed for {} -> {}; data lost at {}",
                    old_path, new_path, old_path
                );
            }
            false
        }
    }
}

// ── Rule parsing & application ────────────────────────────────────────────

/// Represents a parsed body transformation rule.
#[derive(Debug, Clone)]
pub struct BodyRule {
    pub operation: BodyOperation,
    /// Dot-notation path to the field (e.g., `"user.address.city"`,
    /// `"items.0.id"`, `"weird\\.key"`).
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
/// Only extracts rules with `"target": "body"`. Each body rule must have:
/// - `operation`: `"add"`, `"update"`, `"remove"`, or `"rename"`
/// - `key`: dot-notation field path
/// - `value` (for add/update): a JSON value or string (required — missing ⇒ error)
/// - `new_key` (for rename): new dot-notation field path (required — missing ⇒ error)
///
/// Returns `Err` with a descriptive message if any body rule is malformed.
/// Rules whose `target` is not `"body"` are silently skipped (they are
/// validated by the caller — the request/response transformer plugins).
pub fn parse_body_rules(config: &Value) -> Result<Vec<BodyRule>, String> {
    let Some(arr) = config["rules"].as_array() else {
        return Ok(Vec::new());
    };

    let mut rules = Vec::new();
    for (idx, r) in arr.iter().enumerate() {
        // `target` is optional — callers (request_transformer) default missing
        // target to "header". But if `target` is PRESENT and not a string, it
        // is a configuration error and must not be silently ignored. Missing
        // `target` or any non-body string target is skipped here — the caller
        // owns validation for non-body rules.
        let target = match r.get("target") {
            Some(Value::String(s)) => s.as_str(),
            Some(Value::Null) | None => continue,
            Some(_) => {
                return Err(format!(
                    "rule[{idx}]: 'target' must be a string (expected header/query/body)"
                ));
            }
        };
        if target != "body" {
            continue;
        }

        let op_str = match r.get("operation") {
            Some(Value::String(s)) => s.as_str(),
            None => {
                return Err(format!(
                    "rule[{idx}]: 'operation' is required for body rules"
                ));
            }
            Some(_) => {
                return Err(format!(
                    "rule[{idx}]: 'operation' must be a string for body rules"
                ));
            }
        };
        let operation = match op_str {
            "add" => BodyOperation::Add,
            "update" => BodyOperation::Update,
            "remove" => BodyOperation::Remove,
            "rename" => BodyOperation::Rename,
            other => {
                return Err(format!(
                    "rule[{idx}]: unknown body operation '{other}' (expected add/update/remove/rename)"
                ));
            }
        };

        let key = match r.get("key") {
            Some(Value::String(s)) => s.clone(),
            None => {
                return Err(format!("rule[{idx}]: 'key' is required for body rules"));
            }
            Some(_) => {
                return Err(format!(
                    "rule[{idx}]: 'key' must be a string for body rules"
                ));
            }
        };

        // Parse value:
        // - Absent key ⇒ None (no value provided).
        // - Explicit JSON null ⇒ Some(Value::Null). Setting a field to null is
        //   a legitimate operation and must be preserved.
        // - String ⇒ parse as JSON first (so "42" → Number, "true" → Bool),
        //   fall back to a plain JSON string on parse failure.
        // - Any other JSON value ⇒ used verbatim.
        let value = r.get("value").map(|v| {
            if let Some(s) = v.as_str() {
                serde_json::from_str(s).unwrap_or_else(|_| v.clone())
            } else {
                v.clone()
            }
        });

        let new_key = match r.get("new_key") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(format!(
                    "rule[{idx}]: 'new_key' must be a string for body rules"
                ));
            }
        };

        // Operation-specific required-field validation.
        match operation {
            BodyOperation::Add | BodyOperation::Update => {
                if value.is_none() {
                    return Err(format!(
                        "rule[{idx}]: body '{op_str}' operation requires a 'value'"
                    ));
                }
            }
            BodyOperation::Rename => {
                if new_key.is_none() {
                    return Err(format!(
                        "rule[{idx}]: body 'rename' operation requires a 'new_key'"
                    ));
                }
            }
            BodyOperation::Remove => {}
        }

        rules.push(BodyRule {
            operation,
            key,
            value,
            new_key,
        });
    }

    Ok(rules)
}

/// Apply body transformation rules to a JSON body.
///
/// Parses `body` as JSON, applies rules in order, and returns the serialized
/// result. Returns `None` if the body is not valid JSON, is empty, or no rule
/// actually changed the body.
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
                // Only add if the field doesn't already exist.
                if let Some(ref value) = rule.value
                    && get_nested_value(&json, &rule.key).is_none()
                    && set_nested_value(&mut json, &rule.key, value.clone())
                {
                    debug!("body_transform: added field {}", rule.key);
                    modified = true;
                }
            }
            BodyOperation::Update => {
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
///
/// Recognizes `application/json` and any `+json` suffix (RFC 6839). ASCII
/// case-insensitive; allocation-free.
pub fn is_json_content_type(content_type: &str) -> bool {
    ascii_contains_ignore_case(content_type, "application/json")
        || ascii_contains_ignore_case(content_type, "+json")
}

/// ASCII-insensitive substring check. Zero allocation.
fn ascii_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() {
        return true;
    }
    if nb.len() > hb.len() {
        return false;
    }
    // Compare byte-by-byte, lowercasing ASCII letters as we go.
    'outer: for start in 0..=(hb.len() - nb.len()) {
        for i in 0..nb.len() {
            if hb[start + i].eq_ignore_ascii_case(&nb[i]) {
                continue;
            }
            continue 'outer;
        }
        return true;
    }
    false
}
