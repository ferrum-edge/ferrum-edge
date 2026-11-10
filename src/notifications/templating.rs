//! `${var}` template substitution for notification payloads.
//!
//! Simple, allocation-conscious renderer used by the generic webhook channel
//! and any other caller that needs operator-supplied templates with bounded
//! variable injection.
//!
//! Syntax:
//! - `${name}` — replaced with the value of `name` from the supplied map.
//! - `$$`     — literal `$`.
//! - Unknown variables are left as `${name}` in the output (so operators can
//!   spot typos in real payloads). [`validate_template`] checks only that
//!   braces are balanced; it does not report unknown variables.
//!
//! Errors:
//! - Unbalanced `${` (no matching `}`) is a hard error from
//!   [`render_template`] / [`render_template_bounded`] / [`validate_template`].
//! - An unsupported escape (e.g. `$x` where `x` is not `$` or `{`) is left
//!   as-is — `$` followed by a non-special character is common in templates.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Render `template` by substituting `${var}` placeholders from `vars`.
///
/// Returns `Err` only on unbalanced `${`. Unknown variable names are passed
/// through unmodified so misconfigured templates remain auditable.
pub fn render_template(template: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    render_template_with(template, vars, |value, out| out.push_str(value))
}

/// Render `template` while keeping the output at or under `max_bytes`.
///
/// Unlike [`render_template`], this never lets intermediate output grow in
/// proportion to a value that is repeated many times: each literal and each
/// substitution is appended only while room remains. When the ceiling would be
/// exceeded, the output is truncated on a UTF-8 boundary and `marker` is
/// appended so the truncation stays visible. The returned string is always
/// `<= max_bytes` (and may be slightly under when a multi-byte codepoint sits
/// on the boundary).
///
/// Returns `Err` only on unbalanced `${`. Unknown variable names are passed
/// through unmodified (still subject to the byte ceiling).
pub fn render_template_bounded(
    template: &str,
    vars: &HashMap<String, String>,
    max_bytes: usize,
    marker: &str,
) -> Result<String, String> {
    // A bounded render may stop emitting before it reaches the end of the
    // template, but malformed operator syntax must still fail consistently.
    validate_template(template)?;
    let mut out = String::with_capacity(template.len().min(max_bytes));
    let mut i = 0;
    while i < template.len() {
        if out.len() >= max_bytes {
            // Exact fill with more template remaining — reclaim room for the
            // visible truncation marker.
            apply_truncation_marker(&mut out, max_bytes, marker);
            return Ok(out);
        }
        let rest = &template[i..];
        if rest.starts_with("$$") {
            if push_char_bounded(&mut out, '$', max_bytes, marker) {
                return Ok(out);
            }
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced '${{' starting at byte offset {}", i)
            })?;
            let name = &after_open[..close];
            let truncated = if let Some(value) = vars.get(name) {
                push_str_bounded(&mut out, value, max_bytes, marker)
            } else {
                // Pass unknown placeholders through, still subject to the ceiling.
                push_str_bounded(&mut out, "${", max_bytes, marker)
                    || push_str_bounded(&mut out, name, max_bytes, marker)
                    || push_str_bounded(&mut out, "}", max_bytes, marker)
            };
            if truncated {
                return Ok(out);
            }
            i += 2 + close + 1;
            continue;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        if push_char_bounded(&mut out, ch, max_bytes, marker) {
            return Ok(out);
        }
        i += ch.len_utf8();
    }
    Ok(out)
}

/// Render `template` while escaping substituted values for placement inside
/// JSON string literals.
///
/// This intentionally emits the escaped string content without surrounding
/// quotes: a template fragment like `"summary":"${reason}"` remains the
/// operator-authored JSON shape while values containing `"`, `\`, newlines, or
/// other control characters cannot break the JSON body.
pub fn render_template_json_string_escaped(
    template: &str,
    vars: &HashMap<String, String>,
) -> Result<String, String> {
    render_template_with(template, vars, push_json_string_content)
}

fn render_template_with<F>(
    template: &str,
    vars: &HashMap<String, String>,
    mut push_value: F,
) -> Result<String, String>
where
    F: FnMut(&str, &mut String),
{
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < template.len() {
        let rest = &template[i..];
        if rest.starts_with("$$") {
            out.push('$');
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced '${{' starting at byte offset {}", i)
            })?;
            let name = &after_open[..close];
            if let Some(value) = vars.get(name) {
                push_value(value, &mut out);
            } else {
                out.push_str("${");
                out.push_str(name);
                out.push('}');
            }
            i += 2 + close + 1;
            continue;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

fn push_json_string_content(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Append `value` while respecting `max_bytes`. On overflow, truncate on a
/// UTF-8 boundary, append `marker`, and return `true` so the caller stops.
fn push_str_bounded(out: &mut String, value: &str, max_bytes: usize, marker: &str) -> bool {
    let remaining = max_bytes.saturating_sub(out.len());
    if value.len() <= remaining {
        out.push_str(value);
        return false;
    }
    let marker = marker_within_budget(marker, max_bytes);
    let content_budget = max_bytes - marker.len();
    if out.len() < content_budget {
        let need = content_budget - out.len();
        let mut end = need.min(value.len());
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        out.push_str(&value[..end]);
    } else {
        truncate_string_to_budget(out, content_budget);
    }
    out.push_str(marker);
    true
}

fn push_char_bounded(out: &mut String, ch: char, max_bytes: usize, marker: &str) -> bool {
    let ch_len = ch.len_utf8();
    if out.len() + ch_len <= max_bytes {
        out.push(ch);
        return false;
    }
    apply_truncation_marker(out, max_bytes, marker);
    true
}

fn apply_truncation_marker(out: &mut String, max_bytes: usize, marker: &str) {
    let marker = marker_within_budget(marker, max_bytes);
    let content_budget = max_bytes - marker.len();
    truncate_string_to_budget(out, content_budget);
    out.push_str(marker);
}

fn marker_within_budget(marker: &str, max_bytes: usize) -> &str {
    let mut end = marker.len().min(max_bytes);
    while end > 0 && !marker.is_char_boundary(end) {
        end -= 1;
    }
    &marker[..end]
}

fn truncate_string_to_budget(out: &mut String, budget: usize) {
    while out.len() > budget {
        out.pop();
    }
}

/// Inspect `template` and return the set of variable names it references
/// (excluding any in `known`). Useful for warning the operator about typos
/// at plugin construction time without aborting startup.
///
/// Returns `Err` on unbalanced `${`.
#[allow(dead_code)] // Public helper for callers that want a one-shot
// "did the operator typo a placeholder?" check at construction.
pub fn unknown_variables(template: &str, known: &HashSet<&str>) -> Result<Vec<String>, String> {
    let mut unknown = Vec::new();
    let mut i = 0;
    while i < template.len() {
        let rest = &template[i..];
        if rest.starts_with("$$") {
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced '${{' starting at byte offset {}", i)
            })?;
            let name = &after_open[..close];
            if !known.contains(name) && !unknown.iter().any(|n: &String| n == name) {
                unknown.push(name.to_string());
            }
            i += 2 + close + 1;
            continue;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        i += ch.len_utf8();
    }
    Ok(unknown)
}

/// Dry-run `template`: returns `Ok(())` when it is well-formed (balanced
/// braces). Unknown variables are NOT errors and are not reported;
/// [`unknown_variables`] can list them, but no production caller uses it.
pub fn validate_template(template: &str) -> Result<(), String> {
    let mut i = 0;
    while i < template.len() {
        let rest = &template[i..];
        if rest.starts_with("$$") {
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced `${{` starting at byte offset {}", i)
            })?;
            i += 2 + close + 1;
            continue;
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        i += ch.len_utf8();
    }
    Ok(())
}
