//! HTTP header parsing helpers shared by proxy and plugins.

use std::collections::HashMap;

pub(crate) fn cache_control_has_directive(value: &str, directive: &str) -> bool {
    let mut segment_start = 0;
    let mut in_quote = false;
    let mut escaped = false;

    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quote && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if ch == ',' && !in_quote {
            if cache_control_segment_has_directive(&value[segment_start..idx], directive) {
                return true;
            }
            segment_start = idx + ch.len_utf8();
        }
    }

    cache_control_segment_has_directive(&value[segment_start..], directive)
}

fn cache_control_segment_has_directive(segment: &str, directive: &str) -> bool {
    let segment = segment.trim();
    let directive_name = segment
        .split_once('=')
        .map(|(name, _)| name.trim())
        .unwrap_or(segment);
    directive_name.eq_ignore_ascii_case(directive)
}

pub(crate) fn headers_have_cache_control_directive(
    headers: &HashMap<String, String>,
    directive: &str,
) -> bool {
    headers
        .get("cache-control")
        .is_some_and(|value| cache_control_has_directive(value, directive))
}
