//! Shared JSON string escape helper used by AI plugins to safely embed
//! user-controlled text inside JSON error response bodies.
//!
//! Escapes JSON string metacharacters, control characters, and the `<`/`>`
//! characters (the latter two as `\u003c` / `\u003e`) so the result is safe
//! to interpolate inside a JSON string literal that may also be served to a
//! browser context.

/// Escape `s` for use inside a JSON string literal.
///
/// Replaces `\` -> `\\`, `"` -> `\"`, JSON control characters, `<` ->
/// `\u003c`, and `>` -> `\u003e`.
pub fn escape_json_string(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            ch if ch < '\u{20}' => {
                escaped.push_str("\\u00");
                let byte = ch as u8;
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_backslash_and_quote() {
        assert_eq!(escape_json_string(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escapes_angle_brackets() {
        assert_eq!(escape_json_string("<script>"), "\\u003cscript\\u003e");
    }

    #[test]
    fn passes_plain_text_through() {
        assert_eq!(escape_json_string("hello world"), "hello world");
    }

    #[test]
    fn escapes_named_json_control_characters() {
        assert_eq!(
            escape_json_string("line\ncarriage\rthing\tback\u{08}form\u{0c}"),
            "line\\ncarriage\\rthing\\tback\\bform\\f"
        );
    }

    #[test]
    fn escapes_all_other_control_characters_as_unicode() {
        let raw: String = (0u8..=0x1f)
            .filter(|b| !matches!(*b, b'\n' | b'\r' | b'\t' | 0x08 | 0x0c))
            .map(char::from)
            .collect();
        let escaped = escape_json_string(&raw);

        assert!(!escaped.chars().any(|ch| ch < '\u{20}'));
        assert!(escaped.contains("\\u0000"));
        assert!(escaped.contains("\\u001f"));
    }

    #[test]
    fn escaped_output_can_be_interpolated_into_json_string() {
        let raw = "bad\"\n<script>\u{00}\u{1f}\\";
        let body = format!(r#"{{"message":"{}"}}"#, escape_json_string(raw));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("escaped string should be valid JSON");

        assert_eq!(parsed["message"], raw);
    }
}
