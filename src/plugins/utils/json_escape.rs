//! Shared JSON string escape helper used by AI plugins to safely embed
//! user-controlled text inside JSON error response bodies.
//!
//! Escapes JSON string metacharacters and the `<`/`>` characters (the latter
//! two as `\u003c` / `\u003e`) so the result is safe to interpolate inside a
//! JSON string literal that may also be served to a browser context.

/// Escape `s` for use inside a JSON string literal.
///
/// Escapes `\`, `"`, JSON control characters, `<`, and `>`.
pub fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            ch if ch <= '\u{1f}' => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let value = ch as usize;
                out.push_str("\\u00");
                out.push(HEX[(value >> 4) & 0x0f] as char);
                out.push(HEX[value & 0x0f] as char);
            }
            ch => out.push(ch),
        }
    }
    out
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
    fn escapes_json_control_characters() {
        assert_eq!(
            escape_json_string("a\nb\rc\td\u{08}e\u{0c}f\u{00}g\u{1f}"),
            "a\\nb\\rc\\td\\be\\ff\\u0000g\\u001f"
        );
    }

    #[test]
    fn escaped_output_is_valid_when_interpolated_into_json_string() {
        let original = "bad \"field\"\n<script>\u{00}";
        let body = format!(r#"{{"error":"{}"}}"#, escape_json_string(original));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON body");

        assert_eq!(parsed["error"], original);
    }

    #[test]
    fn passes_plain_text_through() {
        assert_eq!(escape_json_string("hello world"), "hello world");
    }
}
