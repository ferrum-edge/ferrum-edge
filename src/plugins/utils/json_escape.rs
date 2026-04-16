//! Shared JSON string escape helper used by AI plugins to safely embed
//! user-controlled text inside JSON error response bodies.
//!
//! Escapes backslash, double-quote, and the `<`/`>` characters (the latter
//! two as `\u003c` / `\u003e`) so the result is safe to interpolate inside a
//! JSON string literal that may also be served to a browser context.

/// Escape `s` for use inside a JSON string literal.
///
/// Replaces `\` → `\\`, `"` → `\"`, `<` → `\u003c`, `>` → `\u003e`.
pub fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
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
}
