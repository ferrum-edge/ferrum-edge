pub use crate::plugins::utils::query::has_conflicting_duplicate_query_key;

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() || haystack.len() < needle_bytes.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle_bytes.len())
        .any(|window| window.eq_ignore_ascii_case(needle_bytes))
}

pub fn has_double_encoded_marker(value: &str) -> bool {
    contains_case_insensitive(value, "%25")
        || contains_case_insensitive(value, "%252e")
        || contains_case_insensitive(value, "%252f")
        || contains_case_insensitive(value, "%255c")
        || contains_case_insensitive(value, "%2500")
}

pub fn has_percent_null_byte(value: &str) -> bool {
    contains_case_insensitive(value, "%00")
}

pub fn has_overlong_utf8_marker(value: &str) -> bool {
    contains_case_insensitive(value, "%c0%ae")
        || contains_case_insensitive(value, "%c0%af")
        || contains_case_insensitive(value, "%e0%80")
        || contains_case_insensitive(value, "%f0%80")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_double_encoded_marker() {
        assert!(has_double_encoded_marker("x=%252e%252e%252fetc"));
        assert!(!has_double_encoded_marker("x=%2e%2e%2fetc"));
    }

    #[test]
    fn case_insensitive_encoding_detection() {
        assert!(has_double_encoded_marker("x=%252E%252E%252Fetc"));
        assert!(has_percent_null_byte("test%00end"));
        assert!(has_overlong_utf8_marker("test%C0%AEend"));
    }
}
