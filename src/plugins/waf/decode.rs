use percent_encoding::percent_decode_str;
use std::collections::HashMap;

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

pub fn has_conflicting_duplicate_query_key(raw_query: &str) -> bool {
    let mut seen: HashMap<String, String> = HashMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_str(raw_key).decode_utf8_lossy().into_owned();
        let value = percent_decode_str(raw_value)
            .decode_utf8_lossy()
            .into_owned();
        match seen.get(&key) {
            Some(previous) if previous != &value => return true,
            Some(_) => {}
            None => {
                seen.insert(key, value);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_conflicting_duplicate_query_key() {
        assert!(has_conflicting_duplicate_query_key("a=1&a=2"));
        assert!(!has_conflicting_duplicate_query_key("a=1&a=1"));
    }

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
