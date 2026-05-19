use percent_encoding::percent_decode_str;
use std::collections::HashMap;

pub fn has_double_encoded_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("%25")
        || lower.contains("%252e")
        || lower.contains("%252f")
        || lower.contains("%255c")
        || lower.contains("%2500")
}

pub fn has_percent_null_byte(value: &str) -> bool {
    value.to_ascii_lowercase().contains("%00")
}

pub fn has_overlong_utf8_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("%c0%ae")
        || lower.contains("%c0%af")
        || lower.contains("%e0%80")
        || lower.contains("%f0%80")
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
}
