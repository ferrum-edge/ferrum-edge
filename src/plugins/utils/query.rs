use percent_encoding::percent_decode_str;
use std::collections::HashMap;

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
    fn detects_conflicting_duplicate_values() {
        assert!(has_conflicting_duplicate_query_key("a=1&a=2"));
    }

    #[test]
    fn allows_identical_duplicate_values() {
        assert!(!has_conflicting_duplicate_query_key("a=1&a=1"));
    }

    #[test]
    fn detects_percent_encoded_key_collision() {
        assert!(has_conflicting_duplicate_query_key("a%20b=1&a%20b=2"));
    }

    #[test]
    fn allows_percent_encoded_keys_with_same_value() {
        assert!(!has_conflicting_duplicate_query_key("a%20b=1&a%20b=1"));
    }

    #[test]
    fn detects_keys_without_equals() {
        assert!(has_conflicting_duplicate_query_key("flag&flag=1"));
    }

    #[test]
    fn allows_distinct_keys_without_equals() {
        assert!(!has_conflicting_duplicate_query_key("flag&other"));
    }

    #[test]
    fn ignores_empty_pairs() {
        assert!(has_conflicting_duplicate_query_key("a=1&&a=2"));
        assert!(!has_conflicting_duplicate_query_key("a=1&&a=1"));
    }
}
