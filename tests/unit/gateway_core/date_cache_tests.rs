//! Unit tests for thread-local Date header caching.

use ferrum_edge::date_cache::{get_cached_date, get_cached_date_bytes};

#[test]
fn test_cached_date_contains_gmt() {
    let date = get_cached_date();
    assert!(
        date.contains("GMT"),
        "Date header should contain GMT: {}",
        date
    );
}

#[test]
fn test_cached_date_is_valid_http_date() {
    let date = get_cached_date();
    assert_eq!(date.len(), 29, "Date length should be fixed: {}", date);
    assert!(date.ends_with("GMT"), "Should end with GMT: {}", date);
    httpdate::parse_http_date(&date).unwrap();
}

#[test]
fn test_cached_date_bytes_have_fixed_http_date_shape() {
    let bytes = get_cached_date_bytes();
    let date = std::str::from_utf8(&bytes).unwrap();

    assert_eq!(bytes.len(), 29);
    assert!(
        !bytes.contains(&0),
        "Date bytes must not contain NUL padding"
    );
    assert!(date.ends_with("GMT"), "Should end with GMT: {}", date);
    httpdate::parse_http_date(date).unwrap();
}

#[test]
fn test_cached_date_string_and_bytes_are_parseable_on_repeated_reads() {
    for _ in 0..8 {
        let date = get_cached_date();
        let bytes = get_cached_date_bytes();
        let byte_date = std::str::from_utf8(&bytes).unwrap();

        assert_eq!(date.len(), 29);
        assert_eq!(byte_date.len(), 29);
        httpdate::parse_http_date(&date).unwrap();
        httpdate::parse_http_date(byte_date).unwrap();
    }
}

#[test]
fn test_cached_date_consistency() {
    // Multiple calls within the same second should return the same value
    let date1 = get_cached_date();
    let date2 = get_cached_date();
    assert_eq!(
        date1, date2,
        "Same-second calls should return identical dates"
    );
}

#[test]
fn test_cached_date_from_multiple_threads() {
    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                let date = get_cached_date();
                assert!(date.contains("GMT"));
                date
            })
        })
        .collect();

    for h in handles {
        let date = h.join().unwrap();
        assert!(date.contains("GMT"));
    }
}
