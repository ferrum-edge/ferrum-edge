//! Unit tests for thread-local Date header caching.

use ferrum_edge::date_cache::get_cached_date;

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
    // HTTP date format: "Thu, 10 Apr 2026 12:34:56 GMT"
    assert!(date.len() >= 25, "Date too short: {}", date);
    assert!(date.ends_with("GMT"), "Should end with GMT: {}", date);
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
