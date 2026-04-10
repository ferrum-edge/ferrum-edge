//! Thread-local HTTP Date header caching.
//!
//! Caches the RFC 2822 formatted date string per-thread, refreshing only when
//! the second changes. Avoids `SystemTime::now()` + formatting (~100ns) on every
//! response.

use std::cell::RefCell;
use std::time::SystemTime;

use httpdate::fmt_http_date;

/// Cached HTTP Date header value with second-granularity refresh.
#[allow(dead_code)] // Used via lib crate public API
struct CachedDate {
    /// The formatted date string (e.g., "Thu, 10 Apr 2026 12:34:56 GMT").
    value: String,
    /// The epoch second when `value` was last generated.
    epoch_second: u64,
}

thread_local! {
    static DATE_CACHE: RefCell<CachedDate> = const { RefCell::new(CachedDate {
        value: String::new(),
        epoch_second: 0,
    }) };
}

/// Get the current HTTP Date header value.
///
/// Returns a cached string that is refreshed at most once per second per thread.
/// Cost: one `SystemTime::now()` (~25ns) + one integer comparison on cache hit.
/// Full formatting (~100ns) only runs when the second rolls over.
///
/// # Example
/// ```
/// let date = ferrum_edge::date_cache::get_cached_date();
/// assert!(date.contains("GMT"));
/// ```
#[allow(dead_code)] // Public API for response Date header injection
pub fn get_cached_date() -> String {
    let now = SystemTime::now();
    let epoch_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    DATE_CACHE.with(|cache| {
        let mut c = cache.borrow_mut();
        if c.epoch_second != epoch_secs {
            c.value = fmt_http_date(now);
            c.epoch_second = epoch_secs;
        }
        c.value.clone()
    })
}
