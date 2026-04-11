//! Thread-local HTTP Date header caching.
//!
//! Caches the RFC 2822 formatted date string per-thread, refreshing only when
//! the second changes. Avoids `SystemTime::now()` + formatting (~100ns) on every
//! response.

use std::cell::Cell;
use std::time::SystemTime;

use httpdate::fmt_http_date;

/// HTTP Date header is always exactly 29 bytes (e.g., "Thu, 10 Apr 2026 12:34:56 GMT").
const HTTP_DATE_LEN: usize = 29;

/// Cached HTTP Date header value with second-granularity refresh.
/// Uses a fixed-size byte array (`Copy`) so the thread-local can use `Cell`
/// instead of `RefCell`, avoiding borrow-tracking overhead on the hot path.
#[allow(dead_code)] // Used via lib crate public API
#[derive(Clone, Copy)]
struct CachedDate {
    /// The formatted date bytes, always exactly HTTP_DATE_LEN.
    bytes: [u8; HTTP_DATE_LEN],
    /// The epoch second when `bytes` was last generated.
    epoch_second: u64,
}

thread_local! {
    static DATE_CACHE: Cell<CachedDate> = const { Cell::new(CachedDate {
        bytes: [0u8; HTTP_DATE_LEN],
        epoch_second: 0,
    }) };
}

/// Get the current HTTP Date header value.
///
/// Returns a cached string that is refreshed at most once per second per thread.
/// Cost: one `SystemTime::now()` (~25ns) + one integer comparison + a 29-byte
/// stack copy on cache hit. Full formatting (~100ns) only runs when the second
/// rolls over.
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
        let mut c = cache.get();
        if c.epoch_second != epoch_secs {
            let formatted = fmt_http_date(now);
            let src = formatted.as_bytes();
            let len = src.len().min(HTTP_DATE_LEN);
            c.bytes[..len].copy_from_slice(&src[..len]);
            c.epoch_second = epoch_secs;
            cache.set(c);
        }
        // The HTTP Date format is always valid ASCII, so from_utf8 cannot fail.
        // Use from_utf8_lossy to avoid unsafe while keeping zero-cost for valid input.
        String::from_utf8(c.bytes.to_vec())
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    })
}
