//! Direct environment variable secret resolution.
//!
//! Returns the value of the env var if set and non-empty.

use std::env;

/// Check if the secret is set directly as an environment variable.
/// Returns `Some(value)` if the env var is set and non-empty.
/// Used by the registry's single-key `resolve_secret()` path and its tests.
#[allow(dead_code)]
pub fn resolve(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_returns_value_when_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        let key = "FERRUM_TEST_SECRET_ENV_RESOLVE_SET_12345";
        // SAFETY: We hold a mutex preventing concurrent env access.
        unsafe { std::env::set_var(key, "my-secret-value") };
        assert_eq!(resolve(key), Some("my-secret-value".to_string()));
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn resolve_returns_none_when_unset() {
        assert_eq!(resolve("FERRUM_TEST_SECRET_DEFINITELY_NOT_SET_XYZ"), None);
    }

    #[test]
    fn resolve_returns_none_when_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        let key = "FERRUM_TEST_SECRET_ENV_RESOLVE_EMPTY_12345";
        // SAFETY: We hold a mutex preventing concurrent env access.
        unsafe { std::env::set_var(key, "") };
        assert_eq!(resolve(key), None);
        unsafe { std::env::remove_var(key) };
    }
}
