//! Direct environment variable secret resolution.
//!
//! Returns the value of the env var if set and non-empty.

use std::env;

/// Check if the secret is set directly as an environment variable.
/// Returns `Some(value)` if the env var is set and non-empty.
pub fn resolve(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}
