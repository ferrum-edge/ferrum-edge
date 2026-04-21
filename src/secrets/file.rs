//! File-based secret resolution (`_FILE` suffix convention).
//!
//! When `FERRUM_X_FILE=/path/to/secret` is set, the secret value is read from
//! that file. Supports Docker secrets (`/run/secrets/`), Kubernetes volume mounts,
//! and Vault Agent file injection.

use std::env;

/// Check if the `{key}_FILE` env var is set and non-empty.
/// Returns the file path if so.
/// Used by the registry's single-key `resolve_secret()` path and its tests.
#[allow(dead_code)]
pub fn resolve_ref(key: &str) -> Option<String> {
    let file_key = format!("{}_FILE", key);
    env::var(&file_key).ok().filter(|s| !s.is_empty())
}

/// Read a secret value from a file path. Trims trailing whitespace
/// (trailing newlines are common in Docker secrets and heredocs).
/// Returns an error if the file cannot be read or is empty after trimming.
pub fn read_secret(path: &str, key: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}_FILE from '{}': {}", key, path, e))?;

    let trimmed = content.trim_end().to_string();
    if trimmed.is_empty() {
        return Err(format!(
            "File '{}' (from {}_FILE) is empty after trimming",
            path, key
        ));
    }

    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_secret_reads_file_content() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "super-secret").unwrap();
        let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
        assert_eq!(result.unwrap(), "super-secret");
    }

    #[test]
    fn read_secret_trims_trailing_whitespace() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "my-secret\n\n").unwrap();
        let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
        assert_eq!(result.unwrap(), "my-secret");
    }

    #[test]
    fn read_secret_trims_trailing_spaces_and_tabs() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "password123  \t").unwrap();
        let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
        assert_eq!(result.unwrap(), "password123");
    }

    #[test]
    fn read_secret_preserves_leading_whitespace() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "  leading-space").unwrap();
        let result = read_secret(tmp.path().to_str().unwrap(), "TEST_KEY");
        assert_eq!(result.unwrap(), "  leading-space");
    }

    #[test]
    fn read_secret_error_for_nonexistent_file() {
        let result = read_secret("/nonexistent/path/secret.txt", "MY_KEY");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Failed to read MY_KEY_FILE"));
    }

    #[test]
    fn read_secret_error_for_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let result = read_secret(tmp.path().to_str().unwrap(), "EMPTY_KEY");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("is empty after trimming"));
    }

    #[test]
    fn read_secret_error_for_whitespace_only_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "   \n\n\t  ").unwrap();
        let result = read_secret(tmp.path().to_str().unwrap(), "WS_KEY");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("is empty after trimming"));
    }

    #[test]
    fn resolve_ref_returns_none_when_not_set() {
        assert!(resolve_ref("FERRUM_TEST_SECRET_NOT_SET_XYZ_99999").is_none());
    }

    #[test]
    fn resolve_ref_returns_path_when_set() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        let key = "FERRUM_TEST_SECRET_FILE_REF_12345";
        let file_key = format!("{}_FILE", key);
        // SAFETY: We hold a mutex preventing concurrent env access.
        unsafe { std::env::set_var(&file_key, "/run/secrets/db_password") };
        assert_eq!(
            resolve_ref(key),
            Some("/run/secrets/db_password".to_string())
        );
        unsafe { std::env::remove_var(&file_key) };
    }
}
