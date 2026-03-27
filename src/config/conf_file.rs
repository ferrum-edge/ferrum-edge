use std::collections::HashMap;
use std::path::Path;
use tracing::info;

/// Default path for the ferrum.conf configuration file.
pub const DEFAULT_CONF_PATH: &str = "./ferrum.conf";

/// Environment variable to override the conf file path.
pub const CONF_PATH_ENV_VAR: &str = "FERRUM_CONF_PATH";

/// Parsed configuration file values. Keys are the same `FERRUM_*` names used
/// by environment variables. Values set here take precedence over env vars.
#[derive(Debug, Default)]
pub struct ConfFile {
    values: HashMap<String, String>,
}

impl ConfFile {
    /// Load the conf file from the path specified by `FERRUM_CONF_PATH` env var,
    /// falling back to `./ferrum.conf`. Returns an empty `ConfFile` if the file
    /// does not exist (silently skipped).
    pub fn load() -> Result<Self, String> {
        let path = std::env::var(CONF_PATH_ENV_VAR).unwrap_or_else(|_| DEFAULT_CONF_PATH.into());

        if !Path::new(&path).exists() {
            return Ok(Self::default());
        }

        info!("Loading configuration from {}", path);
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read conf file '{}': {}", path, e))?;

        Self::parse(&contents)
    }

    /// Parse conf file contents. Format:
    /// - Lines starting with `#` are comments
    /// - Empty lines are ignored
    /// - Key-value pairs: `KEY = VALUE` or `KEY=VALUE`
    /// - Values are trimmed of surrounding whitespace
    /// - Quoted values (`"..."` or `'...'`) have quotes stripped
    pub fn parse(contents: &str) -> Result<Self, String> {
        let mut values = HashMap::new();

        for (line_num, line) in contents.lines().enumerate() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let Some(eq_pos) = trimmed.find('=') else {
                return Err(format!(
                    "Invalid conf file syntax at line {}: missing '=' in '{}'",
                    line_num + 1,
                    trimmed
                ));
            };

            let key = trimmed[..eq_pos].trim().to_string();
            let mut value = trimmed[eq_pos + 1..].trim().to_string();

            // Strip surrounding quotes
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                value = value[1..value.len() - 1].to_string();
            }

            // Strip inline comments (only outside quotes)
            if let Some(comment_pos) = value.find(" #") {
                value = value[..comment_pos].trim_end().to_string();
            }

            if key.is_empty() {
                return Err(format!(
                    "Invalid conf file syntax at line {}: empty key",
                    line_num + 1
                ));
            }

            values.insert(key, value);
        }

        Ok(Self { values })
    }

    /// Get a value from the conf file, returning `None` if not set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    /// Returns true if the conf file has no values (either empty or not loaded).
    #[allow(dead_code)] // Used by integration/unit tests via the lib crate
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let conf = ConfFile::parse("FERRUM_MODE = file\nFERRUM_LOG_LEVEL = debug\n").unwrap();
        assert_eq!(conf.get("FERRUM_MODE"), Some("file"));
        assert_eq!(conf.get("FERRUM_LOG_LEVEL"), Some("debug"));
    }

    #[test]
    fn test_parse_comments_and_empty_lines() {
        let input = "# This is a comment\n\nFERRUM_MODE = file\n  # Another comment\n";
        let conf = ConfFile::parse(input).unwrap();
        assert_eq!(conf.get("FERRUM_MODE"), Some("file"));
        assert_eq!(conf.values.len(), 1);
    }

    #[test]
    fn test_parse_quoted_values() {
        let input = "KEY1 = \"hello world\"\nKEY2 = 'single quoted'\n";
        let conf = ConfFile::parse(input).unwrap();
        assert_eq!(conf.get("KEY1"), Some("hello world"));
        assert_eq!(conf.get("KEY2"), Some("single quoted"));
    }

    #[test]
    fn test_parse_no_spaces() {
        let conf = ConfFile::parse("KEY=value").unwrap();
        assert_eq!(conf.get("KEY"), Some("value"));
    }

    #[test]
    fn test_parse_inline_comments() {
        let conf = ConfFile::parse("KEY = value # this is a comment").unwrap();
        assert_eq!(conf.get("KEY"), Some("value"));
    }

    #[test]
    fn test_parse_empty_value() {
        let conf = ConfFile::parse("KEY =").unwrap();
        assert_eq!(conf.get("KEY"), Some(""));
    }

    #[test]
    fn test_parse_invalid_line() {
        let result = ConfFile::parse("no_equals_sign");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let conf = ConfFile::parse("").unwrap();
        assert!(conf.is_empty());
    }

    #[test]
    fn test_comments_only() {
        let conf = ConfFile::parse("# just comments\n# nothing else\n").unwrap();
        assert!(conf.is_empty());
    }
}
