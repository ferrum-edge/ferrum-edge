//! `ferrum.conf` file parser — provides defaults overridable by environment variables.
//!
//! The conf file uses a simple `KEY=value` format (one per line, `#` comments).
//! Values here serve as defaults in a 3-tier resolution chain:
//! **env var > conf file > hardcoded default**. The `resolve_var()` function
//! in `env_config.rs` implements this precedence.
//!
//! # Load contract
//!
//! `ferrum.conf` is an immutable process-startup snapshot. It is loaded once
//! through the shared bounded stable-file reader (regular-file open target,
//! Unix `O_NONBLOCK`, 1 MiB ceiling with `limit + 1`, two identity/content
//! probes separated by a 20ms settle interval). The accepted result — or a
//! precise load error — is cached for the process lifetime. A failed load is
//! never converted into an empty fallback.
//!
//! When `FERRUM_CONF_PATH` is unset — or set to an empty / whitespace-only
//! value, which configures nothing — and `./ferrum.conf` is genuinely absent,
//! an empty defaults map is accepted for backward compatibility. An explicitly
//! configured non-empty path that is missing, non-regular, oversized, unstable,
//! invalid UTF-8, or malformed fails closed.

use crate::config::stable_file::{
    MAX_FERRUM_CONF_BYTES, StableFileError, StableFileReadOptions, format_stable_file_error,
    read_stable_file,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::info;

/// Lazily-loaded, cached conf-file result. Loaded once on first access via
/// `OnceLock`, shared across all callers for the lifetime of the process. This
/// enables code that runs outside `EnvConfig` (e.g., tracing init in `main()`,
/// secret resolution, plugin constructors) to respect `ferrum.conf` values
/// without re-parsing the file each time — and ensures every consumer observes
/// the same accepted generation or the same sticky load error.
static CONF_FILE_CACHE: OnceLock<Result<ConfFile, String>> = OnceLock::new();

/// Resolve a single `FERRUM_*` variable from the environment or `ferrum.conf`.
///
/// Precedence: **env var > conf file**. Returns `None` if unset in both.
///
/// This is the public entry point for code that needs conf-file-aware variable
/// resolution but does not have access to an `EnvConfig` instance (e.g., early
/// startup in `main()`, secret resolution, plugin constructors, JWT auth).
///
/// A sticky conf-file load failure does **not** invent an empty defaults map:
/// conf lookups return `None` while `ConfFile::load()` / `EnvConfig::from_env()`
/// surface the same cached error.
pub fn resolve_ferrum_var(key: &str) -> Option<String> {
    if let Ok(val) = std::env::var(key) {
        return Some(val);
    }
    conf_value_from_cached(CONF_FILE_CACHE.get_or_init(ConfFile::load_uncached), key)
}

/// Fallible single-key variant of [`resolve_ferrum_var`].
///
/// Precedence matches [`resolve_ferrum_var`] and `EnvConfig`'s `resolve_var`:
/// **env var > conf file**. An exported-but-empty environment value still wins
/// over the conf file (typed parsing at the call site decides whether an empty
/// value is valid). Unlike `EnvConfig::resolve_var`, this logs nothing: it is
/// called per consumer / plugin construction, so repeating the startup
/// env-overrides-conf notice there would be noise.
///
/// A sticky conf-file load failure is propagated instead of resolving to
/// `None`, so callers cannot silently fall back to a default and diverge from
/// `EnvConfig::from_env`. The cached snapshot is borrowed; only the error path
/// clones the (short) cached error string.
#[doc(hidden)]
pub fn resolve_ferrum_var_checked(key: &str) -> Result<Option<String>, String> {
    resolve_ferrum_var_checked_from(
        std::env::var(key).ok(),
        CONF_FILE_CACHE.get_or_init(ConfFile::load_uncached),
        key,
    )
}

/// Precedence half of [`resolve_ferrum_var_checked`], split out so the
/// env-over-conf rule and the sticky error path are testable without pinning
/// the process-wide `OnceLock` snapshot.
#[doc(hidden)]
pub fn resolve_ferrum_var_checked_from(
    env_value: Option<String>,
    cached: &Result<ConfFile, String>,
    key: &str,
) -> Result<Option<String>, String> {
    if let Some(value) = env_value {
        return Ok(Some(value));
    }
    conf_value_checked_from_cached(cached, key)
}

/// Conf-file half of [`resolve_ferrum_var`], split out so the fail-closed
/// behavior is testable without pinning the process-wide `OnceLock` snapshot.
///
/// A sticky load failure resolves to `None`. It must never be converted into an
/// empty defaults map, which would silently turn a malformed or unreadable
/// `ferrum.conf` into "no values configured" for the process lifetime.
#[doc(hidden)]
pub fn conf_value_from_cached(cached: &Result<ConfFile, String>, key: &str) -> Option<String> {
    conf_value_checked_from_cached(cached, key).ok().flatten()
}

/// Fallible conf-file half of [`resolve_ferrum_var_checked`].
///
/// Borrows the cached snapshot and looks up only `key`; a sticky load failure
/// is returned as `Err` so callers can fail closed.
#[doc(hidden)]
pub fn conf_value_checked_from_cached(
    cached: &Result<ConfFile, String>,
    key: &str,
) -> Result<Option<String>, String> {
    match cached {
        Ok(conf) => Ok(conf.get(key).map(|v| v.to_string())),
        Err(error) => Err(error.clone()),
    }
}

/// Default path for the ferrum.conf configuration file.
pub const DEFAULT_CONF_PATH: &str = "./ferrum.conf";

/// Environment variable to override the conf file path.
pub const CONF_PATH_ENV_VAR: &str = "FERRUM_CONF_PATH";

/// Parsed configuration file values. Keys are the same `FERRUM_*` names used
/// by environment variables. Values here provide defaults that can be
/// overridden by environment variables.
#[derive(Debug, Default, Clone)]
pub struct ConfFile {
    values: HashMap<String, String>,
}

impl ConfFile {
    /// Load the conf file from the path specified by `FERRUM_CONF_PATH` env var,
    /// falling back to `./ferrum.conf`. Returns an empty `ConfFile` only when
    /// the default path is genuinely absent. An explicit `FERRUM_CONF_PATH` or
    /// an existing/default path that fails the stable-file contract surfaces a
    /// precise configuration error. The process-wide cache retains that result
    /// for the lifetime of the process.
    pub fn load() -> Result<Self, String> {
        CONF_FILE_CACHE.get_or_init(Self::load_uncached).clone()
    }

    /// Load without consulting the process cache. Intended for tests that need
    /// an isolated path probe; production callers use [`Self::load`].
    pub fn load_from_path(path: &Path, absent_ok: bool) -> Result<Self, String> {
        let options = StableFileReadOptions::new(MAX_FERRUM_CONF_BYTES, "ferrum.conf");
        match read_stable_file(path, options) {
            Ok(contents) => {
                info!(
                    "Loading configuration from {}",
                    crate::startup::sanitize_startup_cause(format!("{path:?}"), &[])
                );
                Self::parse(&contents)
            }
            Err(StableFileError::NotFound) if absent_ok => Ok(Self::default()),
            Err(error) => Err(format_stable_file_error(path, options, &error)),
        }
    }

    fn load_uncached() -> Result<Self, String> {
        let (path, absent_ok) = resolve_conf_path();
        Self::load_from_path(&path, absent_ok)
    }

    /// Parse conf file contents. Format:
    /// - Lines starting with `#` are comments
    /// - Empty lines are ignored
    /// - Key-value pairs: `KEY = VALUE` or `KEY=VALUE`
    /// - Values are trimmed of surrounding whitespace
    /// - Quoted values (`"..."` or `'...'`) are literal, with no escape processing
    /// - After a closing quote, only whitespace and an optional `#` comment are allowed
    /// - Unquoted values end at the first ` #` inline comment
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
                    "Invalid conf file syntax at line {}: missing '='",
                    line_num + 1
                ));
            };

            let key = trimmed[..eq_pos].trim().to_string();
            if key.is_empty() {
                return Err(format!(
                    "Invalid conf file syntax at line {}: empty key",
                    line_num + 1
                ));
            }

            // Exact inventory names win before suffix interpretation: several
            // ordinary path settings legitimately end in _FILE.
            if !crate::config::public_env_inventory::is_recognized_ferrum_setting(&key) {
                let display_key: String = key
                    .chars()
                    .map(|c| match c {
                        'A'..='Z' | 'a'..='z' | '0'..='9' | '_' => c,
                        _ => '?',
                    })
                    .collect();
                let secret_suffix = crate::secrets::EXTERNAL_SECRET_SUFFIXES
                    .iter()
                    .any(|suffix| {
                        key.strip_suffix(*suffix).is_some_and(
                            crate::config::public_env_inventory::is_recognized_ferrum_setting,
                        )
                    });
                return Err(if secret_suffix {
                    format!(
                        "Invalid ferrum.conf key `{display_key}` at line {}: external secret \
                         suffixes are environment-only; set this key in the environment",
                        line_num + 1
                    )
                } else {
                    format!(
                        "Unknown ferrum.conf key `{display_key}` at line {}",
                        line_num + 1
                    )
                });
            }

            let value = trimmed[eq_pos + 1..].trim();
            let value = if let Some(quote @ ('"' | '\'')) = value.chars().next() {
                // Both delimiters are ASCII; find the first matching quote without escapes.
                let quoted = &value[1..];
                let Some(end) = quoted.find(quote) else {
                    return Err(format!(
                        "Invalid conf file syntax at line {}: unclosed quote for key `{key}`",
                        line_num + 1
                    ));
                };
                let trailing = quoted[end + 1..].trim_start();
                if !trailing.is_empty() && !trailing.starts_with('#') {
                    return Err(format!(
                        "Invalid conf file syntax at line {}: \
                         unexpected text after closing quote for key `{key}`",
                        line_num + 1
                    ));
                }
                &quoted[..end]
            } else if let Some(comment_pos) = value.find(" #") {
                value[..comment_pos].trim_end()
            } else {
                value
            };

            values.insert(key, value.to_string());
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

fn resolve_conf_path() -> (PathBuf, bool) {
    conf_path_selection(std::env::var(CONF_PATH_ENV_VAR).ok().as_deref())
}

/// Choose the conf-file path and whether absence is acceptable.
///
/// Takes the configured value directly rather than reading the environment, so
/// the selection rule is testable without touching (or echoing) process
/// environment state.
///
/// An empty or whitespace-only `FERRUM_CONF_PATH` is treated as **unset**: an
/// operator who exports the variable without a value has configured nothing, so
/// falling back to the default path with `absent_ok = true` preserves the
/// historical "no conf file" behavior instead of failing startup on a blank
/// path. An explicit non-empty path stays fail-closed.
#[doc(hidden)]
pub fn conf_path_selection(configured: Option<&str>) -> (PathBuf, bool) {
    match configured {
        Some(path) if !path.trim().is_empty() => (PathBuf::from(path), false),
        _ => (PathBuf::from(DEFAULT_CONF_PATH), true),
    }
}
