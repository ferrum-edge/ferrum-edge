use super::{AutoBool, BackendAllowIps, ConfFile, OperatingMode, resolve_var};
use std::collections::HashMap;

pub(crate) trait EnvValue: Sized {
    fn parse_env(raw: &str, key: &str) -> Result<Self, String>;
}

pub(crate) fn resolve_default<T, F>(conf: &ConfFile, key: &str, default: F) -> Result<T, String>
where
    T: EnvValue,
    F: FnOnce() -> T,
{
    match resolve_var(conf, key) {
        Some(raw) => T::parse_env(&raw, key),
        None => Ok(default()),
    }
}

pub(crate) fn resolve_optional<T>(conf: &ConfFile, key: &str) -> Result<Option<T>, String>
where
    T: EnvValue,
{
    resolve_var(conf, key)
        .map(|raw| T::parse_env(&raw, key))
        .transpose()
}

pub(crate) fn validate_required_string_in_modes(
    key: &str,
    value: Option<&str>,
    mode: &OperatingMode,
    required_modes: &[&str],
    min_len: usize,
) -> Result<(), String> {
    if !mode_matches_any(mode, required_modes) {
        return Ok(());
    }

    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Err(format!(
            "{key} is required in {} mode",
            required_modes.join("/")
        ));
    };

    if value.len() < min_len {
        return Err(format!(
            "{key} must be at least {min_len} characters (got {})",
            value.len()
        ));
    }

    Ok(())
}

fn mode_matches_any(mode: &OperatingMode, candidates: &[&str]) -> bool {
    let current = match mode {
        OperatingMode::Database => "database",
        OperatingMode::File => "file",
        OperatingMode::ControlPlane => "cp",
        OperatingMode::DataPlane => "dp",
        OperatingMode::Migrate => "migrate",
    };

    candidates.contains(&current)
}

fn invalid_env_value(key: &str, raw: &str, expected: &str) -> String {
    format!("Invalid {key} value '{raw}'. Expected {expected}")
}

macro_rules! impl_env_value_parse {
    ($($ty:ty => $expected:literal),+ $(,)?) => {
        $(
            impl EnvValue for $ty {
                fn parse_env(raw: &str, key: &str) -> Result<Self, String> {
                    raw.trim()
                        .parse::<$ty>()
                        .map_err(|_| invalid_env_value(key, raw, $expected))
                }
            }
        )+
    };
}

impl_env_value_parse!(
    u8 => "a valid u8 integer",
    u16 => "a valid u16 integer",
    u32 => "a valid u32 integer",
    u64 => "a valid u64 integer",
    usize => "a valid usize integer",
    f64 => "a valid floating-point number",
);

impl EnvValue for String {
    fn parse_env(raw: &str, _key: &str) -> Result<Self, String> {
        Ok(raw.to_string())
    }
}

impl EnvValue for bool {
    fn parse_env(raw: &str, key: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(invalid_env_value(key, raw, "true, false, 1, or 0")),
        }
    }
}

impl EnvValue for AutoBool {
    fn parse_env(raw: &str, key: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "true" | "1" => Ok(Self::True),
            "false" | "0" => Ok(Self::False),
            _ => Err(invalid_env_value(key, raw, "auto, true, false, 1, or 0")),
        }
    }
}

impl EnvValue for BackendAllowIps {
    fn parse_env(raw: &str, key: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "private" => Ok(Self::Private),
            "public" => Ok(Self::Public),
            "both" => Ok(Self::Both),
            _ => Err(invalid_env_value(key, raw, "private, public, or both")),
        }
    }
}

impl EnvValue for Vec<String> {
    fn parse_env(raw: &str, _key: &str) -> Result<Self, String> {
        Ok(raw
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect())
    }
}

impl EnvValue for HashMap<String, String> {
    fn parse_env(raw: &str, key: &str) -> Result<Self, String> {
        serde_json::from_str(raw).map_err(|err| {
            format!(
                "{}: {}",
                invalid_env_value(key, raw, "a JSON object of string values"),
                err
            )
        })
    }
}

macro_rules! env_config {
    (conf = $conf:expr, mode = $mode:expr; $($rest:tt)*) => {
        env_config!(@parse $conf, $mode; $($rest)*);
    };

    (@parse $conf:expr, $mode:expr;) => {};

    (@parse $conf:expr, $mode:expr; [$section:ident] $($rest:tt)*) => {
        env_config!(@parse $conf, $mode; $($rest)*);
    };

    (@parse $conf:expr, $mode:expr;
        $field:ident : Option<String> = $env:literal
            => required_for([$($required:literal),+ $(,)?]) min_len($min:expr);
        $($rest:tt)*
    ) => {
        let $field: Option<String> =
            $crate::config::env_config::env_config_macro::resolve_optional::<String>($conf, $env)?;
        $crate::config::env_config::env_config_macro::validate_required_string_in_modes(
            $env,
            $field.as_deref(),
            $mode,
            &[$($required),+],
            $min,
        )?;
        env_config!(@parse $conf, $mode; $($rest)*);
    };

    (@parse $conf:expr, $mode:expr;
        $field:ident : Option<$inner:ty> = $env:literal;
        $($rest:tt)*
    ) => {
        let $field: Option<$inner> =
            $crate::config::env_config::env_config_macro::resolve_optional::<$inner>($conf, $env)?;
        env_config!(@parse $conf, $mode; $($rest)*);
    };

    (@parse $conf:expr, $mode:expr;
        $field:ident : $ty:ty = $env:literal => $default:expr, $rule:ident($($args:tt)*);
        $($rest:tt)*
    ) => {
        let mut $field: $ty =
            $crate::config::env_config::env_config_macro::resolve_default::<$ty, _>(
                $conf,
                $env,
                || $default,
            )?;
        env_config!(@apply_rule $field; $rule($($args)*));
        env_config!(@parse $conf, $mode; $($rest)*);
    };

    (@parse $conf:expr, $mode:expr;
        $field:ident : $ty:ty = $env:literal => $default:expr;
        $($rest:tt)*
    ) => {
        let $field: $ty =
            $crate::config::env_config::env_config_macro::resolve_default::<$ty, _>(
                $conf,
                $env,
                || $default,
            )?;
        env_config!(@parse $conf, $mode; $($rest)*);
    };

    (@apply_rule $field:ident; clamp($min:expr, $max:expr)) => {
        $field = $field.clamp($min, $max);
    };

    (@apply_rule $field:ident; max($min:expr)) => {
        $field = $field.max($min);
    };

    (@apply_rule $field:ident; lowercase()) => {
        $field = $field.to_ascii_lowercase();
    };
}

#[cfg(test)]
mod tests {
    use super::super::{ConfFile, OperatingMode};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (key, value) in vars {
            // SAFETY: Tests hold ENV_LOCK while mutating process-global env vars.
            unsafe {
                std::env::set_var(key, value);
            }
        }

        f();

        for (key, _) in vars {
            // SAFETY: Tests hold ENV_LOCK while mutating process-global env vars.
            unsafe {
                std::env::remove_var(key);
            }
        }
    }

    #[test]
    fn macro_default_applies_when_unset() {
        with_env_vars(&[], || {
            let conf = ConfFile::default();
            let _mode = OperatingMode::File;

            let result: Result<u16, String> = (|| {
                env_config! {
                    conf = &conf, mode = &_mode;
                    sample_port: u16 = "FERRUM_SAMPLE_PORT" => 9000u16;
                }
                Ok(sample_port)
            })();

            assert_eq!(result.unwrap(), 9000);
        });
    }

    #[test]
    fn macro_parse_error_surfaces() {
        with_env_vars(&[("FERRUM_SAMPLE_PORT", "not-a-number")], || {
            let conf = ConfFile::default();
            let _mode = OperatingMode::File;

            let result: Result<u16, String> = (|| {
                env_config! {
                    conf = &conf, mode = &_mode;
                    sample_port: u16 = "FERRUM_SAMPLE_PORT" => 9000u16;
                }
                Ok(sample_port)
            })();

            let err = result.unwrap_err();
            assert!(err.contains("FERRUM_SAMPLE_PORT"));
            assert!(err.contains("not-a-number"));
        });
    }

    #[test]
    fn macro_required_for_only_triggers_in_selected_modes() {
        with_env_vars(&[], || {
            let conf = ConfFile::default();
            let file_mode = OperatingMode::File;
            let db_mode = OperatingMode::Database;

            let file_result: Result<Option<String>, String> = (|| {
                env_config! {
                    conf = &conf, mode = &file_mode;
                    sample_secret: Option<String> = "FERRUM_SAMPLE_SECRET"
                        => required_for(["database", "cp"]) min_len(32);
                }
                Ok(sample_secret)
            })();
            assert_eq!(file_result.unwrap(), None);

            let db_result: Result<Option<String>, String> = (|| {
                env_config! {
                    conf = &conf, mode = &db_mode;
                    sample_secret: Option<String> = "FERRUM_SAMPLE_SECRET"
                        => required_for(["database", "cp"]) min_len(32);
                }
                Ok(sample_secret)
            })();

            let err = db_result.unwrap_err();
            assert!(err.contains("FERRUM_SAMPLE_SECRET"));
            assert!(err.contains("database/cp mode"));
        });
    }

    #[test]
    fn macro_min_len_runs_after_parse() {
        with_env_vars(&[("FERRUM_SAMPLE_SECRET", "too-short")], || {
            let conf = ConfFile::default();
            let mode = OperatingMode::Database;

            let result: Result<Option<String>, String> = (|| {
                env_config! {
                    conf = &conf, mode = &mode;
                    sample_secret: Option<String> = "FERRUM_SAMPLE_SECRET"
                        => required_for(["database", "cp"]) min_len(32);
                }
                Ok(sample_secret)
            })();

            let err = result.unwrap_err();
            assert!(err.contains("FERRUM_SAMPLE_SECRET"));
            assert!(err.contains("at least 32 characters"));
        });
    }
}
