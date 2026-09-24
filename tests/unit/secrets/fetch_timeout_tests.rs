//! `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` bounds (issue #5700).
//!
//! One pure rule governs every read of the setting: startup secret resolution
//! (process environment only), `EnvConfig` (environment and `ferrum.conf`), and
//! the runtime single-key fetches. Unset keeps the documented 30-second
//! default; a configured value that is malformed, zero, negative, or above the
//! hard maximum is an error that names the variable and range but never echoes
//! the value.

use std::io::Write;
use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::config::env_config::{
    DEFAULT_SECRET_FETCH_TIMEOUT_SECONDS, HARD_MAX_SECRET_FETCH_TIMEOUT_SECONDS,
    MIN_SECRET_FETCH_TIMEOUT_SECONDS, parse_secret_fetch_timeout,
};
use ferrum_edge::secrets::{resolve_all_env_secrets, resolve_secret};
use tempfile::NamedTempFile;

use crate::unit::env_lock::{with_env_vars, with_env_vars_async};

const KEY: &str = "FERRUM_SECRET_FETCH_TIMEOUT_SECONDS";
const EXPECTED_ERROR: &str =
    "FERRUM_SECRET_FETCH_TIMEOUT_SECONDS must be a whole number of seconds between 1 and 600";

/// Present values that must be refused: zero, malformed, negative, fractional,
/// unit-suffixed, blank, above the hard maximum, and past `u64::MAX`.
const REJECTED: &[&str] = &[
    "0",
    "abc",
    "-1",
    "1.5",
    "30s",
    "",
    "   ",
    "601",
    "18446744073709551615",
    "18446744073709551616",
];

#[test]
fn documented_bounds_match_the_contract() {
    assert_eq!(DEFAULT_SECRET_FETCH_TIMEOUT_SECONDS, 30);
    assert_eq!(MIN_SECRET_FETCH_TIMEOUT_SECONDS, 1);
    assert_eq!(HARD_MAX_SECRET_FETCH_TIMEOUT_SECONDS, 600);
}

#[test]
fn unset_selects_the_default() {
    assert_eq!(
        parse_secret_fetch_timeout(None).unwrap(),
        Duration::from_secs(30)
    );
}

#[test]
fn valid_values_are_accepted_including_both_bounds() {
    for (raw, seconds) in [("1", 1), ("30", 30), (" 45 ", 45), ("600", 600)] {
        assert_eq!(
            parse_secret_fetch_timeout(Some(raw)).unwrap(),
            Duration::from_secs(seconds),
            "{raw:?} must be accepted"
        );
    }
}

#[test]
fn zero_malformed_negative_and_overflow_are_rejected_without_echo() {
    for &raw in REJECTED {
        let error = parse_secret_fetch_timeout(Some(raw)).expect_err(raw);
        assert_eq!(error, EXPECTED_ERROR, "{raw:?}");
    }
}

#[test]
fn startup_resolution_rejects_invalid_environment_values() {
    for &raw in REJECTED {
        with_env_vars_async(&[(KEY, raw)], move || async move {
            let error = match resolve_all_env_secrets().await {
                Ok(_) => panic!("{raw:?} must fail startup secret resolution"),
                Err(error) => error,
            };
            assert_eq!(error, EXPECTED_ERROR, "{raw:?}");
        });
    }
}

#[test]
fn startup_resolution_accepts_unset_and_valid_values() {
    with_env_vars_async(&[], || async {
        let resolved = resolve_all_env_secrets().await.unwrap();
        assert!(resolved.vars.is_empty());
    });
    with_env_vars_async(&[(KEY, "5")], || async {
        let resolved = resolve_all_env_secrets().await.unwrap();
        assert!(resolved.vars.is_empty());
    });
}

#[test]
fn startup_resolution_rejects_zero_before_fetching_a_file_secret() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "file-secret-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let reference = path.clone();

    with_env_vars_async(
        &[(KEY, "0"), ("FERRUM_TEST_FETCH_TO_ZERO_FILE", &path)],
        move || async move {
            let error = match resolve_all_env_secrets().await {
                Ok(_) => panic!("a zero timeout must not resolve any secret"),
                Err(error) => error,
            };
            assert_eq!(error, EXPECTED_ERROR);
            assert!(!error.contains("file-secret-value"));
            assert!(!error.contains(&reference));
        },
    );
}

#[test]
fn runtime_single_key_fetch_rejects_invalid_values() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "runtime-secret-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    for &raw in REJECTED {
        with_env_vars_async(
            &[(KEY, raw), ("FERRUM_TEST_FETCH_TO_RT_FILE", &path)],
            move || async move {
                let result = resolve_secret("FERRUM_TEST_FETCH_TO_RT").await;
                let error = result.expect_err("the runtime fetch must fail");
                assert_eq!(error, EXPECTED_ERROR, "{raw:?}");
                assert!(!error.contains("runtime-secret-value"));
            },
        );
    }

    with_env_vars_async(
        &[(KEY, "5"), ("FERRUM_TEST_FETCH_TO_RT_FILE", &path)],
        || async {
            let result = resolve_secret("FERRUM_TEST_FETCH_TO_RT").await;
            let resolved = result.unwrap().unwrap();
            assert_eq!(resolved.value, "runtime-secret-value");
        },
    );
}

#[test]
fn env_config_rejects_invalid_environment_values() {
    for &raw in REJECTED {
        with_env_vars(
            &[
                ("FERRUM_MODE", "file"),
                ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
                (KEY, raw),
            ],
            || {
                let error = EnvConfig::from_env_with_conf(&ConfFile::default()).unwrap_err();
                assert_eq!(error, EXPECTED_ERROR, "{raw:?}");
            },
        );
    }
}

#[test]
fn env_config_rejects_invalid_conf_file_values() {
    for raw in ["0", "abc", "-1", "601", "18446744073709551616"] {
        with_env_vars(&[], || {
            let conf = ConfFile::parse(&format!(
                "FERRUM_MODE=file\nFERRUM_FILE_CONFIG_PATH=/path/to/config.yaml\n{KEY}={raw}\n"
            ))
            .unwrap();
            let error = EnvConfig::from_env_with_conf(&conf).unwrap_err();
            assert_eq!(error, EXPECTED_ERROR, "{raw:?}");
        });
    }
}

#[test]
fn env_config_accepts_unset_and_valid_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
        ],
        || {
            EnvConfig::from_env_with_conf(&ConfFile::default()).unwrap();
        },
    );
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            (KEY, "600"),
        ],
        || {
            EnvConfig::from_env_with_conf(&ConfFile::default()).unwrap();
        },
    );
    with_env_vars(&[], || {
        let conf = ConfFile::parse(&format!(
            "FERRUM_MODE=file\nFERRUM_FILE_CONFIG_PATH=/path/to/config.yaml\n{KEY}=45\n"
        ))
        .unwrap();
        EnvConfig::from_env_with_conf(&conf).unwrap();
    });
}
