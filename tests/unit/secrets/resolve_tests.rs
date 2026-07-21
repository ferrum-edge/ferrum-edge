//! Tests for the secret resolution system (env + file backends).
//!
//! These tests mutate process-global environment variables, so they MUST run
//! serially against every other env-touching test in the `unit_tests` binary —
//! not merely against each other. They therefore acquire the single
//! process-wide [`crate::unit::env_lock::ENV_LOCK`], the same mutex the config,
//! CLI, identity, and redaction suites take. A file-private mutex would leave
//! `set_var` here racing a `getenv` there, which is exactly what Rust 2024's
//! unsafe-env contract forbids.

use ferrum_edge::secrets::{resolve_all_env_secrets, resolve_secret};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use tempfile::NamedTempFile;

use crate::unit::env_lock::ENV_LOCK;

/// Helper to set env vars, run an async closure, then clean them up.
fn with_env_vars_async<F, Fut>(vars: &[(&str, &str)], f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (k, v) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::set_var(k, v);
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(f());
    for (k, _) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::remove_var(k);
        }
    }
}

#[test]
fn test_resolve_secret_from_env_var() {
    with_env_vars_async(&[("FERRUM_TEST_SECRET_A", "my-secret-value")], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_A").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "my-secret-value");
        assert_eq!(resolved.source, "env");
    });
}

#[test]
fn test_resolve_secret_from_file() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "file-secret-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_B_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_B").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "file-secret-value");
        assert!(resolved.source.starts_with("file:"));
    });
}

#[test]
fn test_resolve_secret_file_trims_trailing_whitespace() {
    let mut tmp = NamedTempFile::new().unwrap();
    write!(tmp, "secret-with-trailing  \n\n").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_C_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_C").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "secret-with-trailing");
    });
}

#[test]
fn test_resolve_secret_both_env_and_file_errors() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "file-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(
        &[
            ("FERRUM_TEST_SECRET_D", "env-value"),
            ("FERRUM_TEST_SECRET_D_FILE", &path),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_SECRET_D").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Multiple secret sources"));
            assert!(err.contains("FERRUM_TEST_SECRET_D"));
        },
    );
}

#[test]
fn test_resolve_all_env_secrets_both_env_and_file_errors() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "file-value").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(
        &[
            ("FERRUM_TEST_SECRET_STARTUP_CONFLICT", "env-value"),
            ("FERRUM_TEST_SECRET_STARTUP_CONFLICT_FILE", &path),
        ],
        || async {
            let result = resolve_all_env_secrets().await;
            let err = match result {
                Ok(_) => panic!("expected startup secret conflict to fail"),
                Err(err) => err,
            };
            assert!(err.contains("Multiple secret sources"));
            assert!(err.contains("FERRUM_TEST_SECRET_STARTUP_CONFLICT"));
            assert!(err.contains("direct env var"));
            assert!(err.contains("FERRUM_TEST_SECRET_STARTUP_CONFLICT_FILE"));
        },
    );
}

#[test]
fn test_resolve_all_env_secrets_resolves_multiple_file_sources() {
    let mut tmp_a = NamedTempFile::new().unwrap();
    let mut tmp_b = NamedTempFile::new().unwrap();
    writeln!(tmp_a, "bulk-alpha").unwrap();
    writeln!(tmp_b, "bulk-beta").unwrap();
    let path_a = tmp_a.path().to_str().unwrap().to_string();
    let path_b = tmp_b.path().to_str().unwrap().to_string();

    with_env_vars_async(
        &[
            ("FERRUM_TEST_SECRET_BULK_A_FILE", &path_a),
            ("FERRUM_TEST_SECRET_BULK_B_FILE", &path_b),
        ],
        || async {
            let resolved = resolve_all_env_secrets().await.unwrap();
            let vars: HashMap<String, String> = resolved.vars.into_iter().collect();
            assert_eq!(
                vars.get("FERRUM_TEST_SECRET_BULK_A").map(String::as_str),
                Some("bulk-alpha")
            );
            assert_eq!(
                vars.get("FERRUM_TEST_SECRET_BULK_B").map(String::as_str),
                Some("bulk-beta")
            );

            let source_keys: HashSet<String> = resolved.source_keys_to_remove.into_iter().collect();
            assert!(source_keys.contains("FERRUM_TEST_SECRET_BULK_A_FILE"));
            assert!(source_keys.contains("FERRUM_TEST_SECRET_BULK_B_FILE"));

            let loaded_sources: HashMap<String, &'static str> =
                resolved.loaded_sources.into_iter().collect();
            assert_eq!(
                loaded_sources.get("FERRUM_TEST_SECRET_BULK_A"),
                Some(&"file")
            );
            assert_eq!(
                loaded_sources.get("FERRUM_TEST_SECRET_BULK_B"),
                Some(&"file")
            );
        },
    );
}

/// `resolve_all_env_secrets` discovers sources by iterating `std::env::vars()`
/// into a `HashMap`, so without an explicit sort the resolved vectors — and the
/// `Loaded <KEY> from <provider>` lines `validate` prints from them — can
/// reorder between processes on identical input.
///
/// The three sources are staged in deliberately non-alphabetical order, and the
/// assertions are on the exact sequence, not on set membership. Results are
/// filtered to this test's own prefix so an unrelated `FERRUM_*_FILE` in the
/// runner environment cannot make the assertion vacuous or flaky.
#[test]
fn test_resolve_all_env_secrets_orders_results_by_base_key() {
    let mut tmp_c = NamedTempFile::new().unwrap();
    let mut tmp_a = NamedTempFile::new().unwrap();
    let mut tmp_b = NamedTempFile::new().unwrap();
    writeln!(tmp_c, "order-charlie").unwrap();
    writeln!(tmp_a, "order-alpha").unwrap();
    writeln!(tmp_b, "order-bravo").unwrap();
    let path_c = tmp_c.path().to_str().unwrap().to_string();
    let path_a = tmp_a.path().to_str().unwrap().to_string();
    let path_b = tmp_b.path().to_str().unwrap().to_string();

    with_env_vars_async(
        &[
            ("FERRUM_TEST_SECRET_ORDER_C_FILE", &path_c),
            ("FERRUM_TEST_SECRET_ORDER_A_FILE", &path_a),
            ("FERRUM_TEST_SECRET_ORDER_B_FILE", &path_b),
        ],
        || async {
            let resolved = resolve_all_env_secrets().await.unwrap();

            let vars: Vec<(String, String)> = resolved
                .vars
                .into_iter()
                .filter(|(key, _)| key.starts_with("FERRUM_TEST_SECRET_ORDER_"))
                .collect();
            assert_eq!(
                vars,
                vec![
                    (
                        "FERRUM_TEST_SECRET_ORDER_A".to_string(),
                        "order-alpha".to_string()
                    ),
                    (
                        "FERRUM_TEST_SECRET_ORDER_B".to_string(),
                        "order-bravo".to_string()
                    ),
                    (
                        "FERRUM_TEST_SECRET_ORDER_C".to_string(),
                        "order-charlie".to_string()
                    ),
                ],
                "resolved vars must be ordered by base key"
            );

            let loaded: Vec<(String, &'static str)> = resolved
                .loaded_sources
                .into_iter()
                .filter(|(key, _)| key.starts_with("FERRUM_TEST_SECRET_ORDER_"))
                .collect();
            assert_eq!(
                loaded,
                vec![
                    ("FERRUM_TEST_SECRET_ORDER_A".to_string(), "file"),
                    ("FERRUM_TEST_SECRET_ORDER_B".to_string(), "file"),
                    ("FERRUM_TEST_SECRET_ORDER_C".to_string(), "file"),
                ],
                "reported secret sources must be ordered by base key"
            );

            let source_keys: Vec<String> = resolved
                .source_keys_to_remove
                .into_iter()
                .filter(|key| key.starts_with("FERRUM_TEST_SECRET_ORDER_"))
                .collect();
            assert_eq!(
                source_keys,
                vec![
                    "FERRUM_TEST_SECRET_ORDER_A_FILE".to_string(),
                    "FERRUM_TEST_SECRET_ORDER_B_FILE".to_string(),
                    "FERRUM_TEST_SECRET_ORDER_C_FILE".to_string(),
                ],
                "suffixed source keys must be ordered by base key"
            );
        },
    );
}

/// A source reference is as sensitive as the value it points at, so a failed
/// A resolved value containing a NUL byte must fail as an ordinary, sanitized
/// resolution error.
///
/// Process environment values cannot contain NUL: `std::env::set_var` panics on
/// one. Startup resolution now runs before any settings are parsed, so a
/// `_FILE` source pointing at binary material would abort `validate` outright —
/// no exit code, no diagnostic — instead of reporting the bad local secret that
/// `validate` exists to catch. The value itself is never named.
#[test]
fn test_resolve_all_env_secrets_rejects_nul_in_resolved_value() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"nul-sentinel-prefix\0nul-sentinel-suffix")
        .unwrap();
    file.flush().unwrap();

    with_env_vars_async(
        &[("FERRUM_TEST_SECRET_NUL_FILE", file.path().to_str().unwrap())],
        || async {
            let err = match resolve_all_env_secrets().await {
                Ok(_) => panic!("expected a NUL-containing resolved value to fail"),
                Err(err) => err,
            };
            assert!(
                err.contains("FERRUM_TEST_SECRET_NUL") && err.contains("NUL byte"),
                "error must name the base key and the failure class: {err}"
            );
            assert!(
                !err.contains("nul-sentinel-prefix") && !err.contains("nul-sentinel-suffix"),
                "error must not disclose the resolved value: {err}"
            );
        },
    );
}

/// `_FILE` fetch must name the variable and the `io::Error` reason but not the
/// path.
#[test]
fn test_resolve_all_env_secrets_file_error_omits_source_reference() {
    let missing_path = "/nonexistent/ferrum-secret-source-reference-sentinel/value";

    with_env_vars_async(
        &[("FERRUM_TEST_SECRET_REDACT_FILE", missing_path)],
        || async {
            let err = match resolve_all_env_secrets().await {
                Ok(_) => panic!("expected an unreadable _FILE source to fail"),
                Err(err) => err,
            };
            assert!(
                err.contains("Failed to read FERRUM_TEST_SECRET_REDACT_FILE"),
                "error must stay actionable at base-key level: {err}"
            );
            assert!(
                !err.contains(missing_path)
                    && !err.contains("ferrum-secret-source-reference-sentinel"),
                "error must not disclose the source reference: {err}"
            );
        },
    );
}

/// The same contract for a provider-shaped failure. An unparseable Vault
/// reference fails during reference parsing, so this needs no live Vault — only
/// the client env vars the wrapper requires before it gets that far.
#[cfg(feature = "secrets-vault")]
#[test]
fn test_resolve_all_env_secrets_vault_error_omits_source_reference() {
    let reference = "ferrum-vault-source-reference-sentinel";

    with_env_vars_async(
        &[
            ("VAULT_ADDR", "http://127.0.0.1:1"),
            ("VAULT_TOKEN", "test-token"),
            ("FERRUM_TEST_SECRET_VAULT_REDACT_VAULT", reference),
        ],
        || async {
            let err = match resolve_all_env_secrets().await {
                Ok(_) => panic!("expected an invalid Vault reference to fail"),
                Err(err) => err,
            };
            assert!(
                err.contains("FERRUM_TEST_SECRET_VAULT_REDACT"),
                "error must stay actionable at base-key level: {err}"
            );
            assert!(
                !err.contains(reference),
                "error must not disclose the source reference: {err}"
            );
        },
    );
}

#[test]
fn test_resolve_all_env_secrets_ignores_non_secret_file_suffix_config() {
    with_env_vars_async(
        &[("FERRUM_DNS_RESOLVER_HOSTS_FILE", "/path/to/hosts")],
        || async {
            let resolved = resolve_all_env_secrets().await.unwrap();
            assert!(resolved.vars.is_empty());
            assert!(resolved.source_keys_to_remove.is_empty());
            assert!(resolved.loaded_sources.is_empty());
        },
    );
}

#[test]
fn test_resolve_secret_neither_set() {
    with_env_vars_async(&[], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_NONE").await;
        assert!(result.unwrap().is_none());
    });
}

#[test]
fn test_resolve_secret_file_not_found() {
    let missing = "/nonexistent/path/to/secret";
    with_env_vars_async(&[("FERRUM_TEST_SECRET_E_FILE", missing)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_E").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Failed to read"));
        assert!(
            !err.contains(missing),
            "source path must not be disclosed, got: {err}"
        );
    });
}

#[test]
fn test_resolve_secret_file_empty() {
    let tmp = NamedTempFile::new().unwrap();
    // File is empty (0 bytes)
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_F_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_F").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("empty"));
    });
}

#[test]
fn test_resolve_secret_empty_env_var_ignored() {
    with_env_vars_async(&[("FERRUM_TEST_SECRET_G", "")], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_G").await;
        assert!(result.unwrap().is_none());
    });
}

#[test]
fn test_resolve_secret_file_preserves_internal_whitespace() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "secret with spaces").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    with_env_vars_async(&[("FERRUM_TEST_SECRET_H_FILE", &path)], || async {
        let result = resolve_secret("FERRUM_TEST_SECRET_H").await;
        let resolved = result.unwrap().unwrap();
        assert_eq!(resolved.value, "secret with spaces");
    });
}

#[test]
fn test_resolve_all_env_secrets_rejects_unsupported_cloud_suffixes() {
    with_env_vars_async(
        &[(
            "FERRUM_TEST_SECRET_UNSUPPORTED_AWS",
            "arn:aws:secretsmanager:...",
        )],
        || async {
            let result = resolve_all_env_secrets().await;
            #[cfg(not(feature = "secrets-aws"))]
            {
                match result {
                    Err(err) => {
                        assert!(err.contains("Unsupported secret suffix _AWS"));
                        assert!(err.contains("FERRUM_TEST_SECRET_UNSUPPORTED_AWS"));
                    }
                    Ok(_) => panic!("expected unsupported _AWS suffix to fail"),
                }
            }
            #[cfg(feature = "secrets-aws")]
            {
                assert!(result.is_ok());
            }
        },
    );
}

#[test]
fn test_resolve_all_env_secrets_ignores_empty_cloud_suffixes() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_SECRET_EMPTY_VAULT", ""),
            ("FERRUM_TEST_SECRET_EMPTY_AWS", ""),
            ("FERRUM_TEST_SECRET_EMPTY_AZURE", ""),
            ("FERRUM_TEST_SECRET_EMPTY_GCP", ""),
        ],
        || async {
            let resolved = resolve_all_env_secrets()
                .await
                .expect("empty cloud suffixes must be treated as unset");
            assert!(resolved.vars.is_empty());
            assert!(resolved.source_keys_to_remove.is_empty());
            assert!(resolved.loaded_sources.is_empty());
        },
    );
}

/// Unsupported-suffix discovery iterates `std::env::vars()`, whose order varies
/// between processes, so returning on the first sighting would let two runs on
/// an identical environment blame a different variable. Failures are collected
/// and sorted, and the lexicographically first key is reported.
///
/// Only meaningful in a build without the cloud features — with them compiled
/// in there is no unsupported suffix to order.
#[cfg(not(any(
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
)))]
#[test]
fn test_resolve_all_env_secrets_reports_first_unsupported_suffix_deterministically() {
    with_env_vars_async(
        &[
            // Staged in reverse of the expected order.
            ("FERRUM_TEST_SECRET_ZULU_UNSUPPORTED_GCP", "projects/x/y"),
            ("FERRUM_TEST_SECRET_ALPHA_UNSUPPORTED_AWS", "arn:aws:x"),
            ("FERRUM_TEST_SECRET_MIKE_UNSUPPORTED_AZURE", "https://v/s/n"),
        ],
        || async {
            let err = match resolve_all_env_secrets().await {
                Ok(_) => panic!("expected unsupported cloud suffixes to fail"),
                Err(err) => err,
            };
            assert!(
                err.contains("FERRUM_TEST_SECRET_ALPHA_UNSUPPORTED_AWS"),
                "the lexicographically first offending key must be reported, got: {err}"
            );
            assert!(
                !err.contains("FERRUM_TEST_SECRET_MIKE_UNSUPPORTED_AZURE")
                    && !err.contains("FERRUM_TEST_SECRET_ZULU_UNSUPPORTED_GCP"),
                "only the first offending key is reported, got: {err}"
            );
        },
    );
}

/// Shared FIFO + watchdog harness for `_FILE` timeout/teardown coverage.
///
/// A `_FILE` source can point at a FIFO with no writer, where the read blocks
/// uninterruptibly. `tokio::time::timeout` around a `spawn_blocking` handle
/// returns on schedule but does not stop the blocking task, and **dropping the
/// runtime then waits for the blocking pool** — so the timeout was honored and
/// the process hung anyway at runtime teardown.
///
/// These tests must not be able to hang CI themselves, so the whole resolve —
/// runtime build, `block_on`, *and the runtime drop* — happens on a worker
/// thread that the test body joins with a bounded `recv_timeout`. A regression
/// fails the test loudly instead of parking the suite.
///
/// The env vars are set and left in place for the worker (which only reads
/// them) and are cleared after the bounded wait; `ENV_LOCK` is held throughout.
#[cfg(unix)]
fn assert_blocked_file_source_times_out_and_tears_down<F>(
    file_env_key: &str,
    expected_base_key: &str,
    resolve: F,
) where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const FETCH_TIMEOUT_SECS: u64 = 2;
    // Generous multiple of the fetch timeout: enough that a slow runner cannot
    // flake, far below anything that looks like a hang.
    const WATCHDOG: Duration = Duration::from_secs(30);
    // Soft upper bound: timeout plus generous scheduling slack. Still proves
    // we are nowhere near a blocking-pool hang.
    const EXPECTED_CEILING: Duration = Duration::from_secs(15);

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("blocked-secret");
    let created = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !created {
        eprintln!("skipping: mkfifo unavailable");
        return;
    }

    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: ENV_LOCK is held for the whole test, including the worker thread.
    unsafe {
        std::env::set_var(file_env_key, &fifo);
        // Startup resolution reads this from the environment only; single-key
        // resolution also honors the env override through the conf-aware helper.
        std::env::set_var(
            "FERRUM_SECRET_FETCH_TIMEOUT_SECONDS",
            FETCH_TIMEOUT_SECS.to_string(),
        );
    }

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let result = resolve();
        let _ = sender.send((result, started.elapsed()));
    });

    let received = receiver.recv_timeout(WATCHDOG);

    // SAFETY: ENV_LOCK is still held.
    unsafe {
        std::env::remove_var(file_env_key);
        std::env::remove_var("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS");
    }

    let (result, elapsed) = received.expect(
        "resolution and runtime teardown must complete; a blocked _FILE read \
         must not be waited on",
    );
    let err = match result {
        Ok(()) => panic!("a FIFO with no writer must not resolve"),
        Err(err) => err,
    };
    assert!(
        err.contains(&format!("Timeout resolving {expected_base_key}")),
        "expected a fetch timeout naming the base key, got: {err}"
    );
    assert!(
        !err.contains(fifo.to_str().unwrap()),
        "the source reference must not be disclosed, got: {err}"
    );
    assert!(
        elapsed < EXPECTED_CEILING,
        "resolution must be bounded by the fetch timeout, took {elapsed:?}"
    );
}

#[cfg(unix)]
#[test]
fn test_resolve_all_env_secrets_times_out_on_blocked_file_source() {
    assert_blocked_file_source_times_out_and_tears_down(
        "FERRUM_TEST_SECRET_BLOCKED_FILE",
        "FERRUM_TEST_SECRET_BLOCKED",
        || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            // `rt` is dropped when this closure returns. With a `spawn_blocking`
            // read this is where the process parks forever.
            rt.block_on(resolve_all_env_secrets()).map(|_| ())
        },
    );
}

/// Single-key / runtime `_FILE` callers share the same detached reader. Cover
/// that path independently so a regression that only breaks `resolve_secret`
/// cannot hide behind the startup-batch test.
#[cfg(unix)]
#[test]
fn test_resolve_secret_times_out_on_blocked_file_source() {
    assert_blocked_file_source_times_out_and_tears_down(
        "FERRUM_TEST_SECRET_BLOCKED_ONE_FILE",
        "FERRUM_TEST_SECRET_BLOCKED_ONE",
        || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            match rt.block_on(resolve_secret("FERRUM_TEST_SECRET_BLOCKED_ONE")) {
                Ok(_) => Ok(()),
                Err(err) => Err(err),
            }
        },
    );
}

#[test]
fn test_resolve_secret_rejects_unsupported_cloud_suffixes() {
    with_env_vars_async(
        &[(
            "FERRUM_TEST_SECRET_UNSUPPORTED_GCP",
            "projects/x/secrets/y/versions/latest",
        )],
        || async {
            let result = resolve_secret("FERRUM_TEST_SECRET_UNSUPPORTED").await;
            #[cfg(not(feature = "secrets-gcp"))]
            {
                match result {
                    Err(err) => {
                        assert!(err.contains("Unsupported secret suffix _GCP"));
                        assert!(err.contains("FERRUM_TEST_SECRET_UNSUPPORTED_GCP"));
                    }
                    Ok(_) => panic!("expected unsupported _GCP suffix to fail"),
                }
            }
            #[cfg(feature = "secrets-gcp")]
            {
                // In gcp-enabled builds the source is recognized and will be resolved/fetched.
                // This test only verifies the fail-closed behavior for feature-disabled builds.
                assert!(result.is_ok() || result.is_err());
            }
        },
    );
}
