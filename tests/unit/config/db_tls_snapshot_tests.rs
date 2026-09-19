use std::path::PathBuf;
use std::str::FromStr;

use ferrum_edge::_test_support::SqlTlsSnapshot;
use ferrum_edge::config::{DbTlsMode, EnvConfig, OperatingMode};
use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use crate::unit::env_lock::with_env_vars;
#[cfg(unix)]
use crate::unit::env_lock::with_env_vars_async;

fn material_path(snapshot: &SqlTlsSnapshot, key: &str) -> PathBuf {
    url::Url::parse(snapshot.url())
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| PathBuf::from(value.as_ref()))
        .unwrap()
}

#[test]
fn sql_tls_modes_match_native_drivers_for_every_database_consumer() {
    with_env_vars(&[], || {
        for mode in [
            OperatingMode::Database,
            OperatingMode::ControlPlane,
            OperatingMode::Migrate,
        ] {
            for (tls, pg, mysql) in [
                (
                    DbTlsMode::Disable,
                    PgSslMode::Disable,
                    MySqlSslMode::Disabled,
                ),
                (
                    DbTlsMode::Prefer,
                    PgSslMode::Prefer,
                    MySqlSslMode::Preferred,
                ),
                (
                    DbTlsMode::Require,
                    PgSslMode::Require,
                    MySqlSslMode::Required,
                ),
                (
                    DbTlsMode::VerifyCa,
                    PgSslMode::VerifyCa,
                    MySqlSslMode::VerifyCa,
                ),
                (
                    DbTlsMode::VerifyFull,
                    PgSslMode::VerifyFull,
                    MySqlSslMode::VerifyIdentity,
                ),
            ] {
                for db_type in ["postgres", "mysql"] {
                    let base = format!("{db_type}://localhost/ferrum");
                    let env = EnvConfig {
                        mode: mode.clone(),
                        db_type: Some(db_type.into()),
                        db_url: Some(base.clone()),
                        db_failover_urls: vec![base.clone()],
                        db_read_replica_url: Some(base),
                        db_tls_mode: Some(tls),
                        ..EnvConfig::default()
                    };
                    let mut urls = env.effective_db_failover_urls().unwrap();
                    urls.push(env.effective_db_url().unwrap().unwrap());
                    urls.push(env.effective_db_read_replica_url().unwrap().unwrap());
                    for url in urls {
                        // The driver ssl-mode enums do not implement `PartialEq`;
                        // compare their `Debug` renderings instead.
                        if db_type == "postgres" {
                            let actual = PgConnectOptions::from_str(&url).unwrap().get_ssl_mode();
                            assert_eq!(format!("{actual:?}"), format!("{pg:?}"));
                        } else {
                            let actual =
                                MySqlConnectOptions::from_str(&url).unwrap().get_ssl_mode();
                            assert_eq!(format!("{actual:?}"), format!("{mysql:?}"));
                        }
                    }
                }
            }
        }
    });
}

#[test]
fn sql_tls_snapshot_keeps_all_accepted_material_after_source_replacement() {
    with_env_vars(&[], || {
        for (db_type, ca_key, cert_key, key_key) in [
            ("postgres", "sslrootcert", "sslcert", "sslkey"),
            ("mysql", "ssl-ca", "ssl-cert", "ssl-key"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut url = url::Url::parse(&format!("{db_type}://localhost/ferrum")).unwrap();
            for key in [ca_key, cert_key, key_key] {
                let path = dir.path().join(format!("{key} & material.pem"));
                std::fs::write(&path, format!("accepted {key}")).unwrap();
                url.query_pairs_mut()
                    .append_pair(key, path.to_str().unwrap());
            }
            let accepted = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            let retained = material_path(&accepted, ca_key);
            for key in [ca_key, cert_key, key_key] {
                std::fs::write(
                    dir.path().join(format!("{key} & material.pem")),
                    format!("candidate {key}"),
                )
                .unwrap();
                assert_eq!(
                    std::fs::read_to_string(material_path(&accepted, key)).unwrap(),
                    format!("accepted {key}"),
                );
            }
            let candidate = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            assert_eq!(
                std::fs::read_to_string(material_path(&candidate, ca_key)).unwrap(),
                format!("candidate {ca_key}"),
            );
            let rejected_path = material_path(&candidate, ca_key);
            drop(candidate);
            assert!(!rejected_path.exists());
            assert!(retained.exists());
            std::fs::remove_dir_all(dir.path()).unwrap();
            assert!(SqlTlsSnapshot::load(url.as_str(), db_type).is_err());
            assert_eq!(
                std::fs::read_to_string(&retained).unwrap(),
                format!("accepted {ca_key}"),
            );
            drop(accepted);
            assert!(!retained.exists());
        }
    });
}

#[test]
fn sql_tls_snapshot_selects_last_driver_alias_without_reading_shadowed_paths() {
    with_env_vars(&[], || {
        for (db_type, first, last) in [
            ("postgres", "sslrootcert", "ssl-ca"),
            ("mysql", "sslca", "ssl-ca"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ca.pem");
            std::fs::write(&path, "accepted CA").unwrap();
            let mut url = url::Url::parse(&format!("{db_type}://localhost/ferrum")).unwrap();
            url.query_pairs_mut()
                .append_pair(first, "/missing/shadowed.pem")
                .append_pair(last, path.to_str().unwrap());
            let snapshot = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            assert_eq!(
                std::fs::read_to_string(material_path(&snapshot, last)).unwrap(),
                "accepted CA",
            );
            assert!(!snapshot.url().contains("shadowed"));
        }
        let url = "sqlite::memory:";
        assert_eq!(SqlTlsSnapshot::load(url, "sqlite").unwrap().url(), url);
    });
}

#[cfg(unix)]
#[test]
fn sql_tls_snapshot_files_are_owner_only_and_scrubbed_before_unlink() {
    use std::os::unix::fs::PermissionsExt;

    with_env_vars(&[], || {
        for (db_type, ca_key, cert_key, key_key) in [
            ("postgres", "sslrootcert", "sslcert", "sslkey"),
            ("mysql", "ssl-ca", "ssl-cert", "ssl-key"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut url = url::Url::parse(&format!("{db_type}://localhost/ferrum")).unwrap();
            for key in [ca_key, cert_key, key_key] {
                let path = dir.path().join(format!("{key}.pem"));
                // Deliberately world-readable at the source: the private copy
                // must not inherit it.
                std::fs::write(&path, format!("secret {key} material")).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
                url.query_pairs_mut()
                    .append_pair(key, path.to_str().unwrap());
            }

            let snapshot = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            let mut snapshot_paths = Vec::new();
            for key in [ca_key, cert_key, key_key] {
                let path = material_path(&snapshot, key);
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "{db_type} {key} snapshot must be owner-read/write only, got {mode:#o}"
                );
                snapshot_paths.push(path);
            }

            // Hard-link one copy so the bytes stay reachable after the snapshot
            // unlinks its own name; the scrub must have zeroed them first.
            let key_index = 2;
            let observer = dir.path().join("observer.pem");
            std::fs::hard_link(&snapshot_paths[key_index], &observer).unwrap();
            assert_eq!(
                std::fs::read(&observer).unwrap(),
                format!("secret {key_key} material").into_bytes(),
            );

            drop(snapshot);
            for path in &snapshot_paths {
                assert!(!path.exists(), "snapshot file must be unlinked on drop");
            }
            let scrubbed = std::fs::read(&observer).unwrap();
            assert!(
                scrubbed.iter().all(|byte| *byte == 0),
                "{db_type} private key copy must be zeroed before unlink, got {scrubbed:?}"
            );
            assert_eq!(scrubbed.len(), format!("secret {key_key} material").len());
        }
    });
}

fn source_env(db_type: &str, material: &str) -> EnvConfig {
    let base = format!("{db_type}://user:dsn-canary@localhost/ferrum");
    EnvConfig {
        db_type: Some(db_type.into()),
        db_url: Some(base.clone()),
        db_failover_urls: vec![base.clone()],
        db_read_replica_url: Some(base),
        db_tls_mode: Some(DbTlsMode::VerifyFull),
        db_tls_ca_cert_path: Some(material.into()),
        db_tls_client_cert_path: Some(material.into()),
        db_tls_client_key_path: Some(material.into()),
        ..EnvConfig::default()
    }
}

#[cfg(unix)]
fn quiet_lazy_options() -> sqlx::any::AnyPoolOptions {
    sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .idle_timeout(None)
        .max_lifetime(None)
}

#[cfg(unix)]
fn private_paths(dir: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ferrum-sql-tls-")
        })
        .collect()
}

#[test]
fn sql_tls_url_helpers_preserve_sources_without_io_or_secret_diagnostics() {
    // An unusable TMPDIR proves none of the public URL helpers materializes
    // even inline PEM; unavailable providers must not be fetched here either.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    with_env_vars(&[("TMPDIR", missing.to_str().unwrap())], || {
        for db_type in ["postgres", "mysql"] {
            for source in [
                "/missing/material & +%#?.pem",
                "file:///missing/material%20file.pem",
                "vault://secret/canary?poll=60s&version=2#key",
                "aws://secret-canary?version=2&poll=5m",
                "azure://https://vault/secrets/canary/2?version=2",
                "gcp://projects/canary/secrets/key/versions/latest",
                "k8s://namespace/canary?key=tls.key&poll=60s",
                "managed://certificates/canary#key",
                "acme://certificates/canary#key",
                "-----BEGIN PRIVATE KEY-----\ninline+canary/=\n-----END PRIVATE KEY-----\n",
            ] {
                let env = source_env(db_type, source);
                let backend = env.effective_sql_backend().unwrap();
                let mut urls = env.effective_db_failover_urls().unwrap();
                urls.push(env.effective_db_url().unwrap().unwrap());
                urls.push(env.effective_db_read_replica_url().unwrap().unwrap());
                urls.push(backend.effective_url.clone());
                drop(env);
                for url in urls {
                    let parsed = url::Url::parse(&url).unwrap();
                    let pairs: Vec<_> = parsed.query_pairs().collect();
                    // Source delimiters must not add SQL options.
                    assert_eq!(pairs.len(), 4);
                    for (_, value) in &pairs[1..] {
                        assert_eq!(value.as_ref(), source);
                    }
                    let redacted = ferrum_edge::config::db_backend::redact_url(&url);
                    assert!(!redacted.contains("canary"));
                    assert!(!redacted.contains("BEGIN"));
                }
                let debug = format!("{backend:?}");
                assert!(!debug.contains("canary"));
                assert!(!debug.contains("BEGIN"));
            }
        }
    });
}

#[cfg(unix)]
#[test]
fn sql_tls_source_generations_belong_to_pools_and_failed_builds_leave_no_files() {
    let dir = tempfile::tempdir().unwrap();
    with_env_vars_async(&[("TMPDIR", dir.path().to_str().unwrap())], || async {
        let foreign = dir.path().join("ferrum-db-client-key-foreign.pem");
        std::fs::write(&foreign, "foreign owner").unwrap();
        for db_type in ["postgres", "mysql"] {
            let accepted_pem =
                "-----BEGIN PRIVATE KEY-----\naccepted-canary\n-----END PRIVATE KEY-----";
            let backend = source_env(db_type, accepted_pem)
                .effective_sql_backend()
                .unwrap();
            let pool = backend.connect_lazy(quiet_lazy_options(), 5).await.unwrap();
            drop(backend);
            let retained = private_paths(dir.path());
            assert_eq!(retained.len(), 3);
            let old_pool = pool.clone();
            drop(pool);
            for path in &retained {
                assert_eq!(std::fs::read_to_string(path).unwrap(), accepted_pem);
            }

            for _ in 0..3 {
                let candidate = source_env(db_type, "-----BEGIN CERTIFICATE-----\ncandidate");
                let candidate_pool = candidate
                    .effective_sql_backend()
                    .unwrap()
                    .connect_lazy(quiet_lazy_options(), 5)
                    .await
                    .unwrap();
                assert_eq!(private_paths(dir.path()).len(), 6);
                drop(candidate_pool);
                assert_eq!(private_paths(dir.path()).len(), 3);
            }
            let mut rejected = source_env(db_type, accepted_pem);
            rejected.db_tls_client_key_path =
                Some(dir.path().join("absent-key").to_str().unwrap().into());
            assert!(
                rejected
                    .effective_sql_backend()
                    .unwrap()
                    .connect_lazy(quiet_lazy_options(), 5)
                    .await
                    .is_err()
            );
            assert_eq!(
                private_paths(dir.path()).len(),
                3,
                "partial snapshots must be removed"
            );
            for path in &retained {
                assert_eq!(std::fs::read_to_string(path).unwrap(), accepted_pem);
            }
            drop(old_pool);
            assert!(private_paths(dir.path()).is_empty());
        }
        assert_eq!(std::fs::read_to_string(foreign).unwrap(), "foreign owner");
    });
}

#[cfg(unix)]
#[test]
fn sql_tls_snapshot_failure_is_fatal_except_for_offline_backup_bootstrap() {
    use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};

    let dir = tempfile::tempdir().unwrap();
    let not_directory = dir.path().join("not-a-directory");
    std::fs::write(&not_directory, "foreign owner").unwrap();
    with_env_vars_async(&[("TMPDIR", not_directory.to_str().unwrap())], || async {
        for db_type in ["postgres", "mysql"] {
            let backend = source_env(db_type, "-----BEGIN CERTIFICATE-----\nmaterial")
                .effective_sql_backend()
                .unwrap();
            assert!(backend.connect_lazy(quiet_lazy_options(), 5).await.is_err());
            let store = DatabaseStore::connect_offline_with_pool_config(
                db_type,
                &backend.effective_url,
                &[],
                DbPoolConfig {
                    min_connections: 0,
                    ..DbPoolConfig::default()
                },
            )
            .await
            .unwrap();
            let pool = store.pool();
            assert_eq!(pool.size(), 0, "offline bootstrap must not dial");
            assert_eq!(
                pool.connect_options().database_url.as_str(),
                backend.effective_url
            );
            pool.close().await;
        }
        assert_eq!(
            std::fs::read_to_string(&not_directory).unwrap(),
            "foreign owner"
        );
    });
}

#[cfg(unix)]
#[test]
fn sql_tls_offline_timeout_fences_abandoned_reads_without_pinning_runtime_teardown() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};

    use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("blocked-cert");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    with_env_vars(&[("TMPDIR", dir.path().to_str().unwrap())], || {
        let mut env = source_env("postgres", "-----BEGIN CERTIFICATE-----\naccepted");
        env.db_tls_client_cert_path = Some(fifo.to_str().unwrap().into());
        let url = env.effective_db_url().unwrap().unwrap();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                // The second attempt must time out waiting for the first
                // detached reader's permit, without spawning another reader.
                for _ in 0..2 {
                    let store = DatabaseStore::connect_offline_with_pool_config(
                        "postgres",
                        &url,
                        &[],
                        DbPoolConfig {
                            connect_timeout_seconds: 1,
                            min_connections: 0,
                            ..DbPoolConfig::default()
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(store.pool().connect_options().database_url.as_str(), url);
                    let sqlite = ferrum_edge::config::EffectiveSqlBackend {
                        db_type: "sqlite".into(),
                        effective_url: "sqlite::memory:".into(),
                    };
                    let pool = sqlite.connect_lazy(quiet_lazy_options(), 1).await.unwrap();
                    drop(pool);
                }
            });
            // This cannot finish with a blocked spawn_blocking reader.
            drop(runtime);
            finished_tx.send(()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut writer = loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
            {
                Ok(writer) => break writer,
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                    assert!(Instant::now() < deadline, "snapshot never reached the FIFO");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("FIFO writer: {error}"),
            }
        };
        // The first PEM was written before the reader reached the FIFO.
        let partial = private_paths(dir.path());
        assert_eq!(partial.len(), 1);
        let observer = dir.path().join("scrub-observer");
        std::fs::hard_link(&partial[0], &observer).unwrap();
        let original_len = std::fs::metadata(&observer).unwrap().len();
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("offline timeout and runtime drop must both finish while TLS read is blocked");
        worker.join().unwrap();
        assert_eq!(
            private_paths(dir.path()).len(),
            1,
            "one permit must fence repeated attempts"
        );
        writer.write_all(b"candidate certificate").unwrap();
        drop(writer);

        // A successful snapshot behind that same permit is a completion
        // barrier: the abandoned generation has been dropped and scrubbed.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let backend = source_env("postgres", "-----BEGIN CERTIFICATE-----\nrecovered")
                .effective_sql_backend()
                .unwrap();
            let pool = backend.connect_lazy(quiet_lazy_options(), 5).await.unwrap();
            drop(pool);
        });
        assert!(private_paths(dir.path()).is_empty());
        let scrubbed = std::fs::read(&observer).unwrap();
        assert_eq!(scrubbed.len() as u64, original_len);
        assert!(scrubbed.iter().all(|byte| *byte == 0));
    });
}
