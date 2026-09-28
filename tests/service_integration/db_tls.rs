//! Real PostgreSQL/MySQL TLS handshakes and retained-pool connection churn.

use std::path::PathBuf;
use std::time::Duration;

use ferrum_edge::_test_support::DbPoolConfig;
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::DatabaseStore;
use ferrum_edge::config::types::Consumer;
use ferrum_edge::config::{DbTlsMode, EnvConfig};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use sqlx::Row;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::containers::{BoxError, fail_in_ci_else_skip, start_within_deadline};
use super::common::host_ports::{allocate_host_port, retry_on_host_port_collision};

struct SqlTlsFixture {
    _container: ContainerAsync<GenericImage>,
    _certificates: tempfile::TempDir,
    env: EnvConfig,
    ca_path: PathBuf,
    ca_pem: String,
    wrong_ca_pem: String,
}

fn ca() -> Result<(String, Issuer<'static, KeyPair>), BoxError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let pem = params.self_signed(&key)?.pem();
    Ok((pem, Issuer::new(params, key)))
}

fn pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 1,
        min_connections: 0,
        acquire_timeout_seconds: 3,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
        ..DbPoolConfig::default()
    }
}

impl SqlTlsFixture {
    fn url(&self, mode: DbTlsMode, matching_name: bool) -> String {
        let mut env = self.env.clone();
        env.db_tls_mode = Some(mode);
        if matching_name {
            let mut url = url::Url::parse(env.db_url.as_ref().unwrap()).unwrap();
            url.set_host(Some("localhost")).unwrap();
            env.db_url = Some(url.into());
        }
        env.effective_db_url().unwrap().unwrap()
    }

    async fn connect(&self, mode: DbTlsMode, matching_name: bool) -> anyhow::Result<DatabaseStore> {
        DatabaseStore::connect_with_pool_config(
            self.env.db_type.as_deref().unwrap(),
            &self.url(mode, matching_name),
            pool_config(),
        )
        .await
    }
}

async fn start_fixture(db_type: &str, expired: bool) -> Result<SqlTlsFixture, BoxError> {
    let certificates = tempfile::tempdir()?;
    let (ca_pem, issuer) = ca()?;
    let (wrong_ca_pem, _) = ca()?;
    let key = KeyPair::generate()?;
    // Deliberately no IP SAN: 127.0.0.1 must fail only under verify-full.
    let mut params = CertificateParams::new(vec!["localhost".into()])?;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    if expired {
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    }
    let server_pem = params.signed_by(&key, &issuer)?.pem();
    let ca_path = certificates.path().join("watched-ca.pem");
    std::fs::write(&ca_path, &ca_pem)?;
    let (container, port) = retry_on_host_port_collision(|| async {
        let port = allocate_host_port()?;
        let image = || {
            let image = if db_type == "postgres" {
                GenericImage::new("postgres", "17")
                    .with_entrypoint("/bin/sh")
                    .with_exposed_port(5432.tcp())
                    .with_mapped_port(port, 5432.tcp())
                    .with_env_var("POSTGRES_USER", "ferrum")
                    .with_env_var("POSTGRES_PASSWORD", "fixture-password")
                    .with_env_var("POSTGRES_DB", "ferrum")
                    .with_cmd([
                        "-ec",
                        "chown postgres:postgres /tmp/server.key\n\
                         chmod 600 /tmp/server.key\n\
                         exec docker-entrypoint.sh postgres -c ssl=on \
                         -c ssl_cert_file=/tmp/server.pem -c ssl_key_file=/tmp/server.key",
                    ])
            } else {
                GenericImage::new("mysql", "8.4")
                    .with_entrypoint("/bin/sh")
                    .with_exposed_port(3306.tcp())
                    .with_mapped_port(port, 3306.tcp())
                    .with_env_var("MYSQL_ROOT_PASSWORD", "fixture-password")
                    .with_env_var("MYSQL_ROOT_HOST", "%")
                    .with_env_var("MYSQL_DATABASE", "ferrum")
                    .with_cmd([
                        "-ec",
                        "chown mysql:mysql /tmp/server.key\n\
                         chmod 600 /tmp/server.key\n\
                         exec docker-entrypoint.sh mysqld --require-secure-transport=ON \
                         --ssl-cert=/tmp/server.pem --ssl-key=/tmp/server.key --ssl-ca=/tmp/ca.pem",
                    ])
            };
            image
                .with_copy_to("/tmp/server.pem", server_pem.as_bytes().to_vec())
                .with_copy_to("/tmp/server.key", key.serialize_pem().into_bytes())
                .with_copy_to("/tmp/ca.pem", ca_pem.as_bytes().to_vec())
        };
        let container = start_within_deadline("SQL TLS", || image().start()).await?;
        Ok((container, port))
    })
    .await?;
    let username = if db_type == "postgres" {
        "ferrum"
    } else {
        "root"
    };
    let fixture = SqlTlsFixture {
        _container: container,
        _certificates: certificates,
        env: EnvConfig {
            db_type: Some(db_type.into()),
            db_url: Some(format!(
                "{db_type}://{username}:fixture-password@127.0.0.1:{port}/ferrum"
            )),
            db_tls_ca_cert_path: Some(ca_path.to_str().unwrap().into()),
            ..EnvConfig::default()
        },
        ca_path,
        ca_pem,
        wrong_ca_pem,
    };
    sqlx::any::install_default_drivers();
    // Prove the host-published mapping before testing policy. Require mode
    // permits the intentionally mismatched/expired cert, but still uses TLS.
    let readiness = fixture.url(DbTlsMode::Require, false);
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if let Ok(pool) = sqlx::any::AnyPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(2))
                .connect(&readiness)
                .await
            {
                sqlx::query("SELECT 1").fetch_one(&pool).await?;
                pool.close().await;
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| "SQL TLS published endpoint readiness timed out")??;
    Ok(fixture)
}

async fn connection_id_and_close(pool: &sqlx::AnyPool, db_type: &str) -> i64 {
    let mut connection = pool.acquire().await.unwrap();
    let query = if db_type == "postgres" {
        "SELECT CAST(pg_backend_pid() AS BIGINT)"
    } else {
        "SELECT CAST(CONNECTION_ID() AS SIGNED)"
    };
    let id = sqlx::query_scalar(query)
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    // Closing the only pooled connection forces a real new TLS handshake.
    connection.close().await.unwrap();
    id
}

async fn write_consumer(store: &DatabaseStore, id: &str) {
    let consumer = Consumer {
        labels: Default::default(),
        id: id.into(),
        namespace: "ferrum".into(),
        username: id.into(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_consumer(&consumer).await.unwrap();
    assert!(store.get_consumer("ferrum", id).await.unwrap().is_some());
}

async fn exercise_tls(db_type: &str) {
    let fixture = match start_fixture(db_type, false).await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip("db_tls", db_type, &error);
            return;
        }
    };
    let matching = fixture.connect(DbTlsMode::VerifyCa, true).await.unwrap();
    matching.pool().close().await;
    let mismatch = fixture.connect(DbTlsMode::VerifyCa, false).await.unwrap();
    // Server-side evidence on the same pool proves encryption as well as CRUD.
    if db_type == "postgres" {
        let encrypted: i32 = sqlx::query_scalar(
            "SELECT CASE WHEN ssl THEN 1 ELSE 0 END FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        )
        .fetch_one(&mismatch.pool())
        .await
        .unwrap();
        assert_eq!(encrypted, 1);
    } else {
        let row = sqlx::query("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
            .fetch_one(&mismatch.pool())
            .await
            .unwrap();
        assert!(!row.get::<String, _>(1).is_empty());
    }
    write_consumer(&mismatch, "verify-ca-mismatch").await;
    mismatch.pool().close().await;
    assert!(fixture.connect(DbTlsMode::VerifyFull, false).await.is_err());

    let mut store = fixture.connect(DbTlsMode::VerifyFull, true).await.unwrap();
    let url = fixture.url(DbTlsMode::VerifyFull, true);
    store.connect_read_replica(&url).await.unwrap();
    let pool = store.pool();
    write_consumer(&store, "before-churn").await;
    let first = connection_id_and_close(&pool, db_type).await;
    write_consumer(&store, "healthy-churn").await;
    let second = connection_id_and_close(&pool, db_type).await;
    assert_ne!(first, second);

    std::fs::write(&fixture.ca_path, &fixture.wrong_ca_pem).unwrap();
    // An unrelated, parseable CA must fail in both verification modes.
    assert!(fixture.connect(DbTlsMode::VerifyCa, false).await.is_err());
    assert!(store.reconnect_tls(&url, None).await.is_err());
    assert!(!pool.is_closed(), "rejection must retain the active pool");
    let mut previous = second;
    for index in 0..3 {
        write_consumer(&store, &format!("rejected-ca-churn-{index}")).await;
        let current = connection_id_and_close(&pool, db_type).await;
        assert_ne!(current, previous);
        previous = current;
    }
    std::fs::write(&fixture.ca_path, "not a PEM certificate").unwrap();
    assert!(store.reconnect_tls(&url, None).await.is_err());
    write_consumer(&store, "malformed-ca-churn").await;
    connection_id_and_close(&pool, db_type).await;

    // A good primary candidate plus a rejected replica must not publish the
    // primary early. The configured replica URL uses the same dedicated DB.
    std::fs::write(&fixture.ca_path, &fixture.ca_pem).unwrap();
    let wrong_path = fixture._certificates.path().join("wrong-ca.pem");
    std::fs::write(&wrong_path, &fixture.wrong_ca_pem).unwrap();
    let mut replica_env = fixture.env.clone();
    replica_env.db_tls_ca_cert_path = Some(wrong_path.to_str().unwrap().into());
    replica_env.db_tls_mode = Some(DbTlsMode::VerifyCa);
    let bad_replica = replica_env.effective_db_url().unwrap().unwrap();
    assert!(store.reconnect_tls(&url, Some(&bad_replica)).await.is_err());
    assert!(!pool.is_closed());
    assert!(store.read_replica_available());
    write_consumer(&store, "rejected-replica").await;

    // Accept a byte-distinct valid bundle, then remove the watched file. Both
    // the new pool and the staged replica retain their copies.
    std::fs::write(&fixture.ca_path, format!("{}\n", fixture.ca_pem)).unwrap();
    store.reconnect_tls(&url, Some(&url)).await.unwrap();
    let replacement = store.pool();
    connection_id_and_close(&replacement, db_type).await;
    std::fs::remove_file(&fixture.ca_path).unwrap();
    write_consumer(&store, "accepted-reload-churn").await;
    store.list_proxies_paginated("ferrum", 10, 0).await.unwrap();
    assert!(store.read_replica_available());
    replacement.close().await;
}

#[tokio::test]
async fn postgres_tls_verify_ca_and_rejected_reload_reconnect() {
    exercise_tls("postgres").await;
}

#[tokio::test]
async fn mysql_tls_verify_ca_and_rejected_reload_reconnect() {
    exercise_tls("mysql").await;
}

async fn exercise_expiry(db_type: &str) {
    let fixture = match start_fixture(db_type, true).await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip("db_tls_expired", db_type, &error);
            return;
        }
    };
    for mode in [DbTlsMode::VerifyCa, DbTlsMode::VerifyFull] {
        assert!(fixture.connect(mode, true).await.is_err());
    }
}

#[tokio::test]
async fn postgres_tls_rejects_expired_server_certificate() {
    exercise_expiry("postgres").await;
}

#[tokio::test]
async fn mysql_tls_rejects_expired_server_certificate() {
    exercise_expiry("mysql").await;
}
