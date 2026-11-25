//! TLS material references authored inside a namespace may only reach that
//! namespace's own material.
//!
//! The gateway resolves every reference with its own identity — its
//! Kubernetes ServiceAccount, cloud credentials, managed store, and
//! filesystem — so a namespace-scoped author must not be able to name another
//! namespace's Secret, a store only the gateway can read, or a gateway file
//! outside the operator-configured tenant file roots. These tests pin the
//! shared static predicate both the mesh DestinationRule boundary and the
//! namespace-claimed Admin API boundary call, plus the load-time re-check.

use std::path::PathBuf;

use ferrum_edge::config::env_config::parse_mesh_tenant_tls_file_roots;
use ferrum_edge::tls::source::{
    MaterialKind, ScopedMaterialReferenceRefusal, check_namespace_scoped_material_reference,
    check_tenant_file_reference_resolved,
};

const INLINE_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

fn check(value: &str, kind: MaterialKind, roots: &[PathBuf]) -> Result<(), String> {
    check_namespace_scoped_material_reference(value, kind, "tenant-a", roots)
        .map_err(|refusal| format!("{refusal:?}"))
}

fn roots(paths: &[&str]) -> Vec<PathBuf> {
    paths.iter().map(PathBuf::from).collect()
}

#[test]
fn own_namespace_secrets_inline_pem_and_system_roots_are_admitted() {
    assert_eq!(
        check("k8s://tenant-a/client-tls#tls.crt", MaterialKind::Cert, &[]),
        Ok(())
    );
    assert_eq!(
        check(
            "kubernetes://tenant-a/client-tls#tls.key",
            MaterialKind::Key,
            &[]
        ),
        Ok(())
    );
    assert_eq!(check(INLINE_CERT, MaterialKind::Cert, &[]), Ok(()));
    assert_eq!(check("system://", MaterialKind::CaBundle, &[]), Ok(()));
}

#[test]
fn another_namespaces_secret_is_refused() {
    let tenant_roots = roots(&["/etc/ferrum/tenant"]);
    for value in [
        "k8s://tenant-b/db-mtls#tls.crt",
        "k8s://egress/partner-mtls#tls.crt",
        "k8s-secret://kube-system/bootstrap#tls.crt",
        // A namespace that merely starts with the owner's name is another
        // namespace.
        "k8s://tenant-a-shadow/db-mtls#tls.crt",
    ] {
        assert_eq!(
            check_namespace_scoped_material_reference(
                value,
                MaterialKind::Cert,
                "tenant-a",
                &tenant_roots,
            ),
            Err(ScopedMaterialReferenceRefusal::ForeignNamespaceSecret),
            "{value} must be refused"
        );
    }
}

#[test]
fn malformed_kubernetes_reference_is_refused_rather_than_admitted() {
    assert_eq!(
        check_namespace_scoped_material_reference(
            "k8s://tenant-a",
            MaterialKind::Cert,
            "tenant-a",
            &[],
        ),
        Err(ScopedMaterialReferenceRefusal::ForeignNamespaceSecret)
    );
}

#[test]
fn an_empty_owner_namespace_admits_no_kubernetes_secret() {
    assert_eq!(
        check_namespace_scoped_material_reference(
            "k8s://tenant-a/client-tls#tls.crt",
            MaterialKind::Cert,
            "",
            &[],
        ),
        Err(ScopedMaterialReferenceRefusal::ForeignNamespaceSecret)
    );
}

#[test]
fn gateway_credential_stores_are_refused() {
    let tenant_roots = roots(&["/etc/ferrum/tenant"]);
    for value in [
        "vault://secret/data/other-team#tls.crt",
        "aws://arn:aws:secretsmanager:us-east-1:1:secret:x",
        "azure://vault.vault.azure.net/secrets/x",
        "gcp://projects/p/secrets/x/versions/latest",
        "managed://certificates/abc#cert",
        "acme://certificates/example.com#cert",
        "pkcs11://token/cert",
    ] {
        assert_eq!(
            check_namespace_scoped_material_reference(
                value,
                MaterialKind::Cert,
                "tenant-a",
                &tenant_roots,
            ),
            Err(ScopedMaterialReferenceRefusal::GatewayCredentialStore),
            "{value} must be refused even when tenant file roots are configured"
        );
    }
}

#[test]
fn local_files_are_refused_when_no_tenant_file_root_is_configured() {
    for value in [
        "/etc/ferrum/partner/tls.key",
        "file:///etc/ferrum/partner/tls.key",
        "relative/tls.key",
    ] {
        assert_eq!(
            check_namespace_scoped_material_reference(value, MaterialKind::Key, "tenant-a", &[]),
            Err(ScopedMaterialReferenceRefusal::GatewayLocalFile),
            "{value} must be refused when no tenant file root is configured"
        );
    }
}

#[test]
fn local_files_under_a_tenant_file_root_are_admitted() {
    let tenant_roots = roots(&["/var/run/tenant-certs", "/etc/ferrum/tenant"]);
    for value in [
        "/etc/ferrum/tenant/tls.key",
        "/etc/ferrum/tenant/nested/dir/tls.key",
        "file:///var/run/tenant-certs/tls.key",
        // Kubernetes projected-volume entries are ordinary names, not `..`.
        "/etc/ferrum/tenant/..data/tls.key",
    ] {
        assert_eq!(
            check(value, MaterialKind::Key, &tenant_roots),
            Ok(()),
            "{value} is under a configured root"
        );
    }
}

#[test]
fn local_files_outside_the_tenant_file_roots_are_refused() {
    let tenant_roots = roots(&["/etc/ferrum/tenant"]);
    for value in [
        // The platform's own material beside the tenant root.
        "/etc/ferrum/partner/tls.key",
        "file:///etc/ferrum/partner/tls.key",
        // A sibling whose name merely starts with the root's name.
        "/etc/ferrum/tenant-other/tls.key",
        // Traversal out of the root, lexically.
        "/etc/ferrum/tenant/../partner/tls.key",
        "file:///etc/ferrum/tenant/../partner/tls.key",
        // Relative paths resolve against the gateway's working directory.
        "etc/ferrum/tenant/tls.key",
        "file://etc/ferrum/tenant/tls.key",
    ] {
        assert_eq!(
            check_namespace_scoped_material_reference(
                value,
                MaterialKind::Key,
                "tenant-a",
                &tenant_roots,
            ),
            Err(ScopedMaterialReferenceRefusal::FileOutsideTenantRoots),
            "{value} must be refused"
        );
    }
}

#[test]
fn load_time_recheck_passes_non_file_references_through() {
    for value in [
        "k8s://tenant-a/client-tls#tls.crt",
        INLINE_CERT,
        "system://",
    ] {
        assert_eq!(
            check_tenant_file_reference_resolved(value, MaterialKind::Cert, &[]),
            Ok(()),
            "{value} is not a file"
        );
    }
}

#[test]
fn load_time_recheck_admits_a_real_file_inside_a_root() {
    let root = tempfile::tempdir().expect("tempdir");
    let file = root.path().join("tls.crt");
    std::fs::write(&file, "material").expect("write file");
    let tenant_roots = vec![root.path().to_path_buf()];
    let value = file.to_str().expect("utf-8 temp path");

    assert_eq!(
        check_tenant_file_reference_resolved(value, MaterialKind::Cert, &tenant_roots),
        Ok(())
    );
}

#[test]
fn load_time_recheck_refuses_a_missing_file() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing = root.path().join("absent.crt");
    let tenant_roots = vec![root.path().to_path_buf()];
    let value = missing.to_str().expect("utf-8 temp path");

    assert_eq!(
        check_tenant_file_reference_resolved(value, MaterialKind::Cert, &tenant_roots),
        Err(ScopedMaterialReferenceRefusal::FileOutsideTenantRoots)
    );
}

#[test]
fn load_time_recheck_refuses_a_file_lexically_outside_the_roots() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    let file = outside.path().join("tls.key");
    std::fs::write(&file, "material").expect("write file");
    let tenant_roots = vec![root.path().to_path_buf()];
    let value = file.to_str().expect("utf-8 temp path");

    assert_eq!(
        check_tenant_file_reference_resolved(value, MaterialKind::Key, &tenant_roots),
        Err(ScopedMaterialReferenceRefusal::FileOutsideTenantRoots)
    );
}

#[cfg(unix)]
#[test]
fn load_time_recheck_refuses_a_symlink_that_escapes_the_root() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    let target = outside.path().join("partner.key");
    std::fs::write(&target, "platform material").expect("write target");
    let link = root.path().join("tls.key");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let tenant_roots = vec![root.path().to_path_buf()];
    let value = link.to_str().expect("utf-8 temp path");

    // Lexically the link is under the root, so the static check admits it...
    assert_eq!(check(value, MaterialKind::Key, &tenant_roots), Ok(()));
    // ...but the node that reads it refuses once the link is resolved.
    assert_eq!(
        check_tenant_file_reference_resolved(value, MaterialKind::Key, &tenant_roots),
        Err(ScopedMaterialReferenceRefusal::FileOutsideTenantRoots)
    );
}

#[cfg(unix)]
#[test]
fn load_time_recheck_admits_a_symlink_that_stays_inside_the_root() {
    // Kubernetes Secret volumes publish `tls.key -> ..data/tls.key`.
    let root = tempfile::tempdir().expect("tempdir");
    let data = root.path().join("..data");
    std::fs::create_dir(&data).expect("data dir");
    std::fs::write(data.join("tls.key"), "material").expect("write target");
    let link = root.path().join("tls.key");
    std::os::unix::fs::symlink(data.join("tls.key"), &link).expect("symlink");
    let tenant_roots = vec![root.path().to_path_buf()];
    let value = link.to_str().expect("utf-8 temp path");

    assert_eq!(
        check_tenant_file_reference_resolved(value, MaterialKind::Key, &tenant_roots),
        Ok(())
    );
}

#[test]
fn refusal_reasons_never_echo_the_reference() {
    for refusal in [
        ScopedMaterialReferenceRefusal::ForeignNamespaceSecret,
        ScopedMaterialReferenceRefusal::GatewayCredentialStore,
        ScopedMaterialReferenceRefusal::GatewayLocalFile,
        ScopedMaterialReferenceRefusal::FileOutsideTenantRoots,
    ] {
        let reason = refusal.reason();
        assert!(!reason.is_empty());
        assert!(!reason.contains("tenant-b"), "{reason}");
        assert!(!reason.contains("/etc/"), "{reason}");
        // The startup renderer withholds quoted spans; a fixed reason must not
        // contain an apostrophe it would mistake for one.
        assert!(!reason.contains('\''), "{reason}");
    }
}

#[test]
fn tenant_file_roots_default_to_none() {
    assert_eq!(parse_mesh_tenant_tls_file_roots(None), Ok(Vec::new()));
    assert_eq!(parse_mesh_tenant_tls_file_roots(Some("")), Ok(Vec::new()));
    assert_eq!(
        parse_mesh_tenant_tls_file_roots(Some(" , ")),
        Ok(Vec::new())
    );
}

#[test]
fn tenant_file_roots_parse_trimmed_absolute_directories() {
    assert_eq!(
        parse_mesh_tenant_tls_file_roots(Some(" /run/tenant , /etc/tenant,/etc/tenant ")),
        Ok(roots(&["/run/tenant", "/etc/tenant"]))
    );
}

#[test]
fn tenant_file_roots_refuse_relative_traversal_and_filesystem_root() {
    for raw in [
        "certs",
        "/etc/tenant,relative-certs",
        "/etc/tenant/../certs",
        "/",
    ] {
        let error = parse_mesh_tenant_tls_file_roots(Some(raw))
            .expect_err("an unusable root must be refused");
        assert!(
            error.contains("FERRUM_MESH_TENANT_TLS_FILE_ROOTS"),
            "{error}"
        );
        // Diagnostics name the entry position, never the configured value.
        assert!(!error.contains("certs"), "{error}");
    }
}

fn bound_file(value: &str, kind: MaterialKind) -> String {
    ferrum_edge::_test_support::bind_tenant_tls_file_for_test(value, kind)
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn refused_tenant_file_does_not_freeze_other_backend_rotations_or_rebuild_every_poll() {
    use ferrum_edge::tls::source::{
        CertSource, load_material_blocking,
        subscription::{
            DynamicMaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
        },
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let trusted = dir.path().join("other-ca.pem");
    std::fs::write(&trusted, b"first accepted bytes").unwrap();
    // A tagged file denied by the shared process policy is the same watcher
    // failure path as an accepted tenant symlink later replaced outside roots.
    // Secure-open/escape behavior itself has separate deterministic tests.
    let denied = CertSource::parse(
        bound_file("/absent/tenant/refused.pem", MaterialKind::CaBundle),
        MaterialKind::CaBundle,
    );
    let sources = vec![
        WatchedMaterialSource::new("backend_ca", denied.clone(), MaterialKind::CaBundle),
        WatchedMaterialSource::new(
            "global_ca",
            CertSource::from_path(&trusted),
            MaterialKind::CaBundle,
        ),
    ];
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_rebuild = observed.clone();
    let trusted_rebuild = trusted.clone();
    let (revision_tx, mut revision_rx) = tokio::sync::watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = ferrum_edge::_test_support::spawn_backend_material_reload_for_test(
        DynamicMaterialSetReloadConfig {
            surface: "test_confined_backend_reload",
            collect_sources: Box::new(move || sources.clone()),
            file_default_interval: Duration::from_secs(3600),
            provider_default_interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: 4096,
            rebuild: Box::new(move || {
                assert!(
                    load_material_blocking(&denied, MaterialKind::CaBundle).is_err(),
                    "refused material must never become usable"
                );
                observed_rebuild
                    .lock()
                    .unwrap()
                    .push(std::fs::read(&trusted_rebuild).unwrap());
                Ok(())
            }),
        },
        Some(shutdown_rx),
    );
    tokio::time::timeout(Duration::from_secs(5), revision_rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        *revision_rx.borrow_and_update(),
        1,
        "initial refusal must invalidate cached configs"
    );
    assert_eq!(
        observed.lock().unwrap().as_slice(),
        &[b"first accepted bytes".to_vec()]
    );
    assert!(request_material_set_reload("test_confined_backend_reload"));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), revision_rx.changed())
            .await
            .is_err(),
        "unchanged refusal must not churn pools"
    );
    std::fs::write(&trusted, b"rotated accepted bytes").unwrap();
    assert!(request_material_set_reload("test_confined_backend_reload"));
    tokio::time::timeout(Duration::from_secs(5), revision_rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        *revision_rx.borrow_and_update(),
        2,
        "another source rotates despite the continuing refusal"
    );
    assert_eq!(
        observed.lock().unwrap().last().unwrap(),
        b"rotated accepted bytes"
    );
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

/// A tenant refusal whose first rebuild fails (for example a gateway CRL that
/// is briefly unreadable during the rebuild) must not be consumed: cached
/// configs are still valid for the refused destination, so the watcher retries
/// the unchanged candidate until a rebuild succeeds, then stops churning.
#[tokio::test]
async fn failed_rebuild_keeps_tenant_refusal_invalidation_pending_until_it_succeeds() {
    use ferrum_edge::tls::source::{
        CertSource,
        subscription::{
            DynamicMaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
        },
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    const SURFACE: &str = "test_confined_backend_reload_retry";
    let dir = tempfile::tempdir().unwrap();
    let trusted = dir.path().join("other-ca.pem");
    std::fs::write(&trusted, b"accepted bytes").unwrap();
    let denied = CertSource::parse(
        bound_file("/absent/tenant/retry.pem", MaterialKind::CaBundle),
        MaterialKind::CaBundle,
    );
    let sources = vec![
        WatchedMaterialSource::new("backend_ca", denied, MaterialKind::CaBundle),
        WatchedMaterialSource::new(
            "global_ca",
            CertSource::from_path(&trusted),
            MaterialKind::CaBundle,
        ),
    ];
    let attempts = Arc::new(AtomicUsize::new(0));
    let rebuild_attempts = attempts.clone();
    let (revision_tx, mut revision_rx) = tokio::sync::watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = ferrum_edge::_test_support::spawn_backend_material_reload_for_test(
        DynamicMaterialSetReloadConfig {
            surface: SURFACE,
            collect_sources: Box::new(move || sources.clone()),
            file_default_interval: Duration::from_secs(3600),
            provider_default_interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: 4096,
            rebuild: Box::new(move || {
                if rebuild_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    anyhow::bail!("transient gateway source failure during rebuild");
                }
                Ok(())
            }),
        },
        Some(shutdown_rx),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while attempts.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "initial refusal must attempt a rebuild"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        *revision_rx.borrow_and_update(),
        0,
        "the failed rebuild published nothing"
    );

    assert!(request_material_set_reload(SURFACE));
    tokio::time::timeout(Duration::from_secs(5), revision_rx.changed())
        .await
        .expect("an unchanged candidate with a pending refusal is retried")
        .unwrap();
    assert_eq!(*revision_rx.borrow_and_update(), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    assert!(request_material_set_reload(SURFACE));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), revision_rx.changed())
            .await
            .is_err(),
        "once applied, an unchanged refusal must not rebuild again"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

/// A tenant file the backend watcher observed refused stays held: a cache
/// built between two polls, while the file briefly resolves inside its root
/// again, cannot capture it. Only the watcher's own observed recovery (and
/// its cache-draining rebuild) lifts the hold, and the next refusal is held
/// again even though a cache was populated in between.
///
/// Tenant roots and the hold are process-global, so the body runs in its own
/// child process.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_tenant_refusal_blocks_cache_population_until_the_watcher_sees_recovery() {
    use ferrum_edge::tls::backend::BackendTlsConfigCache;
    use ferrum_edge::tls::source::{
        CertSource, install_mesh_tenant_tls_file_roots, load_material_blocking,
        subscription::{
            DynamicMaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
        },
    };
    use std::sync::Arc;
    use std::time::Duration;
    const CHILD_ENV: &str = "UNIT_TEST_TENANT_TLS_HOLD_CHILD";
    const TEST_NAME: &str = "unit::tls::scoped_material_reference_tests::\
         held_tenant_refusal_blocks_cache_population_until_the_watcher_sees_recovery";
    const SURFACE: &str = "test_tenant_refusal_hold";
    const KEY: &str = "ca=|cert=|key=|sni=|san=|verify=1|svidg=static";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve unit test executable"),
        )
        .env(CHILD_ENV, "1")
        .args(["--exact", TEST_NAME, "--nocapture"])
        .output()
        .expect("run isolated tenant hold test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated tenant hold test failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        return;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let work = tempfile::tempdir().unwrap();
    let root = work.path().join("tenant");
    let outside = work.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    install_mesh_tenant_tls_file_roots(vec![root.clone()]).unwrap();
    let replace_link = |link: &std::path::Path, target: &std::path::Path| {
        let next = link.with_extension("link-next");
        let _ = std::fs::remove_file(&next);
        std::os::unix::fs::symlink(target, &next).unwrap();
        std::fs::rename(&next, link).unwrap();
    };
    let inside = root.join("inside.pem");
    std::fs::write(&inside, b"tenant bytes").unwrap();
    let escaped = outside.join("platform.pem");
    std::fs::write(&escaped, b"platform bytes").unwrap();
    let link = root.join("ca.pem");
    replace_link(&link, &inside);
    let source = CertSource::parse(
        bound_file(link.to_str().unwrap(), MaterialKind::CaBundle),
        MaterialKind::CaBundle,
    );

    let cache = BackendTlsConfigCache::new();
    let build = |source: CertSource| {
        move || -> Result<rustls::ClientConfig, String> {
            load_material_blocking(&source, MaterialKind::CaBundle)
                .map_err(|error| error.to_string())?;
            Ok(rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth())
        }
    };

    let rebuild_cache = cache.clone();
    let sources = vec![WatchedMaterialSource::new(
        "backend_ca",
        source.clone(),
        MaterialKind::CaBundle,
    )];
    let (revision_tx, mut revision_rx) = tokio::sync::watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = ferrum_edge::_test_support::spawn_backend_material_reload_for_test(
        DynamicMaterialSetReloadConfig {
            surface: SURFACE,
            collect_sources: Box::new(move || sources.clone()),
            file_default_interval: Duration::from_secs(3600),
            provider_default_interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: 4096,
            rebuild: Box::new(move || {
                rebuild_cache.clear();
                Ok(())
            }),
        },
        Some(shutdown_rx),
    );
    async fn next_revision(rx: &mut tokio::sync::watch::Receiver<u64>) -> u64 {
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the watcher publishes a revision")
            .unwrap();
        *rx.borrow_and_update()
    }

    // Accepted: the cache fills from the confined file.
    assert!(
        cache
            .get_or_try_build(KEY.to_string(), build(source.clone()))
            .is_ok()
    );
    assert!(cache.contains_key(KEY));

    // Escape: the watcher observes the refusal, holds it, and drains.
    replace_link(&link, &escaped);
    assert!(request_material_set_reload(SURFACE));
    assert_eq!(next_revision(&mut revision_rx).await, 1);
    assert!(cache.is_empty(), "the refusal drains cached configs");

    // Brief recovery between polls: the file resolves inside its root again,
    // but the watcher has not observed it, so nothing can be cached.
    replace_link(&link, &inside);
    assert!(load_material_blocking(&source, MaterialKind::CaBundle).is_err());
    assert!(
        cache
            .get_or_try_build(KEY.to_string(), build(source.clone()))
            .is_err()
    );
    assert!(
        cache.is_empty(),
        "a held refusal must not populate the cache"
    );

    // Escape again before the next poll: the unchanged refusal stays held.
    replace_link(&link, &escaped);
    assert!(request_material_set_reload(SURFACE));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        cache
            .get_or_try_build(KEY.to_string(), build(source.clone()))
            .is_err()
    );
    assert!(cache.is_empty());

    // Real recovery observed by the watcher lifts the hold.
    replace_link(&link, &inside);
    assert!(request_material_set_reload(SURFACE));
    assert_eq!(next_revision(&mut revision_rx).await, 2);
    assert!(
        cache
            .get_or_try_build(KEY.to_string(), build(source.clone()))
            .is_ok()
    );

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        load_material_blocking(&source, MaterialKind::CaBundle).is_ok(),
        "a stopped watcher releases its holds"
    );
}

#[test]
fn constrained_file_uri_roundtrip_keeps_path_options_identity_and_refreshability() {
    use ferrum_edge::tls::source::{
        CertSource,
        subscription::{source_is_refreshable, source_poll_interval},
    };
    // Windows requires a drive/UNC prefix for absolute-path admission. These
    // are lexical/serialization fixtures; no filesystem open is performed.
    #[cfg(windows)]
    let tenant_root = "C:/tenant";
    #[cfg(not(windows))]
    let tenant_root = "/tenant";
    assert!(PathBuf::from(tenant_root).is_absolute());
    for filename in ["a&b+c%d?e#f.pem", "日本語.pem", "looks?kind=key&poll=0.pem"] {
        let path = format!("{tenant_root}/{filename}");
        assert!(PathBuf::from(&path).is_absolute());
        let bound = bound_file(&path, MaterialKind::Cert);
        let source = CertSource::parse(&bound, MaterialKind::Cert);
        assert!(
            source.as_file_path().is_none(),
            "raw extraction must not discard confinement"
        );
        assert!(source_is_refreshable(&source));
        let encoded = serde_json::to_string(&source).unwrap();
        let reparsed: CertSource = serde_json::from_str(&encoded).unwrap();
        // String deserialization has no field-kind context. The existing
        // source contract reapplies that hint at the material's caller.
        assert_eq!(
            source,
            CertSource::parse(reparsed.to_config_value(), MaterialKind::Cert)
        );
        assert_eq!(source.pool_key_component(), reparsed.pool_key_component());
        assert_ne!(
            source.pool_key_component(),
            CertSource::parse(&path, MaterialKind::Cert).pool_key_component()
        );
        assert_ne!(
            source.source_id(),
            CertSource::parse(&path, MaterialKind::Cert).source_id()
        );
        assert_eq!(
            check(&bound, MaterialKind::Cert, &roots(&[tenant_root])),
            Ok(())
        );
        assert_eq!(bound_file(&bound, MaterialKind::Cert), bound);
    }
    let bound = bound_file(
        &format!("file://{tenant_root}/cert.pem?poll=7&kind=cert"),
        MaterialKind::Cert,
    );
    let source = CertSource::parse(bound, MaterialKind::Cert);
    assert_eq!(
        source_poll_interval(
            &source,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(30)
        ),
        Some(std::time::Duration::from_secs(7))
    );
}

/// Issue #7218: only the documented `?poll=` option sets a source's refresh
/// cadence; the undocumented `poll_interval` / `poll_interval_seconds`
/// spellings are not compatibility aliases.
#[test]
fn source_poll_interval_reads_only_the_documented_poll_option() {
    use ferrum_edge::tls::source::{CertSource, subscription::source_poll_interval};
    let interval = |value: &str| {
        source_poll_interval(
            &CertSource::parse(value, MaterialKind::Cert),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(30),
        )
    };
    assert_eq!(
        interval("file:///etc/ferrum/cert.pem?poll=7"),
        Some(std::time::Duration::from_secs(7))
    );
    for spelling in ["poll_interval", "poll_interval_seconds"] {
        assert_eq!(
            interval(&format!("file:///etc/ferrum/cert.pem?{spelling}=7")),
            Some(std::time::Duration::from_secs(1)),
            "`{spelling}` must not set the poll interval"
        );
    }
}

#[test]
fn malformed_or_forged_constraints_fail_closed_without_plain_file_fallback() {
    let valid = bound_file("/tenant/cert.pem", MaterialKind::Cert);
    let identity = valid.split_once('?').unwrap().0;
    for value in [
        identity.to_string(),
        format!("{identity}?ferrum_tenant_path="),
        format!("{valid}&ferrum_tenant_path=%2Foutside%2Fkey.pem"),
        format!("{identity}?ferrum_tenant_path=%ZZ"),
        format!("{identity}?ferrum_tenant_path=%FF"),
        format!("{identity}?ferrum_tenant_path=%2Foutside%2Fkey.pem"),
        "file:///tenant/cert.pem?ferrum_tenant_path=%2Ftenant%2Fcert.pem".to_string(),
    ] {
        let parsed = ferrum_edge::tls::source::CertSource::parse(&value, MaterialKind::Cert);
        assert_eq!(
            parsed.to_config_value(),
            value,
            "invalid constraints cannot be laundered by serialization"
        );
        assert!(
            check(&value, MaterialKind::Cert, &roots(&["/tenant"])).is_err(),
            "{value}"
        );
        assert!(
            ferrum_edge::_test_support::load_tenant_tls_file_for_test(
                &value,
                MaterialKind::Cert,
                &roots(&["/tenant"]),
                1024
            )
            .is_err(),
            "{value}"
        );
    }
    assert!(
        ferrum_edge::_test_support::bind_tenant_tls_file_for_test(
            "file://user:pass@/tenant/cert.pem",
            MaterialKind::Cert
        )
        .is_err()
    );
    assert!(
        ferrum_edge::_test_support::bind_tenant_tls_file_for_test(
            "file:///tenant/cert.pem?kind=key",
            MaterialKind::Cert
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn confined_loader_reads_inside_aliases_and_rotations_but_refuses_outside_replacements() {
    use ferrum_edge::_test_support::load_tenant_tls_file_for_test as load;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let file = root.path().join("a&b+%?#日本語.pem");
    std::fs::write(&file, INLINE_CERT).unwrap();
    let root_alias = outside.path().join("operator-root");
    std::os::unix::fs::symlink(root.path(), &root_alias).unwrap();
    let link = root_alias.join("tls.pem");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let roots = vec![root_alias.clone()];
    for value in [
        link.display().to_string(),
        format!("file://{}", link.display()),
    ] {
        let bound = bound_file(&value, MaterialKind::Cert);
        let material = load(&bound, MaterialKind::Cert, &roots, 1024).unwrap();
        assert_eq!(material.bytes.expose_secret(), INLINE_CERT.as_bytes());
        // The marker retains the original file identity, so the next load sees
        // legitimate atomic rotation instead of freezing inline material.
        std::fs::write(&file, b"rotated in-root material").unwrap();
        assert_eq!(
            load(&bound, MaterialKind::Cert, &roots, 1024)
                .unwrap()
                .bytes
                .expose_secret(),
            b"rotated in-root material"
        );
        std::fs::write(&file, INLINE_CERT).unwrap();
    }
    let outside_file = outside.path().join("outside.pem");
    std::fs::write(&outside_file, INLINE_CERT).unwrap();
    let bound = bound_file(link.to_str().unwrap(), MaterialKind::Cert);
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&outside_file, &link).unwrap();
    assert!(load(&bound, MaterialKind::Cert, &roots, 1024).is_err());
    // The same pathname remains authorized for a trusted, untagged caller.
    let trusted =
        ferrum_edge::tls::source::CertSource::parse(link.to_str().unwrap(), MaterialKind::Cert);
    assert_eq!(
        ferrum_edge::tls::source::load_material_blocking_with(&trusted, MaterialKind::Cert, 1024)
            .unwrap()
            .bytes
            .expose_secret(),
        INLINE_CERT.as_bytes()
    );
}

#[cfg(unix)]
#[test]
fn checked_final_and_ancestor_paths_cannot_be_swapped_to_outside_links_before_open() {
    use ferrum_edge::_test_support::open_resolved_tenant_tls_file_for_test as open;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let dir = root.path().join("nested");
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("cert.pem");
    std::fs::write(&file, INLINE_CERT).unwrap();
    std::fs::write(outside.path().join("cert.pem"), INLINE_CERT).unwrap();
    let canonical_root = std::fs::canonicalize(root.path()).unwrap();
    let checked = std::fs::canonicalize(&file).unwrap();
    // Deterministic replacement at the resolution-to-open boundary; no timing race.
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(outside.path().join("cert.pem"), &file).unwrap();
    assert!(open(&canonical_root, &checked).is_err());
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
    std::os::unix::fs::symlink(outside.path(), &dir).unwrap();
    assert!(open(&canonical_root, &checked).is_err());
}

#[cfg(unix)]
#[test]
fn confined_material_uses_existing_byte_budget_and_rejects_nonregular_files() {
    use ferrum_edge::_test_support::load_tenant_tls_file_for_test as load;
    let root = tempfile::tempdir().unwrap();
    let roots = vec![root.path().to_path_buf()];
    let file = root.path().join("big.pem");
    std::fs::write(&file, INLINE_CERT).unwrap();
    let bound = bound_file(file.to_str().unwrap(), MaterialKind::Cert);
    assert!(matches!(
        load(&bound, MaterialKind::Cert, &roots, 4),
        Err(ferrum_edge::tls::source::MaterialError::Oversized { .. })
    ));
    let bound = bound_file(root.path().to_str().unwrap(), MaterialKind::Cert);
    assert!(load(&bound, MaterialKind::Cert, &roots, 1024).is_err());
}

#[cfg(not(any(unix, windows)))]
#[test]
fn confined_files_fail_closed_on_platforms_without_safe_component_relative_open() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("cert.pem");
    std::fs::write(&file, INLINE_CERT).unwrap();
    let bound = bound_file(file.to_str().unwrap(), MaterialKind::Cert);
    assert!(
        ferrum_edge::_test_support::load_tenant_tls_file_for_test(
            &bound,
            MaterialKind::Cert,
            &[root.path().to_path_buf()],
            1024
        )
        .is_err()
    );
}

#[test]
fn encoded_confinement_does_not_reduce_the_original_path_length_limit() {
    use ferrum_edge::_test_support::validate_tls_material_source_for_test as validate;
    let path = format!("/tenant/{}.pem", "日".repeat(1100));
    assert!(path.len() < ferrum_edge::config::types::MAX_FILE_PATH_LENGTH);
    let bound = bound_file(&path, MaterialKind::Cert);
    assert!(bound.len() > ferrum_edge::config::types::MAX_FILE_PATH_LENGTH);
    assert!(validate(&path, MaterialKind::Cert).is_ok());
    assert!(validate(&bound, MaterialKind::Cert).is_ok());
    let too_long = format!(
        "/tenant/{}",
        "a".repeat(ferrum_edge::config::types::MAX_FILE_PATH_LENGTH)
    );
    assert!(
        validate(
            &bound_file(&too_long, MaterialKind::Cert),
            MaterialKind::Cert
        )
        .is_err()
    );
}

// Windows-only tenant-file confinement tests (`windows_confined_files`) live in
// the dedicated `tests/windows_confinement_tests.rs` integration-test target so
// `.github/workflows/windows-confinement.yml` builds only those tests on
// `windows-latest` instead of the full `unit_tests` binary.
