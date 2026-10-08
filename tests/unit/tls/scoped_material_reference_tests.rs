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
