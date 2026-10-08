//! TLS material references authored inside a namespace may only reach that
//! namespace's own material.
//!
//! The gateway resolves every reference with its own identity — its
//! Kubernetes ServiceAccount, cloud credentials, managed store, and
//! filesystem — so a namespace-scoped author must not be able to name another
//! namespace's Secret or a store only the gateway can read. These tests pin the
//! shared static predicate both the mesh DestinationRule boundary and the
//! namespace-claimed Admin API boundary call.

use ferrum_edge::tls::source::{
    MaterialKind, ScopedMaterialReferenceRefusal, check_namespace_scoped_material_reference,
};

const INLINE_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

fn check(value: &str, kind: MaterialKind, allow_local_files: bool) -> Result<(), String> {
    check_namespace_scoped_material_reference(value, kind, "tenant-a", allow_local_files)
        .map_err(|refusal| format!("{refusal:?}"))
}

#[test]
fn own_namespace_secrets_inline_pem_and_system_roots_are_admitted() {
    assert_eq!(
        check("k8s://tenant-a/client-tls#tls.crt", MaterialKind::Cert, false),
        Ok(())
    );
    assert_eq!(
        check("kubernetes://tenant-a/client-tls#tls.key", MaterialKind::Key, false),
        Ok(())
    );
    assert_eq!(check(INLINE_CERT, MaterialKind::Cert, false), Ok(()));
    assert_eq!(check("system://", MaterialKind::CaBundle, false), Ok(()));
}

#[test]
fn another_namespaces_secret_is_refused() {
    for value in [
        "k8s://tenant-b/db-mtls#tls.crt",
        "k8s://egress/partner-mtls#tls.crt",
        "k8s-secret://kube-system/bootstrap#tls.crt",
        // A namespace that merely starts with the owner's name is another
        // namespace.
        "k8s://tenant-a-shadow/db-mtls#tls.crt",
    ] {
        assert_eq!(
            check_namespace_scoped_material_reference(value, MaterialKind::Cert, "tenant-a", true),
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
            true,
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
            true,
        ),
        Err(ScopedMaterialReferenceRefusal::ForeignNamespaceSecret)
    );
}

#[test]
fn gateway_credential_stores_are_refused() {
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
            check_namespace_scoped_material_reference(value, MaterialKind::Cert, "tenant-a", true),
            Err(ScopedMaterialReferenceRefusal::GatewayCredentialStore),
            "{value} must be refused even when local files are admitted"
        );
    }
}

#[test]
fn local_files_follow_the_callers_policy() {
    for value in [
        "/etc/ferrum/partner/tls.key",
        "file:///etc/ferrum/partner/tls.key",
    ] {
        assert_eq!(check(value, MaterialKind::Key, true), Ok(()));
        assert_eq!(
            check_namespace_scoped_material_reference(value, MaterialKind::Key, "tenant-a", false),
            Err(ScopedMaterialReferenceRefusal::GatewayLocalFile),
            "{value} must be refused when local files are not admitted"
        );
    }
}

#[test]
fn refusal_reasons_never_echo_the_reference() {
    for refusal in [
        ScopedMaterialReferenceRefusal::ForeignNamespaceSecret,
        ScopedMaterialReferenceRefusal::GatewayCredentialStore,
        ScopedMaterialReferenceRefusal::GatewayLocalFile,
    ] {
        let reason = refusal.reason();
        assert!(!reason.is_empty());
        assert!(!reason.contains("tenant-b"), "{reason}");
        // The startup renderer withholds quoted spans; a fixed reason must not
        // contain an apostrophe it would mistake for one.
        assert!(!reason.contains('\''), "{reason}");
    }
}
