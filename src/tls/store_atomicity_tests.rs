//! Injected-failure coverage for managed TLS and ACME store atomicity.
//!
//! Failed create/update/delete must leave live readers and a reopened store on
//! the exact prior snapshot, with no private temporary artifacts left behind.
//! Lives under `#[cfg(test)]` in the `tls` crate module so fault-injection and
//! temp-artifact helpers stay crate-private / test-only.

use crate::tls::acme::{
    AcmeAccountStore, AcmeCertificateRecord, AcmeCertificateStore, AcmeError,
    AcmeHttp01ChallengeRecord, AcmeHttp01OrderInput, AcmeIssuedCertificateInput, AcmeOrderRecord,
    AcmeOrderStatus, AcmeOrderStore,
};
use crate::tls::managed::{
    ManagedTlsError, ManagedTlsMaterialKind, ManagedTlsRecord, ManagedTlsStore,
};
use crate::tls::private_file::{
    PrivateFileFault, inject_private_file_fault_for_tests, private_temp_artifacts_for_tests,
};
use crate::tls::source::MaterialKind;
use std::path::Path;
use tempfile::TempDir;

const DIRECTORY_URL: &str = "https://acme.example/directory";

fn assert_no_secret_temps(dir: &Path) {
    let artifacts = private_temp_artifacts_for_tests(dir).expect("list temp artifacts");
    assert!(
        artifacts.is_empty(),
        "secret temporary artifacts must not remain after a failed persist: {artifacts:?}"
    );
}

fn sample_managed_ca(id: &str, pem: &str) -> ManagedTlsRecord {
    ManagedTlsRecord::new_ca_bundle(id.to_string(), id.to_string(), None, pem.to_string())
}

fn generated_cert_and_key() -> (String, String) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params =
        rcgen::CertificateParams::new(vec!["example.com".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    (cert.pem(), key_pair.serialize_pem())
}

fn sample_acme_certificate(id: &str, cert_pem: &str, key_pem: &str) -> AcmeCertificateRecord {
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: id.to_string(),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        order_url: Some("https://acme.example/order/1".to_string()),
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        chain_pem: None,
    })
    .expect("acme certificate record")
}

fn sample_acme_order(id: &str, token: &str) -> AcmeOrderRecord {
    AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
        id: id.to_string(),
        certificate_id: Some("edge-cert".to_string()),
        domains: vec!["example.com".to_string()],
        directory_url: DIRECTORY_URL.to_string(),
        account_id: Some("account-1".to_string()),
        account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
        order_url: Some("https://acme.example/order/1".to_string()),
        status: AcmeOrderStatus::PendingChallenges,
        http01_challenges: vec![AcmeHttp01ChallengeRecord {
            identifier: "example.com".to_string(),
            token: token.to_string(),
            key_authorization: format!("{token}.thumbprint"),
        }],
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        finalization: None,
        error: None,
    })
    .expect("acme order record")
}

fn with_fault<T>(fault: PrivateFileFault, f: impl FnOnce() -> T) -> T {
    let guard = inject_private_file_fault_for_tests(fault);
    let result = f();
    guard.disarm();
    result
}

fn assert_live_matches_reopened_managed(store: &ManagedTlsStore, dir: &Path, id: &str) {
    let live = store.get(id);
    let reopened = ManagedTlsStore::open(dir).expect("reopen managed store");
    let disk = reopened.get(id);
    match (live, disk) {
        (Ok(live), Ok(disk)) => {
            assert_eq!(live.id, disk.id);
            assert_eq!(live.kind, disk.kind);
            assert_eq!(live.ca_bundle_pem, disk.ca_bundle_pem);
            assert_eq!(live.cert_pem, disk.cert_pem);
            assert_eq!(live.key_pem, disk.key_pem);
            assert_eq!(live.jwks_json, disk.jwks_json);
        }
        (Err(ManagedTlsError::NotFound(_)), Err(ManagedTlsError::NotFound(_))) => {}
        (live, disk) => panic!("live/disk mismatch: live={live:?} disk={disk:?}"),
    }
    assert_no_secret_temps(dir);
}

fn assert_live_matches_reopened_acme_cert(store: &AcmeCertificateStore, dir: &Path, id: &str) {
    let live = store.get_certificate(id);
    let reopened = AcmeCertificateStore::open(dir).expect("reopen acme cert store");
    let disk = reopened.get_certificate(id);
    match (live, disk) {
        (Ok(live), Ok(disk)) => {
            assert_eq!(live.id, disk.id);
            assert_eq!(live.cert_pem, disk.cert_pem);
            assert_eq!(live.key_pem, disk.key_pem);
            assert_eq!(live.status, disk.status);
        }
        (Err(AcmeError::NotFound(_)), Err(AcmeError::NotFound(_))) => {}
        (live, disk) => panic!("live/disk mismatch: live={live:?} disk={disk:?}"),
    }
    assert_no_secret_temps(dir);
}

fn assert_live_matches_reopened_acme_order(store: &AcmeOrderStore, dir: &Path, id: &str) {
    let live = store.get_order(id);
    let reopened = AcmeOrderStore::open(dir).expect("reopen acme order store");
    let disk = reopened.get_order(id);
    match (live, disk) {
        (Ok(live), Ok(disk)) => {
            assert_eq!(live.id, disk.id);
            assert_eq!(live.status, disk.status);
            assert_eq!(
                live.http01_challenges.len(),
                disk.http01_challenges.len(),
                "challenge count must match"
            );
            for (live_challenge, disk_challenge) in live
                .http01_challenges
                .iter()
                .zip(disk.http01_challenges.iter())
            {
                assert_eq!(live_challenge.token, disk_challenge.token);
                assert_eq!(
                    live_challenge.key_authorization,
                    disk_challenge.key_authorization
                );
            }
            assert_eq!(live.account_credentials_json, disk.account_credentials_json);
        }
        (Err(AcmeError::OrderNotFound(_)), Err(AcmeError::OrderNotFound(_))) => {}
        (live, disk) => panic!("live/disk mismatch: live={live:?} disk={disk:?}"),
    }
    assert_no_secret_temps(dir);
}

fn assert_live_matches_reopened_acme_account(
    store: &AcmeAccountStore,
    dir: &Path,
    directory_url: &str,
    account_id: &str,
    expected: Option<&str>,
) {
    let live = store
        .get_credentials(directory_url, account_id)
        .expect("live credentials");
    let reopened = AcmeAccountStore::open(dir).expect("reopen acme account store");
    let disk = reopened
        .get_credentials(directory_url, account_id)
        .expect("disk credentials");
    assert_eq!(live.as_deref(), expected);
    assert_eq!(disk.as_deref(), expected);
    assert_eq!(live, disk);
    assert_no_secret_temps(dir);
}

#[test]
fn managed_tls_failed_create_update_delete_keep_prior_snapshot() {
    let dir = TempDir::new().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");

    // Create failure: store stays empty.
    let create_err = with_fault(PrivateFileFault::Rename, || {
        store.upsert(sample_managed_ca("edge-ca", "create-ca"), false)
    })
    .expect_err("create must fail under rename fault");
    assert!(matches!(create_err, ManagedTlsError::Write(_)));
    assert!(matches!(
        store.get("edge-ca"),
        Err(ManagedTlsError::NotFound(_))
    ));
    assert!(
        store
            .list(ManagedTlsMaterialKind::CaBundle)
            .expect("list ca bundles")
            .is_empty()
    );
    assert_live_matches_reopened_managed(&store, dir.path(), "edge-ca");

    // Seed version A.
    store
        .upsert(sample_managed_ca("edge-ca", "version-a"), false)
        .expect("seed");

    // Update failure: keep version A.
    let update_err = with_fault(PrivateFileFault::Sync, || {
        store.upsert(sample_managed_ca("edge-ca", "version-b"), true)
    })
    .expect_err("update must fail under sync fault");
    assert!(matches!(update_err, ManagedTlsError::Write(_)));
    let kept = store.get("edge-ca").expect("live version A");
    assert_eq!(kept.ca_bundle_pem.as_deref(), Some("version-a"));
    let material = store
        .material("ca-bundles/edge-ca", MaterialKind::CaBundle)
        .expect("material version A");
    assert_eq!(material.bytes, b"version-a");
    assert_live_matches_reopened_managed(&store, dir.path(), "edge-ca");

    // Delete failure: keep version A.
    let delete_err = with_fault(PrivateFileFault::Create, || store.delete("edge-ca"))
        .expect_err("delete must fail under create fault");
    assert!(matches!(delete_err, ManagedTlsError::Write(_)));
    assert_eq!(
        store
            .get("edge-ca")
            .expect("still present")
            .ca_bundle_pem
            .as_deref(),
        Some("version-a")
    );
    assert_live_matches_reopened_managed(&store, dir.path(), "edge-ca");
}

#[test]
fn managed_tls_failed_dir_sync_restores_prior_snapshot_and_cleans_temps() {
    let dir = TempDir::new().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");
    store
        .upsert(sample_managed_ca("edge-ca", "version-a"), false)
        .expect("seed");

    let err = with_fault(PrivateFileFault::DirSync, || {
        store.upsert(sample_managed_ca("edge-ca", "version-b"), true)
    })
    .expect_err("dir sync fault must fail the mutation");
    assert!(matches!(err, ManagedTlsError::Write(_)));
    assert_eq!(
        store.get("edge-ca").expect("live").ca_bundle_pem.as_deref(),
        Some("version-a")
    );
    assert_live_matches_reopened_managed(&store, dir.path(), "edge-ca");
}

#[test]
fn managed_tls_failed_dir_sync_on_create_leaves_store_empty_and_durable() {
    let dir = TempDir::new().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open");

    let err = with_fault(PrivateFileFault::DirSync, || {
        store.upsert(sample_managed_ca("edge-ca", "brand-new"), false)
    })
    .expect_err("dir sync fault must fail create");
    assert!(matches!(err, ManagedTlsError::Write(_)));
    assert!(matches!(
        store.get("edge-ca"),
        Err(ManagedTlsError::NotFound(_))
    ));
    assert!(
        store
            .list(ManagedTlsMaterialKind::CaBundle)
            .expect("list ca bundles")
            .is_empty()
    );
    assert_live_matches_reopened_managed(&store, dir.path(), "edge-ca");
}

#[test]
fn acme_certificate_failed_create_update_delete_keep_prior_snapshot() {
    let dir = TempDir::new().expect("tempdir");
    let store = AcmeCertificateStore::open(dir.path()).expect("open");
    let (cert_a, key_a) = generated_cert_and_key();
    let (cert_b, key_b) = generated_cert_and_key();

    let create_err = with_fault(PrivateFileFault::Rename, || {
        store.upsert_certificate(sample_acme_certificate("edge-cert", &cert_a, &key_a), false)
    })
    .expect_err("create must fail");
    assert!(matches!(create_err, AcmeError::Write(_)));
    assert!(matches!(
        store.get_certificate("edge-cert"),
        Err(AcmeError::NotFound(_))
    ));
    assert!(
        store
            .list_certificates()
            .expect("list acme certificates")
            .is_empty()
    );
    assert_live_matches_reopened_acme_cert(&store, dir.path(), "edge-cert");

    store
        .upsert_certificate(sample_acme_certificate("edge-cert", &cert_a, &key_a), false)
        .expect("seed");

    let update_err = with_fault(PrivateFileFault::Write, || {
        store.upsert_certificate(sample_acme_certificate("edge-cert", &cert_b, &key_b), true)
    })
    .expect_err("update must fail");
    assert!(matches!(update_err, AcmeError::Write(_)));
    let kept = store.get_certificate("edge-cert").expect("live A");
    assert_eq!(kept.cert_pem, cert_a);
    assert_eq!(kept.key_pem, key_a);
    let material = store
        .material("certificates/edge-cert#key", MaterialKind::Key)
        .expect("key material A");
    assert_eq!(material.bytes, key_a.as_bytes());
    assert_live_matches_reopened_acme_cert(&store, dir.path(), "edge-cert");

    let delete_err = with_fault(PrivateFileFault::Rename, || {
        store.delete_certificate("edge-cert")
    })
    .expect_err("delete must fail");
    assert!(matches!(delete_err, AcmeError::Write(_)));
    assert!(store.get_certificate("edge-cert").is_ok());
    assert_live_matches_reopened_acme_cert(&store, dir.path(), "edge-cert");
}

#[test]
fn acme_order_failed_create_update_delete_keep_prior_snapshot() {
    let dir = TempDir::new().expect("tempdir");
    let store = AcmeOrderStore::open(dir.path()).expect("open");

    let create_err = with_fault(PrivateFileFault::Sync, || {
        store.upsert_order(sample_acme_order("edge-order", "tok_create"), false)
    })
    .expect_err("create must fail");
    assert!(matches!(create_err, AcmeError::Write(_)));
    assert!(matches!(
        store.get_order("edge-order"),
        Err(AcmeError::OrderNotFound(_))
    ));
    assert!(store.http01_key_authorization("tok_create").is_none());
    assert_live_matches_reopened_acme_order(&store, dir.path(), "edge-order");

    store
        .upsert_order(sample_acme_order("edge-order", "tok_version_a"), false)
        .expect("seed");

    let update_err = with_fault(PrivateFileFault::Rename, || {
        store.upsert_order(sample_acme_order("edge-order", "tok_version_b"), true)
    })
    .expect_err("update must fail");
    assert!(matches!(update_err, AcmeError::Write(_)));
    assert_eq!(
        store.http01_key_authorization("tok_version_a").as_deref(),
        Some("tok_version_a.thumbprint")
    );
    assert!(store.http01_key_authorization("tok_version_b").is_none());
    assert_live_matches_reopened_acme_order(&store, dir.path(), "edge-order");

    let delete_err = with_fault(PrivateFileFault::Create, || {
        store.delete_order("edge-order")
    })
    .expect_err("delete must fail");
    assert!(matches!(delete_err, AcmeError::Write(_)));
    assert!(store.get_order("edge-order").is_ok());
    assert_live_matches_reopened_acme_order(&store, dir.path(), "edge-order");
}

#[test]
fn acme_account_failed_create_and_update_keep_prior_snapshot() {
    // Account store has no delete API; cover create and update mutations.
    let dir = TempDir::new().expect("tempdir");
    let store = AcmeAccountStore::open(dir.path()).expect("open");
    let account_id = "https://acme.example/acct/1";
    let creds_a = r#"{"version":"a","private_key":"secret-a"}"#;
    let creds_b = r#"{"version":"b","private_key":"secret-b"}"#;

    let create_err = with_fault(PrivateFileFault::Rename, || {
        store.upsert_account(
            account_id.to_string(),
            DIRECTORY_URL.to_string(),
            creds_a.to_string(),
        )
    })
    .expect_err("create must fail");
    assert!(matches!(create_err, AcmeError::Write(_)));
    assert_live_matches_reopened_acme_account(&store, dir.path(), DIRECTORY_URL, account_id, None);

    store
        .upsert_account(
            account_id.to_string(),
            DIRECTORY_URL.to_string(),
            creds_a.to_string(),
        )
        .expect("seed");

    let update_err = with_fault(PrivateFileFault::DirSync, || {
        store.upsert_account(
            account_id.to_string(),
            DIRECTORY_URL.to_string(),
            creds_b.to_string(),
        )
    })
    .expect_err("update must fail");
    assert!(matches!(update_err, AcmeError::Write(_)));
    assert_live_matches_reopened_acme_account(
        &store,
        dir.path(),
        DIRECTORY_URL,
        account_id,
        Some(creds_a),
    );
}
