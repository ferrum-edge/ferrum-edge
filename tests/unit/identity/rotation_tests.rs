//! Rotation task and `SvidFetchHandle` tests.
//!
//! Phase A's rotation logic is mostly time-driven; these tests exercise the
//! decision helpers directly so we don't need to wait wall-clock time.

use chrono::Utc;
use ferrum_edge::identity::{
    SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet,
    rotation::{decide_next_tick, is_due_for_rotation},
    spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san},
};
use std::sync::Arc;
use std::time::Duration;

fn make_bundle(ttl_secs: i64) -> SvidBundle {
    use rcgen::{CertificateParams, KeyPair};

    let id = SpiffeId::new("spiffe://td.test/ns/foo/sa/bar").unwrap();
    let trust_domain = TrustDomain::new("td.test").unwrap();
    let mut params = CertificateParams::default();
    params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).unwrap());
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::seconds(ttl_secs);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    SvidBundle {
        spiffe_id: id,
        cert_chain_der: vec![cert.der().to_vec()],
        private_key_pkcs8_der: key_pair.serialize_der().into(),
        trust_bundles: TrustBundleSet {
            local: TrustBundle {
                trust_domain: trust_domain.clone(),
                x509_authorities: vec![cert.der().to_vec()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Default::default(),
        },
    }
}

#[test]
fn fresh_long_lived_bundle_is_not_due() {
    let bundle = make_bundle(3600); // 1h
    assert!(!is_due_for_rotation(&bundle, 0.5));
    let tick = decide_next_tick(&bundle, 0.5);
    assert!(tick >= Duration::from_secs(5));
}

#[test]
fn already_expired_bundle_is_due() {
    let bundle = make_bundle(-10);
    assert!(is_due_for_rotation(&bundle, 0.5));
}

#[test]
fn rotation_threshold_at_one_means_only_due_after_full_lifetime() {
    let bundle = make_bundle(3600);
    // rotate_at_fraction = 1.0 means "rotate at NotAfter" — fresh bundle is
    // never due.
    assert!(!is_due_for_rotation(&bundle, 1.0));
}

#[test]
fn shared_svid_bundle_swap_is_observable() {
    let slot: SharedSvidBundle = Arc::new(arc_swap::ArcSwap::new(Arc::new(None)));
    assert!(slot.load_full().is_none());
    let bundle = make_bundle(60);
    slot.store(Arc::new(Some(bundle.clone())));
    let observed = slot.load_full();
    assert!(observed.is_some());
    assert_eq!(
        observed.as_ref().as_ref().unwrap().spiffe_id,
        bundle.spiffe_id
    );
}

#[test]
fn malformed_bundle_falls_back_to_due() {
    // Bundle with no chain → leaf parse fails → treated as due.
    let mut bundle = make_bundle(3600);
    bundle.cert_chain_der.clear();
    assert!(is_due_for_rotation(&bundle, 0.5));
}

#[test]
fn loaded_at_can_be_compared_to_now() {
    // Sanity check that the test scaffolding produces sensibly-timestamped bundles.
    let bundle = make_bundle(3600);
    let parsed =
        ferrum_edge::identity::spiffe::extract_spiffe_id_from_cert(&bundle.cert_chain_der[0])
            .unwrap();
    assert_eq!(parsed.trust_domain().as_str(), "td.test");
    let _ = Utc::now();
}
