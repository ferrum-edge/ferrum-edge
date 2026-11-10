//! Unit coverage for the namespace-keyed gateway trust-bundle resource
//! (issue #3727).
//!
//! Three things are load-bearing here and are asserted directly:
//!
//! 1. **Admission validation.** Oversized, malformed, mis-identified, and
//!    duplicate trust material must be refused *before* persistence or
//!    publication, and the resulting messages must never echo the material.
//! 2. **Publication semantics.** `Unchanged` / `Clear` / `Replace` must be three
//!    distinguishable states on the wire. Collapsing "nothing changed" into
//!    "revoke" is precisely the defect this resource had to fix.
//! 3. **Authority precedence.** Two simultaneous authorities must fail closed
//!    identically on every replica rather than each replica picking one.
//! 4. **Visibility on a store without multi-document transactions.** A
//!    committed create, rotation, or revocation must reach a *running* poller
//!    even when the change-log signal that would have announced it was already
//!    consumed before the document commit. Write ordering cannot prove that, so
//!    the authoritative reader-side drift check is asserted against a
//!    deterministic simulator that reproduces the interleaving exactly.

use crate::unit::gateway_trust_observability_lock::lock_gateway_trust_observability;
use ferrum_edge::config::db_backend::IncrementalResult;
use ferrum_edge::config::gateway_trust::{
    AMBIGUOUS_TRUST_AUTHORITY_MESSAGE, GatewayTrustBundleIdentity, GatewayTrustBundleRecord,
    GatewayTrustDriftSource, GatewayTrustFailureReason, GatewayTrustPublication,
    MAX_AUDIT_ACTOR_CHARS, MAX_FEDERATED_BUNDLES, MAX_JWT_AUTHORITIES_PER_BUNDLE,
    MAX_JWT_AUTHORITY_PEM_BYTES, MAX_TRUST_BUNDLE_JSON_BYTES, MAX_X509_AUTHORITIES_PER_BUNDLE,
    MAX_X509_AUTHORITY_DER_BYTES, NamespaceTrustProjection, TrustAuthorityResolution,
    TrustPublicationScope, detect_gateway_trust_drift, gateway_trust_state_drifted,
    observability_snapshot, project_namespace_trust, published_namespace_generation,
    published_namespace_state, record_ambiguous_authority, record_trust_generation_published,
    record_trust_generation_published_scoped, record_trust_load_rejection, resolve_trust_authority,
    trust_generation_fingerprint,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::CpGrpcServer;
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::identity::ca::PublishedJwtAuthority;
use ferrum_edge::identity::jwt_svid::jwks_document;
use ferrum_edge::modes::mesh::config::{JwtAuthority, TrustBundle, TrustBundleSet};

use async_trait::async_trait;
use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A real self-signed X.509 root, base64-encoded DER. Admission parses the DER,
/// so a fixture of arbitrary bytes would be rejected for the wrong reason and
/// would make the "invalid certificate" test vacuous.
fn root_ca_der_base64(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test CA key generates");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

/// A real SPKI `PUBLIC KEY` PEM. Admission now proves the key is one the
/// JWT-SVID stack can actually verify with, so a placeholder body would be
/// rejected for the wrong reason.
fn usable_public_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test key generates")
        .public_key_pem()
}

/// A bare public JWK in the exact representation federation can persist in a
/// `JwtAuthority.public_key_pem` field.
fn usable_public_jwk() -> String {
    let pem = usable_public_key_pem();
    let document = jwks_document(&[PublishedJwtAuthority::new(
        trust_domain("cluster.local"),
        "rotation-1",
        pem,
    )])
    .expect("test public key publishes as JWKS");
    let document: serde_json::Value =
        serde_json::from_slice(&document).expect("published JWKS is valid JSON");
    serde_json::to_string(&document["keys"][0]).expect("published JWK serializes")
}

fn trust_domain(value: &str) -> TrustDomain {
    TrustDomain::new(value).expect("fixture trust domain is valid")
}

fn bundle_with(authorities: Vec<String>) -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: trust_domain("cluster.local"),
            x509_authorities: authorities,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }
}

fn valid_record() -> GatewayTrustBundleRecord {
    GatewayTrustBundleRecord::new(
        "production",
        "production",
        bundle_with(vec![root_ca_der_base64("ferrum-test-root")]),
    )
}

/// Structural fail-fast must not fund mesh/X.509/JWT/runtime parsers.
fn assert_structural_fail_fast(errors: &[String]) {
    let rendered = errors.join("\n");
    for needle in [
        "TrustBundleSet.",
        "invalid base64",
        "not a parseable X.509 certificate",
        "trailing bytes after its X.509 certificate",
        "not a usable PEM public key",
        "undecodable trust material",
        "repeats a key_id",
        "has an empty key_id",
        "has no authorities",
        ": no authorities",
        "not a valid SPIFFE trust domain",
    ] {
        assert!(
            !rendered.contains(needle),
            "structural fail-fast must skip deep parser diagnostics, found {needle:?} in {errors:?}"
        );
    }
    for error in errors {
        assert!(
            !error.contains("BEGIN"),
            "a validation error must never echo PEM content: {error}"
        );
    }
}

/// Cheap raw-material sum matching production `bundle_raw_material_bytes`.
fn fixture_raw_material_bytes(bundle: &TrustBundleSet) -> usize {
    let mut total = 0usize;
    for entry in std::iter::once(&bundle.local).chain(bundle.federated.iter()) {
        total = total.saturating_add(entry.trust_domain.as_str().len());
        for encoded in &entry.x509_authorities {
            total = total.saturating_add(encoded.len());
        }
        for authority in &entry.jwt_authorities {
            total = total
                .saturating_add(authority.key_id.len())
                .saturating_add(authority.public_key_pem.len());
        }
    }
    total
}

// ── Admission validation ────────────────────────────────────────────────────

#[test]
fn valid_record_passes_admission() {
    let mut record = valid_record();
    record.normalize_fields();
    record
        .validate_fields()
        .expect("a well-formed record must be admitted");
}

#[test]
fn normalize_defaults_the_id_to_the_namespace() {
    let mut record = valid_record();
    record.id = "   ".to_string();
    record.normalize_fields();
    assert_eq!(
        record.id, "production",
        "an omitted id must default to the namespace so the singleton stays addressable"
    );
}

#[test]
fn trust_domain_must_match_the_bundle_identity() {
    let mut record = valid_record();
    // The stored identity column must never be authorable into disagreement
    // with the material it names.
    record.trust_domain = "other.local".to_string();
    let errors = record
        .validate_fields()
        .expect_err("a mismatched identity must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("does not match bundle.local.trust_domain")),
        "expected an identity-mismatch error, got {errors:?}"
    );
}

#[test]
fn base64_that_is_not_a_certificate_is_rejected() {
    let mut record = valid_record();
    record.bundle.local.x509_authorities =
        vec![base64::engine::general_purpose::STANDARD.encode([0_u8; 64])];
    let errors = record
        .validate_fields()
        .expect_err("valid base64 that is not a certificate must still be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("not a parseable X.509 certificate")),
        "expected a certificate-parse error, got {errors:?}"
    );
}

#[test]
fn a_bundle_with_no_authorities_is_rejected() {
    let mut record = valid_record();
    record.bundle.local.x509_authorities.clear();
    let errors = record
        .validate_fields()
        .expect_err("a bundle that authorizes nothing must be rejected");
    assert!(
        errors.iter().any(|error| error.contains("no authorities")),
        "expected an empty-authorities error, got {errors:?}"
    );
}

#[test]
fn too_many_x509_authorities_are_rejected_before_deep_parsers() {
    let mut record = valid_record();
    record.bundle.local.x509_authorities =
        vec!["not-a-certificate".to_string(); MAX_X509_AUTHORITIES_PER_BUNDLE + 1];
    let errors = record
        .validate_fields()
        .expect_err("an unbounded authority list must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("x509 authorities")),
        "expected an authority-count error, got {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn max_count_of_valid_x509_authorities_is_admitted() {
    let der = root_ca_der_base64("ferrum-test-root");
    let mut record = valid_record();
    record.bundle.local.x509_authorities = vec![der; MAX_X509_AUTHORITIES_PER_BUNDLE];
    record
        .validate_fields()
        .expect("the x509 authority-count cap is inclusive");
}

#[test]
fn too_many_federated_bundles_are_rejected_before_deep_parsers() {
    let mut record = valid_record();
    record.bundle.federated = (0..=MAX_FEDERATED_BUNDLES)
        .map(|_| TrustBundle {
            trust_domain: trust_domain("cluster.local"),
            x509_authorities: vec!["not-a-certificate".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        })
        .collect();
    let errors = record
        .validate_fields()
        .expect_err("an unbounded federated list must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("federated bundles")),
        "expected a federated-count error, got {errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|error| !error.contains("repeats the local trust domain")),
        "over-count federated entries must not be walked for duplicate-domain diagnostics: {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn a_federated_entry_repeating_the_local_trust_domain_is_rejected() {
    let mut record = valid_record();
    record.bundle.federated = vec![TrustBundle {
        trust_domain: trust_domain("cluster.local"),
        x509_authorities: vec![root_ca_der_base64("ferrum-test-root")],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }];
    let errors = record
        .validate_fields()
        .expect_err("a duplicate trust domain must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("repeats the local trust domain")),
        "expected a duplicate trust-domain error, got {errors:?}"
    );
}

#[test]
fn a_private_key_pasted_into_a_jwt_authority_is_rejected() {
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![JwtAuthority {
        key_id: "rotation-1".to_string(),
        public_key_pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".to_string(),
    }];
    let errors = record
        .validate_fields()
        .expect_err("a non-public-key PEM must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("not a usable PEM public key")),
        "expected a public-key admission error, got {errors:?}"
    );
}

#[test]
fn bare_jwk_admission_refuses_private_policy_conflicting_and_ambiguous_material() {
    let baseline = usable_public_jwk();
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![JwtAuthority {
        key_id: "rotation-1".to_string(),
        public_key_pem: baseline.clone(),
    }];
    record
        .validate_fields()
        .expect("a genuine bare public JWK must be admitted");

    let baseline_object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&baseline).expect("baseline JWK is an object");
    for (label, member, value) in [
        (
            "private EC scalar",
            "d",
            serde_json::Value::String("private-scalar-must-never-persist".to_string()),
        ),
        (
            "RSA private CRT member",
            "p",
            serde_json::Value::String("private-prime-must-never-persist".to_string()),
        ),
        (
            "symmetric key material",
            "k",
            serde_json::Value::String("symmetric-secret-must-never-persist".to_string()),
        ),
        (
            "encryption use",
            "use",
            serde_json::Value::String("enc".to_string()),
        ),
        (
            "encryption key operation",
            "key_ops",
            serde_json::json!(["encrypt"]),
        ),
        (
            "algorithm the P-256 key cannot produce",
            "alg",
            serde_json::Value::String("ES384".to_string()),
        ),
    ] {
        let mut hostile = baseline_object.clone();
        hostile.insert(member.to_string(), value);
        record.bundle.local.jwt_authorities[0].public_key_pem =
            serde_json::to_string(&hostile).expect("hostile JWK serializes");
        let errors = record
            .validate_fields()
            .err()
            .unwrap_or_else(|| panic!("{label}: hostile bare JWK must be refused"));
        let rendered = errors.join(" ");
        assert!(
            !rendered.contains("must-never-persist"),
            "{label}: admission diagnostics must not echo JWK material"
        );
    }

    let duplicate_use = format!(
        "{},\"use\":\"enc\"}}",
        baseline.strip_suffix('}').expect("JWK object closes")
    );
    record.bundle.local.jwt_authorities[0].public_key_pem = duplicate_use;
    record
        .validate_fields()
        .expect_err("a duplicate policy member is ambiguous and must be refused");
}

#[test]
fn duplicate_jwt_key_ids_within_one_bundle_are_rejected() {
    let pem = usable_public_key_pem();
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![
        JwtAuthority {
            key_id: "same".to_string(),
            public_key_pem: pem.clone(),
        },
        JwtAuthority {
            key_id: "same".to_string(),
            public_key_pem: pem,
        },
    ];
    let errors = record
        .validate_fields()
        .expect_err("a repeated key_id must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("repeats a key_id")),
        "expected a duplicate key_id error, got {errors:?}"
    );
}

#[test]
fn too_many_jwt_authorities_are_rejected_before_deep_parsers() {
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = (0..=MAX_JWT_AUTHORITIES_PER_BUNDLE)
        .map(|index| JwtAuthority {
            key_id: format!("key-{index}"),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
                .to_string(),
        })
        .collect();
    let errors = record
        .validate_fields()
        .expect_err("an unbounded JWT authority list must be rejected");
    assert!(
        errors.iter().any(|error| error.contains("jwt authorities")),
        "expected a JWT authority-count error, got {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn max_count_of_valid_jwt_authorities_is_admitted() {
    let pem = usable_public_key_pem();
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = (0..MAX_JWT_AUTHORITIES_PER_BUNDLE)
        .map(|index| JwtAuthority {
            key_id: format!("key-{index}"),
            public_key_pem: pem.clone(),
        })
        .collect();
    record
        .validate_fields()
        .expect("the jwt authority-count cap is inclusive");
}

#[test]
fn an_oversized_encoded_x509_authority_is_rejected_before_decode() {
    let mut record = valid_record();
    let over_encoded = "A".repeat(4 * MAX_X509_AUTHORITY_DER_BYTES.div_ceil(3) + 4);
    record.bundle.local.x509_authorities = vec![over_encoded];
    let errors = record
        .validate_fields()
        .expect_err("an encoded value that cannot fit the DER cap must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("encoded value cannot decode within")),
        "expected an encoded-size error, got {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn an_oversized_jwt_pem_is_rejected_before_key_parsing() {
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![JwtAuthority {
        key_id: "rotation-1".to_string(),
        public_key_pem: "A".repeat(MAX_JWT_AUTHORITY_PEM_BYTES + 1),
    }];
    let errors = record
        .validate_fields()
        .expect_err("an oversized JWT PEM must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("public_key_pem exceeds")),
        "expected a PEM size error, got {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn an_oversized_bundle_is_rejected_before_deep_parsers_and_the_error_carries_no_material() {
    // One local list of at-cap dummy PEMs is 256 KiB, under the 512 KiB
    // whole-document ceiling. A second at-cap JWT list in one federated
    // bundle stays inside every count and per-entry cap while the cheap
    // aggregate raw sum exceeds the ceiling, so only that bound may fire
    // and the dummy material must not be decoded as keys or certificates.
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = (0..MAX_JWT_AUTHORITIES_PER_BUNDLE)
        .map(|index| JwtAuthority {
            key_id: format!("key-{index}"),
            public_key_pem: "A".repeat(MAX_JWT_AUTHORITY_PEM_BYTES),
        })
        .collect();
    record.bundle.federated = vec![TrustBundle {
        trust_domain: trust_domain("remote.example.com"),
        x509_authorities: Vec::new(),
        jwt_authorities: record.bundle.local.jwt_authorities.clone(),
        refresh_hint_seconds: None,
    }];
    let raw = fixture_raw_material_bytes(&record.bundle);
    assert!(
        raw > MAX_TRUST_BUNDLE_JSON_BYTES,
        "fixture raw material must exceed the whole-bundle cap so deep parsers never run"
    );

    let errors = record
        .validate_fields()
        .expect_err("an oversized bundle must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("the maximum is") && error.contains("bytes")),
        "expected a size error, got {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn json_escaping_overhead_counts_against_the_whole_bundle_cap() {
    // Raw PEM bytes stay under the whole-bundle cap; JSON escaping of
    // backslashes in at-cap dummy PEMs pushes the serialized document over
    // it. The exact public contract must still refuse the record without
    // invoking deep parsers.
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = (0..MAX_JWT_AUTHORITIES_PER_BUNDLE)
        .map(|index| JwtAuthority {
            key_id: format!("key-{index}"),
            public_key_pem: "\\".repeat(MAX_JWT_AUTHORITY_PEM_BYTES),
        })
        .collect();

    let raw = fixture_raw_material_bytes(&record.bundle);
    assert!(
        raw <= MAX_TRUST_BUNDLE_JSON_BYTES,
        "fixture raw material must stay under the cap so only escaping can trip it"
    );
    let encoded = serde_json::to_vec(&record.bundle).expect("escaping fixture serializes");
    assert!(
        encoded.len() > MAX_TRUST_BUNDLE_JSON_BYTES,
        "fixture JSON must exceed the cap so only escaping trips it; encoded {} bytes",
        encoded.len()
    );

    let errors = record
        .validate_fields()
        .expect_err("JSON escaping overhead must count against the encoded-size cap");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("encodes to") && error.contains("the maximum is")),
        "expected an exact encoded-size error, got {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

#[test]
fn an_overlong_audit_actor_is_rejected_without_truncation_or_echo() {
    let mut record = valid_record();
    let overlong = "a".repeat(MAX_AUDIT_ACTOR_CHARS + 1);
    record.updated_by = Some(overlong.clone());
    let errors = record
        .validate_fields()
        .expect_err("an overlong audit actor must be rejected");
    assert!(
        errors.iter().any(|error| {
            error.contains("updated_by exceeds")
                && error.contains(&MAX_AUDIT_ACTOR_CHARS.to_string())
                && error.contains("characters")
        }),
        "expected an audit-actor bound error, got {errors:?}"
    );
    let rendered = errors.join("\n");
    assert!(
        !rendered.contains(&overlong),
        "admission diagnostics must not echo the overlong actor"
    );
}

#[test]
fn an_audit_actor_at_the_character_cap_is_admitted() {
    let mut record = valid_record();
    record.updated_by = Some("a".repeat(MAX_AUDIT_ACTOR_CHARS));
    record
        .validate_fields()
        .expect("the audit-actor cap is inclusive");
}

#[test]
fn a_multibyte_audit_actor_at_the_character_cap_is_admitted() {
    let mut record = valid_record();
    let at_cap = "é".repeat(MAX_AUDIT_ACTOR_CHARS);
    assert_eq!(at_cap.chars().count(), MAX_AUDIT_ACTOR_CHARS);
    assert!(
        at_cap.len() > MAX_AUDIT_ACTOR_CHARS,
        "fixture must exceed 255 UTF-8 bytes so a byte cap would reject it"
    );
    record.updated_by = Some(at_cap);
    record
        .validate_fields()
        .expect("255 Unicode scalar values must be admitted");
}

#[test]
fn a_multibyte_audit_actor_over_the_character_cap_is_rejected_without_echo() {
    let mut record = valid_record();
    let overlong = "é".repeat(MAX_AUDIT_ACTOR_CHARS + 1);
    assert_eq!(overlong.chars().count(), MAX_AUDIT_ACTOR_CHARS + 1);
    record.updated_by = Some(overlong.clone());
    let errors = record
        .validate_fields()
        .expect_err("256 Unicode scalar values must be rejected");
    assert!(
        errors.iter().any(|error| {
            error.contains("updated_by exceeds")
                && error.contains(&MAX_AUDIT_ACTOR_CHARS.to_string())
                && error.contains("characters")
        }),
        "expected an audit-actor bound error, got {errors:?}"
    );
    let rendered = errors.join("\n");
    assert!(
        !rendered.contains(&overlong) && !rendered.contains('é'),
        "admission diagnostics must not echo or truncate the overlong actor: {rendered}"
    );
}

// ── Redacted summary ────────────────────────────────────────────────────────

#[test]
fn the_summary_carries_counts_and_never_material() {
    let der = root_ca_der_base64("ferrum-test-root");
    let mut record = valid_record();
    record.bundle.local.x509_authorities = vec![der.clone(), root_ca_der_base64("second-root")];
    record.bundle.federated = vec![TrustBundle {
        trust_domain: trust_domain("remote.local"),
        x509_authorities: vec![root_ca_der_base64("remote-root")],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }];

    let summary = record.summary();
    assert_eq!(summary.namespace, "production");
    assert_eq!(summary.trust_domain, "cluster.local");
    assert_eq!(summary.x509_authority_count, 2);
    assert_eq!(summary.jwt_authority_count, 0);
    assert_eq!(summary.federated_count, 1);

    let rendered = serde_json::to_string(&summary).expect("summary serializes");
    assert!(
        !rendered.contains(&der),
        "the status summary must never carry trust material"
    );
}

// ── Publication semantics ───────────────────────────────────────────────────

/// Encode one delta publication through the production CP broadcast path and
/// return the side-channel value a subscriber would receive.
fn delta_side_channel(trust: GatewayTrustPublication<'_>) -> String {
    let (tx, mut rx) = tokio::sync::broadcast::channel(4);
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: chrono::Utc::now(),
    };
    let version = delta.poll_timestamp.to_rfc3339();
    assert!(
        CpGrpcServer::broadcast_delta_with_trust_bundles(&tx, &delta, &version, trust),
        "a valid delta publication must be delivered"
    );
    rx.try_recv()
        .expect("the delta reaches the subscriber channel")
        .trust_bundles_json
}

#[test]
fn unchanged_clear_and_replace_are_distinguishable_on_the_wire() {
    // This is the regression the resource exists to prevent: before issue
    // #3727 the delta path encoded "no trust to say" as JSON `null`, which the
    // data plane reads as an explicit revocation.
    assert_eq!(
        delta_side_channel(GatewayTrustPublication::Unchanged),
        "",
        "'nothing to say' must be an EMPTY side channel"
    );
    assert_eq!(
        delta_side_channel(GatewayTrustPublication::Clear),
        "null",
        "'revoke' must be JSON null"
    );
    let record = valid_record();
    let replace = delta_side_channel(GatewayTrustPublication::Replace(&record.bundle));
    assert!(
        replace.contains("cluster.local"),
        "'install' must carry the serialized bundle set"
    );
}

// ── Authority precedence ────────────────────────────────────────────────────

#[test]
fn the_database_record_is_authoritative_when_it_is_the_only_authority() {
    let record = valid_record();
    assert_eq!(
        resolve_trust_authority(Some(&record), None),
        TrustAuthorityResolution::Database
    );
}

#[test]
fn a_file_sourced_value_stands_when_there_is_no_database_record() {
    let file_value = bundle_with(vec![root_ca_der_base64("file-root")]);
    assert_eq!(
        resolve_trust_authority(None, Some(&file_value)),
        TrustAuthorityResolution::File
    );
}

#[test]
fn two_simultaneous_authorities_are_ambiguous_rather_than_ranked() {
    // Ranking them silently would let one replica publish the database value
    // and another the file value — the divergence this resource removes.
    let record = valid_record();
    let file_value = bundle_with(vec![root_ca_der_base64("file-root")]);
    assert_eq!(
        resolve_trust_authority(Some(&record), Some(&file_value)),
        TrustAuthorityResolution::Ambiguous
    );
    assert!(
        !AMBIGUOUS_TRUST_AUTHORITY_MESSAGE.contains("path"),
        "the operator message must not name filesystem paths"
    );
}

#[test]
fn no_authority_at_all_resolves_to_the_database_with_nothing_to_publish() {
    assert_eq!(
        resolve_trust_authority(None, None),
        TrustAuthorityResolution::Database
    );
}

// ── Observability ───────────────────────────────────────────────────────────

/// Counters are process-global, so the observability assertions run in one test
/// rather than racing each other across cargo's parallel test threads.
#[test]
fn observability_counters_are_bounded_and_material_free() {
    let _observability = futures::executor::block_on(lock_gateway_trust_observability());

    let baseline = observability_snapshot();
    assert_eq!(baseline.published_generations_total, 0);
    assert_eq!(baseline.last_published_unix_seconds, 0);
    assert_eq!(baseline.last_failure_reason, "none");

    // A publication that carries no database trust record is not a trust
    // generation and must not move the counters.
    record_trust_generation_published(&[], None, 1_700_000_000);
    assert_eq!(observability_snapshot().published_generations_total, 0);

    record_trust_generation_published(std::slice::from_ref(&valid_record()), None, 1_700_000_000);
    let after_publish = observability_snapshot();
    assert_eq!(after_publish.published_generations_total, 1);
    assert_eq!(after_publish.last_published_unix_seconds, 1_700_000_000);
    assert_eq!(after_publish.last_failure_reason, "none");
    let published = published_namespace_state("production")
        .expect("the exact namespace publication must be observable");
    assert_eq!(published.bundle.revision, valid_record().revision);
    assert_eq!(
        published.generation,
        published_namespace_generation("production")
    );

    // A rejected candidate must NOT look like a publication: the previous valid
    // generation is still the one serving.
    record_trust_load_rejection(GatewayTrustFailureReason::InvalidMaterial);
    let after_rejection = observability_snapshot();
    assert_eq!(after_rejection.load_rejections_total, 1);
    assert_eq!(
        after_rejection.published_generations_total, 1,
        "a refused candidate must not count as a published generation"
    );
    assert_eq!(
        after_rejection.last_published_unix_seconds, 1_700_000_000,
        "a refused candidate must not advance the last-published timestamp"
    );
    assert_eq!(after_rejection.last_failure_reason, "invalid_material");
    assert_eq!(
        published_namespace_state("production"),
        Some(published.clone()),
        "a refused candidate must retain the exact prior namespace generation"
    );

    // An undecodable stored row is its own bounded reason.
    record_trust_load_rejection(GatewayTrustFailureReason::Undecodable);
    assert_eq!(observability_snapshot().last_failure_reason, "undecodable");

    record_ambiguous_authority();
    let after_ambiguous = observability_snapshot();
    assert_eq!(after_ambiguous.ambiguous_authority_total, 1);
    assert_eq!(after_ambiguous.last_failure_reason, "ambiguous_authority");

    // ── The publication counter must not outrun the ambiguity refusal ───────
    //
    // The refusal is resolved per namespace AFTER the swap, during broadcast,
    // so the swap consults the unpartitioned file/overlay slot directly. A
    // generation whose every database record is about to be refused must not
    // report a successful trust publication.
    let file_authority = bundle_with(vec![root_ca_der_base64("file-root")]);
    let before_ambiguous_publication = observability_snapshot();
    record_trust_generation_published(
        std::slice::from_ref(&valid_record()),
        Some(&file_authority),
        1_800_000_000,
    );
    let after_ambiguous_publication = observability_snapshot();
    assert_eq!(
        after_ambiguous_publication.published_generations_total,
        before_ambiguous_publication.published_generations_total,
        "an all-ambiguous generation must not count as a published trust generation"
    );
    assert_eq!(
        after_ambiguous_publication.ambiguous_authority_total,
        before_ambiguous_publication.ambiguous_authority_total + 1,
        "an ambiguous generation must be counted once at the publication boundary"
    );
    assert_eq!(
        after_ambiguous_publication.last_published_unix_seconds,
        before_ambiguous_publication.last_published_unix_seconds,
        "a refused generation must not advance the last-published timestamp"
    );
    assert_eq!(
        after_ambiguous_publication.last_failure_reason, "ambiguous_authority",
        "the refusal must not be cleared by the swap it refused"
    );
    assert_eq!(
        published_namespace_state("production"),
        Some(published),
        "an ambiguous publication must retain the exact prior namespace generation"
    );
    record_trust_generation_published(&[], Some(&file_authority), 1_850_000_000);
    assert!(
        published_namespace_state("production").is_none(),
        "removing the database record resolves ambiguity and must clear its prior database publication"
    );

    // A genuinely accepted generation spanning several namespaces is still ONE
    // generation reaching the swap, counted exactly once — the counter is not
    // per record, and it is not per subscriber either (its call site is the
    // swap, so a data plane reconnecting cannot inflate it).
    let mut second_namespace = valid_record();
    second_namespace.namespace = "staging".to_string();
    second_namespace.id = "staging".to_string();
    let multi_namespace = vec![valid_record(), second_namespace];
    record_trust_generation_published(&multi_namespace, None, 1_900_000_000);
    let after_multi = observability_snapshot();
    assert_eq!(
        after_multi.published_generations_total,
        before_ambiguous_publication.published_generations_total + 1,
        "a multi-namespace generation is one publication, not one per record"
    );
    assert_eq!(after_multi.last_published_unix_seconds, 1_900_000_000);
    assert_eq!(
        after_multi.last_failure_reason, "none",
        "an accepted publication clears the standing failure reason"
    );
    assert!(published_namespace_state("staging").is_some());

    // A mixed full reload can publish the namespaces that refreshed while a
    // rejected namespace retains its last-known-good generation. That is a
    // PARTIAL publication, not recovery: the bounded refusal must stay visible
    // until a later complete reload covers every namespace.
    record_trust_load_rejection(GatewayTrustFailureReason::InvalidMaterial);
    record_trust_generation_published_scoped(
        &multi_namespace,
        None,
        1_925_000_000,
        TrustPublicationScope::Partial,
    );
    assert_eq!(
        observability_snapshot().last_failure_reason,
        "invalid_material",
        "an accepted sibling namespace must not clear a rejected namespace's failure"
    );
    record_trust_generation_published_scoped(
        &multi_namespace,
        None,
        1_930_000_000,
        TrustPublicationScope::Complete,
    );
    assert_eq!(
        observability_snapshot().last_failure_reason,
        "none",
        "only a complete full reload proves the standing refusal recovered"
    );

    // An accepted empty generation is an explicit live revocation. It does not
    // increment the database-record counter, but status must stop reporting
    // either namespace's previously published revision and must clear a
    // standing failure just like an accepted nonempty generation.
    record_trust_load_rejection(GatewayTrustFailureReason::InvalidMaterial);
    let before_revoke = observability_snapshot().published_generations_total;
    record_trust_generation_published(&[], None, 1_950_000_000);
    assert!(published_namespace_state("production").is_none());
    assert!(published_namespace_state("staging").is_none());
    assert_eq!(
        observability_snapshot().published_generations_total,
        before_revoke
    );
    assert_eq!(
        observability_snapshot().last_published_unix_seconds,
        1_950_000_000,
        "an explicit revocation is the most recent successful trust publication"
    );
    assert_eq!(observability_snapshot().last_failure_reason, "none");

    // Re-run the ambiguity refusal so the trailing snapshot assertions below
    // still observe the bounded reason they were written for.
    let ambiguity_before_replay = observability_snapshot().ambiguous_authority_total;
    record_ambiguous_authority();
    let after_ambiguous = observability_snapshot();
    assert_eq!(
        after_ambiguous.ambiguous_authority_total,
        ambiguity_before_replay + 1
    );
    assert_eq!(after_ambiguous.last_failure_reason, "ambiguous_authority");

    // The whole snapshot is a fixed set of integers plus a bounded enum, so it
    // cannot carry a trust domain, a namespace, or an unbounded identifier.
    // There is deliberately no process-wide revision field: revisions are per
    // namespace and a last-writer-wins process atomic would be misleading.
    let rendered = serde_json::to_string(&after_ambiguous).expect("snapshot serializes");
    for forbidden in ["cluster.local", "production", "BEGIN", "revision"] {
        assert!(
            !rendered.contains(forbidden),
            "process metrics must not carry {forbidden}"
        );
    }
}

// ── Configuration identity ──────────────────────────────────────────────────

#[test]
fn the_generation_fingerprint_is_stable_and_changes_with_every_rotation() {
    let record = valid_record();
    let baseline = trust_generation_fingerprint(std::slice::from_ref(&record));

    // Reconstructing the same committed state (a restarted replica) reproduces
    // the same identity.
    assert_eq!(
        baseline,
        trust_generation_fingerprint(std::slice::from_ref(&record.clone())),
        "two replicas holding the same committed state must agree on the generation"
    );

    // A revision bump alone changes the identity, so a configuration checksum
    // built on it cannot report "unchanged" across a rotation.
    let mut rotated = record.clone();
    rotated.revision += 1;
    assert_ne!(
        baseline,
        trust_generation_fingerprint(std::slice::from_ref(&rotated))
    );

    // So does new material.
    let mut rematerialized = record.clone();
    rematerialized
        .bundle
        .local
        .x509_authorities
        .push(root_ca_der_base64("rotated-root"));
    assert_ne!(
        baseline,
        trust_generation_fingerprint(std::slice::from_ref(&rematerialized))
    );

    // Revocation is distinguishable from "no record at all was ever there"
    // only by context, but both hash to the empty generation deterministically.
    assert_eq!(
        trust_generation_fingerprint(&[]),
        trust_generation_fingerprint(&[])
    );
    assert_ne!(baseline, trust_generation_fingerprint(&[]));

    // A digest carries no material.
    assert!(!baseline.contains("BEGIN"));
    assert!(!baseline.contains("cluster.local"));
}

// ── Serde contract ──────────────────────────────────────────────────────────

#[test]
fn the_record_round_trips_through_json_for_backup_and_restore() {
    let mut record = valid_record();
    record.revision = 4;
    record.updated_by = Some("admin@example.test".to_string());

    let encoded = serde_json::to_string(&record).expect("record serializes");
    let decoded: GatewayTrustBundleRecord =
        serde_json::from_str(&encoded).expect("record round-trips");
    assert_eq!(decoded, record);
}

#[test]
fn an_unknown_field_is_rejected_rather_than_silently_dropped() {
    let body = serde_json::json!({
        "id": "production",
        "namespace": "production",
        "trust_domain": "cluster.local",
        "bundle": {"local": {"trust_domain": "cluster.local", "x509_authorities": []}},
        "surprise": true,
    });
    serde_json::from_value::<GatewayTrustBundleRecord>(body)
        .expect_err("deny_unknown_fields must reject an unexpected key");
}

#[test]
fn revision_defaults_to_zero_meaning_no_concurrency_expectation() {
    let body = serde_json::json!({
        "trust_domain": "cluster.local",
        "bundle": {"local": {"trust_domain": "cluster.local", "x509_authorities": []}},
    });
    let decoded: GatewayTrustBundleRecord =
        serde_json::from_value(body).expect("optional fields default");
    assert_eq!(
        decoded.revision, 0,
        "an omitted revision must mean 'no expectation', not revision 1"
    );
}

/// No construction site may seed a revision. Every stored value comes from the
/// backend's durable change sequence, which is what keeps a delete/recreate from
/// handing a new incarnation a revision a stale client still holds.
#[test]
fn a_constructed_record_carries_no_caller_authored_revision() {
    let record = valid_record();
    assert_eq!(
        record.revision, 0,
        "constructing a record must leave the revision unassigned, not seed 1"
    );
}

// ── Usable-material admission (issue #3727 hardening) ───────────────────────

#[test]
fn a_certificate_with_trailing_bytes_is_rejected() {
    // A parser that stops at the end of the certificate would admit an
    // authority whose stored entry carries appended material a differently
    // strict verifier could read as part of the document.
    let der = base64::engine::general_purpose::STANDARD
        .decode(root_ca_der_base64("ferrum-test-root"))
        .expect("fixture decodes");
    let mut with_trailer = der.clone();
    with_trailer.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);

    let mut record = valid_record();
    record.bundle.local.x509_authorities =
        vec![base64::engine::general_purpose::STANDARD.encode(&with_trailer)];
    let errors = record
        .validate_fields()
        .expect_err("a certificate with appended bytes must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("trailing bytes after its X.509 certificate")),
        "expected a trailing-bytes error, got {errors:?}"
    );
}

#[test]
fn a_real_public_key_is_admitted_but_a_well_shaped_fake_is_not() {
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![JwtAuthority {
        key_id: "rotation-1".to_string(),
        public_key_pem: usable_public_key_pem(),
    }];
    record
        .validate_fields()
        .expect("a genuine SPKI public key must be admitted");

    // Correct envelope, unusable body: the old structural check accepted this,
    // and the material would have persisted and published while never being
    // able to validate a token.
    record.bundle.local.jwt_authorities = vec![JwtAuthority {
        key_id: "rotation-1".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----".to_string(),
    }];
    let errors = record
        .validate_fields()
        .expect_err("a PEM envelope around unusable bytes must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("not a usable PEM public key")),
        "expected a public-key admission error, got {errors:?}"
    );
    for error in &errors {
        assert!(
            !error.contains("AAAA"),
            "an admission error must never echo the offered material"
        );
    }
}

// ── Server-owned identity ───────────────────────────────────────────────────

#[test]
fn the_default_id_comes_from_the_server_selected_namespace_only() {
    // The admin write path applies `trim_fields()` while the body's namespace
    // is still whatever the client sent, and derives the default id from the
    // authenticated namespace separately. A hostile body must therefore be
    // unable to steer either value.
    let mut record = GatewayTrustBundleRecord::new(
        "attacker-controlled",
        "  ",
        bundle_with(vec![root_ca_der_base64("ferrum-test-root")]),
    );
    record.trim_fields();
    assert!(
        record.id.is_empty(),
        "trim-only normalization must not derive an id from the body namespace"
    );

    assert_eq!(
        GatewayTrustBundleRecord::default_singleton_id("production"),
        "production",
        "the default id is derived from the server-selected namespace"
    );

    // Once the server has forced the namespace, the shared normalization used
    // by restore/import derives the same value.
    record.namespace = "production".to_string();
    record.normalize_fields();
    assert_eq!(record.id, "production");
}

// ── Ambiguity is a refusal, not a revocation ────────────────────────────────

#[test]
fn two_authorities_keep_the_previously_accepted_trust_rather_than_revoking_it() {
    let _observability = futures::executor::block_on(lock_gateway_trust_observability());
    let record = valid_record();
    let file_value = bundle_with(vec![root_ca_der_base64("file-root")]);

    let projection = project_namespace_trust(Some(&record), Some(&file_value), true);
    assert_eq!(
        projection,
        NamespaceTrustProjection::KeepPrevious,
        "an ambiguous authority must retain last-known-good, not revoke a working generation"
    );
    assert_eq!(
        observability_snapshot().ambiguous_authority_total,
        0,
        "per-subscriber projection must not inflate publication observability"
    );
    record_trust_generation_published(
        std::slice::from_ref(&record),
        Some(&file_value),
        1_800_000_000,
    );
    assert_eq!(
        observability_snapshot().ambiguous_authority_total,
        1,
        "the refusal must be observable even without an active subscriber"
    );
}

#[test]
fn a_single_authority_publishes_and_an_absent_one_clears() {
    let record = valid_record();
    let file_value = bundle_with(vec![root_ca_der_base64("file-root")]);

    assert_eq!(
        project_namespace_trust(Some(&record), None, true),
        NamespaceTrustProjection::Replace(record.bundle.clone())
    );
    assert_eq!(
        project_namespace_trust(None, Some(&file_value), true),
        NamespaceTrustProjection::Replace(file_value.clone())
    );
    // A claim-requiring (multi-namespace) scope must never forward an
    // unpartitioned value: it cannot attribute it to the subscriber.
    assert_eq!(
        project_namespace_trust(None, Some(&file_value), false),
        NamespaceTrustProjection::Clear
    );
    assert_eq!(
        project_namespace_trust(None, None, true),
        NamespaceTrustProjection::Clear
    );
}

// ── Authoritative drift detection (standalone-MongoDB interleaving) ─────────
//
// The write-side ordering on a store without multi-document transactions
// cannot prove a committed mutation is visible to a *running* poller, and the
// cases below encode exactly why. A signal-first write can have its signal
// consumed — cursor advanced, full reload completed against the OLD document —
// before the document commits, and no later signal is ever written. A
// document-first write, or a trailing second signal, moves the same
// invisibility behind a crash boundary instead of removing it.
//
// `detect_gateway_trust_drift` is the reader-side proof: it compares the
// authoritative stored identity with the trust state the running configuration
// was actually built from, so it depends on neither ordering nor on the writer
// surviving. These cells drive it through a deterministic store simulator that
// can interleave those two commits explicitly, which a live MongoDB cell
// cannot do reproducibly.

/// Deterministic stand-in for a configuration store whose trust document and
/// change-log signal are two separate commits.
///
/// Both halves are mutated independently and explicitly by each test, so the
/// exact interleaving under test is written out in the test body rather than
/// raced for.
struct StoreSimulator {
    documents: Mutex<HashMap<String, GatewayTrustBundleIdentity>>,
    signals: Mutex<Vec<u64>>,
    unreadable: Mutex<HashSet<String>>,
    identity_reads: AtomicUsize,
    atomic_trust_writes: bool,
}

impl StoreSimulator {
    /// A store with no multi-document transaction (standalone MongoDB).
    fn standalone() -> Self {
        Self {
            documents: Mutex::new(HashMap::new()),
            signals: Mutex::new(Vec::new()),
            unreadable: Mutex::new(HashSet::new()),
            identity_reads: AtomicUsize::new(0),
            atomic_trust_writes: false,
        }
    }

    /// A store that commits the document and its signal in one transaction
    /// (every SQL backend, and replica-set MongoDB).
    fn transactional() -> Self {
        Self {
            atomic_trust_writes: true,
            ..Self::standalone()
        }
    }

    /// The change-log half of a write commits.
    fn commit_signal(&self, sequence: u64) {
        self.signals.lock().expect("signal log").push(sequence);
    }

    /// The document half of a write commits.
    fn commit_document(&self, namespace: &str, stored: GatewayTrustBundleIdentity) {
        self.documents
            .lock()
            .expect("documents")
            .insert(namespace.to_string(), stored);
    }

    /// The document half of a revocation commits.
    fn remove_document(&self, namespace: &str) {
        self.documents.lock().expect("documents").remove(namespace);
    }

    /// What a full reload would read for this namespace right now.
    fn stored(&self, namespace: &str) -> Option<GatewayTrustBundleIdentity> {
        self.documents
            .lock()
            .expect("documents")
            .get(namespace)
            .cloned()
    }

    /// The highest committed change sequence — what a poller's cursor tracks.
    fn latest_signal(&self) -> u64 {
        self.signals
            .lock()
            .expect("signal log")
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }

    fn make_unreadable(&self, namespace: &str) {
        self.unreadable
            .lock()
            .expect("unreadable set")
            .insert(namespace.to_string());
    }

    fn identity_reads(&self) -> usize {
        self.identity_reads.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl GatewayTrustDriftSource for StoreSimulator {
    fn gateway_trust_writes_are_atomic_with_change_log(&self) -> bool {
        self.atomic_trust_writes
    }

    async fn gateway_trust_bundle_identity(
        &self,
        namespace: &str,
    ) -> Result<Option<GatewayTrustBundleIdentity>, anyhow::Error> {
        self.identity_reads.fetch_add(1, Ordering::Relaxed);
        let unreadable = self
            .unreadable
            .lock()
            .expect("unreadable set")
            .contains(namespace);
        if unreadable {
            anyhow::bail!("simulated authoritative read failure");
        }
        Ok(self.stored(namespace))
    }
}

fn stored_identity(id: &str, domain: &str, revision: u64) -> GatewayTrustBundleIdentity {
    GatewayTrustBundleIdentity {
        id: id.to_string(),
        trust_domain: domain.to_string(),
        revision,
    }
}

/// Build the record a full reload of `stored` would put in the running
/// configuration. Only the identity fields decide drift, so the material is a
/// valid fixture bundle.
fn published_record(
    namespace: &str,
    stored: &GatewayTrustBundleIdentity,
) -> GatewayTrustBundleRecord {
    let mut record = GatewayTrustBundleRecord::new(
        namespace,
        &stored.id,
        bundle_with(vec![root_ca_der_base64("published-root")]),
    );
    record.trust_domain = stored.trust_domain.clone();
    record.revision = stored.revision;
    record
}

/// Publish what a full reload just read, the way the loaders do: the
/// namespace's record is replaced wholesale, or removed.
fn publish_loaded(
    config: &mut GatewayConfig,
    namespace: &str,
    loaded: Option<&GatewayTrustBundleIdentity>,
) {
    config
        .gateway_trust_bundles
        .retain(|record| record.namespace != namespace);
    if let Some(loaded) = loaded {
        config
            .gateway_trust_bundles
            .push(published_record(namespace, loaded));
    }
    config.sort_gateway_trust_bundles();
}

/// One authoritative full reload: read the store *now* and publish exactly
/// what it returned.
fn full_reload(config: &mut GatewayConfig, store: &StoreSimulator, namespace: &str) {
    publish_loaded(config, namespace, store.stored(namespace).as_ref());
}

fn published_revision(config: &GatewayConfig, namespace: &str) -> Option<u64> {
    config
        .gateway_trust_bundle_for(namespace)
        .map(|record| record.revision)
}

#[tokio::test]
async fn a_rotation_that_commits_after_its_signal_was_consumed_is_caught_by_the_next_poll() {
    let store = StoreSimulator::standalone();
    let mut published = GatewayConfig::default();
    let namespaces = vec!["ferrum".to_string()];

    // The store already holds an incarnation the poller published.
    store.commit_signal(4);
    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 4));
    full_reload(&mut published, &store, "ferrum");
    let mut cursor = store.latest_signal();

    // ── The interleaving ────────────────────────────────────────────────────
    // 1. A rotation writes its poll signal first; sequence 5 becomes the
    //    revision the document will carry.
    store.commit_signal(5);

    // 2. The poller consumes sequence 5 and escalates to a full reload. The
    //    document has NOT committed yet, so the reload reads the OLD material
    //    and the cursor advances past 5 anyway.
    full_reload(&mut published, &store, "ferrum");
    cursor = cursor.max(store.latest_signal());
    assert_eq!(
        published_revision(&published, "ferrum"),
        Some(4),
        "the reload that consumed the signal legitimately read the pre-rotation document"
    );

    // 3. Only now does the rotation's document commit, carrying revision 5.
    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 5));
    assert_eq!(
        store.latest_signal(),
        cursor,
        "the interleaving leaves NO unconsumed signal: a signal-driven poller is done"
    );

    // ── The repair ──────────────────────────────────────────────────────────
    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert_eq!(
        drifted,
        vec!["ferrum".to_string()],
        "the drift check must see a committed rotation the change log never announced"
    );

    // The escalation republishes from one authoritative read, and the next
    // poll is quiet again — the check converges instead of spinning.
    full_reload(&mut published, &store, "ferrum");
    assert_eq!(published_revision(&published, "ferrum"), Some(5));
    let settled = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert!(
        settled.is_empty(),
        "a converged namespace must not force a reload on every subsequent tick"
    );
}

#[tokio::test]
async fn a_revocation_that_commits_after_its_signal_was_consumed_is_caught_by_the_next_poll() {
    let store = StoreSimulator::standalone();
    let mut published = GatewayConfig::default();
    let namespaces = vec!["ferrum".to_string()];

    store.commit_signal(9);
    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 9));
    full_reload(&mut published, &store, "ferrum");

    // The revocation's signal commits, the poller consumes it and reloads
    // against a document that is still present, and its cursor advances.
    store.commit_signal(10);
    full_reload(&mut published, &store, "ferrum");
    let cursor = store.latest_signal();
    assert!(
        published.gateway_trust_bundle_for("ferrum").is_some(),
        "the consumed-signal reload still published the roots being revoked"
    );

    // Only now does the delete commit. Nothing else will ever announce it, and
    // this is the dangerous direction: every subscriber is still validating
    // with revoked roots.
    store.remove_document("ferrum");
    assert_eq!(store.latest_signal(), cursor);

    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert_eq!(
        drifted,
        vec!["ferrum".to_string()],
        "a committed revocation with no unconsumed signal must still force a reload"
    );

    full_reload(&mut published, &store, "ferrum");
    assert!(
        published.gateway_trust_bundle_for("ferrum").is_none(),
        "the escalated full reload withdraws the revoked roots"
    );
    let settled = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert!(settled.is_empty());
}

#[tokio::test]
async fn a_create_that_commits_after_its_signal_was_consumed_is_caught_by_the_next_poll() {
    let store = StoreSimulator::standalone();
    let mut published = GatewayConfig::default();
    let namespaces = vec!["ferrum".to_string()];

    // First incarnation of the namespace singleton: signal first, then the
    // poller consumes it and reloads an empty trust state, then the document
    // commits with the sequence the poller already passed.
    store.commit_signal(1);
    full_reload(&mut published, &store, "ferrum");
    let cursor = store.latest_signal();
    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 1));
    assert_eq!(store.latest_signal(), cursor);

    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert_eq!(
        drifted,
        vec!["ferrum".to_string()],
        "a first-incarnation create is invisible to the change log after the same race"
    );
}

#[tokio::test]
async fn a_delete_and_recreate_is_drift_even_though_the_namespace_still_holds_a_record() {
    let store = StoreSimulator::standalone();
    let mut published = GatewayConfig::default();
    let namespaces = vec!["ferrum".to_string()];

    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 7));
    full_reload(&mut published, &store, "ferrum");

    // A revocation and a recreate both land between two polls. The namespace
    // still has "a" record, so only the incarnation-safe revision distinguishes
    // it from the one that was published.
    store.remove_document("ferrum");
    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 12));

    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert_eq!(
        drifted,
        vec!["ferrum".to_string()],
        "a new incarnation under the same id must not read as the published one"
    );
}

#[tokio::test]
async fn a_transactional_backend_pays_nothing_for_the_check() {
    let store = StoreSimulator::transactional();
    let mut published = GatewayConfig::default();

    // Drift that WOULD be reported on a non-transactional store.
    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 3));
    publish_loaded(&mut published, "ferrum", None);

    let namespaces = vec!["ferrum".to_string(), "tenant-b".to_string()];
    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert!(
        drifted.is_empty(),
        "a backend whose trust write and signal are one transaction needs no check"
    );
    assert_eq!(
        store.identity_reads(),
        0,
        "SQL and replica-set MongoDB must not gain a per-poll query"
    );
}

#[tokio::test]
async fn the_sweep_is_one_bounded_read_per_polled_namespace_and_stays_namespace_scoped() {
    let store = StoreSimulator::standalone();
    let mut published = GatewayConfig::default();

    // tenant-a is converged; tenant-b drifted; tenant-c has no trust at all.
    store.commit_document("tenant-a", stored_identity("tenant-a", "a.local", 2));
    store.commit_document("tenant-b", stored_identity("tenant-b", "b.local", 5));
    full_reload(&mut published, &store, "tenant-a");
    publish_loaded(
        &mut published,
        "tenant-b",
        Some(&stored_identity("tenant-b", "b.local", 4)),
    );

    let namespaces = vec![
        "tenant-a".to_string(),
        "tenant-b".to_string(),
        "tenant-c".to_string(),
    ];
    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert_eq!(
        drifted,
        vec!["tenant-b".to_string()],
        "only the tenant whose own document moved may be escalated"
    );
    assert_eq!(
        store.identity_reads(),
        3,
        "exactly one identity read per polled namespace per tick"
    );
}

#[tokio::test]
async fn an_unreadable_stored_document_keeps_the_last_known_good_publication() {
    let store = StoreSimulator::standalone();
    let mut published = GatewayConfig::default();
    let namespaces = vec!["ferrum".to_string()];

    store.commit_document("ferrum", stored_identity("ferrum", "cluster.local", 6));
    full_reload(&mut published, &store, "ferrum");
    store.make_unreadable("ferrum");

    let drifted = detect_gateway_trust_drift(&store, &namespaces, &published).await;
    assert!(
        drifted.is_empty(),
        "a failed authoritative read must not withdraw or churn the trust state"
    );
    assert_eq!(
        published_revision(&published, "ferrum"),
        Some(6),
        "the last known good publication stands"
    );
}

#[test]
fn drift_is_decided_by_identity_alone_in_both_directions() {
    let mut held = valid_record();
    held.revision = 3;
    let same = stored_identity(&held.id, &held.trust_domain, 3);
    let rotated = stored_identity(&held.id, &held.trust_domain, 4);
    let other_id = stored_identity("other", &held.trust_domain, 3);
    let other_domain = stored_identity(&held.id, "other.local", 3);

    assert!(!gateway_trust_state_drifted(None, None));
    assert!(!gateway_trust_state_drifted(Some(&held), Some(&same)));
    assert!(
        gateway_trust_state_drifted(Some(&held), None),
        "a published record with no stored document is a revocation, not a no-op"
    );
    assert!(
        gateway_trust_state_drifted(None, Some(&same)),
        "a stored document with nothing published is an unannounced create"
    );
    assert!(
        gateway_trust_state_drifted(Some(&held), Some(&rotated)),
        "a newer revision under the same id is a rotation"
    );
    assert!(
        gateway_trust_state_drifted(Some(&held), Some(&other_id)),
        "a different resource id is a different record"
    );
    assert!(
        gateway_trust_state_drifted(Some(&held), Some(&other_domain)),
        "a different trust domain is different material"
    );
}

#[test]
fn detect_gateway_trust_drift_read_failure_logs_a_bounded_classification_only() {
    const SOURCE: &str = include_str!("../../../src/config/gateway_trust.rs");
    let body = SOURCE
        .split("pub async fn detect_gateway_trust_drift")
        .nth(1)
        .and_then(|rest| rest.split("\npub async fn ").next())
        .expect("detect_gateway_trust_drift body");
    assert!(
        !body.contains("error = %error"),
        "drift read failures must not render raw store errors:\n{body}"
    );
    assert!(
        body.contains("failure_class"),
        "drift read failures must log a fixed-cardinality classification:\n{body}"
    );
    assert!(
        body.contains("detail_withheld = true"),
        "drift read failures must withhold backend detail:\n{body}"
    );
}

// ── Bound composition: counts vs. total encoded size ────────────────────────
//
// The count caps and the total-byte cap answer different questions and are
// checked in a fixed order. These pin the relationship the operator docs state
// (`docs/cp_dp_mode.md` → "How the trust bounds compose"), so a future edit
// cannot silently reintroduce the 32-vs-256 mismatch that made a documented
// remote-cluster inventory unrepresentable.

#[test]
fn the_federated_bundle_cap_matches_the_mesh_remote_cluster_cap() {
    assert_eq!(
        MAX_FEDERATED_BUNDLES,
        ferrum_edge::modes::mesh::config::MAX_MESH_REMOTE_CLUSTERS,
        "a federated deployment carries one federated trust domain per remote \
         cluster, so a trust cap below the accepted remote-cluster cap would \
         make an already-admissible inventory unrepresentable and reject the \
         whole generation"
    );
}

#[test]
fn the_documented_full_cluster_inventory_with_rotation_overlap_is_admissible() {
    // One rotation-overlap PAIR of real ECDSA P-256 roots per federated trust
    // domain, at the full documented remote-cluster count. Two certificates are
    // generated and reused so the fixture stays cheap; the byte accounting is
    // what the total ceiling is measured against, and identical entries are not
    // deduplicated anywhere in the encoded document.
    let outgoing = root_ca_der_base64("inventory-outgoing-root");
    let incoming = root_ca_der_base64("inventory-incoming-root");
    let mut record = valid_record();
    record.bundle.local.x509_authorities = vec![outgoing.clone(), incoming.clone()];
    record.bundle.federated = (0..MAX_FEDERATED_BUNDLES)
        .map(|index| TrustBundle {
            trust_domain: trust_domain(&format!("remote-{index}.example.com")),
            x509_authorities: vec![outgoing.clone(), incoming.clone()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        })
        .collect();

    let encoded = serde_json::to_vec(&record.bundle).expect("inventory bundle serializes");
    assert!(
        encoded.len() <= MAX_TRUST_BUNDLE_JSON_BYTES,
        "the documented {MAX_FEDERATED_BUNDLES}-cluster inventory with rotation \
         overlap must fit the total ceiling; encoded {} bytes against a \
         {MAX_TRUST_BUNDLE_JSON_BYTES} byte cap",
        encoded.len()
    );
    record
        .validate_fields()
        .expect("the documented full inventory must be admissible");
}

#[test]
fn the_total_byte_ceiling_binds_before_the_count_caps_are_reached() {
    // Inside EVERY count cap and inside every per-entry cap, yet far over the
    // total. This is the case the count caps cannot express, and it must reject
    // on the cheap raw-material sum without funding a deep parser.
    //
    // One under-cap entry (the maximum base64 length that can still decode
    // within `MAX_X509_AUTHORITY_DER_BYTES`), repeated to the per-bundle count
    // cap, in the local bundle plus a single federated bundle.
    let entry = "A".repeat(4 * MAX_X509_AUTHORITY_DER_BYTES.div_ceil(3));
    let authorities = vec![entry; MAX_X509_AUTHORITIES_PER_BUNDLE];
    let mut record = valid_record();
    record.bundle.local.x509_authorities = authorities.clone();
    record.bundle.federated = vec![TrustBundle {
        trust_domain: trust_domain("remote.example.com"),
        x509_authorities: authorities,
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }];
    assert!(
        record.bundle.federated.len() <= MAX_FEDERATED_BUNDLES
            && record.bundle.local.x509_authorities.len() <= MAX_X509_AUTHORITIES_PER_BUNDLE,
        "the fixture must stay inside every count cap so the total is what rejects"
    );

    let errors = record
        .validate_fields()
        .expect_err("an over-total document must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("raw material") && error.contains("bytes")),
        "expected the total raw-material diagnostic, got {errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|error| !error.contains("authorities; the maximum")),
        "no count cap was exceeded, so no count diagnostic may appear: {errors:?}"
    );
    assert_structural_fail_fast(&errors);
}

// ── DP trust side-channel wire boundary ─────────────────────────────────────
//
// The ConfigSync `trust_bundles_json` side channel decodes through the SAME
// shared validator as database admission, and its refusal strings are a bounded
// operator-facing contract. These drive the production parser through
// `dp_client::classify_gateway_trust_side_channel_for_test`, which projects the
// decision onto a fixed label without exposing runtime trust material.

fn classify_side_channel(raw: &str) -> Result<&'static str, String> {
    ferrum_edge::grpc::dp_client::classify_gateway_trust_side_channel_for_test(raw)
}

fn wire_json(bundle: &TrustBundleSet) -> String {
    serde_json::to_string(bundle).expect("wire fixture serializes")
}

#[test]
fn the_trust_side_channel_accepts_a_real_certificate() {
    let bundle = bundle_with(vec![root_ca_der_base64("dp-wire-root")]);
    assert_eq!(
        classify_side_channel(&wire_json(&bundle))
            .expect("a real bounded X.509 authority must be accepted"),
        "replace"
    );
}

#[test]
fn the_trust_side_channel_rejects_malformed_and_trailing_der() {
    let engine = base64::engine::general_purpose::STANDARD;
    let malformed = bundle_with(vec![engine.encode(b"not-a-certificate")]);
    assert!(
        classify_side_channel(&wire_json(&malformed)).is_err(),
        "base64 that is not a certificate must not reach the live verifier"
    );

    let mut der = engine
        .decode(root_ca_der_base64("dp-wire-trailing-root"))
        .expect("fixture DER decodes");
    der.extend_from_slice(b"trailing");
    let trailing = bundle_with(vec![engine.encode(der)]);
    assert!(
        classify_side_channel(&wire_json(&trailing)).is_err(),
        "a certificate with appended bytes must be refused on the wire too"
    );
}

#[test]
fn the_trust_side_channel_rejects_duplicate_or_unusable_jwt_keys() {
    let usable = usable_public_key_pem();
    let jwt_bundle = |authorities: Vec<JwtAuthority>| TrustBundleSet {
        local: TrustBundle {
            trust_domain: trust_domain("cluster.local"),
            x509_authorities: Vec::new(),
            jwt_authorities: authorities,
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    };

    let duplicate = jwt_bundle(vec![
        JwtAuthority {
            key_id: "same".to_string(),
            public_key_pem: usable.clone(),
        },
        JwtAuthority {
            key_id: "same".to_string(),
            public_key_pem: usable,
        },
    ]);
    assert!(
        classify_side_channel(&wire_json(&duplicate)).is_err(),
        "a repeated key_id makes verification ambiguous and must be refused"
    );

    let unusable = jwt_bundle(vec![JwtAuthority {
        key_id: "bad".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----".to_string(),
    }]);
    assert!(
        classify_side_channel(&wire_json(&unusable)).is_err(),
        "a PEM the JWT-SVID parser cannot use must be refused"
    );
}

#[test]
fn the_trust_side_channel_rejects_wire_and_entry_limits() {
    let root = root_ca_der_base64("dp-wire-count-root");
    let over_count = bundle_with(vec![root; MAX_X509_AUTHORITIES_PER_BUNDLE + 1]);
    assert!(
        classify_side_channel(&wire_json(&over_count)).is_err(),
        "the per-bundle authority count cap applies on the wire"
    );

    let over_entry = bundle_with(vec!["A".repeat(MAX_X509_AUTHORITY_DER_BYTES * 2)]);
    assert!(
        classify_side_channel(&wire_json(&over_entry)).is_err(),
        "the per-authority size cap applies on the wire"
    );

    // The RAW wire cap is checked before deserialization, so an oversized value
    // never allocates a document.
    let raw = " ".repeat(MAX_TRUST_BUNDLE_JSON_BYTES + 1);
    assert_eq!(
        classify_side_channel(&raw).expect_err("raw wire cap must reject first"),
        "gateway trust bundles side-channel exceeds the wire limit"
    );
}
