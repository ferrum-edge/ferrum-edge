//! SPIFFE JWT-SVID mint / validate / bundle tests (issue #3617).
//!
//! Covers the library surface (`identity::jwt_svid`) and the three Workload
//! API JWT RPCs. Forged tokens are produced with `ring` directly rather than
//! through the library, so an attack case exercises the validator instead of
//! Ferrum's own minting rules.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ferrum_edge::identity::attestation::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use ferrum_edge::identity::jwt_svid::{
    JwtSvidSigner, LocalJwtAuthority, LocalJwtAuthorityConfig, SharedJwtSvidSigner, jwks_document,
    validate_jwt_svid,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::server::WorkloadApiService;
use std::collections::BTreeMap;
use std::sync::Arc;
use tonic::Request;

// ── fixtures ─────────────────────────────────────────────────────────────

fn td() -> TrustDomain {
    TrustDomain::new("td.test").expect("test trust domain is valid")
}

fn workload_id() -> SpiffeId {
    SpiffeId::from_parts(&td(), "ns/test/sa/foo").expect("test SPIFFE ID is valid")
}

/// A stable, configured signing authority — the production posture. Two calls
/// with the same PEM publish the same `kid`, which is what the restart /
/// multi-replica continuity tests assert.
fn authority_with_key(pem: &str) -> Arc<LocalJwtAuthority> {
    Arc::new(
        LocalJwtAuthority::new(LocalJwtAuthorityConfig::new(td()).with_signing_key_pem(pem))
            .expect("local JWT authority builds from configured material"),
    )
}

/// Dev/test posture: an explicitly opted-in ephemeral key. Used where the test
/// does not care which key signs, only that signing works.
fn authority() -> Arc<LocalJwtAuthority> {
    Arc::new(
        LocalJwtAuthority::new(LocalJwtAuthorityConfig::new(td()).allowing_ephemeral_key())
            .expect("local JWT authority builds"),
    )
}

/// A fresh ES256 (P-256) PKCS#8 private key PEM, the shape
/// `FERRUM_MESH_JWT_SIGNING_KEY_PEM` accepts.
fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key generated")
        .serialize_pem()
}

/// A base config with an explicit key and bounds a test can tighten.
fn config_with_key(pem: &str) -> LocalJwtAuthorityConfig {
    LocalJwtAuthorityConfig::new(td()).with_signing_key_pem(pem)
}

/// A base config for the **ephemeral** (dev/test) posture with bounds a test can
/// tighten.
///
/// In-process key rotation exists only here. A configured authority is rotated
/// externally (new primary + previous verification key), so every cadence /
/// retention / `rotate()` test uses this rather than `config_with_key`.
fn ephemeral_config() -> LocalJwtAuthorityConfig {
    LocalJwtAuthorityConfig::new(td()).allowing_ephemeral_key()
}

fn bundles_of(
    signer: &Arc<LocalJwtAuthority>,
) -> BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> {
    let mut bundles = BTreeMap::new();
    bundles.insert(td(), signer.authorities());
    bundles
}

fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        tonic::metadata::AsciiMetadataValue::from_static("true"),
    );
    req
}

/// CA backend that owns a JWT signing authority (the `internal` posture).
struct JwtCapableCa {
    trust_domain: TrustDomain,
    jwt: Arc<LocalJwtAuthority>,
}

#[async_trait]
impl CertificateAuthority for JwtCapableCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let (spiffe_id, ttl_secs) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            }
            | IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id,
            cert_chain_der: vec![b"stub-cert".to_vec()],
            private_key_pkcs8_der: b"stub-key".to_vec().into(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64),
        })
    }

    async fn trust_bundle(&self, domain: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if domain != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(domain.to_string()));
        }
        Ok(PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![b"stub-root".to_vec()],
            refresh_hint_secs: None,
        })
    }

    async fn jwt_authorities(
        &self,
        domain: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        if domain != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(domain.to_string()));
        }
        Ok(self.jwt.authorities())
    }

    fn jwt_signer(&self) -> Option<SharedJwtSvidSigner> {
        Some(Arc::clone(&self.jwt) as SharedJwtSvidSigner)
    }
}

/// CA backend with no JWT authority at all (the `spire` posture).
struct JwtlessCa {
    trust_domain: TrustDomain,
}

#[async_trait]
impl CertificateAuthority for JwtlessCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let (spiffe_id, ttl_secs) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            }
            | IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id,
            cert_chain_der: vec![b"stub-cert".to_vec()],
            private_key_pkcs8_der: b"stub-key".to_vec().into(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64),
        })
    }

    async fn trust_bundle(&self, domain: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if domain != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(domain.to_string()));
        }
        Ok(PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![b"stub-root".to_vec()],
            refresh_hint_secs: None,
        })
    }

    async fn jwt_authorities(
        &self,
        _domain: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}

struct StubAttestor {
    id: SpiffeId,
}

#[async_trait]
impl Attestor for StubAttestor {
    fn kind(&self) -> &'static str {
        "stub"
    }

    async fn attest(&self, _peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: self.id.clone(),
            selectors: Default::default(),
            attestor_kind: "stub".to_string(),
        })
    }
}

fn jwt_capable_service() -> (WorkloadApiService, Arc<LocalJwtAuthority>) {
    let jwt = authority();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(JwtCapableCa {
        trust_domain: td(),
        jwt: Arc::clone(&jwt),
    });
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
    (WorkloadApiService::new(vec![attestor], ca, td(), 600), jwt)
}

// ── forged-token machinery ───────────────────────────────────────────────

/// DER prefix of a P-256 `SubjectPublicKeyInfo`: `SEQUENCE { AlgorithmIdentifier
/// { id-ecPublicKey, prime256v1 }, BIT STRING (0 unused bits) }`. The 65-byte
/// uncompressed point follows.
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// An attacker-controlled (or independently generated) ES256 key we can forge
/// arbitrary headers and claim sets with.
struct ForgeKey {
    pkcs8: Vec<u8>,
    public_key_pem: String,
}

fn forge_key() -> ForgeKey {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("ring generates a P-256 key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("generated PKCS#8 parses");

    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key_pair.public_key().as_ref());

    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    let encoded = STANDARD.encode(&spki);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    ForgeKey {
        pkcs8: pkcs8.as_ref().to_vec(),
        public_key_pem: pem,
    }
}

/// Sign an arbitrary header/claims pair into a JWS compact serialization.
fn sign_compact(key: &ForgeKey, header_json: &str, claims_json: &str) -> String {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let rng = ring::rand::SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key.pkcs8, &rng)
        .expect("forge key parses");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json.as_bytes()),
        URL_SAFE_NO_PAD.encode(claims_json.as_bytes())
    );
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("forge key signs");
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )
}

/// A bundle holding exactly one forged authority under `kid`.
fn forged_bundles(key: &ForgeKey, kid: &str) -> BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> {
    let mut bundles = BTreeMap::new();
    bundles.insert(
        td(),
        vec![PublishedJwtAuthority {
            trust_domain: td(),
            key_id: kid.to_string(),
            public_key_pem: key.public_key_pem.clone(),
            declared_alg: None,
        }],
    );
    bundles
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn claims_of(validated_json: &[u8]) -> serde_json::Value {
    serde_json::from_slice(validated_json).expect("claims are JSON")
}

// ── mint ─────────────────────────────────────────────────────────────────

#[test]
fn mint_and_validate_round_trip() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["spiffe://td.test/api".to_string()], 0)
        .expect("mint succeeds");

    let validated = validate_jwt_svid(&minted.token, "spiffe://td.test/api", &bundles_of(&signer))
        .expect("round trip validates");

    assert_eq!(validated.spiffe_id, workload_id());
    let claims = claims_of(&validated.claims_json);
    assert_eq!(claims["sub"], workload_id().as_str());
    assert_eq!(claims["aud"][0], "spiffe://td.test/api");
    assert!(claims["exp"].is_number(), "exp must be present");
    assert!(claims["iat"].is_number(), "iat must be present");
    assert!(
        claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()),
        "each token needs a unique identity"
    );
}

#[test]
fn minted_tokens_have_distinct_token_ids() {
    let signer = authority();
    let first = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("first mint");
    let second = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("second mint");
    assert_ne!(
        first.token, second.token,
        "two mints must not produce byte-identical bearer tokens"
    );
}

#[test]
fn mint_rejects_an_empty_audience_list() {
    let signer = authority();
    let err = signer
        .mint(&workload_id(), &[], 0)
        .expect_err("an audience is required");
    assert!(err.to_string().contains("at least one audience"));
}

#[test]
fn mint_rejects_an_empty_audience_entry() {
    let signer = authority();
    assert!(
        signer.mint(&workload_id(), &[String::new()], 0).is_err(),
        "an empty audience string must not reach a signed token"
    );
    assert!(
        signer
            .mint(&workload_id(), &["   ".to_string()], 0)
            .is_err(),
        "a whitespace-only audience must not reach a signed token"
    );
}

#[test]
fn mint_rejects_too_many_or_oversized_audiences() {
    let signer = authority();
    let many: Vec<String> = (0..64).map(|index| format!("aud-{index}")).collect();
    assert!(signer.mint(&workload_id(), &many, 0).is_err());

    let huge = vec!["a".repeat(4096)];
    assert!(signer.mint(&workload_id(), &huge, 0).is_err());
}

#[test]
fn mint_rejects_a_control_character_audience() {
    let signer = authority();
    assert!(
        signer
            .mint(&workload_id(), &["good\u{0000}evil".to_string()], 0)
            .is_err()
    );
}

#[test]
fn mint_collapses_duplicate_audiences_preserving_order() {
    let signer = authority();
    let minted = signer
        .mint(
            &workload_id(),
            &["b".to_string(), "a".to_string(), "b".to_string()],
            0,
        )
        .expect("mint succeeds");
    let validated = validate_jwt_svid(&minted.token, "a", &bundles_of(&signer)).expect("validates");
    let claims = claims_of(&validated.claims_json);
    assert_eq!(claims["aud"], serde_json::json!(["b", "a"]));
}

#[test]
fn mint_refuses_a_subject_from_another_trust_domain() {
    let signer = authority();
    let foreign = SpiffeId::new("spiffe://other.test/ns/x/sa/y").expect("valid SPIFFE ID");
    let err = signer
        .mint(&foreign, &["aud".to_string()], 0)
        .expect_err("cross-trust-domain mint must be refused");
    assert!(err.to_string().contains("trust domain"));
}

#[test]
fn mint_clamps_the_lifetime_to_the_authority_ceiling() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], u64::MAX)
        .expect("mint succeeds");
    let lifetime = (minted.expires_at - minted.issued_at).num_seconds();
    assert!(
        lifetime <= 3600,
        "a caller must not be able to raise the JWT-SVID ceiling (got {lifetime}s)"
    );
    assert!(lifetime > 0);
}

// ── validate: audience / subject ─────────────────────────────────────────

#[test]
fn validate_rejects_a_different_audience() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["intended".to_string()], 0)
        .expect("mint succeeds");
    let err = validate_jwt_svid(&minted.token, "attacker", &bundles_of(&signer))
        .expect_err("audience mismatch must fail");
    assert!(err.to_string().contains("audience"));
}

#[test]
fn validate_rejects_an_empty_audience_argument() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");
    assert!(validate_jwt_svid(&minted.token, "", &bundles_of(&signer)).is_err());
}

#[test]
fn validate_rejects_a_non_spiffe_subject() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"not-a-spiffe-id","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a non-SPIFFE subject must fail");
    assert!(err.to_string().contains("SPIFFE ID"));
}

#[test]
fn validate_rejects_an_issuer_from_another_trust_domain() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","iss":"spiffe://evil.test","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a cross-domain issuer must fail");
    assert!(err.to_string().contains("issuer"));
}

// ── validate: key / algorithm ────────────────────────────────────────────

#[test]
fn validate_rejects_an_unknown_trust_domain() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");

    let mut bundles = BTreeMap::new();
    let other = TrustDomain::new("other.test").expect("valid trust domain");
    bundles.insert(
        other.clone(),
        vec![PublishedJwtAuthority {
            trust_domain: other,
            key_id: "k1".to_string(),
            public_key_pem: forge_key().public_key_pem,
            declared_alg: None,
        }],
    );

    let err = validate_jwt_svid(&minted.token, "aud", &bundles)
        .expect_err("a token from an untrusted domain must fail");
    assert!(err.to_string().contains("trust domain"));
}

#[test]
fn validate_rejects_an_unknown_key_id() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");
    let err = validate_jwt_svid(
        &minted.token,
        "aud",
        &forged_bundles(&forge_key(), "unrelated"),
    )
    .expect_err("an unknown kid must fail");
    assert!(err.to_string().contains("key id"));
}

#[test]
fn validate_rejects_a_signature_from_a_different_key_under_the_same_key_id() {
    // The classic key-substitution attempt: keep the `kid` the verifier
    // expects, but sign with a key the verifier does not hold.
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");
    let real_kid = signer.authorities()[0].key_id.clone();

    let err = validate_jwt_svid(
        &minted.token,
        "aud",
        &forged_bundles(&forge_key(), &real_kid),
    )
    .expect_err("a mismatched key must fail");
    assert!(err.to_string().contains("signature"));
}

#[test]
fn validate_rejects_the_unsecured_none_algorithm() {
    let claims = format!(
        r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
        now() + 300
    );
    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes())
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&forge_key(), "k1"))
        .expect_err("alg=none must fail");
    // The empty signature segment is caught first; either rejection is
    // fail-closed, and the alg check covers the padded-signature form below.
    assert!(!err.to_string().is_empty());

    let with_signature = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"x")
    );
    let err = validate_jwt_svid(&with_signature, "aud", &forged_bundles(&forge_key(), "k1"))
        .expect_err("alg=none must fail");
    assert!(err.to_string().contains("none"));
}

#[test]
fn validate_rejects_a_symmetric_algorithm() {
    // Algorithm confusion: an attacker who can read the public JWT bundle
    // signs an HS256 token with the published public key as the HMAC secret.
    let claims = format!(
        r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
        now() + 300
    );
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"forged-mac")
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&forge_key(), "k1"))
        .expect_err("HS256 must fail against a public-key bundle");
    assert!(err.to_string().contains("symmetric"));
}

#[test]
fn validate_rejects_unknown_critical_headers() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","crit":["ferrum"],"ferrum":1}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("unknown critical headers must fail");
    assert!(err.to_string().contains("critical"));
}

#[test]
fn validate_rejects_a_kidless_token_when_the_bundle_is_ambiguous() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );

    // One key: no `kid` is unambiguous and validates.
    validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect("a single-key bundle resolves a kid-less token");

    // Two keys: the token no longer identifies which authority signed it.
    let mut ambiguous = forged_bundles(&key, "k1");
    ambiguous
        .get_mut(&td())
        .expect("local bundle")
        .push(PublishedJwtAuthority {
            trust_domain: td(),
            key_id: "k2".to_string(),
            public_key_pem: forge_key().public_key_pem,
            declared_alg: None,
        });
    let err = validate_jwt_svid(&token, "aud", &ambiguous)
        .expect_err("an ambiguous kid-less token must fail");
    assert!(err.to_string().contains("which JWT authority"));
}

// ── validate: time and claim hygiene ─────────────────────────────────────

#[test]
fn validate_rejects_an_expired_token() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() - 3600
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("an expired token must fail");
    assert!(err.to_string().contains("expired"));
}

#[test]
fn validate_requires_an_expiry_claim() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        r#"{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"]}"#,
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a token with no exp must fail");
    assert!(err.to_string().contains("expiry"));
}

#[test]
fn validate_rejects_a_not_yet_valid_token() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"nbf":{},"exp":{}}}"#,
            now() + 3600,
            now() + 7200
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a not-yet-valid token must fail");
    assert!(err.to_string().contains("not yet valid"));
}

#[test]
fn validate_rejects_a_future_dated_issue_time() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"iat":{},"exp":{}}}"#,
            now() + 7200,
            now() + 7500
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a future-dated iat must fail");
    assert!(err.to_string().contains("future"));
}

#[test]
fn validate_rejects_repeated_claim_keys() {
    // `{"aud":"attacker","aud":"victim"}` is ambiguous: a last-wins parser and
    // a first-wins parser disagree about what was signed.
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["other"],"aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("repeated claim keys must fail");
    assert!(err.to_string().contains("repeats an object key"));
}

#[test]
fn validate_rejects_repeated_header_keys() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"HS256","alg":"ES256","kid":"k1"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("repeated header keys must fail");
    assert!(err.to_string().contains("repeats an object key"));
}

#[test]
fn validate_rejects_a_non_numeric_expiry() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        r#"{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":"soon"}"#,
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a string exp must fail");
    assert!(err.to_string().contains("non-numeric"));
}

#[test]
fn validate_rejects_a_numeric_date_above_i64_max_without_saturating_it() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        r#"{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":9223372036854775808}"#,
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("an out-of-range NumericDate must fail rather than saturate");
    assert!(err.to_string().contains("representable range"));
}

#[test]
fn validate_rejects_a_bad_typ_header() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"at+jwt"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a non-JWT typ must fail");
    assert!(err.to_string().contains("typ"));
}

// ── validate: malformed / oversized input ────────────────────────────────

#[test]
fn validate_rejects_structurally_malformed_tokens() {
    let bundles = forged_bundles(&forge_key(), "k1");
    for (name, token) in [
        ("empty", String::new()),
        ("one segment", "abc".to_string()),
        ("two segments", "abc.def".to_string()),
        ("four segments", "a.b.c.d".to_string()),
        ("empty middle segment", "abc..def".to_string()),
        ("padded base64", "ab=.cd.ef".to_string()),
        ("non-base64url", "ab+/.cd.ef".to_string()),
    ] {
        assert!(
            validate_jwt_svid(&token, "aud", &bundles).is_err(),
            "{name}: malformed token must be refused"
        );
    }
}

#[test]
fn validate_rejects_an_oversized_token() {
    let bundles = forged_bundles(&forge_key(), "k1");
    let huge = format!("{}.{}.{}", "a".repeat(9000), "b".repeat(16), "c".repeat(16));
    let err = validate_jwt_svid(&huge, "aud", &bundles).expect_err("oversized token must fail");
    assert!(err.to_string().contains("too large"));
}

#[test]
fn validate_reports_no_authority_when_the_bundle_set_is_empty() {
    let empty: BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> = BTreeMap::new();
    let err = validate_jwt_svid("a.b.c", "aud", &empty).expect_err("no authority must fail");
    assert!(
        err.to_string().contains("no JWT authority"),
        "an absent authority is 'unsupported', not 'bad token' (got: {err})"
    );
}

#[test]
fn validation_errors_never_echo_token_bytes() {
    let bundles = forged_bundles(&forge_key(), "k1");
    let marker = "SUPERSECRETMARKER";
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","kid":"{marker}"}}"#).as_bytes()),
        URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{marker}","aud":["{marker}"]}}"#).as_bytes()),
        URL_SAFE_NO_PAD.encode(marker.as_bytes())
    );
    let err = validate_jwt_svid(&token, marker, &bundles).expect_err("must fail");
    assert!(
        !err.to_string().contains(marker),
        "rejection reasons must not reflect hostile token bytes (got: {err})"
    );
}

// ── JWKS bundles ─────────────────────────────────────────────────────────

#[test]
fn jwks_document_refuses_an_empty_authority_set() {
    let err = jwks_document(&[]).expect_err("an empty JWKS is not a conformant bundle");
    assert!(err.to_string().contains("no JWT authorities"));
}

#[test]
fn jwks_document_publishes_a_usable_jwks() {
    let signer = authority();
    let document = jwks_document(&signer.authorities()).expect("JWKS builds");
    let parsed: serde_json::Value = serde_json::from_slice(&document).expect("JWKS is JSON");
    let keys = parsed["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "EC");
    assert_eq!(keys[0]["crv"], "P-256");
    assert_eq!(keys[0]["alg"], "ES256");
    assert_eq!(keys[0]["use"], "sig");
    assert_eq!(keys[0]["kid"], signer.authorities()[0].key_id.as_str());
    assert!(keys[0]["x"].as_str().is_some_and(|x| !x.is_empty()));
    assert!(keys[0]["y"].as_str().is_some_and(|y| !y.is_empty()));
    assert!(
        keys[0].get("d").is_none(),
        "a JWT bundle must never carry private key material"
    );
}

#[test]
fn jwks_document_rejects_duplicate_key_ids() {
    let one = forge_key();
    let two = forge_key();
    let err = jwks_document(&[
        PublishedJwtAuthority {
            trust_domain: td(),
            key_id: "same".to_string(),
            public_key_pem: one.public_key_pem,
            declared_alg: None,
        },
        PublishedJwtAuthority {
            trust_domain: td(),
            key_id: "same".to_string(),
            public_key_pem: two.public_key_pem,
            declared_alg: None,
        },
    ])
    .expect_err("ambiguous key ids must be refused");
    assert!(err.to_string().contains("share a key id"));
}

#[test]
fn jwks_document_rejects_malformed_authority_material() {
    for (name, key_id, pem) in [
        (
            "empty kid",
            "",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        ),
        ("not a pem", "k1", "hello"),
        (
            "not base64",
            "k1",
            "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----",
        ),
        (
            "not an spki",
            "k1",
            "-----BEGIN PUBLIC KEY-----\nAAECAwQFBgcICQoLDA0ODw==\n-----END PUBLIC KEY-----",
        ),
    ] {
        assert!(
            jwks_document(&[PublishedJwtAuthority {
                trust_domain: td(),
                key_id: key_id.to_string(),
                public_key_pem: pem.to_string(),
                declared_alg: None,
            }])
            .is_err(),
            "{name}: malformed authority material must not be published"
        );
    }
}

#[test]
fn jwks_document_rejects_a_multi_block_pem() {
    let one = forge_key();
    let two = forge_key();
    let concatenated = format!("{}{}", one.public_key_pem, two.public_key_pem);
    let err = jwks_document(&[PublishedJwtAuthority {
        trust_domain: td(),
        key_id: "k1".to_string(),
        public_key_pem: concatenated,
        declared_alg: None,
    }])
    .expect_err("a concatenated PEM hides the second key behind one kid");
    assert!(err.to_string().contains("more than one block"));
}

// ── rotation ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_keeps_pre_rotation_tokens_verifiable() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint before rotation");
    let before = signer.generation();

    let after = signer.rotate().await.expect("rotation succeeds");
    assert_eq!(after, before + 1, "rotation bumps the generation");

    let authorities = signer.authorities();
    assert_eq!(
        authorities.len(),
        2,
        "the retired key must stay published through the overlap"
    );

    validate_jwt_svid(&minted.token, "aud", &bundles_of(&signer))
        .expect("a token minted just before rotation stays verifiable");

    let after_rotation = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint after rotation");
    validate_jwt_svid(&after_rotation.token, "aud", &bundles_of(&signer))
        .expect("the fresh key validates too");
    assert_ne!(
        minted.key_id, after_rotation.key_id,
        "rotation must actually change the signing key"
    );
}

#[tokio::test]
async fn rapid_rotation_refuses_rather_than_evicting_a_still_live_key() {
    // Overlap is `max_ttl + 60s` clock-skew leeway = 61s, so every key retired
    // in this test is still inside its overlap. Time-based rotation is disabled
    // (`0`) so the cap is not derived up from a cadence and the manual
    // over-rotation case is reachable at all.
    let mut config = ephemeral_config();
    config.default_ttl_secs = 1;
    config.max_ttl_secs = 1;
    config.key_lifetime_secs = 0;
    config.max_retained_keys = 2;
    let signer = Arc::new(LocalJwtAuthority::new(config).expect("authority builds"));

    // A token minted by the ORIGINAL key. It must still validate after every
    // rotation the authority accepts.
    let oldest = signer
        .mint(&workload_id(), &["aud-a".to_string()], 1)
        .expect("mint succeeds");

    signer.rotate().await.expect("first rotation succeeds");
    signer
        .rotate()
        .await
        .expect("second rotation fills the cap");
    let generation_at_cap = signer.generation();

    let refused = signer
        .rotate()
        .await
        .expect_err("a third rotation would have to evict a still-live retired key");
    assert!(
        matches!(
            refused,
            ferrum_edge::identity::jwt_svid::JwtSvidError::RotationRefused(_)
        ),
        "expected RotationRefused, got {refused:?}"
    );
    assert_eq!(
        signer.generation(),
        generation_at_cap,
        "a refused rotation must not advance the generation"
    );

    let authorities = signer.authorities();
    assert!(
        authorities.len() <= 3,
        "active + at most 2 retained keys, got {}",
        authorities.len()
    );
    // The published set must still be a valid, unambiguous bundle...
    jwks_document(&authorities).expect("retained keys still form a valid JWKS");
    // ...and the oldest still-live token must still validate against it. This is
    // the guarantee the refusal exists to protect.
    validate_jwt_svid(&oldest.token, "aud-a", &bundles_of(&signer))
        .expect("a token inside its permitted lifetime still validates after rotation");
}

#[tokio::test]
async fn construction_refuses_a_cadence_shorter_than_the_overlap_permits() {
    // 1s tokens ⇒ 61s overlap ⇒ ceil(61 / 15 retained slots) = 5s minimum. A 1s
    // cadence could not retain every still-verifiable key inside the
    // published-authority cap, so it is refused rather than silently accepted.
    let mut config = ephemeral_config();
    config.max_ttl_secs = 1;
    config.key_lifetime_secs = 1;
    let error = LocalJwtAuthority::new(config).expect_err("too-short cadence is refused");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidSigningMaterial(_)
        ),
        "expected InvalidSigningMaterial, got {error:?}"
    );
}

#[tokio::test]
async fn a_scheduled_cadence_raises_the_retention_cap_so_rotation_never_refuses() {
    // The cap is DERIVED from the cadence: overlap 61s / 5s lifetime ⇒ 13
    // required slots, even though 1 was configured. Rotating that many times
    // must therefore never hit the refusal path.
    let mut config = ephemeral_config();
    config.default_ttl_secs = 1;
    config.max_ttl_secs = 1;
    config.key_lifetime_secs = 5;
    config.max_retained_keys = 1;
    let signer = Arc::new(LocalJwtAuthority::new(config).expect("authority builds"));

    for index in 0..13 {
        signer
            .rotate()
            .await
            .unwrap_or_else(|e| panic!("rotation {index} must not be refused: {e}"));
    }
    let authorities = signer.authorities();
    assert!(
        authorities.len() <= 14,
        "active + 13 retained slots, got {}",
        authorities.len()
    );
    jwks_document(&authorities).expect("the derived cap still yields a valid JWKS");
}

#[tokio::test]
async fn rotate_if_due_is_a_no_op_while_the_key_is_young() {
    let signer = authority();
    let before = signer.generation();
    assert_eq!(
        signer.rotate_if_due().await.expect("no-op succeeds"),
        None,
        "a fresh key must not rotate"
    );
    assert_eq!(signer.generation(), before);
}

#[tokio::test]
async fn a_u64_rotation_cadence_above_i64_max_is_not_immediately_due() {
    let mut config = ephemeral_config();
    config.key_lifetime_secs = u64::MAX;
    let signer = LocalJwtAuthority::new(config).expect("authority builds");
    let before = signer.generation();

    assert_eq!(
        signer.rotate_if_due().await.expect("no-op succeeds"),
        None,
        "a huge valid u64 cadence must not wrap negative and rotate a fresh key"
    );
    assert_eq!(signer.generation(), before);
}

#[tokio::test]
async fn rotate_if_due_rotates_once_the_lifetime_has_elapsed() {
    // 5s is the shortest cadence a 1s token ceiling permits (overlap 61s over 15
    // retained slots), so this is the fastest deterministic rotation available.
    let mut config = ephemeral_config();
    config.default_ttl_secs = 1;
    config.max_ttl_secs = 1;
    config.key_lifetime_secs = 5;
    let signer = Arc::new(LocalJwtAuthority::new(config).expect("authority builds"));
    let before = signer.generation();
    tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
    let rotated = signer.rotate_if_due().await.expect("rotation succeeds");
    assert_eq!(rotated, Some(before + 1));

    // Two concurrent callers that BOTH observed the same due state must produce
    // exactly ONE rotation: the second re-checks under the rotation gate. Without
    // that re-check the freshly installed key would be rotated away immediately,
    // burning a retention slot and halving its effective lifetime.
    let after_first = signer.generation();
    tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
    let left = Arc::clone(&signer);
    let right = Arc::clone(&signer);
    let (a, b) = tokio::join!(
        tokio::spawn(async move { left.rotate_if_due().await }),
        tokio::spawn(async move { right.rotate_if_due().await }),
    );
    let a = a.expect("task joins").expect("rotation succeeds");
    let b = b.expect("task joins").expect("rotation succeeds");
    assert_eq!(
        [a.is_some(), b.is_some()].iter().filter(|x| **x).count(),
        1,
        "exactly one of two concurrent due observations may rotate"
    );
    assert_eq!(
        signer.generation(),
        after_first + 1,
        "one due observation must yield exactly one generation bump"
    );
}

// ── Workload API RPCs ────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_jwtsvid_mints_for_the_attested_identity() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;

    let (svc, signer) = jwt_capable_service();
    let response = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://td.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("mint succeeds")
        .into_inner();

    assert_eq!(response.svids.len(), 1);
    assert_eq!(response.svids[0].spiffe_id, workload_id().as_str());
    let validated = validate_jwt_svid(
        &response.svids[0].svid,
        "spiffe://td.test/api",
        &bundles_of(&signer),
    )
    .expect("the minted token validates against the published bundle");
    assert_eq!(validated.spiffe_id, workload_id());
}

#[tokio::test]
async fn fetch_jwtsvid_accepts_an_explicit_matching_subject() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;

    let (svc, _) = jwt_capable_service();
    svc.fetch_jwtsvid(workload_request(JwtsvidRequest {
        audience: vec!["aud".to_string()],
        spiffe_id: workload_id().as_str().to_string(),
    }))
    .await
    .expect("the attested identity may be named explicitly");
}

#[tokio::test]
async fn fetch_jwtsvid_denies_a_caller_selected_subject() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["aud".to_string()],
            spiffe_id: "spiffe://td.test/ns/test/sa/victim".to_string(),
        }))
        .await
        .expect_err("an arbitrary subject must be refused");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn fetch_jwtsvid_rejects_an_empty_audience_list() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: Vec::new(),
            spiffe_id: String::new(),
        }))
        .await
        .expect_err("at least one audience is required");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn fetch_jwtsvid_requires_the_workload_metadata_header() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .fetch_jwtsvid(Request::new(JwtsvidRequest {
            audience: vec!["aud".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect_err("the metadata gate runs first");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn fetch_jwt_bundles_streams_the_local_bundle_and_dedups_unchanged_generations() {
    use ferrum_edge::identity::workload_api::proto::JwtBundlesRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    let jwt = authority();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(JwtCapableCa {
        trust_domain: td(),
        jwt: Arc::clone(&jwt),
    });
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        td(),
        600,
        Arc::clone(&rotation),
    );

    let mut stream = svc
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("bundles stream opens")
        .into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for the initial bundle")
        .expect("stream ended unexpectedly")
        .expect("initial bundle was an error");
    assert!(
        !first.bundles.is_empty(),
        "an empty bundles map is never a success response"
    );
    let local = first
        .bundles
        .get(td().as_str())
        .expect("the local trust-domain bundle is mandatory");
    let parsed: serde_json::Value = serde_json::from_slice(local).expect("bundle is a JWKS");
    assert_eq!(parsed["keys"].as_array().expect("keys").len(), 1);

    // A rotation signal that does not change JWT authorities must not
    // republish an identical bundle.
    rotation.send_modify(|value| *value += 1);
    let deduped = tokio::time::timeout(std::time::Duration::from_millis(250), stream.next()).await;
    assert!(
        deduped.is_err(),
        "an unchanged authority set must not be republished"
    );

    // A real JWT key rotation must publish.
    jwt.rotate().await.expect("rotation succeeds");
    rotation.send_modify(|value| *value += 1);
    let updated = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for the rotated bundle")
        .expect("stream ended unexpectedly")
        .expect("rotated bundle was an error");
    let local = updated
        .bundles
        .get(td().as_str())
        .expect("the local bundle is still mandatory");
    let parsed: serde_json::Value = serde_json::from_slice(local).expect("bundle is a JWKS");
    assert_eq!(
        parsed["keys"].as_array().expect("keys").len(),
        2,
        "the rotated bundle carries the new key plus the retained one"
    );
}

#[tokio::test]
async fn fetch_jwt_bundles_is_unimplemented_without_a_jwt_authority() {
    use ferrum_edge::identity::workload_api::proto::JwtBundlesRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let ca: Arc<dyn CertificateAuthority> = Arc::new(JwtlessCa { trust_domain: td() });
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
    let svc = WorkloadApiService::new(vec![attestor], ca, td(), 600);

    let err = svc
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .err()
        .expect("must not return Ok(stream) of empty maps");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn validate_jwtsvid_round_trips_through_the_service() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{JwtsvidRequest, ValidateJwtsvidRequest};

    let (svc, _) = jwt_capable_service();
    let minted = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://td.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("mint succeeds")
        .into_inner();

    let validated = svc
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://td.test/api".to_string(),
            svid: minted.svids[0].svid.clone(),
        }))
        .await
        .expect("validation succeeds")
        .into_inner();

    assert_eq!(validated.spiffe_id, workload_id().as_str());
    let claims = claims_of(&validated.claims_json);
    assert_eq!(claims["sub"], workload_id().as_str());
}

#[tokio::test]
async fn validate_jwtsvid_rejects_a_wrong_audience_through_the_service() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{JwtsvidRequest, ValidateJwtsvidRequest};
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let minted = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["intended".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("mint succeeds")
        .into_inner();

    let err = svc
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "attacker".to_string(),
            svid: minted.svids[0].svid.clone(),
        }))
        .await
        .expect_err("audience mismatch must fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn validate_jwtsvid_requires_the_workload_metadata_header() {
    use ferrum_edge::identity::workload_api::proto::ValidateJwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .validate_jwtsvid(Request::new(ValidateJwtsvidRequest {
            audience: "aud".to_string(),
            svid: "a.b.c".to_string(),
        }))
        .await
        .expect_err("the metadata gate runs first");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn x509_rpcs_are_unaffected_by_the_jwt_surface() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{X509BundlesRequest, X509svidRequest};
    use tokio_stream::StreamExt;

    let (svc, _) = jwt_capable_service();

    let mut svids = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("X.509 SVID stream opens")
        .into_inner();
    let svid = tokio::time::timeout(std::time::Duration::from_secs(2), svids.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("first SVID was an error");
    assert_eq!(svid.svids[0].spiffe_id, workload_id().as_str());
    assert_eq!(svid.svids[0].x509_svid, b"stub-cert");

    let mut bundles = svc
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("X.509 bundle stream opens")
        .into_inner();
    let bundle = tokio::time::timeout(std::time::Duration::from_secs(2), bundles.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("first bundle was an error");
    assert_eq!(
        bundle.bundles.get(td().as_str()).map(Vec::as_slice),
        Some(b"stub-root".as_slice())
    );
}

// ── stable signing material: restart + multi-replica continuity ───────────

#[tokio::test]
async fn configured_signing_material_publishes_a_stable_key_id() {
    // Two independently constructed authorities handed the SAME material are the
    // SAME trust-domain authority. This is what makes a restart and a second
    // replica indistinguishable to a relying party.
    let pem = signing_key_pem();
    let first = authority_with_key(&pem);
    let second = authority_with_key(&pem);

    let left = first.authorities();
    let right = second.authorities();
    assert_eq!(left.len(), 1);
    assert_eq!(
        left[0].key_id, right[0].key_id,
        "the same signing material must publish the same kid"
    );
    assert_eq!(
        left[0].public_key_pem, right[0].public_key_pem,
        "the same signing material must publish the same public key"
    );
    assert_eq!(
        jwks_document(&left).expect("left JWKS"),
        jwks_document(&right).expect("right JWKS"),
        "two replicas of one trust domain must publish a byte-identical JWKS"
    );
    assert!(!first.uses_ephemeral_key());
}

#[tokio::test]
async fn a_token_minted_before_restart_validates_after_restart() {
    let pem = signing_key_pem();
    let before_restart = authority_with_key(&pem);
    let minted = before_restart
        .mint(&workload_id(), &["aud-a".to_string()], 300)
        .expect("mint succeeds");

    // "Restart": a brand-new authority, same configured material, no shared
    // in-memory state at all.
    drop(before_restart);
    let after_restart = authority_with_key(&pem);
    let validated = validate_jwt_svid(&minted.token, "aud-a", &bundles_of(&after_restart))
        .expect("a token minted before the restart still validates after it");
    assert_eq!(validated.spiffe_id, workload_id());
}

#[tokio::test]
async fn a_second_replica_validates_the_first_replicas_token() {
    let pem = signing_key_pem();
    let replica_a = authority_with_key(&pem);
    let replica_b = authority_with_key(&pem);
    let minted = replica_a
        .mint(&workload_id(), &["aud-a".to_string()], 300)
        .expect("mint succeeds");
    validate_jwt_svid(&minted.token, "aud-a", &bundles_of(&replica_b))
        .expect("a peer replica sharing the signing material validates the token");
}

#[tokio::test]
async fn an_ephemeral_key_does_not_survive_a_restart() {
    // The negative counterpart, pinning WHY configured material is required:
    // with an ephemeral key the same restart loses the token entirely.
    let before_restart = authority();
    assert!(before_restart.uses_ephemeral_key());
    let minted = before_restart
        .mint(&workload_id(), &["aud-a".to_string()], 300)
        .expect("mint succeeds");
    drop(before_restart);

    let after_restart = authority();
    let error = validate_jwt_svid(&minted.token, "aud-a", &bundles_of(&after_restart))
        .expect_err("an ephemeral key cannot validate a pre-restart token");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidToken(_)
        ),
        "expected InvalidToken, got {error:?}"
    );
}

#[tokio::test]
async fn a_configured_previous_key_keeps_pre_rotation_tokens_verifiable() {
    // The rolling-restart rotation contract: mint with key A, then restart with
    // B as primary and A retired. A's token must still validate.
    let key_a = signing_key_pem();
    let key_b = signing_key_pem();
    let old = authority_with_key(&key_a);
    let minted = old
        .mint(&workload_id(), &["aud-a".to_string()], 300)
        .expect("mint succeeds");
    drop(old);

    let rotated = Arc::new(
        LocalJwtAuthority::new(
            LocalJwtAuthorityConfig::new(td())
                .with_signing_key_pem(&key_b)
                .with_retired_key_pems([key_a.clone()]),
        )
        .expect("authority builds with a retired key"),
    );
    let authorities = rotated.authorities();
    assert_eq!(
        authorities.len(),
        2,
        "the new primary and the retired key are both published"
    );
    validate_jwt_svid(&minted.token, "aud-a", &bundles_of(&rotated))
        .expect("a pre-rotation token validates against the retired key");
    // And the new primary mints validly too.
    let fresh = rotated
        .mint(&workload_id(), &["aud-a".to_string()], 300)
        .expect("mint succeeds");
    validate_jwt_svid(&fresh.token, "aud-a", &bundles_of(&rotated))
        .expect("the new primary's token validates");
}

// ── configured material rotates EXTERNALLY, never in process ──────────────

#[tokio::test]
async fn configured_material_refuses_in_process_rotation() {
    // The core continuity contract. An in-process replacement would be a
    // different random key on every replica and would vanish on restart, so the
    // authority refuses rather than silently destroying the trust domain's
    // stable identity.
    let pem = signing_key_pem();
    let signer = authority_with_key(&pem);
    assert!(!signer.allows_in_process_rotation());
    let before = signer.generation();
    let key_id_before = signer.active_key_id();

    let refused = signer
        .rotate()
        .await
        .expect_err("a configured authority must refuse to generate a replacement key");
    assert!(
        matches!(
            refused,
            ferrum_edge::identity::jwt_svid::JwtSvidError::RotationRefused(_)
        ),
        "expected RotationRefused, got {refused:?}"
    );
    assert_eq!(
        signer.generation(),
        before,
        "a refused rotation must not advance the generation"
    );
    assert_eq!(
        signer.active_key_id(),
        key_id_before,
        "the configured key must still be the active signing key"
    );
}

#[tokio::test]
async fn a_configured_cadence_is_normalized_away_rather_than_scheduled() {
    // A caller that sets a lifetime on configured material gets NO scheduled
    // rotation: `rotate_if_due` is a permanent no-op. (The env-config layer
    // additionally refuses the setting outright, so an operator is told rather
    // than silently overridden — see the mesh config tests.)
    let mut config = config_with_key(&signing_key_pem());
    config.key_lifetime_secs = 300;
    let signer = Arc::new(LocalJwtAuthority::new(config).expect("authority builds"));
    let before = signer.generation();

    assert_eq!(
        signer.rotate_if_due().await.expect("no-op succeeds"),
        None,
        "configured material must never rotate on a schedule"
    );
    assert_eq!(signer.generation(), before);
}

#[tokio::test]
async fn two_replicas_of_one_configuration_agree_after_a_rotation_attempt() {
    // The HA proof: two replicas handed the same primary + previous key publish
    // a byte-identical JWKS, and a rotation attempt on one of them cannot make
    // them diverge — because it is refused rather than applied.
    let primary = signing_key_pem();
    let previous = signing_key_pem();
    let build = || {
        Arc::new(
            LocalJwtAuthority::new(
                LocalJwtAuthorityConfig::new(td())
                    .with_signing_key_pem(&primary)
                    .with_retired_key_pems([previous.clone()]),
            )
            .expect("authority builds"),
        )
    };
    let replica_a = build();
    let replica_b = build();

    assert!(
        replica_a.rotate().await.is_err(),
        "in-process rotation must be refused on configured material"
    );

    let left = jwks_document(&replica_a.authorities()).expect("replica A JWKS");
    let right = jwks_document(&replica_b.authorities()).expect("replica B JWKS");
    assert_eq!(
        left, right,
        "two replicas of one configuration must publish a byte-identical JWKS even after one of \
         them was asked to rotate"
    );

    // And each replica validates the other's tokens, on BOTH the primary and
    // the retired key.
    let minted = replica_a
        .mint(&workload_id(), &["aud-a".to_string()], 300)
        .expect("mint succeeds");
    validate_jwt_svid(&minted.token, "aud-a", &bundles_of(&replica_b))
        .expect("the peer replica validates the token");
}

#[tokio::test]
async fn a_token_at_the_maximum_lifetime_survives_a_restart() {
    // Restart continuity is asserted at the WORST case the contract covers: a
    // token minted for the full JWT-SVID ceiling must still validate against a
    // fresh authority built from the same material.
    use ferrum_edge::identity::jwt_svid::MAX_JWT_SVID_TTL_SECS;

    let pem = signing_key_pem();
    let before_restart = authority_with_key(&pem);
    let minted = before_restart
        .mint(
            &workload_id(),
            &["aud-a".to_string()],
            MAX_JWT_SVID_TTL_SECS,
        )
        .expect("mint succeeds");
    let lifetime = (minted.expires_at - minted.issued_at).num_seconds();
    assert_eq!(lifetime, MAX_JWT_SVID_TTL_SECS as i64);
    drop(before_restart);

    let after_restart = authority_with_key(&pem);
    validate_jwt_svid(&minted.token, "aud-a", &bundles_of(&after_restart))
        .expect("a maximum-lifetime token minted before the restart still validates after it");
}

#[tokio::test]
async fn a_configured_retired_key_is_published_independently_of_process_uptime() {
    // A configured retired key's publication window belongs to CONFIGURATION,
    // not to this process's clock. Two authorities built at different moments
    // from the same material must therefore publish the same set — otherwise a
    // replica started later would advertise a key its peer had already dropped.
    let primary = signing_key_pem();
    let previous = signing_key_pem();
    let build = || {
        LocalJwtAuthority::new(
            LocalJwtAuthorityConfig::new(td())
                // A one-second ceiling makes the overlap 61s; if the retired key
                // were expiring on a process-relative clock this would be the
                // knob that made two builds disagree.
                .with_signing_key_pem(&primary)
                .with_retired_key_pems([previous.clone()]),
        )
        .expect("authority builds")
    };
    let early = build();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let late = build();
    assert_eq!(early.authorities().len(), 2);
    assert_eq!(
        jwks_document(&early.authorities()).expect("early JWKS"),
        jwks_document(&late.authorities()).expect("late JWKS"),
        "a configured retired key must not expire on a process-relative clock"
    );
}

#[tokio::test]
async fn an_ephemeral_authority_may_still_rotate_in_process() {
    // The negative control for the refusal above: the dev/test posture has no
    // continuity to lose, so it keeps its in-process rotation.
    let signer = authority();
    assert!(signer.allows_in_process_rotation());
    signer
        .rotate()
        .await
        .expect("an ephemeral authority may rotate in process");
}

// ── misconfiguration fails closed ────────────────────────────────────────

#[tokio::test]
async fn absent_signing_material_without_the_dev_opt_in_fails_closed() {
    let error = LocalJwtAuthority::new(LocalJwtAuthorityConfig::new(td()))
        .expect_err("no material and no ephemeral opt-in must fail closed");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidSigningMaterial(_)
        ),
        "expected InvalidSigningMaterial, got {error:?}"
    );
}

#[tokio::test]
async fn a_non_p256_signing_key_is_refused() {
    let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("Ed25519 key generated")
        .serialize_pem();
    let error = LocalJwtAuthority::new(config_with_key(&ed25519))
        .expect_err("a non-P-256 key must be refused rather than mislabelled ES256");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidSigningMaterial(_)
        ),
        "expected InvalidSigningMaterial, got {error:?}"
    );
}

#[tokio::test]
async fn garbage_signing_material_is_refused_without_echoing_it() {
    let secret_looking = "-----BEGIN PRIVATE KEY-----\nSUPERSECRETVALUE\n-----END PRIVATE KEY-----";
    let error = LocalJwtAuthority::new(config_with_key(secret_looking))
        .expect_err("unparseable material must be refused");
    let rendered = error.to_string();
    assert!(
        !rendered.contains("SUPERSECRETVALUE"),
        "a signing-material error must not echo the material: {rendered}"
    );
}

#[tokio::test]
async fn the_same_key_as_both_primary_and_retired_is_refused() {
    let pem = signing_key_pem();
    let error = LocalJwtAuthority::new(
        LocalJwtAuthorityConfig::new(td())
            .with_signing_key_pem(&pem)
            .with_retired_key_pems([pem.clone()]),
    )
    .expect_err("a duplicate kid across primary and retired must be refused");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidSigningMaterial(_)
        ),
        "expected InvalidSigningMaterial, got {error:?}"
    );
}

#[tokio::test]
async fn the_authority_debug_rendering_never_carries_key_material() {
    let pem = signing_key_pem();
    let signer = authority_with_key(&pem);
    let rendered = format!("{signer:?}");
    assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
    let config = config_with_key(&pem);
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
    assert!(
        rendered.contains("signing_key_pem: true"),
        "the config Debug should report presence, not content: {rendered}"
    );
}

// ── authority bounds are enforced before publication AND validation ───────

/// Build `n` distinct, individually valid authorities for one trust domain.
fn distinct_authorities(n: usize) -> Vec<PublishedJwtAuthority> {
    (0..n)
        .map(|_| {
            let key = forge_key();
            PublishedJwtAuthority {
                trust_domain: td(),
                key_id: ferrum_edge::identity::jwt_svid::published_authority_key_id(
                    &key.public_key_pem,
                )
                .expect("key id derives"),
                public_key_pem: key.public_key_pem,
                declared_alg: None,
            }
        })
        .collect()
}

#[test]
fn validate_rejects_an_over_cap_authority_set_the_bundle_rpc_would_also_reject() {
    // 17 > MAX_JWT_AUTHORITIES_PER_TRUST_DOMAIN (16). The point is that BOTH
    // surfaces refuse it: previously `ValidateJWTSVID` scanned the set without a
    // cap while `FetchJWTBundles` refused it.
    let over_cap = distinct_authorities(17);
    let publication =
        jwks_document(&over_cap).expect_err("publication must refuse an over-cap authority set");
    assert!(
        matches!(
            publication,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
        ),
        "expected InvalidAuthority, got {publication:?}"
    );

    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud-a".to_string()], 60)
        .expect("mint succeeds");
    let mut bundles = BTreeMap::new();
    bundles.insert(td(), over_cap);
    let validation = validate_jwt_svid(&minted.token, "aud-a", &bundles)
        .expect_err("validation must refuse the same over-cap set");
    assert!(
        matches!(
            validation,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
        ),
        "expected InvalidAuthority, got {validation:?}"
    );
}

#[test]
fn validate_rejects_a_duplicate_key_id_in_the_bundle() {
    let mut authorities = distinct_authorities(2);
    let duplicated = authorities[0].key_id.clone();
    authorities[1].key_id = duplicated;

    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud-a".to_string()], 60)
        .expect("mint succeeds");
    let mut bundles = BTreeMap::new();
    bundles.insert(td(), authorities.clone());
    let error = validate_jwt_svid(&minted.token, "aud-a", &bundles)
        .expect_err("an ambiguous kid must not resolve to whichever entry came first");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
        ),
        "expected InvalidAuthority, got {error:?}"
    );
    jwks_document(&authorities).expect_err("publication refuses it too");
}

#[test]
fn validate_rejects_an_authority_stamped_with_another_trust_domain() {
    let mut authorities = distinct_authorities(1);
    authorities[0].trust_domain = TrustDomain::new("other.test").expect("valid");

    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud-a".to_string()], 60)
        .expect("mint succeeds");
    let mut bundles = BTreeMap::new();
    bundles.insert(td(), authorities);
    let error = validate_jwt_svid(&minted.token, "aud-a", &bundles)
        .expect_err("a bundle must not carry another trust domain's key");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
        ),
        "expected InvalidAuthority, got {error:?}"
    );
}

#[test]
fn validate_rejects_malformed_authority_material_in_any_bundle() {
    // A malformed FEDERATED bundle fails the call closed rather than validating
    // against the good local one: an operator who configured that federation
    // must see it fail, not silently lose it.
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud-a".to_string()], 60)
        .expect("mint succeeds");
    let mut bundles = bundles_of(&signer);
    bundles.insert(
        TrustDomain::new("federated.test").expect("valid"),
        vec![PublishedJwtAuthority {
            trust_domain: TrustDomain::new("federated.test").expect("valid"),
            key_id: "kid-federated".to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----"
                .to_string(),
            declared_alg: None,
        }],
    );
    let error = validate_jwt_svid(&minted.token, "aud-a", &bundles)
        .expect_err("malformed federated material must fail the call closed");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
        ),
        "expected InvalidAuthority, got {error:?}"
    );
}

// ── JWKS → authority conversion (SPIRE / federated bundle consumption) ────

#[test]
fn jwks_round_trips_through_authority_conversion() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    let pem = signing_key_pem();
    let signer = authority_with_key(&pem);
    let published = signer.authorities();
    let document = jwks_document(&published).expect("JWKS builds");

    let recovered = authorities_from_jwks(&td(), &document).expect("JWKS parses back");
    assert_eq!(recovered.len(), published.len());
    assert_eq!(recovered[0].key_id, published[0].key_id);
    assert_eq!(recovered[0].trust_domain, td());
    // The recovered SPKI must be usable for verification, which is the whole
    // point of consuming an external bundle.
    let minted = signer
        .mint(&workload_id(), &["aud-a".to_string()], 60)
        .expect("mint succeeds");
    let mut bundles = BTreeMap::new();
    bundles.insert(td(), recovered);
    validate_jwt_svid(&minted.token, "aud-a", &bundles)
        .expect("a token validates against authorities recovered from JWKS");
}

#[test]
fn jwks_conversion_rejects_hostile_and_malformed_documents() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    for (label, document) in [
        ("empty", "".to_string()),
        ("not an object", "[]".to_string()),
        ("no keys array", "{\"foo\":1}".to_string()),
        ("empty keys", "{\"keys\":[]}".to_string()),
        (
            "key without kid",
            "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}]}".to_string(),
        ),
        (
            "unsupported kty",
            "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k\",\"k\":\"AA\"}]}".to_string(),
        ),
        (
            "unsupported curve",
            "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"crv\":\"P-521\",\"x\":\"AA\",\"y\":\"AA\"}]}"
                .to_string(),
        ),
        (
            "encryption-only use",
            "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"crv\":\"P-256\",\"use\":\"enc\",\
             \"x\":\"AA\",\"y\":\"AA\"}]}"
                .to_string(),
        ),
        (
            "duplicate JSON key",
            "{\"keys\":[],\"keys\":[]}".to_string(),
        ),
    ] {
        assert!(
            authorities_from_jwks(&td(), document.as_bytes()).is_err(),
            "{label} JWKS must be refused"
        );
    }
}

#[test]
fn jwks_conversion_refuses_an_over_cap_key_list_without_scanning_it() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    // 17 syntactically-shaped entries. The cap is checked before per-key work,
    // so this is refused rather than parsed.
    let entries: Vec<String> = (0..17)
        .map(|i| {
            format!(
                "{{\"kty\":\"EC\",\"kid\":\"k{i}\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}}"
            )
        })
        .collect();
    let document = format!("{{\"keys\":[{}]}}", entries.join(","));
    let error = authorities_from_jwks(&td(), document.as_bytes())
        .expect_err("an over-cap key list must be refused");
    assert!(
        matches!(
            error,
            ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
        ),
        "expected InvalidAuthority, got {error:?}"
    );
}

// ── externally supplied JWK key policy is validated, never skimmed ────────

/// One JWKS document holding a single P-256 key with the given extra members
/// spliced in, so a test can vary exactly one policy member.
fn ec_jwks_with(extra_members: &str) -> String {
    let key = forge_key();
    let recovered = ferrum_edge::identity::jwt_svid::authorities_from_jwks(
        &td(),
        format!("{{\"keys\":[{}]}}", jwk_of(&key.public_key_pem, "k1", "")).as_bytes(),
    );
    assert!(
        recovered.is_ok(),
        "the baseline key must be acceptable, otherwise the negative cases prove nothing"
    );
    format!(
        "{{\"keys\":[{}]}}",
        jwk_of(&key.public_key_pem, "k1", extra_members)
    )
}

/// Render a P-256 SPKI PEM as a JWK object with `extra_members` spliced in.
fn jwk_of(public_key_pem: &str, kid: &str, extra_members: &str) -> String {
    // Recover x/y by round-tripping the PEM through the library's own publisher,
    // so the fixture cannot drift from the encoding under test.
    let published = jwks_document(&[PublishedJwtAuthority::new(td(), kid, public_key_pem)])
        .expect("baseline JWKS builds");
    let parsed: serde_json::Value = serde_json::from_slice(&published).expect("JWKS is JSON");
    let jwk = parsed["keys"][0].as_object().expect("key object").clone();
    let base = format!(
        "\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":{},\"y\":{},\"kid\":{}",
        jwk["x"], jwk["y"], jwk["kid"]
    );
    if extra_members.is_empty() {
        format!("{{{base}}}")
    } else {
        format!("{{{base},{extra_members}}}")
    }
}

#[test]
fn jwks_conversion_rejects_malformed_or_contradictory_key_policy_members() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    for (label, extra) in [
        // A present-but-non-string `use` must be a rejection, not an ignored
        // member: skipping it is a trivial bypass of the signature-use gate.
        ("non-string use", "\"use\":1"),
        ("null use", "\"use\":null"),
        ("object use", "\"use\":{\"v\":\"sig\"}"),
        ("encryption use", "\"use\":\"enc\""),
        // Same for `key_ops`: a bare string is not an array.
        ("string key_ops", "\"key_ops\":\"verify\""),
        ("non-array key_ops", "\"key_ops\":1"),
        ("non-string key_ops entry", "\"key_ops\":[\"verify\",1]"),
        ("key_ops without verify", "\"key_ops\":[\"sign\"]"),
        ("empty key_ops", "\"key_ops\":[]"),
        // RFC 7517 §4.3: `use` and `key_ops` must not contradict each other.
        (
            "sig use with an encryption operation",
            "\"use\":\"sig\",\"key_ops\":[\"verify\",\"encrypt\"]",
        ),
        (
            "sig use with a derivation operation",
            "\"use\":\"sig\",\"key_ops\":[\"verify\",\"deriveKey\"]",
        ),
        // A declared algorithm must be a supported string the key type can
        // actually produce.
        ("non-string alg", "\"alg\":256"),
        ("unknown alg", "\"alg\":\"ES256K\""),
        ("symmetric alg", "\"alg\":\"HS256\""),
        ("alg the curve cannot produce", "\"alg\":\"ES384\""),
    ] {
        let document = ec_jwks_with(extra);
        let error = authorities_from_jwks(&td(), document.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("{label}: a hostile key policy must be refused"));
        assert!(
            matches!(
                error,
                ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
            ),
            "{label}: expected InvalidAuthority, got {error:?}"
        );
    }
}

#[test]
fn jwks_conversion_accepts_consistent_key_policy_members() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    for (label, extra) in [
        ("no policy members", ""),
        ("sig use", "\"use\":\"sig\""),
        ("verify key_ops", "\"key_ops\":[\"verify\"]"),
        (
            "consistent use and key_ops",
            "\"use\":\"sig\",\"key_ops\":[\"verify\",\"sign\"]",
        ),
        ("matching alg", "\"alg\":\"ES256\""),
    ] {
        let document = ec_jwks_with(extra);
        authorities_from_jwks(&td(), document.as_bytes())
            .unwrap_or_else(|e| panic!("{label}: a consistent key policy must be accepted: {e}"));
    }
}

#[test]
fn a_declared_algorithm_narrows_validation_and_is_never_widened() {
    use ferrum_edge::identity::jwt_svid::{authorities_from_jwks, decoding_key_for_authority};
    use jsonwebtoken::Algorithm;

    // A 2048-bit RSA key is compatible with the whole RS*/PS* family, which is
    // exactly why an undeclared one must NOT be verified against all six.
    let rsa_pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("RSA key generated")
        .public_key_pem();

    // Undeclared: the conservative RFC 7518 §3.1 default, RS256 alone.
    let undeclared = PublishedJwtAuthority::new(td(), "rsa-1", rsa_pem.clone());
    let (_, algs) = decoding_key_for_authority(&undeclared).expect("RSA authority is usable");
    assert_eq!(
        algs,
        vec![Algorithm::RS256],
        "an undeclared RSA authority must not be verifiable under the whole RSASSA family"
    );

    // Declared: exactly the declared algorithm, and nothing else in the family.
    let declared = PublishedJwtAuthority {
        declared_alg: Some(Algorithm::RS512),
        ..PublishedJwtAuthority::new(td(), "rsa-1", rsa_pem.clone())
    };
    let (_, algs) = decoding_key_for_authority(&declared).expect("RSA authority is usable");
    assert_eq!(algs, vec![Algorithm::RS512]);

    // A declaration the key type cannot produce is an error, never a widening.
    let impossible = PublishedJwtAuthority {
        declared_alg: Some(Algorithm::ES256),
        ..PublishedJwtAuthority::new(td(), "rsa-1", rsa_pem.clone())
    };
    let error = decoding_key_for_authority(&impossible)
        .expect_err("an ES256 declaration on an RSA key must be refused");
    assert!(matches!(
        error,
        ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
    ));
    jwks_document(&[impossible]).expect_err("publication refuses it too");

    // The declaration survives a JWKS round trip rather than being widened back
    // to the key type's preferred algorithm.
    let published = jwks_document(&[declared]).expect("JWKS builds");
    let parsed: serde_json::Value = serde_json::from_slice(&published).expect("JWKS is JSON");
    assert_eq!(parsed["keys"][0]["alg"], "RS512");
    let recovered = authorities_from_jwks(&td(), &published).expect("JWKS parses back");
    assert_eq!(recovered[0].declared_alg, Some(Algorithm::RS512));
}

#[test]
fn an_authority_pem_must_contain_only_its_one_public_key_envelope() {
    let key = forge_key();
    let base = key.public_key_pem.trim();

    // Surrounding whitespace is fine — it is not data.
    jwks_document(&[PublishedJwtAuthority::new(
        td(),
        "k1",
        format!("\n\n  {base}  \n\n"),
    )])
    .expect("surrounding whitespace must be accepted");

    for (label, pem) in [
        ("leading data", format!("attacker-note\n{base}")),
        ("trailing data", format!("{base}\nattacker-note")),
        (
            "trailing certificate envelope",
            format!("{base}\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
        ),
        (
            "leading private-key envelope",
            format!("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n{base}"),
        ),
    ] {
        let error = jwks_document(&[PublishedJwtAuthority::new(td(), "k1", pem)])
            .err()
            .unwrap_or_else(|| panic!("{label}: extra PEM data must be refused"));
        assert!(
            matches!(
                error,
                ferrum_edge::identity::jwt_svid::JwtSvidError::InvalidAuthority(_)
            ),
            "{label}: expected InvalidAuthority, got {error:?}"
        );
    }
}

// ── Workload API socket contract ─────────────────────────────────────────

#[test]
fn workload_api_socket_config_rejects_unsafe_paths_and_modes() {
    use ferrum_edge::identity::workload_api::WorkloadApiSocketConfig;

    // Relative and traversing paths never resolve somewhere unnamed.
    assert!(
        WorkloadApiSocketConfig::from_parts("relative/socket", "0660")
            .expect("mode parses")
            .validate()
            .is_err(),
        "a relative socket path must be refused"
    );
    assert!(
        WorkloadApiSocketConfig::from_parts("/run/ferrum/../etc/socket", "0660")
            .expect("mode parses")
            .validate()
            .is_err(),
        "a traversing socket path must be refused"
    );
    // A parent directory Ferrum would have to create is refused, not created.
    assert!(
        WorkloadApiSocketConfig::from_parts(
            "/nonexistent-ferrum-workload-api-parent/socket",
            "0660"
        )
        .expect("mode parses")
        .validate()
        .is_err(),
        "a missing parent directory must be refused"
    );
    // World-writable and non-octal modes are configuration errors, never
    // silently replaced by a default.
    assert!(
        WorkloadApiSocketConfig::from_parts("/tmp/ferrum-wl-api.sock", "0666").is_err(),
        "a world-writable socket mode must be refused"
    );
    assert!(
        WorkloadApiSocketConfig::from_parts("/tmp/ferrum-wl-api.sock", "not-octal").is_err(),
        "a non-octal socket mode must be refused"
    );
    assert!(
        WorkloadApiSocketConfig::from_parts("/tmp/ferrum-wl-api.sock", "0660").is_ok(),
        "a well-formed path and mode must be accepted"
    );
}

// ── cryptographic admission of authority public keys ─────────────────────
//
// Shape is neither strength nor curve membership. These pin that a malformed or
// weak authority is refused BEFORE it can be republished in `FetchJWTBundles`
// or turned into a verification key.

/// A valid 2048-bit RSA key's JWK members, recovered through the library's own
/// publisher so the fixture cannot drift from the encoding under test.
fn rsa_jwk_members() -> (Vec<u8>, Vec<u8>) {
    let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("RSA key generated")
        .public_key_pem();
    let published = jwks_document(&[PublishedJwtAuthority::new(td(), "rsa-1", pem.as_str())])
        .expect("a 2048-bit RSA authority publishes");
    let parsed: serde_json::Value = serde_json::from_slice(&published).expect("JWKS is JSON");
    let decode = |member: &str| {
        URL_SAFE_NO_PAD
            .decode(
                parsed["keys"][0][member]
                    .as_str()
                    .expect("member is a string"),
            )
            .expect("member is base64url")
    };
    (decode("n"), decode("e"))
}

fn rsa_jwks(modulus: &[u8], exponent: &[u8]) -> String {
    format!(
        "{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"rsa-1\",\"n\":\"{}\",\"e\":\"{}\"}}]}}",
        URL_SAFE_NO_PAD.encode(modulus),
        URL_SAFE_NO_PAD.encode(exponent)
    )
}

fn spki_pem_from_der(der: &[u8]) -> String {
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    let encoded = STANDARD.encode(der);
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

fn spki_der_from_pem(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .expect("PEM body is base64")
}

#[test]
fn rsa_admission_is_by_significant_bit_length_not_byte_count() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    let (modulus, exponent) = rsa_jwk_members();
    assert_eq!(modulus.len(), 256, "the baseline is a 2048-bit modulus");
    authorities_from_jwks(&td(), rsa_jwks(&modulus, &exponent).as_bytes())
        .expect("a 2048-bit RSA key with exponent 65537 is admitted");

    // 256 BYTES but only 2041 significant BITS. A byte-count floor waves this
    // through; a bit-length floor does not.
    let mut weak = vec![0x01u8];
    weak.extend(std::iter::repeat_n(0xffu8, 255));
    assert_eq!(weak.len(), 256);
    authorities_from_jwks(&td(), rsa_jwks(&weak, &exponent).as_bytes())
        .expect_err("a 2041-bit modulus padded into 256 bytes must be refused");

    // Leading zero octets are not canonical (RFC 7518 §6.3.1) and never count
    // toward strength; DER re-encoding would have silently normalized them.
    let mut padded = vec![0x00u8];
    padded.extend_from_slice(&modulus);
    authorities_from_jwks(&td(), rsa_jwks(&padded, &exponent).as_bytes())
        .expect_err("a leading zero octet in 'n' must be refused, not normalized away");
    let mut padded_exponent = vec![0x00u8];
    padded_exponent.extend_from_slice(&exponent);
    authorities_from_jwks(&td(), rsa_jwks(&modulus, &padded_exponent).as_bytes())
        .expect_err("a leading zero octet in 'e' must be refused");

    // Above the documented RSA-8192 ceiling.
    let oversized = vec![0xffu8; 1025];
    authorities_from_jwks(&td(), rsa_jwks(&oversized, &exponent).as_bytes())
        .expect_err("a modulus beyond the 8192-bit ceiling must be refused");
}

#[test]
fn an_even_rsa_modulus_is_refused_on_both_the_jwk_and_the_spki_path() {
    use ferrum_edge::identity::jwt_svid::{authorities_from_jwks, decoding_key_for_authority};

    // An RSA modulus is a product of odd primes, so it is odd. Size and
    // canonical encoding say nothing about that: the value below is a genuine
    // 2048-bit modulus with a single bit cleared, so it passes every bit-length
    // and canonical-form check and is still not an RSA modulus.
    let (modulus, exponent) = rsa_jwk_members();
    assert_eq!(exponent, vec![0x01, 0x00, 0x01], "the fixture uses 65537");
    let mut even = modulus.clone();
    let last = even.len() - 1;
    assert_eq!(even[last] % 2, 1, "a real modulus is odd to begin with");
    even[last] &= 0xfe;
    assert_eq!(even.len(), 256, "clearing a bit does not change the size");
    assert_ne!(even[0], 0x00, "the value stays canonical big-endian");

    let error = authorities_from_jwks(&td(), rsa_jwks(&even, &exponent).as_bytes())
        .expect_err("an even modulus must not be admitted from a JWKS");
    assert!(
        error.to_string().contains("even"),
        "an even modulus must be refused for its parity, not incidentally: {error}"
    );
    // The baseline differs from it by exactly that one bit, so the refusal above
    // is about the parity rather than about the fixture.
    authorities_from_jwks(&td(), rsa_jwks(&modulus, &exponent).as_bytes())
        .expect("the untouched 2048-bit modulus is admitted");

    // The SPKI path reaches the same admission gate, so an authority whose PEM
    // carries an even modulus never becomes a verification key either. The
    // RSAPublicKey tail is `INTEGER 65537`, so the modulus's least significant
    // byte sits five bytes before it.
    let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("RSA key generated")
        .public_key_pem();
    decoding_key_for_authority(&PublishedJwtAuthority::new(td(), "rsa-1", pem.as_str()))
        .expect("the untampered RSA authority is usable");
    let mut der = spki_der_from_pem(&pem);
    let tail = der.len() - 5;
    assert_eq!(
        &der[tail..],
        [0x02u8, 0x03, 0x01, 0x00, 0x01].as_slice(),
        "the fixture's DER ends in INTEGER 65537"
    );
    der[tail - 1] &= 0xfe;
    let tampered = spki_pem_from_der(&der);
    let error = decoding_key_for_authority(&PublishedJwtAuthority::new(
        td(),
        "rsa-1",
        tampered.as_str(),
    ))
    .expect_err("an even modulus must not become a verification key");
    assert!(
        error.to_string().contains("even"),
        "the SPKI path must refuse the same way the JWK path does: {error}"
    );
}

#[test]
fn rsa_public_exponents_must_be_odd_and_at_least_three() {
    use ferrum_edge::identity::jwt_svid::authorities_from_jwks;

    let (modulus, _) = rsa_jwk_members();
    for (label, exponent) in [
        ("zero", vec![0x00u8]),
        ("one", vec![0x01u8]),
        ("two", vec![0x02u8]),
        ("even", vec![0x01, 0x00, 0x02]),
        (
            "large even",
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
    ] {
        authorities_from_jwks(&td(), rsa_jwks(&modulus, &exponent).as_bytes())
            .err()
            .unwrap_or_else(|| panic!("{label}: an unusable RSA exponent must be refused"));
    }
    // 65537, the one real-world value.
    authorities_from_jwks(&td(), rsa_jwks(&modulus, &[0x01, 0x00, 0x01]).as_bytes())
        .expect("exponent 65537 is admitted");
    // 3 is the RFC 8017 floor and is admitted rather than special-cased away.
    authorities_from_jwks(&td(), rsa_jwks(&modulus, &[0x03]).as_bytes())
        .expect("exponent 3 is admitted");
}

#[test]
fn an_off_curve_ec_point_is_refused_on_both_the_jwk_and_the_spki_path() {
    use ferrum_edge::identity::jwt_svid::{authorities_from_jwks, decoding_key_for_authority};

    let key = forge_key();
    // Baseline: the untampered key is admitted, so the negative cases below
    // prove something about the point rather than about the fixture.
    decoding_key_for_authority(&PublishedJwtAuthority::new(
        td(),
        "k1",
        key.public_key_pem.as_str(),
    ))
    .expect("a genuine P-256 authority is usable");

    // SPKI path: flip the last byte of the uncompressed point. The OID, the
    // 0x04 marker, and both coordinate lengths are all still correct — only
    // curve membership is not.
    let mut der = spki_der_from_pem(&key.public_key_pem);
    let last = der.len() - 1;
    der[last] ^= 0x01;
    let tampered_pem = spki_pem_from_der(&der);
    let error = decoding_key_for_authority(&PublishedJwtAuthority::new(
        td(),
        "k1",
        tampered_pem.as_str(),
    ))
    .expect_err("an off-curve point must not become a verification key");
    let message = error.to_string();
    assert!(
        !message.contains(&STANDARD.encode(&der)[..16]),
        "an authority rejection must never echo key bytes: {message}"
    );

    // JWK path: the same tampering expressed as a `y` coordinate, so a hostile
    // federated bundle cannot republish an off-curve authority either.
    let published = jwks_document(&[PublishedJwtAuthority::new(
        td(),
        "k1",
        key.public_key_pem.as_str(),
    )])
    .expect("baseline JWKS builds");
    let parsed: serde_json::Value = serde_json::from_slice(&published).expect("JWKS is JSON");
    let mut y = URL_SAFE_NO_PAD
        .decode(parsed["keys"][0]["y"].as_str().expect("y is a string"))
        .expect("y is base64url");
    let last = y.len() - 1;
    y[last] ^= 0x01;
    let document = format!(
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"x\":{},\"y\":\"{}\"}}]}}",
        parsed["keys"][0]["x"],
        URL_SAFE_NO_PAD.encode(&y)
    );
    authorities_from_jwks(&td(), document.as_bytes())
        .expect_err("an off-curve JWK point must be refused before publication");
}

#[test]
fn p256_and_p384_authorities_round_trip_through_publication_and_validation() {
    use ferrum_edge::identity::jwt_svid::{authorities_from_jwks, decoding_key_for_authority};
    use jsonwebtoken::Algorithm;

    for (label, params, expected_alg, expected_curve) in [
        (
            "P-256",
            &rcgen::PKCS_ECDSA_P256_SHA256,
            Algorithm::ES256,
            "P-256",
        ),
        (
            "P-384",
            &rcgen::PKCS_ECDSA_P384_SHA384,
            Algorithm::ES384,
            "P-384",
        ),
    ] {
        let pem = rcgen::KeyPair::generate_for(params)
            .unwrap_or_else(|e| panic!("{label} key generated: {e}"))
            .public_key_pem();
        let authority = PublishedJwtAuthority::new(td(), "ec-1", pem.as_str());
        let (_, algs) = decoding_key_for_authority(&authority)
            .unwrap_or_else(|e| panic!("{label}: a genuine authority must be usable: {e}"));
        assert_eq!(
            algs,
            vec![expected_alg],
            "{label}: the curve pins exactly one algorithm"
        );

        let published = jwks_document(&[authority]).expect("JWKS builds");
        let parsed: serde_json::Value = serde_json::from_slice(&published).expect("JWKS is JSON");
        assert_eq!(parsed["keys"][0]["crv"], expected_curve, "{label}");
        let recovered = authorities_from_jwks(&td(), &published)
            .unwrap_or_else(|e| panic!("{label}: the published JWKS parses back: {e}"));
        assert_eq!(recovered.len(), 1, "{label}");
    }
}

// ── retired keys are verification-only, structurally ─────────────────────

#[test]
fn a_configured_retired_key_retains_no_signing_capability() {
    // The docs promise "published for verification only". That has to be true of
    // the retained representation itself, not merely of how it is currently
    // used: a retired entry holding an `EncodingKey` would leave every rotated-
    // off private key loaded and usable for the process's whole lifetime.
    let primary = signing_key_pem();
    let previous = signing_key_pem();
    let authority = LocalJwtAuthority::new(
        LocalJwtAuthorityConfig::new(td())
            .with_signing_key_pem(&primary)
            .with_retired_key_pems([previous.clone()]),
    )
    .expect("an authority with configured retired material builds");

    let retained = authority.retained_public_material();
    assert_eq!(retained.len(), 1, "the configured previous key is retained");
    let (retained_kid, retained_pem) = &retained[0];
    assert!(!retained_kid.is_empty(), "a retained key keeps its kid");
    assert!(
        retained_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "retained material must be an SPKI PUBLIC KEY document, got: {retained_pem}"
    );
    assert!(
        !retained_pem.contains("PRIVATE"),
        "retained material must carry no private envelope"
    );
    assert!(
        jsonwebtoken::EncodingKey::from_ec_pem(retained_pem.as_bytes()).is_err(),
        "retained material must not be constructible into a signing key"
    );

    // It is still PUBLISHED, so the rotation overlap the docs promise is intact.
    let published = authority.authorities();
    assert!(
        published.iter().any(|a| &a.key_id == retained_kid),
        "a retired key must still be published for verification"
    );
    // ...and it never signs: every minted token carries the ACTIVE kid.
    let minted = authority
        .mint(&workload_id(), &["spiffe://aud.test/x".to_string()], 0)
        .expect("the active key mints");
    assert_eq!(minted.key_id, authority.active_key_id());
    assert_ne!(&minted.key_id, retained_kid);
}

#[tokio::test]
async fn an_ephemeral_rotation_retires_only_public_material() {
    let authority = authority();
    let retired_kid = authority.active_key_id();
    authority.rotate().await.expect("an ephemeral key rotates");

    let retained = authority.retained_public_material();
    assert_eq!(retained.len(), 1, "the outgoing key is retained");
    assert_eq!(
        retained[0].0, retired_kid,
        "the outgoing key id is retained"
    );
    assert!(
        retained[0].1.starts_with("-----BEGIN PUBLIC KEY-----")
            && !retained[0].1.contains("PRIVATE"),
        "an in-process rotation must copy only public metadata"
    );
    assert!(
        jsonwebtoken::EncodingKey::from_ec_pem(retained[0].1.as_bytes()).is_err(),
        "the rotated-off key must not remain constructible into a signer"
    );
    assert_ne!(
        authority.active_key_id(),
        retired_kid,
        "rotation installed a new active key"
    );
}

// ── federated trust domains are bounded at configuration ─────────────────

mod federated_bounds {
    use super::*;
    use ferrum_edge::identity::jwt_svid::MAX_JWT_BUNDLE_TRUST_DOMAINS;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{JwtBundlesRequest, X509BundlesRequest};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts every per-trust-domain CA call so a test can assert the fan-out
    /// one RPC produces, which is the actual resource the cap protects.
    struct CountingCa {
        trust_domain: TrustDomain,
        jwt: Arc<LocalJwtAuthority>,
        jwt_calls: AtomicUsize,
        bundle_calls: AtomicUsize,
    }

    #[async_trait]
    impl CertificateAuthority for CountingCa {
        async fn issue_svid(&self, _req: IssuanceRequest) -> Result<SignedSvid, CaError> {
            Err(CaError::UnknownTrustDomain("not used".to_string()))
        }

        async fn trust_bundle(
            &self,
            domain: &TrustDomain,
        ) -> Result<PublishedTrustBundle, CaError> {
            self.bundle_calls.fetch_add(1, Ordering::SeqCst);
            if domain != &self.trust_domain {
                // Every federated alias is an "absent peer", which is precisely
                // the shape that never advanced an output-counted cap.
                return Err(CaError::UnknownTrustDomain(domain.to_string()));
            }
            Ok(PublishedTrustBundle {
                trust_domain: self.trust_domain.clone(),
                roots_der: vec![b"stub-root".to_vec()],
                refresh_hint_secs: None,
            })
        }

        async fn jwt_authorities(
            &self,
            domain: &TrustDomain,
        ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
            self.jwt_calls.fetch_add(1, Ordering::SeqCst);
            if domain != &self.trust_domain {
                // Published-but-empty: the exact case an insertion-counted cap
                // never noticed.
                return Ok(Vec::new());
            }
            Ok(self.jwt.authorities())
        }
    }

    fn counting_ca() -> Arc<CountingCa> {
        Arc::new(CountingCa {
            trust_domain: td(),
            jwt: authority(),
            jwt_calls: AtomicUsize::new(0),
            bundle_calls: AtomicUsize::new(0),
        })
    }

    fn service_with(
        ca: Arc<CountingCa>,
        federated: Vec<TrustDomain>,
    ) -> Result<WorkloadApiService, ferrum_edge::identity::jwt_svid::JwtSvidError> {
        let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
        WorkloadApiService::new(
            vec![attestor],
            ca as Arc<dyn CertificateAuthority>,
            td(),
            600,
        )
        .with_federated_trust_domains(federated)
    }

    fn partner(index: usize) -> TrustDomain {
        TrustDomain::new(format!("partner{index}.test")).expect("trust domain is valid")
    }

    #[tokio::test]
    async fn duplicate_and_local_aliases_collapse_to_one_ca_call_each() {
        let ca = counting_ca();
        // Twenty entries, one distinct partner, plus the local domain repeated.
        let mut configured = vec![td(); 5];
        configured.extend(std::iter::repeat_n(partner(0), 15));
        let svc = service_with(Arc::clone(&ca), configured).expect("within the cap");

        svc.fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
            .await
            .expect("the local bundle is published");
        assert_eq!(
            ca.jwt_calls.load(Ordering::SeqCst),
            2,
            "one local call plus exactly one federated call, not one per alias"
        );

        svc.fetch_x509_bundles(workload_request(X509BundlesRequest {}))
            .await
            .err()
            .expect("the absent federated peer fails the X.509 bundle call");
        assert_eq!(
            ca.bundle_calls.load(Ordering::SeqCst),
            2,
            "the X.509 surface is deduplicated too"
        );
    }

    #[test]
    fn an_over_cap_federated_list_is_refused_rather_than_silently_truncated() {
        // Reporting a trust posture the operator did not configure is worse than
        // refusing one they did: an over-cap list is a constructor error.
        let over_cap: Vec<TrustDomain> = (0..MAX_JWT_BUNDLE_TRUST_DOMAINS).map(partner).collect();
        assert!(
            service_with(counting_ca(), over_cap).is_err(),
            "more federated domains than one bundle response may carry must be refused"
        );

        // One below the cap (the local domain always occupies a slot) is fine.
        let at_cap: Vec<TrustDomain> = (0..MAX_JWT_BUNDLE_TRUST_DOMAINS - 1).map(partner).collect();
        assert!(
            service_with(counting_ca(), at_cap).is_ok(),
            "the documented maximum must remain configurable"
        );
    }

    #[tokio::test]
    async fn empty_federated_bundles_cannot_drive_unbounded_ca_calls() {
        // Every federated alias publishes NOTHING, so an insertion-counted cap
        // never advanced and every configured alias reached the CA. The bound is
        // now on the inputs, so the fan-out is fixed before any call is issued.
        let ca = counting_ca();
        let federated: Vec<TrustDomain> =
            (0..MAX_JWT_BUNDLE_TRUST_DOMAINS - 1).map(partner).collect();
        let svc = service_with(Arc::clone(&ca), federated).expect("at the cap");

        svc.fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
            .await
            .expect("the local bundle is still published");
        assert_eq!(
            ca.jwt_calls.load(Ordering::SeqCst),
            MAX_JWT_BUNDLE_TRUST_DOMAINS,
            "at most the local domain plus the capped federated set is queried"
        );
    }
}
