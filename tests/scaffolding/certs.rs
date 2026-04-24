//! Deterministic test certificate authority + leaf-cert presets.
//!
//! [`TestCa`] wraps an rcgen self-signed root. The helpers on it
//! (`valid`, `expired`, `not_yet_valid`, `wrong_san`, `self_signed`) return
//! ready-to-use PEM blobs for the common scripted-backend scenarios:
//!
//! | Preset          | SAN        | notBefore | notAfter  | Signed by |
//! |-----------------|------------|-----------|-----------|-----------|
//! | `valid`         | localhost  | now-1d    | now+365d  | `TestCa`  |
//! | `expired`       | localhost  | now-2d    | now-1d    | `TestCa`  |
//! | `not_yet_valid` | localhost  | now+1d    | now+30d   | `TestCa`  |
//! | `wrong_san`     | other.test | now-1d    | now+365d  | `TestCa`  |
//! | `self_signed`   | localhost  | now-1d    | now+365d  | itself    |
//!
//! All presets use rcgen's default ECDSA P-256 + SHA-256 signing — small
//! PEM, fast handshake, supported by rustls/ring.
//!
//! ## Usage
//!
//! ```ignore
//! let ca = TestCa::new("ferrum-test-root")?;
//! let (cert_pem, key_pem) = ca.valid()?;
//! ```

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

/// A self-signed test CA that can issue leaf certificates via the preset
/// helpers. Holds both its PEM (for trust-anchor plumbing) and the key
/// material needed to sign leaves.
pub struct TestCa {
    /// PEM-encoded CA certificate (use as trust anchor).
    pub cert_pem: String,
    /// PEM-encoded CA private key.
    pub key_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    /// Mint a fresh self-signed CA with the given Common Name.
    pub fn new(common_name: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 5);

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        // Build an Issuer that owns the params + key so later `signed_by`
        // calls are self-contained. The lifetime is `'static` because
        // `Issuer::new` takes the params by value and clones them into `Cow::Owned`.
        let issuer = Issuer::new(params, key);

        Ok(Self {
            cert_pem,
            key_pem,
            issuer,
        })
    }

    /// A leaf cert chained to this CA that is valid right now (±1 day/+365 days).
    pub fn valid(&self) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        self.issue_leaf(
            &["localhost"],
            OffsetDateTime::now_utc() - Duration::days(1),
            OffsetDateTime::now_utc() + Duration::days(365),
        )
    }

    /// A leaf cert chained to this CA whose `notAfter` is in the past.
    pub fn expired(&self) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        self.issue_leaf(
            &["localhost"],
            OffsetDateTime::now_utc() - Duration::days(2),
            OffsetDateTime::now_utc() - Duration::days(1),
        )
    }

    /// A leaf cert chained to this CA whose `notBefore` is in the future.
    pub fn not_yet_valid(
        &self,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        self.issue_leaf(
            &["localhost"],
            OffsetDateTime::now_utc() + Duration::days(1),
            OffsetDateTime::now_utc() + Duration::days(30),
        )
    }

    /// A leaf cert with a SAN that does NOT match `localhost`.
    pub fn wrong_san(&self) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        self.issue_leaf(
            &["other.test"],
            OffsetDateTime::now_utc() - Duration::days(1),
            OffsetDateTime::now_utc() + Duration::days(365),
        )
    }

    /// A leaf certificate that is **not** chained to this CA; signed by
    /// itself. The CA receiver is kept only so the API is symmetric with
    /// the other presets — callers use this to exercise "untrusted root".
    pub fn self_signed(
        &self,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    fn issue_leaf(
        &self,
        sans: &[&str],
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            DnType::CommonName,
            sans.first().copied().unwrap_or("localhost"),
        );
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if sans.contains(&"localhost") {
            params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));
        }

        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.issuer)?;
        Ok((leaf.pem(), leaf_key.serialize_pem()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_validity_timestamps(pem: &str) -> (i64, i64) {
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("parse pem");
        let (_, cert) = x509_parser::parse_x509_certificate(&block.contents).expect("parse cert");
        (
            cert.validity().not_before.timestamp(),
            cert.validity().not_after.timestamp(),
        )
    }

    #[test]
    fn valid_preset_is_current() {
        let ca = TestCa::new("ferrum-test-root").expect("ca");
        let (cert_pem, key_pem) = ca.valid().expect("valid leaf");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
        let (nb, na) = cert_validity_timestamps(&cert_pem);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(nb < now && na > now, "valid: nb={nb}, na={na}, now={now}");
    }

    #[test]
    fn expired_preset_is_expired() {
        let ca = TestCa::new("ferrum-test-root").expect("ca");
        let (cert_pem, _) = ca.expired().expect("expired leaf");
        let (_, na) = cert_validity_timestamps(&cert_pem);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(na < now, "expired: na={na}, now={now}");
    }

    #[test]
    fn not_yet_valid_preset_future_nb() {
        let ca = TestCa::new("ferrum-test-root").expect("ca");
        let (cert_pem, _) = ca.not_yet_valid().expect("leaf");
        let (nb, _) = cert_validity_timestamps(&cert_pem);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(nb > now, "not_yet_valid: nb={nb}, now={now}");
    }

    #[test]
    fn wrong_san_does_not_contain_localhost() {
        let ca = TestCa::new("ferrum-test-root").expect("ca");
        let (cert_pem, _) = ca.wrong_san().expect("leaf");
        let (_, block) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("parse pem");
        let (_, cert) = x509_parser::parse_x509_certificate(&block.contents).expect("parse cert");
        let san_ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .expect("san extension");
        let san_str = format!("{san_ext:?}");
        assert!(
            san_str.contains("other.test"),
            "expected other.test in SAN: {san_str}"
        );
        assert!(
            !san_str.contains("localhost"),
            "unexpected localhost in SAN: {san_str}"
        );
    }

    #[test]
    fn self_signed_issuer_eq_subject() {
        let ca = TestCa::new("ferrum-test-root").expect("ca");
        let (cert_pem, _) = ca.self_signed().expect("leaf");
        let (_, block) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("parse pem");
        let (_, cert) = x509_parser::parse_x509_certificate(&block.contents).expect("parse cert");
        assert_eq!(cert.issuer().to_string(), cert.subject().to_string());
    }

    #[test]
    fn chained_leaf_issuer_matches_ca_subject() {
        let ca = TestCa::new("ferrum-test-root").expect("ca");
        let (leaf_pem, _) = ca.valid().expect("leaf");

        let (_, leaf_block) =
            x509_parser::pem::parse_x509_pem(leaf_pem.as_bytes()).expect("parse leaf");
        let (_, leaf) =
            x509_parser::parse_x509_certificate(&leaf_block.contents).expect("parse leaf cert");

        let (_, ca_block) =
            x509_parser::pem::parse_x509_pem(ca.cert_pem.as_bytes()).expect("parse ca pem");
        let (_, ca_cert) =
            x509_parser::parse_x509_certificate(&ca_block.contents).expect("parse ca cert");

        assert_eq!(leaf.issuer().to_string(), ca_cert.subject().to_string());
        assert_ne!(leaf.subject().to_string(), leaf.issuer().to_string());
    }
}
