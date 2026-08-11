//! SPIFFE Trust Domain — the security boundary over which a single CA issues SVIDs.
//!
//! Per the SPIFFE ID specification (RFC: SPIFFE-ID), a trust domain is encoded
//! as the host portion of a `spiffe://` URI. It must be:
//!   - non-empty
//!   - lowercase
//!   - composed of letters, digits, hyphens, dots, and underscores
//!   - free of any path component (i.e. no `/`)
//!
//! The reference identifier defines a system of trust — every SVID issued in
//! the domain is verifiable against that domain's bundle. Unlike DNS, trust
//! domains are not required to be resolvable; they're identifiers, not
//! addresses, so we deliberately allow lab values like `cluster.local`.

use serde::{Deserialize, Serialize, de::Error as _};
use std::fmt;
use std::str::FromStr;

/// A SPIFFE trust domain (the host portion of a SPIFFE ID).
///
/// Example: in `spiffe://prod.example.com/ns/foo/sa/bar`, the trust domain is
/// `prod.example.com`.
/// `Ord` is derived so trust domains can key a `BTreeMap` — JWT bundle
/// responses are assembled that way so the serialized map is byte-stable
/// across rebuilds and can be compared for change detection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustDomain(String);

impl Serialize for TrustDomain {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TrustDomain {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        TrustDomain::new(raw).map_err(D::Error::custom)
    }
}

impl TrustDomain {
    /// Parse and validate a trust domain string.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustDomainError> {
        let raw: String = value.into();
        validate(&raw)?;
        Ok(Self(raw))
    }

    /// View as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Format the trust domain as the URI string `spiffe://<trust-domain>`.
    pub fn as_uri(&self) -> String {
        format!("spiffe://{}", self.0)
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TrustDomain {
    type Err = TrustDomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for TrustDomain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validation errors for trust domains.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustDomainError {
    #[error("trust domain must not be empty")]
    Empty,
    #[error("trust domain '{0}' must be lowercase")]
    NotLowercase(String),
    #[error("trust domain '{0}' contains '/' — trust domains do not have a path component")]
    HasPath(String),
    #[error("trust domain '{0}' is too long (max {1}, got {2})")]
    TooLong(String, usize, usize),
    #[error("trust domain '{0}' contains invalid character '{1}'")]
    InvalidChar(String, char),
    #[error("trust domain '{0}' must not begin or end with '.', '-', or '_'")]
    BadBoundary(String),
}

/// Per the SPIFFE-ID spec, a trust domain MUST be at most 255 octets when
/// expressed in URI form. The `spiffe://` prefix is 9 bytes, leaving 246
/// for the trust-domain itself. We pick a slightly tighter cap (240) so the
/// total URI stays well under any 256-byte boundary even after the path is
/// appended.
pub const MAX_TRUST_DOMAIN_LEN: usize = 240;

fn validate(raw: &str) -> Result<(), TrustDomainError> {
    if raw.is_empty() {
        return Err(TrustDomainError::Empty);
    }
    if raw.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(TrustDomainError::TooLong(
            raw.to_string(),
            MAX_TRUST_DOMAIN_LEN,
            raw.len(),
        ));
    }
    if raw.contains('/') {
        return Err(TrustDomainError::HasPath(raw.to_string()));
    }
    if raw != raw.to_lowercase() {
        return Err(TrustDomainError::NotLowercase(raw.to_string()));
    }
    for ch in raw.chars() {
        if !is_trust_domain_char(ch) {
            return Err(TrustDomainError::InvalidChar(raw.to_string(), ch));
        }
    }
    let first = raw.chars().next().unwrap_or('.');
    let last = raw.chars().next_back().unwrap_or('.');
    if matches!(first, '.' | '-' | '_') || matches!(last, '.' | '-' | '_') {
        return Err(TrustDomainError::BadBoundary(raw.to_string()));
    }
    Ok(())
}

#[inline]
fn is_trust_domain_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
}
