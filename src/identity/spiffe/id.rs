//! SPIFFE ID parsing, validation, and formatting.
//!
//! A SPIFFE ID is a URI of the form `spiffe://<trust-domain>/<path>`. The
//! reference identifier specification ([SPIFFE-ID]) defines the syntax we
//! enforce here:
//!
//! - The scheme MUST be exactly `spiffe` (lowercase).
//! - The authority is the trust domain (see [`TrustDomain`]).
//! - The path is a sequence of `/`-separated non-empty segments. Each segment
//!   may contain ASCII letters, digits, hyphens, periods, and underscores.
//!   Dot-only segments (`.` and `..`) are forbidden.
//! - Query and fragment components are forbidden.
//! - Trailing slashes are forbidden.
//! - Empty paths (i.e. the trust-domain root) are allowed and represent the
//!   trust domain itself; in practice these are unusual and we accept them.
//!
//! Hash equality is byte-exact on the validated string form, so two SPIFFE
//! IDs that differ only in case (which is forbidden) will never compare
//! equal because the parser rejects the malformed one.
//!
//! [SPIFFE-ID]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use super::trust_domain::{TrustDomain, TrustDomainError};

/// Maximum total length of a SPIFFE ID URI. Aligns with the spec's reference
/// identifier limit (2048 bytes) but we cap it tighter so URI SAN encoding
/// stays comfortably below any 4 KiB X.509 extension boundaries.
pub const MAX_SPIFFE_ID_LEN: usize = 2048;

/// A validated SPIFFE ID.
///
/// Use [`SpiffeId::new`] / [`SpiffeId::from_str`] to parse. The internal
/// representation stores the canonical URI string; the trust domain and path
/// are also kept as parsed views to avoid re-parsing on every access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    /// Full URI form (`spiffe://<td>/<path>`), validated.
    uri: String,
    /// Byte offset of the first path character (just past the leading `/`),
    /// or `uri.len()` when the path is empty.
    path_offset: usize,
    /// Cached trust domain.
    trust_domain: TrustDomain,
}

impl std::hash::Hash for SpiffeId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // The validated `uri` string is canonical: `path_offset` and
        // `trust_domain` are derived from it. Hashing only `uri` matches the
        // documented "byte-exact on the validated string form" semantics
        // and ensures that the manual impl never drifts from `PartialEq`,
        // which also keys on `uri` byte-equality.
        self.uri.hash(state);
    }
}

impl SpiffeId {
    /// Parse and validate a SPIFFE ID URI string.
    pub fn new(uri: impl Into<String>) -> Result<Self, SpiffeIdError> {
        let raw: String = uri.into();
        parse(raw)
    }

    /// Build a SPIFFE ID from a trust domain and path. The path may be empty
    /// or may start with `/`; either form is normalised. Path segments are
    /// validated.
    pub fn from_parts(td: &TrustDomain, path: &str) -> Result<Self, SpiffeIdError> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return Self::new(format!("spiffe://{}", td.as_str()));
        }
        Self::new(format!("spiffe://{}/{}", td.as_str(), path))
    }

    /// Full URI string (`spiffe://...`).
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Cached trust-domain view.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Path component starting AFTER the leading `/`. Empty for root SPIFFE IDs.
    pub fn path(&self) -> &str {
        &self.uri[self.path_offset..]
    }

    /// Iterate over path segments (slash-separated, never empty).
    pub fn path_segments(&self) -> impl Iterator<Item = &str> {
        // `split('/')` on an empty string yields a single empty element; the
        // `filter` suppresses it so the iterator is empty for root SPIFFE IDs.
        self.path().split('/').filter(|s| !s.is_empty())
    }

    /// Return `(namespace, service_account)` for the exact Istio workload path
    /// `ns/<namespace>/sa/<service-account>`, with no prefix or trailing segments.
    ///
    /// Marker positions are structural: a namespace or account named `sa` or
    /// `ns` is a value, not another marker. URI validation already rejects empty
    /// segments; Kubernetes-specific name validation remains the caller's job.
    pub fn kubernetes_identity(&self) -> Option<(&str, &str)> {
        let mut segments = self.path_segments();
        match (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) {
            (Some("ns"), Some(namespace), Some("sa"), Some(service_account), None) => {
                Some((namespace, service_account))
            }
            _ => None,
        }
    }

    /// Return the Kubernetes service-account name encoded into this SPIFFE ID.
    ///
    /// Exact Istio workload paths use [`SpiffeId::kubernetes_identity`], so
    /// `ns/sa/sa/backend` resolves to `backend`, not the namespace's `sa` value.
    ///
    /// Other paths retain first-marker extraction: return the segment immediately
    /// following the first `sa` segment. Returns `None` when there is no `sa` or
    /// when `sa` is the trailing segment. Only the first `sa` segment is
    /// considered — a path like `sa/foo/sa/bar` resolves to `Some("foo")`, not
    /// `Some("bar")`, because Istio places `sa/<name>` at a single canonical
    /// position and accepting later `sa/...` patterns would weaken identity
    /// checks built on top of this helper.
    pub fn service_account(&self) -> Option<&str> {
        if let Some((_, service_account)) = self.kubernetes_identity() {
            return Some(service_account);
        }
        let mut segments = self.path_segments();
        while let Some(segment) = segments.next() {
            if segment == "sa" {
                return segments.next();
            }
        }
        None
    }

    /// Return the Kubernetes namespace encoded into this SPIFFE ID per the
    /// Istio convention `<...>/ns/<namespace>/sa/<service-account>`.
    ///
    /// Returns the segment immediately following the first `ns` segment in the
    /// path. Returns `None` when the path does not contain an `ns` segment or
    /// when `ns` is the trailing segment. Only the first `ns` segment is
    /// considered — same canonicality rule as [`SpiffeId::service_account`].
    /// The parser rejects empty path segments, so an `ns/` segment can never
    /// resolve to an empty namespace here.
    ///
    /// This is the canonical helper for "source workload namespace" lookups
    /// (e.g. VirtualService `match[].sourceNamespace` predicates). Callers
    /// holding a validated [`SpiffeId`] should prefer this over re-parsing
    /// the URI string by hand.
    pub fn namespace(&self) -> Option<&str> {
        let mut segments = self.path_segments();
        while let Some(segment) = segments.next() {
            if segment == "ns" {
                return segments.next();
            }
        }
        None
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

impl FromStr for SpiffeId {
    type Err = SpiffeIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for SpiffeId {
    fn as_ref(&self) -> &str {
        &self.uri
    }
}

impl Serialize for SpiffeId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.uri)
    }
}

impl<'de> Deserialize<'de> for SpiffeId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        SpiffeId::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Parse errors for SPIFFE IDs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpiffeIdError {
    #[error("SPIFFE ID is empty")]
    Empty,
    #[error("SPIFFE ID '{0}' is too long (max {1}, got {2})")]
    TooLong(String, usize, usize),
    #[error("SPIFFE ID scheme must be 'spiffe' (lowercase), got '{0}'")]
    InvalidScheme(String),
    #[error("SPIFFE ID '{0}' must use the form 'spiffe://<trust-domain>/<path>'")]
    Malformed(String),
    #[error("SPIFFE ID '{0}' must not include a query string")]
    HasQuery(String),
    #[error("SPIFFE ID '{0}' must not include a fragment")]
    HasFragment(String),
    #[error("SPIFFE ID '{0}' must not have a trailing slash")]
    TrailingSlash(String),
    #[error("SPIFFE ID '{uri}' has empty path segment between slashes")]
    EmptyPathSegment { uri: String },
    #[error("SPIFFE ID '{uri}' has forbidden dot-only path segment '{segment}'")]
    DotPathSegment { uri: String, segment: String },
    #[error("SPIFFE ID '{uri}' path segment '{segment}' contains invalid character '{ch}'")]
    InvalidPathChar {
        uri: String,
        segment: String,
        ch: char,
    },
    #[error("SPIFFE ID '{0}' has an invalid trust domain: {1}")]
    InvalidTrustDomain(String, TrustDomainError),
}

fn parse(uri: String) -> Result<SpiffeId, SpiffeIdError> {
    if uri.is_empty() {
        return Err(SpiffeIdError::Empty);
    }
    if uri.len() > MAX_SPIFFE_ID_LEN {
        let len = uri.len();
        return Err(SpiffeIdError::TooLong(uri, MAX_SPIFFE_ID_LEN, len));
    }
    if uri.contains('?') {
        return Err(SpiffeIdError::HasQuery(uri));
    }
    if uri.contains('#') {
        return Err(SpiffeIdError::HasFragment(uri));
    }

    // Per the spec, the scheme is case-sensitive and MUST be lowercase
    // "spiffe". We do not call URI parsers that lowercase silently.
    let after_scheme = match uri.strip_prefix("spiffe://") {
        Some(rest) => rest,
        None => {
            // Tease apart "wrong scheme" vs. "no scheme" for nicer errors.
            return match uri.find("://") {
                Some(idx) => Err(SpiffeIdError::InvalidScheme(uri[..idx].to_string())),
                None => Err(SpiffeIdError::Malformed(uri)),
            };
        }
    };

    if after_scheme.is_empty() {
        return Err(SpiffeIdError::Malformed(uri));
    }

    // Split off the path (the first `/` after the trust domain).
    let (td_str, path_with_leading_slash) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };

    let trust_domain =
        TrustDomain::new(td_str).map_err(|e| SpiffeIdError::InvalidTrustDomain(uri.clone(), e))?;

    if path_with_leading_slash.is_empty() {
        // Root SPIFFE ID (no path).
        return Ok(SpiffeId {
            path_offset: uri.len(),
            uri,
            trust_domain,
        });
    }

    // path_with_leading_slash starts with '/'. Validate.
    if path_with_leading_slash.ends_with('/') {
        return Err(SpiffeIdError::TrailingSlash(uri));
    }
    let path = &path_with_leading_slash[1..];
    if path.is_empty() {
        return Err(SpiffeIdError::TrailingSlash(uri));
    }

    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(SpiffeIdError::EmptyPathSegment { uri: uri.clone() });
        }
        if matches!(segment, "." | "..") {
            return Err(SpiffeIdError::DotPathSegment {
                uri: uri.clone(),
                segment: segment.to_string(),
            });
        }
        for ch in segment.chars() {
            if !is_path_char(ch) {
                return Err(SpiffeIdError::InvalidPathChar {
                    uri: uri.clone(),
                    segment: segment.to_string(),
                    ch,
                });
            }
        }
    }

    let path_offset = "spiffe://".len() + td_str.len() + 1; // +1 for leading '/'
    Ok(SpiffeId {
        path_offset,
        uri,
        trust_domain,
    })
}

/// Per the SPIFFE-ID spec, each path segment is restricted to
/// `[A-Za-z0-9.-_]` — ASCII letters, digits, and the punctuation `.`, `-`, `_`;
/// complete `.` and `..` relative path segments are rejected separately. This
/// is STRICTER than RFC 3986 `pchar`/unreserved: `~`, percent-encoding, and
/// reserved characters are all rejected, so operators must encode SVIDs in
/// canonical form (a conformant peer such as SPIRE/ztunnel rejects them too).
#[inline]
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')
}
