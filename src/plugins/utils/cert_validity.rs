//! Certificate-invariant temporal window shared by the plugins that derive an
//! authenticated principal from a peer X.509 certificate.
//!
//! `mtls_auth` (a Consumer-mapped principal) and `spiffe_identity` (a
//! certificate-derived SPIFFE principal) both have to bound an admitted session
//! by the leaf's `notAfter`, and both memoize their expensive parse per
//! transport connection. What may be memoized is the certificate-*invariant*
//! window; "is this certificate valid right now" is time-dependent and is
//! re-decided on every request. This type is that invariant, and only that.
//!
//! Only the two canonical Unix timestamps are kept. No DER, DN, SAN, serial, or
//! fingerprint reaches this type, and neither value is ever logged, exported as
//! a metric label, or echoed to a client.

use x509_parser::prelude::*;

/// A coherent `notBefore`/`notAfter` interval in canonical Unix seconds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CertValidityWindow {
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
}

impl CertValidityWindow {
    /// Parse a leaf's validity interval, failing closed on anything that cannot
    /// be represented as a coherent window.
    ///
    /// `x509_parser` returns `i64` seconds, so an out-of-range or malformed
    /// ASN.1 time surfaces as a nonsensical value rather than a panic. An
    /// inverted interval (`not_after < not_before`) is rejected outright: such a
    /// certificate can never be valid, and admitting it would make the
    /// per-request check depend on which bound is compared first.
    pub(crate) fn from_certificate(cert: &X509Certificate<'_>) -> Option<Self> {
        let validity = cert.validity();
        Self::from_unix_bounds(
            validity.not_before.timestamp(),
            validity.not_after.timestamp(),
        )
    }

    /// Construct a window from canonical Unix seconds, failing closed on an
    /// inverted interval. Shared by certificate parsing and the explicit-
    /// instant test seam so both sides use the same bounds check.
    pub(crate) fn from_unix_bounds(not_before_unix: i64, not_after_unix: i64) -> Option<Self> {
        if not_after_unix < not_before_unix {
            return None;
        }
        Some(Self {
            not_before_unix,
            not_after_unix,
        })
    }

    /// Whether `now_unix` lies inside the closed interval. Both boundaries are
    /// inclusive, matching RFC 5280's "valid at" semantics and
    /// `x509_parser`'s own `Validity::is_valid_at`.
    pub(crate) fn contains(&self, now_unix: i64) -> bool {
        now_unix >= self.not_before_unix && now_unix <= self.not_after_unix
    }

    /// Tighten the window's end to an additional temporal bound the accepted
    /// authorization path carries — for `mtls_auth`, the earliest `notAfter` of
    /// the cryptographically verified issuer path behind an `allowed_issuers` /
    /// `allowed_ca_fingerprints_sha256` constraint (GHSA-jw5x-439c-78v3).
    ///
    /// Only ever shortens: `None` is a no-op, and a bound later than the leaf's
    /// own `notAfter` cannot lengthen the decision. A bound that falls before
    /// `notBefore` leaves no usable window at all and fails closed as `None`,
    /// exactly like an inverted certificate interval.
    pub(crate) fn tightened_to(self, not_after_unix: Option<i64>) -> Option<Self> {
        let Some(bound) = not_after_unix else {
            return Some(self);
        };
        Self::from_unix_bounds(self.not_before_unix, self.not_after_unix.min(bound))
    }
}
