//! Shared authentication helpers for Ferrum control-plane gRPC surfaces.
//!
//! `ConfigSync` and xDS ADS are separate services, but both enforce the same
//! CP/DP security boundary: HS256 JWT in `authorization` metadata, standard
//! time claims required, and issuer pinned to `FERRUM_CP_DP_GRPC_JWT_ISSUER`.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::collections::HashSet;
use tonic::Status;

/// Namespaces a DP ConfigSync JWT bearer is authorised to subscribe to.
///
/// The `ns` claim is optional only for back-compat with single-namespace CPs.
/// Multi-namespace CP scopes require it automatically. Carriers:
/// - `None` — token has no `ns` claim; only accepted by single-namespace CPs
///   when `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=false`.
/// - `Some(set)` — the bearer may only subscribe to the listed namespaces.
///
/// Tokens may carry the claim as either a single string (`"ns": "prod"`) or
/// an array (`"ns": ["prod","staging"]`). The verifier normalises both into
/// a `HashSet<String>` here so callers don't have to branch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedNamespaces(pub Option<HashSet<String>>);

impl AllowedNamespaces {
    /// Empty (no claim present).
    pub fn empty() -> Self {
        Self(None)
    }

    /// True when the claim is present (any value, even empty array).
    pub fn is_present(&self) -> bool {
        self.0.is_some()
    }

    /// True when the bearer is authorised for `namespace`. Returns `false`
    /// when no claim is present — callers must combine with the back-compat
    /// fallback logic.
    pub fn allows(&self, namespace: &str) -> bool {
        match &self.0 {
            Some(set) => set.contains(namespace),
            None => false,
        }
    }

    /// Return the only authorised namespace when the claim is present and
    /// contains exactly one namespace. Protocols without an explicit namespace
    /// request use this to avoid guessing tenant identity from node metadata.
    pub fn sole_namespace(&self) -> Option<&str> {
        let set = self.0.as_ref()?;
        if set.len() == 1 {
            set.iter().next().map(String::as_str)
        } else {
            None
        }
    }
}

#[allow(clippy::result_large_err, dead_code)]
pub(crate) fn verify_grpc_jwt_metadata(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
) -> Result<(), Status> {
    verify_grpc_jwt_metadata_with_claims(metadata, jwt_secret, expected_issuer).map(|_| ())
}

/// Verify the JWT and return any `ns` claim it carried. Use this variant
/// whenever the caller needs the tenancy-claim path (CP `Subscribe` and
/// `GetFullConfig` today). The verification logic is identical to
/// [`verify_grpc_jwt_metadata`]; the only difference is the extra claim
/// extraction.
#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata_with_claims(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
) -> Result<AllowedNamespaces, Status> {
    let token = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = required_grpc_claims();
    validation.set_issuer(&[expected_issuer]);

    let token_data = decode::<Value>(token, &key, &validation)
        .map_err(|err| Status::unauthenticated(format!("Invalid token: {err}")))?;
    extract_ns_claim(&token_data.claims)
}

fn required_grpc_claims() -> HashSet<String> {
    ["exp", "iat", "sub", "iss"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Pull the `ns` claim out of the decoded JWT body. Accepted shapes:
/// - missing — `AllowedNamespaces::empty()`
/// - `"ns": "production"` — single-namespace claim, single-element set
/// - `"ns": ["production","staging"]` — multi-namespace claim
///
/// Invalid shapes are rejected rather than downgraded to "no claim"; treating
/// a malformed tenant claim as absent would let an ambiguous token fall back
/// to legacy scope-only authorization on multi-namespace CPs.
#[allow(clippy::result_large_err)]
fn extract_ns_claim(claims: &Value) -> Result<AllowedNamespaces, Status> {
    let raw = match claims.get("ns") {
        Some(v) => v,
        None => return Ok(AllowedNamespaces::empty()),
    };

    if let Some(s) = raw.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(Status::unauthenticated(
                "JWT `ns` claim must not be an empty string",
            ));
        }
        let mut set = HashSet::new();
        set.insert(trimmed.to_string());
        return Ok(AllowedNamespaces(Some(set)));
    }

    if let Some(arr) = raw.as_array() {
        let mut set = HashSet::new();
        for value in arr {
            let Some(raw) = value.as_str() else {
                return Err(Status::unauthenticated(
                    "JWT `ns` array claim must contain only strings",
                ));
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(Status::unauthenticated(
                    "JWT `ns` array claim must not contain empty strings",
                ));
            }
            set.insert(trimmed.to_string());
        }
        return Ok(AllowedNamespaces(Some(set)));
    }

    Err(Status::unauthenticated(
        "JWT `ns` claim must be a string or an array of strings",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ns_claim_absent_yields_empty() {
        let claims = json!({ "sub": "node-a", "iss": "ferrum-edge-cp-dp" });
        assert_eq!(
            extract_ns_claim(&claims).expect("absent claim is valid"),
            AllowedNamespaces::empty()
        );
    }

    #[test]
    fn ns_claim_string_normalised_to_single_element_set() {
        let claims = json!({ "ns": "production" });
        let allowed = extract_ns_claim(&claims).expect("string claim is valid");
        assert!(allowed.is_present());
        assert!(allowed.allows("production"));
        assert!(!allowed.allows("staging"));
        assert_eq!(allowed.sole_namespace(), Some("production"));
    }

    #[test]
    fn ns_claim_array_normalised_to_set() {
        let claims = json!({ "ns": ["prod", "staging", "prod"] });
        let allowed = extract_ns_claim(&claims).expect("array claim is valid");
        let inner = allowed.0.expect("set should be present");
        assert_eq!(inner.len(), 2);
        assert!(inner.contains("prod"));
        assert!(inner.contains("staging"));
    }

    #[test]
    fn ns_claim_empty_string_rejected() {
        let claims = json!({ "ns": "  " });
        assert!(extract_ns_claim(&claims).is_err());
    }

    #[test]
    fn ns_claim_empty_array_is_present_but_empty() {
        // Empty array is still a "present" claim — operator explicitly
        // assigned no namespaces, which means the bearer can subscribe to
        // nothing. The CP rejects every namespace; we keep semantics
        // distinct from the missing-claim case.
        let claims = json!({ "ns": [] });
        let allowed = extract_ns_claim(&claims).expect("empty array is valid");
        assert!(allowed.is_present());
        assert!(!allowed.allows("prod"));
        assert_eq!(allowed.sole_namespace(), None);
    }

    #[test]
    fn ns_claim_array_rejects_non_strings() {
        let claims = json!({ "ns": [1, "prod", null, "staging"] });
        assert!(extract_ns_claim(&claims).is_err());
    }

    #[test]
    fn ns_claim_non_string_non_array_rejected() {
        let claims = json!({ "ns": 42 });
        assert!(extract_ns_claim(&claims).is_err());
    }
}
