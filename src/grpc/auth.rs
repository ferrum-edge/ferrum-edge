//! Shared authentication helpers for Ferrum control-plane gRPC surfaces.
//!
//! `ConfigSync` and xDS ADS are separate services, but both enforce the same
//! CP/DP security boundary: HS256 JWT in `authorization` metadata, standard
//! time claims required, and issuer pinned to `FERRUM_CP_DP_GRPC_JWT_ISSUER`.
//!
//! # Audience binding (issue #2475)
//!
//! Issuer + expiry + signature bind a token to a *credential*, not to a
//! *destination*. Two clusters that share the deprecated fallback
//! `FERRUM_CP_DP_GRPC_JWT_SECRET` and the same issuer therefore used to accept
//! each other's cross-cluster remote-discovery tokens. Every gRPC surface now
//! runs an explicit [`GrpcAudiencePolicy`] on top of the existing checks:
//!
//! - Cross-cluster mesh **remote discovery** (`MeshSubscribe` with
//!   `remote_discovery = true`) requires exactly one `aud`, equal to
//!   [`remote_discovery_audience`] of the *receiving* cluster's configured
//!   `FERRUM_MESH_CLUSTER_AUDIENCE`. Missing, malformed, multiple/ambiguous,
//!   or mismatched audiences are refused, and so is an unconfigured receiver.
//! - Every other surface (ordinary local CP↔DP `ConfigSync`, xDS ADS, and
//!   ordinary local mesh `MeshSubscribe`) runs
//!   [`GrpcAudiencePolicy::ReservedForbidden`]: those token classes are
//!   unchanged and carry no `aud`, so any audience at all is refused —
//!   preserving `jsonwebtoken`'s strict `validate_aud` posture — with a
//!   reserved [`MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX`] value reported
//!   distinctly from an unrelated one. That keeps the two token purposes
//!   unambiguous in both directions: a discovery token can never be replayed
//!   as a local subscription token, and a local token can never satisfy the
//!   discovery policy (it carries no `aud` at all).

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::collections::HashSet;
use tonic::Status;

/// Reserved JWT `aud` prefix for cross-cluster mesh **remote-discovery**
/// tokens. The prefix is what makes the token class self-describing: any
/// surface that is not the remote-discovery verifier refuses a token carrying
/// it, so the class cannot be silently substituted for an ordinary CP↔DP or
/// local mesh subscription token.
pub const MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX: &str = "ferrum-mesh-discovery:";

/// Build the remote-discovery audience for a target cluster.
///
/// `cluster_id` is the **stable, operator-visible** target-cluster identifier —
/// `RemoteCluster.name` on the polling data plane and
/// `FERRUM_MESH_CLUSTER_AUDIENCE` on the receiving control plane. It is
/// deliberately independent of `control_plane_url`: the endpoint is mutable
/// (DNS, ports, migration between load balancers) and must never be the thing a
/// credential is bound to.
///
/// Mesh validation rejects leading/trailing whitespace on `RemoteCluster.name`
/// (and `local_cluster`) so the configured identity matches this audience
/// one-to-one. `trim()` here remains defense in depth for the already-canonical
/// `FERRUM_MESH_CLUSTER_AUDIENCE` env path.
pub fn remote_discovery_audience(cluster_id: &str) -> String {
    format!(
        "{MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX}{}",
        cluster_id.trim()
    )
}

/// What a gRPC surface accepts in the JWT `aud` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcAudiencePolicy<'a> {
    /// The surface has no audience of its own, so a token must carry none.
    ///
    /// This preserves `jsonwebtoken`'s strict `validate_aud = true` posture for
    /// these surfaces (RFC 7519 §4.1.3): a token stamped for *some* audience
    /// was minted for a purpose this surface cannot check, and honoring it
    /// whenever the HS256 secret is shared is exactly the substitution this
    /// binding exists to prevent. A reserved mesh audience is reported
    /// separately from an unrelated one so operators can tell a cross-cluster
    /// replay attempt apart from a misconfigured token minter.
    ReservedForbidden,
    /// The surface requires exactly one audience, equal to this value.
    Required(&'a str),
    /// The surface requires an audience but none is configured. Always fails
    /// closed — a receiver that cannot state its own identity must not accept
    /// a cross-cluster credential.
    Unconfigured,
}

/// Why an audience check failed. A closed, compile-time set used as a bounded
/// metric/audit label — never a caller-supplied string, and never the token or
/// any part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceRejectReason {
    /// The surface requires an audience and the token carries none.
    Missing,
    /// The `aud` claim is present but not a non-empty string / array of
    /// non-empty strings.
    Malformed,
    /// The `aud` claim carries more than one value, so the intended target is
    /// ambiguous. Fail closed rather than accepting on any match.
    Ambiguous,
    /// A single, well-formed audience that is not this surface's audience.
    Mismatch,
    /// The receiver has no audience configured but the request requires one.
    Unconfigured,
    /// A reserved mesh audience reached a surface that is not its purpose.
    ReservedAudience,
    /// A surface that expects no audience received a token carrying one.
    UnexpectedAudience,
}

impl AudienceRejectReason {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Ambiguous => "ambiguous",
            Self::Mismatch => "mismatch",
            Self::Unconfigured => "unconfigured",
            Self::ReservedAudience => "reserved_audience",
            Self::UnexpectedAudience => "unexpected_audience",
        }
    }

    /// Operator-facing message. Deliberately fixed strings: the rejected token
    /// (and any claim value inside it) is credential material and is never
    /// echoed back to the caller or into a log line.
    pub const fn as_status_message(self) -> &'static str {
        match self {
            Self::Missing => "Invalid token: required audience claim is missing",
            Self::Malformed => "Invalid token: audience claim is malformed",
            Self::Ambiguous => "Invalid token: audience claim is ambiguous",
            Self::Mismatch => "Invalid token: audience claim is not this cluster",
            Self::Unconfigured => {
                "Remote-cluster discovery is not enabled here: this control plane has no \
                 FERRUM_MESH_CLUSTER_AUDIENCE configured"
            }
            Self::ReservedAudience => {
                "Invalid token: audience claim is reserved for another subscription purpose"
            }
            Self::UnexpectedAudience => "Invalid token: this surface accepts no audience claim",
        }
    }
}

/// Normalize the `aud` claim into at most one audience value.
///
/// RFC 7519 allows `aud` to be a string or an array of strings. Ferrum accepts
/// both shapes but only a *single* value: a multi-audience token does not state
/// an unambiguous target, and honoring it on any match would reintroduce the
/// cross-cluster acceptance this binding exists to prevent.
fn parse_audience_claim(claims: &Value) -> Result<Option<String>, AudienceRejectReason> {
    let raw = match claims.get("aud") {
        Some(value) => value,
        None => return Ok(None),
    };

    if let Some(single) = raw.as_str() {
        let trimmed = single.trim();
        if trimmed.is_empty() {
            return Err(AudienceRejectReason::Malformed);
        }
        return Ok(Some(trimmed.to_string()));
    }

    if let Some(values) = raw.as_array() {
        if values.is_empty() {
            // Present but empty: an explicit, unusable claim. Never downgrade
            // it to "absent" — that would let a malformed token fall through
            // to a policy that only checks for a reserved prefix.
            return Err(AudienceRejectReason::Malformed);
        }
        let mut normalized = Vec::with_capacity(values.len());
        for value in values {
            let Some(entry) = value.as_str() else {
                return Err(AudienceRejectReason::Malformed);
            };
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return Err(AudienceRejectReason::Malformed);
            }
            normalized.push(trimmed.to_string());
        }
        normalized.sort();
        normalized.dedup();
        if normalized.len() > 1 {
            return Err(AudienceRejectReason::Ambiguous);
        }
        // `normalized` is non-empty here (the empty array returned above and
        // dedup cannot empty a non-empty vector).
        return Ok(normalized.pop());
    }

    Err(AudienceRejectReason::Malformed)
}

/// Apply a [`GrpcAudiencePolicy`] to the decoded claims.
fn enforce_audience(
    claims: &Value,
    policy: GrpcAudiencePolicy<'_>,
) -> Result<(), AudienceRejectReason> {
    // The claim is parsed (and can be rejected as malformed/ambiguous) under
    // every policy, including `ReservedForbidden`, so a hostile shape never
    // reaches a surface by being unreadable.
    let audience = parse_audience_claim(claims)?;
    match policy {
        GrpcAudiencePolicy::Unconfigured => Err(AudienceRejectReason::Unconfigured),
        GrpcAudiencePolicy::Required(expected) => match audience {
            Some(found) if found == expected => Ok(()),
            Some(_) => Err(AudienceRejectReason::Mismatch),
            None => Err(AudienceRejectReason::Missing),
        },
        GrpcAudiencePolicy::ReservedForbidden => match audience {
            None => Ok(()),
            Some(found) if found.starts_with(MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX) => {
                Err(AudienceRejectReason::ReservedAudience)
            }
            Some(_) => Err(AudienceRejectReason::UnexpectedAudience),
        },
    }
}

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
///
/// Audience posture is [`GrpcAudiencePolicy::ReservedForbidden`]: these
/// surfaces do not mint or expect an audience, but they must never honor a
/// token minted for the cross-cluster remote-discovery purpose. Surfaces that
/// need a real audience check call
/// [`verify_grpc_jwt_metadata_with_audience`].
#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata_with_claims(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
) -> Result<AllowedNamespaces, Status> {
    verify_grpc_jwt_metadata_with_audience(
        metadata,
        jwt_secret,
        expected_issuer,
        GrpcAudiencePolicy::ReservedForbidden,
    )
    .map_err(|(status, _)| status)
}

/// Verify the JWT under an explicit [`GrpcAudiencePolicy`].
///
/// On failure the bounded [`AudienceRejectReason`] is returned alongside the
/// `Status` **only** when the audience check is what failed, so callers can
/// record a fixed-cardinality audit/metric label without re-deriving it from
/// the (never-logged) token. Signature/expiry/issuer/`ns` failures return
/// `None` and keep their existing messages.
#[allow(clippy::result_large_err, clippy::type_complexity)]
pub(crate) fn verify_grpc_jwt_metadata_with_audience(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
    audience_policy: GrpcAudiencePolicy<'_>,
) -> Result<AllowedNamespaces, (Status, Option<AudienceRejectReason>)> {
    let token = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .ok_or_else(|| {
            (
                Status::unauthenticated("Missing authorization token"),
                None::<AudienceRejectReason>,
            )
        })?;

    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = required_grpc_claims();
    validation.set_issuer(&[expected_issuer]);
    // Audience enforcement is Ferrum's own (`enforce_audience`) so every
    // rejection carries a bounded reason label and multi-valued claims fail
    // closed instead of matching on any element.
    validation.validate_aud = false;

    let token_data = decode::<Value>(token, &key, &validation).map_err(|err| {
        (
            Status::unauthenticated(format!("Invalid token: {err}")),
            None,
        )
    })?;

    if let Err(reason) = enforce_audience(&token_data.claims, audience_policy) {
        return Err((
            Status::unauthenticated(reason.as_status_message()),
            Some(reason),
        ));
    }

    extract_ns_claim(&token_data.claims).map_err(|status| (status, None))
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
    parse_ns_claim(claims).map_err(Status::unauthenticated)
}

/// Transport-agnostic `ns` claim parser shared by the CP/DP gRPC surface and
/// the REST admin API (`FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`). Both planes
/// must accept identical claim shapes so one operator-minted token can carry
/// tenancy for either surface without drift.
pub(crate) fn parse_ns_claim(claims: &Value) -> Result<AllowedNamespaces, String> {
    let raw = match claims.get("ns") {
        Some(v) => v,
        None => return Ok(AllowedNamespaces::empty()),
    };

    if let Some(s) = raw.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("JWT `ns` claim must not be an empty string".to_string());
        }
        let mut set = HashSet::new();
        set.insert(trimmed.to_string());
        return Ok(AllowedNamespaces(Some(set)));
    }

    if let Some(arr) = raw.as_array() {
        let mut set = HashSet::new();
        for value in arr {
            let Some(raw) = value.as_str() else {
                return Err("JWT `ns` array claim must contain only strings".to_string());
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err("JWT `ns` array claim must not contain empty strings".to_string());
            }
            set.insert(trimmed.to_string());
        }
        return Ok(AllowedNamespaces(Some(set)));
    }

    Err("JWT `ns` claim must be a string or an array of strings".to_string())
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

    // ── Audience binding (issue #2475) ────────────────────────────────────

    const CLUSTER_B_AUD: &str = "ferrum-mesh-discovery:cluster-b";

    #[test]
    fn audience_claim_accepts_string_and_single_element_array() {
        assert_eq!(
            parse_audience_claim(&json!({ "aud": " cluster-b " })).expect("string aud"),
            Some("cluster-b".to_string())
        );
        assert_eq!(
            parse_audience_claim(&json!({ "aud": ["cluster-b"] })).expect("array aud"),
            Some("cluster-b".to_string())
        );
        // Duplicates collapse to one unambiguous target.
        assert_eq!(
            parse_audience_claim(&json!({ "aud": ["cluster-b", "cluster-b"] })).expect("dup aud"),
            Some("cluster-b".to_string())
        );
        assert_eq!(
            parse_audience_claim(&json!({ "sub": "n" })).expect("absent"),
            None
        );
    }

    #[test]
    fn audience_claim_malformed_and_ambiguous_shapes_rejected() {
        for malformed in [
            json!({ "aud": "" }),
            json!({ "aud": "   " }),
            json!({ "aud": [] }),
            json!({ "aud": ["cluster-b", ""] }),
            json!({ "aud": [1, 2] }),
            json!({ "aud": 42 }),
            json!({ "aud": { "cluster": "b" } }),
        ] {
            assert_eq!(
                parse_audience_claim(&malformed),
                Err(AudienceRejectReason::Malformed),
                "expected malformed rejection for {malformed}"
            );
        }
        assert_eq!(
            parse_audience_claim(&json!({ "aud": ["cluster-b", "cluster-c"] })),
            Err(AudienceRejectReason::Ambiguous)
        );
    }

    #[test]
    fn required_policy_binds_to_exactly_one_audience() {
        let policy = GrpcAudiencePolicy::Required(CLUSTER_B_AUD);
        assert!(enforce_audience(&json!({ "aud": CLUSTER_B_AUD }), policy).is_ok());
        // Cluster C's verifier refuses B's token even with the same secret+issuer.
        assert_eq!(
            enforce_audience(
                &json!({ "aud": CLUSTER_B_AUD }),
                GrpcAudiencePolicy::Required("ferrum-mesh-discovery:cluster-c")
            ),
            Err(AudienceRejectReason::Mismatch)
        );
        assert_eq!(
            enforce_audience(&json!({ "sub": "dp" }), policy),
            Err(AudienceRejectReason::Missing)
        );
        assert_eq!(
            enforce_audience(
                &json!({ "aud": [CLUSTER_B_AUD, "ferrum-mesh-discovery:cluster-c"] }),
                policy
            ),
            Err(AudienceRejectReason::Ambiguous)
        );
        assert_eq!(
            enforce_audience(&json!({ "aud": 7 }), policy),
            Err(AudienceRejectReason::Malformed)
        );
    }

    #[test]
    fn unconfigured_policy_always_fails_closed() {
        assert_eq!(
            enforce_audience(
                &json!({ "aud": CLUSTER_B_AUD }),
                GrpcAudiencePolicy::Unconfigured
            ),
            Err(AudienceRejectReason::Unconfigured)
        );
        assert_eq!(
            enforce_audience(&json!({ "sub": "dp" }), GrpcAudiencePolicy::Unconfigured),
            Err(AudienceRejectReason::Unconfigured)
        );
    }

    #[test]
    fn reserved_forbidden_policy_separates_the_token_purposes() {
        let policy = GrpcAudiencePolicy::ReservedForbidden;
        // Ordinary CP↔DP / local mesh tokens carry no audience: unchanged.
        assert!(enforce_audience(&json!({ "sub": "dp" }), policy).is_ok());
        // A token minted for ANY other audience is refused, preserving
        // jsonwebtoken's strict `validate_aud` posture for these surfaces.
        assert_eq!(
            enforce_audience(&json!({ "aud": "internal-tooling" }), policy),
            Err(AudienceRejectReason::UnexpectedAudience)
        );
        // A remote-discovery token can never be replayed as a local one.
        assert_eq!(
            enforce_audience(&json!({ "aud": CLUSTER_B_AUD }), policy),
            Err(AudienceRejectReason::ReservedAudience)
        );
        // Malformed shapes still fail closed on this policy.
        assert_eq!(
            enforce_audience(&json!({ "aud": [] }), policy),
            Err(AudienceRejectReason::Malformed)
        );
    }

    #[test]
    fn remote_discovery_audience_is_prefixed_and_trimmed() {
        assert_eq!(remote_discovery_audience(" cluster-b "), CLUSTER_B_AUD);
        assert!(
            remote_discovery_audience("cluster-b")
                .starts_with(MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX)
        );
    }
}
