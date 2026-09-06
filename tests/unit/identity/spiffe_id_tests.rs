//! SPIFFE-ID parser, trust-domain validator, and SPIFFE-URI hashing tests.

use ferrum_edge::identity::spiffe::{
    MAX_SPIFFE_ID_LEN, MAX_TRUST_DOMAIN_LEN, SpiffeId, SpiffeIdError, TrustDomain, TrustDomainError,
};
use std::collections::HashSet;
use std::str::FromStr;

// ── Trust domain ──────────────────────────────────────────────────────────

#[test]
fn trust_domain_accepts_simple_name() {
    let td = TrustDomain::new("prod.example.com").expect("valid");
    assert_eq!(td.as_str(), "prod.example.com");
    assert_eq!(td.as_uri(), "spiffe://prod.example.com");
}

#[test]
fn trust_domain_rejects_empty() {
    assert!(matches!(TrustDomain::new(""), Err(TrustDomainError::Empty)));
}

#[test]
fn trust_domain_rejects_uppercase() {
    assert!(matches!(
        TrustDomain::new("Prod.example.com"),
        Err(TrustDomainError::NotLowercase(_))
    ));
}

#[test]
fn trust_domain_rejects_path_component() {
    assert!(matches!(
        TrustDomain::new("prod.example.com/extra"),
        Err(TrustDomainError::HasPath(_))
    ));
}

#[test]
fn trust_domain_rejects_invalid_char() {
    assert!(matches!(
        TrustDomain::new("prod.example.com!"),
        Err(TrustDomainError::InvalidChar(_, '!'))
    ));
}

#[test]
fn trust_domain_rejects_leading_dot() {
    assert!(matches!(
        TrustDomain::new(".example.com"),
        Err(TrustDomainError::BadBoundary(_))
    ));
}

#[test]
fn trust_domain_rejects_too_long() {
    let raw = "a".repeat(MAX_TRUST_DOMAIN_LEN + 1);
    assert!(matches!(
        TrustDomain::new(raw),
        Err(TrustDomainError::TooLong(_, _))
    ));
}

#[test]
fn trust_domain_too_long_error_is_material_free() {
    // A restore or mesh body can present a multi-hundred-KiB trust-domain
    // string. The length check must fail closed without cloning that value
    // into the error or echoing it from Display/Debug.
    const CANARY: &str = "hostile-trust-domain-canary";
    let raw = format!("{CANARY}{}", "a".repeat(256 * 1024));
    let actual_len = raw.len();
    assert!(actual_len > MAX_TRUST_DOMAIN_LEN);

    let err = TrustDomain::new(raw.clone()).expect_err("overlong trust domain must be rejected");
    assert_eq!(
        err,
        TrustDomainError::TooLong(MAX_TRUST_DOMAIN_LEN, actual_len)
    );

    let rendered = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        !rendered.contains(CANARY) && !rendered.contains(&raw),
        "TooLong diagnostic must not echo the hostile value: {rendered}"
    );
    assert!(
        !debug.contains(CANARY) && !debug.contains(&raw),
        "TooLong debug must not leak the hostile value: {debug}"
    );
    assert!(
        rendered.contains(&MAX_TRUST_DOMAIN_LEN.to_string())
            && rendered.contains(&actual_len.to_string()),
        "TooLong must report max and actual length only: {rendered}"
    );
    assert!(
        rendered.len() < 128,
        "TooLong diagnostic must stay material-free, got {} bytes: {rendered}",
        rendered.len()
    );

    let json = serde_json::to_string(&raw).expect("hostile domain encodes as JSON");
    let serde_err = serde_json::from_str::<TrustDomain>(&json)
        .expect_err("overlong trust domain must fail deserialization")
        .to_string();
    assert!(
        !serde_err.contains(CANARY),
        "deserializing an overlong trust domain must not leak the value: {serde_err}"
    );
}

#[test]
fn trust_domain_round_trips_via_serde() {
    let td = TrustDomain::new("prod.example.com").unwrap();
    let s = serde_json::to_string(&td).unwrap();
    let back: TrustDomain = serde_json::from_str(&s).unwrap();
    assert_eq!(back, td);
}

#[test]
fn trust_domain_serde_rejects_malformed() {
    let bad = "\"PROD.example.com\"";
    assert!(serde_json::from_str::<TrustDomain>(bad).is_err());
}

// ── SPIFFE ID parsing ─────────────────────────────────────────────────────

#[test]
fn spiffe_id_parses_simple() {
    let id = SpiffeId::new("spiffe://prod.example.com/ns/foo/sa/bar").unwrap();
    assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/foo/sa/bar");
    assert_eq!(id.trust_domain().as_str(), "prod.example.com");
    assert_eq!(id.path(), "ns/foo/sa/bar");
    assert_eq!(
        id.path_segments().collect::<Vec<_>>(),
        vec!["ns", "foo", "sa", "bar"]
    );
}

#[test]
fn spiffe_id_root_no_path_ok() {
    let id = SpiffeId::new("spiffe://prod.example.com").unwrap();
    assert_eq!(id.path(), "");
    assert_eq!(id.path_segments().count(), 0);
}

#[test]
fn kubernetes_identity_parses_marker_named_values_positionally() {
    for (namespace, account) in [
        ("sa", "backend"),
        ("sa", "frontend"),
        ("sa", "sa"),
        ("default", "backend"),
        ("ns", "ns"),
    ] {
        let uri = format!("spiffe://cluster.local/ns/{namespace}/sa/{account}");
        let id = SpiffeId::new(uri).unwrap();
        assert_eq!(id.kubernetes_identity(), Some((namespace, account)));
        assert_eq!(id.namespace(), Some(namespace));
        assert_eq!(id.service_account(), Some(account));
    }
}

#[test]
fn kubernetes_identity_preserves_noncanonical_accessor_behavior() {
    for (path, namespace, account) in [
        ("", None, None),
        ("ns/prod", Some("prod"), None),
        ("ns/prod/sa", Some("prod"), None),
        ("sa/foo/sa/bar", None, Some("foo")),
        ("ns/prod/ns/staging/sa/foo", Some("prod"), Some("foo")),
        ("ns/prod/sa/foo/sa/bar", Some("prod"), Some("foo")),
        ("prefix/ns/prod/sa/foo", Some("prod"), Some("foo")),
        ("ns/prod/sa/foo/extra", Some("prod"), Some("foo")),
        ("ns/prod/workload/foo", Some("prod"), None),
    ] {
        let id = SpiffeId::from_parts(&TrustDomain::new("cluster.local").unwrap(), path).unwrap();
        assert_eq!(id.kubernetes_identity(), None, "{path}");
        assert_eq!(id.namespace(), namespace, "{path}");
        assert_eq!(id.service_account(), account, "{path}");
    }
}

#[test]
fn kubernetes_identity_rejects_empty_segments() {
    for path in [
        "ns//sa/backend",
        "ns/sa//backend",
        "ns/sa/sa/",
        "ns/sa/sa//backend",
    ] {
        assert!(SpiffeId::new(format!("spiffe://cluster.local/{path}")).is_err());
    }
}

#[test]
fn service_account_returns_segment_after_first_sa() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/ztunnel").unwrap();
    assert_eq!(id.service_account(), Some("ztunnel"));
}

#[test]
fn service_account_none_when_path_lacks_sa_segment() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default").unwrap();
    assert_eq!(id.service_account(), None);
}

#[test]
fn service_account_none_when_sa_is_trailing() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa").unwrap();
    assert_eq!(id.service_account(), None);
}

#[test]
fn service_account_uses_first_sa_segment() {
    // A second `sa` later in the path must not override the first match.
    let id = SpiffeId::new("spiffe://cluster.local/sa/foo/sa/bar").unwrap();
    assert_eq!(id.service_account(), Some("foo"));
}

#[test]
fn service_account_none_for_root_spiffe_id() {
    let id = SpiffeId::new("spiffe://cluster.local").unwrap();
    assert_eq!(id.service_account(), None);
}

#[test]
fn namespace_returns_segment_after_first_ns() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/ztunnel").unwrap();
    assert_eq!(id.namespace(), Some("default"));
}

#[test]
fn namespace_returns_segment_after_first_ns_for_non_canonical_path() {
    // Only `ns/<namespace>` is required; a SPIFFE ID without `sa/...` still
    // resolves the namespace. Mirrors the Istio convention `spiffe://td/ns/<ns>`
    // for workload group identities.
    let id = SpiffeId::new("spiffe://cluster.local/ns/prod").unwrap();
    assert_eq!(id.namespace(), Some("prod"));
}

#[test]
fn namespace_none_when_path_lacks_ns_segment() {
    let id = SpiffeId::new("spiffe://cluster.local/sa/client").unwrap();
    assert_eq!(id.namespace(), None);
}

#[test]
fn namespace_none_when_ns_is_trailing() {
    let id = SpiffeId::new("spiffe://cluster.local/ns").unwrap();
    assert_eq!(id.namespace(), None);
}

#[test]
fn namespace_uses_first_ns_segment() {
    // A second `ns/...` later in the path must not override the first match.
    // Istio places `ns/<namespace>` at a single canonical position; honoring
    // any later `ns/` segment would weaken authorization built on top of this
    // helper (e.g., `sourceNamespace` predicates).
    let id = SpiffeId::new("spiffe://cluster.local/ns/prod/ns/staging/sa/foo").unwrap();
    assert_eq!(id.namespace(), Some("prod"));
}

#[test]
fn namespace_none_for_root_spiffe_id() {
    let id = SpiffeId::new("spiffe://cluster.local").unwrap();
    assert_eq!(id.namespace(), None);
}

#[test]
fn spiffe_id_rejects_wrong_scheme() {
    assert!(matches!(
        SpiffeId::new("https://prod.example.com/foo"),
        Err(SpiffeIdError::InvalidScheme(_))
    ));
    assert!(matches!(
        SpiffeId::new("SPIFFE://prod.example.com/foo"),
        Err(SpiffeIdError::InvalidScheme(_))
    ));
}

#[test]
fn spiffe_id_rejects_missing_trust_domain() {
    assert!(matches!(
        SpiffeId::new("spiffe:///path"),
        Err(SpiffeIdError::InvalidTrustDomain(_, _))
    ));
}

#[test]
fn spiffe_id_rejects_trailing_slash() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo/"),
        Err(SpiffeIdError::TrailingSlash(_))
    ));
}

#[test]
fn spiffe_id_rejects_query() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo?bar=1"),
        Err(SpiffeIdError::HasQuery(_))
    ));
}

#[test]
fn spiffe_id_rejects_fragment() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo#frag"),
        Err(SpiffeIdError::HasFragment(_))
    ));
}

#[test]
fn spiffe_id_rejects_empty_path_segment() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo//bar"),
        Err(SpiffeIdError::EmptyPathSegment { .. })
    ));
}

#[test]
fn spiffe_id_rejects_dot_only_path_segments() {
    for raw in [
        "spiffe://prod.example.com/.",
        "spiffe://prod.example.com/..",
        "spiffe://prod.example.com/ns/../sa/admin",
        "spiffe://prod.example.com/ns/./sa/admin",
    ] {
        assert!(
            matches!(
                SpiffeId::new(raw),
                Err(SpiffeIdError::DotPathSegment { .. })
            ),
            "{raw} should reject relative path modifiers"
        );
    }
}

#[test]
fn spiffe_id_rejects_invalid_path_char() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo bar"),
        Err(SpiffeIdError::InvalidPathChar { .. })
    ));
}

#[test]
fn spiffe_id_rejects_idn_path() {
    // Non-ASCII in path is rejected.
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/π"),
        Err(SpiffeIdError::InvalidPathChar { .. })
    ));
}

#[test]
fn spiffe_id_rejects_tilde_path_char() {
    // Per the SPIFFE-ID spec a path segment is `[A-Za-z0-9.-_]` — `~` is NOT
    // allowed (stricter than RFC 3986 unreserved). A conformant peer (SPIRE,
    // ztunnel) rejects it, so Ferrum must too rather than accept a non-canonical
    // identity off a hostile/misconfigured peer cert.
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/ns/a~b/sa/x"),
        Err(SpiffeIdError::InvalidPathChar { ch: '~', .. })
    ));
}

#[test]
fn spiffe_id_rejects_too_long() {
    let body = "a".repeat(MAX_SPIFFE_ID_LEN + 1);
    let raw = format!("spiffe://prod.example.com/{body}");
    assert!(matches!(
        SpiffeId::new(raw),
        Err(SpiffeIdError::TooLong(_, _, _))
    ));
}

#[test]
fn spiffe_id_from_str_parses() {
    let id = SpiffeId::from_str("spiffe://td/ns/a/sa/b").unwrap();
    assert_eq!(id.trust_domain().as_str(), "td");
}

#[test]
fn spiffe_id_serde_round_trip() {
    let id = SpiffeId::new("spiffe://prod.example.com/ns/foo/sa/bar").unwrap();
    let s = serde_json::to_string(&id).unwrap();
    let back: SpiffeId = serde_json::from_str(&s).unwrap();
    assert_eq!(back, id);
}

#[test]
fn spiffe_id_hash_eq() {
    let a = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let b = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let mut set: HashSet<SpiffeId> = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

#[test]
fn spiffe_id_from_parts() {
    let td = TrustDomain::new("td").unwrap();
    let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
    assert_eq!(id.as_str(), "spiffe://td/ns/foo/sa/bar");

    // Leading slash is normalised away.
    let id2 = SpiffeId::from_parts(&td, "/ns/foo").unwrap();
    assert_eq!(id2.as_str(), "spiffe://td/ns/foo");

    // Empty path becomes the root.
    let id3 = SpiffeId::from_parts(&td, "").unwrap();
    assert_eq!(id3.as_str(), "spiffe://td");
}
