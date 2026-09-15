//! Unit coverage for the first-class namespace registry helpers (issue #3955).

use ferrum_edge::config::batch_atomicity::{
    BATCH_ADMISSION_LEASE_LOST_MESSAGE, BatchAdmissionLeaseLost, NamespaceAdmissionLeaseHold,
    NamespaceConfigAdmissionLeaseRef,
};
use ferrum_edge::config::namespace_registry::{
    CreateNamespaceRequest, MAX_NAMESPACE_DESCRIPTION_CHARS, NAMESPACE_OCCUPANCY_TABLES,
    NAMESPACE_REGISTRY_ADMISSION_KEY, NAMESPACE_REGISTRY_RETRYABLE_CONFLICT_MESSAGE,
    NAMESPACE_RENAME_COPY_TABLES, NAMESPACE_RENAME_SIMPLE_TABLES, NamespaceRegistryCorrupt,
    NamespaceRegistryError, NamespaceRegistryRetryableConflict, UpdateNamespaceBody,
    is_namespace_registry_retryable_conflict, mtls_dns_admission_namespaces,
    namespace_prefixed_id_suffix_field, namespace_registry_admission_keys, normalize_description,
    normalize_protected_namespaces, parse_namespace_rfc3339, protected_namespaces_contains,
    require_canonical_stored_description, require_namespace_identity,
    require_namespace_keyed_embedded_namespace, require_namespace_keyed_identity,
    require_namespace_prefixed_identity, require_namespace_registry_admission_keys,
    require_namespace_registry_admission_leases, validate_namespace_name,
};

#[test]
fn validate_namespace_name_matches_header_rules() {
    assert!(validate_namespace_name("ferrum").is_ok());
    assert!(validate_namespace_name("prod-1.staging_ns").is_ok());
    assert!(validate_namespace_name("-leading-hyphen").is_err());
    assert!(validate_namespace_name("has space").is_err());
    assert!(validate_namespace_name("").is_err());
    let too_long = "a".repeat(255);
    assert!(validate_namespace_name(&too_long).is_err());
}

#[test]
fn registry_admission_key_can_never_be_a_real_namespace() {
    // The whole cross-process serialization scheme rests on this: the global
    // registry lease must not be takeable by a tenant's own admission row.
    assert!(
        validate_namespace_name(NAMESPACE_REGISTRY_ADMISSION_KEY).is_err(),
        "the global registry admission key must be an invalid namespace name"
    );
}

#[test]
fn normalize_description_trims_and_caps_by_characters() {
    assert_eq!(normalize_description(None).unwrap(), None);
    assert_eq!(normalize_description(Some("  ".into())).unwrap(), None);
    assert_eq!(
        normalize_description(Some("  staging  ".into())).unwrap(),
        Some("staging".into())
    );

    let at_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        normalize_description(Some(at_limit.clone())).unwrap(),
        Some(at_limit)
    );
    let too_long = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    assert!(normalize_description(Some(too_long)).is_err());
}

#[test]
fn normalize_description_limit_counts_characters_not_bytes() {
    // OpenAPI `maxLength` is Unicode scalar values. A 4-byte-per-character
    // description at exactly the limit must be accepted, and one character over
    // must be rejected — a byte-length check would reject both.
    let at_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(at_limit.chars().count(), MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert!(at_limit.len() > MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        normalize_description(Some(at_limit.clone())).unwrap(),
        Some(at_limit)
    );

    let over_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    assert!(normalize_description(Some(over_limit)).is_err());

    // Combining sequences count per scalar value, consistently with the schema.
    let accented: String = "é".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert!(normalize_description(Some(accented)).is_ok());
}

fn parse_update(json: &str) -> UpdateNamespaceBody {
    serde_json::from_str(json).expect("update body deserializes")
}

#[test]
fn update_body_distinguishes_omit_from_clear() {
    let omitted = parse_update(r#"{"name":"prod"}"#).resolve().unwrap();
    assert_eq!(omitted.name.as_deref(), Some("prod"));
    assert_eq!(omitted.description, None);

    let cleared = parse_update(r#"{"description":null}"#).resolve().unwrap();
    assert_eq!(cleared.name, None);
    assert_eq!(cleared.description, Some(None));

    let empty = parse_update(r#"{"description":"  "}"#).resolve().unwrap();
    assert_eq!(empty.description, Some(None));

    let set = parse_update(r#"{"description":" live "}"#)
        .resolve()
        .unwrap();
    assert_eq!(set.description, Some(Some("live".into())));

    let nothing = parse_update("{}").resolve().unwrap();
    assert_eq!(nothing.name, None);
    assert_eq!(nothing.description, None);
}

#[test]
fn update_body_rejects_every_wrong_field_type() {
    // A wrong-typed `description` must NOT be interpreted as a clear: silently
    // erasing an operator's description on a malformed request is exactly the
    // fail-open behaviour this resolver exists to remove.
    for body in [
        r#"{"description":{}}"#,
        r#"{"description":[]}"#,
        r#"{"description":42}"#,
        r#"{"description":true}"#,
    ] {
        let error = parse_update(body)
            .resolve()
            .expect_err("wrong-typed description must be rejected");
        assert!(
            error.contains("description"),
            "error should name the field: {error}"
        );
    }

    // The schema permits `name` only as a string when present.
    for body in [
        r#"{"name":null}"#,
        r#"{"name":7}"#,
        r#"{"name":["a"]}"#,
        r#"{"name":{"value":"a"}}"#,
    ] {
        let error = parse_update(body)
            .resolve()
            .expect_err("wrong-typed name must be rejected");
        assert!(
            error.contains("name"),
            "error should name the field: {error}"
        );
    }
}

#[test]
fn update_body_validates_the_new_name_and_description_bounds() {
    assert!(parse_update(r#"{"name":"bad name"}"#).resolve().is_err());
    assert!(parse_update(r#"{"name":"-leading"}"#).resolve().is_err());
    assert!(parse_update(r#"{"name":""}"#).resolve().is_err());

    let over_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let body = serde_json::json!({ "description": over_limit }).to_string();
    let error = parse_update(&body)
        .resolve()
        .expect_err("over-limit description must be rejected");
    assert!(error.contains("characters"), "{error}");
}

#[test]
fn create_request_deserializes_optional_description() {
    let req: CreateNamespaceRequest = serde_json::from_str(r#"{"name":"tenant-a"}"#).unwrap();
    assert_eq!(req.name, "tenant-a");
    assert!(req.description.is_none());

    let explicit_null: CreateNamespaceRequest =
        serde_json::from_str(r#"{"name":"tenant-a","description":null}"#).unwrap();
    assert!(explicit_null.description.is_none());

    // A wrong-typed description fails deserialization, so the handler answers
    // 400 before reaching persistence.
    assert!(
        serde_json::from_str::<CreateNamespaceRequest>(r#"{"name":"tenant-a","description":5}"#)
            .is_err()
    );
}

#[test]
fn update_body_serde_preserves_present_null_versus_omission() {
    // The whole PUT contract rests on this: serde's Option<T> would map a
    // present JSON null to None, collapsing `{"description":null}` into
    // omission. The presence-aware field deserializer must keep Null.
    let omitted: UpdateNamespaceBody = serde_json::from_str("{}").unwrap();
    assert!(omitted.name.is_none());
    assert!(omitted.description.is_none());

    let name_null: UpdateNamespaceBody = serde_json::from_str(r#"{"name":null}"#).unwrap();
    assert_eq!(name_null.name, Some(serde_json::Value::Null));
    assert!(name_null.resolve().is_err());

    let desc_null: UpdateNamespaceBody = serde_json::from_str(r#"{"description":null}"#).unwrap();
    assert_eq!(desc_null.description, Some(serde_json::Value::Null));
    assert_eq!(desc_null.resolve().unwrap().description, Some(None));

    assert!(serde_json::from_str::<UpdateNamespaceBody>("").is_err());
    assert!(serde_json::from_str::<UpdateNamespaceBody>("null").is_err());
    assert!(serde_json::from_str::<UpdateNamespaceBody>("[]").is_err());
    assert!(serde_json::from_str::<UpdateNamespaceBody>("42").is_err());
}

#[test]
fn mtls_dns_admission_namespaces_are_sorted_and_deduplicated() {
    assert_eq!(
        mtls_dns_admission_namespaces("staging", "staging"),
        vec!["staging"]
    );
    assert_eq!(
        mtls_dns_admission_namespaces("zeta", "alpha"),
        vec!["alpha", "zeta"],
        "rename must lock the alphabetically first name first so SQL row locks \
         and Mongo multi-lease acquisition cannot deadlock"
    );
    assert_eq!(
        mtls_dns_admission_namespaces("alpha", "zeta"),
        vec!["alpha", "zeta"]
    );
}

#[test]
fn durable_namespace_identity_and_timestamps_fail_closed() {
    assert!(require_namespace_identity("a", "a", Some("a")).is_ok());
    assert!(require_namespace_identity("a", "b", None).is_err());
    assert!(require_namespace_identity("a", "a", Some("b")).is_err());
    assert!(require_namespace_identity("", "a", None).is_err());

    let ts = "2026-01-02T03:04:05Z";
    assert!(parse_namespace_rfc3339(ts, "created_at").is_ok());
    let err = parse_namespace_rfc3339("not-a-timestamp", "created_at").unwrap_err();
    assert!(!err.to_string().contains("not-a-timestamp"));
    assert!(err.to_string().contains(NamespaceRegistryCorrupt::MESSAGE));
    assert!(err.to_string().contains("created_at"));
}

#[test]
fn require_namespace_identity_rejects_invalid_stored_grammar() {
    assert!(require_namespace_identity("ferrum", "ferrum", None).is_ok());
    assert!(require_namespace_identity("prod-1.staging_ns", "prod-1.staging_ns", None).is_ok());
    let at_limit = "a".repeat(254);
    assert!(require_namespace_identity(&at_limit, &at_limit, None).is_ok());

    let too_long = "a".repeat(255);
    for invalid in ["has space", "-leading-hyphen", too_long.as_str()] {
        let err = require_namespace_identity(invalid, invalid, None)
            .expect_err("illegal durable names must fail closed even when _id equals name");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(text.contains("name"), "{text}");
        assert!(
            !text.contains(invalid) && !text.contains("alphanumeric"),
            "stored value and validator text must not leak: {text}"
        );
        let err = require_namespace_identity(invalid, invalid, Some(invalid))
            .expect_err("an expected-name match must not bypass grammar");
        assert!(
            !err.to_string().contains(invalid),
            "stored value must not leak: {err}"
        );
    }
}

#[test]
fn require_canonical_stored_description_rejects_noncanonical_strings() {
    assert_eq!(require_canonical_stored_description(None).unwrap(), None);
    assert_eq!(
        require_canonical_stored_description(Some("staging")).unwrap(),
        Some("staging".into())
    );

    let at_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        require_canonical_stored_description(Some(&at_limit)).unwrap(),
        Some(at_limit)
    );
    let at_limit_multibyte: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        at_limit_multibyte.chars().count(),
        MAX_NAMESPACE_DESCRIPTION_CHARS
    );
    assert!(at_limit_multibyte.len() > MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert_eq!(
        require_canonical_stored_description(Some(&at_limit_multibyte)).unwrap(),
        Some(at_limit_multibyte)
    );

    let over_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let over_limit_multibyte = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    for noncanonical in [
        "",
        "  ",
        "\tstaging",
        "staging  ",
        "  staging  ",
        over_limit.as_str(),
        over_limit_multibyte.as_str(),
    ] {
        let err = require_canonical_stored_description(Some(noncanonical))
            .expect_err("noncanonical durable descriptions must not be served");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(text.contains("description"), "{text}");
        assert!(
            (noncanonical.is_empty() || !text.contains(noncanonical))
                && !text.contains("staging")
                && !text.contains("🧪"),
            "stored description must not leak: {text}"
        );
    }
}

#[test]
fn require_namespace_prefixed_identity_requires_suffix_field_and_embedded_namespace() {
    assert_eq!(
        namespace_prefixed_id_suffix_field("consumers").unwrap(),
        "id"
    );
    assert_eq!(
        namespace_prefixed_id_suffix_field("consumer_identity_index").unwrap(),
        "identity_value"
    );
    assert!(namespace_prefixed_id_suffix_field("gateway_trust_bundles").is_err());
    assert!(namespace_prefixed_id_suffix_field("audit_events").is_err());

    assert_eq!(
        require_namespace_prefixed_identity("ns", "ns:alice", Some("ns"), "id", Some("alice"))
            .unwrap(),
        "alice"
    );
    assert_eq!(
        require_namespace_prefixed_identity(
            "ns",
            "ns:alice@ex",
            Some("ns"),
            "identity_value",
            Some("alice@ex"),
        )
        .unwrap(),
        "alice@ex"
    );

    let mismatch_id = require_namespace_prefixed_identity(
        "secret-ns",
        "secret-ns:secret-id",
        Some("secret-ns"),
        "id",
        Some("other-id"),
    )
    .unwrap_err();
    let mismatch_id_text = mismatch_id.to_string();
    assert!(
        mismatch_id_text.contains(NamespaceRegistryCorrupt::MESSAGE)
            && mismatch_id_text.contains("id")
            && !mismatch_id_text.contains("secret"),
        "{mismatch_id_text}"
    );

    let mismatch_identity = require_namespace_prefixed_identity(
        "secret-ns",
        "secret-ns:secret-id",
        Some("secret-ns"),
        "identity_value",
        Some("other"),
    )
    .unwrap_err();
    let mismatch_identity_text = mismatch_identity.to_string();
    assert!(
        mismatch_identity_text.contains("identity_value")
            && !mismatch_identity_text.contains("secret"),
        "{mismatch_identity_text}"
    );

    for (old_id, embedded, suffix) in [
        ("secret-ns:secret-id", None, Some("secret-id")),
        ("secret-ns:secret-id", Some(""), Some("secret-id")),
        ("secret-ns:secret-id", Some("other-ns"), Some("secret-id")),
        ("secret-ns:secret-id", Some("secret-ns"), None),
        ("secret-ns:secret-id", Some("secret-ns"), Some("")),
        ("secret-ns:", Some("secret-ns"), Some("secret-id")),
        ("secret-id", Some("secret-ns"), Some("secret-id")),
        ("other-ns:secret-id", Some("secret-ns"), Some("secret-id")),
    ] {
        let err = require_namespace_prefixed_identity("secret-ns", old_id, embedded, "id", suffix)
            .expect_err("corrupt composite identities must abort");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(
            !text.contains("secret") && !text.contains(old_id),
            "stored identity must not leak: {text}"
        );
    }
}

#[test]
fn require_namespace_keyed_embedded_namespace_is_strict() {
    assert!(require_namespace_keyed_embedded_namespace("ns", Some("ns")).is_ok());
    for embedded in [None, Some(""), Some("other")] {
        let err = require_namespace_keyed_embedded_namespace("secret-ns", embedded)
            .expect_err("keyed documents must not move with a mismatched namespace");
        let text = err.to_string();
        assert!(text.contains(NamespaceRegistryCorrupt::MESSAGE), "{text}");
        assert!(text.contains("namespace"), "{text}");
        assert!(
            !text.contains("secret")
                && !embedded.is_some_and(|value| !value.is_empty() && text.contains(value)),
            "stored namespace must not leak: {text}"
        );
    }
}

#[test]
fn require_namespace_keyed_identity_requires_id_namespace_and_resource() {
    assert_eq!(
        require_namespace_keyed_identity("ns", "ns", Some("ns"), Some("bundle")).unwrap(),
        "bundle"
    );
    assert_eq!(
        require_namespace_keyed_identity("ns", "ns", Some("ns"), Some("ns")).unwrap(),
        "ns",
        "an operator-chosen resource id may equal the namespace"
    );

    let other_key = require_namespace_keyed_identity(
        "secret-ns",
        "other-tenant",
        Some("secret-ns"),
        Some("bundle"),
    )
    .expect_err("a foreign durable _id must abort");
    let text = other_key.to_string();
    assert!(text.contains("identity"), "{text}");
    assert!(!text.contains("secret") && !text.contains("other-tenant") && !text.contains("bundle"));

    let embedded = require_namespace_keyed_identity(
        "secret-ns",
        "secret-ns",
        Some("other-tenant"),
        Some("bundle"),
    )
    .expect_err("embedded namespace mismatch must abort");
    let text = embedded.to_string();
    assert!(text.contains("namespace"), "{text}");
    assert!(!text.contains("secret") && !text.contains("other-tenant"));

    for resource in [None, Some("")] {
        let err =
            require_namespace_keyed_identity("secret-ns", "secret-ns", Some("secret-ns"), resource)
                .expect_err("missing resource identity must abort");
        let text = err.to_string();
        assert!(text.contains("id"), "{text}");
        assert!(!text.contains("secret"));
    }
}

#[test]
fn namespace_rename_simple_tables_move_audit_history_with_tenant() {
    // `audit_events` is the only in-place rewrite left: it is keyed on `id`
    // alone and has no foreign keys. Its authorization-scoping `namespace`
    // column must follow the renamed tenant so an old namespace name cannot
    // expose the renamed tenant's events. `namespace_at_event` is a different
    // column and is not part of this rewrite.
    assert_eq!(NAMESPACE_RENAME_SIMPLE_TABLES, &["audit_events"]);
    // Occupancy still treats API specs as live tenant metadata, and still
    // excludes audit history so leftover events cannot block DELETE.
    assert!(NAMESPACE_OCCUPANCY_TABLES.contains(&"api_specs"));
    assert!(!NAMESPACE_OCCUPANCY_TABLES.contains(&"audit_events"));
}

/// Issue #4627: the four resource tables and the junction key on
/// `(namespace, ...)`, so a rename copies them under the new name parent-first
/// and deletes the old rows. An in-place `UPDATE ... SET namespace = ?` cannot
/// satisfy the composite foreign keys at any statement boundary.
#[test]
fn namespace_rename_copy_tables_cover_every_namespace_keyed_resource_table() {
    let tables: Vec<&str> = NAMESPACE_RENAME_COPY_TABLES
        .iter()
        .map(|(table, _)| *table)
        .collect();
    assert_eq!(
        tables,
        vec![
            "upstreams",
            "proxies",
            "plugin_configs",
            "proxy_plugins",
            "api_specs",
        ],
        "copy order is parent-first; deletes run in reverse"
    );
    for (table, columns) in NAMESPACE_RENAME_COPY_TABLES {
        assert!(
            columns.contains(&"namespace"),
            "{table} copy plan must project the namespace column"
        );
        assert!(
            !NAMESPACE_RENAME_SIMPLE_TABLES.contains(table),
            "{table} must not also be rewritten in place"
        );
        let mut sorted = columns.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "{table} copy plan repeats a column");
    }
}

#[test]
fn namespace_prefixed_id_suffix_field_covers_every_composite_key_collection() {
    for collection in [
        "consumers",
        "proxies",
        "upstreams",
        "plugin_configs",
        "api_specs",
    ] {
        assert_eq!(
            namespace_prefixed_id_suffix_field(collection).expect(collection),
            "id",
            "{collection} keys on \"{{namespace}}:{{id}}\" in MongoDB"
        );
    }
    assert_eq!(
        namespace_prefixed_id_suffix_field("consumer_identity_index").unwrap(),
        "identity_value"
    );
    assert!(namespace_prefixed_id_suffix_field("config_changes").is_err());
}

fn admission_hold(key: &str) -> NamespaceAdmissionLeaseHold<'_> {
    NamespaceAdmissionLeaseHold {
        key,
        lease: NamespaceConfigAdmissionLeaseRef {
            owner: "secret-owner",
            generation: 9,
        },
    }
}

fn assert_lease_set_lost(result: Result<(), BatchAdmissionLeaseLost>, leaked: &[&str]) {
    let err = result.expect_err("malformed lease set must fail closed");
    let text = err.to_string();
    assert_eq!(text, BATCH_ADMISSION_LEASE_LOST_MESSAGE);
    for value in leaked {
        assert!(
            !text.contains(value),
            "malformed lease-set errors must not leak {value}: {text}"
        );
    }
}

#[test]
fn namespace_registry_admission_keys_match_create_update_rename_delete() {
    assert_eq!(
        namespace_registry_admission_keys(&["tenant"]),
        vec![
            NAMESPACE_REGISTRY_ADMISSION_KEY.to_string(),
            "tenant".to_string()
        ]
    );
    assert_eq!(
        namespace_registry_admission_keys(&["leased"]),
        vec![
            NAMESPACE_REGISTRY_ADMISSION_KEY.to_string(),
            "leased".to_string()
        ],
        "delete uses the same one-tenant sequence as create"
    );
    assert_eq!(
        namespace_registry_admission_keys(&["staging", "staging"]),
        vec![
            NAMESPACE_REGISTRY_ADMISSION_KEY.to_string(),
            "staging".to_string()
        ],
        "description-only update de-duplicates source and target"
    );
    assert_eq!(
        namespace_registry_admission_keys(&["zeta", "alpha"]),
        vec![
            NAMESPACE_REGISTRY_ADMISSION_KEY.to_string(),
            "alpha".to_string(),
            "zeta".to_string()
        ]
    );
    assert_eq!(
        namespace_registry_admission_keys(&["alpha", "zeta"]),
        vec![
            NAMESPACE_REGISTRY_ADMISSION_KEY.to_string(),
            "alpha".to_string(),
            "zeta".to_string()
        ]
    );
}

#[test]
fn require_namespace_registry_admission_keys_accepts_canonical_sets() {
    assert!(
        require_namespace_registry_admission_keys(
            &["tenant"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "tenant"]
        )
        .is_ok()
    );
    assert!(
        require_namespace_registry_admission_keys(
            &["staging", "staging"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "staging"]
        )
        .is_ok()
    );
    assert!(
        require_namespace_registry_admission_keys(
            &["zeta", "alpha"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "alpha", "zeta"]
        )
        .is_ok()
    );
    assert!(
        require_namespace_registry_admission_leases(
            &["tenant"],
            &[
                admission_hold(NAMESPACE_REGISTRY_ADMISSION_KEY),
                admission_hold("tenant"),
            ]
        )
        .is_ok()
    );
    assert!(
        require_namespace_registry_admission_leases(
            &["zeta", "alpha"],
            &[
                admission_hold(NAMESPACE_REGISTRY_ADMISSION_KEY),
                admission_hold("alpha"),
                admission_hold("zeta"),
            ]
        )
        .is_ok()
    );
}

#[test]
fn require_namespace_registry_admission_keys_rejects_incomplete_and_substituted_sets() {
    let leaked = &[
        "secret-ns",
        "other-ns",
        "secret-owner",
        "!namespace-registry",
        "9",
    ];

    assert_lease_set_lost(
        require_namespace_registry_admission_keys(&["secret-ns"], &[]),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(
            &["secret-ns"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(&["secret-ns"], &["secret-ns"]),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(
            &["secret-ns"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "secret-ns", "other-ns"],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(
            &["secret-ns"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "secret-ns", "secret-ns"],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(
            &["secret-ns"],
            &["secret-ns", NAMESPACE_REGISTRY_ADMISSION_KEY],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(
            &["zeta", "alpha"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "zeta", "alpha"],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_keys(
            &["secret-ns"],
            &[NAMESPACE_REGISTRY_ADMISSION_KEY, "other-ns"],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_leases(
            &["secret-ns"],
            &[admission_hold(NAMESPACE_REGISTRY_ADMISSION_KEY)],
        ),
        leaked,
    );
    assert_lease_set_lost(
        require_namespace_registry_admission_leases(
            &["secret-ns"],
            &[
                admission_hold("secret-ns"),
                admission_hold(NAMESPACE_REGISTRY_ADMISSION_KEY),
            ],
        ),
        leaked,
    );
}

// ── Protected namespace set (issue #3955 review) ────────────────────────────

#[test]
fn protected_namespaces_are_normalized_deduped_and_sorted() {
    let protected = normalize_protected_namespaces(&[
        "  tenant-b  ".to_string(),
        "tenant-a".to_string(),
        "tenant-b".to_string(),
        "   ".to_string(),
        String::new(),
        "ferrum".to_string(),
    ]);
    assert_eq!(
        protected,
        vec![
            "ferrum".to_string(),
            "tenant-a".to_string(),
            "tenant-b".to_string()
        ],
        "entries must be trimmed, de-duplicated, and sorted so lookup is a binary search"
    );
    for name in ["ferrum", "tenant-a", "tenant-b"] {
        assert!(
            protected_namespaces_contains(&protected, name),
            "{name} must be protected"
        );
    }
    for name in ["tenant-c", "", "tenant-", "TENANT-A"] {
        assert!(
            !protected_namespaces_contains(&protected, name),
            "{name} must not be protected"
        );
    }
}

#[test]
fn protected_namespaces_never_resolve_to_an_empty_set() {
    // A misconfigured or whitespace-only input must not leave the process with
    // nothing protected at all; it falls back to the canonical default.
    for input in [
        Vec::new(),
        vec![String::new()],
        vec!["   ".to_string(), "\t".to_string()],
    ] {
        let protected = normalize_protected_namespaces(&input);
        assert_eq!(protected, vec!["ferrum".to_string()], "input: {input:?}");
        assert!(protected_namespaces_contains(&protected, "ferrum"));
    }
}

#[test]
fn protected_namespace_reason_is_static_and_enumerates_no_tenant() {
    let reason = NamespaceRegistryError::PROTECTED_CONFIGURED_NAMESPACE;
    assert!(
        reason.contains("FERRUM_NAMESPACE") && reason.contains("FERRUM_CP_NAMESPACES"),
        "the reason must name the configuration keys an operator can change: {reason}"
    );
    // A 409 must never let a caller enumerate the rest of the configured set.
    let rendered = NamespaceRegistryError::Protected {
        name: "tenant-a".to_string(),
        reason,
    }
    .to_string();
    assert!(rendered.contains("tenant-a"), "{rendered}");
    for other in ["tenant-b", "tenant-c", "prod", "staging"] {
        assert!(
            !rendered.contains(other),
            "the protected 409 leaked another configured namespace ({other}): {rendered}"
        );
    }
}

// ── Retryable database conflict (issue #3955 review) ────────────────────────

#[test]
fn retryable_registry_conflict_is_typed_chain_aware_and_redacted() {
    let bare = anyhow::Error::new(NamespaceRegistryRetryableConflict);
    assert!(is_namespace_registry_retryable_conflict(&bare));
    assert_eq!(
        bare.to_string(),
        NAMESPACE_REGISTRY_RETRYABLE_CONFLICT_MESSAGE
    );

    // Persistence layers wrap errors with their own context; classification
    // must still find the typed cause.
    let wrapped = anyhow::Error::new(NamespaceRegistryRetryableConflict)
        .context("namespace registry transaction failed");
    assert!(is_namespace_registry_retryable_conflict(&wrapped));

    // The fixed message must not read like a partial write, and must not carry
    // driver text, a relation name, or a tenant name.
    let message = NAMESPACE_REGISTRY_RETRYABLE_CONFLICT_MESSAGE;
    assert!(
        message.contains("nothing was applied"),
        "the retryable message must state the fail-closed outcome: {message}"
    );
    for leak in [
        "40001",
        "40P01",
        "SQLSTATE",
        "config_admission_locks",
        "namespaces",
        "SELECT",
    ] {
        assert!(
            !message.contains(leak),
            "the retryable message leaked driver/schema detail ({leak}): {message}"
        );
    }
}

#[test]
fn retryable_registry_conflict_is_not_confused_with_other_registry_failures() {
    for other in [
        anyhow::Error::new(BatchAdmissionLeaseLost),
        NamespaceRegistryError::name_in_use("tenant-a"),
        NamespaceRegistryError::not_empty("tenant-a"),
        NamespaceRegistryError::protected(
            "tenant-a",
            NamespaceRegistryError::PROTECTED_CONFIGURED_NAMESPACE,
        ),
        anyhow::anyhow!("connection refused"),
    ] {
        assert!(
            !is_namespace_registry_retryable_conflict(&other),
            "misclassified as a retryable database conflict: {other}"
        );
    }
    // ...and the retryable conflict is not a lost lease.
    assert!(
        !ferrum_edge::config::db_backend::is_batch_admission_lease_lost(&anyhow::Error::new(
            NamespaceRegistryRetryableConflict
        ))
    );
}
