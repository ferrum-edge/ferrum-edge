//! A direct provider URI's identifier must not reach operator-facing output.
//!
//! `secrets::registry::redact_source_reference` scrubs the *backend detail* of a
//! failed fetch, but `MaterialError`'s own variants interpolate a `source_id`
//! alongside that detail, and their `Display` reaches `validate` output and
//! startup logs. For a `vault://`/`aws://`/`azure://`/`gcp://` source that
//! `source_id` was the full secret path, ARN, or Key Vault URL — so the
//! reference leaked through the wrapper instead of through the detail.

use ferrum_edge::tls::source::subscription::{WatchedMaterialSource, material_set_fingerprint};
use ferrum_edge::tls::source::{
    CertSource, MaterialError, MaterialKind, MaterializedMaterial, SourceScheme,
};

const HOSTILE_SOURCE: &str = "'TLS_SOURCE_MARKER\"\\\n927451 true";
const HOSTILE_DETAIL: &str = "bare TLS_PROVIDER_MARKER '\"\\\n927451 true";

fn assert_rendered(error: anyhow::Error, expected: &[&str]) {
    let rendered = ferrum_edge::startup::render_startup_error(
        error.context("`backend_tls_client_cert_path`: TLS configuration rejected"),
        &[],
    );
    for &expected in expected {
        assert!(
            rendered.contains(expected),
            "missing {expected:?}: {rendered}"
        );
    }
    assert!(rendered.contains("`backend_tls_client_cert_path`"));
    let rendered = rendered.to_ascii_lowercase();
    for withheld in ["tls_source_marker", "tls_provider_marker", "927451", "true"] {
        assert!(
            !rendered.contains(withheld),
            "leaked {withheld}: {rendered}"
        );
    }
}

#[test]
fn material_error_rendering_withholds_source_details_and_custom_io_chains() {
    for (error, reason) in [
        (
            MaterialError::Io {
                source_id: HOSTILE_SOURCE.to_string(),
                source: std::io::Error::other(std::io::Error::other(HOSTILE_DETAIL)),
            },
            "failed to read TLS material",
        ),
        (
            MaterialError::Secret {
                source_id: HOSTILE_SOURCE.to_string(),
                details: HOSTILE_DETAIL.to_string(),
            },
            "failed to resolve TLS material source",
        ),
        (
            MaterialError::InvalidSource {
                source_id: HOSTILE_SOURCE.to_string(),
                details: HOSTILE_DETAIL.to_string(),
            },
            "invalid TLS material source",
        ),
    ] {
        assert!(std::error::Error::source(&error).is_none());
        assert_rendered(error.into(), &[reason]);
    }
    assert_rendered(
        MaterialError::Oversized {
            kind: MaterialKind::Key,
            max_bytes: 927451,
        }
        .into(),
        &["exceeds the configured maximum"],
    );
}

#[test]
fn backend_error_rendering_withholds_paths_and_opaque_details() {
    use ferrum_edge::tls::backend::TlsError;

    for error in [
        TlsError::Io {
            kind: "backend TLS client certificate",
            path: HOSTILE_SOURCE.into(),
            source: std::io::Error::other(std::io::Error::other(HOSTILE_DETAIL)),
        },
        TlsError::Pem {
            kind: "backend TLS client certificate",
            path: HOSTILE_SOURCE.into(),
            details: HOSTILE_DETAIL.to_string(),
        },
    ] {
        assert!(std::error::Error::source(&error).is_none());
        assert_rendered(
            error.into(),
            &["`backend TLS client certificate`", "Failed to"],
        );
    }
}

#[test]
fn typed_io_fields_and_os_error_causes_remain_available() {
    use ferrum_edge::tls::backend::TlsError;

    let error = MaterialError::Io {
        source_id: HOSTILE_SOURCE.to_string(),
        source: std::io::Error::from_raw_os_error(2),
    };
    let cause = std::error::Error::source(&error).unwrap();
    assert_eq!(
        cause
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(2)
    );
    let MaterialError::Io { source_id, source } = error else {
        unreachable!();
    };
    assert_eq!(source_id, HOSTILE_SOURCE);
    let error = TlsError::Io {
        kind: "backend TLS client certificate",
        path: source_id.into(),
        source,
    };
    assert!(std::error::Error::source(&error).is_some());
    assert_rendered(
        error.into(),
        &["Failed to read", "`backend TLS client certificate`"],
    );
}

#[test]
fn actual_material_loaders_withhold_hostile_references_and_reader_errors() {
    use ferrum_edge::tls::source::{load_material_blocking_with, read_bounded_material_bytes};

    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("'TLS_SOURCE_MARKER.pem");
    let source = CertSource::Path(missing);
    let error = load_material_blocking_with(&source, MaterialKind::Cert, 4096).unwrap_err();
    assert_rendered(error.into(), &["failed to read TLS material"]);

    let source = CertSource::parse(
        "file://operator:TLS_PROVIDER_MARKER@localhost/key.pem",
        MaterialKind::Key,
    );
    let error = load_material_blocking_with(&source, MaterialKind::Key, 4096).unwrap_err();
    assert_rendered(error.into(), &["invalid TLS material source"]);

    struct FailingReader;
    impl std::io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other(HOSTILE_DETAIL))
        }
    }

    let error = read_bounded_material_bytes(FailingReader, MaterialKind::Key, 4096).unwrap_err();
    assert!(std::error::Error::source(&error).is_none());
    let MaterialError::Io { source, .. } = &error else {
        panic!("expected I/O error");
    };
    assert_eq!(source.kind(), std::io::ErrorKind::Other);
    assert_eq!(source.to_string(), HOSTILE_DETAIL);
    assert_rendered(error.into(), &["failed to read TLS material"]);
}

#[test]
fn tls_policy_rendering_keeps_fields_and_suggestions_without_values() {
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::tls::TlsPolicy;

    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    for value in [HOSTILE_SOURCE, "927451", "true"] {
        let config = EnvConfig {
            tls_cipher_suites: Some(value.to_string()),
            ..EnvConfig::default()
        };
        assert_rendered(
            TlsPolicy::from_env_config(&config).unwrap_err(),
            &[
                "`FERRUM_TLS_CIPHER_SUITES`",
                "Unknown cipher suite",
                "`TLS_AES_128_GCM_SHA256`",
            ],
        );
        let config = EnvConfig {
            tls_curves: Some(value.to_string()),
            ..EnvConfig::default()
        };
        assert_rendered(
            TlsPolicy::from_env_config(&config).unwrap_err(),
            &[
                "`FERRUM_TLS_KEY_EXCHANGE_GROUPS`",
                "Unknown curve/group",
                "`secp256r1`",
            ],
        );
        let config = EnvConfig {
            tls_min_version: value.to_string(),
            tls_max_version: value.to_string(),
            ..EnvConfig::default()
        };
        assert_rendered(
            TlsPolicy::from_env_config(&config).unwrap_err(),
            &[
                "`FERRUM_TLS_MIN_VERSION`",
                "`FERRUM_TLS_MAX_VERSION`",
                "No valid TLS versions",
            ],
        );
    }
}

/// The four schemes whose identifier is a secret source reference, with an
/// identifier shaped like the real thing for each.
const PROVIDER_URIS: [&str; 4] = [
    "vault://secret/data/gateway/tls#server-key",
    "aws://arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/tls-AbCdEf",
    "azure://https://gw-prod-kv.vault.azure.net/secrets/tls-key/9f2c",
    "gcp://projects/prod-1234/secrets/tls-key/versions/7",
];

/// Everything after the scheme — the part that names the secret and must never
/// be echoed. Derived rather than hand-listed so the assertion covers the whole
/// identifier instead of a chosen fragment of it.
fn identifier_of(raw: &str) -> &str {
    raw.split_once("://").expect("fixture must be a URI").1
}

fn scheme_of(raw: &str) -> &str {
    raw.split_once("://").expect("fixture must be a URI").0
}

fn uri_source(raw: &str) -> CertSource {
    CertSource::parse(raw, MaterialKind::Key)
}

#[test]
fn provider_schemes_are_classified_as_secret_sources() {
    let providers = [
        SourceScheme::Vault,
        SourceScheme::Aws,
        SourceScheme::Azure,
        SourceScheme::Gcp,
    ];
    for scheme in providers {
        assert!(
            scheme.is_secret_provider(),
            "{} addresses an external secret provider",
            scheme.as_str()
        );
    }

    // Local configuration, not a provider reference. Display helpers retain
    // these identifiers; diagnostic producers must still quote/sanitize them.
    let local = [
        SourceScheme::File,
        SourceScheme::K8sSecret,
        SourceScheme::Acme,
        SourceScheme::Managed,
        SourceScheme::Pkcs11,
    ];
    for scheme in local {
        assert!(
            !scheme.is_secret_provider(),
            "{} is local configuration",
            scheme.as_str()
        );
    }
}

#[test]
fn redacted_source_id_withholds_the_provider_identifier() {
    for raw in PROVIDER_URIS {
        let redacted = uri_source(raw).redacted_source_id();
        assert!(
            !redacted.contains(identifier_of(raw)),
            "the identifier must not survive: {redacted}"
        );
        // The provider label is retained: it is a bounded, fixed-set value that
        // tells an operator which backend to go look at.
        let label = format!("{}://", scheme_of(raw));
        assert!(
            redacted.starts_with(&label),
            "the provider label must be kept for operators: {redacted}"
        );
    }
}

/// The cited path. `load_secret_material` wraps a failed fetch as
/// `MaterialError::Secret { source_id, details }`, and `Display` prints both.
#[test]
fn material_error_display_withholds_the_provider_identifier() {
    for raw in PROVIDER_URIS {
        let error = MaterialError::Secret {
            source_id: uri_source(raw).redacted_source_id(),
            details: "permission denied".to_string(),
        };
        let rendered = error.to_string();
        assert!(
            !rendered.contains(identifier_of(raw)),
            "the wrapper must not re-disclose what the detail scrubbed: {rendered}"
        );
        // The failure class stays actionable.
        assert!(rendered.contains("permission denied"));
    }
}

/// `source_id` is an *identity* — it keys TLS inventory entries and event
/// filters — so it is deliberately not redacted in place, and distinct provider
/// sources must stay distinguishable from each other.
#[test]
fn identity_source_id_is_unchanged_and_still_distinguishing() {
    let first = uri_source("vault://secret/data/gateway/tls#cert");
    let second = uri_source("vault://secret/data/gateway/tls#key");
    assert_ne!(
        first.source_id(),
        second.source_id(),
        "inventory and event filtering depend on these staying distinct"
    );
    assert!(first.source_id().contains("secret/data/gateway/tls"));
    // ...but both collapse to the same non-secret label for operator output.
    assert_eq!(first.redacted_source_id(), second.redacted_source_id());
}

/// Non-provider display helpers retain the configured identity. Configuration
/// diagnostics withhold this supplied text at the rendering/emission boundary.
#[test]
fn non_provider_sources_are_reported_verbatim() {
    let path = uri_source("file:///etc/ferrum/tls/server.pem");
    assert_eq!(path.redacted_source_id(), path.source_id());

    let bare = CertSource::parse("/etc/ferrum/tls/server.pem", MaterialKind::Cert);
    assert_eq!(bare.redacted_source_id(), bare.source_id());
    assert!(bare.redacted_source_id().contains("server.pem"));

    let local = [
        "k8s://ferrum/tls-secret#tls.crt",
        "acme://certificates/edge-cert#cert",
        "managed://edge-cert#cert",
    ];
    for raw in local {
        let source = uri_source(raw);
        assert_eq!(
            source.redacted_source_id(),
            source.source_id(),
            "{raw} is local configuration, not a secret reference"
        );
    }
}

/// A provider URI's query options are part of the same secret reference as its
/// identifier, so they must be withheld on the same test.
///
/// `subscription::source_poll_interval` logs the offending `?poll=` value beside
/// `redacted_source_id()` when it cannot be parsed. Redacting the identifier and
/// then printing an option out of the same URI re-disclosed a slice of exactly
/// what was just withheld. The textual backstop cannot cover it either: it
/// matches a candidate *inside* a message, and the printed option is a
/// **substring of** the resolved URI rather than the other way round, so no
/// candidate ever matches.
#[test]
fn provider_uri_option_values_are_withheld() {
    const POLL_SENTINEL: &str = "poll-option-sentinel-must-not-be-printed";
    for raw in PROVIDER_URIS {
        let source = uri_source(&format!("{raw}?poll={POLL_SENTINEL}"));
        let CertSource::Uri(uri) = &source else {
            panic!("{raw} must parse as a URI source");
        };
        let rendered = uri.redacted_option_value(POLL_SENTINEL);
        assert!(
            !rendered.contains(POLL_SENTINEL),
            "{raw}: a provider URI's option value must not be echoed, got: {rendered}"
        );
        assert_eq!(
            rendered,
            ferrum_edge::secrets::EXTERNAL_SECRET_PLACEHOLDER,
            "{raw}: the option must be withheld with the shared placeholder"
        );
    }
}

/// Non-vacuity control for the above: a locally configured source keeps its
/// option value verbatim.
///
/// Without this, withholding unconditionally would pass the redaction assertion
/// while destroying the diagnostic. `file`/`k8s`/`acme`/`managed` URIs are
/// operator-authored local configuration — a malformed `?poll=` there is a
/// typo the operator must be able to see, and the same reasoning already keeps
/// their identifiers verbatim in `non_provider_sources_are_reported_verbatim`.
///
/// This process resolved no external secrets, so the provenance test is `false`
/// and only the scheme test applies.
#[test]
fn local_source_option_values_stay_verbatim() {
    let local = [
        "file:///etc/ferrum/tls/server.pem",
        "k8s://ferrum/tls-secret#tls.crt",
        "acme://certificates/edge-cert#cert",
        "managed://edge-cert#cert",
    ];
    for raw in local {
        let source = uri_source(&format!("{raw}?poll=nope"));
        let CertSource::Uri(uri) = &source else {
            panic!("{raw} must parse as a URI source");
        };
        assert_eq!(
            uri.redacted_option_value("nope"),
            "nope",
            "{raw} is local configuration; its malformed option must stay diagnosable"
        );
    }
}

/// Inline PEM keeps its existing constant, which already discloses nothing.
#[test]
fn inline_pem_stays_redacted() {
    let pem = "-----BEGIN CERTIFICATE-----\nAAA\n";
    let inline = CertSource::parse(pem, MaterialKind::Cert);
    assert_eq!(inline.redacted_source_id(), inline.source_id());
    assert!(!inline.redacted_source_id().contains("BEGIN CERTIFICATE"));
}

// ── identity vs. display: the two must not be the same string ───────────────
//
// `MaterializedMaterial` carries only the *display* rendering, and it is
// redacted at the producer. That is safe precisely because nothing keys off it:
// every consumer that needs to tell two sources apart reads the configured
// `CertSource`. The tests below pin both halves of that split — the field is
// non-disclosing, and the identity consumers stayed distinguishing.

/// The materialized value carries the redacted label and nothing else, on the
/// struct's `Debug` as well as its field.
///
/// `MaterializedMaterial` is `Debug`-formatted into diagnostics, so a raw
/// identifier stored here would leak through `{:?}` even at call sites that
/// never touch the field by name.
#[test]
fn materialized_material_debug_withholds_the_provider_identifier() {
    for raw in PROVIDER_URIS {
        let material = MaterializedMaterial::from_bytes(
            b"-----BEGIN CERTIFICATE-----\nAAA\n".to_vec(),
            SourceScheme::Vault,
            uri_source(raw).redacted_source_id(),
            MaterialKind::Cert,
            None,
        );
        assert!(
            !material.display_source_id.contains(identifier_of(raw)),
            "the display label must not carry the identifier: {}",
            material.display_source_id
        );
        let rendered = format!("{material:?}");
        assert!(
            !rendered.contains(identifier_of(raw)),
            "Debug must not re-disclose the identifier: {rendered}"
        );
        // The bytes are redacted by `SecretBytes` as before.
        assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
    }
}

/// The rotation predicate keeps seeing a source change.
///
/// `MaterialSetFingerprint` equality is what decides whether TLS material is
/// rebuilt, and `tls::events` derives `cert_id`, `source_id`, and its
/// source-id filter from these same entries. The entry's `source_id` therefore
/// comes from the **configured** `CertSource`, never from
/// `MaterializedMaterial::display_source_id` — which is redacted, so every
/// provider reference under one scheme renders identically and two distinct
/// references with equal bytes and version would compare equal.
///
/// Driven with `file://` sources because a provider fetch needs a live backend,
/// but the property under test is the same one and is visible here: the two
/// files hold **identical bytes**, so `fingerprint` and `version` match exactly
/// and only the source identity can tell the entries apart. It also pins the
/// specific regression shape, since a `file://` source's configured id
/// (`file:///path`) and its materialized display id (the bare `/path`) are
/// different strings.
#[test]
fn identical_material_under_different_references_stays_distinguishable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pem = b"-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----\n";
    let first_path = dir.path().join("first.pem");
    let second_path = dir.path().join("second.pem");
    std::fs::write(&first_path, pem).expect("write first");
    std::fs::write(&second_path, pem).expect("write second");

    let watched = |path: &std::path::Path| {
        WatchedMaterialSource::new(
            "test-cert",
            CertSource::parse(format!("file://{}", path.display()), MaterialKind::Cert),
            MaterialKind::Cert,
        )
    };

    let first = material_set_fingerprint(&[watched(&first_path)]).expect("first fingerprint");
    let second = material_set_fingerprint(&[watched(&second_path)]).expect("second fingerprint");

    assert_eq!(
        first.entries[0].fingerprint, second.entries[0].fingerprint,
        "the fixture is only meaningful if the bytes really are identical"
    );
    assert_ne!(
        first, second,
        "a changed source reference must remain visible to the rotation predicate \
         even when the material behind it is byte-identical"
    );

    // The identity recorded is the configured source id, which is also what
    // `events::event_material_from_source` reports for a not-yet-loaded source,
    // so both event paths agree on one identity for the same source.
    assert_eq!(
        first.entries[0].source_id,
        CertSource::parse(
            format!("file://{}", first_path.display()),
            MaterialKind::Cert
        )
        .source_id(),
    );
}
