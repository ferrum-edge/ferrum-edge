//! Polymorphic TLS material sources.
//!
//! Phase 1 keeps existing path-oriented callers working while introducing the
//! common source substrate used by later live-rotation work. Values parse as:
//! inline PEM when they start with `-----BEGIN `, typed URI when the scheme is
//! known, and filesystem path otherwise.

pub mod subscription;

use futures_util::stream::BoxStream;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use zeroize::Zeroizing;

/// TLS material kind expected from a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaterialKind {
    Cert,
    Key,
    CaBundle,
    Crl,
    Jwks,
    Ocsp,
    Unknown,
}

impl MaterialKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "cert" | "certificate" | "chain" => Some(Self::Cert),
            "key" | "private_key" | "private-key" => Some(Self::Key),
            "ca" | "ca_bundle" | "ca-bundle" | "ca_cert" | "ca-cert" => Some(Self::CaBundle),
            "crl" => Some(Self::Crl),
            "jwks" => Some(Self::Jwks),
            "ocsp" | "ocsp_response" | "ocsp-response" => Some(Self::Ocsp),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cert => "cert",
            Self::Key => "key",
            Self::CaBundle => "ca_bundle",
            Self::Crl => "crl",
            Self::Jwks => "jwks",
            Self::Ocsp => "ocsp",
            Self::Unknown => "unknown",
        }
    }
}

/// Source URI scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceScheme {
    File,
    Vault,
    Aws,
    Azure,
    Gcp,
    K8sSecret,
    Acme,
    Managed,
    Pkcs11,
}

impl SourceScheme {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "file" => Some(Self::File),
            "vault" => Some(Self::Vault),
            "aws" => Some(Self::Aws),
            "azure" => Some(Self::Azure),
            "gcp" => Some(Self::Gcp),
            "k8s" | "kubernetes" | "k8s-secret" => Some(Self::K8sSecret),
            "acme" => Some(Self::Acme),
            "managed" => Some(Self::Managed),
            "pkcs11" => Some(Self::Pkcs11),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Vault => "vault",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
            Self::K8sSecret => "k8s",
            Self::Acme => "acme",
            Self::Managed => "managed",
            Self::Pkcs11 => "pkcs11",
        }
    }

    /// True when this scheme addresses an external secret provider, so its
    /// identifier is a *secret source reference* rather than ordinary local
    /// configuration.
    ///
    /// These are the four schemes whose identifier is a Vault path, an ARN or
    /// secret name, a Key Vault URL, or a GCP secret resource name — the exact
    /// class `secrets::registry::redact_source_reference` already withholds
    /// from backend error text. `file`/`k8s`/`acme`/`managed`/`pkcs11`
    /// identifiers are operator-authored local configuration that appears in
    /// the settings file and is needed verbatim to act on a diagnostic, so they
    /// are deliberately not included.
    pub fn is_secret_provider(self) -> bool {
        matches!(self, Self::Vault | Self::Aws | Self::Azure | Self::Gcp)
    }
}

/// Redacted string wrapper for inline PEM material.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Redacted byte wrapper for materialized PEM/DER bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Parsed typed source URI.
#[derive(Clone, Eq)]
pub struct CertSourceUri {
    pub scheme: SourceScheme,
    pub identifier: String,
    pub kind: MaterialKind,
    pub options: BTreeMap<String, String>,
    /// The complete configured string this URI was parsed from, before the
    /// query was split off. **Provenance only** — never an identity, never
    /// operator-facing.
    ///
    /// [`Self::redacted_option_value`] has to ask whether *this whole value* was
    /// externally materialized, and nothing else on this struct can answer that.
    /// `parse` drops the query before [`Self::source_id`] reconstructs
    /// the identity, so for a source resolved as `file://x?poll=p` the id is
    /// `file://x` — a strict prefix of what was resolved, equal to no resolved
    /// value. Asking `secrets::is_external_secret_value` about the id therefore
    /// answers `false` on genuinely secret material and the option gets printed.
    ///
    /// Excluded from [`PartialEq`] deliberately. `CertSource` equality reaches
    /// `subscription::MaterialFingerprintEntry`, whose `Eq` **is** the rotation
    /// predicate, and identity there is the *parsed* source —
    /// scheme/identifier/kind/options. Two spellings that parse to the same
    /// source are the same source; letting a raw-text difference compare unequal
    /// would report a rotation that never happened.
    raw: String,
}

impl PartialEq for CertSourceUri {
    /// Compares the *parsed* source, not the text it was written as — see
    /// the `raw` field.
    fn eq(&self, other: &Self) -> bool {
        self.scheme == other.scheme
            && self.identifier == other.identifier
            && self.kind == other.kind
            && self.options == other.options
    }
}

impl fmt::Debug for CertSourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertSourceUri")
            .field("scheme", &self.scheme)
            .field("identifier", &self.identifier)
            .field("kind", &self.kind)
            .field("options", &self.options)
            .finish()
    }
}

impl CertSourceUri {
    fn parse(raw: &str, fallback_kind: MaterialKind) -> Option<Self> {
        let (scheme_raw, rest) = raw.split_once("://")?;
        let scheme = SourceScheme::parse(scheme_raw)?;
        let (identifier, query) = match rest.split_once('?') {
            Some((identifier, query)) => (identifier.to_string(), Some(query)),
            None => (rest.to_string(), None),
        };
        let options = query.map(parse_options).unwrap_or_default();
        let kind = options
            .get("kind")
            .and_then(|value| MaterialKind::parse(value))
            .unwrap_or(fallback_kind);

        Some(Self {
            scheme,
            identifier,
            kind,
            options,
            raw: raw.to_string(),
        })
    }

    pub fn source_id(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.identifier)
    }

    /// [`Self::source_id`] with a secret provider's identifier withheld — the
    /// form that is safe to put in an operator-facing error or log record.
    ///
    /// [`Self::source_id`] is an *identity*: it keys TLS inventory entries and
    /// event filters (`tls::events`), so it must stay distinguishing and is not
    /// redacted in place. But it is also what the `MaterialError` variants
    /// interpolate, and their `Display` reaches `validate` output and startup
    /// logs. For a `vault://`/`aws://`/`azure://`/`gcp://` source that means the
    /// full secret path, ARN, or Key Vault URL was printed even though the
    /// backend's own error detail beside it had already been scrubbed by
    /// `secrets::registry::redact_source_reference` — the reference leaked
    /// through the wrapper instead of through the detail.
    ///
    /// The scheme is retained rather than dropped: it is a bounded, fixed-set
    /// label that tells an operator which provider to go look at, and it
    /// discloses nothing the configuration does not already state. Only the
    /// identifier is withheld.
    pub fn redacted_source_id(&self) -> String {
        if self.scheme.is_secret_provider() {
            format!("{}://{}", self.scheme.as_str(), REDACTED_IDENTIFIER)
        } else {
            self.source_id()
        }
    }

    /// Render one of this URI's query-option values for an operator-facing
    /// diagnostic, withholding it when the URI it came from is secret material.
    ///
    /// [`Self::redacted_source_id`] withholds the *identifier*, but the query
    /// string is part of the same configured value, and an option logged beside
    /// the redacted identifier re-disclosed a slice of what was just withheld:
    /// `vault://secret/data/cert?poll=<token>` printed `<token>` verbatim.
    ///
    /// The textual backstop cannot reach it. `secrets::redact_external_secret_values`
    /// matches a candidate *inside* a message, and here the containment is
    /// inverted — the printed option is a **substring of** the resolved URI, so
    /// the URI candidate never matches it. Deriving each query value into its own
    /// candidate was rejected for the reason
    /// [`RedactionPlan::MIN_DERIVED_CANDIDATE_LEN`][min] gives: arming short,
    /// arbitrary option values process-wide shreds unrelated output.
    ///
    /// Two provenance tests, matching the two ways the value can be secret:
    ///
    /// 1. A secret-provider scheme (`vault`/`aws`/`azure`/`gcp`) — the whole URI
    ///    is a secret reference, so its options are too. Same classifier as
    ///    [`Self::redacted_source_id`], so identifier and options cannot diverge.
    ///    This test is independent of the second and is applied first: a
    ///    provider URI withholds its options whether or not it was itself
    ///    externally materialized.
    /// 2. The complete configured URI was externally materialized
    ///    ([`crate::secrets::is_external_secret_value`]) — a `file://` source
    ///    resolved from `FERRUM_FRONTEND_TLS_CERT_SOURCE_FILE` is
    ///    operator-authored in shape but secret in provenance, and its
    ///    `source_id` is otherwise printed verbatim.
    ///
    /// The second test is against the `raw` field, the string as configured, and
    /// asks for **whole-value equality** — not whether a candidate occurs
    /// somewhere inside the parsed identity. Both halves of that matter:
    ///
    /// * [`Self::source_id`] is the wrong input. `parse` strips the
    ///   query before it is reconstructed, so a source resolved as
    ///   `file://x?poll=p` yields `file://x` — a strict prefix of the secret
    ///   that equals no resolved value and contains no whole candidate (the
    ///   one-byte identifier is below `MIN_DERIVED_CANDIDATE_LEN`). The raw
    ///   `poll` option would then be logged despite coming from the secret.
    /// * Containment is the wrong question. Any unrelated resolved value that
    ///   happens to appear inside a locally configured identifier would answer
    ///   `true` — coincidence, not origin — and would withhold an ordinary local
    ///   diagnostic the operator needs.
    ///
    /// Equality needs no minimum length and arms nothing process-wide, so a
    /// one- or two-byte identifier and option are covered exactly.
    ///
    /// Otherwise the value is returned unchanged: `file`/`k8s`/`acme`/`managed`/
    /// `pkcs11` sources that were configured locally are ordinary operator input,
    /// and a malformed option there must stay diagnosable.
    ///
    /// [min]: crate::secrets
    pub fn redacted_option_value(&self, rendered: &str) -> String {
        if self.scheme.is_secret_provider() || crate::secrets::is_external_secret_value(&self.raw) {
            return crate::secrets::EXTERNAL_SECRET_PLACEHOLDER.to_string();
        }
        // The option is not itself secret-derived, but the text may still quote
        // some *other* resolved variable's value verbatim. A no-op in a process
        // that resolved no external secrets.
        crate::secrets::redact_external_secret_values(rendered)
    }
}

/// Substituted for a secret provider's identifier in operator-facing output.
const REDACTED_IDENTIFIER: &str = "<redacted source reference>";

fn parse_options(query: &str) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

/// Configured source of TLS material.
#[derive(Clone, PartialEq, Eq)]
pub enum CertSource {
    Path(PathBuf),
    InlinePem(SecretString),
    Uri(CertSourceUri),
}

impl CertSource {
    pub fn parse(raw: impl Into<String>, kind: MaterialKind) -> Self {
        let raw = raw.into();
        if raw.starts_with("-----BEGIN ") {
            return Self::InlinePem(SecretString::new(raw));
        }
        if let Some(uri) = CertSourceUri::parse(&raw, kind) {
            return Self::Uri(uri);
        }
        Self::Path(PathBuf::from(raw))
    }

    #[allow(dead_code)]
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    #[allow(dead_code)]
    pub fn kind(&self) -> MaterialKind {
        match self {
            Self::Path(_) | Self::InlinePem(_) => MaterialKind::Unknown,
            Self::Uri(uri) => uri.kind,
        }
    }

    pub fn source_id(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
            Self::InlinePem(_) => "inline-pem:<redacted>".to_string(),
            Self::Uri(uri) => uri.source_id(),
        }
    }

    /// [`Self::source_id`] safe for operator-facing output — see
    /// [`CertSourceUri::redacted_source_id`]. Non-URI sources are unchanged.
    pub fn redacted_source_id(&self) -> String {
        match self {
            Self::Uri(uri) => uri.redacted_source_id(),
            other => other.source_id(),
        }
    }

    /// Stable, non-secret component suitable for cache and pool keys.
    ///
    /// Inline PEM intentionally redacts to a constant source id, so cache keys
    /// use a digest to avoid collisions without storing PEM bytes in key
    /// strings.
    pub fn pool_key_component(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
            Self::InlinePem(secret) => {
                let digest = Sha256::digest(secret.expose_secret().as_bytes());
                format!("inline-pem:sha256:{}", hex::encode(digest))
            }
            Self::Uri(_) => self.to_config_value(),
        }
    }

    pub fn as_file_path(&self) -> Option<PathBuf> {
        match self {
            Self::Path(path) => Some(path.clone()),
            Self::Uri(uri) if uri.scheme == SourceScheme::File => {
                uri_file_path(&uri.identifier).map(PathBuf::from)
            }
            _ => None,
        }
    }

    pub fn to_config_value(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
            Self::InlinePem(secret) => secret.expose_secret().to_string(),
            Self::Uri(uri) => {
                if uri.options.is_empty() {
                    uri.source_id()
                } else {
                    let query = uri
                        .options
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>()
                        .join("&");
                    format!("{}://{}?{}", uri.scheme.as_str(), uri.identifier, query)
                }
            }
        }
    }
}

impl fmt::Debug for CertSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => f.debug_tuple("Path").field(path).finish(),
            Self::InlinePem(_) => f.write_str("InlinePem(<redacted>)"),
            Self::Uri(uri) => f.debug_tuple("Uri").field(uri).finish(),
        }
    }
}

impl Serialize for CertSource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_config_value())
    }
}

impl<'de> Deserialize<'de> for CertSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::parse(raw, MaterialKind::Unknown))
    }
}

fn uri_file_path(identifier: &str) -> Option<String> {
    if identifier.is_empty() {
        return None;
    }
    if identifier.starts_with('/') {
        return Some(identifier.to_string());
    }
    Some(identifier.to_string())
}

#[derive(Debug, Error)]
pub enum MaterialError {
    #[error("failed to read TLS material from {source_id}: {source}")]
    Io {
        source_id: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS material source scheme {scheme} is not supported by this runtime loader")]
    UnsupportedScheme { scheme: &'static str },
    #[error("failed to resolve TLS material source {source_id}: {details}")]
    Secret { source_id: String, details: String },
    #[error("invalid TLS material source {source_id}: {details}")]
    InvalidSource { source_id: String, details: String },
}

pub struct MaterializedMaterial {
    pub bytes: SecretBytes,
    pub fingerprint: [u8; 32],
    pub version: Option<String>,
    pub fetched_at: SystemTime,
    pub source_kind: SourceScheme,
    /// **Operator-facing label only. Never an identity.**
    ///
    /// This is the redacted rendering of the source the material came from
    /// (`CertSource::redacted_source_id`): for a `vault://`/`aws://`/`azure://`/
    /// `gcp://` source it is the provider label with the identifier withheld, so
    /// two *different* references under one provider render identically. It is
    /// named `display_` rather than `source_id` precisely so that nothing can
    /// use it for equality, keying, filtering, or rotation detection by
    /// accident — every producer of this struct stamps a redacted value, and a
    /// consumer that needs to tell two sources apart must go back to the
    /// `CertSource` and call [`CertSource::source_id`].
    ///
    /// It exists as a field rather than being re-derived at each print site
    /// because it is interpolated into PEM-parse and verifier-construction
    /// failures across `tls::mod`, `tls::backend`, `dtls`, `identity::file_loader`,
    /// `config::types`, `config::mongo_store`, `ldap_auth`, `tcp_logging`,
    /// `ws_logging`, `soap_ws_security`, `spec_expose`, `http_client`, and
    /// `modes::mesh` — one producer is the only enforceable point.
    pub display_source_id: String,
    pub kind: MaterialKind,
}

impl fmt::Debug for MaterializedMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaterializedMaterial")
            .field("bytes", &self.bytes)
            .field("fingerprint", &hex::encode(self.fingerprint))
            .field("version", &self.version)
            .field("fetched_at", &self.fetched_at)
            .field("source_kind", &self.source_kind)
            // Redacted by construction — see the field's own documentation.
            .field("display_source_id", &self.display_source_id)
            .field("kind", &self.kind)
            .finish()
    }
}

impl MaterializedMaterial {
    /// `display_source_id` must already be redacted; callers pass
    /// [`CertSource::redacted_source_id`] or an equivalent non-secret label.
    pub fn from_bytes(
        bytes: Vec<u8>,
        source_kind: SourceScheme,
        display_source_id: String,
        kind: MaterialKind,
        version: Option<String>,
    ) -> Self {
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&Sha256::digest(&bytes));
        Self {
            bytes: SecretBytes::new(bytes),
            fingerprint,
            version,
            fetched_at: SystemTime::now(),
            source_kind,
            display_source_id,
            kind,
        }
    }
}

#[allow(dead_code)]
pub enum MaterialWatch {
    Fingerprint(BoxStream<'static, Result<MaterializedMaterial, MaterialError>>),
    PollOnly { interval: Duration },
}

#[allow(dead_code)]
#[async_trait::async_trait]
pub trait MaterialLoader: Send + Sync + 'static {
    fn scheme(&self) -> SourceScheme;
    async fn load(&self, uri: &CertSourceUri) -> Result<MaterializedMaterial, MaterialError>;
    async fn watch(&self, uri: &CertSourceUri) -> Result<MaterialWatch, MaterialError>;
}

/// Synchronous Phase 1 materialization for startup paths.
pub fn load_material_blocking(
    source: &CertSource,
    fallback_kind: MaterialKind,
) -> Result<MaterializedMaterial, MaterialError> {
    match source {
        CertSource::Path(path) => load_file_material(path, fallback_kind),
        CertSource::InlinePem(secret) => Ok(MaterializedMaterial::from_bytes(
            secret.expose_secret().as_bytes().to_vec(),
            SourceScheme::File,
            "inline-pem:<redacted>".to_string(),
            fallback_kind,
            None,
        )),
        CertSource::Uri(uri) if uri.scheme == SourceScheme::File => {
            let path =
                uri_file_path(&uri.identifier).ok_or_else(|| MaterialError::InvalidSource {
                    source_id: uri.redacted_source_id(),
                    details: "file URI has no path".to_string(),
                })?;
            load_file_material(Path::new(&path), uri.kind)
        }
        CertSource::Uri(uri)
            if matches!(
                uri.scheme,
                SourceScheme::Vault | SourceScheme::Aws | SourceScheme::Azure | SourceScheme::Gcp
            ) =>
        {
            load_secret_material(uri, fallback_kind)
        }
        CertSource::Uri(uri) if uri.scheme == SourceScheme::K8sSecret => {
            load_k8s_secret_material(uri, fallback_kind)
        }
        CertSource::Uri(uri) if uri.scheme == SourceScheme::Acme => {
            load_acme_material(uri, fallback_kind)
        }
        CertSource::Uri(uri) if uri.scheme == SourceScheme::Managed => {
            load_managed_material(uri, fallback_kind)
        }
        CertSource::Uri(uri) => Err(MaterialError::UnsupportedScheme {
            scheme: uri.scheme.as_str(),
        }),
    }
}

fn load_file_material(
    path: &Path,
    fallback_kind: MaterialKind,
) -> Result<MaterializedMaterial, MaterialError> {
    let source_id = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|source| MaterialError::Io {
        source_id: source_id.clone(),
        source,
    })?;
    Ok(MaterializedMaterial::from_bytes(
        bytes,
        SourceScheme::File,
        source_id,
        fallback_kind,
        None,
    ))
}

fn load_secret_material(
    uri: &CertSourceUri,
    fallback_kind: MaterialKind,
) -> Result<MaterializedMaterial, MaterialError> {
    if !secret_scheme_supported_in_build(uri.scheme) {
        return Err(MaterialError::UnsupportedScheme {
            scheme: uri.scheme.as_str(),
        });
    }

    // Provider-only, never the Vault path / ARN / Key Vault URL. This is both
    // the error wrapper's `source_id` and the materialized value's, because the
    // latter is interpolated into PEM-parse and verifier-construction failures
    // all over the tree (`tls::mod`, `identity::file_loader`, `ldap_auth`,
    // `tcp_logging`, `ws_logging`, `soap_ws_security`, `spec_expose`,
    // `http_client`, `mongo_store`, `modes::mesh`) — one producer is the only
    // place this can be enforced. `resolved.source` is the registry's
    // `<provider>:<identifier>` rendering and carries the reference too, so it
    // is deliberately not used here.
    let source_id = uri.redacted_source_id();
    let scheme = uri.scheme;
    let configured_version = uri.options.get("version").cloned();
    let key = format!("TLS {} material", uri.kind.as_str());

    // Azure: merge path `/<version>` with typed `?version=` (reject conflicts)
    // into the *fetch* reference only. Configured source identity stays on
    // `uri.identifier` + `uri.options` so distinct spellings do not collapse.
    let fetch_identifier = {
        #[cfg(feature = "secrets-azure")]
        {
            if scheme == SourceScheme::Azure {
                crate::secrets::azure_apply_tls_version_option(
                    &uri.identifier,
                    configured_version.as_deref(),
                    &key,
                )
                .map_err(|details| MaterialError::InvalidSource {
                    source_id: source_id.clone(),
                    details,
                })?
            } else {
                uri.identifier.clone()
            }
        }
        #[cfg(not(feature = "secrets-azure"))]
        {
            uri.identifier.clone()
        }
    };

    let resolved =
        resolve_secret_reference_blocking(scheme.as_str().to_string(), fetch_identifier, key)
            .map_err(|details| MaterialError::Secret {
                source_id: source_id.clone(),
                details,
            })?;

    // Azure material reports the version Key Vault actually returned. Other
    // providers keep the historical configured `?version=` metadata label.
    let version = match scheme {
        #[cfg(feature = "secrets-azure")]
        SourceScheme::Azure => resolved.version,
        _ => configured_version,
    };

    Ok(MaterializedMaterial::from_bytes(
        resolved.value.into_bytes(),
        scheme,
        source_id,
        if uri.kind == MaterialKind::Unknown {
            fallback_kind
        } else {
            uri.kind
        },
        version,
    ))
}

fn load_k8s_secret_material(
    uri: &CertSourceUri,
    fallback_kind: MaterialKind,
) -> Result<MaterializedMaterial, MaterialError> {
    let reference = K8sSecretReference::parse(uri, fallback_kind)?;
    let fetched =
        resolve_k8s_secret_reference_blocking(reference.namespace.clone(), reference.name.clone())
            .map_err(|details| MaterialError::Secret {
                source_id: reference.source_id.clone(),
                details,
            })?;

    let bytes = fetched
        .data
        .get(&reference.data_key)
        .map(|value| value.0.clone())
        .ok_or_else(|| MaterialError::InvalidSource {
            source_id: reference.source_id.clone(),
            details: format!(
                "Kubernetes Secret {}/{} does not contain data key {}",
                reference.namespace, reference.name, reference.data_key
            ),
        })?;

    Ok(MaterializedMaterial::from_bytes(
        bytes,
        SourceScheme::K8sSecret,
        reference.source_id,
        reference.kind,
        fetched.resource_version,
    ))
}

fn load_managed_material(
    uri: &CertSourceUri,
    fallback_kind: MaterialKind,
) -> Result<MaterializedMaterial, MaterialError> {
    let kind = if uri.kind == MaterialKind::Unknown {
        fallback_kind
    } else {
        uri.kind
    };
    let store = crate::tls::managed::global_store().map_err(|details| MaterialError::Secret {
        source_id: uri.redacted_source_id(),
        details,
    })?;
    let material =
        store
            .material(&uri.identifier, kind)
            .map_err(|error| MaterialError::InvalidSource {
                source_id: uri.redacted_source_id(),
                details: error.to_string(),
            })?;
    Ok(MaterializedMaterial::from_bytes(
        material.bytes,
        SourceScheme::Managed,
        // `managed::ManagedMaterial`, not a `MaterializedMaterial`. `managed`
        // is not a secret-provider scheme, so its id is local configuration and
        // is already safe as a display label.
        material.source_id,
        material.kind,
        material.version,
    ))
}

fn load_acme_material(
    uri: &CertSourceUri,
    fallback_kind: MaterialKind,
) -> Result<MaterializedMaterial, MaterialError> {
    let kind = if uri.kind == MaterialKind::Unknown {
        fallback_kind
    } else {
        uri.kind
    };
    let store =
        crate::tls::acme::global_certificate_store().map_err(|details| MaterialError::Secret {
            source_id: uri.redacted_source_id(),
            details,
        })?;
    let material =
        store
            .material(&uri.identifier, kind)
            .map_err(|error| MaterialError::InvalidSource {
                source_id: uri.redacted_source_id(),
                details: error.to_string(),
            })?;
    Ok(MaterializedMaterial::from_bytes(
        material.bytes,
        SourceScheme::Acme,
        // `acme::AcmeMaterial`, not a `MaterializedMaterial` — see the managed
        // loader above for why this id is already safe to display.
        material.source_id,
        material.kind,
        material.version,
    ))
}

#[derive(Debug)]
struct K8sSecretReference {
    namespace: String,
    name: String,
    data_key: String,
    kind: MaterialKind,
    source_id: String,
}

impl K8sSecretReference {
    fn parse(uri: &CertSourceUri, fallback_kind: MaterialKind) -> Result<Self, MaterialError> {
        let source_id = uri.source_id();
        let (path, fragment_key) = match uri.identifier.split_once('#') {
            Some((path, key)) => (path, Some(key)),
            None => (uri.identifier.as_str(), None),
        };
        let mut path_parts = path.split('/');
        let namespace = path_parts.next().unwrap_or_default();
        let name = path_parts.next().unwrap_or_default();
        if path_parts.next().is_some() || namespace.is_empty() || name.is_empty() {
            return Err(MaterialError::InvalidSource {
                source_id,
                details: "Kubernetes Secret source must be k8s://<namespace>/<secret>#<data-key>"
                    .to_string(),
            });
        }
        validate_k8s_identifier_component(&source_id, "namespace", namespace, 63)?;
        validate_k8s_identifier_component(&source_id, "secret name", name, 253)?;

        let option_key = uri.options.get("key").map(String::as_str);
        let data_key = match (fragment_key, option_key) {
            (Some(fragment), Some(option)) if fragment != option => {
                return Err(MaterialError::InvalidSource {
                    source_id,
                    details: "Kubernetes Secret source has conflicting fragment and key option"
                        .to_string(),
                });
            }
            (Some(fragment), _) => fragment.to_string(),
            (None, Some(option)) => option.to_string(),
            (None, None) => default_k8s_secret_key(uri.kind, fallback_kind)
                .ok_or_else(|| MaterialError::InvalidSource {
                    source_id: source_id.clone(),
                    details:
                        "Kubernetes Secret source must specify a data key for unknown material kind"
                            .to_string(),
                })?
                .to_string(),
        };
        validate_k8s_secret_data_key(&source_id, &data_key)?;

        let kind = if uri.kind == MaterialKind::Unknown {
            fallback_kind
        } else {
            uri.kind
        };
        let source_id = format!(
            "{}://{}/{}#{}",
            uri.scheme.as_str(),
            namespace,
            name,
            data_key
        );
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            data_key,
            kind,
            source_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct K8sSecretWatchTarget {
    pub namespace: String,
    pub name: String,
    pub source_id: String,
}

pub(crate) fn k8s_secret_watch_target(
    source: &CertSource,
    fallback_kind: MaterialKind,
) -> Option<Result<K8sSecretWatchTarget, MaterialError>> {
    let CertSource::Uri(uri) = source else {
        return None;
    };
    if uri.scheme != SourceScheme::K8sSecret {
        return None;
    }
    Some(
        K8sSecretReference::parse(uri, fallback_kind).map(|reference| K8sSecretWatchTarget {
            namespace: reference.namespace,
            name: reference.name,
            source_id: reference.source_id,
        }),
    )
}

fn default_k8s_secret_key(
    uri_kind: MaterialKind,
    fallback_kind: MaterialKind,
) -> Option<&'static str> {
    match if uri_kind == MaterialKind::Unknown {
        fallback_kind
    } else {
        uri_kind
    } {
        MaterialKind::Cert => Some("tls.crt"),
        MaterialKind::Key => Some("tls.key"),
        MaterialKind::CaBundle => Some("ca.crt"),
        MaterialKind::Crl => Some("tls.crl"),
        MaterialKind::Jwks => Some("jwks.json"),
        MaterialKind::Ocsp => Some("ocsp.der"),
        MaterialKind::Unknown => None,
    }
}

fn validate_k8s_identifier_component(
    source_id: &str,
    label: &str,
    value: &str,
    max_len: usize,
) -> Result<(), MaterialError> {
    if value.is_empty() {
        return Err(MaterialError::InvalidSource {
            source_id: source_id.to_string(),
            details: format!("Kubernetes Secret {label} is empty"),
        });
    }
    if value.len() > max_len {
        return Err(MaterialError::InvalidSource {
            source_id: source_id.to_string(),
            details: format!("Kubernetes Secret {label} exceeds {max_len} bytes"),
        });
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(MaterialError::InvalidSource {
            source_id: source_id.to_string(),
            details: format!("Kubernetes Secret {label} contains a control character"),
        });
    }
    Ok(())
}

fn validate_k8s_secret_data_key(source_id: &str, key: &str) -> Result<(), MaterialError> {
    if key.is_empty() {
        return Err(MaterialError::InvalidSource {
            source_id: source_id.to_string(),
            details: "Kubernetes Secret data key is empty".to_string(),
        });
    }
    if key.len() > 253 {
        return Err(MaterialError::InvalidSource {
            source_id: source_id.to_string(),
            details: "Kubernetes Secret data key exceeds 253 bytes".to_string(),
        });
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(MaterialError::InvalidSource {
            source_id: source_id.to_string(),
            details:
                "Kubernetes Secret data key must contain only ASCII letters, digits, '.', '-', or '_'"
                    .to_string(),
        });
    }
    Ok(())
}

struct FetchedK8sSecret {
    data: std::collections::BTreeMap<String, k8s_openapi::ByteString>,
    resource_version: Option<String>,
}

fn resolve_k8s_secret_reference_blocking(
    namespace: String,
    name: String,
) -> Result<FetchedK8sSecret, String> {
    std::thread::Builder::new()
        .name("tls-k8s-secret-source-loader".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    format!("failed to create TLS Kubernetes Secret loader runtime: {error}")
                })?;
            runtime.block_on(async move {
                let client = kube::Client::try_default()
                    .await
                    .map_err(|error| format!("failed to create Kubernetes client: {error}"))?;
                let secrets: kube::Api<k8s_openapi::api::core::v1::Secret> =
                    kube::Api::namespaced(client, &namespace);
                let secret = secrets.get(&name).await.map_err(|error| {
                    format!("failed to fetch Kubernetes Secret {namespace}/{name}: {error}")
                })?;
                let data = secret.data.unwrap_or_default();
                Ok(FetchedK8sSecret {
                    data,
                    resource_version: secret.metadata.resource_version,
                })
            })
        })
        .map_err(|error| format!("failed to spawn TLS Kubernetes Secret loader thread: {error}"))?
        .join()
        .map_err(|_| "TLS Kubernetes Secret loader thread panicked".to_string())?
}

// Each arm gates a DISTINCT `cfg!(feature = ...)`, so the
// `match_like_matches_macro` suggestion (`matches!(scheme, Vault | Aws | ...)`)
// is incorrect: in a build with only some providers enabled it would report
// every scheme as supported. clippy only sees the post-`cfg!`-expansion form
// (all arms collapse to the same bool when all features are on), hence the
// false positive — suppress it rather than change the semantics.
#[allow(clippy::match_like_matches_macro)]
fn secret_scheme_supported_in_build(scheme: SourceScheme) -> bool {
    match scheme {
        SourceScheme::Vault => cfg!(feature = "secrets-vault"),
        SourceScheme::Aws => cfg!(feature = "secrets-aws"),
        SourceScheme::Azure => cfg!(feature = "secrets-azure"),
        SourceScheme::Gcp => cfg!(feature = "secrets-gcp"),
        _ => false,
    }
}

fn resolve_secret_reference_blocking(
    scheme: String,
    identifier: String,
    key: String,
) -> Result<crate::secrets::ResolvedSecret, String> {
    std::thread::Builder::new()
        .name("tls-secret-source-loader".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("failed to create TLS secret loader runtime: {error}"))?;
            runtime.block_on(crate::secrets::resolve_external_reference(
                &scheme,
                &identifier,
                &key,
            ))
        })
        .map_err(|error| format!("failed to spawn TLS secret loader thread: {error}"))?
        .join()
        .map_err(|_| "TLS secret loader thread panicked".to_string())?
}

#[allow(dead_code)]
pub struct FileLoader;

#[async_trait::async_trait]
impl MaterialLoader for FileLoader {
    fn scheme(&self) -> SourceScheme {
        SourceScheme::File
    }

    async fn load(&self, uri: &CertSourceUri) -> Result<MaterializedMaterial, MaterialError> {
        let path = uri_file_path(&uri.identifier).ok_or_else(|| MaterialError::InvalidSource {
            source_id: uri.redacted_source_id(),
            details: "file URI has no path".to_string(),
        })?;
        load_file_material(Path::new(&path), uri.kind)
    }

    async fn watch(&self, _uri: &CertSourceUri) -> Result<MaterialWatch, MaterialError> {
        Ok(MaterialWatch::PollOnly {
            interval: Duration::from_secs(30),
        })
    }
}

#[allow(dead_code)]
pub struct InlineLoader;

impl InlineLoader {
    #[allow(dead_code)]
    pub fn load_source(
        source: &CertSource,
        kind: MaterialKind,
    ) -> Result<MaterializedMaterial, MaterialError> {
        match source {
            CertSource::InlinePem(_) => load_material_blocking(source, kind),
            other => Err(MaterialError::InvalidSource {
                source_id: other.redacted_source_id(),
                details: "InlineLoader only accepts inline PEM sources".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n";

    #[test]
    fn parse_inline_pem() {
        let source = CertSource::parse(CERT, MaterialKind::Cert);
        assert!(matches!(source, CertSource::InlinePem(_)));
        assert!(!format!("{source:?}").contains("abc"));
    }

    #[test]
    fn inline_pool_key_component_is_hashed() {
        let source = CertSource::parse(CERT, MaterialKind::Cert);
        let component = source.pool_key_component();
        assert!(component.starts_with("inline-pem:sha256:"));
        assert!(!component.contains("BEGIN CERTIFICATE"));
        assert!(!component.contains("abc"));
    }

    #[test]
    fn parse_known_uri() {
        let source =
            CertSource::parse("vault://secret/data/edge#cert?poll=60s", MaterialKind::Cert);
        match source {
            CertSource::Uri(uri) => {
                assert_eq!(uri.scheme, SourceScheme::Vault);
                assert_eq!(uri.identifier, "secret/data/edge#cert");
                assert_eq!(uri.kind, MaterialKind::Cert);
                assert_eq!(uri.options.get("poll").map(String::as_str), Some("60s"));
            }
            other => panic!("expected uri, got {other:?}"),
        }
    }

    #[test]
    fn unknown_uri_like_value_stays_path() {
        let source = CertSource::parse("custom://thing", MaterialKind::Cert);
        assert!(matches!(source, CertSource::Path(_)));
    }

    #[test]
    fn non_begin_dashes_stay_path() {
        let source = CertSource::parse("-----not-a-pem-path", MaterialKind::Cert);
        assert!(matches!(source, CertSource::Path(_)));
    }

    #[test]
    fn file_uri_materializes_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, CERT).expect("write cert");
        let source = CertSource::parse(format!("file://{}", path.display()), MaterialKind::Cert);
        let material = load_material_blocking(&source, MaterialKind::Cert).expect("load");
        assert_eq!(material.bytes.expose_secret(), CERT.as_bytes());
        assert_eq!(material.source_kind, SourceScheme::File);
    }

    #[test]
    fn k8s_secret_reference_defaults_tls_key_from_material_kind() {
        let source = CertSource::parse("k8s://edge/frontend", MaterialKind::Cert);
        let CertSource::Uri(uri) = source else {
            panic!("expected uri source");
        };

        let reference = K8sSecretReference::parse(&uri, MaterialKind::Cert).expect("reference");

        assert_eq!(reference.namespace, "edge");
        assert_eq!(reference.name, "frontend");
        assert_eq!(reference.data_key, "tls.crt");
        assert_eq!(reference.kind, MaterialKind::Cert);
        assert_eq!(reference.source_id, "k8s://edge/frontend#tls.crt");
    }

    #[test]
    fn k8s_secret_reference_accepts_query_key() {
        let source = CertSource::parse(
            "k8s://edge/frontend?kind=ca-bundle&key=custom.pem",
            MaterialKind::Cert,
        );
        let CertSource::Uri(uri) = source else {
            panic!("expected uri source");
        };

        let reference = K8sSecretReference::parse(&uri, MaterialKind::Cert).expect("reference");

        assert_eq!(reference.data_key, "custom.pem");
        assert_eq!(reference.kind, MaterialKind::CaBundle);
        assert_eq!(reference.source_id, "k8s://edge/frontend#custom.pem");
    }

    #[test]
    fn k8s_secret_reference_rejects_unknown_kind_without_key() {
        let source = CertSource::parse("k8s://edge/frontend", MaterialKind::Unknown);
        let CertSource::Uri(uri) = source else {
            panic!("expected uri source");
        };

        let error =
            K8sSecretReference::parse(&uri, MaterialKind::Unknown).expect_err("invalid source");

        assert!(matches!(error, MaterialError::InvalidSource { .. }));
    }

    #[test]
    fn k8s_secret_reference_rejects_conflicting_key_forms() {
        let source = CertSource::parse(
            "k8s://edge/frontend#tls.crt?key=other.crt",
            MaterialKind::Cert,
        );
        let CertSource::Uri(uri) = source else {
            panic!("expected uri source");
        };

        let error =
            K8sSecretReference::parse(&uri, MaterialKind::Cert).expect_err("invalid source");

        assert!(matches!(error, MaterialError::InvalidSource { .. }));
    }

    #[test]
    fn k8s_secret_reference_rejects_malformed_identifier() {
        let source = CertSource::parse("k8s://edge/frontend/extra#tls.crt", MaterialKind::Cert);
        let CertSource::Uri(uri) = source else {
            panic!("expected uri source");
        };

        let error =
            K8sSecretReference::parse(&uri, MaterialKind::Cert).expect_err("invalid source");

        assert!(matches!(error, MaterialError::InvalidSource { .. }));
    }

    #[cfg(not(feature = "secrets-vault"))]
    #[test]
    fn vault_uri_is_unsupported_when_feature_is_disabled() {
        let source = CertSource::parse("vault://secret/data/edge#cert", MaterialKind::Cert);
        let error = load_material_blocking(&source, MaterialKind::Cert).expect_err("unsupported");
        assert!(matches!(
            error,
            MaterialError::UnsupportedScheme { scheme: "vault" }
        ));
    }
}
