//! Opt-in external and cross-document OpenAPI `$ref` resolution.
//!
//! Absent policy keeps the historical fail-closed
//! [`ExtractError::UnsupportedExternalRef`] contract. When both the process
//! gate and the per-spec `x-ferrum-external-refs` extension enable resolution,
//! this module loads referenced documents under strict file/HTTPS containment,
//! resource budgets, and SSRF screening, then returns an immutable snapshot for
//! admission-time persistence. Runtime validation never re-fetches.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::fips::approved::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::extractor::ExtractError;

/// Synthetic document base used when the root submission has no operator base.
/// Never fetched; mirrors the extractor local-schema base.
pub const DEFAULT_DOCUMENT_BASE: &str = "https://ferrum.invalid/local-schema";

const DEFAULT_MAX_DOCUMENTS: usize = 32;
const DEFAULT_MAX_DOCUMENT_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_MAX_AGGREGATE_BYTES: usize = 20 * 1024 * 1024;
const DEFAULT_MAX_REFS: usize = 256;
const DEFAULT_MAX_URI_LENGTH: usize = 2048;
const DEFAULT_MAX_REDIRECTS: usize = 3;
const DEFAULT_MAX_NESTING: usize = 16;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_TOTAL_TIMEOUT_MS: u64 = 60_000;
/// Persistence safety ceiling. The configured aggregate fetch budget defaults
/// to 20 MiB; this larger fixed cap leaves room for JSON framing while keeping
/// corrupt DB rows and restore payloads from driving unbounded allocation.
pub const MAX_EXTERNAL_REF_SNAPSHOT_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_EXTERNAL_REF_SNAPSHOT_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024;

/// Process-level external `$ref` gate and budgets (from EnvConfig / ferrum.conf).
#[derive(Debug, Clone)]
pub struct ExternalRefProcessPolicy {
    /// Master process gate. Default `false` preserves fail-closed rejection.
    pub enabled: bool,
    /// Absolute filesystem jail for `file:` / relative file references.
    pub file_root: Option<PathBuf>,
    /// Canonical HTTPS origins (`https://host[:port]`) allowed for network refs.
    pub allowed_origins: Vec<String>,
    /// Explicit HTTP origins permitted only when listed here (fixture/dev).
    pub allow_http_origins: Vec<String>,
    pub max_documents: usize,
    pub max_document_bytes: usize,
    pub max_aggregate_bytes: usize,
    pub max_refs: usize,
    pub max_uri_length: usize,
    pub max_redirects: usize,
    pub max_nesting: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub total_timeout: Duration,
}

impl Default for ExternalRefProcessPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            file_root: None,
            allowed_origins: Vec::new(),
            allow_http_origins: Vec::new(),
            max_documents: DEFAULT_MAX_DOCUMENTS,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            max_refs: DEFAULT_MAX_REFS,
            max_uri_length: DEFAULT_MAX_URI_LENGTH,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_nesting: DEFAULT_MAX_NESTING,
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            total_timeout: Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS),
        }
    }
}

/// Filesystem jail and origin allowlist strings from env/conf.
pub struct ExternalRefEnvOrigins<'a> {
    pub file_root: &'a str,
    pub allowed_origins: &'a str,
    pub allow_http_origins: &'a str,
}

/// Document/ref/URI nesting budgets from env/conf.
pub struct ExternalRefEnvBudgets {
    pub max_documents: usize,
    pub max_document_bytes: usize,
    pub max_aggregate_bytes: usize,
    pub max_refs: usize,
    pub max_uri_length: usize,
    pub max_redirects: usize,
    pub max_nesting: usize,
}

/// Connect/request/total timeout budgets in milliseconds from env/conf.
pub struct ExternalRefEnvTimeouts {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub total_timeout_ms: u64,
}

impl ExternalRefProcessPolicy {
    /// Build from parsed env/conf strings. Invalid values fail closed.
    pub fn from_env_parts(
        enabled: bool,
        origins: ExternalRefEnvOrigins<'_>,
        budgets: ExternalRefEnvBudgets,
        timeouts: ExternalRefEnvTimeouts,
    ) -> Result<Self, String> {
        let file_root = parse_optional_file_root(origins.file_root)?;
        let allowed_origins = parse_origin_list(origins.allowed_origins, true)?;
        let allow_http_origins = parse_origin_list(origins.allow_http_origins, false)?;
        if budgets.max_documents == 0 {
            return Err("FERRUM_ADMIN_SPEC_EXTERNAL_REFS_MAX_DOCUMENTS must be >= 1".to_string());
        }
        if budgets.max_document_bytes == 0 {
            return Err(
                "FERRUM_ADMIN_SPEC_EXTERNAL_REFS_MAX_DOCUMENT_BYTES must be >= 1".to_string(),
            );
        }
        if budgets.max_aggregate_bytes < budgets.max_document_bytes {
            return Err(
                "FERRUM_ADMIN_SPEC_EXTERNAL_REFS_MAX_AGGREGATE_BYTES must be >= MAX_DOCUMENT_BYTES"
                    .to_string(),
            );
        }
        if budgets.max_refs == 0 || budgets.max_uri_length == 0 || budgets.max_nesting == 0 {
            return Err("external-ref count/uri/nesting budgets must be >= 1".to_string());
        }
        Ok(Self {
            enabled,
            file_root,
            allowed_origins,
            allow_http_origins,
            max_documents: budgets.max_documents,
            max_document_bytes: budgets.max_document_bytes,
            max_aggregate_bytes: budgets.max_aggregate_bytes,
            max_refs: budgets.max_refs,
            max_uri_length: budgets.max_uri_length,
            max_redirects: budgets.max_redirects,
            max_nesting: budgets.max_nesting,
            connect_timeout: Duration::from_millis(timeouts.connect_timeout_ms.max(1)),
            request_timeout: Duration::from_millis(timeouts.request_timeout_ms.max(1)),
            total_timeout: Duration::from_millis(timeouts.total_timeout_ms.max(1)),
        })
    }

    /// Stable digest of the process policy for cache keys / snapshots.
    pub fn policy_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"extref-process-v1\0");
        hasher.update([u8::from(self.enabled)]);
        if let Some(root) = &self.file_root {
            hasher.update(root.to_string_lossy().as_bytes());
        }
        hasher.update(b"\0");
        let mut allowed_origins: Vec<&str> =
            self.allowed_origins.iter().map(String::as_str).collect();
        allowed_origins.sort_unstable();
        allowed_origins.dedup();
        for origin in allowed_origins {
            hasher.update(origin.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(b"|http|");
        let mut allow_http_origins: Vec<&str> =
            self.allow_http_origins.iter().map(String::as_str).collect();
        allow_http_origins.sort_unstable();
        allow_http_origins.dedup();
        for origin in allow_http_origins {
            hasher.update(origin.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(self.max_documents.to_le_bytes());
        hasher.update(self.max_document_bytes.to_le_bytes());
        hasher.update(self.max_aggregate_bytes.to_le_bytes());
        hasher.update(self.max_refs.to_le_bytes());
        hasher.update(self.max_uri_length.to_le_bytes());
        hasher.update(self.max_redirects.to_le_bytes());
        hasher.update(self.max_nesting.to_le_bytes());
        hasher.update(self.connect_timeout.as_millis().to_le_bytes());
        hasher.update(self.request_timeout.as_millis().to_le_bytes());
        hasher.update(self.total_timeout.as_millis().to_le_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Per-spec opt-in extension (`x-ferrum-external-refs`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRefSpecExtension {
    #[serde(default)]
    pub enabled: bool,
    /// Optional absolute document base URI for the submitted root document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_base: Option<String>,
    /// Optional further HTTPS origin allowlist intersected with process policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
}

/// Effective policy after intersecting process gates with the per-spec extension.
#[derive(Debug, Clone)]
pub struct EffectiveExternalRefPolicy {
    pub enabled: bool,
    pub document_base: Url,
    pub file_root: Option<PathBuf>,
    pub allowed_origins: HashSet<String>,
    pub allow_http_origins: HashSet<String>,
    pub max_documents: usize,
    pub max_document_bytes: usize,
    pub max_aggregate_bytes: usize,
    pub max_refs: usize,
    pub max_uri_length: usize,
    pub max_redirects: usize,
    pub max_nesting: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub total_timeout: Duration,
    process_policy_digest: String,
    /// Stable digest of the fully composed process + per-spec policy. This is
    /// the only policy provenance persisted in snapshots or used in cache keys.
    pub effective_policy_digest: String,
}

impl EffectiveExternalRefPolicy {
    pub fn disabled() -> Self {
        let process = ExternalRefProcessPolicy::default();
        Self {
            enabled: false,
            document_base: Url::parse(DEFAULT_DOCUMENT_BASE).expect("static URI"),
            file_root: None,
            allowed_origins: HashSet::new(),
            allow_http_origins: HashSet::new(),
            max_documents: process.max_documents,
            max_document_bytes: process.max_document_bytes,
            max_aggregate_bytes: process.max_aggregate_bytes,
            max_refs: process.max_refs,
            max_uri_length: process.max_uri_length,
            max_redirects: process.max_redirects,
            max_nesting: process.max_nesting,
            connect_timeout: process.connect_timeout,
            request_timeout: process.request_timeout,
            total_timeout: process.total_timeout,
            process_policy_digest: process.policy_digest(),
            effective_policy_digest: String::new(),
        }
        .with_effective_policy_digest()
    }

    pub fn compose(
        process: &ExternalRefProcessPolicy,
        extension: Option<&ExternalRefSpecExtension>,
    ) -> Result<Self, ExtractError> {
        let Some(extension) = extension else {
            let mut disabled = Self::disabled();
            disabled.process_policy_digest = process.policy_digest();
            disabled.max_documents = process.max_documents;
            disabled.max_document_bytes = process.max_document_bytes;
            disabled.max_aggregate_bytes = process.max_aggregate_bytes;
            disabled.max_refs = process.max_refs;
            disabled.max_uri_length = process.max_uri_length;
            disabled.max_redirects = process.max_redirects;
            disabled.max_nesting = process.max_nesting;
            disabled.connect_timeout = process.connect_timeout;
            disabled.request_timeout = process.request_timeout;
            disabled.total_timeout = process.total_timeout;
            disabled.file_root = process.file_root.clone();
            return Ok(disabled.with_effective_policy_digest());
        };

        let document_base = match extension.document_base.as_deref() {
            Some(base) => parse_document_base(base, process)?,
            None => {
                Url::parse(DEFAULT_DOCUMENT_BASE).map_err(|_| ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "internal document base is invalid".to_string(),
                })?
            }
        };

        let mut allowed_origins: HashSet<String> =
            process.allowed_origins.iter().cloned().collect();
        if !extension.allowed_origins.is_empty() {
            let mut narrowed = HashSet::new();
            for raw in &extension.allowed_origins {
                let origin = canonicalize_origin(raw, true).map_err(|error| {
                    ExtractError::MalformedExtension {
                        which: "x-ferrum-external-refs",
                        error,
                    }
                })?;
                if !allowed_origins.contains(&origin) {
                    return Err(ExtractError::MalformedExtension {
                        which: "x-ferrum-external-refs",
                        error: "allowed_origins entry is not permitted by process policy"
                            .to_string(),
                    });
                }
                narrowed.insert(origin);
            }
            allowed_origins = narrowed;
        }

        // Validate every supplied extension field even when either enable gate
        // is off. A disabled feature is not permission to persist malformed or
        // process-disallowed policy that may become active after a config flip.
        if !process.enabled || !extension.enabled {
            let mut disabled = Self::compose(process, None)?;
            disabled.document_base = document_base;
            disabled.allowed_origins = allowed_origins;
            return Ok(disabled.with_effective_policy_digest());
        }

        Ok(Self {
            enabled: true,
            document_base,
            file_root: process.file_root.clone(),
            allowed_origins,
            allow_http_origins: process.allow_http_origins.iter().cloned().collect(),
            max_documents: process.max_documents,
            max_document_bytes: process.max_document_bytes,
            max_aggregate_bytes: process.max_aggregate_bytes,
            max_refs: process.max_refs,
            max_uri_length: process.max_uri_length,
            max_redirects: process.max_redirects,
            max_nesting: process.max_nesting,
            connect_timeout: process.connect_timeout,
            request_timeout: process.request_timeout,
            total_timeout: process.total_timeout,
            process_policy_digest: process.policy_digest(),
            effective_policy_digest: String::new(),
        }
        .with_effective_policy_digest())
    }

    fn with_effective_policy_digest(mut self) -> Self {
        self.effective_policy_digest = effective_policy_digest(
            &self.process_policy_digest,
            self.enabled,
            &self.document_base,
            &self.allowed_origins,
            &self.allow_http_origins,
        );
        self
    }
}

fn effective_policy_digest(
    process_policy_digest: &str,
    enabled: bool,
    document_base: &Url,
    allowed_origins: &HashSet<String>,
    allow_http_origins: &HashSet<String>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"extref-effective-v1\0");
    hash_len_prefixed(&mut hasher, process_policy_digest.as_bytes());
    hasher.update([u8::from(enabled)]);
    hash_len_prefixed(&mut hasher, resource_uri_key(document_base).as_bytes());

    let mut https_origins: Vec<&str> = allowed_origins.iter().map(String::as_str).collect();
    https_origins.sort_unstable();
    hasher.update((https_origins.len() as u64).to_le_bytes());
    for origin in https_origins {
        hash_len_prefixed(&mut hasher, origin.as_bytes());
    }

    let mut http_origins: Vec<&str> = allow_http_origins.iter().map(String::as_str).collect();
    http_origins.sort_unstable();
    hasher.update((http_origins.len() as u64).to_le_bytes());
    for origin in http_origins {
        hash_len_prefixed(&mut hasher, origin.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// One immutable external document admitted at import time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalRefSnapshotDocument {
    /// Stable fetched-document identity without fragment. Candidate admission
    /// forbids userinfo and queries; file identities are hashed so persisted
    /// snapshots and backups do not disclose host paths.
    pub canonical_uri: String,
    /// SHA-256 hex of the canonical normalized JSON value as admitted.
    pub content_digest: String,
    /// `json` or `yaml`.
    pub format: String,
    /// Normalized JSON value of the document.
    pub document: Value,
}

/// Immutable admission snapshot of every external document used for resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalRefSnapshot {
    pub policy_digest: String,
    pub root_document_base: String,
    pub documents: Vec<ExternalRefSnapshotDocument>,
    /// Aggregate digest over policy + ordered document digests.
    pub snapshot_digest: String,
}

impl ExternalRefSnapshot {
    pub fn empty(policy: &EffectiveExternalRefPolicy) -> Self {
        let mut snap = Self {
            policy_digest: policy.effective_policy_digest.clone(),
            root_document_base: snapshot_uri_identity(&policy.document_base),
            documents: Vec::new(),
            snapshot_digest: String::new(),
        };
        snap.snapshot_digest = snap.compute_digest();
        snap
    }

    pub fn compute_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"extref-snapshot-v2\0");
        hasher.update(self.policy_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.root_document_base.as_bytes());
        hasher.update(b"\0");
        for doc in &self.documents {
            hasher.update(doc.canonical_uri.as_bytes());
            hasher.update(b"\0");
            hasher.update(doc.content_digest.as_bytes());
            hasher.update(b"\0");
            hasher.update(doc.format.as_bytes());
            hasher.update(b"\0");
            hash_json_value(&mut hasher, &doc.document);
        }
        hex::encode(hasher.finalize())
    }

    pub fn gzip_bytes(&self) -> Result<Vec<u8>, ExtractError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            ExtractError::SchemaReference(format!(
                "failed to serialize external-ref snapshot: {error}"
            ))
        })?;
        crate::admin::spec_codec::compress_gzip(&json).map_err(|error| {
            ExtractError::SchemaReference(format!(
                "failed to compress external-ref snapshot: {error}"
            ))
        })
    }

    pub fn from_gzip_bytes(bytes: &[u8], max_bytes: usize) -> Result<Self, String> {
        let raw = crate::admin::spec_codec::decompress_gzip_capped(bytes, max_bytes)
            .map_err(|error| format!("external_ref_snapshot decompress failed: {error}"))?;
        let snap: Self = serde_json::from_slice(&raw)
            .map_err(|error| format!("external_ref_snapshot JSON invalid: {error}"))?;
        for doc in &snap.documents {
            if doc.content_digest != normalized_document_digest(&doc.document) {
                return Err("external_ref_snapshot document digest mismatch".to_string());
            }
        }
        let expected = snap.compute_digest();
        if snap.snapshot_digest != expected {
            return Err("external_ref_snapshot digest mismatch".to_string());
        }
        Ok(snap)
    }
}

/// Validate the persisted snapshot/digest pair used by SQL, Mongo, and backup
/// restore. Full-record reads must call this; summary projections intentionally
/// use [`validate_external_ref_summary_digest`] because they omit the blob.
pub fn validate_external_ref_snapshot_pair(
    snapshot: Option<&[u8]>,
    digest: Option<&str>,
) -> Result<(), String> {
    match (snapshot, digest) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            Err("external_ref snapshot and digest must be present together".to_string())
        }
        (Some(bytes), Some(stored_digest)) => {
            if bytes.len() > MAX_EXTERNAL_REF_SNAPSHOT_COMPRESSED_BYTES {
                return Err("external_ref snapshot exceeds persistence size limit".to_string());
            }
            validate_external_ref_summary_digest(Some(stored_digest))?;
            let snapshot = ExternalRefSnapshot::from_gzip_bytes(
                bytes,
                MAX_EXTERNAL_REF_SNAPSHOT_DECOMPRESSED_BYTES,
            )?;
            if snapshot.snapshot_digest != stored_digest {
                return Err("external_ref snapshot digest does not match stored digest".to_string());
            }
            Ok(())
        }
    }
}

pub fn validate_external_ref_summary_digest(digest: Option<&str>) -> Result<(), String> {
    if let Some(value) = digest
        && (value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err("external_ref digest is not lowercase SHA-256 hex".to_string());
    }
    Ok(())
}

fn normalized_document_digest(document: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"extref-document-v1\0");
    hash_json_value(&mut hasher, document);
    hex::encode(hasher.finalize())
}

fn hash_json_value(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hasher.update(b"n"),
        Value::Bool(value) => hasher.update(if *value { b"t" } else { b"f" }),
        Value::Number(value) => {
            hasher.update(b"d");
            hash_len_prefixed(hasher, value.to_string().as_bytes());
        }
        Value::String(value) => {
            hasher.update(b"s");
            hash_len_prefixed(hasher, value.as_bytes());
        }
        Value::Array(values) => {
            hasher.update(b"a");
            hasher.update((values.len() as u64).to_le_bytes());
            for value in values {
                hash_json_value(hasher, value);
            }
        }
        Value::Object(values) => {
            hasher.update(b"o");
            hasher.update((values.len() as u64).to_le_bytes());
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (key, value) in entries {
                hash_len_prefixed(hasher, key.as_bytes());
                hash_json_value(hasher, value);
            }
        }
    }
}

fn hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

/// Loaded external document ready for resolver indexing.
#[derive(Debug, Clone)]
pub struct LoadedExternalDocument {
    pub canonical_uri: Url,
    pub content_digest: String,
    pub format: &'static str,
    pub root: Value,
    pub raw_bytes: Vec<u8>,
}

/// Sync loader used by unit tests and the file path.
pub trait ExternalDocumentLoader: Send + Sync {
    fn load(
        &self,
        uri: &Url,
        policy: &EffectiveExternalRefPolicy,
        deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError>;
}

/// Production loader: containment-safe files + screened HTTPS (and explicit HTTP allowlist).
#[derive(Clone)]
pub struct DefaultExternalDocumentLoader {
    pub egress: crate::config::BackendEgressPolicy,
    pub dns_cache: Option<std::sync::Arc<crate::dns::DnsCache>>,
    /// Optional in-memory fixtures keyed by canonical URI (tests only).
    pub fixtures: HashMap<String, Vec<u8>>,
}

impl Default for DefaultExternalDocumentLoader {
    fn default() -> Self {
        Self {
            egress: crate::config::BackendEgressPolicy::from_allow_ips(
                crate::config::BackendAllowIps::Public,
            ),
            dns_cache: None,
            fixtures: HashMap::new(),
        }
    }
}

impl ExternalDocumentLoader for DefaultExternalDocumentLoader {
    fn load(
        &self,
        uri: &Url,
        policy: &EffectiveExternalRefPolicy,
        deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError> {
        if Instant::now() >= deadline {
            return Err(external_ref_error(
                "external $ref fetch exceeded the total timeout budget",
            ));
        }
        let key = resource_uri_key(uri);
        if let Some(bytes) = self.fixtures.get(&key) {
            return parse_loaded_document(uri, bytes, policy);
        }
        match uri.scheme() {
            "file" => load_file_document(uri, policy),
            "https" => {
                let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
                    external_ref_error("external HTTPS $ref resolution requires an async runtime")
                })?;
                runtime.block_on(load_http_document(
                    uri,
                    policy,
                    &self.egress,
                    self.dns_cache.as_ref(),
                    deadline,
                    true,
                ))
            }
            "http" => {
                let origin = origin_key(uri)?;
                if !policy.allow_http_origins.contains(&origin) {
                    return Err(ExtractError::UnsupportedExternalRef {
                        reference: redact_reference(uri.as_str()),
                    });
                }
                let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
                    external_ref_error("external HTTP $ref resolution requires an async runtime")
                })?;
                runtime.block_on(load_http_document(
                    uri,
                    policy,
                    &self.egress,
                    self.dns_cache.as_ref(),
                    deadline,
                    false,
                ))
            }
            _ => Err(ExtractError::UnsupportedExternalRef {
                reference: redact_reference(uri.as_str()),
            }),
        }
    }
}

/// In-memory map loader for deterministic unit tests (no filesystem / network).
// The binary target compiles this public library module privately and therefore
// cannot observe its integration-test consumers.
#[allow(dead_code)]
#[derive(Default)]
pub struct MapExternalDocumentLoader {
    pub docs: HashMap<String, Vec<u8>>,
}

impl ExternalDocumentLoader for MapExternalDocumentLoader {
    fn load(
        &self,
        uri: &Url,
        policy: &EffectiveExternalRefPolicy,
        _deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError> {
        let key = resource_uri_key(uri);
        let bytes = self
            .docs
            .get(&key)
            .ok_or_else(|| ExtractError::UnsupportedExternalRef {
                reference: redact_reference(uri.as_str()),
            })?;
        parse_loaded_document(uri, bytes, policy)
    }
}

/// Parse `x-ferrum-external-refs` from a root OpenAPI document.
pub fn parse_external_ref_extension(
    root: &Value,
) -> Result<Option<ExternalRefSpecExtension>, ExtractError> {
    let Some(value) = root.get("x-ferrum-external-refs") else {
        return Ok(None);
    };
    if value.as_bool() == Some(true) {
        return Ok(Some(ExternalRefSpecExtension {
            enabled: true,
            ..ExternalRefSpecExtension::default()
        }));
    }
    if value.as_bool() == Some(false) {
        return Ok(Some(ExternalRefSpecExtension::default()));
    }
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|error| ExtractError::MalformedExtension {
            which: "x-ferrum-external-refs",
            error: error.to_string(),
        })
}

/// Collect and load every external document reachable from `root` under policy.
pub fn load_external_documents(
    root: &Value,
    policy: &EffectiveExternalRefPolicy,
    loader: &dyn ExternalDocumentLoader,
) -> Result<(HashMap<String, LoadedExternalDocument>, ExternalRefSnapshot), ExtractError> {
    if !policy.enabled {
        return Ok((HashMap::new(), ExternalRefSnapshot::empty(policy)));
    }

    let deadline = Instant::now()
        .checked_add(policy.total_timeout)
        .ok_or_else(|| external_ref_error("external $ref total timeout budget is invalid"))?;
    let mut loaded: HashMap<String, LoadedExternalDocument> = HashMap::new();
    let mut pending: VecDeque<(Url, usize)> = VecDeque::new();
    let mut seen_refs = 0usize;
    let mut aggregate_bytes = 0usize;
    // In-document `$id` resources are resolved locally; never fetch them.
    let mut local_resources = HashSet::new();
    local_resources.insert(resource_uri_key(&policy.document_base));
    collect_local_resource_ids(root, &policy.document_base, &mut local_resources)?;

    let mut active = HashSet::new();
    collect_refs_from_value(
        root,
        &policy.document_base,
        0,
        &mut CollectRefsState {
            policy,
            local_resources: &local_resources,
            pending: &mut pending,
            seen_refs: &mut seen_refs,
            active: &mut active,
        },
    )?;

    while let Some((uri, depth)) = pending.pop_front() {
        if depth > policy.max_nesting {
            return Err(ExtractError::SchemaTooDeep {
                location: "x-ferrum-external-refs".to_string(),
            });
        }
        let key = resource_uri_key(&uri);
        if loaded.contains_key(&key) {
            continue;
        }
        if loaded.len() >= policy.max_documents {
            return Err(external_ref_error(
                "external $ref document count exceeded the configured budget",
            ));
        }
        validate_candidate_uri(&uri, policy)?;
        let doc = loader.load(&uri, policy, deadline)?;
        aggregate_bytes = aggregate_bytes.saturating_add(doc.raw_bytes.len());
        if aggregate_bytes > policy.max_aggregate_bytes {
            return Err(ExtractError::SchemaTooLarge {
                location: "x-ferrum-external-refs".to_string(),
            });
        }
        let doc_root = doc.root.clone();
        let doc_base = doc.canonical_uri.clone();
        collect_local_resource_ids(&doc_root, &doc_base, &mut local_resources)?;
        loaded.insert(key, doc);
        active.clear();
        collect_refs_from_value(
            &doc_root,
            &doc_base,
            depth + 1,
            &mut CollectRefsState {
                policy,
                local_resources: &local_resources,
                pending: &mut pending,
                seen_refs: &mut seen_refs,
                active: &mut active,
            },
        )?;
    }

    // Different admitted request URIs may redirect to the same canonical
    // resource. Keep one deterministic snapshot entry for that resource, and
    // fail closed if the aliases produced different content during admission.
    let mut loaded_entries: Vec<_> = loaded.iter().collect();
    loaded_entries.sort_unstable_by(|(left_key, left), (right_key, right)| {
        resource_uri_key(&left.canonical_uri)
            .cmp(&resource_uri_key(&right.canonical_uri))
            .then_with(|| left_key.cmp(right_key))
    });
    let mut documents: Vec<ExternalRefSnapshotDocument> = Vec::with_capacity(loaded.len());
    let mut previous_canonical: Option<String> = None;
    let mut previous_digest: Option<&str> = None;
    for (_, doc) in loaded_entries {
        let canonical = resource_uri_key(&doc.canonical_uri);
        if previous_canonical.as_deref() == Some(canonical.as_str()) {
            if previous_digest != Some(doc.content_digest.as_str()) {
                return Err(external_ref_error(
                    "external $ref aliases resolved to inconsistent document content",
                ));
            }
            continue;
        }
        previous_canonical = Some(canonical);
        previous_digest = Some(doc.content_digest.as_str());
        documents.push(ExternalRefSnapshotDocument {
            canonical_uri: snapshot_uri_identity(&doc.canonical_uri),
            content_digest: doc.content_digest.clone(),
            format: doc.format.to_string(),
            document: doc.root.clone(),
        });
    }
    let mut snapshot = ExternalRefSnapshot {
        policy_digest: policy.effective_policy_digest.clone(),
        root_document_base: snapshot_uri_identity(&policy.document_base),
        documents,
        snapshot_digest: String::new(),
    };
    snapshot.snapshot_digest = snapshot.compute_digest();
    Ok((loaded, snapshot))
}

fn collect_local_resource_ids(
    value: &Value,
    base: &Url,
    out: &mut HashSet<String>,
) -> Result<(), ExtractError> {
    match value {
        Value::Object(map) => {
            let child_base = schema_child_base(map, base)?;
            if child_base.as_str() != base.as_str() {
                out.insert(resource_uri_key(&child_base));
            }
            for (key, child) in map {
                if matches!(
                    key.as_str(),
                    "default" | "examples" | "example" | "const" | "enum" | "$ref"
                ) {
                    continue;
                }
                collect_local_resource_ids(child, &child_base, out)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for child in items {
                collect_local_resource_ids(child, base, out)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Mutable traversal accumulators shared across a single document walk.
struct CollectRefsState<'a> {
    policy: &'a EffectiveExternalRefPolicy,
    local_resources: &'a HashSet<String>,
    pending: &'a mut VecDeque<(Url, usize)>,
    seen_refs: &'a mut usize,
    active: &'a mut HashSet<String>,
}

fn collect_refs_from_value(
    value: &Value,
    base: &Url,
    depth: usize,
    state: &mut CollectRefsState<'_>,
) -> Result<(), ExtractError> {
    match value {
        Value::Object(map) => {
            let child_base = schema_child_base(map, base)?;
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                *state.seen_refs = state.seen_refs.saturating_add(1);
                if *state.seen_refs > state.policy.max_refs {
                    return Err(external_ref_error(
                        "external $ref count exceeded the configured budget",
                    ));
                }
                if reference.len() > state.policy.max_uri_length {
                    return Err(external_ref_error(
                        "external $ref URI exceeds the configured length budget",
                    ));
                }
                if let Some(target) =
                    classify_external_target(reference, &child_base, state.local_resources)?
                {
                    let key = resource_uri_key(&target);
                    if state.active.insert(key.clone()) {
                        state.pending.push_back((target, depth));
                        state.active.remove(&key);
                    }
                }
            }
            for (key, child) in map {
                if key == "$ref" {
                    continue;
                }
                // Annotation payloads are not active schema structure.
                if matches!(
                    key.as_str(),
                    "default" | "examples" | "example" | "const" | "enum"
                ) {
                    continue;
                }
                collect_refs_from_value(child, &child_base, depth, state)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for child in items {
                collect_refs_from_value(child, base, depth, state)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn classify_external_target(
    reference: &str,
    base: &Url,
    local_resources: &HashSet<String>,
) -> Result<Option<Url>, ExtractError> {
    let (uri_part, _fragment) = split_ref(reference);
    let Some(uri_part) = uri_part else {
        return Ok(None);
    };
    if uri_part.is_empty() || uri_part.starts_with('#') {
        return Ok(None);
    }
    let joined = base.join(uri_part).map_err(|_| {
        ExtractError::SchemaReference(format!("invalid $ref '{}'", redact_reference(reference)))
    })?;
    let mut resource = joined;
    resource.set_fragment(None);
    let key = resource_uri_key(&resource);
    if local_resources.contains(&key) {
        return Ok(None);
    }
    // Relative joins that remain on the synthetic never-fetched base are local.
    if resource.scheme() == "https" && resource.host_str() == Some("ferrum.invalid") {
        return Ok(None);
    }
    Ok(Some(resource))
}

fn schema_child_base(
    map: &serde_json::Map<String, Value>,
    base: &Url,
) -> Result<Url, ExtractError> {
    let id_value = map
        .get("$id")
        .or_else(|| map.get("id"))
        .and_then(Value::as_str);
    let Some(id_value) = id_value else {
        return Ok(base.clone());
    };
    let resolved = base.join(id_value).map_err(|_| {
        ExtractError::SchemaReference(format!(
            "invalid schema $id '{}'",
            redact_reference(id_value)
        ))
    })?;
    let mut resource = resolved;
    resource.set_fragment(None);
    Ok(resource)
}

fn validate_candidate_uri(
    uri: &Url,
    policy: &EffectiveExternalRefPolicy,
) -> Result<(), ExtractError> {
    if uri.as_str().len() > policy.max_uri_length {
        return Err(external_ref_error(
            "external $ref URI exceeds the configured length budget",
        ));
    }
    if uri.username() != "" || uri.password().is_some() {
        return Err(external_ref_error(
            "external $ref URI must not embed credentials",
        ));
    }
    if uri.query().is_some() {
        return Err(external_ref_error(
            "external $ref URI must not carry a query string",
        ));
    }
    match uri.scheme() {
        "file" => {
            if policy.file_root.is_none() {
                return Err(ExtractError::UnsupportedExternalRef {
                    reference: redact_reference(uri.as_str()),
                });
            }
            Ok(())
        }
        "https" => {
            let origin = origin_key(uri)?;
            if !policy.allowed_origins.contains(&origin) {
                return Err(ExtractError::UnsupportedExternalRef {
                    reference: redact_reference(uri.as_str()),
                });
            }
            screen_host_literal(uri)?;
            Ok(())
        }
        "http" => {
            let origin = origin_key(uri)?;
            if !policy.allow_http_origins.contains(&origin) {
                return Err(ExtractError::UnsupportedExternalRef {
                    reference: redact_reference(uri.as_str()),
                });
            }
            screen_host_literal(uri)?;
            Ok(())
        }
        _ => Err(ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        }),
    }
}

fn screen_host_literal(uri: &Url) -> Result<(), ExtractError> {
    let host = uri
        .host()
        .ok_or_else(|| external_ref_error("external $ref URI is missing a host"))?;
    if matches!(
        &host,
        url::Host::Domain(name)
            if name.eq_ignore_ascii_case("localhost")
                || name.ends_with(".localhost")
                || name.eq_ignore_ascii_case("metadata.google.internal")
    ) {
        // Loopback/metadata hostnames are rejected at the URI gate unless the
        // operator listed an explicit HTTP fixture origin (checked by caller)
        // *and* later DNS screening allows the resolved address. For HTTPS we
        // still reject these names here so accidental public-origin typos fail.
        if uri.scheme() == "https" {
            return Err(external_ref_error(
                "external $ref host is not a permitted public destination",
            ));
        }
    }
    let literal_ip = match host {
        url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        url::Host::Domain(_) => None,
    };
    if let Some(ip) = literal_ip
        && (crate::config::is_always_blocked_range(&ip)
            || crate::config::is_private_ip(&ip)
            || ip.is_loopback()
            || ip.is_unspecified()
            || matches!(ip, IpAddr::V4(v4) if v4.is_link_local() || v4.is_broadcast())
            || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local() || v6.is_multicast()))
        && uri.scheme() == "https"
    {
        // Explicit HTTP fixture origins may target loopback listeners.
        return Err(external_ref_error(
            "external $ref host is not a permitted public destination",
        ));
    }
    Ok(())
}

fn load_file_document(
    uri: &Url,
    policy: &EffectiveExternalRefPolicy,
) -> Result<LoadedExternalDocument, ExtractError> {
    let root = policy
        .file_root
        .as_ref()
        .ok_or_else(|| ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        })?;
    let path = file_uri_to_path(uri)?;
    let bytes = read_contained_file(root, &path, policy.max_document_bytes)?;
    parse_loaded_document(uri, &bytes, policy)
}

async fn load_http_document(
    uri: &Url,
    policy: &EffectiveExternalRefPolicy,
    egress: &crate::config::BackendEgressPolicy,
    dns_cache: Option<&std::sync::Arc<crate::dns::DnsCache>>,
    deadline: Instant,
    require_https: bool,
) -> Result<LoadedExternalDocument, ExtractError> {
    let mut current = uri.clone();
    for redirect_count in 0..=policy.max_redirects {
        if require_https && current.scheme() != "https" {
            return Err(ExtractError::UnsupportedExternalRef {
                reference: redact_reference(current.as_str()),
            });
        }
        validate_candidate_uri(&current, policy)?;

        let hop_deadline = deadline.min(
            Instant::now()
                .checked_add(policy.request_timeout)
                .unwrap_or(deadline),
        );
        let (host, literal_ip) = match current
            .host()
            .ok_or_else(|| external_ref_error("external $ref URI is missing a host"))?
        {
            url::Host::Domain(host) => (host.to_string(), None),
            url::Host::Ipv4(ip) => (ip.to_string(), Some(IpAddr::V4(ip))),
            url::Host::Ipv6(ip) => (ip.to_string(), Some(IpAddr::V6(ip))),
        };
        let port = current
            .port_or_known_default()
            .ok_or_else(|| external_ref_error("external $ref URI is missing a port"))?;
        let pinned_ips = if let Some(ip) = literal_ip {
            vec![ip]
        } else {
            timeout_external_ref(
                hop_deadline,
                resolve_host_addrs(&host, port, dns_cache),
                "external $ref DNS resolution timed out",
            )
            .await??
        };
        if pinned_ips.is_empty() {
            return Err(external_ref_error(
                "external $ref host did not resolve to any address",
            ));
        }
        for ip in &pinned_ips {
            screen_resolved_address(&current, ip, egress)?;
        }

        let socket_addrs: Vec<SocketAddr> = pinned_ips
            .iter()
            .copied()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let remaining = remaining_budget(hop_deadline)?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(policy.connect_timeout.min(remaining))
            .timeout(remaining)
            .no_proxy();
        if literal_ip.is_none() {
            // Pin exactly the screened address set. The request URL retains the
            // hostname, so HTTP Host and TLS SNI/certificate validation remain
            // tied to the policy-approved origin rather than to an IP literal.
            builder = builder.resolve_to_addrs(&host, &socket_addrs);
        }
        let client = builder
            .build()
            .map_err(|_| external_ref_error("failed to build external $ref HTTP client"))?;

        // Construct a bare GET for every hop. Redirects are manual, so no
        // Authorization, Cookie, proxy credentials, or prior-hop headers can
        // be copied to another origin.
        let response = timeout_external_ref(
            hop_deadline,
            client
                .get(current.clone())
                .header(
                    reqwest::header::ACCEPT,
                    "application/json, application/yaml, text/yaml, application/x-yaml, text/x-yaml, text/plain",
                )
                .send(),
            "external $ref HTTP fetch timed out",
        )
        .await?
        .map_err(|error| {
            map_external_ref_reqwest_error(
                error,
                "external $ref HTTP fetch timed out",
                "external $ref HTTP fetch failed",
            )
        })?;

        if response.status().is_redirection() {
            if redirect_count >= policy.max_redirects {
                return Err(external_ref_error("external $ref redirect budget exceeded"));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| external_ref_error("external $ref redirect location is invalid"))?;
            let next = current
                .join(location)
                .map_err(|_| external_ref_error("external $ref redirect location is invalid"))?;
            validate_candidate_uri(&next, policy)?;
            if require_https && next.scheme() != "https" {
                return Err(external_ref_error(
                    "external $ref redirect crossed the permitted transport policy",
                ));
            }
            current = next;
            continue;
        }

        if !response.status().is_success() {
            return Err(external_ref_error(
                "external $ref HTTP fetch returned a non-success status",
            ));
        }
        if let Some(value) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            let content_type = value.to_str().map_err(|_| {
                external_ref_error(
                    "external $ref response Content-Type is not an allowed OpenAPI media type",
                )
            })?;
            if !content_type_allowed(content_type) {
                return Err(external_ref_error(
                    "external $ref response Content-Type is not an allowed OpenAPI media type",
                ));
            }
        }
        if response
            .content_length()
            .is_some_and(|length| length > policy.max_document_bytes as u64)
        {
            return Err(external_document_too_large());
        }

        let mut response = response;
        let mut bytes = Vec::new();
        loop {
            let chunk = timeout_external_ref(
                hop_deadline,
                response.chunk(),
                "external $ref HTTP body read timed out",
            )
            .await?
            .map_err(|error| {
                map_external_ref_reqwest_error(
                    error,
                    "external $ref HTTP body read timed out",
                    "external $ref HTTP body read failed",
                )
            })?;
            let Some(chunk) = chunk else {
                break;
            };
            let new_len = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(external_document_too_large)?;
            if new_len > policy.max_document_bytes {
                return Err(external_document_too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        return parse_loaded_document(&current, &bytes, policy);
    }
    Err(external_ref_error("external $ref redirect budget exceeded"))
}

async fn resolve_host_addrs(
    host: &str,
    port: u16,
    dns_cache: Option<&std::sync::Arc<crate::dns::DnsCache>>,
) -> Result<Vec<IpAddr>, ExtractError> {
    if let Some(cache) = dns_cache {
        return cache
            .resolve_all_fresh(host)
            .await
            .map_err(|_| external_ref_error("external $ref DNS resolution failed"));
    }
    let host_owned = host.to_string();
    let addrs = tokio::net::lookup_host((host_owned.as_str(), port))
        .await
        .map_err(|_| external_ref_error("external $ref DNS resolution failed"))?
        .map(|a| a.ip())
        .collect::<Vec<_>>();
    Ok(addrs)
}

async fn timeout_external_ref<F, T>(
    deadline: Instant,
    future: F,
    timeout_message: &'static str,
) -> Result<T, ExtractError>
where
    F: std::future::Future<Output = T>,
{
    let remaining = remaining_budget(deadline)?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| external_ref_error(timeout_message))
}

/// Classify a reqwest I/O failure without forwarding inner error text.
///
/// The per-request client timeout and `timeout_external_ref` share the same
/// hop deadline. When reqwest wins the race, `is_timeout()` (including the
/// `source()` chain) must keep the same sanitized timeout diagnostic the outer
/// wrapper would have produced.
fn map_external_ref_reqwest_error(
    error: reqwest::Error,
    timeout_message: &'static str,
    failed_message: &'static str,
) -> ExtractError {
    if reqwest_error_is_timeout(&error) {
        external_ref_error(timeout_message)
    } else {
        external_ref_error(failed_message)
    }
}

fn reqwest_error_is_timeout(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    let mut source = std::error::Error::source(error);
    while let Some(err) = source {
        if let Some(inner) = err.downcast_ref::<reqwest::Error>()
            && inner.is_timeout()
        {
            return true;
        }
        source = std::error::Error::source(err);
    }
    false
}

fn remaining_budget(deadline: Instant) -> Result<Duration, ExtractError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| external_ref_error("external $ref fetch exceeded the total timeout budget"))
}

fn screen_resolved_address(
    uri: &Url,
    ip: &IpAddr,
    egress: &crate::config::BackendEgressPolicy,
) -> Result<(), ExtractError> {
    let non_public = crate::config::is_always_blocked_range(ip)
        || crate::config::is_private_ip(ip)
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(v4) if v4.is_link_local() || v4.is_broadcast())
        || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
    // Explicit HTTP origins exist solely for local fixture/development use.
    // Their only non-public exception is loopback; metadata, RFC1918, link-local,
    // unspecified, multicast, and broadcast destinations remain forbidden.
    let explicit_http_loopback = uri.scheme() == "http" && ip.is_loopback();
    if non_public && !explicit_http_loopback {
        return Err(external_ref_error(
            "external $ref host is not a permitted public destination",
        ));
    }
    if !explicit_http_loopback && egress.deny_reason(ip).is_some() {
        return Err(external_ref_error(
            "external $ref destination denied by egress policy",
        ));
    }
    Ok(())
}

fn external_document_too_large() -> ExtractError {
    ExtractError::SchemaTooLarge {
        location: "x-ferrum-external-refs".to_string(),
    }
}

fn content_type_allowed(content_type: &str) -> bool {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    matches!(
        media.as_str(),
        "application/json"
            | "application/yaml"
            | "application/x-yaml"
            | "text/yaml"
            | "text/x-yaml"
            | "text/plain"
            | "application/octet-stream"
    ) || media.ends_with("+json")
        || media.ends_with("+yaml")
}

fn parse_loaded_document(
    uri: &Url,
    bytes: &[u8],
    policy: &EffectiveExternalRefPolicy,
) -> Result<LoadedExternalDocument, ExtractError> {
    if bytes.len() > policy.max_document_bytes {
        return Err(ExtractError::SchemaTooLarge {
            location: "x-ferrum-external-refs".to_string(),
        });
    }
    let format = detect_format(bytes);
    let root = match format {
        "json" => serde_json::from_slice(bytes).map_err(|error| {
            ExtractError::InvalidJson(format!(
                "external document {}: {error}",
                redact_reference(uri.as_str())
            ))
        })?,
        _ => {
            // Bound YAML the same way API-spec admission does.
            const MAX_EXTERNAL_DOC_NODES: usize = 500_000;
            super::bounded_yaml::parse_yaml_to_json(bytes, MAX_EXTERNAL_DOC_NODES).map_err(
                |error| {
                    ExtractError::InvalidYaml(format!(
                        "external document {}: {}",
                        redact_reference(uri.as_str()),
                        error.message()
                    ))
                },
            )?
        }
    };
    let digest = normalized_document_digest(&root);
    let mut canonical = uri.clone();
    canonical.set_fragment(None);
    canonical.set_query(None);
    Ok(LoadedExternalDocument {
        canonical_uri: canonical,
        content_digest: digest,
        format,
        root,
        raw_bytes: bytes.to_vec(),
    })
}

fn detect_format(bytes: &[u8]) -> &'static str {
    match bytes.iter().find(|&&b| !b.is_ascii_whitespace()) {
        Some(b'{') | Some(b'[') => "json",
        _ => "yaml",
    }
}

fn file_uri_to_path(uri: &Url) -> Result<PathBuf, ExtractError> {
    if uri.scheme() != "file" {
        return Err(ExtractError::UnsupportedExternalRef {
            reference: redact_reference(uri.as_str()),
        });
    }
    let raw = uri
        .to_file_path()
        .map_err(|_| external_ref_error("external file $ref URI is not a valid filesystem path"))?;
    Ok(raw)
}

#[cfg(unix)]
fn read_contained_file(
    root: &Path,
    candidate: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, ExtractError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let canonical_root = fs::canonicalize(root)
        .map_err(|_| external_ref_error("external-ref file root is not accessible"))?;
    let relative = if candidate.is_absolute() {
        candidate
            .strip_prefix(root)
            .or_else(|_| candidate.strip_prefix(&canonical_root))
            .map_err(|_| {
                external_ref_error("external file $ref target escapes the configured file root")
            })?
    } else {
        candidate
    };
    let mut names = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => names.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(external_ref_error(
                    "external file $ref target escapes the configured file root",
                ));
            }
        }
    }
    let Some((final_component, directory_components)) = names.split_last() else {
        return Err(external_ref_error(
            "external file $ref target must be a regular file",
        ));
    };

    let mut root_options = OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let mut directory = root_options
        .open(&canonical_root)
        .map_err(|_| external_ref_error("external-ref file root is not accessible"))?;

    for name in directory_components {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            external_ref_error("external file $ref path contains an invalid component")
        })?;
        // SAFETY: `directory` is an owned, open directory descriptor and `name`
        // is NUL-terminated. The returned descriptor is immediately owned by
        // `File`; O_NOFOLLOW refuses a swapped symlink component.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(external_ref_error(
                "external file $ref path is not readable without symbolic links",
            ));
        }
        // SAFETY: `openat` returned a new owned descriptor on success.
        directory = unsafe { File::from_raw_fd(fd) };
    }

    let final_name = CString::new(final_component.as_bytes())
        .map_err(|_| external_ref_error("external file $ref path contains an invalid component"))?;
    // O_NONBLOCK prevents a hostile FIFO/device from blocking before metadata
    // verifies that the opened handle is a regular file.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            final_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(external_ref_error(
            "external file $ref target is not readable without symbolic links",
        ));
    }
    // SAFETY: `openat` returned a new owned descriptor on success.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| external_ref_error("external file $ref target is not readable"))?;
    if !metadata.is_file() {
        return Err(external_ref_error(
            "external file $ref target must be a regular file",
        ));
    }
    let read_limit = (max_bytes as u64).saturating_add(1);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| external_ref_error("external file $ref target is not readable"))?;
    if bytes.len() > max_bytes {
        return Err(external_document_too_large());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_contained_file(
    _root: &Path,
    _candidate: &Path,
    _max_bytes: usize,
) -> Result<Vec<u8>, ExtractError> {
    // std does not expose component-relative, no-reparse-point traversal on
    // every supported non-Unix target. Refuse file refs instead of reopening a
    // previously checked pathname and reintroducing containment TOCTOU.
    Err(external_ref_error(
        "external file $ref loading is unsupported on this platform",
    ))
}

/// Canonicalize `candidate` and require it stay under `root` without symlink escape.
pub fn contain_path(root: &Path, candidate: &Path) -> Result<PathBuf, ExtractError> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|_| external_ref_error("external-ref file root is not accessible"))?;
    reject_symlink_chain(&canonical_root)?;
    // Resolve candidate relative to root when not absolute.
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        canonical_root.join(candidate)
    };
    // Lexical traversal is never needed for an admitted canonical base and is
    // rejected before filesystem lookup.
    for component in joined.components() {
        if matches!(component, Component::ParentDir) {
            return Err(external_ref_error(
                "external file $ref target escapes the configured file root",
            ));
        }
    }
    let meta = fs::symlink_metadata(&joined)
        .map_err(|_| external_ref_error("external file $ref target is not readable"))?;
    if meta.file_type().is_symlink() {
        return Err(external_ref_error(
            "external file $ref target must not be a symbolic link",
        ));
    }
    let canonical = fs::canonicalize(&joined)
        .map_err(|_| external_ref_error("external file $ref target is not readable"))?;
    if !canonical.starts_with(&canonical_root) {
        return Err(external_ref_error(
            "external file $ref target escapes the configured file root",
        ));
    }
    reject_symlink_chain(&canonical)?;
    Ok(canonical)
}

fn reject_symlink_chain(path: &Path) -> Result<(), ExtractError> {
    let mut current = path.to_path_buf();
    loop {
        let meta = fs::symlink_metadata(&current)
            .map_err(|_| external_ref_error("external file $ref path is not readable"))?;
        if meta.file_type().is_symlink() {
            return Err(external_ref_error(
                "external file $ref path must not traverse symbolic links",
            ));
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => break,
        }
    }
    Ok(())
}

fn parse_optional_file_root(raw: &str) -> Result<Option<PathBuf>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err(
            "FERRUM_ADMIN_SPEC_EXTERNAL_REFS_FILE_ROOT must be an absolute path".to_string(),
        );
    }
    Ok(Some(path))
}

fn parse_origin_list(raw: &str, https_only: bool) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(canonicalize_origin(part, https_only)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn canonicalize_origin(raw: &str, https_only: bool) -> Result<String, String> {
    let parsed = Url::parse(raw).map_err(|_| "invalid origin".to_string())?;
    if https_only && parsed.scheme() != "https" {
        return Err("origin must be https".to_string());
    }
    if !https_only && parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("origin must be http or https".to_string());
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err("origin must not embed credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("origin must not carry query or fragment".to_string());
    }
    if parsed.path() != "/" && parsed.path() != "" {
        return Err("origin must not carry a path".to_string());
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) => host.to_ascii_lowercase(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => return Err("origin is missing a host".to_string()),
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "origin is missing a port".to_string())?;
    Ok(format!("{}://{}:{}", parsed.scheme(), host, port))
}

fn parse_document_base(raw: &str, process: &ExternalRefProcessPolicy) -> Result<Url, ExtractError> {
    let parsed = Url::parse(raw).map_err(|_| ExtractError::MalformedExtension {
        which: "x-ferrum-external-refs",
        error: "document_base must be an absolute URI".to_string(),
    })?;
    if parsed.username() != "" || parsed.password().is_some() || parsed.query().is_some() {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-external-refs",
            error: "document_base must not embed credentials or a query string".to_string(),
        });
    }
    match parsed.scheme() {
        "file" => {
            let Some(root) = process.file_root.as_ref() else {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error:
                        "document_base file URI requires FERRUM_ADMIN_SPEC_EXTERNAL_REFS_FILE_ROOT"
                            .to_string(),
                });
            };
            // Ensure the declared base stays inside the jail (best-effort when
            // the path does not yet exist: fall back to parent containment).
            if let Ok(path) = parsed.to_file_path() {
                let probe = if path.exists() {
                    path.clone()
                } else {
                    path.parent().unwrap_or(path.as_path()).to_path_buf()
                };
                if probe.exists() {
                    contain_path(root, &probe).map_err(|_| ExtractError::MalformedExtension {
                        which: "x-ferrum-external-refs",
                        error: "document_base escapes the configured file root".to_string(),
                    })?;
                }
            }
        }
        "https" => {
            let origin = origin_key(&parsed).map_err(|error| ExtractError::MalformedExtension {
                which: "x-ferrum-external-refs",
                error: error.to_string(),
            })?;
            if !process.allowed_origins.iter().any(|o| o == &origin) {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "document_base origin is not permitted by process policy".to_string(),
                });
            }
        }
        "http" => {
            let origin = origin_key(&parsed).map_err(|error| ExtractError::MalformedExtension {
                which: "x-ferrum-external-refs",
                error: error.to_string(),
            })?;
            if !process.allow_http_origins.iter().any(|o| o == &origin) {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-external-refs",
                    error: "document_base HTTP origin is not permitted by process policy"
                        .to_string(),
                });
            }
        }
        _ => {
            return Err(ExtractError::MalformedExtension {
                which: "x-ferrum-external-refs",
                error: "document_base scheme must be file, https, or an allowed http origin"
                    .to_string(),
            });
        }
    }
    let mut cleaned = parsed;
    cleaned.set_fragment(None);
    Ok(cleaned)
}

fn origin_key(uri: &Url) -> Result<String, ExtractError> {
    let host = match uri.host() {
        Some(url::Host::Domain(host)) => host.to_ascii_lowercase(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => return Err(external_ref_error("external $ref URI is missing a host")),
    };
    let port = uri
        .port_or_known_default()
        .ok_or_else(|| external_ref_error("external $ref URI is missing a port"))?;
    canonicalize_origin(&format!("{}://{}:{}", uri.scheme(), host, port), false)
        .map_err(|_| external_ref_error("external $ref URI origin is invalid"))
}

fn split_ref(reference: &str) -> (Option<&str>, &str) {
    match reference.split_once('#') {
        Some(("", fragment)) => (None, fragment),
        Some((uri, fragment)) => (Some(uri), fragment),
        None => (Some(reference), ""),
    }
}

pub fn resource_uri_key(url: &Url) -> String {
    let mut owned = url.clone();
    owned.set_fragment(None);
    normalize_percent_escape_case(owned.as_str())
}

fn snapshot_uri_identity(url: &Url) -> String {
    let key = resource_uri_key(url);
    if url.scheme() != "file" {
        return key;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"extref-file-uri-v1\0");
    hash_len_prefixed(&mut hasher, key.as_bytes());
    format!("file:sha256:{}", hex::encode(hasher.finalize()))
}

fn normalize_percent_escape_case(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(offset) = remaining.find('%') {
        normalized.push_str(&remaining[..offset]);
        let escape = &remaining[offset..];
        if escape.len() >= 3
            && escape.as_bytes()[1].is_ascii_hexdigit()
            && escape.as_bytes()[2].is_ascii_hexdigit()
        {
            normalized.push('%');
            normalized.push(char::from(escape.as_bytes()[1].to_ascii_uppercase()));
            normalized.push(char::from(escape.as_bytes()[2].to_ascii_uppercase()));
            remaining = &escape[3..];
        } else {
            normalized.push('%');
            remaining = &escape[1..];
        }
    }
    normalized.push_str(remaining);
    normalized
}

/// Redact userinfo and query from a reference before putting it in errors/logs.
pub fn redact_reference(reference: &str) -> String {
    let path_candidate = strip_query_for_diagnostic(reference);
    let bytes = path_candidate.as_bytes();
    let windows_absolute = bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'/' | b'\\');
    if Path::new(path_candidate).is_absolute()
        || path_candidate.starts_with("//")
        || path_candidate.starts_with("\\\\")
        || windows_absolute
    {
        if path_candidate.starts_with("//") && !path_candidate.starts_with("///") {
            return redact_protocol_relative(reference);
        }
        return "[filesystem path redacted]".to_string();
    }
    let Ok(mut url) = Url::parse(reference) else {
        if let Some(scheme) = reference_scheme(reference) {
            return redacted_scheme(scheme);
        }
        return redact_relative_reference(path_candidate);
    };
    if url.scheme() == "file" {
        return "file:[redacted]".to_string();
    }
    if !matches!(url.scheme(), "http" | "https") {
        return redacted_scheme(url.scheme());
    }
    if url.host().is_none() {
        return redacted_scheme(url.scheme());
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    let rendered = url.as_str();
    truncate_utf8(rendered, 256)
}

fn strip_query_for_diagnostic(reference: &str) -> &str {
    reference
        .split_once('?')
        .map_or(reference, |(path, _)| path)
}

fn redact_protocol_relative(reference: &str) -> String {
    let Ok(mut url) = Url::parse(&format!("https:{reference}")) else {
        return "[network reference redacted]".to_string();
    };
    if url.host().is_none() {
        return "[network reference redacted]".to_string();
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    let rendered = url
        .as_str()
        .strip_prefix("https:")
        .unwrap_or("//[redacted]");
    truncate_utf8(rendered, 256)
}

fn reference_scheme(reference: &str) -> Option<&str> {
    let (scheme, _) = reference.split_once(':')?;
    let mut bytes = scheme.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some(scheme)
}

fn redacted_scheme(scheme: &str) -> String {
    let scheme = truncate_utf8(scheme, 32);
    format!("{}:[redacted]", scheme.to_ascii_lowercase())
}

fn redact_relative_reference(reference: &str) -> String {
    if let Some((_, suffix)) = reference.rsplit_once('@') {
        return truncate_utf8(&format!("[userinfo redacted]@{suffix}"), 128);
    }
    truncate_utf8(reference, 128)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn external_ref_error(message: &str) -> ExtractError {
    ExtractError::SchemaReference(message.to_string())
}
