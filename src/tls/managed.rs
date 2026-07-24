//! File-backed managed TLS material store.
//!
//! Managed records are used by the admin TLS lifecycle endpoints and by the
//! `managed://` source loader. Private key PEM is persisted because rustls
//! needs it to rebuild configs, but API summaries never serialize it.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::config::types::validate_resource_id;
use crate::tls::source::MaterialKind;

const STORE_FILE_NAME: &str = "managed-tls.json";
const DEFAULT_STORE_DIR: &str = "./ferrum-managed-tls";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedTlsMaterialKind {
    Certificate,
    CaBundle,
    Crl,
    OcspResponse,
    Jwks,
}

impl ManagedTlsMaterialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::CaBundle => "ca_bundle",
            Self::Crl => "crl",
            Self::OcspResponse => "ocsp_response",
            Self::Jwks => "jwks",
        }
    }

    pub fn collection_path(self) -> &'static str {
        match self {
            Self::Certificate => "certificates",
            Self::CaBundle => "ca-bundles",
            Self::Crl => "crls",
            Self::OcspResponse => "ocsp-responses",
            Self::Jwks => "jwks",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedTlsRecord {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub kind: ManagedTlsMaterialKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_der_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedTlsRecordSummary {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub kind: ManagedTlsMaterialKind,
    pub source_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<usize>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ManagedMaterial {
    pub bytes: Vec<u8>,
    pub kind: MaterialKind,
    pub source_id: String,
    pub version: Option<String>,
}

#[derive(Debug, Error)]
pub enum ManagedTlsError {
    #[error("managed TLS store path is invalid: {0}")]
    InvalidPath(String),
    #[error("invalid managed TLS id: {0}")]
    InvalidId(String),
    #[error("managed TLS record '{0}' was not found")]
    NotFound(String),
    #[error("managed TLS record '{0}' already exists")]
    AlreadyExists(String),
    #[error(
        "managed TLS record '{id}' already exists as {actual}, cannot overwrite with {expected}"
    )]
    KindConflict {
        id: String,
        actual: &'static str,
        expected: &'static str,
    },
    #[error("managed TLS record '{id}' does not contain {kind} material")]
    MissingMaterial { id: String, kind: &'static str },
    #[error("managed TLS record '{id}' has kind {actual}, expected {expected}")]
    WrongKind {
        id: String,
        actual: &'static str,
        expected: &'static str,
    },
    #[error("failed to read managed TLS store: {0}")]
    Read(String),
    #[error("failed to write managed TLS store: {0}")]
    Write(String),
    #[error("failed to parse managed TLS store: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ManagedTlsStoreFile {
    #[serde(default)]
    records: BTreeMap<String, ManagedTlsRecord>,
}

#[derive(Debug)]
pub struct ManagedTlsStore {
    path: PathBuf,
    records: RwLock<BTreeMap<String, ManagedTlsRecord>>,
}

impl ManagedTlsStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, ManagedTlsError> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(ManagedTlsError::InvalidPath(
                "store directory must not be empty".to_string(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|error| ManagedTlsError::Write(error.to_string()))?;
        let path = dir.join(STORE_FILE_NAME);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<ManagedTlsStoreFile>(&bytes)
                .map_err(|error| ManagedTlsError::Parse(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ManagedTlsStoreFile::default()
            }
            Err(error) => return Err(ManagedTlsError::Read(error.to_string())),
        };
        Ok(Self {
            path,
            records: RwLock::new(file.records),
        })
    }

    pub fn list(&self, kind: ManagedTlsMaterialKind) -> Vec<ManagedTlsRecordSummary> {
        match self.records.read() {
            Ok(records) => records
                .values()
                .filter(|record| record.kind == kind)
                .map(ManagedTlsRecord::summary)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get(&self, id: &str) -> Result<ManagedTlsRecord, ManagedTlsError> {
        validate_managed_id(id)?;
        let records = self
            .records
            .read()
            .map_err(|_| ManagedTlsError::Read("managed TLS store lock is poisoned".to_string()))?;
        records
            .get(id)
            .cloned()
            .ok_or_else(|| ManagedTlsError::NotFound(id.to_string()))
    }

    pub fn upsert(
        &self,
        mut record: ManagedTlsRecord,
        allow_overwrite: bool,
    ) -> Result<ManagedTlsRecord, ManagedTlsError> {
        validate_managed_id(&record.id)?;
        let mut records = self.records.write().map_err(|_| {
            ManagedTlsError::Write("managed TLS store lock is poisoned".to_string())
        })?;
        let now = Utc::now();
        if let Some(existing) = records.get(&record.id) {
            if !allow_overwrite {
                return Err(ManagedTlsError::AlreadyExists(record.id));
            }
            if existing.kind != record.kind {
                return Err(ManagedTlsError::KindConflict {
                    id: record.id,
                    actual: existing.kind.as_str(),
                    expected: record.kind.as_str(),
                });
            }
            record.created_at = existing.created_at;
            record.updated_at = now;
        } else {
            record.created_at = now;
            record.updated_at = now;
        }
        let mut candidate = records.clone();
        candidate.insert(record.id.clone(), record.clone());
        self.persist_locked(&candidate)?;
        *records = candidate;
        Ok(record)
    }

    pub fn delete(&self, id: &str) -> Result<ManagedTlsRecord, ManagedTlsError> {
        validate_managed_id(id)?;
        let mut records = self.records.write().map_err(|_| {
            ManagedTlsError::Write("managed TLS store lock is poisoned".to_string())
        })?;
        if !records.contains_key(id) {
            return Err(ManagedTlsError::NotFound(id.to_string()));
        }
        let mut candidate = records.clone();
        let removed = candidate
            .remove(id)
            .ok_or_else(|| ManagedTlsError::NotFound(id.to_string()))?;
        self.persist_locked(&candidate)?;
        *records = candidate;
        Ok(removed)
    }

    pub fn material(
        &self,
        identifier: &str,
        fallback_kind: MaterialKind,
    ) -> Result<ManagedMaterial, ManagedTlsError> {
        let reference = ManagedSourceReference::parse(identifier, fallback_kind)?;
        let record = self.get(&reference.id)?;
        reference.material_from(record)
    }

    fn persist_locked(
        &self,
        records: &BTreeMap<String, ManagedTlsRecord>,
    ) -> Result<(), ManagedTlsError> {
        let payload = serde_json::to_vec_pretty(&ManagedTlsStoreFile {
            records: records.clone(),
        })
        .map_err(|error| ManagedTlsError::Write(error.to_string()))?;
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| ManagedTlsError::Write(error.to_string()))
    }
}

impl ManagedTlsRecord {
    pub fn new_certificate(
        id: String,
        name: String,
        description: Option<String>,
        cert_pem: String,
        key_pem: String,
        chain_pem: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description,
            kind: ManagedTlsMaterialKind::Certificate,
            cert_pem: Some(cert_pem),
            key_pem: Some(key_pem),
            chain_pem,
            ca_bundle_pem: None,
            crl_pem: None,
            ocsp_der_base64: None,
            jwks_json: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_ca_bundle(
        id: String,
        name: String,
        description: Option<String>,
        ca_bundle_pem: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description,
            kind: ManagedTlsMaterialKind::CaBundle,
            cert_pem: None,
            key_pem: None,
            chain_pem: None,
            ca_bundle_pem: Some(ca_bundle_pem),
            crl_pem: None,
            ocsp_der_base64: None,
            jwks_json: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_crl(id: String, name: String, description: Option<String>, crl_pem: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description,
            kind: ManagedTlsMaterialKind::Crl,
            cert_pem: None,
            key_pem: None,
            chain_pem: None,
            ca_bundle_pem: None,
            crl_pem: Some(crl_pem),
            ocsp_der_base64: None,
            jwks_json: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_ocsp_response(
        id: String,
        name: String,
        description: Option<String>,
        ocsp_der_base64: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description,
            kind: ManagedTlsMaterialKind::OcspResponse,
            cert_pem: None,
            key_pem: None,
            chain_pem: None,
            ca_bundle_pem: None,
            crl_pem: None,
            ocsp_der_base64: Some(ocsp_der_base64),
            jwks_json: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_jwks(
        id: String,
        name: String,
        description: Option<String>,
        jwks_json: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description,
            kind: ManagedTlsMaterialKind::Jwks,
            cert_pem: None,
            key_pem: None,
            chain_pem: None,
            ca_bundle_pem: None,
            crl_pem: None,
            ocsp_der_base64: None,
            jwks_json: Some(jwks_json),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn summary(&self) -> ManagedTlsRecordSummary {
        let public_bytes = self.public_material_bytes();
        let mut summary = ManagedTlsRecordSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            kind: self.kind,
            source_uri: format!("managed://{}/{}", self.kind.collection_path(), self.id),
            subject: None,
            issuer: None,
            sans: Vec::new(),
            not_before: None,
            not_after: None,
            fingerprint_sha256: public_bytes.as_deref().map(fingerprint_hex),
            certificate_count: None,
            crl_count: None,
            byte_length: public_bytes.as_ref().map(Vec::len),
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        match self.kind {
            ManagedTlsMaterialKind::Certificate | ManagedTlsMaterialKind::CaBundle => {
                if let Some(bytes) = public_bytes
                    && let Ok(metadata) = certificate_metadata(&bytes)
                {
                    summary.subject = metadata.subject;
                    summary.issuer = metadata.issuer;
                    summary.sans = metadata.sans;
                    summary.not_before = metadata.not_before;
                    summary.not_after = metadata.not_after;
                    summary.certificate_count = Some(metadata.count);
                }
            }
            ManagedTlsMaterialKind::Crl => {
                if let Some(bytes) = public_bytes
                    && let Ok(count) = count_crls(&bytes)
                {
                    summary.crl_count = Some(count);
                }
            }
            ManagedTlsMaterialKind::OcspResponse | ManagedTlsMaterialKind::Jwks => {}
        }
        summary
    }

    fn public_material_bytes(&self) -> Option<Vec<u8>> {
        match self.kind {
            ManagedTlsMaterialKind::Certificate => {
                let mut pem = self.cert_pem.clone()?;
                if let Some(chain) = self.chain_pem.as_deref() {
                    if !pem.ends_with('\n') {
                        pem.push('\n');
                    }
                    pem.push_str(chain);
                }
                Some(pem.into_bytes())
            }
            ManagedTlsMaterialKind::CaBundle => self
                .ca_bundle_pem
                .as_ref()
                .map(|value| value.as_bytes().to_vec()),
            ManagedTlsMaterialKind::Crl => {
                self.crl_pem.as_ref().map(|value| value.as_bytes().to_vec())
            }
            ManagedTlsMaterialKind::OcspResponse => self
                .ocsp_der_base64
                .as_deref()
                .and_then(|value| decode_base64(value).ok()),
            ManagedTlsMaterialKind::Jwks => self
                .jwks_json
                .as_ref()
                .map(|value| value.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug)]
struct ManagedSourceReference {
    id: String,
    part: ManagedMaterialPart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedMaterialPart {
    Cert,
    Key,
    CaBundle,
    Crl,
    Ocsp,
    Jwks,
}

impl ManagedMaterialPart {
    fn source_suffix(self) -> &'static str {
        match self {
            Self::Cert => "cert",
            Self::Key => "key",
            Self::CaBundle => "ca-bundle",
            Self::Crl => "crl",
            Self::Ocsp => "ocsp",
            Self::Jwks => "jwks",
        }
    }

    fn material_kind(self) -> MaterialKind {
        match self {
            Self::Cert => MaterialKind::Cert,
            Self::Key => MaterialKind::Key,
            Self::CaBundle => MaterialKind::CaBundle,
            Self::Crl => MaterialKind::Crl,
            Self::Ocsp => MaterialKind::Ocsp,
            Self::Jwks => MaterialKind::Jwks,
        }
    }
}

impl ManagedSourceReference {
    fn parse(identifier: &str, fallback_kind: MaterialKind) -> Result<Self, ManagedTlsError> {
        let (path, fragment) = match identifier.split_once('#') {
            Some((path, fragment)) => (path, Some(fragment)),
            None => (identifier, None),
        };
        let id = path
            .rsplit('/')
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ManagedTlsError::InvalidId(identifier.to_string()))?
            .to_string();
        validate_managed_id(&id)?;
        let part = match fragment {
            Some("cert" | "certificate" | "chain") => ManagedMaterialPart::Cert,
            Some("key" | "private-key" | "private_key") => ManagedMaterialPart::Key,
            Some("ca" | "ca-bundle" | "ca_bundle") => ManagedMaterialPart::CaBundle,
            Some("crl") => ManagedMaterialPart::Crl,
            Some("ocsp" | "ocsp-response" | "ocsp_response") => ManagedMaterialPart::Ocsp,
            Some("jwks" | "jwks-json" | "jwks_json") => ManagedMaterialPart::Jwks,
            Some(other) => return Err(ManagedTlsError::InvalidId(format!("unknown managed TLS material part '{other}'"))),
            None => match fallback_kind {
                MaterialKind::Cert => ManagedMaterialPart::Cert,
                MaterialKind::Key => ManagedMaterialPart::Key,
                MaterialKind::CaBundle => ManagedMaterialPart::CaBundle,
                MaterialKind::Crl => ManagedMaterialPart::Crl,
                MaterialKind::Jwks => ManagedMaterialPart::Jwks,
                MaterialKind::Ocsp => ManagedMaterialPart::Ocsp,
                MaterialKind::Unknown => return Err(ManagedTlsError::InvalidId("managed TLS source must include #cert, #key, #ca-bundle, #crl, #ocsp, or #jwks for unknown material kind".to_string())),
            },
        };
        Ok(Self { id, part })
    }

    fn material_from(&self, record: ManagedTlsRecord) -> Result<ManagedMaterial, ManagedTlsError> {
        let (expected_kind, bytes) = match self.part {
            ManagedMaterialPart::Cert => (
                ManagedTlsMaterialKind::Certificate,
                record.public_material_bytes(),
            ),
            ManagedMaterialPart::Key => (
                ManagedTlsMaterialKind::Certificate,
                record
                    .key_pem
                    .as_ref()
                    .map(|value| value.as_bytes().to_vec()),
            ),
            ManagedMaterialPart::CaBundle => (
                ManagedTlsMaterialKind::CaBundle,
                record
                    .ca_bundle_pem
                    .as_ref()
                    .map(|value| value.as_bytes().to_vec()),
            ),
            ManagedMaterialPart::Crl => (
                ManagedTlsMaterialKind::Crl,
                record
                    .crl_pem
                    .as_ref()
                    .map(|value| value.as_bytes().to_vec()),
            ),
            ManagedMaterialPart::Ocsp => (
                ManagedTlsMaterialKind::OcspResponse,
                record
                    .ocsp_der_base64
                    .as_deref()
                    .and_then(|value| decode_base64(value).ok()),
            ),
            ManagedMaterialPart::Jwks => (
                ManagedTlsMaterialKind::Jwks,
                record
                    .jwks_json
                    .as_ref()
                    .map(|value| value.as_bytes().to_vec()),
            ),
        };
        if record.kind != expected_kind {
            return Err(ManagedTlsError::WrongKind {
                id: record.id,
                actual: record.kind.as_str(),
                expected: expected_kind.as_str(),
            });
        }
        let bytes = bytes.ok_or_else(|| ManagedTlsError::MissingMaterial {
            id: record.id.clone(),
            kind: self.part.source_suffix(),
        })?;
        Ok(ManagedMaterial {
            bytes,
            kind: self.part.material_kind(),
            source_id: format!(
                "managed://{}/{}#{}",
                record.kind.collection_path(),
                record.id,
                self.part.source_suffix()
            ),
            version: Some(record.updated_at.to_rfc3339()),
        })
    }
}

#[derive(Debug)]
struct CertificateMetadata {
    subject: Option<String>,
    issuer: Option<String>,
    sans: Vec<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    count: usize,
}

fn certificate_metadata(bytes: &[u8]) -> Result<CertificateMetadata, String> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse PEM certificates: {error}"))?;
    let first = certs
        .first()
        .ok_or_else(|| "no PEM certificates found".to_string())?;
    let (_, parsed) =
        X509Certificate::from_der(first.as_ref()).map_err(|error| error.to_string())?;
    let subject = Some(parsed.subject().to_string());
    let issuer = Some(parsed.issuer().to_string());
    let not_before = DateTime::<Utc>::from_timestamp(parsed.validity().not_before.timestamp(), 0);
    let not_after = DateTime::<Utc>::from_timestamp(parsed.validity().not_after.timestamp(), 0);
    let mut sans = Vec::new();
    for extension in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(value) => sans.push(value.to_string()),
                    GeneralName::URI(value) => sans.push(value.to_string()),
                    GeneralName::IPAddress(bytes) => sans.push(format!("{bytes:?}")),
                    _ => {}
                }
            }
        }
    }
    sans.sort();
    sans.dedup();
    Ok(CertificateMetadata {
        subject,
        issuer,
        sans,
        not_before,
        not_after,
        count: certs.len(),
    })
}

fn count_crls(bytes: &[u8]) -> Result<usize, String> {
    let crls = rustls_pemfile::crls(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse PEM CRLs: {error}"))?;
    if crls.is_empty() {
        return Err("no PEM CRLs found".to_string());
    }
    Ok(crls.len())
}

fn fingerprint_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;

    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|error| format!("invalid base64 material: {error}"))
}

fn validate_managed_id(id: &str) -> Result<(), ManagedTlsError> {
    validate_resource_id(id).map_err(ManagedTlsError::InvalidId)
}

fn managed_store_dir_from_env() -> PathBuf {
    let path = crate::config::env_config::tls_managed_store_path_from_env();
    if path.is_empty() {
        PathBuf::from(DEFAULT_STORE_DIR)
    } else {
        PathBuf::from(path)
    }
}

static GLOBAL_MANAGED_TLS_STORE: OnceLock<Result<Arc<ManagedTlsStore>, String>> = OnceLock::new();

pub fn global_store() -> Result<Arc<ManagedTlsStore>, String> {
    GLOBAL_MANAGED_TLS_STORE
        .get_or_init(|| {
            ManagedTlsStore::open(managed_store_dir_from_env())
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_cert_and_key() -> (String, String) {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    fn assert_no_temp_files(dir: &std::path::Path) {
        for entry in std::fs::read_dir(dir).expect("read store dir") {
            let entry = entry.expect("dir entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.contains(".tmp-"),
                "orphaned temporary file left behind: {name}"
            );
        }
    }

    #[test]
    fn store_persists_and_loads_certificate_parts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        let record = ManagedTlsRecord::new_certificate(
            "edge-cert".to_string(),
            "Edge Cert".to_string(),
            None,
            cert_pem.clone(),
            key_pem.clone(),
            None,
        );

        store.upsert(record, false).expect("upsert");

        let cert = store
            .material("certificates/edge-cert#cert", MaterialKind::Cert)
            .expect("cert material");
        let key = store
            .material("certificates/edge-cert#key", MaterialKind::Key)
            .expect("key material");
        assert_eq!(cert.bytes, cert_pem.into_bytes());
        assert_eq!(key.bytes, key_pem.into_bytes());

        let reopened = ManagedTlsStore::open(dir.path()).expect("reopen store");
        assert_eq!(reopened.list(ManagedTlsMaterialKind::Certificate).len(), 1);
    }

    #[test]
    fn store_rejects_duplicate_without_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        let record = ManagedTlsRecord::new_certificate(
            "edge-cert".to_string(),
            "Edge Cert".to_string(),
            None,
            cert_pem,
            key_pem,
            None,
        );
        store.upsert(record.clone(), false).expect("first upsert");
        let error = store.upsert(record, false).expect_err("duplicate rejected");
        assert!(matches!(error, ManagedTlsError::AlreadyExists(_)));
    }

    #[test]
    fn store_rejects_cross_kind_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        store
            .upsert(
                ManagedTlsRecord::new_ca_bundle(
                    "shared".to_string(),
                    "Shared CA".to_string(),
                    None,
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                        .to_string(),
                ),
                false,
            )
            .expect("create ca bundle");
        let (cert_pem, key_pem) = generated_cert_and_key();
        let error = store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "shared".to_string(),
                    "Shared Cert".to_string(),
                    None,
                    cert_pem,
                    key_pem,
                    None,
                ),
                true,
            )
            .expect_err("cross-kind overwrite rejected");
        assert!(matches!(
            error,
            ManagedTlsError::KindConflict {
                actual: "ca_bundle",
                expected: "certificate",
                ..
            }
        ));
        assert_eq!(
            store.get("shared").expect("still present").kind,
            ManagedTlsMaterialKind::CaBundle
        );
    }

    #[test]
    fn store_loads_ocsp_response_material() {
        use base64::Engine as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        let ocsp_der = vec![0x30, 0x03, 0x0a, 0x01, 0x00];
        let record = ManagedTlsRecord::new_ocsp_response(
            "edge-ocsp".to_string(),
            "Edge OCSP".to_string(),
            None,
            base64::engine::general_purpose::STANDARD.encode(&ocsp_der),
        );
        store.upsert(record, false).expect("upsert");

        let material = store
            .material("ocsp-responses/edge-ocsp#ocsp", MaterialKind::Ocsp)
            .expect("ocsp material");
        assert_eq!(material.bytes, ocsp_der);
        assert_eq!(material.kind, MaterialKind::Ocsp);

        let summaries = store.list(ManagedTlsMaterialKind::OcspResponse);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].byte_length, Some(5));
    }

    #[test]
    fn failed_create_leaves_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "edge-cert".to_string(),
                    "Edge Cert".to_string(),
                    None,
                    cert_pem.clone(),
                    key_pem.clone(),
                    None,
                ),
                false,
            )
            .expect("seed");
        crate::tls::private_file::inject_replace_failure("rename");

        let error = store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "other-cert".to_string(),
                    "Other Cert".to_string(),
                    None,
                    cert_pem,
                    key_pem,
                    None,
                ),
                false,
            )
            .expect_err("create must fail");
        assert!(matches!(error, ManagedTlsError::Write(_)));
        assert!(store.get("other-cert").is_err());
        assert_eq!(store.list(ManagedTlsMaterialKind::Certificate).len(), 1);
        assert_no_temp_files(dir.path());

        let reopened = ManagedTlsStore::open(dir.path()).expect("reopen after failed create");
        assert_eq!(reopened.list(ManagedTlsMaterialKind::Certificate).len(), 1);
        assert_eq!(
            reopened.get("edge-cert").expect("seed retained").id,
            "edge-cert"
        );
    }

    #[test]
    fn failed_update_leaves_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "edge-cert".to_string(),
                    "Edge Cert A".to_string(),
                    None,
                    cert_pem.clone(),
                    key_pem.clone(),
                    None,
                ),
                false,
            )
            .expect("seed");
        let before = store.get("edge-cert").expect("seed get");
        crate::tls::private_file::inject_replace_failure("write");

        let error = store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "edge-cert".to_string(),
                    "Edge Cert B".to_string(),
                    None,
                    cert_pem,
                    key_pem,
                    None,
                ),
                true,
            )
            .expect_err("update must fail");
        assert!(matches!(error, ManagedTlsError::Write(_)));
        let after = store.get("edge-cert").expect("live get");
        assert_eq!(after.name, before.name);
        assert_eq!(after.updated_at, before.updated_at);
        assert_no_temp_files(dir.path());

        let reopened = ManagedTlsStore::open(dir.path()).expect("reopen after failed update");
        assert_eq!(
            reopened.get("edge-cert").expect("disk get").name,
            "Edge Cert A"
        );
    }

    #[test]
    fn failed_delete_leaves_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ManagedTlsStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        store
            .upsert(
                ManagedTlsRecord::new_certificate(
                    "edge-cert".to_string(),
                    "Edge Cert".to_string(),
                    None,
                    cert_pem,
                    key_pem,
                    None,
                ),
                false,
            )
            .expect("seed");
        crate::tls::private_file::inject_replace_failure("rename");

        let error = store.delete("edge-cert").expect_err("delete must fail");
        assert!(matches!(error, ManagedTlsError::Write(_)));
        assert!(store.get("edge-cert").is_ok());
        assert_eq!(
            store
                .material("certificates/edge-cert#cert", MaterialKind::Cert)
                .expect("material")
                .kind,
            MaterialKind::Cert
        );
        assert_no_temp_files(dir.path());

        let reopened = ManagedTlsStore::open(dir.path()).expect("reopen after failed delete");
        assert!(reopened.get("edge-cert").is_ok());
    }
}
