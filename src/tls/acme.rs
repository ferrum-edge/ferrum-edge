//! File-backed ACME-issued certificate material store.
//!
//! The ACME manager persists successfully issued certificates here. The
//! `acme://` source loader reads the stored material so issued certificates
//! flow through the same reload/inventory path as file, provider, Kubernetes,
//! and admin-managed sources.

// This module mixes always-compiled glue (the TLS-ALPN-01 resolver, HTTP-01
// challenge serving) with order/account-store and challenge-validation helpers
// that only have callers behind `#[cfg(feature = "acme")]`. Those helpers are
// intentionally unused in the default (no-`acme`) build, so suppress dead-code
// warnings there; the `acme`-feature build keeps full dead-code linting.
#![cfg_attr(not(feature = "acme"), allow(dead_code))]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
#[cfg(feature = "acme")]
use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(feature = "acme")]
use uuid::Uuid;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::config::types::validate_resource_id;
use crate::tls::source::MaterialKind;

const STORE_FILE_NAME: &str = "acme-certificates.json";
const ORDER_STORE_FILE_NAME: &str = "acme-orders.json";
const ACCOUNT_STORE_FILE_NAME: &str = "acme-accounts.json";
const DEFAULT_STORE_DIR: &str = "./ferrum-managed-tls";
const HTTP01_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
/// Longest HTTP-01 token [`validate_http01_token`] accepts.
const MAX_HTTP01_TOKEN_LEN: usize = 256;
/// Longest raw request target that could still name a valid HTTP-01 challenge.
///
/// The canonical form of such a target is [`HTTP01_CHALLENGE_PREFIX`] plus a
/// token of at most [`MAX_HTTP01_TOKEN_LEN`] bytes, and canonicalization only
/// ever shrinks a target (every accepted escape collapses three raw bytes to
/// one), so the longest raw spelling is the all-escapes spelling. Anything
/// longer cannot resolve to a challenge, so it is discarded before the
/// canonicalizer runs. This matters because HTTP-01 is served ahead of the
/// operator's URL-length limit: the pre-admission lookup must stay bounded.
const MAX_HTTP01_TARGET_LEN: usize = 3 * (HTTP01_CHALLENGE_PREFIX.len() + MAX_HTTP01_TOKEN_LEN);
pub const TLS_ALPN01_PROTOCOL: &[u8] = b"acme-tls/1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AcmeCertificateStatus {
    Issued,
    Renewing,
    Failed,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AcmeOrderStatus {
    PendingChallenges,
    Ready,
    Processing,
    Valid,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeCertificateRecord {
    pub id: String,
    pub domains: Vec<String>,
    pub directory_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_url: Option<String>,
    pub status: AcmeCertificateStatus,
    pub cert_pem: String,
    pub key_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeHttp01ChallengeRecord {
    pub identifier: String,
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeTlsAlpn01ChallengeRecord {
    pub identifier: String,
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDns01ChallengeRecord {
    pub identifier: String,
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrderRecord {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    pub domains: Vec<String>,
    pub directory_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_credentials_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_url: Option<String>,
    pub status: AcmeOrderStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http01_challenges: Vec<AcmeHttp01ChallengeRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_alpn01_challenges: Vec<AcmeTlsAlpn01ChallengeRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns01_challenges: Vec<AcmeDns01ChallengeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccountRecord {
    pub account_id: String,
    pub directory_url: String,
    pub credentials_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct AcmeIssuedCertificateInput {
    pub id: String,
    pub domains: Vec<String>,
    pub directory_url: String,
    pub account_id: Option<String>,
    pub order_url: Option<String>,
    pub cert_pem: String,
    pub key_pem: String,
    pub chain_pem: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AcmeHttp01OrderInput {
    pub id: String,
    pub certificate_id: Option<String>,
    pub domains: Vec<String>,
    pub directory_url: String,
    pub account_id: Option<String>,
    pub account_credentials_json: Option<String>,
    pub order_url: Option<String>,
    pub status: AcmeOrderStatus,
    pub http01_challenges: Vec<AcmeHttp01ChallengeRecord>,
    pub tls_alpn01_challenges: Vec<AcmeTlsAlpn01ChallengeRecord>,
    pub dns01_challenges: Vec<AcmeDns01ChallengeRecord>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeCertificateSummary {
    pub id: String,
    pub domains: Vec<String>,
    pub directory_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_url: Option<String>,
    pub status: AcmeCertificateStatus,
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
    pub byte_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeHttp01ChallengeSummary {
    pub identifier: String,
    pub token: String,
    pub key_authorization: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeTlsAlpn01ChallengeSummary {
    pub identifier: String,
    pub token: String,
    pub key_authorization_sha256_base64url: String,
    pub alpn_protocol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeDns01ChallengeSummary {
    pub identifier: String,
    pub token: String,
    pub txt_record_name: String,
    pub txt_value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeOrderSummary {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    pub domains: Vec<String>,
    pub directory_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_url: Option<String>,
    pub status: AcmeOrderStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http01_challenges: Vec<AcmeHttp01ChallengeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_alpn01_challenges: Vec<AcmeTlsAlpn01ChallengeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns01_challenges: Vec<AcmeDns01ChallengeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeAccountSummary {
    pub account_id: String,
    pub directory_url: String,
    pub order_count: usize,
    pub certificate_count: usize,
    pub has_persisted_credentials: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_order_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_certificate_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct AcmeMaterial {
    pub bytes: Vec<u8>,
    pub kind: MaterialKind,
    pub source_id: String,
    pub version: Option<String>,
}

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME certificate store path is invalid: {0}")]
    InvalidPath(String),
    #[error("invalid ACME certificate id: {0}")]
    InvalidId(String),
    #[error("invalid ACME certificate domain: {0}")]
    InvalidDomain(String),
    #[error("ACME certificate '{0}' was not found")]
    NotFound(String),
    #[error("ACME certificate '{0}' already exists")]
    AlreadyExists(String),
    #[error("ACME order '{0}' was not found")]
    OrderNotFound(String),
    #[error("ACME order '{0}' already exists")]
    OrderAlreadyExists(String),
    #[error("invalid ACME HTTP-01 challenge token: {0}")]
    InvalidChallengeToken(String),
    #[error("ACME certificate '{id}' does not contain {kind} material")]
    MissingMaterial { id: String, kind: &'static str },
    #[error("failed to read ACME certificate store: {0}")]
    Read(String),
    #[error("failed to write ACME certificate store: {0}")]
    Write(String),
    #[error("failed to parse ACME certificate store: {0}")]
    Parse(String),
    #[error("ACME directory URL is not permitted: {0}")]
    BlockedDirectoryUrl(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AcmeCertificateStoreFile {
    #[serde(default)]
    certificates: BTreeMap<String, AcmeCertificateRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AcmeOrderStoreFile {
    #[serde(default)]
    orders: BTreeMap<String, AcmeOrderRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AcmeAccountStoreFile {
    #[serde(default)]
    accounts: BTreeMap<String, AcmeAccountRecord>,
}

#[derive(Debug)]
pub struct AcmeCertificateStore {
    path: PathBuf,
    certificates: RwLock<BTreeMap<String, AcmeCertificateRecord>>,
}

#[derive(Debug)]
pub struct AcmeOrderStore {
    path: PathBuf,
    orders: RwLock<BTreeMap<String, AcmeOrderRecord>>,
}

#[derive(Debug)]
pub struct AcmeAccountStore {
    path: PathBuf,
    accounts: RwLock<BTreeMap<String, AcmeAccountRecord>>,
}

impl AcmeCertificateStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, AcmeError> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(AcmeError::InvalidPath(
                "store directory must not be empty".to_string(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|error| AcmeError::Write(error.to_string()))?;
        let path = dir.join(STORE_FILE_NAME);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<AcmeCertificateStoreFile>(&bytes)
                .map_err(|error| AcmeError::Parse(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                AcmeCertificateStoreFile::default()
            }
            Err(error) => return Err(AcmeError::Read(error.to_string())),
        };
        Ok(Self {
            path,
            certificates: RwLock::new(file.certificates),
        })
    }

    pub fn list_certificates(&self) -> Vec<AcmeCertificateSummary> {
        match self.certificates.read() {
            Ok(certificates) => certificates
                .values()
                .map(AcmeCertificateRecord::summary)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    #[cfg(feature = "acme")]
    pub fn list_certificate_records(&self) -> Vec<AcmeCertificateRecord> {
        match self.certificates.read() {
            Ok(certificates) => certificates.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get_certificate(&self, id: &str) -> Result<AcmeCertificateRecord, AcmeError> {
        validate_acme_id(id)?;
        let certificates = self
            .certificates
            .read()
            .map_err(|_| AcmeError::Read("ACME certificate store lock is poisoned".to_string()))?;
        certificates
            .get(id)
            .cloned()
            .ok_or_else(|| AcmeError::NotFound(id.to_string()))
    }

    pub fn upsert_certificate(
        &self,
        mut record: AcmeCertificateRecord,
        allow_overwrite: bool,
    ) -> Result<AcmeCertificateRecord, AcmeError> {
        validate_acme_id(&record.id)?;
        validate_acme_domains(&record.domains)?;
        let mut certificates = self
            .certificates
            .write()
            .map_err(|_| AcmeError::Write("ACME certificate store lock is poisoned".to_string()))?;
        let now = Utc::now();
        if let Some(existing) = certificates.get(&record.id) {
            if !allow_overwrite {
                return Err(AcmeError::AlreadyExists(record.id));
            }
            record.created_at = existing.created_at;
            record.updated_at = now;
        } else {
            record.created_at = now;
            record.updated_at = now;
        }
        let mut candidate = certificates.clone();
        candidate.insert(record.id.clone(), record.clone());
        self.persist_locked(&candidate)?;
        *certificates = candidate;
        Ok(record)
    }

    pub fn delete_certificate(&self, id: &str) -> Result<AcmeCertificateRecord, AcmeError> {
        validate_acme_id(id)?;
        let mut certificates = self
            .certificates
            .write()
            .map_err(|_| AcmeError::Write("ACME certificate store lock is poisoned".to_string()))?;
        let mut candidate = certificates.clone();
        let removed = candidate
            .remove(id)
            .ok_or_else(|| AcmeError::NotFound(id.to_string()))?;
        self.persist_locked(&candidate)?;
        *certificates = candidate;
        Ok(removed)
    }

    pub fn material(
        &self,
        identifier: &str,
        fallback_kind: MaterialKind,
    ) -> Result<AcmeMaterial, AcmeError> {
        let reference = AcmeSourceReference::parse(identifier, fallback_kind)?;
        let record = self.get_certificate(&reference.id)?;
        reference.material_from(record)
    }

    fn persist_locked(
        &self,
        certificates: &BTreeMap<String, AcmeCertificateRecord>,
    ) -> Result<(), AcmeError> {
        let payload = serde_json::to_vec_pretty(&AcmeCertificateStoreFile {
            certificates: certificates.clone(),
        })
        .map_err(|error| AcmeError::Write(error.to_string()))?;
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| AcmeError::Write(error.to_string()))?;
        Ok(())
    }
}

impl AcmeOrderStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, AcmeError> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(AcmeError::InvalidPath(
                "store directory must not be empty".to_string(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|error| AcmeError::Write(error.to_string()))?;
        let path = dir.join(ORDER_STORE_FILE_NAME);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<AcmeOrderStoreFile>(&bytes)
                .map_err(|error| AcmeError::Parse(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                AcmeOrderStoreFile::default()
            }
            Err(error) => return Err(AcmeError::Read(error.to_string())),
        };
        Ok(Self {
            path,
            orders: RwLock::new(file.orders),
        })
    }

    pub fn list_orders(&self) -> Vec<AcmeOrderSummary> {
        match self.orders.read() {
            Ok(orders) => orders.values().map(AcmeOrderRecord::summary).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get_order(&self, id: &str) -> Result<AcmeOrderRecord, AcmeError> {
        validate_acme_id(id)?;
        let orders = self
            .orders
            .read()
            .map_err(|_| AcmeError::Read("ACME order store lock is poisoned".to_string()))?;
        orders
            .get(id)
            .cloned()
            .ok_or_else(|| AcmeError::OrderNotFound(id.to_string()))
    }

    pub fn latest_order_for_certificate(
        &self,
        certificate_id: &str,
    ) -> Result<Option<AcmeOrderRecord>, AcmeError> {
        validate_acme_id(certificate_id)?;
        let orders = self
            .orders
            .read()
            .map_err(|_| AcmeError::Read("ACME order store lock is poisoned".to_string()))?;
        Ok(orders
            .values()
            .filter(|order| order.certificate_id.as_deref() == Some(certificate_id))
            .max_by_key(|order| order.updated_at)
            .cloned())
    }

    pub fn upsert_order(
        &self,
        mut record: AcmeOrderRecord,
        allow_overwrite: bool,
    ) -> Result<AcmeOrderRecord, AcmeError> {
        validate_acme_id(&record.id)?;
        if let Some(certificate_id) = record.certificate_id.as_deref() {
            validate_acme_id(certificate_id)?;
        }
        validate_acme_domains(&record.domains)?;
        validate_http01_challenges(&record.http01_challenges)?;
        validate_tls_alpn01_challenges(&record.tls_alpn01_challenges)?;
        validate_dns01_challenges(&record.dns01_challenges)?;
        let mut orders = self
            .orders
            .write()
            .map_err(|_| AcmeError::Write("ACME order store lock is poisoned".to_string()))?;
        let now = Utc::now();
        if let Some(existing) = orders.get(&record.id) {
            if !allow_overwrite {
                return Err(AcmeError::OrderAlreadyExists(record.id));
            }
            record.created_at = existing.created_at;
            record.updated_at = now;
        } else {
            record.created_at = now;
            record.updated_at = now;
        }
        let mut candidate = orders.clone();
        candidate.insert(record.id.clone(), record.clone());
        self.persist_locked(&candidate)?;
        *orders = candidate;
        Ok(record)
    }

    pub fn delete_order(&self, id: &str) -> Result<AcmeOrderRecord, AcmeError> {
        validate_acme_id(id)?;
        let mut orders = self
            .orders
            .write()
            .map_err(|_| AcmeError::Write("ACME order store lock is poisoned".to_string()))?;
        let mut candidate = orders.clone();
        let removed = candidate
            .remove(id)
            .ok_or_else(|| AcmeError::OrderNotFound(id.to_string()))?;
        self.persist_locked(&candidate)?;
        *orders = candidate;
        Ok(removed)
    }

    pub fn http01_key_authorization(&self, token: &str) -> Option<String> {
        if validate_http01_token(token).is_err() {
            return None;
        }
        let orders = self.orders.read().ok()?;
        orders
            .values()
            .filter(|order| {
                matches!(
                    order.status,
                    AcmeOrderStatus::PendingChallenges
                        | AcmeOrderStatus::Ready
                        | AcmeOrderStatus::Processing
                )
            })
            .flat_map(|order| order.http01_challenges.iter())
            .find(|challenge| challenge.token == token)
            .map(|challenge| challenge.key_authorization.clone())
    }

    pub fn tls_alpn01_key_authorization(&self, identifier: &str) -> Option<String> {
        let identifier = normalize_tls_alpn_identifier(identifier)?;
        let orders = self.orders.read().ok()?;
        orders
            .values()
            .filter(|order| {
                matches!(
                    order.status,
                    AcmeOrderStatus::PendingChallenges
                        | AcmeOrderStatus::Ready
                        | AcmeOrderStatus::Processing
                )
            })
            .flat_map(|order| order.tls_alpn01_challenges.iter())
            .find(|challenge| {
                normalize_tls_alpn_identifier(&challenge.identifier) == Some(identifier.clone())
            })
            .map(|challenge| challenge.key_authorization.clone())
    }

    pub fn list_accounts(
        &self,
        certificates: &[AcmeCertificateSummary],
        persisted_accounts: &[AcmeAccountRecord],
    ) -> Vec<AcmeAccountSummary> {
        let mut accounts = BTreeMap::new();
        for persisted in persisted_accounts {
            let account = account_summary_entry(
                &mut accounts,
                &persisted.account_id,
                &persisted.directory_url,
            );
            account.has_persisted_credentials = true;
            account.last_order_at = max_datetime(account.last_order_at, persisted.last_used_at);
        }
        for certificate in certificates {
            let Some(account_id) = certificate.account_id.as_deref() else {
                continue;
            };
            let account =
                account_summary_entry(&mut accounts, account_id, &certificate.directory_url);
            account.certificate_count += 1;
            account.last_certificate_updated_at = max_datetime(
                account.last_certificate_updated_at,
                Some(certificate.updated_at),
            );
        }
        if let Ok(orders) = self.orders.read() {
            for order in orders.values() {
                let Some(account_id) = order.account_id.as_deref() else {
                    continue;
                };
                let account =
                    account_summary_entry(&mut accounts, account_id, &order.directory_url);
                account.order_count += 1;
                account.has_persisted_credentials |= order.account_credentials_json.is_some();
                account.last_order_at = max_datetime(account.last_order_at, Some(order.updated_at));
            }
        }
        accounts.into_values().collect()
    }

    fn persist_locked(&self, orders: &BTreeMap<String, AcmeOrderRecord>) -> Result<(), AcmeError> {
        let payload = serde_json::to_vec_pretty(&AcmeOrderStoreFile {
            orders: orders.clone(),
        })
        .map_err(|error| AcmeError::Write(error.to_string()))?;
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| AcmeError::Write(error.to_string()))?;
        Ok(())
    }
}

impl AcmeAccountStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, AcmeError> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(AcmeError::InvalidPath(
                "store directory must not be empty".to_string(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|error| AcmeError::Write(error.to_string()))?;
        let path = dir.join(ACCOUNT_STORE_FILE_NAME);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<AcmeAccountStoreFile>(&bytes)
                .map_err(|error| AcmeError::Parse(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                AcmeAccountStoreFile::default()
            }
            Err(error) => return Err(AcmeError::Read(error.to_string())),
        };
        Ok(Self {
            path,
            accounts: RwLock::new(file.accounts),
        })
    }

    pub fn list_accounts(&self) -> Vec<AcmeAccountRecord> {
        match self.accounts.read() {
            Ok(accounts) => accounts.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get_credentials(
        &self,
        directory_url: &str,
        account_id: &str,
    ) -> Result<Option<String>, AcmeError> {
        validate_acme_directory_url(directory_url)?;
        validate_acme_account_identifier(account_id)?;
        let key = acme_account_store_key(directory_url, account_id);
        let accounts = self
            .accounts
            .read()
            .map_err(|_| AcmeError::Read("ACME account store lock is poisoned".to_string()))?;
        Ok(accounts
            .get(&key)
            .map(|account| account.credentials_json.clone()))
    }

    pub fn upsert_account(
        &self,
        account_id: String,
        directory_url: String,
        credentials_json: String,
    ) -> Result<AcmeAccountRecord, AcmeError> {
        validate_acme_directory_url(&directory_url)?;
        validate_acme_account_identifier(&account_id)?;
        validate_acme_account_credentials_json(&credentials_json)?;
        let key = acme_account_store_key(&directory_url, &account_id);
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| AcmeError::Write("ACME account store lock is poisoned".to_string()))?;
        let now = Utc::now();
        let record = if let Some(existing) = accounts.get(&key) {
            AcmeAccountRecord {
                account_id,
                directory_url,
                credentials_json,
                created_at: existing.created_at,
                updated_at: now,
                last_used_at: Some(now),
            }
        } else {
            AcmeAccountRecord {
                account_id,
                directory_url,
                credentials_json,
                created_at: now,
                updated_at: now,
                last_used_at: Some(now),
            }
        };
        let mut candidate = accounts.clone();
        candidate.insert(key, record.clone());
        self.persist_locked(&candidate)?;
        *accounts = candidate;
        Ok(record)
    }

    fn persist_locked(
        &self,
        accounts: &BTreeMap<String, AcmeAccountRecord>,
    ) -> Result<(), AcmeError> {
        let payload = serde_json::to_vec_pretty(&AcmeAccountStoreFile {
            accounts: accounts.clone(),
        })
        .map_err(|error| AcmeError::Write(error.to_string()))?;
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| AcmeError::Write(error.to_string()))?;
        Ok(())
    }
}

fn account_summary_entry<'a>(
    accounts: &'a mut BTreeMap<(String, String), AcmeAccountSummary>,
    account_id: &str,
    directory_url: &str,
) -> &'a mut AcmeAccountSummary {
    accounts
        .entry((directory_url.to_string(), account_id.to_string()))
        .or_insert_with(|| AcmeAccountSummary {
            account_id: account_id.to_string(),
            directory_url: directory_url.to_string(),
            order_count: 0,
            certificate_count: 0,
            has_persisted_credentials: false,
            last_order_at: None,
            last_certificate_updated_at: None,
        })
}

fn max_datetime(
    current: Option<DateTime<Utc>>,
    candidate: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

impl AcmeCertificateRecord {
    pub fn new_issued(input: AcmeIssuedCertificateInput) -> Result<Self, AcmeError> {
        validate_acme_domains(&input.domains)?;
        let now = Utc::now();
        let not_after = certificate_metadata(
            combined_public_material(&input.cert_pem, input.chain_pem.as_deref()).as_bytes(),
        )
        .ok()
        .and_then(|metadata| metadata.not_after);
        Ok(Self {
            id: input.id,
            domains: input.domains,
            directory_url: input.directory_url,
            account_id: input.account_id,
            order_url: input.order_url,
            status: AcmeCertificateStatus::Issued,
            cert_pem: input.cert_pem,
            key_pem: input.key_pem,
            chain_pem: input.chain_pem,
            issued_at: Some(now),
            not_after,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn summary(&self) -> AcmeCertificateSummary {
        let public_material = self.public_material();
        let mut summary = AcmeCertificateSummary {
            id: self.id.clone(),
            domains: self.domains.clone(),
            directory_url: self.directory_url.clone(),
            account_id: self.account_id.clone(),
            order_url: self.order_url.clone(),
            status: self.status,
            source_uri: format!("acme://certificates/{}", self.id),
            subject: None,
            issuer: None,
            sans: Vec::new(),
            not_before: None,
            not_after: self.not_after,
            fingerprint_sha256: Some(fingerprint_hex(public_material.as_bytes())),
            certificate_count: None,
            byte_length: Some(public_material.len()),
            issued_at: self.issued_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        if let Ok(metadata) = certificate_metadata(public_material.as_bytes()) {
            summary.subject = metadata.subject;
            summary.issuer = metadata.issuer;
            summary.sans = metadata.sans;
            summary.not_before = metadata.not_before;
            summary.not_after = metadata.not_after.or(summary.not_after);
            summary.certificate_count = Some(metadata.count);
        }
        summary
    }

    fn public_material(&self) -> String {
        combined_public_material(&self.cert_pem, self.chain_pem.as_deref())
    }
}

impl AcmeOrderRecord {
    pub fn new_http01(input: AcmeHttp01OrderInput) -> Result<Self, AcmeError> {
        validate_acme_domains(&input.domains)?;
        if let Some(certificate_id) = input.certificate_id.as_deref() {
            validate_acme_id(certificate_id)?;
        }
        validate_http01_challenges(&input.http01_challenges)?;
        validate_tls_alpn01_challenges(&input.tls_alpn01_challenges)?;
        validate_dns01_challenges(&input.dns01_challenges)?;
        let now = Utc::now();
        Ok(Self {
            id: input.id,
            certificate_id: input.certificate_id,
            domains: input.domains,
            directory_url: input.directory_url,
            account_id: input.account_id,
            account_credentials_json: input.account_credentials_json,
            order_url: input.order_url,
            status: input.status,
            http01_challenges: input.http01_challenges,
            tls_alpn01_challenges: input.tls_alpn01_challenges,
            dns01_challenges: input.dns01_challenges,
            error: input.error,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn summary(&self) -> AcmeOrderSummary {
        AcmeOrderSummary {
            id: self.id.clone(),
            certificate_id: self.certificate_id.clone(),
            domains: self.domains.clone(),
            directory_url: self.directory_url.clone(),
            account_id: self.account_id.clone(),
            order_url: self.order_url.clone(),
            status: self.status,
            http01_challenges: self
                .http01_challenges
                .iter()
                .map(AcmeHttp01ChallengeRecord::summary)
                .collect(),
            tls_alpn01_challenges: self
                .tls_alpn01_challenges
                .iter()
                .map(AcmeTlsAlpn01ChallengeRecord::summary)
                .collect(),
            dns01_challenges: self
                .dns01_challenges
                .iter()
                .map(AcmeDns01ChallengeRecord::summary)
                .collect(),
            error: self.error.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl AcmeHttp01ChallengeRecord {
    pub fn summary(&self) -> AcmeHttp01ChallengeSummary {
        AcmeHttp01ChallengeSummary {
            identifier: self.identifier.clone(),
            token: self.token.clone(),
            key_authorization: self.key_authorization.clone(),
            path: format!("{HTTP01_CHALLENGE_PREFIX}{}", self.token),
        }
    }
}

impl AcmeTlsAlpn01ChallengeRecord {
    pub fn summary(&self) -> AcmeTlsAlpn01ChallengeSummary {
        AcmeTlsAlpn01ChallengeSummary {
            identifier: self.identifier.clone(),
            token: self.token.clone(),
            key_authorization_sha256_base64url: key_authorization_sha256_base64url(
                &self.key_authorization,
            ),
            alpn_protocol: String::from_utf8_lossy(TLS_ALPN01_PROTOCOL).to_string(),
        }
    }
}

impl AcmeDns01ChallengeRecord {
    pub fn summary(&self) -> AcmeDns01ChallengeSummary {
        let txt_record_name = dns01_txt_record_name(&self.identifier).unwrap_or_default();
        AcmeDns01ChallengeSummary {
            identifier: self.identifier.clone(),
            token: self.token.clone(),
            txt_record_name,
            txt_value: key_authorization_sha256_base64url(&self.key_authorization),
        }
    }
}

#[derive(Debug)]
struct AcmeSourceReference {
    id: String,
    part: AcmeMaterialPart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcmeMaterialPart {
    Cert,
    Key,
}

impl AcmeMaterialPart {
    fn source_suffix(self) -> &'static str {
        match self {
            Self::Cert => "cert",
            Self::Key => "key",
        }
    }

    fn material_kind(self) -> MaterialKind {
        match self {
            Self::Cert => MaterialKind::Cert,
            Self::Key => MaterialKind::Key,
        }
    }
}

impl AcmeSourceReference {
    fn parse(identifier: &str, fallback_kind: MaterialKind) -> Result<Self, AcmeError> {
        let (path, fragment) = match identifier.split_once('#') {
            Some((path, fragment)) => (path, Some(fragment)),
            None => (identifier, None),
        };
        let id = path
            .rsplit('/')
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AcmeError::InvalidId(identifier.to_string()))?
            .to_string();
        validate_acme_id(&id)?;
        let part = match fragment {
            Some("cert" | "certificate" | "chain") => AcmeMaterialPart::Cert,
            Some("key" | "private-key" | "private_key") => AcmeMaterialPart::Key,
            Some(other) => {
                return Err(AcmeError::InvalidId(format!(
                    "unknown ACME certificate material part '{other}'"
                )));
            }
            None => match fallback_kind {
                MaterialKind::Cert => AcmeMaterialPart::Cert,
                MaterialKind::Key => AcmeMaterialPart::Key,
                MaterialKind::Unknown => {
                    return Err(AcmeError::InvalidId(
                        "ACME certificate source must include #cert or #key for unknown material kind"
                            .to_string(),
                    ));
                }
                other => {
                    return Err(AcmeError::InvalidId(format!(
                        "ACME certificate source does not support {} material",
                        other.as_str()
                    )));
                }
            },
        };
        Ok(Self { id, part })
    }

    fn material_from(&self, record: AcmeCertificateRecord) -> Result<AcmeMaterial, AcmeError> {
        let bytes = match self.part {
            AcmeMaterialPart::Cert => Some(record.public_material().into_bytes()),
            AcmeMaterialPart::Key => Some(record.key_pem.as_bytes().to_vec()),
        }
        .ok_or_else(|| AcmeError::MissingMaterial {
            id: record.id.clone(),
            kind: self.part.source_suffix(),
        })?;
        Ok(AcmeMaterial {
            bytes,
            kind: self.part.material_kind(),
            source_id: format!(
                "acme://certificates/{}#{}",
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

fn combined_public_material(cert_pem: &str, chain_pem: Option<&str>) -> String {
    let Some(chain_pem) = chain_pem else {
        return cert_pem.to_string();
    };
    let mut combined = cert_pem.to_string();
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(chain_pem);
    combined
}

fn fingerprint_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_acme_id(id: &str) -> Result<(), AcmeError> {
    validate_resource_id(id).map_err(AcmeError::InvalidId)
}

fn validate_acme_domains(domains: &[String]) -> Result<(), AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::InvalidDomain(
            "at least one domain is required".to_string(),
        ));
    }
    for domain in domains {
        let trimmed = domain.trim();
        if trimmed.is_empty() {
            return Err(AcmeError::InvalidDomain(
                "domain must not be empty".to_string(),
            ));
        }
        if trimmed.len() > 253 {
            return Err(AcmeError::InvalidDomain(format!(
                "domain '{trimmed}' exceeds 253 bytes"
            )));
        }
        if trimmed
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(AcmeError::InvalidDomain(format!(
                "domain '{trimmed}' must not contain whitespace or control characters"
            )));
        }
    }
    Ok(())
}

fn validate_acme_directory_url(directory_url: &str) -> Result<(), AcmeError> {
    let directory_url = directory_url.trim();
    if directory_url.is_empty() {
        return Err(AcmeError::InvalidId(
            "ACME directory URL must not be empty".to_string(),
        ));
    }
    if directory_url.len() > 2048 || directory_url.chars().any(char::is_control) {
        return Err(AcmeError::InvalidId(
            "ACME directory URL is invalid".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcmeEndpointOrigin {
    host: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct AcmeEndpointPolicy {
    directory: url::Url,
    origin: AcmeEndpointOrigin,
}

fn acme_public_egress_policy() -> crate::config::BackendEgressPolicy {
    crate::config::BackendEgressPolicy::from_allow_ips(crate::config::BackendAllowIps::Public)
}

/// Return whether a host has the lexical shape of a legacy numeric IPv4 address.
///
/// WHATWG URL parsing canonicalizes many of these forms to IPv4, but deliberately
/// does not recognize every spelling accepted by platform resolvers. In
/// particular, mixed dotted decimal/hex can remain a `Domain` and reach DNS or
/// `getaddrinfo`. ACME rejects the complete ambiguous grammar rather than trying
/// to reproduce each platform's value/range rules:
///
/// - a single optionally signed decimal, octal-looking, or `0x`/`0X` integer;
/// - two or more dotted components where every component is decimal/octal-looking
///   or explicitly hexadecimal, with an optional sign on each component.
///
/// Range and component-count checks are intentionally absent. Overflow and
/// overlong dotted forms are still numeric-looking and must fail closed instead
/// of changing classification across parsers or operating systems.
fn is_ambiguous_legacy_numeric_ipv4_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }

    let is_numeric_component = |component: &str| {
        let component = component
            .strip_prefix('+')
            .or_else(|| component.strip_prefix('-'))
            .unwrap_or(component);
        if component.is_empty() {
            return false;
        }
        if component.bytes().all(|byte| byte.is_ascii_digit()) {
            return true;
        }
        component
            .strip_prefix("0x")
            .or_else(|| component.strip_prefix("0X"))
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    };

    if !host.contains('.') {
        return is_numeric_component(host);
    }
    host.split('.').all(is_numeric_component)
}

fn reject_non_canonical_acme_host(label: &'static str) -> AcmeError {
    AcmeError::BlockedDirectoryUrl(format!(
        "{label} host must be a DNS name or canonical IP literal"
    ))
}

/// Cross-check the raw URI host against the WHATWG-parsed host before its
/// normalized representation is trusted for origin comparison or dialing.
fn validate_acme_host_spelling(
    raw_host: &str,
    parsed: &url::Url,
    label: &'static str,
) -> Result<(), AcmeError> {
    // DNS names do not require percent encoding. Reject it at this boundary so
    // decoding cannot turn an apparently non-numeric host into a numeric literal
    // (or make the RFC URI and WHATWG parsers classify different authorities).
    if raw_host.contains('%') {
        return Err(reject_non_canonical_acme_host(label));
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => {
            // Only canonical dotted decimal is admitted. This rejects integer,
            // alternate-radix, abbreviated, Unicode/IDNA-normalized, leading-zero,
            // trailing-dot, bracketed, and overflow-dependent spellings even when
            // the URL parser happens to canonicalize one of them to IPv4.
            let canonical = ip.to_string();
            if raw_host != canonical.as_str() {
                return Err(reject_non_canonical_acme_host(label));
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            // IPv6 must use URI brackets, but all standard textual compression
            // and hex-case choices remain valid.
            let Some(bare) = raw_host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
            else {
                return Err(reject_non_canonical_acme_host(label));
            };
            if bare.parse::<std::net::Ipv6Addr>().ok() != Some(ip) {
                return Err(reject_non_canonical_acme_host(label));
            }
        }
        Some(url::Host::Domain(domain)) => {
            // Check both parser views. The raw view catches forms URL leaves as a
            // domain (the mixed dotted-hex regression); the normalized view closes
            // case/IDNA normalization differences without rejecting ordinary DNS.
            if is_ambiguous_legacy_numeric_ipv4_host(raw_host)
                || is_ambiguous_legacy_numeric_ipv4_host(domain)
            {
                return Err(reject_non_canonical_acme_host(label));
            }
        }
        None => {
            return Err(AcmeError::BlockedDirectoryUrl(format!(
                "{label} must include a host"
            )));
        }
    }
    Ok(())
}

fn parse_acme_https_endpoint(raw: &str, label: &'static str) -> Result<url::Url, AcmeError> {
    let uri = raw.parse::<http::Uri>().map_err(|_| {
        AcmeError::BlockedDirectoryUrl(format!("{label} must be a valid absolute URL"))
    })?;
    if uri.scheme_str() != Some("https") || uri.authority().is_none() {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} must be an absolute HTTPS URL with an authority"
        )));
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} must not include userinfo"
        )));
    }
    let raw_host = uri
        .host()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| AcmeError::BlockedDirectoryUrl(format!("{label} must include a host")))?;
    let parsed = url::Url::parse(raw).map_err(|_| {
        AcmeError::BlockedDirectoryUrl(format!("{label} must be a valid absolute URL"))
    })?;
    if parsed.scheme() != "https" {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} must use the https scheme"
        )));
    }
    if parsed.host().is_none() {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} must include a host"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} must not include userinfo"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} must not include a fragment"
        )));
    }
    validate_acme_host_spelling(raw_host, &parsed, label)?;
    if let Some(ip) = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    } && let Some(reason) = acme_public_egress_policy().deny_reason(&ip)
    {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "{label} host IP is denied by ACME egress policy: {reason}"
        )));
    }
    Ok(parsed)
}

impl AcmeEndpointPolicy {
    fn new(directory_url: &str) -> Result<Self, AcmeError> {
        let directory = parse_acme_https_endpoint(directory_url.trim(), "directory URL")?;
        let host = directory
            .host_str()
            .ok_or_else(|| {
                AcmeError::BlockedDirectoryUrl("directory URL must include a host".to_string())
            })?
            .to_ascii_lowercase();
        let port = directory.port_or_known_default().ok_or_else(|| {
            AcmeError::BlockedDirectoryUrl(
                "directory URL must include a valid HTTPS port".to_string(),
            )
        })?;
        Ok(Self {
            directory,
            origin: AcmeEndpointOrigin { host, port },
        })
    }

    fn validate_endpoint(
        &self,
        endpoint: &str,
        label: &'static str,
    ) -> Result<url::Url, AcmeError> {
        let parsed = parse_acme_https_endpoint(endpoint, label)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| AcmeError::BlockedDirectoryUrl(format!("{label} must include a host")))?
            .to_ascii_lowercase();
        let port = parsed.port_or_known_default().ok_or_else(|| {
            AcmeError::BlockedDirectoryUrl(format!("{label} must include a valid HTTPS port"))
        })?;
        if host != self.origin.host || port != self.origin.port {
            return Err(AcmeError::BlockedDirectoryUrl(format!(
                "{label} must use the configured ACME directory origin"
            )));
        }
        Ok(parsed)
    }

    fn validate_directory_match(&self, embedded: &str) -> Result<(), AcmeError> {
        let embedded = self.validate_endpoint(embedded, "credential directory URL")?;
        if embedded != self.directory {
            return Err(AcmeError::BlockedDirectoryUrl(
                "credential directory URL does not match the configured directory URL".to_string(),
            ));
        }
        Ok(())
    }
}

/// Validate an operator-supplied ACME directory before any outbound activity.
///
/// Hostnames receive their authoritative public-only decision later, from the
/// Ferrum-controlled connector after fresh whole-answer DNS resolution.
pub(crate) fn validate_acme_directory_url_ssrf_policy(
    directory_url: &str,
) -> Result<(), AcmeError> {
    AcmeEndpointPolicy::new(directory_url).map(|_| ())
}

fn validate_acme_account_identifier(account_id: &str) -> Result<(), AcmeError> {
    let account_id = account_id.trim();
    if account_id.is_empty() {
        return Err(AcmeError::InvalidId(
            "ACME account id must not be empty".to_string(),
        ));
    }
    if account_id.len() > 2048 || account_id.chars().any(char::is_control) {
        return Err(AcmeError::InvalidId(
            "ACME account id is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_acme_account_credentials_json(credentials_json: &str) -> Result<(), AcmeError> {
    if credentials_json.trim().is_empty() {
        return Err(AcmeError::InvalidId(
            "ACME account credentials must not be empty".to_string(),
        ));
    }
    serde_json::from_str::<serde_json::Value>(credentials_json)
        .map_err(|error| AcmeError::Parse(error.to_string()))?;
    Ok(())
}

fn acme_account_store_key(directory_url: &str, account_id: &str) -> String {
    fingerprint_hex(format!("{directory_url}\0{account_id}").as_bytes())
}

fn validate_http01_challenges(challenges: &[AcmeHttp01ChallengeRecord]) -> Result<(), AcmeError> {
    for challenge in challenges {
        validate_http01_token(&challenge.token)?;
        validate_challenge_key_authorization(&challenge.key_authorization)?;
    }
    Ok(())
}

fn validate_tls_alpn01_challenges(
    challenges: &[AcmeTlsAlpn01ChallengeRecord],
) -> Result<(), AcmeError> {
    for challenge in challenges {
        validate_http01_token(&challenge.token)?;
        if normalize_tls_alpn_identifier(&challenge.identifier).is_none() {
            return Err(AcmeError::InvalidDomain(format!(
                "TLS-ALPN-01 identifier '{}' is invalid",
                challenge.identifier
            )));
        }
        validate_challenge_key_authorization(&challenge.key_authorization)?;
    }
    Ok(())
}

fn validate_dns01_challenges(challenges: &[AcmeDns01ChallengeRecord]) -> Result<(), AcmeError> {
    for challenge in challenges {
        validate_http01_token(&challenge.token)?;
        if normalize_dns01_identifier(&challenge.identifier).is_none() {
            return Err(AcmeError::InvalidDomain(format!(
                "DNS-01 identifier '{}' is invalid",
                challenge.identifier
            )));
        }
        validate_challenge_key_authorization(&challenge.key_authorization)?;
    }
    Ok(())
}

fn validate_challenge_key_authorization(key_authorization: &str) -> Result<(), AcmeError> {
    if key_authorization.trim().is_empty() {
        return Err(AcmeError::InvalidChallengeToken(
            "challenge key authorization must not be empty".to_string(),
        ));
    }
    if key_authorization.chars().any(char::is_control) {
        return Err(AcmeError::InvalidChallengeToken(
            "challenge key authorization must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn normalize_tls_alpn_identifier(identifier: &str) -> Option<String> {
    let identifier = identifier.trim().trim_end_matches('.').to_ascii_lowercase();
    if identifier.is_empty()
        || identifier.len() > 253
        || identifier
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '/')
    {
        return None;
    }
    Some(identifier)
}

fn normalize_dns01_identifier(identifier: &str) -> Option<String> {
    let identifier = identifier.trim();
    let identifier = identifier.strip_prefix("*.").unwrap_or(identifier);
    let identifier = normalize_tls_alpn_identifier(identifier)?;
    if identifier.contains('*') {
        return None;
    }
    Some(identifier)
}

fn dns01_txt_record_name(identifier: &str) -> Option<String> {
    normalize_dns01_identifier(identifier).map(|identifier| format!("_acme-challenge.{identifier}"))
}

fn key_authorization_sha256(key_authorization: &str) -> [u8; 32] {
    Sha256::digest(key_authorization.as_bytes()).into()
}

fn key_authorization_sha256_base64url(key_authorization: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(key_authorization_sha256(key_authorization))
}

pub fn tls_alpn01_key_authorization_for_identifier(identifier: &str) -> Option<String> {
    global_order_store()
        .ok()?
        .tls_alpn01_key_authorization(identifier)
}

fn build_tls_alpn01_certified_key(
    identifier: &str,
    key_authorization: &str,
) -> Result<Arc<rustls::sign::CertifiedKey>, AcmeError> {
    let identifier = normalize_tls_alpn_identifier(identifier)
        .ok_or_else(|| AcmeError::InvalidDomain(identifier.to_string()))?;
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|error| AcmeError::Write(error.to_string()))?;
    let mut params = rcgen::CertificateParams::new(vec![identifier])
        .map_err(|error| AcmeError::InvalidDomain(error.to_string()))?;
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(
            &key_authorization_sha256(key_authorization),
        ));
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| AcmeError::Write(error.to_string()))?;
    let crypto_provider = rustls::crypto::ring::default_provider();
    let signing_key = crypto_provider
        .key_provider
        .load_private_key(
            rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
                .map_err(|error| AcmeError::Write(error.to_string()))?,
        )
        .map_err(|error| AcmeError::Write(error.to_string()))?;
    let certified_key = rustls::sign::CertifiedKey::new(vec![cert.der().clone()], signing_key);
    Ok(Arc::new(certified_key))
}

#[derive(Debug)]
pub struct AcmeTlsAlpnResolver {
    fallback: Arc<rustls::sign::CertifiedKey>,
    cache: Mutex<BTreeMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl AcmeTlsAlpnResolver {
    pub fn new(fallback: Arc<rustls::sign::CertifiedKey>) -> Self {
        Self {
            fallback,
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn tls_alpn_certified_key(&self, server_name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let key_authorization = tls_alpn01_key_authorization_for_identifier(server_name)?;
        let cache_key = format!("{server_name}\0{key_authorization}");
        if let Ok(cache) = self.cache.lock()
            && let Some(certified_key) = cache.get(&cache_key)
        {
            return Some(certified_key.clone());
        }
        let certified_key = build_tls_alpn01_certified_key(server_name, &key_authorization).ok()?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(cache_key, certified_key.clone());
        }
        Some(certified_key)
    }
}

impl rustls::server::ResolvesServerCert for AcmeTlsAlpnResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if client_hello_requests_only_acme_tls_alpn(&client_hello)
            && let Some(server_name) = client_hello.server_name()
            && let Some(certified_key) = self.tls_alpn_certified_key(server_name)
        {
            return Some(certified_key);
        }
        Some(self.fallback.clone())
    }
}

fn client_hello_requests_only_acme_tls_alpn(
    client_hello: &rustls::server::ClientHello<'_>,
) -> bool {
    let Some(mut protocols) = client_hello.alpn() else {
        return false;
    };
    matches!(
        (protocols.next(), protocols.next()),
        (Some(protocol), None) if protocol == TLS_ALPN01_PROTOCOL
    )
}

fn validate_http01_token(token: &str) -> Result<(), AcmeError> {
    if token.is_empty() {
        return Err(AcmeError::InvalidChallengeToken(
            "token must not be empty".to_string(),
        ));
    }
    if token.len() > MAX_HTTP01_TOKEN_LEN {
        return Err(AcmeError::InvalidChallengeToken(format!(
            "token exceeds {MAX_HTTP01_TOKEN_LEN} bytes"
        )));
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AcmeError::InvalidChallengeToken(
            "token must contain only base64url characters".to_string(),
        ));
    }
    Ok(())
}

/// The HTTP-01 challenge token a request target names, in the canonical policy
/// coordinate, or `None` when the target does not name exactly one challenge.
///
/// HTTP-01 is served at the frontend boundary ahead of overload admission, so
/// this is where the ACME handler establishes its request coordinate — and it
/// must be the *same* coordinate every later stage uses (private advisory
/// `GHSA-69xf-42xm-4w4f`). Resolving the raw target instead would let an
/// encoded-but-legal spelling of a live challenge — an escaped prefix byte
/// (`/%2Ewell-known/…`) or an escaped base64url token byte
/// (`…/tok%5FABC`) — miss the ACME handler, canonicalize a moment later, and
/// fall through to ordinary routing and backend handling.
///
/// ACME is deliberately *not* a second place that decides what a path means: an
/// ambiguous or refused target resolves to `None` here and falls through to the
/// single request boundary in `handle_proxy_request_inner`, which answers it
/// with the fixed, non-echoing 400. Nothing is normalized or accepted here that
/// the canonicalizer would refuse.
pub fn http01_challenge_token_for_path(path: &str) -> Option<Cow<'_, str>> {
    if path.len() > MAX_HTTP01_TARGET_LEN {
        return None;
    }
    // Canonicalization only ever decodes escapes, so a target with no `%` is
    // already its own canonical form (or is refused outright). Such a target
    // can therefore only name a challenge if it already spells the prefix
    // literally. That keeps the normal GET hot path to a length compare, a
    // prefix compare, and one `memchr` — no allocation and no decode.
    if !path.starts_with(HTTP01_CHALLENGE_PREFIX) && !path.contains('%') {
        return None;
    }
    match crate::policy_path::canonicalize_policy_path(path).ok()? {
        Cow::Borrowed(canonical) => single_http01_token(canonical).map(Cow::Borrowed),
        Cow::Owned(canonical) => {
            single_http01_token(&canonical).map(|token| Cow::Owned(token.to_string()))
        }
    }
}

/// Split a canonical policy path into the single challenge token it addresses.
fn single_http01_token(canonical_path: &str) -> Option<&str> {
    let token = canonical_path.strip_prefix(HTTP01_CHALLENGE_PREFIX)?;
    if token.contains('/') || token.contains('?') {
        return None;
    }
    Some(token)
}

/// Resolve a pending HTTP-01 key authorization for a request target.
///
/// Consumes the canonical policy path — see
/// [`http01_challenge_token_for_path`] for why, and for what a `None` result
/// leaves to the central boundary rejection.
pub fn http01_key_authorization_for_path(path: &str) -> Option<String> {
    let token = http01_challenge_token_for_path(path)?;
    global_order_store().ok()?.http01_key_authorization(&token)
}

fn acme_store_dir_from_env() -> PathBuf {
    let path = crate::config::env_config::tls_managed_store_path_from_env();
    if path.is_empty() {
        PathBuf::from(DEFAULT_STORE_DIR)
    } else {
        PathBuf::from(path)
    }
}

static GLOBAL_ACME_CERTIFICATE_STORE: OnceLock<Result<Arc<AcmeCertificateStore>, String>> =
    OnceLock::new();
static GLOBAL_ACME_ORDER_STORE: OnceLock<Result<Arc<AcmeOrderStore>, String>> = OnceLock::new();
static GLOBAL_ACME_ACCOUNT_STORE: OnceLock<Result<Arc<AcmeAccountStore>, String>> = OnceLock::new();

pub fn global_certificate_store() -> Result<Arc<AcmeCertificateStore>, String> {
    GLOBAL_ACME_CERTIFICATE_STORE
        .get_or_init(|| {
            AcmeCertificateStore::open(acme_store_dir_from_env())
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .clone()
}

pub fn global_order_store() -> Result<Arc<AcmeOrderStore>, String> {
    GLOBAL_ACME_ORDER_STORE
        .get_or_init(|| {
            AcmeOrderStore::open(acme_store_dir_from_env())
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .clone()
}

pub fn global_account_store() -> Result<Arc<AcmeAccountStore>, String> {
    GLOBAL_ACME_ACCOUNT_STORE
        .get_or_init(|| {
            AcmeAccountStore::open(acme_store_dir_from_env())
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .clone()
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeRenewalChallengeType {
    Http01,
    TlsAlpn01,
    Dns01,
}

#[cfg(feature = "acme")]
impl AcmeRenewalChallengeType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "http01" | "http-01" => Some(Self::Http01),
            "tls_alpn01" | "tls-alpn-01" | "tls-alpn01" => Some(Self::TlsAlpn01),
            "dns01" | "dns-01" => Some(Self::Dns01),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http01",
            Self::TlsAlpn01 => "tls_alpn01",
            Self::Dns01 => "dns01",
        }
    }
}

#[cfg(feature = "acme")]
#[derive(Clone)]
pub struct AcmeRenewalSchedulerConfig {
    pub enabled: bool,
    pub renew_when_remaining_days: u64,
    pub check_interval: Duration,
    pub poll_timeout: Duration,
    pub challenge_type: AcmeRenewalChallengeType,
    pub dns01_hook_command: Option<String>,
    pub dns01_propagation: Duration,
    pub dns_cache: crate::dns::DnsCache,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Default)]
pub struct AcmeRenewalRunSummary {
    pub checked: usize,
    pub skipped: usize,
    pub renewed: usize,
    pub failed: usize,
}

#[cfg(feature = "acme")]
pub fn start_renewal_scheduler(
    config: AcmeRenewalSchedulerConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.check_interval);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match run_due_renewals(&config).await {
                        Ok(summary) => {
                            tracing::info!(
                                checked = summary.checked,
                                skipped = summary.skipped,
                                renewed = summary.renewed,
                                failed = summary.failed,
                                challenge_type = config.challenge_type.as_str(),
                                "ACME renewal scan completed"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "ACME renewal scan failed");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!("ACME renewal scheduler shutting down");
                    return;
                }
            }
        }
    }))
}

#[cfg(feature = "acme")]
pub async fn run_due_renewals(
    config: &AcmeRenewalSchedulerConfig,
) -> Result<AcmeRenewalRunSummary, AcmeError> {
    let certificate_store = global_certificate_store().map_err(AcmeError::Read)?;
    let order_store = global_order_store().map_err(AcmeError::Read)?;
    let account_store = global_account_store().map_err(AcmeError::Read)?;
    let mut summary = AcmeRenewalRunSummary::default();
    let renew_before = Utc::now()
        + chrono::Duration::days(i64::try_from(config.renew_when_remaining_days).unwrap_or(30));

    for certificate in certificate_store.list_certificate_records() {
        summary.checked += 1;
        if certificate.status != AcmeCertificateStatus::Issued {
            summary.skipped += 1;
            continue;
        }
        let Some(not_after) = certificate.not_after else {
            summary.skipped += 1;
            continue;
        };
        if not_after > renew_before {
            summary.skipped += 1;
            continue;
        }
        if has_active_renewal_order(&order_store, &certificate.id)? {
            summary.skipped += 1;
            continue;
        }
        match renew_certificate_once(
            &certificate_store,
            &order_store,
            &account_store,
            certificate,
            config,
        )
        .await
        {
            Ok(true) => summary.renewed += 1,
            Ok(false) => summary.skipped += 1,
            Err(error) => {
                summary.failed += 1;
                tracing::warn!(error = %error, "ACME certificate renewal failed");
            }
        }
    }

    Ok(summary)
}

#[cfg(feature = "acme")]
fn has_active_renewal_order(
    order_store: &AcmeOrderStore,
    certificate_id: &str,
) -> Result<bool, AcmeError> {
    Ok(order_store
        .latest_order_for_certificate(certificate_id)?
        .is_some_and(|order| {
            matches!(
                order.status,
                AcmeOrderStatus::PendingChallenges
                    | AcmeOrderStatus::Ready
                    | AcmeOrderStatus::Processing
            )
        }))
}

#[cfg(feature = "acme")]
async fn renew_certificate_once(
    certificate_store: &AcmeCertificateStore,
    order_store: &AcmeOrderStore,
    account_store: &AcmeAccountStore,
    certificate: AcmeCertificateRecord,
    config: &AcmeRenewalSchedulerConfig,
) -> Result<bool, AcmeError> {
    let Some(account_id) = certificate.account_id.as_deref() else {
        return Ok(false);
    };
    let Some(account_credentials_json) = order_store
        .latest_order_for_certificate(&certificate.id)?
        .and_then(|order| order.account_credentials_json)
        .or(account_store.get_credentials(&certificate.directory_url, account_id)?)
    else {
        return Ok(false);
    };

    let prepared = prepare_renewal_order(&certificate, account_credentials_json, config).await?;
    let prepared_credentials_json = prepared.account_credentials_json.clone().ok_or_else(|| {
        AcmeError::InvalidId("ACME renewal order has no account credentials".to_string())
    })?;
    account_store.upsert_account(
        prepared
            .account_id
            .clone()
            .unwrap_or_else(|| account_id.to_string()),
        prepared.directory_url.clone(),
        prepared_credentials_json,
    )?;
    let order = order_store.upsert_order(prepared, false)?;
    if config.challenge_type == AcmeRenewalChallengeType::Dns01 {
        let Some(command) = config.dns01_hook_command.as_deref() else {
            tracing::warn!(
                certificate_id = %certificate.id,
                order_id = %order.id,
                "ACME DNS-01 renewal order created; set FERRUM_ACME_DNS01_HOOK_COMMAND to publish and finalize automatically"
            );
            return Ok(false);
        };
        publish_dns01_challenges_with_hook(command, &order.dns01_challenges).await?;
        if !config.dns01_propagation.is_zero() {
            tokio::time::sleep(config.dns01_propagation).await;
        }
    }

    let completion_result = complete_prepared_renewal_order(&order, config).await;
    if config.challenge_type == AcmeRenewalChallengeType::Dns01
        && let Some(command) = config.dns01_hook_command.as_deref()
        && let Err(error) =
            cleanup_dns01_challenges_with_hook(command, &order.dns01_challenges).await
    {
        tracing::warn!(error = %error, "ACME DNS-01 cleanup hook failed");
    }
    let completed = completion_result?;
    validate_completed_certificate_pair(&completed.cert_pem, &completed.key_pem)?;
    let issued = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: certificate.id.clone(),
        domains: certificate.domains.clone(),
        directory_url: certificate.directory_url.clone(),
        account_id: order.account_id.clone(),
        order_url: order.order_url.clone(),
        cert_pem: completed.cert_pem,
        key_pem: completed.key_pem,
        chain_pem: None,
    })?;
    certificate_store.upsert_certificate(issued, true)?;

    let mut updated_order = order;
    updated_order.status = AcmeOrderStatus::Valid;
    updated_order.error = None;
    order_store.upsert_order(updated_order, true)?;
    let _ = crate::tls::source::subscription::request_all_material_set_reloads();
    Ok(true)
}

#[cfg(feature = "acme")]
async fn prepare_renewal_order(
    certificate: &AcmeCertificateRecord,
    account_credentials_json: String,
    config: &AcmeRenewalSchedulerConfig,
) -> Result<AcmeOrderRecord, AcmeError> {
    let order_config = client::AcmeOrderConfig {
        account: client::AcmeAccountConfig {
            directory_url: certificate.directory_url.clone(),
            contact: Vec::new(),
            terms_of_service_agreed: true,
            existing_credentials_json: Some(crate::tls::source::SecretString::new(
                account_credentials_json,
            )),
        },
        domains: certificate.domains.clone(),
        dns_cache: config.dns_cache.clone(),
    };
    let prepared = match config.challenge_type {
        AcmeRenewalChallengeType::Http01 => client::prepare_http01_order(order_config).await,
        AcmeRenewalChallengeType::TlsAlpn01 => client::prepare_tls_alpn01_order(order_config).await,
        AcmeRenewalChallengeType::Dns01 => client::prepare_dns01_order(order_config).await,
    }
    .map_err(|error| AcmeError::Write(error.to_string()))?;

    let mut http01_challenges = Vec::new();
    let mut tls_alpn01_challenges = Vec::new();
    let mut dns01_challenges = Vec::new();
    for challenge in prepared.challenges {
        match config.challenge_type {
            AcmeRenewalChallengeType::Http01 => {
                http01_challenges.push(AcmeHttp01ChallengeRecord {
                    identifier: challenge.identifier,
                    token: challenge.token,
                    key_authorization: challenge.key_authorization,
                });
            }
            AcmeRenewalChallengeType::TlsAlpn01 => {
                tls_alpn01_challenges.push(AcmeTlsAlpn01ChallengeRecord {
                    identifier: challenge.identifier,
                    token: challenge.token,
                    key_authorization: challenge.key_authorization,
                });
            }
            AcmeRenewalChallengeType::Dns01 => {
                dns01_challenges.push(AcmeDns01ChallengeRecord {
                    identifier: challenge.identifier,
                    token: challenge.token,
                    key_authorization: challenge.key_authorization,
                });
            }
        }
    }

    AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
        id: format!("renew-{}", Uuid::new_v4().simple()),
        certificate_id: Some(certificate.id.clone()),
        domains: prepared.domains,
        directory_url: certificate.directory_url.clone(),
        account_id: Some(prepared.account_id),
        account_credentials_json: Some(
            prepared
                .account_credentials_json
                .expose_secret()
                .to_string(),
        ),
        order_url: Some(prepared.order_url),
        status: AcmeOrderStatus::PendingChallenges,
        http01_challenges,
        tls_alpn01_challenges,
        dns01_challenges,
        error: None,
    })
}

#[cfg(feature = "acme")]
async fn complete_prepared_renewal_order(
    order: &AcmeOrderRecord,
    config: &AcmeRenewalSchedulerConfig,
) -> Result<client::CompletedAcmeHttp01Order, AcmeError> {
    let account_credentials_json = order
        .account_credentials_json
        .clone()
        .ok_or_else(|| AcmeError::InvalidId("ACME order has no account credentials".to_string()))?;
    let order_url = order
        .order_url
        .clone()
        .ok_or_else(|| AcmeError::InvalidId("ACME order has no order URL".to_string()))?;
    let complete_config = client::CompleteAcmeHttp01OrderConfig {
        directory_url: order.directory_url.clone(),
        account_credentials_json: crate::tls::source::SecretString::new(account_credentials_json),
        order_url,
        poll_timeout: config.poll_timeout,
        dns_cache: config.dns_cache.clone(),
    };
    match config.challenge_type {
        AcmeRenewalChallengeType::Http01 => client::complete_http01_order(complete_config).await,
        AcmeRenewalChallengeType::TlsAlpn01 => {
            client::complete_tls_alpn01_order(complete_config).await
        }
        AcmeRenewalChallengeType::Dns01 => client::complete_dns01_order(complete_config).await,
    }
    .map_err(|error| AcmeError::Write(error.to_string()))
}

#[cfg(feature = "acme")]
async fn publish_dns01_challenges_with_hook(
    command: &str,
    challenges: &[AcmeDns01ChallengeRecord],
) -> Result<(), AcmeError> {
    for challenge in challenges {
        run_dns01_hook(command, "present", challenge).await?;
    }
    Ok(())
}

#[cfg(feature = "acme")]
async fn cleanup_dns01_challenges_with_hook(
    command: &str,
    challenges: &[AcmeDns01ChallengeRecord],
) -> Result<(), AcmeError> {
    for challenge in challenges {
        run_dns01_hook(command, "cleanup", challenge).await?;
    }
    Ok(())
}

#[cfg(feature = "acme")]
async fn run_dns01_hook(
    command: &str,
    action: &str,
    challenge: &AcmeDns01ChallengeRecord,
) -> Result<(), AcmeError> {
    let command = command.trim();
    if command.is_empty() {
        return Err(AcmeError::InvalidId(
            "DNS-01 hook command must not be empty".to_string(),
        ));
    }
    let summary = challenge.summary();
    let status = tokio::process::Command::new(command)
        .env("FERRUM_ACME_DNS01_ACTION", action)
        .env("FERRUM_ACME_DNS01_IDENTIFIER", &summary.identifier)
        .env("FERRUM_ACME_DNS01_TOKEN", &summary.token)
        .env(
            "FERRUM_ACME_DNS01_TXT_RECORD_NAME",
            &summary.txt_record_name,
        )
        .env("FERRUM_ACME_DNS01_TXT_VALUE", &summary.txt_value)
        .status()
        .await
        .map_err(|error| AcmeError::Write(format!("failed to run DNS-01 hook: {error}")))?;
    if !status.success() {
        return Err(AcmeError::Write(format!(
            "DNS-01 hook exited with status {status}"
        )));
    }
    Ok(())
}

#[cfg(feature = "acme")]
fn validate_completed_certificate_pair(cert_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
    let cert_chain = rustls_pemfile::certs(&mut Cursor::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AcmeError::Parse(error.to_string()))?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem.as_bytes()))
        .map_err(|error| AcmeError::Parse(error.to_string()))?
        .ok_or_else(|| AcmeError::Parse("no PEM private key found".to_string()))?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| AcmeError::Parse(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|error| AcmeError::Parse(error.to_string()))?;
    crate::tls::check_cert_expiry_from_pem_bytes(
        cert_pem.as_bytes(),
        "acme_renewal_cert",
        "acme://renewal",
        crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
    )
    .map_err(|error| AcmeError::Parse(error.to_string()))?;
    Ok(())
}

#[cfg(feature = "acme")]
pub mod client {
    //! Optional RFC 8555 ACME client substrate.
    //!
    //! This module intentionally prepares orders and challenge material without
    //! wiring challenge publication to listeners. Runtime surfaces decide how to
    //! expose HTTP-01, TLS-ALPN-01, or DNS-01 material before calling ACME
    //! challenge readiness/finalization in follow-on manager work.

    use std::future::{Future, ready};
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http::header::{CONTENT_LENGTH, LOCATION};
    use http::{Request, Response, Uri};
    use http_body_util::{LengthLimitError, Limited};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client as HyperClient;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use instant_acme::{
        Account, AccountCredentials, BodyWrapper, BytesBody, BytesResponse, ChallengeStatus,
        ChallengeType, HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
    };
    use serde::Serialize;
    use thiserror::Error;
    use tower::Service;

    use crate::config::BackendEgressPolicy;
    use crate::dns::{DnsCache, DnsConfig};
    use crate::tls::source::SecretString;

    #[derive(Debug, Clone)]
    pub struct AcmeAccountConfig {
        pub directory_url: String,
        pub contact: Vec<String>,
        pub terms_of_service_agreed: bool,
        pub existing_credentials_json: Option<SecretString>,
    }

    #[derive(Clone)]
    pub struct AcmeOrderConfig {
        pub account: AcmeAccountConfig,
        pub domains: Vec<String>,
        pub dns_cache: DnsCache,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct AcmeHttp01Challenge {
        pub identifier: String,
        pub token: String,
        pub key_authorization: String,
    }

    #[derive(Debug, Clone)]
    pub struct PreparedAcmeHttp01Order {
        pub domains: Vec<String>,
        pub order_url: String,
        pub account_id: String,
        pub account_credentials_json: SecretString,
        pub challenges: Vec<AcmeHttp01Challenge>,
    }

    #[derive(Clone)]
    pub struct CompleteAcmeHttp01OrderConfig {
        pub directory_url: String,
        pub account_credentials_json: SecretString,
        pub order_url: String,
        pub poll_timeout: Duration,
        pub dns_cache: DnsCache,
    }

    #[derive(Debug, Clone)]
    pub struct CompletedAcmeHttp01Order {
        pub cert_pem: String,
        pub key_pem: String,
    }

    pub type AcmeTlsAlpn01Challenge = AcmeHttp01Challenge;
    pub type PreparedAcmeTlsAlpn01Order = PreparedAcmeHttp01Order;
    pub type CompleteAcmeTlsAlpn01OrderConfig = CompleteAcmeHttp01OrderConfig;
    pub type CompletedAcmeTlsAlpn01Order = CompletedAcmeHttp01Order;
    pub type AcmeDns01Challenge = AcmeHttp01Challenge;
    pub type PreparedAcmeDns01Order = PreparedAcmeHttp01Order;
    pub type CompleteAcmeDns01OrderConfig = CompleteAcmeHttp01OrderConfig;
    pub type CompletedAcmeDns01Order = CompletedAcmeHttp01Order;

    #[derive(Debug, Error)]
    pub enum AcmeClientError {
        #[error("invalid ACME order request: {0}")]
        InvalidRequest(String),
        #[error("failed to serialize ACME account credentials: {0}")]
        SerializeCredentials(String),
        #[error("failed to deserialize ACME account credentials: {0}")]
        DeserializeCredentials(String),
        #[error("ACME outbound boundary rejected the request: {0}")]
        EgressPolicy(String),
        #[error("ACME client error: {0}")]
        Client(String),
    }

    /// One wall-clock budget for fresh DNS resolution plus every candidate dial.
    const ACME_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    /// Maximum complete fresh A/AAAA answer accepted for one ACME connection.
    ///
    /// Ferrum still screens every returned address before applying this bound;
    /// an oversized answer is rejected whole and is never truncated to a prefix.
    const MAX_ACME_DNS_CANDIDATES: usize = 64;
    /// Maximum wire bytes accepted from any ACME HTTP response, certificates included.
    const MAX_ACME_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
    const MAX_ACME_RESPONSE_BODY_BYTES_U64: u64 = MAX_ACME_RESPONSE_BODY_BYTES as u64;

    #[derive(Clone)]
    struct ScreenedAcmeConnector {
        dns_cache: DnsCache,
        egress_policy: BackendEgressPolicy,
        connect_timeout: Duration,
    }

    impl ScreenedAcmeConnector {
        fn new(dns_cache: DnsCache) -> Self {
            Self::with_connect_timeout(dns_cache, ACME_CONNECT_TIMEOUT)
        }

        fn with_connect_timeout(dns_cache: DnsCache, connect_timeout: Duration) -> Self {
            let egress_policy = super::acme_public_egress_policy();
            Self {
                dns_cache: dns_cache.with_backend_egress_policy(egress_policy.clone()),
                egress_policy,
                connect_timeout,
            }
        }

        fn screen_candidates(&self, candidates: Vec<IpAddr>) -> Result<Vec<IpAddr>, io::Error> {
            if candidates.is_empty() {
                return Err(io::Error::other(
                    "ACME DNS resolution returned no addresses",
                ));
            }
            for candidate in &candidates {
                if let Some(reason) = self.egress_policy.deny_reason(candidate) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("ACME resolved address denied by egress policy: {reason}"),
                    ));
                }
            }
            if candidates.len() > MAX_ACME_DNS_CANDIDATES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "ACME DNS resolution returned {} addresses, exceeding the limit of {MAX_ACME_DNS_CANDIDATES}",
                        candidates.len()
                    ),
                ));
            }
            Ok(candidates)
        }

        async fn resolve_candidates(&self, host: &str) -> Result<Vec<IpAddr>, io::Error> {
            let candidates = self
                .dns_cache
                .resolve_all_fresh(host)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.screen_candidates(candidates)
        }
    }

    fn acme_connection_deadline_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "ACME fresh DNS resolution and TCP connection deadline exceeded",
        )
    }

    impl Service<Uri> for ScreenedAcmeConnector {
        type Response = TokioIo<tokio::net::TcpStream>;
        type Error = io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, destination: Uri) -> Self::Future {
            let connector = self.clone();
            let egress_policy = self.egress_policy.clone();
            Box::pin(async move {
                if destination.scheme_str() != Some("https") {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "ACME connector requires HTTPS",
                    ));
                }
                let host = destination
                    .host()
                    .filter(|host| !host.is_empty())
                    .ok_or_else(|| io::Error::other("ACME endpoint is missing a host"))?;
                let host = host
                    .strip_prefix('[')
                    .and_then(|host| host.strip_suffix(']'))
                    .unwrap_or(host)
                    .to_string();
                let port = destination.port_u16().unwrap_or(443);

                // Bypass both cache layers on every new connection. The DNS
                // resolver screens the complete A+AAAA answer atomically, so a
                // mixed public/private answer cannot be laundered by an allowed
                // first address.
                let deadline = tokio::time::Instant::now() + connector.connect_timeout;
                let candidates =
                    tokio::time::timeout_at(deadline, connector.resolve_candidates(&host))
                        .await
                        .map_err(|_| acme_connection_deadline_error())??;

                let mut last_error = None;
                for candidate in candidates {
                    // Keep the policy decision adjacent to the concrete socket
                    // open. Only this already-screened address is handed to
                    // Tokio, so no downstream resolver can rebind the dial.
                    if let Some(reason) = egress_policy.deny_reason(&candidate) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("ACME dial candidate denied by egress policy: {reason}"),
                        ));
                    }
                    let address = SocketAddr::new(candidate, port);
                    match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address))
                        .await
                    {
                        Ok(Ok(stream)) => return Ok(TokioIo::new(stream)),
                        Ok(Err(error)) => last_error = Some(error),
                        Err(_) => return Err(acme_connection_deadline_error()),
                    }
                }
                Err(last_error.unwrap_or_else(|| {
                    io::Error::other("all approved ACME connection candidates failed")
                }))
            })
        }
    }

    type AcmeHttpsConnector = hyper_rustls::HttpsConnector<ScreenedAcmeConnector>;
    type AcmeHyperClient = HyperClient<AcmeHttpsConnector, BodyWrapper<Bytes>>;

    struct HyperAcmeHttpClient(AcmeHyperClient);

    fn response_body_too_large_error() -> instant_acme::Error {
        instant_acme::Error::Other(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ACME response body exceeds the {MAX_ACME_RESPONSE_BODY_BYTES}-byte limit"),
        )))
    }

    fn validate_declared_response_body_size(
        headers: &http::HeaderMap,
    ) -> Result<(), instant_acme::Error> {
        let Some(content_length) = headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return Ok(());
        };
        if content_length > MAX_ACME_RESPONSE_BODY_BYTES_U64 {
            return Err(response_body_too_large_error());
        }
        Ok(())
    }

    fn limit_hyper_response_body<B>(
        response: Response<B>,
    ) -> Result<Response<Limited<B>>, instant_acme::Error> {
        validate_declared_response_body_size(response.headers())?;
        Ok(response.map(|body| Limited::new(body, MAX_ACME_RESPONSE_BODY_BYTES)))
    }

    async fn collect_bounded_response_body(
        mut body: Box<dyn BytesBody>,
    ) -> Result<Bytes, instant_acme::Error> {
        let bytes = match body.into_bytes().await {
            Ok(bytes) => bytes,
            Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                return Err(response_body_too_large_error());
            }
            Err(error) => return Err(instant_acme::Error::Other(error)),
        };
        if bytes.len() > MAX_ACME_RESPONSE_BODY_BYTES {
            return Err(response_body_too_large_error());
        }
        Ok(bytes)
    }

    impl HttpClient for HyperAcmeHttpClient {
        fn request(
            &self,
            request: Request<BodyWrapper<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>
        {
            let future = self.0.request(request);
            Box::pin(async move {
                let response = future
                    .await
                    .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
                Ok(BytesResponse::from(limit_hyper_response_body(response)?))
            })
        }
    }

    struct PolicyAcmeHttpClient {
        inner: Box<dyn HttpClient>,
        endpoint_policy: super::AcmeEndpointPolicy,
    }

    impl PolicyAcmeHttpClient {
        fn reject(message: impl Into<String>) -> instant_acme::Error {
            instant_acme::Error::Other(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                message.into(),
            )))
        }
    }

    impl HttpClient for PolicyAcmeHttpClient {
        fn request(
            &self,
            request: Request<BodyWrapper<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>
        {
            let endpoint_policy = self.endpoint_policy.clone();
            let endpoint = request.uri().to_string();
            let validated = match endpoint_policy.validate_endpoint(&endpoint, "request URL") {
                Ok(validated) => validated,
                Err(error) => return Box::pin(ready(Err(Self::reject(error.to_string())))),
            };
            let is_directory = validated == endpoint_policy.directory;
            let future = self.inner.request(request);
            Box::pin(async move {
                let response = future.await?;
                validate_declared_response_body_size(&response.parts.headers)?;
                if response.parts.status.is_redirection() {
                    return Err(Self::reject(
                        "ACME redirects are disabled; redirect responses are rejected",
                    ));
                }
                if let Some(location) = response.parts.headers.get(LOCATION) {
                    let location = location.to_str().map_err(|_| {
                        Self::reject("ACME Location header is not valid visible ASCII")
                    })?;
                    endpoint_policy
                        .validate_endpoint(location, "Location URL")
                        .map_err(|error| Self::reject(error.to_string()))?;
                }

                let BytesResponse { parts, body } = response;
                let bytes = collect_bounded_response_body(body).await?;
                validate_response_endpoint_fields(&endpoint_policy, &bytes, is_directory)
                    .map_err(|error| Self::reject(error.to_string()))?;
                Ok(BytesResponse {
                    parts,
                    body: Box::new(bytes),
                })
            })
        }
    }

    fn validate_response_endpoint_fields(
        policy: &super::AcmeEndpointPolicy,
        body: &[u8],
        is_directory: bool,
    ) -> Result<(), AcmeClientError> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Ok(());
        };
        let Some(object) = value.as_object() else {
            return Ok(());
        };

        let validate_string =
            |value: &serde_json::Value, label: &'static str| -> Result<(), AcmeClientError> {
                let endpoint = value.as_str().ok_or_else(|| {
                    AcmeClientError::EgressPolicy(format!("{label} must be an absolute URL string"))
                })?;
                policy
                    .validate_endpoint(endpoint, label)
                    .map(|_| ())
                    .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))
            };

        if is_directory {
            for (field, label) in [
                ("newNonce", "newNonce URL"),
                ("newAccount", "newAccount URL"),
                ("newOrder", "newOrder URL"),
                ("newAuthz", "newAuthz URL"),
                ("revokeCert", "revokeCert URL"),
                ("keyChange", "keyChange URL"),
                ("renewalInfo", "renewalInfo URL"),
            ] {
                if let Some(value) = object.get(field) {
                    validate_string(value, label)?;
                }
            }
        }

        for (field, label) in [
            ("finalize", "finalize URL"),
            ("certificate", "certificate URL"),
        ] {
            if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
                validate_string(value, label)?;
            }
        }
        if let Some(authorizations) = object.get("authorizations") {
            let authorizations = authorizations.as_array().ok_or_else(|| {
                AcmeClientError::EgressPolicy(
                    "authorizations must be an array of absolute URLs".to_string(),
                )
            })?;
            for authorization in authorizations {
                validate_string(authorization, "authorization URL")?;
            }
        }
        if let Some(challenges) = object.get("challenges") {
            let challenges = challenges.as_array().ok_or_else(|| {
                AcmeClientError::EgressPolicy("challenges must be an array".to_string())
            })?;
            for challenge in challenges {
                let challenge_url = challenge
                    .as_object()
                    .and_then(|challenge| challenge.get("url"))
                    .ok_or_else(|| {
                        AcmeClientError::EgressPolicy(
                            "challenge entry must include an absolute URL".to_string(),
                        )
                    })?;
                validate_string(challenge_url, "challenge URL")?;
            }
        }
        Ok(())
    }

    fn validate_and_deserialize_credentials(
        credentials_json: &SecretString,
        endpoint_policy: &super::AcmeEndpointPolicy,
    ) -> Result<AccountCredentials, AcmeClientError> {
        let value = serde_json::from_str::<serde_json::Value>(credentials_json.expose_secret())
            .map_err(|error| AcmeClientError::DeserializeCredentials(error.to_string()))?;
        let object = value.as_object().ok_or_else(|| {
            AcmeClientError::DeserializeCredentials("credentials must be a JSON object".to_string())
        })?;
        if object.get("urls").is_some_and(|urls| !urls.is_null()) {
            return Err(AcmeClientError::EgressPolicy(
                "legacy ACME credentials with embedded endpoint URLs are not accepted; recreate the account credentials from the configured directory".to_string(),
            ));
        }
        let embedded_directory = object
            .get("directory")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AcmeClientError::EgressPolicy(
                    "ACME credentials must contain their directory URL".to_string(),
                )
            })?;
        endpoint_policy
            .validate_directory_match(embedded_directory)
            .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
        let account_id = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AcmeClientError::EgressPolicy(
                    "ACME credentials must contain an account URL".to_string(),
                )
            })?;
        endpoint_policy
            .validate_endpoint(account_id, "account URL")
            .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
        serde_json::from_value::<AccountCredentials>(value)
            .map_err(|error| AcmeClientError::DeserializeCredentials(error.to_string()))
    }

    fn build_policy_http_client(
        endpoint_policy: super::AcmeEndpointPolicy,
        dns_cache: DnsCache,
    ) -> Result<Box<dyn HttpClient>, AcmeClientError> {
        let connector = ScreenedAcmeConnector::new(dns_cache);
        let https = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|error| AcmeClientError::Client(error.to_string()))?
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        let client = HyperClient::builder(TokioExecutor::new()).build(https);
        Ok(Box::new(PolicyAcmeHttpClient {
            inner: Box::new(HyperAcmeHttpClient(client)),
            endpoint_policy,
        }))
    }

    #[cfg(test)]
    pub(crate) fn default_acme_dns_cache() -> DnsCache {
        DnsCache::new(DnsConfig {
            backend_allow_ips: super::acme_public_egress_policy(),
            ..DnsConfig::default()
        })
    }

    pub(crate) fn configured_acme_dns_cache() -> Result<DnsCache, AcmeClientError> {
        let env_config = crate::config::EnvConfig::from_env().map_err(|_| {
            AcmeClientError::Client(
                "configured Ferrum DNS resolver could not be loaded".to_string(),
            )
        })?;
        Ok(DnsCache::new(DnsConfig {
            global_overrides: env_config.dns_overrides.clone(),
            resolver_addresses: env_config.dns_resolver_address.clone(),
            hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
            dns_order: env_config.dns_order.clone(),
            ttl_override_seconds: env_config.dns_ttl_override,
            min_ttl_seconds: env_config.dns_min_ttl,
            stale_ttl_seconds: env_config.dns_stale_ttl,
            error_ttl_seconds: env_config.dns_error_ttl,
            max_cache_size: env_config.dns_cache_max_size,
            refresh_threshold_percent: env_config.dns_refresh_threshold_percent,
            slow_threshold_ms: env_config.dns_slow_threshold_ms,
            warmup_concurrency: env_config.dns_warmup_concurrency,
            failed_retry_interval_seconds: env_config.dns_failed_retry_interval,
            try_tcp_on_error: env_config.dns_try_tcp_on_error,
            num_concurrent_reqs: env_config.dns_num_concurrent_reqs,
            max_active_requests: env_config.dns_max_active_requests,
            max_concurrent_refreshes: env_config.dns_max_concurrent_refreshes,
            backend_allow_ips: super::acme_public_egress_policy(),
            shard_amount: env_config.pool_shard_amount,
        }))
    }

    pub async fn prepare_http01_order(
        config: AcmeOrderConfig,
    ) -> Result<PreparedAcmeHttp01Order, AcmeClientError> {
        prepare_order(config, ChallengeType::Http01, "http-01").await
    }

    pub async fn prepare_tls_alpn01_order(
        config: AcmeOrderConfig,
    ) -> Result<PreparedAcmeTlsAlpn01Order, AcmeClientError> {
        prepare_order(config, ChallengeType::TlsAlpn01, "tls-alpn-01").await
    }

    pub async fn prepare_dns01_order(
        config: AcmeOrderConfig,
    ) -> Result<PreparedAcmeDns01Order, AcmeClientError> {
        prepare_order(config, ChallengeType::Dns01, "dns-01").await
    }

    async fn prepare_order(
        config: AcmeOrderConfig,
        challenge_type: ChallengeType,
        challenge_name: &'static str,
    ) -> Result<PreparedAcmeHttp01Order, AcmeClientError> {
        let endpoint_policy = super::AcmeEndpointPolicy::new(&config.account.directory_url)
            .map_err(|error| AcmeClientError::InvalidRequest(error.to_string()))?;
        let domains = normalize_order_domains(config.domains)?;
        let account =
            resolve_account(&config.account, endpoint_policy.clone(), config.dns_cache).await?;
        let identifiers = domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = account
            .account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))?;
        let order_url = order.url().to_string();
        endpoint_policy
            .validate_endpoint(&order_url, "order URL")
            .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
        let mut challenges = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization =
                authorization.map_err(|error| AcmeClientError::Client(error.to_string()))?;
            let authorization_url = authorization.url().to_string();
            endpoint_policy
                .validate_endpoint(&authorization_url, "authorization URL")
                .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
            let Some(challenge) = authorization.challenge(challenge_type.clone()) else {
                return Err(AcmeClientError::InvalidRequest(format!(
                    "ACME authorization does not offer {challenge_name}"
                )));
            };
            endpoint_policy
                .validate_endpoint(&challenge.url, "challenge URL")
                .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
            let key_authorization = challenge.key_authorization();
            challenges.push(AcmeHttp01Challenge {
                identifier: challenge.identifier().to_string(),
                token: challenge.token.clone(),
                key_authorization: key_authorization.as_str().to_string(),
            });
        }

        Ok(PreparedAcmeHttp01Order {
            domains,
            order_url,
            account_id: account.account.id().to_string(),
            account_credentials_json: account.credentials_json,
            challenges,
        })
    }

    pub async fn complete_http01_order(
        config: CompleteAcmeHttp01OrderConfig,
    ) -> Result<CompletedAcmeHttp01Order, AcmeClientError> {
        complete_order(config, ChallengeType::Http01, "http-01").await
    }

    pub async fn complete_tls_alpn01_order(
        config: CompleteAcmeTlsAlpn01OrderConfig,
    ) -> Result<CompletedAcmeTlsAlpn01Order, AcmeClientError> {
        complete_order(config, ChallengeType::TlsAlpn01, "tls-alpn-01").await
    }

    pub async fn complete_dns01_order(
        config: CompleteAcmeDns01OrderConfig,
    ) -> Result<CompletedAcmeDns01Order, AcmeClientError> {
        complete_order(config, ChallengeType::Dns01, "dns-01").await
    }

    async fn complete_order(
        config: CompleteAcmeHttp01OrderConfig,
        challenge_type: ChallengeType,
        challenge_name: &'static str,
    ) -> Result<CompletedAcmeHttp01Order, AcmeClientError> {
        let endpoint_policy = super::AcmeEndpointPolicy::new(&config.directory_url)
            .map_err(|error| AcmeClientError::InvalidRequest(error.to_string()))?;
        let order_url = config.order_url.trim();
        if order_url.is_empty() {
            return Err(AcmeClientError::InvalidRequest(
                "order_url must not be empty".to_string(),
            ));
        }
        endpoint_policy
            .validate_endpoint(order_url, "persisted order URL")
            .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
        let account = restore_account(
            &config.account_credentials_json,
            endpoint_policy.clone(),
            config.dns_cache,
        )
        .await?;
        let mut order = account
            .order(order_url.to_string())
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))?;

        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.map_err(|error| AcmeClientError::Client(error.to_string()))?;
                let authorization_url = authorization.url().to_string();
                endpoint_policy
                    .validate_endpoint(&authorization_url, "authorization URL")
                    .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
                let Some(mut challenge) = authorization.challenge(challenge_type.clone()) else {
                    return Err(AcmeClientError::InvalidRequest(format!(
                        "ACME authorization does not offer {challenge_name}"
                    )));
                };
                endpoint_policy
                    .validate_endpoint(&challenge.url, "challenge URL")
                    .map_err(|error| AcmeClientError::EgressPolicy(error.to_string()))?;
                if challenge.status == ChallengeStatus::Valid {
                    continue;
                }
                challenge
                    .set_ready()
                    .await
                    .map_err(|error| AcmeClientError::Client(error.to_string()))?;
            }
        }

        let retry_policy = RetryPolicy::new().timeout(config.poll_timeout);
        let order_status = order
            .poll_ready(&retry_policy)
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))?;
        if order_status != OrderStatus::Ready {
            return Err(AcmeClientError::Client(format!(
                "ACME order reached {order_status:?} before finalization"
            )));
        }

        let key_pem = order
            .finalize()
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))?;
        let cert_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))?;

        Ok(CompletedAcmeHttp01Order { cert_pem, key_pem })
    }

    struct ResolvedAccount {
        account: Account,
        credentials_json: SecretString,
    }

    async fn resolve_account(
        config: &AcmeAccountConfig,
        endpoint_policy: super::AcmeEndpointPolicy,
        dns_cache: DnsCache,
    ) -> Result<ResolvedAccount, AcmeClientError> {
        if config.directory_url.trim().is_empty() {
            return Err(AcmeClientError::InvalidRequest(
                "directory_url must not be empty".to_string(),
            ));
        }
        if let Some(credentials_json) = config.existing_credentials_json.as_ref() {
            let account = restore_account(credentials_json, endpoint_policy, dns_cache).await?;
            return Ok(ResolvedAccount {
                account,
                credentials_json: credentials_json.clone(),
            });
        }

        let builder =
            Account::builder_with_http(build_policy_http_client(endpoint_policy, dns_cache)?);
        let contact = config
            .contact
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let new_account = NewAccount {
            contact: &contact,
            terms_of_service_agreed: config.terms_of_service_agreed,
            only_return_existing: false,
        };
        let (account, credentials) = builder
            .create(&new_account, config.directory_url.trim().to_string(), None)
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))?;
        let credentials_json = serde_json::to_string(&credentials)
            .map_err(|error| AcmeClientError::SerializeCredentials(error.to_string()))?;
        Ok(ResolvedAccount {
            account,
            credentials_json: SecretString::new(credentials_json),
        })
    }

    async fn restore_account(
        credentials_json: &SecretString,
        endpoint_policy: super::AcmeEndpointPolicy,
        dns_cache: DnsCache,
    ) -> Result<Account, AcmeClientError> {
        let credentials = validate_and_deserialize_credentials(credentials_json, &endpoint_policy)?;
        Account::builder_with_http(build_policy_http_client(endpoint_policy, dns_cache)?)
            .from_credentials(credentials)
            .await
            .map_err(|error| AcmeClientError::Client(error.to_string()))
    }

    fn normalize_order_domains(domains: Vec<String>) -> Result<Vec<String>, AcmeClientError> {
        let mut normalized = Vec::new();
        for domain in domains {
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err(AcmeClientError::InvalidRequest(
                    "domains must not contain empty entries".to_string(),
                ));
            }
            if domain.len() > 253 {
                return Err(AcmeClientError::InvalidRequest(format!(
                    "domain '{domain}' exceeds 253 bytes"
                )));
            }
            if domain
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
            {
                return Err(AcmeClientError::InvalidRequest(format!(
                    "domain '{domain}' must not contain whitespace or control characters"
                )));
            }
            if !normalized.contains(&domain) {
                normalized.push(domain);
            }
        }
        if normalized.is_empty() {
            return Err(AcmeClientError::InvalidRequest(
                "domains must contain at least one entry".to_string(),
            ));
        }
        Ok(normalized)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashMap;
        use std::convert::Infallible;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use http::{Response, StatusCode};
        use http_body::Frame;
        use http_body_util::StreamBody;

        struct FakeHttpClient {
            status: StatusCode,
            location: Option<&'static str>,
            content_length: Option<u64>,
            body: Bytes,
            requests: Arc<AtomicUsize>,
        }

        impl HttpClient for FakeHttpClient {
            fn request(
                &self,
                _request: Request<BodyWrapper<Bytes>>,
            ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>
            {
                self.requests.fetch_add(1, Ordering::SeqCst);
                let mut builder = Response::builder().status(self.status);
                if let Some(location) = self.location {
                    builder = builder.header(LOCATION, location);
                }
                if let Some(content_length) = self.content_length {
                    builder = builder.header(CONTENT_LENGTH, content_length);
                }
                let response = builder
                    .body(self.body.clone())
                    .expect("valid fake ACME response");
                let (parts, body) = response.into_parts();
                Box::pin(ready(Ok(BytesResponse {
                    parts,
                    body: Box::new(body),
                })))
            }
        }

        fn fake_boundary(
            body: serde_json::Value,
            status: StatusCode,
            location: Option<&'static str>,
        ) -> (PolicyAcmeHttpClient, Arc<AtomicUsize>) {
            fake_boundary_bytes(
                Bytes::from(serde_json::to_vec(&body).expect("serialize fake response")),
                status,
                location,
                None,
            )
        }

        fn fake_boundary_bytes(
            body: Bytes,
            status: StatusCode,
            location: Option<&'static str>,
            content_length: Option<u64>,
        ) -> (PolicyAcmeHttpClient, Arc<AtomicUsize>) {
            let requests = Arc::new(AtomicUsize::new(0));
            let inner = FakeHttpClient {
                status,
                location,
                content_length,
                body,
                requests: requests.clone(),
            };
            (
                PolicyAcmeHttpClient {
                    inner: Box::new(inner),
                    endpoint_policy: super::super::AcmeEndpointPolicy::new(
                        "https://acme.example/directory",
                    )
                    .expect("endpoint policy"),
                },
                requests,
            )
        }

        async fn boundary_request(
            client: &PolicyAcmeHttpClient,
            endpoint: &str,
        ) -> Result<BytesResponse, instant_acme::Error> {
            let request = Request::builder()
                .uri(endpoint)
                .body(BodyWrapper::default())
                .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
            HttpClient::request(client, request).await
        }

        #[test]
        fn normalize_order_domains_trims_lowercases_and_deduplicates() {
            let domains = normalize_order_domains(vec![
                " Example.COM ".to_string(),
                "example.com".to_string(),
                "www.example.com".to_string(),
            ])
            .expect("normalized domains");

            assert_eq!(
                domains,
                vec!["example.com".to_string(), "www.example.com".to_string()]
            );
        }

        #[test]
        fn credential_directory_mismatch_and_legacy_urls_fail_closed() {
            let policy = super::super::AcmeEndpointPolicy::new("https://acme.example/directory")
                .expect("policy");
            let mismatch = SecretString::new(
                serde_json::json!({
                    "id": "https://acme.example/account/1",
                    "key_pkcs8": "not-reached",
                    "directory": "https://acme.example/other-directory"
                })
                .to_string(),
            );
            let error = validate_and_deserialize_credentials(&mismatch, &policy)
                .err()
                .expect("credential-directory drift must be rejected");
            assert!(error.to_string().contains("does not match"), "{error}");

            let legacy = SecretString::new(
                serde_json::json!({
                    "id": "https://acme.example/account/1",
                    "key_pkcs8": "not-reached",
                    "urls": {
                        "newNonce": "https://169.254.169.254/nonce",
                        "newAccount": "https://acme.example/account",
                        "newOrder": "https://acme.example/order"
                    }
                })
                .to_string(),
            );
            let error = validate_and_deserialize_credentials(&legacy, &policy)
                .err()
                .expect("legacy embedded endpoint set must be rejected");
            assert!(
                error.to_string().contains("legacy ACME credentials"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn private_dns_answer_is_rejected_before_connect() {
            let dns_cache = DnsCache::new(DnsConfig {
                global_overrides: HashMap::from([(
                    "rebind.acme.test".to_string(),
                    "169.254.169.254".to_string(),
                )]),
                ..DnsConfig::default()
            });
            let connector = ScreenedAcmeConnector::new(dns_cache);
            let error = connector
                .resolve_candidates("rebind.acme.test")
                .await
                .expect_err("private DNS answer must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(
                error
                    .to_string()
                    .contains("denied by backend egress policy"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn shared_connection_deadline_covers_fresh_dns_resolution() {
            let stalled_resolver = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind stalled DNS responder");
            let resolver_address = stalled_resolver
                .local_addr()
                .expect("stalled resolver address");
            let _stalled_tcp_resolver = tokio::net::TcpListener::bind(resolver_address)
                .await
                .expect("bind stalled TCP DNS responder");
            let dns_cache = DnsCache::new(DnsConfig {
                resolver_addresses: Some(resolver_address.to_string()),
                try_tcp_on_error: false,
                num_concurrent_reqs: 1,
                ..DnsConfig::default()
            });
            let mut connector =
                ScreenedAcmeConnector::with_connect_timeout(dns_cache, Duration::from_millis(25));
            let destination = "https://deadline.acme.test/directory"
                .parse::<Uri>()
                .expect("ACME destination");
            let result = tokio::time::timeout(Duration::from_secs(1), connector.call(destination))
                .await
                .expect("connector must enforce its shorter shared deadline");
            let error = result
                .err()
                .expect("stalled fresh DNS resolution must time out");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(
                error
                    .to_string()
                    .contains("fresh DNS resolution and TCP connection deadline exceeded"),
                "{error}"
            );
        }

        #[test]
        fn public_multi_address_answer_preserves_every_approved_candidate() {
            let connector = ScreenedAcmeConnector::new(default_acme_dns_cache());
            let candidates = vec![
                "1.1.1.1".parse::<IpAddr>().expect("public IPv4"),
                "2606:4700:4700::1111"
                    .parse::<IpAddr>()
                    .expect("public IPv6"),
            ];
            assert_eq!(
                connector
                    .screen_candidates(candidates.clone())
                    .expect("public candidates"),
                candidates,
                "the connector must not first-answer-pin a multi-address result"
            );
        }

        #[test]
        fn excessive_complete_dns_answer_is_rejected_without_truncation() {
            let connector = ScreenedAcmeConnector::new(default_acme_dns_cache());
            let candidates = (1..=MAX_ACME_DNS_CANDIDATES + 1)
                .map(|suffix| IpAddr::from([11, 0, 0, suffix as u8]))
                .collect::<Vec<_>>();
            let error = connector
                .screen_candidates(candidates)
                .expect_err("excessive complete DNS answer must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(
                error.to_string().contains("exceeding the limit of 64"),
                "{error}"
            );
        }

        #[test]
        fn excessive_dns_answer_is_fully_policy_screened_before_size_rejection() {
            let connector = ScreenedAcmeConnector::new(default_acme_dns_cache());
            let mut candidates = (1..=MAX_ACME_DNS_CANDIDATES + 1)
                .map(|suffix| IpAddr::from([11, 0, 0, suffix as u8]))
                .collect::<Vec<_>>();
            candidates.push(IpAddr::from([127, 0, 0, 1]));
            let error = connector
                .screen_candidates(candidates)
                .expect_err("denied address beyond the size bound must still be screened");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                error.to_string().contains("denied by egress policy"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn declared_oversized_response_body_is_rejected_before_collection() {
            let (client, requests) = fake_boundary_bytes(
                Bytes::new(),
                StatusCode::OK,
                None,
                Some(MAX_ACME_RESPONSE_BODY_BYTES_U64 + 1),
            );
            let error = boundary_request(&client, "https://acme.example/directory")
                .await
                .err()
                .expect("oversized Content-Length must be rejected");
            assert!(
                error.to_string().contains("response body exceeds"),
                "{error}"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn streamed_oversized_response_body_is_stopped_at_hyper_limit() {
            let frames = vec![
                Ok::<_, Infallible>(Frame::data(Bytes::from(vec![
                    b'a';
                    MAX_ACME_RESPONSE_BODY_BYTES
                ]))),
                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"!"))),
            ];
            let response = Response::new(StreamBody::new(futures_util::stream::iter(frames)));
            let response =
                limit_hyper_response_body(response).expect("install streaming response limit");
            let BytesResponse { body, .. } = BytesResponse::from(response);
            let error = collect_bounded_response_body(body)
                .await
                .err()
                .expect("streamed body over the cap must fail while collecting");
            assert!(
                error.to_string().contains("response body exceeds"),
                "{error}"
            );
        }

        #[tokio::test]
        async fn custom_client_body_is_checked_again_after_collection() {
            let (client, requests) = fake_boundary_bytes(
                Bytes::from(vec![b'a'; MAX_ACME_RESPONSE_BODY_BYTES + 1]),
                StatusCode::OK,
                None,
                None,
            );
            let error = boundary_request(&client, "https://acme.example/directory")
                .await
                .err()
                .expect("custom client body over the cap must be rejected");
            assert!(
                error.to_string().contains("response body exceeds"),
                "{error}"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn same_origin_absolute_endpoints_are_allowed() {
            let (client, requests) = fake_boundary(
                serde_json::json!({
                    "authorizations": ["https://acme.example/authz/1?attempt=2"],
                    "finalize": "https://acme.example/finalize/1",
                    "certificate": "https://acme.example/certificate/1"
                }),
                StatusCode::OK,
                Some("https://acme.example/order/1"),
            );
            assert!(
                boundary_request(&client, "https://acme.example/order/1")
                    .await
                    .is_ok(),
                "same-origin paths and queries must remain valid"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn private_directory_and_order_resource_urls_never_reach_transport() {
            let (client, requests) = fake_boundary(serde_json::json!({}), StatusCode::OK, None);
            for endpoint in [
                "https://127.0.0.1/directory",
                "https://169.254.169.254/order/1",
                "https://10.0.0.1/authz/1",
                "https://[::1]/challenge/1",
                "https://[fe80::1]/finalize/1",
                "https://[fc00::1]/certificate/1",
                "https://1.2.3.0x4/order/1",
                "https://0X100000000/authz/1",
                "https://%31.%32.%33.%34/challenge/1",
            ] {
                assert!(
                    boundary_request(&client, endpoint).await.is_err(),
                    "private endpoint must be rejected"
                );
            }
            assert_eq!(
                requests.load(Ordering::SeqCst),
                0,
                "hostile endpoints must fail at their request consumption boundary"
            );
        }

        #[tokio::test]
        async fn private_directory_new_nonce_and_new_order_are_rejected_in_response() {
            for body in [
                serde_json::json!({
                    "newNonce": "https://169.254.169.254/nonce",
                    "newAccount": "https://acme.example/account",
                    "newOrder": "https://acme.example/order"
                }),
                serde_json::json!({
                    "newNonce": "https://acme.example/nonce",
                    "newAccount": "https://acme.example/account",
                    "newOrder": "https://127.0.0.1/order"
                }),
            ] {
                let (client, requests) = fake_boundary(body, StatusCode::OK, None);
                assert!(
                    boundary_request(&client, "https://acme.example/directory")
                        .await
                        .is_err(),
                    "private directory endpoint must be rejected"
                );
                assert_eq!(requests.load(Ordering::SeqCst), 1);
            }
        }

        #[tokio::test]
        async fn private_order_authorization_challenge_finalize_and_certificate_fields_are_rejected()
         {
            let cases = [
                (
                    serde_json::json!({}),
                    Some("https://169.254.169.254/order/1"),
                ),
                (
                    serde_json::json!({
                        "authorizations": ["https://10.0.0.1/authz/1"]
                    }),
                    None,
                ),
                (
                    serde_json::json!({
                        "challenges": [{
                            "type": "http-01",
                            "url": "https://127.0.0.1/challenge/1",
                            "status": "pending",
                            "token": "token"
                        }]
                    }),
                    None,
                ),
                (
                    serde_json::json!({
                        "finalize": "https://[::1]/finalize/1"
                    }),
                    None,
                ),
                (
                    serde_json::json!({
                        "certificate": "https://[fe80::1]/certificate/1"
                    }),
                    None,
                ),
            ];
            for (body, location) in cases {
                let (client, requests) = fake_boundary(body, StatusCode::OK, location);
                assert!(
                    boundary_request(&client, "https://acme.example/order/1")
                        .await
                        .is_err(),
                    "private server-supplied endpoint must be rejected"
                );
                assert_eq!(requests.load(Ordering::SeqCst), 1);
            }
        }

        #[tokio::test]
        async fn https_and_redirect_invariants_fail_closed() {
            let (client, requests) = fake_boundary(serde_json::json!({}), StatusCode::FOUND, None);
            assert!(
                boundary_request(&client, "http://acme.example/directory")
                    .await
                    .is_err(),
                "plaintext ACME endpoint must be rejected"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 0);

            assert!(
                boundary_request(&client, "https://acme.example/directory")
                    .await
                    .is_err(),
                "redirect response must be rejected"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn renewal_completion_uses_credential_and_persisted_order_boundary() {
            let config = CompleteAcmeHttp01OrderConfig {
                directory_url: "https://acme.example/directory".to_string(),
                account_credentials_json: SecretString::new(
                    serde_json::json!({
                        "id": "https://acme.example/account/1",
                        "key_pkcs8": "not-reached",
                        "directory": "https://other.example/directory"
                    })
                    .to_string(),
                ),
                order_url: "https://acme.example/order/1".to_string(),
                poll_timeout: Duration::from_secs(1),
                dns_cache: default_acme_dns_cache(),
            };
            let error = complete_order(config, ChallengeType::Http01, "http-01")
                .await
                .expect_err("renewal restore must reject credential drift before network");
            assert!(matches!(error, AcmeClientError::EgressPolicy(_)));
        }

        #[tokio::test]
        async fn renewal_preparation_uses_the_same_credential_boundary() {
            let config = AcmeOrderConfig {
                account: AcmeAccountConfig {
                    directory_url: "https://acme.example/directory".to_string(),
                    contact: Vec::new(),
                    terms_of_service_agreed: true,
                    existing_credentials_json: Some(SecretString::new(
                        serde_json::json!({
                            "id": "https://acme.example/account/1",
                            "key_pkcs8": "not-reached",
                            "directory": "https://other.example/directory"
                        })
                        .to_string(),
                    )),
                },
                domains: vec!["example.com".to_string()],
                dns_cache: default_acme_dns_cache(),
            };
            let error = prepare_order(config, ChallengeType::Http01, "http-01")
                .await
                .expect_err("renewal preparation must reject credential drift before network");
            assert!(matches!(error, AcmeClientError::EgressPolicy(_)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_url_ssrf_policy_rejects_non_https_and_missing_host() {
        for bad in [
            "http://acme.example/dir", // non-https scheme
            "file:///etc/passwd",      // non-https scheme
            "acme.example/dir",        // missing scheme
            "https:///dir",            // missing host
            "not a url",               // unparseable
        ] {
            assert!(
                validate_acme_directory_url_ssrf_policy(bad).is_err(),
                "expected rejection for {bad}"
            );
        }
    }

    #[test]
    fn directory_url_ssrf_policy_rejects_private_ip_literals() {
        for bad in [
            "https://127.0.0.1/dir",          // IPv4 loopback
            "https://10.0.0.1/dir",           // RFC1918
            "https://169.254.169.254/latest", // link-local cloud metadata
            "https://[::1]/dir",              // IPv6 loopback
            "https://[fe80::1]/dir",          // IPv6 link-local
            "https://[fc00::1]/dir",          // IPv6 ULA
            "https://user@127.0.0.1/dir",     // userinfo must not bypass the IP gate
        ] {
            assert!(
                validate_acme_directory_url_ssrf_policy(bad).is_err(),
                "expected rejection for {bad}"
            );
        }
    }

    #[test]
    fn directory_url_ssrf_policy_rejects_non_canonical_numeric_ips() {
        for bad in [
            "https://2130706433/dir",
            "https://0177.0.0.1/dir",
            "https://127.1/dir",
            // WHATWG URL parsing treats a final all-numeric label as an IPv4
            // candidate. Keep this fail-closed instead of letting the HTTP and
            // URL parser views disagree about the authority.
            "https://example.123/dir",
            "https://0x7f.0.0.1/dir",
            "https://127.0.0x1/dir",
            "https://127.0x1/dir",
            "https://1.2.3.0x4/dir",
            "https://1.2.3.0X4/dir",
            "https://0x7f000001/dir",
            "https://0xA9FEA9FE/dir",
            "https://4294967296/dir",
            "https://0x100000000/dir",
            "https://040000000000/dir",
            "https://999.999.999.999/dir",
            "https://+2130706433/dir",
            "https://1.2.-3.4/dir",
            "https://1.2.3.4./dir",
            "https://%31.%32.%33.%34/dir",
            "https://[1.2.3.4]/dir",
        ] {
            assert!(
                validate_acme_directory_url_ssrf_policy(bad).is_err(),
                "expected rejection for {bad}"
            );
        }

        let error = validate_acme_directory_url_ssrf_policy("https://1.2.3.0x4/private-resource")
            .expect_err("mixed-base host must be rejected");
        assert!(
            !error.to_string().contains("1.2.3.0x4"),
            "rejection must not disclose the endpoint host"
        );
    }

    #[test]
    fn legacy_numeric_classifier_preserves_dns_names() {
        for (host, ambiguous) in [
            ("2130706433", true),
            ("0x100000000", true),
            ("1.2.3.0x4", true),
            ("0377.0X0.0.1", true),
            ("+2130706433", true),
            ("1.2.-3.4", true),
            ("999.999.999.999", true),
            ("1.2.3.4.", true),
            ("beef.cafe", false),
            ("dead.cab", false),
            ("abc.def.1a2b", false),
            ("3com.example.com", false),
            ("example.123", false),
            ("0xlab.io", false),
        ] {
            assert_eq!(
                is_ambiguous_legacy_numeric_ipv4_host(host),
                ambiguous,
                "unexpected legacy-numeric classification for {host:?}"
            );
        }
    }

    #[test]
    fn directory_url_ssrf_policy_accepts_public_ips_and_hostnames() {
        // Syntactically valid hostnames pass the admission layer. The controlled
        // connector makes the authoritative public-only decision after fresh DNS.
        for ok in [
            "https://acme-v02.api.letsencrypt.org/directory",
            " https://acme-staging-v02.api.letsencrypt.org/directory ",
            "https://1.1.1.1/dir",
            "https://[2606:4700:4700::1111]/dir",
            "https://[2606:4700:4700:0:0:0:0:1111]/dir",
            "https://ACME.EXAMPLE.COM/dir",
            "https://acme.example.com./dir",
            "https://acme.example/%64irectory",
            "https://localhost/dir",
            "https://beef.cafe/dir",
            "https://dead.cab/dir",
            "https://abc.def.1a2b/dir",
            "https://3com.example.com/dir",
        ] {
            assert!(
                validate_acme_directory_url_ssrf_policy(ok).is_ok(),
                "expected acceptance for {ok}"
            );
        }
    }

    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn automatic_renewal_preparation_uses_the_acme_outbound_boundary() {
        let certificate = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id: "renewal-boundary".to_string(),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: Some("https://acme.example/account/1".to_string()),
            order_url: None,
            cert_pem: String::new(),
            key_pem: String::new(),
            chain_pem: None,
        })
        .expect("certificate record");
        let credentials = serde_json::json!({
            "id": "https://acme.example/account/1",
            "key_pkcs8": "not-reached",
            "directory": "https://other.example/directory"
        })
        .to_string();
        let config = AcmeRenewalSchedulerConfig {
            enabled: true,
            renew_when_remaining_days: 30,
            check_interval: Duration::from_secs(60),
            poll_timeout: Duration::from_secs(1),
            challenge_type: AcmeRenewalChallengeType::Http01,
            dns01_hook_command: None,
            dns01_propagation: Duration::ZERO,
            dns_cache: client::default_acme_dns_cache(),
        };

        let error = prepare_renewal_order(&certificate, credentials, &config)
            .await
            .expect_err("automatic renewal must reject credential-directory drift");
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    fn generated_cert_and_key() -> (String, String) {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["example.com".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn store_persists_and_loads_certificate_parts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeCertificateStore::open(dir.path()).expect("open store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        let record = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id: "edge-cert".to_string(),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            account_id: Some("account-1".to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            chain_pem: None,
        })
        .expect("record");

        store.upsert_certificate(record, false).expect("upsert");

        let cert = store
            .material("certificates/edge-cert#cert", MaterialKind::Cert)
            .expect("cert material");
        let key = store
            .material("certificates/edge-cert#key", MaterialKind::Key)
            .expect("key material");
        assert_eq!(cert.bytes, cert_pem.into_bytes());
        assert_eq!(key.bytes, key_pem.into_bytes());
        assert_eq!(cert.source_id, "acme://certificates/edge-cert#cert");

        let reopened = AcmeCertificateStore::open(dir.path()).expect("reopen store");
        assert_eq!(reopened.list_certificates().len(), 1);
    }

    #[test]
    fn source_reference_accepts_short_and_collection_forms() {
        let short = AcmeSourceReference::parse("edge-cert#cert", MaterialKind::Unknown)
            .expect("short reference");
        let collection =
            AcmeSourceReference::parse("certificates/edge-cert#key", MaterialKind::Unknown)
                .expect("collection reference");

        assert_eq!(short.id, "edge-cert");
        assert_eq!(short.part, AcmeMaterialPart::Cert);
        assert_eq!(collection.id, "edge-cert");
        assert_eq!(collection.part, AcmeMaterialPart::Key);
    }

    #[test]
    fn source_reference_rejects_unknown_material_part() {
        let error = AcmeSourceReference::parse("edge-cert#ca", MaterialKind::Unknown)
            .expect_err("invalid part");

        assert!(matches!(error, AcmeError::InvalidId(_)));
    }

    #[test]
    fn order_store_serves_pending_http01_challenge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeOrderStore::open(dir.path()).expect("open order store");
        let record = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "edge-order".to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            account_id: None,
            account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges: vec![AcmeHttp01ChallengeRecord {
                identifier: "example.com".to_string(),
                token: "abc_DEF-123".to_string(),
                key_authorization: "abc_DEF-123.thumbprint".to_string(),
            }],
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: Vec::new(),
            error: None,
        })
        .expect("order record");

        store.upsert_order(record, false).expect("upsert order");

        assert_eq!(
            store.http01_key_authorization("abc_DEF-123").as_deref(),
            Some("abc_DEF-123.thumbprint")
        );
        assert_eq!(
            store.list_orders()[0].http01_challenges[0].path,
            "/.well-known/acme-challenge/abc_DEF-123"
        );

        let reopened = AcmeOrderStore::open(dir.path()).expect("reopen order store");
        assert_eq!(
            reopened.http01_key_authorization("abc_DEF-123").as_deref(),
            Some("abc_DEF-123.thumbprint")
        );
    }

    #[test]
    fn order_store_rejects_malformed_http01_token() {
        let error = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "edge-order".to_string(),
            certificate_id: None,
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: None,
            account_credentials_json: None,
            order_url: None,
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges: vec![AcmeHttp01ChallengeRecord {
                identifier: "example.com".to_string(),
                token: "../bad".to_string(),
                key_authorization: "bad.thumbprint".to_string(),
            }],
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: Vec::new(),
            error: None,
        })
        .expect_err("invalid token rejected");

        assert!(matches!(error, AcmeError::InvalidChallengeToken(_)));
    }

    #[test]
    fn order_store_serves_pending_tls_alpn01_challenge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeOrderStore::open(dir.path()).expect("open order store");
        let record = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "edge-order".to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: None,
            account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges: Vec::new(),
            tls_alpn01_challenges: vec![AcmeTlsAlpn01ChallengeRecord {
                identifier: "Example.COM.".to_string(),
                token: "abc_DEF-123".to_string(),
                key_authorization: "abc_DEF-123.thumbprint".to_string(),
            }],
            dns01_challenges: Vec::new(),
            error: None,
        })
        .expect("order record");

        store.upsert_order(record, false).expect("upsert order");

        assert_eq!(
            store.tls_alpn01_key_authorization("example.com").as_deref(),
            Some("abc_DEF-123.thumbprint")
        );
        assert_eq!(
            store.list_orders()[0].tls_alpn01_challenges[0].alpn_protocol,
            "acme-tls/1"
        );
        assert!(
            !store.list_orders()[0].tls_alpn01_challenges[0]
                .key_authorization_sha256_base64url
                .is_empty()
        );
    }

    #[test]
    fn order_summary_exposes_dns01_txt_record() {
        let record = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "edge-order".to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["*.example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: None,
            account_credentials_json: Some(r#"{"redacted":true}"#.to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges: Vec::new(),
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: vec![AcmeDns01ChallengeRecord {
                identifier: "*.Example.COM.".to_string(),
                token: "abc_DEF-123".to_string(),
                key_authorization: "abc_DEF-123.thumbprint".to_string(),
            }],
            error: None,
        })
        .expect("order record");

        let summary = record.summary();

        assert_eq!(
            summary.dns01_challenges[0].txt_record_name,
            "_acme-challenge.example.com"
        );
        assert!(!summary.dns01_challenges[0].txt_value.is_empty());
    }

    #[test]
    fn tls_alpn01_certified_key_contains_acme_identifier_extension() {
        let certified_key = build_tls_alpn01_certified_key("example.com", "abc_DEF-123.thumbprint")
            .expect("validation certified key");
        let (_, certificate) =
            X509Certificate::from_der(certified_key.cert[0].as_ref()).expect("parse cert");
        let acme_identifier = certificate
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");

        assert!(acme_identifier.critical);
    }

    #[test]
    fn latest_order_for_certificate_selects_newest_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeOrderStore::open(dir.path()).expect("open order store");
        let older = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "older-order".to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: None,
            account_credentials_json: Some(r#"{"older":true}"#.to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            status: AcmeOrderStatus::Failed,
            http01_challenges: Vec::new(),
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: Vec::new(),
            error: Some("old failure".to_string()),
        })
        .expect("older order");
        store.upsert_order(older, false).expect("upsert older");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let newer = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "newer-order".to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: None,
            account_credentials_json: Some(r#"{"newer":true}"#.to_string()),
            order_url: Some("https://acme.example/order/2".to_string()),
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges: Vec::new(),
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: Vec::new(),
            error: None,
        })
        .expect("newer order");
        store.upsert_order(newer, false).expect("upsert newer");

        let latest = store
            .latest_order_for_certificate("edge-cert")
            .expect("latest lookup")
            .expect("latest order");

        assert_eq!(latest.id, "newer-order");
    }

    #[test]
    fn account_summaries_do_not_return_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let certificate_store = AcmeCertificateStore::open(dir.path()).expect("open cert store");
        let order_store = AcmeOrderStore::open(dir.path()).expect("open order store");
        let (cert_pem, key_pem) = generated_cert_and_key();
        let certificate = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id: "edge-cert".to_string(),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: Some("https://acme.example/acct/1".to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            cert_pem,
            key_pem,
            chain_pem: None,
        })
        .expect("certificate");
        certificate_store
            .upsert_certificate(certificate, false)
            .expect("upsert certificate");
        let order = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: "edge-order".to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: Some("https://acme.example/acct/1".to_string()),
            account_credentials_json: Some(r#"{"secret":true}"#.to_string()),
            order_url: Some("https://acme.example/order/1".to_string()),
            status: AcmeOrderStatus::Valid,
            http01_challenges: Vec::new(),
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: Vec::new(),
            error: None,
        })
        .expect("order");
        order_store
            .upsert_order(order, false)
            .expect("upsert order");

        let certificates = certificate_store.list_certificates();
        let accounts = order_store.list_accounts(&certificates, &[]);
        let serialized = serde_json::to_string(&accounts).expect("serialize accounts");

        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].order_count, 1);
        assert_eq!(accounts[0].certificate_count, 1);
        assert!(accounts[0].has_persisted_credentials);
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn account_store_persists_credentials_without_exposing_them_in_summaries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let account_store = AcmeAccountStore::open(dir.path()).expect("open account store");
        let order_store = AcmeOrderStore::open(dir.path()).expect("open order store");
        account_store
            .upsert_account(
                "https://acme.example/acct/1".to_string(),
                "https://acme.example/directory".to_string(),
                r#"{"private_key":"secret"}"#.to_string(),
            )
            .expect("upsert account");

        let reopened = AcmeAccountStore::open(dir.path()).expect("reopen account store");
        assert_eq!(
            reopened
                .get_credentials(
                    "https://acme.example/directory",
                    "https://acme.example/acct/1"
                )
                .expect("credentials lookup")
                .as_deref(),
            Some(r#"{"private_key":"secret"}"#)
        );

        let accounts = order_store.list_accounts(&[], &reopened.list_accounts());
        let serialized = serde_json::to_string(&accounts).expect("serialize accounts");

        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].has_persisted_credentials);
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn summary_does_not_return_private_key_material() {
        let (cert_pem, key_pem) = generated_cert_and_key();
        let record = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id: "edge-cert".to_string(),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            account_id: None,
            order_url: None,
            cert_pem,
            key_pem: key_pem.clone(),
            chain_pem: None,
        })
        .expect("record");

        let summary = serde_json::to_string(&record.summary()).expect("serialize summary");

        assert!(!summary.contains(&key_pem));
        assert!(summary.contains("acme://certificates/edge-cert"));
    }
}
