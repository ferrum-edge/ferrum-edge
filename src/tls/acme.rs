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
        if !certificates.contains_key(id) {
            return Err(AcmeError::NotFound(id.to_string()));
        }
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
            .map_err(|error| AcmeError::Write(error.to_string()))
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
        if !orders.contains_key(id) {
            return Err(AcmeError::OrderNotFound(id.to_string()));
        }
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
            .map_err(|error| AcmeError::Write(error.to_string()))
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
            .map_err(|error| AcmeError::Write(error.to_string()))
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

/// Detects non-canonical numeric IPv4 representations that `IpAddr::parse()` rejects
/// but system resolvers (getaddrinfo) interpret as real addresses: decimal integers
/// (`2130706433`), hex integers (`0x7f000001`), hex-dotted (`0x7f.0.0.1`), abbreviated
/// dotted (`127.1`), and octal dotted (`0177.0.0.1`).
fn is_non_canonical_numeric_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if (host.starts_with("0x") || host.starts_with("0X"))
        && host
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b'x' || b == b'X')
    {
        return true;
    }
    if host.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    if !host.contains('.') {
        return false;
    }
    host.split('.').all(|segment| {
        if segment.is_empty() {
            return false;
        }
        if segment.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
        if let Some(hex) = segment
            .strip_prefix("0x")
            .or_else(|| segment.strip_prefix("0X"))
            && !hex.is_empty()
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return true;
        }
        false
    })
}

/// Enforces SSRF policy on an operator-supplied ACME `directory_url` before any
/// outbound ACME network activity.
///
/// This is the single chokepoint guarding directory URLs: it is invoked at order
/// preparation in [`client::prepare_order`] — which covers both interactive order
/// creation and the automatic renewal scheduler — and again at the certificate
/// import boundary, so a stored URL is validated both at rest and immediately
/// before use regardless of how the record was persisted.
///
/// Policy:
/// - must parse as an absolute URL with the `https` scheme and a non-empty host;
/// - if the host is a literal IP, it must be a public address (hard-coded
///   [`BackendAllowIps::Public`](crate::config::BackendAllowIps)). Public CAs are
///   always reachable, while private/reserved literals — loopback, RFC1918,
///   link-local, ULA, and the cloud metadata address `169.254.169.254` — are
///   rejected. `Public` is hard-coded rather than reusing `FERRUM_BACKEND_ALLOW_IPS`
///   (which defaults to `both`, a no-op) so the guard is effective on stock installs.
///
/// Known gap: hostnames are not resolved here, so a hostname whose A/AAAA record
/// resolves to a private IP (e.g. `localhost`, `*.nip.io`, `metadata.google.internal`)
/// is not blocked by this check; the downstream ACME client resolves and connects
/// without an IP gate, so operators must still enforce network-level egress controls.
/// This mirrors the literal-only enforcement used elsewhere for
/// `FERRUM_BACKEND_ALLOW_IPS`.
pub(crate) fn validate_acme_directory_url_ssrf_policy(
    directory_url: &str,
) -> Result<(), AcmeError> {
    let uri: hyper::Uri = directory_url
        .trim()
        .parse()
        .map_err(|_| AcmeError::BlockedDirectoryUrl("must be a valid absolute URL".to_string()))?;
    if uri.scheme_str() != Some("https") {
        return Err(AcmeError::BlockedDirectoryUrl(
            "must use https scheme".to_string(),
        ));
    }
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| AcmeError::BlockedDirectoryUrl("must include a host".to_string()))?;
    // hyper::Uri::host() strips userinfo, so `https://name@127.0.0.1/` resolves to the
    // literal `127.0.0.1` here rather than the userinfo, closing that bypass. IPv6
    // literals are returned bracketed (`[::1]`); strip the brackets before parsing so
    // private IPv6 literals cannot slip past the IP gate as if they were hostnames.
    let host_ip = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host_ip.parse::<std::net::IpAddr>() {
        if !crate::config::check_backend_ip_allowed(&ip, &crate::config::BackendAllowIps::Public) {
            return Err(AcmeError::BlockedDirectoryUrl(format!(
                "host IP {ip} is not a public address"
            )));
        }
    } else if is_non_canonical_numeric_host(host_ip) {
        return Err(AcmeError::BlockedDirectoryUrl(format!(
            "non-standard numeric host '{host_ip}' is not permitted; use a hostname or standard dotted-decimal IP"
        )));
    }
    Ok(())
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
    if token.len() > 256 {
        return Err(AcmeError::InvalidChallengeToken(
            "token exceeds 256 bytes".to_string(),
        ));
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

pub fn http01_key_authorization_for_path(path: &str) -> Option<String> {
    let token = path.strip_prefix(HTTP01_CHALLENGE_PREFIX)?;
    if token.contains('/') || token.contains('?') {
        return None;
    }
    global_order_store().ok()?.http01_key_authorization(token)
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
#[derive(Debug, Clone)]
pub struct AcmeRenewalSchedulerConfig {
    pub enabled: bool,
    pub renew_when_remaining_days: u64,
    pub check_interval: Duration,
    pub poll_timeout: Duration,
    pub challenge_type: AcmeRenewalChallengeType,
    pub dns01_hook_command: Option<String>,
    pub dns01_propagation: Duration,
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
        account_credentials_json: crate::tls::source::SecretString::new(account_credentials_json),
        order_url,
        poll_timeout: config.poll_timeout,
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

    use std::time::Duration;

    use instant_acme::{
        Account, AccountCredentials, ChallengeStatus, ChallengeType, Identifier, NewAccount,
        NewOrder, OrderStatus, RetryPolicy,
    };
    use serde::Serialize;
    use thiserror::Error;

    use crate::tls::source::SecretString;

    #[derive(Debug, Clone)]
    pub struct AcmeAccountConfig {
        pub directory_url: String,
        pub contact: Vec<String>,
        pub terms_of_service_agreed: bool,
        pub existing_credentials_json: Option<SecretString>,
    }

    #[derive(Debug, Clone)]
    pub struct AcmeOrderConfig {
        pub account: AcmeAccountConfig,
        pub domains: Vec<String>,
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

    #[derive(Debug, Clone)]
    pub struct CompleteAcmeHttp01OrderConfig {
        pub account_credentials_json: SecretString,
        pub order_url: String,
        pub poll_timeout: Duration,
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
        #[error("ACME client error: {0}")]
        Client(String),
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
        // SSRF chokepoint: validate the operator-supplied directory URL before any
        // outbound ACME activity. Both interactive order creation and the automatic
        // renewal scheduler funnel through here, so this also closes the renewal path.
        super::validate_acme_directory_url_ssrf_policy(&config.account.directory_url)
            .map_err(|error| AcmeClientError::InvalidRequest(error.to_string()))?;
        let domains = normalize_order_domains(config.domains)?;
        let account = resolve_account(&config.account).await?;
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
        let mut challenges = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization =
                authorization.map_err(|error| AcmeClientError::Client(error.to_string()))?;
            let authorization_url = authorization.url().to_string();
            let Some(challenge) = authorization.challenge(challenge_type.clone()) else {
                return Err(AcmeClientError::InvalidRequest(format!(
                    "ACME authorization '{}' does not offer {}",
                    authorization_url, challenge_name
                )));
            };
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
        let account = restore_account(&config.account_credentials_json).await?;
        let order_url = config.order_url.trim();
        if order_url.is_empty() {
            return Err(AcmeClientError::InvalidRequest(
                "order_url must not be empty".to_string(),
            ));
        }
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
                let Some(mut challenge) = authorization.challenge(challenge_type.clone()) else {
                    return Err(AcmeClientError::InvalidRequest(format!(
                        "ACME authorization '{}' does not offer {}",
                        authorization_url, challenge_name
                    )));
                };
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
    ) -> Result<ResolvedAccount, AcmeClientError> {
        if config.directory_url.trim().is_empty() {
            return Err(AcmeClientError::InvalidRequest(
                "directory_url must not be empty".to_string(),
            ));
        }
        if let Some(credentials_json) = config.existing_credentials_json.as_ref() {
            let account = restore_account(credentials_json).await?;
            return Ok(ResolvedAccount {
                account,
                credentials_json: credentials_json.clone(),
            });
        }

        let builder =
            Account::builder().map_err(|error| AcmeClientError::Client(error.to_string()))?;
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

    async fn restore_account(credentials_json: &SecretString) -> Result<Account, AcmeClientError> {
        let credentials =
            serde_json::from_str::<AccountCredentials>(credentials_json.expose_secret())
                .map_err(|error| AcmeClientError::DeserializeCredentials(error.to_string()))?;
        Account::builder()
            .map_err(|error| AcmeClientError::Client(error.to_string()))?
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
            "https://2130706433/dir", // decimal integer = 127.0.0.1
            "https://0177.0.0.1/dir", // octal = 127.0.0.1 on glibc
            "https://127.1/dir",      // abbreviated = 127.0.0.1
            "https://0x7f.0.0.1/dir", // hex-prefixed = 127.0.0.1
            "https://127.0.0x1/dir",  // mixed-base dotted = 127.0.0.1
            "https://127.0x1/dir",    // mixed-base abbreviated = 127.0.0.1
            "https://1.2.3.0x4/dir",  // mixed-base full dotted
            "https://0x7f000001/dir", // hex integer = 127.0.0.1
            "https://0xA9FEA9FE/dir", // hex integer = 169.254.169.254
        ] {
            assert!(
                validate_acme_directory_url_ssrf_policy(bad).is_err(),
                "expected rejection for {bad}"
            );
        }
    }

    #[test]
    fn non_canonical_numeric_host_detection() {
        for (host, expected) in [
            ("2130706433", true),         // decimal integer
            ("0x7f000001", true),         // hex integer
            ("0XA9FEA9FE", true),         // hex integer uppercase prefix
            ("0x7f.0.0.1", true),         // hex-dotted
            ("127.0.0x1", true),          // mixed-base dotted
            ("127.0x1", true),            // mixed-base abbreviated
            ("1.2.3.0x4", true),          // mixed-base 4-segment
            ("0177.0.0.1", true),         // octal-dotted
            ("127.1", true),              // abbreviated dotted
            ("192.168.1", true),          // abbreviated 3-segment
            ("beef.cafe", false),         // hex-only hostname
            ("dead.cab", false),          // hex-only hostname
            ("abc.def.1a2b", false),      // mixed hex hostname
            ("localhost", false),         // alpha hostname
            ("example.com", false),       // normal hostname
            ("0x-ca.example.com", false), // 0x-prefixed hostname with non-hex chars
            ("0xlab.io", false),          // 0x-prefixed hostname with non-hex chars
            ("0xproject.com", false),     // 0x-prefixed hostname with non-hex chars
            ("", false),                  // empty
        ] {
            assert_eq!(
                is_non_canonical_numeric_host(host),
                expected,
                "is_non_canonical_numeric_host({host:?}) should be {expected}"
            );
        }
    }

    #[test]
    fn directory_url_ssrf_policy_accepts_public_ips_and_hostnames() {
        // Public CAs (hostnames) and public IP literals are permitted. Hostnames
        // resolving to private IPs are a documented gap (no DNS resolution here).
        for ok in [
            "https://acme-v02.api.letsencrypt.org/directory",
            " https://acme-staging-v02.api.letsencrypt.org/directory ", // trimmed
            "https://1.1.1.1/dir",                                      // public IPv4 literal
            "https://[2606:4700:4700::1111]/dir",                       // public IPv6 literal
            "https://localhost/dir",    // hostname gap: not blocked here
            "https://beef.cafe/dir",    // hex-only hostname is not a numeric IP
            "https://dead.cab/dir",     // hex-only hostname is not a numeric IP
            "https://abc.def.1a2b/dir", // mixed hex hostname
        ] {
            assert!(
                validate_acme_directory_url_ssrf_policy(ok).is_ok(),
                "expected acceptance for {ok}"
            );
        }
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

    fn sample_certificate(id: &str, domains: &[&str]) -> AcmeCertificateRecord {
        let (cert_pem, key_pem) = generated_cert_and_key();
        AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
            id: id.to_string(),
            domains: domains.iter().map(|value| (*value).to_string()).collect(),
            directory_url: "https://acme.example/directory".to_string(),
            account_id: None,
            order_url: None,
            cert_pem,
            key_pem,
            chain_pem: None,
        })
        .expect("certificate")
    }

    fn sample_order(id: &str) -> AcmeOrderRecord {
        AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
            id: id.to_string(),
            certificate_id: Some("edge-cert".to_string()),
            domains: vec!["example.com".to_string()],
            directory_url: "https://acme.example/directory".to_string(),
            account_id: Some("https://acme.example/acct/1".to_string()),
            account_credentials_json: None,
            order_url: None,
            status: AcmeOrderStatus::PendingChallenges,
            http01_challenges: Vec::new(),
            tls_alpn01_challenges: Vec::new(),
            dns01_challenges: Vec::new(),
            error: None,
        })
        .expect("order")
    }

    #[test]
    fn acme_certificate_failed_mutations_leave_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeCertificateStore::open(dir.path()).expect("open store");
        store
            .upsert_certificate(sample_certificate("edge-cert", &["example.com"]), false)
            .expect("seed");

        crate::tls::private_file::inject_replace_failure("rename");
        let error = store
            .upsert_certificate(sample_certificate("other-cert", &["other.example"]), false)
            .expect_err("create must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert!(store.get_certificate("other-cert").is_err());

        crate::tls::private_file::inject_replace_failure("write");
        let before = store.get_certificate("edge-cert").expect("seed get");
        let error = store
            .upsert_certificate(sample_certificate("edge-cert", &["example.com"]), true)
            .expect_err("update must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert_eq!(
            store.get_certificate("edge-cert").expect("live get").updated_at,
            before.updated_at
        );

        crate::tls::private_file::inject_replace_failure("rename");
        let error = store
            .delete_certificate("edge-cert")
            .expect_err("delete must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert!(store.get_certificate("edge-cert").is_ok());
        assert_no_temp_files(dir.path());

        let reopened = AcmeCertificateStore::open(dir.path()).expect("reopen");
        assert_eq!(reopened.list_certificates().len(), 1);
        assert!(reopened.get_certificate("edge-cert").is_ok());
    }

    #[test]
    fn acme_order_failed_mutations_leave_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeOrderStore::open(dir.path()).expect("open store");
        store
            .upsert_order(sample_order("edge-order"), false)
            .expect("seed");

        crate::tls::private_file::inject_replace_failure("rename");
        let error = store
            .upsert_order(sample_order("other-order"), false)
            .expect_err("create must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert!(store.get_order("other-order").is_err());

        crate::tls::private_file::inject_replace_failure("write");
        let before = store.get_order("edge-order").expect("seed get");
        let error = store
            .upsert_order(sample_order("edge-order"), true)
            .expect_err("update must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert_eq!(
            store.get_order("edge-order").expect("live get").updated_at,
            before.updated_at
        );

        crate::tls::private_file::inject_replace_failure("rename");
        let error = store.delete_order("edge-order").expect_err("delete must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert!(store.get_order("edge-order").is_ok());
        assert_no_temp_files(dir.path());

        let reopened = AcmeOrderStore::open(dir.path()).expect("reopen");
        assert_eq!(reopened.list_orders().len(), 1);
        assert!(reopened.get_order("edge-order").is_ok());
    }

    #[test]
    fn acme_account_failed_upsert_leaves_memory_and_disk_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = AcmeAccountStore::open(dir.path()).expect("open store");
        store
            .upsert_account(
                "https://acme.example/acct/1".to_string(),
                "https://acme.example/directory".to_string(),
                r#"{"private_key":"version-a"}"#.to_string(),
            )
            .expect("seed");

        crate::tls::private_file::inject_replace_failure("rename");
        let error = store
            .upsert_account(
                "https://acme.example/acct/1".to_string(),
                "https://acme.example/directory".to_string(),
                r#"{"private_key":"version-b"}"#.to_string(),
            )
            .expect_err("upsert must fail");
        assert!(matches!(error, AcmeError::Write(_)));
        assert_eq!(
            store
                .get_credentials(
                    "https://acme.example/directory",
                    "https://acme.example/acct/1"
                )
                .expect("live credentials")
                .as_deref(),
            Some(r#"{"private_key":"version-a"}"#)
        );
        assert_no_temp_files(dir.path());

        let reopened = AcmeAccountStore::open(dir.path()).expect("reopen");
        assert_eq!(
            reopened
                .get_credentials(
                    "https://acme.example/directory",
                    "https://acme.example/acct/1"
                )
                .expect("disk credentials")
                .as_deref(),
            Some(r#"{"private_key":"version-a"}"#)
        );
    }
}
