//! SOAP WS-Security Plugin
//!
//! Validates WS-Security headers in SOAP envelopes at the proxy layer.
//! Supports UsernameToken authentication (PasswordText and PasswordDigest),
//! X.509 certificate signature verification, optional SAML assertion
//! validation, timestamp freshness checks, and nonce replay protection.
//!
//! Runs in `before_proxy` with request body buffering. Priority 1500 places
//! it in the AuthN band after HMAC auth.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ring::digest;
use ring::signature as ring_sig;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn};
use x509_parser::prelude::*;

use super::{Plugin, PluginResult, RequestContext};

// ── Namespace URIs ──────────────────────────────────────────────────────────

const PASSWORD_DIGEST_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const PASSWORD_TEXT_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const XMLDSIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const XMLDSIG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const XMLDSIG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLDSIG_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

// ── Config types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordType {
    PasswordText,
    PasswordDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureAlgorithm {
    RsaSha256,
    RsaSha1,
}

#[derive(Debug, Clone)]
struct Credential {
    username: String,
    password: String,
}

struct TrustedCert {
    /// DER-encoded public key bytes for signature verification.
    public_key_der: Vec<u8>,
    /// SHA-256 fingerprint of the full DER-encoded certificate (for matching).
    fingerprint: Vec<u8>,
}

// ── Nonce cache entry ───────────────────────────────────────────────────────

struct NonceEntry {
    inserted_at: Instant,
}

// ── Plugin struct ───────────────────────────────────────────────────────────

pub struct SoapWsSecurity {
    // Timestamp validation
    require_timestamp: bool,
    timestamp_max_age_seconds: u64,
    timestamp_require_expires: bool,
    clock_skew_seconds: u64,

    // UsernameToken
    username_token_enabled: bool,
    password_type: PasswordType,
    credentials: Vec<Credential>,

    // X.509 signature verification
    x509_enabled: bool,
    trusted_certs: Vec<TrustedCert>,
    allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    require_signed_timestamp: bool,

    // SAML assertion validation
    saml_enabled: bool,
    saml_trusted_issuers: Vec<String>,
    saml_audience: Option<String>,
    saml_clock_skew_seconds: u64,

    // Nonce replay protection
    nonce_cache: Arc<DashMap<String, NonceEntry>>,
    nonce_cache_ttl_seconds: u64,
    max_nonce_cache_size: usize,

    // General
    reject_missing_security_header: bool,
}

impl SoapWsSecurity {
    pub fn new(config: &Value) -> Result<Self, String> {
        // ── Timestamp config ────────────────────────────────────────────
        let ts_cfg = &config["timestamp"];
        let require_timestamp = ts_cfg["require"].as_bool().unwrap_or(true);
        let timestamp_max_age_seconds = ts_cfg["max_age_seconds"].as_u64().unwrap_or(300);
        let timestamp_require_expires = ts_cfg["require_expires"].as_bool().unwrap_or(false);
        let clock_skew_seconds = ts_cfg["clock_skew_seconds"].as_u64().unwrap_or(300);

        // ── UsernameToken config ────────────────────────────────────────
        let ut_cfg = &config["username_token"];
        let username_token_enabled = ut_cfg["enabled"].as_bool().unwrap_or(false);
        let password_type = match ut_cfg["password_type"].as_str().unwrap_or("PasswordDigest") {
            "PasswordText" => PasswordType::PasswordText,
            "PasswordDigest" => PasswordType::PasswordDigest,
            other => {
                return Err(format!(
                    "soap_ws_security: invalid password_type '{}' — must be 'PasswordText' or 'PasswordDigest'",
                    other
                ));
            }
        };

        let credentials: Vec<Credential> = ut_cfg["credentials"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let username = v["username"].as_str()?.to_string();
                        let password = v["password"].as_str()?.to_string();
                        Some(Credential { username, password })
                    })
                    .collect()
            })
            .unwrap_or_default();

        if username_token_enabled && credentials.is_empty() {
            return Err(
                "soap_ws_security: username_token is enabled but no credentials are configured"
                    .to_string(),
            );
        }

        // ── X.509 signature config ──────────────────────────────────────
        let x509_cfg = &config["x509_signature"];
        let x509_enabled = x509_cfg["enabled"].as_bool().unwrap_or(false);

        let trusted_cert_paths: Vec<String> = x509_cfg["trusted_certs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if x509_enabled && trusted_cert_paths.is_empty() {
            return Err(
                "soap_ws_security: x509_signature is enabled but no trusted_certs are configured"
                    .to_string(),
            );
        }

        let mut trusted_certs = Vec::with_capacity(trusted_cert_paths.len());
        for path in &trusted_cert_paths {
            let pem_data = std::fs::read(path).map_err(|e| {
                format!(
                    "soap_ws_security: failed to read trusted cert '{}': {}",
                    path, e
                )
            })?;

            let pem_str = std::str::from_utf8(&pem_data).map_err(|e| {
                format!(
                    "soap_ws_security: trusted cert '{}' is not valid UTF-8: {}",
                    path, e
                )
            })?;

            let der_bytes = extract_pem_der(pem_str)
                .ok_or_else(|| format!("soap_ws_security: failed to decode PEM from '{}'", path))?;

            let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
                format!(
                    "soap_ws_security: failed to parse X.509 cert '{}': {}",
                    path, e
                )
            })?;

            let public_key_der = cert.public_key().raw.to_vec();
            let fingerprint = digest::digest(&digest::SHA256, &der_bytes)
                .as_ref()
                .to_vec();

            trusted_certs.push(TrustedCert {
                public_key_der,
                fingerprint,
            });
        }

        let allowed_signature_algorithms: Vec<SignatureAlgorithm> = x509_cfg["allowed_algorithms"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| match v.as_str()? {
                        "rsa-sha256" => Some(SignatureAlgorithm::RsaSha256),
                        "rsa-sha1" => Some(SignatureAlgorithm::RsaSha1),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec![SignatureAlgorithm::RsaSha256]);

        let require_signed_timestamp = x509_cfg["require_signed_timestamp"]
            .as_bool()
            .unwrap_or(true);

        // ── SAML config ─────────────────────────────────────────────────
        let saml_cfg = &config["saml"];
        let saml_enabled = saml_cfg["enabled"].as_bool().unwrap_or(false);

        let saml_trusted_issuers: Vec<String> = saml_cfg["trusted_issuers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if saml_enabled && saml_trusted_issuers.is_empty() {
            return Err(
                "soap_ws_security: saml is enabled but no trusted_issuers are configured"
                    .to_string(),
            );
        }

        let saml_audience = saml_cfg["audience"].as_str().map(String::from);
        let saml_clock_skew_seconds = saml_cfg["clock_skew_seconds"].as_u64().unwrap_or(300);

        // ── Nonce / replay config ───────────────────────────────────────
        let nonce_cfg = &config["nonce"];
        let nonce_cache_ttl_seconds = nonce_cfg["cache_ttl_seconds"].as_u64().unwrap_or(300);
        let max_nonce_cache_size = nonce_cfg["max_cache_size"].as_u64().unwrap_or(10_000) as usize;

        // ── General ─────────────────────────────────────────────────────
        let reject_missing_security_header = config["reject_missing_security_header"]
            .as_bool()
            .unwrap_or(true);

        // Must have at least one security feature enabled
        if !username_token_enabled && !x509_enabled && !saml_enabled && !require_timestamp {
            return Err(
                "soap_ws_security: no security features enabled — enable at least one of: username_token, x509_signature, saml, or timestamp.require"
                    .to_string(),
            );
        }

        Ok(Self {
            require_timestamp,
            timestamp_max_age_seconds,
            timestamp_require_expires,
            clock_skew_seconds,
            username_token_enabled,
            password_type,
            credentials,
            x509_enabled,
            trusted_certs,
            allowed_signature_algorithms,
            require_signed_timestamp,
            saml_enabled,
            saml_trusted_issuers,
            saml_audience,
            saml_clock_skew_seconds,
            nonce_cache: Arc::new(DashMap::new()),
            nonce_cache_ttl_seconds,
            max_nonce_cache_size,
            reject_missing_security_header,
        })
    }

    // ── Timestamp validation ────────────────────────────────────────────

    fn validate_timestamp(&self, security_block: &str, now: DateTime<Utc>) -> Result<(), String> {
        let ts_block = match find_element_block(security_block, "Timestamp") {
            Some(b) => b,
            None => {
                return if self.require_timestamp {
                    Err("WS-Security: missing Timestamp element".to_string())
                } else {
                    Ok(())
                };
            }
        };

        let created_str = find_element_text(&ts_block, "Created")
            .ok_or_else(|| "WS-Security: Timestamp missing Created element".to_string())?;

        let created = parse_ws_datetime(&created_str)
            .ok_or_else(|| format!("WS-Security: invalid Created timestamp '{}'", created_str))?;

        let skew = chrono::Duration::seconds(self.clock_skew_seconds as i64);
        let max_age = chrono::Duration::seconds(self.timestamp_max_age_seconds as i64);

        // Created must not be in the future (with clock skew tolerance)
        if created > now + skew {
            return Err("WS-Security: Timestamp Created is in the future".to_string());
        }

        // Created must not be too old
        if now - created > max_age + skew {
            return Err(format!(
                "WS-Security: Timestamp Created is too old (max age {}s)",
                self.timestamp_max_age_seconds
            ));
        }

        // Expires check
        if let Some(expires_str) = find_element_text(&ts_block, "Expires") {
            let expires = parse_ws_datetime(&expires_str).ok_or_else(|| {
                format!("WS-Security: invalid Expires timestamp '{}'", expires_str)
            })?;

            if now > expires + skew {
                return Err("WS-Security: Timestamp has expired".to_string());
            }
        } else if self.timestamp_require_expires {
            return Err("WS-Security: Timestamp missing required Expires element".to_string());
        }

        Ok(())
    }

    // ── UsernameToken validation ────────────────────────────────────────

    fn validate_username_token(&self, security_block: &str) -> Result<String, String> {
        let ut_block = find_element_block(security_block, "UsernameToken")
            .ok_or_else(|| "WS-Security: missing UsernameToken element".to_string())?;

        let username = find_element_text(&ut_block, "Username")
            .ok_or_else(|| "WS-Security: UsernameToken missing Username element".to_string())?;

        let password_element = find_element_block(&ut_block, "Password")
            .ok_or_else(|| "WS-Security: UsernameToken missing Password element".to_string())?;

        let password_value = extract_element_text_content(&password_element, "Password")
            .ok_or_else(|| "WS-Security: Password element has no content".to_string())?;

        // Determine password type from the Type attribute, falling back to config
        let effective_type = if let Some(type_attr) = find_attribute(&password_element, "Type") {
            if type_attr.contains("PasswordDigest") || type_attr == PASSWORD_DIGEST_TYPE {
                PasswordType::PasswordDigest
            } else if type_attr.contains("PasswordText") || type_attr == PASSWORD_TEXT_TYPE {
                PasswordType::PasswordText
            } else {
                self.password_type
            }
        } else {
            self.password_type
        };

        // Find the matching credential
        let cred = self
            .credentials
            .iter()
            .find(|c| c.username == username)
            .ok_or_else(|| {
                format!(
                    "WS-Security: unknown username '{}'",
                    escape_xml_chars(&username)
                )
            })?;

        match effective_type {
            PasswordType::PasswordText => {
                if password_value != cred.password {
                    return Err("WS-Security: invalid password".to_string());
                }
            }
            PasswordType::PasswordDigest => {
                // PasswordDigest = Base64(SHA-1(nonce + created + password))
                let nonce_b64 = find_element_text(&ut_block, "Nonce").ok_or_else(|| {
                    "WS-Security: PasswordDigest requires Nonce element".to_string()
                })?;

                let nonce_bytes = BASE64
                    .decode(nonce_b64.trim())
                    .map_err(|e| format!("WS-Security: invalid Nonce base64 encoding: {}", e))?;

                let created = find_element_text(&ut_block, "Created").ok_or_else(|| {
                    "WS-Security: PasswordDigest requires Created element".to_string()
                })?;

                // Check nonce replay
                self.check_nonce_replay(&nonce_b64)?;

                // Compute expected digest: SHA-1(nonce + created + password)
                let mut data =
                    Vec::with_capacity(nonce_bytes.len() + created.len() + cred.password.len());
                data.extend_from_slice(&nonce_bytes);
                data.extend_from_slice(created.as_bytes());
                data.extend_from_slice(cred.password.as_bytes());

                let computed = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
                let expected_b64 = BASE64.encode(computed.as_ref());

                if password_value.trim() != expected_b64 {
                    return Err("WS-Security: PasswordDigest verification failed".to_string());
                }
            }
        }

        Ok(username)
    }

    // ── Nonce replay protection ─────────────────────────────────────────

    fn check_nonce_replay(&self, nonce: &str) -> Result<(), String> {
        // Evict expired entries if cache is at capacity
        if self.nonce_cache.len() >= self.max_nonce_cache_size {
            self.evict_expired_nonces();
        }

        // Hard cap: if still at capacity after evicting expired entries,
        // evict oldest entries to prevent unbounded memory growth under
        // floods of unique fresh nonces.
        if self.nonce_cache.len() >= self.max_nonce_cache_size {
            self.evict_oldest_nonces();
        }

        let now = Instant::now();

        // Check if nonce was already seen
        if let Some(entry) = self.nonce_cache.get(nonce) {
            let age = now.duration_since(entry.inserted_at);
            if age.as_secs() < self.nonce_cache_ttl_seconds {
                return Err("WS-Security: nonce replay detected".to_string());
            }
        }

        // Record the nonce
        self.nonce_cache
            .insert(nonce.to_string(), NonceEntry { inserted_at: now });

        Ok(())
    }

    fn evict_expired_nonces(&self) {
        let now = Instant::now();
        let ttl_secs = self.nonce_cache_ttl_seconds;
        self.nonce_cache
            .retain(|_, entry| now.duration_since(entry.inserted_at).as_secs() < ttl_secs);
    }

    /// Evict oldest entries when the cache is full and no expired entries remain.
    /// Removes 10% of entries (by insertion time) to amortize the eviction cost.
    fn evict_oldest_nonces(&self) {
        let to_remove = (self.max_nonce_cache_size / 10).max(1);
        let mut entries: Vec<(String, Instant)> = self
            .nonce_cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().inserted_at))
            .collect();
        entries.sort_by_key(|(_, inserted_at)| *inserted_at);
        for (key, _) in entries.into_iter().take(to_remove) {
            self.nonce_cache.remove(&key);
        }
    }

    // ── X.509 signature verification ────────────────────────────────────

    fn validate_x509_signature(&self, security_block: &str, soap_body: &str) -> Result<(), String> {
        // Extract the Signature element
        let sig_block = find_element_block(security_block, "Signature")
            .ok_or_else(|| "WS-Security: missing Signature element".to_string())?;

        // Extract SignedInfo (the data that was signed)
        let signed_info = find_element_block(&sig_block, "SignedInfo")
            .ok_or_else(|| "WS-Security: Signature missing SignedInfo element".to_string())?;

        // Determine signature algorithm
        let sig_method_block = find_element_block(&signed_info, "SignatureMethod")
            .ok_or_else(|| "WS-Security: SignedInfo missing SignatureMethod".to_string())?;
        let sig_algorithm_uri =
            find_attribute(&sig_method_block, "Algorithm").ok_or_else(|| {
                "WS-Security: SignatureMethod missing Algorithm attribute".to_string()
            })?;

        let sig_algorithm = match sig_algorithm_uri.as_str() {
            XMLDSIG_RSA_SHA256 => SignatureAlgorithm::RsaSha256,
            XMLDSIG_RSA_SHA1 => SignatureAlgorithm::RsaSha1,
            other => {
                return Err(format!(
                    "WS-Security: unsupported signature algorithm '{}'",
                    other
                ));
            }
        };

        if !self.allowed_signature_algorithms.contains(&sig_algorithm) {
            return Err(format!(
                "WS-Security: signature algorithm '{}' is not allowed",
                sig_algorithm_uri
            ));
        }

        // Verify Reference digests
        self.verify_reference_digests(&signed_info, security_block, soap_body)?;

        // Check that Timestamp is signed (if required)
        if self.require_signed_timestamp {
            self.verify_timestamp_is_signed(&signed_info, security_block)?;
        }

        // Extract SignatureValue
        let sig_value_b64 = find_element_text(&sig_block, "SignatureValue")
            .ok_or_else(|| "WS-Security: Signature missing SignatureValue".to_string())?;

        let sig_bytes = BASE64
            .decode(sig_value_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: invalid SignatureValue base64: {}", e))?;

        // Extract the certificate (BinarySecurityToken or inline KeyInfo)
        let cert_der = self.extract_signing_cert(security_block, &sig_block)?;

        // Verify the cert is trusted
        let cert_fingerprint = digest::digest(&digest::SHA256, &cert_der).as_ref().to_vec();

        let trusted = self
            .trusted_certs
            .iter()
            .find(|tc| tc.fingerprint == cert_fingerprint);

        let public_key_der = match trusted {
            Some(tc) => &tc.public_key_der,
            None => {
                return Err("WS-Security: signing certificate is not trusted".to_string());
            }
        };

        // Verify the signature over SignedInfo
        let signed_info_bytes = signed_info.as_bytes();

        let verify_algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_algorithm {
            SignatureAlgorithm::RsaSha256 => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaSha1 => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        let public_key = ring_sig::UnparsedPublicKey::new(verify_algorithm, public_key_der);

        public_key
            .verify(signed_info_bytes, &sig_bytes)
            .map_err(|_| "WS-Security: signature verification failed".to_string())?;

        debug!("soap_ws_security: X.509 signature verified successfully");
        Ok(())
    }

    fn verify_reference_digests(
        &self,
        signed_info: &str,
        security_block: &str,
        soap_body: &str,
    ) -> Result<(), String> {
        // Find all Reference elements in SignedInfo
        let mut search_from = 0;
        while let Some(ref_block) = find_element_block_from(signed_info, "Reference", search_from) {
            search_from += ref_block.len().min(1);

            let uri = find_attribute(&ref_block, "URI").unwrap_or_default();

            // Determine the digest algorithm
            let digest_method = find_element_block(&ref_block, "DigestMethod")
                .ok_or_else(|| "WS-Security: Reference missing DigestMethod".to_string())?;
            let digest_alg_uri = find_attribute(&digest_method, "Algorithm")
                .ok_or_else(|| "WS-Security: DigestMethod missing Algorithm".to_string())?;

            // Extract expected digest
            let expected_b64 = find_element_text(&ref_block, "DigestValue")
                .ok_or_else(|| "WS-Security: Reference missing DigestValue".to_string())?;

            let expected_bytes = BASE64
                .decode(expected_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid DigestValue base64: {}", e))?;

            // Find the referenced element
            let referenced_content = if uri.is_empty() {
                // Entire document
                soap_body.to_string()
            } else if let Some(ref_id) = uri.strip_prefix('#') {
                find_element_by_wsu_id(security_block, ref_id)
                    .or_else(|| find_element_by_wsu_id(soap_body, ref_id))
                    .ok_or_else(|| {
                        format!("WS-Security: referenced element '{}' not found", ref_id)
                    })?
            } else {
                return Err(format!("WS-Security: unsupported Reference URI '{}'", uri));
            };

            // Compute and compare digest
            let computed = match digest_alg_uri.as_str() {
                XMLDSIG_SHA256 => digest::digest(&digest::SHA256, referenced_content.as_bytes()),
                XMLDSIG_SHA1 => digest::digest(
                    &digest::SHA1_FOR_LEGACY_USE_ONLY,
                    referenced_content.as_bytes(),
                ),
                other => {
                    return Err(format!(
                        "WS-Security: unsupported digest algorithm '{}'",
                        other
                    ));
                }
            };

            if computed.as_ref() != expected_bytes.as_slice() {
                return Err(format!(
                    "WS-Security: digest mismatch for Reference URI '{}'",
                    uri
                ));
            }
        }

        Ok(())
    }

    fn verify_timestamp_is_signed(
        &self,
        signed_info: &str,
        security_block: &str,
    ) -> Result<(), String> {
        // Find the wsu:Id of the Timestamp element
        let ts_block = match find_element_block(security_block, "Timestamp") {
            Some(b) => b,
            None => return Ok(()), // No timestamp to sign — timestamp validation handles this
        };

        let ts_id = match find_wsu_id(&ts_block) {
            Some(id) => id,
            None => {
                return Err(
                    "WS-Security: Timestamp has no wsu:Id — cannot verify it is signed".to_string(),
                );
            }
        };

        // Check that there's a Reference pointing to this Timestamp
        let ref_uri = format!("#{}", ts_id);
        if !signed_info.contains(&ref_uri) {
            return Err("WS-Security: Timestamp is not included in the signature".to_string());
        }

        Ok(())
    }

    fn extract_signing_cert(
        &self,
        security_block: &str,
        sig_block: &str,
    ) -> Result<Vec<u8>, String> {
        // Try BinarySecurityToken first
        if let Some(bst) = find_element_block(security_block, "BinarySecurityToken") {
            let cert_b64 = extract_element_text_content(&bst, "BinarySecurityToken")
                .ok_or_else(|| "WS-Security: BinarySecurityToken has no content".to_string())?;

            return BASE64
                .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid BinarySecurityToken base64: {}", e));
        }

        // Try inline X509Certificate in KeyInfo
        if let Some(key_info) = find_element_block(sig_block, "KeyInfo")
            && let Some(cert_b64) = find_element_text(&key_info, "X509Certificate")
        {
            return BASE64
                .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid X509Certificate base64: {}", e));
        }

        Err("WS-Security: no signing certificate found (expected BinarySecurityToken or X509Certificate in KeyInfo)".to_string())
    }

    // ── SAML assertion validation ───────────────────────────────────────

    fn validate_saml_assertion(
        &self,
        security_block: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let assertion = match find_element_block(security_block, "Assertion") {
            Some(a) => a,
            None => {
                return if self.saml_enabled {
                    Err("WS-Security: missing SAML Assertion element".to_string())
                } else {
                    Ok(())
                };
            }
        };

        // Validate Issuer
        let issuer = find_element_text(&assertion, "Issuer")
            .ok_or_else(|| "WS-Security: SAML Assertion missing Issuer element".to_string())?;

        if !self.saml_trusted_issuers.iter().any(|ti| ti == &issuer) {
            return Err(format!(
                "WS-Security: SAML Issuer '{}' is not trusted",
                escape_xml_chars(&issuer)
            ));
        }

        // Validate Conditions (NotBefore / NotOnOrAfter)
        if let Some(conditions) = find_element_block(&assertion, "Conditions") {
            let skew = chrono::Duration::seconds(self.saml_clock_skew_seconds as i64);

            if let Some(not_before_str) = find_attribute(&conditions, "NotBefore") {
                let not_before = parse_ws_datetime(&not_before_str).ok_or_else(|| {
                    format!("WS-Security: invalid SAML NotBefore '{}'", not_before_str)
                })?;
                if now + skew < not_before {
                    return Err("WS-Security: SAML Assertion is not yet valid".to_string());
                }
            }

            if let Some(not_on_or_after_str) = find_attribute(&conditions, "NotOnOrAfter") {
                let not_on_or_after = parse_ws_datetime(&not_on_or_after_str).ok_or_else(|| {
                    format!(
                        "WS-Security: invalid SAML NotOnOrAfter '{}'",
                        not_on_or_after_str
                    )
                })?;
                if now > not_on_or_after + skew {
                    return Err("WS-Security: SAML Assertion has expired".to_string());
                }
            }

            // Audience restriction
            if let Some(ref expected_audience) = self.saml_audience
                && let Some(audience_restriction) =
                    find_element_block(&conditions, "AudienceRestriction")
            {
                let audience =
                    find_element_text(&audience_restriction, "Audience").ok_or_else(|| {
                        "WS-Security: AudienceRestriction missing Audience element".to_string()
                    })?;

                if &audience != expected_audience {
                    return Err(format!(
                        "WS-Security: SAML Audience '{}' does not match expected '{}'",
                        escape_xml_chars(&audience),
                        expected_audience
                    ));
                }
            }
        }

        debug!("soap_ws_security: SAML assertion validated successfully");
        Ok(())
    }

    // ── Content-type check ──────────────────────────────────────────────

    fn is_soap_content_type(content_type: &str) -> bool {
        let ct = content_type.to_lowercase();
        ct.contains("text/xml")
            || ct.contains("application/soap+xml")
            || ct.contains("application/xml")
    }
}

// ── Plugin trait implementation ─────────────────────────────────────────────

#[async_trait]
impl Plugin for SoapWsSecurity {
    fn name(&self) -> &str {
        "soap_ws_security"
    }

    fn priority(&self) -> u16 {
        super::priority::SOAP_WS_SECURITY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.headers
            .get("content-type")
            .is_some_and(|ct| Self::is_soap_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only process SOAP content types
        // Read from `headers` param (not `ctx.headers`) because the handler may
        // temporarily move headers out of ctx when no plugin modifies them.
        let content_type = match headers.get("content-type") {
            Some(ct) if Self::is_soap_content_type(ct) => ct.clone(),
            _ => return PluginResult::Continue,
        };

        // Get the buffered request body
        let body = match ctx.metadata.get("request_body") {
            Some(b) => b.clone(),
            None => {
                if self.reject_missing_security_header {
                    return PluginResult::Reject {
                        status_code: 400,
                        body: r#"{"error":"SOAP request body is empty"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                return PluginResult::Continue;
            }
        };

        // Find the SOAP envelope
        let envelope = body.trim();
        if !envelope.contains("Envelope") {
            if self.reject_missing_security_header {
                return PluginResult::Reject {
                    status_code: 400,
                    body: r#"{"error":"Request is not a SOAP envelope"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
            return PluginResult::Continue;
        }

        // Extract the SOAP Header and Body
        let soap_header = find_element_block(envelope, "Header");
        let soap_body = find_element_block(envelope, "Body").unwrap_or_default();

        // Find the WS-Security header
        let security_block = soap_header
            .as_deref()
            .and_then(|h| find_element_block(h, "Security"));

        let security_block = match security_block {
            Some(s) => s,
            None => {
                if self.reject_missing_security_header {
                    return PluginResult::Reject {
                        status_code: 401,
                        body: r#"{"error":"WS-Security header is missing"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                return PluginResult::Continue;
            }
        };

        let now = Utc::now();

        // Validate Timestamp
        if self.require_timestamp
            && let Err(e) = self.validate_timestamp(&security_block, now)
        {
            warn!("soap_ws_security: timestamp validation failed: {}", e);
            return PluginResult::Reject {
                status_code: 401,
                body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                headers: HashMap::new(),
            };
        }

        // Validate UsernameToken
        if self.username_token_enabled {
            match self.validate_username_token(&security_block) {
                Ok(username) => {
                    ctx.metadata
                        .insert("soap_ws_username".to_string(), username);
                    debug!(
                        content_type = %content_type,
                        "soap_ws_security: UsernameToken validated"
                    );
                }
                Err(e) => {
                    warn!("soap_ws_security: UsernameToken validation failed: {}", e);
                    return PluginResult::Reject {
                        status_code: 401,
                        body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        // Validate X.509 signature
        if self.x509_enabled
            && let Err(e) = self.validate_x509_signature(&security_block, &soap_body)
        {
            warn!("soap_ws_security: X.509 signature validation failed: {}", e);
            return PluginResult::Reject {
                status_code: 401,
                body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                headers: HashMap::new(),
            };
        }

        // Validate SAML assertion
        if self.saml_enabled
            && let Err(e) = self.validate_saml_assertion(&security_block, now)
        {
            warn!("soap_ws_security: SAML validation failed: {}", e);
            return PluginResult::Reject {
                status_code: 401,
                body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }
}

// ── XML extraction helpers ──────────────────────────────────────────────────
//
// These helpers find elements by local name (ignoring namespace prefixes) to
// support various SOAP toolkit prefix conventions (wsse:, WSSE:, soap:, etc.).

/// Find an element block by local name, starting from position 0.
/// Returns the full element including its content and closing tag.
fn find_element_block(xml: &str, local_name: &str) -> Option<String> {
    find_element_block_from(xml, local_name, 0)
}

/// Find an element block by local name, starting from a given byte offset.
fn find_element_block_from(xml: &str, local_name: &str, start: usize) -> Option<String> {
    let search = &xml[start..];

    // Match <prefix:localName or <localName
    let open_pos = find_tag_start(search, local_name)?;

    let tag_start = open_pos;
    let after_open = &search[tag_start..];

    // Find the actual tag name (with optional prefix)
    let full_tag_name = extract_full_tag_name(after_open)?;

    // Check for self-closing tag
    let tag_header_end = after_open.find('>')?;
    if after_open.as_bytes().get(tag_header_end.checked_sub(1)?) == Some(&b'/') {
        return Some(after_open[..=tag_header_end].to_string());
    }

    // Find matching closing tag </prefix:localName> or </localName>
    let closing = format!("</{}>", full_tag_name);
    let close_pos = search[tag_start..].find(&closing)?;
    let end = tag_start + close_pos + closing.len();

    Some(search[tag_start..end].to_string())
}

/// Find the text content of a direct child element by local name.
fn find_element_text(xml: &str, local_name: &str) -> Option<String> {
    let block = find_element_block(xml, local_name)?;
    extract_element_text_content(&block, local_name)
}

/// Extract text content between the opening and closing tags of an element.
fn extract_element_text_content(element: &str, local_name: &str) -> Option<String> {
    // Find end of opening tag
    let content_start = element.find('>')? + 1;

    // Find start of closing tag (search for </...localName>)
    let close_idx = find_closing_tag_pos(element, local_name)?;

    let content = &element[content_start..close_idx];
    Some(content.trim().to_string())
}

/// Find the position of a closing tag for the given local name.
fn find_closing_tag_pos(element: &str, local_name: &str) -> Option<usize> {
    let bytes = element.as_bytes();
    let name_bytes = local_name.as_bytes();
    let len = bytes.len();
    let name_len = name_bytes.len();

    let mut i = 0;
    while i + 2 + name_len < len {
        if bytes[i] == b'<' && bytes[i + 1] == b'/' {
            // Check for </localName> or </prefix:localName>
            let after_slash = &bytes[i + 2..];
            // Direct match: </localName
            if after_slash.starts_with(name_bytes) {
                let next = after_slash.get(name_len)?;
                if *next == b'>' {
                    return Some(i);
                }
            }
            // Prefixed match: </prefix:localName
            if let Some(colon_pos) = after_slash.iter().position(|&b| b == b':')
                && colon_pos + 1 + name_len <= after_slash.len()
            {
                let after_colon = &after_slash[colon_pos + 1..];
                if after_colon.starts_with(name_bytes) && after_colon.get(name_len) == Some(&b'>') {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Find the starting position of a tag with the given local name.
/// Matches both `<localName` and `<prefix:localName` patterns.
fn find_tag_start(xml: &str, local_name: &str) -> Option<usize> {
    let bytes = xml.as_bytes();
    let name_bytes = local_name.as_bytes();
    let len = bytes.len();
    let name_len = name_bytes.len();

    let mut i = 0;
    while i + 1 + name_len <= len {
        if bytes[i] == b'<' && !matches!(bytes[i + 1], b'/' | b'!' | b'?') {
            let after_lt = &bytes[i + 1..];

            // Direct match: <localName followed by space, >, or /
            if after_lt.starts_with(name_bytes)
                && let Some(&next) = after_lt.get(name_len)
                && matches!(next, b' ' | b'>' | b'/' | b'\t' | b'\n')
            {
                return Some(i);
            }

            // Prefixed match: <prefix:localName
            if let Some(colon_offset) = after_lt.iter().take(64).position(|&b| b == b':') {
                let prefix_part = &after_lt[..colon_offset];
                if prefix_part
                    .iter()
                    .all(|&b| !matches!(b, b' ' | b'>' | b'/'))
                {
                    let after_colon = &after_lt[colon_offset + 1..];
                    if after_colon.starts_with(name_bytes)
                        && let Some(&next) = after_colon.get(name_len)
                        && matches!(next, b' ' | b'>' | b'/' | b'\t' | b'\n')
                    {
                        return Some(i);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Extract the full tag name (including prefix) from a tag start: `<prefix:Name ...>`.
fn extract_full_tag_name(from_tag_start: &str) -> Option<String> {
    let after_lt = &from_tag_start[1..]; // skip '<'
    let end = after_lt.find([' ', '>', '/', '\t', '\n'])?;
    Some(after_lt[..end].to_string())
}

/// Find an attribute value in an element's opening tag.
fn find_attribute(element: &str, attr_name: &str) -> Option<String> {
    // Find the opening tag (up to the first >)
    let tag_end = element.find('>')?;
    let tag = &element[..tag_end];

    // Search for attr_name="value" or attr_name='value'
    // Also handle namespaced attributes like wsu:Id
    let patterns = [format!("{}=\"", attr_name), format!("{}='", attr_name)];

    for pattern in &patterns {
        if let Some(pos) = tag.find(pattern.as_str()) {
            let value_start = pos + pattern.len();
            let quote = tag.as_bytes()[value_start - 1]; // " or '
            let remaining = &tag[value_start..];
            if let Some(value_end) = remaining.find(quote as char) {
                return Some(remaining[..value_end].to_string());
            }
        }
    }

    None
}

/// Find an element by its wsu:Id attribute value.
fn find_element_by_wsu_id(xml: &str, id: &str) -> Option<String> {
    // Search for wsu:Id="id" or Id="id"
    let patterns = [
        format!("wsu:Id=\"{}\"", id),
        format!("Id=\"{}\"", id),
        format!("wsu:Id='{}'", id),
        format!("Id='{}'", id),
    ];

    for pattern in &patterns {
        if let Some(pos) = xml.find(pattern.as_str()) {
            // Walk backwards to find the '<' that starts this element
            let before = &xml[..pos];
            let tag_start = before.rfind('<')?;

            // Extract the full tag name
            let from_tag = &xml[tag_start..];
            let full_tag_name = extract_full_tag_name(from_tag)?;

            // Get the local name for finding the closing tag
            let local_name = if let Some(colon_pos) = full_tag_name.find(':') {
                &full_tag_name[colon_pos + 1..]
            } else {
                &full_tag_name
            };

            // Find the closing tag
            let closing = format!("</{}>", full_tag_name);
            if let Some(close_pos) = xml[tag_start..].find(&closing) {
                let end = tag_start + close_pos + closing.len();
                return Some(xml[tag_start..end].to_string());
            }

            // Try without prefix in closing tag
            let closing_no_prefix = format!("</{}>", local_name);
            if let Some(close_pos) = xml[tag_start..].find(&closing_no_prefix) {
                let end = tag_start + close_pos + closing_no_prefix.len();
                return Some(xml[tag_start..end].to_string());
            }
        }
    }

    None
}

/// Extract the wsu:Id (or plain Id) attribute from an element.
fn find_wsu_id(element: &str) -> Option<String> {
    find_attribute(element, "wsu:Id").or_else(|| find_attribute(element, "Id"))
}

/// Decode PEM to DER bytes (handles the common CERTIFICATE block).
fn extract_pem_der(pem: &str) -> Option<Vec<u8>> {
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem.find(start_marker)? + start_marker.len();
    let end = pem.find(end_marker)?;

    let b64 = pem[start..end].replace(char::is_whitespace, "");
    BASE64.decode(b64.as_bytes()).ok()
}

/// Parse WS-Security datetime formats (ISO 8601 variants).
fn parse_ws_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();

    // Try standard RFC 3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try common WS-Security formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%:z",
    ];

    for fmt in &formats {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }

    // Try without timezone (assume UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }

    None
}

/// Escape special characters for JSON string interpolation.
fn escape_json_chars(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Escape XML special characters for safe interpolation.
fn escape_xml_chars(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nonce_only_plugin(max_size: usize) -> SoapWsSecurity {
        SoapWsSecurity {
            require_timestamp: false,
            timestamp_max_age_seconds: 300,
            timestamp_require_expires: false,
            clock_skew_seconds: 300,
            username_token_enabled: false,
            password_type: PasswordType::PasswordText,
            credentials: Vec::new(),
            x509_enabled: false,
            trusted_certs: Vec::new(),
            allowed_signature_algorithms: Vec::new(),
            require_signed_timestamp: false,
            saml_enabled: false,
            saml_trusted_issuers: Vec::new(),
            saml_audience: None,
            saml_clock_skew_seconds: 300,
            nonce_cache: Arc::new(DashMap::new()),
            nonce_cache_ttl_seconds: 300,
            max_nonce_cache_size: max_size,
            reject_missing_security_header: false,
        }
    }

    #[test]
    fn test_nonce_cache_enforces_max_size() {
        let max = 20;
        let plugin = make_nonce_only_plugin(max);

        // Fill past max with unique nonces
        for i in 0..(max + 50) {
            let nonce = format!("nonce-{}", i);
            let _ = plugin.check_nonce_replay(&nonce);
        }

        // After each insert the cap is enforced, so the cache should never
        // exceed max_size + 1 (the newly inserted entry).
        assert!(
            plugin.nonce_cache.len() <= max + 1,
            "nonce cache size {} exceeds cap {}",
            plugin.nonce_cache.len(),
            max + 1
        );
    }

    #[test]
    fn test_nonce_replay_still_detected_after_eviction() {
        let plugin = make_nonce_only_plugin(100);

        // Insert a nonce
        assert!(plugin.check_nonce_replay("unique-nonce").is_ok());

        // Same nonce should be rejected (replay)
        assert!(plugin.check_nonce_replay("unique-nonce").is_err());
    }
}
