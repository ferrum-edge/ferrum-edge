//! SOAP WS-Security Plugin
//!
//! Validates WS-Security headers in SOAP envelopes at the proxy layer.
//! Supports UsernameToken authentication (PasswordText and PasswordDigest),
//! X.509 certificate signature verification, SAML assertion validation
//! (XMLDSIG signature verification against trusted IdP signing certificates
//! plus issuer / NotBefore / NotOnOrAfter / Audience checks and an enveloped-
//! signature transform over the assertion), timestamp freshness checks, and
//! nonce replay protection.
//!
//! Runs in `before_proxy` with request body buffering. Priority 1500 places
//! it in the AuthN band after HMAC auth.
//!
//! ## XMLDSIG limitation (shared by X.509 and SAML signature paths)
//!
//! Both the WS-Security X.509 signature path and the SAML assertion signature
//! path verify `<SignatureValue>` against the **wire bytes** of `<SignedInfo>`
//! (and digest each Reference against the wire bytes of the referenced
//! element, with the SAML enveloped-signature transform applied for the
//! assertion). They do NOT yet apply Exclusive XML Canonicalization
//! (`xml-exc-c14n#`) before hashing. Signers that canonicalize before signing
//! AND whose canonical output happens to match the wire bytes will verify
//! cleanly; signers whose intermediates re-serialize, reorder attributes, or
//! re-emit namespace declarations may fail verification. Operators
//! integrating with IdPs that mandate strict c14n should validate end-to-end
//! before depending on these paths.
//!
//! ## XML Signature Wrapping (XSW) mitigation
//!
//! Because verification is substring-based rather than DOM + exclusive-c14n,
//! the X.509 path enforces that every signed `#id` Reference resolves to a
//! UNIQUE XML id-bearing attribute across the whole envelope (see
//! `count_wsu_id_occurrences`), rejecting any envelope carrying a duplicate id —
//! the classic XSW vector where an attacker keeps the legitimately-signed
//! element and injects a second element with the same id that the backend
//! consumes. The duplicate scan includes WS-Security `wsu:Id` / prefixed `Id`,
//! bare `Id`, and common alternative spellings (`xml:id`, `ID`, `id`) so
//! backends with broader fragment-id rules fail closed instead of seeing a
//! forwarded alternate referent. The SAML path retains its single-`<Assertion>`
//! guard plus the Reference-URI-equals-assertion-id check. A residual risk
//! remains for a backend that selects a *different* same-local-name element than
//! the gateway digested; reducing the forwarded body to only the signed subtree
//! (or full DOM + exclusive-c14n) is the long-term fix.

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

use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::utils::auth_flow::constant_time_eq;
use super::{Plugin, PluginResult, RequestContext};

// ── Namespace URIs ──────────────────────────────────────────────────────────

const PASSWORD_DIGEST_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const PASSWORD_TEXT_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const XMLDSIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const XMLDSIG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const XMLDSIG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLDSIG_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const WSU_NAMESPACE_URI: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/// Upper bound on the number of `<Reference>` elements processed in a single
/// `<SignedInfo>`. Each reference drives a full-envelope scan + digest before
/// the signature is checked, so this caps attacker-controlled CPU on the
/// unauthenticated request path. Real signatures reference a handful of
/// elements; 64 is far above any legitimate use.
const MAX_SIGNED_REFERENCES: usize = 64;

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

/// XMLDSIG digest algorithm used for `<Reference>` element hashing.
///
/// Tracked separately from `SignatureAlgorithm` so the config surface can
/// gate signature vs digest algorithms independently — overloading a single
/// "algorithms" knob to mean both signature method and reference digest is
/// confusing for operators and produces footguns (e.g. accepting SHA-1
/// digests just because rsa-sha1 is in the allow list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha256,
    Sha1,
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
    allowed_digest_algorithms: Vec<DigestAlgorithm>,
    require_signed_timestamp: bool,

    // SAML assertion validation
    saml_enabled: bool,
    saml_trusted_issuers: Vec<String>,
    saml_audience: Option<String>,
    saml_clock_skew_seconds: u64,
    saml_trusted_signing_certs: Vec<TrustedCert>,
    saml_allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    saml_allowed_digest_algorithms: Vec<DigestAlgorithm>,

    // Nonce replay protection
    nonce_cache: Arc<DashMap<String, NonceEntry>>,
    nonce_cache_ttl_seconds: u64,
    max_nonce_cache_size: usize,

    // General
    reject_missing_security_header: bool,
}

impl SoapWsSecurity {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("soap_ws_security: config must be an object, got: {config}"))?;

        // ── Timestamp config ────────────────────────────────────────────
        let ts_cfg = config_obj.get("timestamp").unwrap_or(&Value::Null);
        let require_timestamp = ts_cfg["require"].as_bool().unwrap_or(true);
        let timestamp_max_age_seconds = ts_cfg["max_age_seconds"].as_u64().unwrap_or(300);
        let timestamp_require_expires = ts_cfg["require_expires"].as_bool().unwrap_or(false);
        let clock_skew_seconds = ts_cfg["clock_skew_seconds"].as_u64().unwrap_or(300);

        // ── UsernameToken config ────────────────────────────────────────
        let ut_cfg = config_obj.get("username_token").unwrap_or(&Value::Null);
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
        let x509_cfg = config_obj.get("x509_signature").unwrap_or(&Value::Null);
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
            let source = CertSource::parse(path, MaterialKind::Cert);
            let material = load_material_blocking(&source, MaterialKind::Cert)
                .map_err(|e| format!("soap_ws_security: failed to load trusted cert: {e}"))?;

            let pem_str = std::str::from_utf8(material.bytes.expose_secret()).map_err(|e| {
                format!(
                    "soap_ws_security: trusted cert '{}' is not valid UTF-8: {}",
                    material.source_id, e
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

            let public_key_der = load_rsa_public_key_from_cert(&cert)
                .map_err(|e| format!("soap_ws_security: trusted cert '{}' {}", path, e))?;

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

        if x509_enabled && allowed_signature_algorithms.is_empty() {
            return Err(
                "soap_ws_security: x509_signature.allowed_algorithms must contain at least one of \
                 'rsa-sha256' or 'rsa-sha1' when x509_signature is enabled"
                    .to_string(),
            );
        }

        let allowed_digest_algorithms: Vec<DigestAlgorithm> = x509_cfg["allowed_digest_algorithms"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| match v.as_str()? {
                        "sha256" => Some(DigestAlgorithm::Sha256),
                        "sha1" => Some(DigestAlgorithm::Sha1),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec![DigestAlgorithm::Sha256]);

        if x509_enabled && allowed_digest_algorithms.is_empty() {
            return Err(
                "soap_ws_security: x509_signature.allowed_digest_algorithms must contain at least \
                 one of 'sha256' or 'sha1' when x509_signature is enabled"
                    .to_string(),
            );
        }

        let require_signed_timestamp = x509_cfg["require_signed_timestamp"]
            .as_bool()
            .unwrap_or(true);

        // ── SAML config ─────────────────────────────────────────────────
        let saml_cfg = config_obj.get("saml").unwrap_or(&Value::Null);
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

        // SAML trusted signing certs — IdP X.509 certs used to verify the
        // assertion's `<Signature>`. Matched by SHA-256 fingerprint of the
        // full DER, so operators must trust each leaf cert directly (no CA
        // chain validation). This is the standard practice for SAML where
        // IdPs publish their signing certs in metadata.
        let saml_trusted_signing_cert_paths: Vec<String> = saml_cfg["trusted_signing_certs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if saml_enabled && saml_trusted_signing_cert_paths.is_empty() {
            return Err(
                "soap_ws_security: saml is enabled but no trusted_signing_certs are configured — \
                 without trusted IdP signing certs, assertion signatures cannot be verified and \
                 any caller could forge an assertion claiming to be issued by a trusted issuer"
                    .to_string(),
            );
        }

        let mut saml_trusted_signing_certs =
            Vec::with_capacity(saml_trusted_signing_cert_paths.len());
        for path in &saml_trusted_signing_cert_paths {
            let source = CertSource::parse(path, MaterialKind::Cert);
            let material = load_material_blocking(&source, MaterialKind::Cert).map_err(|e| {
                format!("soap_ws_security: failed to load SAML trusted signing cert: {e}")
            })?;

            let pem_str = std::str::from_utf8(material.bytes.expose_secret()).map_err(|e| {
                format!(
                    "soap_ws_security: SAML trusted signing cert '{}' is not valid UTF-8: {}",
                    material.source_id, e
                )
            })?;

            let der_bytes = extract_pem_der(pem_str).ok_or_else(|| {
                format!(
                    "soap_ws_security: failed to decode PEM from SAML trusted signing cert '{}'",
                    path
                )
            })?;

            let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
                format!(
                    "soap_ws_security: failed to parse SAML trusted signing cert '{}': {}",
                    path, e
                )
            })?;

            let public_key_der = load_rsa_public_key_from_cert(&cert).map_err(|e| {
                format!(
                    "soap_ws_security: SAML trusted signing cert '{}' {}",
                    path, e
                )
            })?;
            let fingerprint = digest::digest(&digest::SHA256, &der_bytes)
                .as_ref()
                .to_vec();

            saml_trusted_signing_certs.push(TrustedCert {
                public_key_der,
                fingerprint,
            });
        }

        let saml_allowed_signature_algorithms: Vec<SignatureAlgorithm> =
            saml_cfg["allowed_signature_algorithms"]
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

        if saml_enabled && saml_allowed_signature_algorithms.is_empty() {
            return Err(
                "soap_ws_security: saml.allowed_signature_algorithms must contain at least one of \
                 'rsa-sha256' or 'rsa-sha1' when SAML is enabled"
                    .to_string(),
            );
        }

        let saml_allowed_digest_algorithms: Vec<DigestAlgorithm> =
            saml_cfg["allowed_digest_algorithms"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| match v.as_str()? {
                            "sha256" => Some(DigestAlgorithm::Sha256),
                            "sha1" => Some(DigestAlgorithm::Sha1),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_else(|| vec![DigestAlgorithm::Sha256]);

        if saml_enabled && saml_allowed_digest_algorithms.is_empty() {
            return Err(
                "soap_ws_security: saml.allowed_digest_algorithms must contain at least one of \
                 'sha256' or 'sha1' when SAML is enabled"
                    .to_string(),
            );
        }

        // ── Nonce / replay config ───────────────────────────────────────
        let nonce_cfg = config_obj.get("nonce").unwrap_or(&Value::Null);
        let nonce_cache_ttl_seconds = nonce_cfg["cache_ttl_seconds"].as_u64().unwrap_or(300);
        let max_nonce_cache_size = nonce_cfg["max_cache_size"].as_u64().unwrap_or(10_000) as usize;

        // ── General ─────────────────────────────────────────────────────
        let reject_missing_security_header = config_obj
            .get("reject_missing_security_header")
            .and_then(Value::as_bool)
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
            allowed_digest_algorithms,
            require_signed_timestamp,
            saml_enabled,
            saml_trusted_issuers,
            saml_audience,
            saml_clock_skew_seconds,
            saml_trusted_signing_certs,
            saml_allowed_signature_algorithms,
            saml_allowed_digest_algorithms,
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

        // The verification mode is dictated solely by the operator-configured
        // `password_type`, NEVER by the client-supplied `Type` attribute.
        // Letting the wire value select the mode lets an attacker who knows the
        // plaintext credential downgrade a configured PasswordDigest policy
        // (Nonce / Created / replay protection) to plain PasswordText by sending
        // `Type="...#PasswordText"`. If a recognized `Type` attribute is present
        // it must agree with the configured policy; a mismatch is rejected.
        if let Some(type_attr) = find_attribute(&password_element, "Type") {
            let wire_type =
                if type_attr.contains("PasswordDigest") || type_attr == PASSWORD_DIGEST_TYPE {
                    Some(PasswordType::PasswordDigest)
                } else if type_attr.contains("PasswordText") || type_attr == PASSWORD_TEXT_TYPE {
                    Some(PasswordType::PasswordText)
                } else {
                    // Unrecognized Type value — fall through to the configured
                    // policy rather than guessing a verification mode.
                    None
                };
            if let Some(wire_type) = wire_type
                && wire_type != self.password_type
            {
                return Err(
                    "WS-Security: Password Type does not match the configured password_type"
                        .to_string(),
                );
            }
        }
        let effective_type = self.password_type;

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
                // Constant-time compare: `password_value` is attacker-controlled
                // and `cred.password` is the stored shared secret, so a
                // short-circuiting `!=` leaks password bytes via timing. Mirrors
                // basic_auth / hmac_auth; `constant_time_eq` handles length
                // mismatches safely.
                if !constant_time_eq(password_value.as_bytes(), cred.password.as_bytes()) {
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

                // Constant-time compare for consistency with the PasswordText
                // path (the digest is derived from the shared secret).
                if !constant_time_eq(password_value.trim().as_bytes(), expected_b64.as_bytes()) {
                    return Err("WS-Security: PasswordDigest verification failed".to_string());
                }
            }
        }

        Ok(username)
    }

    // ── Nonce replay protection ─────────────────────────────────────────

    /// Check if a nonce has been seen before within the TTL window.
    /// Inserts the nonce into the cache if not a replay.
    pub fn check_nonce_replay(&self, nonce: &str) -> Result<(), String> {
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

    fn validate_x509_signature(
        &self,
        security_block: &str,
        soap_body: &str,
        envelope: &str,
    ) -> Result<(), String> {
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
        self.verify_reference_digests(&signed_info, security_block, soap_body, envelope)?;

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
        envelope: &str,
    ) -> Result<(), String> {
        // Find all Reference elements in SignedInfo. We must use the variant
        // that returns the end offset so we can advance past each match —
        // advancing by 1 byte (or by `ref_block.len().min(1)`, the previous
        // bug) just re-finds the same Reference and loops forever.
        let mut search_from = 0;
        let mut reference_count = 0;
        while let Some((ref_block, next_start)) =
            find_element_block_from_with_end(signed_info, "Reference", search_from)
        {
            reference_count += 1;
            // Bound attacker-controlled work: each Reference triggers a
            // full-envelope id-uniqueness scan plus an element resolution and a
            // digest over the referenced bytes, all before the signature is
            // verified. Capping the Reference count keeps an unauthenticated
            // request from forcing O(references × body) CPU. A legitimate
            // WS-Security signature covers a handful of elements (Timestamp,
            // Body, a few headers); 64 is far above any real use.
            if reference_count > MAX_SIGNED_REFERENCES {
                return Err(format!(
                    "WS-Security: too many Signature References (> {})",
                    MAX_SIGNED_REFERENCES
                ));
            }
            // Defensive: ensure the cursor advances even for pathological
            // inputs (e.g. zero-length match). Without this, a malformed
            // element could still loop indefinitely.
            search_from = next_start.max(search_from + 1);

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
                // XML Signature Wrapping defense: a signed reference must
                // resolve to exactly ONE element in the whole envelope.
                // WS-Security / XMLDSIG ids are document-unique, so a duplicate
                // wsu:Id means an attacker wrapped the signed element — the bytes
                // we digest (the first match) could then differ from the element a
                // backend consumes. The count spans the FULL envelope, not just
                // the regions the resolver searches, so a duplicate injected
                // anywhere is caught. Mirrors the SAML single-Assertion guard.
                let occurrences = count_wsu_id_occurrences(envelope, ref_id)?;
                if occurrences > 1 {
                    return Err(format!(
                        "WS-Security: referenced id '{}' is not unique in the envelope \
                         ({} occurrences) — possible XML signature wrapping",
                        ref_id, occurrences
                    ));
                }
                let security_range = envelope
                    .find(security_block)
                    .map(|start| (start, start + security_block.len()));
                let body_range = if soap_body.is_empty() {
                    None
                } else {
                    envelope
                        .find(soap_body)
                        .map(|start| (start, start + soap_body.len()))
                };

                security_range
                    .and_then(|(start, end)| {
                        find_element_by_wsu_id_in_range(envelope, start, end, ref_id)
                    })
                    .or_else(|| {
                        body_range.and_then(|(start, end)| {
                            find_element_by_wsu_id_in_range(envelope, start, end, ref_id)
                        })
                    })
                    .ok_or_else(|| {
                        format!("WS-Security: referenced element '{}' not found", ref_id)
                    })?
            } else {
                return Err(format!("WS-Security: unsupported Reference URI '{}'", uri));
            };

            // Compute and compare digest. The allowed_digest_algorithms list
            // is checked independently of the signature algorithm list — an
            // operator who wants rsa-sha256 signatures over sha1 digests
            // (rare but valid per XMLDSIG) configures both knobs explicitly,
            // and the default (sha256 only) refuses sha1 digests regardless
            // of which signature algorithm is in use.
            let computed = match digest_alg_uri.as_str() {
                XMLDSIG_SHA256 => {
                    if !self
                        .allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha256)
                    {
                        return Err(format!(
                            "WS-Security: digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA256, referenced_content.as_bytes())
                }
                XMLDSIG_SHA1 => {
                    if !self
                        .allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha1)
                    {
                        return Err(format!(
                            "WS-Security: digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(
                        &digest::SHA1_FOR_LEGACY_USE_ONLY,
                        referenced_content.as_bytes(),
                    )
                }
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

        // XMLDSig requires SignedInfo to contain at least one Reference.
        // A signature with zero references would otherwise be considered
        // valid here even though it signs nothing meaningful — making it
        // trivial to bypass `require_signed_timestamp`.
        if reference_count == 0 {
            return Err("WS-Security: SignedInfo contains no Reference elements".to_string());
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

        let ts_start = security_block
            .find(&ts_block)
            .ok_or_else(|| "WS-Security: Timestamp block could not be located".to_string())?;
        let ts_id = match find_wsu_id_in_xml(security_block, ts_start) {
            Some(id) => id,
            None => {
                return Err(
                    "WS-Security: Timestamp has no wsu:Id — cannot verify it is signed".to_string(),
                );
            }
        };

        // Iterate each <Reference> and compare its parsed URI attribute
        // against `#<timestamp-id>`. A naive substring check on `signed_info`
        // would accept prefix matches (e.g. `URI="#TS-1abc"` for `TS-1`) and
        // would also miss valid signatures that use whitespace around `=`
        // (`URI = "#TS-1"`) or single quotes. Parsing each Reference's URI
        // via `find_attribute` handles all of these uniformly.
        let expected = format!("#{}", ts_id);
        let mut search_from = 0;
        while let Some((ref_block, next_start)) =
            find_element_block_from_with_end(signed_info, "Reference", search_from)
        {
            search_from = next_start.max(search_from + 1);
            if let Some(uri) = find_attribute(&ref_block, "URI")
                && uri == expected
            {
                return Ok(());
            }
        }

        Err("WS-Security: Timestamp is not included in the signature".to_string())
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

    /// Validate the SAML assertion inside a WS-Security header.
    ///
    /// Returns the assertion's Subject NameID on success (the "who" of the
    /// assertion) so callers can stash it in request metadata.
    ///
    /// Verification order is signature-first: an attacker who can post a SOAP
    /// body controls every text node in the assertion, so issuer / conditions
    /// / audience checks only mean something AFTER the assertion's XMLDSIG
    /// signature has been verified against a configured trusted IdP cert.
    fn validate_saml_assertion(
        &self,
        security_block: &str,
        envelope: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<String>, String> {
        let assertion = match find_element_block(security_block, "Assertion") {
            Some(a) => a,
            None => {
                return if self.saml_enabled {
                    Err("WS-Security: missing SAML Assertion element".to_string())
                } else {
                    Ok(None)
                };
            }
        };

        // Defense in depth: only ever validate a single assertion. If an
        // attacker can wedge a second Assertion anywhere in the SOAP envelope,
        // downstream consumers that walk all assertions could see an
        // identity we never verified. Cheap insurance — reject and let the
        // operator deal with malformed/multi-assertion messages explicitly.
        if count_elements(envelope, "Assertion") > 1 {
            return Err(
                "WS-Security: multiple SAML Assertion elements are not allowed".to_string(),
            );
        }

        // ── 1. Signature verification ─────────────────────────────────
        // Must run before any other check — every other field is
        // attacker-controlled until we know the IdP signed this assertion.
        self.validate_saml_signature(&assertion)?;
        let assertion_without_signature = remove_envelope_signature(&assertion);

        // ── 2. Issuer trust ───────────────────────────────────────────
        let issuer = find_element_text(&assertion_without_signature, "Issuer")
            .ok_or_else(|| "WS-Security: SAML Assertion missing Issuer element".to_string())?;

        if !self.saml_trusted_issuers.iter().any(|ti| ti == &issuer) {
            return Err(format!(
                "WS-Security: SAML Issuer '{}' is not trusted",
                escape_xml_chars(&issuer)
            ));
        }

        // ── 3. Conditions: NotBefore / NotOnOrAfter / Audience ────────
        if let Some(conditions) = find_element_block(&assertion_without_signature, "Conditions") {
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

            if let Some(ref expected_audience) = self.saml_audience {
                let Some(audience_restriction) =
                    find_element_block(&conditions, "AudienceRestriction")
                else {
                    return Err(
                        "WS-Security: SAML AudienceRestriction is required when audience is configured"
                            .to_string(),
                    );
                };

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
        } else if self.saml_audience.is_some() {
            return Err(
                "WS-Security: SAML Conditions are required when audience is configured".to_string(),
            );
        }

        // ── 4. Extract Subject NameID for downstream identity use ─────
        let name_id = find_element_block(&assertion_without_signature, "Subject")
            .and_then(|subject| find_element_text(&subject, "NameID"));

        debug!("soap_ws_security: SAML assertion validated successfully");
        Ok(name_id)
    }

    /// Verify the SAML assertion's XMLDSIG signature.
    ///
    /// Steps:
    /// 1. Locate `<Signature>` inside the assertion.
    /// 2. Resolve the signing algorithm and confirm it is in the allow list.
    /// 3. Verify each `<Reference>` digest. The SAML enveloped-signature
    ///    transform is applied — the assertion's Signature element is excised
    ///    from the referenced content before hashing.
    /// 4. Extract the signing cert from `KeyInfo/X509Data/X509Certificate`
    ///    (or `BinarySecurityToken`) and confirm its SHA-256 fingerprint
    ///    matches a configured trusted IdP cert.
    /// 5. Verify `<SignatureValue>` over the `<SignedInfo>` bytes using the
    ///    matched cert's public key.
    fn validate_saml_signature(&self, assertion: &str) -> Result<(), String> {
        let sig_block = find_element_block(assertion, "Signature")
            .ok_or_else(|| "WS-Security: SAML Assertion missing Signature element".to_string())?;

        let signed_info = find_element_block(&sig_block, "SignedInfo")
            .ok_or_else(|| "WS-Security: SAML Signature missing SignedInfo element".to_string())?;

        // ── Resolve signature algorithm ───────────────────────────────
        let sig_method_block = find_element_block(&signed_info, "SignatureMethod")
            .ok_or_else(|| "WS-Security: SAML SignedInfo missing SignatureMethod".to_string())?;
        let sig_algorithm_uri =
            find_attribute(&sig_method_block, "Algorithm").ok_or_else(|| {
                "WS-Security: SAML SignatureMethod missing Algorithm attribute".to_string()
            })?;

        let sig_algorithm = match sig_algorithm_uri.as_str() {
            XMLDSIG_RSA_SHA256 => SignatureAlgorithm::RsaSha256,
            XMLDSIG_RSA_SHA1 => SignatureAlgorithm::RsaSha1,
            other => {
                return Err(format!(
                    "WS-Security: SAML unsupported signature algorithm '{}'",
                    other
                ));
            }
        };

        if !self
            .saml_allowed_signature_algorithms
            .contains(&sig_algorithm)
        {
            return Err(format!(
                "WS-Security: SAML signature algorithm '{}' is not allowed",
                sig_algorithm_uri
            ));
        }

        // ── Verify Reference digest(s) ────────────────────────────────
        self.verify_saml_reference_digests(&signed_info, assertion)?;

        // ── Extract SignatureValue ────────────────────────────────────
        let sig_value_b64 = find_element_text(&sig_block, "SignatureValue")
            .ok_or_else(|| "WS-Security: SAML Signature missing SignatureValue".to_string())?;
        let sig_bytes = BASE64
            .decode(sig_value_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid SignatureValue base64: {}", e))?;

        // ── Resolve signing cert and confirm it is trusted ────────────
        let cert_der = extract_saml_signing_cert(&sig_block)?;
        let cert_fingerprint = digest::digest(&digest::SHA256, &cert_der).as_ref().to_vec();

        let trusted = self
            .saml_trusted_signing_certs
            .iter()
            .find(|tc| tc.fingerprint == cert_fingerprint);

        let public_key_der = match trusted {
            Some(tc) => &tc.public_key_der,
            None => {
                return Err("WS-Security: SAML signing certificate is not trusted".to_string());
            }
        };

        // ── Verify the signature over SignedInfo ──────────────────────
        let verify_algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_algorithm {
            SignatureAlgorithm::RsaSha256 => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaSha1 => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        let public_key = ring_sig::UnparsedPublicKey::new(verify_algorithm, public_key_der);

        public_key
            .verify(signed_info.as_bytes(), &sig_bytes)
            .map_err(|_| "WS-Security: SAML signature verification failed".to_string())?;

        debug!("soap_ws_security: SAML assertion signature verified");
        Ok(())
    }

    /// Verify Reference digests inside the SAML SignedInfo.
    ///
    /// At least one Reference must be present, and at least one Reference
    /// must target the enclosing assertion via `URI="#<assertion-ID>"`. The
    /// enveloped-signature transform is applied for the assertion-targeted
    /// Reference: the assertion's own `<Signature>` element is removed before
    /// digesting. Other References (e.g. SAML 2.0 SubjectConfirmationData)
    /// are NOT supported here — they would require resolving arbitrary IDs
    /// inside the assertion and applying additional transforms, which is
    /// outside the scope of the current pragmatic implementation.
    fn verify_saml_reference_digests(
        &self,
        signed_info: &str,
        assertion: &str,
    ) -> Result<(), String> {
        let assertion_id = find_attribute(assertion, "ID")
            .or_else(|| find_attribute(assertion, "AssertionID"))
            .ok_or_else(|| "WS-Security: SAML Assertion missing ID attribute".to_string())?;
        let expected_uri = format!("#{}", assertion_id);

        // Pre-compute the enveloped-signature transform once.
        let assertion_without_signature = remove_envelope_signature(assertion);

        let mut search_from = 0;
        let mut reference_count = 0;
        let mut covered_assertion = false;

        while let Some((ref_block, next_start)) =
            find_element_block_from_with_end(signed_info, "Reference", search_from)
        {
            reference_count += 1;
            if reference_count > MAX_SIGNED_REFERENCES {
                return Err(format!(
                    "WS-Security: too many SAML Signature References (> {})",
                    MAX_SIGNED_REFERENCES
                ));
            }
            search_from = next_start.max(search_from + 1);

            let uri = find_attribute(&ref_block, "URI").unwrap_or_default();

            // Only Reference URIs that target this assertion are accepted —
            // an attacker who can choose the Reference URI would otherwise
            // pick a stable subtree they can control.
            if uri != expected_uri {
                return Err(format!(
                    "WS-Security: SAML Reference URI '{}' does not target Assertion ID '{}'",
                    uri, expected_uri
                ));
            }

            let digest_method = find_element_block(&ref_block, "DigestMethod")
                .ok_or_else(|| "WS-Security: SAML Reference missing DigestMethod".to_string())?;
            let digest_alg_uri = find_attribute(&digest_method, "Algorithm").ok_or_else(|| {
                "WS-Security: SAML DigestMethod missing Algorithm attribute".to_string()
            })?;

            let expected_b64 = find_element_text(&ref_block, "DigestValue")
                .ok_or_else(|| "WS-Security: SAML Reference missing DigestValue".to_string())?;
            let expected_bytes = BASE64
                .decode(expected_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: SAML invalid DigestValue base64: {}", e))?;

            let computed = match digest_alg_uri.as_str() {
                XMLDSIG_SHA256 => {
                    if !self
                        .saml_allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha256)
                    {
                        return Err(format!(
                            "WS-Security: SAML digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA256, assertion_without_signature.as_bytes())
                }
                XMLDSIG_SHA1 => {
                    if !self
                        .saml_allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha1)
                    {
                        return Err(format!(
                            "WS-Security: SAML digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(
                        &digest::SHA1_FOR_LEGACY_USE_ONLY,
                        assertion_without_signature.as_bytes(),
                    )
                }
                other => {
                    return Err(format!(
                        "WS-Security: SAML unsupported digest algorithm '{}'",
                        other
                    ));
                }
            };

            if computed.as_ref() != expected_bytes.as_slice() {
                return Err("WS-Security: SAML assertion digest mismatch".to_string());
            }

            covered_assertion = true;
        }

        if reference_count == 0 {
            return Err("WS-Security: SAML SignedInfo contains no Reference elements".to_string());
        }

        // Defensive: if all References had matching URIs they already produced
        // `covered_assertion = true`. This is a future-proofing check in case
        // the URI-matching invariant above is ever relaxed.
        if !covered_assertion {
            return Err(
                "WS-Security: SAML signature does not cover the enclosing assertion".to_string(),
            );
        }

        Ok(())
    }

    // ── Content-type check ──────────────────────────────────────────────

    fn is_soap_content_type(content_type: &str) -> bool {
        contains_ascii_case_insensitive(content_type, "text/xml")
            || contains_ascii_case_insensitive(content_type, "application/soap+xml")
            || contains_ascii_case_insensitive(content_type, "application/xml")
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
        if contains_forbidden_xml_declaration(envelope) {
            return PluginResult::Reject {
                status_code: 400,
                body: r#"{"error":"SOAP request contains forbidden XML declaration"}"#.to_string(),
                headers: HashMap::new(),
            };
        }
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
            && let Err(e) = self.validate_x509_signature(&security_block, &soap_body, envelope)
        {
            warn!("soap_ws_security: X.509 signature validation failed: {}", e);
            return PluginResult::Reject {
                status_code: 401,
                body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                headers: HashMap::new(),
            };
        }

        // Validate SAML assertion
        if self.saml_enabled {
            match self.validate_saml_assertion(&security_block, envelope, now) {
                Ok(name_id) => {
                    if let Some(subject) = name_id {
                        ctx.metadata
                            .insert("soap_ws_saml_subject".to_string(), subject);
                    }
                    debug!("soap_ws_security: SAML assertion accepted");
                }
                Err(e) => {
                    warn!("soap_ws_security: SAML validation failed: {}", e);
                    return PluginResult::Reject {
                        status_code: 401,
                        body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(&e)),
                        headers: HashMap::new(),
                    };
                }
            }
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

/// Count the number of (top-level-scan) occurrences of an element by local
/// name. Walks the same cursor pattern as the Reference-digest loop so
/// nested same-named elements aren't double-counted.
fn count_elements(xml: &str, local_name: &str) -> usize {
    let mut count = 0usize;
    let mut search_from = 0;
    while let Some((_, next_start)) = find_element_block_from_with_end(xml, local_name, search_from)
    {
        count += 1;
        search_from = next_start.max(search_from + 1);
    }
    count
}

/// Find an element block by local name, starting from a given byte offset.
fn find_element_block_from(xml: &str, local_name: &str, start: usize) -> Option<String> {
    find_element_block_from_with_end(xml, local_name, start).map(|(block, _)| block)
}

/// Find an element block and also return the absolute end offset (within `xml`)
/// of the matched block. Callers that iterate over multiple sibling elements
/// must use this and advance their cursor with the returned end offset —
/// otherwise they will re-find the same element on the next iteration and
/// loop forever.
fn find_element_block_from_with_end(
    xml: &str,
    local_name: &str,
    start: usize,
) -> Option<(String, usize)> {
    if start > xml.len() {
        return None;
    }
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
        let end = start + tag_start + tag_header_end + 1;
        return Some((after_open[..=tag_header_end].to_string(), end));
    }

    // Find matching closing tag </prefix:localName> or </localName>
    let closing = format!("</{}>", full_tag_name);
    let close_pos = search[tag_start..].find(&closing)?;
    let end_in_search = tag_start + close_pos + closing.len();
    let end = start + end_in_search;

    Some((search[tag_start..end_in_search].to_string(), end))
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
pub(crate) fn find_element_by_wsu_id(xml: &str, id: &str) -> Option<String> {
    find_element_by_wsu_id_in_range(xml, 0, xml.len(), id)
}

fn find_element_by_wsu_id_in_range(
    xml: &str,
    range_start: usize,
    range_end: usize,
    id: &str,
) -> Option<String> {
    if range_start > range_end || range_end > xml.len() {
        return None;
    }

    let mut search_from = range_start;
    while let Some(rel) = xml.get(search_from..range_end)?.find('<') {
        let tag_start = search_from + rel;
        let after_lt = xml.as_bytes().get(tag_start + 1)?;
        if *after_lt == b'/' {
            search_from = tag_start + 1;
            continue;
        }
        if *after_lt == b'!' {
            search_from = skip_markup_declaration(xml, tag_start).ok()?;
            continue;
        }
        if *after_lt == b'?' {
            search_from = skip_processing_instruction(xml, tag_start).ok()?;
            continue;
        }

        let tag_end_rel = find_start_tag_end(xml, tag_start)?;
        let tag = &xml[tag_start + 1..tag_start + tag_end_rel];
        let namespaces = namespace_bindings_for_tag(xml, tag_start)?;
        if !tag_has_resolvable_wsu_id(tag, id, &namespaces) {
            search_from = tag_start + tag_end_rel + 1;
            continue;
        }

        if tag.trim_end().ends_with('/') {
            let tag_end = tag_start + tag_end_rel + 1;
            if tag_end <= range_end {
                return Some(xml[tag_start..tag_end].to_string());
            }
            return None;
        }

        let full_tag_name = extract_full_tag_name(&xml[tag_start..range_end])?;
        let local_name = if let Some(colon_pos) = full_tag_name.find(':') {
            &full_tag_name[colon_pos + 1..]
        } else {
            &full_tag_name
        };

        let closing = format!("</{}>", full_tag_name);
        if let Some(close_pos) = xml[tag_start..range_end].find(&closing) {
            let end = tag_start + close_pos + closing.len();
            return Some(xml[tag_start..end].to_string());
        }

        let closing_no_prefix = format!("</{}>", local_name);
        if let Some(close_pos) = xml[tag_start..range_end].find(&closing_no_prefix) {
            let end = tag_start + close_pos + closing_no_prefix.len();
            return Some(xml[tag_start..end].to_string());
        }

        search_from = tag_start + tag_end_rel + 1;
    }

    None
}

/// Extract the standards-resolvable WS-Security Utility id attribute from an
/// element. Bare `Id` is accepted for compatibility; prefixed `*:Id` attributes
/// are accepted only when that prefix is bound to the WSU namespace URI.
fn find_wsu_id_in_xml(xml: &str, tag_start: usize) -> Option<String> {
    let tag_end_rel = find_start_tag_end(xml, tag_start)?;
    let tag = xml.get(tag_start + 1..tag_start + tag_end_rel)?;
    let namespaces = namespace_bindings_for_tag(xml, tag_start)?;
    find_resolvable_wsu_id_value_in_tag(tag, &namespaces)
}

fn tag_has_resolvable_wsu_id(tag: &str, id: &str, namespaces: &HashMap<String, String>) -> bool {
    scan_tag_attributes(tag, |name, value| {
        is_resolvable_wsu_id_attribute_name(name, namespaces) && value == id
    })
}

fn find_resolvable_wsu_id_value_in_tag(
    tag: &str,
    namespaces: &HashMap<String, String>,
) -> Option<String> {
    let mut found = None;
    scan_tag_attributes(tag, |name, value| {
        if is_resolvable_wsu_id_attribute_name(name, namespaces) {
            found = Some(value.to_string());
            true
        } else {
            false
        }
    });
    found
}

fn is_resolvable_wsu_id_attribute_name(name: &str, namespaces: &HashMap<String, String>) -> bool {
    if name == "Id" {
        return true;
    }

    let Some((prefix, local_name)) = name.rsplit_once(':') else {
        return false;
    };

    local_name == "Id"
        && namespaces
            .get(prefix)
            .is_some_and(|uri| uri == WSU_NAMESPACE_URI)
}

struct NamespaceFrame {
    element_name: String,
    previous_bindings: Vec<(String, Option<String>)>,
}

fn namespace_bindings_for_tag(
    xml: &str,
    target_tag_start: usize,
) -> Option<HashMap<String, String>> {
    let mut namespaces = namespace_bindings_before_tag(xml, target_tag_start)?;
    let tag_end_rel = find_start_tag_end(xml, target_tag_start)?;
    let tag = xml.get(target_tag_start + 1..target_tag_start + tag_end_rel)?;
    apply_namespace_declarations(tag, &mut namespaces);
    Some(namespaces)
}

fn namespace_bindings_before_tag(
    xml: &str,
    target_tag_start: usize,
) -> Option<HashMap<String, String>> {
    let mut namespaces = HashMap::new();
    let mut stack: Vec<NamespaceFrame> = Vec::new();
    let mut search_from = 0usize;

    while search_from < target_tag_start {
        let rel = match xml.get(search_from..target_tag_start)?.find('<') {
            Some(rel) => rel,
            None => break,
        };
        let tag_start = search_from + rel;
        let after_lt = *xml.as_bytes().get(tag_start + 1)?;

        if after_lt == b'/' {
            let tag_end_rel = find_start_tag_end(xml, tag_start)?;
            let tag = xml.get(tag_start + 2..tag_start + tag_end_rel)?.trim();
            revert_namespace_bindings_until(&mut stack, &mut namespaces, tag);
            search_from = tag_start + tag_end_rel + 1;
            continue;
        }
        if after_lt == b'!' {
            search_from = skip_markup_declaration(xml, tag_start).ok()?;
            continue;
        }
        if after_lt == b'?' {
            search_from = skip_processing_instruction(xml, tag_start).ok()?;
            continue;
        }

        let tag_end_rel = find_start_tag_end(xml, tag_start)?;
        let tag = xml.get(tag_start + 1..tag_start + tag_end_rel)?;
        if !tag.trim_end().ends_with('/') {
            let element_name = extract_full_tag_name_from_tag(tag)?.to_string();
            let previous_bindings = apply_namespace_declarations_with_history(tag, &mut namespaces);
            stack.push(NamespaceFrame {
                element_name,
                previous_bindings,
            });
        }
        search_from = tag_start + tag_end_rel + 1;
    }

    Some(namespaces)
}

fn extract_full_tag_name_from_tag(tag: &str) -> Option<&str> {
    let trimmed = tag.trim_start();
    let end = trimmed
        .find([' ', '/', '\t', '\n', '\r'])
        .unwrap_or(trimmed.len());
    if end == 0 {
        None
    } else {
        Some(&trimmed[..end])
    }
}

fn apply_namespace_declarations(tag: &str, namespaces: &mut HashMap<String, String>) {
    scan_tag_attributes(tag, |name, value| {
        if let Some(prefix) = name.strip_prefix("xmlns:") {
            namespaces.insert(prefix.to_string(), value.to_string());
        }
        false
    });
}

fn apply_namespace_declarations_with_history(
    tag: &str,
    namespaces: &mut HashMap<String, String>,
) -> Vec<(String, Option<String>)> {
    let mut previous_bindings = Vec::new();
    scan_tag_attributes(tag, |name, value| {
        if let Some(prefix) = name.strip_prefix("xmlns:") {
            previous_bindings.push((prefix.to_string(), namespaces.get(prefix).cloned()));
            namespaces.insert(prefix.to_string(), value.to_string());
        }
        false
    });
    previous_bindings
}

fn revert_namespace_bindings_until(
    stack: &mut Vec<NamespaceFrame>,
    namespaces: &mut HashMap<String, String>,
    closing_tag_name: &str,
) {
    while let Some(frame) = stack.pop() {
        let matched = frame.element_name == closing_tag_name
            || frame
                .element_name
                .rsplit_once(':')
                .is_some_and(|(_, local_name)| local_name == closing_tag_name);
        for (prefix, previous) in frame.previous_bindings.into_iter().rev() {
            if let Some(uri) = previous {
                namespaces.insert(prefix, uri);
            } else {
                namespaces.remove(&prefix);
            }
        }
        if matched {
            break;
        }
    }
}

fn scan_tag_attributes<F>(tag: &str, mut on_attr: F) -> bool
where
    F: FnMut(&str, &str) -> bool,
{
    let bytes = tag.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/' {
        i += 1;
    }

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'/' {
            break;
        }

        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/')
        {
            i += 1;
        }
        let name = &tag[name_start..i];

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let Some(&quote) = bytes.get(i) else {
            break;
        };
        if !matches!(quote, b'\'' | b'"') {
            continue;
        }
        i += 1;
        let value_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let value = &tag[value_start..i];
        i += 1;

        if on_attr(name, value) {
            return true;
        }
    }

    false
}

/// Count how many start tags in `xml` bear the given XML id attribute value.
/// Used to reject XML Signature Wrapping (XSW): a signed reference whose id
/// appears on more than one element means an attacker injected a duplicate, so
/// the byte range the signature covers may differ from the element a backend
/// consumes.
///
/// The resolver still accepts WS-Security `*:Id` / bare `Id`, but this security
/// gate intentionally counts broader id spellings (`xml:id`, `ID`, `id`) so a
/// backend with broader fragment resolution fails closed. Scanning only start
/// tags avoids rejecting a legitimate request merely because body text contains
/// `Id="..."`. Comments, CDATA, processing instructions, and declarations are
/// skipped as non-element spans. Unlike the narrower extraction helpers, this
/// full-envelope scan treats malformed start tags as errors rather than
/// returning a partial count.
pub(crate) fn count_wsu_id_occurrences(xml: &str, id: &str) -> Result<usize, String> {
    let mut count = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = xml[search_from..].find('<') {
        let tag_start = search_from + rel;
        let Some(after_lt) = xml.as_bytes().get(tag_start + 1) else {
            return Err(
                "WS-Security: malformed XML start tag while scanning referenced ids".into(),
            );
        };
        if *after_lt == b'/' {
            search_from = tag_start + 1;
            continue;
        }
        if *after_lt == b'!' {
            search_from = skip_markup_declaration(xml, tag_start)?;
            continue;
        }
        if *after_lt == b'?' {
            search_from = skip_processing_instruction(xml, tag_start)?;
            continue;
        }

        let tag_end_rel = find_start_tag_end(xml, tag_start).ok_or_else(|| {
            "WS-Security: malformed XML start tag while scanning referenced ids".to_string()
        })?;
        let tag = &xml[tag_start + 1..tag_start + tag_end_rel];
        count += count_id_attributes_in_tag(tag, id);
        search_from = tag_start + tag_end_rel + 1;
    }
    Ok(count)
}

fn skip_markup_declaration(xml: &str, tag_start: usize) -> Result<usize, String> {
    let from_start = xml.get(tag_start..).ok_or_else(|| {
        "WS-Security: malformed XML declaration while scanning referenced ids".to_string()
    })?;

    if from_start.starts_with("<!--") {
        return from_start
            .find("-->")
            .map(|end_rel| tag_start + end_rel + "-->".len())
            .ok_or_else(|| {
                "WS-Security: malformed XML comment while scanning referenced ids".to_string()
            });
    }

    if from_start.starts_with("<![CDATA[") {
        return from_start
            .find("]]>")
            .map(|end_rel| tag_start + end_rel + "]]>".len())
            .ok_or_else(|| {
                "WS-Security: malformed XML CDATA while scanning referenced ids".to_string()
            });
    }

    let decl_end_rel = find_markup_declaration_end(xml, tag_start).ok_or_else(|| {
        "WS-Security: malformed XML declaration while scanning referenced ids".to_string()
    })?;
    Ok(tag_start + decl_end_rel + 1)
}

fn skip_processing_instruction(xml: &str, tag_start: usize) -> Result<usize, String> {
    let from_start = xml.get(tag_start..).ok_or_else(|| {
        "WS-Security: malformed XML processing instruction while scanning referenced ids"
            .to_string()
    })?;

    from_start
        .find("?>")
        .map(|end_rel| tag_start + end_rel + "?>".len())
        .ok_or_else(|| {
            "WS-Security: malformed XML processing instruction while scanning referenced ids"
                .to_string()
        })
}

/// Return the byte offset, relative to `tag_start`, of the end of a `<!...>`
/// declaration. Comments and CDATA have custom terminators and are handled
/// before this helper is called.
fn find_markup_declaration_end(xml: &str, tag_start: usize) -> Option<usize> {
    debug_assert_eq!(xml.as_bytes().get(tag_start), Some(&b'<'));
    let bytes = xml.as_bytes().get(tag_start..)?;
    if !bytes.starts_with(b"<!") {
        return None;
    }

    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut i = 2usize;

    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'\'' | b'"') => quote = Some(bytes[i]),
            None if bytes[i] == b'[' => bracket_depth = bracket_depth.saturating_add(1),
            None if bytes[i] == b']' => bracket_depth = bracket_depth.saturating_sub(1),
            None if bytes[i] == b'>' && bracket_depth == 0 => return Some(i),
            None => {}
        }
        i += 1;
    }

    None
}

/// Return the byte offset, relative to `tag_start`, of the first unquoted `>`.
/// `tag_start` must point at `<`; malformed or unterminated start tags return
/// `None` so callers can fail closed instead of scanning a partial envelope.
fn find_start_tag_end(xml: &str, tag_start: usize) -> Option<usize> {
    debug_assert_eq!(xml.as_bytes().get(tag_start), Some(&b'<'));
    let bytes = xml.as_bytes().get(tag_start..)?;
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let mut quote = None;
    let mut i = 1usize;

    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'\'' | b'"') => quote = Some(bytes[i]),
            None if bytes[i] == b'>' => return Some(i),
            None => {}
        }
        i += 1;
    }

    None
}

fn count_id_attributes_in_tag(tag: &str, id: &str) -> usize {
    let mut count = 0usize;
    scan_tag_attributes(tag, |name, value| {
        if is_xml_id_attribute_name(name) && value == id {
            count += 1;
        }
        false
    });
    count
}

fn is_xml_id_attribute_name(name: &str) -> bool {
    matches!(name, "Id" | "xml:id" | "ID" | "id")
        || name
            .rsplit_once(':')
            .is_some_and(|(_, local_name)| local_name == "Id")
}

/// Resolve the signing certificate from a SAML `<Signature>` block.
///
/// SAML signatures conventionally carry the signing cert inline in
/// `KeyInfo/X509Data/X509Certificate`. A `BinarySecurityToken` reference is
/// also accepted for symmetry with the WS-Security X.509 path, though that
/// is unusual for SAML.
fn extract_saml_signing_cert(sig_block: &str) -> Result<Vec<u8>, String> {
    if let Some(key_info) = find_element_block(sig_block, "KeyInfo")
        && let Some(cert_b64) = find_element_text(&key_info, "X509Certificate")
    {
        return BASE64
            .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid X509Certificate base64: {}", e));
    }

    if let Some(bst) = find_element_block(sig_block, "BinarySecurityToken") {
        let cert_b64 = extract_element_text_content(&bst, "BinarySecurityToken")
            .ok_or_else(|| "WS-Security: SAML BinarySecurityToken has no content".to_string())?;
        return BASE64
            .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| {
                format!(
                    "WS-Security: SAML invalid BinarySecurityToken base64: {}",
                    e
                )
            });
    }

    Err(
        "WS-Security: SAML signature has no signing certificate (expected X509Certificate in KeyInfo)"
            .to_string(),
    )
}

/// Apply the XMLDSIG enveloped-signature transform: return a copy of `xml`
/// with the first `<Signature>` element (and its contents) removed.
///
/// This is what XMLDSIG verifiers do before hashing the referenced element
/// for an enveloped signature — the signer hashed the element with the
/// (then-empty) Signature placeholder excised, so the verifier has to remove
/// it too. For SAML assertions there is exactly one Signature child, so
/// taking the first `<Signature>` match is correct.
fn remove_envelope_signature(xml: &str) -> String {
    let Some((block, end)) = find_element_block_from_with_end(xml, "Signature", 0) else {
        return xml.to_string();
    };
    let start = end - block.len();
    let mut out = String::with_capacity(xml.len() - block.len());
    out.push_str(&xml[..start]);
    out.push_str(&xml[end..]);
    out
}

/// Extract a bare RFC 8017 `RSAPublicKey` DER from a parsed X.509 cert,
/// rejecting non-RSA keys and malformed encodings at load time.
///
/// Both the WS-Security X.509 trust store and the SAML `trusted_signing_certs`
/// trust store funnel cert PEMs through this helper so the verifier always
/// sees the bare `RSAPublicKey` that `ring::signature::RSA_PKCS1_*` expects —
/// passing a full `SubjectPublicKeyInfo` would reject every signature with
/// a generic parse error.
///
/// The returned error string already includes a leading context phrase
/// ("is not an RSA public key …", "RSA SPKI BIT STRING has …", "has
/// malformed RSA public key DER: …"), so callers prepend their own cert
/// path and surrounding identification.
fn load_rsa_public_key_from_cert(cert: &X509Certificate<'_>) -> Result<Vec<u8>, String> {
    let public_key_info = cert.public_key();

    // Defense-in-depth: this plugin only supports RSA-PKCS#1 v1.5 signature
    // verification (rsa-sha256 / rsa-sha1). A non-RSA cert (e.g. ECDSA P-256)
    // would otherwise load silently and surface at request time as a generic
    // "signature verification failed" message, making the misconfiguration
    // hard to diagnose. Reject at load with a precise error.
    if public_key_info.algorithm.algorithm != oid_registry::OID_PKCS1_RSAENCRYPTION {
        return Err(format!(
            "is not an RSA public key (algorithm OID '{}', expected \
             '1.2.840.113549.1.1.1' / rsaEncryption); only RSA certificates \
             are supported for WS-Security signature verification",
            public_key_info.algorithm.algorithm,
        ));
    }

    // An RSA SubjectPublicKeyInfo encapsulates the RSAPublicKey in a BIT
    // STRING whose `unused_bits` MUST be 0 (the contents are byte-aligned
    // DER). Anything else is a malformed cert.
    if public_key_info.subject_public_key.unused_bits != 0 {
        return Err(format!(
            "RSA SPKI BIT STRING has {} unused bits (expected 0)",
            public_key_info.subject_public_key.unused_bits,
        ));
    }

    // Ring's `RSA_PKCS1_*` verification algorithms expect a bare RFC 8017
    // §A.1.1 `RSAPublicKey` (modulus + exponent), NOT a full RFC 5280
    // `SubjectPublicKeyInfo` (which wraps the key with the algorithm
    // identifier OID). For RSA SPKI the inner `subject_public_key` BitString
    // contents ARE that bare `RSAPublicKey` encoding, so use that directly
    // instead of `public_key().raw` (which is the entire SPKI DER) —
    // passing SPKI bytes makes `UnparsedPublicKey::verify` fail to parse
    // the key and reject every signature regardless of validity.
    let public_key_der = public_key_info.subject_public_key.data.to_vec();

    // Structural regression guard: an `RSAPublicKey` DER is a top-level
    // SEQUENCE whose declared length matches the buffer length. A future
    // refactor that accidentally went back to `public_key().raw` (the full
    // SPKI) would also start with 0x30 — so a tag-only check is
    // insufficient — but its declared length would not agree with the
    // buffer. Verifying both tag and length encoding here catches that
    // class of mistake at load time rather than at request time.
    validate_rsa_public_key_der_shape(&public_key_der)
        .map_err(|e| format!("has malformed RSA public key DER: {}", e))?;

    Ok(public_key_der)
}

/// Structural sanity check: `der` must be a top-level DER `SEQUENCE` whose
/// declared length matches the buffer length exactly. This is intentionally
/// the narrow shape of an RFC 8017 `RSAPublicKey ::= SEQUENCE { modulus,
/// publicExponent }`. It does NOT parse the inner integers — ring does that
/// at verify time. The check exists specifically to catch a regression where
/// the full `SubjectPublicKeyInfo` (which also starts with 0x30, but whose
/// length header omits the wrapping `AlgorithmIdentifier` bytes that are
/// still present in the buffer) is passed in place of the bare `RSAPublicKey`.
fn validate_rsa_public_key_der_shape(der: &[u8]) -> Result<(), String> {
    if der.is_empty() {
        return Err("public key DER is empty".to_string());
    }
    if der[0] != 0x30 {
        return Err(format!(
            "expected DER SEQUENCE tag (0x30) at offset 0, got 0x{:02x}",
            der[0]
        ));
    }
    if der.len() < 2 {
        return Err("DER is truncated before length octet".to_string());
    }

    let first_len = der[1];
    let (declared_content_len, header_len) = if first_len & 0x80 == 0 {
        // Short-form: single-byte length, value 0..=127.
        ((first_len & 0x7f) as usize, 2)
    } else {
        // Long-form: low 7 bits give number of length octets that follow.
        let n = (first_len & 0x7f) as usize;
        if n == 0 {
            return Err("indefinite-length encoding is not valid DER".to_string());
        }
        if n > 4 {
            return Err(format!(
                "length uses {n} octets (refusing to parse > 4; a 4-octet length covers 4 GiB)"
            ));
        }
        if der.len() < 2 + n {
            return Err("DER is truncated inside length encoding".to_string());
        }
        let mut declared: usize = 0;
        for &b in &der[2..2 + n] {
            declared = (declared << 8) | b as usize;
        }
        (declared, 2 + n)
    };

    let expected_total = header_len
        .checked_add(declared_content_len)
        .ok_or_else(|| "declared length overflows usize".to_string())?;

    if expected_total != der.len() {
        return Err(format!(
            "length mismatch: header declares {declared_content_len} content bytes \
             ({expected_total}-byte total), buffer is {} bytes \
             (regression: looks like a full SubjectPublicKeyInfo, not a bare RSAPublicKey)",
            der.len()
        ));
    }

    Ok(())
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

fn contains_forbidden_xml_declaration(xml: &str) -> bool {
    contains_ascii_case_insensitive(xml, "<!doctype")
        || contains_ascii_case_insensitive(xml, "<!entity")
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
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
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            ch if ch < '\u{20}' => {
                escaped.push_str("\\u00");
                let byte = ch as u8;
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
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

    #[test]
    fn soap_escape_json_chars_round_trips_control_characters() {
        let raw = "validation failed\"\n<xml>\u{00}\u{1f}\\";
        let body = format!(r#"{{"error":"{}"}}"#, escape_json_chars(raw));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("escaped SOAP error should be valid JSON");

        assert_eq!(parsed["error"], raw);
        assert!(!escape_json_chars(raw).chars().any(|ch| ch < '\u{20}'));
    }

    #[test]
    fn too_many_x509_signature_references_are_rejected() {
        let plugin = SoapWsSecurity::new(&serde_json::json!({
            "timestamp": { "require": true }
        }))
        .expect("timestamp-only config should construct");
        let timestamp = r#"<wsu:Timestamp wsu:Id="TS-1"></wsu:Timestamp>"#;
        let digest = digest::digest(&digest::SHA256, timestamp.as_bytes());
        let digest_b64 = BASE64.encode(digest.as_ref());
        let reference = format!(
            r##"<Reference URI="#TS-1"><DigestMethod Algorithm="{}"/><DigestValue>{}</DigestValue></Reference>"##,
            XMLDSIG_SHA256, digest_b64
        );
        let references =
            std::iter::repeat_n(reference.as_str(), MAX_SIGNED_REFERENCES + 1).collect::<String>();
        let signed_info = format!("<SignedInfo>{}</SignedInfo>", references);

        let err = plugin
            .verify_reference_digests(&signed_info, timestamp, "", timestamp)
            .expect_err("reference cap must reject");

        assert!(err.contains("too many Signature References"), "got: {err}");
    }

    #[test]
    fn too_many_saml_signature_references_are_rejected() {
        let plugin = SoapWsSecurity::new(&serde_json::json!({
            "timestamp": { "require": true }
        }))
        .expect("timestamp-only config should construct");
        let assertion = r#"<Assertion ID="assertion-1"><Issuer>https://idp.example.com</Issuer><Signature></Signature><Subject><NameID>alice@example.com</NameID></Subject></Assertion>"#;
        let assertion_without_signature = remove_envelope_signature(assertion);
        let digest = digest::digest(&digest::SHA256, assertion_without_signature.as_bytes());
        let digest_b64 = BASE64.encode(digest.as_ref());
        let reference = format!(
            r##"<Reference URI="#assertion-1"><DigestMethod Algorithm="{}"/><DigestValue>{}</DigestValue></Reference>"##,
            XMLDSIG_SHA256, digest_b64
        );
        let references =
            std::iter::repeat_n(reference.as_str(), MAX_SIGNED_REFERENCES + 1).collect::<String>();
        let signed_info = format!("<SignedInfo>{}</SignedInfo>", references);

        let err = plugin
            .verify_saml_reference_digests(&signed_info, assertion)
            .expect_err("SAML reference cap must reject");

        assert!(
            err.contains("too many SAML Signature References"),
            "got: {err}"
        );
    }

    /// Iterating over multiple `<Reference>` elements with
    /// `find_element_block_from_with_end` must advance the cursor far enough
    /// to skip past each match — the previous implementation incremented by
    /// just 1 byte and looped forever on signed SOAP envelopes.
    #[test]
    fn multiple_reference_iteration_terminates_and_finds_each_block() {
        // Use a `r##"..."##` raw string so the embedded `#` characters in URI
        // attributes don't terminate the literal early.
        let signed_info = r##"<SignedInfo>
            <Reference URI="#alpha"><DigestValue>aGVsbG8=</DigestValue></Reference>
            <Reference URI="#beta"><DigestValue>d29ybGQ=</DigestValue></Reference>
            <Reference URI="#gamma"><DigestValue>IQ==</DigestValue></Reference>
        </SignedInfo>"##;

        let mut search_from = 0;
        let mut uris = Vec::new();
        let mut iterations = 0;
        while let Some((block, next_start)) =
            find_element_block_from_with_end(signed_info, "Reference", search_from)
        {
            iterations += 1;
            assert!(
                iterations < 50,
                "iteration must terminate (regression: infinite loop)"
            );
            uris.push(find_attribute(&block, "URI").unwrap_or_default());
            search_from = next_start.max(search_from + 1);
        }
        assert_eq!(uris, vec!["#alpha", "#beta", "#gamma"]);
    }

    /// The end offset must point past the closing `</Reference>` so the next
    /// search starts after the just-matched element, not inside it.
    #[test]
    fn end_offset_points_past_closing_tag() {
        let xml = "prefix<Reference URI=\"#a\"></Reference>middle<Reference URI=\"#b\"></Reference>suffix";
        let Some((first_block, end1)) = find_element_block_from_with_end(xml, "Reference", 0)
        else {
            panic!("first Reference match should be present");
        };
        assert!(first_block.contains("#a"));
        // The remainder should still contain the second Reference.
        let remainder = &xml[end1..];
        assert!(remainder.contains("#b"));
        assert!(!remainder.contains("#a"));
    }

    /// Self-closing tags (e.g. `<Reference URI="#x"/>`) also yield a valid
    /// end offset so subsequent iterations advance past them.
    #[test]
    fn self_closing_tag_returns_correct_end() {
        let xml = "before<Foo/>after";
        let Some((block, end)) = find_element_block_from_with_end(xml, "Foo", 0) else {
            panic!("self-closing Foo match should be present");
        };
        assert_eq!(block, "<Foo/>");
        assert_eq!(&xml[end..], "after");
    }

    // ── RSA public-key DER shape validator ──────────────────────────────────
    //
    // These tests pin the structural regression guard that catches a future
    // refactor accidentally routing the full SubjectPublicKeyInfo (instead of
    // the bare RSAPublicKey) into `ring::signature::UnparsedPublicKey::new` —
    // the original PR #844 bug class.

    #[test]
    fn rsa_pk_shape_accepts_short_form_sequence_with_matching_length() {
        // SEQUENCE, content length 3, three content bytes — well-formed.
        let der = [0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(validate_rsa_public_key_der_shape(&der).is_ok());
    }

    #[test]
    fn rsa_pk_shape_accepts_long_form_two_octet_length() {
        // SEQUENCE, long-form length: 0x82 means "next 2 octets are length";
        // 0x01 0x00 = 256 content bytes. Build a buffer of exactly that size.
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0xAB_u8, 256));
        assert_eq!(der.len(), 4 + 256);
        assert!(validate_rsa_public_key_der_shape(&der).is_ok());
    }

    #[test]
    fn rsa_pk_shape_rejects_empty_buffer() {
        let err = validate_rsa_public_key_der_shape(&[]).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_non_sequence_tag() {
        // 0x02 = INTEGER tag — refused even with otherwise-valid length.
        let err = validate_rsa_public_key_der_shape(&[0x02, 0x01, 0x00]).unwrap_err();
        assert!(err.contains("SEQUENCE tag"), "got: {err}");
        assert!(err.contains("0x02"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_truncated_after_tag() {
        let err = validate_rsa_public_key_der_shape(&[0x30]).unwrap_err();
        assert!(err.contains("length octet"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_indefinite_length_encoding() {
        // 0x80 = "indefinite length" — invalid in DER (only BER allows it).
        let err = validate_rsa_public_key_der_shape(&[0x30, 0x80, 0x00, 0x00]).unwrap_err();
        assert!(err.contains("indefinite-length"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_overlong_length_field() {
        // 0x85 = 5 length octets — refused (a 4-octet length already covers 4 GiB).
        let der = [0x30, 0x85, 0, 0, 0, 0, 0, 0];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length uses 5 octets"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_truncated_long_form_length() {
        // 0x82 promises 2 length octets, but only 1 is present.
        let err = validate_rsa_public_key_der_shape(&[0x30, 0x82, 0x00]).unwrap_err();
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_full_spki_shape_via_length_mismatch() {
        // The exact regression: build a synthetic blob that resembles a
        // SubjectPublicKeyInfo's outer wrapping. Its top-level SEQUENCE length
        // header declares a content size that excludes the trailing bytes the
        // buffer still carries — the length check must reject this.
        //
        // Layout: 0x30 0x09 [9 content bytes] [4 extra trailing bytes].
        // 9 + 2 (header) = 11, but the buffer length is 15, so this rejects.
        let der = [
            0x30, 0x09, // SEQUENCE, 9 content bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // 9 content bytes
            0xAA, 0xBB, 0xCC, 0xDD, // trailing extras (would be the inner BIT STRING)
        ];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
        // The hint about the SPKI regression class is included so the
        // failure mode is recognizable to future maintainers.
        assert!(err.contains("SubjectPublicKeyInfo"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_declared_shorter_than_buffer() {
        // Header declares 2 content bytes but buffer has 4 content bytes.
        let der = [0x30, 0x02, 0x01, 0x02, 0x03, 0x04];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_declared_longer_than_buffer() {
        // Header declares 100 content bytes but only 2 content bytes follow.
        let der = [0x30, 0x64, 0x01, 0x02];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }
}
