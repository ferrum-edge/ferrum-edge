use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;
use x509_parser::prelude::*;

use crate::consumer_index::ConsumerIndex;

use super::{Plugin, PluginResult, RequestContext};

/// Supported certificate fields for consumer identity matching.
#[derive(Debug, Clone)]
enum CertField {
    /// Subject Common Name (CN)
    SubjectCn,
    /// Subject Organizational Unit (OU)
    SubjectOu,
    /// Subject Organization (O)
    SubjectO,
    /// First DNS Subject Alternative Name
    SanDns,
    /// First Email Subject Alternative Name
    SanEmail,
    /// SHA-256 fingerprint of the DER-encoded certificate (lowercase hex)
    FingerprintSha256,
    /// Certificate serial number (lowercase hex)
    Serial,
}

impl CertField {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "subject_cn" => Some(Self::SubjectCn),
            "subject_ou" => Some(Self::SubjectOu),
            "subject_o" => Some(Self::SubjectO),
            "san_dns" => Some(Self::SanDns),
            "san_email" => Some(Self::SanEmail),
            "fingerprint_sha256" => Some(Self::FingerprintSha256),
            "serial" => Some(Self::Serial),
            _ => None,
        }
    }
}

/// Per-proxy issuer filter: matches against the peer certificate's issuer DN.
///
/// All specified fields must match (AND logic within a single filter).
/// Multiple filters in `allowed_issuers` are OR'd — any one matching is sufficient.
#[derive(Debug, Clone)]
struct IssuerFilter {
    /// Issuer Common Name (CN)
    cn: Option<String>,
    /// Issuer Organization (O)
    o: Option<String>,
    /// Issuer Organizational Unit (OU)
    ou: Option<String>,
}

impl IssuerFilter {
    fn from_json(val: &Value) -> Option<Self> {
        let obj = val.as_object()?;
        let cn = obj.get("cn").and_then(|v| v.as_str()).map(String::from);
        let o = obj.get("o").and_then(|v| v.as_str()).map(String::from);
        let ou = obj.get("ou").and_then(|v| v.as_str()).map(String::from);
        // At least one field must be specified
        if cn.is_none() && o.is_none() && ou.is_none() {
            return None;
        }
        Some(Self { cn, o, ou })
    }

    /// Check if this filter matches the given certificate's issuer DN.
    fn matches(&self, cert: &X509Certificate<'_>) -> bool {
        let issuer = cert.issuer();

        if let Some(expected_cn) = &self.cn {
            let actual = issuer
                .iter_common_name()
                .next()
                .and_then(|attr| attr.as_str().ok());
            if actual != Some(expected_cn.as_str()) {
                return false;
            }
        }

        if let Some(expected_o) = &self.o {
            let actual = issuer
                .iter_by_oid(&oid_registry::OID_X509_ORGANIZATION_NAME)
                .next()
                .and_then(|attr| attr.as_str().ok());
            if actual != Some(expected_o.as_str()) {
                return false;
            }
        }

        if let Some(expected_ou) = &self.ou {
            let actual = issuer
                .iter_by_oid(&oid_registry::OID_X509_ORGANIZATIONAL_UNIT)
                .next()
                .and_then(|attr| attr.as_str().ok());
            if actual != Some(expected_ou.as_str()) {
                return false;
            }
        }

        true
    }
}

/// mTLS authentication plugin.
///
/// Authenticates consumers by matching a configurable field from the client's
/// TLS certificate against consumer credentials. This operates on top of the
/// server's CA chain verification — the TLS handshake already validates the
/// certificate chain. This plugin provides an additional consumer-scoped
/// identity check with optional per-proxy CA filtering.
///
/// # Plugin Configuration
///
/// ```json
/// {
///   "cert_field": "subject_cn",
///   "allowed_issuers": [
///     { "cn": "Internal Services CA" },
///     { "o": "My Corp", "ou": "Engineering" }
///   ],
///   "allowed_ca_fingerprints_sha256": [
///     "a1b2c3d4e5f6..."
///   ]
/// }
/// ```
///
/// ## Issuer Filtering
///
/// When `allowed_issuers` is set, the plugin verifies the peer certificate's
/// issuer DN matches at least one filter. Within each filter, all specified
/// fields must match (AND logic). Across filters, any match is sufficient (OR).
///
/// When `allowed_ca_fingerprints_sha256` is set, the plugin verifies that at
/// least one certificate in the client's chain (intermediate/CA certs sent
/// during the TLS handshake) has a matching SHA-256 fingerprint. Note: root
/// CAs are typically not included in the client's chain — use `allowed_issuers`
/// for root CA filtering.
///
/// When both are configured, both constraints must pass (AND logic).
///
/// Supported `cert_field` values:
/// - `subject_cn` (default) — Subject Common Name
/// - `subject_ou` — Subject Organizational Unit
/// - `subject_o` — Subject Organization
/// - `san_dns` — First DNS Subject Alternative Name
/// - `san_email` — First email Subject Alternative Name
/// - `fingerprint_sha256` — SHA-256 fingerprint (lowercase hex)
/// - `serial` — Certificate serial number (lowercase hex)
///
/// # Consumer Credentials
///
/// Consumers authenticate via their `mtls_auth` credential:
/// ```json
/// {
///   "mtls_auth": {
///     "identity": "client.example.com"
///   }
/// }
/// ```
pub struct MtlsAuth {
    cert_field: CertField,
    /// Optional per-proxy issuer DN filters (OR across filters, AND within).
    allowed_issuers: Vec<IssuerFilter>,
    /// Optional SHA-256 fingerprints of allowed CA/intermediate certificates.
    allowed_ca_fingerprints_sha256: Vec<String>,
}

impl MtlsAuth {
    pub fn new(config: &Value) -> Self {
        let cert_field = config["cert_field"]
            .as_str()
            .and_then(CertField::from_str)
            .unwrap_or(CertField::SubjectCn);

        let allowed_issuers = config["allowed_issuers"]
            .as_array()
            .map(|arr| arr.iter().filter_map(IssuerFilter::from_json).collect())
            .unwrap_or_default();

        let allowed_ca_fingerprints_sha256 = config["allowed_ca_fingerprints_sha256"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            cert_field,
            allowed_issuers,
            allowed_ca_fingerprints_sha256,
        }
    }

    /// Returns true if any issuer/CA filtering is configured.
    fn has_issuer_constraints(&self) -> bool {
        !self.allowed_issuers.is_empty() || !self.allowed_ca_fingerprints_sha256.is_empty()
    }

    /// Verify the certificate's issuer against configured constraints.
    ///
    /// Returns Ok(()) if no constraints are configured or all pass.
    /// Returns Err(reason) if a constraint fails.
    fn verify_issuer_constraints(
        &self,
        peer_cert: &X509Certificate<'_>,
        chain_der: Option<&[Vec<u8>]>,
    ) -> Result<(), String> {
        // Check allowed_issuers against the peer cert's issuer DN
        if !self.allowed_issuers.is_empty() {
            let matched = self.allowed_issuers.iter().any(|f| f.matches(peer_cert));
            if !matched {
                let issuer_cn = peer_cert
                    .issuer()
                    .iter_common_name()
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .unwrap_or("<unknown>");
                return Err(format!(
                    "Certificate issuer '{}' does not match any allowed issuer",
                    issuer_cn
                ));
            }
        }

        // Check allowed_ca_fingerprints_sha256 against the chain certs
        if !self.allowed_ca_fingerprints_sha256.is_empty() {
            use sha2::{Digest, Sha256};

            let chain = chain_der.unwrap_or(&[]);
            let matched = chain.iter().any(|cert_der| {
                let mut hasher = Sha256::new();
                hasher.update(cert_der);
                let fingerprint = hex::encode(hasher.finalize());
                self.allowed_ca_fingerprints_sha256
                    .iter()
                    .any(|allowed| allowed == &fingerprint)
            });
            if !matched {
                return Err(
                    "No certificate in the chain matches any allowed CA fingerprint".to_string(),
                );
            }
        }

        Ok(())
    }

    /// Extract the configured field value from a DER-encoded X.509 certificate.
    fn extract_cert_identity(&self, der_bytes: &[u8]) -> Result<String, String> {
        let (_, cert) = X509Certificate::from_der(der_bytes)
            .map_err(|e| format!("Failed to parse client certificate: {}", e))?;

        match &self.cert_field {
            CertField::SubjectCn => {
                let cn = cert
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .ok_or_else(|| "No CN found in certificate subject".to_string())?;
                Ok(cn.to_string())
            }
            CertField::SubjectOu => {
                let ou = cert
                    .subject()
                    .iter_by_oid(&oid_registry::OID_X509_ORGANIZATIONAL_UNIT)
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .ok_or_else(|| "No OU found in certificate subject".to_string())?;
                Ok(ou.to_string())
            }
            CertField::SubjectO => {
                let o = cert
                    .subject()
                    .iter_by_oid(&oid_registry::OID_X509_ORGANIZATION_NAME)
                    .next()
                    .and_then(|attr| attr.as_str().ok())
                    .ok_or_else(|| "No O found in certificate subject".to_string())?;
                Ok(o.to_string())
            }
            CertField::SanDns => {
                let san = cert
                    .extensions()
                    .iter()
                    .find_map(|ext| {
                        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
                        {
                            san.general_names.iter().find_map(|name| {
                                if let GeneralName::DNSName(dns) = name {
                                    Some(dns.to_string())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "No DNS SAN found in certificate".to_string())?;
                Ok(san)
            }
            CertField::SanEmail => {
                let email = cert
                    .extensions()
                    .iter()
                    .find_map(|ext| {
                        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
                        {
                            san.general_names.iter().find_map(|name| {
                                if let GeneralName::RFC822Name(email) = name {
                                    Some(email.to_string())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "No email SAN found in certificate".to_string())?;
                Ok(email)
            }
            CertField::FingerprintSha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(der_bytes);
                Ok(hex::encode(hasher.finalize()))
            }
            CertField::Serial => Ok(cert.serial.to_str_radix(16)),
        }
    }
}

#[async_trait]
impl Plugin for MtlsAuth {
    fn name(&self) -> &str {
        "mtls_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::MTLS_AUTH
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let cert_der = match &ctx.tls_client_cert_der {
            Some(der) => der,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No client certificate presented"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        // Parse the certificate once for both issuer verification and identity extraction.
        let (_, parsed_cert) = match X509Certificate::from_der(cert_der) {
            Ok(result) => result,
            Err(e) => {
                debug!("mtls_auth: failed to parse certificate: {}", e);
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid client certificate"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        // Verify issuer constraints (allowed_issuers + allowed_ca_fingerprints_sha256).
        if self.has_issuer_constraints() {
            let chain = ctx.tls_client_cert_chain_der.as_ref().map(|c| c.as_slice());
            if let Err(reason) = self.verify_issuer_constraints(&parsed_cert, chain) {
                debug!("mtls_auth: issuer constraint failed: {}", reason);
                return PluginResult::Reject {
                    status_code: 403,
                    body: format!(r#"{{"error":"{}"}}"#, reason),
                    headers: HashMap::new(),
                };
            }
        }

        let identity = match self.extract_cert_identity(cert_der) {
            Ok(id) => id,
            Err(e) => {
                debug!("mtls_auth: failed to extract identity: {}", e);
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid client certificate"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        // O(1) lookup by mTLS identity via ConsumerIndex
        if let Some(consumer) = consumer_index.find_by_mtls_identity(&identity) {
            if ctx.identified_consumer.is_none() {
                debug!("mtls_auth: identified consumer '{}'", consumer.username);
                ctx.identified_consumer = Some((*consumer).clone());
            }
            return PluginResult::Continue;
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"No consumer found for client certificate"}"#.into(),
            headers: HashMap::new(),
        }
    }
}
