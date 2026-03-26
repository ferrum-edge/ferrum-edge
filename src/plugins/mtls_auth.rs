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

/// mTLS authentication plugin.
///
/// Authenticates consumers by matching a configurable field from the client's
/// TLS certificate against consumer credentials. This operates on top of the
/// server's CA chain verification — the TLS handshake already validates the
/// certificate chain. This plugin provides an additional consumer-scoped
/// identity check.
///
/// # Plugin Configuration
///
/// ```json
/// {
///   "cert_field": "subject_cn"   // which cert field to use as identity
/// }
/// ```
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
}

impl MtlsAuth {
    pub fn new(config: &Value) -> Self {
        let cert_field = config["cert_field"]
            .as_str()
            .and_then(CertField::from_str)
            .unwrap_or(CertField::SubjectCn);

        Self { cert_field }
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
