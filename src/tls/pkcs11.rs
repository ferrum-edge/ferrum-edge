//! PKCS#11-backed TLS private key signing.
//!
//! The configured key never leaves the token. rustls hands us the handshake
//! message, and the token performs the hash-and-sign operation for the selected
//! RSA signature scheme.

use std::fmt;

use anyhow::{Context, anyhow, bail};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::{AuthPin, Ulong};
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};
use zeroize::Zeroizing;

use crate::config::conf_file::resolve_ferrum_var;
use crate::tls::source::CertSourceUri;

const MODULE_PATH_ENV: &str = "FERRUM_PKCS11_MODULE_PATH";
const DEFAULT_KEY_TYPE: &str = "rsa";

#[derive(Clone)]
struct Pkcs11KeyConfig {
    source_id: String,
    module_path: String,
    slot: Option<u64>,
    label: Option<String>,
    id: Option<Vec<u8>>,
    pin: Option<Zeroizing<String>>,
}

impl fmt::Debug for Pkcs11KeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11KeyConfig")
            .field("source_id", &self.source_id)
            .field("module_path", &self.module_path)
            .field("slot", &self.slot)
            .field("label", &self.label)
            .field("id_hex", &self.id.as_ref().map(hex::encode))
            .field("pin", &self.pin.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Pkcs11KeyConfig {
    fn parse(uri: &CertSourceUri) -> anyhow::Result<Self> {
        Self::parse_with_resolvers(
            uri,
            || resolve_ferrum_var(MODULE_PATH_ENV),
            resolve_ferrum_var,
        )
    }

    fn parse_with_resolvers<M, R>(
        uri: &CertSourceUri,
        module_fallback: M,
        var_resolver: R,
    ) -> anyhow::Result<Self>
    where
        M: FnOnce() -> Option<String>,
        R: Fn(&str) -> Option<String>,
    {
        let source_id = uri.source_id();
        let key_type = uri
            .options
            .get("key_type")
            .or_else(|| uri.options.get("type"))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_KEY_TYPE);
        if !key_type.eq_ignore_ascii_case(DEFAULT_KEY_TYPE) {
            bail!(
                "PKCS#11 TLS key source '{}' requested key_type='{}'; only RSA keys are supported",
                source_id,
                key_type
            );
        }

        let module_path = resolve_module_path(uri, module_fallback, &var_resolver)?;
        let slot = parse_slot(uri)?;
        let label = parse_label(uri)?;
        let id = parse_id_hex(uri)?;
        if label.is_none() && id.is_none() {
            bail!(
                "PKCS#11 TLS key source '{}' must set a label in the URI path or ?label=, or set ?id_hex=",
                source_id
            );
        }

        let pin = match uri.options.get("pin_env") {
            Some(pin_env) => {
                validate_var_name(pin_env, "pin_env")?;
                let pin = var_resolver(pin_env).ok_or_else(|| {
                    anyhow!(
                        "PKCS#11 TLS key source '{}' references pin_env='{}' but it is not set",
                        source_id,
                        pin_env
                    )
                })?;
                Some(Zeroizing::new(pin))
            }
            None => None,
        };

        Ok(Self {
            source_id,
            module_path,
            slot,
            label,
            id,
            pin,
        })
    }

    fn selector(&self) -> String {
        match (&self.label, &self.id) {
            (Some(label), Some(id)) => {
                format!("label='{}', id_hex='{}'", label, hex::encode(id))
            }
            (Some(label), None) => format!("label='{label}'"),
            (None, Some(id)) => format!("id_hex='{}'", hex::encode(id)),
            (None, None) => "unconfigured selector".to_string(),
        }
    }
}

fn resolve_module_path<M, R>(
    uri: &CertSourceUri,
    module_fallback: M,
    var_resolver: &R,
) -> anyhow::Result<String>
where
    M: FnOnce() -> Option<String>,
    R: Fn(&str) -> Option<String>,
{
    if let Some(module) = uri
        .options
        .get("module")
        .or_else(|| uri.options.get("module_path"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return Ok(module.to_string());
    }

    if let Some(module_env) = uri.options.get("module_env") {
        validate_var_name(module_env, "module_env")?;
        return var_resolver(module_env).ok_or_else(|| {
            anyhow!(
                "PKCS#11 TLS key source '{}' references module_env='{}' but it is not set",
                uri.source_id(),
                module_env
            )
        });
    }

    module_fallback().ok_or_else(|| {
        anyhow!(
            "PKCS#11 TLS key source '{}' must set ?module= or ?module_env=, or configure {}",
            uri.source_id(),
            MODULE_PATH_ENV
        )
    })
}

fn parse_slot(uri: &CertSourceUri) -> anyhow::Result<Option<u64>> {
    uri.options
        .get("slot")
        .or_else(|| uri.options.get("slot_id"))
        .map(|raw| {
            raw.trim().parse::<u64>().with_context(|| {
                format!(
                    "PKCS#11 TLS key source '{}' has invalid slot id '{}'",
                    uri.source_id(),
                    raw
                )
            })
        })
        .transpose()
}

fn parse_label(uri: &CertSourceUri) -> anyhow::Result<Option<String>> {
    let label = uri
        .options
        .get("label")
        .map(String::as_str)
        .unwrap_or(uri.identifier.as_str())
        .trim();
    if label.is_empty() {
        return Ok(None);
    }
    let decoded = percent_encoding::percent_decode_str(label)
        .decode_utf8()
        .with_context(|| {
            format!(
                "PKCS#11 TLS key source '{}' has a label that is not valid UTF-8",
                uri.source_id()
            )
        })?;
    Ok(Some(decoded.into_owned()))
}

fn parse_id_hex(uri: &CertSourceUri) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(raw) = uri.options.get("id_hex").or_else(|| uri.options.get("id")) else {
        return Ok(None);
    };
    let compact = raw
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != ':')
        .collect::<String>();
    if compact.is_empty() {
        bail!(
            "PKCS#11 TLS key source '{}' has an empty id_hex selector",
            uri.source_id()
        );
    }
    hex::decode(&compact)
        .with_context(|| {
            format!(
                "PKCS#11 TLS key source '{}' has invalid hex in id_hex",
                uri.source_id()
            )
        })
        .map(Some)
}

fn validate_var_name(value: &str, option: &str) -> anyhow::Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        bail!("PKCS#11 {option} option must not be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        bail!("PKCS#11 {option} option must be an environment variable name");
    }
    if chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric())) {
        bail!("PKCS#11 {option} option must be an environment variable name");
    }
    Ok(())
}

#[derive(Clone)]
pub struct Pkcs11SigningKey {
    config: Pkcs11KeyConfig,
    pkcs11: Pkcs11,
}

impl fmt::Debug for Pkcs11SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11SigningKey")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Pkcs11SigningKey {
    fn from_uri(uri: &CertSourceUri) -> anyhow::Result<Self> {
        let config = Pkcs11KeyConfig::parse(uri)?;
        let pkcs11 = Pkcs11::new(&config.module_path)
            .with_context(|| format!("failed to load PKCS#11 module '{}'", config.module_path))?;
        initialize_pkcs11(&pkcs11, &config.module_path)?;
        let signing_key = Self { config, pkcs11 };
        signing_key.validate_key_available()?;
        Ok(signing_key)
    }

    fn validate_key_available(&self) -> anyhow::Result<()> {
        let session = self.open_session()?;
        self.login_if_configured(&session)?;
        self.find_private_key(&session)?;
        Ok(())
    }

    fn sign_with_scheme(
        &self,
        scheme: Pkcs11SignatureScheme,
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let session = self.open_session()?;
        self.login_if_configured(&session)?;
        let key = self.find_private_key(&session)?;
        session
            .sign(&scheme.mechanism(), key, message)
            .with_context(|| {
                format!(
                    "PKCS#11 sign operation failed for {} using {:?}",
                    self.config.selector(),
                    scheme.signature_scheme()
                )
            })
    }

    fn open_session(&self) -> anyhow::Result<Session> {
        let slot = self.selected_slot()?;
        self.pkcs11.open_ro_session(slot).with_context(|| {
            format!(
                "failed to open PKCS#11 read-only session on slot {}",
                slot.id()
            )
        })
    }

    fn selected_slot(&self) -> anyhow::Result<Slot> {
        if let Some(slot_id) = self.config.slot {
            return Slot::try_from(slot_id)
                .with_context(|| format!("invalid PKCS#11 slot id {slot_id}"));
        }
        let slots = self
            .pkcs11
            .get_slots_with_token()
            .context("failed to list PKCS#11 slots with tokens")?;
        slots
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("PKCS#11 module reported no slots with tokens"))
    }

    fn login_if_configured(&self, session: &Session) -> anyhow::Result<()> {
        let Some(pin) = self.config.pin.as_ref() else {
            return Ok(());
        };
        let auth_pin = AuthPin::new(pin.as_str().to_string().into());
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) => Ok(()),
            Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
            Err(error) => Err(anyhow!(
                "failed to log in to PKCS#11 token for {}: {}",
                self.config.selector(),
                error
            )),
        }
    }

    fn find_private_key(&self, session: &Session) -> anyhow::Result<ObjectHandle> {
        let mut template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
        ];
        if let Some(id) = self.config.id.as_ref() {
            template.push(Attribute::Id(id.clone()));
        }
        if let Some(label) = self.config.label.as_ref() {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }

        let mut matches = session.find_objects(&template).with_context(|| {
            format!(
                "failed to search PKCS#11 private keys for {}",
                self.config.selector()
            )
        })?;
        match matches.len() {
            0 => bail!(
                "no PKCS#11 RSA private key matched {}",
                self.config.selector()
            ),
            1 => Ok(matches.remove(0)),
            count => bail!(
                "{} PKCS#11 RSA private keys matched {}; refine the selector with ?label= or ?id_hex=",
                count,
                self.config.selector()
            ),
        }
    }
}

fn initialize_pkcs11(pkcs11: &Pkcs11, module_path: &str) -> anyhow::Result<()> {
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => Ok(()),
        Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(()),
        Err(error) => Err(anyhow!(
            "failed to initialize PKCS#11 module '{}': {}",
            module_path,
            error
        )),
    }
}

#[derive(Debug, Clone, Copy)]
enum Pkcs11SignatureScheme {
    RsaPssSha512,
    RsaPssSha384,
    RsaPssSha256,
    RsaPkcs1Sha512,
    RsaPkcs1Sha384,
    RsaPkcs1Sha256,
}

impl Pkcs11SignatureScheme {
    fn from_signature_scheme(scheme: SignatureScheme) -> Option<Self> {
        match scheme {
            SignatureScheme::RSA_PSS_SHA512 => Some(Self::RsaPssSha512),
            SignatureScheme::RSA_PSS_SHA384 => Some(Self::RsaPssSha384),
            SignatureScheme::RSA_PSS_SHA256 => Some(Self::RsaPssSha256),
            SignatureScheme::RSA_PKCS1_SHA512 => Some(Self::RsaPkcs1Sha512),
            SignatureScheme::RSA_PKCS1_SHA384 => Some(Self::RsaPkcs1Sha384),
            SignatureScheme::RSA_PKCS1_SHA256 => Some(Self::RsaPkcs1Sha256),
            _ => None,
        }
    }

    fn signature_scheme(self) -> SignatureScheme {
        match self {
            Self::RsaPssSha512 => SignatureScheme::RSA_PSS_SHA512,
            Self::RsaPssSha384 => SignatureScheme::RSA_PSS_SHA384,
            Self::RsaPssSha256 => SignatureScheme::RSA_PSS_SHA256,
            Self::RsaPkcs1Sha512 => SignatureScheme::RSA_PKCS1_SHA512,
            Self::RsaPkcs1Sha384 => SignatureScheme::RSA_PKCS1_SHA384,
            Self::RsaPkcs1Sha256 => SignatureScheme::RSA_PKCS1_SHA256,
        }
    }

    fn mechanism(self) -> Mechanism<'static> {
        match self {
            Self::RsaPssSha512 => Mechanism::Sha512RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA512,
                mgf: PkcsMgfType::MGF1_SHA512,
                s_len: Ulong::new(64),
            }),
            Self::RsaPssSha384 => Mechanism::Sha384RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA384,
                mgf: PkcsMgfType::MGF1_SHA384,
                s_len: Ulong::new(48),
            }),
            Self::RsaPssSha256 => Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: Ulong::new(32),
            }),
            Self::RsaPkcs1Sha512 => Mechanism::Sha512RsaPkcs,
            Self::RsaPkcs1Sha384 => Mechanism::Sha384RsaPkcs,
            Self::RsaPkcs1Sha256 => Mechanism::Sha256RsaPkcs,
        }
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        [
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
        .into_iter()
        .find(|scheme| offered.contains(scheme))
        .and_then(Pkcs11SignatureScheme::from_signature_scheme)
        .map(|scheme| {
            Box::new(Pkcs11Signer {
                key: self.clone(),
                scheme,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Clone)]
struct Pkcs11Signer {
    key: Pkcs11SigningKey,
    scheme: Pkcs11SignatureScheme,
}

impl fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("key", &self.key)
            .field("scheme", &self.scheme.signature_scheme())
            .finish()
    }
}

impl Signer for Pkcs11Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        self.key
            .sign_with_scheme(self.scheme, message)
            .map_err(|error| RustlsError::General(format!("PKCS#11 signing failed: {error}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme.signature_scheme()
    }
}

pub fn certified_key_from_uri(
    cert_chain: Vec<CertificateDer<'static>>,
    uri: &CertSourceUri,
) -> anyhow::Result<CertifiedKey> {
    let signing_key = Pkcs11SigningKey::from_uri(uri)?;
    Ok(CertifiedKey::new(
        cert_chain,
        std::sync::Arc::new(signing_key),
    ))
}

pub fn validate_key_source_uri(uri: &CertSourceUri) -> anyhow::Result<()> {
    Pkcs11SigningKey::from_uri(uri).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::source::{CertSource, MaterialKind};

    fn pkcs11_uri(raw: &str) -> CertSourceUri {
        match CertSource::parse(raw.to_string(), MaterialKind::Key) {
            CertSource::Uri(uri) => uri,
            other => panic!("expected PKCS#11 URI, got {other:?}"),
        }
    }

    fn parse_config(raw: &str) -> anyhow::Result<Pkcs11KeyConfig> {
        let uri = pkcs11_uri(raw);
        Pkcs11KeyConfig::parse_with_resolvers(
            &uri,
            || None,
            |name| match name {
                "FERRUM_PKCS11_PIN" => Some("123456".to_string()),
                "FERRUM_PKCS11_MODULE_FROM_ENV" => Some("/usr/lib/pkcs11.so".to_string()),
                _ => None,
            },
        )
    }

    #[test]
    fn parses_label_from_identifier() {
        let config = parse_config(
            "pkcs11://edge-rsa?module=/usr/lib/softhsm/libsofthsm2.so&pin_env=FERRUM_PKCS11_PIN",
        )
        .expect("config parses");
        assert_eq!(config.label.as_deref(), Some("edge-rsa"));
        assert_eq!(config.module_path, "/usr/lib/softhsm/libsofthsm2.so");
        assert!(config.pin.is_some());
        let debug = format!("{config:?}");
        assert!(!debug.contains("123456"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn label_query_overrides_identifier_and_id_hex_is_decoded() {
        let config =
            parse_config("pkcs11://ignored?module=/usr/lib/pkcs11.so&label=edge&id_hex=01:ab cd")
                .expect("config parses");
        assert_eq!(config.label.as_deref(), Some("edge"));
        assert_eq!(config.id.as_deref(), Some([0x01, 0xab, 0xcd].as_slice()));
    }

    #[test]
    fn module_env_can_supply_module_path() {
        let config = parse_config(
            "pkcs11://edge-rsa?module_env=FERRUM_PKCS11_MODULE_FROM_ENV&pin_env=FERRUM_PKCS11_PIN",
        )
        .expect("config parses");
        assert_eq!(config.module_path, "/usr/lib/pkcs11.so");
    }

    #[test]
    fn rejects_non_rsa_key_type() {
        let error = parse_config("pkcs11://edge-ecdsa?module=/usr/lib/pkcs11.so&key_type=ec")
            .expect_err("EC keys are not supported yet");
        assert!(error.to_string().contains("only RSA keys are supported"));
    }

    #[test]
    fn rejects_missing_selector() {
        let error =
            parse_config("pkcs11://?module=/usr/lib/pkcs11.so").expect_err("selector is required");
        assert!(error.to_string().contains("must set a label"));
    }

    #[test]
    fn rejects_missing_module_path() {
        let error =
            parse_config("pkcs11://edge-rsa").expect_err("module path or fallback is required");
        assert!(error.to_string().contains(MODULE_PATH_ENV));
    }

    #[test]
    #[ignore = "requires a configured PKCS#11 token and FERRUM_PKCS11_TEST_KEY_SOURCE"]
    fn signer_loads_configured_token_and_signs() {
        let raw = std::env::var("FERRUM_PKCS11_TEST_KEY_SOURCE")
            .expect("set FERRUM_PKCS11_TEST_KEY_SOURCE to a pkcs11:// key URI");
        let uri = pkcs11_uri(&raw);
        let signing_key = Pkcs11SigningKey::from_uri(&uri).expect("load PKCS#11 signing key");
        let signer = signing_key
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
            .expect("RSA PKCS#1 SHA-256 signer");
        let signature = signer
            .sign(b"ferrum-edge-pkcs11-smoke-test")
            .expect("PKCS#11 sign");
        assert!(!signature.is_empty());
    }
}
