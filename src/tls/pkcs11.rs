//! PKCS#11-backed TLS private key signing.
//!
//! The configured key never leaves the token. rustls hands us the handshake
//! message, and the token performs the hash-and-sign operation for the selected
//! RSA signature scheme.
//!
//! Before any certified key is published to a rustls resolver, the selected
//! token key is *proved* to pair with the configured leaf certificate — see
//! `prove_leaf_pairing`. Without that proof a selector typo or a half-finished
//! HSM/certificate rotation is accepted at config load and only fails later, on
//! every client handshake, taking a listener or a backend mTLS identity out of
//! service.

use std::fmt;
use std::sync::Arc;

use crate::fips::backend::rand::{SecureRandom, SystemRandom};
use crate::fips::backend::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use anyhow::{Context, anyhow, bail};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::{AuthPin, Ulong};
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer, alg_id};
use rustls::sign::{CertifiedKey, Signer, SigningKey, public_key_to_spki};
use rustls::{Error as RustlsError, InconsistentKeys, SignatureAlgorithm, SignatureScheme};
use tracing::{debug, warn};
use x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION;
use zeroize::Zeroizing;

use crate::config::conf_file::resolve_ferrum_var;
use crate::tls::source::CertSourceUri;

const MODULE_PATH_ENV: &str = "FERRUM_PKCS11_MODULE_PATH";
const MODULE_ALLOWED_PATHS_ENV: &str = "FERRUM_PKCS11_MODULE_ALLOWED_PATHS";
const DEFAULT_KEY_TYPE: &str = "rsa";

/// Largest RSA modulus (in bytes, leading zeros stripped) accepted when
/// reconstructing the token public key. 8192-bit is both the largest modulus
/// `ring` will verify on the challenge path and a bound that keeps the DER
/// reconstruction from allocating on an implausible token attribute.
const MAX_RSA_MODULUS_BYTES: usize = 1024;

/// Largest RSA public exponent accepted when reconstructing the token public
/// key. Real exponents are 3 bytes (65537); 16 leaves generous headroom.
const MAX_RSA_EXPONENT_BYTES: usize = 16;

/// Maximum DER size of the PKCS#1 `RSAPublicKey` carried in an accepted leaf
/// certificate. This covers the bounded modulus and exponent above plus their
/// INTEGER and SEQUENCE headers.
const MAX_RSA_PUBLIC_KEY_DER_BYTES: usize = MAX_RSA_MODULUS_BYTES + MAX_RSA_EXPONENT_BYTES + 32;

/// Size of the random challenge signed by the token when the SPKI comparison
/// is unavailable. Fresh per attempt so a captured signature from an earlier
/// configuration cannot stand in for a live proof.
const KEY_MATCH_CHALLENGE_BYTES: usize = 32;

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
    let allowed = var_resolver(MODULE_ALLOWED_PATHS_ENV);
    let supplied = ["module", "module_path", "module_env"]
        .iter()
        .any(|option| uri.options.contains_key(*option));
    if supplied && allowed.is_none() {
        bail!(
            "PKCS#11 module options require {}; omit them to use {}",
            MODULE_ALLOWED_PATHS_ENV,
            MODULE_PATH_ENV
        );
    }
    let module = if let Some(module) = uri
        .options
        .get("module")
        .or_else(|| uri.options.get("module_path"))
    {
        module.clone()
    } else if let Some(module_env) = uri.options.get("module_env") {
        validate_var_name(module_env, "module_env")?;
        var_resolver(module_env).ok_or_else(|| {
            anyhow!(
                "PKCS#11 module_env is not set; check {}",
                MODULE_ALLOWED_PATHS_ENV
            )
        })?
    } else {
        module_fallback().ok_or_else(|| anyhow!("PKCS#11 requires {}", MODULE_PATH_ENV))?
    };
    let module = canonical_module_policy_path(&module)?;
    if !module.is_file() {
        bail!(
            "PKCS#11 module must be a file; check {}",
            MODULE_ALLOWED_PATHS_ENV
        );
    }
    if let Some(allowed) = allowed {
        let mut admitted = false;
        // Validate every entry, even after a match: malformed policy fails closed.
        for entry in allowed.split(',') {
            let entry = canonical_module_policy_path(entry)?;
            admitted |= module == entry || (entry.is_dir() && module.starts_with(&entry));
        }
        if !admitted {
            bail!("PKCS#11 module is outside {}", MODULE_ALLOWED_PATHS_ENV);
        }
    }
    module
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow!("PKCS#11 module path must be UTF-8"))
}

fn canonical_module_policy_path(value: &str) -> anyhow::Result<std::path::PathBuf> {
    let path = std::path::Path::new(value.trim());
    if !path.is_absolute() {
        bail!(
            "PKCS#11 module paths must be absolute; check {}",
            MODULE_ALLOWED_PATHS_ENV
        );
    }
    // Do not disclose configuration-supplied paths or environment values in errors.
    path.canonicalize().map_err(|_| {
        anyhow!(
            "PKCS#11 module paths must exist and resolve; check {}",
            MODULE_ALLOWED_PATHS_ENV
        )
    })
}

/// Check node-local module policy at admission without opening a native library.
/// Runtime key construction repeats this check immediately before loading it.
pub fn validate_module_source_uri(uri: &CertSourceUri) -> anyhow::Result<()> {
    resolve_module_path(
        uri,
        || resolve_ferrum_var(MODULE_PATH_ENV),
        &resolve_ferrum_var,
    )
    .map(|_| ())
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
    /// RFC 5280 SubjectPublicKeyInfo reconstructed from the token's public RSA
    /// attributes, when the token exposes them. `None` means the token withheld
    /// `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT` on the selected private-key object,
    /// and the pairing has to be proved by signature challenge instead.
    public_key_spki: Option<Arc<Vec<u8>>>,
}

impl fmt::Debug for Pkcs11SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11SigningKey")
            .field("config", &self.config)
            .field("public_key_spki_available", &self.public_key_spki.is_some())
            .finish_non_exhaustive()
    }
}

impl Pkcs11SigningKey {
    fn from_uri(uri: &CertSourceUri) -> anyhow::Result<Self> {
        let config = Pkcs11KeyConfig::parse(uri)?;
        let pkcs11 = Pkcs11::new(&config.module_path)
            .with_context(|| format!("failed to load PKCS#11 module '{}'", config.module_path))?;
        initialize_pkcs11(&pkcs11, &config.module_path)?;
        let mut signing_key = Self {
            config,
            pkcs11,
            public_key_spki: None,
        };
        signing_key.public_key_spki = signing_key.load_public_key_spki()?.map(Arc::new);
        Ok(signing_key)
    }

    /// Resolve the token key and, when the token permits it, reconstruct its
    /// SubjectPublicKeyInfo from the selected private-key object.
    ///
    /// Resolving the private key keeps the pre-existing availability and
    /// ambiguity checks: an absent or multiply-matched selector is still an
    /// error before anything is published. Only the public-attribute read is
    /// best effort — `Ok(None)` means "prove the pairing another way", never
    /// "skip the proof".
    ///
    /// A separately selected `CKO_PUBLIC_KEY` is deliberately not trusted
    /// here. Matching label/id attributes are metadata, not cryptographic proof
    /// that a public object pairs with the selected private key. If the private
    /// object withholds its public attributes, the fresh sign-and-verify
    /// challenge against the leaf certificate is the proof.
    fn load_public_key_spki(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let session = self.open_session()?;
        self.login_if_configured(&session)?;
        let private_key = self.find_private_key(&session)?;
        Ok(self.rsa_spki_from_object(&session, private_key))
    }

    /// Reconstruct the SPKI of `object` from its RSA public attributes.
    ///
    /// Returns `None` whenever the token does not give us usable material:
    /// a failed read, a withheld attribute, or bytes that do not encode. Every
    /// such case falls through to the signature challenge, which is an equally
    /// sound proof, so a quirky token degrades in capability and never in
    /// enforcement. Diagnostics carry only the configured selector.
    fn rsa_spki_from_object(&self, session: &Session, object: ObjectHandle) -> Option<Vec<u8>> {
        let attribute_info = match session.get_attribute_info(
            object,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        ) {
            Ok(attribute_info) => attribute_info,
            Err(error) => {
                debug!(
                    selector = %self.config.selector(),
                    error = %error,
                    "PKCS#11 token did not describe its RSA public attributes; proving the certificate pairing by signature challenge instead"
                );
                return None;
            }
        };
        let lengths_are_bounded = matches!(
            attribute_info.as_slice(),
            [
                AttributeInfo::Available(modulus_len),
                AttributeInfo::Available(public_exponent_len)
            ] if *modulus_len <= MAX_RSA_MODULUS_BYTES
                && *public_exponent_len <= MAX_RSA_EXPONENT_BYTES
        );
        if !lengths_are_bounded {
            debug!(
                selector = %self.config.selector(),
                "PKCS#11 token withheld or reported out-of-bounds RSA public attributes; proving the certificate pairing by signature challenge instead"
            );
            return None;
        }

        let attributes = match session.get_attributes(
            object,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        ) {
            Ok(attributes) => attributes,
            Err(error) => {
                debug!(
                    selector = %self.config.selector(),
                    error = %error,
                    "PKCS#11 token did not return RSA public attributes; proving the certificate pairing by signature challenge instead"
                );
                return None;
            }
        };

        let mut modulus: Option<Zeroizing<Vec<u8>>> = None;
        let mut public_exponent: Option<Zeroizing<Vec<u8>>> = None;
        for attribute in attributes {
            match attribute {
                Attribute::Modulus(value) => modulus = Some(Zeroizing::new(value)),
                Attribute::PublicExponent(value) => public_exponent = Some(Zeroizing::new(value)),
                _ => {}
            }
        }

        let (Some(modulus), Some(public_exponent)) = (modulus, public_exponent) else {
            debug!(
                selector = %self.config.selector(),
                "PKCS#11 token withheld the RSA public attributes; proving the certificate pairing by signature challenge instead"
            );
            return None;
        };

        match rsa_spki_der(&modulus, &public_exponent) {
            Ok(spki) => Some(spki),
            Err(error) => {
                warn!(
                    selector = %self.config.selector(),
                    error = %error,
                    "PKCS#11 token returned RSA public attributes that could not be encoded; proving the certificate pairing by signature challenge instead"
                );
                None
            }
        }
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

        let objects = session.iter_objects(&template).with_context(|| {
            format!(
                "failed to start PKCS#11 private-key search for {}",
                self.config.selector()
            )
        })?;
        // Only zero, one, or multiple matters. Stop after two so a broken
        // token cannot make ambiguity detection allocate one handle per match.
        let mut matches = objects
            .take(2)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| {
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
            _ => bail!(
                "multiple PKCS#11 RSA private keys matched {}; refine the selector with ?label= or ?id_hex=",
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

    /// Hand rustls the token's SubjectPublicKeyInfo when we have it, so
    /// [`CertifiedKey::keys_match`] can compare it against the leaf
    /// certificate. Returning `None` is what makes `keys_match` report
    /// [`InconsistentKeys::Unknown`], which is the signal to fall back to the
    /// signature challenge — never a reason to skip the check.
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.public_key_spki
            .as_ref()
            .map(|spki| SubjectPublicKeyInfoDer::from(spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

/// Prove that the selected token key and the configured leaf certificate are a
/// pair, before the certified key reaches any rustls resolver.
///
/// Preferred path is an SPKI comparison against the token's own public
/// attributes. When the token withholds them, the token signs a fresh random
/// challenge that must verify under the leaf certificate's public key — a
/// bounded, single-signature proof of possession.
fn prove_leaf_pairing(certified_key: &CertifiedKey, key: &Pkcs11SigningKey) -> anyhow::Result<()> {
    match certified_key.keys_match() {
        Ok(()) => {
            debug!(
                source = %key.config.source_id,
                selector = %key.config.selector(),
                "PKCS#11 token public key matches the configured leaf certificate"
            );
            Ok(())
        }
        Err(RustlsError::InconsistentKeys(InconsistentKeys::KeyMismatch)) => {
            Err(leaf_mismatch_error(key))
        }
        Err(RustlsError::InconsistentKeys(InconsistentKeys::Unknown)) => {
            let leaf = match certified_key.end_entity_cert() {
                Ok(leaf) => leaf,
                Err(error) => bail!(
                    "PKCS#11 TLS key source '{}' has no leaf certificate to match the token key against: {}",
                    key.config.source_id,
                    error
                ),
            };
            prove_leaf_pairing_by_challenge(key, leaf)
        }
        Err(error) => Err(anyhow!(
            "failed to compare the PKCS#11 token key for {} against the configured leaf certificate: {}",
            key.config.selector(),
            error
        )),
    }
}

fn leaf_mismatch_error(key: &Pkcs11SigningKey) -> anyhow::Error {
    anyhow!(
        "PKCS#11 TLS key source '{}' selects a token key ({}) whose public key does not match the configured leaf certificate; correct the selector or the certificate before this identity can be used",
        key.config.source_id,
        key.config.selector()
    )
}

/// Sign-and-verify proof of possession, used when the token will not disclose
/// its RSA public attributes.
///
/// One signature over `KEY_MATCH_CHALLENGE_BYTES` of fresh randomness, verified
/// with RSA PKCS#1 v1.5 SHA-256 under the leaf certificate's public key. The
/// challenge and the resulting signature never reach a log or an error: a
/// failure reports only the configured source and selector.
fn prove_leaf_pairing_by_challenge(
    key: &Pkcs11SigningKey,
    leaf: &CertificateDer<'_>,
) -> anyhow::Result<()> {
    let leaf_public_key = match leaf_rsa_public_key_der(leaf) {
        Ok(public_key) => public_key,
        Err(error) => bail!(
            "PKCS#11 TLS key source '{}' cannot be matched against the configured leaf certificate: {}",
            key.config.source_id,
            error
        ),
    };

    let mut challenge = [0u8; KEY_MATCH_CHALLENGE_BYTES];
    if SystemRandom::new().fill(&mut challenge).is_err() {
        bail!(
            "failed to generate a PKCS#11 certificate-pairing challenge for {}",
            key.config.selector()
        );
    }

    let signature = key.sign_with_scheme(Pkcs11SignatureScheme::RsaPkcs1Sha256, &challenge)?;

    let verified = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &leaf_public_key)
        .verify(&challenge, &signature)
        .is_ok();
    if !verified {
        bail!(
            "PKCS#11 TLS key source '{}' selects a token key ({}) that did not produce a signature verifiable under the configured leaf certificate; the token key and the certificate are not a pair (this proof also requires an RSA key of 2048-8192 bits)",
            key.config.source_id,
            key.config.selector()
        );
    }

    debug!(
        source = %key.config.source_id,
        selector = %key.config.selector(),
        "PKCS#11 token key proved possession of the configured leaf certificate public key"
    );
    Ok(())
}

/// Extract the DER `RSAPublicKey` bit-string contents from a leaf certificate.
///
/// Errors describe the certificate only in structural terms; they never echo
/// certificate or key bytes.
pub fn leaf_rsa_public_key_der(leaf: &CertificateDer<'_>) -> anyhow::Result<Vec<u8>> {
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| anyhow!("the leaf certificate is not parseable X.509 DER"))?;
    let spki = certificate.public_key();
    if spki.algorithm.algorithm != OID_PKCS1_RSAENCRYPTION {
        bail!("the leaf certificate does not carry an RSA public key");
    }
    if spki.subject_public_key.unused_bits != 0 {
        bail!("the leaf certificate public key bit string is malformed");
    }
    let public_key = spki.subject_public_key.data.as_ref();
    if public_key.len() > MAX_RSA_PUBLIC_KEY_DER_BYTES {
        bail!("the leaf certificate RSA public key is larger than the supported maximum");
    }
    Ok(public_key.to_vec())
}

/// Encode an RFC 5280 SubjectPublicKeyInfo for the RSA public key described by
/// `modulus` and `public_exponent` (unsigned big-endian, as PKCS#11 returns
/// them).
pub fn rsa_spki_der(modulus: &[u8], public_exponent: &[u8]) -> anyhow::Result<Vec<u8>> {
    let public_key = rsa_public_key_der(modulus, public_exponent)?;
    Ok(public_key_to_spki(&alg_id::RSA_ENCRYPTION, public_key)
        .as_ref()
        .to_vec())
}

/// Encode the PKCS#1 `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
/// publicExponent INTEGER }` structure.
pub fn rsa_public_key_der(modulus: &[u8], public_exponent: &[u8]) -> anyhow::Result<Vec<u8>> {
    if modulus.len() > MAX_RSA_MODULUS_BYTES {
        bail!(
            "RSA modulus is larger than the supported maximum of {} bytes",
            MAX_RSA_MODULUS_BYTES
        );
    }
    if public_exponent.len() > MAX_RSA_EXPONENT_BYTES {
        bail!(
            "RSA public exponent is larger than the supported maximum of {} bytes",
            MAX_RSA_EXPONENT_BYTES
        );
    }

    let mut contents = Vec::new();
    der_unsigned_integer(modulus, "RSA modulus", &mut contents)?;
    der_unsigned_integer(public_exponent, "RSA public exponent", &mut contents)?;

    let mut encoded = vec![0x30];
    der_length(contents.len(), &mut encoded)?;
    encoded.extend_from_slice(&contents);
    Ok(encoded)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn der_length(length: usize, out: &mut Vec<u8>) -> anyhow::Result<()> {
    if length < 0x80 {
        // A length below 0x80 always fits the short form's single byte.
        out.push(length as u8);
        return Ok(());
    }
    let be = length.to_be_bytes();
    let significant = strip_leading_zeros(&be);
    if significant.len() > 4 {
        bail!("DER length {} is too large to encode", length);
    }
    // `significant.len()` is 1..=4 here, so the long-form header byte fits.
    out.push(0x80 | (significant.len() as u8));
    out.extend_from_slice(significant);
    Ok(())
}

fn der_unsigned_integer(value: &[u8], label: &str, out: &mut Vec<u8>) -> anyhow::Result<()> {
    let trimmed = strip_leading_zeros(value);
    if trimmed.is_empty() {
        bail!("{label} is empty or zero");
    }
    // DER INTEGERs are signed, so a high bit in the first byte needs a leading
    // zero to keep the value positive.
    let needs_pad = trimmed[0] & 0x80 != 0;
    out.push(0x02);
    der_length(trimmed.len() + usize::from(needs_pad), out)?;
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    Ok(())
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

/// Build the certified key for `cert_chain`, refusing to return one unless the
/// token key is proved to pair with the leaf certificate.
///
/// Callers publish the result to a frontend/Admin `ResolvesServerCert` or to a
/// backend `ResolvesClientCert`, so the proof has to happen here rather than at
/// first handshake. On failure the caller propagates the error and the
/// surrounding reload path keeps the previous known-good material.
pub fn certified_key_from_uri(
    cert_chain: Vec<CertificateDer<'static>>,
    uri: &CertSourceUri,
) -> anyhow::Result<CertifiedKey> {
    let signing_key = Arc::new(Pkcs11SigningKey::from_uri(uri)?);
    let certified_key = CertifiedKey::new(cert_chain, signing_key.clone());
    prove_leaf_pairing(&certified_key, &signing_key)?;
    Ok(certified_key)
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
        let directory = tempfile::tempdir().expect("module directory");
        let module = directory.path().join("module.so");
        std::fs::write(&module, []).expect("inert module fixture");
        let module = module.canonicalize().expect("canonical fixture");
        let module = module.to_str().expect("UTF-8 fixture");
        let raw = raw
            .replace("/usr/lib/softhsm/libsofthsm2.so", module)
            .replace("/usr/lib/pkcs11.so", module);
        let uri = pkcs11_uri(&raw);
        Pkcs11KeyConfig::parse_with_resolvers(
            &uri,
            || None,
            |name| match name {
                "FERRUM_PKCS11_PIN" => Some("123456".to_string()),
                "FERRUM_PKCS11_MODULE_FROM_ENV" => Some(module.to_string()),
                MODULE_ALLOWED_PATHS_ENV => Some(module.to_string()),
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
        assert!(config.module_path.ends_with("module.so"));
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
        assert!(config.module_path.ends_with("module.so"));
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
