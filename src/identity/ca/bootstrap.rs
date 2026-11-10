//! First-run helper that mints a self-signed root for development setups.
//!
//! Production deployments MUST NOT use it: supply file-based SVID material
//! (`FERRUM_GATEWAY_SVID_*`) or use `FERRUM_MESH_CA_BACKEND=spire`. This helper
//! exists only to make local labs and integration tests self-contained.
//!
//! Two safety gates are enforced before generating anything:
//!
//! 1. `FERRUM_MESH_PRODUCTION_MODE=true` — unconditional refusal. We do not
//!    emit a self-signed root in production.
//! 2. `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` — explicit opt-in. Anything else is
//!    treated as "operator did not ask for a bootstrap" and we refuse.
//!
//! Combining both gates means the helper is unreachable unless the operator
//! has affirmatively asked for it AND not declared production mode.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SerialNumber,
};
use std::env;
use tracing::{info, warn};

use super::{CaError, random_positive_serial_bytes};
use crate::identity::spiffe::TrustDomain;

/// Bootstrap configuration.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub trust_domain: TrustDomain,
    /// Common name for the root certificate. Defaults to a label derived
    /// from the trust domain.
    pub common_name: Option<String>,
    /// Lifetime of the bootstrapped root in days. Defaults to 365.
    pub lifetime_days: u32,
}

impl BootstrapConfig {
    pub fn new(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            common_name: None,
            lifetime_days: 365,
        }
    }
}

/// Output of [`bootstrap_dev_root`].
pub struct BootstrappedRoot {
    pub trust_domain: TrustDomain,
    pub root_cert_pem: String,
    pub root_key_pem: String,
}

/// Canonical read of the `FERRUM_MESH_CA_BOOTSTRAP_DEV` dev opt-in.
///
/// Every reader of the opt-in ([`bootstrap_allowed`], [`bootstrap_dev_root`],
/// and the `EnvConfig` validation gate that lets `validate` agree with
/// startup) goes through this one function, so the accepted spelling cannot
/// drift between them. It uses the identity guardrail truthy rule
/// ([`crate::identity::parse_guardrail_flag`]): `true`/`1` opt in; an unset,
/// blank, `false`/`0` or invalid value leaves the bootstrap refused (an invalid
/// value also fails `EnvConfig` validation). This does **not** consult
/// [`crate::identity::production_mode`]; callers check that guardrail first.
pub fn dev_bootstrap_opted_in() -> bool {
    crate::identity::guardrail_opt_in(
        "FERRUM_MESH_CA_BOOTSTRAP_DEV",
        env::var("FERRUM_MESH_CA_BOOTSTRAP_DEV"),
    )
}

/// Returns `true` iff both gates allow bootstrap to run.
pub fn bootstrap_allowed() -> bool {
    if crate::identity::production_mode() {
        return false;
    }
    dev_bootstrap_opted_in()
}

/// Generate a self-signed root suitable for use as the internal CA's
/// trust anchor. Caller persists the result to disk if it wants to.
///
/// Refuses to run unless [`bootstrap_allowed`] returns `true`.
pub fn bootstrap_dev_root(config: BootstrapConfig) -> Result<BootstrappedRoot, CaError> {
    if crate::identity::production_mode() {
        return Err(CaError::Config(
            "FERRUM_MESH_PRODUCTION_MODE=true — refusing to bootstrap a self-signed root. \
             Provide file-based SVID material (FERRUM_GATEWAY_SVID_*) or use \
             FERRUM_MESH_CA_BACKEND=spire."
                .to_string(),
        ));
    }
    if !dev_bootstrap_opted_in() {
        return Err(CaError::Config(
            "FERRUM_MESH_CA_BOOTSTRAP_DEV is not set to true or 1 — bootstrap refused. \
             Set the env var only in dev/test environments."
                .to_string(),
        ));
    }

    let cn = config
        .common_name
        .clone()
        .unwrap_or_else(|| format!("ferrum-mesh-root-{}", config.trust_domain));

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn.clone());
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(config.lifetime_days as i64);

    // 64-bit positive random serial via ring.
    let serial_bytes = random_positive_serial_bytes()?;
    params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CaError::Internal(format!("keypair gen failed: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CaError::Internal(format!("self-sign failed: {e}")))?;

    warn!(
        trust_domain = %config.trust_domain,
        common_name = %cn,
        "FERRUM_MESH_CA_BOOTSTRAP_DEV=true — generated self-signed mesh root \
         (DEV-ONLY, never use in production)"
    );

    info!(
        "bootstrapped self-signed root for trust domain '{}' (CN={}, lifetime={}d)",
        config.trust_domain, cn, config.lifetime_days
    );

    Ok(BootstrappedRoot {
        trust_domain: config.trust_domain,
        root_cert_pem: cert.pem(),
        root_key_pem: key_pair.serialize_pem(),
    })
}
