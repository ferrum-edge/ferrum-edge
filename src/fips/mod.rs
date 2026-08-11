//! FIPS 140-2 / 140-3 deployment mode: request surface, fail-closed policy, and
//! the single cryptographic-provider seam.
//!
//! # Scope of this module, honestly stated
//!
//! Ferrum Edge is **not** a validated cryptographic module and is **not**
//! independently FIPS-certified. No configuration of this binary makes it so.
//!
//! This module implements the application-side parts of a FIPS deployment
//! mode:
//!
//! 1. the operator-facing request surface (`--fips-mode`, `FERRUM_FIPS_MODE`,
//!    `FERRUM_FIPS_REQUIRED_PROVIDER`) and its precedence,
//! 2. a **fail-closed** bootstrap that refuses to start, validate, reload, or
//!    publish configuration when FIPS is requested and the build cannot
//!    provide it, and
//! 3. the single seam — [`base_crypto_provider`], [`backend`],
//!    [`any_supported_signing_key`], [`ticketer`], [`cipher_suite`],
//!    [`kx_group`] — through which every Ferrum-owned cryptographic
//!    construction now resolves its implementation.
//!
//! # Build profiles
//!
//! The backend is selected by a **mutually exclusive** cargo-feature pair
//! declared in `Cargo.toml`:
//!
//! | Feature | Backend | [`BUILD_CAPABLE`] |
//! |---|---|---|
//! | `crypto-ring` (default) | `ring` / `rustls/ring` | `false` |
//! | `fips` | `aws-lc-fips-sys` via `aws-lc-rs/fips` and `rustls/fips` | `true` |
//!
//! Selecting both or neither is a compile error, because "additively enable
//! aws-lc" is precisely the mistake that produces a build which *looks*
//! switched while `sqlx-core`, `quinn-proto`, `tonic`, `ldap3`, and
//! `hyper-rustls` still route through their ring arm. Every one of those crates
//! gates its aws-lc arm on the absence of its ring arm.
//!
//! On a `crypto-ring` build, `FERRUM_FIPS_MODE=enforce` fails closed with
//! [`BootstrapError::BuildNotCapable`] rather than degrading into "run anyway
//! with `ring`". On a `fips` build, enforcement additionally requires the
//! module's power-on self-test (`aws_lc_rs::try_fips_mode`) and rustls's own
//! classification of the installed provider; either failing is also fail-closed.
//!
//! `docs/fips.md` records the module boundary, the operating-environment
//! assumptions, the operator verification procedure, and what is deliberately
//! outside the boundary. [`inventory`] is the machine-readable half of that
//! record.
//!
//! # Why the seam exists
//!
//! Before this module, thirteen files each named `rustls::crypto::ring`
//! directly and three more built cipher-suite tables from
//! provider-qualified constants. A provider swap therefore had to be
//! reproduced at ~55 call sites, and a single missed site would have been a
//! silent non-validated fallback on a real traffic path — exactly the failure
//! mode a FIPS mode exists to prevent. Collapsing them onto one function is
//! what makes the swap reviewable rather than a sprawl, and it is independently
//! useful: provider selection is auditable in one place.

pub mod approved;
pub mod inventory;
pub mod keys;
pub mod policy;

use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;

// ── Mutual exclusion ────────────────────────────────────────────────────────
//
// These are the compile-time half of the contract. The resolved *feature graph*
// is checked separately by `.github/scripts/check_fips_feature_policy.py`,
// because a transitive edge can enable `rustls/ring` without this crate's own
// feature list mentioning it.
#[cfg(all(feature = "crypto-ring", feature = "fips"))]
compile_error!(
    "the `crypto-ring` and `fips` features are mutually exclusive: enabling both leaves the \
     non-FIPS `ring` implementation compiled alongside the AWS-LC FIPS implementation, and several \
     dependencies (sqlx-core, quinn-proto, tonic, ldap3, hyper-rustls) select their ring arm \
     whenever it is present. Build with `--no-default-features --features fips` for the FIPS \
     profile. See docs/fips.md."
);

#[cfg(not(any(feature = "crypto-ring", feature = "fips")))]
compile_error!(
    "exactly one cryptographic backend feature must be selected: `crypto-ring` (the default, \
     ordinary non-FIPS build) or `fips` (the AWS-LC FIPS module profile). See docs/fips.md."
);

/// The ring-API-compatible cryptographic backend this build links.
///
/// Ferrum's non-rustls cryptography (randomness, HMAC, digests, AEAD, HKDF,
/// signature verification) imports from here rather than naming a crate
/// directly, so the implementation is one alias rather than a dozen import
/// sites. `aws-lc-rs` is API-compatible with `ring` across these surfaces,
/// which is what makes the alias sufficient.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub use ring as backend;

/// The ring-API-compatible cryptographic backend this build links.
///
/// On a `fips` build this is `aws-lc-rs` bound to `aws-lc-fips-sys`, so every
/// call site that imports from here reaches the selected AWS-LC FIPS module
/// implementation. Whether a deployed artifact falls under an active CMVP
/// certificate is a separate operator-evidence question; see `docs/fips.md`.
#[cfg(feature = "fips")]
pub use aws_lc_rs as backend;

/// Identifier of the validated-module integration Ferrum has selected.
///
/// This names an *integration*, not a certificate: the certificate number,
/// module version, and operating environment are deployment facts the operator
/// establishes and records per `docs/fips.md`. It is the only accepted value of
/// `FERRUM_FIPS_REQUIRED_PROVIDER`, so a future build that changed integrations
/// cannot silently satisfy an existing FIPS deployment contract.
pub const SUPPORTED_PROVIDER_ID: &str = "aws-lc-fips";

/// Provider identifier reported by an ordinary, non-FIPS build.
pub const RING_PROVIDER_ID: &str = "ring";

/// `true` when this build links the AWS-LC FIPS provider profile rather than
/// `ring`.
///
/// Derived from the selected cargo feature, never hand-set: it is `true`
/// exactly when `--features fips` compiled `aws-lc-rs/fips` and `rustls/fips`
/// into this binary. Every enforcement path reads this rather than assuming.
pub const BUILD_CAPABLE: bool = cfg!(feature = "fips");

/// `true` when this build links the AWS-LC FIPS provider profile.
///
/// Function form of [`BUILD_CAPABLE`] for callers — notably external tests —
/// that need the value without embedding a compile-time constant in an
/// assertion.
pub fn build_capable() -> bool {
    BUILD_CAPABLE
}

/// Run the linked module's power-on self-test / approved-mode check.
///
/// On a FIPS build this asks AWS-LC itself whether it is operating in its
/// approved mode; a module whose integrity check or known-answer tests failed
/// reports `Err` here, and Ferrum then refuses to serve. It is deliberately the
/// module's own answer rather than a Ferrum-side inference.
#[cfg(feature = "fips")]
fn module_self_test() -> Result<(), &'static str> {
    backend::try_fips_mode()
}

/// No AWS-LC FIPS module is linked on a `crypto-ring` build, so there is no
/// self-test to have passed. A definite "no", not an optimistic default.
#[cfg(not(feature = "fips"))]
fn module_self_test() -> Result<(), &'static str> {
    Err("no AWS-LC FIPS cryptographic module is linked in this build")
}

/// Requested FIPS posture.
///
/// Resolved as `--fips-mode` (CLI) > `FERRUM_FIPS_MODE` (environment) >
/// `ferrum.conf` > `off`, matching Ferrum's standard precedence. See
/// [`FipsMode::parse`] for the accepted spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FipsMode {
    /// Ordinary operation. No FIPS policy is applied and behaviour is
    /// unchanged from a gateway that has never heard of this module.
    #[default]
    Off,
    /// Fail-closed FIPS operation.
    Enforce,
}

impl FipsMode {
    /// Parse an operator-supplied mode value.
    ///
    /// Accepts `off`/`false`/`disabled` and `enforce`/`true`/`on`. Any other
    /// value is a configuration error rather than a silent downgrade — a
    /// typo'd `FERRUM_FIPS_MODE=enfroce` must not quietly run non-FIPS.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "false" | "0" | "disabled" | "disable" => Ok(Self::Off),
            "enforce" | "true" | "1" | "on" | "enabled" | "enable" => Ok(Self::Enforce),
            _ => Err(format!(
                "Invalid {FIPS_MODE_ENV}. Expected `off` (default) or `enforce`. The supplied \
                 value is withheld from this diagnostic."
            )),
        }
    }

    /// Canonical rendering, safe for logs and authenticated status surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Enforce => "enforce",
        }
    }

    /// `true` when FIPS policy must be enforced.
    pub fn is_enforcing(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

/// Environment variable carrying the runtime FIPS request.
pub const FIPS_MODE_ENV: &str = "FERRUM_FIPS_MODE";

/// Environment variable pinning the required validated-module integration.
pub const FIPS_REQUIRED_PROVIDER_ENV: &str = "FERRUM_FIPS_REQUIRED_PROVIDER";

/// Read the bootstrap FIPS request from the process environment only.
///
/// This runs before `ferrum.conf` is resolvable: the rustls process-default
/// provider must be installed before any TLS material is parsed, and reading
/// the settings file that early would pin `CONF_FILE_CACHE` before
/// `FERRUM_CONF_PATH_FILE` is materialized (see
/// `.claude/rules/tls-security.md`). `--fips-mode` is materialized into the
/// environment by `cli::apply_run_overrides` / `apply_validate_overrides`
/// beforehand, so CLI and environment are both visible here. A request that
/// reaches Ferrum only through `ferrum.conf` is caught after `EnvConfig`
/// resolution by [`verify_resolved_mode`], which fails closed.
pub fn bootstrap_mode_from_env() -> Result<FipsMode, String> {
    match std::env::var(FIPS_MODE_ENV) {
        Ok(raw) => FipsMode::parse(&raw),
        // `var` reports a non-Unicode value as absent. Ferrum's startup env
        // sweep rejects undecodable `FERRUM_*` values before the gateway runs,
        // so treating it as unset here cannot silently drop an enforce request:
        // `EnvConfig` still fails the command.
        Err(_) => Ok(FipsMode::Off),
    }
}

/// Resolved FIPS state for this process.
///
/// Established exactly once during bootstrap by [`install_crypto_provider`] and
/// read by every later enforcement point (validate, startup, reload,
/// publication, TLS construction, authenticated status).
#[derive(Debug, Clone, Copy)]
pub struct FipsState {
    mode: FipsMode,
    build_capable: bool,
    module_self_test_passed: bool,
    provider_is_fips: bool,
}

impl FipsState {
    /// Requested posture.
    pub fn mode(&self) -> FipsMode {
        self.mode
    }

    /// `true` when FIPS policy must be enforced everywhere.
    pub fn is_enforcing(&self) -> bool {
        self.mode.is_enforcing()
    }

    /// `true` when this binary links the AWS-LC FIPS provider profile.
    pub fn build_capable(&self) -> bool {
        self.build_capable
    }

    /// `true` when the module reported that its power-on self-tests passed and
    /// it is operating in its approved mode.
    pub fn module_self_test_passed(&self) -> bool {
        self.module_self_test_passed
    }

    /// `true` when rustls classifies the installed provider's algorithms as
    /// FIPS-approved.
    pub fn provider_is_fips(&self) -> bool {
        self.provider_is_fips
    }

    /// Stable identifier of the active integration.
    pub fn provider_id(&self) -> &'static str {
        if self.build_capable {
            SUPPORTED_PROVIDER_ID
        } else {
            RING_PROVIDER_ID
        }
    }
}

static STATE: OnceLock<FipsState> = OnceLock::new();

/// The resolved process FIPS state.
///
/// Returns a non-enforcing state when bootstrap has not run (library consumers
/// and external tests that never call [`install_crypto_provider`]). Enforcement
/// therefore never activates implicitly; it activates only where bootstrap
/// established it.
pub fn state() -> FipsState {
    *STATE.get().unwrap_or(&FipsState {
        mode: FipsMode::Off,
        build_capable: BUILD_CAPABLE,
        module_self_test_passed: false,
        provider_is_fips: false,
    })
}

/// `true` when FIPS policy must be enforced in this process.
pub fn is_enforcing() -> bool {
    state().is_enforcing()
}

/// Base rustls crypto provider for this build.
///
/// Every Ferrum-owned rustls configuration — frontend, admin, backend, CP/DP,
/// mesh, DTLS signing, SPIFFE, plugin sinks, and the `health` subcommand —
/// builds from this one function, so provider selection is a single auditable
/// switch rather than fifty-odd call sites that each have to remember.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub fn base_crypto_provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// Base rustls crypto provider for this build.
///
/// On a `fips` build, `rustls/fips` restricts this provider's suites, groups,
/// and signature algorithms to the approved set at compile time, so
/// `CryptoProvider::fips()` is `true` and no non-approved algorithm is
/// reachable through it.
#[cfg(feature = "fips")]
pub fn base_crypto_provider() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// The process-default crypto provider is not the one an enforcing FIPS
/// process requires.
///
/// Carries no detail beyond the fact itself: there is exactly one way to be
/// wrong here, and naming the interloping provider would be guesswork —
/// `CryptoProvider` exposes no identity, only its algorithm classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderMismatch;

impl std::fmt::Display for ProviderMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the installed process-default rustls crypto provider is not classified as \
             FIPS-approved, so an internal client built against it would run its TLS outside the \
             selected `{SUPPORTED_PROVIDER_ID}` module. Refusing to use it while \
             {FIPS_MODE_ENV}=enforce is in effect."
        )
    }
}

impl std::error::Error for ProviderMismatch {}

/// Ensure internal client builders can resolve the compile-time-selected
/// provider when they are exercised outside the binary startup sequence.
///
/// The Ferrum binary still calls [`install_crypto_provider`] first and that
/// fail-closed bootstrap remains authoritative for operator-requested FIPS
/// enforcement. Library and integration tests can construct plugin clients
/// directly, though, and reqwest's provider-neutral feature intentionally has
/// no fallback of its own. Installing the same compile-time-selected provider
/// here keeps those constructors provider-neutral without adding `ring` to a
/// FIPS graph or AWS-LC to the ordinary graph.
///
/// # Fail-closed behaviour
///
/// "A provider is already installed" is **not** the same as "a usable provider
/// is already installed". An embedding application, or a racing constructor on
/// a build that links both arms, can pin `ring` before Ferrum looks; treating
/// any installed provider as acceptable would then hand an enforcing FIPS
/// process a client whose TLS runs outside the selected module — silently, and
/// on a real traffic path.
///
/// So when [`is_enforcing`] holds, this verifies the installed provider's own
/// algorithm classification (`CryptoProvider::fips()`) and returns
/// [`ProviderMismatch`] rather than proceeding. It does not panic: the callers
/// are infallible client constructors on library paths, and they translate the
/// error into a client that cannot complete a request (see
/// `src/plugins/utils/http_client.rs`).
///
/// Outside enforcement the behaviour is exactly as before, so ordinary library
/// and test construction is unaffected.
///
/// # Why the binary cannot normally reach the error
///
/// [`install_crypto_provider`] runs before any client is constructed and is
/// itself fail-closed: it refuses an enforce request on a non-capable build,
/// on a failed module self-test, on a provider rustls does not classify as
/// approved, and — through `install_default`'s own error — when a provider was
/// already installed by someone else. `STATE` is set only on that success path,
/// so `is_enforcing()` implies the FIPS provider was the one installed. This
/// check is the backstop that keeps that implication true if the invariant is
/// ever weakened, rather than a condition the shipped binary is expected to
/// meet at runtime.
pub(crate) fn ensure_internal_client_crypto_provider() -> Result<(), ProviderMismatch> {
    if let Some(installed) = CryptoProvider::get_default() {
        return verify_installed_provider(installed);
    }

    // `install_default` fails only when another thread installed a provider
    // between the check above and this call. That race is precisely the case
    // that must not be waved through, so re-read the winner and classify it
    // rather than assuming the process default is usable.
    if CryptoProvider::install_default(base_crypto_provider()).is_err()
        && let Some(installed) = CryptoProvider::get_default()
    {
        return verify_installed_provider(installed);
    }

    Ok(())
}

/// Classify an installed provider against the enforced posture.
fn verify_installed_provider(installed: &Arc<CryptoProvider>) -> Result<(), ProviderMismatch> {
    if is_enforcing() && !installed.fips() {
        return Err(ProviderMismatch);
    }
    Ok(())
}

/// Parse a DER private key with the selected provider's key provider.
///
/// Mirrors `rustls::crypto::ring::sign::any_supported_type`, which takes a
/// borrow and therefore does not create a second owned DER allocation the
/// caller cannot zeroize — load-bearing for `src/dtls/mod.rs`, which owns its
/// key DER through a zeroizing wrapper.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub fn any_supported_signing_key(
    der: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    rustls::crypto::ring::sign::any_supported_type(der)
}

/// Parse a DER private key with the selected provider's key provider.
/// See the `crypto-ring` arm for why this takes a borrow.
#[cfg(feature = "fips")]
pub fn any_supported_signing_key(
    der: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    rustls::crypto::aws_lc_rs::sign::any_supported_type(der)
}

/// Outcome of [`ec_point_on_named_curve`].
///
/// Three states rather than a `bool`, because "the check could not run" must
/// never collapse into "the point is fine": the caller is admitting trust
/// material, so an unavailable check is a failure, not an acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcPointCheck {
    /// The selected backend accepted the point as a valid, non-identity point
    /// on the named curve.
    OnCurve,
    /// The selected backend refused the point.
    Invalid,
    /// The check itself could not be performed (ephemeral key generation
    /// failed). Treat as a failure.
    Unavailable,
}

/// Prove an uncompressed SEC1 point is a valid, non-identity point on
/// `algorithm`'s named curve, using the **selected backend's own** peer-public-key
/// validation.
///
/// Implemented as a bounded ephemeral ECDH agreement whose shared secret is
/// discarded: both backends validate the peer public key (SEC1 §3.2.2) as part
/// of accepting it, and neither exposes that validation on its own. Routing it
/// here rather than reimplementing curve arithmetic is the point — a second,
/// unrouted elliptic implementation on a trust-admission path is exactly what
/// this module exists to prevent.
///
/// The two backends' `agree_ephemeral` signatures diverge (`ring` 0.17 takes the
/// peer key by reference with an infallible KDF; `aws-lc-rs` takes it by value
/// with an explicit error value and a fallible KDF), so the divergence is
/// absorbed **at the seam**, as every other provider difference in this module
/// is, rather than being cfg-split at the call site.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub fn ec_point_on_named_curve(
    algorithm: &'static backend::agreement::Algorithm,
    point: &[u8],
) -> EcPointCheck {
    let rng = backend::rand::SystemRandom::new();
    let Ok(private) = backend::agreement::EphemeralPrivateKey::generate(algorithm, &rng) else {
        return EcPointCheck::Unavailable;
    };
    let peer = backend::agreement::UnparsedPublicKey::new(algorithm, point);
    match backend::agreement::agree_ephemeral(private, &peer, |_shared_secret| ()) {
        Ok(()) => EcPointCheck::OnCurve,
        Err(_) => EcPointCheck::Invalid,
    }
}

/// Prove an uncompressed SEC1 point lies on `algorithm`'s named curve. See the
/// `crypto-ring` arm for the rationale; on a FIPS build the validation is
/// performed by the selected AWS-LC FIPS module.
#[cfg(feature = "fips")]
pub fn ec_point_on_named_curve(
    algorithm: &'static backend::agreement::Algorithm,
    point: &[u8],
) -> EcPointCheck {
    let rng = backend::rand::SystemRandom::new();
    let Ok(private) = backend::agreement::EphemeralPrivateKey::generate(algorithm, &rng) else {
        return EcPointCheck::Unavailable;
    };
    let peer = backend::agreement::UnparsedPublicKey::new(algorithm, point);
    match backend::agreement::agree_ephemeral(private, peer, (), |_shared_secret| Ok::<(), ()>(()))
    {
        Ok(()) => EcPointCheck::OnCurve,
        Err(()) => EcPointCheck::Invalid,
    }
}

/// TLS 1.2 session-ticket encrypter/decrypter from the selected provider.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub fn ticketer() -> Result<std::sync::Arc<dyn rustls::server::ProducesTickets>, rustls::Error> {
    rustls::crypto::ring::Ticketer::new()
}

/// TLS 1.2 session-ticket encrypter/decrypter from the selected provider.
///
/// On a FIPS build the ticket key is generated by the module's approved DRBG
/// and the ticket AEAD is an approved AES-GCM construction.
#[cfg(feature = "fips")]
pub fn ticketer() -> Result<std::sync::Arc<dyn rustls::server::ProducesTickets>, rustls::Error> {
    rustls::crypto::aws_lc_rs::Ticketer::new()
}

/// Look up a cipher suite by registry identifier in the active provider.
///
/// Ferrum names suites by identifier rather than through a provider-qualified
/// constant path so one suite table serves every provider. A suite the active
/// provider does not implement returns `None`, which callers surface as an
/// explicit "unsupported in this build" configuration error — never as a silent
/// substitution or a silently thinned suite list.
pub fn cipher_suite(id: rustls::CipherSuite) -> Option<rustls::SupportedCipherSuite> {
    base_crypto_provider()
        .cipher_suites
        .into_iter()
        .find(|suite| suite.suite() == id)
}

/// Look up a key-exchange group by named-group identifier in the active
/// provider. See [`cipher_suite`] for why this is a lookup rather than a
/// constant.
pub fn kx_group(name: rustls::NamedGroup) -> Option<&'static dyn rustls::crypto::SupportedKxGroup> {
    base_crypto_provider()
        .kx_groups
        .into_iter()
        .find(|group| group.name() == name)
}

/// Bootstrap error, rendered verbatim to the operator.
///
/// Every variant is a fixed, bounded string plus fixed-set metadata. No
/// operator-supplied value, key material, or module internal state is
/// interpolated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    /// `FERRUM_FIPS_MODE` did not parse.
    InvalidMode(String),
    /// FIPS was requested but this binary cannot provide it.
    BuildNotCapable,
    /// The module is linked but declined to report approved-mode operation.
    SelfTestFailed(&'static str),
    /// rustls does not classify the installed provider as FIPS-approved.
    ProviderNotApproved,
    /// Another crypto provider was already installed process-wide.
    ProviderAlreadyInstalled,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMode(detail) => write!(f, "{detail}"),
            Self::BuildNotCapable => write!(
                f,
                "{FIPS_MODE_ENV}=enforce was requested, but this ferrum-edge build does not link \
                 the `{SUPPORTED_PROVIDER_ID}` validated cryptographic module — it links \
                 `{RING_PROVIDER_ID}`, which is not validated. Ferrum will not fall back to a \
                 non-validated provider, so startup is refused. docs/fips.md documents the \
                 module integration, its build contract, and its current status."
            ),
            Self::SelfTestFailed(reason) => write!(
                f,
                "{FIPS_MODE_ENV}=enforce was requested and the `{SUPPORTED_PROVIDER_ID}` module is \
                 linked, but it did not report approved-mode operation ({reason}). The module's \
                 power-on self-tests must pass before Ferrum will serve or publish configuration."
            ),
            Self::ProviderNotApproved => write!(
                f,
                "{FIPS_MODE_ENV}=enforce was requested but rustls does not classify the installed \
                 crypto provider's algorithms as FIPS-approved. This indicates a build whose \
                 crypto features do not match the FIPS profile documented in docs/fips.md."
            ),
            Self::ProviderAlreadyInstalled => write!(
                f,
                "failed to install the rustls crypto provider: a process-default provider was \
                 already installed"
            ),
        }
    }
}

/// Install the process-default rustls crypto provider and establish FIPS state.
///
/// Called once from `main()` before any TLS material is parsed. Fail-closed:
/// when FIPS is requested and build capability, the module's power-on self-test,
/// or the provider's algorithm classification is missing, this returns an error
/// and the process exits. It never installs a non-approved provider in response
/// to an enforce request, and it never downgrades the request.
pub fn install_crypto_provider() -> Result<FipsState, BootstrapError> {
    let mode = bootstrap_mode_from_env().map_err(BootstrapError::InvalidMode)?;

    if mode.is_enforcing() && !BUILD_CAPABLE {
        return Err(BootstrapError::BuildNotCapable);
    }

    // The module's own answer, asked before anything is installed. On a
    // non-FIPS build this is always `Err`, which is only consulted when an
    // enforce request has already passed the `BUILD_CAPABLE` gate above.
    let self_test = module_self_test();
    if mode.is_enforcing()
        && let Err(reason) = self_test
    {
        return Err(BootstrapError::SelfTestFailed(reason));
    }

    let provider = base_crypto_provider();
    let provider_is_fips = provider.fips();

    if mode.is_enforcing() && !provider_is_fips {
        return Err(BootstrapError::ProviderNotApproved);
    }

    CryptoProvider::install_default(provider)
        .map_err(|_| BootstrapError::ProviderAlreadyInstalled)?;

    let resolved = FipsState {
        mode,
        build_capable: BUILD_CAPABLE,
        module_self_test_passed: BUILD_CAPABLE && self_test.is_ok(),
        provider_is_fips,
    };
    // `install_default` above already guarantees single execution per process;
    // a second call would have returned `ProviderAlreadyInstalled`.
    let _ = STATE.set(resolved);
    Ok(resolved)
}

/// Re-check the fully resolved FIPS request against the installed provider.
///
/// The process-default provider is installed before `ferrum.conf` can be read,
/// so a request that appears only in the settings file (or only through an
/// external-secret source) is not visible at bootstrap. This runs after
/// `EnvConfig` resolution on both the `validate` and `run` paths and fails
/// closed rather than serving under a provider chosen from a stale view of the
/// request.
pub fn verify_resolved_mode(resolved: FipsMode) -> Result<(), String> {
    if !resolved.is_enforcing() || state().is_enforcing() {
        return Ok(());
    }
    if !BUILD_CAPABLE {
        return Err(BootstrapError::BuildNotCapable.to_string());
    }
    Err(format!(
        "{FIPS_MODE_ENV}=enforce was resolved from the settings file, but the process-default \
         crypto provider is installed before `ferrum.conf` is read, so the request arrived too \
         late to select the `{SUPPORTED_PROVIDER_ID}` module. Supply the FIPS request through the \
         process environment ({FIPS_MODE_ENV}=enforce) or the `--fips-mode enforce` CLI flag. See \
         docs/fips.md."
    ))
}

/// Non-sensitive mode/provider/module metadata for authenticated surfaces.
///
/// Deliberately carries no key material, no module internal state, no file
/// paths, and no operator-supplied strings — every field is either a boolean or
/// a value from a fixed set. It is still restricted to the *authenticated*
/// detail tier of `/health` and `/status` (see `src/admin/mod.rs`), because the
/// combination of build profile and enforcement posture is deployment
/// intelligence an anonymous caller has no need for.
pub fn status_metadata() -> serde_json::Value {
    let state = state();
    serde_json::json!({
        "mode": state.mode().as_str(),
        "enforcing": state.is_enforcing(),
        "build_capable": state.build_capable(),
        "build_profile": if BUILD_CAPABLE { "fips" } else { "crypto-ring" },
        "provider": state.provider_id(),
        "module_self_test_passed": state.module_self_test_passed(),
        "provider_algorithms_approved": state.provider_is_fips(),
        // Ferrum is not itself a validated cryptographic module and is not
        // independently certified. This field exists so an operator scraping
        // status cannot mistake "enforcing" for "certified".
        "certified": false,
        "boundary_documentation": "docs/fips.md",
    })
}
