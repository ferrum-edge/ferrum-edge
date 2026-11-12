//! TLS record-layer cipher-suite backend for the ordinary (`crypto-ring`) build.
//!
//! # What is selected, and what is not
//!
//! `ring` 0.17 implements AES-GCM on x86-64 with VAES/VPCLMULQDQ over 256-bit
//! (AVX2) vectors and has no 512-bit path. AWS-LC has an AVX-512 AES-GCM, but no
//! AVX2 VAES one: on a CPU without the AVX-512 features it falls back to plain
//! AES-NI, which is slower than `ring`. Neither is better everywhere, so the
//! ordinary build links rustls's AWS-LC cipher suites **beside** `ring`'s and
//! chooses between them once, at process bootstrap, from the CPU it runs on.
//!
//! Only the provider's `cipher_suites` are replaced — the record-layer AEAD and
//! the HKDF/PRF hash each suite carries, including the QUIC packet and header
//! keys a TLS 1.3 suite supplies. Key-exchange groups, signature verification,
//! the key provider, the secure random source, and the session ticketer stay on
//! `ring`, exactly as before.
//!
//! This is a performance selection on a build that makes no validation claim.
//! It does not touch the `fips` profile: there every suite already comes from
//! the AWS-LC FIPS module, `ring` is not linked, and [`select`] refuses a
//! request for it.
//!
//! # The `auto` rule
//!
//! `auto` selects AWS-LC only when all of the following hold, and keeps `ring`
//! otherwise:
//!
//! 1. the target is x86-64 and not Windows (AWS-LC compiles its AVX-512 AES-GCM
//!    out on Windows);
//! 2. the CPU and operating system expose every feature AWS-LC's own dispatch
//!    (`crypto_gcm_avx512_enabled`) requires: VAES, VPCLMULQDQ, and AVX-512 F,
//!    DQ, BW, and VL;
//! 3. the CPU is on the measured allow-list in [`auto_verdict`].
//!
//! The third condition exists because the feature bits are not sufficient.
//! Intel Ice Lake reports every feature above and showed no net gain when
//! measured, and BoringSSL avoids 512-bit registers on Ice Lake and Tiger Lake
//! because of downclocking, allowing them again from Sapphire Rapids. Rocket
//! Lake has the features too and has not been measured. All three keep `ring`,
//! and so does any CPU that is not listed: a new microarchitecture is admitted
//! by measurement, not by assumption.
//!
//! `FERRUM_TLS_AEAD_BACKEND` (`auto`, `ring`, `aws-lc`) overrides the rule. The
//! override is honoured as given on the ordinary build, including `aws-lc` on a
//! CPU the rule would not have chosen; [`log_startup_selection`] warns about
//! that combination rather than silently substituting `ring`.
//!
//! # Why the selection is fixed at bootstrap
//!
//! The process-default rustls provider is installed exactly once, before
//! `ferrum.conf` is readable, and every Ferrum-owned TLS configuration builds
//! from [`super::base_crypto_provider`]. Resolving the selection in that same
//! step gives the process one provider for its whole life. A request that
//! appears only in the settings file therefore arrives too late, exactly as a
//! FIPS request does, and [`verify_resolved_request`] refuses it with an
//! explicit message instead of running a mixed or silently ignored selection.

use std::sync::OnceLock;

use rustls::crypto::CryptoProvider;

use super::{BUILD_CAPABLE, RING_PROVIDER_ID, SUPPORTED_PROVIDER_ID};

/// Environment variable carrying the operator's record-layer backend request.
pub const TLS_AEAD_BACKEND_ENV: &str = "FERRUM_TLS_AEAD_BACKEND";

/// Operator request for the record-layer cipher-suite backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AeadBackendRequest {
    /// Choose by CPU. See the module documentation for the rule.
    #[default]
    Auto,
    /// Keep `ring`'s cipher suites.
    Ring,
    /// Use AWS-LC's cipher suites.
    AwsLc,
}

impl AeadBackendRequest {
    /// Parse an operator-supplied value.
    ///
    /// Accepts `auto`, `ring`, and `aws-lc`, case-insensitively; a blank value
    /// is `auto`. Anything else is a configuration error rather than a silent
    /// fallback, and the supplied value is not echoed.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "ring" => Ok(Self::Ring),
            "aws-lc" => Ok(Self::AwsLc),
            _ => Err(format!(
                "Invalid {TLS_AEAD_BACKEND_ENV}. Expected `auto` (default), `ring`, or `aws-lc`. \
                 The supplied value is withheld from this diagnostic."
            )),
        }
    }

    /// Canonical rendering, safe for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ring => "ring",
            Self::AwsLc => "aws-lc",
        }
    }
}

/// The implementation that serves the TLS record layer in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadBackend {
    /// `ring`'s cipher suites (ordinary build).
    Ring,
    /// AWS-LC's cipher suites beside `ring`'s key exchange and signatures
    /// (ordinary build).
    AwsLc,
    /// The AWS-LC FIPS module, which serves every suite on a `fips` build.
    AwsLcFips,
}

impl AeadBackend {
    /// Canonical rendering, safe for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ring => RING_PROVIDER_ID,
            Self::AwsLc => "aws-lc",
            Self::AwsLcFips => SUPPORTED_PROVIDER_ID,
        }
    }
}

/// CPU vendor, as far as the `auto` rule distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    /// `AuthenticAMD`.
    Amd,
    /// `GenuineIntel`.
    Intel,
    /// Any other vendor string, or a target without CPUID.
    Other,
}

impl CpuVendor {
    /// Canonical rendering, safe for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amd => "amd",
            Self::Intel => "intel",
            Self::Other => "other",
        }
    }
}

/// Build target, as far as the `auto` rule distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    /// x86-64 on an operating system where AWS-LC compiles its AVX-512 AES-GCM.
    X86_64,
    /// x86-64 Windows. AWS-LC excludes its AVX-512 AES-GCM from Windows builds,
    /// so the CPU's features cannot make it the faster implementation there.
    X86_64Windows,
    /// Every other architecture.
    Other,
}

impl TargetClass {
    /// Canonical rendering, safe for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::X86_64Windows => "x86_64-windows",
            Self::Other => "other",
        }
    }
}

/// The CPU features AWS-LC requires before it dispatches AES-GCM to its AVX-512
/// implementation (`crypto_gcm_avx512_enabled` in AWS-LC's `gcm.c`).
///
/// Kept as individual flags rather than one boolean so the gate can be compared
/// against AWS-LC's source feature by feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Avx512GcmFeatures {
    /// Vector AES.
    pub vaes: bool,
    /// Vector carry-less multiplication.
    pub vpclmulqdq: bool,
    /// AVX-512 Foundation, including operating-system support for ZMM state.
    pub avx512f: bool,
    /// AVX-512 Doubleword and Quadword.
    pub avx512dq: bool,
    /// AVX-512 Byte and Word.
    pub avx512bw: bool,
    /// AVX-512 Vector Length extensions.
    pub avx512vl: bool,
}

impl Avx512GcmFeatures {
    /// Every required feature present.
    pub const ALL: Self = Self {
        vaes: true,
        vpclmulqdq: true,
        avx512f: true,
        avx512dq: true,
        avx512bw: true,
        avx512vl: true,
    };

    /// No required feature present.
    pub const NONE: Self = Self {
        vaes: false,
        vpclmulqdq: false,
        avx512f: false,
        avx512dq: false,
        avx512bw: false,
        avx512vl: false,
    };

    /// `true` when AWS-LC would use its AVX-512 AES-GCM on this CPU.
    pub fn complete(self) -> bool {
        self.vaes
            && self.vpclmulqdq
            && self.avx512f
            && self.avx512dq
            && self.avx512bw
            && self.avx512vl
    }
}

/// Everything the `auto` rule reads about the machine.
///
/// A plain value so the rule is a pure function that tests can drive with the
/// signature of any CPU, not only the one the test happens to run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuFacts {
    /// Build target class.
    pub target: TargetClass,
    /// CPU vendor.
    pub vendor: CpuVendor,
    /// CPUID display family (base family plus extended family).
    pub family: u32,
    /// CPUID display model (extended model and base model combined).
    pub model: u32,
    /// AWS-LC's AVX-512 AES-GCM feature gate.
    pub features: Avx512GcmFeatures,
}

impl CpuFacts {
    /// Facts for a target the rule knows nothing about. Always keeps `ring`.
    pub const UNKNOWN: Self = Self {
        target: TargetClass::Other,
        vendor: CpuVendor::Other,
        family: 0,
        model: 0,
        features: Avx512GcmFeatures::NONE,
    };

    /// Read the facts for the CPU this process is running on.
    pub fn detect() -> Self {
        detect_cpu_facts()
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_cpu_facts() -> CpuFacts {
    use std::arch::x86_64::__cpuid;

    // CPUID is part of the x86-64 baseline, so leaves 0 and 1 are always
    // present. `__cpuid` is an `unsafe fn` on older toolchains and a safe one
    // on newer ones; the allowance keeps this compiling warning-free on both.
    #[allow(unused_unsafe)]
    // SAFETY: the CPUID instruction is available on every x86-64 CPU and has
    // no memory-safety preconditions.
    let (vendor_leaf, signature_leaf) = unsafe { (__cpuid(0), __cpuid(1)) };

    let (family, model) = decode_family_model(signature_leaf.eax);
    CpuFacts {
        target: if cfg!(windows) {
            TargetClass::X86_64Windows
        } else {
            TargetClass::X86_64
        },
        vendor: vendor_from_cpuid(vendor_leaf.ebx, vendor_leaf.ecx, vendor_leaf.edx),
        family,
        model,
        // `is_x86_feature_detected!` already accounts for operating-system
        // support for the extended register state, which is the same
        // condition AWS-LC applies before it trusts the AVX-512 bits.
        features: Avx512GcmFeatures {
            vaes: std::arch::is_x86_feature_detected!("vaes"),
            vpclmulqdq: std::arch::is_x86_feature_detected!("vpclmulqdq"),
            avx512f: std::arch::is_x86_feature_detected!("avx512f"),
            avx512dq: std::arch::is_x86_feature_detected!("avx512dq"),
            avx512bw: std::arch::is_x86_feature_detected!("avx512bw"),
            avx512vl: std::arch::is_x86_feature_detected!("avx512vl"),
        },
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_cpu_facts() -> CpuFacts {
    CpuFacts::UNKNOWN
}

/// Decode the display family and model from CPUID leaf 1 `EAX`.
///
/// The extended family is added only when the base family is `0xF`, and the
/// extended model is combined only for base families `0x6` and `0xF`, as the
/// Intel and AMD manuals both specify.
pub fn decode_family_model(eax: u32) -> (u32, u32) {
    let base_family = (eax >> 8) & 0xf;
    let base_model = (eax >> 4) & 0xf;
    let extended_family = (eax >> 20) & 0xff;
    let extended_model = (eax >> 16) & 0xf;

    let family = if base_family == 0xf {
        base_family + extended_family
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        (extended_model << 4) | base_model
    } else {
        base_model
    };
    (family, model)
}

/// Classify the vendor string CPUID leaf 0 returns in `EBX`, `EDX`, `ECX`.
pub fn vendor_from_cpuid(ebx: u32, ecx: u32, edx: u32) -> CpuVendor {
    // "AuthenticAMD" and "GenuineIntel", four little-endian bytes per register.
    const AMD: (u32, u32, u32) = (0x6874_7541, 0x6974_6e65, 0x444d_4163);
    const INTEL: (u32, u32, u32) = (0x756e_6547, 0x4965_6e69, 0x6c65_746e);

    let registers = (ebx, edx, ecx);
    if registers == AMD {
        CpuVendor::Amd
    } else if registers == INTEL {
        CpuVendor::Intel
    } else {
        CpuVendor::Other
    }
}

/// AMD family `0x19`: Zen 3 and Zen 4. Zen 3 has no AVX-512, so only Zen 4
/// passes the feature gate.
pub const AMD_FAMILY_19H: u32 = 0x19;
/// AMD family `0x1A`: Zen 5.
pub const AMD_FAMILY_1AH: u32 = 0x1a;
/// Intel family 6.
pub const INTEL_FAMILY_6: u32 = 0x6;

/// Intel family-6 models admitted by `auto`: Sapphire Rapids (`0x8F`), Emerald
/// Rapids (`0xCF`), Granite Rapids (`0xAD`), and Granite Rapids-D (`0xAE`).
pub const INTEL_QUALIFIED_MODELS: &[u32] = &[0x8f, 0xcf, 0xad, 0xae];

/// Intel family-6 models older than Sapphire Rapids that report the full
/// feature set and are nevertheless excluded: Ice Lake server (`0x6A`, `0x6C`),
/// Ice Lake client (`0x7D`, `0x7E`, `0x9D`), Tiger Lake (`0x8C`, `0x8D`), and
/// Rocket Lake (`0xA7`). Ice Lake and Tiger Lake are the models BoringSSL avoids
/// 512-bit registers on; Rocket Lake is here because it is unmeasured. They are
/// named, rather than left to fall through as unlisted, so the startup record
/// can say why a CPU that has the features was not selected.
pub const INTEL_PRE_SAPPHIRE_RAPIDS_MODELS: &[u32] =
    &[0x6a, 0x6c, 0x7d, 0x7e, 0x9d, 0x8c, 0x8d, 0xa7];

/// Why a backend was selected. Every rendering is a fixed string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadSelectionReason {
    /// The `fips` profile: every suite comes from the AWS-LC FIPS module.
    FipsBuild,
    /// Process bootstrap has not run (library consumers and external tests).
    NotBootstrapped,
    /// `FERRUM_TLS_AEAD_BACKEND` named the backend.
    OperatorOverride,
    /// `auto`: the features are present and the CPU is on the allow-list.
    QualifiedCpu,
    /// `auto`: not an x86-64 target.
    NotX86_64,
    /// `auto`: x86-64 Windows, where AWS-LC has no AVX-512 AES-GCM.
    WindowsTarget,
    /// `auto`: at least one feature AWS-LC's AVX-512 AES-GCM needs is missing.
    MissingCpuFeatures,
    /// `auto`: an Intel CPU older than Sapphire Rapids that has the features.
    IntelPreSapphireRapids,
    /// `auto`: the features are present but the CPU is not on the allow-list.
    UnlistedCpu,
}

impl AeadSelectionReason {
    /// Canonical rendering, safe for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FipsBuild => "fips-build",
            Self::NotBootstrapped => "not-bootstrapped",
            Self::OperatorOverride => "operator-override",
            Self::QualifiedCpu => "cpu-qualified",
            Self::NotX86_64 => "not-x86-64",
            Self::WindowsTarget => "windows-target",
            Self::MissingCpuFeatures => "cpu-features-missing",
            Self::IntelPreSapphireRapids => "intel-pre-sapphire-rapids",
            Self::UnlistedCpu => "cpu-not-listed",
        }
    }
}

/// What `auto` chooses for a CPU, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoVerdict {
    /// The backend `auto` selects.
    pub backend: AeadBackend,
    /// The rule that decided it.
    pub reason: AeadSelectionReason,
}

/// Apply the `auto` rule to a CPU on the ordinary build.
///
/// A pure function of its argument. The allow-list is deliberately explicit:
///
/// - AMD family `0x19` (Zen 4; Zen 3 fails the feature gate) and `0x1A` (Zen 5);
/// - Intel family 6 models in [`INTEL_QUALIFIED_MODELS`].
///
/// Everything else keeps `ring`, including a CPU that has every feature but is
/// not listed.
pub fn auto_verdict(cpu: &CpuFacts) -> AutoVerdict {
    let ring = |reason| AutoVerdict {
        backend: AeadBackend::Ring,
        reason,
    };

    match cpu.target {
        TargetClass::X86_64 => {}
        TargetClass::X86_64Windows => return ring(AeadSelectionReason::WindowsTarget),
        TargetClass::Other => return ring(AeadSelectionReason::NotX86_64),
    }
    if !cpu.features.complete() {
        return ring(AeadSelectionReason::MissingCpuFeatures);
    }

    let qualified = match cpu.vendor {
        CpuVendor::Amd => matches!(cpu.family, AMD_FAMILY_19H | AMD_FAMILY_1AH),
        CpuVendor::Intel => {
            if cpu.family == INTEL_FAMILY_6 && INTEL_PRE_SAPPHIRE_RAPIDS_MODELS.contains(&cpu.model)
            {
                return ring(AeadSelectionReason::IntelPreSapphireRapids);
            }
            cpu.family == INTEL_FAMILY_6 && INTEL_QUALIFIED_MODELS.contains(&cpu.model)
        }
        CpuVendor::Other => false,
    };

    if qualified {
        AutoVerdict {
            backend: AeadBackend::AwsLc,
            reason: AeadSelectionReason::QualifiedCpu,
        }
    } else {
        ring(AeadSelectionReason::UnlistedCpu)
    }
}

/// The resolved record-layer backend and the inputs that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadSelection {
    /// What the operator asked for.
    pub request: AeadBackendRequest,
    /// What serves the record layer.
    pub backend: AeadBackend,
    /// Why.
    pub reason: AeadSelectionReason,
    /// What `auto` would have chosen on this CPU, whatever the request was.
    pub auto: AutoVerdict,
    /// The CPU facts the rule read.
    pub cpu: CpuFacts,
}

impl AeadSelection {
    /// `true` when an explicit request selected AWS-LC on a CPU where `auto`
    /// keeps `ring` — honoured, but expected to cost throughput.
    pub fn forces_aws_lc_against_auto(&self) -> bool {
        self.backend == AeadBackend::AwsLc && self.auto.backend != AeadBackend::AwsLc
    }
}

/// A request this build cannot honour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadSelectionError {
    /// `ring` was requested on the `fips` profile, which does not link it.
    RingUnavailableOnFipsBuild,
}

impl std::fmt::Display for AeadSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RingUnavailableOnFipsBuild => write!(
                f,
                "{TLS_AEAD_BACKEND_ENV} requested `{RING_PROVIDER_ID}`, but this ferrum-edge build \
                 is the FIPS profile: its TLS record layer runs in the `{SUPPORTED_PROVIDER_ID}` \
                 module and `{RING_PROVIDER_ID}` is not linked. Remove the setting or set it to \
                 `auto`. See docs/fips.md."
            ),
        }
    }
}

impl std::error::Error for AeadSelectionError {}

/// Resolve a request against a CPU and a build profile.
///
/// A pure function: `fips_build` is a parameter rather than a read of
/// [`BUILD_CAPABLE`] so both profiles' behaviour is testable from either build.
///
/// On the `fips` profile the answer is always the AWS-LC FIPS module. `auto`
/// and `aws-lc` are both satisfied by it; `ring` cannot be and is an error,
/// never a silent substitution.
pub fn select(
    request: AeadBackendRequest,
    cpu: &CpuFacts,
    fips_build: bool,
) -> Result<AeadSelection, AeadSelectionError> {
    if fips_build {
        if request == AeadBackendRequest::Ring {
            return Err(AeadSelectionError::RingUnavailableOnFipsBuild);
        }
        let verdict = AutoVerdict {
            backend: AeadBackend::AwsLcFips,
            reason: AeadSelectionReason::FipsBuild,
        };
        return Ok(AeadSelection {
            request,
            backend: verdict.backend,
            reason: verdict.reason,
            auto: verdict,
            cpu: *cpu,
        });
    }

    let auto = auto_verdict(cpu);
    let (backend, reason) = match request {
        AeadBackendRequest::Auto => (auto.backend, auto.reason),
        AeadBackendRequest::Ring => (AeadBackend::Ring, AeadSelectionReason::OperatorOverride),
        AeadBackendRequest::AwsLc => (AeadBackend::AwsLc, AeadSelectionReason::OperatorOverride),
    };
    Ok(AeadSelection {
        request,
        backend,
        reason,
        auto,
        cpu: *cpu,
    })
}

static SELECTION: OnceLock<AeadSelection> = OnceLock::new();

/// The selection in effect when process bootstrap has not run.
///
/// Deterministic on purpose: library consumers and external tests get the
/// build's baseline provider whatever CPU they happen to run on. The CPU rule
/// applies only where [`super::install_crypto_provider`] established it.
fn not_bootstrapped_selection() -> AeadSelection {
    let verdict = if BUILD_CAPABLE {
        AutoVerdict {
            backend: AeadBackend::AwsLcFips,
            reason: AeadSelectionReason::FipsBuild,
        }
    } else {
        AutoVerdict {
            backend: AeadBackend::Ring,
            reason: AeadSelectionReason::NotBootstrapped,
        }
    };
    AeadSelection {
        request: AeadBackendRequest::Auto,
        backend: verdict.backend,
        reason: verdict.reason,
        auto: verdict,
        cpu: CpuFacts::UNKNOWN,
    }
}

/// The record-layer backend selection for this process.
pub fn selection() -> AeadSelection {
    match SELECTION.get() {
        Some(installed) => *installed,
        None => not_bootstrapped_selection(),
    }
}

/// Read the bootstrap request from the process environment only.
///
/// Runs before `ferrum.conf` is resolvable, for the reason
/// [`super::bootstrap_mode_from_env`] documents. A request that reaches Ferrum
/// only through the settings file or an external secret source is caught after
/// `EnvConfig` resolution by [`verify_resolved_request`].
pub fn bootstrap_request_from_env() -> Result<AeadBackendRequest, String> {
    match std::env::var(TLS_AEAD_BACKEND_ENV) {
        Ok(raw) => AeadBackendRequest::parse(&raw),
        // A non-Unicode value reads as absent here. The startup environment
        // sweep rejects undecodable `FERRUM_*` values before the gateway runs,
        // so this cannot silently drop a request.
        Err(_) => Ok(AeadBackendRequest::Auto),
    }
}

/// Resolve the bootstrap selection and fix it for the life of the process.
///
/// Called by [`super::install_crypto_provider`] immediately before it builds
/// the process-default provider, so that provider and every later
/// [`super::base_crypto_provider`] call agree.
pub(super) fn resolve_and_install_bootstrap_selection()
-> Result<AeadSelection, super::BootstrapError> {
    let request =
        bootstrap_request_from_env().map_err(super::BootstrapError::InvalidAeadBackend)?;
    let resolved = select(request, &CpuFacts::detect(), BUILD_CAPABLE)
        .map_err(super::BootstrapError::AeadBackendUnavailable)?;
    // A second bootstrap in one process is already refused by
    // `CryptoProvider::install_default`; keeping the first selection here means
    // the provider that call rejected cannot change what is in effect.
    Ok(*SELECTION.get_or_init(|| resolved))
}

/// Re-check the fully resolved request against the bootstrap selection.
///
/// Two refusals, both explicit:
///
/// - `ring` on the `fips` profile, whichever source supplied it. This is a
///   property of the build, so it is checked even where bootstrap never ran and
///   `validate` reaches the same verdict as startup.
/// - a resolved request that differs from the one bootstrap acted on. The
///   provider is installed before `ferrum.conf` and external secret sources are
///   readable, so such a request arrived too late to be applied; it is refused
///   rather than ignored or half-applied.
pub fn verify_resolved_request(resolved: AeadBackendRequest) -> Result<(), String> {
    if BUILD_CAPABLE && resolved == AeadBackendRequest::Ring {
        return Err(AeadSelectionError::RingUnavailableOnFipsBuild.to_string());
    }
    let Some(installed) = SELECTION.get() else {
        return Ok(());
    };
    if installed.request == resolved {
        return Ok(());
    }
    Err(format!(
        "{TLS_AEAD_BACKEND_ENV} was resolved from the settings file or an external secret source, \
         but the cryptographic provider is installed before either is read, so the request \
         arrived too late to select the TLS record-layer backend. Supply it through the process \
         environment instead ({TLS_AEAD_BACKEND_ENV}=auto, ring, or aws-lc)."
    ))
}

/// Build the ordinary profile's provider with the given record-layer backend.
///
/// [`AeadBackend::AwsLc`] replaces each of `ring`'s cipher suites with AWS-LC's
/// implementation of the same suite, in place, so the suite set and its order
/// are unchanged and only the implementation differs. Everything else in the
/// provider is `ring`'s.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub(super) fn ordinary_profile_provider(backend: AeadBackend) -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    if backend == AeadBackend::AwsLc {
        for suite in provider.cipher_suites.iter_mut() {
            if let Some(replacement) = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
                .iter()
                .find(|candidate| candidate.suite() == suite.suite())
            {
                *suite = *replacement;
            }
        }
    }
    provider
}

/// Build a provider with an explicit record-layer backend, independent of the
/// process selection.
///
/// Returns `None` when this build does not link the requested backend: the
/// ordinary build has no AWS-LC FIPS module, and the `fips` build has neither
/// `ring` nor the non-FIPS AWS-LC suites. External tests use this to exercise
/// the AWS-LC suites on CPUs where `auto` would not select them.
#[cfg(all(feature = "crypto-ring", not(feature = "fips")))]
pub fn crypto_provider_with_backend(backend: AeadBackend) -> Option<CryptoProvider> {
    match backend {
        AeadBackend::Ring | AeadBackend::AwsLc => Some(ordinary_profile_provider(backend)),
        AeadBackend::AwsLcFips => None,
    }
}

/// Build a provider with an explicit record-layer backend, independent of the
/// process selection. See the `crypto-ring` arm.
#[cfg(feature = "fips")]
pub fn crypto_provider_with_backend(backend: AeadBackend) -> Option<CryptoProvider> {
    match backend {
        AeadBackend::AwsLcFips => Some(rustls::crypto::aws_lc_rs::default_provider()),
        AeadBackend::Ring | AeadBackend::AwsLc => None,
    }
}

/// Emit the startup record of the selection: one `info!` with the choice, the
/// reason, and the CPU facts behind it, plus a `warn!` when an explicit request
/// forces AWS-LC onto a CPU where `auto` keeps `ring`.
///
/// Called once from gateway startup, after tracing is initialised. Every
/// rendered value is from a fixed set or is a CPUID number. The requested value
/// is additionally key-tied through `secrets::report_env_field`, so a request
/// that came from an external secret source is withheld rather than re-rendered.
pub fn log_startup_selection() {
    let selection = selection();
    let requested =
        crate::secrets::report_env_field(TLS_AEAD_BACKEND_ENV, selection.request.as_str());
    tracing::info!(
        "TLS record-layer cipher suites: backend={}, requested={}, reason={}, target={}, \
         cpu_vendor={}, cpu_family={}, cpu_model={}, avx512_aes_gcm_features={}",
        selection.backend.as_str(),
        requested,
        selection.reason.as_str(),
        selection.cpu.target.as_str(),
        selection.cpu.vendor.as_str(),
        selection.cpu.family,
        selection.cpu.model,
        if selection.cpu.features.complete() {
            "present"
        } else {
            "absent"
        },
    );
    if selection.forces_aws_lc_against_auto() {
        tracing::warn!(
            "`{TLS_AEAD_BACKEND_ENV}` forces the AWS-LC TLS record-layer cipher suites on a CPU \
             where `auto` keeps ring (auto_reason={}). AWS-LC is faster than ring only where its \
             AVX-512 AES-GCM runs and does not lower the clock; elsewhere it measured slower. \
             Unset the variable to return to the CPU-based default.",
            selection.auto.reason.as_str(),
        );
    }
    if BUILD_CAPABLE && selection.request == AeadBackendRequest::AwsLc {
        tracing::info!(
            "`{TLS_AEAD_BACKEND_ENV}` has no effect on the FIPS profile: every TLS cipher suite \
             already comes from the `{SUPPORTED_PROVIDER_ID}` module"
        );
    }
}
