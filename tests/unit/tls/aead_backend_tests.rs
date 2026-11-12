//! TLS record-layer backend selection (`fips::aead_backend`).
//!
//! Three layers, matching what can go wrong:
//!
//! 1. the selection rule itself, driven as a pure function with the CPUID
//!    signature of every CPU the rule was measured or reasoned about, so the
//!    table holds whatever machine runs the suite;
//! 2. the operator override and its validation, including the bootstrap
//!    reconciliation, which needs a process of its own because the selection
//!    and the rustls process-default provider are both set exactly once;
//! 3. real TLS 1.2 / TLS 1.3 handshakes with bulk data, the secret extraction
//!    the kTLS path depends on, and QUIC key derivation, all with the AWS-LC
//!    suites selected explicitly. `auto` only picks them on AVX-512 CPUs, so
//!    without the explicit selection a runner without AVX-512 would never
//!    execute that code path.
//!
//! Assertions that depend on the build profile are `cfg`-gated on the `fips`
//! feature, so the file is meaningful under both `--features crypto-ring` (the
//! default) and `--no-default-features --features fips`.

use ferrum_edge::config::EnvConfig;
use ferrum_edge::fips;
use ferrum_edge::fips::aead_backend::{
    self, AeadBackend, AeadBackendRequest, AeadSelectionError, AeadSelectionReason,
    Avx512GcmFeatures, CpuFacts, CpuVendor, TargetClass,
};

use crate::unit::env_lock::{EnvGuard, with_env_vars};

// ── Request parsing ─────────────────────────────────────────────────────────

#[test]
fn request_parses_documented_spellings() {
    for (raw, expected) in [
        ("auto", AeadBackendRequest::Auto),
        ("AUTO", AeadBackendRequest::Auto),
        ("", AeadBackendRequest::Auto),
        ("   ", AeadBackendRequest::Auto),
        ("ring", AeadBackendRequest::Ring),
        ("  Ring ", AeadBackendRequest::Ring),
        ("aws-lc", AeadBackendRequest::AwsLc),
        ("AWS-LC", AeadBackendRequest::AwsLc),
    ] {
        assert_eq!(
            AeadBackendRequest::parse(raw),
            Ok(expected),
            "spelling {raw:?}"
        );
    }
    assert_eq!(AeadBackendRequest::default(), AeadBackendRequest::Auto);
    assert_eq!(AeadBackendRequest::Auto.as_str(), "auto");
    assert_eq!(AeadBackendRequest::Ring.as_str(), "ring");
    assert_eq!(AeadBackendRequest::AwsLc.as_str(), "aws-lc");
}

#[test]
fn request_rejects_unknown_values_without_echoing_them() {
    // A typo must be a configuration error, never a silent `auto`.
    for raw in [
        "awslc",
        "aws_lc",
        "boringssl",
        "openssl",
        "ring2",
        "auto,ring",
    ] {
        let err = AeadBackendRequest::parse(raw).expect_err("unknown value is rejected");
        assert!(
            err.contains("FERRUM_TLS_AEAD_BACKEND"),
            "names the setting: {err}"
        );
        assert!(
            !err.contains(raw),
            "the supplied value must not be echoed: {err}"
        );
    }
}

// ── CPUID decoding ──────────────────────────────────────────────────────────

/// CPUID leaf 0 returns the vendor string as `EBX`, `EDX`, `ECX`, four
/// little-endian bytes each. Deriving the registers from the ASCII string keeps
/// this independent of the constants in the module under test.
fn vendor_registers(name: &[u8; 12]) -> (u32, u32, u32) {
    let word = |offset: usize| {
        u32::from_le_bytes([
            name[offset],
            name[offset + 1],
            name[offset + 2],
            name[offset + 3],
        ])
    };
    (word(0), word(4), word(8))
}

#[test]
fn vendor_string_is_classified_from_its_registers() {
    for (name, expected) in [
        (b"AuthenticAMD", CpuVendor::Amd),
        (b"GenuineIntel", CpuVendor::Intel),
        (b"HygonGenuine", CpuVendor::Other),
        (b"CentaurHauls", CpuVendor::Other),
        (b"\0\0\0\0\0\0\0\0\0\0\0\0", CpuVendor::Other),
    ] {
        let (ebx, edx, ecx) = vendor_registers(name);
        assert_eq!(
            aead_backend::vendor_from_cpuid(ebx, ecx, edx),
            expected,
            "vendor {:?}",
            String::from_utf8_lossy(name)
        );
    }
}

// CPUID leaf 1 `EAX` signatures. The low nibble is the stepping, which the
// rule does not read.
const EAX_AMD_ZEN5_EPYC_9V45: u32 = 0x00B0_0F21;
const EAX_AMD_ZEN4_EPYC_9V74: u32 = 0x00A1_0F11;
const EAX_AMD_ZEN3_EPYC_7763: u32 = 0x00A0_0F11;
const EAX_AMD_ZEN2: u32 = 0x0083_0F10;
const EAX_AMD_FAMILY_1BH: u32 = 0x00C0_0F00;
const EAX_INTEL_EMERALD_RAPIDS_8573C: u32 = 0x000C_06F2;
const EAX_INTEL_SAPPHIRE_RAPIDS: u32 = 0x0008_06F8;
const EAX_INTEL_GRANITE_RAPIDS: u32 = 0x000A_06D1;
const EAX_INTEL_ICE_LAKE_SERVER_8370C: u32 = 0x0006_06A6;
const EAX_INTEL_ICE_LAKE_D: u32 = 0x0006_06C1;
const EAX_INTEL_ICE_LAKE_CLIENT: u32 = 0x0007_06E5;
const EAX_INTEL_TIGER_LAKE_MOBILE: u32 = 0x0008_06C1;
const EAX_INTEL_TIGER_LAKE_DESKTOP: u32 = 0x0008_06D1;
const EAX_INTEL_ROCKET_LAKE: u32 = 0x000A_0671;
const EAX_INTEL_SKYLAKE_X: u32 = 0x0005_0657;
const EAX_INTEL_UNLISTED_FAMILY_6: u32 = 0x000F_06F0;
const EAX_INTEL_FAMILY_19: u32 = 0x0040_0F10;

#[test]
fn display_family_and_model_are_decoded_from_the_signature() {
    for (name, eax, family, model) in [
        ("EPYC 9V45 (Zen 5)", EAX_AMD_ZEN5_EPYC_9V45, 0x1a, 0x02),
        ("EPYC 9V74 (Zen 4)", EAX_AMD_ZEN4_EPYC_9V74, 0x19, 0x11),
        ("EPYC 7763 (Zen 3)", EAX_AMD_ZEN3_EPYC_7763, 0x19, 0x01),
        ("Zen 2", EAX_AMD_ZEN2, 0x17, 0x31),
        ("AMD family 1Bh", EAX_AMD_FAMILY_1BH, 0x1b, 0x00),
        (
            "Xeon 8573C (Emerald Rapids)",
            EAX_INTEL_EMERALD_RAPIDS_8573C,
            0x6,
            0xcf,
        ),
        ("Sapphire Rapids", EAX_INTEL_SAPPHIRE_RAPIDS, 0x6, 0x8f),
        ("Granite Rapids", EAX_INTEL_GRANITE_RAPIDS, 0x6, 0xad),
        (
            "Xeon 8370C (Ice Lake)",
            EAX_INTEL_ICE_LAKE_SERVER_8370C,
            0x6,
            0x6a,
        ),
        ("Ice Lake-D", EAX_INTEL_ICE_LAKE_D, 0x6, 0x6c),
        ("Ice Lake client", EAX_INTEL_ICE_LAKE_CLIENT, 0x6, 0x7e),
        ("Tiger Lake mobile", EAX_INTEL_TIGER_LAKE_MOBILE, 0x6, 0x8c),
        (
            "Tiger Lake desktop",
            EAX_INTEL_TIGER_LAKE_DESKTOP,
            0x6,
            0x8d,
        ),
        ("Rocket Lake", EAX_INTEL_ROCKET_LAKE, 0x6, 0xa7),
        ("Skylake-X", EAX_INTEL_SKYLAKE_X, 0x6, 0x55),
        ("unlisted family 6", EAX_INTEL_UNLISTED_FAMILY_6, 0x6, 0xff),
        ("Intel family 19", EAX_INTEL_FAMILY_19, 19, 0x01),
    ] {
        assert_eq!(
            aead_backend::decode_family_model(eax),
            (family, model),
            "{name}"
        );
    }
}

// ── The `auto` rule ─────────────────────────────────────────────────────────

/// Zen 3 has 256-bit VAES and VPCLMULQDQ but no AVX-512 at all.
const FEATURES_ZEN3: Avx512GcmFeatures = Avx512GcmFeatures {
    vaes: true,
    vpclmulqdq: true,
    ..Avx512GcmFeatures::NONE
};

/// Skylake-X and Cascade Lake have AVX-512 F/DQ/BW/VL but neither VAES nor
/// VPCLMULQDQ.
const FEATURES_SKYLAKE_X: Avx512GcmFeatures = Avx512GcmFeatures {
    vaes: false,
    vpclmulqdq: false,
    ..Avx512GcmFeatures::ALL
};

fn x86_64(vendor: CpuVendor, eax: u32, features: Avx512GcmFeatures) -> CpuFacts {
    let (family, model) = aead_backend::decode_family_model(eax);
    CpuFacts {
        target: TargetClass::X86_64,
        vendor,
        family,
        model,
        features,
    }
}

fn zen5() -> CpuFacts {
    x86_64(
        CpuVendor::Amd,
        EAX_AMD_ZEN5_EPYC_9V45,
        Avx512GcmFeatures::ALL,
    )
}

fn zen3() -> CpuFacts {
    x86_64(CpuVendor::Amd, EAX_AMD_ZEN3_EPYC_7763, FEATURES_ZEN3)
}

fn ice_lake_server() -> CpuFacts {
    x86_64(
        CpuVendor::Intel,
        EAX_INTEL_ICE_LAKE_SERVER_8370C,
        Avx512GcmFeatures::ALL,
    )
}

#[test]
fn auto_selects_aws_lc_only_on_the_measured_avx512_cpus() {
    use AeadSelectionReason::{
        IntelPreSapphireRapids, MissingCpuFeatures, QualifiedCpu, UnlistedCpu,
    };
    let all = Avx512GcmFeatures::ALL;

    let cases = [
        // Qualify: the features are present and the CPU is on the allow-list.
        (
            "AMD EPYC 9V45 (Zen 5)",
            x86_64(CpuVendor::Amd, EAX_AMD_ZEN5_EPYC_9V45, all),
            AeadBackend::AwsLc,
            QualifiedCpu,
        ),
        (
            "AMD EPYC 9V74 (Zen 4)",
            x86_64(CpuVendor::Amd, EAX_AMD_ZEN4_EPYC_9V74, all),
            AeadBackend::AwsLc,
            QualifiedCpu,
        ),
        (
            "Intel Xeon Platinum 8573C (Emerald Rapids)",
            x86_64(CpuVendor::Intel, EAX_INTEL_EMERALD_RAPIDS_8573C, all),
            AeadBackend::AwsLc,
            QualifiedCpu,
        ),
        (
            "Intel Sapphire Rapids",
            x86_64(CpuVendor::Intel, EAX_INTEL_SAPPHIRE_RAPIDS, all),
            AeadBackend::AwsLc,
            QualifiedCpu,
        ),
        (
            "Intel Granite Rapids",
            x86_64(CpuVendor::Intel, EAX_INTEL_GRANITE_RAPIDS, all),
            AeadBackend::AwsLc,
            QualifiedCpu,
        ),
        // No AVX-512 AES-GCM in AWS-LC on these: it would fall back to AES-NI.
        (
            "AMD EPYC 7763 (Zen 3)",
            zen3(),
            AeadBackend::Ring,
            MissingCpuFeatures,
        ),
        (
            "AMD Zen 2",
            x86_64(CpuVendor::Amd, EAX_AMD_ZEN2, Avx512GcmFeatures::NONE),
            AeadBackend::Ring,
            MissingCpuFeatures,
        ),
        (
            "Intel Skylake-X / Cascade Lake",
            x86_64(CpuVendor::Intel, EAX_INTEL_SKYLAKE_X, FEATURES_SKYLAKE_X),
            AeadBackend::Ring,
            MissingCpuFeatures,
        ),
        // Every feature present, and still excluded: these lower their clock
        // when 512-bit registers are used.
        (
            "Intel Xeon Platinum 8370C (Ice Lake)",
            ice_lake_server(),
            AeadBackend::Ring,
            IntelPreSapphireRapids,
        ),
        (
            "Intel Ice Lake-D",
            x86_64(CpuVendor::Intel, EAX_INTEL_ICE_LAKE_D, all),
            AeadBackend::Ring,
            IntelPreSapphireRapids,
        ),
        (
            "Intel Ice Lake client",
            x86_64(CpuVendor::Intel, EAX_INTEL_ICE_LAKE_CLIENT, all),
            AeadBackend::Ring,
            IntelPreSapphireRapids,
        ),
        (
            "Intel Tiger Lake mobile",
            x86_64(CpuVendor::Intel, EAX_INTEL_TIGER_LAKE_MOBILE, all),
            AeadBackend::Ring,
            IntelPreSapphireRapids,
        ),
        (
            "Intel Tiger Lake desktop",
            x86_64(CpuVendor::Intel, EAX_INTEL_TIGER_LAKE_DESKTOP, all),
            AeadBackend::Ring,
            IntelPreSapphireRapids,
        ),
        (
            "Intel Rocket Lake",
            x86_64(CpuVendor::Intel, EAX_INTEL_ROCKET_LAKE, all),
            AeadBackend::Ring,
            IntelPreSapphireRapids,
        ),
        // Unknown CPUs keep ring even with every feature present.
        (
            "unlisted Intel family 6 model",
            x86_64(CpuVendor::Intel, EAX_INTEL_UNLISTED_FAMILY_6, all),
            AeadBackend::Ring,
            UnlistedCpu,
        ),
        (
            "Intel family 19",
            x86_64(CpuVendor::Intel, EAX_INTEL_FAMILY_19, all),
            AeadBackend::Ring,
            UnlistedCpu,
        ),
        (
            "AMD family 1Bh",
            x86_64(CpuVendor::Amd, EAX_AMD_FAMILY_1BH, all),
            AeadBackend::Ring,
            UnlistedCpu,
        ),
        (
            "another vendor with every feature",
            x86_64(CpuVendor::Other, EAX_AMD_ZEN5_EPYC_9V45, all),
            AeadBackend::Ring,
            UnlistedCpu,
        ),
    ];

    for (name, cpu, backend, reason) in cases {
        let verdict = aead_backend::auto_verdict(&cpu);
        assert_eq!(verdict.backend, backend, "{name}: backend");
        assert_eq!(verdict.reason, reason, "{name}: reason");

        // `select` under `auto` is exactly the verdict, and never an override.
        let selection = aead_backend::select(AeadBackendRequest::Auto, &cpu, false)
            .expect("auto always resolves on the ordinary build");
        assert_eq!(selection.backend, backend, "{name}: selected backend");
        assert_eq!(selection.reason, reason, "{name}: selected reason");
        assert_eq!(selection.request, AeadBackendRequest::Auto, "{name}");
        assert_eq!(selection.auto, verdict, "{name}");
        assert_eq!(selection.cpu, cpu, "{name}");
        assert!(!selection.forces_aws_lc_against_auto(), "{name}");
    }
}

#[test]
fn auto_requires_every_feature_aws_lc_dispatches_on() {
    // AWS-LC's `crypto_gcm_avx512_enabled` is VAES && VPCLMULQDQ && AVX-512
    // F/DQ/BW/VL. Dropping any one of them on an otherwise qualifying CPU must
    // keep ring, because AWS-LC would then run its AES-NI fallback.
    let all = Avx512GcmFeatures::ALL;
    assert!(all.complete());
    assert!(!Avx512GcmFeatures::NONE.complete());
    assert_eq!(Avx512GcmFeatures::default(), Avx512GcmFeatures::NONE);

    let missing_one = [
        ("vaes", Avx512GcmFeatures { vaes: false, ..all }),
        (
            "vpclmulqdq",
            Avx512GcmFeatures {
                vpclmulqdq: false,
                ..all
            },
        ),
        (
            "avx512f",
            Avx512GcmFeatures {
                avx512f: false,
                ..all
            },
        ),
        (
            "avx512dq",
            Avx512GcmFeatures {
                avx512dq: false,
                ..all
            },
        ),
        (
            "avx512bw",
            Avx512GcmFeatures {
                avx512bw: false,
                ..all
            },
        ),
        (
            "avx512vl",
            Avx512GcmFeatures {
                avx512vl: false,
                ..all
            },
        ),
    ];
    for (name, features) in missing_one {
        assert!(!features.complete(), "without {name}");
        for eax in [EAX_AMD_ZEN5_EPYC_9V45, EAX_AMD_ZEN4_EPYC_9V74] {
            let verdict = aead_backend::auto_verdict(&x86_64(CpuVendor::Amd, eax, features));
            assert_eq!(verdict.backend, AeadBackend::Ring, "without {name}");
            assert_eq!(
                verdict.reason,
                AeadSelectionReason::MissingCpuFeatures,
                "without {name}"
            );
        }
        let verdict = aead_backend::auto_verdict(&x86_64(
            CpuVendor::Intel,
            EAX_INTEL_EMERALD_RAPIDS_8573C,
            features,
        ));
        assert_eq!(verdict.backend, AeadBackend::Ring, "without {name}");
    }
}

#[test]
fn auto_keeps_ring_off_x86_64_and_on_windows() {
    // A qualifying CPU signature and feature set, on targets where they do not
    // matter: AWS-LC has no AVX-512 AES-GCM on Windows, and no other
    // architecture was measured.
    let windows = CpuFacts {
        target: TargetClass::X86_64Windows,
        ..zen5()
    };
    let verdict = aead_backend::auto_verdict(&windows);
    assert_eq!(verdict.backend, AeadBackend::Ring);
    assert_eq!(verdict.reason, AeadSelectionReason::WindowsTarget);

    let other_arch = CpuFacts {
        target: TargetClass::Other,
        ..zen5()
    };
    let verdict = aead_backend::auto_verdict(&other_arch);
    assert_eq!(verdict.backend, AeadBackend::Ring);
    assert_eq!(verdict.reason, AeadSelectionReason::NotX86_64);

    let verdict = aead_backend::auto_verdict(&CpuFacts::UNKNOWN);
    assert_eq!(verdict.backend, AeadBackend::Ring);
    assert_eq!(verdict.reason, AeadSelectionReason::NotX86_64);
}

#[test]
fn detected_cpu_facts_agree_with_the_build_target() {
    let detected = CpuFacts::detect();
    if cfg!(all(target_arch = "x86_64", not(windows))) {
        assert_eq!(detected.target, TargetClass::X86_64);
        assert!(detected.family > 0, "x86-64 always reports a family");
    } else if cfg!(target_arch = "x86_64") {
        assert_eq!(detected.target, TargetClass::X86_64Windows);
    } else {
        assert_eq!(detected, CpuFacts::UNKNOWN);
    }
    // Whatever this machine is, the rule gives it a definite answer, and that
    // answer is AWS-LC only when the features really are present.
    let verdict = aead_backend::auto_verdict(&detected);
    if verdict.backend == AeadBackend::AwsLc {
        assert!(detected.features.complete());
        assert_eq!(detected.target, TargetClass::X86_64);
    }
}

// ── Operator override ───────────────────────────────────────────────────────

#[test]
fn override_is_honoured_as_given_on_the_ordinary_build() {
    // `ring` on a CPU where `auto` would pick AWS-LC.
    let selection = aead_backend::select(AeadBackendRequest::Ring, &zen5(), false)
        .expect("ring is always available on the ordinary build");
    assert_eq!(selection.backend, AeadBackend::Ring);
    assert_eq!(selection.reason, AeadSelectionReason::OperatorOverride);
    assert_eq!(selection.auto.backend, AeadBackend::AwsLc);
    assert!(!selection.forces_aws_lc_against_auto());

    // `aws-lc` where `auto` agrees: an override, but not a contradiction.
    let selection = aead_backend::select(AeadBackendRequest::AwsLc, &zen5(), false)
        .expect("aws-lc is linked on the ordinary build");
    assert_eq!(selection.backend, AeadBackend::AwsLc);
    assert_eq!(selection.reason, AeadSelectionReason::OperatorOverride);
    assert!(!selection.forces_aws_lc_against_auto());

    // `aws-lc` on CPUs where `auto` keeps ring is honoured, never silently
    // replaced, and is flagged so startup can warn about it.
    for (name, cpu, auto_reason) in [
        (
            "Zen 3 without AVX-512",
            zen3(),
            AeadSelectionReason::MissingCpuFeatures,
        ),
        (
            "Ice Lake",
            ice_lake_server(),
            AeadSelectionReason::IntelPreSapphireRapids,
        ),
        (
            "non-x86-64",
            CpuFacts::UNKNOWN,
            AeadSelectionReason::NotX86_64,
        ),
        (
            "Windows",
            CpuFacts {
                target: TargetClass::X86_64Windows,
                ..zen5()
            },
            AeadSelectionReason::WindowsTarget,
        ),
    ] {
        let selection = aead_backend::select(AeadBackendRequest::AwsLc, &cpu, false)
            .expect("an explicit aws-lc request is honoured");
        assert_eq!(selection.backend, AeadBackend::AwsLc, "{name}");
        assert_eq!(
            selection.reason,
            AeadSelectionReason::OperatorOverride,
            "{name}"
        );
        assert_eq!(selection.auto.backend, AeadBackend::Ring, "{name}");
        assert_eq!(selection.auto.reason, auto_reason, "{name}");
        assert!(selection.forces_aws_lc_against_auto(), "{name}");
    }
}

#[test]
fn fips_profile_never_selects_ring_whatever_is_requested() {
    // `fips_build` is a parameter, so this holds on either build: the FIPS
    // profile's record layer is always the AWS-LC FIPS module, on every CPU.
    for cpu in [zen5(), zen3(), ice_lake_server(), CpuFacts::UNKNOWN] {
        for request in [AeadBackendRequest::Auto, AeadBackendRequest::AwsLc] {
            let selection = aead_backend::select(request, &cpu, true)
                .expect("the FIPS module satisfies auto and aws-lc");
            assert_eq!(selection.backend, AeadBackend::AwsLcFips);
            assert_eq!(selection.reason, AeadSelectionReason::FipsBuild);
            assert_eq!(selection.auto.backend, AeadBackend::AwsLcFips);
            assert!(!selection.forces_aws_lc_against_auto());
        }
        // `ring` is not linked there. An explicit error, never a silent
        // substitution in either direction.
        assert_eq!(
            aead_backend::select(AeadBackendRequest::Ring, &cpu, true),
            Err(AeadSelectionError::RingUnavailableOnFipsBuild)
        );
    }

    let rendered = AeadSelectionError::RingUnavailableOnFipsBuild.to_string();
    assert!(rendered.contains("FERRUM_TLS_AEAD_BACKEND"), "{rendered}");
    assert!(rendered.contains(fips::SUPPORTED_PROVIDER_ID), "{rendered}");
    assert!(rendered.contains("docs/fips.md"), "{rendered}");
    assert!(rendered.len() < 1024, "diagnostic stays bounded");
}

#[test]
fn renderings_are_fixed_and_distinct() {
    let reasons = [
        AeadSelectionReason::FipsBuild,
        AeadSelectionReason::NotBootstrapped,
        AeadSelectionReason::OperatorOverride,
        AeadSelectionReason::QualifiedCpu,
        AeadSelectionReason::NotX86_64,
        AeadSelectionReason::WindowsTarget,
        AeadSelectionReason::MissingCpuFeatures,
        AeadSelectionReason::IntelPreSapphireRapids,
        AeadSelectionReason::UnlistedCpu,
    ];
    let rendered: std::collections::HashSet<&str> =
        reasons.iter().map(|reason| reason.as_str()).collect();
    assert_eq!(rendered.len(), reasons.len(), "every reason renders apart");

    assert_eq!(AeadBackend::Ring.as_str(), fips::RING_PROVIDER_ID);
    assert_eq!(AeadBackend::AwsLc.as_str(), "aws-lc");
    assert_eq!(AeadBackend::AwsLcFips.as_str(), fips::SUPPORTED_PROVIDER_ID);
}

// ── Process state without bootstrap ─────────────────────────────────────────

#[test]
fn a_process_that_never_bootstrapped_gets_the_build_baseline() {
    // An external test binary never runs `install_crypto_provider`, so the CPU
    // rule must not apply here: the suite has to behave the same on a runner
    // with AVX-512 and one without.
    let selection = aead_backend::selection();
    assert_eq!(selection.request, AeadBackendRequest::Auto);
    assert_eq!(selection.cpu, CpuFacts::UNKNOWN);
    if fips::build_capable() {
        assert_eq!(selection.backend, AeadBackend::AwsLcFips);
        assert_eq!(selection.reason, AeadSelectionReason::FipsBuild);
    } else {
        assert_eq!(selection.backend, AeadBackend::Ring);
        assert_eq!(selection.reason, AeadSelectionReason::NotBootstrapped);
    }
}

// ── `EnvConfig` validation ──────────────────────────────────────────────────

fn env_config_with_backend(value: Option<&str>) -> Result<EnvConfig, String> {
    let mut vars = vec![
        ("FERRUM_MODE", "file"),
        ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
    ];
    if let Some(value) = value {
        vars.push(("FERRUM_TLS_AEAD_BACKEND", value));
    }
    let mut result = None;
    with_env_vars(&vars, || result = Some(EnvConfig::from_env()));
    result.expect("the closure ran")
}

#[test]
fn env_config_defaults_the_backend_to_auto() {
    let config = env_config_with_backend(None).expect("defaults validate");
    assert_eq!(config.tls_aead_backend, "auto");
    assert_eq!(EnvConfig::default().tls_aead_backend, "auto");
}

#[test]
fn env_config_accepts_the_values_this_build_can_honour() {
    for (value, expected) in [
        ("auto", AeadBackendRequest::Auto),
        ("aws-lc", AeadBackendRequest::AwsLc),
        ("AWS-LC", AeadBackendRequest::AwsLc),
    ] {
        let config = env_config_with_backend(Some(value))
            .unwrap_or_else(|err| panic!("{value:?} must validate: {err}"));
        assert_eq!(
            AeadBackendRequest::parse(&config.tls_aead_backend),
            Ok(expected)
        );
    }
}

#[test]
fn env_config_rejects_an_unknown_backend_without_echoing_it() {
    let err = env_config_with_backend(Some("boringssl")).expect_err("unknown value is rejected");
    assert!(
        err.contains("FERRUM_TLS_AEAD_BACKEND"),
        "names the setting: {err}"
    );
    assert!(
        !err.contains("boringssl"),
        "the supplied value must not be echoed: {err}"
    );
}

#[cfg(not(feature = "fips"))]
#[test]
fn env_config_accepts_ring_on_the_ordinary_build() {
    let config = env_config_with_backend(Some("ring")).expect("ring validates");
    assert_eq!(
        AeadBackendRequest::parse(&config.tls_aead_backend),
        Ok(AeadBackendRequest::Ring)
    );
    // Without bootstrap there is nothing to reconcile against, so every value
    // the build can honour passes the resolved-request check.
    for request in [
        AeadBackendRequest::Auto,
        AeadBackendRequest::Ring,
        AeadBackendRequest::AwsLc,
    ] {
        aead_backend::verify_resolved_request(request).expect("no bootstrap, nothing to refuse");
    }
}

#[cfg(feature = "fips")]
#[test]
fn env_config_refuses_ring_on_the_fips_build() {
    // The FIPS profile does not link ring. Asking for it must fail `validate`
    // and startup alike, whichever source supplied the value.
    let err = env_config_with_backend(Some("ring")).expect_err("ring is refused on a FIPS build");
    assert!(
        err.contains("FERRUM_TLS_AEAD_BACKEND"),
        "names the setting: {err}"
    );
    assert!(
        err.contains(fips::SUPPORTED_PROVIDER_ID),
        "names the module: {err}"
    );

    let err = aead_backend::verify_resolved_request(AeadBackendRequest::Ring)
        .expect_err("ring is refused on a FIPS build");
    assert!(err.contains(fips::SUPPORTED_PROVIDER_ID), "{err}");
    for request in [AeadBackendRequest::Auto, AeadBackendRequest::AwsLc] {
        aead_backend::verify_resolved_request(request)
            .expect("the FIPS module satisfies auto and aws-lc");
    }

    // And the profile's provider is the FIPS module's, untouched by any of
    // this: every suite approved, no ring arm to select.
    let provider = fips::base_crypto_provider();
    assert!(provider.fips());
    assert!(provider.cipher_suites.iter().all(|suite| suite.fips()));
    assert!(aead_backend::crypto_provider_with_backend(AeadBackend::Ring).is_none());
    assert!(aead_backend::crypto_provider_with_backend(AeadBackend::AwsLc).is_none());
    assert!(
        aead_backend::crypto_provider_with_backend(AeadBackend::AwsLcFips)
            .expect("the FIPS module is linked")
            .fips()
    );
}

// ── Bootstrap, in a process of its own ──────────────────────────────────────

/// Marker for the re-executed child. Not a `FERRUM_*` name, so it survives
/// `EnvGuard`'s ambient-configuration cleanup; its value is the backend request
/// the child should bootstrap with (`<unset>` for none).
const BOOTSTRAP_CHILD: &str = "AEAD_BACKEND_BOOTSTRAP_TEST_CHILD";
const UNSET: &str = "<unset>";

/// Re-run one test of this binary in a child process with `request` as the
/// bootstrap request. `install_crypto_provider` sets two process-lifetime
/// values (the selection and the rustls process default), so running it in the
/// shared test process would change what every sibling test builds from.
fn run_bootstrap_child(test_name: &str, request: &str) {
    let test_path = format!("unit::tls::aead_backend_tests::{test_name}");
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_path.as_str(), "--nocapture"])
        .env(BOOTSTRAP_CHILD, request)
        .output()
        .expect("spawn bootstrap child");
    assert!(
        output.status.success(),
        "bootstrap child for {request:?} failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "bootstrap child for {request:?} did not run the test: {output:?}"
    );
}

/// In the child: set the request, bootstrap, and return the result.
fn bootstrap_as_child(request: &str) -> Result<fips::FipsState, fips::BootstrapError> {
    let env = EnvGuard::new(&[]);
    if request != UNSET {
        env.set(aead_backend::TLS_AEAD_BACKEND_ENV, request);
    }
    fips::install_crypto_provider()
}

#[test]
fn bootstrap_fixes_the_selection_and_refuses_a_late_change() {
    let Ok(request) = std::env::var(BOOTSTRAP_CHILD) else {
        let mut requests = vec![UNSET, "auto", "aws-lc"];
        if !fips::build_capable() {
            requests.push("ring");
        }
        for request in requests {
            run_bootstrap_child(
                "bootstrap_fixes_the_selection_and_refuses_a_late_change",
                request,
            );
        }
        return;
    };

    bootstrap_as_child(&request).expect("bootstrap succeeds");
    let expected_request = if request == UNSET {
        AeadBackendRequest::Auto
    } else {
        AeadBackendRequest::parse(&request).expect("the parent passes valid requests")
    };

    // The selection is what the pure rule gives for this machine and request.
    let selection = aead_backend::selection();
    let expected =
        aead_backend::select(expected_request, &CpuFacts::detect(), fips::build_capable())
            .expect("the parent passes requests this build can honour");
    assert_eq!(selection, expected);
    assert_eq!(selection.request, expected_request);

    // The same request reconciles; any other one arrived too late and is
    // refused rather than ignored or half-applied.
    aead_backend::verify_resolved_request(expected_request).expect("the bootstrap request stands");
    for other in [
        AeadBackendRequest::Auto,
        AeadBackendRequest::Ring,
        AeadBackendRequest::AwsLc,
    ] {
        if other == expected_request {
            continue;
        }
        let err = aead_backend::verify_resolved_request(other)
            .expect_err("a request that differs from bootstrap is refused");
        assert!(err.contains("FERRUM_TLS_AEAD_BACKEND"), "{err}");
    }

    // The process-default provider and the seam agree on the suite set.
    let installed =
        rustls::crypto::CryptoProvider::get_default().expect("bootstrap installed a provider");
    let seam = fips::base_crypto_provider();
    assert_eq!(installed.cipher_suites.len(), seam.cipher_suites.len());
    for (installed_suite, seam_suite) in installed.cipher_suites.iter().zip(&seam.cipher_suites) {
        assert_eq!(installed_suite.suite(), seam_suite.suite());
    }

    #[cfg(not(feature = "fips"))]
    ordinary_profile::assert_provider_matches_backend(installed, selection.backend);
    #[cfg(not(feature = "fips"))]
    ordinary_profile::assert_provider_matches_backend(&seam, selection.backend);
}

#[test]
fn bootstrap_rejects_an_unparseable_request() {
    let Ok(request) = std::env::var(BOOTSTRAP_CHILD) else {
        run_bootstrap_child("bootstrap_rejects_an_unparseable_request", "boringssl");
        return;
    };

    let err = bootstrap_as_child(&request).expect_err("an unknown backend refuses bootstrap");
    assert!(
        matches!(err, fips::BootstrapError::InvalidAeadBackend(_)),
        "{err:?}"
    );
    let rendered = err.to_string();
    assert!(rendered.contains("FERRUM_TLS_AEAD_BACKEND"), "{rendered}");
    assert!(!rendered.contains("boringssl"), "{rendered}");
    // Nothing was installed on the refusal path.
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

#[cfg(feature = "fips")]
#[test]
fn bootstrap_refuses_ring_on_the_fips_build() {
    let Ok(request) = std::env::var(BOOTSTRAP_CHILD) else {
        run_bootstrap_child("bootstrap_refuses_ring_on_the_fips_build", "ring");
        return;
    };

    let err = bootstrap_as_child(&request).expect_err("ring is not linked on a FIPS build");
    assert_eq!(
        err,
        fips::BootstrapError::AeadBackendUnavailable(
            AeadSelectionError::RingUnavailableOnFipsBuild
        )
    );
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

// ── The ordinary profile's two providers, exercised for real ────────────────

#[cfg(not(feature = "fips"))]
mod ordinary_profile {
    use std::io::{Cursor, Read, Write};
    use std::sync::Arc;

    use ferrum_edge::fips;
    use ferrum_edge::fips::aead_backend::{self, AeadBackend};
    use rcgen::{CertificateParams, KeyPair};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::quic::{HeaderProtectionKey, KeyChange, Keys, PacketKey};
    use rustls::{CipherSuite, Connection, ConnectionTrafficSecrets, SupportedCipherSuite};

    const HOST: &str = "aead-backend.test";

    const TLS13_SUITES: [CipherSuite; 3] = [
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    const TLS12_ECDSA_SUITES: [CipherSuite; 3] = [
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    const TLS12_RSA_SUITES: [CipherSuite; 3] = [
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    /// Server and client backends for one connection. AWS-LC on both sides, and
    /// AWS-LC against ring in each direction: a real peer is some other
    /// implementation, so interoperability matters more than self-consistency.
    const BACKEND_PAIRS: [(AeadBackend, AeadBackend); 3] = [
        (AeadBackend::AwsLc, AeadBackend::AwsLc),
        (AeadBackend::AwsLc, AeadBackend::Ring),
        (AeadBackend::Ring, AeadBackend::AwsLc),
    ];

    fn provider(backend: AeadBackend) -> CryptoProvider {
        aead_backend::crypto_provider_with_backend(backend)
            .expect("ring and aws-lc are both linked on the ordinary build")
    }

    /// Address of the suite object, which identifies the implementation:
    /// `SupportedCipherSuite` compares equal by identifier alone.
    fn suite_address(suite: SupportedCipherSuite) -> *const () {
        match suite {
            SupportedCipherSuite::Tls12(inner) => std::ptr::from_ref(inner).cast(),
            SupportedCipherSuite::Tls13(inner) => std::ptr::from_ref(inner).cast(),
        }
    }

    fn is_from(suite: SupportedCipherSuite, table: &[SupportedCipherSuite]) -> bool {
        table
            .iter()
            .any(|candidate| suite_address(*candidate) == suite_address(suite))
    }

    fn is_aws_lc_suite(suite: SupportedCipherSuite) -> bool {
        is_from(suite, rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES)
    }

    fn is_ring_suite(suite: SupportedCipherSuite) -> bool {
        is_from(suite, rustls::crypto::ring::ALL_CIPHER_SUITES)
    }

    /// Every suite in `provider` comes from the implementation `backend` names.
    pub(super) fn assert_provider_matches_backend(provider: &CryptoProvider, backend: AeadBackend) {
        assert!(!provider.cipher_suites.is_empty());
        for suite in &provider.cipher_suites {
            match backend {
                AeadBackend::AwsLc => {
                    assert!(
                        is_aws_lc_suite(*suite),
                        "{:?} is not AWS-LC's",
                        suite.suite()
                    );
                    assert!(!is_ring_suite(*suite), "{:?} is ring's", suite.suite());
                }
                AeadBackend::Ring => {
                    assert!(is_ring_suite(*suite), "{:?} is not ring's", suite.suite());
                    assert!(!is_aws_lc_suite(*suite), "{:?} is AWS-LC's", suite.suite());
                }
                AeadBackend::AwsLcFips => panic!("the ordinary build has no FIPS module"),
            }
        }
    }

    #[test]
    fn aws_lc_backend_replaces_every_suite_and_nothing_else() {
        let ring = rustls::crypto::ring::default_provider();
        let ring_selected = provider(AeadBackend::Ring);
        let aws_lc_selected = provider(AeadBackend::AwsLc);

        assert_provider_matches_backend(&ring_selected, AeadBackend::Ring);
        assert_provider_matches_backend(&aws_lc_selected, AeadBackend::AwsLc);

        // Same suites, same order: only the implementation behind each differs,
        // so negotiation and the operator's suite policy are unaffected.
        let identifiers = |provider: &CryptoProvider| -> Vec<CipherSuite> {
            provider
                .cipher_suites
                .iter()
                .map(|suite| suite.suite())
                .collect()
        };
        assert_eq!(identifiers(&ring_selected), identifiers(&ring));
        assert_eq!(identifiers(&aws_lc_selected), identifiers(&ring));
        assert_eq!(
            identifiers(&ring).len(),
            9,
            "three TLS 1.3 and six TLS 1.2 suites"
        );

        // Key exchange, signature verification, the key provider and the
        // random source stay ring's on both.
        for selected in [&ring_selected, &aws_lc_selected] {
            assert_eq!(selected.kx_groups.len(), ring.kx_groups.len());
            for (selected_group, ring_group) in selected.kx_groups.iter().zip(&ring.kx_groups) {
                assert_eq!(selected_group.name(), ring_group.name());
                assert!(
                    std::ptr::addr_eq(
                        std::ptr::from_ref(*selected_group),
                        std::ptr::from_ref(*ring_group)
                    ),
                    "{:?} must be ring's key-exchange group",
                    ring_group.name()
                );
            }
            assert!(std::ptr::eq(
                selected.signature_verification_algorithms.all.as_ptr(),
                ring.signature_verification_algorithms.all.as_ptr()
            ));
            assert_eq!(
                format!("{:?}", selected.key_provider),
                format!("{:?}", ring.key_provider)
            );
            assert_eq!(
                format!("{:?}", selected.secure_random),
                format!("{:?}", ring.secure_random)
            );
            assert!(
                !selected.fips(),
                "the ordinary build claims no FIPS provider"
            );
        }

        // And they are not AWS-LC's: the swap is suites only.
        let aws_lc = rustls::crypto::aws_lc_rs::default_provider();
        assert_ne!(
            format!("{:?}", aws_lc_selected.key_provider),
            format!("{:?}", aws_lc.key_provider)
        );
        assert!(aead_backend::crypto_provider_with_backend(AeadBackend::AwsLcFips).is_none());
    }

    #[test]
    fn the_seam_serves_ring_until_bootstrap_selects_otherwise() {
        // No bootstrap in this process, so `base_crypto_provider` and the suite
        // and group lookups built on it are ring's, on every runner.
        assert_provider_matches_backend(&fips::base_crypto_provider(), AeadBackend::Ring);
        for suite in TLS13_SUITES
            .into_iter()
            .chain(TLS12_ECDSA_SUITES)
            .chain(TLS12_RSA_SUITES)
        {
            let resolved = fips::cipher_suite(suite).expect("the suite is implemented");
            assert!(is_ring_suite(resolved), "{suite:?}");
        }
    }

    struct Peer {
        cert: CertificateDer<'static>,
        key: Vec<u8>,
    }

    impl Peer {
        fn generate(algorithm: &'static rcgen::SignatureAlgorithm) -> Self {
            let key = KeyPair::generate_for(algorithm).expect("server key");
            let cert = CertificateParams::new(vec![HOST.to_string()])
                .expect("server params")
                .self_signed(&key)
                .expect("server cert");
            Self {
                cert: cert.der().clone(),
                key: key.serialize_der(),
            }
        }

        fn ecdsa() -> Self {
            Self::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
        }

        fn server(
            &self,
            provider: CryptoProvider,
            version: &'static rustls::SupportedProtocolVersion,
        ) -> rustls::ServerConfig {
            rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[version])
                .expect("server protocol version")
                .with_no_client_auth()
                .with_single_cert(
                    vec![self.cert.clone()],
                    PrivatePkcs8KeyDer::from(self.key.clone()).into(),
                )
                .expect("server cert")
        }

        fn client(
            &self,
            provider: CryptoProvider,
            version: &'static rustls::SupportedProtocolVersion,
        ) -> rustls::ClientConfig {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.cert.clone()).expect("client root");
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[version])
                .expect("client protocol version")
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    }

    /// `backend`'s provider narrowed to one suite, so the handshake can only
    /// negotiate the implementation under test.
    fn single_suite(backend: AeadBackend, suite: CipherSuite) -> CryptoProvider {
        let base = provider(backend);
        let cipher_suites: Vec<SupportedCipherSuite> = base
            .cipher_suites
            .iter()
            .copied()
            .filter(|candidate| candidate.suite() == suite)
            .collect();
        assert_eq!(cipher_suites.len(), 1, "{suite:?} is implemented once");
        CryptoProvider {
            cipher_suites,
            ..base
        }
    }

    fn version_for(suite: CipherSuite) -> &'static rustls::SupportedProtocolVersion {
        if TLS13_SUITES.contains(&suite) {
            &rustls::version::TLS13
        } else {
            &rustls::version::TLS12
        }
    }

    /// Deliver every TLS byte `from` has pending to `to`. Returns the number of
    /// wire bytes moved and the plaintext `to` produced from them.
    fn pump(from: &mut Connection, to: &mut Connection) -> (usize, Vec<u8>) {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).expect("write_tls");
        }

        let mut plaintext = Vec::new();
        let mut cursor = Cursor::new(wire.as_slice());
        while (cursor.position() as usize) < wire.len() {
            let read = to.read_tls(&mut cursor).expect("read_tls");
            assert!(read > 0, "read_tls made no progress");
            let state = to.process_new_packets().expect("process_new_packets");
            let mut chunk = vec![0u8; state.plaintext_bytes_to_read()];
            to.reader().read_exact(&mut chunk).expect("read plaintext");
            plaintext.extend_from_slice(&chunk);
        }
        (wire.len(), plaintext)
    }

    fn connect(
        server: rustls::ServerConfig,
        client: rustls::ClientConfig,
    ) -> (Connection, Connection) {
        let name = ServerName::try_from(HOST).expect("server name");
        let mut client = Connection::from(
            rustls::ClientConnection::new(Arc::new(client), name).expect("client connection"),
        );
        let mut server = Connection::from(
            rustls::ServerConnection::new(Arc::new(server)).expect("server connection"),
        );

        for _ in 0..32 {
            let (to_server, _) = pump(&mut client, &mut server);
            let (to_client, _) = pump(&mut server, &mut client);
            if to_server == 0 && to_client == 0 {
                assert!(
                    !client.is_handshaking() && !server.is_handshaking(),
                    "handshake stalled"
                );
                return (server, client);
            }
        }
        panic!("handshake did not quiesce");
    }

    /// A payload that is not a repeating block, so a keystream or counter error
    /// anywhere in it changes the comparison.
    fn payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| ((index as u32).wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect()
    }

    fn send(from: &mut Connection, to: &mut Connection, data: &[u8]) -> Vec<u8> {
        // The default 64 KiB send buffer would short-write a megabyte.
        from.set_buffer_limit(None);
        from.writer().write_all(data).expect("buffer plaintext");
        let (_, received) = pump(from, to);
        received
    }

    /// Handshake with `suite`, then move a megabyte each way. A megabyte is
    /// about 64 full records, enough to take AWS-LC's bulk AES-GCM path (the
    /// AVX-512 one where the CPU has it, the AES-NI fallback where it does not).
    fn assert_round_trip(peer: &Peer, suite: CipherSuite) {
        let version = version_for(suite);
        // Not a multiple of the record size or the AES block size.
        let data = payload(1024 * 1024 + 13);

        for (server_backend, client_backend) in BACKEND_PAIRS {
            let (mut server, mut client) = connect(
                peer.server(single_suite(server_backend, suite), version),
                peer.client(single_suite(client_backend, suite), version),
            );
            let label = format!("{suite:?} server={server_backend:?} client={client_backend:?}");

            let server_suite = server.negotiated_cipher_suite().expect("server suite");
            let client_suite = client.negotiated_cipher_suite().expect("client suite");
            assert_eq!(server_suite.suite(), suite, "{label}");
            assert_eq!(client_suite.suite(), suite, "{label}");
            assert_eq!(server.protocol_version(), Some(version.version), "{label}");
            assert_eq!(
                is_aws_lc_suite(server_suite),
                server_backend == AeadBackend::AwsLc,
                "{label}: server implementation"
            );
            assert_eq!(
                is_aws_lc_suite(client_suite),
                client_backend == AeadBackend::AwsLc,
                "{label}: client implementation"
            );

            let received = send(&mut client, &mut server, &data);
            assert!(
                received == data,
                "{label}: client to server payload differs"
            );
            let received = send(&mut server, &mut client, &data);
            assert!(
                received == data,
                "{label}: server to client payload differs"
            );
        }
    }

    #[test]
    fn tls13_handshake_and_bulk_data_round_trip_on_aws_lc_suites() {
        let peer = Peer::ecdsa();
        for suite in TLS13_SUITES {
            assert_round_trip(&peer, suite);
        }
    }

    #[test]
    fn tls12_ecdsa_handshake_and_bulk_data_round_trip_on_aws_lc_suites() {
        // TLS 1.2 also takes the suite's PRF, with ring's key exchange feeding
        // AWS-LC's PRF when the suites are swapped.
        let peer = Peer::ecdsa();
        for suite in TLS12_ECDSA_SUITES {
            assert_round_trip(&peer, suite);
        }
    }

    #[test]
    fn tls12_rsa_handshake_and_bulk_data_round_trip_on_aws_lc_suites() {
        // `rcgen` generates RSA only through its aws-lc backend; where that arm
        // is not compiled the fixture cannot be minted, which is a property of
        // the generator rather than of the suites under test. The ECDSA cases
        // above already cover the same AEAD and PRF implementations.
        let Ok(key) = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256) else {
            return;
        };
        let cert = CertificateParams::new(vec![HOST.to_string()])
            .expect("server params")
            .self_signed(&key)
            .expect("server cert");
        let peer = Peer {
            cert: cert.der().clone(),
            key: key.serialize_der(),
        };
        for suite in TLS12_RSA_SUITES {
            assert_round_trip(&peer, suite);
        }
    }

    fn secret_parts(secrets: &ConnectionTrafficSecrets) -> (&'static str, Vec<u8>, Vec<u8>) {
        match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                ("aes-128-gcm", key.as_ref().to_vec(), iv.as_ref().to_vec())
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                ("aes-256-gcm", key.as_ref().to_vec(), iv.as_ref().to_vec())
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (
                "chacha20-poly1305",
                key.as_ref().to_vec(),
                iv.as_ref().to_vec(),
            ),
            _ => panic!("unexpected traffic-secret variant"),
        }
    }

    #[test]
    fn ktls_secret_extraction_works_on_aws_lc_suites() {
        // The kTLS path hands the kernel the keys rustls extracts from the
        // negotiated suite (`proxy::ktls_accept`). The extraction is
        // implemented per suite, so it has to work for AWS-LC's suites and
        // agree with what a ring peer derives.
        let peer = Peer::ecdsa();
        for suite in TLS13_SUITES.into_iter().chain(TLS12_ECDSA_SUITES) {
            let version = version_for(suite);
            let (expected_cipher, expected_key_len) = match suite {
                CipherSuite::TLS13_AES_128_GCM_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => ("aes-128-gcm", 16),
                CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => ("aes-256-gcm", 32),
                _ => ("chacha20-poly1305", 32),
            };

            for (server_backend, client_backend) in BACKEND_PAIRS {
                let mut server_config = peer.server(single_suite(server_backend, suite), version);
                let mut client_config = peer.client(single_suite(client_backend, suite), version);
                // What `tls::enable_secret_extraction_for_ktls` sets.
                server_config.enable_secret_extraction = true;
                client_config.enable_secret_extraction = true;

                let (server, client) = connect(server_config, client_config);
                let label =
                    format!("{suite:?} server={server_backend:?} client={client_backend:?}");
                let server = server
                    .dangerous_extract_secrets()
                    .unwrap_or_else(|err| panic!("{label}: server extraction: {err}"));
                let client = client
                    .dangerous_extract_secrets()
                    .unwrap_or_else(|err| panic!("{label}: client extraction: {err}"));

                let (cipher, key, iv) = secret_parts(&server.tx.1);
                assert_eq!(cipher, expected_cipher, "{label}");
                assert_eq!(key.len(), expected_key_len, "{label}");
                assert_eq!(iv.len(), 12, "{label}");

                // Each side's transmit keys are the other's receive keys.
                assert_eq!(
                    secret_parts(&server.tx.1),
                    secret_parts(&client.rx.1),
                    "{label}: server tx / client rx"
                );
                assert_eq!(
                    secret_parts(&server.rx.1),
                    secret_parts(&client.tx.1),
                    "{label}: server rx / client tx"
                );
                assert_eq!(server.tx.0, client.rx.0, "{label}: server tx sequence");
                assert_eq!(server.rx.0, client.tx.0, "{label}: server rx sequence");
            }
        }
    }

    /// Call `write` until it yields a key change or stops producing bytes.
    fn drain_handshake(
        mut write: impl FnMut(&mut Vec<u8>) -> Option<KeyChange>,
    ) -> (Vec<u8>, Option<KeyChange>) {
        let mut wire = Vec::new();
        loop {
            let before = wire.len();
            if let Some(change) = write(&mut wire) {
                return (wire, Some(change));
            }
            if wire.len() == before {
                return (wire, None);
            }
        }
    }

    /// Run a QUIC handshake in memory and return each side's 1-RTT keys.
    fn quic_one_rtt_keys(
        server: rustls::ServerConfig,
        client: rustls::ClientConfig,
    ) -> (Keys, Keys) {
        let name = ServerName::try_from(HOST).expect("server name");
        let mut client = rustls::quic::ClientConnection::new(
            Arc::new(client),
            rustls::quic::Version::V1,
            name,
            b"client transport parameters".to_vec(),
        )
        .expect("QUIC client connection");
        let mut server = rustls::quic::ServerConnection::new(
            Arc::new(server),
            rustls::quic::Version::V1,
            b"server transport parameters".to_vec(),
        )
        .expect("QUIC server connection");

        let mut server_keys = None;
        let mut client_keys = None;
        for _ in 0..16 {
            let (wire, change) = drain_handshake(|wire| client.write_hs(wire));
            if !wire.is_empty() {
                server.read_hs(&wire).expect("server read_hs");
            }
            if let Some(KeyChange::OneRtt { keys, .. }) = change {
                client_keys = Some(keys);
            }

            let (wire, change) = drain_handshake(|wire| server.write_hs(wire));
            if !wire.is_empty() {
                client.read_hs(&wire).expect("client read_hs");
            }
            if let Some(KeyChange::OneRtt { keys, .. }) = change {
                server_keys = Some(keys);
            }

            if server_keys.is_some() && client_keys.is_some() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        (
            server_keys.expect("server 1-RTT keys"),
            client_keys.expect("client 1-RTT keys"),
        )
    }

    fn assert_packet_keys_interoperate(
        sealer: &dyn PacketKey,
        opener: &dyn PacketKey,
        label: &str,
    ) {
        // A full-size QUIC packet payload under a short header.
        let header = [0x43u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = payload(1200);
        let mut packet = plaintext.clone();
        let tag = sealer
            .encrypt_in_place(7, &header, &mut packet)
            .unwrap_or_else(|err| panic!("{label}: seal: {err}"));
        assert_ne!(packet, plaintext, "{label}: the payload was not encrypted");
        packet.extend_from_slice(tag.as_ref());
        assert_eq!(packet.len(), plaintext.len() + sealer.tag_len(), "{label}");

        let opened = opener
            .decrypt_in_place(7, &header, &mut packet)
            .unwrap_or_else(|err| panic!("{label}: open: {err}"));
        assert!(
            opened == plaintext.as_slice(),
            "{label}: opened payload differs"
        );
    }

    fn assert_header_keys_interoperate(
        protect: &dyn HeaderProtectionKey,
        unprotect: &dyn HeaderProtectionKey,
        label: &str,
    ) {
        let sample = vec![0x5au8; protect.sample_len()];
        // Short header, four-byte packet number.
        let mut first = 0x43u8;
        let mut packet_number = [9u8, 8, 7, 6];
        protect
            .encrypt_in_place(&sample, &mut first, &mut packet_number)
            .unwrap_or_else(|err| panic!("{label}: protect: {err}"));
        unprotect
            .decrypt_in_place(&sample, &mut first, &mut packet_number)
            .unwrap_or_else(|err| panic!("{label}: unprotect: {err}"));
        assert_eq!(first, 0x43, "{label}: first byte");
        assert_eq!(packet_number, [9, 8, 7, 6], "{label}: packet number");
    }

    #[test]
    fn quic_keys_derived_from_aws_lc_suites_interoperate() {
        // HTTP/3 builds its QUIC configuration from the same provider, and
        // quinn takes its packet and header-protection keys from the negotiated
        // TLS 1.3 suite. Derive them with AWS-LC's suites and check they open
        // what the peer seals, against AWS-LC and against ring.
        let peer = Peer::ecdsa();
        for suite in TLS13_SUITES {
            for (server_backend, client_backend) in BACKEND_PAIRS {
                let mut server_config =
                    peer.server(single_suite(server_backend, suite), &rustls::version::TLS13);
                let mut client_config =
                    peer.client(single_suite(client_backend, suite), &rustls::version::TLS13);
                server_config.alpn_protocols = vec![b"h3".to_vec()];
                client_config.alpn_protocols = vec![b"h3".to_vec()];

                let (server, client) = quic_one_rtt_keys(server_config, client_config);
                let label =
                    format!("{suite:?} server={server_backend:?} client={client_backend:?}");

                assert_packet_keys_interoperate(
                    &*client.local.packet,
                    &*server.remote.packet,
                    &label,
                );
                assert_packet_keys_interoperate(
                    &*server.local.packet,
                    &*client.remote.packet,
                    &label,
                );
                assert_header_keys_interoperate(
                    &*client.local.header,
                    &*server.remote.header,
                    &label,
                );
                assert_header_keys_interoperate(
                    &*server.local.header,
                    &*client.remote.header,
                    &label,
                );
            }
        }
    }

    #[test]
    fn quinn_accepts_a_configuration_built_on_aws_lc_suites() {
        // quinn requires the provider to carry a QUIC-capable
        // TLS13_AES_128_GCM_SHA256 for its Initial keys and refuses the
        // configuration otherwise. The swapped provider must still satisfy it.
        let peer = Peer::ecdsa();
        let mut server = peer.server(provider(AeadBackend::AwsLc), &rustls::version::TLS13);
        server.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = peer.client(provider(AeadBackend::AwsLc), &rustls::version::TLS13);
        client.alpn_protocols = vec![b"h3".to_vec()];

        quinn::crypto::rustls::QuicServerConfig::try_from(server)
            .expect("quinn accepts the AWS-LC-suite server configuration");
        quinn::crypto::rustls::QuicClientConfig::try_from(client)
            .expect("quinn accepts the AWS-LC-suite client configuration");
    }
}
