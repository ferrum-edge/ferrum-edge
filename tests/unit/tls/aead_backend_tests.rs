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
const EAX_INTEL_GRANITE_RAPIDS_D: u32 = 0x000A_06E0;
const EAX_INTEL_ICE_LAKE_CLIENT_7D: u32 = 0x0007_06D0;
const EAX_INTEL_ICE_LAKE_NNPI: u32 = 0x0009_06D0;
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
        ("Granite Rapids-D", EAX_INTEL_GRANITE_RAPIDS_D, 0x6, 0xae),
        (
            "Ice Lake client (0x7D)",
            EAX_INTEL_ICE_LAKE_CLIENT_7D,
            0x6,
            0x7d,
        ),
        ("Ice Lake NNPI", EAX_INTEL_ICE_LAKE_NNPI, 0x6, 0x9d),
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
        (
            "Intel Granite Rapids-D",
            x86_64(CpuVendor::Intel, EAX_INTEL_GRANITE_RAPIDS_D, all),
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
fn every_listed_intel_model_has_a_pinned_verdict() {
    // The lists are written out again here on purpose: dropping, adding or
    // mistyping a model in the module must fail a test, not pass silently.
    assert_eq!(aead_backend::AMD_FAMILY_19H, 0x19);
    assert_eq!(aead_backend::AMD_FAMILY_1AH, 0x1a);
    assert_eq!(aead_backend::INTEL_FAMILY_6, 0x6);
    assert_eq!(
        aead_backend::INTEL_QUALIFIED_MODELS,
        &[0x8f, 0xcf, 0xad, 0xae]
    );
    assert_eq!(
        aead_backend::INTEL_PRE_SAPPHIRE_RAPIDS_MODELS,
        &[0x6a, 0x6c, 0x7d, 0x7e, 0x9d, 0x8c, 0x8d, 0xa7]
    );

    let intel = |model: u32| CpuFacts {
        target: TargetClass::X86_64,
        vendor: CpuVendor::Intel,
        family: aead_backend::INTEL_FAMILY_6,
        model,
        features: Avx512GcmFeatures::ALL,
    };
    for model in aead_backend::INTEL_QUALIFIED_MODELS {
        let verdict = aead_backend::auto_verdict(&intel(*model));
        assert_eq!(verdict.backend, AeadBackend::AwsLc, "model {model:#x}");
        assert_eq!(
            verdict.reason,
            AeadSelectionReason::QualifiedCpu,
            "model {model:#x}"
        );
    }
    for model in aead_backend::INTEL_PRE_SAPPHIRE_RAPIDS_MODELS {
        let verdict = aead_backend::auto_verdict(&intel(*model));
        assert_eq!(verdict.backend, AeadBackend::Ring, "model {model:#x}");
        assert_eq!(
            verdict.reason,
            AeadSelectionReason::IntelPreSapphireRapids,
            "model {model:#x}"
        );
    }
    // A model on neither list, and the same model numbers on another family or
    // vendor, do not qualify.
    for model in aead_backend::INTEL_QUALIFIED_MODELS {
        let other_family = CpuFacts {
            family: 0xf,
            ..intel(*model)
        };
        assert_eq!(
            aead_backend::auto_verdict(&other_family).backend,
            AeadBackend::Ring,
            "family 15 model {model:#x}"
        );
        let amd = CpuFacts {
            vendor: CpuVendor::Amd,
            ..intel(*model)
        };
        assert_eq!(
            aead_backend::auto_verdict(&amd).backend,
            AeadBackend::Ring,
            "AMD family 6 model {model:#x}"
        );
    }
}

#[test]
fn auto_keeps_ring_off_x86_64_and_on_windows() {
    // A qualifying CPU signature and feature set, on targets where they do not
    // matter: AWS-LC has no AVX-512 AES-GCM on Windows, never treats AVX-512 as
    // usable on Apple platforms, and no other architecture was measured.
    let windows = CpuFacts {
        target: TargetClass::X86_64Windows,
        ..zen5()
    };
    let verdict = aead_backend::auto_verdict(&windows);
    assert_eq!(verdict.backend, AeadBackend::Ring);
    assert_eq!(verdict.reason, AeadSelectionReason::WindowsTarget);

    let apple = CpuFacts {
        target: TargetClass::X86_64Apple,
        ..zen5()
    };
    let verdict = aead_backend::auto_verdict(&apple);
    assert_eq!(verdict.backend, AeadBackend::Ring);
    assert_eq!(verdict.reason, AeadSelectionReason::AppleTarget);

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
    if cfg!(not(target_arch = "x86_64")) {
        assert_eq!(detected, CpuFacts::UNKNOWN);
    } else if cfg!(windows) {
        assert_eq!(detected.target, TargetClass::X86_64Windows);
    } else if cfg!(target_vendor = "apple") {
        assert_eq!(detected.target, TargetClass::X86_64Apple);
    } else {
        assert_eq!(detected.target, TargetClass::X86_64);
        assert!(detected.family > 0, "x86-64 always reports a family");
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
        (
            "macOS",
            CpuFacts {
                target: TargetClass::X86_64Apple,
                ..zen5()
            },
            AeadSelectionReason::AppleTarget,
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
        AeadSelectionReason::AppleTarget,
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

/// Re-run one test of this binary in a child process with `marker=value` set.
/// The rustls process-default provider and the record-layer selection are both
/// set at most once per process, so a test that sets either, or that depends on
/// neither being set, needs a process of its own: in the shared test process it
/// would change, or be changed by, what sibling tests build from.
fn run_child(test_name: &str, marker: &str, value: &str) {
    let test_path = format!("unit::tls::aead_backend_tests::{test_name}");
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_path.as_str(), "--nocapture"])
        .env(marker, value)
        .output()
        .expect("spawn child test process");
    assert!(
        output.status.success(),
        "child {test_name} ({value:?}) failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "child {test_name} ({value:?}) did not run the test: {output:?}"
    );
}

/// [`run_child`] with `request` as the bootstrap request.
fn run_bootstrap_child(test_name: &str, request: &str) {
    run_child(test_name, BOOTSTRAP_CHILD, request);
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

#[test]
fn a_refused_bootstrap_publishes_no_selection() {
    // `install_default` succeeds at most once per process. When another
    // provider is already installed, bootstrap fails and must leave the
    // record-layer selection unpublished: otherwise `base_crypto_provider()`
    // would follow a request for a provider that never took effect.
    let Ok(request) = std::env::var(BOOTSTRAP_CHILD) else {
        run_bootstrap_child("a_refused_bootstrap_publishes_no_selection", "aws-lc");
        return;
    };

    let before = aead_backend::selection();
    fips::base_crypto_provider()
        .install_default()
        .expect("nothing is installed in a fresh process");

    let err = bootstrap_as_child(&request).expect_err("a second provider cannot be installed");
    assert_eq!(err, fips::BootstrapError::ProviderAlreadyInstalled);

    let after = aead_backend::selection();
    assert_eq!(after, before, "a refused bootstrap changed the selection");
    assert_eq!(after.request, AeadBackendRequest::Auto);
    if fips::build_capable() {
        assert_eq!(after.reason, AeadSelectionReason::FipsBuild);
    } else {
        assert_eq!(after.backend, AeadBackend::Ring);
        assert_eq!(after.reason, AeadSelectionReason::NotBootstrapped);
    }
    // With nothing published there is nothing to reconcile against, so the
    // request bootstrap could not apply is not treated as in effect either.
    aead_backend::verify_resolved_request(AeadBackendRequest::Auto)
        .expect("no selection was published");

    #[cfg(not(feature = "fips"))]
    ordinary_profile::assert_provider_matches_backend(
        &fips::base_crypto_provider(),
        AeadBackend::Ring,
    );
}

/// Marker for the child of
/// `ferrum_tls_constructors_need_no_process_default_provider`.
const NO_DEFAULT_PROVIDER_CHILD: &str = "AEAD_BACKEND_NO_DEFAULT_PROVIDER_TEST_CHILD";

#[test]
fn ferrum_tls_constructors_need_no_process_default_provider() {
    // rustls's provider-less builders (`WebPkiClientVerifier::builder`,
    // `ClientConfig::builder`) read the process-default provider and, when none
    // is installed, the one its crate features name. With both of rustls's
    // providers linked that fallback is ambiguous and the call panics, so
    // Ferrum's own constructors must name their provider and must work in a
    // process where nothing was ever installed.
    if std::env::var_os(NO_DEFAULT_PROVIDER_CHILD).is_none() {
        run_child(
            "ferrum_tls_constructors_need_no_process_default_provider",
            NO_DEFAULT_PROVIDER_CHILD,
            "1",
        );
        return;
    }
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "the child must start with no process-default provider"
    );

    // A client CA and an ECDSA server leaf it signed, as PEM files.
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "aead backend test CA");
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let server_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let server_cert = rcgen::CertificateParams::new(vec!["aead-backend.test".to_string()])
        .expect("server params")
        .signed_by(&server_key, &issuer)
        .expect("server cert");

    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server-key.pem");
    let ca_path = dir.path().join("client-ca.pem");
    std::fs::write(&cert_path, server_cert.pem()).expect("write server cert");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("write server key");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write client CA");
    let cert = cert_path.to_str().expect("utf-8 path");
    let key = key_path.to_str().expect("utf-8 path");
    let ca = ca_path.to_str().expect("utf-8 path");

    let policy = ferrum_edge::tls::TlsPolicy {
        protocol_versions: vec![&rustls::version::TLS12, &rustls::version::TLS13],
        crypto_provider: std::sync::Arc::new(fips::base_crypto_provider()),
        prefer_server_cipher_order: false,
        session_cache_size: 64,
        early_data_max_size: 0,
    };

    // Frontend mTLS: proxy HTTPS/H2, TCP+TLS, admin HTTPS and CP gRPC.
    ferrum_edge::tls::load_tls_config_with_client_auth(
        cert,
        key,
        Some(ca),
        false,
        &policy,
        30,
        30,
        &[],
    )
    .expect("frontend mTLS configuration builds without a process default");
    // The HTTP/3 listener's client-certificate verifier.
    ferrum_edge::tls::build_client_cert_verifier(ca, &[])
        .expect("the HTTP/3 client verifier builds without a process default");
    // Frontend DTLS with client-certificate verification.
    ferrum_edge::dtls::build_frontend_dtls_config(cert, key, Some(ca), &[], Some(&policy))
        .expect("frontend DTLS configuration builds without a process default");

    // And none of them reached for the global accessor, which would have
    // installed a provider as a side effect where it did not panic.
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "a Ferrum TLS constructor installed a process-default provider"
    );
}

/// Marker for the child of
/// `kubernetes_client_builds_without_a_bootstrapped_provider`.
const KUBE_CLIENT_CHILD: &str = "AEAD_BACKEND_KUBE_CLIENT_TEST_CHILD";

#[test]
fn kubernetes_client_builds_without_a_bootstrapped_provider() {
    // `ferrum-cni await-cleanup` builds a Kubernetes client in a process that
    // never runs the gateway bootstrap, and kube-client's TLS setup uses the
    // provider-less `ClientConfig::builder()`. The one Kubernetes-client
    // constructor therefore has to make sure a provider exists.
    if std::env::var_os(KUBE_CLIENT_CHILD).is_none() {
        run_child(
            "kubernetes_client_builds_without_a_bootstrapped_provider",
            KUBE_CLIENT_CHILD,
            "1",
        );
        return;
    }
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "the child must start with no process-default provider"
    );

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");

    // A cluster CA is set so kube-client takes its `with_root_certificates`
    // path rather than the platform verifier; nothing is ever dialled.
    let mut config = kube::Config::new(
        "https://127.0.0.1:6443"
            .parse()
            .expect("a valid cluster URL"),
    );
    config.root_cert = Some(vec![ca_cert.der().to_vec()]);

    // The client's service stack is spawned onto the current runtime.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _runtime_context = runtime.enter();
    let client = ferrum_edge::k8s_controller::build_kube_client_from_config(config);
    assert!(
        client.is_ok(),
        "the Kubernetes client must build without a bootstrapped provider: {:?}",
        client.as_ref().err()
    );

    // The constructor installed the build's baseline provider, not a selection.
    let installed = rustls::crypto::CryptoProvider::get_default()
        .expect("the constructor installed a provider");
    #[cfg(not(feature = "fips"))]
    ordinary_profile::assert_provider_matches_backend(installed, AeadBackend::Ring);
    #[cfg(feature = "fips")]
    assert!(
        installed.fips(),
        "the FIPS build installs the module's provider"
    );
    assert_eq!(
        aead_backend::selection().request,
        AeadBackendRequest::Auto,
        "building a client publishes no record-layer selection"
    );
}

// ── Production code names its rustls provider ───────────────────────────────

/// rustls constructors that read the process-default provider instead of
/// taking one, written without whitespace.
const PROVIDER_LESS_CONSTRUCTORS: [&str; 10] = [
    "ClientConfig::builder()",
    "ServerConfig::builder()",
    "ClientConfig::builder_with_protocol_versions(",
    "ServerConfig::builder_with_protocol_versions(",
    "WebPkiClientVerifier::builder(",
    "WebPkiServerVerifier::builder(",
    // hyper-rustls connector shorthands, each of which starts from
    // `ClientConfig::builder()`.
    "HttpsConnectorBuilder::new().with_platform_verifier()",
    "HttpsConnectorBuilder::new().try_with_platform_verifier()",
    "HttpsConnectorBuilder::new().with_native_roots()",
    "HttpsConnectorBuilder::new().with_webpki_roots()",
];

/// The attribute that makes an item test-only, as `cargo fmt` writes it.
const TEST_ONLY_ATTRIBUTE: &str = "#[cfg(test)]";

/// Reported in place of a constructor when a file could not be read to its
/// end, so the file fails the guard instead of passing unread.
const UNDELIMITED_SOURCE: &str =
    "a comment, a literal or a #[cfg(test)] item whose end was not found";

/// `text` reduced to its production code, with all whitespace removed, or
/// `None` when a comment, a literal or a test-only item never ends.
///
/// Comments are dropped and string and character literals emptied first, so
/// nothing written inside one can pass for code, for an attribute or for a
/// delimiter. Every item under a bare `#[cfg(test)]` is then dropped by
/// matching its delimiters, whatever its layout. Removing whitespace makes the
/// search indifferent to how a call is wrapped.
///
/// Where the scan cannot be exact it reads test code as production code, never
/// the reverse: an attribute that is not the bare `#[cfg(test)]` (such as
/// `#[cfg(all(test, unix))]`) exempts nothing, and a test-only item can end
/// early (see `after_test_only_item`). What it does not see is a constructor
/// reached through a renamed import or written by a macro. What it cannot
/// delimit is an attribute inside a macro invocation that has a grammar of
/// its own, or on a `where` predicate. The runtime tests above are what cover
/// the paths that matter.
fn production_source(text: &str) -> Option<String> {
    let code = code_only(text)?;
    let mut production = String::with_capacity(code.len());
    let mut rest = code.as_str();
    while let Some((before, after)) = rest.split_once(TEST_ONLY_ATTRIBUTE) {
        production.push_str(before);
        rest = after_test_only_item(after)?;
    }
    production.push_str(rest);
    production.retain(|character| !character.is_whitespace());
    Some(production)
}

/// `text` with its comments removed and its string and character literals
/// emptied, or `None` when one of them never ends.
///
/// Tokens are read forwards, the way the compiler reads them: a word (an
/// identifier, a keyword or a number) is taken whole, a literal takes its
/// suffix with it, and a lifetime takes its name. A raw string is therefore
/// recognised by the word in front of it being exactly `r`, `br` or `cr`,
/// never by whichever character happens to precede a quote.
fn code_only(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut code = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(&current) = chars.get(index) {
        let next = chars.get(index + 1).copied();
        match current {
            '/' if next == Some('/') => {
                while chars.get(index).is_some_and(|&character| character != '\n') {
                    index += 1;
                }
            }
            '/' if next == Some('*') => {
                index = end_of_block_comment(&chars, index + 2)?;
                code.push(' ');
            }
            '"' => {
                index = end_of_word(&chars, end_of_quoted(&chars, index + 1, '"')?);
                code.push_str("\"\"");
            }
            // A character literal: an escape, or one character and its quote.
            '\'' if next == Some('\\') => {
                index = end_of_word(&chars, end_of_quoted(&chars, index + 1, '\'')?);
                code.push_str("''");
            }
            '\'' if chars.get(index + 2) == Some(&'\'') => {
                index = end_of_word(&chars, index + 3);
                code.push_str("''");
            }
            // Any other `'` starts a lifetime or a label.
            '\'' => {
                let end = end_of_word(&chars, index + 1);
                code.extend(&chars[index..end]);
                index = end;
            }
            _ if is_word(current) => {
                let end = end_of_word(&chars, index);
                match raw_string_contents(&chars, index, end) {
                    Some((contents, hashes)) => {
                        let closed = end_of_raw_string(&chars, contents, hashes)?;
                        index = end_of_word(&chars, closed);
                        code.push_str("\"\"");
                    }
                    None => {
                        code.extend(&chars[index..end]);
                        index = end;
                    }
                }
            }
            _ => {
                code.push(current);
                index += 1;
            }
        }
    }
    Some(code)
}

/// `true` for a character of an identifier, a keyword, a number or a literal
/// suffix.
fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The index after the run of word characters that starts at `start`, which
/// is `start` itself when there is none. After a literal, that run is the
/// literal's suffix.
fn end_of_word(chars: &[char], start: usize) -> usize {
    start
        + chars[start..]
            .iter()
            .take_while(|&&character| is_word(character))
            .count()
}

/// The index after the block comment whose text starts at `start`. Block
/// comments nest.
fn end_of_block_comment(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut index = start;
    while depth > 0 {
        match (*chars.get(index)?, chars.get(index + 1).copied()) {
            ('/', Some('*')) => {
                depth += 1;
                index += 2;
            }
            ('*', Some('/')) => {
                depth -= 1;
                index += 2;
            }
            _ => index += 1,
        }
    }
    Some(index)
}

/// The index after the closing `delimiter` of a string or character literal
/// whose contents start at `start`. A backslash escapes the next character.
fn end_of_quoted(chars: &[char], start: usize, delimiter: char) -> Option<usize> {
    let mut index = start;
    loop {
        match *chars.get(index)? {
            '\\' => index += 2,
            character if character == delimiter => return Some(index + 1),
            _ => index += 1,
        }
    }
}

/// Where a raw string's contents start, and how many `#`s close it, when the
/// word at `start..end` is a raw-string prefix with `#`s and a `"` after it.
fn raw_string_contents(chars: &[char], start: usize, end: usize) -> Option<(usize, usize)> {
    if !matches!(&chars[start..end], ['r'] | ['b', 'r'] | ['c', 'r']) {
        return None;
    }
    let hashes = chars[end..]
        .iter()
        .take_while(|&&character| character == '#')
        .count();
    (chars.get(end + hashes) == Some(&'"')).then_some((end + hashes + 1, hashes))
}

/// The index after the raw string whose contents start at `start` and which
/// closes with `"` followed by `hashes` `#`s.
fn end_of_raw_string(chars: &[char], start: usize, hashes: usize) -> Option<usize> {
    let mut index = start;
    loop {
        let end = index + 1 + hashes;
        if *chars.get(index)? == '"'
            && chars
                .get(index + 1..end)?
                .iter()
                .all(|&character| character == '#')
        {
            return Some(end);
        }
        index += 1;
    }
}

/// What follows the item that a `#[cfg(test)]` attribute applies to, given the
/// code right after that attribute; `None` when the item never ends.
///
/// The item ends at the first `;` or `,` outside its own brackets, at the
/// brace that closes its first block (an `else` continues it), or where
/// whatever encloses it closes: a block or a list, a generic parameter list
/// (`>`), a closure's parameters (`|`). None of those lies beyond the item, so
/// production code after it is never skipped. Several can come before its
/// end, such as a comma between generic arguments or a `>` or `|` used as an
/// operator; the rest of that test-only item is then read as production code.
fn after_test_only_item(source: &str) -> Option<&str> {
    let mut item = source.trim_start();
    // Further attributes on the same item.
    while item.starts_with("#[") {
        item = after_attribute(item)?.trim_start();
    }
    let mut depth = 0usize;
    // `<`s outside brackets that no `>` has matched yet.
    let mut angles = 0usize;
    for (offset, character) in item.char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' | '|' if depth == 0 => return Some(&item[offset..]),
            '<' if depth == 0 => angles += 1,
            // Not the `>` of `->` or `=>`.
            '>' if depth == 0 && !item[..offset].ends_with(['-', '=']) => {
                if angles == 0 {
                    return Some(&item[offset..]);
                }
                angles -= 1;
            }
            ')' | ']' => depth -= 1,
            '}' => {
                depth -= 1;
                let after = &item[offset + 1..];
                if depth == 0 && !continues_with_else(after) {
                    let next = after.trim_start();
                    return Some(next.strip_prefix([';', ',']).unwrap_or(after));
                }
            }
            ';' | ',' if depth == 0 => return Some(&item[offset + 1..]),
            _ => {}
        }
    }
    None
}

/// What follows the attribute that `source` starts with; `None` when its
/// bracket never closes.
fn after_attribute(source: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (offset, character) in source.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&source[offset + 1..]);
                }
            }
            _ => {}
        }
    }
    None
}

/// `true` when the code after a closing brace goes on with an `else` branch.
fn continues_with_else(after_brace: &str) -> bool {
    after_brace
        .trim_start()
        .strip_prefix("else")
        .is_some_and(|rest| {
            !rest.starts_with(|character: char| character.is_alphanumeric() || character == '_')
        })
}

/// The provider-less constructors in `text`'s production code, or a marker
/// when the file could not be scanned.
fn provider_less_constructors_in(text: &str) -> Vec<&'static str> {
    let Some(production) = production_source(text) else {
        return vec![UNDELIMITED_SOURCE];
    };
    PROVIDER_LESS_CONSTRUCTORS
        .into_iter()
        .filter(|pattern| production.contains(pattern))
        .collect()
}

#[test]
fn production_code_names_its_rustls_provider() {
    // With both of rustls's providers linked, a provider-less constructor
    // panics unless a process default was installed. The gateway binary always
    // installs one, but the library must not depend on that, so every
    // constructor in production code names its provider. The runtime tests
    // above cover the verifier and Kubernetes paths; this covers the rest (log
    // sinks, health probes, ACME) by construction. Inline `#[cfg(test)]`
    // items are exempt: they install a default first.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut pending = vec![root.join("src")];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("read a source directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            scanned += 1;
            let text = std::fs::read_to_string(&path).expect("read a source file");
            for pattern in provider_less_constructors_in(&text) {
                let relative = path
                    .strip_prefix(&root)
                    .expect("the file is under the repository root")
                    .to_string_lossy()
                    .replace('\\', "/");
                offenders.push(format!("{relative}: {pattern}"));
            }
        }
    }
    offenders.sort();
    assert!(scanned > 100, "the scan did not reach the source tree");
    assert!(
        offenders.is_empty(),
        "production code under src/ reads rustls's process-default provider. Name the provider \
         instead (`builder_with_provider`, or `tls::backend_client_config_builder(None)` for a \
         client that takes the build defaults): {offenders:#?}"
    );
}

#[test]
fn the_provider_guard_rejects_the_forms_it_exists_for() {
    // The guard is only worth having if it sees what it claims to see.
    let caught = |source: &str| provider_less_constructors_in(source);

    assert_eq!(
        caught(
            "fn build() {\n    let config = rustls::ClientConfig::builder()\n        .with_root_certificates(roots);\n}\n"
        ),
        ["ClientConfig::builder()"]
    );
    assert_eq!(
        caught(
            "fn build() {\n    rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])\n}\n"
        ),
        ["ServerConfig::builder_with_protocol_versions("]
    );
    assert_eq!(
        caught(
            "fn build() {\n    ClientConfig::builder_with_protocol_versions(\n        versions,\n    )\n}\n"
        ),
        ["ClientConfig::builder_with_protocol_versions("]
    );
    // However the call is wrapped.
    assert_eq!(
        caught(
            "fn build() {\n    let verifier = WebPkiClientVerifier::builder(\n        roots,\n    );\n}\n"
        ),
        ["WebPkiClientVerifier::builder("]
    );
    assert_eq!(
        caught("fn build() {\n    rustls::ServerConfig::\n        builder ( )\n}\n"),
        ["ServerConfig::builder()"]
    );
    assert_eq!(
        caught(
            "fn build() {\n    HttpsConnectorBuilder::new()\n        .try_with_platform_verifier()\n}\n"
        ),
        ["HttpsConnectorBuilder::new().try_with_platform_verifier()"]
    );

    // Naming the provider is what the guard asks for.
    assert!(
        caught("fn build() {\n    rustls::ClientConfig::builder_with_provider(provider)\n}\n")
            .is_empty()
    );
    assert!(
        caught(
            "fn build() {\n    WebPkiClientVerifier::builder_with_provider(roots, provider)\n}\n"
        )
        .is_empty()
    );
    assert!(
        caught(
            "fn build() {\n    HttpsConnectorBuilder::new().with_provider_and_platform_verifier(provider)\n}\n"
        )
        .is_empty()
    );
    assert_eq!(
        caught("fn build() {\n    HttpsConnectorBuilder::new().with_native_roots()\n}\n"),
        ["HttpsConnectorBuilder::new().with_native_roots()"]
    );
    // Comments are not code.
    assert!(
        caught("/// Unlike `ClientConfig::builder()`, this names its provider.\nfn build() {}\n")
            .is_empty()
    );

    // An inline test module is exempt, and only the module: production code
    // before it, after it, and beside a test-only item inside an `impl` is not.
    let inline_tests = "fn build() {}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn it_builds() {\n        let config = rustls::ServerConfig::builder();\n    }\n}\n";
    assert!(caught(inline_tests).is_empty());
    let production_after_tests =
        format!("{inline_tests}\nfn late() {{\n    rustls::ClientConfig::builder()\n}}\n");
    assert_eq!(caught(&production_after_tests), ["ClientConfig::builder()"]);
    let production_before_tests =
        format!("fn early() {{\n    rustls::ClientConfig::builder()\n}}\n\n{inline_tests}");
    assert_eq!(
        caught(&production_before_tests),
        ["ClientConfig::builder()"]
    );
    let test_only_method = "impl Sink {\n    #[cfg(test)]\n    fn for_test() -> Self {\n        rustls::ServerConfig::builder()\n    }\n\n    fn real(&self) {\n        rustls::ClientConfig::builder()\n    }\n}\n";
    assert_eq!(caught(test_only_method), ["ClientConfig::builder()"]);
    // A comment after the module's closing brace does not extend the exemption.
    let commented_close = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn test_only() {}\n} // end tests\n\nfn real() {\n    let _ = rustls::ClientConfig::builder();\n}\n";
    assert_eq!(caught(commented_close), ["ClientConfig::builder()"]);
    let commented_statement_close = "#[cfg(test)]\nconst FIXTURE: Fixture = Fixture {\n    name: \"x\",\n}; // fixture\n\nfn real() {\n    rustls::ServerConfig::builder()\n}\n";
    assert_eq!(
        caught(commented_statement_close),
        ["ServerConfig::builder()"]
    );
    // Nor does a comment after a test-only item that has no body, or a block
    // comment after a closing brace.
    let commented_bodyless = "#[cfg(test)]\nconst FIXTURE: u8 = 0; // used only by tests\n\nfn real() {\n    let _ = rustls::ClientConfig::builder();\n}\n";
    assert_eq!(caught(commented_bodyless), ["ClientConfig::builder()"]);
    let block_commented_close = "#[cfg(test)]\nmod tests {\n    fn test_only() {}\n} /* end tests */\n\nfn real() {\n    rustls::ClientConfig::builder()\n}\n";
    assert_eq!(caught(block_commented_close), ["ClientConfig::builder()"]);
    // A test-only statement, field or branch ends where it ends, however the
    // code around it is laid out.
    let test_only_statement = "fn real() {\n    #[cfg(test)]\n    let hook = make_hook(|| {\n        rustls::ServerConfig::builder();\n    });\n    let config = rustls::ClientConfig::builder();\n    if ready {\n        go();\n    }\n}\n";
    assert_eq!(caught(test_only_statement), ["ClientConfig::builder()"]);
    let test_only_field = "struct Sink {\n    #[cfg(test)]\n    hook: Hook,\n}\n\nfn real() {\n    rustls::ServerConfig::builder()\n}\n";
    assert_eq!(caught(test_only_field), ["ServerConfig::builder()"]);
    let test_only_branch = "fn real() {\n    #[cfg(test)]\n    if hooked {\n        first();\n    } else {\n        rustls::ServerConfig::builder();\n    }\n    rustls::ClientConfig::builder();\n}\n";
    assert_eq!(caught(test_only_branch), ["ClientConfig::builder()"]);
    // An attribute on a generic or closure parameter ends with the parameter.
    assert_eq!(
        caught("fn real<#[cfg(test)] T>() {\n    rustls::ClientConfig::builder()\n}\n"),
        ["ClientConfig::builder()"]
    );
    assert_eq!(
        caught(
            "fn real<#[cfg(test)] T: Into<String>, U>() {\n    rustls::ClientConfig::builder()\n}\n"
        ),
        ["ClientConfig::builder()"]
    );
    assert_eq!(
        caught("fn real() {\n    run(|#[cfg(test)] hook| rustls::ServerConfig::builder())\n}\n"),
        ["ServerConfig::builder()"]
    );
    // Text inside a literal is not code: a brace or an attribute spelled in
    // one changes nothing, and a constructor spelled in one is not a call.
    let brace_in_string = "#[cfg(test)]\nfn fixture() -> &'static str {\n    \"{\"\n}\n\nfn real() {\n    rustls::ClientConfig::builder()\n}\n";
    assert_eq!(caught(brace_in_string), ["ClientConfig::builder()"]);
    let brace_in_character = "#[cfg(test)]\nfn fixture() -> char {\n    '{'\n}\n\nfn real() {\n    rustls::ClientConfig::builder()\n}\n";
    assert_eq!(caught(brace_in_character), ["ClientConfig::builder()"]);
    let attribute_in_string = "const TEMPLATE: &str = r#\"\n#[cfg(test)]\nmod tests {\n\"#;\n\nfn real() {\n    rustls::ClientConfig::builder()\n}\n";
    assert_eq!(caught(attribute_in_string), ["ClientConfig::builder()"]);
    assert!(
        caught("fn hint() -> &'static str {\n    \"prefer ClientConfig::builder() with a provider\"\n}\n")
            .is_empty()
    );
    // A literal's suffix belongs to it: the `r` after the first string here is
    // not the prefix of a raw string, which would run on to the last quote.
    let suffixed_literal = "macro_rules! discard {\n    ($($tokens:tt)*) => {};\n}\n\ndiscard!(\"\"r\"\\\"\");\n\nfn real() {\n    let _ = rustls::ClientConfig::builder();\n}\n\ndiscard!(\"\\\"\");\n";
    assert_eq!(caught(suffixed_literal), ["ClientConfig::builder()"]);
    // A raw string is still one literal, quotes and all.
    let raw_literal = "const QUOTED: &str = r#\"a \"quoted\" {\"#;\n\nfn real() {\n    rustls::ClientConfig::builder()\n}\n";
    assert_eq!(caught(raw_literal), ["ClientConfig::builder()"]);
    // A file that cannot be read to its end fails the guard; it is never read
    // as "the rest of the file is test code".
    assert_eq!(
        caught("fn real() {\n    let text = \"never closed;\n}\n"),
        [UNDELIMITED_SOURCE]
    );
    let undelimited = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn test_only() {\n        rustls::ClientConfig::builder();\n    }\n";
    assert_eq!(caught(undelimited), [UNDELIMITED_SOURCE]);

    // A block comment is not code: an attribute spelled inside one starts no
    // test item, a constructor spelled inside one is not a call, and one that
    // never ends is reported.
    assert_eq!(
        caught("/*\n#[cfg(test)]\n*/\nfn real() {\n    rustls::ClientConfig::builder()\n}\n"),
        ["ClientConfig::builder()"]
    );
    assert!(caught("/*\n    rustls::ClientConfig::builder()\n*/\nfn real() {}\n").is_empty());
    assert_eq!(
        caught("/*\nfn real() {\n    rustls::ClientConfig::builder()\n}\n"),
        [UNDELIMITED_SOURCE]
    );
    // A test-only item with no body hides nothing that follows it.
    let test_only_import = "#[cfg(test)]\nuse std::sync::Once;\n\nfn real() {\n    rustls::ClientConfig::builder()\n}\n";
    assert_eq!(caught(test_only_import), ["ClientConfig::builder()"]);
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
                    client.local.packet.as_ref(),
                    server.remote.packet.as_ref(),
                    &label,
                );
                assert_packet_keys_interoperate(
                    server.local.packet.as_ref(),
                    client.remote.packet.as_ref(),
                    &label,
                );
                assert_header_keys_interoperate(
                    client.local.header.as_ref(),
                    server.remote.header.as_ref(),
                    &label,
                );
                assert_header_keys_interoperate(
                    server.local.header.as_ref(),
                    client.remote.header.as_ref(),
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
