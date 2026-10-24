#!/usr/bin/env python3
"""Audit the resolved cargo feature graph for the FIPS build profile.

The `crypto-ring` / `fips` cargo features in `Cargo.toml` are the *declared*
contract, and `src/fips/mod.rs` fails compilation when both or neither is
selected. Neither of those catches the failure mode this check exists for: a
**transitive** edge that re-enables `rustls/ring` (or leaves a dependency on its
ring arm) without this crate's own feature list mentioning it. That build looks
switched, reports a FIPS provider, and still routes some traffic through a
non-validated implementation.

So this reads what cargo actually resolved, not what the manifest asked for.

Usage:

    check_fips_feature_policy.py --manifest-check
        Static checks over `Cargo.toml` only. No cargo invocation, no network.

    check_fips_feature_policy.py --tree <path-to-cargo-tree-output> --profile fips
    check_fips_feature_policy.py --tree <path> --profile crypto-ring
        Audit provider selections from `cargo tree -e normal,build
        --prefix none -f '{p}|{f}'` output for that profile.

The normal/build edge filter is load-bearing: test fixtures pin `ring` and
`rustls/ring` as dev-dependencies so the suite compiles under both profiles,
and a dev-dependency is never linked into the shipped binary. Feature-edge
mode can still report the root package's dev-only feature unification even
when combined with `no-dev`; formatting the selected features on normal/build
package nodes audits the production graph instead.

Exit status is 0 when the profile is admissible and 1 otherwise, with every
violation printed.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "Cargo.toml"

# Feature edges that must be present in the `fips` feature list and absent from
# it, paired with their `crypto-ring` counterparts. Each pair is one dependency
# whose aws-lc arm is gated on the absence of its ring arm, so "additively
# enable aws-lc" is not sufficient for it.
REQUIRED_FEATURE_PAIRS = (
    ("rustls/ring", "rustls/fips"),
    ("tokio-rustls/ring", "tokio-rustls/fips"),
    ("tonic/tls-ring", "tonic/tls-aws-lc"),
    ("quinn/rustls-ring", "quinn/rustls-aws-lc-rs-fips"),
    ("sqlx/tls-rustls-ring", "sqlx/tls-rustls-aws-lc-rs"),
    ("ldap3/tls-rustls-ring", "ldap3/tls-rustls-aws-lc-rs"),
    ("rcgen/ring", "rcgen/fips"),
    ("x509-parser/verify", "x509-parser/verify-aws"),
    ("reqwest/__rustls-ring", "reqwest/__rustls-aws-lc-rs"),
    ("hyper-rustls?/ring", "hyper-rustls?/fips"),
    ("instant-acme?/ring", "instant-acme?/fips"),
    ("kube/ring", "kube/aws-lc-rs"),
    ("mongodb/rustls-tls", "mongodb/rustls-tls-aws-lc"),
)

# The `fips` feature must additionally bind the validated module itself.
#
# `aws-lc-rs/fips` is the *only* entry needed for that: on an optional
# dependency, a `dep/feature` edge already activates the dependency, so a
# companion `dep:aws-lc-rs` would be a duplicate activation of the same optional
# dep. `crypto-ring` still needs an explicit `dep:ring`, because `ring` is
# activated by nothing else in that list.
REQUIRED_FIPS_ONLY = ("aws-lc-rs/fips",)
REQUIRED_RING_ONLY = ("dep:ring",)

# Neither profile may name the other's backend crate at all, in any spelling.
# The pair table above catches a known counterpart edge; this catches a *new*
# edge onto the wrong crate that nobody thought to pair. jsonwebtoken's inline
# `aws_lc_rs` (REQUIRED_INLINE_DECLARATIONS) is outside both lists by design:
# it is the same AWS-LC selection on both profiles, not a profile arm.
BACKEND_CRATE_PREFIXES = {
    "crypto-ring": ("aws-lc-rs", "aws_lc_rs", "aws-lc-fips-sys", "aws-lc-sys"),
    "fips": ("ring",),
}

# Optional feature combinations the PR claims are supported on the FIPS
# profile. Each is audited as a resolved feature graph in CI, so a claim that an
# optional feature is FIPS-clean is checked rather than asserted in prose.
#
# `label` is the CI step name; `features` is the exact `--features` argument.
# Every entry is built with `--no-default-features`.
#
# `secrets-*` / `cloud-secrets` are deliberately absent. Their SDKs carry their
# own TLS stacks that Ferrum's provider seam does not reach, so rather than
# claim a coverage this build cannot back, an enforcing FIPS process REFUSES an
# external secret provider before it is used (`fips::policy::check_env_config`,
# `docs/fips.md` §"Deliberately unsupported in FIPS mode"). They are still
# audited below, under CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME, so the
# combination is proven to *build* and the refusal is proven to be the only
# thing standing between it and use.
CLAIMED_FIPS_PROFILES = (
    ("fips", "fips"),
    ("fips + acme", "fips,acme"),
    ("fips + pkcs11", "fips,pkcs11"),
    ("fips + ebpf", "fips,ebpf"),
    ("fips + bench-h1-profile", "fips,bench-h1-profile"),
    ("fips + bench-pool-profile", "fips,bench-pool-profile"),
    ("fips + bench-udp-profile", "fips,bench-udp-profile"),
    ("fips + bench-h1-profile + bench-udp-profile", "fips,bench-h1-profile,bench-udp-profile"),
    ("fips + acme + pkcs11 + ebpf", "fips,acme,pkcs11,ebpf"),
)

# Combinations that must build cleanly and must be refused at runtime.
CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME = (
    ("fips + cloud-secrets", "fips,cloud-secrets"),
)

# Dependencies that must never be declared with an inline crypto-backend
# feature: the backend belongs to the mutually exclusive feature pair, and an
# inline selection would silently win on both profiles.
FORBIDDEN_INLINE_DECLARATIONS = {
    "rustls": ("ring", "aws_lc_rs", "aws-lc-rs", "fips"),
    "tokio-rustls": ("ring", "aws_lc_rs", "aws-lc-rs", "fips"),
    "tonic": ("tls-ring", "tls-aws-lc"),
    "sqlx": ("runtime-tokio-rustls", "tls-rustls", "tls-rustls-ring"),
    "ldap3": ("tls-rustls-ring", "tls-rustls-aws-lc-rs"),
    "hyper-rustls": ("ring", "aws-lc-rs", "fips"),
    "instant-acme": ("ring", "aws-lc-rs", "fips"),
    "kube": ("ring", "aws-lc-rs"),
    "mongodb": ("rustls-tls", "rustls-tls-aws-lc"),
    "x509-parser": ("verify", "verify-aws"),
    # jsonwebtoken is the one deliberate inline selection: see
    # REQUIRED_INLINE_DECLARATIONS below. `rust_crypto` is never admissible.
    "jsonwebtoken": ("rust_crypto",),
    "reqwest": ("rustls",),
}

# Dependencies whose crypto backend is selected inline, identically on both
# profiles, instead of through the feature pair. jsonwebtoken 11 chooses its
# provider automatically only when exactly one of `rust_crypto` / `aws_lc_rs`
# is compiled, and a `fips` build already routes `aws-lc-rs` onto the
# validated module through `aws-lc-rs/fips`. Selecting `aws_lc_rs` inline keeps
# exactly one backend in every feature combination, and keeps the RustCrypto
# `rsa` / `p256` / `p384` signers (RUSTSEC-2023-0071, RUSTSEC-2026-0387) out of
# the ordinary build. Neither profile list may name these dependencies'
# backend features.
REQUIRED_INLINE_DECLARATIONS = {
    "jsonwebtoken": ("aws_lc_rs",),
}

# Dependencies that must be declared with `default-features = false`, because
# their default feature set selects a crypto backend.
REQUIRE_DEFAULT_FEATURES_OFF = (
    "kube",
    "mongodb",
    "quinn",
    "rcgen",
    "rustls",
    "tokio-rustls",
)

# `cargo tree -e features` prints feature edges as `crate feature "name"`.
FEATURE_EDGE = re.compile(r'^[^a-zA-Z0-9]*([A-Za-z0-9_.-]+) feature "([A-Za-z0-9_.-]+)"')
PACKAGE_FEATURE_ROW = re.compile(r'^([A-Za-z0-9_.-]+) v[^|]+\|(.*)$')
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Feature selections that must never appear in a resolved `fips` graph. Each
# one puts a non-validated implementation in control of a real traffic path.
FORBIDDEN_RESOLVED_FIPS = {
    ("rustls", "ring"),
    ("tokio-rustls", "ring"),
    ("quinn", "rustls-ring"),
    ("quinn-proto", "rustls-ring"),
    ("sqlx", "tls-rustls-ring"),
    ("sqlx-core", "_tls-rustls-ring-webpki"),
    ("sqlx-core", "_tls-rustls-ring-native-roots"),
    ("ldap3", "tls-rustls-ring"),
    ("tonic", "tls-ring"),
    ("hyper-rustls", "ring"),
    ("kube", "ring"),
    ("kube-client", "ring"),
    ("mongodb", "rustls-tls"),
    ("rcgen", "ring"),
    ("jsonwebtoken", "rust_crypto"),
    ("x509-parser", "verify"),
    ("reqwest", "__rustls-ring"),
    ("rustls-webpki", "ring"),
    ("webpki", "ring"),
    # Only reachable with `--features acme`, which is one of the claimed
    # profiles below, so this row is what makes that claim mean something.
    # (`hyper-rustls/aws-lc-rs` is deliberately NOT forbidden here:
    # `hyper-rustls/fips` enables it, so it is the *expected* selection.)
    ("instant-acme", "ring"),
}

# Feature selections that must be present in a resolved `fips` graph.
REQUIRED_RESOLVED_FIPS = {
    ("aws-lc-rs", "fips"),
    ("jsonwebtoken", "aws_lc_rs"),
    ("kube", "aws-lc-rs"),
    ("mongodb", "rustls-tls-aws-lc"),
    ("reqwest", "__rustls-aws-lc-rs"),
    ("rustls", "fips"),
}

# The ordinary profile's contract, so a change that quietly moves the default
# build onto a different backend is caught too.
REQUIRED_RESOLVED_RING = {
    ("jsonwebtoken", "aws_lc_rs"),
    ("kube", "ring"),
    ("mongodb", "rustls-tls"),
    ("reqwest", "__rustls-ring"),
    ("rustls", "ring"),
}
FORBIDDEN_RESOLVED_RING = {
    ("aws-lc-rs", "fips"),
    ("jsonwebtoken", "rust_crypto"),
    ("rustls", "fips"),
}

# Ferrum-owned production code must not bypass `crate::fips::approved` by
# importing the independent RustCrypto reference implementations. Test code is
# deliberately exempt: it uses those crates to verify module-backed outputs
# against an implementation that does not share the production seam.
FORBIDDEN_PRODUCTION_CRATE_PATTERNS = (
    re.compile(r"\buse\s+sha2(?:::|\s*;)"),
    re.compile(r"\bsha2::"),
    re.compile(r"\buse\s+hmac(?:::|\s*;)"),
    re.compile(r"\bhmac::Hmac\b"),
)


def read_manifest() -> str:
    return MANIFEST.read_text(encoding="utf-8")


def feature_list(manifest: str, name: str) -> list[str]:
    """Extract one entry of the `[features]` table as a list of strings."""

    # Single-line spelling first: the multi-line pattern would otherwise run
    # past a one-line list's own closing bracket to the next block-closing `]`.
    match = re.search(rf"^{re.escape(name)} = \[([^\n\]]*)\]$", manifest, re.M)
    if match is None:
        match = re.search(rf"^{re.escape(name)} = \[(.*?)^\]", manifest, re.M | re.S)
    if match is None:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def dependency_line(manifest: str, name: str) -> str | None:
    match = re.search(rf'^{re.escape(name)} = (\{{.*?\}}|"[^"]*")$', manifest, re.M)
    return match.group(1) if match else None


def check_manifest() -> list[str]:
    manifest = read_manifest()
    failures: list[str] = []

    ring_features = feature_list(manifest, "crypto-ring")
    fips_features = feature_list(manifest, "fips")
    if not ring_features:
        failures.append("Cargo.toml has no `crypto-ring` feature list")
    if not fips_features:
        failures.append("Cargo.toml has no `fips` feature list")

    default_features = feature_list(manifest, "default")
    if default_features != ["crypto-ring"]:
        failures.append(
            "the default feature set must be exactly [\"crypto-ring\"] so the ordinary "
            f"build is unchanged; found {default_features}"
        )

    for ring_edge, fips_edge in REQUIRED_FEATURE_PAIRS:
        if ring_edge not in ring_features:
            failures.append(f"`crypto-ring` must select {ring_edge!r}")
        if fips_edge not in fips_features:
            failures.append(f"`fips` must select {fips_edge!r}")
        if ring_edge in fips_features:
            failures.append(
                f"`fips` must not select the ring arm {ring_edge!r} — the aws-lc arm of that "
                "dependency is gated on its absence"
            )
        if fips_edge in ring_features:
            failures.append(f"`crypto-ring` must not select {fips_edge!r}")

    for edge in REQUIRED_FIPS_ONLY:
        if edge not in fips_features:
            failures.append(f"`fips` must select {edge!r} to bind the validated module")
    for edge in REQUIRED_RING_ONLY:
        if edge not in ring_features:
            failures.append(f"`crypto-ring` must select {edge!r} to bind the ordinary backend")

    # A duplicate entry in either list is a manifest-integrity fault in its own
    # right: the two lists are read position-for-position as counterparts, and a
    # repeated entry silently breaks that correspondence for every reviewer
    # after it. It is also how a redundant optional-dependency activation
    # (`dep:x` beside `x/feature`) gets in.
    for profile, entries in (("crypto-ring", ring_features), ("fips", fips_features)):
        seen: set[str] = set()
        for entry in entries:
            if entry in seen:
                failures.append(
                    f"`{profile}` lists {entry!r} more than once; each dependency's crypto arm "
                    "must appear exactly once"
                )
            seen.add(entry)
        # `dep:x` beside `x/...` for the same optional dep is the same fault in
        # a different spelling: the `dep/feature` edge already activates it.
        activated_by_feature = {
            entry.split("/", 1)[0].rstrip("?") for entry in entries if "/" in entry
        }
        for entry in entries:
            if entry.startswith("dep:") and entry[4:] in activated_by_feature:
                failures.append(
                    f"`{profile}` selects {entry!r} redundantly: a `{entry[4:]}/<feature>` edge "
                    "in the same list already activates that optional dependency"
                )

    for profile, entries in (("crypto-ring", ring_features), ("fips", fips_features)):
        for prefix in BACKEND_CRATE_PREFIXES[profile]:
            for entry in entries:
                crate = entry.removeprefix("dep:").split("/", 1)[0].rstrip("?")
                if crate == prefix:
                    failures.append(
                        f"`{profile}` names the opposing backend crate {crate!r} via {entry!r}; "
                        "the profiles are mutually exclusive"
                    )

    for dep, forbidden in FORBIDDEN_INLINE_DECLARATIONS.items():
        line = dependency_line(manifest, dep)
        if line is None:
            failures.append(f"dependency {dep!r} is not declared on its own line in Cargo.toml")
            continue
        inline = set(re.findall(r'"([^"]+)"', line))
        for feature in forbidden:
            if feature in inline:
                failures.append(
                    f"dependency {dep!r} must not select the crypto-backend feature "
                    f"{feature!r} inline; it belongs to the `crypto-ring` / `fips` pair"
                )

    for dep, required in REQUIRED_INLINE_DECLARATIONS.items():
        line = dependency_line(manifest, dep)
        if line is None:
            failures.append(f"dependency {dep!r} is not declared on its own line in Cargo.toml")
            continue
        inline = set(re.findall(r'"([^"]+)"', line))
        for feature in required:
            if feature not in inline:
                failures.append(
                    f"dependency {dep!r} must select the crypto-backend feature {feature!r} "
                    "inline so exactly one backend is compiled on every profile"
                )
        for profile, entries in (("crypto-ring", ring_features), ("fips", fips_features)):
            for entry in entries:
                if entry.split("/", 1)[0].rstrip("?") == dep:
                    failures.append(
                        f"`{profile}` must not select {entry!r}: the {dep!r} backend is "
                        "selected inline, identically on both profiles"
                    )

    for dep in REQUIRE_DEFAULT_FEATURES_OFF:
        line = dependency_line(manifest, dep)
        if line is None:
            failures.append(f"dependency {dep!r} is not declared on its own line in Cargo.toml")
        elif "default-features = false" not in line:
            failures.append(
                f"dependency {dep!r} must be declared with `default-features = false`; its "
                "default feature set selects a cryptographic backend"
            )

    dependency_table = re.search(
        r"^\[dependencies\]\s*$\n(.*?)(?=^\[)", manifest, re.M | re.S
    )
    if dependency_table is None:
        failures.append("Cargo.toml has no `[dependencies]` table")
    else:
        for reference_crate in ("sha2", "hmac"):
            if re.search(
                rf"^{re.escape(reference_crate)}\s*=",
                dependency_table.group(1),
                re.M,
            ):
                failures.append(
                    f"RustCrypto reference crate {reference_crate!r} must be dev-only; "
                    "production SHA-2/HMAC uses crate::fips::approved"
                )

    for source_path in sorted((REPO_ROOT / "src").rglob("*.rs")):
        # This module intentionally names the old API in rustdoc while
        # implementing the provider-backed compatibility surface itself.
        if source_path == REPO_ROOT / "src/fips/approved.rs":
            continue
        source = source_path.read_text(encoding="utf-8")
        if any(pattern.search(source) for pattern in FORBIDDEN_PRODUCTION_CRATE_PATTERNS):
            failures.append(
                f"{source_path.relative_to(REPO_ROOT)} imports a RustCrypto SHA-2/HMAC "
                "implementation; route it through crate::fips::approved"
            )

    return failures


def parse_tree(path: Path) -> set[tuple[str, str]]:
    selections: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        clean = ANSI_ESCAPE.sub("", line).strip()
        package_match = PACKAGE_FEATURE_ROW.match(clean)
        if package_match:
            crate = package_match.group(1)
            for feature in package_match.group(2).split(","):
                feature = feature.strip()
                if feature:
                    selections.add((crate, feature))
            continue

        # Retain support for old captured feature-edge trees so operators can
        # still audit an existing diagnostic file. Hosted CI uses package-row
        # mode above because it excludes dev-only feature unification.
        feature_match = FEATURE_EDGE.match(clean)
        if feature_match:
            selections.add((feature_match.group(1), feature_match.group(2)))
    return selections


def check_tree(path: Path, profile: str) -> list[str]:
    selections = parse_tree(path)
    if not selections:
        return [
            f"no provider feature selections parsed from {path}; expected the output of "
            "`cargo tree -e normal,build --prefix none -f '{p}|{f}'`"
        ]

    if profile == "fips":
        required, forbidden = REQUIRED_RESOLVED_FIPS, FORBIDDEN_RESOLVED_FIPS
    elif profile == "crypto-ring":
        required, forbidden = REQUIRED_RESOLVED_RING, FORBIDDEN_RESOLVED_RING
    else:
        return [f"unknown profile {profile!r}"]

    failures: list[str] = []
    for crate, feature in sorted(required):
        if (crate, feature) not in selections:
            observed = sorted(
                selected_feature
                for selected_crate, selected_feature in selections
                if selected_crate == crate
            )
            failures.append(
                f"[{profile}] resolved graph is missing the required selection "
                f"{crate}/{feature}; observed {crate} features: {observed}"
            )
    for crate, feature in sorted(forbidden):
        if (crate, feature) in selections:
            failures.append(
                f"[{profile}] resolved graph still selects {crate}/{feature}, so a "
                "non-validated implementation remains in control of that path"
            )
    return failures


def claimed_profiles() -> tuple[tuple[str, str, bool], ...]:
    """Every claimed FIPS feature combination, with its runtime-support flag."""

    return tuple(
        (label, features, True) for label, features in CLAIMED_FIPS_PROFILES
    ) + tuple(
        (label, features, False)
        for label, features in CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME
    )


def check_claimed_profiles_declared() -> list[str]:
    """Every optional cargo feature must be accounted for by a claimed profile.

    This is what stops the inventory from silently going stale: adding a new
    optional feature to `Cargo.toml` without deciding whether it is supported
    under FIPS fails here, rather than shipping as an implicit claim.
    """

    manifest = read_manifest()
    table = re.search(r"^\[features\]\s*$\n(.*?)(?=^\[)", manifest, re.M | re.S)
    if table is None:
        return ["Cargo.toml has no `[features]` table"]

    declared = set(re.findall(r"^([A-Za-z0-9_-]+) = \[", table.group(1), re.M))
    # `default` is the profile selector; `crypto-ring`/`fips` are the backends
    # themselves; `fuzzing` compiles no cryptography and is never shipped;
    # `cloud-secrets` is the umbrella over the individual `secrets-*` features.
    exempt = {"default", "crypto-ring", "fips", "fuzzing"}
    covered = {
        feature
        for _, features, _ in claimed_profiles()
        for feature in features.split(",")
    }
    # An umbrella feature covers what it expands to.
    for umbrella in list(covered):
        expansion = feature_list(manifest, umbrella)
        covered.update(entry for entry in expansion if entry in declared)

    missing = sorted(declared - exempt - covered)
    if missing:
        return [
            "optional cargo feature(s) "
            f"{missing} are not named by any entry in CLAIMED_FIPS_PROFILES or "
            "CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME. Every optional feature must be "
            "explicitly claimed as FIPS-supported (and audited) or explicitly recorded as "
            "refused at runtime — an unlisted feature is an implicit claim this build cannot back."
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-check", action="store_true")
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--profile", choices=("fips", "crypto-ring"))
    parser.add_argument(
        "--list-claimed-profiles",
        action="store_true",
        help="Print one `<label>\\t<features>` row per claimed FIPS profile, so CI enumerates "
        "the same table this script audits instead of duplicating it in YAML.",
    )
    args = parser.parse_args()

    if args.list_claimed_profiles:
        for label, features, _ in claimed_profiles():
            print(f"{label}\t{features}")
        return 0

    failures: list[str] = []
    if args.manifest_check or args.tree is None:
        failures.extend(check_manifest())
        failures.extend(check_claimed_profiles_declared())
    if args.tree is not None:
        if args.profile is None:
            parser.error("--tree requires --profile")
        failures.extend(check_tree(args.tree, args.profile))

    if failures:
        print("FIPS feature-policy check FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("FIPS feature-policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
