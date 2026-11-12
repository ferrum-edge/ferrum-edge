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

The two profiles are not symmetric, and the checks say so explicitly:

* The `fips` profile may carry no `ring` arm of any kind. That is the hazard
  above, and nothing here relaxes it.
* The ordinary `crypto-ring` profile makes no validation claim, so it may link
  rustls's own AWS-LC cipher suites *beside* ring (`rustls/aws_lc_rs`), which
  `src/fips/aead_backend.rs` selects for the TLS record layer on the CPUs where
  they are faster. That is the only AWS-LC edge the profile may declare
  (`RING_PROFILE_ALLOWED_AWS_LC_EDGES`). Every dependency in it must still
  resolve to its ring arm, and the FIPS module must stay out of it.

Usage:

    check_fips_feature_policy.py --manifest-check
        Static checks over `Cargo.toml` only. No cargo invocation, no network.
        Also runs the synthetic self-test below, so the gate cannot go green on
        a checker that has stopped rejecting what it exists to reject.

    check_fips_feature_policy.py --self-test
        Synthetic mutations of the manifest and of resolved feature graphs,
        each of which must be rejected. No cargo invocation, no network.

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

# The one AWS-LC edge the ordinary profile may declare, spelled exactly.
#
# `rustls/aws_lc_rs` compiles rustls's AWS-LC cipher suites next to its ring
# ones. Ferrum installs them only for the TLS record layer, and only where
# `src/fips/aead_backend.rs` selects them (by CPU, or by an explicit
# `FERRUM_TLS_AEAD_BACKEND=aws-lc`); key exchange, signature verification and
# every dependency's provider arm stay on ring. It adds no library to the
# profile: `aws-lc-sys` is already linked there through jsonwebtoken and dimpl.
#
# This is an allow-list, not a pattern. A second entry is a policy decision that
# needs the same review this one had; any other AWS-LC spelling in the
# `crypto-ring` list fails `check_manifest_text`.
RING_PROFILE_ALLOWED_AWS_LC_EDGES = ("rustls/aws_lc_rs",)

# `src/fips/mod.rs` names `rustls::crypto::aws_lc_rs` in its `crypto-ring` arm,
# so the allowed edge is also required: dropping it is a compile failure, and
# this reports it as the manifest fault it is.
REQUIRED_RING_ONLY = ("dep:ring",) + RING_PROFILE_ALLOWED_AWS_LC_EDGES

# Substrings that mark a feature name as an AWS-LC (or FIPS-module) arm. Used to
# refuse any such edge in the `crypto-ring` list that is not on the allow-list
# above, whichever dependency it is on and however it is spelled.
AWS_LC_FEATURE_MARKERS = ("aws-lc", "aws_lc", "fips")

# Neither profile may name the other's backend crate at all, in any spelling.
# The pair table above catches a known counterpart edge; this catches a *new*
# edge onto the wrong crate that nobody thought to pair. jsonwebtoken's inline
# `aws_lc_rs` (REQUIRED_INLINE_DECLARATIONS) is outside both lists by design:
# it is the same AWS-LC selection on both profiles, not a profile arm.
#
# `rustls/aws_lc_rs` in `crypto-ring` does not name the `aws-lc-rs` crate — it
# is a feature of rustls — so it is not an exception to this table. The
# feature-name checks in `check_manifest_text` are what bound it.
#
# Those feature-name checks now refuse everything this table refuses as well
# (an entry that names `aws-lc-rs` carries an AWS-LC marker, and `dep:ring`
# carries the ring token), so this is a second line of defence. No manifest
# mutation can single it out, so the self-test pins it by value instead.
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
#
# `rustls/aws_lc_rs` is required beside `rustls/ring`: the ordinary build links
# both of rustls's cipher-suite implementations and chooses between them at
# startup. `rustls/ring` staying required is what keeps ring the provider for
# key exchange and signatures.
REQUIRED_RESOLVED_RING = {
    ("jsonwebtoken", "aws_lc_rs"),
    ("kube", "ring"),
    ("mongodb", "rustls-tls"),
    ("reqwest", "__rustls-ring"),
    ("rustls", "aws_lc_rs"),
    ("rustls", "ring"),
    ("tokio-rustls", "ring"),
    ("quinn-proto", "rustls-ring"),
    ("tonic", "tls-ring"),
}

# What "beside ring" must not turn into. The allowed edge is on rustls alone, so
# no dependency may resolve to its own aws-lc arm (each gates that arm on the
# absence of its ring arm, and several would silently switch provider), and the
# FIPS module must not enter the ordinary build by any route.
#
# `rcgen/aws_lc_rs` and `x509-parser/verify-aws` are deliberately absent: dimpl
# has always enabled both in this profile, next to their ring counterparts.
FORBIDDEN_RESOLVED_RING = {
    ("aws-lc-rs", "fips"),
    ("jsonwebtoken", "rust_crypto"),
    ("rustls", "fips"),
    ("rustls-webpki", "aws-lc-rs-fips"),
    ("tokio-rustls", "aws_lc_rs"),
    ("tokio-rustls", "aws-lc-rs"),
    ("tokio-rustls", "fips"),
    ("quinn", "rustls-aws-lc-rs"),
    ("quinn", "rustls-aws-lc-rs-fips"),
    ("quinn-proto", "rustls-aws-lc-rs"),
    ("quinn-proto", "rustls-aws-lc-rs-fips"),
    ("sqlx", "tls-rustls-aws-lc-rs"),
    ("sqlx-core", "_tls-rustls-aws-lc-rs"),
    ("ldap3", "tls-rustls-aws-lc-rs"),
    ("tonic", "tls-aws-lc"),
    ("hyper-rustls", "aws-lc-rs"),
    ("hyper-rustls", "fips"),
    ("kube", "aws-lc-rs"),
    ("kube-client", "aws-lc-rs"),
    ("mongodb", "rustls-tls-aws-lc"),
    ("rcgen", "fips"),
    ("reqwest", "__rustls-aws-lc-rs"),
    ("instant-acme", "aws-lc-rs"),
    ("instant-acme", "fips"),
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

_QUOTED_STRING_RE = re.compile(r'"([^"]+)"')
_DEPENDENCIES_TABLE_RE = re.compile(r"^\[dependencies\]\s*$\n(.*?)(?=^\[)", re.M | re.S)
_FEATURES_TABLE_RE = re.compile(r"^\[features\]\s*$\n(.*?)(?=^\[)", re.M | re.S)
_FEATURE_NAME_RE = re.compile(r"^([A-Za-z0-9_-]+) = \[", re.M)


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
    return _QUOTED_STRING_RE.findall(match.group(1))


def dependency_line(manifest: str, name: str) -> str | None:
    match = re.search(rf'^{re.escape(name)} = (\{{.*?\}}|"[^"]*")$', manifest, re.M)
    return match.group(1) if match else None


def feature_name(entry: str) -> str:
    """The feature half of a `[features]` entry (`dep/feature` or `dep:name`)."""

    if "/" in entry:
        return entry.split("/", 1)[1]
    return entry.removeprefix("dep:")


def check_manifest_text(manifest: str) -> list[str]:
    """Every manifest check that is a pure function of the `Cargo.toml` text."""

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

    # The ordinary profile may link AWS-LC cipher suites beside ring through
    # exactly the allow-listed edge. Any other feature that names AWS-LC or the
    # FIPS module is refused by name, whichever dependency carries it: several
    # dependencies gate their aws-lc arm on the absence of their ring arm, so an
    # unreviewed second edge is how a provider gets switched by accident.
    for entry in ring_features:
        if entry in RING_PROFILE_ALLOWED_AWS_LC_EDGES:
            continue
        name = feature_name(entry)
        if any(marker in name for marker in AWS_LC_FEATURE_MARKERS):
            failures.append(
                f"`crypto-ring` selects the AWS-LC feature {entry!r}; the ordinary profile may "
                f"link AWS-LC only through {list(RING_PROFILE_ALLOWED_AWS_LC_EDGES)} "
                "(rustls's cipher suites, beside ring)"
            )

    # The allow-listed edge belongs to the ordinary profile alone. `rustls/fips`
    # already implies rustls's aws-lc arm, so listing it under `fips` would only
    # blur which list owns it.
    for entry in RING_PROFILE_ALLOWED_AWS_LC_EDGES:
        if entry in fips_features:
            failures.append(
                f"`fips` must not select {entry!r}: it is the ordinary profile's edge, and "
                "`rustls/fips` already selects rustls's aws-lc arm"
            )

    # The mirror image, and the one that matters for a deployment: no `fips`
    # entry may select a feature named for ring, on any dependency, whether or
    # not that dependency has a row in REQUIRED_FEATURE_PAIRS. This is a
    # manifest-level statement of what FORBIDDEN_RESOLVED_FIPS then verifies in
    # the resolved graph.
    for entry in fips_features:
        if "ring" in re.split(r"[^a-z0-9]+", feature_name(entry).lower()):
            failures.append(
                f"`fips` selects the ring feature {entry!r}; a FIPS build must not compile a "
                "ring arm on any dependency"
            )

    for dep, forbidden in FORBIDDEN_INLINE_DECLARATIONS.items():
        line = dependency_line(manifest, dep)
        if line is None:
            failures.append(f"dependency {dep!r} is not declared on its own line in Cargo.toml")
            continue
        inline = set(_QUOTED_STRING_RE.findall(line))
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
        inline = set(_QUOTED_STRING_RE.findall(line))
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

    dependency_table = _DEPENDENCIES_TABLE_RE.search(manifest)
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

    return failures


def source_uses_forbidden_crate(source: str) -> bool:
    """`True` when production source reaches a RustCrypto SHA-2/HMAC crate."""

    return any(pattern.search(source) for pattern in FORBIDDEN_PRODUCTION_CRATE_PATTERNS)


def check_manifest() -> list[str]:
    failures = check_manifest_text(read_manifest())

    for source_path in sorted((REPO_ROOT / "src").rglob("*.rs")):
        # This module intentionally names the old API in rustdoc while
        # implementing the provider-backed compatibility surface itself.
        if source_path == REPO_ROOT / "src/fips/approved.rs":
            continue
        source = source_path.read_text(encoding="utf-8")
        if source_uses_forbidden_crate(source):
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

    return check_selections(selections, profile)


def check_selections(selections: set[tuple[str, str]], profile: str) -> list[str]:
    """Audit one resolved feature graph, already parsed into selections."""

    if profile == "fips":
        required, forbidden = REQUIRED_RESOLVED_FIPS, FORBIDDEN_RESOLVED_FIPS
        consequence = (
            "so a non-validated implementation remains in control of that path"
        )
    elif profile == "crypto-ring":
        required, forbidden = REQUIRED_RESOLVED_RING, FORBIDDEN_RESOLVED_RING
        consequence = (
            "but the ordinary profile may link AWS-LC only as rustls's cipher suites beside "
            "ring: no dependency may leave its ring arm, and the FIPS module must stay out"
        )
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
                f"[{profile}] resolved graph selects {crate}/{feature}, {consequence}"
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


def check_claimed_profiles_declared(manifest: str | None = None) -> list[str]:
    """Every optional cargo feature must be accounted for by a claimed profile.

    This is what stops the inventory from silently going stale: adding a new
    optional feature to `Cargo.toml` without deciding whether it is supported
    under FIPS fails here, rather than shipping as an implicit claim.
    """

    if manifest is None:
        manifest = read_manifest()
    table = _FEATURES_TABLE_RE.search(manifest)
    if table is None:
        return ["Cargo.toml has no `[features]` table"]

    declared = set(_FEATURE_NAME_RE.findall(table.group(1)))
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


def _with_feature_entry(manifest: str, feature: str, entry: str) -> str:
    """Return `manifest` with `entry` appended to one `[features]` list."""

    opening = f"{feature} = [\n"
    if manifest.count(opening) != 1:
        raise ValueError(f"expected exactly one multi-line `{feature}` feature list")
    return manifest.replace(opening, f'{opening}    "{entry}",\n', 1)


def _without_feature_entry(manifest: str, feature: str, entry: str) -> str:
    """Return `manifest` with `entry` removed from one `[features]` list."""

    start = manifest.index(f"{feature} = [\n")
    # Up to and including the newline that ends the list's last entry.
    end = manifest.index("\n]", start) + 1
    line = f'    "{entry}",\n'
    block = manifest[start:end]
    if block.count(line) != 1:
        raise ValueError(f"`{feature}` does not list {entry!r} exactly once")
    return manifest[:start] + block.replace(line, "", 1) + manifest[end:]


# The self-test's own copy of the resolved-graph policy.
#
# These rows are written out a second time, deliberately. The self-test asks
# `check_selections` to reject each of them; if it built its cases from the live
# REQUIRED_/FORBIDDEN_ tables instead, deleting or mistyping a row there would
# delete the case with it and the gate would stay green. A deliberate policy
# change therefore edits two places, and an accidental one fails here.
_PINNED_FORBIDDEN_RESOLVED_RING = frozenset({
    ("aws-lc-rs", "fips"),
    ("jsonwebtoken", "rust_crypto"),
    ("rustls", "fips"),
    ("rustls-webpki", "aws-lc-rs-fips"),
    ("tokio-rustls", "aws_lc_rs"),
    ("tokio-rustls", "aws-lc-rs"),
    ("tokio-rustls", "fips"),
    ("quinn", "rustls-aws-lc-rs"),
    ("quinn", "rustls-aws-lc-rs-fips"),
    ("quinn-proto", "rustls-aws-lc-rs"),
    ("quinn-proto", "rustls-aws-lc-rs-fips"),
    ("sqlx", "tls-rustls-aws-lc-rs"),
    ("sqlx-core", "_tls-rustls-aws-lc-rs"),
    ("ldap3", "tls-rustls-aws-lc-rs"),
    ("tonic", "tls-aws-lc"),
    ("hyper-rustls", "aws-lc-rs"),
    ("hyper-rustls", "fips"),
    ("kube", "aws-lc-rs"),
    ("kube-client", "aws-lc-rs"),
    ("mongodb", "rustls-tls-aws-lc"),
    ("rcgen", "fips"),
    ("reqwest", "__rustls-aws-lc-rs"),
    ("instant-acme", "aws-lc-rs"),
    ("instant-acme", "fips"),
})
_PINNED_REQUIRED_RESOLVED_RING = frozenset({
    ("jsonwebtoken", "aws_lc_rs"),
    ("kube", "ring"),
    ("mongodb", "rustls-tls"),
    ("reqwest", "__rustls-ring"),
    ("rustls", "aws_lc_rs"),
    ("rustls", "ring"),
    ("tokio-rustls", "ring"),
    ("quinn-proto", "rustls-ring"),
    ("tonic", "tls-ring"),
})
_PINNED_FORBIDDEN_RESOLVED_FIPS = frozenset({
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
    ("instant-acme", "ring"),
})
_PINNED_REQUIRED_RESOLVED_FIPS = frozenset({
    ("aws-lc-rs", "fips"),
    ("jsonwebtoken", "aws_lc_rs"),
    ("kube", "aws-lc-rs"),
    ("mongodb", "rustls-tls-aws-lc"),
    ("reqwest", "__rustls-aws-lc-rs"),
    ("rustls", "fips"),
})

# The same second copy for the manifest policy, so a pair, a default-features
# requirement or an inline rule removed from a live table still has a mutation
# that expects the check it carried.
_PINNED_FEATURE_PAIRS = (
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
_PINNED_REQUIRED_FIPS_ONLY = ("aws-lc-rs/fips",)
_PINNED_REQUIRED_RING_ONLY = ("dep:ring", "rustls/aws_lc_rs")
_PINNED_DEFAULT_FEATURES_OFF = ("kube", "mongodb", "quinn", "rcgen", "rustls", "tokio-rustls")
_PINNED_FORBIDDEN_INLINE = (
    ("rustls", "ring"),
    ("rustls", "aws_lc_rs"),
    ("rustls", "aws-lc-rs"),
    ("rustls", "fips"),
    ("tokio-rustls", "ring"),
    ("tokio-rustls", "aws_lc_rs"),
    ("tokio-rustls", "aws-lc-rs"),
    ("tokio-rustls", "fips"),
    ("tonic", "tls-ring"),
    ("tonic", "tls-aws-lc"),
    ("sqlx", "runtime-tokio-rustls"),
    ("sqlx", "tls-rustls"),
    ("sqlx", "tls-rustls-ring"),
    ("ldap3", "tls-rustls-ring"),
    ("ldap3", "tls-rustls-aws-lc-rs"),
    ("hyper-rustls", "ring"),
    ("hyper-rustls", "aws-lc-rs"),
    ("hyper-rustls", "fips"),
    ("instant-acme", "ring"),
    ("instant-acme", "aws-lc-rs"),
    ("instant-acme", "fips"),
    ("kube", "ring"),
    ("kube", "aws-lc-rs"),
    ("mongodb", "rustls-tls"),
    ("mongodb", "rustls-tls-aws-lc"),
    ("x509-parser", "verify"),
    ("x509-parser", "verify-aws"),
    ("jsonwebtoken", "rust_crypto"),
    ("reqwest", "rustls"),
)
_PINNED_REQUIRED_INLINE = (("jsonwebtoken", "aws_lc_rs"),)

# Tables whose rows carry no mutation of their own are pinned by value: the
# backend-crate table is fully covered by the stricter feature-name checks, and
# a claimed FIPS profile is an entry in CI's audit and compile matrix, not a
# rule the checker applies to a manifest.
_PINNED_BACKEND_CRATE_PREFIXES = {
    "crypto-ring": ("aws-lc-rs", "aws_lc_rs", "aws-lc-fips-sys", "aws-lc-sys"),
    "fips": ("ring",),
}
_PINNED_CLAIMED_FIPS_PROFILES = (
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
_PINNED_CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME = (
    ("fips + cloud-secrets", "fips,cloud-secrets"),
)

# One source line per production-crate pattern, each matched by that pattern
# alone, and lines the patterns must leave alone.
_FORBIDDEN_SOURCE_SAMPLES = (
    "use sha2;",
    "let digest = sha2::Sha256::digest(bytes);",
    "use hmac;",
    "type Mac = hmac::Hmac<Hash>;",
)
_ADMISSIBLE_SOURCE_SAMPLES = (
    "use crate::fips::approved::Sha256;",
    "let mac = crate::fips::approved::hmac_sha256(key, data);",
)

# Paired aws-lc arms the ordinary graph has always resolved next to their ring
# counterparts, through dimpl. They are the only pair-table arms that
# FORBIDDEN_RESOLVED_RING may leave out.
_RING_GRAPH_PAIRED_ARM_EXCEPTIONS = frozenset({("x509-parser", "verify-aws")})


def _dependency_line_span(manifest: str, dep: str) -> tuple[int, int]:
    """Start and end offsets of one dependency's own line."""

    match = re.search(rf'^{re.escape(dep)} = (\{{.*?\}}|"[^"]*")$', manifest, re.M)
    if match is None:
        raise ValueError(f"dependency {dep!r} is not declared on its own line")
    return match.start(), match.end()


def _with_dependency_line(manifest: str, dep: str, old: str, new: str) -> str:
    """Return `manifest` with one substring of `dep`'s own line replaced."""

    start, end = _dependency_line_span(manifest, dep)
    line = manifest[start:end]
    if line.count(old) != 1:
        raise ValueError(f"the {dep!r} line does not contain {old!r} exactly once")
    return manifest[:start] + line.replace(old, new, 1) + manifest[end:]


def _with_inline_feature(manifest: str, dep: str, feature: str) -> str:
    """Return `manifest` with `feature` added to `dep`'s inline feature list."""

    start, end = _dependency_line_span(manifest, dep)
    line = manifest[start:end]
    if "features = [" in line:
        mutated = line.replace("features = [", f'features = ["{feature}", ', 1)
    elif line.endswith(" }"):
        mutated = line[: -len(" }")] + f', features = ["{feature}"] }}'
    else:
        version = line.split(" = ", 1)[1]
        mutated = f'{dep} = {{ version = {version}, features = ["{feature}"] }}'
    return manifest[:start] + mutated + manifest[end:]


def _resolved_row(edge: str) -> tuple[str, str]:
    """`dep/feature` or `dep?/feature` as a resolved `(crate, feature)` row."""

    crate, feature = edge.split("/", 1)
    return crate.rstrip("?"), feature


def self_test() -> list[str]:
    """Prove the checks still reject what they exist to reject.

    Manifest cases are single mutations of the real `Cargo.toml`. Resolved-graph
    cases come from the pinned rows above and from REQUIRED_FEATURE_PAIRS, which
    are both kept independently of the tables `check_selections` reads, so a row
    removed from a live table still has a case that expects it. A mutation that
    is *accepted* is the failure: a check has been weakened or bypassed.

    Coverage, so the limits are stated rather than implied: every row of the
    feature-pair, required-edge, default-features, inline and resolved-graph
    tables has a mutation of its own; duplicate and redundant activation, the
    default feature set, the dev-only reference crates, the unclaimed-feature
    rule and each production-crate pattern have one each; the backend-crate and
    claimed-profile tables are pinned by value. Not covered here: the walk over
    `src/` in `check_manifest` (only its predicate is), the cargo-tree parser,
    which the hosted audit exercises on real graphs, and three reports that
    cannot fire alone: the two "feature list is missing" ones (the required-edge
    rules fire with them) and the second own-line report for jsonwebtoken, which
    is in both inline tables.
    """

    failures: list[str] = []
    manifest = read_manifest()

    baseline = check_manifest_text(manifest)
    if baseline:
        # Reported by the ordinary manifest check too; the mutations below are
        # only meaningful against a manifest that is itself admissible.
        return [f"self-test baseline: the committed manifest is not admissible: {baseline}"]

    allowed = RING_PROFILE_ALLOWED_AWS_LC_EDGES[0]
    manifest_mutations = (
        # The ordinary profile's allowance is exactly one edge, spelled one way.
        (
            "crypto-ring drops the allowed rustls AWS-LC edge",
            lambda: _without_feature_entry(manifest, "crypto-ring", allowed),
        ),
        (
            "crypto-ring adds tokio-rustls's AWS-LC arm",
            lambda: _with_feature_entry(manifest, "crypto-ring", "tokio-rustls/aws_lc_rs"),
        ),
        (
            "crypto-ring adds quinn's AWS-LC arm",
            lambda: _with_feature_entry(manifest, "crypto-ring", "quinn/rustls-aws-lc-rs"),
        ),
        (
            "crypto-ring adds the hyphenated rustls AWS-LC alias",
            lambda: _with_feature_entry(manifest, "crypto-ring", "rustls/aws-lc-rs"),
        ),
        (
            "crypto-ring adds rustls's FIPS arm",
            lambda: _with_feature_entry(manifest, "crypto-ring", "rustls/fips"),
        ),
        (
            # Not a paired edge and not an aws-lc spelling: only the FIPS
            # marker refuses it.
            "crypto-ring adds an unpaired FIPS-named arm",
            lambda: _with_feature_entry(manifest, "crypto-ring", "tonic/fips"),
        ),
        (
            "crypto-ring activates the aws-lc-rs backend crate",
            lambda: _with_feature_entry(manifest, "crypto-ring", "dep:aws-lc-rs"),
        ),
        (
            "crypto-ring binds the FIPS module",
            lambda: _with_feature_entry(manifest, "crypto-ring", "aws-lc-rs/fips"),
        ),
        # The FIPS profile is unchanged: no ring arm, by pair or by name.
        (
            "fips adds rustls's ring arm",
            lambda: _with_feature_entry(manifest, "fips", "rustls/ring"),
        ),
        (
            "fips adds an unpaired ring arm",
            lambda: _with_feature_entry(manifest, "fips", "quinn/ring"),
        ),
        (
            "fips activates the ring backend crate",
            lambda: _with_feature_entry(manifest, "fips", "dep:ring"),
        ),
        (
            "fips drops the validated-module binding",
            lambda: _without_feature_entry(manifest, "fips", "aws-lc-rs/fips"),
        ),
        (
            "fips lists the ordinary profile's edge",
            lambda: _with_feature_entry(manifest, "fips", allowed),
        ),
    )
    # Every pinned manifest rule gets a mutation only that rule refuses, so a
    # row dropped from REQUIRED_FEATURE_PAIRS, REQUIRE_DEFAULT_FEATURES_OFF or
    # the inline tables is caught here even though nothing else changed.
    pinned_manifest_mutations: list[tuple[str, object]] = [
        (
            "the default feature set gains a second feature",
            lambda: manifest.replace(
                'default = ["crypto-ring"]', 'default = ["crypto-ring", "acme"]', 1
            ),
        ),
        (
            "sha2 becomes a production dependency",
            lambda: manifest.replace("[dependencies]\n", '[dependencies]\nsha2 = "0.10"\n', 1),
        ),
        (
            "hmac becomes a production dependency",
            lambda: manifest.replace("[dependencies]\n", '[dependencies]\nhmac = "0.12"\n', 1),
        ),
        # Duplicate and redundant activations, which no other rule refuses.
        (
            "crypto-ring lists rustls/ring twice",
            lambda: _with_feature_entry(manifest, "crypto-ring", "rustls/ring"),
        ),
        (
            "fips lists aws-lc-rs/fips twice",
            lambda: _with_feature_entry(manifest, "fips", "aws-lc-rs/fips"),
        ),
        (
            "fips activates aws-lc-rs both by dep: and by feature",
            lambda: _with_feature_entry(manifest, "fips", "dep:aws-lc-rs"),
        ),
        # A dependency whose backend is selected inline may not also be selected
        # by a profile list.
        (
            "fips selects a jsonwebtoken feature",
            lambda: _with_feature_entry(manifest, "fips", "jsonwebtoken/use_pem"),
        ),
        # The inline rules read one line per dependency, so a dependency that
        # is not declared on a line of its own cannot be checked and is refused.
        (
            "tonic is no longer declared on a line of its own",
            lambda: _with_dependency_line(manifest, "tonic", "tonic = {", "tonic  = {"),
        ),
        (
            "quinn is no longer declared on a line of its own",
            lambda: _with_dependency_line(manifest, "quinn", "quinn = {", "quinn  = {"),
        ),
        (
            "the [dependencies] table is missing",
            lambda: manifest.replace("\n[dependencies]\n", "\n[dependencies-renamed]\n", 1),
        ),
    ]
    for ring_edge, fips_edge in _PINNED_FEATURE_PAIRS:
        pinned_manifest_mutations += [
            (
                f"crypto-ring drops {ring_edge}",
                lambda edge=ring_edge: _without_feature_entry(manifest, "crypto-ring", edge),
            ),
            (
                f"fips drops {fips_edge}",
                lambda edge=fips_edge: _without_feature_entry(manifest, "fips", edge),
            ),
            (
                f"fips adds the ring arm {ring_edge}",
                lambda edge=ring_edge: _with_feature_entry(manifest, "fips", edge),
            ),
            (
                f"crypto-ring adds the aws-lc arm {fips_edge}",
                lambda edge=fips_edge: _with_feature_entry(manifest, "crypto-ring", edge),
            ),
        ]
    for edge in _PINNED_REQUIRED_FIPS_ONLY:
        pinned_manifest_mutations.append((
            f"fips drops {edge}",
            lambda edge=edge: _without_feature_entry(manifest, "fips", edge),
        ))
    for edge in _PINNED_REQUIRED_RING_ONLY:
        pinned_manifest_mutations.append((
            f"crypto-ring drops {edge}",
            lambda edge=edge: _without_feature_entry(manifest, "crypto-ring", edge),
        ))
    for dep in _PINNED_DEFAULT_FEATURES_OFF:
        pinned_manifest_mutations.append((
            f"{dep} keeps its default features",
            lambda dep=dep: _with_dependency_line(
                manifest, dep, "default-features = false", "default-features = true"
            ),
        ))
    for dep, feature in _PINNED_FORBIDDEN_INLINE:
        pinned_manifest_mutations.append((
            f"{dep} selects {feature} inline",
            lambda dep=dep, feature=feature: _with_inline_feature(manifest, dep, feature),
        ))
    for dep, feature in _PINNED_REQUIRED_INLINE:
        pinned_manifest_mutations.append((
            f"{dep} drops its inline {feature}",
            lambda dep=dep, feature=feature: _with_dependency_line(
                manifest, dep, f', "{feature}"', ""
            ),
        ))

    for label, mutate in list(manifest_mutations) + pinned_manifest_mutations:
        try:
            mutated = mutate()
        except ValueError as error:
            failures.append(f"self-test could not build the mutation {label!r}: {error}")
            continue
        if mutated == manifest:
            failures.append(f"self-test: the mutation {label!r} did not change the manifest")
            continue
        if not check_manifest_text(mutated):
            failures.append(f"self-test: the manifest check accepted a manifest where {label}")

    # A live manifest table that has grown must grow its pinned copy too.
    for label, live, pinned in (
        ("REQUIRED_FEATURE_PAIRS", set(REQUIRED_FEATURE_PAIRS), set(_PINNED_FEATURE_PAIRS)),
        ("REQUIRED_FIPS_ONLY", set(REQUIRED_FIPS_ONLY), set(_PINNED_REQUIRED_FIPS_ONLY)),
        ("REQUIRED_RING_ONLY", set(REQUIRED_RING_ONLY), set(_PINNED_REQUIRED_RING_ONLY)),
        (
            "REQUIRE_DEFAULT_FEATURES_OFF",
            set(REQUIRE_DEFAULT_FEATURES_OFF),
            set(_PINNED_DEFAULT_FEATURES_OFF),
        ),
        (
            "FORBIDDEN_INLINE_DECLARATIONS",
            {(dep, f) for dep, fs in FORBIDDEN_INLINE_DECLARATIONS.items() for f in fs},
            set(_PINNED_FORBIDDEN_INLINE),
        ),
        (
            "REQUIRED_INLINE_DECLARATIONS",
            {(dep, f) for dep, fs in REQUIRED_INLINE_DECLARATIONS.items() for f in fs},
            set(_PINNED_REQUIRED_INLINE),
        ),
    ):
        unpinned = sorted(live - pinned)
        if unpinned:
            failures.append(
                f"self-test: {label} has entries the self-test does not pin: {unpinned}; add "
                "them to the pinned copy so each keeps a rejection case"
            )

    # Tables pinned by value.
    for label, live, pinned in (
        ("BACKEND_CRATE_PREFIXES", BACKEND_CRATE_PREFIXES, _PINNED_BACKEND_CRATE_PREFIXES),
        ("CLAIMED_FIPS_PROFILES", CLAIMED_FIPS_PROFILES, _PINNED_CLAIMED_FIPS_PROFILES),
        (
            "CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME",
            CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME,
            _PINNED_CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME,
        ),
    ):
        if live != pinned:
            failures.append(
                f"self-test: {label} differs from the copy the self-test pins; a deliberate "
                "change must update both"
            )

    # An optional cargo feature that no claimed profile names must be refused.
    unclaimed = manifest.replace("[features]\n", "[features]\nself-test-unclaimed = []\n", 1)
    if unclaimed == manifest or not check_claimed_profiles_declared(unclaimed):
        failures.append(
            "self-test: an optional cargo feature named by no claimed FIPS profile was accepted"
        )
    if check_claimed_profiles_declared(manifest):
        failures.append("self-test baseline: the committed feature set is not fully claimed")

    # Each production-crate pattern must flag the one line written for it.
    for sample in _FORBIDDEN_SOURCE_SAMPLES:
        matching = [
            pattern for pattern in FORBIDDEN_PRODUCTION_CRATE_PATTERNS if pattern.search(sample)
        ]
        if len(matching) != 1:
            failures.append(
                f"self-test: {sample!r} should be flagged by exactly one production-crate "
                f"pattern, and {len(matching)} matched"
            )
    if len(FORBIDDEN_PRODUCTION_CRATE_PATTERNS) != len(_FORBIDDEN_SOURCE_SAMPLES):
        failures.append(
            "self-test: FORBIDDEN_PRODUCTION_CRATE_PATTERNS has a pattern with no sample line"
        )
    for sample in _ADMISSIBLE_SOURCE_SAMPLES:
        if source_uses_forbidden_crate(sample):
            failures.append(f"self-test: the admissible line {sample!r} was flagged")

    ordinary = set(REQUIRED_RESOLVED_RING)
    fips = set(REQUIRED_RESOLVED_FIPS)
    for profile, selections in (("crypto-ring", ordinary), ("fips", fips)):
        accepted = check_selections(selections, profile)
        if accepted:
            failures.append(
                f"self-test baseline: the required {profile} selections are not admissible: "
                f"{accepted}"
            )

    selection_mutations = (
        # Linking AWS-LC cipher suites beside ring must not become a dependency
        # leaving its ring arm, or the FIPS module entering the ordinary build.
        ("crypto-ring", ordinary | {("tokio-rustls", "aws_lc_rs")}),
        ("crypto-ring", ordinary | {("quinn-proto", "rustls-aws-lc-rs")}),
        ("crypto-ring", ordinary | {("reqwest", "__rustls-aws-lc-rs")}),
        ("crypto-ring", ordinary | {("aws-lc-rs", "fips")}),
        ("crypto-ring", ordinary | {("rustls", "fips")}),
        ("crypto-ring", ordinary - {("rustls", "ring")}),
        ("crypto-ring", ordinary - {("rustls", "aws_lc_rs")}),
        # A nominal FIPS build cannot end up with ring in control of a path.
        ("fips", fips | {("rustls", "ring")}),
        ("fips", fips | {("tokio-rustls", "ring")}),
        ("fips", fips | {("quinn-proto", "rustls-ring")}),
        ("fips", fips | {("rustls-webpki", "ring")}),
        ("fips", fips | {("reqwest", "__rustls-ring")}),
        ("fips", fips - {("aws-lc-rs", "fips")}),
        ("fips", fips - {("rustls", "fips")}),
    )
    for profile, selections in selection_mutations:
        if not check_selections(selections, profile):
            base = ordinary if profile == "crypto-ring" else fips
            delta = sorted(selections ^ base)
            failures.append(
                f"self-test: the resolved-graph audit accepted a {profile} graph that differs "
                f"from the required selections by {delta}"
            )

    # Every pinned forbidden row must be individually fatal and every pinned
    # required row individually necessary, in both profiles. The rows come from
    # the self-test's own copy, so one that has gone missing from a live table
    # is reported here instead of silently losing its case.
    for profile, base, forbidden, required in (
        (
            "crypto-ring",
            ordinary,
            _PINNED_FORBIDDEN_RESOLVED_RING,
            _PINNED_REQUIRED_RESOLVED_RING,
        ),
        ("fips", fips, _PINNED_FORBIDDEN_RESOLVED_FIPS, _PINNED_REQUIRED_RESOLVED_FIPS),
    ):
        for row in sorted(forbidden):
            if not check_selections(base | {row}, profile):
                failures.append(
                    f"self-test: the resolved-graph audit accepted the forbidden {profile} "
                    f"selection {row[0]}/{row[1]}"
                )
        for row in sorted(required):
            if not check_selections((base | required) - {row}, profile):
                failures.append(
                    f"self-test: the resolved-graph audit accepted a {profile} graph without "
                    f"the required selection {row[0]}/{row[1]}"
                )

    # A live table that has grown must grow the pinned copy too, or the new row
    # would have no case of its own.
    for label, live, pinned in (
        ("FORBIDDEN_RESOLVED_RING", FORBIDDEN_RESOLVED_RING, _PINNED_FORBIDDEN_RESOLVED_RING),
        ("REQUIRED_RESOLVED_RING", REQUIRED_RESOLVED_RING, _PINNED_REQUIRED_RESOLVED_RING),
        ("FORBIDDEN_RESOLVED_FIPS", FORBIDDEN_RESOLVED_FIPS, _PINNED_FORBIDDEN_RESOLVED_FIPS),
        ("REQUIRED_RESOLVED_FIPS", REQUIRED_RESOLVED_FIPS, _PINNED_REQUIRED_RESOLVED_FIPS),
    ):
        unpinned = sorted(set(live) - pinned)
        if unpinned:
            failures.append(
                f"self-test: {label} has rows the self-test does not pin: {unpinned}; add them "
                "to the pinned copy so each keeps a rejection case"
            )

    # The resolved tables must also agree with the manifest pair table, which
    # is maintained separately: each dependency's ring arm is forbidden in the
    # FIPS graph, and each aws-lc arm is forbidden in the ordinary graph.
    for ring_edge, fips_edge in REQUIRED_FEATURE_PAIRS:
        ring_row, fips_row = _resolved_row(ring_edge), _resolved_row(fips_edge)
        if not check_selections(fips | {ring_row}, "fips"):
            failures.append(
                f"self-test: the FIPS graph audit accepted {ring_row[0]}/{ring_row[1]}, the ring "
                f"arm paired with {fips_edge!r}"
            )
        if fips_row in _RING_GRAPH_PAIRED_ARM_EXCEPTIONS:
            continue
        if not check_selections(ordinary | {fips_row}, "crypto-ring"):
            failures.append(
                f"self-test: the ordinary graph audit accepted {fips_row[0]}/{fips_row[1]}, the "
                f"aws-lc arm paired with {ring_edge!r}"
            )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-check", action="store_true")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run only the synthetic rejection cases (also part of --manifest-check).",
    )
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
    if args.self_test:
        failures.extend(self_test())
        if failures:
            print("FIPS feature-policy self-test FAILED:", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
        print("FIPS feature-policy self-test passed.")
        return 0

    if args.manifest_check or args.tree is None:
        failures.extend(check_manifest())
        failures.extend(check_claimed_profiles_declared())
        failures.extend(self_test())
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
