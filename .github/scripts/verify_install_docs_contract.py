#!/usr/bin/env python3
"""Statically verify operator install docs match the release binary asset contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
CLI_MD = REPO_ROOT / "docs" / "cli.md"
CI_CD_MD = REPO_ROOT / "docs" / "ci_cd.md"
RELEASE_YML = REPO_ROOT / ".github/workflows/release.yml"
CI_YML = REPO_ROOT / ".github/workflows/ci.yml"

COPY_TRUSTED_DEST = re.compile(
    r'copy_trusted_asset (?:release-binaries-|binary-)[^/]+/([^\s]+) ([^\s]+)'
)
FORBIDDEN_INSTALL_PATTERNS = (
    re.compile(r"releases/latest/download"),
    re.compile(
        r"https://github\.com/ferrum-edge/ferrum-edge/releases/latest(?=[\"')])"
    ),
    re.compile(r"ferrum-edge-x86_64-unknown-linux-gnu\.tar\.gz"),
    re.compile(r"x86_64-unknown-linux-gnu\.tar\.gz"),
)
LINUX_X86_64_BINARY = "ferrum-edge-linux-x86_64"
LINUX_X86_64_CHECKSUM = f"{LINUX_X86_64_BINARY}.sha256"
EXPLICIT_TAG_GUIDANCE = re.compile(
    r"(?:prerelease|/releases/latest|releases/latest endpoint)",
    re.IGNORECASE,
)


def release_gateway_assets(release_workflow: str) -> frozenset[str]:
    assets: set[str] = set()
    for _source, dest in COPY_TRUSTED_DEST.findall(release_workflow):
        if dest.startswith("ferrum-edge-"):
            assets.add(dest)
    return frozenset(assets)


def check_operator_install_docs(
    readme: str,
    cli_md: str,
    ci_cd_md: str,
    release_workflow: str,
    latest_workflow: str,
) -> list[str]:
    errors: list[str] = []
    for workflow_label, workflow in (
        ("stable release workflow", release_workflow),
    ):
        gateway_assets = release_gateway_assets(workflow)
        if LINUX_X86_64_BINARY not in gateway_assets:
            errors.append(
                f"{workflow_label} is missing the Linux x86_64 gateway binary asset"
            )
        if LINUX_X86_64_CHECKSUM not in gateway_assets:
            errors.append(
                f"{workflow_label} is missing the Linux x86_64 checksum asset"
            )

    for label, text in (
        ("README.md", readme),
        ("docs/cli.md", cli_md),
        ("docs/ci_cd.md", ci_cd_md),
    ):
        for pattern in FORBIDDEN_INSTALL_PATTERNS:
            if pattern.search(text):
                errors.append(
                    f"{label} documents a broken install URL or tarball name "
                    f"({pattern.pattern!r})"
                )

    for label, text in (("README.md", readme), ("docs/cli.md", cli_md)):
        for token in (
            LINUX_X86_64_BINARY,
            LINUX_X86_64_CHECKSUM,
            "sha256sum -c",
            "releases/download/${TAG}",
        ):
            if token not in text:
                errors.append(f"{label} quick-install contract is missing {token!r}")
        if not EXPLICIT_TAG_GUIDANCE.search(text):
            errors.append(
                f"{label} must explain explicit release tags vs GitHub /releases/latest "
                "while prerelease tags are published"
            )

    if "api.github.com/repos/ferrum-edge/ferrum-edge/releases/latest" in ci_cd_md:
        errors.append(
            "docs/ci_cd.md must not use the GitHub releases/latest API while the "
            "published tag may be a prerelease"
        )
    for token in (
        LINUX_X86_64_BINARY,
        LINUX_X86_64_CHECKSUM,
        "sha256sum -c",
    ):
        if token not in ci_cd_md:
            errors.append(f"docs/ci_cd.md download instructions are missing {token!r}")

    return errors


def check_repository() -> list[str]:
    release_workflow = RELEASE_YML.read_text(encoding="utf-8")
    latest_workflow = CI_YML.read_text(encoding="utf-8")
    return check_operator_install_docs(
        README.read_text(encoding="utf-8"),
        CLI_MD.read_text(encoding="utf-8"),
        CI_CD_MD.read_text(encoding="utf-8"),
        release_workflow,
        latest_workflow,
    )


def run_self_test() -> list[str]:
    failures: list[str] = []
    release_workflow = RELEASE_YML.read_text(encoding="utf-8")
    latest_workflow = CI_YML.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    cli_md = CLI_MD.read_text(encoding="utf-8")
    ci_cd_md = CI_CD_MD.read_text(encoding="utf-8")

    if check_operator_install_docs(
        readme, cli_md, ci_cd_md, release_workflow, latest_workflow
    ):
        failures.append("the checked-in install docs do not satisfy the contract")
        return failures

    broken_readme = readme.replace(
        LINUX_X86_64_BINARY,
        "ferrum-edge-x86_64-unknown-linux-gnu.tar.gz",
        1,
    )
    if not check_operator_install_docs(
        broken_readme, cli_md, ci_cd_md, release_workflow, latest_workflow
    ):
        failures.append("broken tarball install recipe was not rejected")

    broken_ci_cd = ci_cd_md.replace(
        'gh release download --repo ferrum-edge/ferrum-edge "$TAG"',
        "curl -s https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/latest",
        1,
    )
    if not check_operator_install_docs(
        readme, cli_md, broken_ci_cd, release_workflow, latest_workflow
    ):
        failures.append("broken releases/latest API download recipe was not rejected")

    return failures


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv == ["--self-test"]:
        failures = run_self_test()
    else:
        failures = check_repository()

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
