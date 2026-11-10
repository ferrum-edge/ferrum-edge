#!/usr/bin/env python3
"""Generate src/plugins/cors_psl_ancestors.rs from the locked `psl` crate.

The CORS credentialed-wildcard interlock needs every domain that is not itself
a public suffix but has a Public Suffix List rule strictly beneath it. That
index is derived from the `data/rules.txt` bundled with the exact `psl`
version Cargo.lock resolves, so a `psl` bump must regenerate it.

The script reads the locked `psl` version and checksum from Cargo.lock,
downloads that crate from static.crates.io (or reads a local `.crate` given
with --crate), verifies its SHA-256 against the lockfile, and renders the
index. Nothing is compiled.

    python3 scripts/generate_cors_psl_ancestors.py          # rewrite the index
    python3 scripts/generate_cors_psl_ancestors.py --check  # CI parity gate
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import sys
import tarfile
import time
import tomllib
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = REPO_ROOT / "Cargo.lock"
INDEX = REPO_ROOT / "src" / "plugins" / "cors_psl_ancestors.rs"
CRATE_URL = "https://static.crates.io/crates/psl/psl-{version}.crate"

HEADER = """\
//! Generated from the Public Suffix List bundled with `psl` {version}
//! (`data/rules.txt`). Do not edit by hand: regenerate with
//! `python3 scripts/generate_cors_psl_ancestors.py`.
//!
//! Every domain that is NOT itself a public suffix but has a PSL rule strictly
//! beneath it (for example `amazonaws.com`, above `s3.amazonaws.com`). A
//! wildcard or regex origin over one of these covers independently
//! registrable tenants. Regenerate when bumping `psl`: for each non-exception
//! rule (IDNA labels as punycode, a leading `*.` removed), collect its proper
//! ancestors with at least two labels that are not themselves rules or
//! wildcard parents, then sort.
"""


def locked_psl() -> tuple[str, str]:
    """Return (version, sha256) of the single locked `psl` package."""
    lock = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    packages = [p for p in lock.get("package", []) if p.get("name") == "psl"]
    if len(packages) != 1:
        versions = [p.get("version") for p in packages]
        sys.exit(f"error: expected exactly one locked psl package, found {versions}")
    package = packages[0]
    checksum = package.get("checksum")
    if not checksum:
        sys.exit("error: locked psl package has no checksum (not from crates.io?)")
    return package["version"], checksum


def fetch_crate(version: str) -> bytes:
    url = CRATE_URL.format(version=version)
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                return response.read()
        except OSError as error:  # URLError and socket errors
            last_error = error
            time.sleep(2**attempt)
    sys.exit(f"error: could not download {url}: {last_error}")


def bundled_rules(crate: bytes, version: str, checksum: str) -> str:
    actual = hashlib.sha256(crate).hexdigest()
    if actual != checksum:
        sys.exit(
            f"error: psl-{version}.crate sha256 {actual} does not match the "
            f"Cargo.lock checksum {checksum}"
        )
    member = f"psl-{version}/data/rules.txt"
    with tarfile.open(fileobj=io.BytesIO(crate), mode="r:gz") as archive:
        try:
            extracted = archive.extractfile(member)
        except KeyError:
            extracted = None
        if extracted is None:
            sys.exit(f"error: {member} is missing from the psl crate")
        return extracted.read().decode("utf-8")


def to_ascii(rule: str) -> str:
    """Lower-case a rule and punycode its non-ASCII labels."""
    labels = []
    for label in rule.lower().split("."):
        if label != "*" and not label.isascii():
            label = label.encode("idna").decode("ascii")
        labels.append(label)
    return ".".join(labels)


def suffix_ancestors(rules_text: str) -> list[str]:
    rules: set[str] = set()
    wildcard_parents: set[str] = set()
    entries: list[str] = []
    for line in rules_text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0]
        if rule.startswith("!"):
            # Exception rules carve registrable names out of a wildcard; they
            # never introduce a new suffix boundary.
            continue
        rule = to_ascii(rule)
        if rule.startswith("*."):
            rule = rule[2:]
            wildcard_parents.add(rule)
        else:
            rules.add(rule)
        entries.append(rule)

    ancestors: set[str] = set()
    for entry in entries:
        labels = entry.split(".")
        # Proper ancestors with at least two labels.
        for start in range(1, len(labels) - 1):
            ancestor = ".".join(labels[start:])
            if ancestor not in rules and ancestor not in wildcard_parents:
                ancestors.add(ancestor)
    return sorted(ancestors)


def render(version: str, ancestors: list[str]) -> str:
    body = "".join(f'    "{name}",\n' for name in ancestors)
    return (
        HEADER.format(version=version)
        + "\npub(crate) const PSL_SUFFIX_ANCESTORS: &[&str] = &[\n"
        + body
        + "];\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed index differs from the generated one",
    )
    parser.add_argument(
        "--crate",
        type=Path,
        help="read psl-<version>.crate from this path instead of crates.io",
    )
    args = parser.parse_args()

    version, checksum = locked_psl()
    crate = args.crate.read_bytes() if args.crate else fetch_crate(version)
    generated = render(version, suffix_ancestors(bundled_rules(crate, version, checksum)))
    relative = INDEX.relative_to(REPO_ROOT)

    if args.check:
        committed = INDEX.read_text(encoding="utf-8")
        if committed == generated:
            print(f"{relative} matches psl {version}")
            return 0
        sys.stdout.writelines(
            difflib.unified_diff(
                committed.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                f"{relative} (committed)",
                f"{relative} (generated from psl {version})",
            )
        )
        print(
            f"::error file={relative}::index is stale for psl {version}; run "
            "python3 scripts/generate_cors_psl_ancestors.py and commit the result",
            file=sys.stderr,
        )
        return 1

    INDEX.write_text(generated, encoding="utf-8")
    print(f"wrote {relative} from psl {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
