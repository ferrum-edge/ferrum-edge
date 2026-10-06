#!/usr/bin/env python3
"""Reconstruct the shipped Hyper source from its pinned crate and ordered patches.

Run in GitHub-hosted CI before Cargo can generate files in the vendor tree.
No formatter or source-copy overlay is allowed between application and hashing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/upstream-hyper-patches"
VENDOR_REL = "vendor/hyper-1.10.0-ferrum-patched"
ARCHIVE_SHA256 = "eb92f162bf56536459fc83c79b974bb12837acfed43d6bc370a7916d0ae15ecc"
UPSTREAM_REVISION = "79dbab620bf14b96cd5d53a60ca35d7fe2ddbaf1"
SERIES = (
    "001-upgraded-h2-connect-error-reset/hyper-upgraded-h2-connect-error-reset.patch",
    "002-min-data-frame-capacity/hyper-min-data-frame-capacity.patch",
    "003-greedy-h1-read/hyper-greedy-h1-read.patch",
    "004-h2-body-write-timeout/hyper-h2-body-write-timeout.patch",
    "005-h2-small-window-coalescing/hyper-h2-small-window-coalescing.patch",
)
ROOT_FILES = {"Cargo.toml", "LICENSE", "README.md"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_hash(path: Path) -> str:
    # All governed Hyper paths are text. Match the vendor integrity contract.
    return sha256(path.read_bytes().replace(b"\r", b""))


def validate_series(lines: list[str], available: set[str]) -> None:
    if tuple(lines) != SERIES or available != set(SERIES):
        raise ValueError("Hyper patches must be exactly the complete ordered 001-005 series")


def validate_member(member: tarfile.TarInfo) -> None:
    path = PurePosixPath(member.name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0] != "hyper-1.10.0"
        or not (member.isfile() or member.isdir())
    ):
        raise ValueError(f"Unexpected crate archive member: {member.name!r}")


def manifest_hashes(manifest: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    prefix = VENDOR_REL + "/"
    for line in manifest.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        digest, name = line.split(maxsplit=1)
        if not name.startswith(prefix):
            continue
        relative = name.removeprefix(prefix)
        path = PurePosixPath(relative)
        if (
            not re.fullmatch(r"[0-9a-f]{64}", digest)
            or path.is_absolute()
            or ".." in path.parts
            or relative in hashes
        ):
            raise ValueError(f"Invalid or duplicate Hyper manifest entry: {name!r}")
        hashes[relative] = digest
    if not hashes:
        raise ValueError("Hyper is missing from the vendor integrity manifest")
    return hashes


def compare_source(reconstructed: Path, vendor: Path, expected: dict[str, str]) -> None:
    vendor_files = {p.relative_to(vendor).as_posix() for p in vendor.rglob("*") if p.is_file()}
    source_files = {
        p.relative_to(reconstructed).as_posix()
        for p in (reconstructed / "src").rglob("*")
        if p.is_file()
    } | ROOT_FILES
    if vendor_files != set(expected) or source_files != set(expected):
        raise ValueError("Reconstructed, vendored and manifest Hyper file sets differ")
    for name, digest in sorted(expected.items()):
        rebuilt = reconstructed / name
        shipped = vendor / name
        if rebuilt.read_bytes() != shipped.read_bytes():
            raise ValueError(f"Reconstructed Hyper bytes differ from vendor: {name}")
        if source_hash(rebuilt) != digest or source_hash(shipped) != digest:
            raise ValueError(f"Hyper source differs from its integrity manifest: {name}")


def verify(archive: Path, evidence: Path) -> None:
    archive_bytes = archive.read_bytes()
    if sha256(archive_bytes) != ARCHIVE_SHA256:
        raise ValueError("Hyper crate archive checksum differs from the crates.io pin")
    validate_series(
        (DOCS / "series").read_text().splitlines(),
        {p.relative_to(DOCS).as_posix() for p in DOCS.rglob("*.patch")},
    )
    expected = manifest_hashes(ROOT / "vendor/VENDOR_INTEGRITY.sha256")
    evidence.mkdir(parents=True, exist_ok=True)
    patch_hashes: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="hyper-patch-stack-") as temporary:
        destination = Path(temporary)
        with tarfile.open(archive, "r:gz") as crate:
            for member in crate.getmembers():
                validate_member(member)
            crate.extractall(destination, filter="data")
        reconstructed = destination / "hyper-1.10.0"
        provenance = json.loads((reconstructed / ".cargo_vcs_info.json").read_text())
        if provenance["git"]["sha1"] != UPSTREAM_REVISION:
            raise ValueError("Hyper crate VCS revision differs from the pinned source")
        if provenance["git"].get("dirty") is not True:
            raise ValueError("Hyper 1.10.0's published dirty VCS marker differs from the archive")
        for name in SERIES:
            patch_bytes = (DOCS / name).read_bytes()
            patch_hashes[name] = sha256(patch_bytes)
            # Keep argv literal for trusted policy inspection; stdin is patch data.
            subprocess.run(
                ["git", "apply", "--verbose", "--whitespace=nowarn", "-"],
                input=patch_bytes,
                cwd=reconstructed,
                check=True,
            )
        compare_source(reconstructed, ROOT / VENDOR_REL, expected)
        (evidence / "reconstructed.sha256").write_text(
            "".join(
                f"{source_hash(reconstructed / name)}  {VENDOR_REL}/{name}\n"
                for name in sorted(expected)
            )
        )
    report = {
        "archive_sha256": ARCHIVE_SHA256,
        "upstream_revision": UPSTREAM_REVISION,
        "upstream_vcs_dirty": True,
        "patch_sha256": patch_hashes,
        "files_verified": len(expected),
        "comparison": "exact vendor bytes and LF-normalized integrity manifest hashes",
    }
    (evidence / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


class VerificationTests(unittest.TestCase):
    def test_order_and_completeness_are_required(self) -> None:
        validate_series(list(SERIES), set(SERIES))
        for lines in (list(reversed(SERIES)), list(SERIES[:-1]), list(SERIES) + [SERIES[0]]):
            with self.assertRaises(ValueError):
                validate_series(lines, set(SERIES))
        with self.assertRaises(ValueError):
            validate_series(list(SERIES), set(SERIES) | {"unexpected.patch"})

    def test_archive_members_cannot_escape_or_link(self) -> None:
        for name in ("../src/mod.rs", "/hyper-1.10.0/src/mod.rs", "hyper-1.10.0/../outside"):
            with self.assertRaises(ValueError):
                validate_member(tarfile.TarInfo(name))
        link = tarfile.TarInfo("hyper-1.10.0/src/link")
        link.type = tarfile.SYMTYPE
        with self.assertRaises(ValueError):
            validate_member(link)

    def test_comparison_covers_untouched_files_and_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            reconstructed, vendor = base / "rebuilt", base / "vendor"
            names = ROOT_FILES | {"src/changed.rs", "src/untouched.rs"}
            for root in (reconstructed, vendor):
                (root / "src").mkdir(parents=True)
                for name in names:
                    (root / name).write_bytes(b"original\n")
            expected = {name: source_hash(vendor / name) for name in names}
            compare_source(reconstructed, vendor, expected)
            untouched = reconstructed / "src/untouched.rs"
            for data in (b"drift\n", b"original\r\n"):
                untouched.write_bytes(data)
                with self.assertRaises(ValueError):
                    compare_source(reconstructed, vendor, expected)
            untouched.write_bytes(b"original\n")
            bad_manifest = dict(expected)
            bad_manifest["src/changed.rs"] = "0" * 64
            with self.assertRaises(ValueError):
                compare_source(reconstructed, vendor, bad_manifest)
            with self.assertRaises(ValueError):
                compare_source(
                    reconstructed,
                    vendor,
                    {k: v for k, v in expected.items() if k != "src/untouched.rs"},
                )
            (reconstructed / "src/extra.rs").write_bytes(b"extra\n")
            with self.assertRaises(ValueError):
                compare_source(reconstructed, vendor, expected)

    def test_ordered_patches_apply_from_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/mod.rs").write_bytes(b"upstream\n")
            for patch_bytes in (
                b"--- a/src/mod.rs\n+++ b/src/mod.rs\n@@ -1 +1 @@\n-upstream\n+pending_data\n",
                b"--- a/src/mod.rs\n+++ b/src/mod.rs\n@@ -1 +1 @@\n-pending_data\n+progress\n",
            ):
                subprocess.run(
                    ["git", "apply", "--verbose", "--whitespace=nowarn", "-"],
                    input=patch_bytes,
                    cwd=root,
                    capture_output=True,
                    check=True,
                )
            self.assertEqual((root / "src/mod.rs").read_bytes(), b"progress\n")

    def test_incremental_patch_cannot_apply_to_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/mod.rs").write_text("upstream\n")
            patch_bytes = (
                b"--- a/src/mod.rs\n+++ b/src/mod.rs\n@@ -1 +1 @@\n-pending_data\n+progress\n"
            )
            with self.assertRaises(subprocess.CalledProcessError):
                subprocess.run(
                    ["git", "apply", "--verbose", "--whitespace=nowarn", "-"],
                    input=patch_bytes,
                    cwd=root,
                    capture_output=True,
                    check=True,
                )
            self.assertEqual((root / "src/mod.rs").read_text(), "upstream\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(VerificationTests)
        )
        if not result.wasSuccessful():
            raise SystemExit(1)
    else:
        if args.archive is None or args.evidence is None:
            parser.error("--archive and --evidence are required")
        verify(args.archive.resolve(), args.evidence.resolve())


if __name__ == "__main__":
    main()
