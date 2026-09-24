#!/usr/bin/env python3
"""Inventory every standalone Cargo workspace root in the repository.

The root `Cargo.toml` declares no `[workspace]`, so `cargo fmt --all`,
`cargo check`, `cargo clippy`, and `cargo deny` at the repository root only see
the root `ferrum-edge` package. Every other manifest (the fuzz crate, the
`tests/performance/**` benchmark harnesses, and any crate added later) is
resolved by Cargo as its own workspace with its own `Cargo.lock`, and is
invisible to those root gates (issues #5703, #5704, #5707, #5708).

This script prints one repository-relative manifest path per line for every
such workspace root, so the `standalone-cargo` CI job and the dependency-audit
lanes cover new standalone crates automatically instead of relying on a
hand-maintained list. It only reads files; it never runs Cargo.

A manifest is inventoried unless:

* it is the root `Cargo.toml` (covered by the root gates);
* it lives under an `EXCLUDED_PREFIXES` tree, each of which has a dedicated
  owner documented below;
* it lives under a build-output or VCS directory (`SKIPPED_DIR_NAMES`); or
* it is a member of an ancestor manifest's `[workspace]` (the ancestor workspace
  root is inventoried instead, and the per-workspace commands cover members).

    python3 .github/scripts/standalone_cargo_manifests.py
    python3 .github/scripts/standalone_cargo_manifests.py --self-test
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath


# Trees that contain Cargo manifests but are validated by a dedicated owner.
EXCLUDED_PREFIXES = {
    # Patched copies of upstream crates wired in through the root
    # `[patch.crates-io]` table. They compile inside the root graph, run their
    # own regression suites in ci.yml `test-vendor-patches`, and keep upstream
    # formatting so the patch diff against upstream stays reviewable.
    "vendor/": "vendored upstream crates (test-vendor-patches, root graph)",
    # The eBPF programs form a nightly `bpfel-unknown-none` workspace that only
    # builds with `-Z build-std` and bpf-linker. ci.yml `build-ebpf` owns that
    # compile, and both dependency-audit lanes already run a dedicated
    # cargo-deny step over `ebpf/Cargo.toml`.
    "ebpf/": "nightly BPF workspace (build-ebpf, eBPF cargo-deny step)",
}

SKIPPED_DIR_NAMES = frozenset({".git", "target", "node_modules"})


def discover_manifests(repo_root: Path) -> list[str]:
    """Return every `Cargo.toml` under `repo_root` as a sorted POSIX path."""

    manifests: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIPPED_DIR_NAMES)
        if "Cargo.toml" in filenames:
            rel = (Path(dirpath) / "Cargo.toml").relative_to(repo_root)
            manifests.append(rel.as_posix())
    return sorted(manifests)


def load_manifest(repo_root: Path, rel: str) -> dict:
    with (repo_root / rel).open("rb") as handle:
        return tomllib.load(handle)


def is_excluded(rel: str) -> bool:
    return any(rel.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def member_of_ancestor_workspace(rel: str, parsed: dict[str, dict]) -> bool:
    """Return whether an ancestor manifest's `[workspace]` owns this manifest.

    Mirrors Cargo's root search: a package that declares its own `[workspace]`
    table is always its own root. Otherwise Cargo walks up the ancestors and the
    first `[workspace]` that does not list the package's directory verbatim in
    its `exclude` array owns it; an excluding workspace is skipped and the walk
    continues upwards.
    """

    if "workspace" in parsed[rel]:
        return False
    package_dir = PurePosixPath(rel).parent
    for ancestor in package_dir.parents:
        at_root = str(ancestor) == "."
        candidate = "Cargo.toml" if at_root else f"{ancestor}/Cargo.toml"
        workspace = parsed.get(candidate, {}).get("workspace")
        if workspace is None:
            continue
        relative = (
            package_dir.as_posix() if at_root else package_dir.relative_to(ancestor).as_posix()
        )
        excluded = {
            PurePosixPath(entry).as_posix()
            for entry in workspace.get("exclude", [])
            if isinstance(entry, str)
        }
        if relative in excluded:
            continue
        return True
    return False


def standalone_workspace_roots(repo_root: Path) -> list[str]:
    manifests = discover_manifests(repo_root)
    parsed = {rel: load_manifest(repo_root, rel) for rel in manifests}
    roots: list[str] = []
    for rel in manifests:
        if rel == "Cargo.toml" or is_excluded(rel):
            continue
        if member_of_ancestor_workspace(rel, parsed):
            continue
        roots.append(rel)
    return roots


def self_test() -> list[str]:
    failures: list[str] = []
    fixture = {
        "Cargo.toml": '[package]\nname = "root"\nversion = "0.1.0"\n',
        "fuzz/Cargo.toml": '[package]\nname = "fuzz"\nversion = "0.0.0"\n',
        "tests/performance/Cargo.toml": '[package]\nname = "backend"\nversion = "0.1.0"\n',
        "tests/performance/mesh/Cargo.toml": '[package]\nname = "mesh"\nversion = "0.1.0"\n',
        "tests/performance/new_bench/Cargo.toml": '[package]\nname = "nb"\nversion = "0.1.0"\n',
        "vendor/h3/Cargo.toml": '[package]\nname = "h3"\nversion = "0.0.8"\n',
        "ebpf/Cargo.toml": '[workspace]\nmembers = ["prog"]\n',
        "ebpf/prog/Cargo.toml": '[package]\nname = "prog"\nversion = "0.1.0"\n',
        "tools/ws/Cargo.toml": '[workspace]\nmembers = ["a"]\nexclude = ["detached"]\n',
        "tools/ws/a/Cargo.toml": '[package]\nname = "a"\nversion = "0.1.0"\n',
        "tools/ws/detached/Cargo.toml": '[package]\nname = "d"\nversion = "0.1.0"\n',
        "tools/ws/own/Cargo.toml": '[package]\nname = "o"\nversion = "0.1.0"\n\n[workspace]\n',
        "fuzz/target/debug/build/x/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
        "target/package/y/Cargo.toml": '[package]\nname = "y"\nversion = "0.1.0"\n',
    }
    expected = [
        "fuzz/Cargo.toml",
        "tests/performance/Cargo.toml",
        "tests/performance/mesh/Cargo.toml",
        "tests/performance/new_bench/Cargo.toml",
        "tools/ws/Cargo.toml",
        "tools/ws/detached/Cargo.toml",
        "tools/ws/own/Cargo.toml",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, text in fixture.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        actual = standalone_workspace_roots(root)
        if actual != expected:
            failures.append(
                f"standalone inventory fixture: expected {expected!r}, got {actual!r}"
            )

        # A root manifest that grows a [workspace] absorbs its nested members,
        # which the root gates then cover. A package excluded by a nearer
        # workspace keeps walking up and joins the root workspace.
        (root / "Cargo.toml").write_text(
            '[package]\nname = "root"\nversion = "0.1.0"\n\n'
            '[workspace]\nexclude = ["fuzz"]\n',
            encoding="utf-8",
        )
        actual = standalone_workspace_roots(root)
        expected_with_root_workspace = [
            "fuzz/Cargo.toml",
            "tools/ws/Cargo.toml",
            "tools/ws/own/Cargo.toml",
        ]
        if actual != expected_with_root_workspace:
            failures.append(
                "standalone inventory root-workspace fixture: expected "
                f"{expected_with_root_workspace!r}, got {actual!r}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="repository root to scan (default: current directory)",
    )
    args = parser.parse_args()

    if args.self_test:
        failures = self_test()
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        if not failures:
            print("standalone Cargo manifest inventory self-test passed", file=sys.stderr)
        return 1 if failures else 0

    roots = standalone_workspace_roots(args.repo_root)
    if not roots:
        # Fail closed: an empty inventory would silently turn every standalone
        # gate into a no-op.
        print("::error::no standalone Cargo manifests were discovered", file=sys.stderr)
        return 1
    for rel in roots:
        print(rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
