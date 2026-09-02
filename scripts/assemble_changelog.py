#!/usr/bin/env python3
"""Assemble `CHANGELOG.md` and `docs/upgrade_guide.md` from `changelog.d/` fragments.

Every pull request with a user-visible change adds one small file under
`changelog.d/` instead of editing the shared `## [Unreleased]` block, so two
pull requests touching unrelated source files no longer conflict in the
changelog (issue #4487).

Fragment naming: `changelog.d/<ref>.<section>.md`

  <ref>      the issue number (`4487`) or `pr<N>` when there is no issue
  <section>  one of added, changed, deprecated, removed, fixed, security
             (the Keep a Changelog sections `CHANGELOG.md` already uses), or
             `upgrade` for a `docs/upgrade_guide.md` block

Usage:
  python3 -I scripts/assemble_changelog.py --preview
  python3 -I scripts/assemble_changelog.py --check
  python3 -I scripts/assemble_changelog.py --release 0.10.0 [--date 2026-09-30]
  python3 -I scripts/assemble_changelog.py --self-test
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

FRAGMENT_DIR_NAME = "changelog.d"

# Keep a Changelog section order, matching the headings already in CHANGELOG.md.
CHANGELOG_SECTIONS: tuple[str, ...] = (
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
)
UPGRADE_SECTION = "upgrade"
VALID_SECTIONS: tuple[str, ...] = CHANGELOG_SECTIONS + (UPGRADE_SECTION,)

SECTION_HEADINGS = {name: f"### {name.capitalize()}" for name in CHANGELOG_SECTIONS}

REF_RE = re.compile(r"\A(?:[0-9]+|pr[0-9]+)\Z")
UNRELEASED_HEADING = "## [Unreleased]"
BREAKING_TOKEN = "**BREAKING"
MARKDOWN_LINK_RE = re.compile(r"\]\(([^)]*)\)")
RELEASE_HEADING_RE = re.compile(r"^## \[([0-9]+\.[0-9]+\.[0-9]+)\]", re.MULTILINE)
VERSION_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
DATE_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")

REPO_URL = "https://github.com/ferrum-edge/ferrum-edge"

# Files under changelog.d/ that are documentation, not change fragments.
NON_FRAGMENT_NAMES = frozenset({"README.md"})


class Fragment:
    """One parsed `changelog.d/` file."""

    def __init__(self, path: Path, ref: str, section: str, body: str) -> None:
        self.path = path
        self.ref = ref
        self.section = section
        self.body = body

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def is_breaking(self) -> bool:
        return BREAKING_TOKEN in self.body


def fragment_dir(root: Path) -> Path:
    return root / FRAGMENT_DIR_NAME


def fragment_paths(root: Path) -> list[Path]:
    directory = fragment_dir(root)
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix == ".md" and path.name not in NON_FRAGMENT_NAMES
    )


def parse_name(name: str) -> tuple[str, str] | str:
    """Return `(ref, section)` or an error string."""
    stem = name[: -len(".md")]
    parts = stem.split(".")
    if len(parts) != 2:
        return (
            f"{FRAGMENT_DIR_NAME}/{name}: malformed fragment name; expected "
            "<ref>.<section>.md, for example 4487.changed.md or pr4501.fixed.md"
        )
    ref, section = parts
    if not REF_RE.match(ref):
        return (
            f"{FRAGMENT_DIR_NAME}/{name}: '{ref}' is not a valid reference; use the "
            "issue number (4487) or pr<N> (pr4501) when there is no issue"
        )
    if section not in VALID_SECTIONS:
        return (
            f"{FRAGMENT_DIR_NAME}/{name}: unknown section '{section}'; valid sections "
            f"are {', '.join(VALID_SECTIONS)}"
        )
    return (ref, section)


def check_changelog_body(name: str, body: str) -> list[str]:
    """A changelog fragment is exactly one top-level Markdown bullet."""
    failures: list[str] = []
    lines = body.split("\n")
    if not lines or not lines[0].startswith("- "):
        failures.append(
            f"{FRAGMENT_DIR_NAME}/{name}: body must begin with one top-level bullet "
            "('- ' at column 0)"
        )
        return failures
    for index, line in enumerate(lines[1:], start=2):
        if line.startswith("- "):
            failures.append(
                f"{FRAGMENT_DIR_NAME}/{name}: line {index} starts a second top-level "
                "bullet; one fragment holds exactly one bullet — split it into two files"
            )
        elif line.strip() and not line.startswith("  "):
            failures.append(
                f"{FRAGMENT_DIR_NAME}/{name}: line {index} is a continuation line that "
                "is not indented two spaces"
            )
    return failures


def check_upgrade_body(name: str, body: str) -> list[str]:
    """An upgrade fragment is one or more `### ` blocks for the upgrade guide."""
    if not body.startswith("### "):
        return [
            f"{FRAGMENT_DIR_NAME}/{name}: upgrade fragments must begin with a "
            "'### <heading> (issue [#N](...))' block, matching docs/upgrade_guide.md"
        ]
    return []


def check_links(name: str, body: str) -> list[str]:
    """Fragments move to the repository root at release time, so relative links break."""
    failures: list[str] = []
    for target in MARKDOWN_LINK_RE.findall(body):
        target = target.strip()
        if not target.startswith(("http://", "https://", "#")):
            failures.append(
                f"{FRAGMENT_DIR_NAME}/{name}: link target '{target}' is relative; use "
                f"an absolute {REPO_URL}/blob/main/... URL, because the fragment's text "
                "is moved to the repository root at release time"
            )
    return failures


def load_fragments(root: Path) -> tuple[list[Fragment], list[str]]:
    fragments: list[Fragment] = []
    failures: list[str] = []
    for path in fragment_paths(root):
        parsed = parse_name(path.name)
        if isinstance(parsed, str):
            failures.append(parsed)
            continue
        ref, section = parsed
        body = path.read_text(encoding="utf-8").replace("\r\n", "\n").strip("\n")
        if not body.strip():
            failures.append(f"{FRAGMENT_DIR_NAME}/{path.name}: body is empty")
            continue
        if section == UPGRADE_SECTION:
            failures.extend(check_upgrade_body(path.name, body))
        else:
            failures.extend(check_changelog_body(path.name, body))
        failures.extend(check_links(path.name, body))
        fragments.append(Fragment(path, ref, section, body))
    return fragments, failures


def check_breaking_pairing(fragments: list[Fragment]) -> list[str]:
    failures: list[str] = []
    upgrade_refs = {f.ref for f in fragments if f.section == UPGRADE_SECTION}
    breaking_refs: set[str] = set()
    for fragment in fragments:
        if fragment.section == UPGRADE_SECTION:
            continue
        if not fragment.is_breaking:
            continue
        breaking_refs.add(fragment.ref)
        if fragment.ref not in upgrade_refs:
            failures.append(
                f"{FRAGMENT_DIR_NAME}/{fragment.name}: a {BREAKING_TOKEN} bullet needs "
                f"upgrade guidance; add {FRAGMENT_DIR_NAME}/{fragment.ref}.upgrade.md"
            )
    for fragment in fragments:
        if fragment.section != UPGRADE_SECTION:
            continue
        if fragment.ref not in breaking_refs:
            failures.append(
                f"{FRAGMENT_DIR_NAME}/{fragment.name}: upgrade guidance without a "
                f"{BREAKING_TOKEN} changelog bullet for '{fragment.ref}'; add one, or "
                "drop this file"
            )
    return failures


def render_changelog_sections(fragments: list[Fragment]) -> str:
    """Render the non-empty Keep a Changelog sections, in canonical order."""
    blocks: list[str] = []
    for section in CHANGELOG_SECTIONS:
        bullets = [f.body for f in fragments if f.section == section]
        if not bullets:
            continue
        blocks.append(SECTION_HEADINGS[section] + "\n\n" + "\n\n".join(bullets))
    return "\n\n".join(blocks)


def render_upgrade_blocks(fragments: list[Fragment]) -> str:
    blocks = [f.body for f in fragments if f.section == UPGRADE_SECTION]
    return "\n\n".join(blocks)


def unreleased_bounds(changelog: str) -> tuple[int, int] | None:
    """Byte offsets of the `## [Unreleased]` section body, heading excluded."""
    at = changelog.find(UNRELEASED_HEADING)
    if at < 0:
        return None
    start = at + len(UNRELEASED_HEADING)
    rest = changelog[start:]
    end = rest.find("\n## ")
    return (start, start + end) if end >= 0 else (start, len(changelog))


def check_repository(root: Path = REPO_ROOT) -> list[str]:
    fragments, failures = load_fragments(root)
    failures.extend(check_breaking_pairing(fragments))

    changelog_path = root / "CHANGELOG.md"
    changelog = changelog_path.read_text(encoding="utf-8")
    bounds = unreleased_bounds(changelog)
    if bounds is None:
        failures.append(f"CHANGELOG.md must contain an '{UNRELEASED_HEADING}' heading")
        return failures

    start, end = bounds
    if changelog[start:end].strip():
        failures.append(
            f"CHANGELOG.md '{UNRELEASED_HEADING}' must stay empty between releases; "
            f"unreleased entries live in {FRAGMENT_DIR_NAME}/ fragments and are "
            "assembled by 'scripts/assemble_changelog.py --release'. Move the hand-"
            f"written text into a {FRAGMENT_DIR_NAME}/<ref>.<section>.md file"
        )
    return failures


def render_preview(root: Path = REPO_ROOT) -> str:
    fragments, _ = load_fragments(root)
    sections = render_changelog_sections(fragments)
    out = UNRELEASED_HEADING + "\n"
    if sections:
        out += "\n" + sections + "\n"
    upgrade = render_upgrade_blocks(fragments)
    if upgrade:
        out += "\n<!-- docs/upgrade_guide.md blocks -->\n\n" + upgrade + "\n"
    return out


def previous_version(changelog: str) -> str | None:
    match = RELEASE_HEADING_RE.search(changelog)
    return match.group(1) if match else None


def rewrite_changelog(changelog: str, version: str, date: str, sections: str) -> str:
    bounds = unreleased_bounds(changelog)
    if bounds is None:
        raise ValueError(f"CHANGELOG.md must contain an '{UNRELEASED_HEADING}' heading")
    start, end = bounds
    previous = previous_version(changelog)

    body = f"\n\n## [{version}] - {date}\n"
    if sections:
        body += "\n" + sections + "\n"
    updated = changelog[:start] + body + changelog[end:]

    # Compare-link references at the bottom of the file, when the file keeps them.
    unreleased_link = re.compile(rf"^\[Unreleased\]: {re.escape(REPO_URL)}/compare/.*$", re.MULTILINE)
    if unreleased_link.search(updated):
        if previous:
            new_link = f"{REPO_URL}/compare/v{previous}...v{version}"
        else:
            new_link = f"{REPO_URL}/releases/tag/v{version}"
        updated = unreleased_link.sub(
            f"[Unreleased]: {REPO_URL}/compare/v{version}...HEAD\n"
            f"[{version}]: {new_link}",
            updated,
            count=1,
        )
    return updated


def upgrade_guide_heading(version: str) -> str:
    return f"## Breaking changes in {version}"


def rewrite_upgrade_guide(guide: str, version: str, blocks: str) -> str:
    """Insert `blocks` under the release's breaking-changes heading."""
    heading = upgrade_guide_heading(version)
    if heading in guide:
        at = guide.index(heading) + len(heading)
        rest = guide[at:]
        end = rest.find("\n## ")
        insert_at = at + (end if end >= 0 else len(rest))
        return guide[:insert_at] + "\n\n" + blocks + "\n" + guide[insert_at:]

    intro = (
        f"{heading}\n\n"
        f"Every `BREAKING` changelog entry in the `[{version}]` release is listed here "
        "exactly once, with its issue number and the operator action that entry already "
        "states. Read this section before the per-mode procedures below.\n\n"
    )
    existing = re.search(r"^## Breaking changes in ", guide, re.MULTILINE)
    insert_at = existing.start() if existing else len(guide)
    return guide[:insert_at] + intro + blocks + "\n\n" + guide[insert_at:]


def release(root: Path, version: str, date: str) -> list[str]:
    if not VERSION_RE.match(version):
        return [f"--release expects an X.Y.Z version, got '{version}'"]
    if not DATE_RE.match(date):
        return [f"--date expects YYYY-MM-DD, got '{date}'"]

    failures = check_repository(root)
    if failures:
        return failures

    fragments, _ = load_fragments(root)
    if not fragments:
        print(
            f"no {FRAGMENT_DIR_NAME}/ fragments to assemble; CHANGELOG.md and "
            "docs/upgrade_guide.md are unchanged"
        )
        return []

    changelog_path = root / "CHANGELOG.md"
    changelog_path.write_text(
        rewrite_changelog(
            changelog_path.read_text(encoding="utf-8"),
            version,
            date,
            render_changelog_sections(fragments),
        ),
        encoding="utf-8",
    )

    blocks = render_upgrade_blocks(fragments)
    if blocks:
        guide_path = root / "docs" / "upgrade_guide.md"
        guide_path.write_text(
            rewrite_upgrade_guide(guide_path.read_text(encoding="utf-8"), version, blocks),
            encoding="utf-8",
        )

    for fragment in fragments:
        fragment.path.unlink()

    print(
        f"assembled {len(fragments)} fragment(s) into CHANGELOG.md [{version}] - {date}"
    )
    return []


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture(root: Path) -> None:
    """A minimal, valid repository shape for the self-test."""
    _write(
        root,
        "CHANGELOG.md",
        "# Changelog\n\n"
        f"{UNRELEASED_HEADING}\n\n"
        "## [0.9.0] - 2026-09-02\n\n"
        "### Changed\n\n"
        "- **Old entry** (issue #1).\n\n"
        f"[Unreleased]: {REPO_URL}/compare/v0.9.0...HEAD\n"
        f"[0.9.0]: {REPO_URL}/releases/tag/v0.9.0\n",
    )
    _write(
        root,
        "docs/upgrade_guide.md",
        "# Safe Upgrade Guide\n\nIntro paragraph.\n\n"
        "## Breaking changes in 0.9.0\n\n### Old thing (issue [#1](x))\n\nText.\n",
    )
    fragment_dir(root).mkdir(parents=True, exist_ok=True)


def run_self_test() -> list[str]:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _fixture(root)
        frags = fragment_dir(root)

        def expect_reject(label: str, files: dict[str, str]) -> None:
            for existing in fragment_paths(root):
                existing.unlink()
            for name, text in files.items():
                (frags / name).write_text(text, encoding="utf-8")
            if not check_repository(root):
                failures.append(f"{label} was not rejected")

        def expect_accept(label: str, files: dict[str, str]) -> None:
            for existing in fragment_paths(root):
                existing.unlink()
            for name, text in files.items():
                (frags / name).write_text(text, encoding="utf-8")
            errors = check_repository(root)
            if errors:
                failures.append(f"{label} was rejected: {errors}")

        expect_accept("a valid changed fragment", {"4487.changed.md": "- **A** (issue #4487).\n"})
        expect_accept(
            "a valid breaking pair",
            {
                "10.changed.md": "- **BREAKING** — **A** (issue #10).\n  Wrapped line.\n",
                "10.upgrade.md": "### A (issue [#10](https://example.invalid/10))\n\nDo X.\n",
            },
        )
        expect_accept("an empty fragment directory", {})
        expect_reject("an unknown section", {"10.notasection.md": "- **A** (issue #10).\n"})
        expect_reject("a malformed name", {"nosection.md": "- **A**.\n"})
        expect_reject("a non-numeric reference", {"abc.changed.md": "- **A**.\n"})
        expect_reject("an empty body", {"10.changed.md": "\n\n"})
        expect_reject(
            "two top-level bullets", {"10.changed.md": "- **A** (issue #10).\n- **B**.\n"}
        )
        expect_reject("a body that is not a bullet", {"10.changed.md": "Plain text.\n"})
        expect_reject(
            "an unindented continuation line",
            {"10.changed.md": "- **A** (issue #10).\ncontinued.\n"},
        )
        expect_reject(
            "a BREAKING bullet without upgrade guidance",
            {"10.changed.md": "- **BREAKING** — **A** (issue #10).\n"},
        )
        expect_reject(
            "upgrade guidance without a BREAKING bullet",
            {
                "10.changed.md": "- **A** (issue #10).\n",
                "10.upgrade.md": "### A (issue [#10](https://example.invalid/10))\n\nDo X.\n",
            },
        )
        expect_reject(
            "an upgrade fragment that is not a ### block",
            {
                "10.changed.md": "- **BREAKING** — **A** (issue #10).\n",
                "10.upgrade.md": "Do X.\n",
            },
        )
        expect_reject(
            "a relative link target",
            {"10.changed.md": "- **A** (issue #10). See [docs](docs/ci_cd.md).\n"},
        )

        # A hand-edited [Unreleased] block.
        for existing in fragment_paths(root):
            existing.unlink()
        changelog_path = root / "CHANGELOG.md"
        original = changelog_path.read_text(encoding="utf-8")
        changelog_path.write_text(
            original.replace(
                f"{UNRELEASED_HEADING}\n\n", f"{UNRELEASED_HEADING}\n\n- hand-written\n\n", 1
            ),
            encoding="utf-8",
        )
        if not check_repository(root):
            failures.append("a hand-edited [Unreleased] section was not rejected")
        changelog_path.write_text(original, encoding="utf-8")

        # A CHANGELOG without an [Unreleased] heading.
        changelog_path.write_text("# Changelog\n\n## [0.9.0] - 2026-09-02\n", encoding="utf-8")
        if not check_repository(root):
            failures.append("a CHANGELOG.md without [Unreleased] was not rejected")
        changelog_path.write_text(original, encoding="utf-8")

        # --release renders, inserts upgrade guidance, and consumes the fragments.
        (frags / "10.changed.md").write_text(
            "- **BREAKING** — **A** (issue #10).\n", encoding="utf-8"
        )
        (frags / "10.upgrade.md").write_text(
            "### A (issue [#10](https://example.invalid/10))\n\nDo X.\n", encoding="utf-8"
        )
        (frags / "11.fixed.md").write_text("- **B** (issue #11).\n", encoding="utf-8")
        errors = release(root, "0.10.0", "2026-09-30")
        if errors:
            failures.append(f"--release on valid fragments failed: {errors}")
        released = changelog_path.read_text(encoding="utf-8")
        for expected in (
            f"{UNRELEASED_HEADING}\n\n## [0.10.0] - 2026-09-30\n",
            "### Changed\n\n- **BREAKING** — **A** (issue #10).",
            "### Fixed\n\n- **B** (issue #11).",
            f"[Unreleased]: {REPO_URL}/compare/v0.10.0...HEAD",
            f"[0.10.0]: {REPO_URL}/compare/v0.9.0...v0.10.0",
        ):
            if expected not in released:
                failures.append(f"--release output is missing {expected!r}")
        if "### Changed" in released.split("## [0.10.0]")[0]:
            failures.append("--release left content in the [Unreleased] section")
        guide = (root / "docs" / "upgrade_guide.md").read_text(encoding="utf-8")
        if "## Breaking changes in 0.10.0" not in guide or "Do X." not in guide:
            failures.append("--release did not insert the upgrade-guide block")
        if "## Breaking changes in 0.9.0" not in guide or "Old thing" not in guide:
            failures.append("--release disturbed an older upgrade-guide section")
        if guide.index("in 0.10.0") > guide.index("in 0.9.0"):
            failures.append("--release did not insert the newest section first")
        if fragment_paths(root):
            failures.append("--release did not delete the consumed fragments")
        if check_repository(root):
            failures.append("--release left the repository failing --check")

        # Idempotent: a second --release is a no-op.
        before = changelog_path.read_text(encoding="utf-8")
        errors = release(root, "0.10.0", "2026-09-30")
        if errors:
            failures.append(f"a second --release reported failures: {errors}")
        if changelog_path.read_text(encoding="utf-8") != before:
            failures.append("a second --release was not a no-op")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble CHANGELOG.md from changelog.d/ fragments."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preview", action="store_true", help="print the rendered fragments")
    group.add_argument("--check", action="store_true", help="validate fragments and CHANGELOG.md")
    group.add_argument("--release", metavar="X.Y.Z", help="assemble fragments into a release")
    group.add_argument("--self-test", action="store_true", help="run the script's own tests")
    parser.add_argument("--date", metavar="YYYY-MM-DD", help="release date (default: today, UTC)")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.preview:
        sys.stdout.write(render_preview())
        return 0

    if args.self_test:
        failures = run_self_test()
    elif args.release:
        date = args.date or datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
        failures = release(REPO_ROOT, args.release, date)
    else:
        failures = check_repository()

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
