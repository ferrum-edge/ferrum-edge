#!/usr/bin/env python3
"""Validate first-party Markdown relative links and GitHub heading slugs.

Checks tracked `*.md` files for relative file targets and `#fragment` anchors
using GitHub's heading-slug algorithm (GFM / html-pipeline TableOfContentsFilter):

1. lowercase
2. strip punctuation (keep Unicode word characters, hyphens, spaces, underscores)
3. spaces → hyphens
4. duplicate headings get `-1`, `-2`, …

External URLs (`http(s):`, `mailto:`, …) are ignored. Vendored and other
generated trees are excluded explicitly rather than skipped silently.

Usage:
  python3 -I .github/scripts/check_markdown_links.py --self-test
  python3 -I .github/scripts/check_markdown_links.py
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]

# Explicit exclusions — keep this list intentional and greppable.
EXCLUDE_PREFIXES: tuple[str, ...] = (
    "vendor/",
    "target/",
    "node_modules/",
)

FIXTURE_RELATIVE = Path("tests/fixtures/markdown_link_check/github_heading_slugs.md")

PUNCTUATION_RE = re.compile(r"[^\w\- ]", re.UNICODE)
ATX_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
INLINE_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(([^)]+)\)")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
HTML_TAG_RE = re.compile(r"<[^>]+>")
BOLD_RE = re.compile(r"(\*\*|__)(.+?)\1")
ITALIC_STAR_RE = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
CUSTOM_HEADING_ID_RE = re.compile(r"\s*\{#([A-Za-z0-9_-]+)\}\s*$")
GITHUB_LINE_FRAGMENT_RE = re.compile(r"^L\d+(?:-L\d+)?$")
FENCE_RE = re.compile(r"^(```|~~~)")


@dataclass(frozen=True)
class LinkRef:
    source: Path
    line: int
    target: str


@dataclass(frozen=True)
class LinkError:
    source: Path
    line: int
    target: str
    reason: str

    def format(self) -> str:
        rel = self.source.as_posix()
        return f"{rel}:{self.line}: unresolved target `{self.target}` ({self.reason})"


def posix_rel(path: Path, root: Path = REPO_ROOT) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def is_excluded(rel_posix: str) -> bool:
    return any(rel_posix == prefix.rstrip("/") or rel_posix.startswith(prefix) for prefix in EXCLUDE_PREFIXES)


def tracked_markdown_files(root: Path = REPO_ROOT) -> list[Path]:
    raw = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"],
        text=False,
    )
    files: list[Path] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        rel = entry.decode()
        if is_excluded(rel):
            continue
        files.append(root / rel)
    return sorted(files)


def heading_plain_text(raw: str) -> str:
    """Approximate GFM heading text (code spans keep content; underscores stay)."""
    text = raw.strip()
    text = CUSTOM_HEADING_ID_RE.sub("", text)
    text = INLINE_CODE_RE.sub(r"\1", text)
    text = MD_IMAGE_RE.sub(r"\1", text)
    text = MD_LINK_RE.sub(r"\1", text)
    text = HTML_TAG_RE.sub("", text)
    text = BOLD_RE.sub(r"\2", text)
    text = ITALIC_STAR_RE.sub(r"\1", text)
    return text.strip()


def github_slug(text: str) -> str:
    slug = text.lower()
    slug = PUNCTUATION_RE.sub("", slug)
    return slug.replace(" ", "-")


def collect_heading_slugs(content: str) -> set[str]:
    seen: dict[str, int] = {}
    slugs: set[str] = set()
    in_fence = False
    for line in content.splitlines():
        if FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = ATX_HEADING_RE.match(line)
        if not match:
            continue
        raw_heading = match.group(2).strip()
        custom = CUSTOM_HEADING_ID_RE.search(raw_heading)
        if custom:
            slugs.add(custom.group(1))
        base = github_slug(heading_plain_text(raw_heading))
        if not base:
            continue
        count = seen.get(base, 0)
        slug = base if count == 0 else f"{base}-{count}"
        seen[base] = count + 1
        slugs.add(slug)
    return slugs


def iter_inline_links(content: str, source: Path) -> Iterable[LinkRef]:
    in_fence = False
    for lineno, line in enumerate(content.splitlines(), 1):
        if FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in INLINE_LINK_RE.finditer(line):
            yield LinkRef(source=source, line=lineno, target=match.group(2).strip())


def normalize_link_destination(raw: str) -> str | None:
    target = raw.strip()
    if not target or target in {"#", "/"}:
        return None
    if target.startswith("<") and ">" in target:
        target = target[1:].split(">", 1)[0].strip()
    else:
        target = re.split(r"\s+", target, maxsplit=1)[0]
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https", "mailto", "ftp", "tel"}:
        return None
    if target.startswith("//"):
        return None
    return target


def check_file(
    path: Path,
    *,
    root: Path,
    slug_cache: dict[Path, set[str]],
) -> list[LinkError]:
    errors: list[LinkError] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            LinkError(
                source=path,
                line=1,
                target=posix_rel(path, root),
                reason=f"unreadable: {exc}",
            )
        ]

    def slugs_for(target_path: Path) -> set[str]:
        cached = slug_cache.get(target_path)
        if cached is not None:
            return cached
        try:
            text = target_path.read_text(encoding="utf-8")
        except OSError:
            slug_cache[target_path] = set()
            return slug_cache[target_path]
        slug_cache[target_path] = collect_heading_slugs(text)
        return slug_cache[target_path]

    for ref in iter_inline_links(content, path):
        target = normalize_link_destination(ref.target)
        if target is None:
            continue

        file_part, frag = target, ""
        if "#" in target:
            file_part, frag = target.split("#", 1)
            frag = unquote(frag)

        if file_part == "":
            dest = path
        else:
            if file_part.startswith("/"):
                # Site-root paths are not first-party repo-relative links.
                continue
            dest = (path.parent / file_part).resolve()
            try:
                dest.relative_to(root.resolve())
            except ValueError:
                errors.append(
                    LinkError(ref.source, ref.line, target, "path escapes repository root")
                )
                continue
            if is_excluded(posix_rel(dest, root)):
                continue
            if not dest.exists():
                errors.append(LinkError(ref.source, ref.line, target, "missing file"))
                continue
            if dest.is_dir():
                continue
            if dest.suffix.lower() != ".md":
                # Non-markdown first-party files: existence only.
                continue

        if not frag or GITHUB_LINE_FRAGMENT_RE.fullmatch(frag):
            continue
        if frag not in slugs_for(dest):
            errors.append(
                LinkError(
                    ref.source,
                    ref.line,
                    target,
                    f"missing heading slug `#{frag}`",
                )
            )
    return errors


def check_repository(root: Path = REPO_ROOT) -> list[LinkError]:
    slug_cache: dict[Path, set[str]] = {}
    errors: list[LinkError] = []
    for path in tracked_markdown_files(root):
        errors.extend(check_file(path, root=root, slug_cache=slug_cache))
    return errors


def run_self_test(root: Path = REPO_ROOT) -> None:
    fixture = root / FIXTURE_RELATIVE
    if not fixture.is_file():
        raise AssertionError(f"missing regression fixture: {FIXTURE_RELATIVE.as_posix()}")

    content = fixture.read_text(encoding="utf-8")
    slugs = collect_heading_slugs(content)
    expected = {
        "markdown-link-check-github-slug-fixture",
        "punctuation-hello-world",
        "code-with-foo_bar-underscores",
        "name_with_underscores",
        "duplicate-heading",
        "duplicate-heading-1",
        "a-parens--ampersand",
    }
    missing = expected - slugs
    unexpected = slugs - expected
    if missing or unexpected:
        raise AssertionError(
            "fixture slug mismatch: "
            f"missing={sorted(missing)} unexpected={sorted(unexpected)} got={sorted(slugs)}"
        )

    # Punctuation, inline code, underscores, and duplicate suffix behavior.
    assert github_slug(heading_plain_text("Punctuation: Hello, World!")) == "punctuation-hello-world"
    assert (
        github_slug(heading_plain_text("Code with `foo_bar` underscores"))
        == "code-with-foo_bar-underscores"
    )
    assert github_slug(heading_plain_text("name_with_underscores")) == "name_with_underscores"
    assert github_slug(heading_plain_text("A (parens) & ampersand!")) == "a-parens--ampersand"

    errors = check_file(fixture, root=root, slug_cache={})
    if errors:
        details = "\n".join(err.format() for err in errors)
        raise AssertionError(f"fixture links must resolve:\n{details}")

    # Negative checks: broken fragment/file must report source file + line + target.
    synthetic = (
        "# Synthetic\n\n"
        "[missing file](./no-such-doc.md)\n"
        "[missing slug](#no-such-heading)\n"
    )
    with tempfile.TemporaryDirectory(prefix="md-link-check-") as tmp:
        synth_path = Path(tmp) / "synthetic.md"
        synth_path.write_text(synthetic, encoding="utf-8")
        synth_errors = check_file(synth_path, root=Path(tmp), slug_cache={})
    assert any(err.line == 3 and "missing file" in err.reason for err in synth_errors), (
        synth_errors
    )
    assert any(
        err.line == 4 and "missing heading slug" in err.reason for err in synth_errors
    ), synth_errors
    assert all(":" in err.format() and err.target in err.format() for err in synth_errors)
    print("markdown link-check self-test passed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the GitHub-slug regression fixture and exit",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (default: inferred from script location)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.self_test:
        try:
            run_self_test(root)
        except AssertionError as exc:
            print(f"::error::{exc}", file=sys.stderr)
            return 1
        return 0

    errors = check_repository(root)
    if not errors:
        tracked = len(tracked_markdown_files(root))
        print(
            f"Checked {tracked} tracked Markdown files; "
            "all first-party relative links and GitHub heading slugs resolved."
        )
        return 0

    for err in errors:
        print(f"::error file={err.source.as_posix()},line={err.line}::{err.format()}")
    print(
        f"markdown link-check failed with {len(errors)} unresolved target(s)",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
