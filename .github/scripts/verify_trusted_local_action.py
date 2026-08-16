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
* contents match byte for byte and the executable bit matches,
* the action directory holds no extra file and no symlink of any kind,
* every ancestor directory of the action is an ordinary directory.

Anything the manifest cannot answer — an empty archive, an unreadable file, an
unexpected member type — fails closed. The verifier deliberately spawns no
process and never reads a secret; the workflow performs the one `git archive`
invocation while the runner `PATH` is still the pristine one.

Byte identity is the default. Issue #3904 admits exactly one additional move
for `.github/actions/setup-kubernetes-tools`: the frozen current trusted
generation (sole governed file `action.yml`, non-executable, SHA-256
`6ecb4bde09a0d3d456d6019c03ef1678c3903cbc0275bba31fde3e56f6e6ef08`) may
become the frozen PR #3910 generation (same path set and mode, SHA-256
`41dd4b9ae1b0ad74e021e2974afbcdac1a1bc0d856a166a57e94046e803d6cd9`). Both
generations are bound here, including every governed file and executable bit.
Another base generation, a one-byte or mode change, an extra or missing file,
or any other local-action path is still rejected. The candidate cannot supply
a digest or extend the map. Once the destination is the trusted base,
unchanged destination bytes pass by ordinary identity and further unadmitted
drift still fails. Retire the predecessor constants after that landing so the
old tree cannot remain an admitted source.

Usage:
  python3 -I .github/scripts/verify_trusted_local_action.py --self-test
  python3 -I .github/scripts/verify_trusted_local_action.py \
      --action-path .github/actions/setup-kubernetes-tools \
      --trusted-archive "$RUNNER_TEMP/trusted-k8s-tools.tar"
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
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
# Bound a hostile archive so a crafted manifest cannot exhaust the runner.
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 8 * 1024 * 1024

# The only local-action path that may use the generation transition below.
# Every other `uses: ./.github/actions/...` tree stays on ordinary byte identity.
SETUP_KUBERNETES_TOOLS_ACTION_PATH = ".github/actions/setup-kubernetes-tools"
# Published SHA-256 of the sole governed file in each bound generation. The
# complete identity also includes the path set and executable bit; see
# `generation_fingerprint`. Bytes live at the bottom of this file so the
# extracted checker does not read a candidate digest or companion fixture.
SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML_SHA256 = (
    "6ecb4bde09a0d3d456d6019c03ef1678c3903cbc0275bba31fde3e56f6e6ef08"
)
SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML_SHA256 = (
    "41dd4b9ae1b0ad74e021e2974afbcdac1a1bc0d856a166a57e94046e803d6cd9"
)


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
        if actual != expected:
            findings.append(f"{relative}: differs from the trusted revision")
    return findings


def generation_fingerprint(
    files: dict[str, tuple[bool, bytes]],
) -> tuple[tuple[str, bool, str], ...]:
    """Bind a complete local-action generation: path set, mode, and content.

    The identity is the sorted tuple of `(relative path, executable bit,
    SHA-256 of the file bytes)`. An extra file, a missing file, a flipped
    executable bit, or a one-byte edit all produce a different identity.
    """

    return tuple(
        (path, executable, hashlib.sha256(payload).hexdigest())
        for path, (executable, payload) in sorted(files.items())
    )


def setup_kubernetes_tools_current_generation() -> tuple[tuple[str, bool, str], ...]:
    return generation_fingerprint(
        {"action.yml": (False, SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML)}
    )


def setup_kubernetes_tools_destination_generation() -> (
    tuple[tuple[str, bool, str], ...]
):
    return generation_fingerprint(
        {"action.yml": (False, SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML)}
    )


def setup_kubernetes_tools_destination_path_modes() -> dict[str, bool]:
    return {
        path: executable
        for path, executable, _digest in setup_kubernetes_tools_destination_generation()
    }


def admitted_transition_payload_limit() -> int:
    """Tight exact-safe bound: the frozen destination `action.yml` size."""

    return min(
        MAX_MEMBER_BYTES, len(SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML)
    )


def read_admitted_transition_generation(
    root: Path,
    action_dir: PurePosixPath,
    manifest: dict[str, tuple[bool, bytes]],
) -> dict[str, tuple[bool, bytes]] | None:
    """Read the local tree only when the frozen transition is still possible.

    Proves the action path, trusted source fingerprint, and destination
    path set/modes before any candidate payload is read. Extra, missing, or
    remoded paths return `None` without reading unrelated files. The
    destination payload read is bounded and fails closed on oversize or a
    short/changed read.
    """

    if action_dir.as_posix() != SETUP_KUBERNETES_TOOLS_ACTION_PATH:
        return None
    if generation_fingerprint(manifest) != setup_kubernetes_tools_current_generation():
        return None
    try:
        discovered = local_action_files(root, action_dir)
    except (TrustedActionError, OSError):
        return None
    expected_modes = setup_kubernetes_tools_destination_path_modes()
    if set(discovered) != set(expected_modes):
        return None
    generation: dict[str, tuple[bool, bytes]] = {}
    limit = admitted_transition_payload_limit()
    for relative, path in discovered.items():
        try:
            payload = read_bounded_local_payload(
                path,
                limit=limit,
                expected_executable=expected_modes[relative],
            )
        except (TrustedActionError, OSError):
            return None
        generation[relative] = (expected_modes[relative], payload)
    return generation


def is_admitted_generation_transition(
    action_dir: PurePosixPath,
    trusted: dict[str, tuple[bool, bytes]],
    local: dict[str, tuple[bool, bytes]],
) -> bool:
    """Accept only the frozen setup-kubernetes-tools current→destination move.

    Source and destination are both bound in this extracted checker. The
    working tree cannot supply a digest, name another path, or widen the
    pair. A revert (destination trusted, current local) is not admitted.
    """

    if action_dir.as_posix() != SETUP_KUBERNETES_TOOLS_ACTION_PATH:
        return False
    return (
        generation_fingerprint(trusted) == setup_kubernetes_tools_current_generation()
        and generation_fingerprint(local)
        == setup_kubernetes_tools_destination_generation()
    )


def evaluate_local_action(
    root: Path,
    action_dir: PurePosixPath,
    manifest: dict[str, tuple[bool, bytes]],
) -> tuple[list[str], bool]:
    """Compare the working tree to the trusted manifest, then the frozen pair.

    Returns `(findings, admitted_transition)`. Ordinary byte identity yields
    empty findings and `False`. The one admitted generation move yields empty
    findings and `True`. Every other mismatch keeps its fail-closed findings.

    The transition fallback does not read candidate payloads until the action
    path, trusted source fingerprint, and local path set/modes still match
    the frozen destination shape. Extra or missing paths, mode mismatches,
    oversize payloads, and short or changed reads keep the original findings.
    """

    findings = verify_local_action(root, action_dir, manifest)
    if not findings:
        return findings, False
    local = read_admitted_transition_generation(root, action_dir, manifest)
    if local is None:
        return findings, False
    if is_admitted_generation_transition(action_dir, manifest, local):
        return [], True
    return findings, False


def _write(path: Path, contents: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    path.chmod(0o755 if executable else 0o644)


def _write_sparse(path: Path, size: int) -> None:
    """Create a holey file of `size` bytes without materializing the payload."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.truncate(size)


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


def _archive_generation(
    action_dir: str,
    files: dict[str, tuple[bool, bytes]],
) -> bytes:
    entries = [
        (name, payload, 0o775 if executable else 0o664)
        for name, (executable, payload) in files.items()
    ]
    return _archive_bytes(action_dir, entries)


def _write_generation(
    root: Path,
    action_dir: str,
    files: dict[str, tuple[bool, bytes]],
) -> None:
    for name, (executable, payload) in files.items():
        _write(root / action_dir / name, payload, executable=executable)


def _current_setup_k8s_files() -> dict[str, tuple[bool, bytes]]:
    return {"action.yml": (False, SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML)}


def _destination_setup_k8s_files() -> dict[str, tuple[bool, bytes]]:
    return {"action.yml": (False, SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML)}


def run_self_test() -> list[str]:
    """Synthetic manifests and worktrees: only an exact match is accepted.

    Also proves the frozen setup-kubernetes-tools current→destination pair:
    exact old→new admission, then rejection of a wrong predecessor, a wrong
    destination digest, extra or missing files, a mode change, an oversized
    destination payload, an oversized extra file, and the same bytes on an
    unrelated action path. Destination-as-base identity still passes; further
    unadmitted drift and a revert still fail.
    """

    failures: list[str] = []
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
        try:
            findings, transitioned = evaluate_local_action(
                clean, action_dir, manifest
            )
        except TrustedActionError as exc:
            failures.append(f"matching action tree evaluate raised: {exc}")
        else:
            if findings or transitioned:
                failures.append(
                    "matching action tree lost ordinary byte-identical behavior: "
                    f"findings={findings} transitioned={transitioned}"
                )

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

        failures.extend(_generation_transition_self_tests(Path(tmp), action_dir))

    return failures


def _generation_transition_self_tests(
    tmp: Path,
    default_action_dir: PurePosixPath,
) -> list[str]:
    """Exact old→new admission and every nearby miss for the frozen pair.

    Includes bounded-read rejection of an oversized destination payload and
    an oversized extra file that must not be read during the fallback.
    """

    failures: list[str] = []
    current_files = _current_setup_k8s_files()
    destination_files = _destination_setup_k8s_files()
    current_fp = setup_kubernetes_tools_current_generation()
    destination_fp = setup_kubernetes_tools_destination_generation()
    action_dir = normalize_action_path(SETUP_KUBERNETES_TOOLS_ACTION_PATH)
    if action_dir != default_action_dir:
        failures.append(
            "setup-kubernetes-tools path drifted from the self-test action dir"
        )

    if hashlib.sha256(SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML).hexdigest() != (
        SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML_SHA256
    ):
        failures.append("current setup-kubernetes-tools payload hash drifted")
    if hashlib.sha256(SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML).hexdigest() != (
        SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML_SHA256
    ):
        failures.append("destination setup-kubernetes-tools payload hash drifted")
    if current_fp != (
        ("action.yml", False, SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML_SHA256),
    ):
        failures.append(f"current generation fingerprint drifted: {current_fp}")
    if destination_fp != (
        ("action.yml", False, SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML_SHA256),
    ):
        failures.append(
            f"destination generation fingerprint drifted: {destination_fp}"
        )
    if current_fp == destination_fp:
        failures.append("current and destination generations are not distinct")

    current_manifest = _manifest_from_bytes(
        _archive_generation(SETUP_KUBERNETES_TOOLS_ACTION_PATH, current_files),
        action_dir,
    )
    destination_manifest = _manifest_from_bytes(
        _archive_generation(SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files),
        action_dir,
    )
    if generation_fingerprint(current_manifest) != current_fp:
        failures.append("archived current generation lost a bound field")
    if generation_fingerprint(destination_manifest) != destination_fp:
        failures.append("archived destination generation lost a bound field")

    admitted = tmp / "admitted-old-to-new"
    _write_generation(
        admitted, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    try:
        findings, transitioned = evaluate_local_action(
            admitted, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"exact current→destination transition raised: {exc}")
    else:
        if findings or not transitioned:
            failures.append(
                "exact current→destination transition was rejected: "
                f"findings={findings} transitioned={transitioned}"
            )

    current_match = tmp / "current-byte-identical"
    _write_generation(
        current_match, SETUP_KUBERNETES_TOOLS_ACTION_PATH, current_files
    )
    try:
        findings, transitioned = evaluate_local_action(
            current_match, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"current byte-identical tree raised: {exc}")
    else:
        if findings or transitioned:
            failures.append(
                "current byte-identical tree was not an ordinary match: "
                f"findings={findings} transitioned={transitioned}"
            )

    dest_match = tmp / "destination-as-trusted-base"
    _write_generation(
        dest_match, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    try:
        findings, transitioned = evaluate_local_action(
            dest_match, action_dir, destination_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"destination-as-base identical tree raised: {exc}")
    else:
        if findings or transitioned:
            failures.append(
                "destination-as-base identical tree was not an ordinary match: "
                f"findings={findings} transitioned={transitioned}"
            )

    dest_drift = tmp / "destination-unadmitted-drift"
    drifted_dest = destination_files["action.yml"][1] + b"# unadmitted drift\n"
    _write_generation(
        dest_drift,
        SETUP_KUBERNETES_TOOLS_ACTION_PATH,
        {"action.yml": (False, drifted_dest)},
    )
    try:
        findings, transitioned = evaluate_local_action(
            dest_drift, action_dir, destination_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"destination-base drift raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("unadmitted drift against destination base was accepted")

    revert = tmp / "destination-to-current-revert"
    _write_generation(revert, SETUP_KUBERNETES_TOOLS_ACTION_PATH, current_files)
    try:
        findings, transitioned = evaluate_local_action(
            revert, action_dir, destination_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"destination→current revert raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("destination→current revert was accepted")

    wrong_old = tmp / "wrong-old-generation"
    _write_generation(
        wrong_old, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    wrong_old_files = {
        "action.yml": (
            False,
            current_files["action.yml"][1] + b"# not the frozen predecessor\n",
        )
    }
    wrong_old_manifest = _manifest_from_bytes(
        _archive_generation(SETUP_KUBERNETES_TOOLS_ACTION_PATH, wrong_old_files),
        action_dir,
    )
    try:
        findings, transitioned = evaluate_local_action(
            wrong_old, action_dir, wrong_old_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"wrong old generation raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("wrong old generation was accepted as a transition")

    wrong_dest = tmp / "wrong-destination-digest"
    _write_generation(
        wrong_dest,
        SETUP_KUBERNETES_TOOLS_ACTION_PATH,
        {
            "action.yml": (
                False,
                destination_files["action.yml"][1] + b"# one-byte dest miss\n",
            )
        },
    )
    try:
        findings, transitioned = evaluate_local_action(
            wrong_dest, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"wrong destination digest raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("wrong destination digest was accepted")

    extra_dest = tmp / "destination-extra-file"
    _write_generation(
        extra_dest, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    _write(
        extra_dest / SETUP_KUBERNETES_TOOLS_ACTION_PATH / "bin" / "extra.sh",
        b"#!/bin/sh\necho extra\n",
        executable=True,
    )
    try:
        findings, transitioned = evaluate_local_action(
            extra_dest, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"destination extra file raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("destination extra file was accepted")

    oversized_extra = tmp / "destination-oversized-extra-file"
    _write_generation(
        oversized_extra, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    extra_overflow = (
        oversized_extra
        / SETUP_KUBERNETES_TOOLS_ACTION_PATH
        / "bin"
        / "overflow.bin"
    )
    _write_sparse(extra_overflow, MAX_MEMBER_BYTES + 1)
    if extra_overflow.stat().st_size != MAX_MEMBER_BYTES + 1:
        failures.append(
            "oversized extra-file fixture did not reach MAX_MEMBER_BYTES + 1"
        )
    try:
        findings, transitioned = evaluate_local_action(
            oversized_extra, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"oversized extra file raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("oversized extra file was accepted as a transition")
        elif not any(item.startswith("bin/overflow.bin:") for item in findings):
            failures.append(
                "oversized extra file lost the ordinary extra-path finding: "
                f"{findings}"
            )
    if (
        read_admitted_transition_generation(
            oversized_extra, action_dir, current_manifest
        )
        is not None
    ):
        failures.append(
            "oversized extra file still produced a transition generation"
        )

    oversized_primary = tmp / "destination-oversized-primary-file"
    _write_generation(
        oversized_primary,
        SETUP_KUBERNETES_TOOLS_ACTION_PATH,
        destination_files,
    )
    primary_overflow = (
        oversized_primary
        / SETUP_KUBERNETES_TOOLS_ACTION_PATH
        / "action.yml"
    )
    _write_sparse(primary_overflow, MAX_MEMBER_BYTES + 1)
    try:
        findings, transitioned = evaluate_local_action(
            oversized_primary, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"oversized primary file raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("oversized primary file was accepted as a transition")
        elif not any("exceeds" in item for item in findings):
            failures.append(
                "oversized primary file lost the bounded-read finding: "
                f"{findings}"
            )

    oversized_dest = tmp / "destination-oversized-payload"
    _write_generation(
        oversized_dest,
        SETUP_KUBERNETES_TOOLS_ACTION_PATH,
        {
            "action.yml": (
                False,
                destination_files["action.yml"][1] + b"\0",
            )
        },
    )
    try:
        findings, transitioned = evaluate_local_action(
            oversized_dest, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"oversized destination payload raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append(
                "oversized destination payload was accepted as a transition"
            )
        elif not any(
            "differs from the trusted revision" in item for item in findings
        ):
            failures.append(
                "oversized destination payload lost the ordinary byte-diff "
                f"finding: {findings}"
            )
    if (
        read_admitted_transition_generation(
            oversized_dest, action_dir, current_manifest
        )
        is not None
    ):
        failures.append(
            "oversized destination payload still produced a transition generation"
        )

    missing_dest = tmp / "destination-missing-file"
    missing_dest.joinpath(SETUP_KUBERNETES_TOOLS_ACTION_PATH).mkdir(parents=True)
    try:
        findings, transitioned = evaluate_local_action(
            missing_dest, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"destination missing file raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("destination missing action.yml was accepted")

    remoded_dest = tmp / "destination-mode-change"
    _write_generation(
        remoded_dest, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    (
        remoded_dest / SETUP_KUBERNETES_TOOLS_ACTION_PATH / "action.yml"
    ).chmod(0o755)
    try:
        findings, transitioned = evaluate_local_action(
            remoded_dest, action_dir, current_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"destination mode change raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("destination executable-bit change was accepted")

    extra_source_files = dict(current_files)
    extra_source_files["bin/helper.sh"] = (True, b"#!/bin/sh\necho helper\n")
    extra_source_manifest = _manifest_from_bytes(
        _archive_generation(SETUP_KUBERNETES_TOOLS_ACTION_PATH, extra_source_files),
        action_dir,
    )
    extra_source = tmp / "wrong-old-extra-file"
    _write_generation(
        extra_source, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    try:
        findings, transitioned = evaluate_local_action(
            extra_source, action_dir, extra_source_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"source extra file raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("wrong old generation with an extra file was accepted")

    remoded_source_files = {"action.yml": (True, current_files["action.yml"][1])}
    remoded_source_manifest = _manifest_from_bytes(
        _archive_generation(
            SETUP_KUBERNETES_TOOLS_ACTION_PATH, remoded_source_files
        ),
        action_dir,
    )
    remoded_source = tmp / "wrong-old-mode"
    _write_generation(
        remoded_source, SETUP_KUBERNETES_TOOLS_ACTION_PATH, destination_files
    )
    try:
        findings, transitioned = evaluate_local_action(
            remoded_source, action_dir, remoded_source_manifest
        )
    except TrustedActionError as exc:
        failures.append(f"source mode change raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append("wrong old generation with a mode change was accepted")

    other_dir_text = ".github/actions/other-action"
    other_dir = normalize_action_path(other_dir_text)
    other_current = _manifest_from_bytes(
        _archive_generation(other_dir_text, current_files), other_dir
    )
    other_transition = tmp / "unrelated-path-transition"
    _write_generation(other_transition, other_dir_text, destination_files)
    try:
        findings, transitioned = evaluate_local_action(
            other_transition, other_dir, other_current
        )
    except TrustedActionError as exc:
        failures.append(f"unrelated path transition raised: {exc}")
    else:
        if not findings or transitioned:
            failures.append(
                "current→destination bytes were accepted on an unrelated action path"
            )

    other_match = tmp / "unrelated-path-byte-identical"
    _write_generation(other_match, other_dir_text, current_files)
    try:
        findings, transitioned = evaluate_local_action(
            other_match, other_dir, other_current
        )
    except TrustedActionError as exc:
        failures.append(f"unrelated path byte-identical tree raised: {exc}")
    else:
        if findings or transitioned:
            failures.append(
                "unrelated path lost ordinary byte-identical behavior: "
                f"findings={findings} transitioned={transitioned}"
            )

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

    if admitted_transition_payload_limit() != len(
        SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML
    ):
        failures.append("admitted transition payload limit drifted from destination")

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
        findings, admitted_transition = evaluate_local_action(
            root, action_dir, manifest
        )
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
    if admitted_transition:
        local_count = len(setup_kubernetes_tools_destination_generation())
        print(
            f"{action_dir.as_posix()} matches the admitted "
            f"setup-kubernetes-tools generation transition "
            f"({len(manifest)} trusted files → {local_count} local files)"
        )
        return 0
    print(
        f"{action_dir.as_posix()} matches the trusted revision "
        f"({len(manifest)} governed files)"
    )
    return 0


# Frozen complete generations for the one admitted setup-kubernetes-tools
# transition (issue #3904). Each mapping is the entire governed tree:
# `action.yml` only, non-executable (git 100644). Source is origin/main at
# this predecessor PR; destination is PR #3910 head
# 937710ce513588b3d3e6d1814516bdd00648398e. The extracted checker carries
# these bytes so a candidate cannot supply a digest or companion fixture.
SETUP_KUBERNETES_TOOLS_CURRENT_ACTION_YML = (
    b'name: Setup Kubernetes tools\n'
    b'description: >-\n'
    b'  Install kind, kubectl, and Helm from official versioned release URLs after\n'
    b'  verifying each download against repository-pinned SHA-256 digests and the\n'
    b'  matching official published checksum files. Fail closed on download or\n'
    b'  verification errors. Never pipes remote content to a shell.\n'
    b'\n'
    b'inputs:\n'
    b'  kind-version:\n'
    b'    description: kind release tag (for example v0.27.0)\n'
    b'    required: false\n'
    b'    default: "v0.27.0"\n'
    b'  kubectl-version:\n'
    b'    description: kubectl release tag (for example v1.32.3)\n'
    b'    required: false\n'
    b'    default: "v1.32.3"\n'
    b'  helm-version:\n'
    b'    description: Helm release tag (for example v3.17.3)\n'
    b'    required: false\n'
    b'    default: "v3.17.3"\n'
    b'  kind-sha256:\n'
    b'    description: >-\n'
    b'      Expected SHA-256 of kind-linux-amd64 from the kind GitHub release\n'
    b'      checksum file for kind-version.\n'
    b'    required: false\n'
    b'    default: "a6875aaea358acf0ac07786b1a6755d08fd640f4c79b7a2e46681cc13f49a04b"\n'
    b'  kubectl-sha256:\n'
    b'    description: >-\n'
    b'      Expected SHA-256 of the linux/amd64 kubectl binary from\n'
    b'      dl.k8s.io for kubectl-version.\n'
    b'    required: false\n'
    b'    default: "ab209d0c5134b61486a0486585604a616a5bb2fc07df46d304b3c95817b2d79f"\n'
    b'  helm-sha256:\n'
    b'    description: >-\n'
    b'      Expected SHA-256 of helm-<version>-linux-amd64.tar.gz from get.helm.sh\n'
    b'      for helm-version.\n'
    b'    required: false\n'
    b'    default: "ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd"\n'
    b'  install-kind:\n'
    b'    description: Install kind when true\n'
    b'    required: false\n'
    b'    default: "true"\n'
    b'  install-kubectl:\n'
    b'    description: Install kubectl when true\n'
    b'    required: false\n'
    b'    default: "true"\n'
    b'  install-helm:\n'
    b'    description: Install Helm when true\n'
    b'    required: false\n'
    b'    default: "true"\n'
    b'\n'
    b'runs:\n'
    b'  using: composite\n'
    b'  steps:\n'
    b'    - name: Install kind, kubectl, and Helm with pinned checksums\n'
    b'      shell: bash\n'
    b'      env:\n'
    b'        KIND_VERSION: ${{ inputs.kind-version }}\n'
    b'        KUBECTL_VERSION: ${{ inputs.kubectl-version }}\n'
    b'        HELM_VERSION: ${{ inputs.helm-version }}\n'
    b'        KIND_SHA256: ${{ inputs.kind-sha256 }}\n'
    b'        KUBECTL_SHA256: ${{ inputs.kubectl-sha256 }}\n'
    b'        HELM_SHA256: ${{ inputs.helm-sha256 }}\n'
    b'        INSTALL_KIND: ${{ inputs.install-kind }}\n'
    b'        INSTALL_KUBECTL: ${{ inputs.install-kubectl }}\n'
    b'        INSTALL_HELM: ${{ inputs.install-helm }}\n'
    b'      run: |\n'
    b'        set -euo pipefail\n'
    b'\n'
    b'        # Linux/amd64 GitHub-hosted runners only. Refuse other platforms instead\n'
    b'        # of silently installing binaries for the wrong OS or architecture.\n'
    b'        os="$(uname -s)"\n'
    b'        arch="$(uname -m)"\n'
    b'        if [ "$os" != "Linux" ] || { [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; }; then\n'
    b'          echo "::error::setup-kubernetes-tools supports linux/amd64 only (got ${os}/${arch})"\n'
    b'          exit 1\n'
    b'        fi\n'
    b'\n'
    b'        require_sha256() {\n'
    b'          local value="$1"\n'
    b'          local label="$2"\n'
    b'          if ! [[ "$value" =~ ^[0-9a-f]{64}$ ]]; then\n'
    b'            echo "::error::${label} must be a 64-character lowercase hex SHA-256"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        download() {\n'
    b'          local url="$1"\n'
    b'          local dest="$2"\n'
    b'          if ! curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \\\n'
    b'            --connect-timeout 30 --max-time 300 \\\n'
    b'            -o "$dest" "$url"; then\n'
    b'            echo "::error::download failed: ${url}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'          if [ ! -s "$dest" ]; then\n'
    b'            echo "::error::download produced an empty file: ${url}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        file_sha256() {\n'
    b'          # Prefer sha256sum (Linux runners); fall back to shasum (macOS).\n'
    b'          if command -v sha256sum >/dev/null 2>&1; then\n'
    b'            sha256sum "$1" | awk \'{print $1}\'\n'
    b'          elif command -v shasum >/dev/null 2>&1; then\n'
    b'            shasum -a 256 "$1" | awk \'{print $1}\'\n'
    b'          else\n'
    b'            echo "::error::neither sha256sum nor shasum is available"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        verify_pinned_sha256() {\n'
    b'          local path="$1"\n'
    b'          local expected="$2"\n'
    b'          local label="$3"\n'
    b'          local actual\n'
    b'          actual="$(file_sha256 "$path")"\n'
    b'          if [ "$actual" != "$expected" ]; then\n'
    b'            echo "::error::${label} checksum mismatch: got ${actual}, want ${expected}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        # Cross-check the repository pin against the official published\n'
    b'        # checksum for this exact version. Reject if either the download or the\n'
    b'        # pin disagrees with official provenance.\n'
    b'        assert_official_checksum_matches_pin() {\n'
    b'          local official_url="$1"\n'
    b'          local pinned="$2"\n'
    b'          local label="$3"\n'
    b'          local checksum_path official\n'
    b'          checksum_path="$(mktemp)"\n'
    b'          download "$official_url" "$checksum_path"\n'
    b'          official="$(awk \'{print $1; exit}\' "$checksum_path" | tr -d \'[:space:]\' | tr \'A-F\' \'a-f\')"\n'
    b'          rm -f "$checksum_path"\n'
    b'          if ! [[ "$official" =~ ^[0-9a-f]{64}$ ]]; then\n'
    b'            echo "::error::${label}: official checksum file did not contain a SHA-256 digest (${official_url})"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'          if [ "$official" != "$pinned" ]; then\n'
    b'            echo "::error::${label}: repository pin ${pinned} does not match official checksum ${official} from ${official_url}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        install_dir="${RUNNER_TEMP}/ferrum-k8s-tools/bin"\n'
    b'        work_dir="${RUNNER_TEMP}/ferrum-k8s-tools/work"\n'
    b'        mkdir -p "$install_dir" "$work_dir"\n'
    b'        echo "$install_dir" >> "$GITHUB_PATH"\n'
    b'\n'
    b'        if [ "$INSTALL_KIND" = "true" ]; then\n'
    b'          require_sha256 "$KIND_SHA256" "kind-sha256"\n'
    b'          kind_bin="${work_dir}/kind-linux-amd64"\n'
    b'          # GitHub release assets are the authoritative kind provenance.\n'
    b'          download \\\n'
    b'            "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" \\\n'
    b'            "$kind_bin"\n'
    b'          assert_official_checksum_matches_pin \\\n'
    b'            "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64.sha256sum" \\\n'
    b'            "$KIND_SHA256" \\\n'
    b'            "kind ${KIND_VERSION}"\n'
    b'          verify_pinned_sha256 "$kind_bin" "$KIND_SHA256" "kind ${KIND_VERSION}"\n'
    b'          install -m 0755 "$kind_bin" "${install_dir}/kind"\n'
    b'          "${install_dir}/kind" version\n'
    b'        fi\n'
    b'\n'
    b'        if [ "$INSTALL_KUBECTL" = "true" ]; then\n'
    b'          require_sha256 "$KUBECTL_SHA256" "kubectl-sha256"\n'
    b'          kubectl_bin="${work_dir}/kubectl"\n'
    b'          download \\\n'
    b'            "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \\\n'
    b'            "$kubectl_bin"\n'
    b'          assert_official_checksum_matches_pin \\\n'
    b'            "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl.sha256" \\\n'
    b'            "$KUBECTL_SHA256" \\\n'
    b'            "kubectl ${KUBECTL_VERSION}"\n'
    b'          verify_pinned_sha256 "$kubectl_bin" "$KUBECTL_SHA256" "kubectl ${KUBECTL_VERSION}"\n'
    b'          install -m 0755 "$kubectl_bin" "${install_dir}/kubectl"\n'
    b'          "${install_dir}/kubectl" version --client=true\n'
    b'        fi\n'
    b'\n'
    b'        if [ "$INSTALL_HELM" = "true" ]; then\n'
    b'          require_sha256 "$HELM_SHA256" "helm-sha256"\n'
    b'          helm_archive="${work_dir}/helm-linux-amd64.tar.gz"\n'
    b'          # Official Helm distribution host; never raw.githubusercontent.com/helm/helm/main.\n'
    b'          download \\\n'
    b'            "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \\\n'
    b'            "$helm_archive"\n'
    b'          assert_official_checksum_matches_pin \\\n'
    b'            "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz.sha256sum" \\\n'
    b'            "$HELM_SHA256" \\\n'
    b'            "helm ${HELM_VERSION}"\n'
    b'          verify_pinned_sha256 "$helm_archive" "$HELM_SHA256" "helm ${HELM_VERSION}"\n'
    b'          tar -xzf "$helm_archive" -C "$work_dir"\n'
    b'          if [ ! -x "${work_dir}/linux-amd64/helm" ]; then\n'
    b'            echo "::error::helm archive did not contain linux-amd64/helm"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'          install -m 0755 "${work_dir}/linux-amd64/helm" "${install_dir}/helm"\n'
    b'          "${install_dir}/helm" version --short\n'
    b'        fi\n'
)

SETUP_KUBERNETES_TOOLS_DESTINATION_ACTION_YML = (
    b'name: Setup Kubernetes tools\n'
    b'description: >-\n'
    b'  Install kind, kubectl, and Helm from official versioned release URLs after\n'
    b'  verifying each download against repository-pinned SHA-256 digests and the\n'
    b'  matching official published checksum files. Restored cache entries are\n'
    b'  re-checked against the same pins before install. Fail closed on download or\n'
    b'  verification errors. Never pipes remote content to a shell.\n'
    b'\n'
    b'inputs:\n'
    b'  kind-version:\n'
    b'    description: kind release tag (for example v0.27.0)\n'
    b'    required: false\n'
    b'    default: "v0.27.0"\n'
    b'  kubectl-version:\n'
    b'    description: kubectl release tag (for example v1.32.3)\n'
    b'    required: false\n'
    b'    default: "v1.32.3"\n'
    b'  helm-version:\n'
    b'    description: Helm release tag (for example v3.17.3)\n'
    b'    required: false\n'
    b'    default: "v3.17.3"\n'
    b'  kind-sha256:\n'
    b'    description: >-\n'
    b'      Expected SHA-256 of kind-linux-amd64 from the kind GitHub release\n'
    b'      checksum file for kind-version.\n'
    b'    required: false\n'
    b'    default: "a6875aaea358acf0ac07786b1a6755d08fd640f4c79b7a2e46681cc13f49a04b"\n'
    b'  kubectl-sha256:\n'
    b'    description: >-\n'
    b'      Expected SHA-256 of the linux/amd64 kubectl binary from\n'
    b'      dl.k8s.io for kubectl-version.\n'
    b'    required: false\n'
    b'    default: "ab209d0c5134b61486a0486585604a616a5bb2fc07df46d304b3c95817b2d79f"\n'
    b'  helm-sha256:\n'
    b'    description: >-\n'
    b'      Expected SHA-256 of helm-<version>-linux-amd64.tar.gz from get.helm.sh\n'
    b'      for helm-version.\n'
    b'    required: false\n'
    b'    default: "ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd"\n'
    b'  install-kind:\n'
    b'    description: Install kind when true\n'
    b'    required: false\n'
    b'    default: "true"\n'
    b'  install-kubectl:\n'
    b'    description: Install kubectl when true\n'
    b'    required: false\n'
    b'    default: "true"\n'
    b'  install-helm:\n'
    b'    description: Install Helm when true\n'
    b'    required: false\n'
    b'    default: "true"\n'
    b'\n'
    b'runs:\n'
    b'  using: composite\n'
    b'  steps:\n'
    b'    # Exact-key restore only: versions, checksums, install subset, and runner\n'
    b'    # platform/arch all participate in the key. Prefix restore-keys are omitted\n'
    b'    # so a different pin cannot be installed from a partial match. Checksums\n'
    b'    # are verified again after restore; a mismatch discards the entry and\n'
    b'    # re-downloads rather than installing untrusted bytes.\n'
    b'    - name: Restore pinned Kubernetes tool downloads\n'
    b'      uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0\n'
    b'      with:\n'
    b'        path: ${{ runner.temp }}/ferrum-k8s-tools/cache\n'
    b'        key: ferrum-k8s-tools-v1-${{ runner.os }}-${{ runner.arch }}-kind-${{ inputs.kind-version }}-${{ inputs.kind-sha256 }}-kubectl-${{ inputs.kubectl-version }}-${{ inputs.kubectl-sha256 }}-helm-${{ inputs.helm-version }}-${{ inputs.helm-sha256 }}-ik-${{ inputs.install-kind }}-ic-${{ inputs.install-kubectl }}-ih-${{ inputs.install-helm }}\n'
    b'\n'
    b'    - name: Install kind, kubectl, and Helm with pinned checksums\n'
    b'      shell: bash\n'
    b'      env:\n'
    b'        KIND_VERSION: ${{ inputs.kind-version }}\n'
    b'        KUBECTL_VERSION: ${{ inputs.kubectl-version }}\n'
    b'        HELM_VERSION: ${{ inputs.helm-version }}\n'
    b'        KIND_SHA256: ${{ inputs.kind-sha256 }}\n'
    b'        KUBECTL_SHA256: ${{ inputs.kubectl-sha256 }}\n'
    b'        HELM_SHA256: ${{ inputs.helm-sha256 }}\n'
    b'        INSTALL_KIND: ${{ inputs.install-kind }}\n'
    b'        INSTALL_KUBECTL: ${{ inputs.install-kubectl }}\n'
    b'        INSTALL_HELM: ${{ inputs.install-helm }}\n'
    b'      run: |\n'
    b'        set -euo pipefail\n'
    b'\n'
    b'        # Linux/amd64 GitHub-hosted runners only. Refuse other platforms instead\n'
    b'        # of silently installing binaries for the wrong OS or architecture.\n'
    b'        os="$(uname -s)"\n'
    b'        arch="$(uname -m)"\n'
    b'        if [ "$os" != "Linux" ] || { [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; }; then\n'
    b'          echo "::error::setup-kubernetes-tools supports linux/amd64 only (got ${os}/${arch})"\n'
    b'          exit 1\n'
    b'        fi\n'
    b'\n'
    b'        require_sha256() {\n'
    b'          local value="$1"\n'
    b'          local label="$2"\n'
    b'          if ! [[ "$value" =~ ^[0-9a-f]{64}$ ]]; then\n'
    b'            echo "::error::${label} must be a 64-character lowercase hex SHA-256"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        download() {\n'
    b'          local url="$1"\n'
    b'          local dest="$2"\n'
    b'          if ! curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \\\n'
    b'            --connect-timeout 30 --max-time 300 \\\n'
    b'            -o "$dest" "$url"; then\n'
    b'            echo "::error::download failed: ${url}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'          if [ ! -s "$dest" ]; then\n'
    b'            echo "::error::download produced an empty file: ${url}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        file_sha256() {\n'
    b'          # Prefer sha256sum (Linux runners); fall back to shasum (macOS).\n'
    b'          if command -v sha256sum >/dev/null 2>&1; then\n'
    b'            sha256sum "$1" | awk \'{print $1}\'\n'
    b'          elif command -v shasum >/dev/null 2>&1; then\n'
    b'            shasum -a 256 "$1" | awk \'{print $1}\'\n'
    b'          else\n'
    b'            echo "::error::neither sha256sum nor shasum is available"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        verify_pinned_sha256() {\n'
    b'          local path="$1"\n'
    b'          local expected="$2"\n'
    b'          local label="$3"\n'
    b'          local actual\n'
    b'          actual="$(file_sha256 "$path")"\n'
    b'          if [ "$actual" != "$expected" ]; then\n'
    b'            echo "::error::${label} checksum mismatch: got ${actual}, want ${expected}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        # Compare the repository pin against the official published checksum\n'
    b'        # for this exact version. Reject if either the artifact or the pin\n'
    b'        # disagrees with official provenance. Official checksum files are\n'
    b'        # always fetched and are never taken from cache.\n'
    b'        assert_official_checksum_matches_pin() {\n'
    b'          local official_url="$1"\n'
    b'          local pinned="$2"\n'
    b'          local label="$3"\n'
    b'          local checksum_path official\n'
    b'          checksum_path="$(mktemp)"\n'
    b'          download "$official_url" "$checksum_path"\n'
    b'          official="$(awk \'{print $1; exit}\' "$checksum_path" | tr -d \'[:space:]\' | tr \'A-F\' \'a-f\')"\n'
    b'          rm -f "$checksum_path"\n'
    b'          if ! [[ "$official" =~ ^[0-9a-f]{64}$ ]]; then\n'
    b'            echo "::error::${label}: official checksum file did not contain a SHA-256 digest (${official_url})"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'          if [ "$official" != "$pinned" ]; then\n'
    b'            echo "::error::${label}: repository pin ${pinned} does not match official checksum ${official} from ${official_url}"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'        }\n'
    b'\n'
    b'        restore_or_download() {\n'
    b'          local dest="$1"\n'
    b'          local url="$2"\n'
    b'          local expected="$3"\n'
    b'          local label="$4"\n'
    b'          if [ -s "$dest" ]; then\n'
    b'            local actual\n'
    b'            actual="$(file_sha256 "$dest")"\n'
    b'            if [ "$actual" = "$expected" ]; then\n'
    b'              echo "${label}: restored pinned artifact from cache"\n'
    b'              return 0\n'
    b'            fi\n'
    b'            echo "::warning::${label}: restored cache checksum mismatch: got ${actual}, want ${expected}; discarding and re-downloading"\n'
    b'            rm -f "$dest"\n'
    b'          fi\n'
    b'          download "$url" "$dest"\n'
    b'        }\n'
    b'\n'
    b'        install_dir="${RUNNER_TEMP}/ferrum-k8s-tools/bin"\n'
    b'        work_dir="${RUNNER_TEMP}/ferrum-k8s-tools/work"\n'
    b'        cache_dir="${RUNNER_TEMP}/ferrum-k8s-tools/cache"\n'
    b'        mkdir -p "$install_dir" "$work_dir" "$cache_dir"\n'
    b'        echo "$install_dir" >> "$GITHUB_PATH"\n'
    b'\n'
    b'        if [ "$INSTALL_KIND" = "true" ]; then\n'
    b'          require_sha256 "$KIND_SHA256" "kind-sha256"\n'
    b'          kind_bin="${cache_dir}/kind-linux-amd64"\n'
    b'          # GitHub release assets are the authoritative kind provenance.\n'
    b'          restore_or_download \\\n'
    b'            "$kind_bin" \\\n'
    b'            "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" \\\n'
    b'            "$KIND_SHA256" \\\n'
    b'            "kind ${KIND_VERSION}"\n'
    b'          assert_official_checksum_matches_pin \\\n'
    b'            "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64.sha256sum" \\\n'
    b'            "$KIND_SHA256" \\\n'
    b'            "kind ${KIND_VERSION}"\n'
    b'          verify_pinned_sha256 "$kind_bin" "$KIND_SHA256" "kind ${KIND_VERSION}"\n'
    b'          install -m 0755 "$kind_bin" "${install_dir}/kind"\n'
    b'          "${install_dir}/kind" version\n'
    b'        fi\n'
    b'\n'
    b'        if [ "$INSTALL_KUBECTL" = "true" ]; then\n'
    b'          require_sha256 "$KUBECTL_SHA256" "kubectl-sha256"\n'
    b'          kubectl_bin="${cache_dir}/kubectl"\n'
    b'          restore_or_download \\\n'
    b'            "$kubectl_bin" \\\n'
    b'            "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \\\n'
    b'            "$KUBECTL_SHA256" \\\n'
    b'            "kubectl ${KUBECTL_VERSION}"\n'
    b'          assert_official_checksum_matches_pin \\\n'
    b'            "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl.sha256" \\\n'
    b'            "$KUBECTL_SHA256" \\\n'
    b'            "kubectl ${KUBECTL_VERSION}"\n'
    b'          verify_pinned_sha256 "$kubectl_bin" "$KUBECTL_SHA256" "kubectl ${KUBECTL_VERSION}"\n'
    b'          install -m 0755 "$kubectl_bin" "${install_dir}/kubectl"\n'
    b'          "${install_dir}/kubectl" version --client=true\n'
    b'        fi\n'
    b'\n'
    b'        if [ "$INSTALL_HELM" = "true" ]; then\n'
    b'          require_sha256 "$HELM_SHA256" "helm-sha256"\n'
    b'          helm_archive="${cache_dir}/helm-linux-amd64.tar.gz"\n'
    b'          # Official Helm distribution host; never raw.githubusercontent.com/helm/helm/main.\n'
    b'          restore_or_download \\\n'
    b'            "$helm_archive" \\\n'
    b'            "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \\\n'
    b'            "$HELM_SHA256" \\\n'
    b'            "helm ${HELM_VERSION}"\n'
    b'          assert_official_checksum_matches_pin \\\n'
    b'            "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz.sha256sum" \\\n'
    b'            "$HELM_SHA256" \\\n'
    b'            "helm ${HELM_VERSION}"\n'
    b'          verify_pinned_sha256 "$helm_archive" "$HELM_SHA256" "helm ${HELM_VERSION}"\n'
    b'          tar -xzf "$helm_archive" -C "$work_dir"\n'
    b'          if [ ! -x "${work_dir}/linux-amd64/helm" ]; then\n'
    b'            echo "::error::helm archive did not contain linux-amd64/helm"\n'
    b'            exit 1\n'
    b'          fi\n'
    b'          install -m 0755 "${work_dir}/linux-amd64/helm" "${install_dir}/helm"\n'
    b'          "${install_dir}/helm" version --short\n'
    b'        fi\n'
)


if __name__ == "__main__":
    raise SystemExit(main())
