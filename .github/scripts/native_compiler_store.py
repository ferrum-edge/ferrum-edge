#!/usr/bin/env python3
"""Stream a bounded compiler store as data; never execute cache contents."""
import argparse
import hashlib
import json
import os
import re
import stat
import struct
import tempfile
from pathlib import Path

MAGIC = b"FerrumCompilerStore\x00v1\n"
MAX_MANIFEST = 8 * 1024 * 1024
MAX_PAYLOAD = 3 * 1024 * 1024 * 1024
MAX_FILES = 32768
CHUNK = 1024 * 1024
BUILD_SPEC = "fuzz-properties-nightly-2025-07-01-locked-v1"
IDENTITY_KEYS = {"snapshot_sha", "run_id", "run_attempt", "platform", "build_spec"}


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate manifest key")
        result[name] = value
    return result


def identity():
    value = {
        "snapshot_sha": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "platform": os.environ["RUNNER_OS"] + "-" + os.environ["RUNNER_ARCH"],
        "build_spec": BUILD_SPEC,
    }
    validate_identity(value)
    return value


def validate_identity(value):
    if (not isinstance(value, dict) or set(value) != IDENTITY_KEYS
            or not all(isinstance(v, str) for v in value.values())
            or not re.fullmatch(r"[0-9a-f]{40}", value["snapshot_sha"])
            or not re.fullmatch(r"[1-9][0-9]*", value["run_id"])
            or not re.fullmatch(r"[1-9][0-9]*", value["run_attempt"])
            or value["platform"] != "Linux-X64" or value["build_spec"] != BUILD_SPEC):
        raise ValueError("incompatible snapshot identity")


def safe_name(name):
    return (isinstance(name, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", name) is not None
            and len(name.split("/")) <= 8
            and all(part not in ("", ".", "..") for part in name.split("/")))


def regular_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(descriptor)
        raise ValueError("cache input must be a regular file with exactly one link")
    return os.fdopen(descriptor, "rb"), info


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def copy_exact(source, size, destination=None, aggregate=None):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(CHUNK, remaining))
        if not chunk:
            raise ValueError("truncated compiler-store entry")
        digest.update(chunk)
        if aggregate is not None:
            aggregate.update(chunk)
        if destination is not None:
            destination.write(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("compiler-store root must be a real directory")
    files, total = [], 0
    # The producer stops all compiler-store writers before this bounded walk.
    # Refuse every special file/link rather than following it outside the store.
    directories = [root]
    visited = 0
    while directories:
        directory = directories.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > MAX_FILES * 4:
                    raise ValueError("too many filesystem entries")
                path = Path(entry.path)
                name = path.relative_to(root).as_posix()
                if not safe_name(name) or entry.is_symlink():
                    raise ValueError("unsafe compiler-store path")
                if entry.is_dir(follow_symlinks=False):
                    directories.append(path)
                    continue
                stream, info = regular_file(path)
                with stream:
                    total += info.st_size
                    if total > MAX_PAYLOAD or len(files) >= MAX_FILES:
                        raise ValueError("compiler store exceeds the proof bound")
                    digest = copy_exact(stream, info.st_size)
                    if stream.read(1) or fingerprint(os.fstat(stream.fileno())) != fingerprint(info):
                        raise ValueError("compiler store changed during inventory")
                files.append((name, info, digest))
    if not files:
        raise ValueError("compiler store is empty")
    return sorted(files, key=lambda entry: entry[0])


def header(metadata):
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_MANIFEST:
        raise ValueError("manifest exceeds the proof bound")
    return MAGIC + struct.pack(">Q", len(encoded)) + encoded


def export_store(root, archive, expected):
    validate_identity(expected)
    entries = inventory(root)
    metadata = {"version": 1, "family": "fuzz-smoke-compiler-store", "identity": expected,
                "files": [{"name": name, "bytes": info.st_size, "sha256": digest}
                          for name, info, digest in entries]}
    aggregate = hashlib.sha256()
    with archive.open("xb") as output:
        prefix = header(metadata)
        output.write(prefix)
        aggregate.update(prefix)
        for name, before, expected_digest in entries:
            stream, current = regular_file(root / name)
            with stream:
                if fingerprint(current) != fingerprint(before):
                    raise ValueError("compiler store changed before capture")
                actual = copy_exact(stream, current.st_size, output, aggregate)
                if (actual != expected_digest or stream.read(1)
                        or fingerprint(os.fstat(stream.fileno())) != fingerprint(before)):
                    raise ValueError("compiler store changed during capture")
    return {"archive_sha256": aggregate.hexdigest(), "archive_bytes": archive.stat().st_size,
            "payload_bytes": sum(info.st_size for _, info, _ in entries), "files": len(entries)}


def read_manifest(stream, expected, aggregate):
    prefix = stream.read(len(MAGIC) + 8)
    if len(prefix) != len(MAGIC) + 8 or not prefix.startswith(MAGIC):
        raise ValueError("incompatible compiler-store frame")
    size = struct.unpack(">Q", prefix[-8:])[0]
    if size == 0 or size > MAX_MANIFEST:
        raise ValueError("manifest size exceeds the proof bound")
    encoded = stream.read(size)
    if len(encoded) != size:
        raise ValueError("truncated manifest")
    aggregate.update(prefix)
    aggregate.update(encoded)
    metadata = json.loads(encoded, object_pairs_hook=unique_object)
    if (not isinstance(metadata, dict) or set(metadata) != {"version", "family", "identity", "files"}
            or type(metadata["version"]) is not int or metadata["version"] != 1
            or metadata["family"] != "fuzz-smoke-compiler-store"):
        raise ValueError("incompatible compiler-store manifest")
    validate_identity(metadata["identity"])
    if metadata["identity"] != expected:
        raise ValueError("snapshot belongs to a different run, source or platform")
    files = metadata["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("file count exceeds the proof bound")
    names, total = set(), 0
    previous = ""
    for entry in files:
        if (not isinstance(entry, dict) or set(entry) != {"name", "bytes", "sha256"}
                or not safe_name(entry["name"]) or entry["name"] <= previous
                or type(entry["bytes"]) is not int or entry["bytes"] < 0
                or not isinstance(entry["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ValueError("invalid or unordered compiler-store entry")
        name = entry["name"]
        if any(parent.as_posix() in names for parent in Path(name).parents):
            raise ValueError("a file cannot also be a directory")
        total += entry["bytes"]
        if total > MAX_PAYLOAD:
            raise ValueError("payload exceeds the proof bound")
        names.add(name)
        previous = name
    return files, total


def restore_store(archive, destination, expected, expected_digest):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ValueError("invalid expected archive digest")
    validate_identity(expected)
    stream, initial = regular_file(archive)
    with stream:
        if initial.st_size > len(MAGIC) + 8 + MAX_MANIFEST + MAX_PAYLOAD:
            raise ValueError("archive exceeds the proof bound")
        aggregate = hashlib.sha256()
        files, total = read_manifest(stream, expected, aggregate)
        payload_offset = stream.tell()
        # Validate every path, payload byte and the producer's archive digest
        # before creating a destination. No extraction API or executable mode.
        for entry in files:
            if copy_exact(stream, entry["bytes"], aggregate=aggregate) != entry["sha256"]:
                raise ValueError("compiler-store entry checksum mismatch")
        if stream.read(1) or aggregate.hexdigest() != expected_digest:
            raise ValueError("trailing bytes or archive checksum mismatch")
        if fingerprint(os.fstat(stream.fileno())) != fingerprint(initial):
            raise ValueError("archive changed during validation")
        destination.mkdir(mode=0o700)
        stream.seek(payload_offset)
        for entry in files:
            path = destination / entry["name"]
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open("xb") as output:
                digest = copy_exact(stream, entry["bytes"], output)
            path.chmod(0o600)
            if digest != entry["sha256"]:
                raise ValueError("archive changed during restoration")
        if stream.read(1) or fingerprint(os.fstat(stream.fileno())) != fingerprint(initial):
            raise ValueError("archive changed during restoration")
    restored = inventory(destination)
    expected_files = [(entry["name"], entry["bytes"], entry["sha256"]) for entry in files]
    if [(name, info.st_size, digest) for name, info, digest in restored] != expected_files:
        raise ValueError("restored compiler bytes differ from the validated manifest")
    return {"archive_sha256": expected_digest, "archive_bytes": initial.st_size,
            "files": len(files), "payload_bytes": total, "byte_identity": True,
            "image_executed": False, "compiler_executed": False}


def self_test():
    expected = {"snapshot_sha": "a" * 40, "run_id": "1", "run_attempt": "1",
                "platform": "Linux-X64", "build_spec": BUILD_SPEC}
    with tempfile.TemporaryDirectory(prefix="compiler-store-contracts-") as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        (source / "a").mkdir()
        (source / "a/empty").write_bytes(b"")
        (source / "a/binary").write_bytes(bytes(range(256)) * 4097)
        archive = root / "good"
        proof = export_store(source, archive, expected)
        result = restore_store(archive, root / "restored", expected, proof["archive_sha256"])
        assert result["files"] == 2 and result["payload_bytes"] == 256 * 4097
        try:
            restore_store(archive, root / "restored", expected, proof["archive_sha256"])
        except FileExistsError:
            pass
        else:
            raise AssertionError("existing destination overwritten")
        data = archive.read_bytes()  # Only the small test fixture, never production data.
        size = struct.unpack(">Q", data[len(MAGIC):len(MAGIC) + 8])[0]
        metadata = json.loads(data[len(MAGIC) + 8:len(MAGIC) + 8 + size])
        payload = data[len(MAGIC) + 8 + size:]
        bad = [b"", data[:5], data[:-1], data + b"x",
               MAGIC + struct.pack(">Q", MAX_MANIFEST + 1)]
        for name in ("../escape", "/absolute", "a//b", "a/./b", "a/../b", "a\\b"):
            altered = json.loads(json.dumps(metadata))
            altered["files"][0]["name"] = name
            bad.append(header(altered) + payload)
        for altered_files in (
                [], metadata["files"] * 2,
                [{"name": "a", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                 {"name": "a/b", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}],
                [{"name": "a", "bytes": MAX_PAYLOAD + 1, "sha256": "a" * 64}],
                [{"name": "a", "bytes": True, "sha256": "a" * 64}]):
            altered = json.loads(json.dumps(metadata))
            altered["files"] = altered_files
            bad.append(header(altered) + payload)
        for field, value in (("version", True), ("family", "other"),
                             ("identity", {**expected, "run_id": "2"})):
            bad.append(header({**metadata, field: value}) + payload)
        bad.append(header(metadata) + bytes([payload[0] ^ 1]) + payload[1:])
        duplicate = b'{"version":1,"version":1}'
        bad.append(MAGIC + struct.pack(">Q", len(duplicate)) + duplicate)
        for number, value in enumerate(bad):
            candidate = root / f"bad-{number}"
            candidate.write_bytes(value)
            destination = root / f"rejected-{number}"
            try:
                restore_store(candidate, destination, expected, hashlib.sha256(value).hexdigest())
            except ValueError:
                assert not destination.exists()
            else:
                raise AssertionError(f"invalid frame {number} accepted")
        (source / "linked").symlink_to(archive)
        try:
            export_store(source, root / "linked-frame", expected)
        except ValueError:
            pass
        else:
            raise AssertionError("source symlink accepted")
    print(f"Compiler-store contracts passed: streaming round trip, {len(bad)} invalid frames, no overwrite, no links")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("self-test", "export", "restore"))
    args = parser.parse_args()
    if args.mode == "self-test":
        self_test()
        return
    root = Path(os.environ["RUNNER_TEMP"]) / "ferrum-native-compiler"
    if args.mode == "export":
        context = root / "context"
        context.mkdir(parents=True)
        source = Path(os.environ["GITHUB_WORKSPACE"]) / ".cache/sccache"
        proof = export_store(source, context / "cache.bin", identity())
    else:
        proof = restore_store(root / "delivery/cache.bin", root / "restored",
                              identity(), os.environ["COMPILER_ARCHIVE_SHA256"])
    (root / "proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof))


if __name__ == "__main__":
    main()
