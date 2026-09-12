#!/usr/bin/env python3
"""Bounded, synthetic native-cache transport proof; never execute a process."""
import argparse
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
from pathlib import Path

MAX_ARCHIVE = 1024 * 1024
MAX_FILES = 16
MAX_PAYLOAD = 256 * 1024
MANIFEST = "manifest.json"


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate manifest key")
        result[name] = value
    return result


def fixture():
    # Generated public bytes only: no workspace, Cargo home or environment data.
    return {"compiler/00/empty": b"",
            "compiler/ab/binary": bytes(range(256)) * 256,
            "compiler/ff/text": b"Ferrum native cache transport proof\n" * 32}


def archive_bytes(files):
    metadata = {"version": 1, "family": "synthetic-compiler-store", "files": {
        name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in files.items()}}
    entries = {MANIFEST: json.dumps(metadata, sort_keys=True).encode(), **files}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(entries.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


def validate(data):
    if not data or len(data) > MAX_ARCHIVE:
        raise ValueError("archive size is outside the proof bound")
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = member.name
            if (len(files) >= MAX_FILES or not member.isreg() or member.pax_headers
                    or member.sparse is not None or name in files
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", name)
                    or any(part in ("", ".", "..") for part in name.split("/"))):
                raise ValueError("unsupported, duplicate or unsafe archive member")
            total += member.size
            if member.size < 0 or total > MAX_PAYLOAD:
                raise ValueError("payload exceeds the proof bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("missing regular-file data")
            content = stream.read(MAX_PAYLOAD + 1)
            if len(content) != member.size:
                raise ValueError("truncated member")
            files[name] = content
    if MANIFEST not in files:
        raise ValueError("missing manifest")
    metadata = json.loads(files.pop(MANIFEST), object_pairs_hook=unique_object)
    if (not isinstance(metadata, dict)
            or set(metadata) != {"version", "family", "files"}
            or type(metadata["version"]) is not int or metadata["version"] != 1
            or metadata["family"] != "synthetic-compiler-store"
            or not isinstance(metadata["files"], dict)
            or set(metadata["files"]) != set(files)):
        raise ValueError("incompatible manifest or undeclared files")
    for name, content in files.items():
        if any(str(parent) in files for parent in Path(name).parents):
            raise ValueError("a file cannot also be a parent directory")
        entry = metadata["files"][name]
        if (not name.startswith("compiler/") or not isinstance(entry, dict)
                or set(entry) != {"bytes", "sha256"}
                or type(entry["bytes"]) is not int or entry["bytes"] != len(content)
                or entry["sha256"] != hashlib.sha256(content).hexdigest()):
            raise ValueError("invalid compiler-store entry or checksum")
    return files


def restore(data, destination):
    # Validate every byte and path before creating the destination. No tar
    # extraction API, preserved ownership, links or executable modes are used.
    files = validate(data)
    destination.mkdir(mode=0o700)
    for name, content in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        path.chmod(0o600)
    return files


def self_test():
    original = fixture()
    good = archive_bytes(original)
    assert validate(good) == original
    bad = [b"", b"x" * (MAX_ARCHIVE + 1), good[:600],
           archive_bytes({"../escape": b"x"}), archive_bytes({"/absolute": b"x"}),
           archive_bytes({"compiler/../escape": b"x"}),
           archive_bytes({"compiler//empty": b"x"}),
           archive_bytes({"credentials": b"x"}),
           archive_bytes({"compiler/a": b"x", "compiler/a/b": b"y"}),
           archive_bytes({"compiler/large": b"x" * (MAX_PAYLOAD + 1)}),
           archive_bytes({f"compiler/{n}": b"x" for n in range(MAX_FILES)})]
    # Replace one payload byte while preserving tar headers and manifest.
    corrupted = bytearray(good)
    with tarfile.open(fileobj=io.BytesIO(good), mode="r:") as archive:
        corrupted[archive.getmember("compiler/ab/binary").offset_data] ^= 1
    bad.append(bytes(corrupted))
    for manifest in (b'null', b'{"version":1,"version":1}', b'{'):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo(MANIFEST)
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))
        bad.append(stream.getvalue())
    for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo("compiler/link")
            member.type, member.linkname = kind, "../../escape"
            archive.addfile(member)
        bad.append(stream.getvalue())
    for names in (("compiler/a", "compiler/a"), ("compiler/a",)):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in names:
                archive.addfile(tarfile.TarInfo(name))
        bad.append(stream.getvalue())
    with tempfile.TemporaryDirectory(prefix="native-envelope-contracts-") as temporary:
        root = Path(temporary)
        for index, data in enumerate(bad):
            destination = root / str(index)
            try:
                restore(data, destination)
            except (ValueError, tarfile.TarError):
                assert not destination.exists(), "invalid data must not create a destination"
            else:
                raise AssertionError(f"invalid archive {index} was accepted")
        destination = root / "valid"
        assert restore(good, destination) == original
        assert {str(p.relative_to(destination)): p.read_bytes()
                for p in destination.rglob("*") if p.is_file()} == original
        try:
            restore(good, destination)
        except FileExistsError:
            pass
        else:
            raise AssertionError("an existing destination must not be overwritten")
    print(f"Native envelope contracts passed: round trip, {len(bad)} invalid archives, no overwrite")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("self-test", "prepare", "verify"))
    args = parser.parse_args()
    if args.mode == "self-test":
        self_test()
        return
    root = Path(os.environ["RUNNER_TEMP"]) / "ferrum-native-envelope"
    if args.mode == "prepare":
        context = root / "context"
        context.mkdir(parents=True)
        (context / "envelope.tar").write_bytes(archive_bytes(fixture()))
        (root / "delivery").mkdir()
    else:
        path = root / "delivery/envelope.tar"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
            raise ValueError("missing, linked or oversized envelope")
        data = path.read_bytes()
        if validate(data) != fixture():
            raise ValueError("retrieved bytes do not match the independent public fixture")
        files = restore(data, root / "restored")
        proof = {"archive_bytes": len(data), "archive_sha256": hashlib.sha256(data).hexdigest(),
                 "files": len(files), "payload_bytes": sum(map(len, files.values())),
                 "byte_identity": True, "image_executed": False}
        (root / "proof.json").write_text(json.dumps(proof, indent=2) + "\n")
        print(json.dumps(proof))


if __name__ == "__main__":
    main()
