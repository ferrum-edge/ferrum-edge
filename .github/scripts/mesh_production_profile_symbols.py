#!/usr/bin/env python3
"""Bounded remote-only Envoy symbol acquisition; never executes an image.

Run through mesh_production_profile_symbols.sh on hosted Linux x64. Success
qualifies matching function symbols, NOT sampled coverage or source attribution.
The caller must retain report.json and gate every subsequent decoded capture.
"""
import argparse
import gzip
import hashlib
import json
import mmap
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import signal
import struct
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

REPOSITORY = "envoyproxy/envoy"
PRODUCTION = "sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4"
DEBUG_TAG = "v1.39.1-debug"
GIB = 1024 ** 3
LIMITS = dict(transfer_bytes=4 * GIB, layer_bytes=3 * GIB,
              unpacked_bytes=12 * GIB, retained_bytes=6 * GIB,
              file_bytes=4 * GIB, metadata_bytes=8 * 1024 ** 2,
              manifest_bytes=1024 ** 2, wall_seconds=900,
              minimum_free_bytes=12 * GIB, archive_members=200000)
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))
TARGETS = {"usr/local/bin/envoy": "envoy", "usr/local/bin/envoy.dwp": "envoy.dwp"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            h.update(block)
    return h.hexdigest()


def digest_ok(value):
    return (isinstance(value, str) and value.startswith("sha256:")
            and len(value) == 71 and all(c in "0123456789abcdef" for c in value[7:]))


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == "https", "non-HTTPS registry redirect")
        follow = super().redirect_request(req, fp, code, msg, headers, newurl)
        if follow is not None:
            follow.remove_header("Authorization")
        return follow


class Registry:
    def __init__(self):
        self.started = time.monotonic()
        self.transfer = self.metadata = self.unpacked = self.members = 0
        self.opener = urllib.request.build_opener(SafeRedirect())
        self.token = None
        self.token_deadline = 0
        self.refresh_token()

    def refresh_token(self):
        url = "https://auth.docker.io/token?" + urllib.parse.urlencode({
            "service": "registry.docker.io", "scope": f"repository:{REPOSITORY}:pull"})
        response = json.loads(self.small(url))
        token = response["token"]
        require(isinstance(token, str) and 0 < len(token) <= 16384, "invalid registry token")
        self.token = token
        lifetime = response.get("expires_in", 300)
        require(type(lifetime) is int and lifetime >= 60, "invalid anonymous token lifetime")
        self.token_deadline = time.monotonic() + min(lifetime, 300) - 30

    def deadline(self):
        require(time.monotonic() - self.started < LIMITS["wall_seconds"], "preflight deadline")

    def open(self, url):
        self.deadline()
        headers = {"Accept": ACCEPT, "User-Agent": "ferrum-symbol-preflight/1"}
        if urllib.parse.urlsplit(url).netloc == "registry-1.docker.io":
            if time.monotonic() >= self.token_deadline:
                self.refresh_token()
            headers["Authorization"] = "Bearer " + self.token
        return self.opener.open(urllib.request.Request(url, headers=headers), timeout=30)

    def small(self, url):
        with self.open(url) as response:
            data = response.read(LIMITS["manifest_bytes"] + 1)
        self.deadline()
        self.metadata += len(data)
        require(len(data) <= LIMITS["manifest_bytes"] and
                self.metadata <= LIMITS["metadata_bytes"], "registry metadata bound")
        return data

    def manifest(self, reference):
        require(digest_ok(reference) or reference == DEBUG_TAG, "unapproved image reference")
        data = self.small(f"https://registry-1.docker.io/v2/{REPOSITORY}/manifests/{reference}")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if digest_ok(reference):
            require(digest == reference, "manifest digest mismatch")
        return json.loads(data), digest, data

    def resolve(self, reference, output):
        top, resolved, raw_manifest = self.manifest(reference)
        (output / "manifest-root.json").write_bytes(raw_manifest)
        manifest, digest = top, resolved
        if "manifests" in top:
            rows = [r for r in top["manifests"] if r.get("platform", {}).get("os") == "linux"
                    and r.get("platform", {}).get("architecture") == "amd64"
                    and r.get("platform", {}).get("variant", "") in ("", "v1")]
            require(len(rows) == 1 and digest_ok(rows[0].get("digest")), "ambiguous amd64 image")
            manifest, digest, raw_manifest = self.manifest(rows[0]["digest"])
        require(manifest.get("schemaVersion") == 2 and isinstance(manifest.get("layers"), list),
                "not an OCI/Docker image manifest")
        require(0 < len(manifest["layers"]) <= 64, "layer count bound")
        for row in manifest["layers"]:
            require(digest_ok(row.get("digest")) and type(row.get("size")) is int
                    and 0 < row["size"] <= LIMITS["layer_bytes"], "invalid/big layer descriptor")
            require(row.get("mediaType") in ("application/vnd.oci.image.layer.v1.tar+gzip",
                    "application/vnd.docker.image.rootfs.diff.tar.gzip"), "unsupported layer encoding")
        config = manifest.get("config", {})
        require(digest_ok(config.get("digest")), "missing image config digest")
        raw = self.small(f"https://registry-1.docker.io/v2/{REPOSITORY}/blobs/{config['digest']}")
        require("sha256:" + hashlib.sha256(raw).hexdigest() == config["digest"], "config digest mismatch")
        decoded = json.loads(raw)
        require(decoded.get("architecture") == "amd64" and decoded.get("os") == "linux", "wrong image architecture")
        (output / "image-config.json").write_bytes(raw)
        (output / "manifest-platform.json").write_bytes(raw_manifest)
        return dict(requested=reference, resolved_digest=resolved, platform_digest=digest,
                    pinned_reference=f"{REPOSITORY}@{digest}", manifest=manifest)

    def download(self, descriptor, path):
        expected = descriptor["size"]
        require(self.transfer + expected <= LIMITS["transfer_bytes"], "compressed transfer bound")
        self.deadline()
        h, size = hashlib.sha256(), 0
        url = f"https://registry-1.docker.io/v2/{REPOSITORY}/blobs/{descriptor['digest']}"
        with self.open(url) as response, open(path, "xb") as target:
            declared = response.headers.get("Content-Length")
            require(declared is not None and int(declared) == expected, "layer Content-Length mismatch")
            while True:
                self.deadline()
                block = response.read(min(1024 ** 2, expected - size + 1))
                if not block:
                    break
                size += len(block)
                self.transfer += len(block)
                require(size <= expected and self.transfer <= LIMITS["transfer_bytes"], "layer transfer overrun")
                h.update(block)
                target.write(block)
        require(size == expected and "sha256:" + h.hexdigest() == descriptor["digest"], "layer digest/length mismatch")


class UnpackedReader:
    def __init__(self, source, budget):
        self.source, self.budget = source, budget

    def read(self, size=-1):
        self.budget.deadline()
        require(0 <= size <= 1024 ** 2, "unbounded archive read")
        data = self.source.read(size)
        self.budget.unpacked += len(data)
        require(self.budget.unpacked <= LIMITS["unpacked_bytes"], "unpacked archive bound")
        return data


def extract_layer(archive_path, destination, scratch, budget):
    """Apply only selected regular files, handling whiteouts without extracting paths."""
    staged, removed = {}, set()
    with gzip.open(archive_path, "rb") as compressed:
        reader = UnpackedReader(compressed, budget)
        with tarfile.open(fileobj=reader, mode="r|") as archive:
            for member in archive:
                budget.deadline()
                budget.members += 1
                require(budget.members <= LIMITS["archive_members"], "archive member bound")
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and ".." not in path.parts, "unsafe archive path")
                name = str(path)
                if any(path in PurePosixPath(target).parents for target in TARGETS):
                    require(not member.issym() and not member.islnk(), "selected artifact parent is a link")
                for target in TARGETS:
                    target_path = PurePosixPath(target)
                    if path.name == ".wh..wh..opq" and path.parent in target_path.parents:
                        removed.add(target)
                    elif path.name.startswith(".wh."):
                        erased = path.parent / path.name[4:]
                        if erased == target_path or erased in target_path.parents:
                            removed.add(target)
                if name not in TARGETS:
                    # Still consume through the bounded reader; never extract arbitrary members.
                    continue
                require(member.isreg() and 0 < member.size <= LIMITS["file_bytes"], "selected artifact is not a bounded regular file")
                require(name not in staged, "duplicate selected file in one layer")
                retained = sum(p.stat().st_size for p in destination.parent.glob("*/envoy*"))
                staged_bytes = sum(p.stat().st_size for p in staged.values())
                require(retained + staged_bytes + member.size <= LIMITS["retained_bytes"], "retained artifact bound")
                target = scratch / TARGETS[name]
                source = archive.extractfile(member)
                require(source is not None, "missing selected member data")
                with source, open(target, "xb") as output:
                    remaining = member.size
                    while remaining:
                        budget.deadline()
                        data = source.read(min(1024 ** 2, remaining))
                        require(bool(data), "truncated selected file")
                        output.write(data)
                        remaining -= len(data)
                staged[name] = target
        # Consume the rest to enforce expansion bounds and gzip CRC, including padding.
        while reader.read(1024 ** 2):
            pass
    for target in removed:
        (destination / TARGETS[target]).unlink(missing_ok=True)
    for target, source in staged.items():
        os.replace(source, destination / TARGETS[target])


class Elf:
    def __init__(self, path):
        self.file = open(path, "rb")
        self.map = None
        try:
            self.map = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
            self.parse()
        except Exception:
            self.close()
            raise

    def parse(self):
        require(self.map[:7] == b"\x7fELF\x02\x01\x01", "expected ELF64 little endian")
        h = self.unpack("<HHIQQQIHHHHHH", 16)
        self.kind, self.machine, self.entry = h[0], h[1], h[3]
        require(self.machine == 62 and h[2] == 1 and h[7] == 64, "unsupported ELF architecture/header")
        require(h[10] == 64 and 0 < h[11] <= 65535 and h[12] < h[11], "unsupported section table")
        require(h[8] in (0, 56) and h[9] <= 4096, "unsupported program table")
        self.raw_sections = [self.unpack("<IIQQQQIIQQ", h[5] + i * h[10]) for i in range(h[11])]
        names = self.raw_sections[h[12]]
        require(names[5] <= 16 * 1024 ** 2, "section name table bound")
        strings = self.read(names[4], names[5])
        self.sections = {}
        for section in self.raw_sections[1:]:
            require(section[0] < len(strings), "invalid section name")
            end = strings.find(b"\0", section[0])
            require(end != -1, "unterminated section name")
            name = strings[section[0]:end].decode("ascii")
            require(name not in self.sections, "duplicate ELF section")
            if section[1] != 8:
                self.bounds(section[4], section[5])
            self.sections[name] = section
        self.programs = [self.unpack("<IIQQQQQQ", h[4] + i * h[8]) for i in range(h[9])]

    def close(self):
        if self.map is not None:
            self.map.close()
        self.file.close()

    def bounds(self, offset, size):
        require(0 <= offset <= len(self.map) and 0 <= size <= len(self.map) - offset, "ELF range outside file")

    def read(self, offset, size):
        self.bounds(offset, size)
        return self.map[offset:offset + size]

    def unpack(self, fmt, offset):
        self.bounds(offset, struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.map, offset)

    def hash(self, offset, size):
        self.bounds(offset, size)
        h = hashlib.sha256()
        for start in range(offset, offset + size, 1024 ** 2):
            h.update(self.map[start:min(start + 1024 ** 2, offset + size)])
        return h.hexdigest()

    def build_id(self):
        section = self.sections.get(".note.gnu.build-id")
        if section is None:
            return None
        require(section[5] <= 4096, "build ID note bound")
        namesz, descsz, kind = self.unpack("<III", section[4])
        require(namesz == 4 and kind == 3 and 4 <= descsz <= 64
                and 12 + 4 + descsz <= section[5], "malformed GNU build ID")
        require(self.read(section[4] + 12, 4) == b"GNU\0", "wrong build ID note name")
        return self.read(section[4] + 16, descsz).hex()

    def allocated(self):
        return {name: dict(type=s[1], flags=s[2], address=s[3], size=s[5], alignment=s[8],
                          sha256=None if s[1] == 8 else self.hash(s[4], s[5]))
                for name, s in self.sections.items() if s[2] & 2}

    def executable_segments(self):
        return [dict(flags=p[1], offset=p[2], address=p[3], filesz=p[5], memsz=p[6], align=p[7],
                     sha256=self.hash(p[2], p[5])) for p in self.programs if p[0] == 1 and p[1] & 1]

    def functions(self):
        section = self.sections.get(".symtab")
        require(section is not None and section[9] == 24 and section[5] % 24 == 0
                and section[5] <= 512 * 1024 ** 2, "missing/invalid bounded .symtab")
        count = 0
        for offset in range(section[4], section[4] + section[5], 24):
            _, info, _, index, _, size = self.unpack("<IBBHQQ", offset)
            if info & 15 == 2 and index != 0 and size > 0:
                count += 1
        return count


def verify_symbols(production, debug, dwp, minimum_functions=10000):
    opened = []
    try:
        for path in (production, debug, dwp):
            require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= LIMITS["file_bytes"], "missing/oversize symbol artifact")
            opened.append(Elf(path))
        prod, sym, package = opened
        require(prod.kind == sym.kind and prod.kind in (2, 3) and prod.entry == sym.entry, "ELF entry/type mismatch")
        build_id = prod.build_id()
        require(build_id is not None and build_id == sym.build_id(), "production/debug build ID mismatch")
        require(prod.allocated() == sym.allocated(), "production/debug allocated sections differ")
        segments = prod.executable_segments()
        require(bool(segments) and segments == sym.executable_segments(), "production/debug executable segments differ")
        functions = sym.functions()
        require(functions >= minimum_functions, "insufficient defined function symbols")
        require(package.kind == 1, "DWP must be a relocatable ELF")
        for section in (".debug_cu_index", ".debug_info.dwo", ".debug_abbrev.dwo"):
            require(section in package.sections and package.sections[section][5] > 0, "incomplete DWP package")
        index = package.sections[".debug_cu_index"]
        version, columns, units, slots = package.unpack("<IIII", index[4])
        require(version in (2, 5) and 0 < columns <= 64 and 0 < units <= slots <= 2 ** 24,
                "invalid DWP compilation-unit index")
        require(16 + slots * 12 + columns * 4 + units * columns * 8 <= index[5], "truncated DWP index")
        return dict(build_id=build_id, defined_function_symbols=functions,
                    allocated_section_count=len(prod.allocated()), executable_segments=segments,
                    function_symbol_setup_verified=True, sampled_coverage_verified=False,
                    sampled_coverage="not measured; every capture must pass its own coverage gate",
                    source_line_setup_verified=False,
                    dwp=dict(build_id=package.build_id(), compilation_units=units,
                             association="same pinned debug image; DWO association not yet verified"),
                    artifacts={p.name + (".production" if p == production else ".debug"): {
                        "path": str(p), "bytes": p.stat().st_size, "sha256": sha256_file(p)}
                        for p in (production, debug, dwp)})
    finally:
        for elf in opened:
            elf.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new artifact directory; must not exist")
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and platform.system() == "Linux"
            and platform.machine() == "x86_64", "remote GitHub Actions Linux x64 only")
    args.output.mkdir(parents=False, exist_ok=False)
    report = dict(schema=1, status="failed", limits=LIMITS, production_reference=PRODUCTION,
                  debug_tag=DEBUG_TAG, ferrum_symbols="not provided by Main Latest Image run 39611137595")
    registry = None

    def interrupted(_signum, _frame):
        raise TimeoutError("symbol preflight interrupted by outer deadline or cancellation")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        require(shutil.disk_usage(args.output).free >= LIMITS["minimum_free_bytes"], "insufficient preflight disk budget")
        registry = Registry()
        images = {}
        for role, reference in (("production", PRODUCTION), ("debug", DEBUG_TAG)):
            directory = args.output / role
            directory.mkdir()
            images[role] = registry.resolve(reference, directory)
        # Resolve/pin BOTH manifests before downloading any layers. Never pull a mutable tag again.
        report["images"] = images
        (args.output / "resolved-images.json").write_text(json.dumps(images, indent=2, sort_keys=True) + "\n")
        descriptors = [layer for image in images.values() for layer in image["manifest"]["layers"]]
        require(sum(row["size"] for row in descriptors) <= LIMITS["transfer_bytes"], "planned compressed transfer bound")
        for role, image in images.items():
            for layer in image["manifest"]["layers"]:
                registry.deadline()
                require(shutil.disk_usage(args.output).free >= layer["size"] + LIMITS["file_bytes"] + GIB,
                        "insufficient extraction disk reserve")
                with tempfile.TemporaryDirectory(prefix="layer-", dir=args.output) as temp:
                    scratch = Path(temp)
                    blob = scratch / "layer.gz"
                    registry.download(layer, blob)
                    extract_layer(blob, args.output / role, scratch, registry)
        report["verification"] = verify_symbols(args.output / "production/envoy", args.output / "debug/envoy",
                                                 args.output / "debug/envoy.dwp")
        report["status"] = "function-symbol-preflight-passed"
    except Exception as error:
        # Do not include request headers, token responses, or exception URLs.
        report["failure"] = {"type": type(error).__name__, "reason": str(error)[:500]}
    finally:
        if registry is not None:
            report["resources"] = dict(compressed_layer_bytes=registry.transfer, metadata_bytes=registry.metadata,
                                       unpacked_bytes=registry.unpacked, archive_members=registry.members,
                                       elapsed_seconds=time.monotonic() - registry.started)
        (args.output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.output / "report.json"),
                      "failure": report.get("failure")}))
    return 0 if report["status"] == "function-symbol-preflight-passed" else 1


if __name__ == "__main__":
    sys.exit(main())
