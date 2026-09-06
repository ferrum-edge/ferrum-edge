#!/usr/bin/env python3
"""Fail-closed GNU ABI gate for published ferrum-edge and ferrum-cni binaries.

The scanner reads DT_NEEDED, DT_RPATH/DT_RUNPATH, GNU version-need records,
and e_machine from an ELF; it rejects GLIBC symbol versions above the
declared floor, unexpected shared libraries, a runtime library search path,
and an e_machine that does not match the advertised architecture. It is the
hosted artifact gate for issue #4301: a moving ubuntu-latest glibc floor
must not ship. Parsing stays in-process so trusted automation policy can
inspect this file; computed process argv fails closed.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".github" / "linux-gnu-abi.toml"
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SMOKE_PY = REPO_ROOT / ".github" / "scripts" / "smoke_linux_gnu_baseline.py"
SMOKE_SH = REPO_ROOT / ".github" / "scripts" / "smoke_linux_gnu_baseline.sh"
PT_LOAD = 1
PT_DYNAMIC = 2
DT_NEEDED = 1
DT_STRTAB = 5
DT_RPATH = 15
DT_RUNPATH = 29
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
EM_X86_64 = 62
EM_AARCH64 = 183
SYSROOT_BUILD_SH = REPO_ROOT / ".github" / "scripts" / "build_linux_gnu_sysroot.sh"
PROCESS_API_TOKENS = (
    "import sub" + "process",
    "from sub" + "process",
    "sub" + "process.run",
    "sub" + "process.Popen",
    "os." + "system(",
    "os." + "popen(",
    "asyncio.create_sub" + "process",
)
README = REPO_ROOT / "README.md"
CLI_MD = REPO_ROOT / "docs" / "cli.md"
CI_CD_MD = REPO_ROOT / "docs" / "ci_cd.md"

DEDICATED_SYSROOT_TARGET_DIR = "/src/target/linux-gnu-sysroot"
GLIBC_VERSION_RE = re.compile(r"\bGLIBC_(\d+(?:\.\d+)*)\b")
NEEDED_RE = re.compile(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]")
LINUX_GNU_ASSETS = (
    "ferrum-edge-linux-x86_64",
    "ferrum-cni-linux-x86_64",
    "ferrum-edge-linux-aarch64",
    "ferrum-cni-linux-aarch64",
)


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def check_contract_shape(contract: dict[str, Any]) -> list[str]:
    """Reject a contract whose top-level keys are missing or mis-scoped.

    TOML binds a bare key to the table header above it, so an `allowed_needed`
    array written below `[smoke.ubuntu2204]` silently becomes that table's
    member instead of a top-level key. Every consumer then raises `KeyError`
    on a well-formed file rather than reporting a diagnosable contract error,
    so the shape is proven here before any scan or fixture reads it.
    """

    errors: list[str] = []
    for key in ("glibc_max_version", "allowed_needed"):
        if key not in contract:
            errors.append(
                f"{CONTRACT_PATH.name} must define top-level {key!r}; a bare "
                "key written below a [table] header belongs to that table"
            )
    allowed = contract.get("allowed_needed")
    if allowed is not None:
        if not isinstance(allowed, list) or not all(
            isinstance(item, str) for item in allowed
        ):
            errors.append(f"{CONTRACT_PATH.name} allowed_needed must be a list of SONAMEs")
        elif "libc.so.6" not in allowed:
            errors.append(f"{CONTRACT_PATH.name} allowed_needed must permit libc.so.6")
    return errors


def parse_version(text: str) -> tuple[int, ...]:
    parts = text.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid version {text!r}")
    return tuple(int(part) for part in parts)


def version_exceeds(observed: tuple[int, ...], ceiling: tuple[int, ...]) -> bool:
    return observed > ceiling


def glibc_versions_from_readelf(text: str) -> list[str]:
    return sorted(set(GLIBC_VERSION_RE.findall(text)))


def needed_libraries_from_readelf(text: str) -> list[str]:
    return sorted(set(NEEDED_RE.findall(text)))


def _elf_unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("is a truncated ELF")
    return struct.unpack_from(fmt, data, offset)


def _elf_read_cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ValueError("string table offset is outside the ELF")
    end = data.find(b"\x00", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return data[offset:end].decode("ascii", "replace")


def _elf_va_to_offset(loads: list[tuple[int, int, int]], virtual_addr: int) -> int:
    for file_offset, virtual_base, file_size in loads:
        if virtual_base <= virtual_addr < virtual_base + file_size:
            return file_offset + (virtual_addr - virtual_base)
    raise ValueError(f"virtual address 0x{virtual_addr:x} is not in a PT_LOAD segment")


def _collect_verneed_versions(
    data: bytes,
    verneed_offset: int,
    verneed_count: int,
    strtab: int,
    endian: str,
) -> set[str]:
    versions: set[str] = set()
    cursor = verneed_offset
    for _ in range(max(verneed_count, 0)):
        if cursor + 16 > len(data):
            raise ValueError("truncated GNU verneed table")
        _vn_version, vn_cnt, _vn_file, vn_aux, vn_next = struct.unpack_from(
            f"{endian}HHIII", data, cursor
        )
        aux = cursor + vn_aux
        for _unused in range(vn_cnt):
            if aux + 16 > len(data):
                raise ValueError("truncated GNU vernaux table")
            _vna_hash, _vna_flags, _vna_other, vna_name, vna_next = struct.unpack_from(
                f"{endian}IHHII", data, aux
            )
            name = _elf_read_cstring(data, strtab + vna_name)
            match = GLIBC_VERSION_RE.search(name)
            if match is not None:
                versions.add(match.group(1))
            if vna_next == 0:
                break
            aux += vna_next
        if vn_next == 0:
            break
        cursor += vn_next
    return versions


def parse_elf_abi(
    data: bytes,
) -> tuple[list[str], list[str], list[tuple[str, str]], int]:
    """Return GLIBC versions, DT_NEEDED SONAMEs, DT_RPATH/DT_RUNPATH, e_machine.

    The scanner stays in-process so trusted automation policy can statically
    inspect this file. Computed process argv fails closed.
    """

    if data[:4] != b"\x7fELF":
        raise ValueError("is not an ELF file")
    if len(data) < 52:
        raise ValueError("is a truncated ELF header")

    elf_class = data[4]
    encoding = data[5]
    if elf_class not in {1, 2}:
        raise ValueError("has an unsupported ELF class")
    if encoding not in {1, 2}:
        raise ValueError("has an unsupported ELF encoding")

    elf64 = elf_class == 2
    endian = "<" if encoding == 1 else ">"
    e_machine = _elf_unpack(f"{endian}H", data, 18)[0]
    u32 = f"{endian}I"
    u64 = f"{endian}Q"

    if elf64:
        phoff = _elf_unpack(u64, data, 32)[0]
        phentsize, phnum = _elf_unpack(f"{endian}HH", data, 54)
    else:
        phoff = _elf_unpack(u32, data, 28)[0]
        phentsize, phnum = _elf_unpack(f"{endian}HH", data, 42)

    loads: list[tuple[int, int, int]] = []
    dynamic_offset = -1
    dynamic_size = 0
    for index in range(phnum):
        start = phoff + index * phentsize
        p_type = _elf_unpack(u32, data, start)[0]
        if elf64:
            p_offset, p_vaddr, _p_paddr, p_filesz = _elf_unpack(
                f"{endian}QQQQ", data, start + 8
            )
        else:
            p_offset, p_vaddr, _p_paddr, p_filesz = _elf_unpack(
                f"{endian}IIII", data, start + 4
            )
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic_offset = p_offset
            dynamic_size = p_filesz

    if dynamic_offset < 0:
        raise ValueError("has no PT_DYNAMIC segment")

    dyn_entry = 16 if elf64 else 8
    needed_offsets: list[int] = []
    rpath_offsets: list[tuple[str, int]] = []
    strtab_va = -1
    verneed_va = -1
    verneed_count = 0
    cursor = dynamic_offset
    dyn_end = dynamic_offset + dynamic_size
    tag_fmt = f"{endian}q" if elf64 else f"{endian}i"
    val_fmt = f"{endian}Q" if elf64 else f"{endian}I"
    tag_size = 8 if elf64 else 4
    while cursor + dyn_entry <= dyn_end:
        tag = _elf_unpack(tag_fmt, data, cursor)[0]
        value = _elf_unpack(val_fmt, data, cursor + tag_size)[0]
        if tag == 0:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(value)
        elif tag == DT_STRTAB:
            strtab_va = value
        elif tag == DT_RPATH:
            rpath_offsets.append(("DT_RPATH", value))
        elif tag == DT_RUNPATH:
            rpath_offsets.append(("DT_RUNPATH", value))
        elif tag == DT_VERNEED:
            verneed_va = value
        elif tag == DT_VERNEEDNUM:
            verneed_count = value
        cursor += dyn_entry

    if strtab_va < 0:
        raise ValueError("is missing DT_STRTAB")
    strtab = _elf_va_to_offset(loads, strtab_va)
    needed = sorted(
        {_elf_read_cstring(data, strtab + offset) for offset in needed_offsets}
    )
    search_paths = [
        (tag, _elf_read_cstring(data, strtab + offset))
        for tag, offset in rpath_offsets
    ]

    versions: set[str] = set()
    if verneed_va >= 0 and verneed_count:
        verneed_offset = _elf_va_to_offset(loads, verneed_va)
        versions = _collect_verneed_versions(
            data, verneed_offset, verneed_count, strtab, endian
        )

    return sorted(versions), needed, search_paths, e_machine


def advertised_e_machine(binary: Path) -> tuple[int | None, str | None]:
    """Return the e_machine implied by a published asset name or sysroot path."""

    name = binary.name
    rendered = str(binary)
    wants_x86 = name.endswith("-x86_64") or "x86_64-unknown-linux-gnu" in rendered
    wants_arm = name.endswith("-aarch64") or "aarch64-unknown-linux-gnu" in rendered
    if wants_x86 and wants_arm:
        return None, (
            f"{binary} advertises both x86_64 and aarch64; "
            "refusing to choose an e_machine"
        )
    if wants_x86:
        return EM_X86_64, None
    if wants_arm:
        return EM_AARCH64, None
    return None, None


def scan_binary(binary: Path, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not binary.is_file() or binary.is_symlink():
        return [f"{binary} is not a regular file"]

    payload = binary.read_bytes()
    if payload[:4] != b"\x7fELF":
        return [f"{binary} is not an ELF file"]

    try:
        versions, needed, search_paths, e_machine = parse_elf_abi(payload)
    except ValueError as error:
        return [f"{binary} {error}"]
    ceiling = parse_version(str(contract["glibc_max_version"]))
    allowed = set(contract["allowed_needed"])

    expected_machine, advertised_error = advertised_e_machine(binary)
    if advertised_error is not None:
        errors.append(advertised_error)
    elif expected_machine is not None and e_machine != expected_machine:
        observed = {
            EM_X86_64: "EM_X86_64",
            EM_AARCH64: "EM_AARCH64",
        }.get(e_machine, f"e_machine={e_machine}")
        required = {
            EM_X86_64: "EM_X86_64 (62)",
            EM_AARCH64: "EM_AARCH64 (183)",
        }[expected_machine]
        errors.append(
            f"{binary} is {observed} ({e_machine}); advertised architecture "
            f"requires {required}"
        )

    for tag, value in search_paths:
        errors.append(
            f"{binary} embeds {tag}={value!r}; published GNU assets must not "
            "set a runtime library search path"
        )

    if not versions:
        errors.append(f"{binary} has no GLIBC version-need records")
    else:
        observed = [parse_version(item) for item in versions]
        maximum = max(observed)
        if version_exceeds(maximum, ceiling):
            pretty = ".".join(str(part) for part in maximum)
            errors.append(
                f"{binary} requires GLIBC_{pretty}, above the declared floor "
                f"GLIBC_{contract['glibc_max_version']}"
            )

    if "libc.so.6" not in needed:
        errors.append(f"{binary} is missing libc.so.6 (GNU artifacts must be dynamically linked)")

    unexpected = [name for name in needed if name not in allowed]
    if unexpected:
        errors.append(
            f"{binary} dynamically links unexpected libraries: {', '.join(unexpected)}"
        )
    return errors


def scan_assets(paths: list[Path], contract: dict[str, Any]) -> list[str]:
    errors = check_contract_shape(contract)
    if errors:
        return errors
    if not paths:
        return ["no GNU binaries were supplied to the ABI gate"]
    for path in paths:
        errors.extend(scan_binary(path, contract))
    return errors


def _producer_job_errors(
    workflow: str,
    label: str,
    job: str,
    upload_name: str,
) -> list[str]:
    """Lint producer-job text for the expected sysroot / scan / upload shape.

    This is a textual check of workflow YAML this pull request can still
    edit. It is not the tamper control. It is defeated by templating (the
    existing `Copy binary` step already writes
    `target/${{ matrix.target }}/release/...`) and by any rewrite that keeps
    the required substrings while changing behavior. The security boundary
    is the trusted-base byte-freeze of `build-binaries` /
    `build-release-binaries` plus `linux_gnu_producer_contract_errors` on
    main, which holds the destination digest to one sysroot build, one
    staged-asset scan before upload, and no rebuilt
    `target/x86_64-unknown-linux-gnu/...` scanner operand.
    """

    errors: list[str] = []
    body = _job_body(workflow, job)
    if not body:
        return [f"{label} is missing the x86_64 GNU producer job {job}"]

    if "bash .github/scripts/build_linux_gnu_sysroot.sh" not in body:
        errors.append(
            f"{label} {job} must build the published x86_64 GNU binaries in "
            "the pinned sysroot"
        )
    if "matrix.target == 'x86_64-unknown-linux-gnu'" not in body:
        errors.append(
            f"{label} {job} must select the pinned sysroot build with "
            "matrix.target == 'x86_64-unknown-linux-gnu'"
        )
    if "matrix.target != 'x86_64-unknown-linux-gnu'" not in body:
        errors.append(
            f"{label} {job} must exclude the x86_64 GNU target from the "
            "native runner compile"
        )
    for token in (
        "python3 -I .github/scripts/verify_linux_gnu_abi.py --self-test",
        "python3 -I .github/scripts/verify_linux_gnu_abi.py --check-contract",
        "python3 -I .github/scripts/smoke_linux_gnu_baseline.py --self-test",
        "sha256sum -c ferrum-edge-linux-x86_64.sha256",
        "sha256sum -c ferrum-cni-linux-x86_64.sha256",
        "release-assets/ferrum-edge-linux-x86_64",
        "release-assets/ferrum-cni-linux-x86_64",
        "bash .github/scripts/smoke_linux_gnu_baseline.sh",
        "--edge release-assets/ferrum-edge-linux-x86_64",
        "--cni release-assets/ferrum-cni-linux-x86_64",
    ):
        if token not in body:
            errors.append(f"{label} {job} is missing required {token}")

    # Literal-path lint only. Templated operands such as
    # `target/${{ matrix.target }}/release/ferrum-edge` do not match, so this
    # cannot be the tamper control — see the docstring.
    if re.search(r"target/x86_64-unknown-linux-gnu/[^\s\\]*ferrum-(?:edge|cni)", body):
        errors.append(
            f"{label} {job} must gate the staged published assets, not a path "
            "in a build tree"
        )

    # String-offset ordering of the first occurrences. It is a shape lint,
    # not a proof that the scanned bytes are the uploaded bytes.
    scan_at = body.find("release-assets/ferrum-edge-linux-x86_64")
    upload_at = body.find(f"name: {upload_name}")
    if scan_at < 0 or upload_at < 0:
        errors.append(
            f"{label} {job} must scan the staged assets and upload {upload_name}"
        )
    elif scan_at > upload_at:
        errors.append(
            f"{label} {job} must gate the staged published assets before "
            f"uploading {upload_name}"
        )
    return errors


def _aarch64_verifier_errors(
    workflow: str,
    label: str,
    job: str,
    producer: str,
    artifact: str,
) -> list[str]:
    """Prove the ARM64 gate reads the artifact the frozen Cross job published.

    The ARM64 producer is frozen by trusted Cross policy, so its bytes cannot
    be gated from inside it. They are downloaded, checksum-verified, and
    scanned as published instead — never rebuilt.
    """

    errors: list[str] = []
    body = _job_body(workflow, job)
    if not body:
        return [f"{label} is missing the ARM64 GNU ABI job {job}"]
    if _job_needs(workflow, job) != {producer}:
        errors.append(f"{label} {job} must need exactly {producer}")
    if "runs-on: ubuntu-24.04-arm" not in body:
        errors.append(f"{label} {job} must run on an ARM64 runner")
    for token in (
        f"name: {artifact}",
        "sha256sum -c ferrum-edge-linux-aarch64.sha256",
        "sha256sum -c ferrum-cni-linux-aarch64.sha256",
        "gnu-artifacts/ferrum-edge-linux-aarch64",
        "gnu-artifacts/ferrum-cni-linux-aarch64",
        "python3 -I .github/scripts/verify_linux_gnu_abi.py --self-test",
        "python3 -I .github/scripts/verify_linux_gnu_abi.py --check-contract",
        "python3 -I .github/scripts/smoke_linux_gnu_baseline.py --self-test",
        "bash .github/scripts/smoke_linux_gnu_baseline.sh",
    ):
        if token not in body:
            errors.append(f"{label} {job} is missing required {token}")
    if "build_linux_gnu_sysroot.sh" in body:
        errors.append(
            f"{label} {job} must scan the published ARM64 artifact, not a "
            "rebuilt binary"
        )
    return errors


def check_release_wiring(contract: dict[str, Any], release_yml: str, ci_yml: str) -> list[str]:
    errors: list[str] = []
    sysroot_image = contract["sysroot"]["image"]
    smoke_floor = contract["smoke"]["floor"]["image"]
    smoke_ubuntu = contract["smoke"]["ubuntu2204"]["image"]
    protoc_sha = contract["sysroot"]["protoc_sha256"]

    # The pinned inputs live in .github/linux-gnu-abi.toml, which both hosted
    # helpers read, so the workflows do not restate them. The contract itself
    # is what must stay digest-pinned.
    for token, label in (
        (sysroot_image, "pinned GNU sysroot image"),
        (smoke_floor, "oldest-baseline smoke image"),
        (smoke_ubuntu, "Ubuntu 22.04 smoke image"),
    ):
        if "@sha256:" not in token:
            errors.append(f"{label} must be digest-pinned ({token})")
    if len(protoc_sha) != 64 or any(c not in "0123456789abcdef" for c in protoc_sha):
        errors.append("pinned protoc SHA-256 must be a 64-character hex digest")

    errors.extend(
        _producer_job_errors(
            release_yml,
            "release.yml",
            "build-release-binaries",
            "release-binaries-${{ matrix.target }}",
        )
    )
    errors.extend(
        _aarch64_verifier_errors(
            release_yml,
            "release.yml",
            "verify-linux-gnu-abi-aarch64",
            "build-release-arm64-cross",
            "release-binaries-aarch64-unknown-linux-gnu",
        )
    )
    if "  linux-gnu-abi-release-gate:\n" not in release_yml:
        errors.append("release.yml is missing the linux-gnu-abi-release-gate job")
    if _job_needs(release_yml, "linux-gnu-abi-release-gate") != {
        "create-release",
        "verify-linux-gnu-abi-aarch64",
    }:
        errors.append(
            "release.yml linux-gnu-abi-release-gate must join create-release "
            "and verify-linux-gnu-abi-aarch64"
        )
    if "    needs: [create-release, attest-release-images]\n" not in release_yml:
        errors.append("release.yml changed the frozen attestation-gate needs")

    # Publication still consumes the historical GNU asset names.
    for asset in LINUX_GNU_ASSETS:
        if asset not in release_yml:
            errors.append(f"release.yml must keep publishing {asset}")

    # Frozen create-release needs must not grow an ABI edge; the ARM64 join
    # gate is the admitted place to fail-close after those frozen jobs.
    if (
        "needs: [build-release-binaries, build-release-arm64-cross, "
        "docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest]"
        not in release_yml
    ):
        errors.append("release.yml changed the frozen create-release needs graph")

    for job in ("verify-pr-linux-gnu-abi", "verify-latest-linux-gnu-abi-aarch64",
                "linux-gnu-abi-latest-gate", "latest-release", "build-arm64-cross"):
        if _job_body(ci_yml, job):
            errors.append(f"ci.yml production job {job} must remain in the release lane")
    return errors


def _job_body(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    return match.group("body") if match else ""


def _job_needs(workflow: str, job: str) -> set[str]:
    body = _job_body(workflow, job)
    if not body:
        return set()
    inline = re.search(
        r"(?m)^    needs: \[(?P<needs>[A-Za-z0-9_-]+(?:, [A-Za-z0-9_-]+)*)\]$",
        body,
    )
    if inline:
        return set(inline.group("needs").split(", "))
    listed = re.search(r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", body)
    if listed:
        return {
            line.strip().removeprefix("- ").strip()
            for line in listed.group("needs").splitlines()
            if line.strip().startswith("- ")
        }
    scalar = re.search(r"(?m)^    needs: ([A-Za-z0-9_-]+)$", body)
    if scalar:
        return {scalar.group(1)}
    return set()


def check_no_process_api(source: str, label: str) -> list[str]:
    errors: list[str] = []
    for token in PROCESS_API_TOKENS:
        if token in source:
            errors.append(f"{label} must not use process API {token}")
    return errors


def check_smoke_script(source: str) -> list[str]:
    errors: list[str] = []
    forbidden_ro_chmod = "chmod +x /" + "gnu"
    if forbidden_ro_chmod in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must not chmod binaries through the "
            "read-only /gnu mount"
        )
    if '--volume "$stage:/gnu:ro"' not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must bind-mount the staged GNU "
            "directory read-only at /gnu"
        )
    if ":/gnu:rw" in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must not expose a read-write /gnu mount"
        )
    if 'chmod +x -- "$stage/ferrum-edge" "$stage/ferrum-cni"' not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must set +x on host staged copies "
            "before mounting /gnu:ro"
        )
    if "docker pull --platform" not in source or "docker run --rm" not in source:
        errors.append(
            "smoke_linux_gnu_baseline.sh must keep docker argv0 a literal docker"
        )
    if (
        '"$LINUX_GNU_SMOKE_FLOOR_IMAGE" != "$floor_image"' not in source
        or '"$LINUX_GNU_SMOKE_UBUNTU2204_IMAGE" != "$ubuntu_image"' not in source
    ):
        errors.append(
            "smoke_linux_gnu_baseline.sh must cross-check "
            "LINUX_GNU_SMOKE_FLOOR_IMAGE and LINUX_GNU_SMOKE_UBUNTU2204_IMAGE "
            "against the contract when those env vars are set"
        )
    return errors


def check_operator_docs(readme: str, cli_md: str, ci_cd_md: str, contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    floor = f"GLIBC_{contract['glibc_max_version']}"
    for label, text in (("README.md", readme), ("docs/cli.md", cli_md), ("docs/ci_cd.md", ci_cd_md)):
        for token in (floor, "AlmaLinux 8.10", "libgcc_s.so.1", "libz.so.1"):
            if token not in text:
                errors.append(f"{label} must document {token}")
        if "ferrum-edge-linux-x86_64" not in text:
            errors.append(f"{label} must keep the GNU x86_64 artifact name")
    for token in ("verify-linux-gnu-abi-aarch64", "linux-gnu-abi-release-gate"):
        if token not in ci_cd_md:
            errors.append(f"docs/ci_cd.md must document the versioned-release GNU ABI job {token}")
    if "release-dispatch.yml" not in ci_cd_md:
        errors.append("docs/ci_cd.md must document the manual release dispatcher release-dispatch.yml")
    if "linux-gnu-sysroot" not in ci_cd_md:
        errors.append("docs/ci_cd.md must document the isolated sysroot CARGO_TARGET_DIR")
    return errors


def check_sysroot_builder(source: str) -> list[str]:
    errors: list[str] = []
    dedicated = DEDICATED_SYSROOT_TARGET_DIR
    if f"--env CARGO_TARGET_DIR={dedicated}" not in source:
        errors.append(
            "sysroot builder must pin docker CARGO_TARGET_DIR to "
            f"{dedicated} with no host fallback"
        )
    if f'[[ "${{CARGO_TARGET_DIR:-}}" != "{dedicated}" ]]' not in source:
        errors.append(
            "sysroot builder must fail closed unless CARGO_TARGET_DIR is "
            f"exactly {dedicated}"
        )
    if f"--target-dir {dedicated}" not in source:
        errors.append(
            f"sysroot builder must pass cargo --target-dir {dedicated}"
        )
    if '--env CARGO_TARGET_DIR="$CARGO_TARGET_DIR"' in source:
        errors.append("sysroot builder must not pass host CARGO_TARGET_DIR into the container")
    if re.search(r"(?m)^\s+/src/target\s*$", source):
        errors.append("sysroot builder must not chown or otherwise use the whole /src/target tree")
    for token in (
        'target_root="$work_root/target"',
        '[[ -L "$target_root" ]]',
        'mkdir -p -- "$target_root"',
        '[[ ! -d "$target_root" || ! -w "$target_root" ]]',
    ):
        if token not in source:
            errors.append(
                "sysroot builder must create and validate the host-owned "
                f"canonical target parent ({token})"
            )
    chown_dedicated = (
        '    chown -R "${HOST_UID}:${HOST_GID}" \\\n'
        f"      {dedicated} \\\n"
    )
    if chown_dedicated not in source:
        errors.append(
            "sysroot builder must scope host ownership repair to "
            f"{dedicated}"
        )
    if '[[ -L "$src" ]]' not in source or '[[ -L "$dest" ]]' not in source:
        errors.append(
            "sysroot builder must reject symlink sources and canonical destinations"
        )
    if "copy_sysroot_binary ferrum-edge" not in source:
        errors.append("sysroot builder must copy ferrum-edge to the canonical path")
    if "copy_sysroot_binary ferrum-cni" not in source:
        errors.append("sysroot builder must copy ferrum-cni to the canonical path")
    if "cp -f --" not in source:
        errors.append("sysroot builder must copy proven binaries with cp -f --")
    if "clang-devel" not in source:
        errors.append(
            "sysroot builder must install clang-devel so bindgen build scripts "
            "can load libclang inside the pinned sysroot"
        )
    if "export LIBCLANG_PATH=/usr/lib64" not in source:
        errors.append("sysroot builder must pin LIBCLANG_PATH for bindgen build scripts")
    if 'compgen -G "$LIBCLANG_PATH/libclang.so*"' not in source:
        errors.append(
            "sysroot builder must fail closed when libclang is absent from the pinned sysroot"
        )
    if "--env RUSTFLAGS=" not in source:
        errors.append(
            "sysroot builder must set empty RUSTFLAGS so workspace mold "
            "rustflags cannot apply inside the sysroot"
        )
    if "--env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=" not in source:
        errors.append(
            "sysroot builder must clear CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS "
            "at the same precedence as the linker override"
        )
    return errors


def check_repository() -> list[str]:
    contract = load_contract()
    shape = check_contract_shape(contract)
    if shape:
        return shape
    errors: list[str] = []
    if str(contract.get("glibc_max_version")) != "2.34":
        errors.append("declared GLIBC floor must be 2.34")
    errors.extend(
        check_release_wiring(
            contract,
            RELEASE_YML.read_text(encoding="utf-8"),
            CI_YML.read_text(encoding="utf-8"),
        )
    )
    errors.extend(
        check_operator_docs(
            README.read_text(encoding="utf-8"),
            CLI_MD.read_text(encoding="utf-8"),
            CI_CD_MD.read_text(encoding="utf-8"),
            contract,
        )
    )
    errors.extend(check_no_process_api(Path(__file__).read_text(encoding="utf-8"), "verify_linux_gnu_abi.py"))
    errors.extend(check_no_process_api(SMOKE_PY.read_text(encoding="utf-8"), "smoke_linux_gnu_baseline.py"))
    if not SMOKE_SH.is_file():
        errors.append("smoke_linux_gnu_baseline.sh is missing")
    else:
        errors.extend(check_smoke_script(SMOKE_SH.read_text(encoding="utf-8")))
    errors.extend(check_sysroot_builder(SYSROOT_BUILD_SH.read_text(encoding="utf-8")))
    return errors


READELF_FLOOR_FIXTURE = """\
Version symbols section '.gnu.version' contains 4 entries:
  0x0060:   Name: GLIBC_2.2.5  Flags: none  Version: 2
  0x0070:   Name: GLIBC_2.34  Flags: none  Version: 3
Dynamic section at offset 0x0 contains 4 entries:
  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
  0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
"""

READELF_TOO_NEW_FIXTURE = """\
Version symbols section '.gnu.version' contains 4 entries:
  0x0060:   Name: GLIBC_2.2.5  Flags: none  Version: 2
  0x0070:   Name: GLIBC_2.39  Flags: none  Version: 3
Dynamic section at offset 0x0 contains 3 entries:
  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  0x0000000000000001 (NEEDED)             Shared library: [libz.so.1]
"""

READELF_UNEXPECTED_LIB_FIXTURE = """\
Version symbols section '.gnu.version' contains 2 entries:
  0x0060:   Name: GLIBC_2.17  Flags: none  Version: 2
Dynamic section at offset 0x0 contains 3 entries:
  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  0x0000000000000001 (NEEDED)             Shared library: [libssl.so.3]
"""


def evaluate_readelf_fixture(text: str, contract: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    versions = glibc_versions_from_readelf(text)
    needed = needed_libraries_from_readelf(text)
    ceiling = parse_version(str(contract["glibc_max_version"]))
    allowed = set(contract["allowed_needed"])
    if versions:
        maximum = max(parse_version(item) for item in versions)
        if version_exceeds(maximum, ceiling):
            pretty = ".".join(str(part) for part in maximum)
            errors.append(
                f"{label} requires GLIBC_{pretty}, above the declared floor "
                f"GLIBC_{contract['glibc_max_version']}"
            )
    else:
        errors.append(f"{label} has no GLIBC version-need records")
    if "libc.so.6" not in needed:
        errors.append(f"{label} is missing libc.so.6")
    unexpected = [name for name in needed if name not in allowed]
    if unexpected:
        errors.append(f"{label} dynamically links unexpected libraries: {', '.join(unexpected)}")
    return errors


def _synthetic_dynamic_elf64(
    needed: list[str],
    glibc_names: list[str],
    *,
    e_machine: int = EM_X86_64,
    rpath: str | None = None,
    runpath: str | None = None,
) -> bytes:
    """Build a little-endian ELF64 with DT_NEEDED and GNU verneed records."""

    extra_strings = [item for item in (rpath, runpath) if item is not None]
    strings = ["", *needed, *glibc_names, *extra_strings]
    strtab = b"".join(item.encode("ascii") + b"\x00" for item in strings)
    offsets: dict[str, int] = {}
    cursor = 0
    for item in strings:
        offsets[item] = cursor
        cursor += len(item) + 1

    ehdr_size = 64
    phdr_size = 56
    phnum = 2
    extra_dyn = (1 if rpath is not None else 0) + (1 if runpath is not None else 0)
    dyn_count = len(needed) + 4 + extra_dyn  # STRTAB, VERNEED, VERNEEDNUM, NULL
    dyn_size = dyn_count * 16
    verneed_size = 16 + 16 * len(glibc_names)
    phoff = ehdr_size
    dyn_off = phoff + phdr_size * phnum
    strtab_off = dyn_off + dyn_size
    verneed_off = strtab_off + len(strtab)
    file_size = verneed_off + verneed_size

    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        e_machine,
        1,
        0,
        phoff,
        0,
        0,
        ehdr_size,
        phdr_size,
        phnum,
        0,
        0,
        0,
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, file_size, file_size, 1)
    dynamic = struct.pack(
        "<IIQQQQQQ", 2, 4, dyn_off, dyn_off, dyn_off, dyn_size, dyn_size, 8
    )
    dyn_entries = bytearray()
    for name in needed:
        dyn_entries.extend(struct.pack("<qQ", DT_NEEDED, offsets[name]))
    dyn_entries.extend(struct.pack("<qQ", DT_STRTAB, strtab_off))
    dyn_entries.extend(struct.pack("<qQ", DT_VERNEED, verneed_off))
    dyn_entries.extend(struct.pack("<qQ", DT_VERNEEDNUM, 1))
    if rpath is not None:
        dyn_entries.extend(struct.pack("<qQ", DT_RPATH, offsets[rpath]))
    if runpath is not None:
        dyn_entries.extend(struct.pack("<qQ", DT_RUNPATH, offsets[runpath]))
    dyn_entries.extend(struct.pack("<qQ", 0, 0))

    aux_offset = 16
    verneed = struct.pack(
        "<HHIII",
        1,
        len(glibc_names),
        offsets[needed[0]] if needed else 0,
        aux_offset,
        0,
    )
    vernaux = bytearray()
    for index, name in enumerate(glibc_names):
        next_off = 16 if index + 1 < len(glibc_names) else 0
        vernaux.extend(struct.pack("<IHHII", 0, 0, index + 2, offsets[name], next_off))

    return bytes(ehdr + load + dynamic + dyn_entries + strtab + verneed + vernaux)


def run_self_test() -> list[str]:
    failures: list[str] = []
    contract = load_contract()
    shape = check_contract_shape(contract)
    if shape:
        # Every fixture below indexes the contract directly. Reporting the
        # shape is strictly more useful than raising out of the first one.
        return shape
    ceiling = parse_version("2.34")

    if parse_version("2.34") > ceiling:
        failures.append("equal floor version was treated as too new")
    if not version_exceeds(parse_version("2.39"), ceiling):
        failures.append("GLIBC_2.39 was not rejected against the 2.34 floor")
    if version_exceeds(parse_version("2.17"), ceiling):
        failures.append("GLIBC_2.17 was rejected against the 2.34 floor")
    if not version_exceeds(parse_version("2.34.1"), ceiling):
        failures.append("GLIBC_2.34.1 was not rejected against the 2.34 floor")

    # A contract whose `allowed_needed` slid under a [table] header parses
    # fine and then breaks every consumer, so the shape guard is exercised.
    if not check_contract_shape({"glibc_max_version": "2.34"}):
        failures.append("a contract without a top-level allowed_needed was accepted")
    if not check_contract_shape({**contract, "allowed_needed": ["libm.so.6"]}):
        failures.append("a contract that does not permit libc.so.6 was accepted")
    if not check_contract_shape({"allowed_needed": list(contract["allowed_needed"])}):
        failures.append("a contract without a top-level glibc_max_version was accepted")

    if evaluate_readelf_fixture(READELF_FLOOR_FIXTURE, contract, "floor-fixture"):
        failures.append("in-floor GLIBC_2.34 fixture was rejected")
    too_new = evaluate_readelf_fixture(READELF_TOO_NEW_FIXTURE, contract, "too-new-fixture")
    if not any("GLIBC_2.39" in item for item in too_new):
        failures.append("GLIBC_2.39 fixture was not rejected")
    unexpected = evaluate_readelf_fixture(
        READELF_UNEXPECTED_LIB_FIXTURE, contract, "unexpected-lib-fixture"
    )
    if not any("libssl.so.3" in item for item in unexpected):
        failures.append("unexpected SONAME fixture was not rejected")

    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "missing"
        missing_errors = scan_binary(missing, contract)
        if not missing_errors:
            failures.append("missing binary was accepted")
        not_elf = Path(tmp) / "not-elf"
        not_elf.write_bytes(b"not an elf")
        not_elf_errors = scan_binary(not_elf, contract)
        if not any("not an ELF file" in item for item in not_elf_errors):
            failures.append("non-ELF file was not rejected")

        floor_elf = Path(tmp) / "floor.elf"
        floor_elf.write_bytes(
            _synthetic_dynamic_elf64(["libc.so.6", "libgcc_s.so.1"], ["GLIBC_2.2.5", "GLIBC_2.34"])
        )
        if scan_binary(floor_elf, contract):
            failures.append("in-floor synthetic ELF was rejected")

        too_new_elf = Path(tmp) / "too-new.elf"
        too_new_elf.write_bytes(
            _synthetic_dynamic_elf64(["libc.so.6", "libz.so.1"], ["GLIBC_2.2.5", "GLIBC_2.39"])
        )
        too_new_elf_errors = scan_binary(too_new_elf, contract)
        if not any("GLIBC_2.39" in item for item in too_new_elf_errors):
            failures.append("synthetic GLIBC_2.39 ELF was not rejected")

        unexpected_elf = Path(tmp) / "unexpected.elf"
        unexpected_elf.write_bytes(
            _synthetic_dynamic_elf64(["libc.so.6", "libssl.so.3"], ["GLIBC_2.17"])
        )
        unexpected_elf_errors = scan_binary(unexpected_elf, contract)
        if not any("libssl.so.3" in item for item in unexpected_elf_errors):
            failures.append("synthetic unexpected SONAME ELF was not rejected")

        named_x86 = Path(tmp) / "ferrum-edge-linux-x86_64"
        named_x86.write_bytes(
            _synthetic_dynamic_elf64(
                ["libc.so.6", "libgcc_s.so.1"], ["GLIBC_2.2.5", "GLIBC_2.34"]
            )
        )
        if scan_binary(named_x86, contract):
            failures.append("in-floor x86_64 advertised ELF was rejected")

        aarch_as_x86 = Path(tmp) / "mismatch-x86" / "ferrum-edge-linux-x86_64"
        aarch_as_x86.parent.mkdir()
        aarch_as_x86.write_bytes(
            _synthetic_dynamic_elf64(
                ["libc.so.6", "libgcc_s.so.1"],
                ["GLIBC_2.2.5", "GLIBC_2.34"],
                e_machine=EM_AARCH64,
            )
        )
        aarch_as_x86_errors = scan_binary(aarch_as_x86, contract)
        if not any("EM_AARCH64" in item and "EM_X86_64" in item for item in aarch_as_x86_errors):
            failures.append("aarch64 ELF advertised as x86_64 was not rejected")

        x86_as_aarch = Path(tmp) / "mismatch-arm" / "ferrum-edge-linux-aarch64"
        x86_as_aarch.parent.mkdir()
        x86_as_aarch.write_bytes(
            _synthetic_dynamic_elf64(
                ["libc.so.6", "libgcc_s.so.1"],
                ["GLIBC_2.2.5", "GLIBC_2.34"],
                e_machine=EM_X86_64,
            )
        )
        x86_as_aarch_errors = scan_binary(x86_as_aarch, contract)
        if not any("EM_X86_64" in item and "EM_AARCH64" in item for item in x86_as_aarch_errors):
            failures.append("x86_64 ELF advertised as aarch64 was not rejected")

        path_mismatch = (
            Path(tmp) / "target" / "x86_64-unknown-linux-gnu" / "release" / "ferrum-edge"
        )
        path_mismatch.parent.mkdir(parents=True)
        path_mismatch.write_bytes(
            _synthetic_dynamic_elf64(
                ["libc.so.6", "libgcc_s.so.1"],
                ["GLIBC_2.2.5", "GLIBC_2.34"],
                e_machine=EM_AARCH64,
            )
        )
        path_mismatch_errors = scan_binary(path_mismatch, contract)
        if not any("EM_AARCH64" in item for item in path_mismatch_errors):
            failures.append(
                "aarch64 ELF under x86_64-unknown-linux-gnu was not rejected"
            )

        rpath_elf = Path(tmp) / "rpath.elf"
        rpath_elf.write_bytes(
            _synthetic_dynamic_elf64(
                ["libc.so.6", "libgcc_s.so.1"],
                ["GLIBC_2.2.5", "GLIBC_2.34"],
                rpath="/opt/build/lib",
            )
        )
        rpath_errors = scan_binary(rpath_elf, contract)
        if not any("DT_RPATH" in item and "/opt/build/lib" in item for item in rpath_errors):
            failures.append("synthetic DT_RPATH ELF was not rejected")

        runpath_elf = Path(tmp) / "runpath.elf"
        runpath_elf.write_bytes(
            _synthetic_dynamic_elf64(
                ["libc.so.6", "libgcc_s.so.1"],
                ["GLIBC_2.2.5", "GLIBC_2.34"],
                runpath="/writable/lib",
            )
        )
        runpath_errors = scan_binary(runpath_elf, contract)
        if not any("DT_RUNPATH" in item and "/writable/lib" in item for item in runpath_errors):
            failures.append("synthetic DT_RUNPATH ELF was not rejected")

        mis_scoped = scan_assets([named_x86], {"smoke": {}})
        if not any("must define top-level" in item for item in mis_scoped):
            failures.append(
                "a mis-scoped contract on the binaries scan path was not diagnosed"
            )

    scanner_source = Path(__file__).read_text(encoding="utf-8")
    if not check_no_process_api(
        "import " + "subprocess\n" + scanner_source,
        "verify_linux_gnu_abi.py",
    ):
        failures.append("subprocess import in ABI scanner was not rejected")
    if not check_no_process_api(
        "import " + "subprocess\n" + SMOKE_PY.read_text(encoding="utf-8"),
        "smoke_linux_gnu_baseline.py",
    ):
        failures.append("subprocess import in smoke self-test was not rejected")

    # The pinned build and smoke images live in .github/linux-gnu-abi.toml,
    # which every hosted helper reads, so an unpinned tag is rejected there
    # rather than by restating the digest in each workflow.
    unpinned_contract = {
        **contract,
        "sysroot": {**contract["sysroot"], "image": "almalinux:latest"},
    }
    if not check_release_wiring(
        unpinned_contract,
        RELEASE_YML.read_text(encoding="utf-8"),
        CI_YML.read_text(encoding="utf-8"),
    ):
        failures.append("an unpinned GNU sysroot image was not rejected")

    short_protoc_contract = {
        **contract,
        "sysroot": {**contract["sysroot"], "protoc_sha256": "deadbeef"},
    }
    if not check_release_wiring(
        short_protoc_contract,
        RELEASE_YML.read_text(encoding="utf-8"),
        CI_YML.read_text(encoding="utf-8"),
    ):
        failures.append("an unpinned protoc checksum was not rejected")

    mutated_docs = README.read_text(encoding="utf-8").replace("GLIBC_2.34", "GLIBC_2.39", 1)
    if not check_operator_docs(
        mutated_docs,
        CLI_MD.read_text(encoding="utf-8"),
        CI_CD_MD.read_text(encoding="utf-8"),
        contract,
    ):
        failures.append("README GLIBC floor regression was not rejected")

    ci_yml = CI_YML.read_text(encoding="utf-8")
    for job in ("verify-pr-linux-gnu-abi", "build-arm64-cross", "latest-release"):
        mutated = ci_yml + f"\n  {job}:\n    steps: []\n"
        if not check_release_wiring(contract, RELEASE_YML.read_text(encoding="utf-8"), mutated):
            failures.append(f"retired CI production job {job} was not rejected")

    mutated_smoke = SMOKE_SH.read_text(encoding="utf-8").replace(
        '--volume "$stage:/gnu:ro"',
        '--volume "$stage:/gnu:rw"',
        1,
    )
    if not check_smoke_script(mutated_smoke):
        failures.append("read-write /gnu smoke mount was not rejected")

    mutated_smoke_env = SMOKE_SH.read_text(encoding="utf-8").replace(
        '"$LINUX_GNU_SMOKE_FLOOR_IMAGE" != "$floor_image"',
        '"$LINUX_GNU_SMOKE_FLOOR_IMAGE" == "$floor_image"',
        1,
    )
    if not check_smoke_script(mutated_smoke_env):
        failures.append("smoke script without a floor-image contract cross-check was not rejected")

    builder = SYSROOT_BUILD_SH.read_text(encoding="utf-8")
    mutated_target_dir = builder.replace(
        "--env CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot",
        "--env CARGO_TARGET_DIR=/src/target",
        1,
    )
    if not check_sysroot_builder(mutated_target_dir):
        failures.append("unisolated CARGO_TARGET_DIR in sysroot builder was not rejected")

    mutated_host_override = builder.replace(
        "--env CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot",
        '--env CARGO_TARGET_DIR="$CARGO_TARGET_DIR"',
        1,
    )
    if not check_sysroot_builder(mutated_host_override):
        failures.append("host CARGO_TARGET_DIR passthrough in sysroot builder was not rejected")

    mutated_chown = builder.replace(
        '    chown -R "${HOST_UID}:${HOST_GID}" \\\n'
        "      /src/target/linux-gnu-sysroot \\\n"
        "      /opt/cargo \\\n",
        '    chown -R "${HOST_UID}:${HOST_GID}" \\\n'
        "      /src/target \\\n"
        "      /opt/cargo \\\n",
        1,
    )
    if not check_sysroot_builder(mutated_chown):
        failures.append("whole /src/target chown in sysroot builder was not rejected")

    mutated_target_parent = builder.replace('mkdir -p -- "$target_root"\n', "", 1)
    if not check_sysroot_builder(mutated_target_parent):
        failures.append("missing host-owned target parent preparation was not rejected")

    mutated_target_parent_symlink = builder.replace(
        '[[ -L "$target_root" ]]', '[[ -d "$target_root" ]]', 1
    )
    if not check_sysroot_builder(mutated_target_parent_symlink):
        failures.append("host target parent symlink acceptance was not rejected")

    mutated_symlink = builder.replace('[[ -L "$src" ]]', '[[ -d "$src" ]]', 1)
    if not check_sysroot_builder(mutated_symlink):
        failures.append("sysroot builder without symlink rejection was not rejected")

    mutated_cni_copy = builder.replace("copy_sysroot_binary ferrum-cni\n", "", 1)
    if not check_sysroot_builder(mutated_cni_copy):
        failures.append("sysroot builder missing ferrum-cni canonical copy was not rejected")

    mutated_clang = builder.replace(" clang clang-devel\n", "\n", 1)
    if not check_sysroot_builder(mutated_clang):
        failures.append("sysroot builder without clang-devel was not rejected")

    mutated_libclang_path = builder.replace(
        "    export LIBCLANG_PATH=/usr/lib64\n", "", 1
    )
    if not check_sysroot_builder(mutated_libclang_path):
        failures.append("sysroot builder without a pinned LIBCLANG_PATH was not rejected")

    mutated_libclang_guard = builder.replace(
        '    if ! compgen -G "$LIBCLANG_PATH/libclang.so*" > /dev/null; then\n'
        "      echo \"::error::pinned sysroot is missing libclang under $LIBCLANG_PATH; "
        'bindgen build scripts cannot run" >&2\n'
        "      exit 1\n"
        "    fi\n",
        "",
        1,
    )
    if not check_sysroot_builder(mutated_libclang_guard):
        failures.append("sysroot builder without a libclang presence guard was not rejected")

    mutated_target_rustflags = builder.replace(
        "  --env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS= \\\n",
        "",
        1,
    )
    if not check_sysroot_builder(mutated_target_rustflags):
        failures.append(
            "sysroot builder without cleared target rustflags was not rejected"
        )

    release_yml = RELEASE_YML.read_text(encoding="utf-8")
    producer_body = _job_body(release_yml, "build-release-binaries")
    if not producer_body:
        failures.append("release.yml x86_64 GNU producer job body is missing")
    else:
        mutated_native = release_yml.replace(
            producer_body,
            producer_body.replace(
                "bash .github/scripts/build_linux_gnu_sysroot.sh",
                "cargo build --features cloud-secrets --release "
                "--target x86_64-unknown-linux-gnu",
                1,
            ),
            1,
        )
        if not check_release_wiring(contract, mutated_native, ci_yml):
            failures.append(
                "a native x86_64 GNU release producer was not rejected"
            )

        mutated_rebuilt = release_yml.replace(
            producer_body,
            producer_body.replace(
                "release-assets/ferrum-edge-linux-x86_64 \\\n",
                "target/x86_64-unknown-linux-gnu/release/ferrum-edge \\\n",
                1,
            ),
            1,
        )
        if not check_release_wiring(contract, mutated_rebuilt, ci_yml):
            failures.append(
                "a release producer that gates a rebuilt binary was not rejected"
            )

    mutated_arm_rebuild = release_yml.replace(
        "  verify-linux-gnu-abi-aarch64:\n",
        "  verify-linux-gnu-abi-aarch64-missing:\n",
        1,
    )
    if not check_release_wiring(contract, mutated_arm_rebuild, ci_yml):
        failures.append("a missing ARM64 GNU ABI job was not rejected")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("binaries", nargs="*", type=Path)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    failures: list[str] = []
    if args.self_test:
        failures.extend(run_self_test())
    if args.check_contract:
        failures.extend(check_repository())
    if args.binaries:
        contract = load_contract()
        shape = check_contract_shape(contract)
        failures.extend(shape)
        if not shape:
            failures.extend(scan_assets(args.binaries, contract))
    if not args.self_test and not args.check_contract and not args.binaries:
        parser.error("supply binaries, --self-test, and/or --check-contract")

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
